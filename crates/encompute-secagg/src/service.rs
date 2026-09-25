//! The coordinator over HTTP, and the participant client.
//!
//! | Method | Path | |
//! |---|---|---|
//! | GET | /v1/round | the spec and round |
//! | GET | /v1/status | stage, awaited parties, outcome |
//! | POST | /v1/join, /v1/shares, /v1/masked, /v1/consistency, /v1/reveal | a party's message |
//! | GET | /v1/keys, /v1/inbox/{party}, /v1/survivors, /v1/unmask | the coordinator's broadcasts |
//! | GET | /v1/receipt | the signed aggregation receipt, once done |
//!
//! A stage closes when every expected party has answered or its timeout
//! passes (dropouts); closing below the threshold aborts the round. There
//! is no endpoint for any individual value: the coordinator never has one.
//! The aggregate itself is returned to the coordinator's process, not
//! served.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::json;

use encompute_attestation::AttestationRecord;
use encompute_ir::confidentiality::PartyId;
use encompute_ir::{Code, Error, Result};

use crate::protocol::{Inbox, KeysBroadcast, Survivors, UnmaskRequest};
use crate::round::{
    AggregateAsset, AggregationReceipt, AggregationRound, AggregationSpec, RoundCoordinator,
    RoundParticipant,
};

const MAX_BODY: u64 = 64 << 20;

/// Protocol messages accepted per source address per minute.
pub const POSTS_PER_MINUTE: u32 = 600;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundStage {
    Advertise,
    ShareKeys,
    MaskedInput,
    Consistency,
    Unmask,
    Done,
    Aborted,
}

/// What `/v1/round` returns.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundOffer {
    pub spec: AggregationSpec,
    pub round: AggregationRound,
    pub round_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub stage: RoundStage,
    pub awaiting: Vec<PartyId>,
    #[serde(default)]
    pub error: Option<ErrorBody>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl From<&Error> for ErrorBody {
    fn from(e: &Error) -> Self {
        Self {
            code: e.code.as_str().into(),
            message: e.message.clone(),
        }
    }
}

struct State {
    coord: RoundCoordinator,
    stage: RoundStage,
    since: Instant,
    keys: Option<KeysBroadcast>,
    inboxes: Option<BTreeMap<PartyId, Inbox>>,
    survivors: Option<Survivors>,
    unmask: Option<UnmaskRequest>,
    receipt: Option<AggregationReceipt>,
    aggregate: Option<AggregateAsset>,
    error: Option<Error>,
}

/// A coordinator serving one round.
#[derive(Clone)]
pub struct CoordinatorService {
    state: Arc<Mutex<State>>,
    stage_timeout: Duration,
    offer: Arc<RoundOffer>,
}

impl CoordinatorService {
    pub fn new(coord: RoundCoordinator, stage_timeout: Duration) -> Result<Self> {
        let offer = RoundOffer {
            spec: coord.spec.clone(),
            round: coord.round.clone(),
            round_id: coord.round_id()?,
        };
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                coord,
                stage: RoundStage::Advertise,
                since: Instant::now(),
                keys: None,
                inboxes: None,
                survivors: None,
                unmask: None,
                receipt: None,
                aggregate: None,
                error: None,
            })),
            stage_timeout,
            offer: Arc::new(offer),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Closes the current stage if everyone answered or it timed out.
    pub fn tick(&self) {
        let mut s = self.lock();
        if matches!(s.stage, RoundStage::Done | RoundStage::Aborted) {
            return;
        }
        if !s.coord.awaiting().is_empty() && s.since.elapsed() < self.stage_timeout {
            return;
        }
        let st = &mut *s;
        let r: Result<RoundStage> = (|| {
            Ok(match st.stage {
                RoundStage::Advertise => {
                    st.keys = Some(st.coord.close_advertise()?);
                    RoundStage::ShareKeys
                }
                RoundStage::ShareKeys => {
                    st.inboxes = Some(st.coord.close_shares()?);
                    RoundStage::MaskedInput
                }
                RoundStage::MaskedInput => {
                    st.survivors = Some(st.coord.close_masked()?);
                    RoundStage::Consistency
                }
                RoundStage::Consistency => {
                    st.unmask = Some(st.coord.close_consistency()?);
                    RoundStage::Unmask
                }
                RoundStage::Unmask => {
                    let (a, r) = st.coord.finalize()?;
                    st.aggregate = Some(a);
                    st.receipt = Some(r);
                    RoundStage::Done
                }
                done => done,
            })
        })();
        match r {
            Ok(next) => st.stage = next,
            Err(e) => {
                st.error = Some(e);
                st.stage = RoundStage::Aborted;
            }
        }
        st.since = Instant::now();
    }

    pub fn status(&self) -> Status {
        let s = self.lock();
        Status {
            stage: s.stage,
            awaiting: s.coord.awaiting().into_iter().collect(),
            error: s.error.as_ref().map(ErrorBody::from),
        }
    }

    /// Ticks until the round ends; returns the aggregate and receipt.
    pub fn run_to_completion(&self) -> Result<(AggregateAsset, AggregationReceipt)> {
        loop {
            self.tick();
            {
                let s = self.lock();
                match s.stage {
                    RoundStage::Done => {
                        return Ok((
                            s.aggregate.clone().expect("done"),
                            s.receipt.clone().expect("done"),
                        ))
                    }
                    RoundStage::Aborted => return Err(s.error.clone().expect("aborted")),
                    _ => {}
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn post(&self, what: &str, body: &[u8]) -> Result<()> {
        let parse = |e: serde_json::Error| {
            Error::new(
                Code::AggregationProtocol,
                format!("malformed {what} message: {e}"),
            )
        };
        let mut s = self.lock();
        let c = &mut s.coord;
        match what {
            "join" => c.receive_advertise(serde_json::from_slice(body).map_err(parse)?),
            "shares" => c.receive_shares(serde_json::from_slice(body).map_err(parse)?),
            "masked" => c.receive_masked(serde_json::from_slice(body).map_err(parse)?),
            "consistency" => c.receive_consistency(serde_json::from_slice(body).map_err(parse)?),
            "reveal" => c.receive_reveal(serde_json::from_slice(body).map_err(parse)?),
            _ => Err(Error::new(Code::Remote, format!("no such message {what}"))),
        }
    }

    /// `Ok(None)`: not ready yet.
    fn get(&self, path: &[&str]) -> Result<Option<serde_json::Value>> {
        let s = self.lock();
        if s.stage == RoundStage::Aborted {
            return Err(s.error.clone().expect("aborted"));
        }
        Ok(match path {
            ["keys"] => s.keys.as_ref().map(val),
            ["inbox", party] => match &s.inboxes {
                None => None,
                Some(i) => Some(
                    i.iter()
                        .find(|(p, _)| p.as_str() == *party)
                        .map(|(_, x)| val(x))
                        .ok_or_else(|| {
                            Error::new(
                                Code::AggregationThreshold,
                                format!("{party} is not in U2 (it did not share keys in time)"),
                            )
                        })?,
                ),
            },
            ["survivors"] => s.survivors.as_ref().map(val),
            ["unmask"] => s.unmask.as_ref().map(val),
            ["receipt"] => s.receipt.as_ref().map(val),
            _ => return Err(Error::new(Code::Remote, "no such endpoint")),
        })
    }

    fn handle(&self, method: &tiny_http::Method, path: &str, body: &[u8]) -> (u16, String) {
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let err = |e: &Error| {
            let status = match e.code {
                Code::AggregationUnauthorized => 403,
                Code::AggregationThreshold => 410,
                Code::Remote => 404,
                _ => 409,
            };
            (status, json!(ErrorBody::from(e)).to_string())
        };
        match (method, parts.as_slice()) {
            (tiny_http::Method::Get, ["v1", "round"]) => (200, json!(*self.offer).to_string()),
            (tiny_http::Method::Get, ["v1", "status"]) => (200, json!(self.status()).to_string()),
            (tiny_http::Method::Post, ["v1", what]) => match self.post(what, body) {
                Ok(()) => (200, "{}".into()),
                Err(e) => err(&e),
            },
            (tiny_http::Method::Get, ["v1", rest @ ..]) => match self.get(rest) {
                Ok(Some(v)) => (200, v.to_string()),
                Ok(None) => (425, json!({"code": "", "message": "not ready"}).to_string()),
                Err(e) => err(&e),
            },
            _ => (
                404,
                json!({"code": "ENC1701", "message": "no such endpoint"}).to_string(),
            ),
        }
    }

    /// Serves HTTP on `server` from a background thread. Messages (POSTs)
    /// are limited to [`POSTS_PER_MINUTE`] per source address; a party
    /// sends five per round.
    pub fn spawn(&self, server: tiny_http::Server) {
        let me = self.clone();
        std::thread::spawn(move || {
            let mut posts: std::collections::HashMap<std::net::IpAddr, (u64, u32)> =
                std::collections::HashMap::new();
            for mut req in server.incoming_requests() {
                let method = req.method().clone();
                if method == tiny_http::Method::Post {
                    if let Some(ip) = req.remote_addr().map(|a| a.ip()) {
                        let minute = encompute_attestation::unix_now() / 60;
                        if posts.len() > 65_536 {
                            posts.retain(|_, (m, _)| *m == minute);
                        }
                        let w = posts.entry(ip).or_insert((minute, 0));
                        if w.0 != minute {
                            *w = (minute, 0);
                        }
                        w.1 += 1;
                        if w.1 > POSTS_PER_MINUTE {
                            let body = json!({"code": "ENC1701", "message": "too many messages; retry later"});
                            let _ = req.respond(
                                tiny_http::Response::from_string(body.to_string())
                                    .with_status_code(429),
                            );
                            continue;
                        }
                    }
                }
                let path = req.url().split('?').next().unwrap_or("").to_owned();
                let mut body = Vec::new();
                let (status, out) = match req.as_reader().take(MAX_BODY + 1).read_to_end(&mut body)
                {
                    Ok(_) if body.len() as u64 > MAX_BODY => (
                        413,
                        json!({"code": "ENC1701", "message": "body too large"}).to_string(),
                    ),
                    Ok(_) => me.handle(&method, &path, &body),
                    Err(_) => (400, "{}".into()),
                };
                let h = tiny_http::Header::from_bytes("Content-Type", "application/json")
                    .expect("header");
                let _ = req.respond(
                    tiny_http::Response::from_string(out)
                        .with_status_code(status)
                        .with_header(h),
                );
            }
        });
    }
}

fn val<T: Serialize>(x: &T) -> serde_json::Value {
    serde_json::to_value(x).expect("serializable")
}

/// A participant talking to a coordinator over HTTP.
pub struct ParticipantClient {
    url: String,
    agent: ureq::Agent,
    poll: Duration,
    timeout: Duration,
}

impl ParticipantClient {
    pub fn new(url: &str, timeout: Duration) -> Self {
        Self {
            url: url.trim_end_matches('/').to_owned(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(60))
                .build(),
            poll: Duration::from_millis(50),
            timeout,
        }
    }

    fn remote(e: ureq::Error) -> Error {
        match e {
            ureq::Error::Status(_, r) => match r.into_json::<ErrorBody>() {
                Ok(b) => Error::new(
                    Code::parse(&b.code).unwrap_or(Code::Remote),
                    format!("coordinator: {}", b.message),
                ),
                Err(e) => Error::new(Code::Remote, format!("coordinator: {e}")),
            },
            e => Error::new(Code::Remote, format!("coordinator: {e}")),
        }
    }

    pub fn offer(&self) -> Result<RoundOffer> {
        self.agent
            .get(&format!("{}/v1/round", self.url))
            .call()
            .map_err(Self::remote)?
            .into_json()
            .map_err(|e| Error::new(Code::Remote, e.to_string()))
    }

    pub fn send<T: Serialize>(&self, what: &str, msg: &T) -> Result<()> {
        self.agent
            .post(&format!("{}/v1/{what}", self.url))
            .send_json(serde_json::to_value(msg).expect("serializable"))
            .map_err(Self::remote)?;
        Ok(())
    }

    /// Polls a broadcast until it is ready.
    pub fn wait<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let start = Instant::now();
        loop {
            match self.agent.get(&format!("{}/v1/{path}", self.url)).call() {
                Ok(r) => {
                    return r
                        .into_json()
                        .map_err(|e| Error::new(Code::Remote, e.to_string()))
                }
                Err(ureq::Error::Status(425, _)) => {}
                Err(e) => return Err(Self::remote(e)),
            }
            if start.elapsed() > self.timeout {
                return Err(Error::new(
                    Code::Remote,
                    format!("timed out waiting for {path}"),
                ));
            }
            std::thread::sleep(self.poll);
        }
    }

    /// Runs this party's side of the round to the end; returns the
    /// receipt.
    pub fn participate(&self, mut p: RoundParticipant) -> Result<AggregationReceipt> {
        let party = p.party().as_str().to_owned();
        self.send("join", &p.advertise()?)?;
        let keys: KeysBroadcast = self.wait("keys")?;
        self.send("shares", &p.share_keys(&keys)?)?;
        let inbox: Inbox = self.wait(&format!("inbox/{party}"))?;
        self.send("masked", &p.masked_input(&inbox)?)?;
        let survivors: Survivors = self.wait("survivors")?;
        self.send("consistency", &p.consistency(&survivors)?)?;
        let unmask: UnmaskRequest = self.wait("unmask")?;
        self.send("reveal", &p.unmask(&unmask)?)?;
        self.wait("receipt")
    }
}

/// Joins the coordinator's current round if it matches `approved`.
pub fn join(
    client: &ParticipantClient,
    approved: &AggregationSpec,
    party: &PartyId,
    identity: ed25519_dalek::SigningKey,
    values: &[f64],
    attestation: Option<AttestationRecord>,
    last_sequence: Option<u64>,
) -> Result<RoundParticipant> {
    let offer = client.offer()?;
    if offer.round.id()? != offer.round_id {
        return Err(Error::new(
            Code::AggregationBinding,
            "the round's ID does not match the round",
        ));
    }
    RoundParticipant::join(
        approved,
        &offer.spec,
        &offer.round,
        party,
        identity,
        values,
        attestation,
        last_sequence,
    )
}
