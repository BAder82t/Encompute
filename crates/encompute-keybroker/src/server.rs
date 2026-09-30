//! The broker over HTTP (JSON):
//!
//! - `POST /v1/challenge` → [`AttestationChallenge`](encompute_attestation::AttestationChallenge)
//! - `POST /v1/attest` (evidence) → [`SessionInfo`](crate::SessionInfo)
//! - `POST /v1/release` (`{"session", "asset_id"}`) → [`EncryptedKeyGrant`](encompute_attestation::EncryptedKeyGrant)
//!
//! - `POST /v1/release/governed` ([`GovernedReleaseRequest`](crate::GovernedReleaseRequest))
//!   → [`GovernedGrant`](crate::GovernedGrant): a governed release, persisted
//!   before the key is sealed
//! - `POST /v1/authorizations` (an owner-signed authorization) and
//!   `POST /v1/authorizations/revoke` (an owner-signed revocation): both
//!   verified under the owner's pinned governance key, then persisted
//!
//! - `POST /v1/messages`: signed messages from the pinned control plane
//!   (`asset.revoked`: every version of the asset's key is destroyed;
//!   `authorization.revoked`: an authorization is no longer used;
//!   `asset.expired`: the asset is never released again)
//! - `GET /live`, `GET /ready`
//!
//! There is no endpoint that returns a key in the clear, and none that
//! manages keys: owners manage them offline with the CLI. The control plane
//! can only deny.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use encompute_attestation::{public_denial, AttestationEvidence, KeyReleaseReceipt};
use encompute_ir::{Code, Error};
use encompute_trust::authz::{SignedAuthorizationV2, SignedRevocationV2};
use encompute_verification::http;

use crate::{GovernedGrant, GovernedReleaseRequest, KeyBroker};

const MAX_BODY: u64 = 96 << 10;

/// Requests per source address per minute: a host flooding the broker can
/// exhaust its own allowance, not the open-challenge table.
pub const REQUESTS_PER_MINUTE: u32 = 60;

/// A fixed one-minute window per source address.
struct RateLimit {
    windows: HashMap<IpAddr, (u64, u32)>,
    per_minute: u32,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            windows: HashMap::new(),
            per_minute: REQUESTS_PER_MINUTE,
        }
    }
}

impl RateLimit {
    fn allow(&mut self, ip: IpAddr, now: u64) -> bool {
        let minute = now / 60;
        if self.windows.len() > 65_536 {
            self.windows.retain(|_, (m, _)| *m == minute);
        }
        let w = self.windows.entry(ip).or_insert((minute, 0));
        if w.0 != minute {
            *w = (minute, 0);
        }
        w.1 += 1;
        w.1 <= self.per_minute
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseRequest {
    pub session: String,
    pub asset_id: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ErrorBody {
    pub code: String,
    pub message: String,
}

fn reply(status: u16, body: String) -> http::Response {
    http::Response::new(status, "application/json", body.into_bytes())
}

fn error_reply(e: &Error) -> http::Response {
    let status = match e.code {
        Code::Remote => 400,
        Code::Freshness if e.message.starts_with("too many requests") => 429,
        Code::KeyRelease if e.message.starts_with("no key for") => 404,
        _ => 403,
    };
    // A refusal tells the (unauthenticated) caller what its own evidence
    // shows, never what the asset's policy expects: the full reason goes
    // to the broker's own log.
    let message = match e.code {
        Code::WorkloadPolicy => {
            let public = public_denial(&e.message);
            if public != e.message {
                eprintln!("key broker: refused: {}: {}", e.code, e.message);
            }
            public
        }
        _ => e.message.clone(),
    };
    let body = serde_json::to_string(&ErrorBody {
        code: e.code.as_str().into(),
        message,
    })
    .unwrap_or_default();
    reply(status, body)
}

fn json<T: Serialize>(v: &T) -> Result<String, Error> {
    serde_json::to_string(v).map_err(|e| Error::new(Code::Remote, e.to_string()))
}

struct ServiceSignerRef(zeroize::Zeroizing<[u8; 32]>, String);

/// The control plane this broker accepts revocations from (pinned key).
pub struct ControlChannel {
    /// This broker's service ID (the messages' recipient).
    pub me: String,
    pub control_id: String,
    pub control_key: String,
    /// The one organization this broker serves: revocations for any other
    /// organization are refused.
    pub organization: String,
    /// Nonces seen, with their timestamps; pruned past the skew window
    /// (older requests are refused by their timestamp anyway).
    seen: Mutex<std::collections::HashMap<String, u64>>,
    /// Where to report key releases (the control plane's URL and this
    /// broker's signing key), for the audit trail.
    reporter: Option<(String, encompute_verification::ServiceSigner)>,
}

impl ControlChannel {
    pub fn new(me: &str, control_id: &str, control_key: &str, organization: &str) -> Self {
        Self {
            me: me.into(),
            control_id: control_id.into(),
            control_key: control_key.into(),
            organization: organization.into(),
            seen: Mutex::new(Default::default()),
            reporter: None,
        }
    }

    /// Reports every key release attempt (allowed or denied) to the
    /// control plane at `url`, signed by `signer`.
    pub fn with_reporter(
        mut self,
        url: &str,
        signer: encompute_verification::ServiceSigner,
    ) -> Self {
        self.reporter = Some((url.trim_end_matches('/').into(), signer));
        self
    }

    /// Best effort, off the request path: a release is never delayed or
    /// changed by reporting it. A governed release also names its
    /// authorization, job and (when granted) the broker's receipt.
    fn report_release(
        &self,
        asset: &str,
        allowed: bool,
        reason: Option<&str>,
        governed: Option<Governed<'_>>,
    ) {
        let Some((url, signer)) = &self.reporter else {
            return;
        };
        let mut payload = serde_json::json!({"asset": asset, "allowed": allowed, "reason": reason});
        if let Some(g) = governed {
            payload["authorization_id"] = g.authorization_id.into();
            payload["job_id"] = g.job_id.into();
            if let Some(r) = g.receipt {
                payload["receipt"] = serde_json::to_value(r).unwrap_or_default();
            }
        }
        let msg = encompute_verification::service::seal(
            signer,
            "key.release",
            &self.control_id,
            Default::default(),
            &payload,
            3600,
        );
        let Ok(m) = msg else { return };
        let (url, control, signer) = (
            url.clone(),
            self.control_id.clone(),
            ServiceSignerRef(signer.seed(), signer.id().to_owned()),
        );
        std::thread::spawn(move || {
            if let Ok(s) = encompute_verification::ServiceSigner::from_seed(&signer.1, &signer.0) {
                let agent = ureq::AgentBuilder::new()
                    .timeout(std::time::Duration::from_secs(10))
                    .redirects(0)
                    .build();
                let _ = encompute_verification::service::signed_call(
                    &agent,
                    &s,
                    &url,
                    &control,
                    "POST",
                    "/v1/messages",
                    &Default::default(),
                    &serde_json::to_value(&m).expect("serializable"),
                );
            }
        });
    }

    /// The organization a message names must be this broker's.
    fn for_me(&self, kind: &str, organization: Option<&str>) -> Result<(), Error> {
        if organization != Some(self.organization.as_str()) {
            return Err(Error::new(
                Code::ServiceAuthentication,
                format!(
                    "{kind} is for organization {organization:?}; this broker serves {:?}",
                    self.organization
                ),
            ));
        }
        Ok(())
    }

    /// Applies a signed message; revocations are idempotent.
    fn receive(
        &self,
        b: &mut KeyBroker,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<String, Error> {
        use encompute_verification::service::{now, open, MessageEnvelope, ServiceHeaders};
        let get = |n: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(n))
                .map(|(_, v)| v.clone())
        };
        let h = ServiceHeaders::from_lookup(get)?
            .ok_or_else(|| Error::new(Code::ServiceAuthentication, "unsigned message"))?;
        if h.sender != self.control_id {
            return Err(Error::new(
                Code::ServiceAuthentication,
                "messages come from the control plane only",
            ));
        }
        h.verify(
            &self.control_key,
            "POST",
            "/v1/messages",
            body,
            &self.me,
            now(),
        )?;
        {
            let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
            let t = now();
            let window = 2 * encompute_verification::service::MAX_CLOCK_SKEW_SECS;
            seen.retain(|_, at| t.saturating_sub(*at) <= window);
            if seen.insert(h.nonce.clone(), h.timestamp).is_some() {
                return Err(Error::new(Code::ServiceAuthentication, "replayed request"));
            }
        }
        let m: MessageEnvelope = serde_json::from_slice(body)
            .map_err(|e| Error::new(Code::BadInput, format!("message: {e}")))?;
        open(&m, &self.control_key, &self.me, now())?;
        match m.kind.as_str() {
            "asset.revoked" => {
                let asset = m.payload["key_ref"]
                    .as_str()
                    .ok_or_else(|| Error::new(Code::BadInput, "asset.revoked names no key"))?;
                // The organization is in the signed envelope: a revocation
                // for another organization's asset never destroys this
                // organization's keys, whatever key_ref it names.
                if m.organization.as_deref() != Some(self.organization.as_str()) {
                    return Err(Error::new(
                        Code::ServiceAuthentication,
                        format!(
                            "asset.revoked is for organization {:?}; this broker serves {:?}",
                            m.organization, self.organization
                        ),
                    ));
                }
                let revoked = match b.revoke_for(&self.organization, asset) {
                    Ok(v) => v,
                    // Not held here for this organization: nothing to revoke.
                    Err(e) if e.code == Code::KeyRelease => vec![],
                    Err(e) => return Err(e),
                };
                json(&serde_json::json!({"asset": asset, "revoked_versions": revoked}))
            }
            // Deny-only: the control plane cannot sign an owner's
            // revocation, but it may stop releases under an authorization
            // it revoked (anchored first). It never enables one.
            "authorization.revoked" => {
                self.for_me("authorization.revoked", m.organization.as_deref())?;
                let id = m.payload["authorization_id"].as_str().ok_or_else(|| {
                    Error::new(
                        Code::BadInput,
                        "authorization.revoked names no authorization",
                    )
                })?;
                let now = now();
                let at = m.payload["revoked_at"].as_u64().map_or(now, |t| t.min(now));
                // Only an authorization installed here is recorded: an
                // unknown ID is acknowledged and changes nothing.
                let revoked = b.revoke_authorization_from_control(id, at)?;
                json(&serde_json::json!({
                    "authorization_id": id,
                    "revoked": revoked,
                    "revoked_at": at
                }))
            }
            "asset.expired" => {
                self.for_me("asset.expired", m.organization.as_deref())?;
                let asset = m.payload["key_ref"]
                    .as_str()
                    .ok_or_else(|| Error::new(Code::BadInput, "asset.expired names no key"))?;
                let expired = match b.expire_for(&self.organization, asset) {
                    Ok(()) => true,
                    // Not held here for this organization: nothing to expire.
                    Err(e) if e.code == Code::KeyRelease => false,
                    Err(e) => return Err(e),
                };
                json(&serde_json::json!({"asset": asset, "expired": expired}))
            }
            other => Err(Error::new(
                Code::BadInput,
                format!("unknown message kind {other}"),
            )),
        }
    }
}

fn handle(broker: &Mutex<KeyBroker>, path: &str, body: &[u8]) -> Result<String, Error> {
    let bad = |m: String| Error::new(Code::Remote, m);
    let mut b = broker.lock().unwrap_or_else(|p| p.into_inner());
    match path {
        "/v1/challenge" => json(&b.challenge()?),
        "/v1/attest" => {
            let e = AttestationEvidence::from_bytes(body)?;
            json(&b.verify_attestation(&e)?)
        }
        "/v1/release" => {
            let r: ReleaseRequest = serde_json::from_slice(body)
                .map_err(|e| bad(format!("malformed release request: {e}")))?;
            json(&b.release_key(&r.session, &r.asset_id)?)
        }
        _ => Err(bad(format!("no such endpoint {path}"))),
    }
}

/// Serves `broker` until the process exits.
pub fn serve(broker: &Mutex<KeyBroker>, server: http::Server) {
    serve_with_limit(broker, server, REQUESTS_PER_MINUTE)
}

/// Serves `broker` with its own per-address request limit. Without a way
/// to persist its state, it refuses governed releases and authorization
/// changes (their counters, used tickets and revocations must survive a
/// restart): serve those with [`serve_with_control`].
pub fn serve_with_limit(broker: &Mutex<KeyBroker>, server: http::Server, per_minute: u32) {
    let h = Broker {
        broker,
        control: None,
        persist: None,
        limit: Mutex::new(RateLimit {
            per_minute,
            ..RateLimit::default()
        }),
    };
    server.serve(&h)
}

/// Serves `broker`, accepting revocations from `control`; `persist` saves
/// the broker's state after a revocation. Requests are read on the
/// server's connection threads, within its time and size limits, so a
/// slow client never holds the broker.
pub fn serve_with_control(
    broker: &Mutex<KeyBroker>,
    server: http::Server,
    per_minute: u32,
    control: Option<&ControlChannel>,
    persist: &(dyn Fn(&KeyBroker) -> Result<(), Error> + Sync),
) {
    let h = Broker {
        broker,
        control,
        persist: Some(persist),
        limit: Mutex::new(RateLimit {
            per_minute,
            ..RateLimit::default()
        }),
    };
    server.serve(&h)
}

struct Broker<'a> {
    broker: &'a Mutex<KeyBroker>,
    control: Option<&'a ControlChannel>,
    persist: Option<&'a Persist<'a>>,
    limit: Mutex<RateLimit>,
}

/// Saves the broker's state.
type Persist<'a> = dyn Fn(&KeyBroker) -> Result<(), Error> + Sync + 'a;

/// What a governed release report names.
struct Governed<'a> {
    authorization_id: &'a str,
    job_id: Option<&'a str>,
    receipt: Option<&'a KeyReleaseReceipt>,
}

impl<'a> Broker<'a> {
    fn persist(&self) -> Result<&'a Persist<'a>, Error> {
        self.persist.ok_or_else(|| {
            Error::new(
                Code::KeyRelease,
                "this broker does not persist its state; it makes no governed release and \
                 installs or revokes no authorization",
            )
        })
    }

    /// Prepare, persist, then seal: a release that was not persisted grants
    /// nothing. (A generation mark in the organization's KMS, advanced
    /// after the write and before sealing, fits between the two.)
    fn release_governed(&self, body: &[u8]) -> Result<String, Error> {
        let req: GovernedReleaseRequest = serde_json::from_slice(body)
            .map_err(|e| Error::new(Code::Remote, format!("malformed release request: {e}")))?;
        let persist = self.persist();
        let r = persist.and_then(|persist| {
            let mut b = self.broker.lock().unwrap_or_else(|p| p.into_inner());
            let pending = b.prepare_governed_release(&req)?;
            persist(&b)?;
            let (grant, receipt) = b.finish_release(pending)?;
            Ok(GovernedGrant { grant, receipt })
        });
        if let Some(c) = self.control {
            c.report_release(
                &req.asset_id,
                r.is_ok(),
                r.as_ref().err().map(|e| e.code.as_str()),
                Some(Governed {
                    authorization_id: &req.authorization_id,
                    job_id: req.ticket.as_ref().map(|t| t.job_id.as_str()),
                    receipt: r.as_ref().ok().map(|g| &g.receipt),
                }),
            );
        }
        json(&r?)
    }

    fn authorizations(&self, path: &str, body: &[u8]) -> Result<String, Error> {
        let bad = |e: serde_json::Error| Error::new(Code::Remote, format!("malformed body: {e}"));
        let persist = self.persist()?;
        let mut b = self.broker.lock().unwrap_or_else(|p| p.into_inner());
        if path == "/v1/authorizations" {
            let a: SignedAuthorizationV2 = serde_json::from_slice(body).map_err(bad)?;
            let id = b.install_authorization(&a)?;
            persist(&b)?;
            json(&serde_json::json!({ "authorization_id": id }))
        } else {
            let r: SignedRevocationV2 = serde_json::from_slice(body).map_err(bad)?;
            b.revoke_authorization_signed(&r)?;
            persist(&b)?;
            json(&serde_json::json!({ "authorization_id": r.body.authorization }))
        }
    }
}

impl http::Handler for Broker<'_> {
    fn body_limit(&self, _: &http::Request) -> usize {
        MAX_BODY as usize
    }

    fn handle(&self, req: http::Request) -> http::Response {
        if let Some(ip) = req.remote.map(|a| a.ip()) {
            let allowed = self
                .limit
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .allow(ip, encompute_attestation::unix_now());
            if !allowed {
                return error_reply(&Error::new(
                    Code::Freshness,
                    "too many requests; retry later",
                ));
            }
        }
        let path = req.path().to_owned();
        if req.method == "GET" && (path == "/live" || path == "/ready") {
            return reply(200, "{\"ok\":true}".into());
        }
        if req.method != "POST" {
            return error_reply(&Error::new(Code::Remote, "use POST"));
        }
        let body = &req.body;
        let out = if path == "/v1/messages" {
            match self.control {
                Some(c) => self.persist().and_then(|persist| {
                    let mut b = self.broker.lock().unwrap_or_else(|p| p.into_inner());
                    c.receive(&mut b, &req.headers, body)
                        .and_then(|r| persist(&b).map(|_| r))
                }),
                None => Err(Error::new(
                    Code::ServiceAuthentication,
                    "no control plane is configured",
                )),
            }
        } else if path == "/v1/release/governed" {
            self.release_governed(body)
        } else if path == "/v1/authorizations" || path == "/v1/authorizations/revoke" {
            self.authorizations(&path, body)
        } else {
            let r = handle(self.broker, &path, body);
            if path == "/v1/release" {
                if let (Some(c), Ok(req)) =
                    (self.control, serde_json::from_slice::<ReleaseRequest>(body))
                {
                    let reason = r.as_ref().err().map(|e| e.code.as_str());
                    c.report_release(&req.asset_id, r.is_ok(), reason, None);
                }
            }
            r
        };
        match out {
            Ok(json) => reply(200, json),
            Err(e) => error_reply(&e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_is_per_address_and_per_minute() {
        let mut r = RateLimit::default();
        let (a, b): (IpAddr, IpAddr) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
        for _ in 0..REQUESTS_PER_MINUTE {
            assert!(r.allow(a, 600));
        }
        assert!(!r.allow(a, 601));
        assert!(r.allow(b, 601));
        assert!(r.allow(a, 660));
    }
}
