//! The broker over HTTP (JSON):
//!
//! - `POST /v1/challenge` → [`AttestationChallenge`](encompute_attestation::AttestationChallenge)
//! - `POST /v1/attest` (evidence) → [`SessionInfo`](crate::SessionInfo)
//! - `POST /v1/release` (`{"session", "asset_id"}`) → [`EncryptedKeyGrant`](encompute_attestation::EncryptedKeyGrant)
//!
//! - `POST /v1/messages`: signed messages from the pinned control plane
//!   (`asset.revoked`: every version of the asset's key is destroyed)
//! - `GET /live`, `GET /ready`
//!
//! There is no endpoint that returns a key in the clear, and none that
//! manages keys: owners manage them offline with the CLI. The control plane
//! can only revoke.

use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use encompute_attestation::AttestationEvidence;
use encompute_ir::{Code, Error};

use crate::KeyBroker;

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

fn reply(req: tiny_http::Request, status: u16, body: String) {
    let h = tiny_http::Header::from_bytes("Content-Type", "application/json").expect("header");
    let _ = req.respond(
        tiny_http::Response::from_string(body)
            .with_status_code(status)
            .with_header(h),
    );
}

fn error_reply(req: tiny_http::Request, e: &Error) {
    let status = match e.code {
        Code::Remote => 400,
        Code::Freshness if e.message.starts_with("too many requests") => 429,
        Code::KeyRelease if e.message.starts_with("no key for") => 404,
        _ => 403,
    };
    let body = serde_json::to_string(&ErrorBody {
        code: e.code.as_str().into(),
        message: e.message.clone(),
    })
    .unwrap_or_default();
    reply(req, status, body);
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
    /// Nonces seen, with their timestamps; pruned past the skew window
    /// (older requests are refused by their timestamp anyway).
    seen: Mutex<std::collections::HashMap<String, u64>>,
    /// Where to report key releases (the control plane's URL and this
    /// broker's signing key), for the audit trail.
    reporter: Option<(String, encompute_verification::ServiceSigner)>,
}

impl ControlChannel {
    pub fn new(me: &str, control_id: &str, control_key: &str) -> Self {
        Self {
            me: me.into(),
            control_id: control_id.into(),
            control_key: control_key.into(),
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
    /// changed by reporting it.
    fn report_release(&self, asset: &str, allowed: bool, reason: Option<&str>) {
        let Some((url, signer)) = &self.reporter else {
            return;
        };
        let msg = encompute_verification::service::seal(
            signer,
            "key.release",
            &self.control_id,
            Default::default(),
            &serde_json::json!({"asset": asset, "allowed": allowed, "reason": reason}),
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
                let revoked = match b.revoke_all(asset) {
                    Ok(v) => v,
                    // Not held here: nothing to release, nothing to revoke.
                    Err(e) if e.code == Code::KeyRelease => vec![],
                    Err(e) => return Err(e),
                };
                json(&serde_json::json!({"asset": asset, "revoked_versions": revoked}))
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

/// Serves `broker` until the server is dropped.
pub fn serve(broker: &Mutex<KeyBroker>, server: &tiny_http::Server) {
    serve_with_limit(broker, server, REQUESTS_PER_MINUTE)
}

/// Serves `broker` with its own per-address request limit.
pub fn serve_with_limit(broker: &Mutex<KeyBroker>, server: &tiny_http::Server, per_minute: u32) {
    serve_with_control(broker, server, per_minute, None, &|_| Ok(()))
}

/// Serves `broker`, accepting revocations from `control`; `persist` saves
/// the broker's state after a revocation.
pub fn serve_with_control(
    broker: &Mutex<KeyBroker>,
    server: &tiny_http::Server,
    per_minute: u32,
    control: Option<&ControlChannel>,
    persist: &dyn Fn(&KeyBroker) -> Result<(), Error>,
) {
    let mut limit = RateLimit {
        per_minute,
        ..RateLimit::default()
    };
    for mut req in server.incoming_requests() {
        if let Some(ip) = req.remote_addr().map(|a| a.ip()) {
            if !limit.allow(ip, encompute_attestation::unix_now()) {
                error_reply(
                    req,
                    &Error::new(Code::Freshness, "too many requests; retry later"),
                );
                continue;
            }
        }
        let path = req.url().split('?').next().unwrap_or("").to_owned();
        if *req.method() == tiny_http::Method::Get && (path == "/live" || path == "/ready") {
            reply(req, 200, "{\"ok\":true}".into());
            continue;
        }
        if *req.method() != tiny_http::Method::Post {
            error_reply(req, &Error::new(Code::Remote, "use POST"));
            continue;
        }
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|h| {
                (
                    h.field.as_str().as_str().to_owned(),
                    h.value.as_str().to_owned(),
                )
            })
            .collect();
        let mut body = Vec::new();
        if req
            .as_reader()
            .take(MAX_BODY + 1)
            .read_to_end(&mut body)
            .is_err()
            || body.len() as u64 > MAX_BODY
        {
            error_reply(req, &Error::new(Code::Remote, "request body too large"));
            continue;
        }
        let out = if path == "/v1/messages" {
            match control {
                Some(c) => {
                    let mut b = broker.lock().unwrap_or_else(|p| p.into_inner());
                    c.receive(&mut b, &headers, &body)
                        .and_then(|r| persist(&b).map(|_| r))
                }
                None => Err(Error::new(
                    Code::ServiceAuthentication,
                    "no control plane is configured",
                )),
            }
        } else {
            let r = handle(broker, &path, &body);
            if path == "/v1/release" {
                if let (Some(c), Ok(req)) =
                    (control, serde_json::from_slice::<ReleaseRequest>(&body))
                {
                    let reason = r.as_ref().err().map(|e| e.code.as_str());
                    c.report_release(&req.asset_id, r.is_ok(), reason);
                }
            }
            r
        };
        match out {
            Ok(json) => reply(req, 200, json),
            Err(e) => error_reply(req, &e),
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
