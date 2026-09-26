//! The broker over HTTP (JSON):
//!
//! - `POST /v1/challenge` → [`AttestationChallenge`](encompute_attestation::AttestationChallenge)
//! - `POST /v1/attest` (evidence) → [`SessionInfo`](crate::SessionInfo)
//! - `POST /v1/release` (`{"session", "asset_id"}`) → [`EncryptedKeyGrant`](encompute_attestation::EncryptedKeyGrant)
//!
//! There is no endpoint that returns a key in the clear, and none that
//! manages keys: owners manage them offline with the CLI.

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
        if *req.method() != tiny_http::Method::Post {
            error_reply(req, &Error::new(Code::Remote, "use POST"));
            continue;
        }
        let path = req.url().split('?').next().unwrap_or("").to_owned();
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
        match handle(broker, &path, &body) {
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
