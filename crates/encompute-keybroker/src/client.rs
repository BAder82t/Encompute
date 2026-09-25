use std::time::Duration;

use serde::de::DeserializeOwned;

use encompute_attestation::{AttestationChallenge, AttestationEvidence, EncryptedKeyGrant};
use encompute_ir::{Code, Error, Result};

use crate::server::{ErrorBody, ReleaseRequest};
use crate::SessionInfo;

/// A key broker over HTTP.
#[derive(Clone, Debug)]
pub struct BrokerClient {
    url: String,
    agent: ureq::Agent,
}

impl BrokerClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.trim_end_matches('/').to_owned(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn post<T: DeserializeOwned>(&self, path: &str, body: &[u8]) -> Result<T> {
        let remote = |m: String| Error::new(Code::Remote, m);
        let r = self
            .agent
            .post(&format!("{}{path}", self.url))
            .set("Content-Type", "application/json")
            .send_bytes(body);
        let resp = match r {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => {
                let e: ErrorBody = r
                    .into_json()
                    .map_err(|e| remote(format!("broker error body: {e}")))?;
                let code = Code::parse(&e.code).unwrap_or(Code::Remote);
                return Err(Error::new(code, format!("broker: {}", e.message)));
            }
            Err(e) => return Err(remote(format!("{}: {e}", self.url))),
        };
        resp.into_json()
            .map_err(|e| remote(format!("malformed broker reply: {e}")))
    }

    pub fn challenge(&self) -> Result<AttestationChallenge> {
        self.post("/v1/challenge", b"{}")
    }

    pub fn attest(&self, evidence: &AttestationEvidence) -> Result<SessionInfo> {
        self.post("/v1/attest", &evidence.to_bytes()?)
    }

    pub fn release(&self, session: &str, asset_id: &str) -> Result<EncryptedKeyGrant> {
        let body = serde_json::to_vec(&ReleaseRequest {
            session: session.to_owned(),
            asset_id: asset_id.to_owned(),
        })
        .map_err(|e| Error::new(Code::Remote, e.to_string()))?;
        self.post("/v1/release", &body)
    }
}
