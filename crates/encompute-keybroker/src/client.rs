use std::collections::BTreeMap;
use std::time::Duration;

use serde::de::DeserializeOwned;

use encompute_attestation::{AttestationChallenge, AttestationEvidence, EncryptedKeyGrant};
use encompute_ir::{Code, Error, Result};

use encompute_trust::authz::{SignedAuthorizationV2, SignedRevocationV2};

use crate::server::{ErrorBody, ReleaseRequest};
use crate::{GovernedGrant, GovernedReleaseRequest, SessionInfo};

/// Trusted broker keys: a non-empty map of 64 lowercase hex characters.
fn check_trusted(trusted: &BTreeMap<String, String>) -> Result<()> {
    let hex64 = |k: &str| {
        k.len() == 64
            && k.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if trusted.is_empty() || trusted.values().any(|k| !hex64(k)) {
        return Err(Error::new(
            Code::BadInput,
            "trusted broker keys must be a non-empty map of 64 lowercase hex characters",
        ));
    }
    Ok(())
}

/// A key broker over HTTP.
#[derive(Clone, Debug)]
pub struct BrokerClient {
    url: String,
    agent: ureq::Agent,
    /// The broker's grant-signing key (hex), if pinned.
    pinned_key: Option<String>,
    /// Broker ID -> grant-signing key (hex) the workload's attested
    /// identity names: grants from any other signer are refused.
    trusted: Option<BTreeMap<String, String>>,
    /// Asset or key ID -> the broker ID that holds its key (the attested
    /// identity's per-asset binding): a key's grant is accepted only from
    /// that broker, and a key it leaves out is not asked for.
    asset_brokers: Option<BTreeMap<String, String>>,
}

impl BrokerClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.trim_end_matches('/').to_owned(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
            pinned_key: None,
            trusted: None,
            asset_brokers: None,
        }
    }

    /// `URL` or `URL#KEY`: KEY pins the broker's grant-signing key (hex
    /// Ed25519, as `keys serve` prints it).
    pub fn parse(spec: &str) -> Result<Self> {
        match spec.split_once('#') {
            None => Ok(Self::new(spec)),
            Some((url, key)) => Self::new(url).with_pinned_key(key),
        }
    }

    /// Accepts grants only signed by `key` (hex Ed25519).
    pub fn with_pinned_key(mut self, key: &str) -> Result<Self> {
        let ok = key.len() == 64
            && key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err(Error::new(
                Code::BadInput,
                format!("broker key {key:?} is not 64 lowercase hex characters"),
            ));
        }
        self.pinned_key = Some(key.to_owned());
        Ok(self)
    }

    /// Accepts grants only from a broker `trusted` names (broker ID ->
    /// hex Ed25519 grant-signing key), taken from the workload's attested
    /// identity (a training spec), never from whoever supplies the URL.
    ///
    /// One broker only: trusted for every key, a second broker could grant
    /// a key of its choosing for the first one's assets. Several brokers
    /// need a per-asset binding ([`Self::trusting_per_asset`]).
    pub fn trusting(mut self, trusted: &BTreeMap<String, String>) -> Result<Self> {
        check_trusted(trusted)?;
        if trusted.len() != 1 {
            return Err(Error::new(
                Code::KeyRelease,
                "several trusted brokers need a per-asset broker binding: each would otherwise \
                 be trusted for every key",
            ));
        }
        self.trusted = Some(trusted.clone());
        Ok(self)
    }

    /// Accepts a grant for a key only from the broker `asset_brokers` binds
    /// it to (asset or key ID -> broker ID), signed by that broker's key in
    /// `trusted`; both come from the workload's attested identity. A key
    /// the binding leaves out is refused before it is asked for.
    pub fn trusting_per_asset(
        mut self,
        trusted: &BTreeMap<String, String>,
        asset_brokers: &BTreeMap<String, String>,
    ) -> Result<Self> {
        check_trusted(trusted)?;
        if asset_brokers.is_empty() {
            return Err(Error::new(
                Code::BadInput,
                "a per-asset broker binding binds at least one key",
            ));
        }
        if let Some((key, broker)) = asset_brokers
            .iter()
            .find(|(_, b)| !trusted.contains_key(*b))
        {
            return Err(Error::new(
                Code::KeyRelease,
                format!(
                    "the per-asset binding binds {key} to {broker}, whose grant-signing key is \
                     not pinned"
                ),
            ));
        }
        self.trusted = Some(trusted.clone());
        self.asset_brokers = Some(asset_brokers.clone());
        Ok(self)
    }

    pub fn trusted_brokers(&self) -> Option<&BTreeMap<String, String>> {
        self.trusted.as_ref()
    }

    /// The per-asset broker binding, if the workload has one.
    pub fn asset_brokers(&self) -> Option<&BTreeMap<String, String>> {
        self.asset_brokers.as_ref()
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn pinned_key(&self) -> Option<&str> {
        self.pinned_key.as_deref()
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

    /// A governed release: the key under the owner's authorization, with
    /// the control plane's ticket; returns the grant and the broker's
    /// key-release receipt.
    pub fn release_governed(&self, req: &GovernedReleaseRequest) -> Result<GovernedGrant> {
        let body = serde_json::to_vec(req).map_err(|e| Error::new(Code::Remote, e.to_string()))?;
        self.post("/v1/release/governed", &body)
    }

    /// Installs an owner authorization (verified by the broker under the
    /// owner's pinned governance key); returns its ID.
    pub fn install_authorization(&self, a: &SignedAuthorizationV2) -> Result<String> {
        let body = serde_json::to_vec(a).map_err(|e| Error::new(Code::Remote, e.to_string()))?;
        let r: serde_json::Value = self.post("/v1/authorizations", &body)?;
        r["authorization_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::new(Code::Remote, "malformed broker reply"))
    }

    /// Delivers the owner's signed revocation of an authorization.
    pub fn revoke_authorization(&self, r: &SignedRevocationV2) -> Result<()> {
        let body = serde_json::to_vec(r).map_err(|e| Error::new(Code::Remote, e.to_string()))?;
        let _: serde_json::Value = self.post("/v1/authorizations/revoke", &body)?;
        Ok(())
    }
}
