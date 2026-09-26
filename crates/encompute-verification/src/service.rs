//! Service identity: every internal service (the control plane, each
//! evaluator, SecAgg coordinator and key broker, and automation clients)
//! holds its own Ed25519 key. Requests between services, asynchronous
//! messages, job grants and audit checkpoints are signed statements.
//!
//! Identity is the key, never a source IP, a hostname or a private network.
//! Transport security (TLS) is a separate, additional layer; these
//! signatures stay valid through proxies and message brokers, which are not
//! trusted for confidentiality or correctness.
//!
//! A signed request binds: the method and path, the sender and recipient
//! service IDs, a timestamp, a random nonce (the recipient refuses a nonce
//! twice), the SHA-256 of the body, and the security-relevant IDs the
//! request is about (organization, project, plan, job...).

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use encompute_ir::{Code, Error, Result};

use crate::canonical::canonical_json;
use crate::hash::{hex, tagged, unhex};

/// Domain of signed service requests.
pub const SERVICE_REQUEST: &str = "encompute.service-request.v1";
/// Domain of signed asynchronous messages.
pub const SERVICE_MESSAGE: &str = "encompute.service-message.v1";
/// Domain of job grants (control plane → evaluator).
pub const JOB_GRANT: &str = "encompute.job-grant.v1";
/// Domain of signed audit checkpoints.
pub const AUDIT_CHECKPOINT: &str = "encompute.audit-checkpoint.v1";
/// Domain of the control plane's state anchor (privacy and audit roots).
pub const STATE_ANCHOR: &str = "encompute.state-anchor.v1";

/// Requests older or newer than this are refused.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

fn auth(msg: impl Into<String>) -> Error {
    Error::new(Code::ServiceAuthentication, msg)
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Service IDs: 1–63 of `[a-z0-9-]`, e.g. `control-plane`, `evaluator-17`.
pub fn check_service_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 63
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(auth(format!(
            "service ID {id:?} must be 1-63 characters of a-z, 0-9 and -"
        )));
    }
    Ok(())
}

/// A service's signing key and ID.
pub struct ServiceSigner {
    id: String,
    key: SigningKey,
}

impl ServiceSigner {
    pub fn from_seed(id: &str, seed: &[u8; 32]) -> Result<Self> {
        check_service_id(id)?;
        Ok(Self {
            id: id.into(),
            key: SigningKey::from_bytes(seed),
        })
    }

    pub fn generate(id: &str) -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut()).map_err(|e| auth(format!("no randomness: {e}")))?;
        Self::from_seed(id, &seed)
    }

    /// Reads a 32-byte seed (raw, or 64 hex characters) from a secret file.
    pub fn from_file(id: &str, path: &std::path::Path) -> Result<Self> {
        let b = Zeroizing::new(
            std::fs::read(path).map_err(|e| auth(format!("{}: {e}", path.display())))?,
        );
        let seed: Zeroizing<Vec<u8>> = if b.len() == 32 {
            Zeroizing::new(b.to_vec())
        } else {
            let t = String::from_utf8_lossy(&b).trim().to_owned();
            Zeroizing::new(
                unhex(&t).ok_or_else(|| auth(format!("{}: not a 32-byte key", path.display())))?,
            )
        };
        let seed: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| auth(format!("{}: not a 32-byte key", path.display())))?;
        Self::from_seed(id, &seed)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_bytes())
    }

    pub fn public_key_hex(&self) -> String {
        hex(self.key.verifying_key().as_bytes())
    }

    /// Signs `SHA256(domain || 0 || canonical JSON of statement)`.
    pub fn sign<T: Serialize>(&self, domain: &str, statement: &T) -> Result<String> {
        let d = tagged(domain, &canonical_json(statement)?);
        Ok(hex(&self.key.sign(&d).to_bytes()))
    }

    /// Headers for a signed request to `recipient`.
    pub fn sign_request(
        &self,
        method: &str,
        path: &str,
        recipient: &str,
        bind: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<ServiceHeaders> {
        check_service_id(recipient)?;
        let mut n = [0u8; 16];
        getrandom::getrandom(&mut n).map_err(|e| auth(format!("no randomness: {e}")))?;
        let mut h = ServiceHeaders {
            sender: self.id.clone(),
            recipient: recipient.into(),
            timestamp: now(),
            nonce: hex(&n),
            bind: bind.clone(),
            signature: String::new(),
        };
        h.signature = self.sign(SERVICE_REQUEST, &h.statement(method, path, body))?;
        Ok(h)
    }
}

impl std::fmt::Debug for ServiceSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServiceSigner({})", self.id)
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Verifies `signature` (hex) by `public_key` (hex) over `statement`.
pub fn verify_signed<T: Serialize>(
    public_key: &str,
    domain: &str,
    statement: &T,
    signature: &str,
) -> Result<()> {
    let pk: [u8; 32] = unhex(public_key)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| auth("malformed service public key"))?;
    let pk = VerifyingKey::from_bytes(&pk).map_err(|_| auth("malformed service public key"))?;
    let sig = unhex(signature)
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or_else(|| auth("malformed service signature"))?;
    let d = tagged(domain, &canonical_json(statement)?);
    pk.verify_strict(&d, &sig)
        .map_err(|_| auth("the service signature is invalid"))
}

/// The authentication headers of a signed service request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceHeaders {
    pub sender: String,
    pub recipient: String,
    pub timestamp: u64,
    pub nonce: String,
    /// Security-relevant IDs the request is about. Covered by the
    /// signature and logged, but informational: recipients authorize from
    /// the signed method, path and body, never from these values.
    pub bind: BTreeMap<String, String>,
    pub signature: String,
}

#[derive(Serialize)]
struct RequestStatement<'a> {
    method: &'a str,
    path: &'a str,
    sender: &'a str,
    recipient: &'a str,
    timestamp: u64,
    nonce: &'a str,
    bind: &'a BTreeMap<String, String>,
    body_sha256: String,
}

pub const H_SENDER: &str = "Encompute-Sender";
pub const H_RECIPIENT: &str = "Encompute-Recipient";
pub const H_TIMESTAMP: &str = "Encompute-Timestamp";
pub const H_NONCE: &str = "Encompute-Nonce";
pub const H_BIND: &str = "Encompute-Bind";
pub const H_SIGNATURE: &str = "Encompute-Signature";

impl ServiceHeaders {
    fn statement<'a>(
        &'a self,
        method: &'a str,
        path: &'a str,
        body: &[u8],
    ) -> RequestStatement<'a> {
        RequestStatement {
            method,
            path,
            sender: &self.sender,
            recipient: &self.recipient,
            timestamp: self.timestamp,
            nonce: &self.nonce,
            bind: &self.bind,
            body_sha256: sha256_hex(body),
        }
    }

    /// `(header, value)` pairs to send.
    pub fn to_pairs(&self) -> Vec<(&'static str, String)> {
        vec![
            (H_SENDER, self.sender.clone()),
            (H_RECIPIENT, self.recipient.clone()),
            (H_TIMESTAMP, self.timestamp.to_string()),
            (H_NONCE, self.nonce.clone()),
            (
                H_BIND,
                serde_json::to_string(&self.bind).expect("serializable"),
            ),
            (H_SIGNATURE, self.signature.clone()),
        ]
    }

    /// Reads the headers; `None` if the request carries no signature at all.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>> {
        let Some(signature) = get(H_SIGNATURE) else {
            return Ok(None);
        };
        let need = |h: &str| get(h).ok_or_else(|| auth(format!("missing {h} header")));
        let bind = match get(H_BIND) {
            Some(b) if !b.is_empty() => {
                serde_json::from_str(&b).map_err(|_| auth(format!("malformed {H_BIND} header")))?
            }
            _ => BTreeMap::new(),
        };
        Ok(Some(Self {
            sender: need(H_SENDER)?,
            recipient: need(H_RECIPIENT)?,
            timestamp: need(H_TIMESTAMP)?
                .parse()
                .map_err(|_| auth(format!("malformed {H_TIMESTAMP} header")))?,
            nonce: need(H_NONCE)?,
            bind,
            signature,
        }))
    }

    /// Checks the signature by `public_key`, that this service is the
    /// recipient, and the timestamp. The caller must also refuse a nonce it
    /// has seen (within the skew window).
    pub fn verify(
        &self,
        public_key: &str,
        method: &str,
        path: &str,
        body: &[u8],
        me: &str,
        now: u64,
    ) -> Result<()> {
        if self.recipient != me {
            return Err(auth(format!(
                "the request is addressed to {}, not {me}",
                self.recipient
            )));
        }
        if self.timestamp.abs_diff(now) > MAX_CLOCK_SKEW_SECS {
            return Err(auth("the request is expired or from the future"));
        }
        if self.nonce.len() != 32 || unhex(&self.nonce).is_none() {
            return Err(auth("malformed request nonce"));
        }
        verify_signed(
            public_key,
            SERVICE_REQUEST,
            &self.statement(method, path, body),
            &self.signature,
        )
    }
}

// --- job grants and messages (shared by the control plane and services) ------

/// A job grant: the control plane's signed authorization for one evaluator
/// to run one job's program, before it expires. The evaluator also asks the
/// control plane to start the job (a revoked or cancelled job never starts).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobGrant {
    pub version: u32,
    pub job_id: String,
    pub organization: String,
    pub project: String,
    pub plan_id: String,
    pub spec_id: String,
    pub program_id: String,
    pub evaluator: String,
    pub backend: String,
    pub profile: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub issuer: String,
    pub issuer_public_key: String,
    #[serde(default)]
    pub signature: String,
}

pub const JOB_GRANT_VERSION: u32 = 1;
/// A grant is usable for this long after scheduling.
pub const JOB_GRANT_TTL_SECS: u64 = 3600;
/// The HTTP header carrying a grant (hex of its JSON).
pub const H_JOB_GRANT: &str = "Encompute-Job-Grant";

impl JobGrant {
    /// The signed part (everything but the signature).
    pub fn unsigned(&self) -> JobGrant {
        JobGrant {
            signature: String::new(),
            ..self.clone()
        }
    }

    /// Checks the grant was signed by `control_key` (pinned), names
    /// `evaluator` and `program_id`, and has not expired.
    pub fn verify(
        &self,
        control_key: &str,
        evaluator: &str,
        program_id: &str,
        now: u64,
    ) -> Result<()> {
        if self.version != JOB_GRANT_VERSION {
            return Err(auth(format!("job grant version {}", self.version)));
        }
        if self.issuer_public_key != control_key {
            return Err(auth(
                "the job grant was not issued by the pinned control plane",
            ));
        }
        verify_signed(control_key, JOB_GRANT, &self.unsigned(), &self.signature)?;
        if self.evaluator != evaluator {
            return Err(auth(format!(
                "the job grant is for evaluator {}",
                self.evaluator
            )));
        }
        if self.program_id != program_id {
            return Err(auth("the job grant is for another program"));
        }
        if now > self.expires_at {
            return Err(auth("the job grant expired"));
        }
        Ok(())
    }

    pub fn to_header(&self) -> String {
        hex(&serde_json::to_vec(self).expect("serializable"))
    }

    pub fn from_header(h: &str) -> Result<Self> {
        let b = unhex(h.trim()).ok_or_else(|| auth("malformed job grant header"))?;
        serde_json::from_slice(&b).map_err(|e| auth(format!("malformed job grant: {e}")))
    }
}

/// An asynchronous message between services. Large payloads travel as a
/// URI and digest, never inline.
#[derive(Clone, Debug, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageEnvelope {
    pub protocol_version: u32,
    pub message_id: String,
    pub kind: String,
    pub sender: String,
    pub recipient: String,
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub job: Option<String>,
    #[serde(default)]
    pub round: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub payload_digest: String,
    pub payload: serde_json::Value,
    /// Over every field above but the payload itself (bound by digest).
    pub signature: String,
}

pub const MESSAGE_PROTOCOL: u32 = 1;
/// Largest inline payload; bigger data goes by URI and digest.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Serialize)]
pub struct MessageStatement<'a> {
    pub protocol_version: u32,
    pub message_id: &'a str,
    pub kind: &'a str,
    pub sender: &'a str,
    pub recipient: &'a str,
    pub organization: &'a Option<String>,
    pub project: &'a Option<String>,
    pub job: &'a Option<String>,
    pub round: &'a Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub payload_digest: &'a str,
}

impl MessageEnvelope {
    pub fn statement(&self) -> MessageStatement<'_> {
        MessageStatement {
            protocol_version: self.protocol_version,
            message_id: &self.message_id,
            kind: &self.kind,
            sender: &self.sender,
            recipient: &self.recipient,
            organization: &self.organization,
            project: &self.project,
            job: &self.job,
            round: &self.round,
            created_at: self.created_at,
            expires_at: self.expires_at,
            payload_digest: &self.payload_digest,
        }
    }
}

/// What a message is about.
#[derive(Clone, Debug, Default)]
pub struct Scope {
    pub organization: Option<String>,
    pub project: Option<String>,
    pub job: Option<String>,
    pub round: Option<String>,
}

/// Builds and signs a message.
pub fn seal<T: Serialize>(
    signer: &ServiceSigner,
    kind: &str,
    recipient: &str,
    scope: Scope,
    payload: &T,
    ttl_secs: u64,
) -> Result<MessageEnvelope> {
    let payload = serde_json::to_value(payload).map_err(|e| auth(format!("payload: {e}")))?;
    let bytes = canonical_json(&payload)?;
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(auth(
            "message payload too large: send large data by URI and digest",
        ));
    }
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|e| auth(format!("no randomness: {e}")))?;
    let t = now();
    let mut m = MessageEnvelope {
        protocol_version: MESSAGE_PROTOCOL,
        message_id: format!("msg_{}", hex(&id)),
        kind: kind.into(),
        sender: signer.id().into(),
        recipient: recipient.into(),
        organization: scope.organization,
        project: scope.project,
        job: scope.job,
        round: scope.round,
        created_at: t,
        expires_at: t + ttl_secs,
        payload_digest: sha256_hex(&bytes),
        payload,
        signature: String::new(),
    };
    m.signature = signer.sign(SERVICE_MESSAGE, &m.statement())?;
    Ok(m)
}

/// Checks a received message: version, recipient, expiry, payload digest and
/// the signature by `sender_public_key`. Idempotency is the consumer's job.
pub fn open(m: &MessageEnvelope, sender_public_key: &str, me: &str, now: u64) -> Result<()> {
    if m.protocol_version != MESSAGE_PROTOCOL {
        return Err(auth(format!("message protocol {}", m.protocol_version)));
    }
    if m.recipient != me {
        return Err(auth(format!(
            "message addressed to {}, not {me}",
            m.recipient
        )));
    }
    if now > m.expires_at {
        return Err(auth("expired message"));
    }
    if m.created_at > now + MAX_CLOCK_SKEW_SECS {
        return Err(auth("message from the future"));
    }
    if sha256_hex(&canonical_json(&m.payload)?) != m.payload_digest {
        return Err(auth("message payload does not match its digest"));
    }
    verify_signed(
        sender_public_key,
        SERVICE_MESSAGE,
        &m.statement(),
        &m.signature,
    )
}

/// Sends a signed request with a JSON body to another service; returns the
/// JSON reply (or the peer's error code and message).
#[allow(clippy::too_many_arguments)]
pub fn signed_call(
    agent: &ureq::Agent,
    signer: &ServiceSigner,
    base_url: &str,
    recipient: &str,
    method: &str,
    path: &str,
    bind: &BTreeMap<String, String>,
    body: &serde_json::Value,
) -> Result<serde_json::Value> {
    let bytes = if body.is_null() {
        vec![]
    } else {
        serde_json::to_vec(body).expect("serializable")
    };
    let h = signer.sign_request(method, path, recipient, bind, &bytes)?;
    let mut r = agent
        .request(method, &format!("{}{path}", base_url.trim_end_matches('/')))
        .set("Content-Type", "application/json");
    for (k, v) in h.to_pairs() {
        r = r.set(k, &v);
    }
    let resp = if bytes.is_empty() {
        r.call()
    } else {
        r.send_bytes(&bytes)
    };
    match resp {
        Ok(r) => r
            .into_json()
            .map_err(|e| Error::new(Code::Remote, format!("{base_url}: {e}"))),
        Err(ureq::Error::Status(status, r)) => {
            let v: serde_json::Value = r.into_json().unwrap_or(serde_json::Value::Null);
            let code = v["code"]
                .as_str()
                .and_then(Code::parse)
                .unwrap_or(Code::Remote);
            Err(Error::new(
                code,
                format!(
                    "{recipient} refused ({status}): {}",
                    v["message"].as_str().unwrap_or("")
                ),
            ))
        }
        Err(e) => Err(Error::new(
            Code::Remote,
            format!("cannot reach {recipient}: {e}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_requests_bind_everything() {
        let s = ServiceSigner::from_seed("evaluator-17", &[3; 32]).unwrap();
        let pk = s.public_key_hex();
        let bind: BTreeMap<String, String> = [("job".to_owned(), "job_1".to_owned())].into();
        let h = s
            .sign_request("POST", "/v1/messages", "control-plane", &bind, b"{}")
            .unwrap();
        let t = h.timestamp;
        h.verify(&pk, "POST", "/v1/messages", b"{}", "control-plane", t)
            .unwrap();
        let bad = |h: &ServiceHeaders, m: &str, p: &str, b: &[u8], me: &str, now: u64| {
            assert_eq!(
                h.verify(&pk, m, p, b, me, now).unwrap_err().code,
                Code::ServiceAuthentication
            )
        };
        bad(&h, "GET", "/v1/messages", b"{}", "control-plane", t);
        bad(&h, "POST", "/v1/jobs", b"{}", "control-plane", t);
        bad(&h, "POST", "/v1/messages", b"{ }", "control-plane", t);
        bad(&h, "POST", "/v1/messages", b"{}", "keybroker-a", t);
        bad(&h, "POST", "/v1/messages", b"{}", "control-plane", t + 301);
        let mut other = h.clone();
        other.bind.insert("job".into(), "job_2".into());
        bad(&other, "POST", "/v1/messages", b"{}", "control-plane", t);
        let mut other = h.clone();
        other.sender = "evaluator-18".into();
        bad(&other, "POST", "/v1/messages", b"{}", "control-plane", t);
        // Another service's key.
        let o = ServiceSigner::from_seed("evaluator-17", &[4; 32]).unwrap();
        assert!(h
            .verify(
                &o.public_key_hex(),
                "POST",
                "/v1/messages",
                b"{}",
                "control-plane",
                t
            )
            .is_err());
        // Header round trip.
        let pairs = h.to_pairs();
        let get = |n: &str| pairs.iter().find(|(k, _)| *k == n).map(|(_, v)| v.clone());
        assert_eq!(ServiceHeaders::from_lookup(get).unwrap().unwrap(), h);
        assert_eq!(ServiceHeaders::from_lookup(|_| None).unwrap(), None);
        assert!(check_service_id("Evaluator 1").is_err());
    }

    #[test]
    fn job_grants_bind_issuer_evaluator_program_and_expiry() {
        let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
        let mut g = JobGrant {
            version: JOB_GRANT_VERSION,
            job_id: "job_1".into(),
            organization: "modelco".into(),
            project: "prj_1".into(),
            plan_id: "pln_1".into(),
            spec_id: "s".repeat(64),
            program_id: "p".repeat(64),
            evaluator: "evaluator-1".into(),
            backend: "openfhe-exact".into(),
            profile: "BINFHE_STD128_GINX_BITS_V1".into(),
            issued_at: 1000,
            expires_at: 2000,
            issuer: "control-plane".into(),
            issuer_public_key: control.public_key_hex(),
            signature: String::new(),
        };
        g.signature = control.sign(JOB_GRANT, &g.unsigned()).unwrap();
        let pk = control.public_key_hex();
        let p = "p".repeat(64);
        g.verify(&pk, "evaluator-1", &p, 1500).unwrap();
        let g2 = JobGrant::from_header(&g.to_header()).unwrap();
        assert_eq!(g2, g);
        let refused = |r: Result<()>| assert_eq!(r.unwrap_err().code, Code::ServiceAuthentication);
        refused(g.verify(&pk, "evaluator-2", &p, 1500));
        refused(g.verify(&pk, "evaluator-1", &"q".repeat(64), 1500));
        refused(g.verify(&pk, "evaluator-1", &p, 2001));
        let other = ServiceSigner::from_seed("control-plane", &[6; 32]).unwrap();
        refused(g.verify(&other.public_key_hex(), "evaluator-1", &p, 1500));
        // Edited fields invalidate the signature.
        let mut e = g.clone();
        e.expires_at = 9999;
        refused(e.verify(&pk, "evaluator-1", &p, 1500));
        let mut e = g.clone();
        e.backend = "tfhe-rs".into();
        refused(e.verify(&pk, "evaluator-1", &p, 1500));
        // A grant re-signed by another key but claiming the pinned one.
        let mut f = g.clone();
        f.expires_at = 9999;
        f.signature = other.sign(JOB_GRANT, &f.unsigned()).unwrap();
        refused(f.verify(&pk, "evaluator-1", &p, 1500));
    }
}
