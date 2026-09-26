//! The audit trail: append-only, hash-chained events, with signed
//! checkpoints of the chain's root (anchored outside the database).
//!
//! Every security-sensitive state transition writes one event in the same
//! transaction as the change it records. Events carry identifiers only:
//! never keys, plaintext data, model weights or gradients (`refs` values are
//! checked to be identifiers or digests).

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use postgres::GenericClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::hex;
use encompute_verification::service::{verify_signed, ServiceSigner, AUDIT_CHECKPOINT};

use crate::db::db_err;

pub const GENESIS: &str = "genesis";
const EVENT_DOMAIN: &[u8] = b"encompute.audit-event.v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    Denied,
    Succeeded,
    Failed,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Allowed => "allowed",
            Outcome::Denied => "denied",
            Outcome::Succeeded => "succeeded",
            Outcome::Failed => "failed",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "allowed" => Outcome::Allowed,
            "denied" => Outcome::Denied,
            "succeeded" => Outcome::Succeeded,
            "failed" => Outcome::Failed,
            _ => return Err(Error::new(Code::Artifact, format!("audit outcome {s:?}"))),
        })
    }
}

/// An event to record.
#[derive(Clone, Debug)]
pub struct AuditDraft {
    pub organization: Option<String>,
    pub actor: String,
    pub action: &'static str,
    pub resource_type: &'static str,
    pub resource_id: String,
    pub project: Option<String>,
    pub result: Outcome,
    pub request_id: String,
    /// Related IDs (plan, policy, spec, key version...): identifiers only.
    pub refs: BTreeMap<String, String>,
}

impl AuditDraft {
    pub fn new(
        actor: &str,
        request_id: &str,
        action: &'static str,
        resource_type: &'static str,
        resource_id: &str,
        result: Outcome,
    ) -> Self {
        Self {
            organization: None,
            actor: actor.into(),
            action,
            resource_type,
            resource_id: resource_id.into(),
            project: None,
            result,
            request_id: request_id.into(),
            refs: BTreeMap::new(),
        }
    }

    pub fn org(mut self, org: &str) -> Self {
        self.organization = Some(org.into());
        self
    }

    pub fn project(mut self, p: &str) -> Self {
        self.project = Some(p.into());
        self
    }

    pub fn r#ref(mut self, k: &str, v: impl Into<String>) -> Self {
        self.refs.insert(k.into(), v.into());
        self
    }
}

/// A recorded event, as it is hashed and served.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub seq: i64,
    pub event_id: String,
    /// Unix time in microseconds.
    pub at_us: i64,
    pub organization: Option<String>,
    pub actor: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub project: Option<String>,
    pub result: Outcome,
    pub request_id: String,
    pub refs: BTreeMap<String, String>,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditEvent {
    fn compute_hash(&self) -> Result<String> {
        let mut e = self.clone();
        e.hash = String::new();
        let mut h = Sha256::new();
        h.update(EVENT_DOMAIN);
        h.update(canonical_json(&e)?);
        Ok(hex(&h.finalize()))
    }
}

/// Identifiers and digests only: a value that could be a payload is refused.
fn check_ref_value(k: &str, v: &str) -> Result<()> {
    let ok = v.len() <= 256
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/@+".contains(&b));
    if !ok {
        return Err(Error::new(
            Code::BadInput,
            format!("audit reference {k} must be an identifier or digest"),
        ));
    }
    Ok(())
}

fn to_system_time(us: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(us.max(0) as u64)
}

fn from_system_time(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// Appends `draft` to the chain inside the caller's transaction. The chain
/// head row is locked, so concurrent appends serialize.
pub fn append(t: &mut impl GenericClient, draft: AuditDraft) -> Result<AuditEvent> {
    for (k, v) in &draft.refs {
        check_ref_value(k, v)?;
    }
    check_ref_value("resource_id", &draft.resource_id)?;
    let head = t
        .query_one("SELECT seq, hash FROM audit_head WHERE id FOR UPDATE", &[])
        .map_err(db_err)?;
    let seq: i64 = head.get::<_, i64>(0) + 1;
    let prev_hash: String = head.get(1);
    let at_us = from_system_time(SystemTime::now());
    let mut e = AuditEvent {
        seq,
        event_id: crate::model::new_id("evt"),
        at_us,
        organization: draft.organization,
        actor: draft.actor,
        action: draft.action.into(),
        resource_type: draft.resource_type.into(),
        resource_id: draft.resource_id,
        project: draft.project,
        result: draft.result,
        request_id: draft.request_id,
        refs: draft.refs,
        prev_hash,
        hash: String::new(),
    };
    e.hash = e.compute_hash()?;
    t.execute(
        "INSERT INTO audit_events (seq, event_id, at, organization_id, actor, action,
             resource_type, resource_id, project_id, result, request_id, refs, prev_hash, hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        &[
            &e.seq,
            &e.event_id,
            &to_system_time(e.at_us),
            &e.organization,
            &e.actor,
            &e.action,
            &e.resource_type,
            &e.resource_id,
            &e.project,
            &e.result.as_str(),
            &e.request_id,
            &serde_json::to_value(&e.refs).expect("serializable"),
            &e.prev_hash,
            &e.hash,
        ],
    )
    .map_err(db_err)?;
    t.execute(
        "UPDATE audit_head SET seq = $1, hash = $2 WHERE id",
        &[&e.seq, &e.hash],
    )
    .map_err(db_err)?;
    Ok(e)
}

fn row_to_event(r: &postgres::Row) -> Result<AuditEvent> {
    let at: SystemTime = r.get("at");
    Ok(AuditEvent {
        seq: r.get("seq"),
        event_id: r.get("event_id"),
        at_us: from_system_time(at),
        organization: r.get("organization_id"),
        actor: r.get("actor"),
        action: r.get("action"),
        resource_type: r.get("resource_type"),
        resource_id: r.get("resource_id"),
        project: r.get("project_id"),
        result: Outcome::parse(r.get("result"))?,
        request_id: r.get("request_id"),
        refs: serde_json::from_value(r.get("refs")).map_err(db_err)?,
        prev_hash: r.get("prev_hash"),
        hash: r.get("hash"),
    })
}

/// Events after `after`, oldest first, optionally for one organization.
pub fn list(
    c: &mut impl GenericClient,
    organization: Option<&str>,
    after: i64,
    limit: i64,
) -> Result<Vec<AuditEvent>> {
    let rows = match organization {
        Some(o) => c.query(
            "SELECT * FROM audit_events WHERE organization_id = $1 AND seq > $2
             ORDER BY seq LIMIT $3",
            &[&o, &after, &limit],
        ),
        None => c.query(
            "SELECT * FROM audit_events WHERE seq > $1 ORDER BY seq LIMIT $2",
            &[&after, &limit],
        ),
    }
    .map_err(db_err)?;
    rows.iter().map(row_to_event).collect()
}

fn chain_err(m: impl Into<String>) -> Error {
    Error::new(Code::TrustEvidence, m)
}

/// Recomputes the whole chain: every hash, link and sequence number.
/// Returns (last seq, root).
pub fn verify_chain(c: &mut impl GenericClient) -> Result<(i64, String)> {
    let mut prev = GENESIS.to_owned();
    let mut seq = 0i64;
    loop {
        let rows = c
            .query(
                "SELECT * FROM audit_events WHERE seq > $1 ORDER BY seq LIMIT 1000",
                &[&seq],
            )
            .map_err(db_err)?;
        if rows.is_empty() {
            break;
        }
        for r in &rows {
            let e = row_to_event(r)?;
            if e.seq != seq + 1 || e.prev_hash != prev {
                return Err(chain_err(format!(
                    "audit event {} is out of order or unchained (deleted, reordered or inserted events)",
                    e.seq
                )));
            }
            if e.compute_hash()? != e.hash {
                return Err(chain_err(format!("audit event {} was modified", e.seq)));
            }
            prev = e.hash.clone();
            seq = e.seq;
        }
    }
    let head = c
        .query_one("SELECT seq, hash FROM audit_head WHERE id", &[])
        .map_err(db_err)?;
    let (hs, hh): (i64, String) = (head.get(0), head.get(1));
    if hs != seq || hh != prev {
        return Err(chain_err("the audit head does not match the chain"));
    }
    Ok((seq, prev))
}

/// The hash of event `seq` (or the genesis for 0).
pub fn hash_at(c: &mut impl GenericClient, seq: i64) -> Result<Option<String>> {
    if seq == 0 {
        return Ok(Some(GENESIS.into()));
    }
    Ok(
        c.query_opt("SELECT hash FROM audit_events WHERE seq = $1", &[&seq])
            .map_err(db_err)?
            .map(|r| r.get(0)),
    )
}

/// A signed statement of the chain's root at `seq`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCheckpoint {
    pub seq: i64,
    pub root: String,
    pub signer: String,
    pub signer_public_key: String,
    #[serde(default)]
    pub signature: String,
}

impl AuditCheckpoint {
    fn statement(&self) -> AuditCheckpoint {
        AuditCheckpoint {
            signature: String::new(),
            ..self.clone()
        }
    }

    pub fn verify(&self, public_key: &str) -> Result<()> {
        if self.signer_public_key != public_key {
            return Err(chain_err("the audit checkpoint was signed by another key"));
        }
        verify_signed(
            public_key,
            AUDIT_CHECKPOINT,
            &self.statement(),
            &self.signature,
        )
    }
}

/// Signs and stores a checkpoint of the current head.
pub fn checkpoint(c: &mut impl GenericClient, signer: &ServiceSigner) -> Result<AuditCheckpoint> {
    let head = c
        .query_one("SELECT seq, hash FROM audit_head WHERE id", &[])
        .map_err(db_err)?;
    let mut cp = AuditCheckpoint {
        seq: head.get(0),
        root: head.get(1),
        signer: signer.id().into(),
        signer_public_key: signer.public_key_hex(),
        signature: String::new(),
    };
    cp.signature = signer.sign(AUDIT_CHECKPOINT, &cp.statement())?;
    c.execute(
        "INSERT INTO audit_checkpoints (seq, root, signer, signature) VALUES ($1, $2, $3, $4)
         ON CONFLICT (seq) DO NOTHING",
        &[&cp.seq, &cp.root, &cp.signer, &cp.signature],
    )
    .map_err(db_err)?;
    Ok(cp)
}
