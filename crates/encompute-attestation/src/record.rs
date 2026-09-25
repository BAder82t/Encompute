use encompute_ir::{Code, Result};
use encompute_verification::canonical::canonical_json;
use serde::{Deserialize, Serialize};

use crate::grant::WorkloadSession;
use crate::policy::{AttestationPolicy, VerifiedWorkload};
use crate::provider::{AttestationEvidence, Verifier};
use crate::util::{err, hex, tagged, RECORD};

pub const RECORD_VERSION: u32 = 1;

/// The attestation behind an evaluator's receipts, kept beside them.
/// Receipts carry only its ID and the session ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRecord {
    pub version: u32,
    pub evidence: AttestationEvidence,
}

impl AttestationRecord {
    pub fn new(evidence: AttestationEvidence) -> Self {
        Self {
            version: RECORD_VERSION,
            evidence,
        }
    }

    /// `SHA256("encompute.attestation-record.v1" || 0x00 || canonical JSON)`, hex.
    pub fn id(&self) -> Result<String> {
        Ok(hex(&tagged(RECORD, &canonical_json(self)?)))
    }

    pub fn session_id(&self) -> Result<String> {
        WorkloadSession::session_id_of(&self.evidence.binding)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let r: Self = serde_json::from_slice(bytes).map_err(|e| {
            err(
                Code::Attestation,
                format!("malformed attestation record: {e}"),
            )
        })?;
        if r.version != RECORD_VERSION {
            return Err(err(
                Code::Attestation,
                format!("attestation record version {}", r.version),
            ));
        }
        Ok(r)
    }

    /// Verifies the record as history: signature, binding and policy, but
    /// not expiry (the attestation authorized a session in the past).
    pub fn verify(
        &self,
        verifier: &Verifier,
        policy: &AttestationPolicy,
    ) -> Result<VerifiedWorkload> {
        let w = verifier.verify_claims(&self.evidence, None)?;
        policy.check(&w)?;
        Ok(w)
    }
}
