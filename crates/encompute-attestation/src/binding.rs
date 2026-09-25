use encompute_ir::{Code, Result};
use encompute_verification::canonical::canonical_json;
use serde::{Deserialize, Serialize};

use crate::util::{check_hex, err, hex, random32, tagged, Digest32, BINDING};

pub const BINDING_VERSION: u32 = 1;

/// What an attestation vouches for: this execution spec, under this
/// confidentiality policy, from this artifact, signing receipts with this
/// evaluator key, reachable at this session key, answering this challenge.
///
/// Evidence commits to [`WorkloadBinding::hash`]. Changing any field (a
/// host substituting its own session key, say) changes the hash, and the
/// evidence no longer verifies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadBinding {
    pub version: u32,
    /// Lowercase hex `ExecutionSpecId`.
    pub execution_spec_id: String,
    /// Lowercase hex `PolicyId`; absent for programs without
    /// confidentiality declarations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// SHA-256 of the compiled artifact's `manifest.json`.
    pub artifact_digest: String,
    /// The evaluator's Ed25519 receipt-signing key (32 bytes hex).
    pub evaluator_public_key: String,
    /// The session's X25519 HPKE key (32 bytes hex), generated in the TEE.
    pub session_public_key: String,
    /// The broker's challenge nonce (32 bytes hex).
    pub challenge_nonce: String,
}

impl WorkloadBinding {
    /// `SHA256("encompute.workload-binding.v1" || 0x00 || canonical JSON)`.
    pub fn hash(&self) -> Result<Digest32> {
        self.check_form()?;
        Ok(tagged(BINDING, &canonical_json(self)?))
    }

    /// Lowercase hex of [`Self::hash`]: the value evidence carries as its
    /// nonce (64 characters, within every provider's nonce limits).
    pub fn nonce(&self) -> Result<String> {
        Ok(hex(&self.hash()?))
    }

    pub fn check_form(&self) -> Result<()> {
        if self.version != BINDING_VERSION {
            return Err(err(
                Code::Attestation,
                format!("workload binding version {}", self.version),
            ));
        }
        let c = Code::Attestation;
        check_hex(c, "binding execution spec ID", &self.execution_spec_id, 32)?;
        if let Some(p) = &self.policy_id {
            check_hex(c, "binding policy ID", p, 32)?;
        }
        check_hex(c, "binding artifact digest", &self.artifact_digest, 32)?;
        check_hex(c, "binding evaluator key", &self.evaluator_public_key, 32)?;
        check_hex(c, "binding session key", &self.session_public_key, 32)?;
        check_hex(c, "binding challenge nonce", &self.challenge_nonce, 32)?;
        Ok(())
    }
}

/// A broker's fresh, single-use challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationChallenge {
    pub broker_id: String,
    /// 32 random bytes, lowercase hex.
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl AttestationChallenge {
    pub fn new(broker_id: &str, now: u64, ttl_secs: u64) -> Result<Self> {
        Ok(Self {
            broker_id: broker_id.to_owned(),
            nonce: hex(&random32(Code::Freshness)?),
            issued_at: now,
            expires_at: now.saturating_add(ttl_secs),
        })
    }
}
