use std::fmt;

use encompute_ir::Result;
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json;
use crate::hash::{hex, tagged, SPEC};

pub const SPEC_VERSION: u32 = 1;

/// What is to be executed: every identity an execution depends on, derived
/// from data Encompute already owns. `program_id`, `plan_id` and
/// `parameter_set_id` are SHA-256 of the artifact's `program.eir`,
/// `plan.json` and `parameters.json` bytes (the same IDs envelopes carry).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSpec {
    pub version: u32,
    pub program_id: String,
    pub plan_id: String,
    pub parameter_set_id: String,
    /// "ckks" or "exact".
    pub plan_kind: String,
    pub plan_version: u32,
    /// "approximate" or "exact".
    pub semantics: String,
    /// "CKKS" or "TFHE".
    pub scheme: String,
    pub backend: String,
    pub backend_version: String,
    /// Hex `PolicyId` of the program's confidentiality declarations
    /// (ADR-010); absent for programs without any, so their spec IDs are
    /// unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// Hex `PrivacyPolicyId` of its differential-privacy configuration
    /// (ADR-013); absent without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_policy_id: Option<String>,
}

/// `SHA256("encompute.execution-spec.v1" || 0x00 || canonical spec)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExecutionSpecId(pub [u8; 32]);

impl ExecutionSpecId {
    /// Lowercase hex, as stored in receipts and `verification.json`.
    pub fn hex(&self) -> String {
        hex(&self.0)
    }
}

impl fmt::Display for ExecutionSpecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "encspec1:{}", self.hex())
    }
}

impl ExecutionSpec {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }

    pub fn id(&self) -> ExecutionSpecId {
        let bytes = self.canonical_bytes().expect("strings and integers only");
        ExecutionSpecId(tagged(SPEC, &bytes))
    }
}

/// `SHA256("encompute.confidentiality-policy.v1" || 0x00 || canonical
/// confidentiality declarations)`: binds parties, assets, policies,
/// purpose, input bindings, derivations and output destinations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PolicyId(pub [u8; 32]);

impl PolicyId {
    pub fn of(c: &encompute_ir::confidentiality::Confidentiality) -> Self {
        let bytes = crate::canonical::canonical_json(c).expect("strings and integers only");
        Self(crate::hash::tagged(crate::hash::POLICY, &bytes))
    }

    pub fn hex(&self) -> String {
        hex(&self.0)
    }
}

/// The approved privacy configuration: each asset's budget (unit, epsilon,
/// delta) and each aggregation's mechanism (kind, clip norm, noise
/// multiplier, and the codec it acts on). `None` without any.
/// `SHA256("encompute.privacy-policy.v1" || 0x00 || canonical JSON)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PrivacyPolicyId(pub [u8; 32]);

impl PrivacyPolicyId {
    pub fn of(c: &encompute_ir::confidentiality::Confidentiality) -> Option<Self> {
        use std::collections::BTreeMap;
        let budgets: BTreeMap<&str, &encompute_ir::confidentiality::PrivacyBudget> = c
            .assets
            .iter()
            .filter_map(|a| a.policy.privacy.as_ref().map(|b| (a.id.as_str(), b)))
            .collect();
        let mechanisms: BTreeMap<&str, (&encompute_ir::confidentiality::DpMechanism, _)> = c
            .aggregations
            .iter()
            .filter_map(|a| a.dp.as_ref().map(|d| (a.output.as_str(), (d, &a.codec))))
            .collect();
        if budgets.is_empty() && mechanisms.is_empty() {
            return None;
        }
        #[derive(Serialize)]
        struct Canonical<'a> {
            budgets: &'a BTreeMap<&'a str, &'a encompute_ir::confidentiality::PrivacyBudget>,
            mechanisms: &'a BTreeMap<
                &'a str,
                (
                    &'a encompute_ir::confidentiality::DpMechanism,
                    &'a encompute_ir::confidentiality::FixedPointCodec,
                ),
            >,
        }
        let bytes = crate::canonical::canonical_json(&Canonical {
            budgets: &budgets,
            mechanisms: &mechanisms,
        })
        .expect("strings and integers only");
        Some(Self(crate::hash::tagged(
            crate::hash::PRIVACY_POLICY,
            &bytes,
        )))
    }

    pub fn hex(&self) -> String {
        hex(&self.0)
    }
}

impl fmt::Display for PrivacyPolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "encprivacy1:{}", self.hex())
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "encpolicy1:{}", self.hex())
    }
}
