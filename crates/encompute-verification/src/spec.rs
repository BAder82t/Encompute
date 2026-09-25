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
