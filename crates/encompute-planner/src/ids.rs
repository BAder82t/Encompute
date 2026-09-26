//! Plan identity: `SHA256("encompute.confidential-execution-plan.v1" ||
//! 0x00 || canonical plan)`, shown as `encplan1:<hex>`.

use sha2::{Digest, Sha256};

use encompute_ir::{Program, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::hex;

use crate::model::ConfidentialExecutionPlan;

const PLAN: &str = "encompute.confidential-execution-plan.v1";

/// The program ID (SHA-256 of its canonical `.eir` text), as everywhere
/// else in Encompute.
pub fn program_id(program: &Program) -> String {
    hex(&Sha256::digest(program.to_string().as_bytes()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanId(pub [u8; 32]);

impl PlanId {
    pub fn of(plan: &ConfidentialExecutionPlan) -> Result<Self> {
        let mut h = Sha256::new();
        h.update(PLAN.as_bytes());
        h.update([0u8]);
        h.update(canonical_json(plan)?);
        Ok(Self(h.finalize().into()))
    }

    pub fn hex(&self) -> String {
        hex(&self.0)
    }
}

impl std::fmt::Display for PlanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "encplan1:{}", self.hex())
    }
}

impl ConfidentialExecutionPlan {
    pub fn id(&self) -> Result<PlanId> {
        PlanId::of(self)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        serde_json::from_slice(b).map_err(|e| {
            encompute_ir::Error::new(
                encompute_ir::Code::PlanInvalid,
                format!("malformed plan: {e}"),
            )
        })
    }
}
