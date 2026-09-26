//! Confidential checkpoints: the adapter, optimizer state and round,
//! sealed and bound to the project, training spec, run, policies, lineage
//! and the privacy ledgers' positions. Resume refuses a checkpoint from
//! another project, spec or policy, and one whose privacy state is behind
//! (or ahead of) the authoritative ledgers: restoring an old checkpoint
//! never restores spent budget.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use encompute_ir::{Code, Error, Result};
use encompute_privacy::{ledger, Checkpoint};

use crate::seal::{open, seal, sha256_hex};

pub const CHECKPOINT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointHeader {
    pub version: u32,
    pub project: String,
    pub training_spec_id: String,
    pub run_id: String,
    pub round: u32,
    pub adapter_id: String,
    /// SHA-256 of the sealed payload (hex).
    pub payload_digest: String,
    pub policy_id: Option<String>,
    pub privacy_policy_id: Option<String>,
    /// Each budgeted asset's ledger position when the checkpoint was made.
    pub ledgers: BTreeMap<String, Checkpoint>,
    /// The trust bundle root when the checkpoint was made.
    pub lineage_root: Option<String>,
}

/// What a resume must match.
pub struct ResumeExpectation<'a> {
    pub project: &'a str,
    pub training_spec_id: &'a str,
    pub policy_id: Option<&'a str>,
    pub privacy_policy_id: Option<&'a str>,
    /// The authoritative ledgers.
    pub ledger_dir: &'a Path,
}

fn err(m: impl Into<String>) -> Error {
    Error::new(Code::Checkpoint, m)
}

pub fn seal_checkpoint(key: &[u8], header: &CheckpointHeader, payload: &[u8]) -> Result<Vec<u8>> {
    if header.payload_digest != sha256_hex(payload) {
        return Err(err(
            "the header's payload digest does not match the payload",
        ));
    }
    seal(key, header, payload)
}

/// Opens a checkpoint for resuming, or says why it cannot be resumed.
pub fn resume(
    key: &[u8],
    bytes: &[u8],
    expect: &ResumeExpectation<'_>,
) -> Result<(CheckpointHeader, Zeroizing<Vec<u8>>)> {
    let (h, payload): (CheckpointHeader, _) = open(key, bytes)?;
    if h.version != CHECKPOINT_VERSION || sha256_hex(&payload) != h.payload_digest {
        return Err(err("the checkpoint is corrupted"));
    }
    if h.project != expect.project {
        return Err(err(format!(
            "this checkpoint belongs to project {}, not {}",
            h.project, expect.project
        )));
    }
    if h.training_spec_id != expect.training_spec_id {
        return Err(Error::new(
            Code::TrainingSpec,
            "this checkpoint was made under another training spec (model, code, configuration, \
             privacy or participants differ)",
        ));
    }
    if h.policy_id.as_deref() != expect.policy_id
        || h.privacy_policy_id.as_deref() != expect.privacy_policy_id
    {
        return Err(Error::new(
            Code::TrainingSpec,
            "this checkpoint was made under another confidentiality or privacy policy",
        ));
    }
    for (asset, cp) in &h.ledgers {
        let path = expect.ledger_dir.join(format!("{asset}.ledger"));
        let view = ledger::read(&path)?;
        // The ledger must not have been rolled back past the checkpoint...
        view.extends(cp)?;
        // ...and the checkpoint must be current: an older checkpoint would
        // resume from a state whose releases the ledger already charged.
        if view.checkpoint()? != *cp {
            return Err(err(format!(
                "the checkpoint is stale: {asset}'s privacy ledger has advanced to entry {} \
                 since (a later round was released); resume from the latest checkpoint",
                view.entries.len()
            )));
        }
    }
    Ok((h, payload))
}
