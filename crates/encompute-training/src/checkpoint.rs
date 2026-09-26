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
use encompute_privacy::{ledger, Checkpoint, PrivacyEvent};

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
    /// Aggregation rounds released after this checkpoint whose adapters
    /// were never accepted (a crash before the commit point). Their ledger
    /// entries may follow the checkpoint: their privacy stays spent, only
    /// their training progress is lost. Any other later entry (a round
    /// whose adapter was accepted) makes the checkpoint stale.
    pub lost_rounds: &'a [String],
    /// The run being resumed, if a specific one: a checkpoint of another
    /// run (even of the same spec) is refused.
    pub run_id: Option<&'a str>,
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
    if expect.run_id.is_some_and(|r| r != h.run_id) {
        return Err(err(format!(
            "this checkpoint belongs to another training run ({})",
            &h.run_id[..h.run_id.len().min(16)]
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
        // ...and the checkpoint must be current: every later entry must
        // belong to a round released but never accepted. Otherwise an
        // older checkpoint would resume from before accepted rounds.
        let mut reserved = std::collections::BTreeMap::new();
        for e in &view.entries {
            if let PrivacyEvent::Reserve {
                event_id, round_id, ..
            } = &e.event
            {
                reserved.insert(event_id.clone(), round_id.clone());
            }
        }
        for e in view.entries.iter().skip(cp.seq as usize) {
            let round = reserved.get(e.event.event_id()).cloned().flatten();
            if !round.is_some_and(|r| expect.lost_rounds.contains(&r)) {
                return Err(err(format!(
                    "the checkpoint is stale: {asset}'s privacy ledger has advanced to entry {} \
                     since (a later round was released and accepted); resume from the latest \
                     checkpoint",
                    view.entries.len()
                )));
            }
        }
    }
    Ok((h, payload))
}
