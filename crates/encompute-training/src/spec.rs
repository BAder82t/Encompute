//! The training specification: everything security-relevant about one
//! confidential fine-tuning, canonical, with an ID (`enctrain1:`) that
//! workers attest to, key brokers release keys for, and checkpoints and
//! adapters are bound to. Changing any of it (base model, code, LoRA
//! configuration, optimizer, privacy, aggregation, participants, plan)
//! changes the ID.

use serde::{Deserialize, Serialize};

use encompute_attestation::{AttestationPolicy, TeeKind};
use encompute_ir::{Code, Error, Result};
use encompute_secagg::PartyIdentity;
use encompute_verification::canonical::canonical_json;

use crate::tagged_hex;

pub const SPEC_VERSION: u32 = 1;
const SPEC: &str = "encompute.training-spec.v1";
const RUN: &str = "encompute.training-run.v1";

fn bad(m: impl Into<String>) -> Error {
    Error::new(Code::TrainingSpec, m)
}

/// A decimal number as an exact string (canonical JSON has no floats).
fn positive(name: &str, s: &str) -> Result<()> {
    match s.parse::<f64>() {
        Ok(x) if x.is_finite() && x > 0.0 && format!("{x:?}") == s => Ok(()),
        _ => Err(bad(format!(
            "{name} must be a positive number written as Rust prints it (e.g. \"0.01\"), not \
             {s:?}"
        ))),
    }
}

/// The security-relevant training configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingConfig {
    /// `lora`.
    pub method: String,
    pub rank: u32,
    pub alpha: u32,
    /// Module names adapted (sorted, distinct).
    pub target_modules: Vec<String>,
    /// `sgd` or `adam`.
    pub optimizer: String,
    pub learning_rate: String,
    /// Per-contribution L2 clip of the adapter update (before
    /// aggregation; the DP sensitivity).
    pub update_clip: String,
    pub local_steps: u32,
    pub batch_size: u32,
    pub rounds: u32,
    /// Adapter parameters (the aggregated vector's length).
    pub adapter_parameters: u64,
    /// Patient-level (example-level) DP-SGD. Absent: organization-level
    /// privacy, where each participant's whole update is clipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dp_sgd: Option<DpSgdConfig>,
}

/// DP-SGD: each worker computes per-example gradients, sums each privacy
/// unit's (grouping its records), clips each unit's to `per_example_clip`,
/// Poisson-samples the units with `sampling_rate`, and contributes the sum
/// of the sampled units' clipped gradients to secure aggregation. The
/// coordinator adds discrete Gaussian noise to the sum. One gradient step
/// per round.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpSgdConfig {
    /// The privacy unit (`patient`, `user`, `record`...), never
    /// `organization`.
    pub privacy_unit: String,
    /// L2 clip of each unit's gradient.
    pub per_example_clip: String,
    /// `poisson`.
    pub sampling: String,
    pub sampling_rate: String,
    pub noise_multiplier: String,
    pub delta: String,
    /// `unit_ids` (records grouped by a per-record unit ID, whose digest
    /// each dataset commitment binds) or `none` (one record is one unit).
    pub grouping: String,
    /// The accountant, with its version.
    pub accountant: String,
    /// The expected number of sampled units per round, over all datasets
    /// (the server update's denominator).
    pub expected_batch: String,
}

impl DpSgdConfig {
    fn validate(&self, local_steps: u32) -> Result<()> {
        if matches!(self.privacy_unit.as_str(), "organization" | "") {
            return Err(bad(
                "DP-SGD protects a unit inside a participant (patient, user, record), not an organization",
            ));
        }
        if self.sampling != "poisson" {
            return Err(bad("DP-SGD sampling is poisson"));
        }
        if !["unit_ids", "none"].contains(&self.grouping.as_str()) {
            return Err(bad("DP-SGD grouping is unit_ids or none"));
        }
        if self.accountant != encompute_ir::confidentiality::SAMPLED_PRIVACY_ACCOUNTANT {
            return Err(bad(format!(
                "DP-SGD is accounted with {}",
                encompute_ir::confidentiality::SAMPLED_PRIVACY_ACCOUNTANT
            )));
        }
        if local_steps != 1 {
            return Err(bad(
                "DP-SGD takes one gradient step per round (local_steps 1): each step is one \
                 accounted release",
            ));
        }
        for (n, v) in [
            ("per_example_clip", &self.per_example_clip),
            ("sampling_rate", &self.sampling_rate),
            ("noise_multiplier", &self.noise_multiplier),
            ("delta", &self.delta),
            ("expected_batch", &self.expected_batch),
        ] {
            positive(n, v)?;
        }
        let q: f64 = self.sampling_rate.parse().unwrap_or(1.0);
        let d: f64 = self.delta.parse().unwrap_or(1.0);
        if q >= 1.0 || d >= 1.0 {
            return Err(bad("sampling_rate and delta must be below 1"));
        }
        Ok(())
    }
}

impl TrainingConfig {
    pub fn validate(&self) -> Result<()> {
        if self.method != "lora" {
            return Err(bad("only LoRA fine-tuning is supported"));
        }
        if self.rank == 0 || self.alpha == 0 || self.local_steps == 0 || self.batch_size == 0 {
            return Err(bad(
                "rank, alpha, local steps and batch size must be positive",
            ));
        }
        if self.rounds == 0 || self.adapter_parameters == 0 {
            return Err(bad("rounds and adapter parameters must be positive"));
        }
        let mut t = self.target_modules.clone();
        t.sort();
        t.dedup();
        if t != self.target_modules || t.is_empty() {
            return Err(bad("target modules must be non-empty, sorted and distinct"));
        }
        if !["sgd", "adam"].contains(&self.optimizer.as_str()) {
            return Err(bad("the optimizer is sgd or adam"));
        }
        positive("learning_rate", &self.learning_rate)?;
        positive("update_clip", &self.update_clip)?;
        if let Some(d) = &self.dp_sgd {
            d.validate(self.local_steps)?;
        }
        Ok(())
    }
}

/// A commitment to a model: never the weights.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCommitment {
    pub asset_id: String,
    pub owner: String,
    /// E.g. the class and shape summary.
    pub architecture: String,
    /// SHA-256 of the serialized weights (hex).
    pub weights_digest: String,
}

/// A commitment to a dataset: never the samples.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetCommitment {
    pub asset_id: String,
    pub owner: String,
    /// The gradient asset the owner contributes for it.
    pub gradient_asset: String,
    /// SHA-256 of the dataset as its owner holds it (hex).
    pub digest: String,
    /// DP-SGD: the number of privacy units in the dataset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_units: Option<u64>,
    /// DP-SGD: SHA-256 of the per-record unit IDs (hex), which the
    /// dataset digest also covers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grouping_digest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingSpec {
    pub version: u32,
    pub project: String,
    /// The purpose every asset's policy allows.
    pub purpose: String,
    /// The approved confidential execution plan (hex PlanId).
    pub plan_id: String,
    /// The aggregation program's ID, its policies and aggregation spec.
    pub program_id: String,
    pub policy_id: Option<String>,
    pub privacy_policy_id: Option<String>,
    pub aggregation_spec_id: String,
    pub base_model: ModelCommitment,
    /// Sorted by asset ID.
    pub datasets: Vec<DatasetCommitment>,
    /// SHA-256 of the training code the workers run (hex).
    pub code_digest: String,
    /// SHA-256 of the canonical adapter parameter layout (module,
    /// parameter, shape, offset, length, dtype): the order tensors are
    /// flattened in for aggregation.
    pub layout_digest: String,
    pub config: TrainingConfig,
    /// The contributing parties and their identity keys.
    pub participants: Vec<PartyIdentity>,
}

fn hex64(name: &str, s: &str) -> Result<()> {
    if s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(bad(format!("{name} must be 64 lowercase hex digits")))
    }
}

impl TrainingSpec {
    pub fn validate(&self) -> Result<()> {
        if self.version != SPEC_VERSION {
            return Err(bad(format!("training spec version {}", self.version)));
        }
        self.config.validate()?;
        hex64("plan_id", &self.plan_id)?;
        hex64("program_id", &self.program_id)?;
        hex64("code_digest", &self.code_digest)?;
        hex64("layout_digest", &self.layout_digest)?;
        hex64("weights_digest", &self.base_model.weights_digest)?;
        if self.datasets.len() < 2 {
            return Err(bad("training needs datasets from at least two parties"));
        }
        if self
            .datasets
            .windows(2)
            .any(|w| w[0].asset_id >= w[1].asset_id)
        {
            return Err(bad("datasets must be sorted and distinct"));
        }
        let dp = self.config.dp_sgd.as_ref();
        for d in &self.datasets {
            hex64("dataset digest", &d.digest)?;
            match (dp, d.privacy_units, &d.grouping_digest) {
                (None, None, None) => {}
                (Some(c), Some(n), g) if n > 0 => match (c.grouping.as_str(), g) {
                    ("unit_ids", Some(g)) => hex64("grouping digest", g)?,
                    ("none", None) => {}
                    _ => {
                        return Err(bad(format!(
                            "{}'s grouping does not match the DP-SGD grouping {}",
                            d.asset_id, c.grouping
                        )))
                    }
                },
                (Some(_), _, _) => {
                    return Err(bad(format!(
                        "DP-SGD needs {}'s number of privacy units",
                        d.asset_id
                    )))
                }
                (None, _, _) => {
                    return Err(bad(format!(
                        "{} declares privacy units, but the run is not DP-SGD",
                        d.asset_id
                    )))
                }
            }
            if !self
                .participants
                .iter()
                .any(|p| p.party.as_str() == d.owner)
            {
                return Err(bad(format!(
                    "{}'s owner {} is not a participant",
                    d.asset_id, d.owner
                )));
            }
        }
        Ok(())
    }

    /// `SHA256("encompute.training-spec.v1" || 0x00 || canonical spec)`.
    pub fn id(&self) -> Result<String> {
        Ok(tagged_hex(SPEC, &[&canonical_json(self)?]))
    }

    /// One execution of this spec.
    pub fn run_id(&self, nonce: &str) -> Result<String> {
        Ok(tagged_hex(RUN, &[self.id()?.as_bytes(), nonce.as_bytes()]))
    }

    /// The dataset of `party`.
    pub fn dataset_of(&self, party: &str) -> Option<&DatasetCommitment> {
        self.datasets.iter().find(|d| d.owner == party)
    }

    /// The attestation policy under which owners release model and
    /// dataset keys: a workload must bind this training spec (which binds
    /// the plan, policies, model, code, configuration and participants)
    /// and run exactly this training code in an approved image.
    pub fn attestation_policy(&self, image: &str, development: bool) -> Result<AttestationPolicy> {
        let mut p = AttestationPolicy::new(&self.id()?, self.policy_id.as_deref());
        p.artifact_digest = Some(self.code_digest.clone());
        p.allowed_images = vec![image.to_owned()];
        p.allowed_tee = if development {
            vec![TeeKind::Mock]
        } else {
            vec![TeeKind::IntelTdx, TeeKind::AmdSevSnp]
        };
        p.allow_development = development;
        p.validate()?;
        Ok(p)
    }
}
