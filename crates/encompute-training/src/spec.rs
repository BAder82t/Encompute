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
const PARTICIPANT: &str = "encompute.training-participant.v1";

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
    /// Hugging Face PEFT LoRA (`method` `peft-lora`). Absent: the
    /// reference LoRA implementation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peft: Option<PeftConfig>,
}

/// The PEFT adapter configuration: every field that changes what trains
/// or how.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeftConfig {
    /// `LORA`.
    pub peft_type: String,
    pub r: u32,
    pub lora_alpha: u32,
    pub lora_dropout: String,
    /// Sorted, distinct.
    pub target_modules: Vec<String>,
    /// `none`, `all` or `lora_only`.
    pub bias: String,
    /// Fully trained modules (the classification head), sorted, distinct.
    pub modules_to_save: Vec<String>,
    /// `SEQ_CLS`.
    pub task_type: String,
    /// `true` or `gaussian`.
    pub init_lora_weights: String,
    pub adapter_name: String,
    /// The installed PEFT library (major.minor), as the package binds.
    pub library: String,
}

impl PeftConfig {
    fn validate(&self, c: &TrainingConfig) -> Result<()> {
        let sorted = |v: &Vec<String>| {
            let mut t = v.clone();
            t.sort();
            t.dedup();
            t == *v
        };
        if self.peft_type != "LORA" || self.task_type != "SEQ_CLS" {
            return Err(bad("PEFT support is LoRA for sequence classification"));
        }
        if self.r == 0 || self.lora_alpha == 0 || self.target_modules.is_empty() {
            return Err(bad("PEFT LoRA needs a rank, an alpha and target modules"));
        }
        if !sorted(&self.target_modules) || !sorted(&self.modules_to_save) {
            return Err(bad(
                "PEFT target modules and modules to save must be sorted, distinct",
            ));
        }
        if !["none", "all", "lora_only"].contains(&self.bias.as_str()) {
            return Err(bad("PEFT bias is none, all or lora_only"));
        }
        if !["true", "gaussian"].contains(&self.init_lora_weights.as_str()) {
            return Err(bad("PEFT init_lora_weights is true or gaussian"));
        }
        if self.adapter_name.is_empty() {
            return Err(bad("PEFT needs an adapter name"));
        }
        match self.lora_dropout.parse::<f64>() {
            Ok(d) if (0.0..1.0).contains(&d) && format!("{d:?}") == self.lora_dropout => {}
            _ => {
                return Err(bad(
                    "PEFT lora_dropout must be in [0, 1), written as Rust prints it",
                ))
            }
        }
        if c.rank != self.r || c.alpha != self.lora_alpha || c.target_modules != self.target_modules
        {
            return Err(bad(
                "the LoRA rank, alpha and target modules must be PEFT's",
            ));
        }
        Ok(())
    }
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
        if !["lora", "peft-lora"].contains(&self.method.as_str()) {
            return Err(bad("only LoRA fine-tuning is supported (lora, peft-lora)"));
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
        match (&self.peft, self.method.as_str()) {
            (Some(p), "peft-lora") => p.validate(self)?,
            (None, "lora") => {}
            _ => {
                return Err(bad(
                    "method is lora (reference) or peft-lora (with a PEFT config)",
                ))
            }
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
    /// The Hugging Face package the model was imported from: its
    /// resolved revision, every file's digest, the tokenizer and library
    /// versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub huggingface: Option<crate::hf::HfModelPackage>,
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
    /// Text datasets: how the owner tokenized it. Tokenization changes the
    /// effective training data, so it is bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preprocessing: Option<TextPreprocessing>,
}

/// How a text dataset was tokenized (and chunked): each chunk keeps its
/// record's privacy unit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextPreprocessing {
    /// The model package's tokenizer digest.
    pub tokenizer_digest: String,
    pub max_length: u32,
    pub truncation: bool,
    /// `max_length`.
    pub padding: String,
    /// Chunk overlap in tokens when long records are split into several
    /// (each chunk keeps its record's unit); absent: truncated to one.
    pub stride: Option<u32>,
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
        let hf = self.base_model.huggingface.as_ref();
        if let Some(p) = hf {
            p.validate()?;
        }
        if hf.is_some() != self.config.peft.is_some() {
            return Err(bad(
                "a Hugging Face model trains with PEFT, and PEFT needs a Hugging Face model",
            ));
        }
        if let (Some(p), Some(c)) = (hf, &self.config.peft) {
            if p.libraries.peft != c.library {
                return Err(bad("the PEFT library version is not the package's"));
            }
        }
        for d in &self.datasets {
            hex64("dataset digest", &d.digest)?;
            match (hf, &d.preprocessing) {
                (None, None) => {}
                (Some(p), Some(t))
                    if t.tokenizer_digest == p.tokenizer_digest
                        && t.max_length > 0
                        && t.padding == "max_length"
                        && (t.truncation || t.stride.is_none()) => {}
                (Some(_), Some(_)) => {
                    return Err(bad(format!(
                        "{} was not tokenized with the model package's tokenizer, or its \
                         preprocessing is malformed",
                        d.asset_id
                    )))
                }
                (Some(_), None) => {
                    return Err(bad(format!("{} needs its text preprocessing", d.asset_id)))
                }
                (None, Some(_)) => {
                    return Err(bad(format!(
                        "{} declares text preprocessing without a Hugging Face model",
                        d.asset_id
                    )))
                }
            }
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
    /// The execution a confidential training job attests to: this training
    /// spec, as this participant. A participant's dataset and output keys
    /// are released only under it, so a session acts for one participant,
    /// and its evidence's participant is attested, not merely claimed.
    pub fn participant_execution_id(&self, party: &str) -> Result<String> {
        if !self.participants.iter().any(|p| p.party.as_str() == party) {
            return Err(bad(format!(
                "{party} is not a participant of this training spec"
            )));
        }
        Ok(tagged_hex(
            PARTICIPANT,
            &[self.id()?.as_bytes(), party.as_bytes()],
        ))
    }

    /// [`Self::attestation_policy`], scoped to one participant's jobs.
    pub fn participant_attestation_policy(
        &self,
        party: &str,
        image: &str,
        development: bool,
    ) -> Result<AttestationPolicy> {
        let mut p = self.attestation_policy(image, development)?;
        p.execution_spec_id = self.participant_execution_id(party)?;
        p.validate()?;
        Ok(p)
    }

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
