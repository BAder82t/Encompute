//! The training specification: everything security-relevant about one
//! confidential fine-tuning, canonical, with an ID (`enctrain1:`) that
//! workers attest to, key brokers release keys for, and checkpoints and
//! adapters are bound to. Changing any of it (base model, code, LoRA
//! configuration, optimizer, privacy, aggregation, participants, plan,
//! key brokers, coordinator, initial adapter) changes the ID.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use encompute_attestation::{AttestationPolicy, TeeKind};
use encompute_ir::{Code, Error, Result};
use encompute_secagg::PartyIdentity;
use encompute_verification::canonical::canonical_json;

use crate::tagged_hex;

/// 2: typed, allowlisted architectures; the key brokers, the coordinator
/// and the initial adapter are bound; privacy unit counts are optional
/// public figures.
pub const SPEC_VERSION: u32 = 2;
const SPEC: &str = "encompute.training-spec.v1";
const CONFIG: &str = "encompute.training-config.v1";

/// The reference model factory (`method` `lora`).
pub const REFERENCE_FACTORY: &str = "encompute.torch.models:tiny_classifier";
/// The Hugging Face factory (`method` `peft-lora`): the package's own
/// `config.json`, Transformers-native classes only.
pub const HF_FACTORY: &str = "encompute.torch.hf:from_config";
/// The reference factory's keyword arguments, each a positive integer.
const REFERENCE_KWARGS: &[&str] = &["classes", "dim", "seq", "vocab"];
const MAX_REFERENCE_DIM: u64 = 1 << 20;
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
    /// The model factory and its arguments (JSON: `factory`, `kwargs`):
    /// one of the factories the worker image ships (see
    /// [`Architecture`]), never an arbitrary callable.
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
    /// SHA-256 of the dataset as its owner holds it (hex). The dataset
    /// carries a random salt its owner keeps, so the digest is a hiding
    /// commitment: nobody can test a guessed dataset against it.
    pub digest: String,
    /// DP-SGD: the number of privacy units the owner approved for
    /// publication (a public figure, not a count of the data), which the
    /// default sampling rate is derived from. Absent: the sampling rate
    /// was set explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_units: Option<u64>,
    /// DP-SGD: SHA-256 of the per-record unit IDs and the dataset's salt
    /// (hex), which the dataset digest also covers.
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
    /// The key brokers whose grants workers accept: broker ID -> its
    /// grant-signing key (hex Ed25519). Part of the attested identity, so
    /// the host cannot choose or omit a broker's key.
    pub key_brokers: BTreeMap<String, String>,
    /// The coordinator's adapter-record signing key (hex Ed25519): a
    /// worker trains only from an adapter it recorded.
    pub coordinator_key: String,
    /// SHA-256 of the initial adapter (`adapter-0`, hex): round 1 starts
    /// from it.
    pub initial_adapter_digest: String,
}

/// A model factory the worker image ships, and its arguments: the only
/// code a training spec can name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Architecture {
    pub factory: String,
    pub kwargs: serde_json::Map<String, serde_json::Value>,
}

impl Architecture {
    /// Parses and checks `base_model.architecture`: an allowlisted
    /// factory, and arguments of its schema.
    pub fn parse(s: &str) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_str(s)
            .map_err(|e| bad(format!("the model architecture is not JSON: {e}")))?;
        let o = v
            .as_object()
            .ok_or_else(|| bad("the model architecture is not an object"))?;
        if o.len() != 2 {
            return Err(bad(
                "the model architecture has exactly a factory and kwargs",
            ));
        }
        let factory = o
            .get("factory")
            .and_then(|f| f.as_str())
            .ok_or_else(|| bad("the model architecture names no factory"))?
            .to_owned();
        let kwargs = o
            .get("kwargs")
            .and_then(|k| k.as_object())
            .ok_or_else(|| bad("the model architecture's kwargs are not an object"))?
            .clone();
        let a = Self { factory, kwargs };
        match a.factory.as_str() {
            REFERENCE_FACTORY => {
                for (k, v) in &a.kwargs {
                    let ok = REFERENCE_KWARGS.contains(&k.as_str())
                        && v.as_u64()
                            .is_some_and(|n| (1..=MAX_REFERENCE_DIM).contains(&n));
                    if !ok {
                        return Err(bad(format!(
                            "{REFERENCE_FACTORY}: {k} is not one of {} (a positive integer)",
                            REFERENCE_KWARGS.join(", ")
                        )));
                    }
                }
            }
            HF_FACTORY => {
                let mut keys: Vec<&str> = a.kwargs.keys().map(String::as_str).collect();
                keys.sort_unstable();
                if keys != ["config", "num_labels", "task"]
                    || !a.kwargs["config"].is_string()
                    || a.kwargs["num_labels"].as_u64().is_none()
                    || a.kwargs["task"].as_str().is_none()
                {
                    return Err(bad(format!(
                        "{HF_FACTORY} takes exactly config (the package's config.json), \
                         num_labels and task"
                    )));
                }
            }
            other => {
                return Err(bad(format!(
                "model factory {other:?} is not one the worker image ships ({REFERENCE_FACTORY}, \
                     {HF_FACTORY}): a training spec cannot name other code"
            )))
            }
        }
        Ok(a)
    }

    /// The architecture fits the spec: the reference factory for reference
    /// LoRA; for PEFT, the Hugging Face factory with exactly the package's
    /// `config.json` bytes, labels and task.
    fn check(&self, spec: &TrainingSpec) -> Result<()> {
        match (self.factory.as_str(), &spec.base_model.huggingface) {
            (REFERENCE_FACTORY, None) => Ok(()),
            (HF_FACTORY, Some(p)) => {
                let config = self.kwargs["config"].as_str().unwrap_or_default();
                if crate::seal::sha256_hex(config.as_bytes()) != p.config_digest {
                    return Err(bad(
                        "the architecture's config is not the model package's config.json",
                    ));
                }
                let v: serde_json::Value =
                    serde_json::from_str(config).map_err(|e| bad(format!("config.json: {e}")))?;
                if crate::hf::check_config(&v)? != p.model_type {
                    return Err(bad("the architecture's model type is not the package's"));
                }
                if self.kwargs["num_labels"].as_u64() != Some(u64::from(p.num_labels))
                    || self.kwargs["task"].as_str() != Some(p.task.as_str())
                {
                    return Err(bad(
                        "the architecture's labels or task are not the package's",
                    ));
                }
                Ok(())
            }
            _ => Err(bad(format!(
                "a reference model is built with {REFERENCE_FACTORY}, a Hugging Face model with \
                 {HF_FACTORY}"
            ))),
        }
    }
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
        hex64("coordinator_key", &self.coordinator_key)?;
        hex64("initial_adapter_digest", &self.initial_adapter_digest)?;
        if self.key_brokers.is_empty() {
            return Err(bad(
                "a training spec names its key brokers and their grant-signing keys",
            ));
        }
        // One broker per spec: a workload trusts every broker named here for
        // every asset, so with two, one broker could grant a key (such as a
        // participant's contribution key) for an asset held by the other.
        // Several owners' brokers need a per-asset binding first.
        if self.key_brokers.len() != 1 {
            return Err(bad(
                "a training spec names exactly one key broker: several brokers would each be \
                 trusted for every asset",
            ));
        }
        for (id, key) in &self.key_brokers {
            if id.is_empty() {
                return Err(bad("a key broker needs an ID"));
            }
            hex64("a key broker's grant-signing key", key)?;
        }
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
        Architecture::parse(&self.base_model.architecture)?.check(self)?;
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
                (Some(_), Some(0), _) => {
                    return Err(bad(format!(
                        "{}'s public number of privacy units is zero",
                        d.asset_id
                    )))
                }
                (Some(c), _, g) => match (c.grouping.as_str(), g) {
                    ("unit_ids", Some(g)) => hex64("grouping digest", g)?,
                    ("none", None) => {}
                    _ => {
                        return Err(bad(format!(
                            "{}'s grouping does not match the DP-SGD grouping {}",
                            d.asset_id, c.grouping
                        )))
                    }
                },
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

    /// `SHA256("encompute.training-config.v1" || 0x00 || canonical
    /// config)`: what a worker's evidence says it trained with.
    pub fn config_digest(&self) -> Result<String> {
        Ok(tagged_hex(CONFIG, &[&canonical_json(&self.config)?]))
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
        // Keys go only to a workload bound to the spec's DP configuration.
        p.privacy_policy_id = self.privacy_policy_id.clone();
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
