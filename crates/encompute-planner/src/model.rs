//! The planner's vocabulary: what must be true (requirements), what can
//! make it true (mechanisms), what is available (context), and the plan.
//! Everything here is canonical JSON (no floats), so a plan has one ID.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Someone who might see data.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
pub enum Principal {
    /// A declared party.
    Party(String),
    /// Whoever operates the machines a step runs on (cloud, host OS,
    /// administrators), unless it runs at a party that may see the data.
    ComputeHost,
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Principal::Party(p) => f.write_str(p),
            Principal::ComputeHost => f.write_str("the compute host"),
        }
    }
}

/// What must be true: never how to make it true.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "requirement", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustRequirement {
    /// `principal` must not be able to read `asset`.
    HideFrom { asset: String, principal: Principal },
    /// `asset` leaves only inside the aggregate `output`: no individual
    /// contribution is ever revealed.
    AggregateOnly { asset: String, output: String },
    /// `asset` may be used only for `purpose`.
    Purpose { asset: String, purpose: String },
    /// Releases derived from `asset` stay within its declared budget.
    PrivacyBudget {
        asset: String,
        unit: String,
        epsilon: String,
        delta: String,
    },
    /// The workload running `step` must prove its identity.
    RequireAttestation { step: String },
    /// `step`'s result must be verifiably correct.
    RequireCorrectness { step: String },
    /// `output` is released only with at least `minimum` contributors.
    MinimumParticipants { output: String, minimum: usize },
    /// Every step runs in `region`.
    ExecutionRegion { region: String },
    /// Every execution is recorded with signed evidence.
    SignedEvidence,
}

/// Encrypted computation scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    Ckks,
    /// TFHE-rs (research builds only).
    Tfhe,
    Bgv,
    /// OpenFHE BinFHE gate circuits: production exact programs.
    BinFhe,
}

/// Something Encompute already has that makes requirements true.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "mechanism", rename_all = "snake_case", deny_unknown_fields)]
pub enum Mechanism {
    /// Compile-time flow, purpose and release checks (ADR-010).
    PolicyEnforcement,
    /// Owners sign approval of the program (ADR-014).
    OwnerAuthorization,
    /// Signed execution, aggregation and privacy receipts.
    SignedReceipts,
    /// Computation on ciphertexts; the host sees only ciphertexts.
    Fhe { scheme: Scheme, backend: String },
    /// Re-execution proofs of the exact computation (ADR-009).
    VerifiedExecution,
    /// A TEE protects the workload's memory from its host.
    ConfidentialCompute { tee: String, provider: String },
    /// Hardware attestation of the workload's identity (ADR-011).
    Attestation { provider: String },
    /// Keys released only to the attested workload (ADR-011).
    AttestedKeyRelease,
    /// Bonawitz secure aggregation: only the sum is revealed (ADR-012).
    SecureAggregation { threshold: usize, colluding: usize },
    /// Discrete Gaussian noise on the release, budgets in a ledger
    /// (ADR-013).
    DifferentialPrivacy {
        noise_multiplier: String,
        clip_norm: String,
        /// DP-SGD: the Poisson sampling rate of the privacy units, each
        /// clipped separately (example level). Absent: each party's whole
        /// contribution is clipped (organization level).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sampling_rate: Option<String>,
    },
    /// The step runs at a party allowed to see everything it reads.
    LocalExecution { party: String },
}

impl Mechanism {
    pub fn name(&self) -> String {
        match self {
            Mechanism::PolicyEnforcement => "policy enforcement".into(),
            Mechanism::OwnerAuthorization => "owner authorization".into(),
            Mechanism::SignedReceipts => "signed receipts".into(),
            Mechanism::Fhe { scheme, backend } => format!(
                "FHE ({}, {backend})",
                match scheme {
                    Scheme::Ckks => "CKKS",
                    Scheme::Tfhe => "TFHE",
                    Scheme::Bgv => "BGV",
                    Scheme::BinFhe => "BinFHE",
                }
            ),
            Mechanism::VerifiedExecution => "verified execution (re-execution proofs)".into(),
            Mechanism::ConfidentialCompute { tee, provider } => {
                format!("confidential compute ({tee}, {provider})")
            }
            Mechanism::Attestation { provider } => format!("attestation ({provider})"),
            Mechanism::AttestedKeyRelease => "attestation-gated key release".into(),
            Mechanism::SecureAggregation {
                threshold,
                colluding,
            } => format!("secure aggregation (threshold {threshold}, colluding ≤ {colluding})"),
            Mechanism::DifferentialPrivacy {
                noise_multiplier,
                clip_norm,
                sampling_rate: None,
            } => format!(
                "differential privacy (discrete Gaussian, noise {noise_multiplier}, clip \
                 {clip_norm})"
            ),
            Mechanism::DifferentialPrivacy {
                noise_multiplier,
                clip_norm,
                sampling_rate: Some(q),
            } => format!(
                "differential privacy, example level (DP-SGD: per-example clip {clip_norm}, \
                 Poisson sampling {q}, discrete Gaussian noise {noise_multiplier})"
            ),
            Mechanism::LocalExecution { party } => format!("local execution at {party}"),
        }
    }

    /// The evidence this mechanism leaves.
    pub fn evidence(&self) -> Vec<EvidenceKind> {
        match self {
            Mechanism::OwnerAuthorization => vec![EvidenceKind::OwnerAuthorization],
            Mechanism::Fhe { .. } => vec![EvidenceKind::ExecutionReceipt],
            Mechanism::VerifiedExecution => {
                vec![EvidenceKind::ExecutionReceipt, EvidenceKind::ExecutionProof]
            }
            Mechanism::ConfidentialCompute { .. } | Mechanism::Attestation { .. } => {
                vec![EvidenceKind::AttestationRecord]
            }
            Mechanism::AttestedKeyRelease => vec![EvidenceKind::KeyGrant],
            Mechanism::SecureAggregation { .. } => vec![EvidenceKind::AggregationReceipt],
            Mechanism::DifferentialPrivacy { .. } => vec![EvidenceKind::PrivacyReceipt],
            Mechanism::PolicyEnforcement
            | Mechanism::SignedReceipts
            | Mechanism::LocalExecution { .. } => vec![],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    OwnerAuthorization,
    ExecutionReceipt,
    ExecutionProof,
    AttestationRecord,
    KeyGrant,
    AggregationReceipt,
    PrivacyReceipt,
}

impl EvidenceKind {
    pub fn name(self) -> &'static str {
        match self {
            EvidenceKind::OwnerAuthorization => "OwnerAuthorization",
            EvidenceKind::ExecutionReceipt => "ExecutionReceipt",
            EvidenceKind::ExecutionProof => "ExecutionProof",
            EvidenceKind::AttestationRecord => "AttestationRecord",
            EvidenceKind::KeyGrant => "KeyGrant",
            EvidenceKind::AggregationReceipt => "AggregationReceipt",
            EvidenceKind::PrivacyReceipt => "PrivacyReceipt",
        }
    }
}

/// Encrypted backends this installation can run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendCatalog {
    /// CKKS on OpenFHE.
    pub ckks: bool,
    /// Exact programs on TFHE-rs (research builds only).
    pub tfhe: bool,
    /// Exact programs on OpenFHE BinFHE (production).
    #[serde(default)]
    pub openfhe_exact: bool,
    /// Exact programs on OpenFHE BGV.
    pub bgv: bool,
    /// Re-execution proofs on BGV (research build).
    pub verified_execution: bool,
}

/// A trusted execution environment on offer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeeOffer {
    /// `intel-tdx`, `amd-sev-snp`, `nvidia-cc`, `mock`.
    pub tee: String,
    /// Attestation provider: `gcp-confidential-space` or `mock`.
    pub provider: String,
    #[serde(default)]
    pub gpu: bool,
    /// Only debug-mode workloads (memory readable by the host).
    #[serde(default)]
    pub debug_only: bool,
    /// Runs outside the planning party's premises.
    #[serde(default)]
    pub cloud: bool,
    #[serde(default)]
    pub region: Option<String>,
}

/// What infrastructure exists.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Infrastructure {
    #[serde(default)]
    pub tees: Vec<TeeOffer>,
    /// An Encompute key broker the owners run (attested key release).
    #[serde(default)]
    pub key_broker: bool,
    /// Ordinary (untrusted) hosts are in the cloud.
    #[serde(default)]
    pub host_cloud: bool,
    #[serde(default)]
    pub host_region: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Objective {
    #[default]
    Latency,
    Cost,
}

/// Soft preferences, and the hard ones a user may add.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    #[serde(default)]
    pub objective: Objective,
    /// Nothing runs in the cloud (hard).
    #[serde(default)]
    pub local_only: bool,
    /// Every step runs in this region (hard).
    #[serde(default)]
    pub region: Option<String>,
    /// Accept development-only (mock) attestation.
    #[serde(default)]
    pub allow_development: bool,
}

/// Security profile: presets that expand into visible requirements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// Policies enforced, aggregate-only and budgets enforced, signed
    /// receipts.
    #[default]
    Standard,
    /// Plus: every workload outside FHE or the owner's premises, and every
    /// aggregation coordinator, attested; verified execution where the
    /// program is covered.
    Strong,
    /// Plus: every computation verifiably correct; production attestation
    /// only.
    Maximum,
}

impl Profile {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "standard" => Some(Profile::Standard),
            "strong" => Some(Profile::Strong),
            "maximum" => Some(Profile::Maximum),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Profile::Standard => "standard",
            Profile::Strong => "strong",
            Profile::Maximum => "maximum",
        }
    }

    /// What the profile adds, in words.
    pub fn expands_to(self) -> &'static [&'static str] {
        match self {
            Profile::Standard => &[
                "confidentiality, purpose and release policies enforced",
                "aggregate-only assets through secure aggregation",
                "differential privacy wherever a budget is declared",
                "signed receipts for every execution",
            ],
            Profile::Strong => &[
                "everything in standard",
                "attestation for every workload outside FHE or the owner's premises",
                "attestation for every aggregation coordinator",
                "verified execution wherever the program is covered",
            ],
            Profile::Maximum => &[
                "everything in strong",
                "every computation verifiably correct",
                "production attestation only (no development evidence)",
            ],
        }
    }
}

/// Facts about the compiled program the planner cannot compute from the
/// IR alone (supplied by the runtime, which compiled it).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramFacts {
    /// `approximate` or `exact`.
    pub semantics: String,
    /// The program compiles to an encrypted plan.
    pub fhe_supported: bool,
    /// Every operation is covered by re-execution proofs.
    pub proof_covered: bool,
    /// Encrypted operations (for cost estimates).
    pub operations: u64,
}

/// Local training, declared by a project: each data owner's data and the
/// model meet, and only gradients (aggregate-only assets) leave.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingDeclaration {
    pub model: String,
    /// Data assets trained on, one step per asset.
    pub data: Vec<String>,
    /// The training must be verifiable. No execution proof covers general
    /// training, so this requires each training workload to be attested
    /// (integrity under the TEE's hardware trust), never less.
    #[serde(default)]
    pub verified: bool,
    /// The unit the training's privacy protects: `organization` (each
    /// participant's whole update clipped) or a unit inside a participant
    /// (`patient`, `user`, `record`), which needs per-example clipping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_unit: Option<String>,
    /// The training clips each privacy unit's gradient (DP-SGD).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub per_example_clipping: bool,
    /// The workload: `pytorch-reference` or
    /// `huggingface-sequence-classification`. Workload metadata, not a
    /// security mechanism: the mechanisms still follow from the policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
}

/// The training workloads Encompute supports.
pub const TRAINING_FRAMEWORKS: &[&str] =
    &["pytorch-reference", "huggingface-sequence-classification"];

/// Everything a plan was made from, carried in the plan so any verifier
/// can re-derive and check it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningContext {
    pub profile: Profile,
    pub catalog: BackendCatalog,
    pub infrastructure: Infrastructure,
    pub preferences: Preferences,
    pub facts: ProgramFacts,
    #[serde(default)]
    pub training: Option<TrainingDeclaration>,
}

/// Where a step runs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "at", content = "detail", rename_all = "snake_case")]
pub enum Placement {
    /// An ordinary machine the data owners do not trust.
    UntrustedHost,
    /// Inside a TEE.
    Tee(TeeOffer),
    /// At a party's own premises.
    Party(String),
    /// Distributed over the contributing parties and a coordinator.
    Parties,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StepKind {
    /// The program's computation.
    Evaluate,
    /// Training on one data asset with the model.
    Train { data: String, model: String },
    /// Aggregating an output from the parties' contributions.
    Aggregate { output: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionStep {
    pub id: String,
    pub kind: StepKind,
    /// Assets the step reads.
    pub assets: Vec<String>,
    pub placement: Placement,
    pub mechanisms: Vec<Mechanism>,
    /// Estimated, never guaranteed.
    pub estimated_ms: u64,
}

/// One requirement, and how the plan satisfies it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementSatisfaction {
    pub requirement: TrustRequirement,
    pub step: Option<String>,
    pub satisfied_by: Vec<Mechanism>,
    pub reason: String,
    pub evidence: Vec<EvidenceKind>,
}

/// What should happen, and why it satisfies every requirement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfidentialExecutionPlan {
    pub version: u32,
    pub program_id: String,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub privacy_policy_id: Option<String>,
    pub context: PlanningContext,
    pub requirements: Vec<TrustRequirement>,
    pub steps: Vec<ExecutionStep>,
    pub satisfaction: Vec<RequirementSatisfaction>,
    pub selected_mechanisms: BTreeSet<Mechanism>,
    pub evidence_required: BTreeSet<EvidenceKind>,
    /// Estimated, never guaranteed.
    pub estimated_ms: u64,
}

/// A candidate the planner considered for a step, for `explain --deep`
/// (not part of the plan or its ID).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub step: String,
    pub placement: Placement,
    pub mechanisms: Vec<Mechanism>,
    pub estimated_ms: u64,
    /// Why it was rejected; `None` for the selected one or a valid,
    /// costlier one.
    pub rejected: Option<String>,
    pub selected: bool,
}
