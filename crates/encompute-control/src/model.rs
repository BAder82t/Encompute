//! Control-plane objects and the v1 API's JSON contracts.
//!
//! These are intentional API types, not internal Rust structures: they
//! change only with a new API version.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use encompute_ir::{Code, Error, Result};
use encompute_verification::hex;

/// The reserved organization whose admins operate the platform (create
/// organizations, register platform services).
pub const PLATFORM_ORG: &str = "platform";

pub fn bad(msg: impl Into<String>) -> Error {
    Error::new(Code::BadInput, msg)
}

/// A random ID with a type prefix, e.g. `job_3f9a…`.
pub fn new_id(prefix: &str) -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("operating-system randomness");
    format!("{prefix}_{}", hex(&b))
}

/// Organization IDs are readable slugs: `hospital-a`.
pub fn check_slug(what: &str, s: &str) -> Result<()> {
    if s.len() < 2
        || s.len() > 63
        || !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || s.starts_with('-')
        || s.ends_with('-')
    {
        return Err(bad(format!(
            "{what} {s:?} must be 2-63 characters of a-z, 0-9 and - (not at the ends)"
        )));
    }
    Ok(())
}

/// Free-text names: bounded, printable.
pub fn check_name(what: &str, s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 200 || s.chars().any(|c| c.is_control()) {
        return Err(bad(format!("{what} must be 1-200 printable characters")));
    }
    Ok(())
}

/// Lowercase hex SHA-256 digests.
pub fn check_digest(what: &str, s: &str) -> Result<()> {
    let h = s.strip_prefix("sha256:").unwrap_or(s);
    if h.len() != 64
        || !h
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(bad(format!(
            "{what} must be a lowercase hex SHA-256 digest"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    OrganizationAdmin,
    SecurityAdmin,
    DataOwner,
    ModelOwner,
    MlDeveloper,
    Auditor,
    Operator,
}

impl Role {
    pub const ALL: [Role; 7] = [
        Role::OrganizationAdmin,
        Role::SecurityAdmin,
        Role::DataOwner,
        Role::ModelOwner,
        Role::MlDeveloper,
        Role::Auditor,
        Role::Operator,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::OrganizationAdmin => "organization_admin",
            Role::SecurityAdmin => "security_admin",
            Role::DataOwner => "data_owner",
            Role::ModelOwner => "model_owner",
            Role::MlDeveloper => "ml_developer",
            Role::Auditor => "auditor",
            Role::Operator => "operator",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Role::ALL
            .into_iter()
            .find(|r| r.as_str() == s)
            .ok_or_else(|| bad(format!("unknown role {s:?}")))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    Control,
    Evaluator,
    Secagg,
    Keybroker,
    Automation,
}

impl ServiceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceKind::Control => "control",
            ServiceKind::Evaluator => "evaluator",
            ServiceKind::Secagg => "secagg",
            ServiceKind::Keybroker => "keybroker",
            ServiceKind::Automation => "automation",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        [
            ServiceKind::Control,
            ServiceKind::Evaluator,
            ServiceKind::Secagg,
            ServiceKind::Keybroker,
            ServiceKind::Automation,
        ]
        .into_iter()
        .find(|k| k.as_str() == s)
        .ok_or_else(|| bad(format!("unknown service kind {s:?}")))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Dataset,
    Model,
    Adapter,
    Checkpoint,
    Program,
    Artifact,
}

impl AssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AssetKind::Dataset => "dataset",
            AssetKind::Model => "model",
            AssetKind::Adapter => "adapter",
            AssetKind::Checkpoint => "checkpoint",
            AssetKind::Program => "program",
            AssetKind::Artifact => "artifact",
        }
    }
}

// --- job states -------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Created,
    Planning,
    Planned,
    WaitingForApproval,
    Authorized,
    Queued,
    Running,
    Verifying,
    Succeeded,
    Failed,
    Cancelled,
}

impl JobState {
    pub const ALL: [JobState; 11] = [
        JobState::Created,
        JobState::Planning,
        JobState::Planned,
        JobState::WaitingForApproval,
        JobState::Authorized,
        JobState::Queued,
        JobState::Running,
        JobState::Verifying,
        JobState::Succeeded,
        JobState::Failed,
        JobState::Cancelled,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            JobState::Created => "created",
            JobState::Planning => "planning",
            JobState::Planned => "planned",
            JobState::WaitingForApproval => "waiting_for_approval",
            JobState::Authorized => "authorized",
            JobState::Queued => "queued",
            JobState::Running => "running",
            JobState::Verifying => "verifying",
            JobState::Succeeded => "succeeded",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        JobState::ALL
            .into_iter()
            .find(|j| j.as_str() == s)
            .ok_or_else(|| bad(format!("unknown job state {s:?}")))
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            JobState::Succeeded | JobState::Failed | JobState::Cancelled
        )
    }

    /// The only legal transitions. Everything else is ENC2604.
    pub fn can_go_to(self, to: JobState) -> bool {
        use JobState::*;
        match (self, to) {
            (Created, Planning) | (Planning, Planned) => true,
            (Planned, WaitingForApproval) | (Planned, Authorized) => true,
            (WaitingForApproval, Authorized) => true,
            (Authorized, Queued) | (Queued, Running) | (Running, Verifying) => true,
            (Verifying, Succeeded) => true,
            // Any live job can fail or be cancelled; finished ones cannot.
            (from, Failed) | (from, Cancelled) => !from.is_terminal(),
            _ => false,
        }
    }
}

// --- API requests -----------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOrganization {
    pub id: String,
    pub display_name: String,
    /// The organization's first admin (an OIDC identity). Platform admins
    /// create organizations but get no access inside them.
    #[serde(default)]
    pub admin: Option<FirstAdmin>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstAdmin {
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUser {
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub email: Option<String>,
    pub roles: Vec<Role>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateServiceAccount {
    pub id: String,
    pub kind: ServiceKind,
    pub public_key: String,
    #[serde(default)]
    pub roles: Vec<Role>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProject {
    pub organization: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddProjectMember {
    pub organization: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterAsset {
    pub organization: String,
    pub kind: AssetKind,
    pub name: String,
    pub digest: String,
    #[serde(default)]
    pub size_bytes: Option<i64>,
    #[serde(default)]
    pub media_type: Option<String>,
    #[serde(default)]
    pub storage_uri: Option<String>,
    /// The asset's release policy (who may learn it, for which purposes).
    #[serde(default)]
    pub policy: serde_json::Value,
    /// Parent assets (lineage).
    #[serde(default)]
    pub parents: Vec<String>,
    /// Wrapped-key reference (provider, key ref, version, broker); never key
    /// material.
    #[serde(default)]
    pub key_ref: Option<KeyRef>,
    /// A privacy budget for the asset: creates its privacy ledger.
    #[serde(default)]
    pub privacy_budget: Option<encompute_ir::confidentiality::PrivacyBudget>,
}

/// Where an asset's key lives. Only references: the key broker holds the
/// wrapped material, and the customer's KMS holds the root key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRef {
    pub broker: String,
    pub provider: String,
    pub key_ref: String,
    pub key_version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveAsset {
    pub project: String,
    pub purpose: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePlan {
    pub project: String,
    /// The program (`.eir` text).
    pub program: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitJob {
    pub project: String,
    pub plan: String,
    pub purpose: String,
    #[serde(default)]
    pub source_assets: Vec<String>,
    pub requested_output: String,
    #[serde(default)]
    pub policy: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteJob {
    /// The evaluator's signed receipt (canonical JSON).
    pub receipt: serde_json::Value,
    /// The client's commitments to the exact request and response bytes.
    pub request_commitment: String,
    pub output_commitment: String,
    pub key_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterEvaluator {
    pub id: String,
    pub url: String,
    /// The evaluator's receipt-signing public key (hex).
    pub receipt_key: String,
    /// Backends it runs, e.g. `openfhe`, `openfhe-exact`.
    pub backends: Vec<String>,
    /// Parameter profiles it supports, e.g. `BINFHE_STD128_GINX_BITS_V1`,
    /// `CKKS` (any vetted CKKS parameters).
    pub profiles: Vec<String>,
    pub openfhe_version: String,
    pub capacity: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorStatus {
    pub status: String,
}

pub use encompute_verification::service::{
    JobGrant, MessageEnvelope, MessageStatement, JOB_GRANT_TTL_SECS, JOB_GRANT_VERSION,
    MESSAGE_PROTOCOL,
};

/// Selected response shapes.
#[derive(Debug, Serialize)]
pub struct JobView {
    pub id: String,
    pub organization: String,
    pub project: String,
    pub plan: String,
    pub spec_id: String,
    pub program_id: String,
    pub purpose: String,
    pub source_assets: Vec<String>,
    pub requested_output: String,
    pub scheme: String,
    pub backend: String,
    pub profile: String,
    pub state: JobState,
    pub evaluator: Option<String>,
    pub evaluator_url: Option<String>,
    /// The receipt key the evaluator registered: clients verify receipts
    /// against it.
    pub evaluator_receipt_key: Option<String>,
    pub grant: Option<JobGrant>,
    pub error: Option<String>,
    pub initiated_by: String,
    pub transitions: Vec<BTreeMap<String, String>>,
}
