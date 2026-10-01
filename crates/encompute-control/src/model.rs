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

/// An artifact's storage URI (metadata the control plane never
/// dereferences, but clients may): printable, no whitespace or
/// backslashes, and no `..` path segment, even percent-encoded, so it
/// cannot point a consumer outside the location it names.
pub fn check_storage_uri(s: &str) -> Result<()> {
    check_name("storage_uri", s)?;
    let decoded = s
        .replace("%2e", ".")
        .replace("%2E", ".")
        .replace("%2f", "/")
        .replace("%2F", "/")
        .replace("%5c", "\\")
        .replace("%5C", "\\");
    if decoded.chars().any(|c| c.is_whitespace() || c == '\\')
        || decoded.split('/').any(|seg| seg == "..")
    {
        return Err(bad(
            "storage_uri must not contain whitespace, backslashes or '..' path segments",
        ));
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
            // A governed job whose per-job approvals stopped counting
            // before it was scheduled (an approver disabled, or no longer
            // holding the role) waits for approval again.
            (Authorized, WaitingForApproval) => true,
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
    /// `standard` (the default) or `governed`; immutable.
    #[serde(default)]
    pub governance: Option<GovernanceMode>,
    /// Organizations to invite; each one's admin accepts
    /// (`POST /v1/projects/{id}/members`).
    #[serde(default)]
    pub organizations: Vec<String>,
    /// Key custody, fixed by the mode: `sovereign` for a governed project
    /// (`standard` is refused), `standard` for a standard one.
    #[serde(default)]
    pub custody: Option<Custody>,
}

/// Who holds the keys of a project's sources. In sovereign custody every
/// source's key is held by a key broker its own organization registered
/// (`POST /v1/organizations/{org}/key-brokers`), never a platform broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Custody {
    Standard,
    Sovereign,
}

impl Custody {
    pub fn as_str(self) -> &'static str {
        match self {
            Custody::Standard => "standard",
            Custody::Sovereign => "sovereign",
        }
    }
}

/// An organization registers one of its own key-broker service accounts
/// as its key broker. Only public information: the key it signs grants
/// with, the kind of KMS behind it, the key namespace it serves, and where
/// it says it runs.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterKeyBroker {
    /// The broker's service-account ID (kind `keybroker`, of this
    /// organization).
    pub id: String,
    /// Hex Ed25519 key the broker signs key grants with.
    pub grant_public_key: String,
    /// The KMS behind the broker (`openbao-transit`, `aws-kms`, ...).
    pub provider_kind: String,
    /// The key namespace it serves in that KMS.
    pub key_ref_namespace: String,
    /// Where it says it runs (self-declared, never evidence): string
    /// fields such as `country` or `region`.
    #[serde(default)]
    pub location: serde_json::Map<String, serde_json::Value>,
}

/// The scheduled evaluator asks for a release ticket for one source.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestReleaseTicket {
    /// Hex `AssetVersionId` of the source whose key the workload needs.
    pub asset_version_id: String,
}

/// A recipient records a governed job's released result as a derived
/// asset it holds as custodian (a dataset version of its own).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterDerivedAsset {
    /// The job's output the result is.
    pub output: String,
    pub kind: AssetKind,
    /// The result's series and version label (its name is
    /// `series@version`).
    pub series: String,
    pub version: String,
    pub digest: String,
    /// The key at the custodian's own key broker.
    pub key_ref: KeyRef,
    /// The onward policy it is held under (the IR asset policy, in its
    /// canonical JSON form): never wider than its parents' registered
    /// policies joined.
    pub ir_policy: serde_json::Value,
    /// Its release class: within the output's, every parent's and every
    /// authorization's.
    pub release_class: encompute_verification::governance::ReleaseClass,
    /// The custodian's release record of it, signed with its governance
    /// key.
    pub release_record: encompute_trust::authz::SignedReleaseRecord,
}

/// The custodian asks for an export ticket of a derived result to one
/// recipient.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestExport {
    pub recipient: String,
    /// The export's release class (default: the result's own): within the
    /// result's and every ancestor authorization's.
    #[serde(default)]
    pub release_class: Option<encompute_verification::governance::ReleaseClass>,
}

/// A project's mode. A governed project computes across organizations for
/// declared purposes under owner-signed authorizations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceMode {
    #[default]
    Standard,
    Governed,
}

impl GovernanceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            GovernanceMode::Standard => "standard",
            GovernanceMode::Governed => "governed",
        }
    }
}

/// An organization's governance public key (hex Ed25519). The private key
/// stays in the organization's KMS or HSM.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposeGovernanceKey {
    pub public_key: String,
    #[serde(default)]
    pub kms_key_ref: Option<String>,
}

/// A purpose of a governed project (the control plane adds the project and
/// version, and computes the PurposeId).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposePurpose {
    /// The proposing member organization.
    pub organization: String,
    pub name: String,
    #[serde(default = "first_revision")]
    pub revision: u32,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub legal_basis_ref: Option<String>,
    pub modes: std::collections::BTreeSet<encompute_verification::governance::PurposeMode>,
    pub allowed_release_classes:
        std::collections::BTreeSet<encompute_verification::governance::ReleaseClass>,
    pub recipients: std::collections::BTreeSet<String>,
    #[serde(default)]
    pub linkage_policy_id: Option<String>,
    #[serde(default)]
    pub min_aggregate_parties: Option<u32>,
    pub valid_from: u64,
    pub valid_until: u64,
}

fn first_revision() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptPurpose {
    pub acceptance: encompute_trust::authz::SignedPurposeAcceptance,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposeAuthorization {
    /// The authorization, without approvals.
    pub body: encompute_trust::authz::AuthorizationV2,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveAuthorization {
    /// The role the approver approves in (one it holds).
    pub role: Role,
}

/// The owner's governance-key signature over the approved body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationSignature {
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeAuthorization {
    pub reason: String,
    /// The owner's signed revocation, when it has one (the key broker
    /// needs it).
    #[serde(default)]
    pub revocation: Option<encompute_trust::authz::SignedRevocationV2>,
    /// Governed projects: the owner's next signed revocation head, covering
    /// this revocation. Accepted together with it (both or neither);
    /// without one the revocation is recorded and the head is owed.
    #[serde(default)]
    pub revocation_head: Option<encompute_trust::govlog::SignedRevocationHead>,
}

/// Retiring a purpose: in a governed project, optionally with the
/// proposer's next signed revocation head (see [`RevokeAuthorization`]).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirePurpose {
    #[serde(default)]
    pub revocation_head: Option<encompute_trust::govlog::SignedRevocationHead>,
}

/// How an organization takes part in a project: as a member, or (governed
/// projects only) as an auditor organization, which reads the project's
/// shared records and changes nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Participation {
    #[default]
    Member,
    Auditor,
}

impl Participation {
    pub fn as_str(self) -> &'static str {
        match self {
            Participation::Member => "member",
            Participation::Auditor => "auditor",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "member" => Ok(Participation::Member),
            "auditor" => Ok(Participation::Auditor),
            _ => Err(bad(format!("unknown participation {s:?}"))),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddProjectMember {
    pub organization: String,
    /// Invitations only: `member` (the default) or `auditor`.
    #[serde(default)]
    pub participation: Option<Participation>,
}

/// Removes a principal's role in an organization (all its roles there when
/// `role` is absent).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveMembership {
    pub principal: String,
    #[serde(default)]
    pub role: Option<Role>,
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
    /// A dataset version: its series and version label (both or neither;
    /// the name is then `series@version`). A version is immutable.
    #[serde(default)]
    pub series: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    /// The project the asset is registered for. In a project with
    /// sovereign custody the asset's key must be held by a key broker the
    /// asset's own organization registered.
    #[serde(default)]
    pub project: Option<String>,
    /// A dataset version's deletion date (Unix seconds; versions only,
    /// never changed): no job uses the version from then on, and no grant
    /// outlives it.
    #[serde(default)]
    pub delete_after: Option<u64>,
    /// Until when the owner keeps a dataset version (Unix seconds;
    /// versions only, fixed): never after `delete_after`, which can then
    /// never be brought forward past it.
    #[serde(default)]
    pub retention_until: Option<u64>,
    /// Until when the evidence about a dataset version (receipts, audit,
    /// anchors, release records) is kept (Unix seconds; versions only): it
    /// may later be extended, never shortened.
    #[serde(default)]
    pub evidence_retention_until: Option<u64>,
    /// A dataset version's registered confidentiality policy (the IR
    /// asset policy, in its JSON form; versions only, never changed): a
    /// governed job's program declares a policy at least as strict for it.
    #[serde(default)]
    pub ir_policy: Option<serde_json::Value>,
    /// A dataset version's release-class ceiling (versions only, never
    /// changed): every output of a governed job reading it is within it.
    #[serde(default)]
    pub release_class: Option<encompute_verification::governance::ReleaseClass>,
}

/// An owner's change of a dataset version's retention: its deletion date
/// brought forward (never pushed back), its evidence retention extended
/// (never shortened). At least one.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRetention {
    #[serde(default)]
    pub delete_after: Option<u64>,
    #[serde(default)]
    pub evidence_retention_until: Option<u64>,
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

/// A privacy population: the hard cap on every release from one
/// organization's series of datasets (all versions, every project).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePopulation {
    pub organization: String,
    pub series: String,
    pub budget: encompute_ir::confidentiality::PrivacyBudget,
}

/// A proposed privacy scope: a share of a population for one project,
/// purpose (by name) and, optionally, program.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposeScope {
    pub population: String,
    pub project: String,
    pub purpose: String,
    #[serde(default)]
    pub program_id: Option<String>,
    /// The scope's cap, at the population's unit and delta: no more than
    /// the population's.
    pub epsilon: f64,
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
    /// Governed projects (required there, refused elsewhere): the active
    /// purpose the job runs for (its PurposeId, hex). Its name is
    /// `purpose`, and the program's declared purpose.
    #[serde(default)]
    pub purpose_id: Option<String>,
    /// Governed projects (required there, refused elsewhere): each program
    /// output's release class and recipients, within the purpose and every
    /// source's authorization.
    #[serde(default)]
    pub outputs: Option<BTreeMap<String, encompute_verification::governance::GovernanceOutput>>,
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
    /// The machine profile (all optional). Self-reported: it steers
    /// placement and estimates only, never a security decision.
    #[serde(default)]
    pub cpu_model: Option<String>,
    #[serde(default)]
    pub logical_cores: Option<i32>,
    #[serde(default)]
    pub memory_bytes: Option<i64>,
    /// The calibrated cost profile the evaluator was benchmarked under,
    /// e.g. `openfhe-1.5.1/apple-m3-max`.
    #[serde(default)]
    pub benchmark_profile: Option<String>,
    /// Worker threads the evaluator uses for one job's gates.
    #[serde(default)]
    pub max_parallel_gates: Option<i32>,
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
    /// The plan's work estimate: bootstrapped gates for exact programs, 0
    /// for CKKS or plans made before estimates existed.
    pub estimated_gates: u64,
    /// The scheduler's completion estimate on the chosen evaluator
    /// (milliseconds; its queue included), once scheduled.
    pub estimated_ms: Option<u64>,
    /// Worker threads the chosen evaluator uses per job (its advertised
    /// `max_parallel_gates`), when it said.
    pub evaluator_parallel_gates: Option<u32>,
    /// Governed projects: the purpose (PurposeId) the job runs for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose_id: Option<String>,
    /// Governed projects: the GovernanceId its execution spec carries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_id: Option<String>,
}
