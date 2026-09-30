//! Governed-project identities (public-sector governance).
//!
//! A governed project computes across institutions for one declared
//! purpose. What an execution in it is bound to has content-addressed
//! identities, each `SHA256(domain || 0x00 || canonical JSON)`:
//!
//! - [`PurposeId`] (`encompute.purpose.v1`, shown `encpurpose1:`): the
//!   purpose, its project, allowed modes, release classes, recipients and
//!   validity window. Editing a purpose is a new revision with a new ID.
//! - [`GovernanceId`] (`encompute.governance-binding.v1`, `encgov1:`): the
//!   project, purpose, linkage policy, the exact input versions (with their
//!   owners) and each output's release class and recipients. The execution
//!   spec carries it ([`crate::ExecutionSpec::governed`]), so the spec ID,
//!   and everything bound to the spec, changes with any of them.
//! - [`ProgramSetId`] (`encompute.program-set.v1`, `encprogset1:`): a
//!   sorted, duplicate-free set of program IDs. An owner authorizes one
//!   program or one such set: never a pattern or wildcard.
//! - [`AssetVersionId`] (`encompute.asset-version.v1`, `encassetv1:`): one
//!   immutable version of a dataset series.
//!
//! Absent optional fields are not serialized, so adding one later keeps
//! every existing ID.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use encompute_ir::confidentiality::ReleaseForm;
use encompute_ir::{Code, Error, Result};

use crate::canonical::canonical_json;
use crate::hash::{hex, tagged, unhex};

pub const PURPOSE_VERSION: u32 = 1;
pub const GOVERNANCE_BINDING_VERSION: u32 = 1;
pub const PROGRAM_SET_VERSION: u32 = 1;
pub const ASSET_VERSION_VERSION: u32 = 1;

pub(crate) const PURPOSE: &str = "encompute.purpose.v1";
pub(crate) const GOVERNANCE: &str = "encompute.governance-binding.v1";
pub(crate) const PROGRAM_SET: &str = "encompute.program-set.v1";
pub(crate) const ASSET_VERSION: &str = "encompute.asset-version.v1";

fn bad(msg: impl Into<String>) -> Error {
    Error::new(Code::BadInput, msg)
}

/// Whether `s` is 32 bytes of lowercase hex (an ID or digest).
pub fn is_hex32(s: &str) -> bool {
    s.len() == 64 && unhex(s).is_some()
}

fn check_hex32(what: &str, s: &str) -> Result<()> {
    if is_hex32(s) {
        Ok(())
    } else {
        Err(bad(format!("{what} must be 32 bytes of lowercase hex")))
    }
}

/// Short printable labels (names, organizations, recipients).
fn check_label(what: &str, s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 200 || s.chars().any(|c| c.is_control()) {
        return Err(bad(format!("{what} must be 1-200 printable characters")));
    }
    Ok(())
}

macro_rules! content_id {
    ($name:ident, $display:literal) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            /// Lowercase hex, as stored and transmitted.
            pub fn hex(&self) -> String {
                hex(&self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($display, ":{}"), self.hex())
            }
        }
    };
}

content_id!(PurposeId, "encpurpose1");
content_id!(GovernanceId, "encgov1");
content_id!(ProgramSetId, "encprogset1");
content_id!(AssetVersionId, "encassetv1");

fn id_of<T: Serialize>(domain: &str, v: &T) -> [u8; 32] {
    tagged(
        domain,
        &canonical_json(v).expect("strings, integers and sets only"),
    )
}

/// How a purpose computes across its sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurposeMode {
    /// Per-subject exact answers over linked records (needs a linkage
    /// policy).
    RecordLevelExact,
    /// Aggregates (statistics, secure aggregation, DP).
    Aggregate,
    /// Confidential model collaboration (training, inference).
    ModelCollaboration,
}

/// What may be released, to whom and in which form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseClass {
    Never,
    BooleanOnly,
    AggregateOnly,
    DpAggregateOnly,
    AuthorizedAgencyOnly,
    DerivedArtifactOnly,
}

impl ReleaseClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ReleaseClass::Never => "never",
            ReleaseClass::BooleanOnly => "boolean-only",
            ReleaseClass::AggregateOnly => "aggregate-only",
            ReleaseClass::DpAggregateOnly => "dp-aggregate-only",
            ReleaseClass::AuthorizedAgencyOnly => "authorized-agency-only",
            ReleaseClass::DerivedArtifactOnly => "derived-artifact-only",
        }
    }

    pub const ALL: [ReleaseClass; 6] = [
        ReleaseClass::Never,
        ReleaseClass::BooleanOnly,
        ReleaseClass::AggregateOnly,
        ReleaseClass::DpAggregateOnly,
        ReleaseClass::AuthorizedAgencyOnly,
        ReleaseClass::DerivedArtifactOnly,
    ];

    /// Whether a release of class `self` stays within `ceiling`, the class
    /// an owner (or a purpose) allows. The owners' order, a partial order:
    /// every class is within itself; boolean-only, aggregate-only and
    /// dp-aggregate-only are within authorized-agency-only;
    /// dp-aggregate-only is within aggregate-only; derived-artifact-only
    /// and never are within only themselves. The control plane (at
    /// submission) and the key broker (at key release) both decide with
    /// this one function.
    pub fn within(self, ceiling: ReleaseClass) -> bool {
        use ReleaseClass::*;
        self == ceiling
            || matches!(
                (self, ceiling),
                (
                    BooleanOnly | AggregateOnly | DpAggregateOnly,
                    AuthorizedAgencyOnly
                ) | (DpAggregateOnly, AggregateOnly)
            )
    }

    /// Whether this class allows a release in form `f`: boolean-only a
    /// boolean or a bounded category; aggregate-only an aggregate, with or
    /// without differential privacy; dp-aggregate-only a DP aggregate;
    /// derived-artifact-only a derived artifact; authorized-agency-only
    /// any form; never none (it releases nothing).
    pub fn allows_form(self, f: ReleaseForm) -> bool {
        match self {
            ReleaseClass::Never => false,
            ReleaseClass::BooleanOnly => {
                matches!(
                    f,
                    ReleaseForm::Boolean | ReleaseForm::BoundedCategory { .. }
                )
            }
            ReleaseClass::AggregateOnly => {
                matches!(f, ReleaseForm::Aggregate | ReleaseForm::DpAggregate)
            }
            ReleaseClass::DpAggregateOnly => f == ReleaseForm::DpAggregate,
            ReleaseClass::AuthorizedAgencyOnly => true,
            ReleaseClass::DerivedArtifactOnly => f == ReleaseForm::DerivedArtifact,
        }
    }

    /// Whether an output that provably takes forms `provable` may be
    /// released under this class: authorized-agency-only releases any
    /// value to its recipients, never releases nothing (the output stays
    /// sealed); every other class needs a provable form it allows.
    pub fn admits(self, provable: &BTreeSet<ReleaseForm>) -> bool {
        match self {
            ReleaseClass::Never | ReleaseClass::AuthorizedAgencyOnly => true,
            c => provable.iter().any(|&f| c.allows_form(f)),
        }
    }
}

/// Whether an output requested at class `requested` is allowed under
/// `ceiling`, an owner authorization's release class: within it, or never
/// released at all (sealed). The one check the control plane and the key
/// broker share.
pub fn release_within(requested: ReleaseClass, ceiling: ReleaseClass) -> bool {
    requested == ReleaseClass::Never || requested.within(ceiling)
}

/// A declared purpose of a governed project. `name` is what programs
/// declare (`Confidentiality.purpose`). The window is strict:
/// `valid_from <= t < valid_until`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Purpose {
    pub version: u32,
    pub project_id: String,
    pub name: String,
    pub revision: u32,
    pub description: String,
    /// An opaque label for the legal basis; never interpreted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_basis_ref: Option<String>,
    pub modes: BTreeSet<PurposeMode>,
    pub allowed_release_classes: BTreeSet<ReleaseClass>,
    /// Organizations that may receive results.
    pub recipients: BTreeSet<String>,
    /// Hex `LinkageId`; required for record-level exact computation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linkage_policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_aggregate_parties: Option<u32>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub created_by_org: String,
}

impl Purpose {
    pub fn id(&self) -> PurposeId {
        PurposeId(id_of(PURPOSE, self))
    }

    /// Well formed: a known version, names, at least one mode, class and
    /// recipient, a non-empty window, and a linkage policy for record-level
    /// exact computation.
    pub fn check(&self) -> Result<()> {
        if self.version != PURPOSE_VERSION {
            return Err(bad(format!("purpose version {}", self.version)));
        }
        check_label("purpose project", &self.project_id)?;
        check_label("purpose name", &self.name)?;
        check_label("purpose organization", &self.created_by_org)?;
        if self.description.len() > 2000 || self.description.chars().any(|c| c.is_control()) {
            return Err(bad(
                "a purpose description is at most 2000 printable characters",
            ));
        }
        if let Some(l) = &self.legal_basis_ref {
            check_label("legal basis reference", l)?;
        }
        if self.revision == 0 {
            return Err(bad("purpose revisions start at 1"));
        }
        if self.modes.is_empty() {
            return Err(bad("a purpose names at least one mode"));
        }
        if self.allowed_release_classes.is_empty() {
            return Err(bad("a purpose names at least one release class"));
        }
        if self.recipients.is_empty() {
            return Err(bad("a purpose names at least one recipient"));
        }
        for r in &self.recipients {
            check_label("recipient", r)?;
        }
        if let Some(l) = &self.linkage_policy_id {
            check_hex32("linkage policy ID", l)?;
        }
        if self.modes.contains(&PurposeMode::RecordLevelExact) && self.linkage_policy_id.is_none() {
            return Err(bad("record-level exact computation needs a linkage policy"));
        }
        if self.min_aggregate_parties.is_some_and(|m| m < 2) {
            return Err(bad("an aggregate needs at least 2 parties"));
        }
        if self.valid_from >= self.valid_until {
            return Err(bad("a purpose's window must end after it starts"));
        }
        Ok(())
    }

    /// Strict: `valid_from <= t < valid_until`, no margin.
    pub fn is_valid_at(&self, t: u64) -> bool {
        self.valid_from <= t && t < self.valid_until
    }
}

/// One source of a governed execution: the exact version, a (salted)
/// commitment to its digest, and its owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceInput {
    pub asset_version_id: String,
    pub digest_commitment: String,
    pub organization: String,
}

/// One output: its release class and recipients.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceOutput {
    pub release_class: ReleaseClass,
    pub recipients: BTreeSet<String>,
}

/// Everything a governed execution is bound to beyond its program and
/// policy. Authorization IDs are deliberately absent: reissuing an
/// authorization must not change what is computed (they are in the grant).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceBinding {
    pub version: u32,
    pub project: String,
    pub purpose_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linkage_policy_id: Option<String>,
    /// Program input name → source.
    pub inputs: BTreeMap<String, GovernanceInput>,
    /// Program output name → release.
    pub outputs: BTreeMap<String, GovernanceOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_policy_digest: Option<String>,
    /// Per-source broker binding: asset version ID (as in `inputs`) -> the
    /// key broker that holds its key. Keyed by version, never by the
    /// owner's key reference, so the map (carried in grants and tickets
    /// other organizations see) names no KMS key. A governed broker
    /// refuses to release the key of a version this map gives to another
    /// broker, or leaves out. Empty (and then not
    /// serialized, so existing GovernanceIds are unchanged): no binding.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub asset_brokers: BTreeMap<String, String>,
}

impl GovernanceBinding {
    pub fn id(&self) -> GovernanceId {
        GovernanceId(id_of(GOVERNANCE, self))
    }

    pub fn check(&self) -> Result<()> {
        if self.version != GOVERNANCE_BINDING_VERSION {
            return Err(bad(format!("governance binding version {}", self.version)));
        }
        check_label("project", &self.project)?;
        check_hex32("purpose ID", &self.purpose_id)?;
        for d in [
            &self.linkage_policy_id,
            &self.placement_digest,
            &self.project_policy_digest,
        ]
        .into_iter()
        .flatten()
        {
            check_hex32("governance digest", d)?;
        }
        if self.inputs.is_empty() {
            return Err(bad("a governed execution has at least one source"));
        }
        for (name, i) in &self.inputs {
            check_label("input", name)?;
            check_hex32("asset version ID", &i.asset_version_id)?;
            check_hex32("digest commitment", &i.digest_commitment)?;
            check_label("input organization", &i.organization)?;
        }
        for (version, broker) in &self.asset_brokers {
            check_hex32("asset version ID", version)?;
            check_label("key broker", broker)?;
        }
        for (name, o) in &self.outputs {
            check_label("output", name)?;
            if o.recipients.is_empty() && o.release_class != ReleaseClass::Never {
                return Err(bad(format!("output {name} has no recipient")));
            }
            // Released to nobody means nobody: no recipient could be named
            // in a ticket or an export for it.
            if o.release_class == ReleaseClass::Never && !o.recipients.is_empty() {
                return Err(bad(format!(
                    "output {name} is never released: it names no recipient"
                )));
            }
            for r in &o.recipients {
                check_label("recipient", r)?;
            }
        }
        Ok(())
    }
}

impl ProgramSetId {
    /// The ID of a set of program IDs: sorted, each once, never empty.
    pub fn of<I, S>(programs: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut set = BTreeSet::new();
        for p in programs {
            let p = p.into();
            check_hex32("program ID", &p)?;
            if !set.insert(p) {
                return Err(bad("a program set names each program once"));
            }
        }
        Self::of_set(&set)
    }

    fn of_set(set: &BTreeSet<String>) -> Result<Self> {
        if set.is_empty() {
            return Err(bad("a program set is never empty"));
        }
        #[derive(Serialize)]
        struct Canonical<'a> {
            version: u32,
            programs: &'a BTreeSet<String>,
        }
        Ok(Self(id_of(
            PROGRAM_SET,
            &Canonical {
                version: PROGRAM_SET_VERSION,
                programs: set,
            },
        )))
    }
}

/// What an owner authorizes: one program, or one content-addressed set
/// (whose members travel with it, so anyone can check its ID). Never a
/// pattern.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProgramRef {
    Program {
        program_id: String,
    },
    ProgramSet {
        program_set_id: String,
        programs: BTreeSet<String>,
    },
}

impl ProgramRef {
    pub fn check(&self) -> Result<()> {
        match self {
            ProgramRef::Program { program_id } => check_hex32("program ID", program_id),
            ProgramRef::ProgramSet {
                program_set_id,
                programs,
            } => {
                for p in programs {
                    check_hex32("program ID", p)?;
                }
                if ProgramSetId::of_set(programs)?.hex() != *program_set_id {
                    return Err(Error::new(
                        Code::GovernanceProgramNotAuthorized,
                        "the program set's members do not match its ID",
                    ));
                }
                Ok(())
            }
        }
    }

    /// Whether `program_id` is authorized (exact match only).
    pub fn covers(&self, program_id: &str) -> bool {
        match self {
            ProgramRef::Program { program_id: p } => p == program_id,
            ProgramRef::ProgramSet { programs, .. } => programs.contains(program_id),
        }
    }
}

/// One immutable version of a dataset series (`series@label`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetVersion {
    pub version: u32,
    pub organization: String,
    pub series: String,
    pub label: String,
    /// The asset's registered digest.
    pub digest: String,
}

impl AssetVersion {
    pub fn id(&self) -> AssetVersionId {
        AssetVersionId(id_of(ASSET_VERSION, self))
    }

    pub fn check(&self) -> Result<()> {
        if self.version != ASSET_VERSION_VERSION {
            return Err(bad(format!(
                "asset version record version {}",
                self.version
            )));
        }
        check_label("organization", &self.organization)?;
        for (what, s) in [("series", &self.series), ("version", &self.label)] {
            check_label(what, s)?;
            if s.contains('@') || s.chars().any(char::is_whitespace) {
                return Err(bad(format!("an asset {what} has no '@' or whitespace")));
            }
        }
        let d = self.digest.strip_prefix("sha256:").unwrap_or(&self.digest);
        check_hex32("asset digest", d)
    }

    /// The asset name of this version: `series@label`.
    pub fn name(&self) -> String {
        format!("{}@{}", self.series, self.label)
    }
}

/// The governance part of a v2 job grant (governed projects only): the
/// plan's real PlanId, the purpose, the full binding (so the evaluator can
/// recompute the governed spec), the authorization set and the strict end
/// of every authorization, purpose and asset window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantGovernance {
    pub plan_hash: String,
    pub purpose_id: String,
    pub governance_id: String,
    pub binding: GovernanceBinding,
    pub authorization_set_id: String,
    /// `min(authorizations' valid_until, purpose valid_until, ...)`: the
    /// grant is dead at this second (strict).
    pub not_after: u64,
}

impl GrantGovernance {
    /// Consistent with itself and with the grant naming `project`.
    pub fn check(&self, project: &str) -> Result<()> {
        self.binding.check()?;
        check_hex32("plan hash", &self.plan_hash)?;
        check_hex32("authorization set ID", &self.authorization_set_id)?;
        if self.binding.id().hex() != self.governance_id {
            return Err(bad("the grant's binding is not its governance ID"));
        }
        if self.binding.purpose_id != self.purpose_id {
            return Err(Error::new(
                Code::GovernancePurposeMismatch,
                "the grant's binding is for another purpose",
            ));
        }
        if self.binding.project != project {
            return Err(Error::new(
                Code::GovernancePurposeMismatch,
                "the grant's binding is for another project",
            ));
        }
        Ok(())
    }
}
