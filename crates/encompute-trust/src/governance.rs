//! The cross-agency trust report (ADR-027): the governance rows of one
//! governed job, computed from signed evidence only.
//!
//! [`TrustGraph::governance_report`] runs the existing [`TrustGraph::report`]
//! first, and then adds the governance rows from the same rebuilt graph
//! and the typed evidence of the job: the control plane's signed grant,
//! the owners' signed authorizations (or, in a shared view, the cards the
//! control plane shows other organizations), the purpose and the
//! organizations' signed acceptances, the custodians' signed release
//! records, and the project's governance log with its proofs, witnesses
//! and the owners' revocation heads ([`AuditEvidence`]).
//!
//! The rules, which the tests pin:
//!
//! - **Anchors come from the caller.** Organization governance keys and the
//!   control plane's key are in [`GovernanceAnchors`]; the bundle's own
//!   keys are never consulted. A key that is not pinned is UNCHECKED, never
//!   a pass.
//! - **Fail closed.** Missing evidence is NOT PRESENT, evidence that cannot
//!   be checked against a pin is UNCHECKED, evidence that contradicts is
//!   FAILED. The verdict is SATISFIED only if no row is any of these.
//! - **Not applicable only with backing.** A feature this release cannot
//!   evidence (residency, linkage, privacy scopes, the result-key model, a
//!   project charter) is NOT APPLICABLE only when the signed binding or
//!   authorizations show it is not declared, and NOT PRESENT when they
//!   declare it. Never a pass.
//! - **Validity at execution time.** An authorization is judged at the
//!   grant's signed issue time, never at the time of verification. What it
//!   says now is shown apart and never fails a historical audit.
//! - **Shared views redact, they do not fake.** An owner's signed
//!   authorization names its approvers, so a shared view carries a card
//!   instead; its signature cannot be checked from the card, so what rests
//!   on it is UNCHECKED until the owner discloses the signed document.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use encompute_ir::{parse, Code, Error, Result};
use encompute_planner::{
    ConfidentialExecutionPlan, ExecutionStep, Mechanism, Placement, TrustRequirement,
};
use encompute_verification::governance::{
    GovernanceBinding, GrantGovernance, Purpose, PurposeMode, ReleaseClass,
};
use encompute_verification::service::{verify_signed, JOB_GRANT, JOB_GRANT_V2};
use encompute_verification::{ExecutionSpec, JobGrant, PolicyId};

use crate::authz::{
    AuthorizationSetId, AuthorizationV2, SignedAuthorizationV2, SignedPurposeAcceptance,
    SignedReleaseRecord, SignedRevocationV2,
};
use crate::govlog::{
    check_revocation_heads_from, kind, members_at, GovEvent, HeadVerdict, InclusionProof,
    Partition, SignedCheckpointWitness, SignedProjectCheckpoint, SignedRevocationHead,
};
use crate::graph::{node_id, Evidence, NodeKind, TrustGraph};
use crate::report::{Anchors, ReportOptions, Status, Tally, TrustReport};

/// The version of [`GovernanceEvidence`] and [`AuditEvidence`].
pub const GOVERNANCE_EVIDENCE_VERSION: u32 = 1;

/// The id of the legal boundary line every report ends with.
pub const LEGAL_BOUNDARY_ID: &str = "encompute.legal-boundary.v1";

/// The one-line legal boundary (see `docs/public-sector.md`).
pub const LEGAL_BOUNDARY: &str = "This report shows that the computation matched what the institutions technically authorized; it is not legal advice, a compliance certification, or evidence that any authorization was lawful.";

fn bad(m: impl Into<String>) -> Error {
    Error::new(Code::GovernanceBundleMalformed, m)
}

// --- evidence --------------------------------------------------------------

/// One approval as another organization sees it: never the identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedApproval {
    pub organization: String,
    pub role: String,
    pub at: u64,
    /// A per-project pseudonym of the approver (`psn_` and a keyed hash).
    pub approver: String,
}

/// What every participant sees of an owner's authorization: its body (the
/// approvers' identities removed), each approval as a pseudonym, and the
/// ID of the signed document. The signature is not here, because the
/// signed document names the approvers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationCard {
    /// The AuthorizationId of the owner's full signed document.
    pub id: String,
    /// The fingerprint of the governance key that signed it.
    pub governance_key_id: String,
    /// The body with its approvals removed.
    pub body: AuthorizationV2,
    pub approvals: Vec<SharedApproval>,
}

/// An authorization in the evidence: the owner's signed document (the
/// owner's own view, or a disclosure), or the card of the shared view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "form", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorizationEntry {
    Signed {
        document: Box<SignedAuthorizationV2>,
    },
    Card {
        card: Box<AuthorizationCard>,
    },
}

impl AuthorizationEntry {
    pub fn id(&self) -> String {
        match self {
            AuthorizationEntry::Signed { document } => document.id(),
            AuthorizationEntry::Card { card } => card.id.clone(),
        }
    }

    pub fn body(&self) -> &AuthorizationV2 {
        match self {
            AuthorizationEntry::Signed { document } => &document.body,
            AuthorizationEntry::Card { card } => &card.body,
        }
    }
}

/// A job's governance evidence: typed, with no free-form values.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceEvidence {
    pub version: u32,
    pub project: String,
    pub job_id: String,
    pub purpose: Purpose,
    /// Each organization's signed acceptance of the purpose.
    pub purpose_acceptances: Vec<SignedPurposeAcceptance>,
    /// The execution spec the job ran under (its ID is the receipt's).
    pub spec: ExecutionSpec,
    /// The control plane's signed grant.
    pub grant: JobGrant,
    /// The owners' authorizations the grant binds.
    pub authorizations: Vec<AuthorizationEntry>,
    /// Owners' signed revocations of those authorizations.
    #[serde(default)]
    pub authorization_revocations: Vec<SignedRevocationV2>,
    /// The custodians' signed release records of the job's outputs.
    #[serde(default)]
    pub release_records: Vec<SignedReleaseRecord>,
    /// The submitter as a per-project pseudonym (shared views).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitter: Option<String>,
}

/// One log event with its inclusion proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub event: GovEvent,
    pub proof: InclusionProof,
}

/// A governed project's log as a reader can verify it: the control plane's
/// signed checkpoint, every event of the project's partition with its
/// inclusion proof, the members' witnesses and the owners' signed
/// revocation heads. Events carry only identifiers (INV-247).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvidence {
    pub version: u32,
    pub project: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<SignedProjectCheckpoint>,
    /// The members the control plane lists (the baseline for organizations
    /// with no membership event of their own).
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub witnesses: Vec<SignedCheckpointWitness>,
    #[serde(default)]
    pub events: Vec<AuditEntry>,
    #[serde(default)]
    pub revocation_heads: Vec<SignedRevocationHead>,
}

// --- anchors and options ----------------------------------------------------

/// The keys the verifier trusts, from its own pins (never the bundle).
#[derive(Clone, Debug, Default)]
pub struct GovernanceAnchors {
    /// Organization → its governance public key (hex).
    pub organizations: BTreeMap<String, String>,
    /// The control plane's public key (hex).
    pub control_plane: Option<String>,
}

#[derive(Default)]
pub struct GovernanceOptions<'a> {
    /// The base report's options (its anchors carry the evaluators).
    pub base: ReportOptions<'a>,
    pub anchors: GovernanceAnchors,
    /// The time the revocation heads must reach: a head dated before it
    /// says nothing of later revocations (UNCHECKED). Default: the grant's
    /// signed issue time, the time of the run.
    pub as_of: Option<u64>,
    /// The time "now" lines are shown for (default: the system clock).
    pub now: Option<u64>,
    /// Signed authorizations the owners disclosed, to replace the cards of
    /// the shared view: each must be exactly the document a card names.
    pub disclosures: Vec<SignedAuthorizationV2>,
}

// --- the report -------------------------------------------------------------

/// The governance rows, in order.
pub const GOVERNANCE_ROWS: [&str; 17] = [
    "Project",
    "Organizations",
    "Key custody",
    "Purpose",
    "Source assets",
    "Linkage",
    "Raw data centralized",
    "Decryption control",
    "Ownership retained",
    "Location",
    "Mechanism",
    "Approvals",
    "Authorization window",
    "Unauthorized releases",
    "Privacy policy",
    "Execution evidence",
    "Audit chain",
];

#[derive(Clone, Debug, Serialize)]
pub struct GovernanceRow {
    pub name: &'static str,
    pub status: Status,
    /// What a non-specialist reads: `NO`, `YES`, `NONE`, `INDEPENDENT`,
    /// `VALID AT GRANT`, `UNKNOWN` or a mechanism in words.
    pub value: Option<String>,
    pub details: Vec<String>,
}

/// A revocation the log records.
#[derive(Clone, Debug, Serialize)]
pub struct RevocationNote {
    pub organization: Option<String>,
    pub kind: String,
    pub subject: String,
    pub at: u64,
    /// Results derived from what was revoked (they stay on record).
    pub downstream: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every row passes or is not applicable with signed backing.
    Satisfied,
    /// Nothing contradicts, but something is unchecked or not evidenced.
    NotFullyEvidenced,
    /// A row failed or the base report did.
    NotSatisfied,
}

#[derive(Clone, Debug, Serialize)]
pub struct GovernanceReport {
    pub base: TrustReport,
    pub rows: Vec<GovernanceRow>,
    pub revocations: Vec<RevocationNote>,
    /// Per authorization: what it says now (informational, never fails).
    pub authorization_now: Vec<String>,
    /// The audit's findings in words.
    pub audit_notes: Vec<String>,
    pub verdict: Verdict,
    /// Why the verdict is not SATISFIED.
    pub unmet: Vec<String>,
    pub legal_boundary: &'static str,
}

impl GovernanceReport {
    pub fn row(&self, name: &str) -> Option<&GovernanceRow> {
        self.rows.iter().find(|r| r.name == name)
    }

    pub fn satisfied(&self) -> bool {
        self.verdict == Verdict::Satisfied
    }
}

// --- the grant ---------------------------------------------------------------

enum GrantState<'a> {
    /// Signed by the pinned control-plane key, and consistent.
    Verified(&'a GrantGovernance),
    /// Consistent, but the control plane's key is not pinned.
    Unpinned(&'a GrantGovernance),
    Bad(String),
}

fn check_grant<'a>(ev: &'a GovernanceEvidence, a: &GovernanceAnchors) -> GrantState<'a> {
    let g = &ev.grant;
    let Some(gg) = &g.governance else {
        return GrantState::Bad("the job grant carries no governance".into());
    };
    if g.version != JOB_GRANT_V2 {
        return GrantState::Bad(format!("job grant version {}", g.version));
    }
    if let Err(e) = gg.check(&g.project) {
        return GrantState::Bad(e.message);
    }
    if g.project != ev.project || g.job_id != ev.job_id {
        return GrantState::Bad("the grant is for another project or job".into());
    }
    if g.issued_at >= g.expires_at {
        return GrantState::Bad("the grant's window is empty".into());
    }
    if g.expires_at > gg.not_after {
        return GrantState::Bad("the grant outlives its authorizations".into());
    }
    match &a.control_plane {
        None => GrantState::Unpinned(gg),
        Some(k) => {
            if g.issuer_public_key != *k {
                return GrantState::Bad(
                    "the grant is not signed by the pinned control-plane key".into(),
                );
            }
            match verify_signed(k, JOB_GRANT, &g.unsigned(), &g.signature) {
                Ok(()) => GrantState::Verified(gg),
                Err(_) => GrantState::Bad("the grant's signature does not verify".into()),
            }
        }
    }
}

// --- authorizations -----------------------------------------------------------

enum Sig {
    /// The owner's signature verified under its pinned key.
    Verified,
    /// Signed, but the organization's key is not pinned.
    Unpinned,
    /// A card: the signature cannot be checked from it.
    Card,
    Bad(String),
}

struct Auth<'a> {
    id: String,
    party: &'a str,
    body: &'a AuthorizationV2,
    sig: Sig,
    /// (approver as shown, role, time).
    approvals: Vec<(String, String, u64)>,
}

fn authorizations<'a>(ev: &'a GovernanceEvidence, a: &GovernanceAnchors) -> Vec<Auth<'a>> {
    ev.authorizations
        .iter()
        .map(|e| match e {
            AuthorizationEntry::Signed { document } => {
                let party = document.body.party.as_str();
                let sig = match a.organizations.get(party) {
                    None => Sig::Unpinned,
                    Some(k) => match document.verify(k) {
                        Ok(()) => Sig::Verified,
                        Err(x) => Sig::Bad(x.message),
                    },
                };
                Auth {
                    id: document.id(),
                    party,
                    body: &document.body,
                    sig,
                    approvals: document
                        .body
                        .approvals
                        .iter()
                        .map(|p| {
                            (
                                format!("{}/{}", p.idp_issuer, p.approver_subject),
                                p.role.clone(),
                                p.at,
                            )
                        })
                        .collect(),
                }
            }
            AuthorizationEntry::Card { card } => Auth {
                id: card.id.clone(),
                party: card.body.party.as_str(),
                body: &card.body,
                sig: Sig::Card,
                approvals: card
                    .approvals
                    .iter()
                    .map(|p| (p.approver.clone(), p.role.clone(), p.at))
                    .collect(),
            },
        })
        .collect()
}

impl GovernanceEvidence {
    /// The same evidence with each card the owner disclosed replaced by the
    /// signed document: the document's ID must be the card's, so only the
    /// very document a card names can replace it.
    pub fn disclosed(&self, docs: &[SignedAuthorizationV2]) -> Self {
        let mut out = self.clone();
        for e in &mut out.authorizations {
            if let AuthorizationEntry::Card { card } = e {
                if let Some(d) = docs.iter().find(|d| d.id() == card.id) {
                    *e = AuthorizationEntry::Signed {
                        document: Box::new(d.clone()),
                    };
                }
            }
        }
        out
    }
}

// --- the audit -----------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditState {
    /// The checkpoint, every event's proof and the heads were checked.
    Verified,
    /// Present, but the control plane's key is not pinned.
    Unpinned,
    /// No checkpoint in the evidence.
    Missing,
    Bad(String),
}

#[derive(Clone, Debug)]
pub struct HeadFinding {
    pub organization: String,
    pub verdict: HeadVerdict,
    pub reason: String,
    /// The date of the latest head the log records, when supplied.
    pub head_at: Option<u64>,
}

/// What checking an [`AuditEvidence`] against the pins found.
#[derive(Clone, Debug)]
pub struct AuditFindings {
    pub state: AuditState,
    pub events: Vec<GovEvent>,
    pub members: Vec<String>,
    pub witnessed_by: Vec<String>,
    pub witnessed: bool,
    pub heads: Vec<HeadFinding>,
    pub notes: Vec<String>,
    /// The run reaches back to what the verdict depends on: the log's first
    /// event, or the issuance of every authorization the job runs under.
    /// Without it, nothing shows what happened to them in between.
    pub complete: bool,
}

impl AuditFindings {
    fn unverified(state: AuditState, note: &str) -> Self {
        Self {
            state,
            events: vec![],
            members: vec![],
            witnessed_by: vec![],
            witnessed: false,
            heads: vec![],
            notes: vec![note.to_owned()],
            complete: false,
        }
    }

    pub fn is_verified(&self) -> bool {
        self.state == AuditState::Verified
    }
}

/// Checks a project's log as a reader: the checkpoint's signature under the
/// pinned control-plane key, every event's inclusion proof, the members
/// recomputed from the verified membership events, each witness under the
/// pinned organization key, and each owner's latest revocation head through
/// the verified log, for a run at `as_of`.
pub fn check_audit(
    audit: &AuditEvidence,
    a: &GovernanceAnchors,
    owners: &BTreeSet<String>,
    required: &BTreeSet<String>,
    authorizations: &BTreeSet<String>,
    as_of: u64,
) -> AuditFindings {
    if audit.version != GOVERNANCE_EVIDENCE_VERSION {
        return AuditFindings::unverified(
            AuditState::Bad(format!("audit evidence version {}", audit.version)),
            "the audit section has an unknown version",
        );
    }
    let Some(cp) = &audit.checkpoint else {
        return AuditFindings::unverified(
            AuditState::Missing,
            "the project's log has no checkpoint in the evidence",
        );
    };
    let Some(control) = &a.control_plane else {
        return AuditFindings::unverified(
            AuditState::Unpinned,
            "the control plane's key is not pinned: the log's checkpoint was not checked",
        );
    };
    let fail = |m: String| AuditFindings::unverified(AuditState::Bad(m.clone()), &m);
    if let Err(e) = cp.verify(control) {
        return fail(format!("the checkpoint does not verify: {}", e.message));
    }
    let partition = Partition::Project(audit.project.clone()).to_string();
    if cp.body.partition != partition {
        return fail(format!(
            "the checkpoint is of {}, not {partition}",
            cp.body.partition
        ));
    }
    // A contiguous run of the project's events from some start to the
    // checkpoint's size, each proven against it: no gap, no duplicate, the
    // last one the checkpoint's own. What an exporter leaves out of such a
    // run is detected, so what follows the start is complete.
    let mut prev: Option<u64> = None;
    for e in &audit.events {
        if prev.is_some_and(|p| e.event.pseq != p + 1) {
            return fail(format!(
                "the events are not a contiguous run: event {} follows {}",
                e.event.pseq,
                prev.unwrap_or(0)
            ));
        }
        prev = Some(e.event.pseq);
        if let Err(x) = cp.includes(&e.event, &e.proof) {
            return fail(format!("event {}: {}", e.event.pseq, x.message));
        }
    }
    if prev.unwrap_or(0) != cp.body.size {
        return fail(format!(
            "the run ends at event {}, not at the checkpoint's {}: what came after was left out",
            prev.unwrap_or(0),
            cp.body.size
        ));
    }
    let events: Vec<GovEvent> = audit.events.iter().map(|e| e.event.clone()).collect();
    let members = members_at(&events, cp.body.size, &audit.members);
    let mut notes = vec![];
    let first = events.first().map_or(1, |e| e.pseq);
    let from_start = first <= 1;
    // Reaches back far enough: the first event, or the issuance of every
    // authorization of the set (a revocation of one can only come after).
    let issued: BTreeSet<&str> = events
        .iter()
        .filter(|e| e.kind == kind::AUTHORIZATION_ISSUED)
        .filter_map(|e| e.refs.get("authorization_id").map(String::as_str))
        .collect();
    let complete = from_start || authorizations.iter().all(|a| issued.contains(a.as_str()));
    if !complete {
        notes.push("the run of events does not reach back to the issuance of every authorization the job ran under: nothing shows what happened to them in between. Sign a fresh revocation head (or export from a log that reaches back) to make this bundle checkable".into());
    }
    let mut witnessed_by = vec![];
    for w in &audit.witnesses {
        let org = &w.body.organization;
        let ok = a
            .organizations
            .get(org)
            .is_some_and(|k| *k == w.public_key && w.verify(k).is_ok())
            && w.body.witnesses(&cp.body);
        if ok {
            if !witnessed_by.contains(org) {
                witnessed_by.push(org.clone());
            }
        } else {
            notes.push(format!(
                "the witness of {org} does not verify under its pinned key (or is not for this checkpoint)"
            ));
        }
    }
    // The member list in the bundle is a baseline the control plane
    // states (unsigned): every owner and participant of the signed binding
    // must witness whatever it says, so dropping an organization from it
    // changes nothing.
    let mut must: BTreeSet<&String> = members.iter().collect();
    must.extend(required.iter());
    // A run that does not begin at the log's start cannot show who joined
    // before it: the control plane's baseline stays required, never dropped.
    if !from_start {
        must.extend(audit.members.iter());
    }
    let witnessed = !must.is_empty() && must.iter().all(|o| witnessed_by.contains(*o));
    for o in required {
        if !members.contains(o) {
            notes.push(format!(
                "{o} takes part in the job but is not in the member list the control plane stated: it must witness all the same"
            ));
        }
    }
    for o in &members {
        if !a.organizations.contains_key(o) {
            notes.push(format!(
                "no pinned key for member {o}: its witness cannot count"
            ));
        }
    }
    // Every owner owes a head through the log; so does anyone who has
    // signed or recorded one.
    let mut head_orgs: BTreeSet<String> = owners.clone();
    for e in &events {
        if e.kind == kind::REVOCATION_HEAD_SIGNED || kind::REVOCATIONS.contains(&e.kind.as_str()) {
            if let Some(o) = &e.org {
                head_orgs.insert(o.clone());
            }
        }
    }
    let mut heads = vec![];
    for org in head_orgs {
        let Some(key) = a.organizations.get(&org) else {
            heads.push(HeadFinding {
                organization: org.clone(),
                verdict: HeadVerdict::HeadTooOld,
                reason: format!("no pinned key for {org}: its revocation head cannot be checked"),
                head_at: None,
            });
            continue;
        };
        let c = check_revocation_heads_from(
            &events,
            &audit.revocation_heads,
            &org,
            &audit.project,
            as_of,
            key,
            None,
            from_start,
        );
        let head_at = c.head_seq.and_then(|s| {
            audit
                .revocation_heads
                .iter()
                .find(|h| h.body.organization == org && h.body.seq == s)
                .map(|h| h.body.at)
        });
        heads.push(HeadFinding {
            organization: org,
            verdict: c.verdict,
            reason: c.reason,
            head_at,
        });
    }
    AuditFindings {
        state: AuditState::Verified,
        events,
        members,
        witnessed_by,
        witnessed,
        heads,
        notes,
        complete,
    }
}

// --- rows -----------------------------------------------------------------------

fn is_pass(s: Status) -> bool {
    matches!(
        s,
        Status::Verified
            | Status::Satisfied
            | Status::Authorized
            | Status::Attested
            | Status::Complete
            | Status::NotApplicable
    )
}

fn grow(
    t: Tally,
    name: &'static str,
    ok: Status,
    value: Option<&str>,
    otherwise: Option<&str>,
) -> GovernanceRow {
    let r = t.row(name, ok);
    let value = if is_pass(r.status) { value } else { otherwise };
    GovernanceRow {
        name,
        status: r.status,
        value: value.map(str::to_owned),
        details: r.details,
    }
}

fn not_applicable(name: &'static str, why: &str) -> GovernanceRow {
    GovernanceRow {
        name,
        status: Status::NotApplicable,
        value: Some("NOT APPLICABLE".into()),
        details: vec![why.to_owned()],
    }
}

fn not_present(name: &'static str, why: &str) -> GovernanceRow {
    GovernanceRow {
        name,
        status: Status::NotPresent,
        value: Some("NOT EVIDENCED".into()),
        details: vec![why.to_owned()],
    }
}

fn failed_all(why: &str) -> Vec<GovernanceRow> {
    GOVERNANCE_ROWS
        .iter()
        .map(|n| GovernanceRow {
            name: n,
            status: Status::Failed,
            value: None,
            details: vec![why.to_owned()],
        })
        .collect()
}

/// Everything the rows read, computed once.
struct Job<'a> {
    ev: &'a GovernanceEvidence,
    gg: &'a GrantGovernance,
    binding: &'a GovernanceBinding,
    /// The signed time of the run: the grant's issue time.
    t0: u64,
    auths: Vec<Auth<'a>>,
    program: Option<encompute_ir::Program>,
    plan: Option<&'a ConfidentialExecutionPlan>,
    audit: &'a AuditFindings,
    anchors: &'a GovernanceAnchors,
    /// Organizations whose data the job reads, and the submitter's.
    participants: BTreeSet<String>,
}

impl<'a> Job<'a> {
    fn recipients(&self) -> BTreeSet<String> {
        self.binding
            .outputs
            .values()
            .flat_map(|o| o.recipients.iter().cloned())
            .collect()
    }

    fn input_asset(&self, input: &str) -> Option<&str> {
        self.program
            .as_ref()?
            .confidentiality()?
            .inputs
            .get(input)
            .map(String::as_str)
    }

    fn describe_card(&self, a: &Auth<'_>) -> String {
        format!("authorization {} of {}", short(&a.id), a.party)
    }
}

fn short(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

fn sig_status(t: &mut Tally, j: &Job<'_>, a: &Auth<'_>) {
    match &a.sig {
        Sig::Verified => {}
        Sig::Unpinned => t.unanchored(format!(
            "{}: no pinned governance key for {}",
            j.describe_card(a),
            a.party
        )),
        Sig::Card => t.unanchored(format!(
            "{} is a card of the shared view: its signature cannot be checked without the owner's signed document",
            j.describe_card(a)
        )),
        Sig::Bad(m) => t.fail(format!("{}: {m}", j.describe_card(a))),
    }
}

fn row_project(j: &Job<'_>) -> GovernanceRow {
    let mut t = Tally {
        present: true,
        ..Tally::default()
    };
    // Every organization whose data the job reads accepts the purpose; the
    // submitter and the recipients need not (their consent is not data).
    let owners: BTreeSet<&String> = j.binding.inputs.values().map(|i| &i.organization).collect();
    for org in owners {
        let Some(acc) =
            j.ev.purpose_acceptances
                .iter()
                .find(|x| x.body.organization == *org)
        else {
            t.fail(format!("{org} has no signed acceptance of the purpose"));
            continue;
        };
        if acc.body.project != j.ev.project || acc.body.purpose_id != j.binding.purpose_id {
            t.fail(format!(
                "the acceptance of {org} is for another project or purpose"
            ));
            continue;
        }
        if acc.body.accepted_at > j.t0 {
            t.fail(format!(
                "{org} accepted the purpose at {}, after the grant at {}",
                acc.body.accepted_at, j.t0
            ));
        }
        match j.anchors.organizations.get(org) {
            None => t.unanchored(format!("no pinned governance key for {org}")),
            Some(k) => {
                if acc.public_key != *k || acc.verify(k).is_err() {
                    t.fail(format!(
                        "the acceptance of {org} does not verify under its pinned key"
                    ));
                }
            }
        }
    }
    for o in j.participants.iter().chain(j.recipients().iter()) {
        if !j.binding.inputs.values().any(|i| &i.organization == o)
            && !j
                .ev
                .purpose_acceptances
                .iter()
                .any(|x| &x.body.organization == o)
        {
            t.note(format!(
                "{o} takes part (as submitter or recipient) and has signed no acceptance of the purpose"
            ));
        }
    }
    t.note("this release has no separate project charter: the consent shown is each organization's signed acceptance of the purpose".into());
    grow(
        t,
        "Project",
        Status::Satisfied,
        Some("PURPOSE ACCEPTED BY EVERY PARTICIPANT"),
        Some("UNKNOWN"),
    )
}

fn row_organizations(j: &Job<'_>) -> GovernanceRow {
    let mut t = Tally {
        present: true,
        ..Tally::default()
    };
    let recipients = j.recipients();
    let orgs: BTreeSet<&String> = j.participants.iter().chain(recipients.iter()).collect();
    let mut by_key: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for o in &orgs {
        match j.anchors.organizations.get(*o) {
            None => t.unanchored(format!("no pinned governance key for {o}")),
            Some(k) => by_key.entry(k).or_default().push(o),
        }
    }
    for (_, os) in by_key.iter().filter(|(_, os)| os.len() > 1) {
        t.fail(format!(
            "{} share one pinned key: they are not distinct organizations",
            os.join(", ")
        ));
    }
    t.note(format!(
        "{} organization(s): {}",
        orgs.len(),
        orgs.iter()
            .map(|o| o.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    grow(
        t,
        "Organizations",
        Status::Satisfied,
        Some("DISTINCT PINNED KEYS"),
        None,
    )
}

fn custody(plan: &ConfidentialExecutionPlan) -> Vec<(&str, &str, &str)> {
    plan.requirements
        .iter()
        .filter_map(|r| match r {
            TrustRequirement::KeyCustody {
                asset,
                organization,
                broker,
            } => Some((asset.as_str(), organization.as_str(), broker.as_str())),
            _ => None,
        })
        .collect()
}

fn row_key_custody(j: &Job<'_>) -> GovernanceRow {
    let Some(plan) = j.plan else {
        return not_present(
            "Key custody",
            "the plan is not in the evidence: custody cannot be read from it",
        );
    };
    let custody = custody(plan);
    if custody.is_empty() {
        return not_present(
            "Key custody",
            "the plan records no sovereign custody for any source: where each key lives is not evidenced",
        );
    }
    let mut t = Tally {
        present: true,
        ..Tally::default()
    };
    for (name, input) in &j.binding.inputs {
        let Some(asset) = j.input_asset(name) else {
            t.unanchored(format!(
                "input {name}: the program is not in the evidence, so its asset is unknown"
            ));
            continue;
        };
        match custody.iter().find(|(a, _, _)| *a == asset) {
            None => t.fail(format!(
                "input {name} ({asset}) has no sovereign custody: its key is not shown to be at its owner's own broker"
            )),
            Some((_, org, broker)) => {
                if *org != input.organization {
                    t.fail(format!(
                        "input {name}: its key is at a broker of {org}, not of its owner {}",
                        input.organization
                    ));
                }
                match j.binding.asset_brokers.get(&input.asset_version_id) {
                    Some(b) if b != broker => t.fail(format!(
                        "input {name}: the binding names broker {b}, the plan {broker}"
                    )),
                    None if !j.binding.asset_brokers.is_empty() => t.fail(format!(
                        "input {name}: the binding names no broker for its version"
                    )),
                    _ => {}
                }
            }
        }
    }
    let mut by_broker: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (_, org, broker) in &custody {
        by_broker.entry(broker).or_default().insert(org);
    }
    for (b, orgs) in by_broker.iter().filter(|(_, o)| o.len() > 1) {
        t.fail(format!(
            "broker {b} holds the keys of {} organizations: custody is shared",
            orgs.len()
        ));
    }
    t.note("no project-wide key appears in the plan".into());
    grow(
        t,
        "Key custody",
        Status::Satisfied,
        Some("INDEPENDENT"),
        Some("UNKNOWN"),
    )
}

fn row_purpose(j: &Job<'_>) -> GovernanceRow {
    let mut t = Tally {
        present: true,
        ..Tally::default()
    };
    let p = &j.ev.purpose;
    if let Err(e) = p.check() {
        t.fail(format!("the purpose is malformed: {}", e.message));
    }
    if p.id().hex() != j.binding.purpose_id {
        t.fail("the purpose in the evidence is not the one the grant binds".into());
    }
    if p.project_id != j.ev.project {
        t.fail("the purpose belongs to another project".into());
    }
    if !p.is_valid_at(j.t0) {
        t.fail(format!(
            "the grant was issued at {}, outside the purpose's window [{}, {})",
            j.t0, p.valid_from, p.valid_until
        ));
    }
    if j.gg.not_after > p.valid_until {
        t.fail("the grant outlives the purpose's window".into());
    }
    match j.program.as_ref().and_then(|x| x.confidentiality()) {
        None => t.unanchored(
            "the program is not in the evidence: its declared purpose was not compared".into(),
        ),
        Some(c) => {
            if c.purpose.as_deref() != Some(p.name.as_str()) {
                t.fail(format!(
                    "the program declares purpose {:?}, the project's is {:?}",
                    c.purpose, p.name
                ));
            }
        }
    }
    for a in &j.auths {
        if a.body.purpose_id != j.binding.purpose_id {
            t.fail(format!("{} is for another purpose", j.describe_card(a)));
        } else if matches!(a.sig, Sig::Card) {
            t.unanchored(format!(
                "{}: its purpose is the card's claim, not a checked signature",
                j.describe_card(a)
            ));
        }
    }
    match &p.legal_basis_ref {
        Some(l) => t.note(format!("legal reference {l}: recorded, not checked")),
        None => t.note("no legal reference was recorded".into()),
    }
    grow(t, "Purpose", Status::Satisfied, Some(&p.name), None)
}

fn row_source_assets(j: &Job<'_>) -> GovernanceRow {
    let mut t = Tally {
        present: !j.binding.inputs.is_empty(),
        ..Tally::default()
    };
    // The authorizations in the evidence are exactly the set the signed
    // grant binds: nothing omitted, nothing added.
    match AuthorizationSetId::of(j.auths.iter().map(|a| a.id.clone())) {
        Err(e) => t.fail(format!("the authorizations are not a set: {}", e.message)),
        Ok(set) if set.hex() != j.gg.authorization_set_id => t.fail(
            "the authorizations in the evidence are not the set the grant binds (one is missing, added or changed)"
                .into(),
        ),
        Ok(_) => {}
    }
    let spec_id = j.ev.spec.id().hex();
    for (name, input) in &j.binding.inputs {
        let for_version: Vec<&Auth<'_>> = j
            .auths
            .iter()
            .filter(|a| a.body.asset_version_id == input.asset_version_id)
            .collect();
        if for_version.is_empty() {
            t.fail(format!(
                "input {name}: no authorization of version {} is in the evidence",
                short(&input.asset_version_id)
            ));
        }
        for a in for_version {
            if a.party != input.organization {
                t.fail(format!(
                    "input {name}: {} is signed by {}, not by the version's owner {}",
                    j.describe_card(a),
                    a.party,
                    input.organization
                ));
            }
            if a.body.asset_digest_commitment != input.digest_commitment {
                t.fail(format!(
                    "input {name}: the authorization commits to another digest than the binding"
                ));
            }
            if !a.body.program.covers(&j.ev.spec.program_id) {
                t.fail(format!(
                    "{} does not cover this program",
                    j.describe_card(a)
                ));
            }
            if let Some(pin) = &a.body.execution_spec_ids {
                if !pin.contains(&spec_id) {
                    t.fail(format!(
                        "{} pins other execution specs than this job's",
                        j.describe_card(a)
                    ));
                }
            }
            if j.ev
                .spec
                .policy_id
                .as_deref()
                .is_some_and(|p| p != a.body.policy_id)
            {
                t.fail(format!(
                    "{} is for another policy than the job's",
                    j.describe_card(a)
                ));
            }
            sig_status(&mut t, j, a);
        }
    }
    for a in &j.auths {
        if !j
            .binding
            .inputs
            .values()
            .any(|i| i.asset_version_id == a.body.asset_version_id)
        {
            t.fail(format!(
                "{} is for a version the job does not read",
                j.describe_card(a)
            ));
        }
    }
    let versions: Vec<String> = j
        .binding
        .inputs
        .iter()
        .map(|(n, i)| format!("{n}: {} of {}", short(&i.asset_version_id), i.organization))
        .collect();
    t.note(format!("bound versions: {}", versions.join("; ")));
    grow(
        t,
        "Source assets",
        Status::Satisfied,
        Some("EACH SIGNED BY ITS OWNER"),
        None,
    )
}

/// Whether every authorization is a verified signature: "nothing is
/// declared" may not rest on the body of a card or an unchecked document.
fn all_signed(j: &Job<'_>) -> bool {
    j.auths.iter().all(|a| matches!(a.sig, Sig::Verified))
}

fn unchecked_na(name: &'static str) -> GovernanceRow {
    GovernanceRow {
        name,
        status: Status::Unchecked,
        value: Some("UNKNOWN".into()),
        details: vec![
            "whether the feature is declared rests on authorizations whose signatures are not all verified (a card, an unpinned key or an invalid signature)".into(),
        ],
    }
}

fn row_linkage(j: &Job<'_>) -> GovernanceRow {
    let declared = j.binding.linkage_policy_id.is_some()
        || j.ev.purpose.linkage_policy_id.is_some()
        || j.ev.purpose.modes.contains(&PurposeMode::RecordLevelExact)
        || j.auths.iter().any(|a| a.body.linkage_policy_id.is_some());
    if !declared && !all_signed(j) {
        return unchecked_na("Linkage");
    }
    if declared {
        not_present(
            "Linkage",
            "a linkage policy is declared; its co-signatures and evidence are not available in this release",
        )
    } else {
        not_applicable(
            "Linkage",
            "no linkage policy in the signed binding, the purpose or any authorization",
        )
    }
}

fn describe_mechanism(m: &Mechanism) -> String {
    match m {
        Mechanism::PolicyEnforcement => "policy enforcement".into(),
        Mechanism::OwnerAuthorization => "owner authorization".into(),
        Mechanism::SignedReceipts => "signed receipts".into(),
        Mechanism::Fhe { scheme, backend } => {
            format!("encrypted computation ({scheme:?}, {backend})")
        }
        Mechanism::VerifiedExecution => "verified execution".into(),
        Mechanism::ConfidentialCompute { tee, provider } => {
            format!("a confidential VM ({tee}, {provider})")
        }
        Mechanism::Attestation { provider } => format!("workload attestation ({provider})"),
        Mechanism::AttestedKeyRelease => "keys released to the attested workload".into(),
        Mechanism::SecureAggregation { .. } => "secure aggregation".into(),
        Mechanism::DifferentialPrivacy { .. } => "differential privacy".into(),
        other => format!("{other:?}").to_lowercase(),
    }
}

fn describe_step(s: &ExecutionStep) -> String {
    let at = match &s.placement {
        Placement::UntrustedHost => "an untrusted host".to_owned(),
        Placement::Tee(_) => "a confidential VM".to_owned(),
        Placement::Party(p) => format!("{p}'s own premises"),
        Placement::Parties => "the contributing parties".to_owned(),
    };
    let ms: Vec<String> = s.mechanisms.iter().map(describe_mechanism).collect();
    format!("{} on {at} with {}", s.id, ms.join(", "))
}

fn row_mechanism(j: &Job<'_>) -> GovernanceRow {
    let Some(plan) = j.plan else {
        return not_present(
            "Mechanism",
            "no plan matching the grant's plan hash is in the evidence",
        );
    };
    let mut t = Tally {
        present: !plan.steps.is_empty(),
        ..Tally::default()
    };
    // A plan made before the binding existed carries none; one that
    // carries a governance ID carries this job's.
    if plan
        .governance_id
        .as_deref()
        .is_some_and(|g| g != j.gg.governance_id)
    {
        t.fail("the plan is bound to another job's governance ID".into());
    }
    for s in &plan.steps {
        t.note(describe_step(s));
    }
    grow(t, "Mechanism", Status::Satisfied, None, None)
}

fn row_raw_data(j: &Job<'_>) -> GovernanceRow {
    let Some(plan) = j.plan else {
        return GovernanceRow {
            name: "Raw data centralized",
            status: Status::NotPresent,
            value: Some("UNKNOWN".into()),
            details: vec![
                "no plan is in the evidence, so where each source is consumed is not shown".into(),
            ],
        };
    };
    let cust = custody(plan);
    let owner_of = |asset: &str| {
        cust.iter()
            .find(|(a, _, _)| *a == asset)
            .map(|(_, o, _)| *o)
    };
    let mut t = Tally {
        present: !plan.steps.is_empty(),
        ..Tally::default()
    };
    for s in &plan.steps {
        let fhe = s
            .mechanisms
            .iter()
            .any(|m| matches!(m, Mechanism::Fhe { .. }));
        let secagg = s
            .mechanisms
            .iter()
            .any(|m| matches!(m, Mechanism::SecureAggregation { .. }));
        let ok = match &s.placement {
            Placement::UntrustedHost => fhe,
            Placement::Parties => secagg,
            Placement::Party(p) => {
                !s.assets.is_empty() && s.assets.iter().all(|a| owner_of(a) == Some(p.as_str()))
            }
            Placement::Tee(_) => false,
        };
        if !ok {
            let why = match &s.placement {
                Placement::Tee(_) => "it runs in a confidential VM, and the owners' brokers' key-release evidence is not in this release",
                Placement::UntrustedHost => "it runs on an untrusted host without encrypted computation",
                Placement::Party(_) => "it runs at a party that is not shown to own everything it reads",
                Placement::Parties => "it is distributed without secure aggregation",
            };
            t.unanchored(format!("step {}: {why}", s.id));
        }
    }
    t.note("NO means every step that reads a source is the owner's own client, encrypted computation on an untrusted host, or secure-aggregation masking".into());
    let mut r = grow(
        t,
        "Raw data centralized",
        Status::Satisfied,
        Some("NO"),
        Some("UNKNOWN"),
    );
    if r.status == Status::Unchecked {
        r.value = Some("UNKNOWN".into());
    }
    r
}

fn row_decryption() -> GovernanceRow {
    not_present(
        "Decryption control",
        "who holds the key to a result is not recorded in signed evidence in this release (the key model is an open decision); this row never claims one",
    )
}

fn row_ownership(j: &Job<'_>) -> GovernanceRow {
    let mut t = Tally {
        present: !j.binding.inputs.is_empty(),
        ..Tally::default()
    };
    let mut wrong_owner = false;
    for (name, input) in &j.binding.inputs {
        let docs: Vec<&Auth<'_>> = j
            .auths
            .iter()
            .filter(|a| a.body.asset_version_id == input.asset_version_id)
            .collect();
        if docs.is_empty() {
            t.unanchored(format!(
                "input {name}: no owner authorization is in the evidence"
            ));
        }
        for a in docs {
            if a.party != input.organization {
                wrong_owner = true;
                t.fail(format!(
                    "input {name}: the version is authorized by {}, not by its owner {}",
                    a.party, input.organization
                ));
            }
            match &a.sig {
                Sig::Verified => {}
                Sig::Bad(m) => t.fail(format!("{}: {m}", j.describe_card(a))),
                _ => t.unanchored(format!(
                    "input {name}: {} is not a checked signature of its owner",
                    j.describe_card(a)
                )),
            }
        }
    }
    t.note("ownership means control within Encompute (keys, authorization, revocation), not legal title".into());
    let mut r = grow(
        t,
        "Ownership retained",
        Status::Satisfied,
        Some("YES"),
        Some("UNKNOWN"),
    );
    if wrong_owner {
        r.value = Some("NO".into());
    }
    r
}

fn row_location(j: &Job<'_>) -> GovernanceRow {
    let planned = j.plan.is_some_and(|p| {
        p.requirements
            .iter()
            .any(|r| matches!(r, TrustRequirement::ExecutionRegion { .. }))
    });
    if j.binding.placement_digest.is_some() || planned {
        not_present(
            "Location",
            "a placement constraint is declared; evidence of where the job ran is not available in this release",
        )
    } else {
        not_applicable(
            "Location",
            "no placement constraint in the signed binding or the plan",
        )
    }
}

fn row_approvals(j: &Job<'_>) -> GovernanceRow {
    let mut t = Tally {
        present: !j.auths.is_empty(),
        ..Tally::default()
    };
    let mut per_org: BTreeMap<&str, usize> = BTreeMap::new();
    for a in &j.auths {
        let what = j.describe_card(a);
        if a.approvals.is_empty() {
            t.fail(format!("{what} has no approvals"));
        }
        let people: BTreeSet<&str> = a.approvals.iter().map(|(p, _, _)| p.as_str()).collect();
        // The submitter is a pseudonym; a raw approver of the submitter's
        // own organization cannot be compared with it.
        if j.ev
            .submitter
            .as_deref()
            .is_some_and(|s| s.starts_with("psn_"))
            && j.ev.grant.organization == a.party
            && a.approvals.iter().any(|(p, _, _)| !p.starts_with("psn_"))
        {
            t.unanchored(format!(
                "{what}: its approvers are shown by identity and the submitter by pseudonym, so that they are different people cannot be checked"
            ));
        }
        if let Err(e) = crate::authz::quorum_met(
            a.approvals.iter().map(|(p, r, _)| (p.as_str(), r.as_str())),
            2,
            &BTreeMap::new(),
        ) {
            t.fail(format!("{what}: {}", e.message));
        }
        for (p, role, at) in &a.approvals {
            if role == "auditor" {
                t.fail(format!("{what}: an auditor approved"));
            }
            if *at > j.t0 {
                t.fail(format!("{what}: an approval is dated after the grant"));
            }
            if j.ev.submitter.as_deref() == Some(p.as_str()) {
                t.fail(format!(
                    "{what}: the job's submitter is one of the approvers"
                ));
            }
        }
        if let AuthorizationEntry::Card { card } = &j.ev.authorizations[j
            .auths
            .iter()
            .position(|x| x.id == a.id)
            .expect("an authorization of the list")]
        {
            if card.approvals.iter().any(|p| p.organization != a.party) {
                t.fail(format!("{what}: an approval is by another organization"));
            }
        } else if let Some(AuthorizationEntry::Signed { document }) =
            j.ev.authorizations.iter().find(|e| e.id() == a.id)
        {
            if let Err(e) = document.body.check_approvals() {
                t.fail(format!("{what}: {}", e.message));
            }
        }
        match &a.sig {
            Sig::Verified => {}
            Sig::Unpinned => t.unanchored(format!("{what}: no pinned key for {}", a.party)),
            Sig::Card => t.unanchored(format!(
                "{what}: its approvers are pseudonyms ({} distinct) counted from the control plane's card, not verified",
                people.len()
            )),
            Sig::Bad(m) => t.fail(format!("{what}: {m}")),
        }
        *per_org.entry(a.party).or_default() += people.len();
    }
    for (o, n) in &per_org {
        t.note(format!(
            "{o}: {n} distinct approver(s) across its authorizations"
        ));
    }
    t.note("per-job approvals are the control plane's own record, not signed: they are not counted here".into());
    grow(
        t,
        "Approvals",
        Status::Satisfied,
        Some("QUORUM OF DISTINCT HUMANS PER AGENCY"),
        None,
    )
}

/// What the verified log and the signed revocations say about one
/// authorization.
struct Revoked {
    /// When the owner revoked it (the earliest), if it did.
    authorization: Option<u64>,
    /// When its governance key was revoked, if it was.
    key: Option<u64>,
}

fn revoked(j: &Job<'_>, a: &Auth<'_>) -> Revoked {
    let mut auth: Option<u64> = None;
    let mut keyr: Option<u64> = None;
    let take = |slot: &mut Option<u64>, at: u64| *slot = Some(slot.map_or(at, |x| x.min(at)));
    for r in &j.ev.authorization_revocations {
        if r.body.authorization == a.id && r.body.party == a.party {
            let ok = j
                .anchors
                .organizations
                .get(a.party)
                .is_some_and(|k| r.verify(k).is_ok());
            if ok {
                take(&mut auth, r.body.issued_at);
            }
        }
    }
    if j.audit.is_verified() {
        let kid = match j.ev.authorizations.iter().find(|e| e.id() == a.id) {
            Some(AuthorizationEntry::Signed { document }) => {
                Some(crate::authz::governance_key_id(&document.public_key))
            }
            Some(AuthorizationEntry::Card { card }) => Some(card.governance_key_id.clone()),
            None => None,
        };
        for e in &j.audit.events {
            if e.org.as_deref() != Some(a.party) {
                continue;
            }
            if e.kind == kind::AUTHORIZATION_REVOKED
                && e.refs.get("authorization_id").is_some_and(|x| *x == a.id)
            {
                take(&mut auth, e.at);
            }
            if e.kind == kind::GOVERNANCE_KEY_REVOKED
                && kid
                    .as_ref()
                    .is_some_and(|k| e.refs.get("key_id") == Some(k))
            {
                take(&mut keyr, e.at);
            }
        }
    }
    Revoked {
        authorization: auth,
        key: keyr,
    }
}

fn row_window(j: &Job<'_>) -> GovernanceRow {
    let mut t = Tally {
        present: !j.auths.is_empty(),
        ..Tally::default()
    };
    for a in &j.auths {
        let what = j.describe_card(a);
        let b = a.body;
        if !b.is_valid_at(j.t0) {
            t.fail(format!(
                "{what} is valid [{}, {}), not at the grant's signed time {}",
                b.valid_from, b.valid_until, j.t0
            ));
        }
        if j.gg.not_after > b.valid_until {
            t.fail(format!("{what}: the grant outlives it"));
        }
        if b.issued_at > j.t0 {
            t.fail(format!("{what} was issued after the grant"));
        }
        let r = revoked(j, a);
        if let Some(at) = r.authorization.filter(|at| *at <= j.t0) {
            t.fail(format!(
                "{what} was revoked at {at}, at or before the run at {}",
                j.t0
            ));
        }
        if let Some(at) = r.key {
            if b.issued_at >= at || j.t0 >= at {
                t.fail(format!(
                    "{what} rests on a governance key revoked at {at}, before it was used"
                ));
            }
        }
        // Revoked while the grant was still usable: the run's own time is
        // not in the evidence (a receipt carries none), so whether it came
        // first cannot be told.
        for at in [r.authorization, r.key].into_iter().flatten() {
            if at > j.t0 && at <= j.ev.grant.expires_at {
                t.unanchored(format!(
                    "{what} (or its key) was revoked at {at}, after the grant at {} and before it expired at {}: whether the run came first is not evidenced",
                    j.t0, j.ev.grant.expires_at
                ));
            }
        }
        if !j.audit.is_verified() || !j.audit.complete {
            t.unanchored(format!(
                "{what}: whether it or its key was revoked before the run rests on the project's log, which is {}",
                if j.audit.is_verified() {
                    "not shown back to its issuance"
                } else {
                    "not verified"
                }
            ));
        }
        sig_status(&mut t, j, a);
    }
    t.note(format!(
        "judged at the grant's signed time {} (valid until {}), never at the time of verification; the run's own time is not evidenced, only that the grant was issued then",
        j.t0, j.gg.not_after
    ));
    grow(
        t,
        "Authorization window",
        Status::Satisfied,
        Some("VALID AT GRANT"),
        None,
    )
}

fn row_releases(j: &Job<'_>) -> GovernanceRow {
    if j.ev.release_records.is_empty()
        && j.binding
            .outputs
            .values()
            .any(|o| o.release_class != ReleaseClass::Never)
    {
        return GovernanceRow {
            name: "Unauthorized releases",
            status: Status::NotPresent,
            value: Some("UNKNOWN".into()),
            details: vec![
                "no signed release record is in the evidence: nothing shows what was released, so none is claimed to be absent"
                    .into(),
            ],
        };
    }
    let mut t = Tally {
        present: true,
        ..Tally::default()
    };
    let version_ids: BTreeSet<&String> = j
        .binding
        .inputs
        .values()
        .map(|i| &i.asset_version_id)
        .collect();
    let auth_ids: BTreeSet<&String> = j.auths.iter().map(|a| &a.id).collect();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for r in &j.ev.release_records {
        let b = &r.body;
        *seen.entry(b.output.as_str()).or_default() += 1;
        let what = format!("release record of output {}", b.output);
        let Some(out) = j.binding.outputs.get(&b.output) else {
            t.fail(format!("{what}: the job has no such output"));
            continue;
        };
        if b.job_id != j.ev.job_id
            || b.project != j.ev.project
            || b.purpose_id != j.binding.purpose_id
            || b.governance_id != j.gg.governance_id
        {
            t.fail(format!(
                "{what} is for another job, project, purpose or governance ID"
            ));
        }
        if b.parents.iter().collect::<BTreeSet<_>>() != version_ids {
            t.fail(format!(
                "{what}: its parents are not exactly the job's source versions"
            ));
        }
        if b.authorization_ids.iter().collect::<BTreeSet<_>>() != auth_ids {
            t.fail(format!(
                "{what}: it was not released under exactly the authorizations the grant binds"
            ));
        }
        if !b.release_class.within(out.release_class) {
            t.fail(format!(
                "{what}: its class is wider than the job's output class"
            ));
        }
        for a in &j.auths {
            if !b.release_class.within(a.body.release_class) {
                t.fail(format!(
                    "{what}: its class is wider than {} allows",
                    j.describe_card(a)
                ));
            }
        }
        for rec in b.recipients.keys() {
            if !out.recipients.contains(rec) {
                t.fail(format!("{what}: {rec} is not a recipient of the output"));
            }
            for a in &j.auths {
                if !a.body.recipients.contains(rec) {
                    t.fail(format!(
                        "{what}: {rec} is not a recipient {} allows",
                        j.describe_card(a)
                    ));
                }
            }
        }
        if !out.recipients.contains(&b.party) {
            t.fail(format!(
                "{what}: its custodian {} is not a recipient",
                b.party
            ));
        }
        match j.anchors.organizations.get(&b.party) {
            None => t.unanchored(format!("{what}: no pinned governance key for {}", b.party)),
            Some(k) => {
                if r.public_key != *k || r.verify(k).is_err() {
                    t.fail(format!(
                        "{what} does not verify under its custodian's pinned key"
                    ));
                }
            }
        }
    }
    for (name, n) in &seen {
        if *n > 1 {
            t.fail(format!("output {name} has {n} release records"));
        }
    }
    for (name, out) in &j.binding.outputs {
        if out.release_class != ReleaseClass::Never && !seen.contains_key(name.as_str()) {
            t.unanchored(format!(
                "output {name} ({}) has no signed release record: nothing shows what was released of it",
                out.release_class.as_str()
            ));
        }
    }
    t.note("a released result cannot be recalled; this row covers what was recorded".into());
    grow(
        t,
        "Unauthorized releases",
        Status::Satisfied,
        Some("NONE"),
        Some("UNKNOWN"),
    )
}

fn row_privacy(j: &Job<'_>, base: &TrustReport) -> GovernanceRow {
    let scoped = j.auths.iter().any(|a| a.body.privacy_scope_id.is_some());
    let budgeted = j.ev.spec.privacy_policy_id.is_some()
        || j.auths.iter().any(|a| a.body.privacy_policy_id.is_some());
    if scoped {
        return not_present(
            "Privacy policy",
            "an authorization names a privacy scope; scoped budgets are not evidenced in this release",
        );
    }
    if !budgeted && !all_signed(j) {
        return unchecked_na("Privacy policy");
    }
    if !budgeted {
        return not_applicable(
            "Privacy policy",
            "no DP budget applies: no privacy policy in the spec or any authorization",
        );
    }
    let Some(b) = base.rows.iter().find(|r| r.name == "Privacy budget") else {
        return not_present(
            "Privacy policy",
            "the base report has no privacy-budget row",
        );
    };
    GovernanceRow {
        name: "Privacy policy",
        status: b.status,
        value: is_pass(b.status).then(|| "BUDGETS SPENT WITHIN POLICY".to_owned()),
        details: b.details.clone(),
    }
}

fn row_execution(j: &Job<'_>, g: &TrustGraph) -> GovernanceRow {
    let mut t = Tally::default();
    let spec = &j.ev.spec;
    let spec_id = spec.id().hex();
    let grant = &j.ev.grant;
    if spec_id != grant.spec_id {
        t.present = true;
        t.fail("the recomputed execution spec is not the one the grant is for".into());
    }
    if spec.governance_id.as_deref() != Some(j.binding.id().hex().as_str())
        || j.binding.id().hex() != j.gg.governance_id
    {
        t.present = true;
        t.fail("the spec's governance ID is not the recomputed ID of the grant's binding".into());
    }
    if spec.program_id != grant.program_id {
        t.present = true;
        t.fail("the spec runs another program than the grant".into());
    }
    if let Some(c) = j.program.as_ref().and_then(|p| p.confidentiality()) {
        if spec.policy_id.as_deref() != Some(PolicyId::of(c).hex().as_str()) {
            t.present = true;
            t.fail("the spec's policy is not the program's".into());
        }
    }
    let receipts: Vec<_> = g
        .of(NodeKind::Execution)
        .filter_map(|(_, n)| match &n.evidence {
            Some(Evidence::ExecutionReceipt(r)) if r.receipt.spec_id == spec_id => Some(r),
            _ => None,
        })
        .collect();
    match receipts.as_slice() {
        [] => {
            if !t.present {
                t.note("no execution receipt of this spec is in the evidence".into());
            }
        }
        [r] => {
            t.present = true;
            if r.receipt.grant_digest.as_deref() != Some(grant.digest().as_str()) {
                t.fail("the receipt does not name the digest of the grant it is bound to".into());
            }
            if r.receipt.program_id != spec.program_id {
                t.fail("the receipt is for another program".into());
            }
        }
        _ => {
            t.present = true;
            t.fail("more than one receipt of this job's spec".into());
        }
    }
    t.note(
        "the receipt's request and response binding is not re-checked (ciphertexts excluded)"
            .into(),
    );
    grow(
        t,
        "Execution evidence",
        Status::Satisfied,
        Some("SPEC RECOMPUTED"),
        None,
    )
}

fn revocations(j: &Job<'_>) -> Vec<RevocationNote> {
    if !j.audit.is_verified() {
        return vec![];
    }
    let mut out = vec![];
    for e in &j.audit.events {
        if !kind::REVOCATIONS.contains(&e.kind.as_str()) {
            continue;
        }
        let mut downstream = vec![];
        for r in &j.ev.release_records {
            let hit = |v: &String| *v == e.subject || e.refs.values().any(|x| x == v);
            if r.body.parents.iter().any(hit) || r.body.authorization_ids.iter().any(hit) {
                downstream.push(r.body.derived_version_id.clone());
            }
        }
        out.push(RevocationNote {
            organization: e.org.clone(),
            kind: e.kind.clone(),
            subject: e.subject.clone(),
            at: e.at,
            downstream,
        });
    }
    out
}

fn row_audit(j: &Job<'_>, as_of: u64) -> (GovernanceRow, Vec<String>) {
    let a = j.audit;
    let mut t = Tally::default();
    let mut notes = a.notes.clone();
    match &a.state {
        AuditState::Missing => {}
        AuditState::Unpinned => {
            t.present = true;
            t.unanchored(a.notes.first().cloned().unwrap_or_default());
        }
        AuditState::Bad(m) => {
            t.present = true;
            t.fail(m.clone());
        }
        AuditState::Verified => {
            t.present = true;
            if !a.complete {
                t.unanchored(
                    "the run of events does not reach back to the issuance of every authorization: sign a fresh revocation head to make this bundle checkable".into(),
                );
            }
            for e in &a.events {
                if e.subject == j.ev.job_id
                    && (e.kind == kind::JOB_CANCELLED || e.kind == kind::JOB_FAILED)
                {
                    t.fail(format!(
                        "the log records {} for this job at {}, yet a receipt exists",
                        e.kind, e.at
                    ));
                }
            }
            if !a.witnessed {
                t.unanchored(format!(
                    "the checkpoint is not witnessed by every member (witnessed by: {})",
                    if a.witnessed_by.is_empty() {
                        "nobody".to_owned()
                    } else {
                        a.witnessed_by.join(", ")
                    }
                ));
            }
            for h in &a.heads {
                match h.verdict {
                    HeadVerdict::Covered => notes.push(format!(
                        "{}: every revocation covered as of {} (revocations after that are not covered)",
                        h.organization,
                        h.head_at.map_or("?".to_owned(), |x| x.to_string())
                    )),
                    HeadVerdict::HeadTooOld => t.unanchored(format!(
                        "{}: revocation head UNCHECKED for a run at {as_of}: {}",
                        h.organization, h.reason
                    )),
                    other => t.fail(format!(
                        "{}: revocation head {}: {}",
                        h.organization,
                        other.label(),
                        h.reason
                    )),
                }
            }
        }
    }
    let n = a.events.len();
    let row = grow(
        t,
        "Audit chain",
        Status::Satisfied,
        Some("WITNESSED, HEADS COVER THE RUN"),
        None,
    );
    if a.is_verified() {
        notes.push(format!(
            "{n} event(s) proven by inclusion in the signed checkpoint"
        ));
    }
    (row, notes)
}

// --- the report ---------------------------------------------------------------------

impl TrustGraph {
    /// The cross-agency trust report of one governed job: the base report
    /// first (every base row must pass), then the governance rows, from
    /// this graph's rebuilt evidence, the job's governance evidence and
    /// the project's log, checked against the caller's anchors only.
    pub fn governance_report(
        &self,
        ev: &GovernanceEvidence,
        audit: &AuditEvidence,
        opts: &GovernanceOptions<'_>,
    ) -> Result<GovernanceReport> {
        if ev.version != GOVERNANCE_EVIDENCE_VERSION {
            return Err(bad(format!("governance evidence version {}", ev.version)));
        }
        let disclosed;
        let ev = if opts.disclosures.is_empty() {
            ev
        } else {
            disclosed = ev.disclosed(&opts.disclosures);
            &disclosed
        };
        // The base report, with the caller's pinned governance keys
        // overriding anything the bundle anchors itself.
        let mut anchors: Anchors = opts.base.anchors.clone();
        for (o, k) in &opts.anchors.organizations {
            anchors
                .governance_keys
                .entry(o.clone())
                .or_insert_with(|| k.clone());
        }
        let base = self.report_with(&opts.base, &anchors)?;
        let g = self.rebuild().graph;
        let now = opts.now.unwrap_or_else(encompute_attestation::unix_now);

        let grant_state = check_grant(ev, &opts.anchors);
        let (gg, grant_verified) = match &grant_state {
            GrantState::Verified(gg) => (*gg, true),
            GrantState::Unpinned(gg) => (*gg, false),
            GrantState::Bad(m) => {
                return Ok(finish(
                    base,
                    failed_all(&format!("the job grant is not valid: {m}")),
                    vec![],
                    vec![],
                    vec![],
                ));
            }
        };
        let binding = &gg.binding;
        let t0 = ev.grant.issued_at;
        let as_of = opts.as_of.map_or(t0, |x| x.max(t0));
        let program = match g.node(&node_id(NodeKind::Program, &ev.spec.program_id)) {
            Some(n) => match &n.evidence {
                Some(Evidence::Program(text)) => parse(text).ok(),
                _ => None,
            },
            None => None,
        };
        let plan = g.of(NodeKind::Plan).find_map(|(_, n)| match &n.evidence {
            Some(Evidence::Plan(p))
                if p.id().map(|i| i.hex()).ok().as_deref() == Some(gg.plan_hash.as_str()) =>
            {
                Some(p.as_ref())
            }
            _ => None,
        });
        let mut participants: BTreeSet<String> = binding
            .inputs
            .values()
            .map(|i| i.organization.clone())
            .collect();
        participants.insert(ev.grant.organization.clone());
        let owners: BTreeSet<String> = binding
            .inputs
            .values()
            .map(|i| i.organization.clone())
            .collect();
        let auth_ids: BTreeSet<String> = authorizations(ev, &opts.anchors)
            .into_iter()
            .map(|a| a.id)
            .collect();
        let findings = check_audit(
            audit,
            &opts.anchors,
            &owners,
            &participants,
            &auth_ids,
            as_of,
        );
        let job = Job {
            ev,
            gg,
            binding,
            t0,
            auths: authorizations(ev, &opts.anchors),
            program,
            plan,
            audit: &findings,
            anchors: &opts.anchors,
            participants,
        };
        let (audit_row, audit_notes) = row_audit(&job, as_of);
        let mut rows = vec![
            row_project(&job),
            row_organizations(&job),
            row_key_custody(&job),
            row_purpose(&job),
            row_source_assets(&job),
            row_linkage(&job),
            row_raw_data(&job),
            row_decryption(),
            row_ownership(&job),
            row_location(&job),
            row_mechanism(&job),
            row_approvals(&job),
            row_window(&job),
            row_releases(&job),
            row_privacy(&job, &base),
            row_execution(&job, &g),
            audit_row,
        ];
        if !grant_verified {
            for r in &mut rows {
                if is_pass(r.status) {
                    r.status = Status::Unchecked;
                    r.value = Some("UNKNOWN".into());
                    r.details.push(
                        "the control plane's key is not pinned: the signed grant (its binding, time and authorization set) was not verified"
                            .into(),
                    );
                }
            }
        }
        // What each authorization says now: informational, never failing.
        let mut authorization_now = vec![];
        for a in &job.auths {
            let r = revoked(&job, a);
            let state = if r.key.is_some_and(|at| at <= now) {
                "REVOKED (its governance key was revoked)"
            } else if r.authorization.is_some_and(|at| at <= now) {
                "REVOKED"
            } else if !a.body.is_valid_at(now) {
                "EXPIRED"
            } else {
                "VALID"
            };
            authorization_now.push(format!("{}: now: {state}", job.describe_card(a)));
        }
        let revs = revocations(&job);
        Ok(finish(base, rows, revs, authorization_now, audit_notes))
    }
}

fn finish(
    base: TrustReport,
    rows: Vec<GovernanceRow>,
    revocations: Vec<RevocationNote>,
    authorization_now: Vec<String>,
    audit_notes: Vec<String>,
) -> GovernanceReport {
    let mut failed = vec![];
    let mut unchecked = vec![];
    for r in &base.rows {
        if r.name == "Owner authorization" {
            continue;
        }
        match r.status {
            Status::Failed => failed.push(format!("{} failed", r.name)),
            Status::Unchecked => unchecked.push(format!(
                "{} is not checked against trusted keys or policies",
                r.name
            )),
            _ => {}
        }
    }
    for u in &base.unmet {
        // The version 1 owner-authorization row does not apply in a governed
        // project: the owners' version 2 authorizations are checked by the
        // cross-agency rows, which are stricter.
        if u.starts_with("Owner authorization") {
            continue;
        }
        if !failed.contains(u) && !unchecked.contains(u) {
            unchecked.push(u.clone());
        }
    }
    for r in &rows {
        match r.status {
            Status::Failed => failed.push(format!("{} failed", r.name)),
            Status::Unchecked => unchecked.push(format!("{} is unchecked or unknown", r.name)),
            Status::NotPresent => unchecked.push(format!("{} is not evidenced", r.name)),
            _ => {}
        }
    }
    let verdict = if !failed.is_empty() {
        Verdict::NotSatisfied
    } else if !unchecked.is_empty() {
        Verdict::NotFullyEvidenced
    } else {
        Verdict::Satisfied
    };
    let mut unmet = failed;
    unmet.extend(unchecked);
    unmet.dedup();
    GovernanceReport {
        base,
        rows,
        revocations,
        authorization_now,
        audit_notes,
        verdict,
        unmet,
        legal_boundary: LEGAL_BOUNDARY,
    }
}

impl fmt::Display for GovernanceReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "CROSS-AGENCY TRUST REPORT")?;
        writeln!(f, "bundle {}\n", &self.base.root[..16])?;
        writeln!(f, "BASE TRUST REPORT")?;
        for r in &self.base.rows {
            writeln!(f, "{:<26}{}", r.name, r.status)?;
            for d in &r.details {
                writeln!(f, "  - {d}")?;
            }
            if r.name == "Owner authorization" {
                writeln!(
                    f,
                    "  - not counted in a governed project: the owners' version 2 authorizations are checked by the cross-agency rows"
                )?;
            }
        }
        writeln!(f, "\nCROSS-AGENCY ROWS")?;
        for r in &self.rows {
            match &r.value {
                Some(v) if v != "NOT APPLICABLE" && v != "NOT EVIDENCED" => {
                    writeln!(f, "{:<26}{} ({v})", r.name, r.status)?
                }
                _ => writeln!(f, "{:<26}{}", r.name, r.status)?,
            }
            for d in &r.details {
                writeln!(f, "  - {d}")?;
            }
        }
        for l in &self.authorization_now {
            writeln!(f, "  - {l} (informational)")?;
        }
        for n in &self.audit_notes {
            writeln!(f, "  - audit: {n}")?;
        }
        if !self.revocations.is_empty() {
            writeln!(f, "\nREVOCATIONS (stay on record; nothing is erased)")?;
            for r in &self.revocations {
                writeln!(
                    f,
                    "  {} {} {} at {}{}",
                    r.organization.as_deref().unwrap_or("-"),
                    r.kind,
                    r.subject,
                    r.at,
                    if r.downstream.is_empty() {
                        String::new()
                    } else {
                        format!("; derived results: {}", r.downstream.join(", "))
                    }
                )?;
            }
        }
        writeln!(f, "\nRESULT")?;
        match self.verdict {
            Verdict::Satisfied => writeln!(f, "CROSS-AGENCY REQUIREMENTS SATISFIED")?,
            Verdict::NotFullyEvidenced => {
                writeln!(f, "CROSS-AGENCY REQUIREMENTS NOT FULLY EVIDENCED")?;
                for u in &self.unmet {
                    writeln!(f, "  - {u}")?;
                }
            }
            Verdict::NotSatisfied => {
                writeln!(f, "CROSS-AGENCY REQUIREMENTS NOT SATISFIED")?;
                for u in &self.unmet {
                    writeln!(f, "  - {u}")?;
                }
            }
        }
        writeln!(f, "{}", self.legal_boundary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> TrustReport {
        TrustReport {
            root: "0".repeat(64),
            rows: vec![],
            revoked: Default::default(),
            unmet: vec![],
            satisfied: true,
        }
    }

    fn row(name: &'static str, status: Status) -> GovernanceRow {
        GovernanceRow {
            name,
            status,
            value: None,
            details: vec![],
        }
    }

    /// The verdict is SATISFIED only when every row passes or is not
    /// applicable with backing; one unchecked or not evidenced row makes
    /// it NOT FULLY EVIDENCED, and one failure NOT SATISFIED.
    #[test]
    fn the_verdict_follows_the_worst_row() {
        let rows = |s: Status| {
            vec![
                row("A", Status::Satisfied),
                row("B", Status::NotApplicable),
                row("C", s),
            ]
        };
        let v = |s| finish(base(), rows(s), vec![], vec![], vec![]).verdict;
        assert_eq!(v(Status::Verified), Verdict::Satisfied);
        assert_eq!(v(Status::NotApplicable), Verdict::Satisfied);
        assert_eq!(v(Status::Unchecked), Verdict::NotFullyEvidenced);
        assert_eq!(v(Status::NotPresent), Verdict::NotFullyEvidenced);
        assert_eq!(v(Status::Failed), Verdict::NotSatisfied);
        // A failed base row is never outvoted.
        let mut b = base();
        b.rows.push(crate::report::Row {
            name: "Plan",
            status: Status::Failed,
            details: vec![],
        });
        let r = finish(b, rows(Status::Verified), vec![], vec![], vec![]);
        assert_eq!(r.verdict, Verdict::NotSatisfied);
        // The report names the line only for a verdict of SATISFIED.
        let ok = finish(base(), rows(Status::Verified), vec![], vec![], vec![]);
        assert!(ok
            .to_string()
            .contains("CROSS-AGENCY REQUIREMENTS SATISFIED"));
        assert!(ok.to_string().contains(LEGAL_BOUNDARY));
    }
}
