//! Plans, jobs, evaluators and scheduling.
//!
//! A job moves through explicit, validated states. The control plane never
//! sees inputs or outputs: the client encrypts, sends ciphertexts to the
//! scheduled evaluator with the job's grant, decrypts, and reports the
//! evaluator's signed receipt with its own commitments to the exact bytes.
//! The evaluator asks the control plane before starting (so a job revoked
//! or cancelled after scheduling never starts), and reports completion as a
//! signed message.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use postgres::{GenericClient, Transaction};

// A governed job's evidence bundle (child module: it reads the job rows).
#[path = "governance_bundle.rs"]
pub(crate) mod governance_bundle;
use serde_json::{json, Value};

use encompute_evaluator::{compile_program, execution_spec, transcript_for, CompiledProgram, Ids};
use encompute_ir::{Code, Error, Program, Result};
use encompute_planner::{
    plan_or_fail, verify_plan, verify_plan_with, BackendCatalog, ConfidentialExecutionPlan,
    Infrastructure, Origin, PlacementContext, PlacementSource, PlanFloor, PlanningContext,
    Preferences, Profile, ProgramFacts, Roles, SourceCustody,
};
use encompute_trust::authz::{
    job_approval_statement, quorum_met, AuthorizationSetId, SignedAuthorizationV2,
};
use encompute_verification::governance::{
    is_hex32, release_within, GovernanceBinding, GovernanceInput, GrantGovernance, ReleaseClass,
    GOVERNANCE_BINDING_VERSION,
};
use encompute_verification::service::{
    now, sha256_hex, verify_signed, UploadGrant, UploadKind, JOB_GRANT, JOB_GRANT_V2, UPLOAD_GRANT,
    UPLOAD_GRANT_TTL_SECS, UPLOAD_GRANT_VERSION,
};
use encompute_verification::{
    verify_receipt, EvaluatorIdentity, ExecutionSpec, ExpectedExecution, SignedExecutionReceipt,
};

use crate::audit::{self, Outcome};
use crate::authn::PrincipalKind;
use crate::authz::{
    asset_visible, conflict, deny_auditor, forbidden, not_found, project_role_orgs, project_row,
    project_visible, require, require_human_not_submitter, ProjectRow,
};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::log::LogLine;
use crate::model::{
    bad, check_name, new_id, CompleteJob, CreatePlan, EvaluatorStatus, JobGrant, JobState, JobView,
    KeyRef, MessageEnvelope, RegisterEvaluator, RequestUploadGrant, Role, ServiceKind, SubmitJob,
    JOB_GRANT_TTL_SECS, JOB_GRANT_VERSION, PLATFORM_ORG,
};

/// Evaluators silent for longer are unhealthy.
pub const HEARTBEAT_TIMEOUT_SECS: u64 = 90;

/// The scheduler's cost of one bootstrapped gate on one core, in
/// milliseconds: OpenFHE BinFHE at STD128 (GINX) measures about 55 ms per
/// gate. A ranking constant: placement compares evaluators by it, it
/// promises no latency.
pub const GATE_MS: u64 = 55;

/// A job's scheduling work: its bootstrapped gates, and at least one unit
/// (CKKS jobs and plans made before estimates count one each, so load still
/// spreads).
fn work_units(estimated_gates: u64) -> u64 {
    estimated_gates.max(1)
}

/// Estimated completion time (ms) of a job of `gates` on an evaluator
/// already holding `queued_units` of work, running
/// `min(max_parallel_gates, logical_cores)` gates at a time (whichever it
/// advertised; one when it advertised neither). The machine profile is
/// self-reported: it steers placement, never a security decision.
pub fn estimated_ms(
    queued_units: u64,
    gates: u64,
    logical_cores: Option<i32>,
    max_parallel_gates: Option<i32>,
) -> u64 {
    let parallel = match (max_parallel_gates, logical_cores) {
        (Some(p), Some(c)) => p.min(c),
        (Some(n), None) | (None, Some(n)) => n,
        (None, None) => 1,
    }
    .max(1) as u64;
    queued_units
        .saturating_add(work_units(gates))
        .saturating_mul(GATE_MS)
        / parallel
}

/// Bootstrapped gates a compiled program costs (exact programs); 0 for
/// CKKS, or when the count is unavailable.
fn estimated_gates(c: &CompiledProgram) -> u64 {
    c.exact()
        .and_then(|e| encompute_exact::bits::gate_count(&e.plan).ok())
        .unwrap_or(0)
}

/// The parameter profile a job needs from its evaluator.
pub fn job_profile(c: &CompiledProgram) -> String {
    match c.exact() {
        Some(e) => e.profile.profile.clone(),
        None => encompute_evaluator::CKKS_PROFILE.into(),
    }
}

/// What the compiler knows about a program, for the planner.
fn facts(program: &Program) -> Result<ProgramFacts> {
    use encompute_analysis::Semantics;
    let semantics = encompute_analysis::semantics(program)?;
    let (name, fhe_supported, proof_covered, (binfhe_ms, bgv_ms)) = match semantics {
        Semantics::Approximate => (
            "approximate",
            encompute_ckks::compile(program).is_ok(),
            false,
            (None, None),
        ),
        Semantics::Exact => match encompute_exact::compile(program) {
            Ok(c) => (
                "exact",
                true,
                encompute_evaluator::proof_coverable(&c.plan),
                // The estimates the evaluator's compiler selects the backend by.
                encompute_evaluator::exact_estimates(&c.plan),
            ),
            Err(_) => ("exact", false, false, (None, None)),
        },
    };
    Ok(ProgramFacts {
        semantics: name.into(),
        fhe_supported,
        proof_covered,
        operations: program.nodes().len() as u64,
        binfhe_ms,
        bgv_ms,
    })
}

/// The backends the control plane accepts in a plan: every production
/// backend it schedules, never a research one. (Which of them the
/// deployment offers right now changes as evaluators register; a stored
/// plan stays valid meanwhile.)
fn accepted_catalog() -> BackendCatalog {
    BackendCatalog {
        ckks: true,
        tfhe: false,
        openfhe_exact: true,
        bgv: true,
        verified_execution: true,
    }
}

/// A plan's stored document.
#[derive(serde::Serialize, serde::Deserialize)]
struct PlanDoc {
    plan_id: String,
    plan: ConfidentialExecutionPlan,
    scheme: String,
    backend: String,
    backend_version: String,
    profile: String,
    proof_required: bool,
    /// Bootstrapped gates (exact programs; 0 for CKKS). Absent from plans
    /// made before schema version 2.
    #[serde(default)]
    estimated_gates: u64,
}

/// What a job's program declares about its sources: its purpose, and the
/// registered assets its secret inputs are bound to (a program names a
/// registered asset by its ID in an `asset` declaration). The bound assets
/// are the job's authoritative sources: the server derives them from the
/// program, and never takes a request's list as provenance.
struct SourceBinding {
    purpose: Option<String>,
    assets: std::collections::BTreeSet<String>,
}

impl SourceBinding {
    fn of(c: &mut impl GenericClient, program: &Program) -> Result<Self> {
        let conf = program.confidentiality();
        let named: Vec<String> = conf
            .map(|c| {
                c.inputs
                    .values()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>()
            })
            .unwrap_or_default()
            .into_iter()
            .collect();
        let assets = if named.is_empty() {
            Default::default()
        } else {
            c.query("SELECT id FROM assets WHERE id = ANY($1)", &[&named])
                .map_err(db_err)?
                .iter()
                .map(|r| r.get(0))
                .collect()
        };
        Ok(Self {
            purpose: conf.and_then(|c| c.purpose.clone()),
            assets,
        })
    }

    /// The job's sources, as recorded: the program's bound assets, in order.
    fn sources(&self) -> Vec<String> {
        self.assets.iter().cloned().collect()
    }

    /// Sovereign custody of each source: its owner organization and the key
    /// broker holding its key, which must be an active broker that
    /// organization registered itself (never a platform broker, another
    /// organization's, or none: ENC2715). One entry per source, in order.
    fn custody(&self, c: &mut impl GenericClient) -> Result<Vec<SourceCustody>> {
        let mut out = Vec::with_capacity(self.assets.len());
        for a in &self.assets {
            let r = c
                .query_one(
                    "SELECT organization_id, key_ref FROM assets WHERE id = $1",
                    &[a],
                )
                .map_err(db_err)?;
            let organization: String = r.get(0);
            let broker = r
                .get::<_, Option<Value>>(1)
                .and_then(|k| serde_json::from_value::<KeyRef>(k).ok())
                .map(|k| k.broker);
            super::require_own_broker(c, &organization, broker.as_deref())
                .map_err(|e| Error::new(e.code, format!("source {a}: {}", e.message)))?;
            out.push(SourceCustody {
                asset: a.clone(),
                organization,
                broker: broker.expect("checked above"),
            });
        }
        Ok(out)
    }

    /// The request must state the program's purpose, and list exactly the
    /// registered assets the program binds, each once: nothing the program
    /// reads may be left out, nothing it does not read may be added or
    /// stand in (another version of a dataset is another asset), and a
    /// program that binds none lists none. The job record, revocation,
    /// audit and the trust report follow these sources.
    /// Refusals carry their audit reason.
    fn check(
        &self,
        purpose: &str,
        sources: &[String],
    ) -> std::result::Result<(), (&'static str, Error)> {
        if let Some(p) = &self.purpose {
            if p != purpose {
                return Err((
                    "purpose_mismatch",
                    forbidden(format!(
                        "the request's purpose {purpose:?} is not the one the program declares, {p:?}"
                    )),
                ));
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        if let Some(a) = sources.iter().find(|a| !seen.insert(a.as_str())) {
            return Err((
                "duplicate_source",
                forbidden(format!("asset {a} is listed as a source more than once")),
            ));
        }
        if let Some(a) = self.assets.iter().find(|a| !sources.contains(a)) {
            return Err((
                "unlisted_source",
                forbidden(format!(
                    "the program reads asset {a}, which the job does not list as a source"
                )),
            ));
        }
        if let Some(a) = sources.iter().find(|a| !self.assets.contains(*a)) {
            let why = if self.assets.is_empty() {
                "the program binds no input to a registered asset, so the job lists no source"
            } else {
                "the program reads no input from it"
            };
            return Err((
                "undeclared_source",
                forbidden(format!("asset {a} is listed as a source, but {why}")),
            ));
        }
        Ok(())
    }
}

/// What a governed job is bound to (`jobs.governance`), fixed at
/// submission: the governance binding its execution spec carries, the
/// plan's PlanId, and the owner authorizations it runs under (one per
/// source).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JobGovernance {
    binding: GovernanceBinding,
    governance_id: String,
    /// The plan's PlanId (hex), which the version 2 grant carries.
    plan_hash: String,
    authorization_set_id: String,
    /// Authorization row → its AuthorizationId.
    authorizations: BTreeMap<String, String>,
    /// Source version → the owner's key reference at submission. Kept on
    /// the job only (the binding's broker map is keyed by version and
    /// names no key), so a key re-bound under another name is refused at
    /// start as before.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    source_keys: BTreeMap<String, String>,
}

/// The lifecycle transitions of a governed job that revalidate it:
/// submission builds and checks its binding and authorizations, then each
/// per-job approval, scheduling and start call `revalidate_governed` once.
/// Completion does not (a job that started inside its window may complete
/// after it); release tickets are checked again at the owner's broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernedStage {
    /// A person's per-job four-eyes approval (the quorum is what it
    /// collects, so it is not required yet).
    Approve,
    Schedule,
    Start,
    /// A release or export ticket for a running job: everything start
    /// checks except the privacy budget (start has reserved it already).
    Ticket,
}

impl GovernedStage {
    pub fn as_str(self) -> &'static str {
        match self {
            GovernedStage::Approve => "approve",
            GovernedStage::Schedule => "schedule",
            GovernedStage::Start => "start",
            GovernedStage::Ticket => "ticket",
        }
    }
}

/// A refusal in a governed project.
fn gov(code: Code, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

/// A submission refusal to audit: (resource type, resource, organization,
/// reason).
type Denied = RefCell<Option<(&'static str, String, String, &'static str)>>;

struct JobRow {
    id: String,
    organization: String,
    project: String,
    plan: String,
    spec_id: String,
    program_id: String,
    purpose: String,
    sources: Vec<String>,
    requested_output: String,
    scheme: String,
    backend: String,
    profile: String,
    state: JobState,
    evaluator: Option<String>,
    grant: Option<JobGrant>,
    receipt: Option<Value>,
    evidence: Option<Value>,
    error: Option<String>,
    initiated_by: String,
    created_at: SystemTime,
    estimated_gates: u64,
    estimated_ms: Option<u64>,
    /// Governed jobs: the purpose, the binding and authorizations, and
    /// when the job started (Unix seconds).
    purpose_id: Option<String>,
    governance: Option<JobGovernance>,
    started_at: Option<u64>,
}

fn job_row(c: &mut impl GenericClient, id: &str, lock: bool) -> Result<Option<JobRow>> {
    let q = format!(
        "SELECT id, organization_id, project_id, plan_id, spec_id, program_id, purpose, source_assets,
                requested_output, scheme, backend, profile, state, evaluator_id, job_grant, receipt,
                evidence, error, initiated_by, created_at, estimated_gates, estimated_ms,
                purpose_id, governance, floor(extract(epoch FROM started_at))::bigint
           FROM jobs WHERE id = $1 {}",
        if lock { "FOR UPDATE" } else { "" }
    );
    let Some(r) = c.query_opt(&q, &[&id]).map_err(db_err)? else {
        return Ok(None);
    };
    Ok(Some(JobRow {
        id: r.get(0),
        organization: r.get(1),
        project: r.get(2),
        plan: r.get(3),
        spec_id: r.get(4),
        program_id: r.get(5),
        purpose: r.get(6),
        sources: serde_json::from_value(r.get(7)).unwrap_or_default(),
        requested_output: r.get(8),
        scheme: r.get(9),
        backend: r.get(10),
        profile: r.get(11),
        state: JobState::parse(r.get(12))?,
        evaluator: r.get(13),
        grant: r
            .get::<_, Option<Value>>(14)
            .and_then(|v| serde_json::from_value(v).ok()),
        receipt: r.get(15),
        evidence: r.get(16),
        error: r.get(17),
        initiated_by: r.get(18),
        created_at: r.get(19),
        estimated_gates: r.get::<_, i64>(20).max(0) as u64,
        estimated_ms: r.get::<_, Option<i64>>(21).map(|v| v.max(0) as u64),
        purpose_id: r.get(22),
        governance: r
            .get::<_, Option<Value>>(23)
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| db_err(format!("stored job governance: {e}")))?,
        started_at: r.get::<_, Option<i64>>(24).map(|v| v.max(0) as u64),
    }))
}

/// What the privacy scopes need of a job.
fn privacy_facts(j: &JobRow) -> super::privacy_scopes::JobFacts {
    super::privacy_scopes::JobFacts {
        job: j.id.clone(),
        project: j.project.clone(),
        purpose: j.purpose.clone(),
        program: j.program_id.clone(),
        plan: j.plan.clone(),
    }
}

/// Whether `p` may see the job: its organization's members, and the
/// owners of its source assets; in a governed project everyone taking part
/// (members and auditor organizations, who get the shared view).
fn job_visible(c: &mut impl GenericClient, ctx: &Ctx, j: &JobRow) -> Result<()> {
    if ctx.principal.member_of(&j.organization) {
        return Ok(());
    }
    if matches!(ctx.principal.service_kind(), Some(ServiceKind::Evaluator))
        && j.evaluator.as_deref() == Some(ctx.actor())
    {
        return Ok(());
    }
    if j.governance.is_some() {
        let p = project_row(c, &j.project)?.ok_or_else(|| not_found("job", &j.id))?;
        return if p
            .members
            .iter()
            .chain(&p.auditors)
            .any(|o| ctx.principal.member_of(o))
        {
            Ok(())
        } else {
            Err(not_found("job", &j.id))
        };
    }
    let orgs: Vec<String> = ctx.principal.organizations().into_iter().collect();
    let owns = c
        .query_opt(
            "SELECT 1 FROM assets WHERE id = ANY($1) AND organization_id = ANY($2) LIMIT 1",
            &[&j.sources, &orgs],
        )
        .map_err(db_err)?;
    if owns.is_some() {
        Ok(())
    } else {
        Err(not_found("job", &j.id))
    }
}

/// The job's project; a governed one refuses an auditor (D9,
/// [`deny_auditor`]). Every call that changes a job takes it first.
fn job_project(c: &mut impl GenericClient, ctx: &Ctx, j: &JobRow) -> Result<ProjectRow> {
    let p = project_row(c, &j.project)?.ok_or_else(|| not_found("job", &j.id))?;
    deny_auditor(&ctx.principal, &p)?;
    Ok(p)
}

/// How `actor` appears to a viewer outside the submitting organization:
/// itself when it is the viewer's own or a platform service (evaluators,
/// the control plane, the scheduler), otherwise only its organization and
/// kind (`modelco/user`, `modelco/service`).
fn actor_label(c: &mut impl GenericClient, ctx: &Ctx, actor: &str) -> Result<String> {
    let owner = c
        .query_opt(
            "SELECT organization_id, 'user' FROM users WHERE id = $1
             UNION ALL
             SELECT organization_id, 'service' FROM service_accounts WHERE id = $1
             LIMIT 1",
            &[&actor],
        )
        .map_err(db_err)?
        .map(|r| (r.get::<_, Option<String>>(0), r.get::<_, String>(1)));
    Ok(match owner {
        Some((Some(org), kind)) if org != PLATFORM_ORG && !ctx.principal.member_of(&org) => {
            format!("{org}/{kind}")
        }
        // A platform principal, the viewer's own, or not a principal (the
        // control plane itself, an operator's recovery).
        _ => actor.to_owned(),
    })
}

impl Control {
    /// What the deployment offers. A standard project counts only the
    /// platform's evaluators: an operator-owned one is scheduled for
    /// governed jobs that admit it, never for a standard job.
    fn catalog(&self, c: &mut impl GenericClient, governed: bool) -> Result<BackendCatalog> {
        let backends: Vec<String> = c
            .query(
                // (A draining or briefly silent evaluator does not change
                // which plans are possible; scheduling checks health.)
                "SELECT DISTINCT jsonb_array_elements_text(e.backends)
                   FROM evaluators e JOIN service_accounts s ON s.id = e.service_account
                  WHERE $1 OR s.organization_id IS NULL",
                &[&governed],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        let has = |b: &str| backends.iter().any(|x| x == b);
        Ok(BackendCatalog {
            ckks: has("openfhe"),
            // The control plane never plans research backends.
            tfhe: false,
            openfhe_exact: has("openfhe-exact"),
            bgv: has("openfhe"),
            verified_execution: has("vfhe"),
        })
    }

    // --- plans ------------------------------------------------------------------

    /// Checks a plan (one just made, or one loaded from the database) for
    /// its program. In production also against the control plane's own
    /// floor, never the context the plan declares about itself: the
    /// compiler's facts for the program, production backends only (never a
    /// research one), production attestation only, and at least the
    /// standard profile.
    pub fn verify_stored_plan(
        &self,
        program: &Program,
        plan: &ConfidentialExecutionPlan,
    ) -> Result<()> {
        if !self.env.is_production() {
            return verify_plan(program, plan);
        }
        verify_plan_with(
            program,
            plan,
            &PlanFloor {
                facts: Some(facts(program)?),
                catalog: Some(accepted_catalog()),
                ..PlanFloor::production(Profile::Standard)
            },
        )
    }

    pub fn create_plan(&self, ctx: &Ctx, r: CreatePlan) -> Result<Value> {
        if r.program.len() > 4 << 20 {
            return Err(bad("program too large"));
        }
        // Authorized before any parsing or compiling: a caller outside the
        // project costs no compilation.
        let mut c = self.db.conn()?;
        let project = project_visible(&mut *c, &ctx.principal, &r.project)?;
        deny_auditor(&ctx.principal, &project)?;
        let orgs = project_role_orgs(
            &ctx.principal,
            &project,
            &[Role::MlDeveloper, Role::OrganizationAdmin],
        );
        let Some(org) = orgs.first().cloned() else {
            return Err(forbidden(
                "planning needs ml_developer in a project member organization",
            ));
        };
        drop(c);
        let program = encompute_ir::parse(&r.program)?;
        let compiled = compile_program(&program)?;
        let ids = Ids::of(&program, &compiled);
        let target = compiled.target_backend();
        let spec = execution_spec(&ids, &compiled, target);
        let mut c = self.db.conn()?;
        // Sovereign custody: each source's key at a broker its own
        // organization registered, bound into the plan. Otherwise: some
        // active key broker.
        let (key_broker, custody) = if project.sovereign() {
            let custody = match SourceBinding::of(&mut *c, &program)?.custody(&mut *c) {
                Ok(k) => k,
                Err(e) => {
                    self.metrics.inc("encompute_plans_failed_total", "custody");
                    self.audit_denied(
                        ctx.draft("plan.failed", "project", &r.project, Outcome::Denied)
                            .org(&org)
                            .project(&r.project)
                            .r#ref("program", ids.program_id.clone())
                            .r#ref("reason", "source_custody"),
                    );
                    return Err(e);
                }
            };
            (!custody.is_empty(), custody)
        } else {
            let any = c
                .query_opt(
                    "SELECT 1 FROM service_accounts WHERE kind = 'keybroker' AND status = 'active' LIMIT 1",
                    &[],
                )
                .map_err(db_err)?
                .is_some();
            (any, Vec::new())
        };
        // A governed project's plan names where it may run: the project's
        // constraints (which every member holds), the table they are read
        // against, and the evaluators on offer now. An owner's own
        // constraints are applied where the job is bound, never carried
        // here.
        let placement = if project.governed() {
            Some(PlacementContext {
                constraints: super::placement::project_placement(&mut *c, &r.project)?
                    .map(|p| {
                        vec![PlacementSource {
                            origin: Origin::Project(r.project.clone()),
                            constraints: p.constraints,
                        }]
                    })
                    .unwrap_or_default(),
                locations_digest: encompute_planner::locations::digest(),
                production: self.env.is_production(),
                roles: Roles {
                    source_owners: custody.iter().map(|k| k.organization.clone()).collect(),
                    participants: project.members.iter().cloned().collect(),
                    ..Roles::default()
                },
            })
        } else {
            None
        };
        // Only evaluators this project may use are put in its plan: the
        // platform's, its members' and those a constraint names. Another
        // tenant's infrastructure is not shown to the project.
        let evaluators = match &placement {
            Some(pc) => super::placement::evaluator_offers(&mut *c)?
                .into_iter()
                .filter(|o| {
                    o.operator == encompute_planner::placement::PLATFORM_OPERATOR
                        || pc.roles.participants.contains(&o.operator)
                        || pc.constraints.iter().any(|s| {
                            s.constraints
                                .allowed_operators
                                .as_ref()
                                .is_some_and(|x| x.contains(&o.operator))
                                || s.constraints
                                    .allowed_evaluators
                                    .as_ref()
                                    .is_some_and(|x| x.contains(&o.id))
                        })
                })
                .collect(),
            None => vec![],
        };
        let pctx = PlanningContext {
            profile: Profile::Standard,
            catalog: self.catalog(&mut *c, project.governed())?,
            infrastructure: Infrastructure {
                evaluators,
                tees: vec![],
                key_broker,
                host_cloud: true,
                host_region: None,
            },
            preferences: Preferences::default(),
            facts: facts(&program)?,
            training: None,
            custody,
            placement,
        };
        drop(c);
        let plan = match plan_or_fail(&program, &pctx) {
            Ok(p) => p,
            Err(e) => {
                self.metrics.inc("encompute_plans_failed_total", "planning");
                self.audit_denied(
                    ctx.draft("plan.failed", "project", &r.project, Outcome::Failed)
                        .org(&org)
                        .project(&r.project)
                        .r#ref("program", ids.program_id.clone()),
                );
                return Err(e);
            }
        };
        self.verify_stored_plan(&program, &plan)?;
        let plan_id = plan.id()?.to_string();
        let (backend, backend_version) = target.label();
        let doc = PlanDoc {
            plan_id: plan_id.clone(),
            plan,
            scheme: compiled.scheme().into(),
            backend: backend.into(),
            backend_version: backend_version.into(),
            profile: job_profile(&compiled),
            proof_required: compiled.proof_required(),
            estimated_gates: estimated_gates(&compiled),
        };
        let id = new_id("pln");
        self.tx_anchored(|t| {
            t.execute(
                "INSERT INTO plans (id, organization_id, project_id, program_id, spec_id, program, document, created_by)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &id,
                    &org,
                    &r.project,
                    &ids.program_id,
                    &spec.id().hex(),
                    &program.to_string(),
                    &serde_json::to_value(&doc).expect("serializable"),
                    &ctx.actor(),
                ],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                ctx.draft("plan.created", "plan", &id, Outcome::Succeeded)
                    .org(&org)
                    .project(&r.project)
                    .r#ref("plan_id", plan_id.clone())
                    .r#ref("program", ids.program_id.clone())
                    .r#ref("spec", spec.id().hex()),
            )?;
            Ok(())
        })?;
        Ok(json!({
            "id": id, "project": r.project, "organization": org, "plan_id": plan_id,
            "program_id": ids.program_id, "spec_id": spec.id().hex(),
            "scheme": doc.scheme, "backend": doc.backend, "profile": doc.profile,
            "mechanisms": doc.plan.selected_mechanisms,
            "estimated_gates": doc.estimated_gates,
            "estimated_single_core_ms": doc.estimated_gates.saturating_mul(GATE_MS),
        }))
    }

    /// The execution spec of a stored plan (its program compiled again),
    /// before any governance binding.
    pub(crate) fn plan_spec(
        &self,
        c: &mut impl GenericClient,
        plan: &str,
    ) -> Result<ExecutionSpec> {
        self.load_plan(c, plan).map(|(_, _, spec, _)| spec)
    }

    /// The program, compiled spec and plan document of a stored plan.
    fn load_plan(
        &self,
        c: &mut impl GenericClient,
        plan: &str,
    ) -> Result<(Program, CompiledProgram, ExecutionSpec, PlanDocView)> {
        let r = c
            .query_opt(
                "SELECT program, document FROM plans WHERE id = $1",
                &[&plan],
            )
            .map_err(db_err)?
            .ok_or_else(|| not_found("plan", plan))?;
        let program = encompute_ir::parse(r.get(0))?;
        let compiled = compile_program(&program)?;
        let spec = execution_spec(
            &Ids::of(&program, &compiled),
            &compiled,
            compiled.target_backend(),
        );
        let doc: PlanDoc = serde_json::from_value(r.get(1)).map_err(db_err)?;
        Ok((program, compiled, spec, PlanDocView { doc }))
    }

    // --- jobs -------------------------------------------------------------------

    /// Records a state transition (validated) in the caller's transaction.
    pub fn transition_in(
        &self,
        t: &mut Transaction<'_>,
        actor: &str,
        _request: &str,
        job: &str,
        to: JobState,
        reason: Option<&str>,
    ) -> Result<()> {
        let r = t
            .query_one(
                "SELECT state, project_id, organization_id FROM jobs WHERE id = $1 FOR UPDATE",
                &[&job],
            )
            .map_err(db_err)?;
        let from = JobState::parse(r.get(0))?;
        let (project, org): (String, String) = (r.get(1), r.get(2));
        if !from.can_go_to(to) {
            return Err(conflict(format!(
                "job {job} cannot go from {} to {}",
                from.as_str(),
                to.as_str()
            )));
        }
        let seq: i32 = t
            .query_one(
                "SELECT count(*)::int + 1 FROM job_transitions WHERE job_id = $1",
                &[&job],
            )
            .map_err(db_err)?
            .get(0);
        t.execute(
            "INSERT INTO job_transitions (job_id, seq, from_state, to_state, actor, reason)
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[&job, &seq, &from.as_str(), &to.as_str(), &actor, &reason],
        )
        .map_err(db_err)?;
        t.execute(
            "UPDATE jobs SET state = $2, updated_at = now(), error = COALESCE($3, error) WHERE id = $1",
            &[&job, &to.as_str(), &(if to == JobState::Failed { reason } else { None })],
        )
        .map_err(db_err)?;
        // An ended job never runs again: recorded in the governance log.
        let ended = match to {
            JobState::Failed => Some(crate::govlog::kind::JOB_FAILED),
            JobState::Cancelled => Some(crate::govlog::kind::JOB_CANCELLED),
            _ => None,
        };
        if let Some(kind) = ended {
            let partition = crate::govlog::for_project(t, &project, Some(&org))?;
            crate::govlog::append(
                t,
                crate::govlog::Draft::new(partition, kind, job)
                    .org(&org)
                    .r#ref("project", project.as_str()),
            )?;
        }
        self.metrics.inc("encompute_jobs_total", to.as_str());
        Ok(())
    }

    /// Submits a job. `idempotency_key` makes retries safe: the same key
    /// and request return the same job; the same key with another request
    /// is a conflict. Nothing security-sensitive happens twice.
    pub fn submit_job(
        &self,
        ctx: &Ctx,
        r: SubmitJob,
        idempotency_key: &str,
        request_digest: &str,
    ) -> Result<(Value, bool)> {
        check_name("Idempotency-Key", idempotency_key)?;
        check_name("purpose", &r.purpose)?;
        check_name("requested_output", &r.requested_output)?;
        for attempt in 0..3 {
            match self.submit_once(ctx, &r, idempotency_key, request_digest) {
                Err(e) if e.code == Code::Remote && e.message.contains("unique") && attempt < 2 => {
                    continue
                }
                other => {
                    if let Ok((ref v, true)) = other {
                        let id = v["id"].as_str().unwrap_or_default().to_owned();
                        self.schedule_after(&id);
                        return Ok((self.job_view(ctx, &id)?, true));
                    }
                    return other;
                }
            }
        }
        Err(conflict("concurrent submissions with this Idempotency-Key"))
    }

    fn submit_once(
        &self,
        ctx: &Ctx,
        r: &SubmitJob,
        key: &str,
        digest: &str,
    ) -> Result<(Value, bool)> {
        let denied: Denied = RefCell::new(None);
        let out = self.tx_anchored(|t| {
            let project = project_visible(t, &ctx.principal, &r.project)?;
            deny_auditor(&ctx.principal, &project)?;
            let orgs = project_role_orgs(&ctx.principal, &project, &[Role::MlDeveloper]);
            let Some(org) = orgs.first().cloned() else {
                return Err(forbidden("submitting a job needs ml_developer in a project member organization"));
            };
            // A purpose object and declared releases belong to governed
            // projects; a standard project's request is as it always was.
            if !project.governed() && (r.purpose_id.is_some() || r.outputs.is_some()) {
                return Err(bad(
                    "purpose_id and outputs belong to jobs in governed projects",
                ));
            }
            if let Some(row) = t
                .query_opt(
                    "SELECT id, request_digest FROM jobs WHERE organization_id = $1 AND idempotency_key = $2",
                    &[&org, &key],
                )
                .map_err(db_err)?
            {
                let (id, d): (String, String) = (row.get(0), row.get(1));
                if d != digest {
                    return Err(conflict("this Idempotency-Key was used for a different request"));
                }
                return Ok((json!({"id": id}), false));
            }
            let plan = t
                .query_opt(
                    "SELECT spec_id, program_id, document, program FROM plans WHERE id = $1 AND project_id = $2",
                    &[&r.plan, &r.project],
                )
                .map_err(db_err)?
                .ok_or_else(|| not_found("plan", &r.plan))?;
            let doc: PlanDoc = serde_json::from_value(plan.get(2)).map_err(db_err)?;
            // What the job is for, and which registered assets it reads, are
            // the program's declarations (bound into its program and spec
            // IDs), never only the request's word.
            let program = encompute_ir::parse(plan.get::<_, &str>(3))?;
            if project.governed() {
                return self.submit_governed(
                    t,
                    ctx,
                    r,
                    Submission {
                        project: &project,
                        org: &org,
                        key,
                        digest,
                        doc: &doc,
                        program: &program,
                        program_id: plan.get(1),
                    },
                    &denied,
                );
            }
            let binding = SourceBinding::of(t, &program)?;
            // A listed asset the program does not bind is refused below;
            // one the caller cannot see is not found, as anywhere else (the
            // refusal never tells an unknown ID from a hidden one).
            for a in r.source_assets.iter().filter(|a| !binding.assets.contains(*a)) {
                asset_visible(t, &ctx.principal, a)?;
            }
            if let Err((why, e)) = binding.check(&r.purpose, &r.source_assets) {
                *denied.borrow_mut() = Some(("plan", r.plan.clone(), org.clone(), why));
                return Err(e);
            }
            // From here on the sources are the derived set (equal to the
            // request's list, which only confirms it).
            let sources = binding.sources();
            if let Some(pol) = &r.policy {
                let ok = t
                    .query_opt(
                        "SELECT 1 FROM policies WHERE id = $1 AND project_id = $2 AND status = 'approved'",
                        &[pol, &r.project],
                    )
                    .map_err(db_err)?;
                if ok.is_none() {
                    return Err(not_found("approved policy", pol));
                }
            }
            let mut needs_approval = std::collections::BTreeSet::new();
            // Lock the source assets (shared) until this transaction ends: a
            // concurrent revocation either commits first (and is seen here)
            // or waits, then finds this job and fails it.
            t.execute("SELECT 1 FROM assets WHERE id = ANY($1) FOR SHARE", &[&sources])
                .map_err(db_err)?;
            for a in &sources {
                let asset = asset_visible(t, &ctx.principal, a)?;
                if asset.status == "revoked" {
                    *denied.borrow_mut() = Some(("asset", a.clone(), org.clone(), "revoked"));
                    return Err(conflict(format!("asset {a} is revoked")));
                }
                if asset.organization != org {
                    // Another organization's approval is for a purpose: the
                    // program must declare which.
                    if binding.purpose.is_none() {
                        *denied.borrow_mut() = Some(("asset", a.clone(), org.clone(), "no_declared_purpose"));
                        return Err(forbidden(format!(
                            "asset {a} belongs to {}: a program using it declares its purpose \
                             (`purpose \"...\"` on its `program` line)",
                            asset.organization
                        )));
                    }
                    // ...and reads it by its registered ID: another
                    // organization's approval never covers a source the
                    // program does not declare.
                    if !binding.assets.contains(a) {
                        *denied.borrow_mut() = Some(("asset", a.clone(), org.clone(), "undeclared_source"));
                        return Err(forbidden(format!(
                            "asset {a} belongs to {}: a program using it binds an input to it \
                             (`asset \"{a}\" ...` and `input ... asset \"{a}\"`)",
                            asset.organization
                        )));
                    }
                    // Approved for this project and purpose while the
                    // submitting organization was a member.
                    let approved = t
                        .query_opt(
                            "SELECT 1 FROM asset_approval_members
                              WHERE asset_id = $1 AND project_id = $2 AND purpose = $3 AND organization_id = $4",
                            &[a, &r.project, &r.purpose, &org],
                        )
                        .map_err(db_err)?;
                    if approved.is_none() {
                        *denied.borrow_mut() = Some(("asset", a.clone(), org.clone(), "not_approved"));
                        return Err(forbidden(format!(
                            "asset {a} is not approved by its owner for this project and purpose {:?}",
                            r.purpose
                        )));
                    }
                    if asset.policy["require_job_approval"] == json!(true) {
                        needs_approval.insert(asset.organization.clone());
                    }
                }
            }
            let id = new_id("job");
            t.execute(
                "INSERT INTO jobs (id, organization_id, project_id, plan_id, spec_id, program_id, policy_id, purpose,
                     source_assets, requested_output, scheme, backend, profile, state, initiated_by,
                     idempotency_key, request_digest, estimated_gates)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'created', $14, $15, $16, $17)",
                &[
                    &id,
                    &org,
                    &r.project,
                    &r.plan,
                    &plan.get::<_, String>(0),
                    &plan.get::<_, String>(1),
                    &r.policy,
                    &r.purpose,
                    &json!(sources),
                    &r.requested_output,
                    &doc.scheme,
                    &doc.backend,
                    &doc.profile,
                    &ctx.actor(),
                    &key,
                    &digest,
                    &(doc.estimated_gates.min(i64::MAX as u64) as i64),
                ],
            )
            .map_err(|e| {
                if e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                    Error::new(Code::Remote, "unique idempotency key race")
                } else {
                    db_err(e)
                }
            })?;
            let a = ctx.actor();
            self.transition_in(t, a, &ctx.request_id, &id, JobState::Planning, None)?;
            self.transition_in(t, a, &ctx.request_id, &id, JobState::Planned, None)?;
            let next = if needs_approval.is_empty() {
                JobState::Authorized
            } else {
                JobState::WaitingForApproval
            };
            self.transition_in(t, a, &ctx.request_id, &id, next, None)?;
            audit::append(
                t,
                ctx.draft("job.created", "job", &id, Outcome::Succeeded)
                    .org(&org)
                    .project(&r.project)
                    .r#ref("plan", r.plan.clone())
                    .r#ref("plan_id", doc.plan_id.clone())
                    .r#ref("spec", plan.get::<_, String>(0))
                    .r#ref("state", next.as_str()),
            )?;
            Ok((json!({"id": id}), true))
        });
        if let (Err(_), Some((rtype, rid, org, why))) = (&out, denied.into_inner()) {
            self.metrics.inc("encompute_key_release_denied_total", why);
            self.audit_denied(
                ctx.draft("job.denied", rtype, &rid, Outcome::Denied)
                    .org(&org)
                    .project(&r.project)
                    .r#ref("reason", why),
            );
        }
        out
    }

    /// Submits a job in a governed project (in the caller's transaction,
    /// after authorization and the idempotency check). The job runs for one
    /// active purpose whose name the program and the request declare
    /// (ENC2702), inside the purpose's window (ENC2705), over registered
    /// dataset versions only (ENC2704), each under an active authorization
    /// its owner signed (ENC2701; the submitter's own sources too), usable
    /// now (ENC2705, ENC2706, ENC2708), covering the program, its policies
    /// and any spec pin (ENC2703), the purpose's linkage (ENC2711) and every
    /// output's release (ENC2709). The rows every decision reads are
    /// share-locked, so a concurrent revocation either commits first and is
    /// seen here, or waits and then finds (and fails) this job.
    fn submit_governed(
        &self,
        t: &mut Transaction<'_>,
        ctx: &Ctx,
        r: &SubmitJob,
        s: Submission<'_>,
        denied: &Denied,
    ) -> Result<(Value, bool)> {
        let org = s.org;
        let deny = |rtype: &'static str, rid: &str, why: &'static str, e: Error| -> Error {
            *denied.borrow_mut() = Some((rtype, rid.to_owned(), org.to_owned(), why));
            e
        };
        let (Some(purpose_id), Some(outputs)) = (&r.purpose_id, &r.outputs) else {
            return Err(bad(
                "a job in a governed project names its purpose (purpose_id) and each output's release (outputs)",
            ));
        };
        if !is_hex32(purpose_id) {
            return Err(bad("purpose_id must be 32 bytes of lowercase hex"));
        }
        // The plan's execution spec (compiled once per plan, before any
        // row is locked).
        let spec = self.cached_plan_spec_in(t, &r.plan)?;
        let at = now();
        // The purpose: active in this project, named alike by the request
        // and the program, and inside its window.
        let purpose = crate::ops::governance::usable_purpose(t, &r.project, purpose_id)
            .map_err(|e| deny("plan", &r.plan, "purpose", e))?;
        let binding = SourceBinding::of(t, s.program)?;
        if binding.purpose.as_deref() != Some(purpose.name.as_str()) || r.purpose != purpose.name {
            return Err(deny(
                "plan",
                &r.plan,
                "purpose_mismatch",
                gov(
                    Code::GovernancePurposeMismatch,
                    format!(
                        "the job's purpose {:?}, the program's declared purpose {:?} and the purpose's name {:?} must be the same",
                        r.purpose, binding.purpose, purpose.name
                    ),
                ),
            ));
        }
        if !purpose.is_valid_at(at) {
            return Err(deny(
                "plan",
                &r.plan,
                "purpose_expired",
                gov(
                    Code::GovernanceAuthorizationExpired,
                    format!(
                        "the purpose is valid from {} until {}, not at {at}",
                        purpose.valid_from, purpose.valid_until
                    ),
                ),
            ));
        }
        // The sources: exactly the program's bound assets, as for any job.
        for a in r
            .source_assets
            .iter()
            .filter(|a| !binding.assets.contains(*a))
        {
            asset_visible(t, &ctx.principal, a)?;
        }
        if let Err((why, e)) = binding.check(&r.purpose, &r.source_assets) {
            return Err(deny("plan", &r.plan, why, e));
        }
        let sources = binding.sources();
        if sources.is_empty() {
            return Err(deny(
                "plan",
                &r.plan,
                "no_source",
                gov(
                    Code::GovernanceAuthorizationMissing,
                    "a job in a governed project reads registered dataset versions, each under its owner's authorization: this program binds none",
                ),
            ));
        }
        if let Some(pol) = &r.policy {
            let ok = t
                .query_opt(
                    "SELECT 1 FROM policies WHERE id = $1 AND project_id = $2 AND status = 'approved'",
                    &[pol, &r.project],
                )
                .map_err(db_err)?;
            if ok.is_none() {
                return Err(not_found("approved policy", pol));
            }
        }
        t.execute(
            "SELECT 1 FROM assets WHERE id = ANY($1) ORDER BY id FOR SHARE",
            &[&sources],
        )
        .map_err(db_err)?;
        // Source → (owner, version, the broker's key ID).
        let mut versions: BTreeMap<String, (String, String, Option<String>)> = BTreeMap::new();
        // Source → its owner's registered policy and release class.
        let mut registered: BTreeMap<String, (Option<Value>, Option<String>)> = BTreeMap::new();
        for a in &sources {
            let row = t
                .query_one(
                    "SELECT organization_id, status, version_id, expired_at IS NOT NULL, delete_after, key_ref,
                            ir_policy, release_class
                       FROM assets WHERE id = $1",
                    &[a],
                )
                .map_err(db_err)?;
            let owner: String = row.get(0);
            // A source of an organization outside the project is not one
            // its members may know of.
            if !s.project.members.contains(&owner) {
                return Err(not_found("asset", a));
            }
            if row.get::<_, String>(1) == "revoked" {
                return Err(deny(
                    "asset",
                    a,
                    "revoked",
                    gov(
                        Code::GovernanceAuthorizationRevoked,
                        format!("asset {a} is revoked"),
                    ),
                ));
            }
            if row.get::<_, bool>(3)
                || row
                    .get::<_, Option<i64>>(4)
                    .is_some_and(|d| d.max(0) as u64 <= at)
            {
                return Err(deny(
                    "asset",
                    a,
                    "expired",
                    gov(
                        Code::GovernanceAuthorizationExpired,
                        format!("asset {a} is past its deletion date"),
                    ),
                ));
            }
            let Some(version) = row.get::<_, Option<String>>(2) else {
                return Err(deny(
                    "asset",
                    a,
                    "not_a_version",
                    gov(
                        Code::GovernanceAssetVersionMismatch,
                        format!("asset {a} is not a dataset version: a governed job reads registered versions only"),
                    ),
                ));
            };
            let key = row
                .get::<_, Option<Value>>(5)
                .and_then(|k| serde_json::from_value::<KeyRef>(k).ok())
                .map(|k| k.key_ref);
            versions.insert(a.clone(), (owner, version, key));
            registered.insert(a.clone(), (row.get(6), row.get(7)));
        }
        // Every source's ancestors too: a derived result whose source was
        // revoked or expired is not used again (the walk, not only the
        // mark, decides).
        self.check_lineage(t, &sources, at)
            .map_err(|e| deny("plan", &r.plan, "source_lineage", e))?;
        // Governed projects are always in sovereign custody: each source's
        // key at a broker its own organization registered (ENC2715).
        let custody = binding
            .custody(t)
            .map_err(|e| deny("plan", &r.plan, "source_custody", e))?;
        // Every output of the program is declared, within the purpose.
        let declared: BTreeSet<&str> = s
            .program
            .outputs()
            .iter()
            .map(|o| o.name.as_str())
            .collect();
        if let Some(n) = outputs.keys().find(|n| !declared.contains(n.as_str())) {
            return Err(bad(format!("the program has no output {n:?}")));
        }
        let release = |m: String| gov(Code::GovernanceReleaseClass, m);
        if let Some(n) = declared.iter().find(|n| !outputs.contains_key(**n)) {
            return Err(deny(
                "plan",
                &r.plan,
                "undeclared_output",
                release(format!(
                    "output {n:?} has no declared release class and recipients"
                )),
            ));
        }
        for (n, o) in outputs {
            check_name("output", n)?;
            // An auditor organization never receives a release (D9).
            if let Some(x) = o.recipients.iter().find(|x| {
                s.project.auditors.contains(*x) || s.project.invited_auditors.contains(*x)
            }) {
                return Err(deny(
                    "plan",
                    &r.plan,
                    "auditor_recipient",
                    gov(
                        Code::GovernanceAuditorSeparation,
                        format!("{x} audits this project and receives no release (output {n:?})"),
                    ),
                ));
            }
            if !purpose
                .allowed_release_classes
                .iter()
                .any(|c| release_within(o.release_class, *c))
            {
                return Err(deny(
                    "plan",
                    &r.plan,
                    "release_class",
                    release(format!(
                        "the purpose does not allow release class {} (output {n:?})",
                        o.release_class.as_str()
                    )),
                ));
            }
            if let Some(x) = o
                .recipients
                .iter()
                .find(|x| !purpose.recipients.contains(*x))
            {
                return Err(deny(
                    "plan",
                    &r.plan,
                    "recipient",
                    release(format!(
                        "{x} is not a recipient the purpose allows (output {n:?})"
                    )),
                ));
            }
        }
        release_forms(s.program, outputs, &purpose.name, &registered)
            .map_err(|(why, e)| deny("plan", &r.plan, why, e))?;
        // One owner authorization per source, and, for a derived result,
        // one of every organization owning an ancestor of it (consent
        // carries through derivation: the custodian's alone never
        // suffices). What the governance log holds revoked stays revoked,
        // whatever the authorization's row says now.
        // (source, authorizing organization) → (row, document).
        let mut chosen: BTreeMap<(String, String), (String, SignedAuthorizationV2)> =
            BTreeMap::new();
        // A scope pin is consulted only by a job that releases a
        // differential-privacy aggregate (the same test the job's
        // reservations use): for any other job a conflict between pins
        // changes nothing and refuses nothing.
        let releases_dp = super::privacy_scopes::program_releases_dp(s.program)?;
        for a in &sources {
            let (owner, version, _) = &versions[a];
            let mut orgs = vec![owner.clone()];
            orgs.extend(
                super::derived::lineage_owners(t, a)?
                    .into_iter()
                    .filter(|o| o != owner),
            );
            for org in &orgs {
                let key = (a.clone(), org.clone());
                let candidates: Vec<(String, Option<String>, Option<Value>)> = t
                    .query(
                        "SELECT id, authorization_id, signed FROM authorizations
                          WHERE project_id = $1 AND organization_id = $2 AND asset_version_id = $3
                            AND purpose_id = $4 AND status IN ('active', 'revoked')
                          ORDER BY id FOR SHARE",
                        &[&r.project, org, version, purpose_id],
                    )
                    .map_err(db_err)?
                    .iter()
                    .map(|x| (x.get(0), x.get(1), x.get(2)))
                    .collect();
                // A lineage owner authorizes the same version, under the
                // commitment its owner's authorization binds.
                let commitment = chosen
                    .get(&(a.clone(), owner.clone()))
                    .map(|(_, x)| x.body.asset_digest_commitment.clone());
                let mut refusal: Option<(&'static str, Error)> = None;
                for (row, aid, signed) in candidates {
                    let mut ids = vec![row.as_str()];
                    ids.extend(aid.as_deref());
                    if crate::govlog::first_in(
                        t,
                        crate::govlog::NegSet::RevokedAuthorizations,
                        &ids,
                    )?
                    .is_some()
                    {
                        refusal.get_or_insert((
                            "revoked_authorization",
                            gov(
                                Code::GovernanceAuthorizationRevoked,
                                format!("authorization {row} was revoked"),
                            ),
                        ));
                        continue;
                    }
                    if let Err(e) = crate::ops::governance::usable_at(t, &row, at) {
                        refusal.get_or_insert(("unusable_authorization", e));
                        continue;
                    }
                    let signed: SignedAuthorizationV2 = signed
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|e| db_err(format!("stored authorization: {e}")))?
                        .ok_or_else(|| db_err("a usable authorization is signed"))?;
                    if org != owner
                        && commitment.as_deref()
                            != Some(signed.body.asset_digest_commitment.as_str())
                    {
                        refusal.get_or_insert((
                            "commitment_mismatch",
                            gov(
                                Code::GovernanceAssetVersionMismatch,
                                format!(
                                    "authorization {row} commits to another digest of the version than its owner's"
                                ),
                            ),
                        ));
                        continue;
                    }
                    // Every candidate is looked at: one that covers the job
                    // and asks for per-job four-eyes approval is never
                    // shadowed by a broader one; the job runs under it and
                    // waits for that approval.
                    match covers(&signed, &spec, &purpose.linkage_policy_id, outputs) {
                        Ok(()) => {
                            // Two usable authorizations of one source that
                            // pin different privacy scopes (or only one of
                            // them does) are refused for a job that releases
                            // a differential-privacy aggregate, never
                            // resolved by the order of their IDs.
                            if let Some((other, c)) = chosen.get(&key) {
                                if releases_dp
                                    && c.body.privacy_scope_id != signed.body.privacy_scope_id
                                {
                                    return Err(deny(
                                        "asset",
                                        a,
                                        "scope_pin_conflict",
                                        gov(
                                            Code::GovernancePrivacyScope,
                                            format!(
                                                "authorizations {other} and {row} of the same source pin different privacy scopes (or only one does): refused, not resolved by chance"
                                            ),
                                        ),
                                    ));
                                }
                            }
                            let take = chosen.get(&key).is_none_or(|(_, c)| {
                                signed.body.per_job_four_eyes && !c.body.per_job_four_eyes
                            });
                            if take {
                                chosen.insert(key.clone(), (row, signed));
                            }
                        }
                        Err(e) => {
                            refusal.get_or_insert(e);
                        }
                    }
                }
                if !chosen.contains_key(&key) {
                    let (why, e) = refusal.unwrap_or((
                        "not_authorized",
                        gov(
                            Code::GovernanceAuthorizationMissing,
                            if org == owner {
                                format!(
                                    "{owner} has not authorized its dataset version {version} (asset {a}) for this purpose: every source's owner authorizes it, its own jobs included"
                                )
                            } else {
                                format!(
                                    "{org} has not authorized dataset version {version} (asset {a}) for this purpose: it is derived from {org}'s data, and every owner in a derived source's lineage authorizes its use"
                                )
                            },
                        ),
                    ));
                    return Err(deny("asset", a, why, e));
                }
            }
        }
        // Probing limits across derivation: one more execution under each
        // authorization, the sources' ancestors' included.
        let mut counted: Vec<(String, SignedAuthorizationV2)> = chosen.values().cloned().collect();
        counted.extend(super::derived::ancestor_authorizations(t, &sources)?);
        super::derived::check_executions(t, &counted, None)
            .map_err(|e| deny("plan", &r.plan, "execution_limit", e))?;
        // The binding: each input's version with its owner's commitment,
        // each output's release, each source key's broker.
        let conf = s
            .program
            .confidentiality()
            .ok_or_else(|| bad("a program binding sources declares them"))?;
        let inputs = conf
            .inputs
            .iter()
            .filter_map(|(name, a)| {
                chosen
                    .get(&(a.clone(), versions.get(a)?.0.clone()))
                    .map(|(_, x)| (name, x))
            })
            .map(|(name, x)| {
                (
                    name.clone(),
                    GovernanceInput {
                        asset_version_id: x.body.asset_version_id.clone(),
                        digest_commitment: x.body.asset_digest_commitment.clone(),
                        organization: x.body.party.clone(),
                    },
                )
            })
            .collect();
        // Keyed by source version: the map travels in grants and tickets
        // other organizations see, and names no key reference.
        let asset_brokers = custody
            .iter()
            .filter(|c| versions[&c.asset].2.is_some())
            .map(|c| (versions[&c.asset].1.clone(), c.broker.clone()))
            .collect();
        let binding = GovernanceBinding {
            version: GOVERNANCE_BINDING_VERSION,
            project: r.project.clone(),
            purpose_id: purpose_id.clone(),
            linkage_policy_id: purpose.linkage_policy_id.clone(),
            inputs,
            outputs: outputs.clone(),
            // The project's constraints at submission, by digest (none:
            // absent, so a project without any keeps its IDs).
            placement_digest: super::placement::project_placement(t, &r.project)?.map(|p| p.digest),
            project_policy_digest: None,
            asset_brokers,
        };
        binding.check()?;
        // Placement: some evaluator is admissible for this job now, under
        // the project's constraints, every owner's own, and the separation
        // of operators (ENC2710, ENC2725). Nothing is bound that no
        // machine could run.
        let owners: Vec<PlacementSource> = chosen
            .values()
            .filter_map(|(_, x)| {
                x.body.limits.placement.clone().map(|c| PlacementSource {
                    origin: Origin::Organization(x.body.party.clone()),
                    constraints: c,
                })
            })
            .collect();
        let admitted = self
            .job_admission(
                t,
                &super::placement::JobPlacement {
                    project: &r.project,
                    plan: &r.plan,
                    binding: &binding,
                    backend: &s.doc.backend,
                    owners,
                    parties: chosen.values().map(|(_, x)| x.body.party.clone()).collect(),
                    pins: chosen
                        .values()
                        .filter_map(|(_, x)| x.body.limits.project_placement_digest.clone())
                        .collect(),
                },
            )
            .map_err(|e| deny("plan", &r.plan, "placement", e))?;
        if admitted.admitted.is_empty() {
            return Err(deny(
                "plan",
                &r.plan,
                "placement",
                super::placement::placement_refused(&admitted),
            ));
        }
        let spec = spec.governed(&binding);
        let spec_id = spec.id().hex();
        // An authorization pinned to execution specs covers only those.
        for ((a, _), (row, x)) in &chosen {
            if x.body
                .execution_spec_ids
                .as_ref()
                .is_some_and(|ids| !ids.contains(&spec_id))
            {
                return Err(deny(
                    "asset",
                    a,
                    "spec_not_authorized",
                    gov(
                        Code::GovernanceProgramNotAuthorized,
                        format!("authorization {row} is pinned to other execution specs"),
                    ),
                ));
            }
        }
        let authorizations: BTreeMap<String, String> = chosen
            .values()
            .map(|(row, x)| (row.clone(), x.body.id()))
            .collect();
        let set = AuthorizationSetId::of(authorizations.values().cloned())?;
        let plan_hash = s
            .doc
            .plan_id
            .strip_prefix("encplan1:")
            .unwrap_or(&s.doc.plan_id)
            .to_owned();
        let source_keys = versions
            .values()
            .filter_map(|(_, v, k)| k.clone().map(|k| (v.clone(), k)))
            .collect();
        let governance = JobGovernance {
            governance_id: binding.id().hex(),
            binding,
            plan_hash,
            authorization_set_id: set.hex().to_owned(),
            authorizations,
            source_keys,
        };
        let id = new_id("job");
        t.execute(
            "INSERT INTO jobs (id, organization_id, project_id, plan_id, spec_id, program_id, policy_id, purpose,
                 source_assets, requested_output, scheme, backend, profile, state, initiated_by,
                 idempotency_key, request_digest, estimated_gates, purpose_id, governance)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'created', $14, $15, $16, $17, $18, $19)",
            &[
                &id,
                &org,
                &r.project,
                &r.plan,
                &spec_id,
                &s.program_id,
                &r.policy,
                &r.purpose,
                &json!(sources),
                &r.requested_output,
                &s.doc.scheme,
                &s.doc.backend,
                &s.doc.profile,
                &ctx.actor(),
                &s.key,
                &s.digest,
                &(s.doc.estimated_gates.min(i64::MAX as u64) as i64),
                purpose_id,
                &serde_json::to_value(&governance).expect("serializable"),
            ],
        )
        .map_err(|e| {
            if e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                Error::new(Code::Remote, "unique idempotency key race")
            } else {
                db_err(e)
            }
        })?;
        for ((a, _), (row, x)) in &chosen {
            t.execute(
                "INSERT INTO job_authorizations (job_id, authorization_row, authorization_id, asset_id)
                 VALUES ($1, $2, $3, $4)",
                &[&id, row, &x.body.id(), a],
            )
            .map_err(db_err)?;
        }
        // An owner that asks for per-job four eyes has its people approve
        // this job first.
        let next = if chosen.values().any(|(_, x)| x.body.per_job_four_eyes) {
            JobState::WaitingForApproval
        } else {
            JobState::Authorized
        };
        let actor = ctx.actor();
        for to in [JobState::Planning, JobState::Planned, next] {
            self.transition_in(t, actor, &ctx.request_id, &id, to, None)?;
        }
        audit::append(
            t,
            ctx.draft("job.created", "job", &id, Outcome::Succeeded)
                .org(org)
                .project(&r.project)
                .r#ref("plan", r.plan.clone())
                .r#ref("plan_id", s.doc.plan_id.clone())
                .r#ref("spec", spec_id)
                .r#ref("purpose", purpose_id.clone())
                .r#ref("governance", governance.governance_id.clone())
                .r#ref("authorization_set", governance.authorization_set_id.clone())
                .r#ref("state", next.as_str()),
        )?;
        Ok((json!({"id": id}), true))
    }

    /// Revalidates governed job `j` at `at` for the lifecycle transition
    /// `stage`: the one check scheduling and start make (and a later layer
    /// may bind to, see [`Control::revalidate_governed_job`]), with every
    /// row it reads share-locked against a concurrent change. Refused
    /// when anything changed since submission:
    ///
    /// 1. identities: the governance binding, the authorization set, the
    ///    plan's spec under the binding or the plan's PlanId no longer
    ///    recompute to the job's stored IDs, or (at start) the grant is not
    ///    this control plane's for them (ENC2703);
    /// 2. the purpose: retired (ENC2706) or outside its window (ENC2705);
    /// 3. each source: revoked (ENC2706), expired (ENC2705), its version
    ///    substituted (ENC2704), or its key's broker disabled, not its
    ///    organization's own, or re-bound away from the binding's broker
    ///    (ENC2715); or, for a derived result, a source of it revoked or
    ///    expired since (ENC2706, ENC2705);
    /// 4. each authorization: not the document recorded (ENC2703), no
    ///    longer active (revoked, in the database or the governance log: ENC2706;
    ///    otherwise ENC2701), for another version (ENC2704), unusable at
    ///    `at` (its window, governance key, purpose or version: ENC2705,
    ///    ENC2706, ENC2708), or no longer covering the job (ENC2703,
    ///    ENC2709, ENC2711);
    /// 5. per-job four eyes (except when approving): an owner whose
    ///    authorization asks for it without its quorum of distinct people
    ///    approving this job's spec and authorization set (ENC2707);
    /// 6. (except when approving) each authorization's `max_executions`,
    ///    counting every job under it through derived results (ENC2714);
    /// 7. `at` at or after `not_after`, the strict end of every
    ///    authorization, purpose and source window, deletion dates
    ///    included (ENC2705);
    /// 8. (except when approving) placement: the project's and the owners'
    ///    constraints and the separation of operators (ENC2710, ENC2725);
    /// 9. last, the privacy budget ([`Control::governed_privacy_budget`],
    ///    read-only: a scope that can pay, ENC2719, ENC2201), so a job
    ///    refused for authorization, placement or its window never reaches
    ///    the scopes. Starting reserves only after every check here passed.
    ///
    /// Returns `not_after`.
    fn revalidate_governed(
        &self,
        t: &mut Transaction<'_>,
        j: &JobRow,
        stage: GovernedStage,
        at: u64,
    ) -> Result<u64> {
        let g = j
            .governance
            .as_ref()
            .ok_or_else(|| conflict(format!("job {} is not a governed job", j.id)))?;
        let identity = |m: String| gov(Code::GovernanceProgramNotAuthorized, m);
        let expired = |m: String| gov(Code::GovernanceAuthorizationExpired, m);
        let withdrawn = |m: String| gov(Code::GovernanceAuthorizationRevoked, m);
        let version = |m: String| gov(Code::GovernanceAssetVersionMismatch, m);
        // 1. The stored identities recompute.
        g.binding.check().map_err(|e| identity(e.message))?;
        if g.binding.id().hex() != g.governance_id
            || g.binding.project != j.project
            || j.purpose_id.as_deref() != Some(g.binding.purpose_id.as_str())
        {
            return Err(identity(
                "the job's governance binding no longer recomputes to its GovernanceId".into(),
            ));
        }
        let recorded: BTreeMap<String, String> = t
            .query(
                "SELECT authorization_row, authorization_id FROM job_authorizations WHERE job_id = $1",
                &[&j.id],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        if recorded != g.authorizations
            || AuthorizationSetId::of(g.authorizations.values().cloned())?.hex()
                != g.authorization_set_id
        {
            return Err(identity(
                "the job's authorizations no longer recompute to its authorization set".into(),
            ));
        }
        let base = self.cached_plan_spec_in(t, &j.plan)?;
        let spec = base.clone().governed(&g.binding);
        if spec.id().hex() != j.spec_id || spec.program_id != j.program_id {
            return Err(identity(
                "the plan's spec under the job's binding no longer recomputes to the job's spec"
                    .into(),
            ));
        }
        let doc: PlanDoc = serde_json::from_value(
            t.query_one("SELECT document FROM plans WHERE id = $1", &[&j.plan])
                .map_err(db_err)?
                .get(0),
        )
        .map_err(db_err)?;
        if doc
            .plan_id
            .strip_prefix("encplan1:")
            .unwrap_or(&doc.plan_id)
            != g.plan_hash
        {
            return Err(identity(
                "the job's plan is not the one it was bound to".into(),
            ));
        }
        if matches!(stage, GovernedStage::Start | GovernedStage::Ticket) {
            let grant = j.grant.as_ref().ok_or_else(|| conflict("no grant"))?;
            let pk = self.signer.public_key_hex();
            let bound = grant.governance.as_ref().is_some_and(|x| {
                x.governance_id == g.governance_id
                    && x.binding == g.binding
                    && x.authorization_set_id == g.authorization_set_id
                    && x.plan_hash == g.plan_hash
                    && x.purpose_id == g.binding.purpose_id
            });
            if grant.issuer_public_key != pk
                || verify_signed(&pk, JOB_GRANT, &grant.unsigned(), &grant.signature).is_err()
                || grant.job_id != j.id
                || grant.spec_id != j.spec_id
                || !bound
            {
                return Err(identity(
                    "the job's grant is not this control plane's grant for its binding".into(),
                ));
            }
        }
        // 2. The purpose.
        let purpose = crate::ops::governance::usable_purpose(t, &j.project, &g.binding.purpose_id)?;
        if !purpose.is_valid_at(at) {
            return Err(expired(format!(
                "the purpose is valid from {} until {}, not at {at}",
                purpose.valid_from, purpose.valid_until
            )));
        }
        let mut not_after = purpose.valid_until;
        // 3. The sources, their versions and their keys' brokers.
        let rows = t
            .query(
                "SELECT id, organization_id, status, expired_at IS NOT NULL, delete_after, version_id, key_ref
                   FROM assets WHERE id = ANY($1) ORDER BY id FOR SHARE",
                &[&j.sources],
            )
            .map_err(db_err)?;
        if rows.len() != j.sources.len() {
            return Err(version("a source of the job is not on record".into()));
        }
        let mut keys = BTreeMap::new();
        let mut versions = BTreeMap::new();
        for r in &rows {
            let (a, owner): (String, String) = (r.get(0), r.get(1));
            if r.get::<_, String>(2) == "revoked" {
                return Err(withdrawn(format!("source {a} was revoked")));
            }
            if r.get::<_, bool>(3) {
                return Err(expired(format!("source {a} expired")));
            }
            if let Some(d) = r.get::<_, Option<i64>>(4) {
                not_after = not_after.min(d.max(0) as u64);
            }
            let v: Option<String> = r.get(5);
            let Some(v) = v.filter(|v| {
                g.binding
                    .inputs
                    .values()
                    .any(|i| &i.asset_version_id == v && i.organization == owner)
            }) else {
                return Err(version(format!(
                    "source {a} is no longer the dataset version the job is bound to"
                )));
            };
            versions.insert(a.clone(), v.clone());
            let key = r
                .get::<_, Option<Value>>(6)
                .and_then(|k| serde_json::from_value::<KeyRef>(k).ok());
            super::require_own_broker(t, &owner, key.as_ref().map(|k| k.broker.as_str()))
                .map_err(|e| Error::new(e.code, format!("source {a}: {}", e.message)))?;
            let key = key.expect("checked above");
            if g.source_keys.get(&v).is_some_and(|k| *k != key.key_ref) {
                return Err(gov(
                    Code::GovernanceCustody,
                    format!("source {a}'s key is no longer the one the job was bound to"),
                ));
            }
            keys.insert(v.clone(), key.broker);
        }
        // Their ancestors: none revoked or expired since.
        self.check_lineage(t, &j.sources, at)?;
        if !g.binding.asset_brokers.is_empty() && keys != g.binding.asset_brokers {
            return Err(gov(
                Code::GovernanceCustody,
                "a source's key is no longer at the broker the job's binding names",
            ));
        }
        // 4. The authorizations the job runs under: every lineage owner's
        //    among them for a derived source.
        super::derived::require_lineage_consent(t, &j.id, &j.sources)?;
        let base_spec = base.clone();
        for (row, aid) in &g.authorizations {
            let until = self.check_bound_authorization(
                t,
                BoundAuthorization {
                    row,
                    authorization_id: aid,
                    binding: &g.binding,
                    base_spec: &base_spec,
                    spec_id: &j.spec_id,
                    versions: &versions,
                },
                at,
            )?;
            not_after = not_after.min(until);
        }
        // 5. Per-job four eyes: every owner that asks for it has its quorum
        //    (an approval is what collects it).
        if stage != GovernedStage::Approve {
            let owners = four_eyes_owners(t, g)?;
            job_quorums(t, j, g, &owners)?;
        }
        // 6. The owners' execution limits, counted through derived results
        //    (every job reading one released under an authorization counts
        //    against it).
        if stage != GovernedStage::Approve {
            let mut counted =
                super::derived::lineage_authorizations(t, std::slice::from_ref(&j.id))?;
            counted.extend(super::derived::ancestor_authorizations(t, &j.sources)?);
            super::derived::check_executions(t, &counted, Some(&j.id))?;
        }
        // 8. Placement. The plan names where it may run and the binding's
        //    project constraints exist (scheduling, which then picks only
        //    among the evaluators the constraints admit); at start the
        //    scheduled evaluator is still admitted under the constraints,
        //    the owners' and the separation of operators as they are now,
        //    and is still the machine the grant recorded (ENC2710,
        //    ENC2725).
        if stage != GovernedStage::Approve {
            let (evaluator, recorded) =
                if matches!(stage, GovernedStage::Start | GovernedStage::Ticket) {
                    let ev = j.evaluator.as_deref().ok_or_else(|| {
                        Error::new(Code::GovernanceResidency, "the job has no evaluator")
                    })?;
                    (
                        Some(ev),
                        j.grant
                            .as_ref()
                            .and_then(|x| x.governance.as_ref())
                            .and_then(|x| x.placement.as_ref()),
                    )
                } else {
                    (None, None)
                };
            self.check_job_placement(t, &j.id, &g.binding, evaluator, recorded)?;
        }
        // 7. The window, strictly.
        if at >= not_after {
            return Err(expired(format!(
                "the job's governed window ended at {not_after}"
            )));
        }
        // 9. The privacy budget, last of the checks: authorization,
        //    placement and the window refuse first (with their own codes),
        //    and only a job that passed them all is judged against, and at
        //    start reserves in, its scopes (read-only here: reserving is
        //    the last step of start itself).
        self.governed_privacy_budget(t, j, stage)?;
        Ok(not_after)
    }

    /// One authorization a governed job runs under (row `row`, document
    /// `authorization_id`), checked at `at` with its row share-locked: the
    /// per-authorization step of [`Self::revalidate_governed`], and what a
    /// release ticket checks for its source. Refused: revoked in the
    /// governance log or the database (ENC2706), no longer active (ENC2701), not the
    /// recorded document or its purpose (ENC2703), for another version
    /// than its source in `versions` (asset → version, ENC2704), unusable at
    /// `at` (ENC2705, ENC2706, ENC2708), no longer matching the binding's
    /// input, or not covering the program, policies, linkage, releases or
    /// spec pin ([`covers`]). Returns its `valid_until`.
    pub(crate) fn check_bound_authorization(
        &self,
        t: &mut Transaction<'_>,
        b: BoundAuthorization<'_>,
        at: u64,
    ) -> Result<u64> {
        let (row, aid) = (b.row, b.authorization_id);
        let identity = |m: String| gov(Code::GovernanceProgramNotAuthorized, m);
        let withdrawn = |m: String| gov(Code::GovernanceAuthorizationRevoked, m);
        if crate::govlog::first_in(t, crate::govlog::NegSet::RevokedAuthorizations, &[row, aid])?
            .is_some()
        {
            return Err(withdrawn(format!("authorization {row} was revoked")));
        }
        let r = t
            .query_opt(
                "SELECT status, authorization_id, asset_id, asset_version_id, purpose_id, valid_until, signed
                   FROM authorizations WHERE id = $1 FOR SHARE",
                &[&row],
            )
            .map_err(db_err)?
            .ok_or_else(|| {
                gov(
                    Code::GovernanceAuthorizationMissing,
                    format!("authorization {row} is not on record"),
                )
            })?;
        let status: String = r.get(0);
        match status.as_str() {
            "active" => {}
            "revoked" => return Err(withdrawn(format!("authorization {row} was revoked"))),
            s => {
                return Err(gov(
                    Code::GovernanceAuthorizationMissing,
                    format!("authorization {row} is {s}, not active"),
                ))
            }
        }
        let (stored_id, asset, v, p): (Option<String>, String, String, String) =
            (r.get(1), r.get(2), r.get(3), r.get(4));
        if stored_id.as_deref() != Some(aid) || p != b.binding.purpose_id {
            return Err(identity(format!(
                "authorization {row} is no longer the document the job was submitted under"
            )));
        }
        if b.versions.get(&asset) != Some(&v) {
            return Err(gov(
                Code::GovernanceAssetVersionMismatch,
                format!("authorization {row} is for another version than the job's source"),
            ));
        }
        crate::ops::governance::usable_at(t, row, at)?;
        let signed: SignedAuthorizationV2 = r
            .get::<_, Option<Value>>(6)
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| db_err(format!("stored authorization: {e}")))?
            .ok_or_else(|| db_err("a usable authorization is signed"))?;
        // The input's owner, or (for a derived source) an owner in its
        // lineage.
        let party = &signed.body.party;
        let lineage_owner = b
            .binding
            .inputs
            .values()
            .any(|i| i.asset_version_id == v && &i.organization != party)
            && super::derived::lineage_owners(t, &asset)?.contains(party);
        if signed.body.id() != aid
            || !b.binding.inputs.values().any(|i| {
                i.asset_version_id == v
                    && i.digest_commitment == signed.body.asset_digest_commitment
                    && (&i.organization == party || lineage_owner)
            })
        {
            return Err(identity(format!(
                "authorization {row} no longer matches the job's binding"
            )));
        }
        covers(
            &signed,
            b.base_spec,
            &b.binding.linkage_policy_id,
            &b.binding.outputs,
        )
        .map_err(|(_, e)| e)?;
        if signed
            .body
            .execution_spec_ids
            .as_ref()
            .is_some_and(|ids| !ids.contains(b.spec_id))
        {
            return Err(identity(format!(
                "authorization {row} is pinned to other execution specs"
            )));
        }
        Ok(r.get::<_, i64>(5).max(0) as u64)
    }

    /// The privacy-budget step of [`Self::revalidate_governed`]: a governed
    /// job whose program releases a differential-privacy aggregate needs a
    /// scope (and population) for every source that can pay for the release
    /// now: no scope (ENC2719) or an exhausted scope or population
    /// (ENC2201) fails it at scheduling and at start. Read-only: starting
    /// is what reserves ([`Self::reserve_job_privacy`]). A job that
    /// releases no such aggregate is not concerned.
    fn governed_privacy_budget(
        &self,
        t: &mut Transaction<'_>,
        j: &JobRow,
        stage: GovernedStage,
    ) -> Result<()> {
        if matches!(stage, GovernedStage::Approve | GovernedStage::Ticket) {
            return Ok(());
        }
        self.check_job_privacy(t, &privacy_facts(j), None, false)
            .map(|_| ())
    }

    /// Everything start checks, except the privacy budget (start reserved
    /// it), for a release or export ticket of running governed job `id`, in
    /// the caller's transaction. Returns `not_after`.
    pub(super) fn revalidate_for_ticket(&self, t: &mut Transaction<'_>, id: &str) -> Result<u64> {
        let j = job_row(t, id, false)?.ok_or_else(|| not_found("job", id))?;
        self.revalidate_governed(t, &j, GovernedStage::Ticket, now())
    }

    /// Revalidates governed job `id` now for `stage`, without changing it:
    /// exactly the check scheduling and start make (a refusal carries the
    /// same code and message). Returns `not_after`. For a later layer (an
    /// execution epoch) to bind to; the transitions themselves call it.
    pub fn revalidate_governed_job(&self, id: &str, stage: GovernedStage) -> Result<u64> {
        self.tx_anchored(|t| {
            let j = job_row(t, id, false)?.ok_or_else(|| not_found("job", id))?;
            self.revalidate_governed(t, &j, stage, now())
        })
    }

    /// Fails governed job `j` (in the caller's transaction) for `e`,
    /// audited with its code; the caller anchors the ended job after
    /// commit.
    fn fail_governed(
        &self,
        t: &mut Transaction<'_>,
        actor: &str,
        request_id: &str,
        j: &JobRow,
        stage: GovernedStage,
        e: &Error,
    ) -> Result<()> {
        self.transition_in(
            t,
            actor,
            request_id,
            &j.id,
            JobState::Failed,
            Some(&e.message),
        )?;
        audit::append(
            t,
            audit::AuditDraft::new(
                actor,
                request_id,
                "job.failed",
                "job",
                &j.id,
                Outcome::Failed,
            )
            .org(&j.organization)
            .project(&j.project)
            .r#ref("reason", e.code.as_str())
            .r#ref("check", "revalidate_governed")
            .r#ref("stage", stage.as_str()),
        )?;
        Ok(())
    }

    pub fn job_view(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let j = job_row(&mut *c, id, false)?.ok_or_else(|| not_found("job", id))?;
        job_visible(&mut *c, ctx, &j)?;
        // The evaluator's URL and receipt key, like the grant, go only to
        // the submitting organization (the one that runs the job).
        let submitter = ctx.principal.member_of(&j.organization);
        // In a governed project the scheduled evaluator sees the grant and
        // nothing else ([`crate::views`]).
        if j.governance.is_some()
            && !submitter
            && ctx.principal.service_kind() == Some(ServiceKind::Evaluator)
            && j.evaluator.as_deref() == Some(ctx.actor())
        {
            return Ok(json!({"id": j.id, "grant": j.grant}));
        }
        // Everyone else taking part in a governed project gets the shared
        // view: the same bytes for each (actors as `organization/kind`
        // whoever asks).
        let shared = j.governance.is_some() && !submitter;
        let mut shared_labels = crate::views::Labels::default();
        let (url, receipt_key, parallel): (Option<String>, Option<String>, Option<i32>) =
            match &j.evaluator {
                Some(e) if submitter => c
                    .query_opt(
                        "SELECT url, receipt_key, max_parallel_gates FROM evaluators WHERE id = $1",
                        &[e],
                    )
                    .map_err(db_err)?
                    .map_or((None, None, None), |r| {
                        (Some(r.get(0)), Some(r.get(1)), r.get(2))
                    }),
                _ => (None, None, None),
            };
        // Who acted is the submitting organization's own business: other
        // viewers (its source assets' owners) see the actor's organization
        // and kind, never another organization's user or account IDs.
        let mut labels = std::collections::BTreeMap::new();
        let mut label = |c: &mut postgres::Client, actor: String| -> Result<String> {
            if submitter {
                return Ok(actor);
            }
            if shared {
                return shared_labels.label(c, &actor);
            }
            if let Some(l) = labels.get(&actor) {
                return Ok(String::clone(l));
            }
            let l = actor_label(c, ctx, &actor)?;
            labels.insert(actor, l.clone());
            Ok(l)
        };
        let rows = c
            .query(
                "SELECT from_state, to_state, actor, COALESCE(reason, '') FROM job_transitions WHERE job_id = $1 ORDER BY seq",
                &[&id],
            )
            .map_err(db_err)?;
        let mut transitions = vec![];
        for r in &rows {
            let mut t: std::collections::BTreeMap<String, String> =
                [("from", 0), ("to", 1), ("actor", 2), ("reason", 3)]
                    .into_iter()
                    .map(|(k, i)| (k.to_owned(), r.get::<_, String>(i)))
                    .collect();
            let actor = t.remove("actor").unwrap_or_default();
            t.insert("actor".into(), label(&mut c, actor)?);
            transitions.push(t);
        }
        let initiated_by = label(&mut c, j.initiated_by.clone())?;
        // Where the job was placed, as scheduling recorded it; or why it
        // has not been placed.
        let placement = j
            .grant
            .as_ref()
            .and_then(|g| g.governance.as_ref())
            .and_then(|g| g.placement.clone());
        let placement_waiting = if j.governance.is_some() && j.state == JobState::Authorized {
            match j
                .governance
                .as_ref()
                .map(|g| self.admission_for_job(&mut *c, &j.id, &g.binding))
                .expect("governed")
            {
                Ok(a) if a.admitted.is_empty() => {
                    Some(format!("no admissible evaluator: {}", a.why_none()))
                }
                Ok(_) => None,
                // A residency refusal says why; anything else (a database
                // error) is not for a viewer.
                Err(e) if e.code == Code::GovernanceResidency => Some(e.message),
                Err(_) => Some("its placement cannot be judged now".to_owned()),
            }
        } else {
            None
        };
        // The grant goes only to the submitting organization.
        let grant = if submitter { j.grant.clone() } else { None };
        let v = JobView {
            id: j.id,
            organization: j.organization,
            project: j.project,
            plan: j.plan,
            spec_id: j.spec_id,
            program_id: j.program_id,
            purpose: j.purpose,
            source_assets: j.sources,
            requested_output: j.requested_output,
            scheme: j.scheme,
            backend: j.backend,
            profile: j.profile,
            state: j.state,
            evaluator: j.evaluator,
            evaluator_url: url,
            evaluator_receipt_key: receipt_key,
            grant,
            error: j.error,
            initiated_by,
            transitions,
            estimated_gates: j.estimated_gates,
            estimated_ms: j.estimated_ms,
            evaluator_parallel_gates: parallel.map(|p| p.max(1) as u32),
            purpose_id: j.purpose_id,
            governance_id: j.governance.map(|g| g.governance_id),
            placement,
            placement_waiting,
        };
        Ok(serde_json::to_value(v).expect("serializable"))
    }

    pub fn list_jobs(&self, ctx: &Ctx, project: Option<&str>) -> Result<Value> {
        let orgs: Vec<String> = ctx.principal.organizations().into_iter().collect();
        let mut c = self.db.conn()?;
        let rows = c
            .query(
                "SELECT j.id, j.project_id, j.state, j.backend, j.created_at FROM jobs j
                  WHERE (j.organization_id = ANY($1)
                         OR (j.governance IS NOT NULL AND EXISTS (
                               SELECT 1 FROM project_members m
                                WHERE m.project_id = j.project_id AND m.status = 'active'
                                  AND m.organization_id = ANY($1))))
                    AND ($2::text IS NULL OR j.project_id = $2)
                  ORDER BY j.created_at DESC, j.id LIMIT 200",
                &[&orgs, &project],
            )
            .map_err(db_err)?;
        Ok(Value::Array(
            rows.iter()
                .map(|r| {
                    json!({"id": r.get::<_, String>(0), "project": r.get::<_, String>(1),
                           "state": r.get::<_, String>(2), "backend": r.get::<_, String>(3)})
                })
                .collect(),
        ))
    }

    pub fn cancel_job(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        self.tx_anchored(|t| {
            let j = job_row(t, id, true)?.ok_or_else(|| not_found("job", id))?;
            job_visible(t, ctx, &j)?;
            job_project(t, ctx, &j)?;
            if !ctx.principal.member_of(&j.organization) {
                return Err(not_found("job", id));
            }
            require(
                &ctx.principal,
                &j.organization,
                &[
                    Role::MlDeveloper,
                    Role::OrganizationAdmin,
                    Role::SecurityAdmin,
                ],
                "cancelling a job",
            )?;
            self.transition_in(
                t,
                ctx.actor(),
                &ctx.request_id,
                id,
                JobState::Cancelled,
                Some("cancelled"),
            )?;
            audit::append(
                t,
                ctx.draft("job.cancelled", "job", id, Outcome::Succeeded)
                    .org(&j.organization)
                    .project(&j.project),
            )?;
            Ok(json!({"id": id, "state": "cancelled"}))
        })
        // (`tx_anchored` anchors the cancellation before it returns: a
        // restored database cannot bring the job back.)
    }

    /// The job's initiator asks for an upload grant: the control plane's
    /// signed authorization to upload one program, or one set of evaluation
    /// keys (named by key ID), once, to the job's scheduled evaluator. The
    /// grant names the initiator (the principal authenticated here), the
    /// job, the evaluator, the program, the keys, a random ID the evaluator
    /// spends and an expiry that never outlives the job's own grant.
    /// Nobody else gets one, whatever role they hold in the organization:
    /// the job grant is visible to the whole submitting organization, so it
    /// opens no upload.
    pub fn issue_upload_grant(&self, ctx: &Ctx, id: &str, r: RequestUploadGrant) -> Result<Value> {
        let key_id = match (r.kind, &r.key_id) {
            (UploadKind::Keys, Some(k)) if is_hex32(k) => k.clone(),
            (UploadKind::Keys, _) => {
                return Err(bad("keys need a key_id: 32 bytes of lowercase hex"))
            }
            (UploadKind::Program, None) => String::new(),
            (UploadKind::Program, Some(_)) => return Err(bad("a program upload names no key_id")),
        };
        self.tx_anchored(|t| {
            let j = job_row(t, id, false)?.ok_or_else(|| not_found("job", id))?;
            job_visible(t, ctx, &j)?;
            job_project(t, ctx, &j)?;
            if !ctx.principal.member_of(&j.organization) {
                return Err(not_found("job", id));
            }
            if j.initiated_by != ctx.actor() {
                return Err(forbidden(
                    "only the principal that submitted the job asks for its upload grants",
                ));
            }
            if j.state != JobState::Queued {
                return Err(conflict(format!(
                    "job {id} is {}: upload grants are issued for a scheduled (queued) job",
                    j.state.as_str()
                )));
            }
            let grant = j
                .grant
                .as_ref()
                .ok_or_else(|| conflict("the job has no grant"))?;
            // Only for a grant this control plane signed for this job.
            let pk = self.signer.public_key_hex();
            if grant.issuer_public_key != pk
                || verify_signed(&pk, JOB_GRANT, &grant.unsigned(), &grant.signature).is_err()
                || grant.job_id != id
                || j.evaluator.as_deref() != Some(grant.evaluator.as_str())
            {
                return Err(conflict(
                    "the job's grant is not one this control plane issued for it",
                ));
            }
            let at = now();
            if at >= grant.expires_at {
                return Err(conflict("the job's grant expired"));
            }
            if let Some(g) = &grant.governance {
                if at >= g.not_after {
                    return Err(Error::new(
                        Code::GovernanceAuthorizationExpired,
                        "the job's governed window has ended",
                    ));
                }
            }
            let mut nonce = [0u8; 16];
            getrandom::getrandom(&mut nonce).expect("operating-system randomness");
            let mut g = UploadGrant {
                version: UPLOAD_GRANT_VERSION,
                grant_id: encompute_verification::hex(&nonce),
                kind: r.kind,
                organization: j.organization.clone(),
                project: j.project.clone(),
                job_id: j.id.clone(),
                client: ctx.actor().to_owned(),
                evaluator: grant.evaluator.clone(),
                program_id: j.program_id.clone(),
                key_id: key_id.clone(),
                issued_at: at,
                expires_at: (at + UPLOAD_GRANT_TTL_SECS).min(grant.expires_at),
                issuer: self.service_id.clone(),
                issuer_public_key: pk,
                signature: String::new(),
            };
            g.signature = self.signer.sign(UPLOAD_GRANT, &g.unsigned())?;
            audit::append(
                t,
                ctx.draft("job.upload_granted", "job", id, Outcome::Succeeded)
                    .org(&j.organization)
                    .project(&j.project)
                    .r#ref("grant", g.grant_id.clone())
                    .r#ref("kind", r.kind.as_str().to_owned())
                    .r#ref("evaluator", g.evaluator.clone()),
            )?;
            Ok(json!({"grant": g, "header": g.to_header()}))
        })
    }

    /// An owner approves a job that uses its asset (assets whose policy
    /// sets `require_job_approval`). In a governed project that policy
    /// field is ignored: see [`Self::approve_governed`].
    pub fn approve_job(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let ended = std::cell::Cell::new(false);
        let out = self.tx_anchored(|t| {
            ended.set(false);
            let j = job_row(t, id, true)?.ok_or_else(|| not_found("job", id))?;
            job_visible(t, ctx, &j)?;
            job_project(t, ctx, &j)?;
            if j.governance.is_some() {
                return self.approve_governed(t, ctx, &j, &ended);
            }
            if j.state != JobState::WaitingForApproval {
                return Err(conflict(format!("job {id} is {}, not waiting for approval", j.state.as_str())));
            }
            let required: Vec<String> = t
                .query(
                    "SELECT DISTINCT organization_id FROM assets
                      WHERE id = ANY($1) AND organization_id <> $2 AND policy->>'require_job_approval' = 'true'",
                    &[&j.sources, &j.organization],
                )
                .map_err(db_err)?
                .iter()
                .map(|r| r.get(0))
                .collect();
            // An owner's consent is a person's, in the owning organization
            // itself: never a service account (an automation key), nor a
            // user homed elsewhere who holds a role there.
            if !matches!(ctx.principal.kind, PrincipalKind::User { .. }) {
                return Err(forbidden("jobs are approved by people (the assets' owners), not services"));
            }
            let mine: Vec<&String> = required
                .iter()
                .filter(|o| ctx.principal.organization.as_deref() == Some(o.as_str()))
                .filter(|o| ctx.principal.any_role(o, &[Role::DataOwner, Role::ModelOwner, Role::OrganizationAdmin]))
                .collect();
            if mine.is_empty() {
                return Err(forbidden("only the owners of this job's assets approve it"));
            }
            for o in &mine {
                t.execute(
                    "INSERT INTO job_approvals (job_id, organization_id, approved_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    &[&id, o, &ctx.actor()],
                )
                .map_err(db_err)?;
                audit::append(t, ctx.draft("job.approved", "job", id, Outcome::Succeeded).org(o).project(&j.project))?;
            }
            let approved: i64 = t
                .query_one(
                    "SELECT count(*) FROM job_approvals WHERE job_id = $1 AND organization_id = ANY($2)",
                    &[&id, &required],
                )
                .map_err(db_err)?
                .get(0);
            if approved as usize == required.len() {
                self.transition_in(t, ctx.actor(), &ctx.request_id, id, JobState::Authorized, None)?;
                audit::append(t, ctx.draft("job.authorized", "job", id, Outcome::Succeeded).org(&j.organization).project(&j.project))?;
            }
            Ok(Ok(()))
        })?;
        if ended.get() {
            // Anchored as ended: a restored database cannot revive it.
            self.checkpoint_log()?;
        }
        out?;
        self.schedule_after(id);
        self.job_view(ctx, id)
    }

    /// A person's per-job four-eyes approval of governed job `j` (locked;
    /// in the caller's transaction). The job waits for it when an
    /// authorization it runs under asks for per-job four eyes; each such
    /// owner has a quorum of its own people approve, under its approval
    /// rule for the project (at least two people; by default a data owner
    /// and a security admin). The approver is a person homed in that
    /// organization with a role the rule names, never a service account,
    /// an auditor or the job's submitter, and approves once
    /// ([`require_human_not_submitter`], ENC2707). The job is revalidated
    /// first, as scheduling and start do: if it no longer may run (its
    /// window over, ENC2705; an authorization revoked, ENC2706; ...) it
    /// fails and is anchored as ended (`ended`), and the approval is
    /// refused. The approval is a statement over the job, its governed spec
    /// and its authorization set; once every owner's quorum is met the job
    /// is authorized.
    fn approve_governed(
        &self,
        t: &mut Transaction<'_>,
        ctx: &Ctx,
        j: &JobRow,
        ended: &std::cell::Cell<bool>,
    ) -> Result<Result<()>> {
        let id = &j.id;
        let g = j.governance.as_ref().expect("a governed job");
        if j.state != JobState::WaitingForApproval {
            return Err(conflict(format!(
                "job {id} is {}, not waiting for approval",
                j.state.as_str()
            )));
        }
        let owners = four_eyes_owners(t, g)?;
        // The organization the person approves for: their own, or else one
        // they hold a role in (refused below: roles held from another
        // organization never count).
        let p = &ctx.principal;
        let Some(org) = p
            .organization
            .clone()
            .filter(|o| owners.contains(o))
            .or_else(|| owners.iter().find(|o| p.member_of(o)).cloned())
        else {
            return Err(forbidden(
                "only people of the organizations whose authorization asks for per-job approval approve this job",
            ));
        };
        let (_, rule) = crate::ops::governance::approval_rule(t, &j.project, &org)?;
        let mut roles: Vec<Role> = rule
            .keys()
            .filter_map(|r| Role::parse(r).ok())
            .filter(|r| *r != Role::Auditor)
            .collect();
        if roles.is_empty() {
            roles = vec![Role::DataOwner, Role::SecurityAdmin];
        }
        require_human_not_submitter(p, &org, &roles, "approving a governed job", &j.initiated_by)?;
        let again = t
            .query_opt(
                "SELECT 1 FROM job_human_approvals WHERE job_id = $1 AND approver_id = $2",
                &[id, &ctx.actor()],
            )
            .map_err(db_err)?;
        if again.is_some() {
            return Err(Error::new(
                Code::GovernanceFourEyesIncomplete,
                "this person has approved this job already: four eyes are different people",
            ));
        }
        if let Err(e) = self.revalidate_governed(t, j, GovernedStage::Approve, now()) {
            self.fail_governed(
                t,
                ctx.actor(),
                &ctx.request_id,
                j,
                GovernedStage::Approve,
                &e,
            )?;
            ended.set(true);
            return Ok(Err(e));
        }
        // The rule's role this approval counts for: the first one the
        // person holds that is still short, else the first one they hold.
        let given: Vec<String> = t
            .query(
                "SELECT role FROM job_human_approvals WHERE job_id = $1 AND organization_id = $2",
                &[id, &org],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        let held: Vec<Role> = roles
            .iter()
            .copied()
            .filter(|r| p.has_role(&org, *r))
            .collect();
        let role = held
            .iter()
            .find(|r| {
                let need = rule.get(r.as_str()).copied().unwrap_or(0) as usize;
                given.iter().filter(|x| x.as_str() == r.as_str()).count() < need
            })
            .or(held.first())
            .copied()
            .expect("require_human checked a role");
        let statement = job_statement(j, g);
        t.execute(
            "INSERT INTO job_human_approvals (job_id, organization_id, approver_id, role, statement_digest)
             VALUES ($1, $2, $3, $4, $5)",
            &[id, &org, &ctx.actor(), &role.as_str(), &statement],
        )
        .map_err(db_err)?;
        // Rows first, the audit chain last.
        let authorized = job_quorums(t, j, g, &owners).is_ok();
        if authorized {
            self.transition_in(
                t,
                ctx.actor(),
                &ctx.request_id,
                id,
                JobState::Authorized,
                None,
            )?;
        }
        audit::append(
            t,
            ctx.draft("job.approved", "job", id, Outcome::Succeeded)
                .org(&org)
                .project(&j.project)
                .r#ref("role", role.as_str())
                .r#ref("statement", statement.clone()),
        )?;
        if authorized {
            audit::append(
                t,
                ctx.draft("job.authorized", "job", id, Outcome::Succeeded)
                    .org(&j.organization)
                    .project(&j.project),
            )?;
        }
        Ok(Ok(()))
    }

    // --- scheduling ---------------------------------------------------------------

    /// Places authorized jobs on compatible, ready evaluators.
    pub fn schedule_pending(&self) -> Result<()> {
        let ids: Vec<String> = self
            .db
            .conn()?
            .query(
                "SELECT id FROM jobs WHERE state = 'authorized' ORDER BY created_at LIMIT 100",
                &[],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        for id in ids {
            self.schedule_job(&id)?;
        }
        Ok(())
    }

    /// Schedules a job that was just submitted or approved, for callers that
    /// answer with the job as it stands (its state says whether it was
    /// placed): an error is not returned to them, but it is logged, so a job
    /// left authorized without a reason can be diagnosed.
    fn schedule_after(&self, id: &str) {
        if let Err(e) = self.schedule_job(id) {
            LogLine::new(&self.service_id, "schedule_failed")
                .field("job", id)
                .field("code", e.code)
                .field("error", &e.message)
                .emit();
        }
    }

    /// Schedules one authorized job: only an evaluator that registered the
    /// job's backend and parameter profile, is ready, heard from recently,
    /// and has capacity. Among those, the one with the lowest estimated
    /// completion time ([`estimated_ms`]: its queued and running work plus
    /// this job, over its advertised parallelism); ties go to the lowest
    /// evaluator ID. Returns whether it was placed.
    ///
    /// A governed job is checked again first, on the control plane's clock:
    /// if anything it runs under was revoked or its window is over, it
    /// fails (anchored as ended). Its version 2 grant carries the binding,
    /// the plan's PlanId and the authorization set, and never outlives
    /// `not_after`, the strict end of every authorization, purpose and
    /// source window. One whose per-job four-eyes approvals no longer
    /// count (ENC2707: an approver disabled, homed elsewhere or without the
    /// role now) is not failed but waits for approval again; once
    /// scheduled, start refuses and fails it instead.
    pub fn schedule_job(&self, id: &str) -> Result<bool> {
        let (placed, ended) = self.tx_anchored(|t| {
            let Some(j) = job_row(t, id, true)? else { return Ok((false, false)) };
            if j.state != JobState::Authorized {
                return Ok((false, false));
            }
            let governed = match &j.governance {
                None => None,
                Some(g) => match self.revalidate_governed(t, &j, GovernedStage::Schedule, now()) {
                    Ok(not_after) => Some((g, not_after)),
                    // Its per-job approvals no longer count (an approver
                    // disabled or without the role now): not scheduled, it
                    // waits for approval again rather than failing.
                    Err(e) if e.code == Code::GovernanceFourEyesIncomplete => {
                        self.transition_in(t, &self.service_id, "scheduler", id, JobState::WaitingForApproval, Some(&e.message))?;
                        audit::append(
                            t,
                            audit::AuditDraft::new(&self.service_id, "scheduler", "job.approval_lapsed", "job", id, Outcome::Denied)
                                .org(&j.organization)
                                .project(&j.project)
                                .r#ref("reason", e.code.as_str())
                                .r#ref("check", "revalidate_governed")
                                .r#ref("stage", GovernedStage::Schedule.as_str()),
                        )?;
                        return Ok((false, false));
                    }
                    Err(e) => {
                        self.fail_governed(t, &self.service_id, "scheduler", &j, GovernedStage::Schedule, &e)?;
                        return Ok((false, true));
                    }
                },
            };
            // A governed job runs only where its placement admits it now:
            // under the project's constraints, its owners' own, and the
            // separation of operators, at the evidence the registry holds.
            // With none admissible it waits (never another evaluator).
            let admitted = match &governed {
                Some((g, _)) => match self.admission_for_job(t, id, &g.binding) {
                    Ok(a) => Some(a.admitted),
                    Err(e) => {
                        self.fail_governed(t, &self.service_id, "scheduler", &j, GovernedStage::Schedule, &e)?;
                        return Ok((false, true));
                    }
                },
                None => None,
            };
            // Hard constraints first (backend, profile, health, freshness,
            // capacity); cost only orders what is left.
            let candidates = t
                .query(
                    "SELECT e.id, e.capacity,
                            (SELECT count(*) FROM jobs x WHERE x.evaluator_id = e.id AND x.state IN ('queued', 'running', 'verifying')),
                            (SELECT COALESCE(sum(GREATEST(x.estimated_gates, 1)), 0)::bigint FROM jobs x
                              WHERE x.evaluator_id = e.id AND x.state IN ('queued', 'running')),
                            e.logical_cores, e.max_parallel_gates
                       FROM evaluators e JOIN service_accounts s ON s.id = e.service_account
                      WHERE e.status = 'ready' AND s.status = 'active'
                        -- An operator's own evaluator runs only the governed
                        -- jobs whose placement admits it (judged below).
                        AND ($4 OR s.organization_id IS NULL)
                        AND e.backends ? $1 AND e.profiles ? $2
                        AND e.last_heartbeat > now() - make_interval(secs => $3)
                      ORDER BY e.id",
                    &[&j.backend, &j.profile, &(HEARTBEAT_TIMEOUT_SECS as f64), &governed.is_some()],
                )
                .map_err(db_err)?;
            let Some((estimate, evaluator)) = candidates
                .iter()
                .filter(|r| r.get::<_, i64>(2) < r.get::<_, i32>(1) as i64)
                .filter(|r| {
                    admitted
                        .as_ref()
                        .is_none_or(|a| a.iter().any(|x| x.id == r.get::<_, String>(0)))
                })
                .map(|r| {
                    let est = estimated_ms(
                        r.get::<_, i64>(3).max(0) as u64,
                        j.estimated_gates,
                        r.get(4),
                        r.get(5),
                    );
                    (est, r.get::<_, String>(0))
                })
                .min()
            else {
                // Nothing to place it on: logged, because the caller of a job
                // submission is not told (it sees the job still authorized).
                LogLine::new(&self.service_id, "schedule_no_candidate")
                    .field("job", id)
                    .field("backend", &j.backend)
                    .field("profile", &j.profile)
                    .field("ready_evaluators", candidates.len())
                    .field("governed", governed.is_some())
                    .emit();
                return Ok((false, false));
            };
            let t0 = now();
            let (version, governance, expires_at) = match governed {
                None => (JOB_GRANT_VERSION, None, t0 + JOB_GRANT_TTL_SECS),
                Some((g, not_after)) => (
                    JOB_GRANT_V2,
                    Some(GrantGovernance {
                        plan_hash: g.plan_hash.clone(),
                        purpose_id: g.binding.purpose_id.clone(),
                        governance_id: g.governance_id.clone(),
                        binding: g.binding.clone(),
                        authorization_set_id: g.authorization_set_id.clone(),
                        not_after,
                        // Where the job is placed: its evaluator's
                        // operator, location and evidence now.
                        placement: admitted
                            .as_ref()
                            .and_then(|a| a.iter().find(|x| x.id == evaluator))
                            .map(super::placement::grant_placement),
                    }),
                    (t0 + JOB_GRANT_TTL_SECS).min(not_after),
                ),
            };
            let mut g = JobGrant {
                governance,
                version,
                job_id: j.id.clone(),
                organization: j.organization.clone(),
                project: j.project.clone(),
                plan_id: j.plan.clone(),
                spec_id: j.spec_id.clone(),
                program_id: j.program_id.clone(),
                evaluator: evaluator.clone(),
                backend: j.backend.clone(),
                profile: j.profile.clone(),
                issued_at: t0,
                expires_at,
                issuer: self.service_id.clone(),
                issuer_public_key: self.signer.public_key_hex(),
                signature: String::new(),
            };
            g.signature = self.signer.sign(JOB_GRANT, &g.unsigned())?;
            t.execute(
                "UPDATE jobs SET evaluator_id = $2, job_grant = $3, estimated_ms = $4 WHERE id = $1",
                &[
                    &id,
                    &evaluator,
                    &serde_json::to_value(&g).expect("serializable"),
                    &(estimate.min(i64::MAX as u64) as i64),
                ],
            )
            .map_err(db_err)?;
            self.transition_in(t, &self.service_id, "scheduler", id, JobState::Queued, None)?;
            audit::append(
                t,
                audit::AuditDraft::new(&self.service_id, "scheduler", "job.scheduled", "job", id, Outcome::Succeeded)
                    .org(&j.organization)
                    .project(&j.project)
                    .r#ref("evaluator", evaluator.clone())
                    .r#ref("profile", j.profile.clone())
                    .r#ref("estimated_gates", j.estimated_gates.to_string())
                    .r#ref("estimated_ms", estimate.to_string()),
            )?;
            Ok((true, false))
        })?;
        if ended {
            // Anchored as ended: a restored database cannot revive it.
            self.checkpoint_log()?;
        }
        Ok(placed)
    }

    /// The scheduled evaluator asks to start: allowed only if the job is
    /// still queued for it, its grant is valid, and no source asset was
    /// revoked. Never replays a started job.
    pub fn start_job(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        if ctx.principal.service_kind() != Some(ServiceKind::Evaluator) {
            return Err(forbidden("only the scheduled evaluator starts a job"));
        }
        let ended = std::cell::Cell::new(false);
        // What the anchor holds, read before the transaction takes any lock
        // (the anchor's lock is outermost); and the ledgers the start
        // reserved in, to anchor once it committed.
        let anchored = self.anchor.snapshot();
        let reserved = RefCell::new(BTreeSet::<String>::new());
        let r = self.tx_anchored(|t| {
            ended.set(false);
            reserved.borrow_mut().clear();
            let j = job_row(t, id, true)?.ok_or_else(|| not_found("job", id))?;
            if j.evaluator.as_deref() != Some(ctx.actor()) {
                return Err(not_found("job", id));
            }
            job_project(t, ctx, &j)?;
            // A start whose reservations committed but were not yet
            // anchored (the anchor store failed after the commit) is retried
            // by the same evaluator: it anchors them and is acknowledged. A
            // job whose ledgers are all anchored does not start again.
            if j.state == JobState::Running && j.governance.is_some() {
                let behind = self.unanchored_job_ledgers(t, &j.id)?;
                if !behind.is_empty() {
                    reserved.borrow_mut().extend(behind);
                    let g = j.grant.clone().ok_or_else(|| conflict("no grant"))?;
                    return Ok(Ok(json!({"id": id, "state": "running", "grant": g})));
                }
            }
            if j.state != JobState::Queued {
                return Err(conflict(format!(
                    "job {id} is {}: it does not start (again)",
                    j.state.as_str()
                )));
            }
            let g = j.grant.clone().ok_or_else(|| conflict("no grant"))?;
            // A governed job starts only while everything it runs under is
            // still valid, strictly, on the control plane's clock; otherwise
            // it fails and is anchored as ended.
            if j.governance.is_some() {
                if let Err(e) = self.revalidate_governed(t, &j, GovernedStage::Start, now()) {
                    // The evidence for its evaluator's location was renewed
                    // since scheduling and nothing else changed (the check
                    // without the recorded placement passes): not a moved
                    // machine, so the job is scheduled again, not failed.
                    if e.code == Code::GovernanceResidency {
                        let rec = g.governance.as_ref().and_then(|x| x.placement.as_ref());
                        let binding = j.governance.as_ref().map(|x| &x.binding);
                        if let (Some(rec), Some(binding)) = (rec, binding) {
                            if self.check_job_placement(t, &j.id, binding, Some(ctx.actor()), None).is_ok()
                                && self.placement_only_renewed(t, &j.id, binding, ctx.actor(), rec)?
                            {
                                t.execute(
                                    "UPDATE jobs SET evaluator_id = NULL, job_grant = NULL, estimated_ms = NULL WHERE id = $1",
                                    &[&id],
                                )
                                .map_err(db_err)?;
                                self.transition_in(
                                    t,
                                    ctx.actor(),
                                    &ctx.request_id,
                                    id,
                                    JobState::Authorized,
                                    Some(&e.message),
                                )?;
                                audit::append(
                                    t,
                                    ctx.draft("job.requeued", "job", id, Outcome::Denied)
                                        .org(&j.organization)
                                        .project(&j.project)
                                        .r#ref("reason", "location_evidence_renewed")
                                        .r#ref("stage", GovernedStage::Start.as_str()),
                                )?;
                                return Ok(Err(e));
                            }
                        }
                    }
                    self.fail_governed(
                        t,
                        ctx.actor(),
                        &ctx.request_id,
                        &j,
                        GovernedStage::Start,
                        &e,
                    )?;
                    ended.set(true);
                    return Ok(Err(e));
                }
                t.execute("UPDATE jobs SET started_at = now() WHERE id = $1", &[&id])
                    .map_err(db_err)?;
            }
            if now() > g.expires_at {
                return Err(conflict("the job's grant expired"));
            }
            let revoked: i64 = t
                .query_one(
                    "SELECT count(*) FROM assets WHERE id = ANY($1) AND status = 'revoked'",
                    &[&j.sources],
                )
                .map_err(db_err)?
                .get(0);
            if revoked > 0 {
                self.transition_in(
                    t,
                    ctx.actor(),
                    &ctx.request_id,
                    id,
                    JobState::Failed,
                    Some("a source asset was revoked"),
                )?;
                audit::append(
                    t,
                    ctx.draft("job.failed", "job", id, Outcome::Failed)
                        .org(&j.organization)
                        .project(&j.project)
                        .r#ref("reason", "revoked_asset"),
                )?;
                return Ok(Err(conflict("a source asset was revoked")));
            }
            // The job's differential-privacy release is reserved in its
            // sources' scopes and populations before it runs (so before any
            // noise exists): last, so a job refused above reserves nothing.
            if j.governance.is_some() {
                match self.reserve_job_privacy(
                    t,
                    ctx.actor(),
                    &ctx.request_id,
                    &privacy_facts(&j),
                    &j.organization,
                    &anchored,
                )? {
                    Ok(keys) => reserved.borrow_mut().extend(keys),
                    Err(e) => {
                        self.fail_governed(
                            t,
                            ctx.actor(),
                            &ctx.request_id,
                            &j,
                            GovernedStage::Start,
                            &e,
                        )?;
                        ended.set(true);
                        return Ok(Err(e));
                    }
                }
            }
            self.transition_in(t, ctx.actor(), &ctx.request_id, id, JobState::Running, None)?;
            audit::append(
                t,
                ctx.draft("job.started", "job", id, Outcome::Succeeded)
                    .org(&j.organization)
                    .project(&j.project)
                    .r#ref("evaluator", ctx.actor().to_owned()),
            )?;
            Ok(Ok(json!({"id": id, "state": "running", "grant": g})))
        })?;
        // The reservations are anchored before the evaluator is told the
        // job started: committed spending is never forgotten.
        self.anchor_ledgers(&reserved.borrow())?;
        // (`tx_anchored` anchored the refusal already: a checkpoint is made
        // here only if the anchor does not hold the job's ending, so a start
        // that is anchored does not chase a log other writers keep
        // extending.)
        if ended.get() && !self.anchored(crate::govlog::NegSet::EndedJobs, id)? {
            self.checkpoint_log()?;
        }
        r
    }

    /// The evaluator's signed receipt for a job it ran (message or call).
    pub fn evaluator_completed(
        &self,
        evaluator: &str,
        request: &str,
        id: &str,
        receipt: &Value,
        eval_seconds: Option<f64>,
    ) -> Result<Value> {
        let out =
            self.tx_anchored(|t| self.evaluator_completed_in(t, evaluator, request, id, receipt))?;
        if let Some(s) = eval_seconds {
            self.metrics
                .observe("encompute_evaluation_duration_seconds", "all", s);
        }
        Ok(out)
    }

    fn evaluator_completed_in(
        &self,
        t: &mut Transaction<'_>,
        evaluator: &str,
        request: &str,
        id: &str,
        receipt: &Value,
    ) -> Result<Value> {
        let signed: SignedExecutionReceipt =
            serde_json::from_value(receipt.clone()).map_err(|e| bad(format!("receipt: {e}")))?;
        {
            let j = job_row(t, id, true)?.ok_or_else(|| not_found("job", id))?;
            if j.evaluator.as_deref() != Some(evaluator) {
                return Err(not_found("job", id));
            }
            let key: String = t
                .query_one(
                    "SELECT receipt_key FROM evaluators WHERE id = $1",
                    &[&evaluator],
                )
                .map_err(db_err)?
                .get(0);
            let ident = EvaluatorIdentity::from_public_key_hex(&key)?;
            signed.verify_signature(&ident)?;
            if signed.receipt.spec_id != j.spec_id || signed.receipt.program_id != j.program_id {
                return Err(Error::new(
                    Code::Receipt,
                    "the receipt is for another execution spec or program",
                ));
            }
            if j.governance.is_some() {
                governed_receipt(&j, &signed)?;
            }
            if let Some(prev) = &j.receipt {
                if prev != receipt {
                    return Err(conflict(
                        "the evaluator already reported another receipt for this job",
                    ));
                }
                return Ok(json!({"id": id, "state": j.state, "duplicate": true}));
            }
            t.execute(
                "UPDATE jobs SET receipt = $2 WHERE id = $1",
                &[&id, receipt],
            )
            .map_err(db_err)?;
            if j.state == JobState::Running {
                self.transition_in(t, evaluator, request, id, JobState::Verifying, None)?;
            }
            audit::append(
                t,
                audit::AuditDraft::new(
                    evaluator,
                    request,
                    "job.executed",
                    "job",
                    id,
                    Outcome::Succeeded,
                )
                .org(&j.organization)
                .project(&j.project)
                .r#ref("execution", signed.receipt.execution_id.clone()),
            )?;
            Ok(json!({"id": id, "state": "verifying"}))
        }
    }

    /// The client reports the receipt it received with its commitments to
    /// the exact bytes it sent and got; the control plane verifies every
    /// binding against the job's spec and the registered evaluator key.
    pub fn complete_job(&self, ctx: &Ctx, id: &str, r: CompleteJob) -> Result<Value> {
        let res = self.tx_anchored(|t| {
            let j = job_row(t, id, true)?.ok_or_else(|| not_found("job", id))?;
            job_visible(t, ctx, &j)?;
            job_project(t, ctx, &j)?;
            if !ctx.principal.member_of(&j.organization) {
                return Err(not_found("job", id));
            }
            require(
                &ctx.principal,
                &j.organization,
                &[Role::MlDeveloper],
                "completing a job",
            )?;
            if !matches!(j.state, JobState::Running | JobState::Verifying) {
                if j.state == JobState::Succeeded && j.receipt.as_ref() == Some(&r.receipt) {
                    return Ok(Ok(
                        json!({"id": id, "state": "succeeded", "duplicate": true}),
                    ));
                }
                return Err(conflict(format!("job {id} is {}", j.state.as_str())));
            }
            let signed: SignedExecutionReceipt = serde_json::from_value(r.receipt.clone())
                .map_err(|e| bad(format!("receipt: {e}")))?;
            let evaluator = j
                .evaluator
                .clone()
                .ok_or_else(|| conflict("no evaluator"))?;
            let key: String = t
                .query_one(
                    "SELECT receipt_key FROM evaluators WHERE id = $1",
                    &[&evaluator],
                )
                .map_err(db_err)?
                .get(0);
            let (_, compiled, spec, doc) = self.load_plan(t, &j.plan)?;
            // A governed job's spec is its plan's under its binding (and
            // its transcript is the one for that spec).
            let spec = match &j.governance {
                Some(g) => spec.governed(&g.binding),
                None => spec,
            };
            let transcript = transcript_for(&compiled, &spec).map(|x| x.id().hex());
            let ident = EvaluatorIdentity::from_public_key_hex(&key)?;
            let check = verify_receipt(
                &signed,
                &ExpectedExecution {
                    spec: &spec,
                    key_id: &r.key_id,
                    request_commitment: &r.request_commitment,
                    output_commitment: &r.output_commitment,
                    transcript_hash: transcript.as_deref(),
                    proof_expected: doc.doc.proof_required,
                    trusted_evaluator: &ident,
                },
            )
            .and_then(|v| {
                if j.governance.is_some() {
                    governed_receipt(&j, &signed)?;
                }
                Ok(v)
            });
            let evaluator_receipt_differs = j.receipt.as_ref().is_some_and(|x| x != &r.receipt);
            let evidence = json!({
                "request_commitment": r.request_commitment,
                "output_commitment": r.output_commitment,
                "key_id": r.key_id,
            });
            // A governed job that reserved differential-privacy releases
            // succeeds only if each was reported committed: a release that
            // ran but was never accounted is a failure, not a success.
            let unaccounted = self.unaccounted_reservations(t, id)?;
            match (check, evaluator_receipt_differs) {
                (Ok(_), false) if unaccounted.is_none() => {
                    t.execute(
                        "UPDATE jobs SET receipt = $2, evidence = $3 WHERE id = $1",
                        &[&id, &r.receipt, &evidence],
                    )
                    .map_err(db_err)?;
                    if j.state == JobState::Running {
                        self.transition_in(
                            t,
                            ctx.actor(),
                            &ctx.request_id,
                            id,
                            JobState::Verifying,
                            None,
                        )?;
                    }
                    self.transition_in(
                        t,
                        ctx.actor(),
                        &ctx.request_id,
                        id,
                        JobState::Succeeded,
                        None,
                    )?;
                    audit::append(
                        t,
                        ctx.draft("job.succeeded", "job", id, Outcome::Succeeded)
                            .org(&j.organization)
                            .project(&j.project)
                            .r#ref("evaluator", evaluator.clone())
                            .r#ref("execution", signed.receipt.execution_id.clone()),
                    )?;
                    let secs = SystemTime::now()
                        .duration_since(j.created_at)
                        .unwrap_or_default()
                        .as_secs_f64();
                    self.metrics
                        .observe("encompute_job_duration_seconds", &j.backend, secs);
                    Ok(Ok(json!({"id": id, "state": "succeeded"})))
                }
                (check, _) => {
                    let why = match check {
                        Err(e) => e.message,
                        Ok(_) if evaluator_receipt_differs => {
                            "the client's receipt differs from the one the evaluator reported"
                                .into()
                        }
                        Ok(_) => unaccounted.clone().unwrap_or_default(),
                    };
                    t.execute(
                        "UPDATE jobs SET evidence = $2 WHERE id = $1",
                        &[&id, &evidence],
                    )
                    .map_err(db_err)?;
                    self.transition_in(
                        t,
                        ctx.actor(),
                        &ctx.request_id,
                        id,
                        JobState::Failed,
                        Some(&why),
                    )?;
                    audit::append(
                        t,
                        ctx.draft("trust.failed", "job", id, Outcome::Failed)
                            .org(&j.organization)
                            .project(&j.project),
                    )?;
                    Ok(Err(Error::new(Code::Receipt, why)))
                }
            }
        })?;
        if res.is_err() {
            self.metrics
                .inc("encompute_trust_failures_total", "receipt");
        }
        res
    }

    /// The trust report of a job, rebuilt from its signed evidence and the
    /// trusted keys every time: never a stored "trusted" flag.
    pub fn trust_report(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let j = job_row(&mut *c, id, false)?.ok_or_else(|| not_found("job", id))?;
        job_visible(&mut *c, ctx, &j)?;
        // A governed job's evaluator sees its grant and nothing else.
        if j.governance.is_some()
            && ctx.principal.service_kind() == Some(ServiceKind::Evaluator)
            && !ctx.principal.member_of(&j.organization)
        {
            return Err(not_found("job", id));
        }
        let mut checks = vec![];
        let mut ok = true;
        let mut check = |name: &str, r: Result<String>| match r {
            Ok(d) => checks.push(json!({"check": name, "status": "VERIFIED", "detail": d})),
            Err(e) => {
                ok = false;
                checks.push(json!({"check": name, "status": "FAILED", "detail": e.message}));
            }
        };
        let (program, compiled, spec, doc) = self.load_plan(&mut *c, &j.plan)?;
        let spec = match &j.governance {
            Some(g) => spec.governed(&g.binding),
            None => spec,
        };
        check(
            "plan",
            self.verify_stored_plan(&program, &doc.doc.plan)
                .map(|_| format!("plan {} satisfies its requirements", doc.doc.plan_id)),
        );
        check(
            "execution spec",
            if spec.id().hex() == j.spec_id {
                Ok(spec.id().to_string())
            } else {
                Err(conflict(
                    "the job's spec ID does not match its plan's program",
                ))
            },
        );
        let grant = j.grant.clone();
        check(
            "job grant",
            match &grant {
                None => Err(conflict("the job was never scheduled")),
                Some(g) => (|| {
                    if g.issuer_public_key != self.signer.public_key_hex() {
                        return Err(forbidden("the grant was not issued by this control plane"));
                    }
                    verify_signed(&g.issuer_public_key, JOB_GRANT, &g.unsigned(), &g.signature)?;
                    if g.job_id != j.id
                        || g.spec_id != j.spec_id
                        || Some(&g.evaluator) != j.evaluator.as_ref()
                    {
                        return Err(conflict(
                            "the grant does not bind this job, spec and evaluator",
                        ));
                    }
                    if let Some(jg) = &j.governance {
                        let gg = g.governance.as_ref().ok_or_else(|| {
                            conflict("a governed job's grant carries its governance")
                        })?;
                        gg.check(&j.project)?;
                        if gg.governance_id != jg.governance_id
                            || gg.authorization_set_id != jg.authorization_set_id
                        {
                            return Err(conflict(
                                "the grant does not bind the job's governance and authorizations",
                            ));
                        }
                    }
                    Ok(format!("signed for evaluator {}", g.evaluator))
                })(),
            },
        );
        let receipt_status = match (&j.receipt, &j.evidence, &j.evaluator) {
            (Some(rv), Some(ev), Some(e)) => (|| {
                let signed: SignedExecutionReceipt =
                    serde_json::from_value(rv.clone()).map_err(|x| bad(x.to_string()))?;
                let key: String = c
                    .query_one("SELECT receipt_key FROM evaluators WHERE id = $1", &[e])
                    .map_err(db_err)?
                    .get(0);
                let ident = EvaluatorIdentity::from_public_key_hex(&key)?;
                let s = |k: &str| ev[k].as_str().unwrap_or_default().to_owned();
                let transcript = transcript_for(&compiled, &spec).map(|x| x.id().hex());
                verify_receipt(
                    &signed,
                    &ExpectedExecution {
                        spec: &spec,
                        key_id: &s("key_id"),
                        request_commitment: &s("request_commitment"),
                        output_commitment: &s("output_commitment"),
                        transcript_hash: transcript.as_deref(),
                        proof_expected: doc.doc.proof_required,
                        trusted_evaluator: &ident,
                    },
                )?;
                if j.governance.is_some() {
                    governed_receipt(&j, &signed)?;
                }
                Ok(format!(
                    "signed by registered evaluator {e}; binds the request and response bytes"
                ))
            })(),
            _ => Err(conflict("no verified receipt yet")),
        };
        check("receipt", receipt_status);
        // The job's sources are the assets its program binds (derived at
        // submission); a recorded list that differs from the program's
        // bindings fails the report rather than being trusted.
        let derived = SourceBinding::of(&mut *c, &program)?.sources();
        let mut recorded = j.sources.clone();
        recorded.sort();
        let named = if derived.is_empty() {
            "none (the program binds no input to a registered asset)".to_owned()
        } else {
            derived.join(", ")
        };
        if recorded != derived {
            ok = false;
            checks.push(json!({"check": "source assets", "status": "FAILED",
                "detail": format!("the job records sources {:?}, but its program binds {named}", j.sources)}));
        } else {
            let revoked: Vec<String> = c
                .query(
                    "SELECT id FROM assets WHERE id = ANY($1) AND status = 'revoked'",
                    &[&derived],
                )
                .map_err(db_err)?
                .iter()
                .map(|r| r.get(0))
                .collect();
            let mut note = if revoked.is_empty() {
                "no source asset is revoked".to_owned()
            } else {
                format!("revoked since: {}", revoked.join(", "))
            };
            // A source past its deletion date since is noted, never failed:
            // the evidence of a job that ran before it stays valid after
            // the data is deleted.
            let expired: Vec<String> = c
                .query(
                    "SELECT id FROM assets WHERE id = ANY($1) AND expired_at IS NOT NULL",
                    &[&derived],
                )
                .map_err(db_err)?
                .iter()
                .map(|r| r.get(0))
                .collect();
            if !expired.is_empty() {
                note.push_str(&format!(
                    "; expired since (deletion date passed): {}",
                    expired.join(", ")
                ));
            }
            checks.push(json!({"check": "source assets",
                "status": if revoked.is_empty() { "VERIFIED" } else { "REVOKED" },
                "sources": derived,
                "detail": format!("the program's bound assets: {named}; {note}")}));
        }
        // A governed job: every authorization it ran under is judged at the
        // job's start (execution time, on the control plane's clock), never
        // now: evidence of a job that ran inside its window stays valid
        // after the window ends. Whether each may be used now is shown
        // apart and never fails the report.
        if let Some(g) = &j.governance {
            let status = match j.started_at {
                None => Err(conflict("the job never started")),
                Some(at) => self.tx_anchored(|t| {
                    let mut current = vec![];
                    for row in g.authorizations.keys() {
                        crate::ops::governance::usable_at(t, row, at)?;
                        current.push(match crate::ops::governance::usable_at(t, row, now()) {
                            Ok(()) => format!("{row}: VALID"),
                            Err(e) if e.code == Code::GovernanceAuthorizationExpired => {
                                format!("{row}: EXPIRED")
                            }
                            Err(e) => format!("{row}: REVOKED ({})", e.code.as_str()),
                        });
                    }
                    Ok(current)
                }),
            };
            match status {
                Ok(current) => checks.push(json!({"check": "governance", "status": "VERIFIED",
                    "detail": format!(
                        "purpose {}, governance {}, authorization set {}: VALID AT EXECUTION (started at {})",
                        g.binding.purpose_id, g.governance_id, g.authorization_set_id,
                        j.started_at.unwrap_or_default()),
                    "now": current})),
                Err(e) => {
                    ok = false;
                    checks.push(json!({"check": "governance", "status": "FAILED", "detail": e.message}));
                }
            }
        }
        let verdict = if ok && j.state == JobState::Succeeded {
            "SATISFIED"
        } else {
            "NOT SATISFIED"
        };
        if verdict != "SATISFIED" && j.state == JobState::Succeeded {
            self.metrics.inc("encompute_trust_failures_total", "report");
            self.audit_denied(
                ctx.draft("trust.failed", "job", id, Outcome::Failed)
                    .org(&j.organization)
                    .project(&j.project),
            );
        }
        Ok(json!({
            "job": id, "state": j.state, "verdict": verdict,
            "scheme": j.scheme, "backend": j.backend, "profile": j.profile,
            "execution_proof": if doc.doc.proof_required { "REQUIRED" } else { "NOT PRESENT (a receipt is a signed claim, not a proof)" },
            "checks": checks,
        }))
    }

    // --- evaluators -----------------------------------------------------------------

    pub fn register_evaluator(&self, ctx: &Ctx, r: RegisterEvaluator) -> Result<Value> {
        if ctx.principal.service_kind() != Some(ServiceKind::Evaluator) || ctx.actor() != r.id {
            return Err(forbidden(
                "an evaluator registers itself, with its own service identity",
            ));
        }
        check_name("url", &r.url)?;
        EvaluatorIdentity::from_public_key_hex(&r.receipt_key)
            .map_err(|_| bad("receipt_key must be an Ed25519 public key"))?;
        if r.capacity <= 0 || r.capacity > 10_000 {
            return Err(bad("capacity must be 1-10000"));
        }
        if r.backends.iter().any(|b| b == "tfhe-rs") {
            return Err(Error::new(
                Code::InsecureConfiguration,
                "research backends are not scheduled by the control plane",
            ));
        }
        for b in r.backends.iter().chain(&r.profiles) {
            check_name("backend/profile", b)?;
        }
        // The machine profile is self-reported and only ever steers
        // placement; validated for sanity, not trusted.
        if let Some(m) = &r.cpu_model {
            check_name("cpu_model", m)?;
        }
        if let Some(p) = &r.benchmark_profile {
            check_name("benchmark_profile", p)?;
        }
        for (what, v) in [
            ("logical_cores", r.logical_cores),
            ("max_parallel_gates", r.max_parallel_gates),
        ] {
            if v.is_some_and(|n| !(1..=65_536).contains(&n)) {
                return Err(bad(format!("{what} must be 1-65536")));
            }
        }
        if r.memory_bytes.is_some_and(|n| n <= 0) {
            return Err(bad("memory_bytes must be positive"));
        }
        let out = self.tx_anchored(|t| {
            let endpoint_before = super::placement::endpoint_of(t, &r.id)?;
            let status: String = t.query_one(
                "INSERT INTO evaluators (id, service_account, url, receipt_key, backends, profiles, openfhe_version, capacity, status,
                                         cpu_model, logical_cores, memory_bytes, benchmark_profile, max_parallel_gates)
                 VALUES ($1, $1, $2, $3, $4, $5, $6, $7, 'ready', $8, $9, $10, $11, $12)
                 ON CONFLICT (id) DO UPDATE SET url = $2, receipt_key = $3, backends = $4, profiles = $5,
                     openfhe_version = $6, capacity = $7, last_heartbeat = now(),
                     -- An operator's drain holds across the evaluator's restarts.
                     status = CASE WHEN evaluators.status = 'draining' THEN 'draining' ELSE 'ready' END,
                     cpu_model = $8, logical_cores = $9, memory_bytes = $10, benchmark_profile = $11,
                     max_parallel_gates = $12
                 RETURNING status",
                &[
                    &r.id, &r.url, &r.receipt_key, &json!(r.backends), &json!(r.profiles), &r.openfhe_version, &r.capacity,
                    &r.cpu_model, &r.logical_cores, &r.memory_bytes, &r.benchmark_profile, &r.max_parallel_gates,
                ],
            )
            .map_err(|e| {
                if e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                    conflict("this receipt key belongs to another evaluator")
                } else {
                    db_err(e)
                }
            })?
            .get(0);
            // Its operator (the organization of its service account) and
            // the location it reports: recorded as its own, self-declared
            // claim, and a changed location loses any evidence.
            let operator = super::placement::operator_of(t, &r.id)?
                .unwrap_or_else(|| PLATFORM_ORG.to_owned());
            self.endpoint_changed(t, ctx, &r.id, &operator, endpoint_before.clone())?;
            self.register_location(t, ctx, &r.id, &operator, r.location.as_ref())?;
            // An evaluator registers when its process starts: a job it was
            // running and never reported died with the old process. It
            // fails now (never replayed) rather than staying "running"
            // forever behind the new process's heartbeats.
            let lost: Vec<(String, String)> = t
                .query(
                    "SELECT id, organization_id FROM jobs
                      WHERE evaluator_id = $1 AND state = 'running' AND receipt IS NULL
                      FOR UPDATE",
                    &[&r.id],
                )
                .map_err(db_err)?
                .iter()
                .map(|x| (x.get(0), x.get(1)))
                .collect();
            for (job, _) in &lost {
                self.transition_in(
                    t,
                    ctx.actor(),
                    &ctx.request_id,
                    job,
                    JobState::Failed,
                    Some("the evaluator restarted while running it; not replayed"),
                )?;
            }
            for (job, org) in &lost {
                audit::append(
                    t,
                    ctx.draft("job.failed", "job", job, Outcome::Failed)
                        .org(org)
                        .r#ref("reason", "evaluator_restarted"),
                )?;
            }
            let mut d = ctx
                .draft("evaluator.registered", "evaluator", &r.id, Outcome::Succeeded)
                .org(&operator)
                .r#ref("backends", r.backends.join("+"))
                .r#ref("profiles", r.profiles.join("+"))
                .r#ref("openfhe", r.openfhe_version.clone())
                // Which receipt key clients will be told to trust.
                .r#ref("receipt_key_sha256", sha256_hex(r.receipt_key.as_bytes()));
            if let Some(p) = &r.benchmark_profile {
                d = d.r#ref("benchmark_profile", p.clone());
            }
            audit::append(t, d)?;
            Ok(json!({"id": r.id, "status": status, "control_public_key": self.signer.public_key_hex()}))
        })?;
        self.checkpoint_log()?;
        Ok(out)
    }

    /// Heartbeat / status: the evaluator itself (ready, busy, draining,
    /// unhealthy) or a platform operator (draining, ready).
    pub fn evaluator_status(&self, ctx: &Ctx, id: &str, r: EvaluatorStatus) -> Result<Value> {
        self.tx_anchored(|t| self.evaluator_status_in(t, ctx, id, &r))
    }

    fn evaluator_status_in(
        &self,
        t: &mut Transaction<'_>,
        ctx: &Ctx,
        id: &str,
        r: &EvaluatorStatus,
    ) -> Result<Value> {
        let own = ctx.principal.service_kind() == Some(ServiceKind::Evaluator) && ctx.actor() == id;
        let operator = ctx.principal.has_role(PLATFORM_ORG, Role::Operator);
        let allowed = match r.status.as_str() {
            "ready" | "draining" => own || operator,
            "busy" | "unhealthy" => own,
            _ => return Err(bad("status is ready, busy, draining or unhealthy")),
        };
        if !allowed {
            return Err(forbidden(
                "an evaluator reports its own status; operators may drain it",
            ));
        }
        {
            let current: String = t
                .query_opt(
                    "SELECT status FROM evaluators WHERE id = $1 FOR UPDATE",
                    &[&id],
                )
                .map_err(db_err)?
                .ok_or_else(|| not_found("evaluator", id))?
                .get(0);
            // An operator's drain holds until an operator lifts it: the
            // evaluator's own "ready" heartbeat does not undo it.
            let status = if own && !operator && current == "draining" && r.status == "ready" {
                "draining".to_owned()
            } else {
                r.status.clone()
            };
            t.execute(
                "UPDATE evaluators SET status = $2, last_heartbeat = CASE WHEN $3 THEN now() ELSE last_heartbeat END WHERE id = $1",
                &[&id, &status, &own],
            )
            .map_err(db_err)?;
            let r = EvaluatorStatus { status };
            if r.status == "draining" || !own {
                audit::append(
                    t,
                    ctx.draft("evaluator.status", "evaluator", id, Outcome::Succeeded)
                        .org(PLATFORM_ORG)
                        .r#ref("status", r.status.clone()),
                )?;
            }
            let running: i64 = t
                .query_one("SELECT count(*) FROM jobs WHERE evaluator_id = $1 AND state IN ('queued', 'running', 'verifying')", &[&id])
                .map_err(db_err)?
                .get(0);
            Ok(json!({"id": id, "status": r.status, "jobs_in_flight": running}))
        }
    }

    /// The platform's operators and admins list every evaluator; an
    /// organization's admins and security admins list the ones it operates.
    pub fn list_evaluators(&self, ctx: &Ctx) -> Result<Value> {
        let platform = ctx
            .principal
            .any_role(PLATFORM_ORG, &[Role::Operator, Role::OrganizationAdmin]);
        let orgs: Vec<String> = ctx
            .principal
            .organizations()
            .into_iter()
            .filter(|o| {
                ctx.principal
                    .any_role(o, &[Role::OrganizationAdmin, Role::SecurityAdmin])
            })
            .collect();
        // Anyone else is refused as ever: not found for a tenant, forbidden
        // for a platform member without the role.
        let refused = || {
            require(
                &ctx.principal,
                PLATFORM_ORG,
                &[Role::Operator, Role::OrganizationAdmin],
                "listing evaluators",
            )
            .err()
            .unwrap_or_else(|| forbidden("listing evaluators needs operator or organization_admin"))
        };
        if !platform && orgs.is_empty() {
            return Err(refused());
        }
        let mut c = self.db.conn()?;
        if !platform {
            let operates = c
                .query_opt(
                    "SELECT 1 FROM evaluators e JOIN service_accounts s ON s.id = e.service_account
                      WHERE s.organization_id = ANY($1) LIMIT 1",
                    &[&orgs],
                )
                .map_err(db_err)?;
            if operates.is_none() {
                return Err(refused());
            }
        }
        Ok(Value::Array(
            c.query(
                "SELECT e.id, e.url, e.backends, e.profiles, e.openfhe_version, e.capacity, e.status,
                        e.cpu_model, e.logical_cores, e.memory_bytes, e.benchmark_profile, e.max_parallel_gates,
                        s.organization_id, e.location, e.location_evidence,
                        e.location_evidence_digest,
                        floor(extract(epoch FROM e.location_valid_until))::bigint
                   FROM evaluators e JOIN service_accounts s ON s.id = e.service_account
                  WHERE $1 OR s.organization_id = ANY($2)
                  ORDER BY e.id",
                &[&platform, &orgs],
            )
                .map_err(db_err)?
                .iter()
                .map(|r| {
                    json!({"id": r.get::<_, String>(0), "url": r.get::<_, String>(1), "backends": r.get::<_, Value>(2),
                           "profiles": r.get::<_, Value>(3), "openfhe_version": r.get::<_, String>(4),
                           "capacity": r.get::<_, i32>(5), "status": r.get::<_, String>(6),
                           "cpu_model": r.get::<_, Option<String>>(7),
                           "logical_cores": r.get::<_, Option<i32>>(8),
                           "memory_bytes": r.get::<_, Option<i64>>(9),
                           "benchmark_profile": r.get::<_, Option<String>>(10),
                           "max_parallel_gates": r.get::<_, Option<i32>>(11),
                           "operator": r.get::<_, Option<String>>(12).unwrap_or_else(|| PLATFORM_ORG.to_owned()),
                           "location": r.get::<_, Option<Value>>(13),
                           "location_evidence": r.get::<_, String>(14),
                           "location_evidence_digest": r.get::<_, Option<String>>(15),
                           "location_valid_until": r.get::<_, Option<i64>>(16)})
                })
                .collect(),
        ))
    }

    /// Marks silent evaluators unhealthy, and resolves jobs stranded by a
    /// restart or a lost evaluator: queued jobs whose grant expired are
    /// re-authorized (they never started); running jobs on an evaluator
    /// that is gone fail (never replayed).
    pub fn expire_evaluators(&self) -> Result<()> {
        self.tx_anchored(|t| {
            t.execute(
                "UPDATE evaluators SET status = 'unhealthy'
                  WHERE status IN ('ready', 'busy') AND last_heartbeat < now() - make_interval(secs => $1)",
                &[&(HEARTBEAT_TIMEOUT_SECS as f64)],
            )
            .map_err(db_err)?;
            let stale: Vec<(String, String, String)> = t
                .query(
                    "SELECT j.id, j.state, j.organization_id FROM jobs j
                       LEFT JOIN evaluators e ON e.id = j.evaluator_id
                      WHERE (j.state = 'queued' AND (j.job_grant->>'expires_at')::bigint < $1)
                         OR (j.state = 'running' AND e.status = 'unhealthy'
                             AND (j.job_grant->>'expires_at')::bigint < $1)",
                    &[&(now() as i64)],
                )
                .map_err(db_err)?
                .iter()
                .map(|r| (r.get(0), r.get(1), r.get(2)))
                .collect();
            for (id, state, org) in stale {
                if state == "queued" {
                    // Never started: cancel the grant by failing the job; the
                    // client resubmits (with a new idempotency key).
                    self.transition_in(t, &self.service_id, "recovery", &id, JobState::Failed, Some("the grant expired before the evaluator started"))?;
                } else {
                    self.transition_in(t, &self.service_id, "recovery", &id, JobState::Failed, Some("the evaluator was lost while running; not replayed"))?;
                }
                audit::append(
                    t,
                    audit::AuditDraft::new(&self.service_id, "recovery", "job.failed", "job", &id, Outcome::Failed).org(&org),
                )?;
            }
            Ok(())
        })
    }

    // --- messages and the outbox ------------------------------------------------------

    /// A signed message from a service, applied once.
    pub fn receive_message(&self, ctx: &Ctx, m: &MessageEnvelope) -> Result<Value> {
        if m.sender != ctx.actor() {
            return Err(Error::new(
                Code::ServiceAuthentication,
                "the message's sender is not the calling service",
            ));
        }
        let pk: String = self
            .db
            .conn()?
            .query_one(
                "SELECT public_key FROM service_accounts WHERE id = $1",
                &[&m.sender],
            )
            .map_err(db_err)?
            .get(0);
        crate::transport::open(m, &pk, &self.service_id, now())?;
        let duplicate = |t: &mut Transaction<'_>| -> Result<Option<Value>> {
            Ok(t.query_opt(
                "SELECT outcome FROM inbox WHERE consumer = $1 AND message_id = $2",
                &[&self.service_id, &m.message_id],
            )
            .map_err(db_err)?
            .map(|r| {
                let mut v: Value = r.get(0);
                v["duplicate"] = json!(true);
                v
            }))
        };
        if m.kind == "privacy.event" {
            // The ledger applies an event once by its ID, under the
            // ledger row's lock, in its own transaction (and anchors it
            // after commit): a concurrent duplicate finds the entry.
            if let Some(v) = self.tx_anchored(|t| duplicate(t))? {
                return Ok(v);
            }
            let event = serde_json::from_value(m.payload["event"].clone())
                .map_err(|e| bad(format!("event: {e}")))?;
            // A governed job's release is charged to a scope (and its
            // population); anything else to the asset's own ledger.
            let outcome = match (m.payload["scope"].as_str(), m.payload["asset"].as_str()) {
                (Some(scope), None) => self.privacy_spend_scoped(ctx, scope, event)?,
                (None, Some(asset)) => self.privacy_spend(ctx, asset, event)?,
                _ => return Err(bad("privacy.event names an asset or a scope")),
            };
            self.db
                .conn()?
                .execute(
                    "INSERT INTO inbox (consumer, message_id, outcome) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    &[&self.service_id, &m.message_id, &outcome],
                )
                .map_err(db_err)?;
            return Ok(outcome);
        }
        // One transaction: the inbox row first (a concurrent delivery of
        // the same message waits on it, then finds it), then the effect.
        let outcome = self.tx_anchored(|t| {
            let fresh = t
                .execute(
                    "INSERT INTO inbox (consumer, message_id, outcome) VALUES ($1, $2, 'null') ON CONFLICT DO NOTHING",
                    &[&self.service_id, &m.message_id],
                )
                .map_err(db_err)?;
            if fresh == 0 {
                return duplicate(t)?.ok_or_else(|| conflict("message is being applied"));
            }
            let outcome = match m.kind.as_str() {
                "job.completed" => {
                    let job = m
                        .job
                        .as_deref()
                        .ok_or_else(|| bad("job.completed names no job"))?;
                    self.evaluator_completed_in(
                        t,
                        &m.sender,
                        &ctx.request_id,
                        job,
                        &m.payload["receipt"],
                    )?
                }
                "evaluator.heartbeat" => self.evaluator_status_in(
                    t,
                    ctx,
                    &m.sender,
                    &EvaluatorStatus {
                        status: m.payload["status"].as_str().unwrap_or("ready").into(),
                    },
                )?,
                "key.release" => {
                    if ctx.principal.service_kind() != Some(ServiceKind::Keybroker) {
                        return Err(forbidden("key releases are reported by key brokers"));
                    }
                    let asset = m.payload["asset"]
                        .as_str()
                        .ok_or_else(|| bad("key.release names no asset"))?;
                    let allowed = m.payload["allowed"].as_bool().unwrap_or(false);
                    // A broker reports on the assets of its own organization
                    // (the platform's brokers: on any organization's).
                    let mapped = t
                        .query_opt(
                            "SELECT id, organization_id FROM assets WHERE key_ref->>'broker' = $1 AND key_ref->>'key_ref' = $2
                                AND ($3::text IS NULL OR organization_id = $3)
                              ORDER BY id LIMIT 1",
                            &[&m.sender, &asset, &ctx.principal.organization],
                        )
                        .map_err(db_err)?
                        .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)));
                    let (resource, org) = match &mapped {
                        Some((id, org)) => (id.clone(), Some(org.clone())),
                        None => (asset.to_owned(), None),
                    };
                    let mut d = ctx
                        .draft(
                            if allowed {
                                "key.release.allowed"
                            } else {
                                "key.release.denied"
                            },
                            "asset",
                            &resource,
                            if allowed {
                                Outcome::Allowed
                            } else {
                                Outcome::Denied
                            },
                        )
                        .r#ref("broker", m.sender.clone());
                    if let Some(o) = &org {
                        d = d.org(o);
                    }
                    if let Some(reason) = m.payload["reason"].as_str() {
                        d = d.r#ref("reason", reason.to_owned());
                    }
                    audit::append(t, d)?;
                    json!({"recorded": true})
                }
                "secagg.round.completed" => json!({"recorded": true}),
                other => return Err(bad(format!("unknown message kind {other:?}"))),
            };
            t.execute(
                "UPDATE inbox SET outcome = $3 WHERE consumer = $1 AND message_id = $2",
                &[&self.service_id, &m.message_id, &outcome],
            )
            .map_err(db_err)?;
            Ok(outcome)
        })?;
        // Metrics for a message applied now (not for a duplicate).
        if outcome.get("duplicate").is_none() {
            match m.kind.as_str() {
                "job.completed" => {
                    if let Some(ms) = m.payload["evaluation_ms"].as_u64() {
                        self.metrics.observe(
                            "encompute_evaluation_duration_seconds",
                            "all",
                            ms as f64 / 1000.0,
                        );
                    }
                }
                "key.release" if m.payload["allowed"].as_bool() != Some(true) => {
                    self.metrics
                        .inc("encompute_key_release_denied_total", "broker");
                }
                "secagg.round.completed" => {
                    if let Some(ms) = m.payload["duration_ms"].as_u64() {
                        self.metrics.observe(
                            "encompute_secagg_round_duration_seconds",
                            "all",
                            ms as f64 / 1000.0,
                        );
                    }
                }
                _ => {}
            }
        }
        Ok(outcome)
    }

    /// Delivers pending outbox messages (at least once).
    pub fn deliver_outbox(&self) -> Result<()> {
        let pending: Vec<(String, String, Value)> = self
            .db
            .conn()?
            .query(
                "SELECT message_id, url, envelope FROM outbox WHERE delivered_at IS NULL AND attempts < 100
                  ORDER BY created_at LIMIT 20",
                &[],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect();
        for (id, url, env) in pending {
            let m: MessageEnvelope = serde_json::from_value(env).map_err(db_err)?;
            // A key broker learns of a revocation only once the anchor holds
            // the governance log's event of it (its position is at most the
            // anchored size): a restored database cannot then un-revoke an
            // asset whose key the broker already destroyed without it being
            // noticed. Likewise an owner authorization's revocation and an
            // asset's expiry.
            let gate = match m.kind.as_str() {
                "asset.revoked" => Some(("asset", crate::govlog::NegSet::RevokedAssets)),
                "authorization.revoked" => Some((
                    "authorization",
                    crate::govlog::NegSet::RevokedAuthorizations,
                )),
                "asset.expired" => Some(("asset", crate::govlog::NegSet::ExpiredAssets)),
                _ => None,
            };
            if let Some((field, set)) = gate {
                let Some(subject) = m.payload[field].as_str() else {
                    continue;
                };
                if !self.anchored(set, subject)? {
                    continue;
                }
            }
            let r = self.transport.send(&url, &m);
            let mut c = self.db.conn()?;
            match r {
                Ok(()) => c.execute("UPDATE outbox SET delivered_at = now(), attempts = attempts + 1 WHERE message_id = $1", &[&id]),
                Err(e) => {
                    LogLine::new(&self.service_id, "outbox_retry").id("message", Some(&id)).field("error", &e.message).emit();
                    c.execute(
                        "UPDATE outbox SET attempts = attempts + 1, last_error = $2 WHERE message_id = $1",
                        &[&id, &e.message],
                    )
                }
            }
            .map_err(db_err)?;
        }
        Ok(())
    }
}

/// A loaded plan's document.
struct PlanDocView {
    doc: PlanDoc,
}

/// What [`Control::submit_governed`] needs from the checks before it.
struct Submission<'a> {
    project: &'a ProjectRow,
    org: &'a str,
    key: &'a str,
    digest: &'a str,
    doc: &'a PlanDoc,
    program: &'a Program,
    program_id: String,
}

/// The release checks of a governed submission that need the program: each
/// output's requested class admits a form the compiler proves the output
/// takes (a program that releases in a form its sources do not allow,
/// ENC1907 at compilation, is ENC2709 here); every source with a
/// registered policy is declared by the program at least as strictly for
/// `purpose` (ENC2709, or ENC2702 for its purposes); and every output's
/// class is within each source's registered release class (ENC2709).
fn release_forms(
    program: &Program,
    outputs: &BTreeMap<String, encompute_verification::governance::GovernanceOutput>,
    purpose: &str,
    registered: &BTreeMap<String, (Option<Value>, Option<String>)>,
) -> std::result::Result<(), (&'static str, Error)> {
    let release = |why, m: String| (why, gov(Code::GovernanceReleaseClass, m));
    let forms = encompute_analysis::confidentiality::output_forms(program)
        .map_err(|e| {
            if e.code == Code::ReleaseForm {
                release("release_form", e.message)
            } else {
                ("program", e)
            }
        })?
        .unwrap_or_default();
    for (n, o) in outputs {
        let provable = forms.get(n).cloned().unwrap_or_default();
        if !o.release_class.admits(&provable) {
            return Err(release(
                "release_form",
                format!(
                    "output {n:?} is released as {}, but the compiler does not prove it takes a form that class allows",
                    o.release_class.as_str()
                ),
            ));
        }
    }
    let conf = program.confidentiality();
    for (a, (policy, class)) in registered {
        // Every governed source carries its owner's registered policy and
        // release class; without them the checks below could not bound it.
        if policy.is_none() || class.is_none() {
            return Err(release(
                "registered_policy",
                format!(
                    "asset {a} has no registered policy and release class: a governed job reads only versions registered with ir_policy and release_class"
                ),
            ));
        }
        if let Some(policy) = policy {
            let registered: encompute_ir::confidentiality::AssetPolicy =
                serde_json::from_value(policy.clone()).map_err(|e| {
                    (
                        "registered_policy",
                        db_err(format!("registered policy: {e}")),
                    )
                })?;
            let Some(declared) = conf.and_then(|c| c.asset(a)) else {
                return Err(release(
                    "registered_policy",
                    format!(
                        "the program does not declare asset {a}, whose owner registered its policy"
                    ),
                ));
            };
            encompute_analysis::confidentiality::refines(&declared.policy, &registered, purpose)
                .map_err(|e| {
                    let m = format!("asset {a}: {}", e.message);
                    if e.code == Code::PurposeViolation {
                        ("registered_policy", gov(Code::GovernancePurposeMismatch, m))
                    } else {
                        release("registered_policy", m)
                    }
                })?;
        }
        if let Some(class) = class {
            let ceiling = ReleaseClass::ALL
                .into_iter()
                .find(|c| c.as_str() == class)
                .ok_or_else(|| {
                    (
                        "registered_policy",
                        db_err(format!("release class {class}")),
                    )
                })?;
            if let Some((n, o)) = outputs
                .iter()
                .find(|(_, o)| !release_within(o.release_class, ceiling))
            {
                return Err(release(
                    "release_class",
                    format!(
                        "output {n:?} is released as {}, beyond {class}, the release class asset {a} was registered with",
                        o.release_class.as_str()
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Whether owner authorization `a` covers an execution of `spec` (before
/// its binding) with the purpose's `linkage` and `outputs`: the same checks
/// the owner's key broker makes. Refusals carry their audit reason.
fn covers(
    a: &SignedAuthorizationV2,
    spec: &ExecutionSpec,
    linkage: &Option<String>,
    outputs: &BTreeMap<String, encompute_verification::governance::GovernanceOutput>,
) -> std::result::Result<(), (&'static str, Error)> {
    let b = &a.body;
    let program = |m: &str| {
        (
            "program_not_authorized",
            gov(Code::GovernanceProgramNotAuthorized, m.to_owned()),
        )
    };
    if !b.program.covers(&spec.program_id) {
        return Err(program("the owner did not authorize this program"));
    }
    if spec.policy_id.as_deref() != Some(b.policy_id.as_str()) {
        return Err(program(
            "the program runs under another confidentiality policy than the owner authorized",
        ));
    }
    if spec.privacy_policy_id != b.privacy_policy_id {
        return Err(program(
            "the program runs under another privacy policy than the owner authorized",
        ));
    }
    if b.linkage_policy_id != *linkage {
        return Err((
            "linkage",
            gov(
                Code::GovernanceLinkageMismatch,
                "the owner authorized another linkage policy than the purpose's",
            ),
        ));
    }
    // Probing controls: limits on repeated queries, and at most the
    // authorized number of boolean-only outputs per job.
    if let Err(e) = a.body.check_probing_limits() {
        return Err(("release", e));
    }
    if !a.body.probing_outputs_within(outputs) {
        return Err((
            "release",
            gov(
                Code::GovernanceReleaseClass,
                "the job releases more boolean-only outputs than the owner authorized per job (max_outputs_per_job, one when absent)",
            ),
        ));
    }
    for (name, o) in outputs {
        // The owners' release-class order, the key broker's own check.
        let class_ok = release_within(o.release_class, b.release_class);
        if !class_ok || !o.recipients.is_subset(&b.recipients) {
            return Err((
                "release",
                gov(
                    Code::GovernanceReleaseClass,
                    format!("output {name} releases more, or to others, than the owner authorized"),
                ),
            ));
        }
    }
    Ok(())
}

/// The organizations whose authorization, among those governed job `g`
/// runs under, asks for per-job four-eyes approval: each has a quorum of
/// its own people approve the job before it is scheduled.
fn four_eyes_owners(t: &mut Transaction<'_>, g: &JobGovernance) -> Result<BTreeSet<String>> {
    let rows: Vec<String> = g.authorizations.keys().cloned().collect();
    let mut owners = BTreeSet::new();
    for r in t
        .query(
            "SELECT organization_id, signed FROM authorizations WHERE id = ANY($1) ORDER BY id",
            &[&rows],
        )
        .map_err(db_err)?
    {
        let signed: SignedAuthorizationV2 = r
            .get::<_, Option<Value>>(1)
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| db_err(format!("stored authorization: {e}")))?
            .ok_or_else(|| db_err("a job's authorization is signed"))?;
        if signed.body.per_job_four_eyes {
            owners.insert(r.get(0));
        }
    }
    Ok(owners)
}

/// The statement each approver of governed job `j` approves: its job ID,
/// governed spec ID and authorization set.
fn job_statement(j: &JobRow, g: &JobGovernance) -> String {
    job_approval_statement(&j.id, &j.spec_id, &g.authorization_set_id)
}

/// Whether every organization in `owners` has its quorum for governed job
/// `j`: under its approval rule for the project, enough distinct people of
/// it approved this job's statement (ENC2707). Only approvals over the
/// job's current statement count, never its submitter's, and only while
/// the approver still may approve (validity at execution time, as
/// [`require_human`](crate::authz::require_human) checks when approving):
/// an active user, homed in the organization, still holding the role the
/// approval counted for and not an auditor there. An approval that stops
/// counting stays on record as evidence.
fn job_quorums(
    t: &mut Transaction<'_>,
    j: &JobRow,
    g: &JobGovernance,
    owners: &BTreeSet<String>,
) -> Result<()> {
    let statement = job_statement(j, g);
    for org in owners {
        let (min, roles) = crate::ops::governance::approval_rule(t, &j.project, org)?;
        let approvals: Vec<(String, String)> = t
            .query(
                "SELECT a.approver_id, a.role FROM job_human_approvals a
                   JOIN users u ON u.id = a.approver_id AND u.status = 'active'
                    AND u.organization_id = a.organization_id
                  WHERE a.job_id = $1 AND a.organization_id = $2 AND a.statement_digest = $3
                    AND a.approver_id <> $4
                    AND EXISTS (SELECT 1 FROM memberships m WHERE m.principal_id = a.approver_id
                                   AND m.organization_id = a.organization_id AND m.role = a.role)
                    AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.principal_id = a.approver_id
                                       AND m.organization_id = a.organization_id AND m.role = 'auditor')",
                &[&j.id, org, &statement, &j.initiated_by],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        quorum_met(approvals, min, &roles).map_err(|e| {
            Error::new(
                e.code,
                format!("{org}'s per-job approval of job {}: {}", j.id, e.message),
            )
        })?;
    }
    Ok(())
}

/// A governed job's receipt: a version 4 receipt naming the digest of the
/// job's own grant (so of its signed issue time, binding and authorization
/// set), for a job that started inside the grant's window. A job that
/// started before `not_after` may complete after it.
fn governed_receipt(j: &JobRow, signed: &SignedExecutionReceipt) -> Result<()> {
    let receipt = |m: &str| Error::new(Code::Receipt, m.to_owned());
    let grant = j
        .grant
        .as_ref()
        .ok_or_else(|| receipt("the job has no grant"))?;
    let not_after = grant
        .governance
        .as_ref()
        .map(|g| g.not_after)
        .ok_or_else(|| receipt("a governed job's grant carries its governance"))?;
    if signed.receipt.grant_digest.as_deref() != Some(grant.digest().as_str()) {
        return Err(receipt(
            "a governed job's receipt names the digest of the grant it ran under (version 4), and this names no grant or another one",
        ));
    }
    if j.started_at.is_none_or(|s| s >= not_after) {
        return Err(receipt("the job did not start inside its governed window"));
    }
    Ok(())
}

/// What [`Control::check_bound_authorization`] checks one authorization
/// against: the job's binding, its plan's spec before the binding, its
/// governed spec ID, and its sources' versions (asset → version).
pub(crate) struct BoundAuthorization<'a> {
    pub row: &'a str,
    pub authorization_id: &'a str,
    pub binding: &'a GovernanceBinding,
    pub base_spec: &'a ExecutionSpec,
    pub spec_id: &'a str,
    pub versions: &'a BTreeMap<String, String>,
}

/// What a derived result, and each export of it, needs of the governed
/// job that released it: fixed at submission (the database refuses to
/// change a governed job's execution, sources or binding).
pub(crate) struct ReleasedJob {
    pub id: String,
    pub project: String,
    pub plan: String,
    pub spec_id: String,
    pub succeeded: bool,
    pub sources: Vec<String>,
    pub binding: GovernanceBinding,
    pub governance_id: String,
    pub plan_hash: String,
    /// Authorization row → its AuthorizationId.
    pub authorizations: BTreeMap<String, String>,
}

/// Governed job `id` as [`ReleasedJob`] (not locked); a standard job is
/// refused. With `ctx`, the caller must see the job, and an auditor is
/// refused (D9): the job's project is returned.
pub(crate) fn released_job(
    c: &mut impl GenericClient,
    ctx: Option<&Ctx>,
    id: &str,
) -> Result<(ReleasedJob, ProjectRow)> {
    let j = job_row(c, id, false)?.ok_or_else(|| not_found("job", id))?;
    let p = match ctx {
        Some(ctx) => {
            job_visible(c, ctx, &j)?;
            job_project(c, ctx, &j)?
        }
        None => project_row(c, &j.project)?.ok_or_else(|| not_found("project", &j.project))?,
    };
    let g = j.governance.clone().ok_or_else(|| {
        conflict(format!(
            "job {id} is not a governed job: derived results and exports belong to governed projects"
        ))
    })?;
    Ok((
        ReleasedJob {
            id: j.id,
            project: j.project,
            plan: j.plan,
            spec_id: j.spec_id,
            succeeded: j.state == JobState::Succeeded,
            sources: j.sources,
            binding: g.binding,
            governance_id: g.governance_id,
            plan_hash: g.plan_hash,
            authorizations: g.authorizations,
        },
        p,
    ))
}
