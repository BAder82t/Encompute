//! Plans, jobs, evaluators and scheduling.
//!
//! A job moves through explicit, validated states. The control plane never
//! sees inputs or outputs: the client encrypts, sends ciphertexts to the
//! scheduled evaluator with the job's grant, decrypts, and reports the
//! evaluator's signed receipt with its own commitments to the exact bytes.
//! The evaluator asks the control plane before starting (so a job revoked
//! or cancelled after scheduling never starts), and reports completion as a
//! signed message.

use std::time::SystemTime;

use postgres::{GenericClient, Transaction};
use serde_json::{json, Value};

use encompute_evaluator::{compile_program, execution_spec, transcript_for, CompiledProgram, Ids};
use encompute_ir::{Code, Error, Program, Result};
use encompute_planner::{
    plan_or_fail, verify_plan, BackendCatalog, ConfidentialExecutionPlan, Infrastructure,
    PlanningContext, Preferences, Profile, ProgramFacts,
};
use encompute_verification::service::{now, verify_signed, JOB_GRANT};
use encompute_verification::{
    verify_receipt, EvaluatorIdentity, ExecutionSpec, ExpectedExecution, SignedExecutionReceipt,
};

use crate::audit::{self, Outcome};
use crate::authz::{
    asset_visible, conflict, forbidden, not_found, project_role_orgs, project_visible, require,
};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::log::LogLine;
use crate::model::{
    bad, check_name, new_id, CompleteJob, CreatePlan, EvaluatorStatus, JobGrant, JobState, JobView,
    MessageEnvelope, RegisterEvaluator, Role, ServiceKind, SubmitJob, JOB_GRANT_TTL_SECS,
    JOB_GRANT_VERSION, PLATFORM_ORG,
};

/// Evaluators silent for longer are unhealthy.
pub const HEARTBEAT_TIMEOUT_SECS: u64 = 90;

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
    let (name, fhe_supported, proof_covered) = match semantics {
        Semantics::Approximate => (
            "approximate",
            encompute_ckks::compile(program).is_ok(),
            false,
        ),
        Semantics::Exact => match encompute_exact::compile(program) {
            Ok(c) => ("exact", true, encompute_evaluator::proof_coverable(&c.plan)),
            Err(_) => ("exact", false, false),
        },
    };
    Ok(ProgramFacts {
        semantics: name.into(),
        fhe_supported,
        proof_covered,
        operations: program.nodes().len() as u64,
    })
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
}

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
}

fn job_row(c: &mut impl GenericClient, id: &str, lock: bool) -> Result<Option<JobRow>> {
    let q = format!(
        "SELECT id, organization_id, project_id, plan_id, spec_id, program_id, purpose, source_assets,
                requested_output, scheme, backend, profile, state, evaluator_id, job_grant, receipt,
                evidence, error, initiated_by, created_at
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
    }))
}

/// Whether `p` may see the job: its organization's members, and the
/// owners of its source assets.
fn job_visible(c: &mut impl GenericClient, ctx: &Ctx, j: &JobRow) -> Result<()> {
    if ctx.principal.member_of(&j.organization) {
        return Ok(());
    }
    if matches!(ctx.principal.service_kind(), Some(ServiceKind::Evaluator))
        && j.evaluator.as_deref() == Some(ctx.actor())
    {
        return Ok(());
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

impl Control {
    fn catalog(&self, c: &mut impl GenericClient) -> Result<BackendCatalog> {
        let backends: Vec<String> = c
            .query(
                // What the deployment offers (a draining or briefly silent
                // evaluator does not change which plans are possible;
                // scheduling checks health).
                "SELECT DISTINCT jsonb_array_elements_text(backends) FROM evaluators",
                &[],
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

    pub fn create_plan(&self, ctx: &Ctx, r: CreatePlan) -> Result<Value> {
        if r.program.len() > 4 << 20 {
            return Err(bad("program too large"));
        }
        let program = encompute_ir::parse(&r.program)?;
        let compiled = compile_program(&program)?;
        let ids = Ids::of(&program, &compiled);
        let target = compiled.target_backend();
        let spec = execution_spec(&ids, &compiled, target);
        let mut c = self.db.conn()?;
        let project = project_visible(&mut *c, &ctx.principal, &r.project)?;
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
        let key_broker = c
            .query_opt(
                "SELECT 1 FROM service_accounts WHERE kind = 'keybroker' AND status = 'active' LIMIT 1",
                &[],
            )
            .map_err(db_err)?
            .is_some();
        let pctx = PlanningContext {
            profile: Profile::Standard,
            catalog: self.catalog(&mut *c)?,
            infrastructure: Infrastructure {
                tees: vec![],
                key_broker,
                host_cloud: true,
                host_region: None,
            },
            preferences: Preferences::default(),
            facts: facts(&program)?,
            training: None,
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
        verify_plan(&program, &plan)?;
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
        };
        let id = new_id("pln");
        self.db.tx(|t| {
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
        }))
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
            .query_one("SELECT state FROM jobs WHERE id = $1 FOR UPDATE", &[&job])
            .map_err(db_err)?;
        let from = JobState::parse(r.get(0))?;
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
                        let _ = self.schedule_job(&id);
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
        let denied = std::cell::RefCell::new(None);
        let out = self.db.tx(|t| {
            let project = project_visible(t, &ctx.principal, &r.project)?;
            let orgs = project_role_orgs(&ctx.principal, &project, &[Role::MlDeveloper]);
            let Some(org) = orgs.first().cloned() else {
                return Err(forbidden("submitting a job needs ml_developer in a project member organization"));
            };
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
                    "SELECT spec_id, program_id, document FROM plans WHERE id = $1 AND project_id = $2",
                    &[&r.plan, &r.project],
                )
                .map_err(db_err)?
                .ok_or_else(|| not_found("plan", &r.plan))?;
            let doc: PlanDoc = serde_json::from_value(plan.get(2)).map_err(db_err)?;
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
            t.execute("SELECT 1 FROM assets WHERE id = ANY($1) FOR SHARE", &[&r.source_assets])
                .map_err(db_err)?;
            for a in &r.source_assets {
                let asset = asset_visible(t, &ctx.principal, a)?;
                if asset.status == "revoked" {
                    *denied.borrow_mut() = Some((a.clone(), org.clone(), "revoked"));
                    return Err(conflict(format!("asset {a} is revoked")));
                }
                if asset.organization != org {
                    let approved = t
                        .query_opt(
                            "SELECT 1 FROM asset_approvals WHERE asset_id = $1 AND project_id = $2 AND purpose = $3",
                            &[a, &r.project, &r.purpose],
                        )
                        .map_err(db_err)?;
                    if approved.is_none() {
                        *denied.borrow_mut() = Some((a.clone(), org.clone(), "not_approved"));
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
                     idempotency_key, request_digest)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'created', $14, $15, $16)",
                &[
                    &id,
                    &org,
                    &r.project,
                    &r.plan,
                    &plan.get::<_, String>(0),
                    &plan.get::<_, String>(1),
                    &r.policy,
                    &r.purpose,
                    &json!(r.source_assets),
                    &r.requested_output,
                    &doc.scheme,
                    &doc.backend,
                    &doc.profile,
                    &ctx.actor(),
                    &key,
                    &digest,
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
        if let (Err(_), Some((asset, org, why))) = (&out, denied.into_inner()) {
            self.metrics.inc("encompute_key_release_denied_total", why);
            self.audit_denied(
                ctx.draft("job.denied", "asset", &asset, Outcome::Denied)
                    .org(&org)
                    .project(&r.project)
                    .r#ref("reason", why),
            );
        }
        out
    }

    pub fn job_view(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let j = job_row(&mut *c, id, false)?.ok_or_else(|| not_found("job", id))?;
        job_visible(&mut *c, ctx, &j)?;
        let (url, receipt_key): (Option<String>, Option<String>) = match &j.evaluator {
            Some(e) => c
                .query_opt(
                    "SELECT url, receipt_key FROM evaluators WHERE id = $1",
                    &[e],
                )
                .map_err(db_err)?
                .map_or((None, None), |r| (Some(r.get(0)), Some(r.get(1)))),
            None => (None, None),
        };
        let transitions = c
            .query(
                "SELECT from_state, to_state, actor, COALESCE(reason, '') FROM job_transitions WHERE job_id = $1 ORDER BY seq",
                &[&id],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| {
                [("from", 0), ("to", 1), ("actor", 2), ("reason", 3)]
                    .into_iter()
                    .map(|(k, i)| (k.to_owned(), r.get::<_, String>(i)))
                    .collect()
            })
            .collect();
        // The grant goes only to the submitting organization.
        let grant = if ctx.principal.member_of(&j.organization) {
            j.grant.clone()
        } else {
            None
        };
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
            initiated_by: j.initiated_by,
            transitions,
        };
        Ok(serde_json::to_value(v).expect("serializable"))
    }

    pub fn list_jobs(&self, ctx: &Ctx, project: Option<&str>) -> Result<Value> {
        let orgs: Vec<String> = ctx.principal.organizations().into_iter().collect();
        let mut c = self.db.conn()?;
        let rows = c
            .query(
                "SELECT id, project_id, state, backend, created_at FROM jobs
                  WHERE organization_id = ANY($1) AND ($2::text IS NULL OR project_id = $2)
                  ORDER BY created_at DESC LIMIT 200",
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
        self.db.tx(|t| {
            let j = job_row(t, id, true)?.ok_or_else(|| not_found("job", id))?;
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
    }

    /// An owner approves a job that uses its asset (assets whose policy
    /// sets `require_job_approval`).
    pub fn approve_job(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let out = self.db.tx(|t| {
            let j = job_row(t, id, true)?.ok_or_else(|| not_found("job", id))?;
            job_visible(t, ctx, &j)?;
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
            let mine: Vec<&String> = required
                .iter()
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
            Ok(())
        });
        out?;
        let _ = self.schedule_job(id);
        self.job_view(ctx, id)
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

    /// Schedules one authorized job: only an evaluator that registered the
    /// job's backend and parameter profile, is ready, heard from recently,
    /// and has capacity. Returns whether it was placed.
    pub fn schedule_job(&self, id: &str) -> Result<bool> {
        self.db.tx(|t| {
            let Some(j) = job_row(t, id, true)? else { return Ok(false) };
            if j.state != JobState::Authorized {
                return Ok(false);
            }
            let candidates = t
                .query(
                    "SELECT e.id, e.capacity,
                            (SELECT count(*) FROM jobs x WHERE x.evaluator_id = e.id AND x.state IN ('queued', 'running', 'verifying'))
                       FROM evaluators e
                      WHERE e.status = 'ready'
                        AND e.backends ? $1 AND e.profiles ? $2
                        AND e.last_heartbeat > now() - make_interval(secs => $3)
                      ORDER BY 3, e.id",
                    &[&j.backend, &j.profile, &(HEARTBEAT_TIMEOUT_SECS as f64)],
                )
                .map_err(db_err)?;
            let Some(e) = candidates
                .iter()
                .find(|r| r.get::<_, i64>(2) < r.get::<_, i32>(1) as i64)
            else {
                return Ok(false);
            };
            let evaluator: String = e.get(0);
            let t0 = now();
            let mut g = JobGrant {
                version: JOB_GRANT_VERSION,
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
                expires_at: t0 + JOB_GRANT_TTL_SECS,
                issuer: self.service_id.clone(),
                issuer_public_key: self.signer.public_key_hex(),
                signature: String::new(),
            };
            g.signature = self.signer.sign(JOB_GRANT, &g.unsigned())?;
            t.execute(
                "UPDATE jobs SET evaluator_id = $2, job_grant = $3 WHERE id = $1",
                &[&id, &evaluator, &serde_json::to_value(&g).expect("serializable")],
            )
            .map_err(db_err)?;
            self.transition_in(t, &self.service_id, "scheduler", id, JobState::Queued, None)?;
            audit::append(
                t,
                audit::AuditDraft::new(&self.service_id, "scheduler", "job.scheduled", "job", id, Outcome::Succeeded)
                    .org(&j.organization)
                    .project(&j.project)
                    .r#ref("evaluator", evaluator.clone())
                    .r#ref("profile", j.profile.clone()),
            )?;
            Ok(true)
        })
    }

    /// The scheduled evaluator asks to start: allowed only if the job is
    /// still queued for it, its grant is valid, and no source asset was
    /// revoked. Never replays a started job.
    pub fn start_job(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        if ctx.principal.service_kind() != Some(ServiceKind::Evaluator) {
            return Err(forbidden("only the scheduled evaluator starts a job"));
        }
        let r = self.db.tx(|t| {
            let j = job_row(t, id, true)?.ok_or_else(|| not_found("job", id))?;
            if j.evaluator.as_deref() != Some(ctx.actor()) {
                return Err(not_found("job", id));
            }
            if j.state != JobState::Queued {
                return Err(conflict(format!(
                    "job {id} is {}: it does not start (again)",
                    j.state.as_str()
                )));
            }
            let g = j.grant.clone().ok_or_else(|| conflict("no grant"))?;
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
                return Ok(Err(conflict("a source asset was revoked")));
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
        let signed: SignedExecutionReceipt =
            serde_json::from_value(receipt.clone()).map_err(|e| bad(format!("receipt: {e}")))?;
        let out = self.db.tx(|t| {
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
        })?;
        if let Some(s) = eval_seconds {
            self.metrics
                .observe("encompute_evaluation_duration_seconds", "all", s);
        }
        Ok(out)
    }

    /// The client reports the receipt it received with its commitments to
    /// the exact bytes it sent and got; the control plane verifies every
    /// binding against the job's spec and the registered evaluator key.
    pub fn complete_job(&self, ctx: &Ctx, id: &str, r: CompleteJob) -> Result<Value> {
        let res = self.db.tx(|t| {
            let j = job_row(t, id, true)?.ok_or_else(|| not_found("job", id))?;
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
            );
            let evaluator_receipt_differs = j.receipt.as_ref().is_some_and(|x| x != &r.receipt);
            let evidence = json!({
                "request_commitment": r.request_commitment,
                "output_commitment": r.output_commitment,
                "key_id": r.key_id,
            });
            match (check, evaluator_receipt_differs) {
                (Ok(_), false) => {
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
                        Ok(_) => "the client's receipt differs from the one the evaluator reported"
                            .into(),
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
        check(
            "plan",
            verify_plan(&program, &doc.doc.plan)
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
                Ok(format!(
                    "signed by registered evaluator {e}; binds the request and response bytes"
                ))
            })(),
            _ => Err(conflict("no verified receipt yet")),
        };
        check("receipt", receipt_status);
        let revoked: Vec<String> = c
            .query(
                "SELECT id FROM assets WHERE id = ANY($1) AND status = 'revoked'",
                &[&j.sources],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        let assets_note = if revoked.is_empty() {
            "no source asset is revoked".to_owned()
        } else {
            format!("revoked since: {}", revoked.join(", "))
        };
        checks.push(json!({"check": "source assets", "status": if revoked.is_empty() { "VERIFIED" } else { "REVOKED" }, "detail": assets_note}));
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
        self.db.tx(|t| {
            t.execute(
                "INSERT INTO evaluators (id, service_account, url, receipt_key, backends, profiles, openfhe_version, capacity, status)
                 VALUES ($1, $1, $2, $3, $4, $5, $6, $7, 'ready')
                 ON CONFLICT (id) DO UPDATE SET url = $2, receipt_key = $3, backends = $4, profiles = $5,
                     openfhe_version = $6, capacity = $7, status = 'ready', last_heartbeat = now()",
                &[&r.id, &r.url, &r.receipt_key, &json!(r.backends), &json!(r.profiles), &r.openfhe_version, &r.capacity],
            )
            .map_err(|e| {
                if e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                    conflict("this receipt key belongs to another evaluator")
                } else {
                    db_err(e)
                }
            })?;
            audit::append(
                t,
                ctx.draft("evaluator.registered", "evaluator", &r.id, Outcome::Succeeded)
                    .org(PLATFORM_ORG)
                    .r#ref("backends", r.backends.join("+"))
                    .r#ref("profiles", r.profiles.join("+"))
                    .r#ref("openfhe", r.openfhe_version.clone()),
            )?;
            Ok(json!({"id": r.id, "status": "ready", "control_public_key": self.signer.public_key_hex()}))
        })
    }

    /// Heartbeat / status: the evaluator itself (ready, busy, draining,
    /// unhealthy) or a platform operator (draining, ready).
    pub fn evaluator_status(&self, ctx: &Ctx, id: &str, r: EvaluatorStatus) -> Result<Value> {
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
        self.db.tx(|t| {
            let current: String = t
                .query_opt("SELECT status FROM evaluators WHERE id = $1 FOR UPDATE", &[&id])
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
        })
    }

    pub fn list_evaluators(&self, ctx: &Ctx) -> Result<Value> {
        require(
            &ctx.principal,
            PLATFORM_ORG,
            &[Role::Operator, Role::OrganizationAdmin],
            "listing evaluators",
        )?;
        let mut c = self.db.conn()?;
        Ok(Value::Array(
            c.query("SELECT id, url, backends, profiles, openfhe_version, capacity, status FROM evaluators ORDER BY id", &[])
                .map_err(db_err)?
                .iter()
                .map(|r| {
                    json!({"id": r.get::<_, String>(0), "url": r.get::<_, String>(1), "backends": r.get::<_, Value>(2),
                           "profiles": r.get::<_, Value>(3), "openfhe_version": r.get::<_, String>(4),
                           "capacity": r.get::<_, i32>(5), "status": r.get::<_, String>(6)})
                })
                .collect(),
        ))
    }

    /// Marks silent evaluators unhealthy, and resolves jobs stranded by a
    /// restart or a lost evaluator: queued jobs whose grant expired are
    /// re-authorized (they never started); running jobs on an evaluator
    /// that is gone fail (never replayed).
    pub fn expire_evaluators(&self) -> Result<()> {
        self.db.tx(|t| {
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
        {
            let mut c = self.db.conn()?;
            if let Some(r) = c
                .query_opt(
                    "SELECT outcome FROM inbox WHERE consumer = $1 AND message_id = $2",
                    &[&self.service_id, &m.message_id],
                )
                .map_err(db_err)?
            {
                let mut v: Value = r.get(0);
                v["duplicate"] = json!(true);
                return Ok(v);
            }
        }
        let outcome = match m.kind.as_str() {
            "job.completed" => {
                let job = m
                    .job
                    .as_deref()
                    .ok_or_else(|| bad("job.completed names no job"))?;
                self.evaluator_completed(
                    &m.sender,
                    &ctx.request_id,
                    job,
                    &m.payload["receipt"],
                    m.payload["evaluation_ms"]
                        .as_u64()
                        .map(|ms| ms as f64 / 1000.0),
                )?
            }
            "evaluator.heartbeat" => self.evaluator_status(
                ctx,
                &m.sender,
                EvaluatorStatus {
                    status: m.payload["status"].as_str().unwrap_or("ready").into(),
                },
            )?,
            "privacy.event" => {
                let asset = m.payload["asset"]
                    .as_str()
                    .ok_or_else(|| bad("privacy.event names no asset"))?;
                let event = serde_json::from_value(m.payload["event"].clone())
                    .map_err(|e| bad(format!("event: {e}")))?;
                self.privacy_spend(ctx, asset, event)?
            }
            "key.release" => {
                if ctx.principal.service_kind() != Some(ServiceKind::Keybroker) {
                    return Err(forbidden("key releases are reported by key brokers"));
                }
                let asset = m.payload["asset"]
                    .as_str()
                    .ok_or_else(|| bad("key.release names no asset"))?;
                let allowed = m.payload["allowed"].as_bool().unwrap_or(false);
                let mapped = self
                    .db
                    .conn()?
                    .query_opt(
                        "SELECT id, organization_id FROM assets WHERE key_ref->>'broker' = $1 AND key_ref->>'key_ref' = $2",
                        &[&m.sender, &asset],
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
                self.db.tx(|t| audit::append(t, d.clone()).map(|_| ()))?;
                if !allowed {
                    self.metrics
                        .inc("encompute_key_release_denied_total", "broker");
                }
                json!({"recorded": true})
            }
            "secagg.round.completed" => {
                if let Some(ms) = m.payload["duration_ms"].as_u64() {
                    self.metrics.observe(
                        "encompute_secagg_round_duration_seconds",
                        "all",
                        ms as f64 / 1000.0,
                    );
                }
                json!({"recorded": true})
            }
            other => return Err(bad(format!("unknown message kind {other:?}"))),
        };
        self.db
            .conn()?
            .execute(
                "INSERT INTO inbox (consumer, message_id, outcome) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                &[&self.service_id, &m.message_id, &outcome],
            )
            .map_err(db_err)?;
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
