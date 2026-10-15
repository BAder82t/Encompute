//! Authorization is re-read INSIDE the transaction that takes effect, after
//! the row locks it needs (`ops::revalidate`), for six classes of protected
//! operation: (1) a job submitted against an asset, (2) a user or service
//! account that then changes state, (3) an asset approval a job is bound to,
//! (4) an action that needs an organization role, (5) an action that needs a
//! project membership, (6) the job cancel and the evaluator's start.
//!
//! Every test runs on real PostgreSQL. The "refused at the transaction
//! boundary" tests call the operation on `Control` directly with a principal
//! that was authenticated BEFORE the authority was revoked through the API:
//! that skips `Control::enforce` and authentication (the request-level
//! decision, which here is stale) so that only the transaction's own
//! re-read can refuse. They set the revoked state through the normal API
//! first; nothing here changes state back. The lock-timeout tests hold a
//! conflicting row lock legitimately (an open transaction updating the row)
//! longer than the revalidation's timeout.

mod common;

use std::time::{Duration, Instant};

use common::*;
use encompute_control::authn::{Credentials, Principal, PrincipalKind};
use encompute_control::model::{ServiceKind, SubmitJob};
use encompute_control::Ctx;
use encompute_ir::Code;
use serde_json::{json, Value};

fn http(w: &World) -> Client {
    let addr = live(
        &w.t.control,
        encompute_verification::http::Limits::default(),
    );
    Client::new(addr)
}

fn one(url: &str, q: &str) -> i64 {
    postgres::Client::connect(url, postgres::NoTls)
        .unwrap()
        .query_one(q, &[])
        .unwrap()
        .get::<_, i64>(0)
}

fn text(url: &str, q: &str) -> String {
    postgres::Client::connect(url, postgres::NoTls)
        .unwrap()
        .query_one(q, &[])
        .unwrap()
        .get::<_, String>(0)
}

/// A user authenticated now, as the request path does before the handler.
fn principal(w: &World, who: &As) -> Principal {
    let As::User(sub) = who else { panic!("a user") };
    let bearer = format!("Bearer {}", token(sub));
    let mut c = w.t.control.db.conn().unwrap();
    w.t.control
        .auth
        .authenticate(
            &mut *c,
            &Credentials {
                authorization: Some(&bearer),
                service: None,
                method: "GET",
                path: "/v1/whoami",
                body: &[],
            },
        )
        .unwrap()
}

/// The evaluator's principal as its signed request authenticates it.
fn evaluator_principal(w: &World) -> Principal {
    Principal {
        id: w.evaluator.id.clone(),
        kind: PrincipalKind::Service {
            service_kind: ServiceKind::Evaluator,
        },
        organization: None,
        roles: Default::default(),
    }
}

fn ctx(p: Principal) -> Ctx {
    Ctx {
        principal: p,
        request_id: "req-txn-test".into(),
    }
}

fn submit_req(w: &World, plan: &str, sources: &[&str]) -> SubmitJob {
    SubmitJob {
        project: w.project.clone(),
        plan: plan.into(),
        purpose: "medical-training".into(),
        source_assets: sources.iter().map(|s| s.to_string()).collect(),
        requested_output: "out".into(),
        policy: None,
    }
}

fn submit_direct(
    w: &World,
    c: &Ctx,
    plan: &str,
    sources: &[&str],
    key: &str,
) -> encompute_ir::Result<(Value, bool)> {
    w.t.control.submit_job(
        c,
        submit_req(w, plan, sources),
        key,
        &format!("digest-{key}"),
    )
}

fn id_of(w: &World, who: &As) -> String {
    w.t.ok(who, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn remove_role(w: &World, admin: &As, org: &str, who: &As, role: &str) {
    let id = id_of(w, who);
    w.t.ok(
        admin,
        "POST",
        &format!("/v1/organizations/{org}/memberships/remove"),
        Some(json!({"principal": id, "role": role})),
    );
}

/// The plan `a_dev` and `b_dev` can both use over the model.
fn model_plan(w: &World) -> String {
    w.plan(&exact_own(&w.model_b))
}

/// An approved dataset plan: the owner approves, modelco plans over it.
fn approved_dataset_plan(w: &World) -> String {
    let (d, p) = (&w.dataset_a, &w.project);
    w.t.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{d}/approvals"),
        Some(json!({"project": p, "purpose": "medical-training"})),
    );
    w.t.ok(
        &w.b_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": p, "program": exact_over(d, "hospital-a", "dataset", "medical-training")})),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

// ---------------------------------------------------------------------------
// (1) job submission against an asset

#[test]
fn class1_revoked_asset_is_refused_in_the_transaction_and_leaves_nothing() {
    let Some(w) = world() else { return };
    let url = w.t.env0.url.clone();
    let m = w.model_b.clone();
    let plan = model_plan(&w);
    let c = ctx(principal(&w, &w.b_dev));
    // Valid authority succeeds.
    let (v, fresh) = submit_direct(&w, &c, &plan, &[&m], "ok-1").expect("valid authority");
    assert!(fresh && v["id"].is_string(), "{v}");
    let jobs = one(&url, "SELECT count(*) FROM jobs");
    let created = one(
        &url,
        "SELECT count(*) FROM audit_events WHERE action = 'job.created'",
    );
    // Revoked through the API; then the operation, bypassing the request check.
    w.t.ok(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None);
    let e = submit_direct(&w, &c, &plan, &[&m], "after-revoke").unwrap_err();
    assert_eq!(e.code, Code::Conflict, "{e:?}");
    assert!(e.message.contains("revoked"), "{e:?}");
    assert_eq!(one(&url, "SELECT count(*) FROM jobs"), jobs, "no job");
    assert_eq!(
        one(
            &url,
            "SELECT count(*) FROM audit_events WHERE action = 'job.created'"
        ),
        created,
        "no job.created event"
    );
    assert_eq!(
        one(
            &url,
            "SELECT count(*) FROM jobs WHERE idempotency_key = 'after-revoke'"
        ),
        0
    );
}

#[test]
fn class1_submitter_role_removed_is_refused_in_the_transaction() {
    let Some(w) = world() else { return };
    let url = w.t.env0.url.clone();
    let m = w.model_b.clone();
    let plan = model_plan(&w);
    let stale = ctx(principal(&w, &w.b_dev));
    let created = one(
        &url,
        "SELECT count(*) FROM audit_events WHERE action = 'job.created'",
    );
    remove_role(&w, &w.b_admin, "modelco", &w.b_dev, "ml_developer");
    let e = submit_direct(&w, &stale, &plan, &[&m], "stale-role").unwrap_err();
    assert_eq!(e.code, Code::Forbidden, "{e:?}");
    assert!(e.message.contains("no longer held"), "{e:?}");
    assert_eq!(one(&url, "SELECT count(*) FROM jobs"), 0);
    assert_eq!(
        one(
            &url,
            "SELECT count(*) FROM audit_events WHERE action = 'job.created'"
        ),
        created
    );
    // The request path refuses the same call too (the earlier decision).
    let cl = http(&w);
    let (s, v) = cl.call_with(
        &w.b_dev,
        "POST",
        "/v1/jobs",
        Some(
            json!({"project": w.project, "plan": plan, "purpose": "medical-training",
                    "source_assets": [m], "requested_output": "out"}),
        ),
        &[("Idempotency-Key", "http-after-removal")],
    );
    assert_eq!(s, 403, "{v}");
}

#[test]
fn class1_project_membership_ended_is_refused_in_the_transaction() {
    let Some(w) = world() else { return };
    let url = w.t.env0.url.clone();
    let (d, p) = (w.dataset_a.clone(), w.project.clone());
    // hospital-a's developer plans and submits over its own dataset.
    let plan = w.t.ok(
        &w.a_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": p, "program": exact_own(&d)})),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let stale = ctx(principal(&w, &w.a_dev));
    let (_, fresh) =
        submit_direct(&w, &stale, &plan, &[&d], "member-ok").expect("a member submits");
    assert!(fresh);
    w.t.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/projects/{p}/members/remove"),
        Some(json!({"organization": "hospital-a"})),
    );
    let jobs = one(&url, "SELECT count(*) FROM jobs");
    let e = submit_direct(&w, &stale, &plan, &[&d], "member-gone").unwrap_err();
    assert_eq!(e.code, Code::NotFound, "{e:?}");
    assert!(e.message.contains("project"), "{e:?}");
    assert_eq!(one(&url, "SELECT count(*) FROM jobs"), jobs);
}

// ---------------------------------------------------------------------------
// (2) authentication of a user or service account that changes state

#[test]
fn class2_disabled_user_cannot_change_state_through_a_stale_principal() {
    let Some(w) = world() else { return };
    let url = w.t.env0.url.clone();
    let stale = ctx(principal(&w, &w.b_dev));
    let program = exact_own(&w.model_b);
    let plans = one(&url, "SELECT count(*) FROM plans");
    // Valid: a plan.
    w.t.control
        .create_plan(
            &stale,
            encompute_control::model::CreatePlan {
                project: w.project.clone(),
                program: program.clone(),
            },
        )
        .expect("valid authority");
    let plans_ok = one(&url, "SELECT count(*) FROM plans");
    assert!(plans_ok > plans);
    let id = id_of(&w, &w.b_dev);
    w.t.ok(
        &w.b_admin,
        "POST",
        &format!("/v1/organizations/modelco/users/{id}/disable"),
        None,
    );
    let e =
        w.t.control
            .create_plan(
                &stale,
                encompute_control::model::CreatePlan {
                    project: w.project.clone(),
                    program,
                },
            )
            .unwrap_err();
    assert_eq!(e.code, Code::Unauthenticated, "{e:?}");
    assert!(e.message.contains("disabled"), "{e:?}");
    assert_eq!(one(&url, "SELECT count(*) FROM plans"), plans_ok, "no plan");
    // A disabled user is refused for every other state change the same way.
    let e = w.t.control.cancel_job(&stale, "job-none").unwrap_err();
    assert_eq!(e.code, Code::Unauthenticated, "{e:?}");
}

#[test]
fn class2_disabled_service_account_cannot_start_a_job_through_a_stale_principal() {
    let Some(w) = world() else { return };
    let url = w.t.env0.url.clone();
    let m = w.model_b.clone();
    let plan = model_plan(&w);
    let (s, j) = w.job(&plan, &[&m], "for-start");
    assert_eq!(s, 201, "{j}");
    let job = j["id"].as_str().unwrap().to_owned();
    assert_eq!(
        text(&url, &format!("SELECT state FROM jobs WHERE id = '{job}'")),
        "queued"
    );
    let stale = ctx(evaluator_principal(&w));
    w.t.ok(
        &w.platform,
        "POST",
        &format!(
            "/v1/organizations/platform/service-accounts/{}/disable",
            w.evaluator.id
        ),
        None,
    );
    let started = one(
        &url,
        "SELECT count(*) FROM audit_events WHERE action = 'job.started'",
    );
    let e = w.t.control.start_job(&stale, &job).unwrap_err();
    assert_eq!(e.code, Code::ServiceAuthentication, "{e:?}");
    assert_eq!(
        text(&url, &format!("SELECT state FROM jobs WHERE id = '{job}'")),
        "queued"
    );
    assert_eq!(
        one(
            &url,
            "SELECT count(*) FROM audit_events WHERE action = 'job.started'"
        ),
        started
    );
}

// ---------------------------------------------------------------------------
// (3) an approval a job is bound to

#[test]
fn class3_withdrawn_approval_is_refused_in_the_transaction() {
    let Some(w) = world() else { return };
    let url = w.t.env0.url.clone();
    let (d, p) = (w.dataset_a.clone(), w.project.clone());
    let plan = approved_dataset_plan(&w);
    let c = ctx(principal(&w, &w.b_dev));
    let (_, fresh) = submit_direct(&w, &c, &plan, &[&d], "approved").expect("approved");
    assert!(fresh);
    w.t.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{d}/approvals/withdraw"),
        Some(json!({"project": p, "purpose": "medical-training"})),
    );
    let jobs = one(&url, "SELECT count(*) FROM jobs");
    let created = one(
        &url,
        "SELECT count(*) FROM audit_events WHERE action = 'job.created'",
    );
    let e = submit_direct(&w, &c, &plan, &[&d], "withdrawn").unwrap_err();
    // The withdrawn approval no longer makes the asset visible to modelco.
    assert_eq!(e.code, Code::NotFound, "{e:?}");
    assert_eq!(one(&url, "SELECT count(*) FROM jobs"), jobs);
    assert_eq!(
        one(
            &url,
            "SELECT count(*) FROM audit_events WHERE action = 'job.created'"
        ),
        created
    );
}

// ---------------------------------------------------------------------------
// (4) an organization role

#[test]
fn class4_role_removed_is_refused_for_cancel_and_leaves_the_job() {
    let Some(w) = world() else { return };
    let url = w.t.env0.url.clone();
    let m = w.model_b.clone();
    let plan = model_plan(&w);
    let (s, j) = w.job(&plan, &[&m], "to-cancel");
    assert_eq!(s, 201, "{j}");
    let job = j["id"].as_str().unwrap().to_owned();
    let stale = ctx(principal(&w, &w.b_dev));
    remove_role(&w, &w.b_admin, "modelco", &w.b_dev, "ml_developer");
    let e = w.t.control.cancel_job(&stale, &job).unwrap_err();
    assert_eq!(e.code, Code::Forbidden, "{e:?}");
    assert_eq!(
        text(&url, &format!("SELECT state FROM jobs WHERE id = '{job}'")),
        "queued"
    );
    assert_eq!(
        one(
            &url,
            "SELECT count(*) FROM audit_events WHERE action = 'job.cancelled'"
        ),
        0
    );
    assert!(!w.t.control.anchor.snapshot().ended_jobs.contains(&job));
}

#[test]
fn class4_role_removed_is_refused_for_an_owner_action() {
    let Some(w) = world() else { return };
    let url = w.t.env0.url.clone();
    let m = w.model_b.clone();
    let stale = ctx(principal(&w, &w.b_owner));
    remove_role(&w, &w.b_admin, "modelco", &w.b_owner, "model_owner");
    let e = w.t.control.revoke_asset(&stale, &m).unwrap_err();
    // The stale principal still carries the role; the revalidation refuses.
    assert_eq!(e.code, Code::Forbidden, "{e:?}");
    assert_eq!(
        text(&url, &format!("SELECT status FROM assets WHERE id = '{m}'")),
        "active"
    );
    assert!(!w.t.control.anchor.snapshot().revoked.contains(&m));
    assert_eq!(
        one(
            &url,
            "SELECT count(*) FROM audit_events WHERE action = 'asset.revoked'"
        ),
        0
    );
}

// ---------------------------------------------------------------------------
// (5) a project membership

#[test]
fn class5_left_project_cannot_plan_through_a_stale_principal() {
    let Some(w) = world() else { return };
    let url = w.t.env0.url.clone();
    let p = w.project.clone();
    let stale = ctx(principal(&w, &w.a_dev));
    let program = exact_own(&w.dataset_a);
    let req = |program: &str| encompute_control::model::CreatePlan {
        project: p.clone(),
        program: program.to_owned(),
    };
    w.t.control
        .create_plan(&stale, req(&program))
        .expect("a member plans");
    let plans = one(&url, "SELECT count(*) FROM plans");
    w.t.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/projects/{p}/members/remove"),
        Some(json!({"organization": "hospital-a"})),
    );
    let e = w.t.control.create_plan(&stale, req(&program)).unwrap_err();
    assert_eq!(e.code, Code::NotFound, "{e:?}");
    assert_eq!(one(&url, "SELECT count(*) FROM plans"), plans);
    // Approving an asset for the project needs the membership too.
    let e =
        w.t.control
            .approve_asset(
                &ctx(principal(&w, &w.a_owner)),
                &w.dataset_a,
                encompute_control::model::ApproveAsset {
                    project: p.clone(),
                    purpose: "medical-training".into(),
                },
            )
            .unwrap_err();
    assert!(matches!(e.code, Code::NotFound | Code::Forbidden), "{e:?}");
    assert_eq!(one(&url, "SELECT count(*) FROM asset_approvals"), 0);
}

// ---------------------------------------------------------------------------
// (6) job cancel and the evaluator's start

#[test]
fn class6_cancelled_and_failed_jobs_do_not_start_and_a_valid_start_runs() {
    let Some(w) = world() else { return };
    let url = w.t.env0.url.clone();
    let m = w.model_b.clone();
    let plan = model_plan(&w);
    let ev = ctx(evaluator_principal(&w));
    let state = |job: &str| text(&url, &format!("SELECT state FROM jobs WHERE id = '{job}'"));
    // Valid authority starts.
    let (_, j) = w.job(&plan, &[&m], "valid");
    let ok = j["id"].as_str().unwrap().to_owned();
    w.t.control
        .start_job(&ev, &ok)
        .expect("the scheduled evaluator starts it");
    assert_eq!(state(&ok), "running");
    // Cancelled.
    let (_, j) = w.job(&plan, &[&m], "cancelled");
    let cancelled = j["id"].as_str().unwrap().to_owned();
    w.t.ok(
        &w.b_dev,
        "POST",
        &format!("/v1/jobs/{cancelled}/cancel"),
        None,
    );
    let e = w.t.control.start_job(&ev, &cancelled).unwrap_err();
    assert_eq!(e.code, Code::Conflict, "{e:?}");
    assert_eq!(state(&cancelled), "cancelled");
    // A second cancel is refused as well (the state moves only once).
    let e =
        w.t.control
            .cancel_job(&ctx(principal(&w, &w.b_dev)), &cancelled)
            .unwrap_err();
    assert_eq!(e.code, Code::Conflict, "{e:?}");
    // Failed by a revocation: the asset is revoked, the job failed.
    let (_, j) = w.job(&plan, &[&m], "failed");
    let failed = j["id"].as_str().unwrap().to_owned();
    w.t.ok(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None);
    assert_eq!(state(&failed), "failed");
    let e = w.t.control.start_job(&ev, &failed).unwrap_err();
    assert_eq!(e.code, Code::Conflict, "{e:?}");
    assert_eq!(state(&failed), "failed");
    assert_eq!(
        one(
            &url,
            "SELECT count(*) FROM audit_events WHERE action = 'job.started'"
        ),
        1,
        "only the valid start is recorded"
    );
}

// ---------------------------------------------------------------------------
// a conflicting lock held longer than the timeout fails the request closed

/// Holds `lock_sql` (a row lock) in an open transaction on its own
/// connection, runs `request` meanwhile, and returns what it answered and
/// how long it took.
fn with_lock_held<T>(url: &str, lock_sql: &str, request: impl FnOnce() -> T) -> (T, Duration) {
    let mut holder = postgres::Client::connect(url, postgres::NoTls).unwrap();
    holder.batch_execute("BEGIN").unwrap();
    holder.batch_execute(lock_sql).unwrap();
    let t0 = Instant::now();
    let out = request();
    let took = t0.elapsed();
    holder.batch_execute("COMMIT").unwrap();
    (out, took)
}

fn assert_timed_out(s: u16, v: &Value, took: Duration) {
    assert_eq!(s, 500, "{v}");
    assert!(
        v["message"]
            .as_str()
            .is_some_and(|m| m.contains("lock timeout") && m.contains("55P03")),
        "{v}"
    );
    assert!(
        took >= Duration::from_secs(4) && took < Duration::from_secs(20),
        "the wait is bounded by the 5 s timeout: {took:?}"
    );
}

fn submit_http(w: &World, cl: &Client, plan: &str, src: &str, key: &str) -> (u16, Value) {
    cl.call_with(
        &w.b_dev,
        "POST",
        "/v1/jobs",
        Some(
            json!({"project": w.project, "plan": plan, "purpose": "medical-training",
                    "source_assets": [src], "requested_output": "out"}),
        ),
        &[("Idempotency-Key", key)],
    )
}

#[test]
fn lock_timeout_on_the_account_row_fails_closed() {
    let Some(w) = world() else { return };
    let (cl, url, m) = (http(&w), w.t.env0.url.clone(), w.model_b.clone());
    let plan = model_plan(&w);
    let id = id_of(&w, &w.b_dev);
    let ((s, v), took) = with_lock_held(
        &url,
        &format!("SELECT 1 FROM users WHERE id = '{id}' FOR UPDATE"),
        || submit_http(&w, &cl, &plan, &m, "locked-user"),
    );
    assert_timed_out(s, &v, took);
    assert_eq!(one(&url, "SELECT count(*) FROM jobs"), 0, "no state change");
    // Released: the same valid request succeeds.
    let (s, v) = submit_http(&w, &cl, &plan, &m, "locked-user");
    assert_eq!(s, 201, "{v}");
}

#[test]
fn lock_timeout_on_the_asset_row_fails_closed() {
    let Some(w) = world() else { return };
    let (cl, url, m) = (http(&w), w.t.env0.url.clone(), w.model_b.clone());
    let plan = model_plan(&w);
    let ((s, v), took) = with_lock_held(
        &url,
        &format!("SELECT 1 FROM assets WHERE id = '{m}' FOR UPDATE"),
        || submit_http(&w, &cl, &plan, &m, "locked-asset"),
    );
    assert_timed_out(s, &v, took);
    assert_eq!(one(&url, "SELECT count(*) FROM jobs"), 0);
    assert_eq!(
        one(
            &url,
            "SELECT count(*) FROM audit_events WHERE action = 'job.created'"
        ),
        0
    );
    let (s, v) = submit_http(&w, &cl, &plan, &m, "locked-asset");
    assert_eq!(s, 201, "{v}");
}

#[test]
fn lock_timeout_on_the_approval_row_fails_closed() {
    let Some(w) = world() else { return };
    let (cl, url, d) = (http(&w), w.t.env0.url.clone(), w.dataset_a.clone());
    let plan = approved_dataset_plan(&w);
    let ((s, v), took) = with_lock_held(
        &url,
        &format!("SELECT 1 FROM asset_approval_members WHERE asset_id = '{d}' FOR UPDATE"),
        || submit_http(&w, &cl, &plan, &d, "locked-approval"),
    );
    assert_timed_out(s, &v, took);
    assert_eq!(one(&url, "SELECT count(*) FROM jobs"), 0);
    let (s, v) = submit_http(&w, &cl, &plan, &d, "locked-approval");
    assert_eq!(s, 201, "{v}");
}

#[test]
fn lock_timeout_on_the_job_row_fails_closed_for_cancel_and_start() {
    let Some(w) = world() else { return };
    let (cl, url, m) = (http(&w), w.t.env0.url.clone(), w.model_b.clone());
    let plan = model_plan(&w);
    let (s, j) = w.job(&plan, &[&m], "held-job");
    assert_eq!(s, 201, "{j}");
    let job = j["id"].as_str().unwrap().to_owned();
    let ((s, v), took) = with_lock_held(
        &url,
        &format!("SELECT 1 FROM jobs WHERE id = '{job}' FOR UPDATE"),
        || cl.call(&w.b_dev, "POST", &format!("/v1/jobs/{job}/cancel"), None),
    );
    assert_timed_out(s, &v, took);
    assert_eq!(
        text(&url, &format!("SELECT state FROM jobs WHERE id = '{job}'")),
        "queued"
    );
    let ((s, v), took) = with_lock_held(
        &url,
        &format!("SELECT 1 FROM jobs WHERE id = '{job}' FOR UPDATE"),
        || {
            cl.call(
                &w.evaluator.service,
                "POST",
                &format!("/v1/jobs/{job}/start"),
                None,
            )
        },
    );
    assert_timed_out(s, &v, took);
    assert_eq!(
        text(&url, &format!("SELECT state FROM jobs WHERE id = '{job}'")),
        "queued"
    );
    assert_eq!(
        one(
            &url,
            "SELECT count(*) FROM audit_events WHERE action = 'job.started'"
        ),
        0
    );
    let (s, v) = cl.call(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    assert_eq!(s, 200, "{v}");
}

// ---------------------------------------------------------------------------
// ordinary concurrency, correct lock order

/// Runs `a` and `b` at the same moment on two threads; both must return
/// well within the lock timeout.
fn race<A: Send, B: Send>(a: impl FnOnce() -> A + Send, b: impl FnOnce() -> B + Send) -> (A, B) {
    let barrier = std::sync::Barrier::new(2);
    let t0 = Instant::now();
    let out = std::thread::scope(|s| {
        let ha = s.spawn(|| {
            barrier.wait();
            a()
        });
        let hb = s.spawn(|| {
            barrier.wait();
            b()
        });
        (ha.join().unwrap(), hb.join().unwrap())
    });
    assert!(
        t0.elapsed() < Duration::from_secs(4),
        "no wait on a lock: {:?}",
        t0.elapsed()
    );
    out
}

#[test]
fn concurrent_revoke_and_submit_both_complete_with_a_consistent_outcome() {
    let (mut submitted, mut refused) = (0, 0);
    for round in 0..8u64 {
        let Some(w) = world() else { return };
        let (cl, url, m) = (http(&w), w.t.env0.url.clone(), w.model_b.clone());
        let plan = model_plan(&w);
        let ((rs, rv), (ss, sv)) = race(
            || {
                // Staggered starts: the two orders both occur.
                std::thread::sleep(Duration::from_millis(round * 6));
                cl.call(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None)
            },
            || submit_http(&w, &cl, &plan, &m, &format!("race-{round}")),
        );
        assert_eq!(rs, 200, "{rv}");
        assert!(ss == 201 || ss == 409, "{ss} {sv}");
        assert_eq!(
            text(&url, &format!("SELECT status FROM assets WHERE id = '{m}'")),
            "revoked"
        );
        let live_jobs = one(
            &url,
            "SELECT count(*) FROM jobs WHERE state NOT IN ('failed', 'cancelled')",
        );
        assert_eq!(
            live_jobs, 0,
            "no job over the revoked asset stays alive (submit {ss})"
        );
        if ss == 201 {
            submitted += 1;
            assert_eq!(
                rv["failed_jobs"].as_array().map(|a| a.len()),
                Some(1),
                "{rv}"
            );
        } else {
            refused += 1;
            assert_eq!(one(&url, "SELECT count(*) FROM jobs"), 0);
        }
    }
    eprintln!("RACE revoke/submit: submit committed first {submitted}, revoke first {refused}");
}

#[test]
fn concurrent_role_removal_and_submit_both_complete_with_a_consistent_outcome() {
    for round in 0..6u64 {
        let Some(w) = world() else { return };
        let (cl, url, m) = (http(&w), w.t.env0.url.clone(), w.model_b.clone());
        let plan = model_plan(&w);
        let id = id_of(&w, &w.b_dev);
        let ((rs, rv), (ss, sv)) = race(
            || {
                std::thread::sleep(Duration::from_millis(round * 6));
                cl.call(
                    &w.b_admin,
                    "POST",
                    "/v1/organizations/modelco/memberships/remove",
                    Some(json!({"principal": id, "role": "ml_developer"})),
                )
            },
            || submit_http(&w, &cl, &plan, &m, &format!("role-race-{round}")),
        );
        assert_eq!(rs, 200, "{rv}");
        assert!(ss == 201 || ss == 403, "{ss} {sv}");
        let jobs = one(&url, "SELECT count(*) FROM jobs");
        assert_eq!(jobs, if ss == 201 { 1 } else { 0 }, "{ss} {sv}");
        eprintln!("RACE role/submit round {round}: submit {ss}");
        assert_eq!(
            one(
                &url,
                &format!("SELECT count(*) FROM memberships WHERE principal_id = '{id}'")
            ),
            0
        );
    }
}

#[test]
fn concurrent_user_disable_and_cancel_both_complete_with_a_consistent_outcome() {
    for round in 0..6 {
        let Some(w) = world() else { return };
        let (cl, url, m) = (http(&w), w.t.env0.url.clone(), w.model_b.clone());
        let plan = model_plan(&w);
        let (s, j) = w.job(&plan, &[&m], &format!("c-{round}"));
        assert_eq!(s, 201, "{j}");
        let job = j["id"].as_str().unwrap().to_owned();
        let id = id_of(&w, &w.b_dev);
        let ((ds, dv), (cs, cv)) = race(
            || {
                cl.call(
                    &w.b_admin,
                    "POST",
                    &format!("/v1/organizations/modelco/users/{id}/disable"),
                    None,
                )
            },
            || cl.call(&w.b_dev, "POST", &format!("/v1/jobs/{job}/cancel"), None),
        );
        assert_eq!(ds, 200, "{dv}");
        assert!(cs == 200 || cs == 401, "{cs} {cv}");
        let st = text(&url, &format!("SELECT state FROM jobs WHERE id = '{job}'"));
        assert_eq!(st, if cs == 200 { "cancelled" } else { "queued" });
    }
}
