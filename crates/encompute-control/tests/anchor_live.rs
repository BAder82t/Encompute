//! Continuous enforcement (0.3.1, ENC-SF-2026-413): a transition the anchor
//! already holds (a revocation, a disable, a cancellation, a withdrawn
//! approval, a removed role or membership) that a database writer undoes
//! WHILE THE SERVICE RUNS does not permit the operation it denied. The
//! service finds the database no longer extends the anchor on the next
//! request (and on the background tick), raises the rollback alarm and
//! latches: every request is refused (ENC2202) and `/ready` answers 503,
//! until the operator restores the state or runs `recover` and restarts.
//!
//! Each test: the transition is acknowledged through the API (the anchor
//! holds it), the attacker (arbitrary SQL, triggers off, no signing key, no
//! anchor access) undoes it in the database, and the protected operation is
//! attempted over real HTTP as the principal it was denied to. The result is
//! printed (`LIVE <transition>: ...`) for the report.

mod common;

use common::*;
use serde_json::{json, Value};

fn sql(url: &str, q: &str) {
    postgres::Client::connect(url, postgres::NoTls)
        .unwrap()
        .batch_execute(&format!("SET session_replication_role = replica; {q}"))
        .unwrap();
}
fn scalar(url: &str, q: &str) -> String {
    postgres::Client::connect(url, postgres::NoTls)
        .unwrap()
        .query_one(q, &[])
        .unwrap()
        .get::<_, String>(0)
}

fn http(w: &World) -> Client {
    let addr = live(
        &w.t.control,
        encompute_verification::http::Limits::default(),
    );
    Client::new(addr)
}

fn state_refused(s: u16, v: &Value) -> bool {
    s == 500
        && v["code"] == "ENC2202"
        && v["message"]
            .as_str()
            .is_some_and(|m| m.contains("STATE ROLLBACK"))
}

fn succeeded(s: u16) -> bool {
    (200..300).contains(&s)
}

/// What the report records for a transition: the protected operation's result
/// right after the revert.
fn report(name: &str, first: (u16, &Value)) {
    eprintln!(
        "LIVE {name}: right after the revert -> {} {}",
        first.0,
        if succeeded(first.0) {
            "SUCCEEDED"
        } else {
            "REFUSED"
        },
    );
}

/// The protected operation is refused with the state-rollback error, the
/// service is latched (a second, unrelated request is refused too), and
/// `/ready` is 503.
fn assert_latched(w: &World, cl: &Client, name: &str, first: (u16, Value)) {
    assert!(
        state_refused(first.0, &first.1),
        "{name}: the protected operation after the revert: {} {}",
        first.0,
        first.1
    );
    let (s, v) = cl.call(&w.a_owner, "GET", "/v1/whoami", None);
    assert!(state_refused(s, &v), "{name}: latched: {s} {v}");
    let (s, _) = cl.raw("GET", "/ready", &[], &[]);
    assert_eq!(s, 503, "{name}: /ready");
    let (s, _) = cl.raw("GET", "/live", &[], &[]);
    assert_eq!(s, 200, "{name}: /live stays up");
    assert!(w
        .t
        .control
        .metrics
        .render()
        .contains("encompute_state_rollback_total{label="));
}

fn submit(cl: &Client, w: &World, plan: &str, sources: &[&str], key: &str) -> (u16, Value) {
    cl.call_with(
        &w.b_dev,
        "POST",
        "/v1/jobs",
        Some(
            json!({"project": w.project, "plan": plan, "purpose": "medical-training",
                    "source_assets": sources, "requested_output": "out"}),
        ),
        &[("Idempotency-Key", key)],
    )
}

/// (1) a revoked asset is used in a new job.
#[test]
fn live_1_revoked_asset_restored_does_not_run_a_job() {
    let Some(w) = world() else { return };
    let cl = http(&w);
    let m = w.model_b.clone();
    let url = w.t.env0.url.clone();
    let plan = w.plan(&exact_own(&m));
    cl.ok(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None);
    assert!(w.t.control.anchor.snapshot().revoked.contains(&m));
    let (s, v) = submit(&cl, &w, &plan, &[&m], "honest");
    assert!(!succeeded(s), "a revoked asset runs a job: {s} {v}");
    sql(
        &url,
        &format!("UPDATE assets SET status='active', revoked_at=NULL WHERE id='{m}'"),
    );
    let first = submit(&cl, &w, &plan, &[&m], "attack");
    report("revoke asset", (first.0, &first.1));
    assert_latched(&w, &cl, "revoke asset", first);
}

/// (2) a revocation failed a queued job; the asset and the job are restored,
/// and the evaluator starts the job.
#[test]
fn live_2_revoked_asset_and_failed_job_restored_does_not_start() {
    let Some(w) = world() else { return };
    let cl = http(&w);
    let m = w.model_b.clone();
    let url = w.t.env0.url.clone();
    let plan = w.plan(&exact_own(&m));
    let (st, j) = submit(&cl, &w, &plan, &[&m], "to-fail");
    assert_eq!(st, 201, "{j}");
    let job = j["id"].as_str().unwrap().to_owned();
    let v = cl.ok(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None);
    assert_eq!(v["failed_jobs"], json!([job]), "{v}");
    let (s, _) = cl.call(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    assert!(!succeeded(s));
    sql(
        &url,
        &format!(
            "UPDATE assets SET status='active', revoked_at=NULL WHERE id='{m}';
             UPDATE jobs SET state='queued', error=NULL WHERE id='{job}'"
        ),
    );
    let first = cl.call(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    report("revoke asset with a failed job", (first.0, &first.1));
    assert_latched(&w, &cl, "revoke asset with a failed job", first);
}

/// (3) an approval withdrawn, then restored: a job over the dataset runs.
#[test]
fn live_3_withdrawn_approval_restored_does_not_cover_a_job() {
    let Some(w) = world() else { return };
    let cl = http(&w);
    let (d, p) = (w.dataset_a.clone(), w.project.clone());
    let url = w.t.env0.url.clone();
    cl.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{d}/approvals"),
        Some(json!({"project": p, "purpose": "medical-training"})),
    );
    let plan = cl.ok(
        &w.b_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": p, "program": exact_over(&d, "hospital-a", "dataset", "medical-training")})),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (s, v) = submit(&cl, &w, &plan, &[&d], "with-approval");
    assert_eq!(s, 201, "baseline: the approval covers the job: {v}");
    sql(
        &url,
        &format!(
            "CREATE TABLE atk_ap AS SELECT * FROM asset_approvals WHERE asset_id='{d}';
             CREATE TABLE atk_apm AS SELECT * FROM asset_approval_members WHERE asset_id='{d}'"
        ),
    );
    cl.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{d}/approvals/withdraw"),
        Some(json!({"project": p, "purpose": "medical-training"})),
    );
    assert!(!w.t.control.anchor.snapshot().withdrawn_grants.is_empty());
    let (s, v) = submit(&cl, &w, &plan, &[&d], "after-withdraw");
    assert!(!succeeded(s), "a withdrawn approval covers a job: {s} {v}");
    sql(
        &url,
        &format!(
            "DELETE FROM withdrawn_grants WHERE asset_id='{d}';
             INSERT INTO asset_approvals SELECT * FROM atk_ap;
             INSERT INTO asset_approval_members SELECT * FROM atk_apm"
        ),
    );
    let first = submit(&cl, &w, &plan, &[&d], "attack");
    report("withdraw approval", (first.0, &first.1));
    assert_latched(&w, &cl, "withdraw approval", first);
}

/// (4) a disabled service account authenticates again.
#[test]
fn live_4_disabled_service_account_restored_does_not_authenticate() {
    let Some(w) = world() else { return };
    let cl = http(&w);
    let sa = std::sync::Arc::new(
        encompute_verification::ServiceSigner::from_seed("secagg-9", &[39; 32]).unwrap(),
    );
    cl.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({"id": "secagg-9", "kind": "secagg", "public_key": sa.public_key_hex()})),
    );
    let svc = As::Service(sa);
    cl.ok(&svc, "GET", "/v1/whoami", None);
    cl.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts/secagg-9/disable",
        None,
    );
    assert!(w
        .t
        .control
        .anchor
        .snapshot()
        .disabled_services
        .contains("secagg-9"));
    let (s, _) = cl.call(&svc, "GET", "/v1/whoami", None);
    assert!(!succeeded(s));
    sql(
        &w.t.env0.url,
        "UPDATE service_accounts SET status='active' WHERE id='secagg-9'",
    );
    let first = cl.call(&svc, "GET", "/v1/whoami", None);
    report("disable service account", (first.0, &first.1));
    assert_latched(&w, &cl, "disable service account", first);
}

/// (5) a disabled user authenticates again.
#[test]
fn live_5_disabled_user_restored_does_not_authenticate() {
    let Some(w) = world() else { return };
    let cl = http(&w);
    let id = cl.ok(&w.a_dev, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    cl.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/organizations/hospital-a/users/{id}/disable"),
        None,
    );
    assert!(w.t.control.anchor.snapshot().disabled_users.contains(&id));
    let (s, _) = cl.call(&w.a_dev, "GET", "/v1/whoami", None);
    assert!(!succeeded(s));
    sql(
        &w.t.env0.url,
        &format!("UPDATE users SET status='active' WHERE id='{id}'"),
    );
    let first = cl.call(&w.a_dev, "GET", "/v1/whoami", None);
    report("disable user", (first.0, &first.1));
    assert_latched(&w, &cl, "disable user", first);
}

/// (6) a cancelled job is revived and the evaluator starts it.
#[test]
fn live_6_cancelled_job_revived_does_not_start() {
    let Some(w) = world() else { return };
    let cl = http(&w);
    let plan = w.plan(&exact_own(&w.model_b));
    let (st, j) = submit(&cl, &w, &plan, &[&w.model_b], "to-cancel");
    assert_eq!(st, 201, "{j}");
    let job = j["id"].as_str().unwrap().to_owned();
    cl.ok(&w.b_dev, "POST", &format!("/v1/jobs/{job}/cancel"), None);
    assert!(w.t.control.anchor.snapshot().ended_jobs.contains(&job));
    let (s, _) = cl.call(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    assert!(!succeeded(s));
    sql(
        &w.t.env0.url,
        &format!("UPDATE jobs SET state='queued', error=NULL WHERE id='{job}'"),
    );
    let first = cl.call(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    report("cancel job", (first.0, &first.1));
    assert_latched(&w, &cl, "cancel job", first);
}

/// (7) a removed role is held again: the principal plans with it.
#[test]
fn live_7_removed_role_restored_is_not_exercised() {
    let Some(w) = world() else { return };
    let cl = http(&w);
    let multi = user(
        &w.t,
        &w.a_admin,
        "hospital-a",
        "a-multi",
        &["ml_developer", "auditor"],
    );
    let principal = cl.ok(&multi, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let url = w.t.env0.url.clone();
    sql(
        &url,
        &format!(
            "CREATE TABLE atk_roles AS SELECT * FROM memberships
              WHERE principal_id='{principal}' AND organization_id='hospital-a' AND role='ml_developer'"
        ),
    );
    let role = scalar(&url, "SELECT membership_id FROM atk_roles");
    let plan = |who: &As| {
        cl.call(
            who,
            "POST",
            "/v1/plans",
            Some(json!({"project": w.project, "program": EXACT})),
        )
    };
    assert!(succeeded(plan(&multi).0), "baseline: the role plans");
    cl.ok(
        &w.a_admin,
        "POST",
        "/v1/organizations/hospital-a/memberships/remove",
        Some(json!({"principal": principal, "role": "ml_developer"})),
    );
    assert!(w.t.control.anchor.snapshot().removed_roles.contains(&role));
    let (s, v) = plan(&multi);
    assert!(!succeeded(s), "a removed role still plans: {s} {v}");
    sql(
        &url,
        &format!("DELETE FROM removed_roles WHERE id='{role}'; INSERT INTO memberships SELECT * FROM atk_roles"),
    );
    let first = plan(&multi);
    report("remove role", (first.0, &first.1));
    assert_latched(&w, &cl, "remove role", first);
}

/// (8) a left project's membership is back: its developer plans in it.
#[test]
fn live_8_left_project_restored_is_not_usable() {
    let Some(w) = world() else { return };
    let cl = http(&w);
    let p = w.project.clone();
    let url = w.t.env0.url.clone();
    sql(
        &url,
        &format!(
            "CREATE TABLE atk_pm AS SELECT * FROM project_members
              WHERE project_id='{p}' AND organization_id='hospital-a'"
        ),
    );
    let mid = scalar(&url, "SELECT membership_id FROM atk_pm");
    let plan = || {
        cl.call(
            &w.a_dev,
            "POST",
            "/v1/plans",
            Some(json!({"project": p, "program": EXACT})),
        )
    };
    assert!(succeeded(plan().0), "baseline");
    cl.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/projects/{p}/members/remove"),
        Some(json!({"organization": "hospital-a"})),
    );
    assert!(w
        .t
        .control
        .anchor
        .snapshot()
        .removed_memberships
        .contains(&mid));
    let (s, v) = plan();
    assert!(!succeeded(s), "a left project is still usable: {s} {v}");
    sql(
        &url,
        &format!("DELETE FROM removed_memberships WHERE id='{mid}'; INSERT INTO project_members SELECT * FROM atk_pm"),
    );
    let first = plan();
    report("leave project", (first.0, &first.1));
    assert_latched(&w, &cl, "leave project", first);
}

/// The window does not close by itself: a disabled user restored in the
/// database acts, tick after tick, for as long as the service runs (before
/// 0.3.1's continuous enforcement), and with no request in between the
/// background tick alone finds it and latches (after).
#[test]
fn live_0_the_background_tick_alone_latches_without_any_request() {
    let Some(w) = world() else { return };
    let cl = http(&w);
    let id = cl.ok(&w.a_dev, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    cl.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/organizations/hospital-a/users/{id}/disable"),
        None,
    );
    sql(
        &w.t.env0.url,
        &format!("UPDATE users SET status='active' WHERE id='{id}'"),
    );
    // No request: only the background work runs.
    for _ in 0..3 {
        w.t.control.tick();
    }
    let (s, _) = cl.raw("GET", "/ready", &[], &[]);
    assert_eq!(s, 503, "the tick found the undone disable and latched");
    let (s, v) = cl.call(&w.a_dev, "GET", "/v1/whoami", None);
    assert!(state_refused(s, &v), "{s} {v}");
}

/// Cost of one enforcement check against an anchor holding `N` IDs of each of
/// the seven kinds (run by hand: `N=100000 cargo test --test anchor_live
/// live_cost -- --ignored --nocapture`). Prints the mean and worst of 50.
#[test]
#[ignore]
fn live_cost_measurement() {
    let Some(w) = world() else { return };
    let n: usize = std::env::var("N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    w.t.control
        .anchor
        .update(&w.t.control.signer, |a| {
            for i in 0..n {
                a.revoked.insert(format!("ast_fake{i:08}"));
                a.disabled_services.insert(format!("svc_fake{i:08}"));
                a.disabled_users.insert(format!("usr_fake{i:08}"));
                a.ended_jobs.insert(format!("job_fake{i:08}"));
                a.withdrawn_grants.insert(format!("apr_fake{i:08}"));
                a.removed_memberships.insert(format!("mem_fake{i:08}"));
                a.removed_roles.insert(format!("rol_fake{i:08}"));
            }
        })
        .unwrap();
    let mut worst = std::time::Duration::ZERO;
    let mut total = std::time::Duration::ZERO;
    for _ in 0..50 {
        let t0 = std::time::Instant::now();
        w.t.control.enforce().unwrap();
        let d = t0.elapsed();
        worst = worst.max(d);
        total += d;
    }
    eprintln!(
        "COST N={n} per kind ({} ids): mean {:?}, worst {:?}; anchor {} bytes",
        7 * n,
        total / 50,
        worst,
        w.t.control.anchor.bytes()
    );
}
