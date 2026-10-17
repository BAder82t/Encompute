//! A security-negative transition (a revocation, a disable, a cancellation, a
//! withdrawn approval, a removed membership or role) is acknowledged only
//! when the state anchor holds what the call committed (threat model section
//! 4.6; the same window as `anchor_window.rs`).
//!
//! The attacker owns the database and acts while the service runs: a LOCK
//! TABLE queued behind the call's own write is granted the instant the call
//! commits, so the attacker undoes the transition between the commit and the
//! service's anchoring read. In 0.3.0 and 0.3.1 candidates the call re-read
//! the database, found nothing to anchor and acknowledged a transition the
//! database no longer held and the anchor never recorded, so a restart could
//! not notice it. Every test asserts the safe behaviour: no acknowledgement
//! (ENC2202), the anchor holds what the call committed, a retry lands.

mod common;

use common::window::{in_window, in_window_parts, in_window_with, Fault, Opts, Part, INCONCLUSIVE};
use common::*;
use serde_json::{json, Value};

fn sql(url: &str, q: &str) {
    postgres::Client::connect(url, postgres::NoTls)
        .unwrap()
        .batch_execute(q)
        .unwrap();
}
fn scalar(url: &str, q: &str) -> String {
    postgres::Client::connect(url, postgres::NoTls)
        .unwrap()
        .query_one(q, &[])
        .unwrap()
        .get::<_, String>(0)
}

fn refused(s: u16, v: &Value, what: &str) -> bool {
    s == 500
        && v["code"] == "ENC2202"
        && v["message"]
            .as_str()
            .is_some_and(|m| m.contains(&format!("{what} STATE ROLLBACK")))
}
/// Subsequent enforcement: the anchor keeps the removal the call committed, so
/// a restart over the database the attacker restored is refused (not served).
fn restart_refuses(t: T, what: &str) {
    let e = t
        .restart()
        .err()
        .expect("a restart over the restored state must be refused");
    let e = e.to_string();
    assert!(e.contains(&format!("{what} STATE ROLLBACK")), "{e}");
}
fn rollbacks_counted(t: &T) -> bool {
    t.control
        .metrics
        .render()
        .contains("encompute_state_rollback_total{label=")
}

/// (1) an asset revocation undone in the window: not acknowledged, anchored.
#[test]
fn revocation_undone_in_the_window_is_not_acknowledged() {
    let Some(w) = world() else { return };
    let m = w.model_b.clone();
    let url = w.t.env0.url.clone();
    let undo = format!("UPDATE assets SET status='active', revoked_at=NULL WHERE id='{m}'");
    let (s, v) = in_window(&url, &["assets"], &undo, || {
        w.t.call(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None)
    });
    assert!(
        refused(s, &v, "REVOCATION"),
        "acknowledged then forgotten: {s} {v}"
    );
    assert!(rollbacks_counted(&w.t));
    assert!(
        w.t.control.anchor.snapshot().revoked.contains(&m),
        "the anchor must hold the revocation the call committed"
    );
    assert_eq!(
        scalar(&url, &format!("SELECT status FROM assets WHERE id='{m}'")),
        "active"
    );
    // The retry lands, and the honest state starts.
    let (s, v) =
        w.t.call(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None);
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "revoked");
    w.t.restart().expect("the honest database starts");
}

/// (2) a revocation whose failed job is un-failed in the window.
#[test]
fn failed_job_of_a_revocation_undone_in_the_window_is_not_acknowledged() {
    let Some(w) = world() else { return };
    let m = w.model_b.clone();
    let plan = w.plan(&exact_own(&m));
    let (st, j) = w.job(&plan, &[&m], "to-fail");
    assert_eq!(st, 201, "{j}");
    let job = j["id"].as_str().unwrap().to_owned();
    let url = w.t.env0.url.clone();
    let undo = format!(
        "UPDATE assets SET status='active', revoked_at=NULL WHERE id='{m}';
         UPDATE jobs SET state='queued', error=NULL WHERE id='{job}'"
    );
    let (s, v) = in_window(&url, &["assets"], &undo, || {
        w.t.call(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None)
    });
    assert!(refused(s, &v, "REVOCATION"), "{s} {v}");
    let a = w.t.control.anchor.snapshot();
    assert!(
        a.revoked.contains(&m) && a.ended_jobs.contains(&job),
        "{a:?}"
    );
}

/// (3) an approval withdrawn, then restored in the window.
#[test]
fn withdrawn_approval_restored_in_the_window_is_not_acknowledged() {
    let Some(w) = world() else { return };
    let (d, p) = (w.dataset_a.clone(), w.project.clone());
    w.t.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{d}/approvals"),
        Some(json!({"project": p, "purpose": "medical-training"})),
    );
    let url = w.t.env0.url.clone();
    sql(
        &url,
        &format!(
            "CREATE TABLE atk_ap AS SELECT * FROM asset_approvals WHERE asset_id='{d}';
             CREATE TABLE atk_apm AS SELECT * FROM asset_approval_members WHERE asset_id='{d}'"
        ),
    );
    // The undo is split by the table each statement modifies: each part runs in
    // the session that holds that table (all three held at the commit).
    let undo_grants = format!("DELETE FROM withdrawn_grants WHERE asset_id='{d}'");
    let (s, v) = in_window_parts(
        &url,
        &[
            ("withdrawn_grants", &undo_grants),
            (
                "asset_approvals",
                "INSERT INTO asset_approvals SELECT * FROM atk_ap",
            ),
            (
                "asset_approval_members",
                "INSERT INTO asset_approval_members SELECT * FROM atk_apm",
            ),
        ],
        || {
            w.t.call(
                &w.a_owner,
                "POST",
                &format!("/v1/assets/{d}/approvals/withdraw"),
                Some(json!({"project": p, "purpose": "medical-training"})),
            )
        },
    );
    assert!(refused(s, &v, "APPROVAL"), "{s} {v}");
    assert!(!w.t.control.anchor.snapshot().withdrawn_grants.is_empty());
    restart_refuses(w.t, "APPROVAL");
}

/// (4) a service account disabled, then enabled again in the window.
#[test]
fn service_disable_undone_in_the_window_is_not_acknowledged() {
    let Some(w) = world() else { return };
    let sa = std::sync::Arc::new(
        encompute_verification::ServiceSigner::from_seed("secagg-9", &[39; 32]).unwrap(),
    );
    w.t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({"id": "secagg-9", "kind": "secagg", "public_key": sa.public_key_hex()})),
    );
    let url = w.t.env0.url.clone();
    let undo = "UPDATE service_accounts SET status='active' WHERE id='secagg-9'";
    let (s, v) = in_window(&url, &["service_accounts"], undo, || {
        w.t.call(
            &w.platform,
            "POST",
            "/v1/organizations/platform/service-accounts/secagg-9/disable",
            None,
        )
    });
    assert!(refused(s, &v, "SERVICE ACCOUNT"), "{s} {v}");
    assert!(w
        .t
        .control
        .anchor
        .snapshot()
        .disabled_services
        .contains("secagg-9"));
    restart_refuses(w.t, "SERVICE ACCOUNT");
}

/// (5) a user disabled, then enabled again in the window.
#[test]
fn user_disable_undone_in_the_window_is_not_acknowledged() {
    let Some(w) = world() else { return };
    let who = w.t.ok(&w.a_dev, "GET", "/v1/whoami", None);
    let id = who["id"].as_str().unwrap().to_owned();
    let url = w.t.env0.url.clone();
    let undo = format!("UPDATE users SET status='active' WHERE id='{id}'");
    let (s, v) = in_window(&url, &["users"], &undo, || {
        w.t.call(
            &w.a_admin,
            "POST",
            &format!("/v1/organizations/hospital-a/users/{id}/disable"),
            None,
        )
    });
    assert!(refused(s, &v, "USER"), "{s} {v}");
    assert!(w.t.control.anchor.snapshot().disabled_users.contains(&id));
    restart_refuses(w.t, "USER");
}

/// (6) a job cancelled, then revived in the window.
#[test]
fn cancelled_job_revived_in_the_window_is_not_acknowledged() {
    let Some(w) = world() else { return };
    let plan = w.plan(&exact_own(&w.model_b));
    let (st, j) = w.job(&plan, &[&w.model_b], "to-cancel");
    assert_eq!(st, 201, "{j}");
    let job = j["id"].as_str().unwrap().to_owned();
    let url = w.t.env0.url.clone();
    let undo = format!("UPDATE jobs SET state='queued', error=NULL WHERE id='{job}'");
    let (s, v) = in_window(&url, &["jobs"], &undo, || {
        w.t.call(&w.b_dev, "POST", &format!("/v1/jobs/{job}/cancel"), None)
    });
    assert!(refused(s, &v, "JOB"), "{s} {v}");
    assert!(w.t.control.anchor.snapshot().ended_jobs.contains(&job));
    restart_refuses(w.t, "JOB");
}

/// (7) a role removed, then given back (same membership) in the window.
#[test]
fn role_removal_undone_in_the_window_is_not_acknowledged() {
    let Some(w) = world() else { return };
    let multi = user(
        &w.t,
        &w.a_admin,
        "hospital-a",
        "a-multi",
        &["ml_developer", "auditor"],
    );
    let principal = w.t.ok(&multi, "GET", "/v1/whoami", None)["id"]
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
    // Split by table: the service reads `memberships` after its commit, so that
    // table is held too (and the whole undo lands before that read).
    let undo_removed = format!("DELETE FROM removed_roles WHERE id='{role}'");
    let (s, v) = in_window_parts(
        &url,
        &[
            (
                "memberships",
                "INSERT INTO memberships SELECT * FROM atk_roles",
            ),
            ("removed_roles", &undo_removed),
        ],
        || {
            w.t.call(
                &w.a_admin,
                "POST",
                "/v1/organizations/hospital-a/memberships/remove",
                Some(json!({"principal": principal, "role": "ml_developer"})),
            )
        },
    );
    assert!(refused(s, &v, "ROLE"), "{s} {v}");
    assert!(w.t.control.anchor.snapshot().removed_roles.contains(&role));
    restart_refuses(w.t, "ROLE");
}

/// (8) an organization leaves a project; its membership is back in the window.
#[test]
fn project_leave_undone_in_the_window_is_not_acknowledged() {
    let Some(w) = world() else { return };
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
    let undo_removed = format!("DELETE FROM removed_memberships WHERE id='{mid}'");
    let (s, v) = in_window_parts(
        &url,
        &[
            (
                "project_members",
                "INSERT INTO project_members SELECT * FROM atk_pm",
            ),
            ("removed_memberships", &undo_removed),
        ],
        || {
            w.t.call(
                &w.a_admin,
                "POST",
                &format!("/v1/projects/{p}/members/remove"),
                Some(json!({"organization": "hospital-a"})),
            )
        },
    );
    assert!(refused(s, &v, "MEMBERSHIP"), "{s} {v}");
    assert!(w
        .t
        .control
        .anchor
        .snapshot()
        .removed_memberships
        .contains(&mid));
    restart_refuses(w.t, "MEMBERSHIP");
}

/// Negative control for the window helper itself. A window that misses is
/// reported as INCONCLUSIVE, never silently accepted:
///
/// 1. the old `LOCK TABLE a, b` behaviour (the second table is requested only
///    after the first was granted, i.e. after the target's commit): the second
///    request cannot be queued behind the target, the barrier does not hold;
/// 2. an attacker that holds a table the service never reads after its commit:
///    the service answers without ever being seen waiting behind the attacker;
/// 3. the same scenario with the correct sequencing passes, and the undone
///    disable is refused (so the detector is not just always failing).
#[test]
fn window_helper_negative_control_a_missed_window_is_inconclusive() {
    let Some(w) = world() else { return };
    let url = w.t.env0.url.clone();
    let disable = |subject: &str, parts: &[Part<'_>], opts: &Opts| {
        let me = user(&w.t, &w.a_admin, "hospital-a", subject, &["auditor"]);
        let id = w.t.ok(&me, "GET", "/v1/whoami", None)["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let undo = format!("UPDATE users SET status='active' WHERE id='{id}'");
        let parts: Vec<Part> = parts
            .iter()
            .map(|p| Part {
                table: p.table,
                sql: if p.sql == "<undo>" { &undo } else { p.sql },
            })
            .collect();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            in_window_with(&url, &parts, opts, || {
                w.t.call(
                    &w.a_admin,
                    "POST",
                    &format!("/v1/organizations/hospital-a/users/{id}/disable"),
                    None,
                )
            })
        }));
        (id, caught)
    };
    let msg = |e: &Box<dyn std::any::Any + Send>| -> String {
        e.downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    };
    let quick = Opts {
        barrier_timeout: std::time::Duration::from_secs(3),
        observe_timeout: std::time::Duration::from_secs(3),
        ..Opts::default()
    };
    // The target writes both `users` and `audit_head`.
    let both = [
        Part {
            table: "users",
            sql: "<undo>",
        },
        Part {
            table: "audit_head",
            sql: "",
        },
    ];
    // 1. sequential locks (the old behaviour)
    let sequential = Opts {
        fault: Fault::SequentialLocks,
        ..quick
    };
    let (_, caught) = disable("ctl-1", &both, &sequential);
    let e = caught.expect_err("a sequentially requested lock must be reported");
    eprintln!("negative control 1: {}", msg(&e));
    assert!(
        msg(&e).contains(INCONCLUSIVE) && msg(&e).contains("queued behind the target"),
        "{}",
        msg(&e)
    );
    // 2. the attacker holds a table the service does not read after its commit
    let uncovered = [Part {
        table: "audit_head",
        sql: "SELECT 1",
    }];
    let (_, caught) = disable("ctl-2", &uncovered, &quick);
    let e = caught.expect_err("a window the service never waits in must be reported");
    eprintln!("negative control 2: {}", msg(&e));
    assert!(msg(&e).contains(INCONCLUSIVE), "{}", msg(&e));
    // 3. the correct sequencing on the same scenario is a proven window
    let (id, caught) = disable("ctl-3", &both, &quick);
    let (s, v) = caught.expect("a proven window is not inconclusive");
    assert!(refused(s, &v, "USER"), "{s} {v}");
    assert!(w.t.control.anchor.snapshot().disabled_users.contains(&id));
}
