//! An anchored security-negative transition is undone by deleting its row,
//! too, not only by changing it back: a revoked asset, a disabled service
//! account or user, or a cancelled job whose row a database-level attacker
//! deleted (triggers disabled) is refused at start, like one shown live
//! again. Recovery records the loss in the signed anchor (the ID stays
//! blocked: it is never used again), and a service ID that was disabled is
//! never registered again.
//!
//! (Withdrawn approvals, removed memberships and removed roles are anchored
//! as the absence of their rows: a missing row is their anchored state.)
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use serde_json::json;

use common::*;

/// Stops `t`, lets `f` edit its database, and returns the start's refusal
/// and the recovery notes; then starts again and returns the control plane.
fn deleted_then_recovered(t: T, f: impl FnOnce(&str), expect: &str, id: &str) -> T {
    let env0 = t.env0;
    drop(t.control);
    f(&env0.url);
    let e = env0
        .start()
        .err()
        .unwrap_or_else(|| panic!("a deleted {id} passed the rollback check"));
    assert!(e.message.contains(expect), "{e}");
    assert!(e.message.contains(id), "{e}");
    let notes = run_recovery(&env0);
    assert!(
        notes.iter().any(|n| n.contains(id) && n.contains("lost")),
        "{notes:?}"
    );
    let t = env0.start().unwrap();
    assert!(t
        .control
        .anchor
        .snapshot()
        .lost
        .iter()
        .any(|l| l.ends_with(id)));
    t
}

#[test]
fn deleting_a_revoked_asset_row_refuses_start() {
    let Some(w) = world() else { return };
    let asset = w.model_b.clone();
    w.t.ok(
        &w.b_owner,
        "POST",
        &format!("/v1/assets/{asset}/revoke"),
        None,
    );
    let t = deleted_then_recovered(
        w.t,
        |url| {
            attacker(
                url,
                &["assets"],
                &format!("DELETE FROM assets WHERE id = '{asset}'"),
            )
        },
        "REVOCATION STATE ROLLBACK",
        &asset,
    );
    // A second restart is clean.
    t.restart().unwrap();
}

#[test]
fn deleting_a_disabled_service_account_refuses_start_and_its_id_stays_retired() {
    let Some(w) = world() else { return };
    let s = encompute_verification::ServiceSigner::from_seed("a-robot", &[5; 32]).unwrap();
    w.t.ok(
        &w.a_admin,
        "POST",
        "/v1/organizations/hospital-a/service-accounts",
        Some(json!({"id": "a-robot", "kind": "automation", "public_key": s.public_key_hex()})),
    );
    w.t.ok(
        &w.a_admin,
        "POST",
        "/v1/organizations/hospital-a/service-accounts/a-robot/disable",
        None,
    );
    let a_admin = w.a_admin.clone();
    let t = deleted_then_recovered(
        w.t,
        |url| {
            attacker(
                url,
                &["service_accounts"],
                "DELETE FROM service_accounts WHERE id = 'a-robot'",
            )
        },
        "SERVICE ACCOUNT STATE ROLLBACK",
        "a-robot",
    );
    // Its ID is never registered again, under any key.
    let s2 = encompute_verification::ServiceSigner::from_seed("a-robot", &[6; 32]).unwrap();
    let (st, v) = t.call(
        &a_admin,
        "POST",
        "/v1/organizations/hospital-a/service-accounts",
        Some(json!({"id": "a-robot", "kind": "automation", "public_key": s2.public_key_hex()})),
    );
    assert_eq!(st, 409, "{v}");
}

#[test]
fn deleting_a_disabled_user_refuses_start() {
    let Some(w) = world() else { return };
    let who = w.t.ok(&w.a_dev, "GET", "/v1/whoami", None);
    let id = who["id"].as_str().unwrap().to_owned();
    w.t.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/organizations/hospital-a/users/{id}/disable"),
        None,
    );
    deleted_then_recovered(
        w.t,
        |url| {
            attacker(
                url,
                &["users"],
                &format!("DELETE FROM users WHERE id = '{id}'"),
            )
        },
        "USER STATE ROLLBACK",
        &id,
    );
}

#[test]
fn deleting_a_cancelled_job_refuses_start() {
    let Some(w) = world() else { return };
    let plan = w.plan(&exact_own(&w.model_b));
    let (_, j) = w.job(&plan, &[&w.model_b], "to-cancel");
    let job = j["id"].as_str().unwrap().to_owned();
    w.t.ok(&w.b_dev, "POST", &format!("/v1/jobs/{job}/cancel"), None);
    deleted_then_recovered(
        w.t,
        |url| {
            attacker(
                url,
                &["jobs", "job_transitions", "job_approvals"],
                &format!(
                    "DELETE FROM job_transitions WHERE job_id = '{job}';
                     DELETE FROM job_approvals WHERE job_id = '{job}';
                     DELETE FROM jobs WHERE id = '{job}'"
                ),
            )
        },
        "JOB STATE ROLLBACK",
        &job,
    );
}
