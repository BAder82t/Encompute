//! The state anchor against a database attacker who acts while the control
//! plane runs, or restores a backup (threat model §4.6): the anchor only
//! moves forward along the same chains, divergence is refused at run time,
//! and security-negative transitions (freezes, disables, cancellations,
//! revocations, withdrawn approvals, left projects, removed roles) survive
//! a restore and recovery.

mod common;

use std::sync::Arc;

use common::*;
use serde_json::{json, Value};

fn spend(t: &T, who: &As, d: &str, ev: &str, sigma2: u64) -> (u16, Value) {
    t.call(
        who,
        "POST",
        &format!("/v1/privacy/{d}/events"),
        Some(reserve(ev, sigma2)),
    )
}

fn anchored_seq(t: &T, d: &str) -> u64 {
    t.control.anchor.snapshot().ledgers[d].seq
}

fn rollbacks_counted(t: &T, what: &str) -> bool {
    t.control.metrics.render().contains(&format!(
        "encompute_state_rollback_total{{label=\"{what}\"}}"
    ))
}

/// Review finding CP-S-1 (ENC-SF-2026-033): a privacy ledger rolled back while the service
/// runs is refused at the next spend (ENC2202 PRIVACY STATE ROLLBACK), is
/// never written into the anchor, and the next start refuses it too. On
/// rc.3 spending resumed on the rolled-back ledger and, once it outgrew the
/// anchored one, the anchor adopted the fork.
#[test]
fn online_ledger_rollback_is_refused_and_never_anchored() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    let mut n = 0;
    loop {
        let (s, v) = spend(&w.t, &w.a_owner, &d, &format!("exp-{n}"), 18);
        if s != 200 {
            assert_eq!((s, v["code"].as_str()), (409, Some("ENC2201")), "{v}");
            break;
        }
        n += 1;
    }
    assert!(n >= 2);
    assert_eq!(anchored_seq(&w.t, &d), n);
    let before = w.t.control.anchor.snapshot();
    // The database attacker rolls the ledger back while the service runs.
    let mut c = postgres::Client::connect(&w.t.env0.url, postgres::NoTls).unwrap();
    c.execute("DELETE FROM privacy_entries WHERE asset_id = $1", &[&d])
        .unwrap();
    // Every later spend is refused; none is recorded or anchored.
    for m in 0..(n + 3) {
        let (s, v) = spend(&w.t, &w.a_owner, &d, &format!("cheap-{m}"), 200);
        assert_eq!(s, 500, "spend {m} on a rolled-back ledger: {v}");
        assert_eq!(v["code"], "ENC2202", "{v}");
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .contains("PRIVACY STATE ROLLBACK"),
            "{v}"
        );
    }
    let entries: i64 = c
        .query_one(
            "SELECT count(*) FROM privacy_entries WHERE asset_id = $1",
            &[&d],
        )
        .unwrap()
        .get(0);
    assert_eq!(entries, 0, "nothing was appended to the rolled-back ledger");
    assert_eq!(
        w.t.control.anchor.snapshot(),
        before,
        "the anchor is unchanged"
    );
    assert!(w.t.control.anchor_ledger(&d).is_err());
    assert!(rollbacks_counted(&w.t, "privacy"));
    // A forked ledger that outgrows the anchored one (written straight
    // into the database) is not adopted either.
    let view = encompute_control::control::load_ledger(&mut c, &d)
        .unwrap()
        .unwrap();
    let mut fork = view;
    for m in 0..(n + 2) {
        let e: encompute_privacy::PrivacyEvent =
            serde_json::from_value(reserve(&format!("fork-{m}"), 200)).unwrap();
        let (next, entry) = fork.append_event(e).unwrap();
        c.execute(
            "INSERT INTO privacy_entries (asset_id, seq, entry) VALUES ($1, $2, $3)",
            &[
                &d,
                &(entry.seq as i64),
                &serde_json::to_value(&entry).unwrap(),
            ],
        )
        .unwrap();
        fork = next;
    }
    assert!(fork.entries.len() as u64 > n);
    let (s, v) = spend(&w.t, &w.a_owner, &d, "after-fork", 200);
    assert_eq!((s, v["code"].as_str()), (500, Some("ENC2202")), "{v}");
    assert!(w.t.control.anchor_ledger(&d).is_err());
    assert_eq!(anchored_seq(&w.t, &d), n, "the fork was never anchored");
    drop(c);
    // And the next start refuses the database.
    let e = w.t.restart().err().expect("a rolled-back ledger started");
    assert!(e.message.contains("PRIVACY STATE ROLLBACK"), "{e}");
}

/// Review finding CP-S-2 (ENC-SF-2026-034): a ledger frozen by recovery stays frozen whatever
/// the database says. (A) Clearing the flag while the service runs does
/// not make it spendable, and the next start refuses the database (FREEZE
/// STATE ROLLBACK). (B) Restoring the same pre-recovery backup again and
/// recovering again freezes it again. On rc.3 both variants spent again.
#[test]
fn a_frozen_ledger_stays_frozen_whatever_the_database_says() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    for i in 0..3 {
        spend(&w.t, &w.a_owner, &d, &format!("s-{i}"), 200);
    }
    let World {
        t,
        a_owner,
        a_auditor,
        ..
    } = w;
    let url = t.env0.url.clone();
    let env0 = t.env0;
    drop(t.control);
    let backup = format!("{}_frbk", url.rsplit('/').next().unwrap());
    backup_database(&url, &backup);
    let t = env0.start().unwrap();
    assert_eq!(spend(&t, &a_owner, &d, "after-backup", 200).0, 200);
    let env0 = t.env0;
    drop(t.control);
    restore_database(&backup, &url);
    assert!(env0.start().is_err(), "the rollback is refused first");
    run_recovery(&env0);
    let t = env0.start().unwrap();
    assert_eq!(spend(&t, &a_owner, &d, "frozen-try", 200).0, 409);
    assert!(t.control.anchor.snapshot().frozen.contains(&d));

    // (A) The database attacker clears the flag while the service runs.
    let mut c = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    c.execute("UPDATE privacy_ledgers SET frozen_reason = NULL", &[])
        .unwrap();
    let (s, v) = spend(&t, &a_owner, &d, "unfrozen-by-sql", 200);
    assert_eq!((s, v["code"].as_str()), (409, Some("ENC2201")), "{v}");
    drop(c);
    let env0 = t.env0;
    drop(t.control);
    let e = env0.start().err().expect("an unfrozen ledger started");
    assert!(e.message.contains("FREEZE STATE ROLLBACK"), "{e}");
    assert!(e.message.contains(&d), "{e}");
    let notes = run_recovery(&env0);
    assert!(
        notes.iter().any(|n| n.contains(&d) && n.contains("frozen")),
        "{notes:?}"
    );
    let t = env0.start().unwrap();
    let v = t.ok(&a_auditor, "GET", &format!("/v1/privacy/{d}"), None);
    assert!(v["frozen"].is_string(), "{v}");
    assert_eq!(spend(&t, &a_owner, &d, "after-refreeze", 200).0, 409);

    // (B) The restore-only attacker restores the same pre-recovery backup
    // again; the operator follows the printed instruction and recovers.
    let env0 = t.env0;
    drop(t.control);
    restore_database(&backup, &url);
    assert!(env0.start().is_err(), "the second restore is refused");
    let notes = run_recovery(&env0);
    assert!(
        notes.iter().any(|n| n.contains(&d) && n.contains("frozen")),
        "{notes:?}"
    );
    let t = env0.start().expect("starts after the second recovery");
    let v = t.ok(&a_auditor, "GET", &format!("/v1/privacy/{d}"), None);
    assert!(v["frozen"].is_string(), "still frozen: {v}");
    let (s, v) = spend(&t, &a_owner, &d, "after-second-recovery", 200);
    assert_eq!((s, v["code"].as_str()), (409, Some("ENC2201")), "{v}");
}

/// Review finding CP-S-3 (ENC-SF-2026-038): audit events already anchored that are deleted
/// while the service runs are never re-anchored: the checkpoint refuses a
/// chain that does not extend the anchored root (ENC2202 AUDIT STATE
/// ROLLBACK), the background checkpoint raises an alarm instead of
/// wrapping, and the next start refuses. On rc.3 the next checkpoint
/// signed and anchored the forked chain and restart passed.
#[test]
fn online_audit_rollback_is_never_reanchored() {
    let Some(w) = world() else { return };
    let cp = w.t.ok(&w.platform, "POST", "/v1/audit/checkpoints", None);
    let anchored = cp["seq"].as_i64().unwrap();
    let mut c = postgres::Client::connect(&w.t.env0.url, postgres::NoTls).unwrap();
    c.batch_execute(
        "DELETE FROM audit_events WHERE seq > 3;
         UPDATE audit_head SET seq = 3, hash = (SELECT hash FROM audit_events WHERE seq = 3)",
    )
    .unwrap();
    let before = w.t.control.anchor.snapshot();
    // Behind the anchor: the background checkpoint alarms (it used to
    // wrap around and re-sign every tick).
    w.t.control.maybe_checkpoint();
    assert_eq!(w.t.control.anchor.snapshot(), before);
    assert!(rollbacks_counted(&w.t, "audit"));
    // Traffic regrows the chain past the anchored sequence number.
    let mut i = 0;
    loop {
        let head: i64 = c
            .query_one("SELECT seq FROM audit_head", &[])
            .unwrap()
            .get(0);
        if head > anchored + 5 {
            break;
        }
        w.t.ok(
            &w.b_dev,
            "POST",
            "/v1/projects",
            Some(json!({"organization": "modelco", "name": format!("p{i}")})),
        );
        i += 1;
    }
    let (s, v) = w.t.call(&w.platform, "POST", "/v1/audit/checkpoints", None);
    assert_eq!((s, v["code"].as_str()), (500, Some("ENC2202")), "{v}");
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("AUDIT STATE ROLLBACK"),
        "{v}"
    );
    w.t.control.maybe_checkpoint();
    assert_eq!(
        w.t.control.anchor.snapshot(),
        before,
        "the forked chain was never anchored"
    );
    let signed: i64 = c
        .query_one(
            "SELECT count(*) FROM audit_checkpoints WHERE seq > $1",
            &[&anchored],
        )
        .unwrap()
        .get(0);
    assert_eq!(signed, 0, "no checkpoint of the forked chain was signed");
    drop(c);
    let e =
        w.t.restart()
            .err()
            .expect("deleted anchored events started");
    assert!(e.message.contains("AUDIT STATE ROLLBACK"), "{e}");
}

/// Review finding CP-S-4 (ENC-SF-2026-039): disabled service accounts and users, and
/// cancelled jobs, are anchored. A backup restored from before them is
/// refused at start even when no audit checkpoint happened since (it
/// started silently on rc.3), and recovery re-applies them (on rc.3 it
/// only recorded an audit gap and the compromised service was active).
#[test]
fn restore_and_recovery_keep_disables_and_cancellations() {
    let Some(w) = world() else { return };
    let sa =
        Arc::new(encompute_verification::ServiceSigner::from_seed("secagg-9", &[39; 32]).unwrap());
    w.t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({"id": "secagg-9", "kind": "secagg", "public_key": sa.public_key_hex()})),
    );
    let who = w.t.ok(&w.a_dev, "GET", "/v1/whoami", None);
    let a_dev_id = who["id"].as_str().unwrap().to_owned();
    let plan = w.plan(&exact_own(&w.model_b));
    let (_, j) = w.job(&plan, &[&w.model_b], "to-cancel");
    let job = j["id"].as_str().unwrap().to_owned();
    let World {
        t,
        platform,
        a_admin,
        a_dev,
        b_dev,
        ..
    } = w;
    let url = t.env0.url.clone();
    let env0 = t.env0;
    drop(t.control);
    let backup = format!("{}_sabk", url.rsplit('/').next().unwrap());
    backup_database(&url, &backup);
    let t = env0.start().unwrap();
    // A key compromise and a mistaken job: disable, disable, cancel.
    t.ok(
        &platform,
        "POST",
        "/v1/organizations/platform/service-accounts/secagg-9/disable",
        None,
    );
    t.ok(
        &a_admin,
        "POST",
        &format!("/v1/organizations/hospital-a/users/{a_dev_id}/disable"),
        None,
    );
    t.ok(&b_dev, "POST", &format!("/v1/jobs/{job}/cancel"), None);
    let a = t.control.anchor.snapshot();
    assert!(a.disabled_services.contains("secagg-9"));
    assert!(a.disabled_users.contains(&a_dev_id));
    assert!(a.ended_jobs.contains(&job));
    let env0 = t.env0;
    drop(t.control);
    restore_database(&backup, &url);
    let e = env0
        .start()
        .err()
        .expect("a restore un-disabled a service account silently");
    assert!(e.message.contains("SERVICE ACCOUNT STATE ROLLBACK"), "{e}");
    assert!(e.message.contains("secagg-9"), "{e}");
    let notes = run_recovery(&env0);
    for what in ["secagg-9", a_dev_id.as_str(), job.as_str()] {
        assert!(
            notes
                .iter()
                .any(|n| n.contains(what) && n.contains("re-applied")),
            "{what}: {notes:?}"
        );
    }
    let t = env0.start().unwrap();
    let mut c = t.control.db.conn().unwrap();
    let status: String = c
        .query_one(
            "SELECT status FROM service_accounts WHERE id = 'secagg-9'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(status, "disabled");
    let state: String = c
        .query_one("SELECT state FROM jobs WHERE id = $1", &[&job])
        .unwrap()
        .get(0);
    assert_eq!(state, "failed");
    drop(c);
    let (s, _) = t.call(&As::Service(sa), "GET", "/v1/whoami", None);
    assert_eq!(s, 401, "the compromised service stays out");
    let (s, _) = t.call(&a_dev, "GET", "/v1/whoami", None);
    assert_eq!(s, 401, "the disabled user stays out");
    // A second restart is clean.
    t.restart().unwrap();
}

/// Review finding CP-S-9 (ENC-SF-2026-084): a key broker learns of a revocation only once
/// the anchor holds it. A revocation committed to the database but not yet
/// anchored (a crash between the two) stays in the outbox; the background
/// anchoring catches up, then it is delivered.
#[test]
fn broker_revocation_is_delivered_only_once_anchored() {
    let Some(w) = world() else { return };
    let kb =
        encompute_verification::ServiceSigner::from_seed("keybroker-modelco", &[21; 32]).unwrap();
    w.t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({"id": "keybroker-modelco", "kind": "keybroker",
                    "public_key": kb.public_key_hex(), "url": "http://kb.internal:8760"})),
    );
    // The revocation as it stands after the commit, before the anchor.
    let m = encompute_control::transport::seal(
        &w.t.control.signer,
        "asset.revoked",
        "keybroker-modelco",
        Default::default(),
        &json!({"asset": w.model_b, "key_ref": "model-7", "key_version": 1}),
        300,
    )
    .unwrap();
    {
        let mut c = w.t.control.db.conn().unwrap();
        c.execute(
            "UPDATE assets SET status = 'revoked' WHERE id = $1",
            &[&w.model_b],
        )
        .unwrap();
        c.execute(
            "INSERT INTO outbox (message_id, recipient, url, envelope) VALUES ($1, $2, $3, $4)",
            &[
                &m.message_id,
                &"keybroker-modelco",
                &"http://kb.internal:8760",
                &serde_json::to_value(&m).unwrap(),
            ],
        )
        .unwrap();
    }
    w.t.control.deliver_outbox().unwrap();
    assert!(
        w.t.transport.drain().is_empty(),
        "sent before it was anchored"
    );
    w.t.control.tick();
    assert!(w.t.control.anchor.snapshot().revoked.contains(&w.model_b));
    let sent = w.t.transport.drain();
    assert!(
        sent.iter()
            .any(|(u, x)| u == "http://kb.internal:8760" && x.kind == "asset.revoked"),
        "{sent:?}"
    );
}

/// Review finding rc.4 F4 (ENC-SF-2026-091): a withdrawn asset approval, and the grants an
/// organization lost by leaving a project, are anchored. A backup restored
/// from before them is refused at start (APPROVAL STATE ROLLBACK), recovery
/// withdraws them again, and an approval given again after a withdrawal is
/// a new one (so it never trips the check). On rc.3 the restored database
/// silently shared the asset again.
#[test]
fn restore_and_recovery_keep_withdrawn_approvals() {
    let Some(w) = world() else { return };
    let project = w.project.clone();
    let approve = |t: &T, who: &As, asset: &str| {
        t.ok(
            who,
            "POST",
            &format!("/v1/assets/{asset}/approvals"),
            Some(json!({"project": project, "purpose": "medical-training"})),
        )
    };
    let approval_id = |t: &T, asset: &str| -> String {
        t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT approval_id FROM asset_approvals WHERE asset_id = $1",
                &[&asset],
            )
            .unwrap()
            .get(0)
    };
    approve(&w.t, &w.a_owner, &w.dataset_a);
    approve(&w.t, &w.b_owner, &w.model_b);
    w.t.ok(
        &w.b_dev,
        "GET",
        &format!("/v1/assets/{}", w.dataset_a),
        None,
    );
    w.t.ok(
        &w.a_owner,
        "GET",
        &format!("/v1/assets/{}", w.model_b),
        None,
    );
    let first = approval_id(&w.t, &w.dataset_a);
    let World {
        t,
        a_admin,
        a_owner,
        b_dev,
        b_admin,
        dataset_a,
        model_b,
        ..
    } = w;
    let url = t.env0.url.clone();
    let env0 = t.env0;
    drop(t.control);
    let backup = format!("{}_apbk", url.rsplit('/').next().unwrap());
    backup_database(&url, &backup);
    let t = env0.start().unwrap();
    // hospital-a withdraws its approval; then modelco removes hospital-a
    // from the project, ending modelco's grant of its model to it.
    t.ok(
        &a_owner,
        "POST",
        &format!("/v1/assets/{dataset_a}/approvals/withdraw"),
        Some(json!({"project": project, "purpose": "medical-training"})),
    );
    t.ok(
        &b_admin,
        "POST",
        &format!("/v1/projects/{project}/members/remove"),
        Some(json!({"organization": "hospital-a"})),
    );
    let a = t.control.anchor.snapshot();
    assert!(
        a.withdrawn_grants.contains(&first),
        "{:?}",
        a.withdrawn_grants
    );
    assert!(
        a.withdrawn_grants.iter().any(|g| g.starts_with("apg_")),
        "the ended grants: {:?}",
        a.withdrawn_grants
    );
    let env0 = t.env0;
    drop(t.control);
    restore_database(&backup, &url);
    let e = env0
        .start()
        .err()
        .expect("a restore brought a withdrawn approval back silently");
    assert!(e.message.contains("APPROVAL STATE ROLLBACK"), "{e}");
    let notes = run_recovery(&env0);
    assert!(
        notes
            .iter()
            .any(|n| n.contains(&first) && n.contains("withdrawal re-applied")),
        "{notes:?}"
    );
    let t = env0.start().unwrap();
    // Neither side's sharing came back (nor hospital-a's membership: see
    // `restore_and_recovery_keep_a_left_project_left`).
    let (s, _) = t.call(&b_dev, "GET", &format!("/v1/assets/{dataset_a}"), None);
    assert_eq!(s, 404, "the withdrawn approval is withdrawn again");
    let (s, _) = t.call(&a_owner, "GET", &format!("/v1/assets/{model_b}"), None);
    assert_eq!(s, 404, "the ended grant is ended again");
    // Joining and approving again is a new approval: a restart is clean.
    for who in [&b_admin, &a_admin] {
        t.ok(
            who,
            "POST",
            &format!("/v1/projects/{project}/members"),
            Some(json!({"organization": "hospital-a"})),
        );
    }
    approve(&t, &a_owner, &dataset_a);
    let again = approval_id(&t, &dataset_a);
    assert_ne!(again, first);
    t.ok(&b_dev, "GET", &format!("/v1/assets/{dataset_a}"), None);
    t.restart().unwrap();
}

/// Review finding rc.4 F4 residual (ENC-SF-2026-091): leaving a project is anchored. An
/// organization leaves; a backup from before is restored: startup refuses it
/// (MEMBERSHIP STATE ROLLBACK), recovery removes the membership again, and
/// the organization gets nothing back: not the project's details, not the
/// right to plan or submit jobs there, not its failed job, not the grants
/// its membership held, and approvals given afterwards do not cover it.
/// Joining again is a new membership, so a restart is clean. On rc.3 (and
/// with only the grants anchored) the restored member saw the project,
/// submitted and queued a job there, and a later approval covered it again.
#[test]
fn restore_and_recovery_keep_a_left_project_left() {
    let Some(w) = world() else { return };
    let project = w.project.clone();
    let membership = |t: &T| -> Option<String> {
        t.control
            .db
            .conn()
            .unwrap()
            .query_opt(
                "SELECT membership_id FROM project_members WHERE project_id = $1 AND organization_id = 'hospital-a'",
                &[&project],
            )
            .unwrap()
            .map(|r| r.get(0))
    };
    // modelco's model is approved to the project (covering hospital-a), and
    // hospital-a has a job queued there over its own data.
    w.t.ok(
        &w.b_owner,
        "POST",
        &format!("/v1/assets/{}/approvals", w.model_b),
        Some(json!({"project": project, "purpose": "medical-training"})),
    );
    w.t.ok(
        &w.a_owner,
        "GET",
        &format!("/v1/assets/{}", w.model_b),
        None,
    );
    let plan = w.t.ok(
        &w.a_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": project, "program": EXACT})),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let submit = |t: &T, who: &As, key: &str| {
        t.call_with(
            who,
            "POST",
            "/v1/jobs",
            Some(
                json!({"project": project, "plan": plan, "purpose": "own-research",
                        "source_assets": [], "requested_output": "out"}),
            ),
            &[("Idempotency-Key", key)],
        )
    };
    let (s, j) = submit(&w.t, &w.a_dev, "before-leaving");
    assert_eq!(s, 201, "{j}");
    assert_eq!(j["state"], "queued", "{j}");
    let job = j["id"].as_str().unwrap().to_owned();
    let first = membership(&w.t).expect("hospital-a is a member");
    let World {
        t,
        a_admin,
        a_owner,
        a_dev,
        b_admin,
        b_owner,
        b_dev,
        model_b,
        evaluator,
        ..
    } = w;
    let url = t.env0.url.clone();
    let env0 = t.env0;
    drop(t.control);
    let backup = format!("{}_pmbk", url.rsplit('/').next().unwrap());
    backup_database(&url, &backup);
    let t = env0.start().unwrap();
    // hospital-a leaves.
    let v = t.ok(
        &a_admin,
        "POST",
        &format!("/v1/projects/{project}/members/remove"),
        Some(json!({"organization": "hospital-a"})),
    );
    assert_eq!(v["failed_jobs"], json!([job]), "{v}");
    let a = t.control.anchor.snapshot();
    assert!(
        a.removed_memberships.contains(&first),
        "{:?}",
        a.removed_memberships
    );
    assert!(a.ended_jobs.contains(&job));
    let env0 = t.env0;
    drop(t.control);
    restore_database(&backup, &url);
    // (The failed job is found first; the membership on its own below.)
    let e = env0
        .start()
        .err()
        .expect("a restore brought a left project back silently");
    assert!(e.message.contains("STATE ROLLBACK"), "{e}");
    let notes = run_recovery(&env0);
    assert!(
        notes
            .iter()
            .any(|n| n.contains(&first) && n.contains("removal re-applied")),
        "{notes:?}"
    );
    let t = env0.start().unwrap();
    assert_eq!(membership(&t), None);
    // No project details, plans or job submissions for hospital-a.
    let (s, _) = t.call(&a_admin, "GET", &format!("/v1/projects/{project}"), None);
    assert_eq!(s, 404, "the left project is visible again");
    let projects = t.ok(&a_admin, "GET", "/v1/projects", None);
    assert!(!projects.to_string().contains(&project), "{projects}");
    let (s, v) = t.call(
        &a_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": project, "program": EXACT})),
    );
    assert_eq!(s, 404, "planning in the left project: {v}");
    let (s, v) = submit(&t, &a_dev, "after-restore");
    assert_eq!(s, 404, "a job in the left project: {v}");
    // Its job from before stays failed; the evaluator cannot start it.
    let v = t.ok(&a_dev, "GET", &format!("/v1/jobs/{job}"), None);
    assert_eq!(v["state"], "failed", "{v}");
    let (s, _) = t.call(
        &evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    assert_eq!(s, 409);
    // The grant its membership held stays ended, and an approval given now
    // covers the members only.
    let (s, _) = t.call(&a_owner, "GET", &format!("/v1/assets/{model_b}"), None);
    assert_eq!(s, 404, "the ended grant is back");
    let v = t.ok(
        &b_owner,
        "POST",
        &format!("/v1/assets/{model_b}/approvals"),
        Some(json!({"project": project, "purpose": "evaluation"})),
    );
    assert_eq!(v["members"], json!(["modelco"]), "{v}");
    let (s, _) = t.call(&a_owner, "GET", &format!("/v1/assets/{model_b}"), None);
    assert_eq!(s, 404, "a new approval covers the left organization");
    let v = t.ok(&b_dev, "GET", &format!("/v1/projects/{project}"), None);
    assert_eq!(v["members"], json!(["modelco"]), "{v}");
    // Joining again (invited, then accepted) is a new membership: a
    // restart is clean, and hospital-a sees the project again.
    for who in [&b_admin, &a_admin] {
        t.ok(
            who,
            "POST",
            &format!("/v1/projects/{project}/members"),
            Some(json!({"organization": "hospital-a"})),
        );
    }
    let again = membership(&t).expect("hospital-a joined again");
    assert_ne!(again, first);
    let t = t.restart().unwrap();
    t.ok(&a_admin, "GET", &format!("/v1/projects/{project}"), None);
    // The membership alone (no grant or job ended with it) is refused too.
    let env0 = t.env0;
    drop(t.control);
    let backup2 = format!("{backup}2");
    backup_database(&url, &backup2);
    let t = env0.start().unwrap();
    t.ok(
        &b_admin,
        "POST",
        &format!("/v1/projects/{project}/members/remove"),
        Some(json!({"organization": "hospital-a"})),
    );
    let env0 = t.env0;
    drop(t.control);
    restore_database(&backup2, &url);
    let e = env0
        .start()
        .err()
        .expect("a restore brought a removed membership back silently");
    assert!(e.message.contains("MEMBERSHIP STATE ROLLBACK"), "{e}");
    assert!(e.message.contains(&again), "{e}");
    let notes = run_recovery(&env0);
    assert!(
        notes
            .iter()
            .any(|n| n.contains(&again) && n.contains("removal re-applied")),
        "{notes:?}"
    );
    let t = env0.start().unwrap();
    let (s, _) = t.call(&a_admin, "GET", &format!("/v1/projects/{project}"), None);
    assert_eq!(s, 404);
    t.restart().unwrap();
}

/// Review finding rc.4 (ENC-SF-2026-093): removing a principal's role is
/// anchored before it is acknowledged. A database restored from a backup
/// that still holds the role is refused at startup (ROLE STATE ROLLBACK,
/// naming the role's membership ID); recovery removes it again (audited),
/// and the principal cannot act with it. On rc.3 the restore silently gave
/// the role back.
#[test]
fn restore_and_recovery_keep_a_removed_role_removed() {
    let Some(w) = world() else { return };
    let World { t, a_admin, .. } = w;
    // hospital-a's admin grants a person two roles.
    let multi = user(
        &t,
        &a_admin,
        "hospital-a",
        "a-multi",
        &["ml_developer", "auditor"],
    );
    let principal = t.ok(&multi, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let role_id = |t: &T| -> Option<String> {
        t.control
            .db
            .conn()
            .unwrap()
            .query_opt(
                "SELECT membership_id FROM memberships
                  WHERE principal_id = $1 AND organization_id = 'hospital-a' AND role = 'ml_developer'",
                &[&principal],
            )
            .unwrap()
            .map(|r| r.get(0))
    };
    // Creating a project in hospital-a needs ml_developer (or admin).
    let create = |t: &T, name: &str| {
        t.call(
            &multi,
            "POST",
            "/v1/projects",
            Some(json!({"organization": "hospital-a", "name": name})),
        )
    };
    let (s, v) = create(&t, "with-the-role");
    assert_eq!(s, 201, "{v}");
    let first = role_id(&t).expect("a-multi holds ml_developer");
    assert!(first.starts_with("rol_"), "{first}");
    let url = t.env0.url.clone();
    let env0 = t.env0;
    drop(t.control);
    let backup = format!("{}_rlbk", url.rsplit('/').next().unwrap());
    backup_database(&url, &backup);
    let t = env0.start().unwrap();
    // The role is removed, and anchored before the answer.
    let v = t.ok(
        &a_admin,
        "POST",
        "/v1/organizations/hospital-a/memberships/remove",
        Some(json!({"principal": principal, "role": "ml_developer"})),
    );
    assert_eq!(v["removed"], json!(["ml_developer"]), "{v}");
    assert!(
        t.control.anchor.snapshot().removed_roles.contains(&first),
        "the removal was acknowledged before it was anchored"
    );
    let (s, _) = create(&t, "after-removal");
    assert_eq!(s, 403);
    let env0 = t.env0;
    drop(t.control);
    restore_database(&backup, &url);
    let e = env0
        .start()
        .err()
        .expect("a restore gave a removed role back silently");
    assert!(e.message.contains("ROLE STATE ROLLBACK"), "{e}");
    assert!(e.message.contains(&first), "{e}");
    let notes = run_recovery(&env0);
    assert!(
        notes
            .iter()
            .any(|n| n.contains(&first) && n.contains("removal re-applied")),
        "{notes:?}"
    );
    let t = env0.start().unwrap();
    assert_eq!(role_id(&t), None);
    let reapplied: i64 = t
        .control
        .db
        .conn()
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_events
              WHERE action = 'membership.removed' AND resource_id = $1
                AND refs->>'memberships' = $2 AND refs->>'reason' = 'anchored_removal_reapplied'",
            &[&principal, &first],
        )
        .unwrap()
        .get(0);
    assert_eq!(reapplied, 1, "the re-applied removal is audited");
    // The principal keeps its other role, and cannot act with the removed one.
    let who = t.ok(&multi, "GET", "/v1/whoami", None);
    assert!(!who.to_string().contains("ml_developer"), "{who}");
    assert!(who.to_string().contains("auditor"), "{who}");
    let (s, v) = create(&t, "after-restore");
    assert_eq!(s, 403, "the removed role is back: {v}");
    // Granting the role again is a new membership (no API grants a role to
    // an existing principal: written directly, as an operator would), and
    // a restart is clean.
    t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "INSERT INTO memberships (principal_id, organization_id, role) VALUES ($1, 'hospital-a', 'ml_developer')",
            &[&principal],
        )
        .unwrap();
    let again = role_id(&t).expect("granted again");
    assert_ne!(again, first);
    let t = t.restart().unwrap();
    let (s, v) = create(&t, "granted-again");
    assert_eq!(s, 201, "{v}");
    t.restart().unwrap();
}

/// Approvals, project memberships and organization roles made before
/// schema version 4 get IDs
/// derived from their content, so a backup from before the upgrade,
/// migrated after a restore, gets the same IDs the anchor may hold.
#[test]
fn approvals_from_before_version_4_get_stable_ids() {
    let ids = |seed: &str| -> Option<Vec<String>> {
        let url = fresh_database()?;
        let db = encompute_control::db::Db::connect(&url).unwrap();
        assert_eq!(db.migrate_to(3).unwrap(), 3);
        db.conn()
            .unwrap()
            .batch_execute(&format!(
                "INSERT INTO organizations (id, display_name, status, policy_namespace) VALUES ('o', 'o', 'active', 'o');
                 INSERT INTO memberships (principal_id, organization_id, role, created_at)
                      VALUES ('usr_1', 'o', 'ml_developer', '2026-07-01T00:00:00Z');
                 INSERT INTO projects (id, organization_id, name, status) VALUES ('p', 'o', 'p', 'active');
                 INSERT INTO project_members (project_id, organization_id, added_by, created_at) VALUES ('p', 'o', '{seed}', '2026-08-01T00:00:00Z');
                 INSERT INTO assets (id, organization_id, kind, name, digest, policy, lineage_root, parents, status, created_by)
                      VALUES ('a', 'o', 'dataset', 'a', 'd', '{{}}', 'a', '[]', 'active', 'u');
                 INSERT INTO asset_approvals (asset_id, project_id, purpose, approved_by, created_at)
                      VALUES ('a', 'p', 'x', '{seed}', '2026-09-01T00:00:00Z');
                 INSERT INTO asset_approval_members (asset_id, project_id, purpose, organization_id, created_at)
                      VALUES ('a', 'p', 'x', 'o', '2026-09-01T00:00:00Z');"
            ))
            .unwrap();
        assert_eq!(db.migrate().unwrap(), 4);
        let r = db
            .conn()
            .unwrap()
            .query_one(
                "SELECT ap.approval_id, am.grant_id, (SELECT membership_id FROM project_members),
                        (SELECT membership_id FROM memberships)
                   FROM asset_approvals ap JOIN asset_approval_members am USING (asset_id)",
                &[],
            )
            .unwrap();
        Some(vec![r.get(0), r.get(1), r.get(2), r.get(3)])
    };
    let Some(a) = ids("u1") else { return };
    let b = ids("u2").unwrap();
    assert_eq!(a, b, "same approval, same IDs");
    assert!(
        a[0].starts_with("apv_")
            && a[1].starts_with("apg_")
            && a[2].starts_with("pmb_")
            && a[3].starts_with("rol_"),
        "{a:?}"
    );
}

/// An rc.3 database (schema version 2) has no approval members: version 3
/// fills them in from the approvals. Restoring the same rc.3 backup into a
/// fresh database and migrating it again must give every row the same ID,
/// or the anchor's withdrawn grants would no longer match (ENC-SF-2026-091).
#[test]
fn a_schema_2_backup_migrated_twice_gets_the_same_ids() {
    let ids = || -> Option<Vec<String>> {
        let url = fresh_database()?;
        let db = encompute_control::db::Db::connect(&url).unwrap();
        assert_eq!(db.migrate_to(2).unwrap(), 2);
        db.conn()
            .unwrap()
            .batch_execute(
                "INSERT INTO organizations (id, display_name, status, policy_namespace)
                      VALUES ('o', 'o', 'active', 'o'), ('q', 'q', 'active', 'q');
                 INSERT INTO memberships (principal_id, organization_id, role, created_at)
                      VALUES ('usr_1', 'o', 'ml_developer', '2026-07-01T00:00:00Z'),
                             ('usr_2', 'q', 'organization_admin', '2026-07-02T00:00:00Z');
                 INSERT INTO projects (id, organization_id, name, status) VALUES ('p', 'o', 'p', 'active');
                 INSERT INTO project_members (project_id, organization_id, added_by, created_at)
                      VALUES ('p', 'o', 'usr_1', '2026-08-01T00:00:00Z'),
                             ('p', 'q', 'usr_1', '2026-08-02T00:00:00Z');
                 INSERT INTO assets (id, organization_id, kind, name, digest, policy, lineage_root, parents, status, created_by)
                      VALUES ('a', 'o', 'dataset', 'a', 'd', '{}', 'a', '[]', 'active', 'u'),
                             ('b', 'q', 'dataset', 'b', 'd', '{}', 'b', '[]', 'active', 'u');
                 INSERT INTO asset_approvals (asset_id, project_id, purpose, approved_by, created_at)
                      VALUES ('a', 'p', 'x', 'usr_1', '2026-09-01T00:00:00Z'),
                             ('b', 'p', 'y', 'usr_2', '2026-09-02T00:00:00Z');",
            )
            .unwrap();
        assert_eq!(db.migrate().unwrap(), 4);
        let mut out = Vec::new();
        for q in [
            "SELECT approval_id FROM asset_approvals ORDER BY asset_id",
            "SELECT grant_id FROM asset_approval_members ORDER BY asset_id, organization_id",
            "SELECT membership_id FROM project_members ORDER BY organization_id",
            "SELECT membership_id FROM memberships ORDER BY principal_id",
        ] {
            for r in db.conn().unwrap().query(q, &[]).unwrap() {
                out.push(r.get::<_, String>(0));
            }
        }
        Some(out)
    };
    let Some(a) = ids() else { return };
    // A later restore of the same backup, migrated at another time.
    std::thread::sleep(std::time::Duration::from_millis(20));
    let b = ids().unwrap();
    assert_eq!(a, b, "the same backup migrated twice gets the same IDs");
    let count = |p: &str| a.iter().filter(|id| id.starts_with(p)).count();
    assert_eq!(
        (count("apv_"), count("apg_"), count("pmb_"), count("rol_")),
        (2, 4, 2, 2),
        "{a:?}"
    );
}
