//! Persistent state: privacy spending is race-safe, idempotent, survives
//! restarts, and cannot be rolled back by restoring an older database; the
//! audit chain is tamper-evident and anchored the same way.

mod common;

use std::sync::Arc;

use common::*;
use serde_json::json;

use encompute_control::audit::{AuditDraft, Outcome};

fn spent(w: &World, d: &str) -> f64 {
    w.t.ok(&w.a_auditor, "GET", &format!("/v1/privacy/{d}"), None)["spent"]["epsilon"]
        .as_f64()
        .unwrap()
}

#[test]
fn privacy_spending_is_race_safe_and_idempotent() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    // How many releases of this cost fit the budget (epsilon 3)?
    let sigma2 = 18;
    let ev: encompute_privacy::PrivacyEvent =
        serde_json::from_value(reserve("probe", sigma2)).unwrap();
    let budget = encompute_ir::confidentiality::PrivacyBudget {
        unit: encompute_ir::confidentiality::PrivacyUnit::Patient,
        epsilon: 3.0,
        delta: 1e-6,
    };
    let fits =
        encompute_privacy::ledger::affordable(ev.rho().unwrap(), None, &budget).unwrap() as usize;
    assert!(
        fits > 1 && fits < 16,
        "choose sigma2 so the race is meaningful: {fits}"
    );
    let w = Arc::new(w);
    let results: Vec<u16> = (0..16)
        .map(|i| {
            let (w, d) = (w.clone(), d.clone());
            std::thread::spawn(move || {
                let (s, v) = w.t.call(
                    &w.a_owner,
                    "POST",
                    &format!("/v1/privacy/{d}/events"),
                    Some(reserve(&format!("race-{i}"), sigma2)),
                );
                if s == 409 {
                    assert_eq!(v["code"], "ENC2201", "{v}");
                }
                s
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    assert_eq!(
        results.iter().filter(|s| **s == 200).count(),
        fits,
        "{results:?}"
    );
    assert_eq!(results.iter().filter(|s| **s == 409).count(), 16 - fits);
    let before = spent(&w, &d);
    assert!(before <= 3.0);
    // Duplicate delivery of a recorded event: not charged twice.
    let (s, v) = w.t.call(
        &w.a_owner,
        "POST",
        &format!("/v1/privacy/{d}/events"),
        Some(reserve("race-0", sigma2)),
    );
    if results[0] == 200 {
        assert_eq!(s, 200);
        assert_eq!(v["duplicate"], true);
    }
    assert_eq!(spent(&w, &d), before);
    // The same event ID with other contents is a conflict.
    let (s, _) = w.t.call(
        &w.a_owner,
        "POST",
        &format!("/v1/privacy/{d}/events"),
        Some(reserve("race-0", sigma2 + 1)),
    );
    assert!(s == 409);
    // Denials are audited, and the ledger verifies.
    let export = w.t.ok(
        &w.a_auditor,
        "GET",
        &format!("/v1/privacy/{d}/ledger"),
        None,
    );
    let view: encompute_privacy::LedgerView = serde_json::from_value(export).unwrap();
    view.verify().unwrap();
    assert_eq!(view.entries.len(), fits);
    let audit = w.t.ok(&w.a_auditor, "GET", "/v1/audit?limit=1000", None);
    assert!(audit
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["action"] == "privacy.denied"));
}

#[test]
fn restart_keeps_spending_and_restoring_an_older_backup_is_refused() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    for i in 0..3 {
        w.t.ok(
            &w.a_owner,
            "POST",
            &format!("/v1/privacy/{d}/events"),
            Some(reserve(&format!("s-{i}"), 200)),
        );
    }
    let after3 = spent(&w, &d);
    let World {
        t,
        a_owner,
        a_auditor,
        ..
    } = w;
    let url = t.env0.url.clone();
    // Restart: the spending is still there.
    let t = t.restart().unwrap();
    let view = |t: &T| t.ok(&a_auditor, "GET", &format!("/v1/privacy/{d}"), None);
    assert_eq!(view(&t)["spent"]["epsilon"].as_f64().unwrap(), after3);
    // Back up now, spend more, then restore the older backup.
    let env0 = t.env0;
    drop(t.control);
    let backup = format!("{}_backup", url.rsplit('/').next().unwrap());
    backup_database(&url, &backup);
    let t = env0.start().unwrap();
    t.ok(
        &a_owner,
        "POST",
        &format!("/v1/privacy/{d}/events"),
        Some(reserve("s-after-backup", 200)),
    );
    let spent4 = view(&t)["spent"]["epsilon"].as_f64().unwrap();
    assert!(spent4 > after3);
    let env0 = t.env0;
    drop(t.control);
    restore_database(&backup, &url);
    let e = env0
        .start()
        .err()
        .expect("an older backup started silently");
    assert!(
        e.message.contains("PRIVACY STATE ROLLBACK") || e.message.contains("AUDIT STATE ROLLBACK"),
        "{e}"
    );
    assert!(e.message.contains("STARTUP REFUSED"), "{e}");

    // Explicit recovery: the rolled-back ledger is frozen (exhausted), so
    // the forgotten spending can never be spent again.
    let db = encompute_control::db::Db::connect(&url).unwrap();
    let signer =
        encompute_verification::ServiceSigner::from_seed("control-plane", &env0.seed).unwrap();
    let store =
        Box::new(encompute_control::anchor::DirAnchor::new(env0.anchor_dir.clone()).unwrap());
    let cfg = encompute_control::config::Config {
        env: encompute_control::config::Env::Development,
        listen: "127.0.0.1:0".into(),
        service_id: "control-plane".into(),
        database_url: zeroize::Zeroizing::new(url.clone()),
        signing_key_file: None,
        oidc: vec![],
        dev_token_secret: None,
        anchor: encompute_control::config::AnchorConfig::Dir(env0.anchor_dir.clone()),
        audit_checkpoint_every: 5,
    };
    let rc = encompute_control::Control::for_recovery(&cfg, db, signer, store).unwrap();
    let notes = rc.recover("operator-1").unwrap();
    assert!(
        notes.iter().any(|n| n.contains(&d) && n.contains("frozen")),
        "{notes:?}"
    );
    drop(rc);
    let t = env0.start().unwrap();
    let v = view(&t);
    assert!(v["frozen"].as_str().unwrap().contains("rolled back"), "{v}");
    let (s, v) = t.call(
        &a_owner,
        "POST",
        &format!("/v1/privacy/{d}/events"),
        Some(reserve("after-recovery", 200)),
    );
    assert_eq!(s, 409, "{v}");
    assert_eq!(v["code"], "ENC2201");
    // The recovery is on the record.
    let audit = t.ok(&a_auditor, "GET", "/v1/audit?limit=1000", None);
    assert!(!audit.as_array().unwrap().is_empty());
    let mut c = t.control.db.conn().unwrap();
    let frozen: i64 = c
        .query_one(
            "SELECT count(*) FROM audit_events WHERE action = 'privacy.ledger.frozen'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(frozen, 1);
}

#[test]
fn audit_chain_is_tamper_evident_and_anchored() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let cp = t.ok(&w.platform, "POST", "/v1/audit/checkpoints", None);
    assert!(cp["seq"].as_i64().unwrap() > 5);
    let cp: encompute_control::audit::AuditCheckpoint = serde_json::from_value(cp).unwrap();
    cp.verify(&t.control.signer.public_key_hex()).unwrap();
    // Payload-shaped references are refused: audit carries identifiers only.
    let mut c = t.control.db.conn().unwrap();
    let e = encompute_control::audit::append(
        &mut *c,
        AuditDraft::new("x", "r", "test", "asset", "a1", Outcome::Succeeded)
            .r#ref("note", "patient name: Jane Doe"),
    )
    .unwrap_err();
    assert_eq!(e.code, encompute_ir::Code::BadInput);
    // Editing an event breaks the chain; startup refuses.
    c.execute(
        "UPDATE audit_events SET action = 'asset.approved' WHERE seq = 3",
        &[],
    )
    .unwrap();
    assert!(encompute_control::audit::verify_chain(&mut *c).is_err());
    drop(c);
    let env0 = w.t.env0;
    drop(w.t.control);
    let e = env0.start().err().expect("a tampered audit chain started");
    assert!(e.message.contains("modified"), "{e}");
}

#[test]
fn truncated_audit_and_tampered_or_missing_anchor_are_refused() {
    let Some(w) = world() else { return };
    w.t.ok(&w.platform, "POST", "/v1/audit/checkpoints", None);
    let env0 = w.t.env0;
    drop(w.t.control);
    // Deleting the anchored tail of the chain (and fixing the head row, as
    // an attacker with database access would) is detected.
    {
        let mut c = postgres::Client::connect(&env0.url, postgres::NoTls).unwrap();
        let head: i64 = c
            .query_one("SELECT seq FROM audit_head", &[])
            .unwrap()
            .get(0);
        c.batch_execute(&format!(
            "DELETE FROM audit_events WHERE seq > {n};
             UPDATE audit_head SET seq = {n}, hash = (SELECT hash FROM audit_events WHERE seq = {n})",
            n = head - 2
        ))
        .unwrap();
    }
    let e = env0.start().err().expect("a truncated audit trail started");
    assert!(e.message.contains("AUDIT STATE ROLLBACK"), "{e}");

    // A tampered anchor (signature) is refused.
    let Some(w) = world() else { return };
    let env0 = w.t.env0;
    drop(w.t.control);
    let p = env0.anchor_dir.join("state-anchor.json");
    let mut a: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    a["ledgers"] = json!({});
    std::fs::write(&p, serde_json::to_vec(&a).unwrap()).unwrap();
    let e = env0.start().err().expect("a tampered anchor was accepted");
    assert!(e.message.contains("signature"), "{e}");
    // A missing anchor with a populated database is refused.
    std::fs::remove_file(&p).unwrap();
    let e = env0.start().err().expect("a missing anchor was accepted");
    assert!(e.message.contains("missing"), "{e}");
}

#[test]
fn secagg_privacy_events_arrive_once_through_messages() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let d = w.dataset_a.clone();
    let sa =
        Arc::new(encompute_verification::ServiceSigner::from_seed("secagg-1", &[31; 32]).unwrap());
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({"id": "secagg-1", "kind": "secagg", "public_key": sa.public_key_hex()})),
    );
    let ev: encompute_privacy::PrivacyEvent =
        serde_json::from_value(reserve("round-7-release", 200)).unwrap();
    // A SecAgg service the owner did not authorize cannot spend this
    // tenant's budget (even though it is a platform service).
    let (s, v) = t.call(
        &As::Service(sa.clone()),
        "POST",
        &format!("/v1/privacy/{d}/events"),
        Some(reserve("rogue", 200)),
    );
    assert_eq!(s, 404, "{v}");
    let spender = |who: &As, svc: &str| {
        t.call(
            who,
            "POST",
            &format!("/v1/privacy/{d}/spenders"),
            Some(json!({"service": svc})),
        )
        .0
    };
    assert_eq!(
        spender(&w.b_owner, "secagg-1"),
        404,
        "another tenant cannot authorize spenders"
    );
    assert_eq!(
        spender(&w.a_owner, "evaluator-1"),
        400,
        "only SecAgg services spend"
    );
    assert_eq!(spender(&w.a_owner, "secagg-1"), 200);
    let m = encompute_verification::service::seal(
        &sa,
        "privacy.event",
        "control-plane",
        encompute_verification::service::Scope {
            round: Some("round-7".into()),
            ..Default::default()
        },
        &json!({"asset": d, "event": ev}),
        300,
    )
    .unwrap();
    let body = serde_json::to_value(&m).unwrap();
    let first = t.ok(
        &As::Service(sa.clone()),
        "POST",
        "/v1/messages",
        Some(body.clone()),
    );
    let again = t.ok(&As::Service(sa.clone()), "POST", "/v1/messages", Some(body));
    assert_eq!(first["duplicate"], false);
    assert_eq!(again["duplicate"], true);
    let v = t.ok(&w.a_auditor, "GET", &format!("/v1/privacy/{d}"), None);
    assert_eq!(v["entries"], 1);
    // The same event re-sent in a new message (a redelivery by the
    // coordinator) is recognized by its event ID: still one entry.
    let m2 = encompute_verification::service::seal(
        &sa,
        "privacy.event",
        "control-plane",
        Default::default(),
        &json!({"asset": d, "event": ev}),
        300,
    )
    .unwrap();
    let r = t.ok(
        &As::Service(sa),
        "POST",
        "/v1/messages",
        Some(serde_json::to_value(&m2).unwrap()),
    );
    assert_eq!(r["duplicate"], true);
    let v = t.ok(&w.a_auditor, "GET", &format!("/v1/privacy/{d}"), None);
    assert_eq!(v["entries"], 1);
}

#[test]
fn revocation_racing_submissions_leaves_no_usable_job() {
    let Some(w) = world() else { return };
    let plan = w.plan(EXACT);
    let w = Arc::new(w);
    let submitters: Vec<_> = (0..8)
        .map(|i| {
            let (w, plan) = (w.clone(), plan.clone());
            std::thread::spawn(move || {
                let (s, v) = w.job(&plan, &[&w.model_b], &format!("race-{i}"));
                assert!(s == 201 || s == 409, "{s} {v}");
            })
        })
        .collect();
    let revoker = {
        let w = w.clone();
        std::thread::spawn(move || {
            w.t.ok(
                &w.b_owner,
                "POST",
                &format!("/v1/assets/{}/revoke", w.model_b),
                None,
            );
        })
    };
    for h in submitters {
        h.join().unwrap();
    }
    revoker.join().unwrap();
    // Whatever the interleaving: no job that uses the revoked model can
    // still start.
    let mut c = w.t.control.db.conn().unwrap();
    let live: i64 = c
        .query_one(
            "SELECT count(*) FROM jobs WHERE source_assets ? $1 AND state NOT IN ('failed', 'cancelled')",
            &[&w.model_b],
        )
        .unwrap()
        .get(0);
    assert_eq!(live, 0);
}

#[test]
fn concurrent_policy_approvals_apply_once() {
    let Some(w) = world() else { return };
    let p = w.t.ok(
        &w.b_sec,
        "POST",
        &format!("/v1/projects/{}/policies", w.project),
        Some(json!({"retention_days": 30})),
    );
    let id = p["id"].as_str().unwrap().to_owned();
    // The author cannot approve its own policy.
    let (s, _) = w.t.call(
        &w.b_sec,
        "POST",
        &format!("/v1/policies/{id}/approve"),
        None,
    );
    assert_eq!(s, 403);
    let w = Arc::new(w);
    let results: Vec<u16> = (0..6)
        .map(|_| {
            let (w, id) = (w.clone(), id.clone());
            std::thread::spawn(move || {
                w.t.call(
                    &w.b_sec2,
                    "POST",
                    &format!("/v1/policies/{id}/approve"),
                    None,
                )
                .0
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    assert_eq!(
        results.iter().filter(|s| **s == 200).count(),
        1,
        "{results:?}"
    );
    assert!(results.iter().all(|s| *s == 200 || *s == 409));
    let mut c = w.t.control.db.conn().unwrap();
    let n: i64 = c
        .query_one(
            "SELECT count(*) FROM audit_events WHERE action = 'policy.approved'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(n, 1);
}
