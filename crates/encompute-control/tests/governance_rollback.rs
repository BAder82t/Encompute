//! INV-226: the governance event log against a database attacker and a
//! restored backup. The state anchor holds only the log's size and head
//! (constant size); every start checks that the database's log verifies,
//! still holds the anchored head at the anchored size, and that nothing it
//! records is undone. Dropping, truncating, reordering or forking the log
//! is refused (GOVERNANCE LOG STATE ROLLBACK), and so is a restore that
//! brings back a revoked authorization, a retired purpose, a revoked
//! governance key or an expired asset. Recovery needs the log's missing
//! events (an export) and re-applies what the log records. A key broker
//! hears of a revocation only once its event is anchored. A version-1
//! anchor (0.3.0) migrates into the log once, with no window in which it
//! could be rolled back.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use std::collections::BTreeSet;

use serde_json::json;

use common::gov::*;
use common::*;
use encompute_control::anchor::{StateAnchor, StateAnchorV1, StoredAnchor};
use encompute_control::govlog::{self, extra_kind, Draft};
use encompute_trust::govlog::Partition;

const LOG_TABLES: &[&str] = &[
    "governance_events",
    "governance_head",
    "governance_tree_nodes",
    "governance_checkpoints",
];

/// Stops the control plane: its environment.
fn stop(t: T) -> Env0 {
    let env0 = t.env0;
    drop(t.control);
    env0
}

/// The start is refused, naming `what`.
fn refused_start(env0: &Env0, what: &str) -> String {
    let e = env0
        .start()
        .err()
        .unwrap_or_else(|| panic!("started although {what} was expected"));
    assert!(e.message.contains(what), "{e}");
    assert_eq!(e.code.as_str(), "ENC2202", "{e}");
    e.message
}

fn stored_anchor(env0: &Env0) -> StoredAnchor {
    StoredAnchor::parse(&std::fs::read(env0.anchor_dir.join("state-anchor.json")).unwrap()).unwrap()
}

fn v2(env0: &Env0) -> StateAnchor {
    match stored_anchor(env0) {
        StoredAnchor::V2(a) => a,
        StoredAnchor::V1(_) => panic!("the stored anchor is still version 1"),
    }
}

fn glog_head(url: &str) -> (i64, String) {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    let r = c
        .query_one("SELECT gseq, hash FROM governance_head WHERE id", &[])
        .unwrap();
    (r.get(0), r.get(1))
}

/// A governed world with a key, a purpose, an active authorization and a
/// second asset: (world, key row, purpose, authorization row, asset).
fn governed() -> Option<(G, String, String, String, String)> {
    let g = gov_world()?;
    let k = key(1);
    let (purpose, version) = g.ready(&k);
    let (row, _) = g.activated(&purpose, &version, &k);
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    let key_row = keys[0]["id"].as_str().unwrap().to_owned();
    let asset = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": TAX, "kind": "dataset", "name": "wages@2026-q1",
                    "series": "wages", "version": "2026-q1", "digest": "e".repeat(64),
                    "ir_policy": registered(TAX)["ir_policy"], "release_class": "boolean-only"}),
        ),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    Some((g, key_row, purpose, row, asset))
}

/// The four governed transitions a restore must not undo.
fn negative_transitions(g: &G, key_row: &str, purpose: &str, row: &str, asset: &str) {
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{row}/revoke"),
        Some(json!({"reason": "withdrawn"})),
    );
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{purpose}/retire"),
        None,
    );
    g.t.ok(
        &g.tax_sec2,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{key_row}/revoke"),
        None,
    );
    assert!(g.t.control.expire_asset("retention", asset).unwrap());
    for (set, id) in [
        (NegSet::RevokedAuthorizations, row),
        (NegSet::RetiredPurposes, purpose),
        (NegSet::RevokedKeys, key_row),
        (NegSet::ExpiredAssets, asset),
    ] {
        assert!(anchored(&g.t, set, id), "{set:?} {id} is not anchored");
    }
}

/// Dropping one anchored event (the last, with the head moved back to
/// match, or one in the middle) is refused at start; so is the log's
/// head row edited alone.
#[test]
fn dropping_one_event_is_refused() {
    let Some((g, key_row, purpose, row, asset)) = governed() else {
        return;
    };
    negative_transitions(&g, &key_row, &purpose, &row, &asset);
    let env0 = stop(g.t);
    let url = env0.url.clone();
    let backup = format!("{}_g1bk", db_name(&url));
    backup_database(&url, &backup);
    let (n, _) = glog_head(&url);
    assert!(n >= 4, "{n}");
    assert_eq!(v2(&env0).glog_size, n, "everything is anchored");
    // The last event, and the head moved back onto the one before it.
    attacker(
        &url,
        LOG_TABLES,
        &format!(
            "DELETE FROM governance_events WHERE gseq = {n};
             UPDATE governance_head SET gseq = {m}, hash = (SELECT hash FROM governance_events WHERE gseq = {m});",
            m = n - 1
        ),
    );
    refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    // One in the middle.
    restore_database(&backup, &url);
    env0.started();
    attacker(
        &url,
        LOG_TABLES,
        "DELETE FROM governance_events WHERE gseq = 2",
    );
    let m = refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    assert!(m.contains("does not verify"), "{m}");
    // The head alone.
    restore_database(&backup, &url);
    attacker(
        &url,
        LOG_TABLES,
        "UPDATE governance_head SET gseq = gseq - 1",
    );
    refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    restore_database(&backup, &url);
    env0.started();
}

/// Truncating one project's events (its partition), or the log's global
/// tail with the head moved back, is refused at start.
#[test]
fn truncating_a_project_or_the_tail_is_refused() {
    let Some((g, key_row, purpose, row, asset)) = governed() else {
        return;
    };
    negative_transitions(&g, &key_row, &purpose, &row, &asset);
    let project = format!("p:{}", g.project);
    let env0 = stop(g.t);
    let url = env0.url.clone();
    let backup = format!("{}_g2bk", db_name(&url));
    backup_database(&url, &backup);
    // The project's partition, its tree and its checkpoints.
    attacker(
        &url,
        LOG_TABLES,
        &format!(
            "DELETE FROM governance_events WHERE partition = '{project}';
             DELETE FROM governance_tree_nodes WHERE partition = '{project}';
             DELETE FROM governance_checkpoints WHERE partition = '{project}';"
        ),
    );
    refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    // The global tail (the last three events), the head moved back and
    // the trees and checkpoints left as they were.
    restore_database(&backup, &url);
    let (n, _) = glog_head(&url);
    attacker(
        &url,
        LOG_TABLES,
        &format!(
            "DELETE FROM governance_events WHERE gseq > {m};
             UPDATE governance_head SET gseq = {m}, hash = (SELECT hash FROM governance_events WHERE gseq = {m});",
            m = n - 3
        ),
    );
    let m = refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    assert!(m.contains(&format!("governance event {n}")), "{m}");
    restore_database(&backup, &url);
    env0.started();
}

/// Swapping two events' positions in the global chain is refused at
/// start.
#[test]
fn swapping_gseq_is_refused() {
    let Some((g, key_row, purpose, row, asset)) = governed() else {
        return;
    };
    negative_transitions(&g, &key_row, &purpose, &row, &asset);
    let env0 = stop(g.t);
    let url = env0.url.clone();
    attacker(
        &url,
        LOG_TABLES,
        "UPDATE governance_events SET gseq = 1000000 WHERE gseq = 1;
         UPDATE governance_events SET gseq = 1 WHERE gseq = 2;
         UPDATE governance_events SET gseq = 2 WHERE gseq = 1000000;",
    );
    refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
}

/// A forked log written with the control plane's own code (every hash,
/// tree node and the head recomputed, as long as the anchored one or
/// longer) still does not hold the anchored head: refused.
#[test]
fn a_forked_chain_with_recomputed_hashes_is_refused() {
    let Some((g, key_row, purpose, row, asset)) = governed() else {
        return;
    };
    negative_transitions(&g, &key_row, &purpose, &row, &asset);
    let env0 = stop(g.t);
    let url = env0.url.clone();
    let (n, _) = glog_head(&url);
    // Everything the log held, dropped; the head back to the start.
    attacker(
        &url,
        LOG_TABLES,
        "DELETE FROM governance_events; DELETE FROM governance_tree_nodes;
         DELETE FROM governance_checkpoints;
         UPDATE governance_head SET gseq = 0,
                hash = '0000000000000000000000000000000000000000000000000000000000000000';",
    );
    // The fork: one more event than the anchored log, nothing revoked.
    let db = encompute_control::db::Db::connect(&url).unwrap();
    db.tx(|t| {
        for i in 0..=n {
            govlog::append(
                t,
                Draft::new(
                    Partition::Platform,
                    govlog::kind::USER_DISABLED,
                    &format!("usr_fork_{i}"),
                ),
            )?;
        }
        Ok(())
    })
    .unwrap();
    {
        let mut c = db.conn().unwrap();
        let (size, _) = govlog::verify_chain(&mut *c).unwrap();
        assert_eq!(size, n + 1, "the fork is a well-formed chain");
    }
    drop(db);
    let m = refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    assert!(m.contains(&format!("governance event {n}")), "{m}");
}

/// A restored backup taken before an authorization was revoked, a purpose
/// retired, a governance key revoked and an asset expired is refused (the
/// log is behind the anchor); recovery without the missing events is
/// refused too; recovery with an export taken before the restore puts the
/// events back, re-applies all four (a retirement and a key revocation at
/// their original time) and the database verifies again. Each of the four
/// undone alone, with the log intact, is refused naming it.
#[test]
fn restores_resurrecting_governed_state_are_refused_and_recovered() {
    let Some((g, key_row, purpose, row, asset)) = governed() else {
        return;
    };
    let env0 = stop(g.t);
    let url = env0.url.clone();
    let backup = format!("{}_g3bk", db_name(&url));
    backup_database(&url, &backup);
    let t = env0.started();
    let g = G { t, ..g };
    negative_transitions(&g, &key_row, &purpose, &row, &asset);
    let retired_at = |t: &T| -> (i64, i64) {
        let mut c = t.control.db.conn().unwrap();
        let r = c
            .query_one(
                "SELECT extract(epoch FROM p.retired_at)::bigint, extract(epoch FROM k.revoked_at)::bigint
                   FROM purposes p, governance_keys k WHERE p.id = $1 AND k.id = $2",
                &[&purpose, &key_row],
            )
            .unwrap();
        (r.get(0), r.get(1))
    };
    let original = retired_at(&g.t);
    let env0 = stop(g.t);
    let export = restore_behind_the_log(&env0, &backup);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let notes = run_recovery_importing(&env0, &export);
    for (id, what) in [
        (row.as_str(), "revocation re-applied"),
        (purpose.as_str(), "retirement re-applied"),
        (key_row.as_str(), "revocation re-applied"),
        (asset.as_str(), "expiry re-applied"),
    ] {
        assert!(
            notes.iter().any(|n| n.contains(id) && n.contains(what)),
            "{id}: {notes:?}"
        );
    }
    assert!(
        notes.iter().any(|n| n.contains("restored from the export")),
        "{notes:?}"
    );
    let t = env0.started();
    // Re-applied at the original time (the event's, within the second the
    // row recorded).
    let again = retired_at(&t);
    assert!(
        (again.0 - original.0).abs() <= 1 && (again.1 - original.1).abs() <= 1,
        "{again:?} vs {original:?}"
    );
    for (set, id) in [
        (NegSet::RevokedAuthorizations, &row),
        (NegSet::RetiredPurposes, &purpose),
        (NegSet::RevokedKeys, &key_row),
        (NegSet::ExpiredAssets, &asset),
    ] {
        assert!(anchored(&t, set, id), "{set:?} {id}");
    }
    let kinds: BTreeSet<String> = t
        .control
        .db
        .conn()
        .unwrap()
        .query("SELECT kind FROM governance_events", &[])
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    for k in [
        "authorization.revoked.reapplied",
        "purpose.retired.reapplied",
        "governance_key.revoked.reapplied",
    ] {
        assert!(kinds.contains(k), "{k}: {kinds:?}");
    }
    // Each one undone alone (the log intact) is refused, naming it.
    let env0 = stop(t);
    let after = format!("{}_g3af", db_name(&url));
    backup_database(&url, &after);
    for (table, sql, what, id) in [
        (
            "authorizations",
            format!("UPDATE authorizations SET status = 'active', revoked_at = NULL, revoked_by = NULL WHERE id = '{row}'"),
            "AUTHORIZATION STATE ROLLBACK",
            &row,
        ),
        (
            "purposes",
            format!("UPDATE purposes SET status = 'active', retired_at = NULL, retired_by = NULL WHERE id = '{purpose}'"),
            "PURPOSE STATE ROLLBACK",
            &purpose,
        ),
        (
            "governance_keys",
            format!("UPDATE governance_keys SET status = 'active', revoked_at = NULL, revoked_by = NULL WHERE id = '{key_row}'"),
            "GOVERNANCE KEY STATE ROLLBACK",
            &key_row,
        ),
        (
            "assets",
            format!("UPDATE assets SET expired_at = NULL WHERE id = '{asset}'"),
            "EXPIRY STATE ROLLBACK",
            &asset,
        ),
    ] {
        attacker(&url, &[table], &sql);
        let m = refused_start(&env0, what);
        assert!(m.contains(id.as_str()), "{m}");
        restore_database(&after, &url);
    }
    env0.started();
}

/// INV-193 on the log: a revocation committed (its event written) but not
/// yet checkpointed is never sent to a key broker; once the log's
/// checkpoint anchors the event, it is.
#[test]
fn authorization_revoked_reaches_the_broker_only_after_the_checkpoint() {
    let Some((g, _, _, row, _)) = governed() else {
        return;
    };
    let m = encompute_control::transport::seal(
        &g.t.control.signer,
        "authorization.revoked",
        "tax-broker",
        encompute_control::transport::Scope {
            organization: Some(TAX.into()),
            ..Default::default()
        },
        &json!({"authorization": row, "revoked_at": now()}),
        300,
    )
    .unwrap();
    // Queued without its event: never sent.
    g.t.control
        .db
        .tx(|c| {
            c.execute(
                "INSERT INTO outbox (message_id, recipient, url, envelope) VALUES ($1, 'tax-broker', 'http://kb.tax:8760', $2)",
                &[&m.message_id, &serde_json::to_value(&m).unwrap()],
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
    g.t.control.tick();
    assert!(g.t.transport.drain().is_empty(), "sent without its event");
    // Its event committed, not yet checkpointed: still not sent.
    let before = g.t.control.anchor.snapshot().glog_size;
    g.t.control
        .db
        .tx(|c| {
            c.execute(
                "UPDATE authorizations SET status = 'revoked', revoked_by = 'x', revoked_at = now() WHERE id = $1",
                &[&row],
            )
            .unwrap();
            let partition = govlog::for_project(c, &g.project, None)?;
            govlog::append(
                c,
                Draft::new(partition, govlog::kind::AUTHORIZATION_REVOKED, &row),
            )?;
            Ok(())
        })
        .unwrap();
    g.t.control.deliver_outbox().unwrap();
    assert!(
        g.t.transport.drain().is_empty(),
        "sent before it was anchored"
    );
    assert!(!anchored(&g.t, NegSet::RevokedAuthorizations, &row));
    assert_eq!(g.t.control.anchor.snapshot().glog_size, before);
    // The checkpoint anchors it; then it is sent.
    g.t.control.checkpoint_log().unwrap();
    assert!(g.t.control.anchor.snapshot().glog_size > before);
    assert!(anchored(&g.t, NegSet::RevokedAuthorizations, &row));
    g.t.control.deliver_outbox().unwrap();
    let sent = g.t.transport.drain();
    assert!(
        sent.iter().any(|(_, x)| x.message_id == m.message_id),
        "{sent:?}"
    );
}

/// The anchor's size does not grow with negative transitions: a hundred
/// disables (each its own event, checkpointed) leave it within a few bytes.
#[test]
fn the_anchor_size_stays_constant() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let before = t.control.anchor.bytes();
    for i in 0..100 {
        let u = user(
            t,
            &w.a_admin,
            "hospital-a",
            &format!("temp-{i}"),
            &["ml_developer"],
        );
        let id = t.ok(&u, "GET", "/v1/whoami", None)["id"]
            .as_str()
            .unwrap()
            .to_owned();
        t.ok(
            &w.a_admin,
            "POST",
            &format!("/v1/organizations/hospital-a/users/{id}/disable"),
            None,
        );
        assert!(anchored(t, NegSet::DisabledUsers, &id));
    }
    let after = t.control.anchor.bytes();
    assert!(
        after <= before + 16,
        "the anchor grew from {before} to {after} bytes"
    );
}

// --- migration from a version-1 anchor (0.3.0) -------------------------------------

/// What 0.3.0 would have anchored for this database: every set the
/// database shows, plus `extra` (each `set:id` also recorded as lost), the
/// frozen ledgers, and the current audit root and ledgers.
fn v1_of(t: &T, frozen: &[String], lost: &[(&str, &str)]) -> StateAnchorV1 {
    let a = t.control.anchor.snapshot();
    let mut v1 = StateAnchorV1::empty(&t.control.signer);
    v1.counter = a.counter;
    v1.audit_seq = a.audit_seq;
    v1.audit_root = a.audit_root.clone();
    v1.ledgers = encompute_control::govlog::ledger_floors(&mut *t.control.db.conn().unwrap())
        .unwrap()
        .into_iter()
        .collect();
    v1.frozen = frozen.iter().cloned().collect();
    let mut c = t.control.db.conn().unwrap();
    let mut ids = |sql: &str| -> BTreeSet<String> {
        c.query(sql, &[])
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect()
    };
    v1.revoked = ids("SELECT id FROM assets WHERE status = 'revoked'");
    v1.disabled_services = ids("SELECT id FROM service_accounts WHERE status = 'disabled'");
    v1.disabled_users = ids("SELECT id FROM users WHERE status = 'disabled'");
    v1.ended_jobs = ids("SELECT id FROM jobs WHERE state IN ('failed', 'cancelled')");
    v1.withdrawn_grants = ids("SELECT id FROM withdrawn_grants");
    v1.removed_memberships = ids("SELECT id FROM removed_memberships");
    v1.removed_roles = ids("SELECT id FROM removed_roles");
    v1.revoked_authorizations = ids("SELECT id FROM authorizations WHERE status = 'revoked'
         UNION SELECT authorization_id FROM authorizations
          WHERE status = 'revoked' AND authorization_id IS NOT NULL");
    v1.expired_assets = ids("SELECT id FROM assets WHERE expired_at IS NOT NULL");
    for (set, id) in lost {
        match *set {
            "authorization" => v1.revoked_authorizations.insert(id.to_string()),
            "job" => v1.ended_jobs.insert(id.to_string()),
            other => panic!("{other}"),
        };
        v1.lost.insert(format!("{set}:{id}"));
    }
    v1.sign(&t.control.signer).unwrap();
    v1
}

/// Turns `env0`'s deployment into a 0.3.0 one: no governance log (as
/// before schema version 13's events), `v1` stored as its anchor.
fn as_version_1(env0: &Env0, v1: &StateAnchorV1) {
    attacker(
        &env0.url,
        &[
            "governance_events",
            "governance_head",
            "governance_tree_nodes",
            "governance_checkpoints",
            "governance_anchor_genesis",
        ],
        "DELETE FROM governance_events; DELETE FROM governance_tree_nodes;
         DELETE FROM governance_checkpoints; DELETE FROM governance_anchor_genesis;
         UPDATE governance_head SET gseq = 0,
                hash = '0000000000000000000000000000000000000000000000000000000000000000';",
    );
    // 0.3.0 kept no mirror of the log either.
    let _ = std::fs::remove_dir_all(env0.anchor_dir.join("governance-log"));
    std::fs::write(
        env0.anchor_dir.join("state-anchor.json"),
        serde_json::to_vec_pretty(v1).unwrap(),
    )
    .unwrap();
}

/// The version-1 set of `set`.
fn v1_set(v1: &StateAnchorV1, set: NegSet) -> BTreeSet<String> {
    match set {
        NegSet::RevokedAssets => v1.revoked.clone(),
        NegSet::DisabledServices => v1.disabled_services.clone(),
        NegSet::DisabledUsers => v1.disabled_users.clone(),
        NegSet::EndedJobs => v1.ended_jobs.clone(),
        NegSet::WithdrawnGrants => v1.withdrawn_grants.clone(),
        NegSet::RemovedMemberships => v1.removed_memberships.clone(),
        NegSet::RemovedRoles => v1.removed_roles.clone(),
        NegSet::RevokedAuthorizations => v1.revoked_authorizations.clone(),
        NegSet::ExpiredAssets => v1.expired_assets.clone(),
        NegSet::FrozenLedgers => v1.frozen.clone(),
        NegSet::RetiredPurposes | NegSet::RevokedKeys => BTreeSet::new(),
    }
}

/// A standard world in which every set of a version-1 anchor holds
/// something: a revoked and an expired asset, a disabled service account
/// and user, a cancelled job, a withdrawn approval and an ended grant, a
/// removed project membership and organization role; a frozen ledger; and
/// a revoked authorization and an ended job whose rows were lost.
fn every_set() -> Option<(T, StateAnchorV1)> {
    let w = world()?;
    let t = &w.t;
    let project = w.project.clone();
    let sa = encompute_verification::ServiceSigner::from_seed("secagg-7", &[37; 32]).unwrap();
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({"id": "secagg-7", "kind": "secagg", "public_key": sa.public_key_hex()})),
    );
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts/secagg-7/disable",
        None,
    );
    let leaver = user(
        t,
        &w.a_admin,
        "hospital-a",
        "a-leaver",
        &["ml_developer", "auditor"],
    );
    let leaver_id = t.ok(&leaver, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    t.ok(
        &w.a_admin,
        "POST",
        "/v1/organizations/hospital-a/memberships/remove",
        Some(json!({"principal": leaver_id, "role": "ml_developer"})),
    );
    t.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/organizations/hospital-a/users/{leaver_id}/disable"),
        None,
    );
    let plan = w.plan(&exact_own(&w.model_b));
    let (_, j) = w.job(&plan, &[&w.model_b], "to-cancel");
    let job = j["id"].as_str().unwrap().to_owned();
    t.ok(&w.b_dev, "POST", &format!("/v1/jobs/{job}/cancel"), None);
    for (who, asset) in [(&w.a_owner, &w.dataset_a), (&w.b_owner, &w.model_b)] {
        t.ok(
            who,
            "POST",
            &format!("/v1/assets/{asset}/approvals"),
            Some(json!({"project": project, "purpose": "medical-training"})),
        );
    }
    t.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{}/approvals/withdraw", w.dataset_a),
        Some(json!({"project": project, "purpose": "medical-training"})),
    );
    t.ok(
        &w.b_admin,
        "POST",
        &format!("/v1/projects/{project}/members/remove"),
        Some(json!({"organization": "hospital-a"})),
    );
    t.ok(
        &w.b_owner,
        "POST",
        &format!("/v1/assets/{}/revoke", w.model_b),
        None,
    );
    assert!(t.control.expire_asset("retention", &w.dataset_a).unwrap());
    // A frozen ledger (recovery froze it under 0.3.0).
    t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE privacy_ledgers SET frozen_reason = 'frozen by recovery' WHERE asset_id = $1",
            &[&w.dataset_a],
        )
        .unwrap();
    let v1 = v1_of(
        t,
        std::slice::from_ref(&w.dataset_a),
        &[("authorization", "aut_lost_1"), ("job", "job_lost_1")],
    );
    for set in NegSet::ALL {
        if !matches!(set, NegSet::RetiredPurposes | NegSet::RevokedKeys) {
            assert!(!v1_set(&v1, set).is_empty(), "{set:?} is empty");
        }
    }
    Some((w.t, v1))
}

/// A 0.3.0 deployment whose anchor holds every set, a frozen ledger and
/// lost rows migrates at the first start: the log's sets equal the
/// anchor's, the lost rows are recorded lost, the genesis event's digest
/// is the stored version-1 anchor's (kept beside it, signature intact),
/// and the anchor is version 2, recording where it came from. It starts
/// again unchanged, and a version-2 anchor is never read as version 1.
#[test]
fn a_version_1_anchor_with_every_set_migrates() {
    let Some((t, v1)) = every_set() else { return };
    let env0 = stop(t);
    as_version_1(&env0, &v1);
    let t = env0.started();
    let a = v2(&env0);
    let from = a.migrated_from.clone().expect("migrated");
    assert_eq!(from.counter, v1.counter);
    assert_eq!(from.digest, v1.digest().unwrap());
    assert_eq!(a.counter, v1.counter + 1);
    assert_eq!(a.audit_seq, v1.audit_seq);
    // Each ledger's checkpoint became a log event, the latest its floor.
    let floors: std::collections::BTreeMap<_, _> =
        encompute_control::govlog::ledger_floors(&mut *t.control.db.conn().unwrap())
            .unwrap()
            .into_iter()
            .collect();
    assert_eq!(floors, v1.ledgers);
    for set in NegSet::ALL {
        let logged: BTreeSet<String> = log_set(&t, set).into_iter().collect();
        assert_eq!(logged, v1_set(&v1, set), "{set:?}");
        for id in &logged {
            assert!(anchored(&t, set, id), "{set:?} {id}");
        }
    }
    assert!(is_lost(&t, "aut_lost_1") && is_lost(&t, "job_lost_1"));
    // The genesis: its digest, and the anchor kept beside it.
    let mut c = t.control.db.conn().unwrap();
    let r = c
        .query_one(
            "SELECT e.gseq, e.body #>> '{refs,digest}', g.anchor, g.digest FROM governance_events e
               JOIN governance_anchor_genesis g ON g.gseq = e.gseq WHERE e.kind = $1",
            &[&extra_kind::ANCHOR_GENESIS],
        )
        .unwrap();
    let (gseq, digest, kept, kept_digest): (i64, String, String, String) =
        (r.get(0), r.get(1), r.get(2), r.get(3));
    assert_eq!(gseq, 1);
    assert_eq!(digest, from.digest);
    assert_eq!(kept_digest, from.digest);
    assert_eq!(
        encompute_verification::service::sha256_hex(kept.as_bytes()),
        from.digest
    );
    let back: StateAnchorV1 = serde_json::from_str(&kept).unwrap();
    back.verify(&t.control.signer.public_key_hex()).unwrap();
    assert_eq!(back, v1);
    drop(c);
    // Constant size: no ID of the sets is in it.
    let stored = std::fs::read_to_string(env0.anchor_dir.join("state-anchor.json")).unwrap();
    for id in v1_set(&v1, NegSet::EndedJobs) {
        assert!(!stored.contains(&id), "{id} is in the anchor");
    }
    // An earlier release refuses it (fail closed: no downgrade).
    assert!(serde_json::from_str::<StateAnchorV1>(&stored).is_err());
    // Starts again, unchanged.
    let env0 = stop(t);
    let t = env0.started();
    assert_eq!(v2(&env0), a);
    drop(t);
}

/// Each ledger checkpoint of a version-1 anchor becomes a
/// `privacy.ledger_checkpoint` event after the genesis (platform partition,
/// the entry count and root, nothing else), the ledger's floor from then on;
/// the version-2 anchor holds none of them, and a ledger restored behind its
/// migrated floor is refused at the next start.
#[test]
fn v1_anchor_ledgers_migrate_to_log_events() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    for i in 0..2 {
        let (s, _) = w.t.call(
            &w.a_owner,
            "POST",
            &format!("/v1/privacy/{d}/events"),
            Some(reserve(&format!("s-{i}"), 200)),
        );
        assert_eq!(s, 200);
    }
    let v1 = v1_of(&w.t, &[], &[]);
    assert_eq!(v1.ledgers[&d].seq, 2);
    let env0 = stop(w.t);
    as_version_1(&env0, &v1);
    let t = env0.started();
    let mut c = t.control.db.conn().unwrap();
    let events = c
        .query(
            "SELECT subject_id, body -> 'refs', body ->> 'partition', gseq FROM governance_events
              WHERE kind = $1 ORDER BY gseq",
            &[&extra_kind::LEDGER_CHECKPOINT],
        )
        .unwrap();
    assert_eq!(events.len(), v1.ledgers.len());
    for r in &events {
        let asset: String = r.get(0);
        let refs: serde_json::Value = r.get(1);
        let cp = &v1.ledgers[&asset];
        assert_eq!(refs["seq"], json!(cp.seq.to_string()), "{asset}");
        assert_eq!(refs["root"], json!(cp.root), "{asset}");
        assert_eq!(refs.as_object().unwrap().len(), 2);
        assert_eq!(r.get::<_, String>(2), "platform");
        assert!(r.get::<_, i64>(3) > 1, "after the genesis");
    }
    let floor = t.control.ledger_floor(&d).unwrap().unwrap();
    assert_eq!(floor, v1.ledgers[&d]);
    drop(c);
    // The anchor holds none of it, and records where it came from.
    let a = v2(&env0);
    assert_eq!(a.migrated_from.unwrap().counter, v1.counter);
    let stored = std::fs::read_to_string(env0.anchor_dir.join("state-anchor.json")).unwrap();
    assert!(!stored.contains("ledgers") && !stored.contains(&d));
    // The ledger restored behind the migrated floor is refused.
    let env0 = stop(t);
    attacker(
        &env0.url,
        &["privacy_entries"],
        &format!("DELETE FROM privacy_entries WHERE asset_id = '{d}' AND seq = 2"),
    );
    refused_start(&env0, "PRIVACY STATE ROLLBACK");
}

/// A crash between the genesis transaction and the anchor's replacement
/// leaves the version-1 anchor and the migrated log: the next start only
/// replaces the anchor. If anything but the migration's events followed
/// the genesis (the anchor store was rolled back afterwards), or the log
/// was migrated from another anchor, the start is refused.
#[test]
fn a_crash_between_genesis_and_the_anchor_resumes() {
    let Some((t, v1)) = every_set() else { return };
    let env0 = stop(t);
    as_version_1(&env0, &v1);
    // The migration ran; the anchor's replacement is lost.
    let t = env0.started();
    let migrated = v2(&env0);
    let env0 = stop(t);
    std::fs::write(
        env0.anchor_dir.join("state-anchor.json"),
        serde_json::to_vec_pretty(&v1).unwrap(),
    )
    .unwrap();
    let before = glog_head(&env0.url);
    let t = env0.started();
    assert_eq!(glog_head(&env0.url), before, "nothing migrated twice");
    let a = v2(&env0);
    assert_eq!(a.migrated_from, migrated.migrated_from);
    assert_eq!(
        (a.glog_size, &a.glog_head),
        (migrated.glog_size, &migrated.glog_head)
    );
    // The log moves on; then the version-1 anchor is put back: refused.
    let u = user(
        &t,
        &As::User("a-admin".into()),
        "hospital-a",
        "a-late",
        &["ml_developer"],
    );
    let late = t.ok(&u, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    t.ok(
        &As::User("a-admin".into()),
        "POST",
        &format!("/v1/organizations/hospital-a/users/{late}/disable"),
        None,
    );
    let env0 = stop(t);
    std::fs::write(
        env0.anchor_dir.join("state-anchor.json"),
        serde_json::to_vec_pretty(&v1).unwrap(),
    )
    .unwrap();
    let m = refused_start(&env0, "ANCHOR STATE ROLLBACK");
    assert!(m.contains("moved on"), "{m}");
    // Another version-1 anchor than the one migrated: refused.
    let mut other = v1.clone();
    other.counter += 5;
    other
        .sign(
            &encompute_verification::ServiceSigner::from_seed("control-plane", &env0.seed).unwrap(),
        )
        .unwrap();
    std::fs::write(
        env0.anchor_dir.join("state-anchor.json"),
        serde_json::to_vec_pretty(&other).unwrap(),
    )
    .unwrap();
    let m = refused_start(&env0, "ANCHOR STATE ROLLBACK");
    assert!(m.contains("another version-1 state anchor"), "{m}");
}

/// A version-1 anchor the database does not extend (a revoked asset shown
/// active) is never migrated: the start is refused with 0.3.0's refusal,
/// the log stays empty and the anchor stays version 1.
#[test]
fn a_version_1_anchor_failing_its_checks_is_never_migrated() {
    let Some((t, v1)) = every_set() else { return };
    let revoked = v1.revoked.iter().next().unwrap().clone();
    let env0 = stop(t);
    as_version_1(&env0, &v1);
    attacker(
        &env0.url,
        &["assets"],
        &format!("UPDATE assets SET status = 'active', revoked_at = NULL WHERE id = '{revoked}'"),
    );
    let m = refused_start(&env0, "REVOCATION STATE ROLLBACK");
    assert!(m.contains("was not migrated"), "{m}");
    assert_eq!(glog_head(&env0.url).0, 0, "nothing was migrated");
    assert!(matches!(stored_anchor(&env0), StoredAnchor::V1(ref a) if *a == v1));
    // Nor can recovery run on it with this release.
    let db = encompute_control::db::Db::connect(&env0.url).unwrap();
    let signer =
        encompute_verification::ServiceSigner::from_seed("control-plane", &env0.seed).unwrap();
    let store =
        Box::new(encompute_control::anchor::DirAnchor::new(env0.anchor_dir.clone()).unwrap());
    let e = encompute_control::Control::for_recovery(&recovery_config(&env0), db, signer, store)
        .err()
        .expect("recovered a version-1 anchor");
    assert!(e.message.contains("version 1"), "{e}");
}

/// An empty 0.3.0 deployment (an anchor with empty sets) migrates: the
/// genesis event alone.
#[test]
fn an_empty_version_1_anchor_migrates() {
    let Some(t) = setup() else { return };
    let v1 = v1_of(&t, &[], &[]);
    let env0 = stop(t);
    as_version_1(&env0, &v1);
    let t = env0.started();
    let a = v2(&env0);
    assert_eq!(a.glog_size, 1, "the genesis event alone");
    assert_eq!(a.migrated_from.unwrap().digest, v1.digest().unwrap());
    for set in NegSet::ALL {
        assert!(log_set(&t, set).is_empty(), "{set:?}");
    }
}

// --- the governance log mirror in the anchor store --------------------------------

fn mirror_dir(env0: &Env0) -> std::path::PathBuf {
    env0.anchor_dir.join("governance-log")
}

/// The mirror's segment files, in segment-number order.
fn segment_files(env0: &Env0) -> Vec<std::path::PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(mirror_dir(env0))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    v.sort();
    v
}

/// The path of segment `n`.
fn segment(env0: &Env0, n: u64) -> std::path::PathBuf {
    mirror_dir(env0).join(format!("{n:012}.jsonl"))
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    let _ = std::fs::remove_dir_all(to);
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

/// The events the mirror's segments hold, in segment order (a segment
/// starting at event 1 begins again).
fn mirror_events(env0: &Env0) -> Vec<govlog::Exported> {
    let mut out: Vec<govlog::Exported> = vec![];
    for f in segment_files(env0) {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        let Ok(events) = text
            .lines()
            .map(serde_json::from_str::<govlog::Exported>)
            .collect::<Result<Vec<_>, _>>()
        else {
            continue;
        };
        if events.first().is_some_and(|e| e.gseq == 1) {
            out.clear();
        }
        out.extend(events);
    }
    out
}

/// Appends `n` events in one transaction.
fn fill(t: &T, prefix: &str, n: usize) {
    t.control
        .db
        .tx(|tx| {
            for i in 0..n {
                govlog::append(
                    tx,
                    Draft::new(
                        Partition::Platform,
                        govlog::kind::ROLE_REMOVED,
                        &format!("{prefix}_{i}"),
                    ),
                )?;
            }
            Ok(())
        })
        .unwrap();
}

fn in_log(url: &str, subject: &str) -> bool {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    c.query_opt(
        "SELECT 1 FROM governance_events WHERE subject_id = $1",
        &[&subject],
    )
    .unwrap()
    .is_some()
}

fn append_role_removal(t: &T, id: &str) {
    t.control
        .db
        .tx(|tx| {
            govlog::append(
                tx,
                Draft::new(Partition::Platform, govlog::kind::ROLE_REMOVED, id),
            )
            .map(|_| ())
        })
        .unwrap();
}

/// Every checkpoint writes the mirror before the anchor; after a backup
/// older than the anchor is restored, recovery takes the missing events
/// from the mirror on its own, exactly up to the anchored head, and
/// re-applies what they record.
#[test]
fn old_backup_restore_recovers_from_mirror() {
    let Some((g, key_row, purpose, row, asset)) = governed() else {
        return;
    };
    let env0 = stop(g.t);
    let backup = format!("{}_m1bk", db_name(&env0.url));
    backup_database(&env0.url, &backup);
    let g = G {
        t: env0.started(),
        ..g
    };
    negative_transitions(&g, &key_row, &purpose, &row, &asset);
    let env0 = stop(g.t);
    let a = v2(&env0);
    assert!(mirror_events(&env0).len() as i64 >= a.glog_size);
    restore_database(&backup, &env0.url);
    refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    let notes = run_recovery(&env0);
    assert!(
        notes
            .iter()
            .any(|n| n.contains("from the mirror")
                && n.contains(&format!("(event {})", a.glog_size))),
        "{notes:?}"
    );
    for (id, what) in [
        (row.as_str(), "revocation re-applied"),
        (purpose.as_str(), "retirement re-applied"),
        (key_row.as_str(), "revocation re-applied"),
        (asset.as_str(), "expiry re-applied"),
    ] {
        assert!(
            notes.iter().any(|n| n.contains(id) && n.contains(what)),
            "{id}: {notes:?}"
        );
    }
    let t = env0.started();
    assert!(anchored(&t, NegSet::RevokedAuthorizations, &row));
}

/// A crash between the mirror's write and the anchor's update (the
/// anchor store refuses the write): the call fails, the old anchor stays
/// authoritative, the mirrored suffix is an orphan. Recovery after a
/// restore replays exactly up to the anchored head, never the orphan, and
/// the next checkpoint replaces the orphan with the database's own events.
#[test]
fn mirror_written_before_anchor_cas() {
    let Some(t) = setup() else { return };
    let env0 = stop(t);
    let backup = format!("{}_m2bk", db_name(&env0.url));
    backup_database(&env0.url, &backup);
    let (t, fail) = env0.start_flaky();
    append_role_removal(&t, "rol_anchored");
    t.control.checkpoint_log().unwrap();
    let anchored_size = t.control.anchor.snapshot().glog_size;
    append_role_removal(&t, "rol_orphan");
    fail.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(t.control.checkpoint_log().is_err());
    assert_eq!(t.control.anchor.snapshot().glog_size, anchored_size);
    let env0 = stop(t);
    // The mirror was written first: it holds the orphan; the anchor does not.
    assert_eq!(v2(&env0).glog_size, anchored_size);
    let m = mirror_events(&env0);
    assert_eq!(m.len() as i64, anchored_size + 1);
    assert_eq!(m.last().unwrap().event.subject, "rol_orphan");
    // The old anchor wins: the start accepts it and ignores the orphan.
    let t = env0.started();
    assert_eq!(t.control.anchor.snapshot().glog_size, anchored_size);
    let env0 = stop(t);
    // A restore older than the anchor: recovery replays the mirror up to
    // the anchored head only.
    restore_database(&backup, &env0.url);
    refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    run_recovery(&env0);
    assert!(in_log(&env0.url, "rol_anchored"));
    assert!(!in_log(&env0.url, "rol_orphan"), "the orphan was replayed");
    // The next checkpoint mirrors the database's own event in its place.
    let t = env0.started();
    append_role_removal(&t, "rol_after");
    t.control.checkpoint_log().unwrap();
    let env0 = stop(t);
    let m = mirror_events(&env0);
    assert!(m.iter().all(|e| e.event.subject != "rol_orphan"), "{m:?}");
    assert!(m.iter().any(|e| e.event.subject == "rol_after"));
    env0.started();
}

/// A mirror truncated, reordered, forked (with recomputed hashes) or
/// edited is refused at start; recovery rebuilds it from a database that
/// extends the anchor. A truncated mirror cannot recover an older backup.
#[test]
fn truncated_mirror_is_refused() {
    let Some((g, key_row, purpose, row, asset)) = governed() else {
        return;
    };
    let env0 = stop(g.t);
    let backup = format!("{}_m3bk", db_name(&env0.url));
    backup_database(&env0.url, &backup);
    let g = G {
        t: env0.started(),
        ..g
    };
    negative_transitions(&g, &key_row, &purpose, &row, &asset);
    let env0 = stop(g.t);
    let saved = env0.anchor_dir.join("mirror-copy");
    copy_dir(&mirror_dir(&env0), &saved);
    // Truncated: the segment's last two events are gone.
    let seg = segment(&env0, 1);
    let text = std::fs::read_to_string(&seg).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    lines.truncate(lines.len() - 2);
    std::fs::write(&seg, lines.join("\n") + "\n").unwrap();
    let m = refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    assert!(m.contains("truncated"), "{m}");
    // Recovery cannot bring an older backup back with it.
    let live = format!("{}_m3lv", db_name(&env0.url));
    backup_database(&env0.url, &live);
    restore_database(&backup, &env0.url);
    {
        let db = encompute_control::db::Db::connect(&env0.url).unwrap();
        let signer =
            encompute_verification::ServiceSigner::from_seed("control-plane", &env0.seed).unwrap();
        let store =
            Box::new(encompute_control::anchor::DirAnchor::new(env0.anchor_dir.clone()).unwrap());
        let rc =
            encompute_control::Control::for_recovery(&recovery_config(&env0), db, signer, store)
                .unwrap();
        let e = rc
            .recover("operator-1")
            .expect_err("recovered from a truncated mirror");
        assert!(e.message.contains("RECOVERY REFUSED"), "{e}");
    }
    // With the live database back, recovery rebuilds the mirror.
    restore_database(&live, &env0.url);
    let notes = run_recovery(&env0);
    assert!(
        notes.iter().any(|n| n.contains("mirror: rebuilt")),
        "{notes:?}"
    );
    env0.started();
}

/// Each segment is bound to the anchored head: reordering segments, a
/// forked rewrite with recomputed hashes, or one edited event is refused
/// at start.
#[test]
fn tampered_mirror_segment_is_refused() {
    let Some((g, key_row, purpose, row, asset)) = governed() else {
        return;
    };
    // More than one segment: 600 events (500 to a segment).
    fill(&g.t, "rol_bulk", 600);
    negative_transitions(&g, &key_row, &purpose, &row, &asset);
    let env0 = stop(g.t);
    assert!(segment_files(&env0).len() >= 2);
    let saved = env0.anchor_dir.join("mirror-copy");
    copy_dir(&mirror_dir(&env0), &saved);
    let restore = || copy_dir(&saved, &mirror_dir(&env0));
    // Reordered: the first two segments swap places.
    let (s1, s2) = (segment(&env0, 1), segment(&env0, 2));
    std::fs::rename(&s1, mirror_dir(&env0).join("swap")).unwrap();
    std::fs::rename(&s2, &s1).unwrap();
    std::fs::rename(mirror_dir(&env0).join("swap"), &s2).unwrap();
    let m = refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    // The segment starting at event 1 begins the mirror again.
    assert!(m.contains("truncated"), "{m}");
    restore();
    // Reordered within a segment: two lines swap.
    let text = std::fs::read_to_string(&s1).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    lines.swap(3, 4);
    std::fs::write(&s1, lines.join("\n") + "\n").unwrap();
    let m = refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    assert!(m.contains("not contiguous"), "{m}");
    restore();
    // Edited: one event's time changes.
    let seg = &segment(&env0, 1);
    let text = std::fs::read_to_string(seg).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let mut x: govlog::Exported = serde_json::from_str(&lines[0]).unwrap();
    x.event.at += 1;
    lines[0] = serde_json::to_string(&x).unwrap();
    std::fs::write(seg, lines.join("\n") + "\n").unwrap();
    let m = refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    assert!(m.contains("modified"), "{m}");
    restore();
    // Forked: a full rewrite whose second event names something else, every
    // hash after it recomputed.
    let mut events = mirror_events(&env0);
    events[1].event.subject = "rol_forged".into();
    let mut prev = encompute_trust::govlog::CHAIN_GENESIS;
    for e in events.iter_mut() {
        let h = encompute_trust::govlog::chain_hash(
            &prev,
            e.gseq as u64,
            &e.event.leaf_hash().unwrap(),
        );
        e.hash = encompute_trust::govlog::hash_hex(&h);
        prev = h;
    }
    // (A rewrite starting at event 1, in segments of its own after the
    // others.)
    let next = segment_files(&env0).len() as u64 + 1;
    for (i, chunk) in events.chunks(500).enumerate() {
        std::fs::write(
            segment(&env0, next + i as u64),
            govlog::to_lines(chunk).unwrap(),
        )
        .unwrap();
    }
    let m = refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    assert!(m.contains("another history"), "{m}");
    restore();
    env0.started();
}

/// A migrated asset revocation reaches its owner's partition and every
/// governed project that uses the asset.
#[test]
fn a_migrated_asset_revocation_reaches_every_using_project() {
    let Some((g, _, _, row, _)) = governed() else {
        return;
    };
    let asset: String =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT asset_id FROM authorizations WHERE id = $1", &[&row])
            .unwrap()
            .get(0);
    g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/assets/{asset}/revoke"),
        None,
    );
    let v1 = v1_of(&g.t, &[], &[]);
    assert!(v1.revoked.contains(&asset));
    let project = format!("p:{}", g.project);
    let env0 = stop(g.t);
    as_version_1(&env0, &v1);
    let t = env0.started();
    let partitions: BTreeSet<String> = t
        .control
        .db
        .conn()
        .unwrap()
        .query(
            "SELECT partition FROM governance_events WHERE kind = 'migrated.revoked' AND subject_id = $1",
            &[&asset],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(
        partitions,
        [format!("o:{TAX}"), project].into_iter().collect(),
    );
}

/// The migration reads 0.3.0's checks, its sets and writes their events
/// in one snapshot under the log's head lock: a transition committed
/// concurrently waits for the migration and is then logged after it, as
/// its own event, never lost between the snapshot and the events.
#[test]
fn a_concurrent_writer_cannot_escape_the_migration_snapshot() {
    let Some(w) = world() else { return };
    let dev = w.t.ok(&w.a_dev, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let v1 = v1_of(&w.t, &[], &[]);
    let env0 = stop(w.t);
    as_version_1(&env0, &v1);
    let writer: std::sync::Arc<std::sync::Mutex<Option<std::thread::JoinHandle<()>>>> =
        Default::default();
    let blocked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (writer, blocked, url, dev) = (
            writer.clone(),
            blocked.clone(),
            env0.url.clone(),
            dev.clone(),
        );
        encompute_control::set_migration_test_hook(Some(Box::new(move || {
            let (url, dev) = (url.clone(), dev.clone());
            let h = std::thread::spawn(move || {
                let mut c = postgres::Client::connect(&url, postgres::NoTls).unwrap();
                let mut tx = c.transaction().unwrap();
                tx.execute(
                    "UPDATE users SET status = 'disabled' WHERE id = $1",
                    &[&dev],
                )
                .unwrap();
                govlog::append(
                    &mut tx,
                    Draft::new(
                        Partition::Organization("hospital-a".into()),
                        govlog::kind::USER_DISABLED,
                        &dev,
                    )
                    .org("hospital-a"),
                )
                .unwrap();
                tx.commit().unwrap();
            });
            std::thread::sleep(std::time::Duration::from_millis(500));
            blocked.store(!h.is_finished(), std::sync::atomic::Ordering::SeqCst);
            *writer.lock().unwrap() = Some(h);
        })));
    }
    let t = env0.started();
    encompute_control::set_migration_test_hook(None);
    writer.lock().unwrap().take().unwrap().join().unwrap();
    assert!(
        blocked.load(std::sync::atomic::Ordering::SeqCst),
        "the writer was not held back by the migration"
    );
    let mut c = t.control.db.conn().unwrap();
    let migrated: i64 = c
        .query_one(
            "SELECT count(*) FROM governance_events WHERE kind = 'migrated.disabled_users' AND subject_id = $1",
            &[&dev],
        )
        .unwrap()
        .get(0);
    assert_eq!(migrated, 0, "the snapshot predates the writer");
    let (own, last_migration): (i64, i64) = {
        let r = c
            .query_one(
                "SELECT (SELECT gseq FROM governance_events WHERE kind = 'user.disabled' AND subject_id = $1),
                        (SELECT max(gseq) FROM governance_events WHERE kind LIKE 'migrated.%' OR kind = 'anchor.genesis')",
                &[&dev],
            )
            .unwrap();
        (r.get(0), r.get(1))
    };
    assert!(own > last_migration, "{own} {last_migration}");
    drop(c);
    let env0 = stop(t);
    env0.started();
}

/// A deny event's API call returns only once its checkpoint (mirror, then
/// anchor) is durable: on success the revocation is already anchored and
/// its broker message deliverable at once.
#[test]
fn a_revocation_is_anchored_when_its_call_returns() {
    let Some((g, key_row, purpose, row, asset)) = governed() else {
        return;
    };
    negative_transitions(&g, &key_row, &purpose, &row, &asset);
    // (negative_transitions asserts each is anchored right after its call,
    // with no background tick in between.)
    let m = encompute_control::transport::seal(
        &g.t.control.signer,
        "authorization.revoked",
        "tax-broker",
        encompute_control::transport::Scope {
            organization: Some(TAX.into()),
            ..Default::default()
        },
        &json!({"authorization": row, "revoked_at": now()}),
        300,
    )
    .unwrap();
    g.t.control
        .db
        .tx(|c| {
            c.execute(
                "INSERT INTO outbox (message_id, recipient, url, envelope) VALUES ($1, 'tax-broker', 'http://kb.tax:8760', $2)",
                &[&m.message_id, &serde_json::to_value(&m).unwrap()],
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
    g.t.control.deliver_outbox().unwrap();
    assert!(g
        .t
        .transport
        .drain()
        .iter()
        .any(|(_, x)| x.message_id == m.message_id));
    let env0 = stop(g.t);
    let mirrored = mirror_events(&env0);
    assert!(mirrored.iter().any(|e| e.event.subject == row));
}

/// When the forced checkpoint of a deny event fails, the call fails
/// (the change is committed and the database enforces it); a retry is
/// idempotent and anchors it.
#[test]
fn a_failed_forced_checkpoint_fails_the_call_and_a_retry_anchors_it() {
    let Some(w) = world() else { return };
    let World { t, a_admin, .. } = w;
    let u = user(&t, &a_admin, "hospital-a", "a-temp", &["ml_developer"]);
    let id = t.ok(&u, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let env0 = stop(t);
    let (t, fail) = env0.start_flaky();
    fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let path = format!("/v1/organizations/hospital-a/users/{id}/disable");
    let (s, v) = t.call(&a_admin, "POST", &path, None);
    assert!(s >= 500, "{s} {v}");
    assert_eq!(v["code"], "ENC2202", "{v}");
    assert!(!anchored(&t, NegSet::DisabledUsers, &id));
    // The database enforces it already: the user is disabled.
    assert_eq!(t.call(&u, "GET", "/v1/whoami", None).0, 401);
    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    t.ok(&a_admin, "POST", &path, None);
    assert!(anchored(&t, NegSet::DisabledUsers, &id));
}

// --- the mirror's segments: damage, caps, writers, crashes ------------------------

/// A control plane with an empty log started and stopped: its environment.
fn plain() -> Option<Env0> {
    setup().map(stop)
}

fn checkpoint_one(t: &T, id: &str) {
    append_role_removal(t, id);
    t.control.checkpoint_log().unwrap();
}

/// A segment torn while the service runs (a partial write, however it
/// came about) does not wedge checkpointing: the writer takes where the
/// mirror ends from the database, ignores the damaged segment and writes
/// the events whole; the next start accepts it.
#[test]
fn torn_newest_segment_does_not_wedge_checkpointing() {
    let Some(env0) = plain() else { return };
    let t = env0.started();
    checkpoint_one(&t, "rol_a");
    let env0 = stop(t);
    let t = env0.started();
    let seg = segment(&env0, 1);
    let text = std::fs::read_to_string(&seg).unwrap();
    std::fs::write(&seg, &text[..text.len() - 40]).unwrap();
    checkpoint_one(&t, "rol_b");
    checkpoint_one(&t, "rol_c");
    let env0 = stop(t);
    let events = mirror_events(&env0);
    assert_eq!(events.len() as i64, v2(&env0).glog_size);
    env0.started();
}

/// Garbage planted as the newest segment (the next number, or a far one)
/// does not wedge checkpointing either, nor block the next start.
#[test]
fn garbage_planted_segment_does_not_wedge_checkpointing() {
    let Some(env0) = plain() else { return };
    let t = env0.started();
    checkpoint_one(&t, "rol_a");
    std::fs::write(segment(&env0, 2), "not json at all\n").unwrap();
    std::fs::write(segment(&env0, 999), "{\"gseq\": 1}\n").unwrap();
    // Too large to read: refused as a segment, ignored.
    std::fs::write(segment(&env0, 1000), "x".repeat(600 * 1024)).unwrap();
    let env1 = stop(t);
    let t = env1.started();
    for i in 0..3 {
        checkpoint_one(&t, &format!("rol_b{i}"));
    }
    let env0 = stop(t);
    assert_eq!(mirror_events(&env0).len() as i64, v2(&env0).glog_size);
    env0.started();
}

/// Recovery's rebuild ignores damaged segments and writes the mirror
/// again, as a run starting at event 1 after every segment there is.
#[test]
fn rebuild_ignores_damaged_segments() {
    let Some(env0) = plain() else { return };
    let t = env0.started();
    fill(&t, "rol_bulk", 600);
    checkpoint_one(&t, "rol_a");
    let env0 = stop(t);
    assert!(segment_files(&env0).len() >= 2);
    std::fs::write(segment(&env0, 1), "garbage\n").unwrap();
    std::fs::write(segment(&env0, 2), "").unwrap();
    refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    let notes = run_recovery(&env0);
    assert!(
        notes.iter().any(|n| n.contains("mirror: rebuilt")),
        "{notes:?}"
    );
    let t = env0.started();
    checkpoint_one(&t, "rol_after");
    let env0 = stop(t);
    env0.started();
}

/// Checkpoints do not pile up segments: each extends the open one.
#[test]
fn many_small_checkpoints_do_not_create_many_segments() {
    let Some(env0) = plain() else { return };
    let t = env0.started();
    for i in 0..60 {
        checkpoint_one(&t, &format!("rol_{i}"));
    }
    let env0 = stop(t);
    let n = segment_files(&env0).len();
    assert!(n <= 2, "{n} segments for 60 one-event checkpoints");
    assert_eq!(mirror_events(&env0).len() as i64, v2(&env0).glog_size);
    env0.started();
}

/// A segment stays under the byte cap (far below an OpenBao KV entry's
/// 1 MiB) however large its events are, and the events all arrive.
#[test]
fn segment_byte_cap_respected() {
    let Some(env0) = plain() else { return };
    let t = env0.started();
    t.control
        .db
        .tx(|tx| {
            for i in 0..100 {
                let mut d = Draft::new(
                    Partition::Platform,
                    govlog::kind::ROLE_REMOVED,
                    &format!("rol_big_{i}"),
                );
                for a in 'a'..='z' {
                    d = d.r#ref(&format!("k{a}"), "x".repeat(250));
                }
                govlog::append(tx, d)?;
            }
            Ok(())
        })
        .unwrap();
    t.control.checkpoint_log().unwrap();
    checkpoint_one(&t, "rol_after");
    let env0 = stop(t);
    let files = segment_files(&env0);
    assert!(files.len() >= 3, "{} segments", files.len());
    for f in &files {
        let len = std::fs::metadata(f).unwrap().len() as usize;
        assert!(
            len <= encompute_control::mirror::SEGMENT_BYTES + 16 * 1024,
            "{} is {len} bytes",
            f.display()
        );
    }
    assert_eq!(mirror_events(&env0).len() as i64, v2(&env0).glog_size);
    env0.started();
}

/// Two writers racing for one segment: exactly one create wins, the other
/// fails closed (and a replace is atomic).
#[test]
fn two_writers_one_segment() {
    use encompute_control::anchor::{AnchorStore, DirAnchor};
    let dir = tmp_dir("two-writers");
    let store = std::sync::Arc::new(DirAnchor::new(dir).unwrap());
    for round in 1..=20u64 {
        let results: Vec<_> = (0..2)
            .map(|w| {
                let s = store.clone();
                std::thread::spawn(move || s.mirror_create(round, &format!("writer {w}\n")))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "{results:?}"
        );
        let e = results.iter().find_map(|r| r.as_ref().err()).unwrap();
        assert!(e.message.contains("written concurrently"), "{e}");
        let text = store.mirror_read(round).unwrap();
        assert!(text == "writer 0\n" || text == "writer 1\n");
    }
    store.mirror_replace(1, "replaced\n", &|_| Ok(())).unwrap();
    assert_eq!(store.mirror_read(1).unwrap(), "replaced\n");
    assert!(store.mirror_replace(99, "x\n", &|_| Ok(())).is_err());
}

/// A mirror whose newest segment differs from the database's log at or
/// below the anchored size is refused by the writer (tampering), not
/// overwritten silently.
#[test]
fn a_mirror_differing_below_the_anchored_size_is_refused_by_the_writer() {
    let Some(env0) = plain() else { return };
    let t = env0.started();
    checkpoint_one(&t, "rol_a");
    let env0 = stop(t);
    let t = env0.started();
    let seg = segment(&env0, 1);
    let text = std::fs::read_to_string(&seg).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let last = lines.len() - 1;
    let mut x: govlog::Exported = serde_json::from_str(&lines[last]).unwrap();
    x.hash = "ab".repeat(32);
    lines[last] = serde_json::to_string(&x).unwrap();
    std::fs::write(&seg, lines.join("\n") + "\n").unwrap();
    append_role_removal(&t, "rol_b");
    let e = t
        .control
        .checkpoint_log()
        .expect_err("overwrote a tampered mirror");
    assert!(e.message.contains("GOVERNANCE LOG STATE ROLLBACK"), "{e}");
    assert!(e.message.contains("differs"), "{e}");
}

/// Leftover temporary files (a crash while writing an anchor or a
/// segment) are ignored and do not block anything.
#[test]
fn leftover_tmp_files_are_ignored() {
    let Some(env0) = plain() else { return };
    let t = env0.started();
    checkpoint_one(&t, "rol_a");
    std::fs::write(env0.anchor_dir.join(".state-anchor.json.1.1.tmp"), "junk").unwrap();
    std::fs::write(
        mirror_dir(&env0).join(".000000000001.jsonl.1.1.tmp"),
        "junk",
    )
    .unwrap();
    std::fs::write(mirror_dir(&env0).join("000000000002.jsonl.tmp"), "junk").unwrap();
    checkpoint_one(&t, "rol_b");
    let env0 = stop(t);
    env0.started();
    // No temporary file of ours is left behind by normal operation.
    let t = env0.started();
    checkpoint_one(&t, "rol_c");
    let env0 = stop(t);
    let left: Vec<_> = std::fs::read_dir(&env0.anchor_dir)
        .unwrap()
        .chain(std::fs::read_dir(mirror_dir(&env0)).unwrap())
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp") && !n.contains(".1.1.") && n != "000000000002.jsonl.tmp")
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

/// The child of [`a_real_kill_between_the_mirror_and_the_anchor`]: runs
/// only when started by it.
#[test]
fn real_kill_child() {
    let (Ok(url), Ok(dir)) = (
        std::env::var("ENCOMPUTE_KILL_URL"),
        std::env::var("ENCOMPUTE_KILL_DIR"),
    ) else {
        return;
    };
    let env0 = Env0 {
        url,
        anchor_dir: dir.into(),
        seed: [42; 32],
        oidc: vec![],
        env: encompute_control::config::Env::Development,
    };
    let (t, armed) = env0.start_killable();
    append_role_removal(&t, "rol_killed");
    armed.store(true, std::sync::atomic::Ordering::SeqCst);
    // The mirror is written, then the process dies at the anchor's write.
    let _ = t.control.checkpoint_log();
    std::process::exit(0);
}

/// A real crash (a child process killed between the mirror's write and the
/// anchor's compare-and-set): the old anchor wins, the mirrored suffix is
/// an orphan that is not replayed, and the next checkpoint replaces it.
#[test]
fn a_real_kill_between_the_mirror_and_the_anchor() {
    if std::env::var("ENCOMPUTE_KILL_URL").is_ok() {
        return;
    }
    let Some(t) = setup() else { return };
    checkpoint_one(&t, "rol_anchored");
    let env0 = stop(t);
    let before = v2(&env0);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "real_kill_child", "--test-threads=1"])
        .env("ENCOMPUTE_KILL_URL", &env0.url)
        .env("ENCOMPUTE_KILL_DIR", &env0.anchor_dir)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(137), "{status:?}");
    assert_eq!(v2(&env0), before, "the anchor was not updated");
    let m = mirror_events(&env0);
    assert_eq!(m.last().unwrap().event.subject, "rol_killed");
    assert!(m.len() as i64 > before.glog_size);
    // The old anchor wins; the orphan is not in the mirror's anchored part.
    let t = env0.started();
    assert_eq!(t.control.anchor.snapshot().glog_size, before.glog_size);
    // The database kept the killed event (it committed): the next
    // checkpoint anchors it and the mirror agrees with the database.
    t.control.checkpoint_log().unwrap();
    let env0 = stop(t);
    assert_eq!(mirror_events(&env0).len() as i64, v2(&env0).glog_size);
    env0.started();
}

/// Whichever path appends a deny event, the transaction that did is
/// followed by a checkpoint before the call returns; an event that is not
/// a deny event (an issued authorization) is left to the background task.
#[test]
fn a_deny_event_on_any_path_is_anchored_before_the_call_returns() {
    let Some(env0) = plain() else { return };
    let t = env0.started();
    t.control
        .tx_anchored(|tx| {
            govlog::append(
                tx,
                Draft::new(Partition::Platform, govlog::kind::JOB_FAILED, "job_x"),
            )
            .map(|_| ())
        })
        .unwrap();
    assert!(anchored(&t, NegSet::EndedJobs, "job_x"));
    let size = t.control.anchor.snapshot().glog_size;
    t.control
        .tx_anchored(|tx| {
            govlog::append(
                tx,
                Draft::new(
                    Partition::Platform,
                    govlog::kind::AUTHORIZATION_ISSUED,
                    "atz_x",
                ),
            )
            .map(|_| ())
        })
        .unwrap();
    assert_eq!(t.control.anchor.snapshot().glog_size, size, "batched");
}

/// The first lines of segment `n` as events.
fn read_segment(env0: &Env0, n: u64) -> Vec<govlog::Exported> {
    std::fs::read_to_string(segment(env0, n))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// A parseable segment of events `from..=to` that the database does not
/// hold (a planted one).
fn plant(env0: &Env0, n: u64, from: i64, to: i64) {
    let base = read_segment(env0, 1).pop().unwrap();
    let mut out = vec![];
    for g in from..=to {
        let mut x = base.clone();
        x.gseq = g;
        x.hash = format!("{g:064x}");
        out.push(x);
    }
    std::fs::write(segment(env0, n), govlog::to_lines(&out).unwrap()).unwrap();
}

/// A planted, parseable newest segment that starts far past the log used
/// to make the writer write nothing and still let the anchor move: the
/// mirror must hold every anchored event before the anchor moves.
#[test]
fn planted_far_ahead_segment_cannot_skip_the_write() {
    let Some(env0) = plain() else { return };
    let t = env0.started();
    checkpoint_one(&t, "rol_a");
    let env0 = stop(t);
    let t = env0.started();
    let size = t.control.anchor.snapshot().glog_size;
    plant(&env0, 2, size + 10, size + 11);
    checkpoint_one(&t, "rol_b");
    let env0 = stop(t);
    let a = v2(&env0);
    assert_eq!(read_segment(&env0, 1).len() as i64, a.glog_size);
    env0.started();
}

/// A planted segment that overlaps what the writer writes (a gap before
/// it) is rewritten: the mirror is extended from the last valid segment,
/// the planted one blanked, and the next start accepts the result.
#[test]
fn planted_segment_with_gap_is_rewritten() {
    let Some(env0) = plain() else { return };
    let t = env0.started();
    checkpoint_one(&t, "rol_a");
    let env0 = stop(t);
    let t = env0.started();
    let size = t.control.anchor.snapshot().glog_size;
    for i in 0..5 {
        append_role_removal(&t, &format!("rol_gap{i}"));
    }
    plant(&env0, 2, size + 3, size + 4);
    t.control.checkpoint_log().unwrap();
    let env0 = stop(t);
    let a = v2(&env0);
    assert_eq!(a.glog_size, size + 5);
    assert_eq!(read_segment_len(&env0, 1), a.glog_size);
    env0.started();
}

fn read_segment_len(env0: &Env0, n: u64) -> i64 {
    read_segment(env0, n).len() as i64
}

/// A writer with a stale view (an older database, an older anchor in
/// memory) cannot shrink or fork a segment another control plane anchored
/// further: the replacement is refused and the mirror is untouched.
#[test]
fn stale_writer_cannot_shrink_an_anchored_segment() {
    let Some(env0) = plain() else { return };
    let t = env0.started();
    checkpoint_one(&t, "rol_a");
    let env0 = stop(t);
    // A copy of the database as it is now, for the stale writer.
    let old_db = format!("{}_stale", db_name(&env0.url));
    backup_database(&env0.url, &old_db);
    let old_url = {
        let (base, _) = env0.url.rsplit_once('/').unwrap();
        format!("{base}/{old_db}")
    };
    let stale_env = Env0 {
        url: old_url,
        anchor_dir: env0.anchor_dir.clone(),
        seed: env0.seed,
        oidc: vec![],
        env: env0.env,
    };
    let stale = stale_env.started();
    let live = env0.started();
    for i in 0..3 {
        checkpoint_one(&live, &format!("rol_live{i}"));
    }
    let anchored = live.control.anchor.snapshot().glog_size;
    let before = std::fs::read_to_string(segment(&env0, 1)).unwrap();
    // The stale writer's database has another event at the next position.
    append_role_removal(&stale, "rol_stale");
    let e = stale
        .control
        .checkpoint_log()
        .expect_err("a stale writer rewrote an anchored mirror");
    assert!(
        e.message.contains("GOVERNANCE LOG STATE ROLLBACK")
            || e.message.contains("refusing to replace"),
        "{e}"
    );
    assert_eq!(std::fs::read_to_string(segment(&env0, 1)).unwrap(), before);
    assert_eq!(read_segment_len(&env0, 1), anchored);
    drop(stale);
    drop(live);
    env0.started();
}

/// A deny event appended where a call returns `Ok(Err(..))` (the receipt
/// failure shape) through `tx_anchored` is anchored; a failing checkpoint
/// fails the call and keeps the obligation, which the next call settles.
#[test]
fn complete_job_receipt_failure_is_anchored() {
    let Some(env0) = plain() else { return };
    let (t, fail) = env0.start_flaky();
    let r: encompute_ir::Result<encompute_ir::Result<()>> = t.control.tx_anchored(|tx| {
        govlog::append(
            tx,
            Draft::new(Partition::Platform, govlog::kind::JOB_FAILED, "job_receipt"),
        )?;
        Ok(Err(encompute_ir::Error::new(
            encompute_ir::Code::Receipt,
            "the receipt does not verify",
        )))
    });
    assert!(r.unwrap().is_err());
    assert!(anchored(&t, NegSet::EndedJobs, "job_receipt"));
    // A failing checkpoint fails the call; the change is committed.
    fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let r: encompute_ir::Result<()> = t.control.tx_anchored(|tx| {
        govlog::append(
            tx,
            Draft::new(
                Partition::Platform,
                govlog::kind::JOB_FAILED,
                "job_receipt2",
            ),
        )
        .map(|_| ())
    });
    assert!(r.is_err());
    assert!(!anchored(&t, NegSet::EndedJobs, "job_receipt2"));
    // The obligation survives: the next call (even a plain read) settles it.
    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    t.control.tx_anchored(|_| Ok(())).unwrap();
    assert!(anchored(&t, NegSet::EndedJobs, "job_receipt2"));
}

/// A flag a plain transaction left on this thread does not make an
/// unrelated call checkpoint.
#[test]
fn flag_does_not_leak_between_calls() {
    let Some(env0) = plain() else { return };
    let t = env0.started();
    let size = t.control.anchor.snapshot().glog_size;
    t.control
        .db
        .tx(|tx| {
            govlog::append(
                tx,
                Draft::new(Partition::Platform, govlog::kind::JOB_FAILED, "job_plain"),
            )
            .map(|_| ())
        })
        .unwrap();
    t.control.tx_anchored(|_| Ok(())).unwrap();
    assert_eq!(t.control.anchor.snapshot().glog_size, size, "leaked");
    assert!(!anchored(&t, NegSet::EndedJobs, "job_plain"));
}

/// Cancelling a job is anchored when the call returns.
#[test]
fn cancel_job_is_anchored() {
    let Some(w) = world() else { return };
    let plan = w.plan(&exact_own(&w.model_b));
    let (_, j) = w.job(&plan, &[&w.model_b], "to-cancel-anchored");
    let job = j["id"].as_str().unwrap().to_owned();
    w.t.ok(&w.b_dev, "POST", &format!("/v1/jobs/{job}/cancel"), None);
    assert!(anchored(&w.t, NegSet::EndedJobs, &job));
}
