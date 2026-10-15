//! ENC-SF-2026-412 and its closure (0.3.1): a privacy ledger is spendable only
//! when the state anchor holds its genesis checkpoint. A ledger row the
//! anchor has no checkpoint for (a creation whose anchoring failed, a row a
//! database writer inserted or re-inserted) refuses every spend (ENC2202)
//! until the operator anchors it deliberately (`anchor_unanchored`, the
//! `encompute-control anchor-ledgers` command), audited.
//!
//! The attacker owns the database and acts while the service runs, without
//! the signing key or the anchor store. Spends go through the HTTP API as a
//! normal data owner.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::*;
use serde_json::{json, Value};

const HONEST_CAP_NOTE: &str = "an honest epsilon-3 cap is a handful of spends";

fn spend(t: &T, who: &As, d: &str, ev: &str) -> (u16, Value) {
    t.call(
        who,
        "POST",
        &format!("/v1/privacy/{d}/events"),
        Some(reserve(ev, 18)),
    )
}

/// Spends until the first refusal, at most `max`: how many were acknowledged.
fn spends_accepted(t: &T, who: &As, d: &str, max: usize) -> usize {
    let mut n = 0;
    while n < max && spend(t, who, d, &format!("x-{n}")).0 == 200 {
        n += 1;
    }
    n
}

fn sql(url: &str, q: &str) {
    postgres::Client::connect(url, postgres::NoTls)
        .unwrap()
        .batch_execute(q)
        .unwrap();
}

fn inflate_sql(id: &str) -> String {
    format!("UPDATE privacy_ledgers SET genesis = jsonb_set(genesis, '{{budget,epsilon}}', '\"3000.0\"'::jsonb) WHERE asset_id='{id}'")
}

/// SQL a writer runs to give `id` a ledger of its own: another ledger's
/// genesis with the asset changed and the budget raised 1000-fold.
fn forge_ledger_sql(id: &str, template: &str) -> String {
    format!(
        "INSERT INTO privacy_ledgers (asset_id, organization_id, genesis)
         SELECT '{id}', 'hospital-a', jsonb_set(jsonb_set(genesis, '{{asset_id}}', to_jsonb('{id}'::text)), '{{budget,epsilon}}', '\"3000.0\"'::jsonb)
         FROM privacy_ledgers WHERE asset_id='{template}'"
    )
}

fn asset_id_by_name(url: &str, name: &str) -> String {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    c.query_one("SELECT id FROM assets WHERE name=$1", &[&name])
        .unwrap()
        .get(0)
}

fn register(t: &T, who: &As, name: &str, with_budget: bool) -> (u16, Value) {
    let mut body = json!({"organization": "hospital-a", "kind": "dataset", "name": name, "digest": "9".repeat(64)});
    if with_budget {
        body["privacy_budget"] = budget(3.0);
    }
    t.call(who, "POST", "/v1/assets", Some(body))
}

fn refused_unanchored(s: u16, v: &Value) -> bool {
    s == 500
        && v["code"] == "ENC2202"
        && v["message"]
            .as_str()
            .is_some_and(|m| m.contains("not anchored"))
}

/// Runs `acting` while a database-owner session queues ACCESS EXCLUSIVE on
/// `tables` behind the call's write to the first of them (granted the instant
/// the call commits), runs `attack_sql` there, and only then lets the
/// service's post-commit read proceed.
fn in_window<R: Send>(
    url: &str,
    tables: &[&str],
    attack_sql: &str,
    acting: impl FnOnce() -> R + Send,
) -> R {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    c.batch_execute(
        "CREATE OR REPLACE FUNCTION atk_sleep() RETURNS trigger AS $$ BEGIN PERFORM pg_sleep(1.0); RETURN NULL; END $$ LANGUAGE plpgsql;
         DROP TRIGGER IF EXISTS atk_slow ON audit_events;
         CREATE TRIGGER atk_slow AFTER INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION atk_sleep();",
    )
    .unwrap();
    let done = AtomicBool::new(false);
    let r = std::thread::scope(|s| {
        let h = s.spawn(|| {
            let mut a = postgres::Client::connect(url, postgres::NoTls).unwrap();
            let me: i32 = a.query_one("SELECT pg_backend_pid()", &[]).unwrap().get(0);
            loop {
                let n: i64 = a
                    .query_one(
                        "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
                         WHERE c.relname=$1 AND l.mode='RowExclusiveLock' AND l.granted AND l.pid<>$2",
                        &[&tables[0], &me],
                    )
                    .unwrap()
                    .get(0);
                if n > 0 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let mut tx = a.transaction().unwrap();
            tx.batch_execute(&format!(
                "LOCK TABLE {} IN ACCESS EXCLUSIVE MODE",
                tables.join(", ")
            ))
            .unwrap();
            std::thread::sleep(Duration::from_millis(500));
            tx.batch_execute(&format!(
                "SET LOCAL session_replication_role = replica; {attack_sql}"
            ))
            .unwrap();
            tx.commit().unwrap();
            done.store(true, Ordering::SeqCst);
        });
        let r = acting();
        h.join().unwrap();
        r
    });
    assert!(done.load(Ordering::SeqCst));
    c.batch_execute("DROP TRIGGER IF EXISTS atk_slow ON audit_events")
        .unwrap();
    r
}

#[cfg(unix)]
fn set_dir_mode(d: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(d, std::fs::Permissions::from_mode(mode)).unwrap();
}

// ---- 412 (a): how the unanchored state is reached, and what it buys ----

/// A writer FORCES the unanchored state, with no crash and no outage: in the
/// creation window it deletes the ledger row (the call finds the ledger
/// missing before anchoring, and is not acknowledged), then inserts a ledger
/// row of its own with a 1000-fold budget. A data owner then spends through
/// the API.
#[test]
fn g1_writer_forces_an_unanchored_ledger_with_its_own_genesis() {
    let Some(w) = world() else { return };
    let World {
        t,
        a_owner,
        dataset_a,
        ..
    } = w;
    let url = t.env0.url.clone();
    let (s, v) = in_window(
        &url,
        &["privacy_ledgers"],
        "DELETE FROM privacy_ledgers WHERE asset_id IN (SELECT id FROM assets WHERE name='forced-2030')",
        || register(&t, &a_owner, "forced-2030", true),
    );
    assert!(s != 201, "the creation must not be acknowledged: {s} {v}");
    let id = asset_id_by_name(&url, "forced-2030");
    sql(&url, &forge_ledger_sql(&id, &dataset_a));
    let n = spends_accepted(&t, &a_owner, &id, 40);
    assert_eq!(n, 0, "{HONEST_CAP_NOTE}; {n} of 40 were acknowledged");
    let (s, v) = spend(&t, &a_owner, &id, "again");
    assert!(
        refused_unanchored(s, &v),
        "a spend on a ledger the anchor never saw is refused with the operator's message: {s} {v}"
    );
}

/// An honest anchor-store outage at creation (the call errors), then a writer
/// rewrites the genesis before the first spend.
#[cfg(unix)]
#[test]
fn g2_anchor_outage_at_creation_then_genesis_rewritten() {
    let Some(w) = world() else { return };
    let World { t, a_owner, .. } = w;
    let url = t.env0.url.clone();
    set_dir_mode(&t.env0.anchor_dir, 0o500);
    let (s, v) = register(&t, &a_owner, "outage-2030", true);
    set_dir_mode(&t.env0.anchor_dir, 0o700);
    assert!(
        s != 201,
        "no acknowledgement while the anchor write fails: {s} {v}"
    );
    let id = asset_id_by_name(&url, "outage-2030");
    sql(&url, &inflate_sql(&id));
    let n = spends_accepted(&t, &a_owner, &id, 40);
    assert_eq!(n, 0, "{HONEST_CAP_NOTE}; {n} of 40 were acknowledged");
}

/// A writer creates a ledger for an asset registered without any budget.
#[test]
fn g3_writer_inserts_a_ledger_for_an_asset_without_one() {
    let Some(w) = world() else { return };
    let World {
        t,
        a_owner,
        dataset_a,
        ..
    } = w;
    let url = t.env0.url.clone();
    let (s, v) = register(&t, &a_owner, "nobudget-2030", false);
    assert_eq!(s, 201, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    sql(&url, &forge_ledger_sql(&id, &dataset_a));
    let n = spends_accepted(&t, &a_owner, &id, 40);
    assert_eq!(n, 0, "{HONEST_CAP_NOTE}; {n} of 40 were acknowledged");
}

// W15 (a creation committed but never anchored, the genesis rewritten across a
// crash) is pinned in anchor_window_adversarial.rs.

// ---- honest-path liveness, the operator's step, the upgrade ----

/// Control: an honest ledger accepts a handful of spends, then refuses by
/// budget (409), never by the anchor.
#[test]
fn g0_an_honest_ledger_spends_up_to_its_cap() {
    let Some(w) = world() else { return };
    let World {
        t,
        a_owner,
        dataset_a,
        ..
    } = w;
    let n = spends_accepted(&t, &a_owner, &dataset_a, 40);
    assert!((1..20).contains(&n), "{n}");
    let (s, v) = spend(&t, &a_owner, &dataset_a, "over");
    assert_eq!(s, 409, "{v}");
    assert_eq!(
        v["code"], "ENC2201",
        "refused by the budget, not by the anchor"
    );
}

/// An anchor outage at creation: the call is not acknowledged. When the store
/// is back the process anchors the genesis it committed (on its next tick)
/// and the ledger is honestly spendable: liveness without trusting the
/// database.
#[cfg(unix)]
#[test]
fn g4_an_outage_at_creation_heals_without_trusting_the_database() {
    let Some(w) = world() else { return };
    let World { t, a_owner, .. } = w;
    let url = t.env0.url.clone();
    set_dir_mode(&t.env0.anchor_dir, 0o500);
    let (s, v) = register(&t, &a_owner, "heal-2030", true);
    assert_ne!(s, 201, "{v}");
    let id = asset_id_by_name(&url, "heal-2030");
    // Still down: the tick cannot anchor, and spends are refused.
    t.control.tick();
    assert!(refused_unanchored(
        spend(&t, &a_owner, &id, "e0").0,
        &spend(&t, &a_owner, &id, "e0").1
    ));
    set_dir_mode(&t.env0.anchor_dir, 0o700);
    t.control.tick();
    assert!(t.control.anchor.snapshot().ledgers.contains_key(&id));
    let n = spends_accepted(&t, &a_owner, &id, 40);
    assert!((1..20).contains(&n), "an honest cap: {n}");
}

/// The outage heals only to what the call committed: a writer who rewrote
/// the genesis before the process anchored it again gets it refused (rollback
/// alarm), and the ledger never spends the rewritten budget.
#[cfg(unix)]
#[test]
fn g4b_a_genesis_rewritten_during_an_outage_is_never_anchored_as_rewritten() {
    let Some(w) = world() else { return };
    let World { t, a_owner, .. } = w;
    let url = t.env0.url.clone();
    set_dir_mode(&t.env0.anchor_dir, 0o500);
    let (s, _) = register(&t, &a_owner, "heal-rewritten", true);
    assert_ne!(s, 201);
    let id = asset_id_by_name(&url, "heal-rewritten");
    sql(&url, &inflate_sql(&id));
    set_dir_mode(&t.env0.anchor_dir, 0o700);
    t.control.tick();
    let n = spends_accepted(&t, &a_owner, &id, 40);
    assert_eq!(n, 0, "{HONEST_CAP_NOTE}; {n} of 40 acknowledged");
    assert!(t
        .control
        .metrics
        .render()
        .contains("encompute_state_rollback_total{label="));
}

/// The operator's step: audited, names the budget it anchors, and only for
/// ledgers that are unanchored.
#[test]
fn g5_the_operator_anchors_an_unanchored_ledger_deliberately_and_audibly() {
    let Some(w) = world() else { return };
    let World {
        t,
        a_owner,
        dataset_a,
        ..
    } = w;
    let f = std::fs::read_dir(&t.env0.anchor_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| !p.to_string_lossy().ends_with(".lock"))
        .unwrap();
    let old = std::fs::read(&f).unwrap();
    let (s, v) = register(&t, &a_owner, "crash-honest", true);
    assert_eq!(s, 201, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let env0 = t.env0;
    drop(t.control);
    std::fs::write(&f, &old).unwrap();
    let t = env0.start().unwrap();
    assert_eq!(t.control.unanchored_ledgers().unwrap(), vec![id.clone()]);
    assert!(refused_unanchored(
        spend(&t, &a_owner, &id, "e").0,
        &spend(&t, &a_owner, &id, "e").1
    ));
    // Named wrongly: refused, nothing anchored.
    assert!(t
        .control
        .anchor_unanchored("operator-1", Some(std::slice::from_ref(&dataset_a)))
        .is_err());
    let notes = t
        .control
        .anchor_unanchored("operator-1", Some(std::slice::from_ref(&id)))
        .unwrap();
    assert_eq!(notes.len(), 1);
    assert!(notes[0].contains("epsilon 3 "), "{notes:?}");
    // The audit trail names the operator and the checkpoint.
    let mut c = postgres::Client::connect(&t.env0.url, postgres::NoTls).unwrap();
    let row = c
        .query_one(
            "SELECT actor, refs::text FROM audit_events WHERE action='privacy.ledger.genesis_anchored' AND resource_id=$1",
            &[&id],
        )
        .unwrap();
    let (actor, refs): (String, String) = (row.get(0), row.get(1));
    assert_eq!(actor, "operator-1");
    assert!(
        refs.contains("checkpoint_root") && refs.contains("epsilon"),
        "{refs}"
    );
    let n = spends_accepted(&t, &a_owner, &id, 40);
    assert!((1..20).contains(&n), "an honest cap: {n}");
    assert!(t.control.unanchored_ledgers().unwrap().is_empty());
    // A second run finds nothing to anchor.
    assert!(t
        .control
        .anchor_unanchored("operator-1", None)
        .unwrap()
        .is_empty());
}

/// Upgrade: a ledger that already has an anchored checkpoint (every ledger
/// created by a released 0.3 that acknowledged its creation) is spendable
/// across a restart with nothing to do, and raises no alarm.
#[test]
fn g6_anchored_ledgers_are_untouched_by_the_upgrade() {
    let Some(w) = world() else { return };
    let World {
        t,
        a_owner,
        dataset_a,
        ..
    } = w;
    assert_eq!(spend(&t, &a_owner, &dataset_a, "s0").0, 200);
    let t = t.restart().unwrap();
    assert!(t.control.unanchored_ledgers().unwrap().is_empty());
    assert!(!t
        .control
        .render_metrics()
        .contains("encompute_unanchored_ledgers{label=\"all\"} 1"));
    assert_eq!(spend(&t, &a_owner, &dataset_a, "s1").0, 200);
}

/// Honest concurrency: creations and spends from several threads at once all
/// succeed (no spurious refusal from the anchored-genesis rule).
#[test]
fn g7_concurrent_creations_and_spends_stay_live() {
    let Some(w) = world() else { return };
    let World { t, a_owner, .. } = w;
    let ids: Vec<String> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..4)
            .map(|i| {
                let (t, a) = (&t, &a_owner);
                s.spawn(move || {
                    let (st, v) = register(t, a, &format!("conc-{i}"), true);
                    assert_eq!(st, 201, "{v}");
                    v["id"].as_str().unwrap().to_owned()
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    std::thread::scope(|s| {
        for id in &ids {
            for k in 0..2 {
                let (t, a, id) = (&t, &a_owner, id.clone());
                s.spawn(move || {
                    let (st, v) = spend(t, a, &id, &format!("c{k}"));
                    assert_eq!(st, 200, "{v}");
                });
            }
        }
    });
    assert!(t.control.unanchored_ledgers().unwrap().is_empty());
}
