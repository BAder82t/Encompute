//! A privacy spend or a ledger creation is acknowledged only when the state
//! anchor holds exactly what the call committed (threat model section 4.6).
//!
//! The attacker owns the database and acts while the service runs: a LOCK
//! TABLE queued behind the call's insert is granted the instant the call
//! commits, so the attacker changes the ledger between the commit and the
//! service's anchoring read. In 0.3.0 the call re-read the ledger, found it
//! still extended the old anchor, anchored nothing and acknowledged a spend
//! (or a rewritten genesis) the ledger no longer held. Every test here asserts
//! the safe behaviour: no acknowledgement, no cap defeated, no forged genesis
//! anchored. The last tests keep honest concurrency, retries and restarts
//! unchanged.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
fn rollbacks_counted(t: &T) -> bool {
    t.control
        .metrics
        .render()
        .contains("encompute_state_rollback_total{label=")
}
fn entries(url: &str, d: &str) -> i64 {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    c.query_one(
        "SELECT count(*) FROM privacy_entries WHERE asset_id=$1",
        &[&d],
    )
    .unwrap()
    .get(0)
}

/// Run `acting` (the service call) while a database-owner session waits for
/// the call's INSERT into `table`, queues ACCESS EXCLUSIVE behind it (granted
/// the instant the call commits, before the service's post-commit read),
/// runs `attack_sql`, and only then lets the service's read proceed.
fn in_window<R: Send>(
    url: &str,
    table: &str,
    attack_sql: &str,
    acting: impl FnOnce() -> R + Send,
) -> R {
    // The attacker slows the call's audit insert so the window to queue the lock exists.
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    c.batch_execute(
        "CREATE OR REPLACE FUNCTION atk_sleep() RETURNS trigger AS $$ BEGIN PERFORM pg_sleep(1.0); RETURN NULL; END $$ LANGUAGE plpgsql;
         DROP TRIGGER IF EXISTS atk_slow ON audit_events;
         CREATE TRIGGER atk_slow AFTER INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION atk_sleep();",
    ).unwrap();
    let done = AtomicBool::new(false);
    let r =
        std::thread::scope(|s| {
            let h =
                s.spawn(|| {
                    let mut a = postgres::Client::connect(url, postgres::NoTls).unwrap();
                    let me: i32 = a.query_one("SELECT pg_backend_pid()", &[]).unwrap().get(0);
                    // wait until another backend holds RowExclusiveLock on the table
                    loop {
                        let n: i64 = a.query_one(
                    "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
                     WHERE c.relname=$1 AND l.mode='RowExclusiveLock' AND l.granted AND l.pid<>$2",
                    &[&table, &me]).unwrap().get(0);
                        if n > 0 {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    let mut tx = a.transaction().unwrap();
                    // blocks until the service's transaction has committed
                    tx.batch_execute(&format!("LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"))
                        .unwrap();
                    // the service's post-commit read is now queued behind us
                    std::thread::sleep(Duration::from_millis(500));
                    tx.batch_execute(attack_sql).unwrap();
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

fn rollback_refused(s: u16, v: &Value) -> bool {
    s == 500
        && v["code"] == "ENC2202"
        && v["message"]
            .as_str()
            .is_some_and(|m| m.contains("PRIVACY STATE ROLLBACK"))
}

fn new_asset(t: &T, who: &As, name: &str, eps: f64) -> String {
    let v = t.ok(who, "POST", "/v1/assets", Some(json!({"organization": "hospital-a", "kind": "dataset", "name": name, "digest": "e".repeat(64), "privacy_budget": budget(eps)})));
    v["id"].as_str().unwrap().to_owned()
}

/// A spend whose entry is erased between its commit and its anchoring is
/// not acknowledged: refused as a rollback (ENC2202), alarmed, and nothing is
/// recorded in the anchor. The client may retry the same event: it is then
/// recorded afresh and acknowledged, and the service still starts.
#[test]
fn spend_erased_in_the_window_is_not_acknowledged() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    assert_eq!(spend(&w.t, &w.a_owner, &d, "s-0", 18).0, 200);
    let seq0 = anchored_seq(&w.t, &d);
    let snap0 = w.t.control.anchor.snapshot();
    let del = format!("DELETE FROM privacy_entries WHERE asset_id='{d}' AND seq > {seq0}");
    let (s, v) = in_window(&w.t.env0.url, "privacy_entries", &del, || {
        spend(&w.t, &w.a_owner, &d, "s-1", 18)
    });
    assert!(
        rollback_refused(s, &v),
        "an erased spend must not be acknowledged: {s} {v}"
    );
    assert!(rollbacks_counted(&w.t), "the rollback alarm is raised");
    assert_eq!(entries(&w.t.env0.url, &d), seq0 as i64);
    assert_eq!(
        anchored_seq(&w.t, &d),
        seq0,
        "nothing is recorded for a refused spend"
    );
    assert_eq!(
        w.t.control.anchor.snapshot().counter,
        snap0.counter,
        "the anchor was not written"
    );
    // Retrying the same event is correct: nothing was acknowledged, so it is recorded afresh.
    let (s2, v2) = spend(&w.t, &w.a_owner, &d, "s-1", 18);
    assert_eq!(s2, 200, "{v2}");
    assert_eq!(v2["duplicate"], false);
    assert_eq!(anchored_seq(&w.t, &d), seq0 + 1);
    w.t.restart().expect("an honest ledger starts");
}

fn wait_blocked_on(c: &mut postgres::Client, table: &str) {
    for _ in 0..4000 {
        let n: i64 = c
            .query_one(
                "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
                 WHERE c.relname=$1 AND NOT l.granted AND l.pid<>pg_backend_pid()",
                &[&table],
            )
            .unwrap()
            .get(0);
        if n > 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("the window did not open on {table}");
}

/// Like [`in_window`] for a call that writes nothing (the duplicate answer),
/// so no insert of its own opens the window. One session holds
/// `privacy_entries`, so the call stalls inside its transaction after it
/// locked the ledger row; a second queues ACCESS EXCLUSIVE on
/// `privacy_ledgers` behind that row lock, runs `attack_sql` the instant the
/// call commits, and only then lets the call's post-commit read proceed.
fn in_window_readonly<R: Send>(
    url: &str,
    attack_sql: &str,
    acting: impl FnOnce() -> R + Send,
) -> R {
    let mut hold = postgres::Client::connect(url, postgres::NoTls).unwrap();
    hold.batch_execute("BEGIN; LOCK TABLE privacy_entries IN ACCESS EXCLUSIVE MODE")
        .unwrap();
    std::thread::scope(|s| {
        let attacker = s.spawn(|| {
            let mut a = postgres::Client::connect(url, postgres::NoTls).unwrap();
            wait_blocked_on(&mut a, "privacy_entries");
            let mut tx = a.transaction().unwrap();
            // granted the instant the call commits
            tx.batch_execute("LOCK TABLE privacy_ledgers IN ACCESS EXCLUSIVE MODE")
                .unwrap();
            std::thread::sleep(Duration::from_millis(500));
            tx.batch_execute(attack_sql).unwrap();
            tx.commit().unwrap();
        });
        let releaser = s.spawn(move || {
            let mut w = postgres::Client::connect(url, postgres::NoTls).unwrap();
            wait_blocked_on(&mut w, "privacy_entries"); // the call is inside its transaction
            wait_blocked_on(&mut w, "privacy_ledgers"); // the attacker is queued behind it
            hold.batch_execute("COMMIT").unwrap();
        });
        let r = acting();
        attacker.join().unwrap();
        releaser.join().unwrap();
        r
    })
}

/// A retry of an event the ledger already holds (the duplicate answer) is
/// bound the same way: acknowledged only when the anchor covers the entry
/// it returns. The anchor is behind the ledger here (an older validly
/// signed copy of the anchor file, as after a crash between a commit and its
/// anchoring); the entry the retry would return is erased in the window.
#[test]
fn duplicate_answer_erased_in_the_window_is_not_acknowledged() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    assert_eq!(spend(&w.t, &w.a_owner, &d, "s-0", 18).0, 200);
    let World { t, a_owner, .. } = w;
    let dir = t.env0.anchor_dir.clone();
    let f = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| !p.to_string_lossy().ends_with(".lock"))
        .unwrap();
    let old = std::fs::read(&f).unwrap();
    assert_eq!(spend(&t, &a_owner, &d, "s-1", 18).0, 200);
    let env0 = t.env0;
    drop(t.control);
    std::fs::write(&f, &old).unwrap();
    let t = env0.start().expect("a ledger ahead of its anchor starts");
    let behind = anchored_seq(&t, &d);
    assert_eq!(behind, 1, "the anchor is one behind the ledger");
    let del = format!("DELETE FROM privacy_entries WHERE asset_id='{d}' AND seq = 2");
    let (s, v) = in_window_readonly(&t.env0.url, &del, || spend(&t, &a_owner, &d, "s-1", 18));
    assert!(
        rollback_refused(s, &v),
        "an erased entry must not be acknowledged as a duplicate: {s} {v}"
    );
    assert_eq!(anchored_seq(&t, &d), behind, "nothing is recorded");
}

/// An honest retry of an event the anchor already covers answers "duplicate"
/// with the stored entry, unchanged.
#[test]
fn honest_retry_is_acknowledged_as_a_duplicate() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    let (s, first) = spend(&w.t, &w.a_owner, &d, "s-0", 18);
    assert_eq!(s, 200, "{first}");
    let (s, again) = spend(&w.t, &w.a_owner, &d, "s-0", 18);
    assert_eq!(s, 200, "{again}");
    assert_eq!(again["duplicate"], true);
    assert_eq!(
        (&again["seq"], &again["hash"]),
        (&first["seq"], &first["hash"])
    );
    assert_eq!(anchored_seq(&w.t, &d), 1);
    assert_eq!(entries(&w.t.env0.url, &d), 1);
}

/// (f) the cap cannot be consumed: the in-window erase repeated far past the
/// honest cap acknowledges nothing, and the honest cap still holds.
#[test]
fn repeated_erase_in_the_window_does_not_defeat_the_cap() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    let sib = new_asset(&w.t, &w.a_owner, "sib", 3.0);
    let mut cap = 0;
    while spend(&w.t, &w.a_owner, &sib, &format!("c-{cap}"), 18).0 == 200 {
        cap += 1;
    }
    assert!(cap >= 2);
    let n = cap * 3 + 3;
    let mut acked = 0;
    for i in 0..n {
        let seq0 = anchored_seq(&w.t, &d);
        let del = format!("DELETE FROM privacy_entries WHERE asset_id='{d}' AND seq > {seq0}");
        let (s, v) = in_window(&w.t.env0.url, "privacy_entries", &del, || {
            spend(&w.t, &w.a_owner, &d, &format!("atk-{i}"), 18)
        });
        if s == 200 {
            acked += 1;
        } else {
            assert!(rollback_refused(s, &v), "round {i}: {s} {v}");
        }
    }
    assert_eq!(
        acked, 0,
        "{acked} of {n} erased spends were acknowledged (honest cap {cap})"
    );
    let mut again = 0;
    while spend(&w.t, &w.a_owner, &d, &format!("h-{again}"), 18).0 == 200 {
        again += 1;
    }
    assert!(
        acked + again <= cap,
        "{} spends acknowledged against a cap of {cap}",
        acked + again
    );
}

/// (e) asset creation with a budget: a genesis rewritten before it is
/// anchored is not acknowledged, and the forged ledger can never be spent
/// on (the intended genesis is what the anchor holds).
#[test]
fn genesis_rewritten_in_the_window_is_not_acknowledged() {
    let Some(w) = world() else { return };
    let body = json!({"organization": "hospital-a", "kind": "dataset", "name": "patients-2027", "digest": "c".repeat(64), "privacy_budget": budget(3.0)});
    let sql = "UPDATE privacy_ledgers SET genesis = jsonb_set(genesis, '{budget,epsilon}', '\"30.0\"'::jsonb) WHERE created_at > now() - interval '1 minute' AND asset_id NOT IN (SELECT asset_id FROM privacy_entries)";
    let (s, v) = in_window(&w.t.env0.url, "privacy_ledgers", sql, || {
        w.t.call(&w.a_owner, "POST", "/v1/assets", Some(body.clone()))
    });
    assert!(
        rollback_refused(s, &v),
        "a rewritten genesis must not be acknowledged: {s} {v}"
    );
    assert!(rollbacks_counted(&w.t));
    let mut c = postgres::Client::connect(&w.t.env0.url, postgres::NoTls).unwrap();
    let id: String = c
        .query_one(
            "SELECT asset_id FROM privacy_ledgers WHERE genesis->'budget'->>'epsilon' = '30.0'",
            &[],
        )
        .expect("the forged ledger is what the attacker left behind")
        .get(0);
    // The forged ledger is refused for every spend: it does not extend the
    // checkpoint of the genesis the call committed.
    for i in 0..5 {
        let (s, v) = spend(&w.t, &w.a_owner, &id, &format!("g-{i}"), 18);
        assert!(
            rollback_refused(s, &v),
            "spend {i} on the forged ledger: {s} {v}"
        );
    }
    assert_eq!(entries(&w.t.env0.url, &id), 0);
    assert!(w
        .t
        .control
        .anchor
        .snapshot()
        .ledgers
        .get(&id)
        .is_some_and(|cp| cp.seq == 0));
}

/// (e2) the ledger row deleted in the window.
#[test]
fn ledger_row_deleted_in_the_window_is_not_acknowledged() {
    let Some(w) = world() else { return };
    let body = json!({"organization": "hospital-a", "kind": "dataset", "name": "patients-2028", "digest": "d".repeat(64), "privacy_budget": budget(3.0)});
    let sql = "DELETE FROM privacy_ledgers WHERE created_at > now() - interval '1 minute' AND asset_id NOT IN (SELECT asset_id FROM privacy_entries) AND asset_id NOT IN (SELECT asset_id FROM privacy_spenders)";
    let (s, v) = in_window(&w.t.env0.url, "privacy_ledgers", sql, || {
        w.t.call(&w.a_owner, "POST", "/v1/assets", Some(body.clone()))
    });
    assert!(rollback_refused(s, &v), "{s} {v}");
}

/// Honest concurrency is unchanged: 8 threads x 10 spends on one ledger, and
/// the same across four ledgers, are all acknowledged; the anchor, the
/// database and the audit trail agree, and the service restarts.
#[test]
fn honest_concurrent_spends_are_all_acknowledged_and_consistent() {
    let Some(w) = world() else { return };
    let one = new_asset(&w.t, &w.a_owner, "busy-0", 100000.0);
    let many: Vec<String> = (1..=4)
        .map(|i| new_asset(&w.t, &w.a_owner, &format!("busy-{i}"), 100000.0))
        .collect();
    let barrier = std::sync::Barrier::new(16);
    let results: Vec<(String, u16, Value)> = std::thread::scope(|s| {
        let mut hs = vec![];
        for th in 0..8 {
            let (t, who, one, barrier) = (&w.t, &w.a_owner, &one, &barrier);
            hs.push(s.spawn(move || {
                barrier.wait();
                (0..10)
                    .map(|i| {
                        let (st, v) = spend(t, who, one, &format!("one-{th}-{i}"), 18);
                        (one.clone(), st, v)
                    })
                    .collect::<Vec<_>>()
            }));
        }
        for th in 0..8 {
            let (t, who, many, barrier) = (&w.t, &w.a_owner, &many, &barrier);
            hs.push(s.spawn(move || {
                barrier.wait();
                (0..10)
                    .map(|i| {
                        let d = &many[(th + i) % many.len()];
                        let (st, v) = spend(t, who, d, &format!("many-{th}-{i}"), 18);
                        (d.clone(), st, v)
                    })
                    .collect::<Vec<_>>()
            }));
        }
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(results.len(), 160);
    for (d, s, v) in &results {
        assert_eq!(*s, 200, "{d}: {v}");
    }
    assert_eq!(anchored_seq(&w.t, &one), 80);
    assert_eq!(entries(&w.t.env0.url, &one), 80);
    let total: i64 = many.iter().map(|d| entries(&w.t.env0.url, d)).sum();
    assert_eq!(total, 80);
    for d in &many {
        assert_eq!(anchored_seq(&w.t, d), entries(&w.t.env0.url, d) as u64);
    }
    w.t.restart().expect("the honest ledgers start");
}

// ---- controls: protections that already hold and must keep holding -------

/// The last entry erased AFTER the anchor recorded it: the next spend is
/// refused (ENC2202), and so is the next start.
#[test]
fn control_erase_after_the_anchor_is_detected() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    for i in 0..3 {
        assert_eq!(spend(&w.t, &w.a_owner, &d, &format!("s-{i}"), 18).0, 200);
    }
    let n = anchored_seq(&w.t, &d);
    let mut c = postgres::Client::connect(&w.t.env0.url, postgres::NoTls).unwrap();
    c.execute(
        "DELETE FROM privacy_entries WHERE asset_id=$1 AND seq=$2",
        &[&d, &(n as i64)],
    )
    .unwrap();
    let (s, v) = spend(&w.t, &w.a_owner, &d, "next", 18);
    assert!(rollback_refused(s, &v), "{s} {v}");
    assert!(rollbacks_counted(&w.t));
    drop(c);
    assert!(w.t.restart().is_err(), "start-up refuses the erased ledger");
}

/// An older database restored across a restart is refused at start.
#[test]
fn control_older_database_restored_across_a_restart_is_refused() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    assert_eq!(spend(&w.t, &w.a_owner, &d, "s-0", 18).0, 200);
    let World { t, a_owner, .. } = w;
    let url = t.env0.url.clone();
    let env0 = t.env0;
    drop(t.control);
    let backup = format!("{}_bk", db_name(&url));
    backup_database(&url, &backup);
    let t = env0.start().unwrap();
    for i in 1..3 {
        assert_eq!(spend(&t, &a_owner, &d, &format!("s-{i}"), 18).0, 200);
    }
    let env0 = t.env0;
    drop(t.control);
    restore_database(&backup, &url);
    assert!(env0.start().is_err());
}

/// Older rows restored while the service runs: the next spend is refused.
#[test]
fn control_older_rows_restored_while_running_are_refused() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    assert_eq!(spend(&w.t, &w.a_owner, &d, "s-0", 18).0, 200);
    for i in 1..4 {
        assert_eq!(spend(&w.t, &w.a_owner, &d, &format!("s-{i}"), 18).0, 200);
    }
    let mut c = postgres::Client::connect(&w.t.env0.url, postgres::NoTls).unwrap();
    c.execute(
        "DELETE FROM privacy_entries WHERE asset_id=$1 AND seq > 1",
        &[&d],
    )
    .unwrap();
    let (s, v) = spend(&w.t, &w.a_owner, &d, "after-restore", 18);
    assert!(rollback_refused(s, &v), "{s} {v}");
    drop(c);
    assert!(w.t.restart().is_err());
}

/// A lowered anchor without a valid signature is refused at start.
#[test]
fn control_unsigned_lowered_anchor_is_refused() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    assert_eq!(spend(&w.t, &w.a_owner, &d, "s-0", 18).0, 200);
    let f = std::fs::read_dir(&w.t.env0.anchor_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| !p.to_string_lossy().ends_with(".lock"))
        .unwrap();
    for i in 1..4 {
        assert_eq!(spend(&w.t, &w.a_owner, &d, &format!("s-{i}"), 18).0, 200);
    }
    let now = String::from_utf8_lossy(&std::fs::read(&f).unwrap()).to_string();
    let forged = now.replacen("\"seq\": 4", "\"seq\": 1", 1);
    assert_ne!(forged, now, "the test edits the anchor");
    let env0 = w.t.env0;
    drop(w.t.control);
    std::fs::write(&f, forged.as_bytes()).unwrap();
    assert!(env0.start().is_err());
}
