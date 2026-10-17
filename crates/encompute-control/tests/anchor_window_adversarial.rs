//! Independent adversarial review of the 0.3.1 spend and creation anchoring
//! (`anchor_window.rs`): attempts to get an acknowledged spend or creation
//! forgotten, or an unauthorised use of the cap, on a database owner's terms
//! (arbitrary SQL, LOCK TABLE windows queued behind the service's
//! transaction, triggers and constraints off), without the signing key or the
//! anchor store. Each test is one attempt (W01 ...); each asserts the safe
//! behaviour.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::window::{in_window, in_window_hooked, in_window_readonly, Opts, Part};
use common::*;
use encompute_privacy::{LedgerView, PrivacyEvent};
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

fn rollback_refused(s: u16, v: &Value) -> bool {
    s == 500
        && v["code"] == "ENC2202"
        && v["message"]
            .as_str()
            .is_some_and(|m| m.contains("PRIVACY STATE ROLLBACK"))
}

fn sql(url: &str, q: &str) {
    postgres::Client::connect(url, postgres::NoTls)
        .unwrap()
        .batch_execute(q)
        .unwrap();
}

/// The ledger of `d` as the database holds it.
fn view_of(url: &str, d: &str) -> LedgerView {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    let g: Value = c
        .query_one(
            "SELECT genesis FROM privacy_ledgers WHERE asset_id=$1",
            &[&d],
        )
        .unwrap()
        .get(0);
    let entries: Vec<Value> = c
        .query(
            "SELECT entry FROM privacy_entries WHERE asset_id=$1 ORDER BY seq",
            &[&d],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    serde_json::from_value(json!({"genesis": g, "entries": entries})).unwrap()
}

/// SQL that replaces the entry after the first `keep` ones by a forged,
/// hash-consistent one for `event`.
fn forge_after(url: &str, d: &str, keep: usize, event: Value) -> String {
    let mut v = view_of(url, d);
    v.entries.truncate(keep);
    let ev: PrivacyEvent = serde_json::from_value(event).unwrap();
    let (_, e) = v.append_event(ev).unwrap();
    let ej = serde_json::to_string(&e).unwrap().replace('\'', "''");
    format!(
        "DELETE FROM privacy_entries WHERE asset_id='{d}' AND seq > {keep};
         INSERT INTO privacy_entries (asset_id, seq, entry) VALUES ('{d}', {}, '{ej}'::jsonb)",
        e.seq
    )
}

fn not_acked(s: u16) -> bool {
    s != 200 && s != 201
}

// ---- W01: the very first spend of a fresh ledger (anchored genesis, seq 0) ----
#[test]
fn w01_first_spend_erased_in_the_window() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    assert_eq!(anchored_seq(&w.t, &d), 0, "creation anchored the genesis");
    let del = format!("DELETE FROM privacy_entries WHERE asset_id='{d}'");
    let (s, v) = in_window(
        &w.t.env0.url,
        &["privacy_entries", "privacy_ledgers"],
        &del,
        || spend(&w.t, &w.a_owner, &d, "f-0", 18),
    );
    assert!(rollback_refused(s, &v), "{s} {v}");
    assert_eq!(anchored_seq(&w.t, &d), 0);
    let (s, v) = spend(&w.t, &w.a_owner, &d, "f-0", 18);
    assert_eq!(s, 200, "retry lands: {v}");
    assert_eq!(anchored_seq(&w.t, &d), 1);
}

// ---- W02: erased and replaced by a forged, cheaper, hash-consistent entry ----
#[test]
fn w02_spend_replaced_by_a_forged_valid_entry() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    assert_eq!(spend(&w.t, &w.a_owner, &d, "s-0", 18).0, 200);
    let forged = forge_after(&w.t.env0.url, &d, 1, reserve("forged", 100000));
    let (s, v) = in_window(
        &w.t.env0.url,
        &["privacy_entries", "privacy_ledgers"],
        &forged,
        || spend(&w.t, &w.a_owner, &d, "s-1", 18),
    );
    assert!(
        rollback_refused(s, &v),
        "a replaced entry must not be acknowledged: {s} {v}"
    );
    assert_eq!(anchored_seq(&w.t, &d), 1, "the forged head is not anchored");
}

// ---- W03: the duplicate answer's entry replaced by a forged one (anchor one behind) ----
#[test]
fn w03_duplicate_answer_replaced_by_a_forged_entry() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    assert_eq!(spend(&w.t, &w.a_owner, &d, "s-0", 18).0, 200);
    let World { t, a_owner, .. } = w;
    let f = std::fs::read_dir(&t.env0.anchor_dir)
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
    let forged = forge_after(&t.env0.url, &d, 1, reserve("forged", 1));
    let (s, v) = in_window_readonly(&t.env0.url, &forged, true, || {
        spend(&t, &a_owner, &d, "s-1", 18)
    });
    assert!(rollback_refused(s, &v), "{s} {v}");
    assert_eq!(anchored_seq(&t, &d), 1);
}

// ---- W04: genesis rewritten after the creation was anchored (idle), then a spend ----
#[test]
fn w04_genesis_rewritten_after_anchoring_then_spend() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    sql(&w.t.env0.url, &format!("UPDATE privacy_ledgers SET genesis = jsonb_set(genesis, '{{budget,epsilon}}', '\"300.0\"'::jsonb) WHERE asset_id='{d}'"));
    for i in 0..3 {
        let (s, v) = spend(&w.t, &w.a_owner, &d, &format!("g-{i}"), 18);
        assert!(rollback_refused(s, &v), "spend {i}: {s} {v}");
    }
    assert_eq!(entries(&w.t.env0.url, &d), 0);
}

// ---- W05: genesis rewritten in the window of the first spend ----
// The attacker holds both tables the service reads after its commit (the genesis
// first), each queued behind the call before it commits, so no read can precede the rewrite.
#[test]
fn w05_genesis_rewritten_in_the_window_of_the_first_spend() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    let rewrite = format!("UPDATE privacy_ledgers SET genesis = jsonb_set(genesis, '{{budget,epsilon}}', '\"300.0\"'::jsonb) WHERE asset_id='{d}'");
    let (s, v) = in_window(
        &w.t.env0.url,
        &["privacy_ledgers", "privacy_entries"],
        &rewrite,
        || spend(&w.t, &w.a_owner, &d, "f-0", 18),
    );
    assert!(s == 500 && v["code"] == "ENC2202", "{s} {v}");
    assert!(rollbacks_counted(&w.t), "the alarm is raised");
    assert_eq!(anchored_seq(&w.t, &d), 0);
    let (s, v) = spend(&w.t, &w.a_owner, &d, "f-1", 18);
    assert!(
        s == 500 && v["code"] == "ENC2202",
        "the rewritten ledger stays refused: {s} {v}"
    );
}

// ---- W05b: the ACCEPTED post-verification race, kept separate from W05 ----
// The same rewrite, but the attacker holds only the entries table: the service
// reads the genesis (unblocked) BEFORE the rewrite, then its entries read waits
// and sees the entry it appended. The call is acknowledged for a state it
// verified (the honest chain); the rewrite landed after that verification, so
// this is NOT a pre-verification window and proves nothing about rollback
// detection of the call itself. What must hold instead: the anchor holds exactly
// the honest checkpoint the call committed, the altered genesis cannot authorise
// another spend, and a restart refuses the changed ledger. (W05 is the test of
// the pre-verification rewrite.)
#[test]
fn w05b_genesis_rewritten_after_the_service_read_it() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    let url = w.t.env0.url.clone();
    let honest_genesis = serde_json::to_value(view_of(&url, &d).genesis).unwrap();
    let rewrite = format!("UPDATE privacy_ledgers SET genesis = jsonb_set(genesis, '{{budget,epsilon}}', '\"300.0\"'::jsonb) WHERE asset_id='{d}'");
    let (s, v) = in_window(&url, &["privacy_entries"], &rewrite, || {
        spend(&w.t, &w.a_owner, &d, "f-0", 18)
    });
    assert_eq!(
        s, 200,
        "the genesis read precedes the rewrite, so the call is acknowledged: {s} {v}"
    );
    // the checkpoint of the honest chain: the original genesis and the committed entry
    let entries: Vec<Value> = view_of(&url, &d)
        .entries
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();
    let honest: LedgerView =
        serde_json::from_value(json!({"genesis": honest_genesis, "entries": entries})).unwrap();
    let honest_cp = honest.checkpoint().unwrap();
    assert_eq!(honest_cp.seq, 1);
    assert_eq!(
        w.t.control.anchor.snapshot().ledgers[&d],
        honest_cp,
        "the anchor holds exactly the checkpoint (seq and root) the call committed"
    );
    assert_eq!(v["seq"], 1);
    let (s2, v2) = spend(&w.t, &w.a_owner, &d, "f-1", 18);
    assert!(
        s2 == 500 && v2["code"] == "ENC2202",
        "the altered genesis must not authorise another spend: {s2} {v2}"
    );
    assert_eq!(anchored_seq(&w.t, &d), 1, "nothing further is anchored");
    assert!(
        w.t.restart().is_err(),
        "a restart refuses the changed ledger"
    );
}

// ---- W06: two concurrent spends, the first one's entry erased in the window ----
#[test]
fn w06_two_concurrent_spends_one_erased() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    let url = w.t.env0.url.clone();
    let del = format!("DELETE FROM privacy_entries WHERE asset_id='{d}'");
    let results: Vec<(u16, Value)> = in_window(&url, &["privacy_entries"], &del, || {
        std::thread::scope(|s| {
            let a = s.spawn(|| spend(&w.t, &w.a_owner, &d, "c-a", 18));
            let b = s.spawn(|| spend(&w.t, &w.a_owner, &d, "c-b", 18));
            vec![a.join().unwrap(), b.join().unwrap()]
        })
    });
    let held = view_of(&url, &d);
    for (s, v) in &results {
        if *s == 200 {
            assert!(
                held.entries
                    .iter()
                    .any(|e| e.hash == v["hash"].as_str().unwrap_or("")),
                "acknowledged {v} is not in the ledger: {:?}",
                held.entries
                    .iter()
                    .map(|e| (e.seq, e.hash.clone()))
                    .collect::<Vec<_>>()
            );
        } else {
            assert!(rollback_refused(*s, v), "{s} {v}");
        }
    }
    let a = w.t.control.anchor.snapshot().ledgers[&d].clone();
    held.extends(&a).expect("the ledger extends the anchor");
}

// ---- W07: anchor one behind (crash copy): honest duplicate retry and new spend ----
#[test]
fn w07_anchor_one_behind_honest_retry_and_new_spend() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    assert_eq!(spend(&w.t, &w.a_owner, &d, "s-0", 18).0, 200);
    let World { t, a_owner, .. } = w;
    let f = std::fs::read_dir(&t.env0.anchor_dir)
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
    assert_eq!(anchored_seq(&t, &d), 1);
    let (s, v) = spend(&t, &a_owner, &d, "s-1", 18);
    assert_eq!((s, &v["duplicate"]), (200, &json!(true)), "{v}");
    assert_eq!(
        anchored_seq(&t, &d),
        2,
        "the honest retry anchors what it answers"
    );
    let (s, v) = spend(&t, &a_owner, &d, "s-2", 18);
    assert_eq!(s, 200, "{v}");
    assert_eq!(anchored_seq(&t, &d), 3);
}

// ---- W08: entries reordered after anchoring ----
#[test]
fn w08_entries_reordered_after_anchoring() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    for i in 0..3 {
        assert_eq!(spend(&w.t, &w.a_owner, &d, &format!("s-{i}"), 18).0, 200);
    }
    sql(&w.t.env0.url, &format!("SET session_replication_role = replica; UPDATE privacy_entries SET seq = seq + 100 WHERE asset_id='{d}' AND seq IN (1,2); UPDATE privacy_entries SET seq = CASE seq WHEN 101 THEN 202 ELSE 201 END WHERE asset_id='{d}' AND seq IN (101,102); UPDATE privacy_entries SET seq = seq - 200 WHERE asset_id='{d}' AND seq > 200"));
    let (s, v) = spend(&w.t, &w.a_owner, &d, "next", 18);
    assert!(not_acked(s), "{s} {v}");
    assert!(
        w.t.restart().is_err(),
        "start-up refuses the reordered ledger"
    );
}

// ---- W09: ledger row deleted and re-created with the same genesis ----
#[test]
fn w09_ledger_deleted_and_recreated_with_the_same_genesis() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    for i in 0..3 {
        assert_eq!(spend(&w.t, &w.a_owner, &d, &format!("s-{i}"), 18).0, 200);
    }
    let url = w.t.env0.url.clone();
    sql(&url, &format!("SET session_replication_role = replica; CREATE TABLE atk_l AS SELECT * FROM privacy_ledgers WHERE asset_id='{d}'; DELETE FROM privacy_entries WHERE asset_id='{d}'; DELETE FROM privacy_ledgers WHERE asset_id='{d}'; INSERT INTO privacy_ledgers SELECT * FROM atk_l"));
    let (s, v) = spend(&w.t, &w.a_owner, &d, "again", 18);
    assert!(rollback_refused(s, &v), "{s} {v}");
    assert!(w.t.restart().is_err());
}

// ---- W10: a spend on a ledger created in the same window ----
#[test]
fn w10_spend_on_a_ledger_created_then_erased_in_the_window() {
    let Some(w) = world() else { return };
    let body = json!({"organization": "hospital-a", "kind": "dataset", "name": "fresh-2029", "digest": "f".repeat(64), "privacy_budget": budget(3.0)});
    let created = w.t.ok(&w.a_owner, "POST", "/v1/assets", Some(body));
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(anchored_seq(&w.t, &id), 0);
    let del = format!("DELETE FROM privacy_entries WHERE asset_id='{id}'");
    let (s, v) = in_window(
        &w.t.env0.url,
        &["privacy_entries", "privacy_ledgers"],
        &del,
        || spend(&w.t, &w.a_owner, &id, "n-0", 18),
    );
    assert!(rollback_refused(s, &v), "{s} {v}");
    assert_eq!(anchored_seq(&w.t, &id), 0);
}

// ---- W11: the background tick racing the window ----
// The tick starts only once the helper has PROVEN the window (the attacker holds
// both tables, the call's own post-commit read is seen waiting behind them), so a
// tick that detects the rollback cannot stand in for a window the call missed; it
// then races the attack and the release.
#[test]
fn w11_background_tick_racing_the_window() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    assert_eq!(spend(&w.t, &w.a_owner, &d, "s-0", 18).0, 200);
    let seq0 = anchored_seq(&w.t, &d);
    let stop = AtomicBool::new(false);
    let ticking = AtomicBool::new(false);
    let del = format!("DELETE FROM privacy_entries WHERE asset_id='{d}' AND seq > {seq0}");
    let (s, v) = std::thread::scope(|sc| {
        let ticker = sc.spawn(|| {
            while !stop.load(Ordering::SeqCst) {
                if ticking.load(Ordering::SeqCst) {
                    w.t.control.tick();
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let parts = [
            Part {
                table: "privacy_entries",
                sql: &del,
            },
            Part {
                table: "privacy_ledgers",
                sql: "",
            },
        ];
        let start_ticks = || ticking.store(true, Ordering::SeqCst);
        let r = in_window_hooked(
            &w.t.env0.url,
            &parts,
            &Opts::default(),
            Some(&start_ticks),
            || spend(&w.t, &w.a_owner, &d, "s-1", 18),
        );
        stop.store(true, Ordering::SeqCst);
        ticker.join().unwrap();
        r
    });
    assert!(rollback_refused(s, &v), "{s} {v}");
    assert_eq!(anchored_seq(&w.t, &d), seq0);
}

// ---- W12 (control): an attack that changes nothing is acknowledged ----
#[test]
fn w12_control_noop_attack_is_acknowledged() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    let (s, v) = in_window(
        &w.t.env0.url,
        &["privacy_entries", "privacy_ledgers"],
        "SELECT 1",
        || spend(&w.t, &w.a_owner, &d, "s-0", 18),
    );
    assert_eq!(s, 200, "{v}");
    assert_eq!(anchored_seq(&w.t, &d), 1);
}

// ---- W13: the entry and the spend's audit event both erased ----
#[test]
fn w13_entry_and_audit_trace_erased_in_the_window() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    let both = format!("DELETE FROM privacy_entries WHERE asset_id='{d}'; DELETE FROM audit_events WHERE seq = (SELECT max(seq) FROM audit_events); UPDATE audit_head SET seq = (SELECT max(seq) FROM audit_events), hash = (SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1) WHERE id");
    let (s, v) = in_window(
        &w.t.env0.url,
        &["privacy_entries", "privacy_ledgers"],
        &both,
        || spend(&w.t, &w.a_owner, &d, "s-0", 18),
    );
    assert!(not_acked(s), "{s} {v}");
    assert_eq!(anchored_seq(&w.t, &d), 0);
}

// ---- W14: an earlier entry's content modified in the window ----
#[test]
fn w14_earlier_entry_modified_in_the_window() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    assert_eq!(spend(&w.t, &w.a_owner, &d, "s-0", 18).0, 200);
    let edit = format!("UPDATE privacy_entries SET entry = jsonb_set(entry, '{{event,sigma2}}', '1'::jsonb) WHERE asset_id='{d}' AND seq=1");
    let (s, v) = in_window(
        &w.t.env0.url,
        &["privacy_entries", "privacy_ledgers"],
        &edit,
        || spend(&w.t, &w.a_owner, &d, "s-1", 18),
    );
    assert!(not_acked(s), "{s} {v}");
    assert_eq!(anchored_seq(&w.t, &d), 1);
}

// ---- W15 (CLOSED in 0.3.1, ENC-SF-2026-412): a ledger committed but never
// anchored (a crash, or an anchor-store outage, between the creation's commit
// and its anchoring; the call was never acknowledged) has no anchored genesis.
// One who rewrites the genesis while the service is down (or before the first
// spend) used to have it accepted and anchored at the first spend (40 of 40
// spends against an honest cap of a handful). Now every spend on a ledger the
// anchor holds no checkpoint for is refused (ENC2202), the restart alarms
// (the `encompute_unanchored_ledgers` gauge and a log line), and only an
// operator's deliberate, audited `anchor-ledgers` makes it spendable. More
// scenarios in anchor_genesis.rs. ----
#[test]
fn w15_unanchored_ledger_genesis_rewritten_across_a_crash_refuses_spends() {
    let Some(w) = world() else { return };
    let World { t, a_owner, .. } = w;
    let f = std::fs::read_dir(&t.env0.anchor_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| !p.to_string_lossy().ends_with(".lock"))
        .unwrap();
    let old = std::fs::read(&f).unwrap();
    let body = json!({"organization": "hospital-a", "kind": "dataset", "name": "crash-2030", "digest": "9".repeat(64), "privacy_budget": budget(3.0)});
    let id = t.ok(&a_owner, "POST", "/v1/assets", Some(body))["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let url = t.env0.url.clone();
    let env0 = t.env0;
    drop(t.control);
    std::fs::write(&f, &old).unwrap();
    sql(&url, &format!("UPDATE privacy_ledgers SET genesis = jsonb_set(genesis, '{{budget,epsilon}}', '\"3000.0\"'::jsonb) WHERE asset_id='{id}'"));
    let t = env0
        .start()
        .expect("starts: the operator is alarmed, not locked out");
    let mut n = 0;
    while n < 40 && spend(&t, &a_owner, &id, &format!("x-{n}"), 18).0 == 200 {
        n += 1;
    }
    assert_eq!(
        n, 0,
        "{n} spends acknowledged on the rewritten genesis (an honest cap is a few)"
    );
    let (s, v) = spend(&t, &a_owner, &id, "again", 18);
    assert!(
        s == 500
            && v["code"] == "ENC2202"
            && v["message"].as_str().unwrap().contains("not anchored"),
        "{s} {v}"
    );
    assert!(t
        .control
        .render_metrics()
        .contains("encompute_unanchored_ledgers{label=\"all\"} 1"));
}
