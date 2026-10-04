//! INV-226 and INV-160 and INV-192: the privacy ledgers' checkpoints are
//! events of the governance log (`privacy.ledger_checkpoint`), so the state
//! anchor is constant in size, and a restored older ledger is still
//! detected, frozen and refused, now through the log. A ledger's floor is
//! the latest such event of its asset, read through an index.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use common::*;
use encompute_control::govlog::{self, extra_kind, Draft};
use encompute_trust::govlog::{kind, Partition};
use serde_json::{json, Value};

fn spend(t: &T, who: &As, d: &str, ev: &str) -> (u16, Value) {
    t.call(
        who,
        "POST",
        &format!("/v1/privacy/{d}/events"),
        Some(reserve(ev, 200)),
    )
}

fn stored_anchor_json(env0: &Env0) -> Value {
    serde_json::from_slice(&std::fs::read(env0.anchor_dir.join("state-anchor.json")).unwrap())
        .unwrap()
}

fn checkpoint_events(t: &T, asset: &str) -> i64 {
    t.control
        .db
        .conn()
        .unwrap()
        .query_one(
            "SELECT count(*) FROM governance_events WHERE kind = $1 AND subject_id = $2",
            &[&extra_kind::LEDGER_CHECKPOINT, &asset],
        )
        .unwrap()
        .get(0)
}

/// The anchor holds the same fixed fields however many assets, revocations
/// and spends there are: its size at 10 000 revocations, a thousand more
/// ledgers and real spends is its size at the start (digits of its counters
/// apart), and no per-asset or per-ID field exists.
#[test]
fn anchor_size_is_constant_across_assets_revocations_and_spends() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let d = w.dataset_a.clone();
    let before = t.control.anchor.bytes();
    let keys = |t: &T| -> Vec<String> {
        let mut k: Vec<String> = serde_json::to_value(t.control.anchor.snapshot())
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        k.sort();
        k
    };
    let fields = keys(t);
    // Real spends, each anchored before it returns.
    for i in 0..3 {
        assert_eq!(spend(t, &w.a_owner, &d, &format!("s-{i}")).0, 200);
    }
    assert_eq!(t.control.ledger_floor(&d).unwrap().unwrap().seq, 3);
    // A thousand more ledgers' checkpoints, and 10 000 revocations (events
    // of assets the database does not hold: nothing here restarts).
    t.control
        .db
        .tx(|tx| {
            for i in 0..1000 {
                govlog::append_ledger_checkpoint(
                    tx,
                    &format!("ast_{i:032}"),
                    &encompute_privacy::Checkpoint {
                        seq: 1 + i as u64,
                        root: format!("{i:064x}"),
                    },
                )?;
            }
            for i in 0..10_000 {
                govlog::append(
                    tx,
                    Draft::new(
                        Partition::Platform,
                        kind::ASSET_REVOKED,
                        &format!("ast_r{i:031}"),
                    ),
                )?;
            }
            Ok(())
        })
        .unwrap();
    t.control.checkpoint_log().unwrap();
    // And spends afterwards, now with a log of 11 000 events behind them.
    for i in 3..5 {
        assert_eq!(spend(t, &w.a_owner, &d, &format!("s-{i}")).0, 200);
    }
    let after = t.control.anchor.bytes();
    assert!(
        after < before + 64,
        "the anchor grew from {before} to {after} bytes"
    );
    assert_eq!(keys(t), fields, "no per-asset or per-ID field");
    assert!(t.control.anchor.snapshot().glog_size > 11_000);
    assert_eq!(
        after,
        encompute_control::anchor::serialized_len(&t.control.anchor.snapshot())
    );
    let stored = std::fs::read_to_string(t.env0.anchor_dir.join("state-anchor.json")).unwrap();
    assert!(!stored.contains(&d), "no asset ID is in the anchor");
}

/// The rollback of INV-160 through the log: a backup restored under an
/// anchor and a log that moved on (the operator kept the log's events) is
/// refused at start, naming the ledger; the floor is the log's latest
/// checkpoint, not a field of the anchor; recovery freezes the ledger and
/// moves its floor to what the database holds, and spending stays refused.
/// Freezing is a deny event: the freeze is anchored before recovery returns.
#[test]
fn ledger_restore_detected_through_the_log() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    for i in 0..2 {
        assert_eq!(spend(&w.t, &w.a_owner, &d, &format!("s-{i}")).0, 200);
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
    let backup = format!("{}_lgbk", url.rsplit('/').next().unwrap());
    backup_database(&url, &backup);
    let t = env0.started();
    for i in 2..5 {
        assert_eq!(spend(&t, &a_owner, &d, &format!("s-{i}")).0, 200);
    }
    assert_eq!(t.control.ledger_floor(&d).unwrap().unwrap().seq, 5);
    // The floor is in the log, once per spend (the ledger's creation
    // included), and not in the anchor.
    assert_eq!(checkpoint_events(&t, &d), 1 + 5);
    assert!(stored_anchor_json(&env0).get("ledgers").is_none());
    let env0 = t.env0;
    drop(t.control);
    restore_keeping_log(&env0, &backup);
    let e = env0.start().err().expect("a restored ledger started");
    assert!(e.message.contains("PRIVACY STATE ROLLBACK"), "{e}");
    assert!(e.message.contains(&d), "{e}");

    let notes = run_recovery(&env0);
    assert!(
        notes.iter().any(|n| n.contains(&d) && n.contains("frozen")),
        "{notes:?}"
    );
    // The freeze (a deny event) is anchored when recovery returns, and so
    // is the ledger's new floor (what the database holds, behind the old).
    let a =
        serde_json::from_value::<encompute_control::anchor::StateAnchor>(stored_anchor_json(&env0))
            .unwrap();
    let t = env0.started();
    assert!(t
        .control
        .anchored(encompute_control::govlog::NegSet::FrozenLedgers, &d)
        .unwrap());
    let head = {
        let mut c = t.control.db.conn().unwrap();
        govlog::verify_chain(&mut *c).unwrap().0
    };
    assert!(a.glog_size <= head);
    assert_eq!(t.control.ledger_floor(&d).unwrap().unwrap().seq, 2);
    let v = t.ok(&a_auditor, "GET", &format!("/v1/privacy/{d}"), None);
    assert!(v["frozen"].is_string(), "{v}");
    let (s, v) = spend(&t, &a_owner, &d, "after-recovery");
    assert_eq!((s, v["code"].as_str()), (409, Some("ENC2201")), "{v}");
    // And it starts again.
    t.restarted();
}

/// A ledger frozen by recovery is anchored before `recover` returns: the
/// anchor already holds the log through the freeze event.
#[test]
fn ledger_freeze_is_anchored_before_the_call_returns() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    assert_eq!(spend(&w.t, &w.a_owner, &d, "s-0").0, 200);
    let url = w.t.env0.url.clone();
    let env0 = w.t.env0;
    drop(w.t.control);
    let backup = format!("{}_frzbk", url.rsplit('/').next().unwrap());
    backup_database(&url, &backup);
    let t = env0.started();
    for i in 1..3 {
        assert_eq!(spend(&t, &w.a_owner, &d, &format!("s-{i}")).0, 200);
    }
    let env0 = t.env0;
    drop(t.control);
    restore_keeping_log(&env0, &backup);
    run_recovery(&env0);
    // Read the anchor and the log without starting the control plane.
    let a =
        serde_json::from_value::<encompute_control::anchor::StateAnchor>(stored_anchor_json(&env0))
            .unwrap();
    let mut c = postgres::Client::connect(&env0.url, postgres::NoTls).unwrap();
    let freeze = govlog::first_gseq(&mut c, NegSet::FrozenLedgers, &d)
        .unwrap()
        .expect("the freeze is in the log");
    let (size, _) = govlog::verify_chain(&mut c).unwrap();
    assert!(
        freeze <= a.glog_size,
        "the freeze (event {freeze}) is past the anchored size {}",
        a.glog_size
    );
    assert_eq!(a.glog_size, size, "recovery anchored the whole log");
}

/// An ordinary spend writes one checkpoint event, and not a deny event: a
/// freeze is. A retry that finds the ledger no further than its checkpoint
/// appends nothing.
#[test]
fn spends_append_one_checkpoint_each_and_retries_none() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let d = &w.dataset_a;
    let n0 = checkpoint_events(t, d);
    assert_eq!(spend(t, &w.a_owner, d, "s-0").0, 200);
    assert_eq!(checkpoint_events(t, d), n0 + 1);
    // A duplicate delivery and a re-anchoring add none.
    assert_eq!(spend(t, &w.a_owner, d, "s-0").0, 200);
    t.control.anchor_ledger(d).unwrap();
    assert_eq!(checkpoint_events(t, d), n0 + 1);
    let a = t.control.anchor.snapshot();
    let mut c = t.control.db.conn().unwrap();
    let (size, head) = govlog::verify_chain(&mut *c).unwrap();
    assert_eq!((a.glog_size, a.glog_head), (size, head));
    // The event's leaf holds the entry count and the root, nothing else.
    let refs: Value = c
        .query_one(
            "SELECT body -> 'refs' FROM governance_events WHERE kind = $1 AND subject_id = $2
              ORDER BY gseq DESC LIMIT 1",
            &[&extra_kind::LEDGER_CHECKPOINT, d],
        )
        .unwrap()
        .get(0);
    let mut keys: Vec<&str> = refs
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort();
    assert_eq!(keys, ["root", "seq"]);
    assert_eq!(refs["seq"], json!("1"));
}

/// The latest checkpoint of an asset is one probe of the partial index
/// (subject, newest first): no scan of the log behind it, no sort of the
/// asset's checkpoints, whether the asset spends constantly or checkpointed
/// twice long before thousands of other events; and the startup read of
/// every floor agrees.
#[test]
fn latest_ledger_checkpoint_lookup_is_indexed() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let cp = |seq: u64| encompute_privacy::Checkpoint {
        seq,
        root: format!("{seq:064x}"),
    };
    let (cold, hot) = (format!("ast_{:032}", 1), format!("ast_{:032}", 2));
    t.control
        .db
        .tx(|tx| {
            // The cold asset: two checkpoints, then the log moves on.
            govlog::append_ledger_checkpoint(tx, &cold, &cp(1))?;
            govlog::append_ledger_checkpoint(tx, &cold, &cp(2))?;
            // 300 assets of ten checkpoints each, and one asset of 3000,
            // interleaved.
            for i in 1..=3000u64 {
                govlog::append_ledger_checkpoint(tx, &hot, &cp(i))?;
                if i % 10 == 0 {
                    for a in 0..10 {
                        govlog::append_ledger_checkpoint(
                            tx,
                            &format!("ast_{:032}", 100 + (i / 10 + a) % 300),
                            &cp(i),
                        )?;
                    }
                }
            }
            Ok(())
        })
        .unwrap();
    let mut c = t.control.db.conn().unwrap();
    assert_eq!(
        govlog::latest_ledger_checkpoint(&mut *c, &hot)
            .unwrap()
            .unwrap()
            .seq,
        3000
    );
    assert_eq!(
        govlog::latest_ledger_checkpoint(&mut *c, &cold)
            .unwrap()
            .unwrap()
            .seq,
        2,
        "the latest, not the first and not the largest asset's"
    );
    assert!(govlog::latest_ledger_checkpoint(&mut *c, "ast_none")
        .unwrap()
        .is_none());
    let floors = govlog::ledger_floors(&mut *c).unwrap();
    assert_eq!(floors.iter().find(|(a, _)| *a == hot).unwrap().1.seq, 3000);
    assert_eq!(floors.iter().find(|(a, _)| *a == cold).unwrap().1.seq, 2);
    assert!(floors.len() >= 302);
    // The plans of the lookup (as the control plane issues it).
    c.batch_execute("ANALYZE governance_events").unwrap();
    // The startup read of every floor is a skip scan: a recursive union of
    // probes of the partial index (one per asset), not a pass over the
    // checkpoints and not a Sort or HashAggregate of them.
    {
        let mut tx = c.transaction().unwrap();
        tx.batch_execute("SET LOCAL enable_seqscan = off").unwrap();
        let plan: Vec<String> = tx
            .query(
                &format!(
                    "EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF) {}",
                    govlog::ledger_floors_sql()
                ),
                &[],
            )
            .unwrap()
            .iter()
            .map(|r| r.get::<_, String>(0))
            .collect();
        let plan = plan.join("\n");
        assert!(plan.contains("Recursive Union"), "{plan}");
        assert!(
            plan.contains("governance_events_ledger_checkpoint"),
            "{plan}"
        );
        assert!(!plan.contains("HashAggregate"), "{plan}");
    }
    for (asset, indexed) in [(&cold, true), (&hot, false)] {
        let plan: Vec<String> = c
            .query(
                "EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF)
                 SELECT body -> 'refs' FROM governance_events
                  WHERE kind = 'privacy.ledger_checkpoint' AND subject_id = $1
                  ORDER BY gseq DESC LIMIT 1",
                &[asset],
            )
            .unwrap()
            .iter()
            .map(|r| r.get::<_, String>(0))
            .collect();
        let plan = plan.join("\n");
        assert!(
            !plan.contains("Seq Scan") && !plan.contains("Sort"),
            "{plan}"
        );
        assert!(plan.contains("Index Scan"), "{plan}");
        assert!(plan.contains("rows=1 "), "{plan}");
        if indexed {
            assert!(
                plan.contains("governance_events_ledger_checkpoint"),
                "{plan}"
            );
        }
    }
}

/// Startup reads each ledger's floor from the log: a ledger the database
/// lost, whose checkpoint the log holds, is refused, naming it.
#[test]
fn a_missing_ledger_with_a_checkpoint_is_refused_at_start() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    assert_eq!(spend(&w.t, &w.a_owner, &d, "s-0").0, 200);
    let url = w.t.env0.url.clone();
    drop(w.t.control);
    attacker(
        &url,
        &["privacy_ledgers", "privacy_entries"],
        &format!("DELETE FROM privacy_entries WHERE asset_id = '{d}'; DELETE FROM privacy_ledgers WHERE asset_id = '{d}'"),
    );
    let e = w.t.env0.start().err().expect("a missing ledger started");
    assert!(e.message.contains("PRIVACY STATE ROLLBACK"), "{e}");
    assert!(e.message.contains(&d), "{e}");
}

/// Root cause of the intermittent "the privacy ledger of ast_... is missing
/// (the version-1 state anchor was not migrated)" start-up refusals: the
/// harness named a test's anchor directory by process ID and a counter
/// only, never removed it, and reused one that existed. A process ID that
/// came round again found an earlier run's directory, with its version-1
/// anchor, and the control plane (rightly) refused a database that had none
/// of its ledgers. A scratch directory is now always new and empty.
#[test]
fn scratch_directories_are_never_reused() {
    let probe = tmp_dir("sc");
    // encompute-control-sc_{pid}_{counter}_{time} (the harness's unique names).
    let n: u64 = probe
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .split('_')
        .nth(2)
        .unwrap()
        .parse()
        .unwrap();
    // Earlier runs' leftovers under the names this process would use next
    // (in the old and the current scheme).
    let pid = std::process::id();
    let mut stale = vec![];
    for k in n + 1..n + 40 {
        let d = std::env::temp_dir().join(format!("encompute-control-sc-{pid}-{k}"));
        if std::fs::create_dir(&d).is_ok() {
            std::fs::write(d.join("state-anchor.json"), b"{\"version\": 1}").unwrap();
            stale.push(d);
        }
    }
    let mut seen = std::collections::HashSet::new();
    for _ in 0..39 {
        let d = tmp_dir("sc");
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0, "{}", d.display());
        assert!(
            seen.insert(d.clone()),
            "{} was handed out twice",
            d.display()
        );
    }
    for d in stale {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// A consistently rewound database (ledger entries, checkpoint events and
/// the log's head alike) passes the ledger's own floor; the spend path
/// still refuses it, before anything is written, because the log no longer
/// holds the anchored head.
#[test]
fn a_spend_on_a_consistently_rewound_database_is_refused_before_it_commits() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    for i in 0..2 {
        assert_eq!(spend(&w.t, &w.a_owner, &d, &format!("s-{i}")).0, 200);
    }
    let url = w.t.env0.url.clone();
    // Rewind: the last spend's ledger entry and the log from its
    // checkpoint event on (the anchor holds the later head).
    let mut c = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let cut: i64 = c
        .query_one(
            "SELECT max(gseq) FROM governance_events WHERE kind = $1 AND subject_id = $2",
            &[&extra_kind::LEDGER_CHECKPOINT, &d],
        )
        .unwrap()
        .get(0);
    let before = w.t.control.anchor.snapshot();
    assert!(before.glog_size >= cut);
    drop(c);
    attacker(
        &url,
        &[
            "privacy_entries",
            "governance_events",
            "governance_head",
            "governance_tree_nodes",
            "governance_checkpoints",
        ],
        &format!(
            "DELETE FROM privacy_entries WHERE asset_id = '{d}' AND seq = 2;
             DELETE FROM governance_checkpoints WHERE size >= {cut};
             DELETE FROM governance_tree_nodes WHERE partition = 'platform' AND level = 0
                 AND idx >= (SELECT pseq - 1 FROM governance_events WHERE gseq = {cut});
             DELETE FROM governance_events WHERE gseq >= {cut};
             UPDATE governance_head SET gseq = {prev}, hash = (SELECT hash FROM governance_events WHERE gseq = {prev})",
            prev = cut - 1
        ),
    );
    let (s, v) = spend(&w.t, &w.a_owner, &d, "after-rewind");
    assert_eq!((s, v["code"].as_str()), (500, Some("ENC2202")), "{v}");
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("GOVERNANCE LOG STATE ROLLBACK"),
        "{v}"
    );
    let mut c = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let n: i64 = c
        .query_one(
            "SELECT count(*) FROM privacy_entries WHERE asset_id = $1",
            &[&d],
        )
        .unwrap()
        .get(0);
    assert_eq!(n, 1, "nothing was committed on the rewound ledger");
    assert_eq!(
        w.t.control.anchor.snapshot(),
        before,
        "nothing was anchored"
    );
}

/// Spends are limited per actor and asset, and a reservation that charges
/// next to nothing is refused (each is an event of the log and its mirror).
#[test]
fn spends_are_rate_limited_per_actor_and_asset_and_tiny_rho_is_refused() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let d = w.dataset_a.clone();
    t.control.spend_limit.set(3);
    for i in 0..3 {
        assert_eq!(spend(t, &w.a_owner, &d, &format!("r-{i}")).0, 200);
    }
    let (s, v) = spend(t, &w.a_owner, &d, "r-3");
    assert_ne!(s, 200, "{v}");
    assert!(
        v["message"].as_str().unwrap().contains("privacy spend"),
        "{v}"
    );
    // Not charged: nothing was written for the refused one.
    assert_eq!(t.control.ledger_floor(&d).unwrap().unwrap().seq, 3);
    // Another asset (and another actor) has its own allowance.
    let other = t.ok(
        &w.a_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": "hospital-a", "kind": "dataset", "name": "second",
                    "digest": "c".repeat(64), "privacy_budget": budget(3.0)}),
        ),
    );
    let o = other["id"].as_str().unwrap();
    assert_eq!(spend(t, &w.a_owner, o, "r-0").0, 200);
    t.control.spend_limit.set(1200);
    // A reservation charging less than the floor is refused.
    let (s, v) = t.call(
        &w.a_owner,
        "POST",
        &format!("/v1/privacy/{d}/events"),
        Some(reserve("tiny", 4_000_000_000)),
    );
    assert_ne!(s, 200, "{v}");
    assert_eq!(v["code"], "ENC2204", "{v}");
}

/// A measurement behind the capacity note in deployment.md: what a spend
/// adds to the governance log and its mirror.
#[test]
fn a_spend_adds_one_small_event_to_the_log_and_the_mirror() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let d = w.dataset_a.clone();
    let size = |t: &T| t.control.anchor.snapshot().glog_size;
    let mirror = |t: &T| -> u64 {
        std::fs::read_dir(t.env0.anchor_dir.join("governance-log"))
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum()
    };
    let (n0, b0) = (size(t), mirror(t));
    for i in 0..20 {
        assert_eq!(spend(t, &w.a_owner, &d, &format!("m-{i}")).0, 200);
    }
    let (events, bytes) = (size(t) - n0, mirror(t) - b0);
    assert_eq!(events, 20, "one event per spend");
    let per = bytes / 20;
    eprintln!("MIRROR GROWTH: {per} bytes per spend");
    assert!(per < 700, "{per} bytes per spend");
}
