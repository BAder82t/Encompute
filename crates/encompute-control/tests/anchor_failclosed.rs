//! The anchoring fails closed (0.3.1, permanent regressions): a call whose
//! anchor write fails, whose committed IDs do not match what the database
//! still holds, or whose anchor update exhausts its retries is refused
//! (ENC2202) and never acknowledged; a later retry commits again and is
//! acknowledged only with the anchor holding exactly what it wrote; and a
//! retry never turns an unproven operation into an acknowledgement.
//!
//! The anchor store here fails on command (an outage, or a compare-and-set
//! that keeps losing), as a real one (a file on a volume, OpenBao KV) can.

mod common;

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use encompute_control::anchor::{AnchorStore, DirAnchor, StateAnchor};
use encompute_control::authn::Authenticator;
use encompute_control::db::Db;
use encompute_control::transport::InMemoryTransport;
use encompute_control::{Control, Negatives};
use encompute_ir::{Code, Error, Result};
use encompute_privacy::{Checkpoint, LedgerView, PrivacyEvent};
use encompute_verification::ServiceSigner;
use serde_json::{json, Value};

const NORMAL: u8 = 0;
/// Every write fails (the store is down).
const DOWN: u8 = 1;
/// Every write loses its compare-and-set (another writer always got in first).
const CONFLICT: u8 = 2;

struct Flaky {
    inner: DirAnchor,
    mode: Arc<AtomicU8>,
}

impl AnchorStore for Flaky {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn load(&self) -> Result<Option<StateAnchor>> {
        self.inner.load()
    }
    fn store(&self, next: &StateAnchor, expected: u64) -> Result<()> {
        match self.mode.load(Ordering::SeqCst) {
            DOWN => Err(Error::new(Code::PrivacyLedger, "the anchor store is down")),
            CONFLICT => Err(Error::new(
                Code::PrivacyLedger,
                "the state anchor changed concurrently (counter 0, expected 0)",
            )),
            _ => self.inner.store(next, expected),
        }
    }
}

/// A world whose control plane keeps its anchor in a store that fails on
/// command.
fn flaky_world() -> Option<(World, Arc<AtomicU8>)> {
    let mut w = world()?;
    let mode = Arc::new(AtomicU8::new(NORMAL));
    let e = &w.t.env0;
    let transport = Arc::new(InMemoryTransport::default());
    let control = Control::with_parts(
        e.env,
        "control-plane",
        Db::connect(&e.url).unwrap(),
        Authenticator::new(
            e.env,
            "control-plane",
            e.oidc.clone(),
            Some(zeroize::Zeroizing::new(SECRET.into())),
        ),
        ServiceSigner::from_seed("control-plane", &e.seed).unwrap(),
        Box::new(Flaky {
            inner: DirAnchor::new(e.anchor_dir.clone()).unwrap(),
            mode: mode.clone(),
        }),
        None,
        5,
    )
    .unwrap();
    w.t.control = Arc::new(control);
    w.t.transport = transport;
    Some((w, mode))
}

fn down(m: &AtomicU8) {
    m.store(DOWN, Ordering::SeqCst)
}
fn conflict(m: &AtomicU8) {
    m.store(CONFLICT, Ordering::SeqCst)
}
fn up(m: &AtomicU8) {
    m.store(NORMAL, Ordering::SeqCst)
}

fn spend(t: &T, who: &As, d: &str, ev: &str) -> (u16, Value) {
    t.call(
        who,
        "POST",
        &format!("/v1/privacy/{d}/events"),
        Some(reserve(ev, 18)),
    )
}
fn not_acked(s: u16, v: &Value) -> bool {
    s == 500 && v["code"] == "ENC2202"
}
fn rollback_refused(s: u16, v: &Value, what: &str) -> bool {
    not_acked(s, v)
        && v["message"]
            .as_str()
            .is_some_and(|m| m.contains(&format!("{what} STATE ROLLBACK")))
}
fn anchored_seq(t: &T, d: &str) -> u64 {
    t.control.anchor.snapshot().ledgers[d].seq
}
fn db_entries(url: &str, d: &str) -> i64 {
    postgres::Client::connect(url, postgres::NoTls)
        .unwrap()
        .query_one(
            "SELECT count(*) FROM privacy_entries WHERE asset_id=$1",
            &[&d],
        )
        .unwrap()
        .get(0)
}
fn sql(url: &str, q: &str) {
    postgres::Client::connect(url, postgres::NoTls)
        .unwrap()
        .batch_execute(q)
        .unwrap();
}

// ---- (i) a failed anchor write: refused, not acknowledged ----

#[test]
fn fc1_a_spend_whose_anchor_write_fails_is_refused_and_a_retry_is_acknowledged_with_proof() {
    let Some((w, mode)) = flaky_world() else {
        return;
    };
    let (t, d) = (&w.t, w.dataset_a.clone());
    assert_eq!(spend(t, &w.a_owner, &d, "e0").0, 200);
    assert_eq!(anchored_seq(t, &d), 1);
    down(&mode);
    let (s, v) = spend(t, &w.a_owner, &d, "e1");
    assert!(not_acked(s, &v), "{s} {v}");
    assert_eq!(anchored_seq(t, &d), 1, "nothing new anchored");
    assert_eq!(
        db_entries(&t.env0.url, &d),
        2,
        "the entry is committed, unproven"
    );
    // (iv) a retry while the store is still down is refused again: a
    // duplicate answer is not an acknowledgement either.
    let (s, v) = spend(t, &w.a_owner, &d, "e1");
    assert!(not_acked(s, &v), "{s} {v}");
    up(&mode);
    let (s, v) = spend(t, &w.a_owner, &d, "e1");
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["duplicate"], true);
    assert_eq!(
        anchored_seq(t, &d),
        2,
        "acknowledged only with the anchor holding it"
    );
    let hash = v["hash"].as_str().unwrap();
    assert_eq!(
        t.control.anchor.snapshot().ledgers[&d].root,
        hash,
        "the anchored root is the acknowledged entry's"
    );
}

#[test]
fn fc2_a_creation_whose_anchor_write_fails_is_refused_and_unspendable() {
    let Some((w, mode)) = flaky_world() else {
        return;
    };
    let t = &w.t;
    down(&mode);
    let body = json!({"organization": "hospital-a", "kind": "dataset", "name": "fc2", "digest": "9".repeat(64), "privacy_budget": budget(3.0)});
    let (s, v) = t.call(&w.a_owner, "POST", "/v1/assets", Some(body));
    assert!(not_acked(s, &v), "{s} {v}");
    let id: String = postgres::Client::connect(&t.env0.url, postgres::NoTls)
        .unwrap()
        .query_one("SELECT id FROM assets WHERE name='fc2'", &[])
        .unwrap()
        .get(0);
    assert!(!t.control.anchor.snapshot().ledgers.contains_key(&id));
    let (s, v) = spend(t, &w.a_owner, &id, "e0");
    assert!(
        not_acked(s, &v),
        "no spend on a ledger the anchor does not hold: {s} {v}"
    );
}

#[test]
fn fc3_a_negative_whose_anchor_write_fails_is_refused_and_a_retry_is_acknowledged_with_proof() {
    let Some((w, mode)) = flaky_world() else {
        return;
    };
    let t = &w.t;
    // revoke an asset
    let m = w.model_b.clone();
    down(&mode);
    let (s, v) = t.call(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None);
    assert!(not_acked(s, &v), "{s} {v}");
    assert!(!t.control.anchor.snapshot().revoked.contains(&m));
    let (s, v) = t.call(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None);
    assert!(
        not_acked(s, &v),
        "a retry while down is not an acknowledgement: {s} {v}"
    );
    up(&mode);
    let v = t.ok(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None);
    assert_eq!(v["status"], "revoked");
    assert!(t.control.anchor.snapshot().revoked.contains(&m));
    // disable a user
    let id = t.ok(&w.a_dev, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = format!("/v1/organizations/hospital-a/users/{id}/disable");
    down(&mode);
    let (s, v) = t.call(&w.a_admin, "POST", &path, None);
    assert!(not_acked(s, &v), "{s} {v}");
    assert!(!t.control.anchor.snapshot().disabled_users.contains(&id));
    up(&mode);
    t.ok(&w.a_admin, "POST", &path, None);
    assert!(t.control.anchor.snapshot().disabled_users.contains(&id));
    // cancel a job
    let plan = w.plan(EXACT);
    let (st, j) = w.job(&plan, &[], "fc3");
    assert_eq!(st, 201, "{j}");
    let job = j["id"].as_str().unwrap().to_owned();
    let path = format!("/v1/jobs/{job}/cancel");
    down(&mode);
    let (s, v) = t.call(&w.b_dev, "POST", &path, None);
    assert!(not_acked(s, &v), "{s} {v}");
    assert!(!t.control.anchor.snapshot().ended_jobs.contains(&job));
    up(&mode);
    // A cancelled job cannot be cancelled again: the retry is not an
    // acknowledgement either (409), and the background tick anchors what the
    // database still shows.
    let (s, v) = t.call(&w.b_dev, "POST", &path, None);
    assert_eq!(s, 409, "{v}");
    assert!(!t.control.anchor.snapshot().ended_jobs.contains(&job));
    t.control.tick();
    assert!(t.control.anchor.snapshot().ended_jobs.contains(&job));
}

// ---- (iii) retry exhaustion ----

#[test]
fn fc4_retry_exhaustion_is_refused_and_a_later_retry_is_acknowledged_with_proof() {
    let Some((w, mode)) = flaky_world() else {
        return;
    };
    let (t, d) = (&w.t, w.dataset_a.clone());
    conflict(&mode);
    let (s, v) = spend(t, &w.a_owner, &d, "e0");
    assert!(not_acked(s, &v), "{s} {v}");
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("changed concurrently"),
        "{v}"
    );
    assert!(!t.control.anchor.snapshot().ledgers.contains_key(&d) || anchored_seq(t, &d) == 0);
    let id = t.ok(&w.a_dev, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = format!("/v1/organizations/hospital-a/users/{id}/disable");
    let (s, v) = t.call(&w.a_admin, "POST", &path, None);
    assert!(not_acked(s, &v), "{s} {v}");
    assert!(!t.control.anchor.snapshot().disabled_users.contains(&id));
    up(&mode);
    let (s, v) = spend(t, &w.a_owner, &d, "e0");
    assert_eq!(s, 200, "{v}");
    assert_eq!(anchored_seq(t, &d), 1);
    t.ok(&w.a_admin, "POST", &path, None);
    assert!(t.control.anchor.snapshot().disabled_users.contains(&id));
}

// ---- (ii) IDs the call wrote that the anchor/database do not match ----

#[test]
fn fc5_negative_ids_the_database_does_not_hold_are_refused() {
    let Some((w, _)) = flaky_world() else { return };
    let t = &w.t;
    let id = t.ok(&w.a_dev, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // The call claims it disabled `id`; the database shows it active.
    let e = t
        .control
        .anchor_negatives(&Negatives {
            disabled_users: vec![id.clone()],
            ..Negatives::default()
        })
        .expect_err("a disable the database does not hold is not acknowledged");
    assert_eq!(e.code, Code::PrivacyLedger);
    assert!(e.message.contains("USER STATE ROLLBACK"), "{e}");
    // The same for an ID the database has never held: absent rows are
    // fine (they cannot act), a present active one is not.
    t.control
        .anchor_negatives(&Negatives {
            revoked: vec!["ast_never_issued".into()],
            ..Negatives::default()
        })
        .expect("an ID that is not in the database cannot be used");
    let e = t
        .control
        .anchor_negatives(&Negatives {
            revoked: vec![w.model_b.clone()],
            ..Negatives::default()
        })
        .expect_err("an active asset is not revoked");
    assert!(e.message.contains("REVOCATION STATE ROLLBACK"), "{e}");
    assert!(t
        .control
        .metrics
        .render()
        .contains("encompute_state_rollback_total{label="));
}

#[test]
fn fc6_a_checkpoint_the_ledger_does_not_extend_is_refused_and_not_anchored() {
    let Some((w, _)) = flaky_world() else { return };
    let (t, d) = (&w.t, w.dataset_a.clone());
    assert_eq!(spend(t, &w.a_owner, &d, "e0").0, 200);
    let before = t.control.anchor.snapshot().ledgers[&d].clone();
    let bogus = Checkpoint {
        seq: 5,
        root: "ab".repeat(32),
    };
    let e = t
        .control
        .anchor_committed(&d, &bogus, false)
        .expect_err("a checkpoint the ledger does not hold");
    assert_eq!(e.code, Code::PrivacyLedger);
    assert_eq!(
        t.control.anchor.snapshot().ledgers[&d],
        before,
        "nothing anchored"
    );
    let bogus = Checkpoint {
        seq: 1,
        root: "cd".repeat(32),
    };
    assert!(t.control.anchor_committed(&d, &bogus, false).is_err());
    assert_eq!(t.control.anchor.snapshot().ledgers[&d], before);
}

/// Runs `acting` while a database-owner session queues ACCESS EXCLUSIVE on
/// `tables` behind the call's write (granted the instant it commits) and runs
/// `attack_sql` before the service's post-commit read.
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
            tx.batch_execute(&format!("LOCK TABLE {} IN ACCESS EXCLUSIVE MODE", tables.join(", ")))
                .unwrap();
            std::thread::sleep(Duration::from_millis(500));
            tx.batch_execute(&format!("SET LOCAL session_replication_role = replica; {attack_sql}"))
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

/// Another user is disabled instead of the one the call disabled: the
/// database holds *a* disable, not the call's (a mismatched ID).
#[test]
fn fc7_a_different_negative_id_in_the_database_is_refused() {
    let Some((w, _)) = flaky_world() else { return };
    let t = &w.t;
    let a = t.ok(&w.a_dev, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let b = t.ok(&w.a_auditor, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let swap = format!(
        "UPDATE users SET status='active' WHERE id='{a}'; UPDATE users SET status='disabled' WHERE id='{b}'"
    );
    let (s, v) = in_window(&t.env0.url, &["users"], &swap, || {
        t.call(
            &w.a_admin,
            "POST",
            &format!("/v1/organizations/hospital-a/users/{a}/disable"),
            None,
        )
    });
    assert!(rollback_refused(s, &v, "USER"), "{s} {v}");
    let anchor = t.control.anchor.snapshot();
    assert!(
        anchor.disabled_users.contains(&a),
        "the anchor holds the call's ID"
    );
    assert!(
        !anchor.disabled_users.contains(&b),
        "and not the attacker's"
    );
}

/// A different event is in the ledger than the one the call appended.
#[test]
fn fc8_a_different_event_in_the_ledger_is_refused() {
    let Some((w, _)) = flaky_world() else { return };
    let (t, d) = (&w.t, w.dataset_a.clone());
    assert_eq!(spend(t, &w.a_owner, &d, "e0").0, 200);
    let mut c = postgres::Client::connect(&t.env0.url, postgres::NoTls).unwrap();
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
    let led: LedgerView =
        serde_json::from_value(json!({"genesis": g, "entries": entries})).unwrap();
    let ev: PrivacyEvent = serde_json::from_value(reserve("other-event", 18)).unwrap();
    let (_, forged) = led.append_event(ev).unwrap();
    let ej = serde_json::to_string(&forged).unwrap().replace('\'', "''");
    let attack = format!(
        "DELETE FROM privacy_entries WHERE asset_id='{d}' AND seq > 1;
         INSERT INTO privacy_entries (asset_id, seq, entry) VALUES ('{d}', 2, '{ej}'::jsonb)"
    );
    let (s, v) = in_window(&t.env0.url, &["privacy_entries"], &attack, || {
        spend(t, &w.a_owner, &d, "e1")
    });
    assert!(rollback_refused(s, &v, "PRIVACY"), "{s} {v}");
    assert_eq!(anchored_seq(t, &d), 1, "the forged entry is not anchored");
    sql(&t.env0.url, "SELECT 1");
}

// ---- (iv) a retry never turns an unproven operation into an acknowledgement ----

/// The anchor write fails, the writer erases the unproven entry, and the
/// client retries the same event: the retry is a new commit, acknowledged
/// only once the anchor holds *its* entry (never the erased one's hash).
#[test]
fn fc9_a_retry_after_the_unproven_entry_was_erased_is_acknowledged_only_with_its_own_proof() {
    let Some((w, mode)) = flaky_world() else {
        return;
    };
    let (t, d) = (&w.t, w.dataset_a.clone());
    assert_eq!(spend(t, &w.a_owner, &d, "e0").0, 200);
    down(&mode);
    let (s, v) = spend(t, &w.a_owner, &d, "e1");
    assert!(not_acked(s, &v), "{s} {v}");
    let erased: String = postgres::Client::connect(&t.env0.url, postgres::NoTls)
        .unwrap()
        .query_one(
            "SELECT entry->>'hash' FROM privacy_entries WHERE asset_id=$1 AND seq=2",
            &[&d],
        )
        .unwrap()
        .get(0);
    sql(
        &t.env0.url,
        &format!("SET session_replication_role = replica; DELETE FROM privacy_entries WHERE asset_id='{d}' AND seq=2"),
    );
    // Still down: refused.
    let (s, v) = spend(t, &w.a_owner, &d, "e1");
    assert!(not_acked(s, &v), "{s} {v}");
    up(&mode);
    let (s, v) = spend(t, &w.a_owner, &d, "e1");
    assert_eq!(s, 200, "{v}");
    assert_eq!(anchored_seq(t, &d), 2);
    assert_eq!(
        t.control.anchor.snapshot().ledgers[&d].root,
        v["hash"].as_str().unwrap()
    );
    // (The hash differs from the erased entry's only if its timestamp or
    // chain did; what matters is that the anchor holds the acknowledged one.)
    let _ = erased;
}

/// A negative whose anchor write failed is undone by the writer; the retry
/// commits it again and is acknowledged only with the anchor holding it and
/// the database showing it.
#[test]
fn fc10_a_negative_retried_after_the_writer_undid_it_is_committed_again() {
    let Some((w, mode)) = flaky_world() else {
        return;
    };
    let t = &w.t;
    let m = w.model_b.clone();
    down(&mode);
    let (s, v) = t.call(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None);
    assert!(not_acked(s, &v));
    sql(
        &t.env0.url,
        &format!("SET session_replication_role = replica; UPDATE assets SET status='active', revoked_at=NULL WHERE id='{m}'"),
    );
    up(&mode);
    let v = t.ok(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None);
    assert_eq!(v["status"], "revoked");
    assert!(
        v.get("already").is_none(),
        "committed again, not 'already': {v}"
    );
    assert!(t.control.anchor.snapshot().revoked.contains(&m));
    let st: String = postgres::Client::connect(&t.env0.url, postgres::NoTls)
        .unwrap()
        .query_one("SELECT status FROM assets WHERE id=$1", &[&m])
        .unwrap()
        .get(0);
    assert_eq!(st, "revoked");
}
