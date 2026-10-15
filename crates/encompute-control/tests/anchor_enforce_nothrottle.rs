//! Continuous enforcement is never skipped (0.3.1, ENC-SF-2026-413, B1).
//!
//! The live rollback check used to be throttled: once a check took more than
//! 20 ms, the next ones within ten times that (at most 2 s) were skipped. The
//! measured time included waits the database writer or a slow anchor write
//! controls, so a writer who held a table lock for 200 ms bought itself two
//! seconds in which a restored revocation (or disable) passed unseen.
//!
//! The invariant: a slow database operation, a lock wait, a slow anchor
//! write or an overloaded machine NEVER lets a protected request bypass the
//! live check. A check that cannot complete fails the request (closed); it
//! is not a pass, and, being no proof of a rollback, it does not latch.
//!
//! Each test makes one request wait at the check for 400 ms (a table lock the
//! check reads, or the anchor's lock), lets it finish, and then, at once and
//! well inside the old two-second window, restores an acknowledged
//! transition and calls the protected operation as the revoked principal.

mod common;

use common::*;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

fn sql(url: &str, q: &str) {
    postgres::Client::connect(url, postgres::NoTls)
        .unwrap()
        .batch_execute(&format!("SET session_replication_role = replica; {q}"))
        .unwrap();
}

fn http(w: &World) -> Client {
    let addr = live(
        &w.t.control,
        encompute_verification::http::Limits::default(),
    );
    Client::new(addr)
}

fn succeeded(s: u16) -> bool {
    (200..300).contains(&s)
}

fn state_refused(s: u16, v: &Value) -> bool {
    s == 500
        && v["code"] == "ENC2202"
        && v["message"]
            .as_str()
            .is_some_and(|m| m.contains("STATE ROLLBACK"))
}

/// A second connection that holds `LOCK TABLE <table> IN ACCESS EXCLUSIVE
/// MODE` for `hold`; returns once the lock is taken.
fn hold_table(url: &str, table: &str, hold: Duration) -> std::thread::JoinHandle<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    let (url, table) = (url.to_owned(), table.to_owned());
    let h = std::thread::spawn(move || {
        let mut c = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        c.batch_execute(&format!(
            "BEGIN; LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"
        ))
        .unwrap();
        tx.send(()).unwrap();
        std::thread::sleep(hold);
        c.batch_execute("COMMIT").unwrap();
    });
    rx.recv().unwrap();
    h
}

/// The protected operation is refused with the state-rollback error, the
/// service is latched (a second, unrelated request is refused too) and
/// `/ready` is 503.
fn assert_latched(w: &World, cl: &Client, name: &str, first: (u16, Value)) {
    assert!(
        state_refused(first.0, &first.1),
        "{name}: the protected operation after the revert: {} {}",
        first.0,
        first.1
    );
    let (s, v) = cl.call(&w.a_owner, "GET", "/v1/whoami", None);
    assert!(state_refused(s, &v), "{name}: latched: {s} {v}");
    let (s, _) = cl.raw("GET", "/ready", &[], &[]);
    assert_eq!(s, 503, "{name}: /ready");
}

fn submit(cl: &Client, w: &World, plan: &str, sources: &[&str], key: &str) -> (u16, Value) {
    cl.call_with(
        &w.b_dev,
        "POST",
        "/v1/jobs",
        Some(
            json!({"project": w.project, "plan": plan, "purpose": "medical-training",
                    "source_assets": sources, "requested_output": "out"}),
        ),
        &[("Idempotency-Key", key)],
    )
}

/// One honest request that has to wait `>= 300 ms` at the check.
fn slow_honest_request(w: &World, cl: &Client, why: &str) {
    let t0 = Instant::now();
    let (s, v) = cl.call(&w.a_owner, "GET", "/v1/whoami", None);
    let d = t0.elapsed();
    assert!(succeeded(s), "{why}: the honest request: {s} {v}");
    assert!(
        d >= Duration::from_millis(300),
        "{why}: the request did not wait at the check ({d:?}); the test proves nothing"
    );
    eprintln!("NOTHROTTLE {why}: the honest request waited {d:?}");
}

/// (a1) A writer holds a lock on `assets` for 400 ms (the check's first read
/// waits), then restores a revoked asset within the old skip window: the next
/// job over the asset is refused and the control plane latched.
#[test]
fn table_lock_wait_does_not_skip_the_check_asset_revocation() {
    let Some(w) = world() else { return };
    let cl = http(&w);
    let m = w.model_b.clone();
    let url = w.t.env0.url.clone();
    let plan = w.plan(&exact_own(&m));
    cl.ok(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None);
    assert!(w.t.control.anchor.snapshot().revoked.contains(&m));
    let lock = hold_table(&url, "assets", Duration::from_millis(400));
    slow_honest_request(&w, &cl, "assets lock");
    lock.join().unwrap();
    sql(
        &url,
        &format!("UPDATE assets SET status='active', revoked_at=NULL WHERE id='{m}'"),
    );
    let first = submit(&cl, &w, &plan, &[&m], "attack");
    eprintln!(
        "NOTHROTTLE revoke asset after the lock wait: {} {}",
        first.0, first.1
    );
    assert!(
        !succeeded(first.0),
        "a revoked asset runs a job inside the old skip window: {} {}",
        first.0,
        first.1
    );
    assert_latched(&w, &cl, "revoke asset after the lock wait", first);
}

/// (a2) The same for a disabled user and a lock on `users`.
#[test]
fn table_lock_wait_does_not_skip_the_check_user_disable() {
    let Some(w) = world() else { return };
    let cl = http(&w);
    let id = cl.ok(&w.a_dev, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    cl.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/organizations/hospital-a/users/{id}/disable"),
        None,
    );
    assert!(w.t.control.anchor.snapshot().disabled_users.contains(&id));
    let (s, _) = cl.call(&w.a_dev, "GET", "/v1/whoami", None);
    assert!(!succeeded(s));
    let url = w.t.env0.url.clone();
    let lock = hold_table(&url, "users", Duration::from_millis(400));
    slow_honest_request(&w, &cl, "users lock");
    lock.join().unwrap();
    sql(
        &url,
        &format!("UPDATE users SET status='active' WHERE id='{id}'"),
    );
    let first = cl.call(&w.a_dev, "GET", "/v1/whoami", None);
    eprintln!(
        "NOTHROTTLE disable user after the lock wait: {} {}",
        first.0, first.1
    );
    assert!(
        !succeeded(first.0),
        "a disabled user authenticates inside the old skip window: {} {}",
        first.0,
        first.1
    );
    assert_latched(&w, &cl, "disable user after the lock wait", first);
}

/// (b) A slow anchor write holds the anchor's lock for 400 ms (what a slow
/// remote anchor store does): the request waits at the check. Restoring the
/// revocation right after is still found.
#[test]
fn slow_anchor_write_does_not_skip_the_check() {
    let Some(w) = world() else { return };
    let cl = http(&w);
    let m = w.model_b.clone();
    let url = w.t.env0.url.clone();
    let plan = w.plan(&exact_own(&m));
    cl.ok(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None);
    assert!(w.t.control.anchor.snapshot().revoked.contains(&m));
    let (tx, rx) = std::sync::mpsc::channel();
    let control = w.t.control.clone();
    let writer = std::thread::spawn(move || {
        control
            .anchor
            .try_update(&control.signer, |_| {
                let _ = tx.send(());
                std::thread::sleep(Duration::from_millis(400));
                Ok(false)
            })
            .unwrap();
    });
    rx.recv().unwrap();
    slow_honest_request(&w, &cl, "anchor lock");
    writer.join().unwrap();
    sql(
        &url,
        &format!("UPDATE assets SET status='active', revoked_at=NULL WHERE id='{m}'"),
    );
    let first = submit(&cl, &w, &plan, &[&m], "attack");
    eprintln!(
        "NOTHROTTLE revoke asset after the slow anchor write: {} {}",
        first.0, first.1
    );
    assert!(
        !succeeded(first.0),
        "a revoked asset runs a job after a slow anchor write: {} {}",
        first.0,
        first.1
    );
    assert_latched(&w, &cl, "revoke asset after the slow anchor write", first);
}

/// (c) The check cannot complete: a writer holds the lock on `assets` far
/// longer than the check's own lock timeout. The request must FAIL (not pass),
/// without the rollback error (a database that does not answer is not proof
/// of a rollback) and without latching; once the lock is gone the service
/// answers again, and a restored revocation is then found.
#[test]
fn a_check_that_cannot_complete_fails_the_request() {
    let Some(w) = world() else { return };
    let cl = http(&w);
    let m = w.model_b.clone();
    let url = w.t.env0.url.clone();
    let plan = w.plan(&exact_own(&m));
    cl.ok(&w.b_owner, "POST", &format!("/v1/assets/{m}/revoke"), None);
    let lock = hold_table(&url, "assets", Duration::from_secs(8));
    let t0 = Instant::now();
    let (s, v) = cl.call(&w.a_owner, "GET", "/v1/whoami", None);
    let waited = t0.elapsed();
    eprintln!("NOTHROTTLE unfinished check: {s} {v} after {waited:?}");
    assert!(
        !succeeded(s),
        "a request passes although the check could not complete: {s} {v}"
    );
    assert!(
        waited < Duration::from_secs(7),
        "the check waited for the lock for {waited:?}: it is not bounded"
    );
    assert!(
        !state_refused(s, &v),
        "a database that does not answer is not a rollback: {s} {v}"
    );
    lock.join().unwrap();
    let (s, v) = cl.call(&w.a_owner, "GET", "/v1/whoami", None);
    assert!(succeeded(s), "not latched by the failed check: {s} {v}");
    let (s, _) = cl.raw("GET", "/ready", &[], &[]);
    assert_eq!(s, 200, "/ready after the failed check");
    sql(
        &url,
        &format!("UPDATE assets SET status='active', revoked_at=NULL WHERE id='{m}'"),
    );
    let first = submit(&cl, &w, &plan, &[&m], "attack");
    assert_latched(&w, &cl, "revoke asset after the failed check", first);
}
