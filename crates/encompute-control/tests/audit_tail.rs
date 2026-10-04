//! The audit chain's tail: which audit events the anchor covers, and when.
//!
//! The state anchor holds the audit chain's head next to the governance
//! log's, in one signed record with one commit point (the anchor's
//! compare-and-set). A checkpoint of the log (forced and synchronous for
//! every security deny event, and run by the background pass every two
//! seconds) anchors the audit head with it, so:
//!
//! - a deny call does not return before every audit event committed
//!   before it, its own included, is anchored: truncating them is
//!   refused at the next start (AUDIT STATE ROLLBACK);
//! - an ordinary audit event (one that grants or merely records) waits for
//!   the next checkpoint: at most the background pass, 2 seconds by
//!   default, or the next deny event. Truncating that unanchored tail is
//!   not detectable, and these tests state it rather than hide it;
//! - the audit chain has no mirror: the anchor detects a truncated chain,
//!   it never restores one.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use std::sync::atomic::Ordering;

use common::*;
use serde_json::json;

fn audit_head(url: &str) -> (i64, String) {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    let r = c
        .query_one("SELECT seq, hash FROM audit_head WHERE id", &[])
        .unwrap();
    (r.get(0), r.get(1))
}

/// Deletes the audit events after `keep` and moves the head back (a
/// database attacker truncating the tail).
fn truncate_audit(url: &str, keep: i64) {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    c.batch_execute(&format!(
        "DELETE FROM audit_events WHERE seq > {keep};
         UPDATE audit_head SET seq = {keep}, hash = (SELECT hash FROM audit_events WHERE seq = {keep})"
    ))
    .unwrap();
}

/// A user the organization's admin disables: a security deny event.
fn disable_a_user(w: &World, name: &str) {
    let u = user(&w.t, &w.a_admin, "hospital-a", name, &["ml_developer"]);
    let id = w.t.ok(&u, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    w.t.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/organizations/hospital-a/users/{id}/disable"),
        None,
    );
}

/// A deny call returns only once the audit chain is anchored up to the
/// head the call left (its own audit event included); truncating the
/// events after the previous checkpoint is then refused. Before the audit
/// head joined the log's checkpoint, the anchor lagged the head and this
/// truncation started silently.
#[test]
fn a_deny_call_anchors_the_audit_events_before_it() {
    let Some(w) = world() else { return };
    // Ordinary events first: they are in the chain, not yet anchored.
    for i in 0..3 {
        w.t.ok(
            &w.b_dev,
            "POST",
            "/v1/projects",
            Some(json!({"organization": "modelco", "name": format!("tail-{i}")})),
        );
    }
    let (before, _) = audit_head(&w.t.env0.url);
    assert!(w.t.control.anchor.snapshot().audit_seq < before);
    disable_a_user(&w, "tail-victim");
    let (head, root) = audit_head(&w.t.env0.url);
    let a = w.t.control.anchor.snapshot();
    assert_eq!(
        (a.audit_seq, a.audit_root.as_str()),
        (head, root.as_str()),
        "the deny call returned with the audit chain anchored only to {}",
        a.audit_seq
    );
    // The three ordinary events and the deny's own audit event are
    // covered: dropping any of them is a rollback.
    let url = w.t.env0.url.clone();
    let env0 = w.t.env0;
    drop(w.t.control);
    truncate_audit(&url, before);
    let e = env0.start().err().expect("a truncated audit tail started");
    assert!(e.message.contains("AUDIT STATE ROLLBACK"), "{e}");
}

/// The background pass (the log's checkpoint) anchors the ordinary audit
/// events nobody forced. The window before it is real and bounded by that
/// pass: truncating inside it is not detected, and nothing is replayed or
/// resurrected.
#[test]
fn ordinary_audit_events_wait_for_the_next_checkpoint_and_no_longer() {
    let Some(w) = world() else { return };
    w.t.control.checkpoint_log().unwrap();
    let anchored = w.t.control.anchor.snapshot();
    w.t.ok(
        &w.b_dev,
        "POST",
        "/v1/projects",
        Some(json!({"organization": "modelco", "name": "ordinary"})),
    );
    let (head, _) = audit_head(&w.t.env0.url);
    // Not anchored by the request itself.
    assert_eq!(w.t.control.anchor.snapshot(), anchored);
    assert!(head > anchored.audit_seq);
    // The next pass anchors it, whatever the 100-event threshold says.
    w.t.control.checkpoint_log().unwrap();
    let a = w.t.control.anchor.snapshot();
    assert_eq!(a.audit_seq, head);
    // A pass with nothing new writes nothing.
    w.t.control.checkpoint_log().unwrap();
    assert_eq!(w.t.control.anchor.snapshot().counter, a.counter);
    // Inside the window (events after the last checkpoint) a truncation
    // is accepted: the database is ahead of the anchor, never behind.
    w.t.ok(
        &w.b_dev,
        "POST",
        "/v1/projects",
        Some(json!({"organization": "modelco", "name": "unanchored"})),
    );
    let url = w.t.env0.url.clone();
    let env0 = w.t.env0;
    drop(w.t.control);
    truncate_audit(&url, head);
    let t = env0.started();
    assert_eq!(t.control.anchor.snapshot().audit_seq, head);
}

/// The anchor store failing at the commit point: the deny call fails (the
/// database already enforces the change), the anchor keeps its old audit
/// head, and the next checkpoint, after the store is back, anchors the
/// audit events too. A crash in the same window leaves the database ahead
/// of the anchor, which a start accepts.
#[test]
fn a_failed_anchor_write_leaves_the_audit_tail_for_the_next_checkpoint() {
    let Some(env0) = setup().map(|t| {
        let e = t.env0;
        drop(t.control);
        e
    }) else {
        return;
    };
    let (t, fail) = env0.start_flaky();
    t.control
        .bootstrap(encompute_control::authn::DEV_ISSUER, "platform-admin", None)
        .unwrap();
    let platform = As::User("platform-admin".into());
    t.ok(
        &platform,
        "POST",
        "/v1/organizations",
        Some(json!({"id": "org-x", "display_name": "x", "admin": {"issuer": encompute_control::authn::DEV_ISSUER, "subject": "x-admin"}})),
    );
    t.control.checkpoint_log().unwrap();
    let anchored = t.control.anchor.snapshot();
    let x_admin = As::User("x-admin".into());
    let u = user(&t, &x_admin, "org-x", "x-user", &["ml_developer"]);
    let id = t.ok(&u, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    t.control.checkpoint_log().unwrap();
    let anchored2 = t.control.anchor.snapshot();
    assert!(anchored2.audit_seq > anchored.audit_seq);
    fail.store(true, Ordering::SeqCst);
    let (s, _) = t.call(
        &x_admin,
        "POST",
        &format!("/v1/organizations/org-x/users/{id}/disable"),
        None,
    );
    assert_ne!(s, 200, "a deny call succeeded without its anchor");
    assert_eq!(t.control.anchor.snapshot(), anchored2);
    let (head, _) = audit_head(&t.env0.url);
    assert!(
        head > anchored2.audit_seq,
        "the deny's audit event is in the database"
    );
    // The database is ahead of the anchor: a restart accepts it, and the
    // next checkpoint anchors the log and the audit chain together.
    let env0 = t.env0;
    drop(t.control);
    let t = env0.started();
    t.control.checkpoint_log().unwrap();
    let a = t.control.anchor.snapshot();
    assert_eq!(a.audit_seq, audit_head(&t.env0.url).0);
    assert!(a.audit_seq >= head);
}
