//! Concurrent denies in one organization all succeed (ENC-SF-2026-341).
//!
//! `govlog::append` locked the log's head and read the partition's size and
//! right edge in one statement; the reads used the snapshot taken before the
//! lock wait, so a transaction that had waited inserted a leaf at a position
//! the transaction before it had used: 500 ENC1701 "duplicate key ...
//! governance_tree_nodes_pkey" for most concurrent denies in one
//! organization. Nothing was acknowledged and a sequential retry succeeded,
//! but any two concurrent denies collided. The head is now locked in a
//! statement of its own and the partition read after it.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use std::sync::{Arc, Barrier};

use common::*;
use serde_json::{json, Value};

fn pg_client(url: &str) -> postgres::Client {
    postgres::Client::connect(url, postgres::NoTls).unwrap()
}

const THREADS: usize = 8;
const ROUNDS: usize = 20;

fn mk_asset(w: &World, name: &str) -> String {
    let v = w.t.ok(
        &w.a_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": "hospital-a", "kind": "dataset", "name": name,
                    "digest": "d".repeat(64)}),
        ),
    );
    v["id"].as_str().unwrap().to_owned()
}

/// Eight threads, twenty rounds: in each round every thread revokes its own
/// asset of the same organization at the same moment. Every call is 200,
/// every asset is revoked with exactly one event, and the log verifies. (On
/// the unchanged append this failed for more than half of the calls.)
#[test]
fn concurrent_denies_in_one_organization_all_succeed_and_the_chain_verifies() {
    let Some(w) = world() else { return };
    let url = w.t.env0.url.clone();
    let assets: Vec<Vec<String>> = (0..THREADS)
        .map(|th| {
            (0..ROUNDS)
                .map(|r| mk_asset(&w, &format!("live-{th}-{r}")))
                .collect()
        })
        .collect();
    let barrier = Arc::new(Barrier::new(THREADS));
    let results: Vec<Vec<(u16, Value)>> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..THREADS)
            .map(|th| {
                let (w, barrier, mine) = (&w, barrier.clone(), &assets[th]);
                sc.spawn(move || {
                    mine.iter()
                        .map(|id| {
                            barrier.wait();
                            w.t.call(
                                &w.a_owner,
                                "POST",
                                &format!("/v1/assets/{id}/revoke"),
                                Some(json!({})),
                            )
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let failed: Vec<&(u16, Value)> = results.iter().flatten().filter(|r| r.0 != 200).collect();
    assert!(
        failed.is_empty(),
        "{} of {} concurrent denies failed, first: {:?}",
        failed.len(),
        THREADS * ROUNDS,
        failed.first()
    );
    // Whatever failed would have been whole: status and event agree for
    // every asset (nothing half-applied).
    let mut c = pg_client(&url);
    for id in assets.iter().flatten() {
        let status: String = c
            .query_one("SELECT status FROM assets WHERE id = $1", &[id])
            .unwrap()
            .get(0);
        let events: i64 = c
            .query_one(
                "SELECT count(*) FROM governance_events WHERE kind = 'asset.revoked' AND subject_id = $1",
                &[id],
            )
            .unwrap()
            .get(0);
        assert_eq!(
            (status.as_str(), events),
            ("revoked", 1),
            "{id}: the status and its event agree"
        );
    }
    let mut cc = w.t.control.db.conn().unwrap();
    encompute_control::govlog::verify_chain(&mut *cc).expect("the chain verifies");
}

/// Users and assets of one organization denied at the same time, with
/// retries of the failed ones forbidden to hide a failure: a deny that did
/// fail would be whole (no status change without its event, no event without
/// its status), so the check is on every row either way.
#[test]
fn a_deny_that_fails_is_never_half_applied() {
    let Some(w) = world() else { return };
    let url = w.t.env0.url.clone();
    let n = 6;
    let users: Vec<String> = (0..n)
        .map(|i| {
            user(
                &w.t,
                &w.a_admin,
                "hospital-a",
                &format!("live-u{i}"),
                &["ml_developer"],
            );
            pg_client(&url)
                .query_one(
                    "SELECT id FROM users WHERE subject = $1",
                    &[&format!("live-u{i}")],
                )
                .unwrap()
                .get(0)
        })
        .collect();
    let assets: Vec<String> = (0..n).map(|i| mk_asset(&w, &format!("half-{i}"))).collect();
    let barrier = Arc::new(Barrier::new(2 * n));
    std::thread::scope(|sc| {
        for id in &users {
            let (w, b) = (&w, barrier.clone());
            sc.spawn(move || {
                b.wait();
                w.t.call(
                    &w.a_admin,
                    "POST",
                    &format!("/v1/organizations/hospital-a/users/{id}/disable"),
                    Some(json!({})),
                )
            });
        }
        for id in &assets {
            let (w, b) = (&w, barrier.clone());
            sc.spawn(move || {
                b.wait();
                w.t.call(
                    &w.a_owner,
                    "POST",
                    &format!("/v1/assets/{id}/revoke"),
                    Some(json!({})),
                )
            });
        }
    });
    let mut c = pg_client(&url);
    for id in &users {
        let s: String = c
            .query_one("SELECT status FROM users WHERE id = $1", &[id])
            .unwrap()
            .get(0);
        let e: i64 = c
            .query_one(
                "SELECT count(*) FROM governance_events WHERE kind = 'user.disabled' AND subject_id = $1",
                &[id],
            )
            .unwrap()
            .get(0);
        assert_eq!(
            (s == "disabled", e),
            (e == 1, e),
            "{id}: status and event agree"
        );
        assert_eq!(e, 1, "{id}: every concurrent deny succeeded");
    }
    for id in &assets {
        let s: String = c
            .query_one("SELECT status FROM assets WHERE id = $1", &[id])
            .unwrap()
            .get(0);
        let e: i64 = c
            .query_one(
                "SELECT count(*) FROM governance_events WHERE kind = 'asset.revoked' AND subject_id = $1",
                &[id],
            )
            .unwrap()
            .get(0);
        assert_eq!(
            (s == "revoked", e),
            (e == 1, e),
            "{id}: status and event agree"
        );
        assert_eq!(e, 1, "{id}: every concurrent deny succeeded");
    }
    let mut cc = w.t.control.db.conn().unwrap();
    encompute_control::govlog::verify_chain(&mut *cc).expect("the chain verifies");
}
