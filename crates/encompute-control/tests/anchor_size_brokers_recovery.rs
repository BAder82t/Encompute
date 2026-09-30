//! Pre-merge fixes: the state anchor's size is measured and exported, the
//! key-broker checks of service-account and asset registration serialize
//! on one lock, and recovery re-creates a frozen ledger whose row the
//! database lost.

mod common;

use std::time::Duration;

use common::*;
use serde_json::json;

fn anchor_bytes_metric(rendered: &str) -> u64 {
    rendered
        .lines()
        .find_map(|l| l.strip_prefix("encompute_anchor_bytes{label=\"all\"} "))
        .unwrap_or_else(|| panic!("no encompute_anchor_bytes in:\n{rendered}"))
        .parse()
        .unwrap()
}

/// The anchor is re-signed whole on every write and an OpenBao KV entry is
/// limited in size (1 MiB by default), so its serialized size is measured
/// on every write and at startup and exported as `encompute_anchor_bytes`.
#[test]
fn the_anchor_size_is_measured_on_every_write_and_exported() {
    let Some(w) = world() else { return };
    let t = &w.t;
    use encompute_control::anchor::{serialized_len, ANCHOR_WARN_BYTES};
    // Set at startup, and served on /metrics.
    let at_start = anchor_bytes_metric(&t.control.metrics.render());
    assert!(at_start > 0);
    assert!(at_start < ANCHOR_WARN_BYTES);
    let (s, _) = t.call(&As::Nobody, "GET", "/metrics", None);
    assert_eq!(s, 200);
    let now = t.control.anchor.bytes();
    assert_eq!(now, serialized_len(&t.control.anchor.snapshot()));
    assert_eq!(anchor_bytes_metric(&t.control.render_metrics()), now);
    // Every write measures it again.
    t.control
        .anchor
        .update(&t.control.signer, |a| {
            // (Removed roles: their anchored state is the absence of their
            // rows, so IDs the database never held pass the start check;
            // an ended job the database does not hold is a rollback.)
            for i in 0..100 {
                a.removed_roles.insert(format!("rol_{i:032}"));
            }
        })
        .unwrap();
    let grown = t.control.anchor.bytes();
    assert!(grown > now + 100 * 36, "{now} -> {grown}");
    assert_eq!(grown, serialized_len(&t.control.anchor.snapshot()));
    assert_eq!(anchor_bytes_metric(&t.control.render_metrics()), grown);
    // And after a restart, as loaded.
    let env0 = w.t.env0;
    drop(w.t.control);
    let t = env0.start().unwrap();
    assert_eq!(anchor_bytes_metric(&t.control.metrics.render()), grown);
}

/// Holds the key-broker lock of `broker` in a transaction of its own, runs
/// `write` in it, then `other` on another thread: `other` must wait for the
/// transaction, and then see its write. Returns `other`'s result.
fn serialized_against<R: Send>(
    url: &str,
    broker: &str,
    write: impl FnOnce(&mut postgres::Transaction<'_>),
    other: impl FnOnce() -> R + Send,
) -> R {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    let mut tx = c.transaction().unwrap();
    encompute_control::keybroker_lock(&mut tx, broker).unwrap();
    write(&mut tx);
    std::thread::scope(|s| {
        let h = s.spawn(other);
        std::thread::sleep(Duration::from_millis(700));
        assert!(
            !h.is_finished(),
            "the other registration did not wait for the broker's lock"
        );
        tx.commit().unwrap();
        h.join().unwrap()
    })
}

/// ENC-SF-2026-041 follow-up: registering an organization's key broker and
/// registering another organization's asset naming that broker take the
/// same lock (the broker ID's), so both cannot pass their checks
/// concurrently. On rc.3 the asset path locked (broker, key) instead and
/// did not wait: both registrations were accepted.
#[test]
fn broker_and_asset_registration_serialize_on_the_broker_id() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let url = t.env0.url.clone();

    // (A) other-co's broker "keybroker-race" is being registered (locked,
    // written, not committed): modelco's asset naming it waits, then is
    // refused.
    let kb = encompute_verification::ServiceSigner::from_seed("keybroker-race", &[91; 32]).unwrap();
    let (s, v) = serialized_against(
        &url,
        "keybroker-race",
        |tx| {
            tx.execute(
                "INSERT INTO service_accounts (id, organization_id, kind, public_key, status)
                 VALUES ('keybroker-race', 'other-co', 'keybroker', $1, 'active')",
                &[&kb.public_key_hex()],
            )
            .unwrap();
        },
        || {
            t.call(
                &w.b_owner,
                "POST",
                "/v1/assets",
                Some(
                    json!({"organization": "modelco", "kind": "model", "name": "model-race",
                            "digest": "d".repeat(64),
                            "key_ref": {"broker": "keybroker-race", "provider": "openbao-transit",
                                        "key_ref": "model-race", "key_version": 1}}),
                ),
            )
        },
    );
    assert_eq!(s, 409, "an asset naming another organization's broker: {v}");

    // (B) modelco's asset naming "keybroker-race2" is being registered:
    // other-co's broker of that name waits, then is refused.
    let kb2 =
        encompute_verification::ServiceSigner::from_seed("keybroker-race2", &[92; 32]).unwrap();
    let (s, v) = serialized_against(
        &url,
        "keybroker-race2",
        |tx| {
            tx.execute(
                "INSERT INTO assets (id, organization_id, kind, name, digest, policy, lineage_root,
                     parents, key_ref, status, created_by)
                 VALUES ('ast_race2', 'modelco', 'model', 'model-race2', $1, '{}', 'ast_race2', '[]',
                     $2, 'active', 'b-owner')",
                &[
                    &"e".repeat(64),
                    &json!({"broker": "keybroker-race2", "provider": "openbao-transit",
                            "key_ref": "model-race2", "key_version": 1}),
                ],
            )
            .unwrap();
        },
        || {
            t.call(
                &w.c_admin,
                "POST",
                "/v1/organizations/other-co/service-accounts",
                Some(json!({"id": "keybroker-race2", "kind": "keybroker",
                            "public_key": kb2.public_key_hex(), "url": "http://other.example:1"})),
            )
        },
    );
    assert_eq!(s, 409, "a broker another organization's asset names: {v}");

    // Unrelated brokers and keys still register.
    t.ok(
        &w.b_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": "modelco", "kind": "model", "name": "model-9",
                    "digest": "f".repeat(64),
                    "key_ref": {"broker": "keybroker-modelco", "provider": "openbao-transit",
                                "key_ref": "model-9", "key_version": 1}}),
        ),
    );
}

/// An anchor-frozen ledger whose `privacy_ledgers` row the database lost
/// (its asset still held) refuses startup; recovery re-creates the row,
/// frozen and audited, so the next start succeeds and the ledger stays
/// frozen. Before, recovery's UPDATE matched no row and the start was
/// refused again, with no way out.
#[test]
fn recovery_recreates_a_frozen_ledger_whose_row_was_lost() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    let spend = |t: &T, ev: &str| {
        t.call(
            &w.a_owner,
            "POST",
            &format!("/v1/privacy/{d}/events"),
            Some(reserve(ev, 200)),
        )
    };
    for i in 0..2 {
        assert_eq!(spend(&w.t, &format!("s-{i}")).0, 200);
    }
    let url = w.t.env0.url.clone();
    let env0 = w.t.env0;
    drop(w.t.control);
    // A rollback, recovered: the ledger is frozen in the anchor.
    let mut c = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    c.execute("DELETE FROM privacy_entries WHERE asset_id = $1", &[&d])
        .unwrap();
    assert!(env0.start().is_err());
    run_recovery(&env0);
    let t = env0.start().unwrap();
    assert!(t.control.anchor.snapshot().frozen.contains(&d));
    assert_eq!(spend(&t, "frozen-1").0, 409);
    let env0 = t.env0;
    drop(t.control);

    // The database loses the ledger's row (the asset is still there).
    c.execute("DELETE FROM privacy_spenders WHERE asset_id = $1", &[&d])
        .unwrap();
    c.execute("DELETE FROM privacy_entries WHERE asset_id = $1", &[&d])
        .unwrap();
    c.execute("DELETE FROM privacy_ledgers WHERE asset_id = $1", &[&d])
        .unwrap();
    let e = env0.start().err().expect("a missing frozen ledger started");
    assert!(e.message.contains("PRIVACY STATE ROLLBACK"), "{e}");
    assert!(e.message.contains(&d), "{e}");

    let notes = run_recovery(&env0);
    assert!(
        notes
            .iter()
            .any(|n| n.contains(&d) && n.contains("re-created frozen")),
        "{notes:?}"
    );
    let reason: Option<String> = c
        .query_one(
            "SELECT frozen_reason FROM privacy_ledgers WHERE asset_id = $1",
            &[&d],
        )
        .unwrap()
        .get(0);
    let reason = reason.expect("re-created frozen");
    assert!(reason.contains("re-created by recovery"), "{reason}");
    let audited: i64 = c
        .query_one(
            "SELECT count(*) FROM audit_events WHERE action = 'privacy.ledger.frozen'
               AND resource_id = $1 AND refs::text LIKE '%recreated_missing_row%'",
            &[&d],
        )
        .unwrap()
        .get(0);
    assert_eq!(audited, 1, "the re-creation is audited");
    drop(c);

    let t = env0.start().expect("starts after recovery");
    let a = t.control.anchor.snapshot();
    assert!(a.frozen.contains(&d));
    assert_eq!(
        a.ledgers[&d].seq, 0,
        "the anchor follows the re-created ledger"
    );
    let v = t.ok(&w.a_auditor, "GET", &format!("/v1/privacy/{d}"), None);
    assert!(v["frozen"].is_string(), "{v}");
    let (s, v) = spend(&t, "after-recreation");
    assert_eq!((s, v["code"].as_str()), (409, Some("ENC2201")), "{v}");
    // And it starts again.
    let env0 = t.env0;
    drop(t.control);
    env0.start().expect("starts again");
}
