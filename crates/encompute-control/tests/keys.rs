//! Key events in the audit trail: releases reported by key brokers (allowed
//! and denied), and root key rotations.

mod common;

use std::sync::Arc;

use common::*;
use serde_json::json;

#[test]
fn key_releases_and_rotations_are_audited() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let kb = Arc::new(
        encompute_verification::ServiceSigner::from_seed("keybroker-modelco", &[41; 32]).unwrap(),
    );
    t.ok(&w.platform, "POST", "/v1/organizations/platform/service-accounts",
         Some(json!({"id": "keybroker-modelco", "kind": "keybroker", "public_key": kb.public_key_hex()})));
    let report = |allowed: bool, reason: Option<&str>| {
        let m = encompute_verification::service::seal(
            &kb,
            "key.release",
            "control-plane",
            Default::default(),
            &json!({"asset": "model-7", "allowed": allowed, "reason": reason}),
            300,
        )
        .unwrap();
        t.ok(
            &As::Service(kb.clone()),
            "POST",
            "/v1/messages",
            Some(serde_json::to_value(&m).unwrap()),
        )
    };
    report(true, None);
    report(false, Some("ENC2002"));
    let events = t.ok(&w.b_auditor, "GET", "/v1/audit?limit=1000", None);
    let rel: Vec<_> = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"].as_str().unwrap().starts_with("key.release"))
        .collect();
    assert_eq!(rel.len(), 2, "{rel:?}");
    assert_eq!(
        rel[0]["resource_id"], w.model_b,
        "mapped to modelco's asset"
    );
    assert_eq!(rel[1]["result"], "denied");
    // Only key brokers report releases.
    let m = encompute_verification::service::seal(
        &w.evaluator.signer,
        "key.release",
        "control-plane",
        Default::default(),
        &json!({"asset": "model-7", "allowed": true}),
        300,
    )
    .unwrap();
    let (s, _) = t.call(
        &w.evaluator.service,
        "POST",
        "/v1/messages",
        Some(serde_json::to_value(&m).unwrap()),
    );
    assert_eq!(s, 403);
    // hospital-a does not see modelco's key events.
    let a = t.ok(&w.a_auditor, "GET", "/v1/audit?limit=1000", None);
    assert!(!a.to_string().contains("key.release"));

    // Root key rotation: recorded by a security admin of the organization.
    let body = json!({"organization": "modelco", "provider": "openbao-transit",
                      "key_ref": "https://bao.example/transit/keys/modelco", "old_version": 1, "new_version": 2});
    let (s, _) = t.call(
        &w.b_dev,
        "POST",
        "/v1/organizations/modelco/key-rotations",
        Some(body.clone()),
    );
    assert_eq!(s, 403);
    let (s, _) = t.call(
        &w.a_admin,
        "POST",
        "/v1/organizations/modelco/key-rotations",
        Some(body.clone()),
    );
    assert_eq!(s, 404);
    t.ok(
        &w.b_sec,
        "POST",
        "/v1/organizations/modelco/key-rotations",
        Some(body),
    );
    let (s, _) = t.call(
        &w.b_sec,
        "POST",
        "/v1/organizations/modelco/key-rotations",
        Some(json!({"provider": "p", "key_ref": "k", "old_version": 2, "new_version": 2})),
    );
    assert_eq!(s, 400, "versions only move forward");
    let events = t.ok(&w.b_auditor, "GET", "/v1/audit?limit=1000", None);
    let rot = events
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "key.rotated")
        .unwrap();
    assert_eq!(rot["refs"]["old_version"], "1");
    assert_eq!(rot["refs"]["new_version"], "2");
    assert!(rot["actor"].as_str().unwrap().starts_with("usr_"));
}

/// Tenant A cannot point an asset at tenant B's broker key and revoke it:
/// the key reference is refused, and every revocation names the owner's
/// organization in the signed envelope (the broker checks it).
#[test]
fn cross_tenant_key_ref_cannot_be_registered_or_revoked() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let kb =
        encompute_verification::ServiceSigner::from_seed("keybroker-modelco", &[41; 32]).unwrap();
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({"id": "keybroker-modelco", "kind": "keybroker", "public_key": kb.public_key_hex(),
                    "url": "http://keybroker-modelco.internal:8760"})),
    );
    let key_ref = json!({"broker": "keybroker-modelco", "provider": "openbao-transit",
                         "key_ref": "model-7", "key_version": 1});
    // hospital-a registers a dataset naming modelco's key...
    let (s, v) = t.call(
        &w.a_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": "hospital-a", "kind": "dataset", "name": "decoy",
                    "digest": "c".repeat(64), "key_ref": key_ref}),
        ),
    );
    assert_eq!(s, 409, "another organization's key reference: {v}");
    // ...so it has no asset whose revocation reaches modelco's broker.
    let assets = t.ok(&w.a_owner, "GET", "/v1/assets", None);
    for a in assets.as_array().unwrap() {
        if a["organization"] == "hospital-a" && !a["key_ref"].is_null() {
            let (s, _) = t.call(
                &w.a_owner,
                "POST",
                &format!("/v1/assets/{}/revoke", a["id"].as_str().unwrap()),
                None,
            );
            assert!((200..300).contains(&s));
        }
    }
    assert!(
        t.transport.drain().is_empty(),
        "no revocation of modelco's key was sent on hospital-a's behalf"
    );
    // modelco may register another asset on its own key.
    t.ok(
        &w.b_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": "modelco", "kind": "checkpoint", "name": "model-7-ckpt",
                    "digest": "d".repeat(64), "key_ref": key_ref}),
        ),
    );
    // The owner's revocation names its organization, signed.
    t.ok(
        &w.b_owner,
        "POST",
        &format!("/v1/assets/{}/revoke", w.model_b),
        None,
    );
    let sent = t.transport.drain();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].1.kind, "asset.revoked");
    assert_eq!(sent[0].1.organization.as_deref(), Some("modelco"));
}

/// The transport may deliver a message many times at once: the inbox row
/// and the message's effect are one transaction, so it applies once, for
/// every kind (here an evaluator's drain heartbeat, which is audited).
#[test]
fn concurrent_duplicate_messages_apply_once() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let drains = || {
        t.ok(
            &w.platform,
            "GET",
            "/v1/audit?organization=platform&limit=1000",
            None,
        )
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "evaluator.status" && e["refs"]["status"] == "draining")
        .count()
    };
    let before = drains();
    let m = encompute_verification::service::seal(
        &w.evaluator.signer,
        "evaluator.heartbeat",
        "control-plane",
        Default::default(),
        &json!({"status": "draining"}),
        300,
    )
    .unwrap();
    let body = serde_json::to_value(&m).unwrap();
    let who = w.evaluator.service.clone();
    let barrier = std::sync::Barrier::new(8);
    let results: Vec<(u16, serde_json::Value)> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..8)
            .map(|_| {
                s.spawn(|| {
                    barrier.wait();
                    t.call(&who, "POST", "/v1/messages", Some(body.clone()))
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for (s, v) in &results {
        assert_eq!(*s, 200, "{v}");
    }
    let fresh = results
        .iter()
        .filter(|(_, v)| v["duplicate"] != true)
        .count();
    assert_eq!(fresh, 1, "exactly one delivery applied: {results:?}");
    assert_eq!(drains() - before, 1, "the drain was audited once");
}
