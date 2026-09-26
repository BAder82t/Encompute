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
