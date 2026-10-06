//! Governed release over HTTP: owners install and revoke authorizations
//! (verified under their pinned governance key), the workload asks for its
//! key with a ticket, the broker persists its counters and seen tickets
//! before it grants (a failed write grants nothing), and the control plane
//! can only deny (`authorization.revoked`, `asset.expired`).

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::json;

use common::*;
use encompute_attestation::{unix_now, GRANT_VERSION_GOVERNED};
use encompute_ir::Code;
use encompute_keybroker::{
    acquire_keys, acquire_keys_governed, serve_with_control, BrokerClient, ControlChannel,
    DevelopmentFileStore, GovernedKeyRequest, KeyBroker,
};
use encompute_trust::authz::RevocationV2;
use encompute_verification::http::Server;
use encompute_verification::service::{seal, Scope};

const ME: &str = "keybroker-tax";

fn tmp() -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "encompute-kb-authz-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A governed world on the real clock, its state saved at `path` (the
/// authorization is not installed: the tests install it over HTTP).
fn saved_world(path: &Path) -> World {
    let mut a = authorization();
    let now = unix_now();
    a.valid_from = now - 100;
    a.valid_until = now + 3600;
    a.issued_at = now - 200;
    a.limits.max_releases = Some(2);
    let spec = spec_for(&binding());
    let clock = Arc::new(AtomicU64::new(now));
    let mut b = bare_broker(&clock, &spec);
    b.bind_version(ASSET, &asset_version()).unwrap();
    b.pin_governance_key(&governance_public_key()).unwrap();
    b.save(path).unwrap();
    World {
        broker: b,
        clock,
        evaluator: encompute_verification::EvaluatorSigner::from_seed(&[9; 32]),
        binding: binding(),
        spec,
        authorization: signed(a),
        placement: None,
        zone: None,
    }
}

/// A broker process over the state at `path`, on the real clock, pinned
/// to `w`'s grant key; `fail_persist` makes its next state write fail.
fn start(w: &World, path: &Path, fail_persist: &'static AtomicBool) -> BrokerClient {
    let b = KeyBroker::load(path, verifier(), Box::new(DevelopmentFileStore))
        .unwrap()
        .with_governance(governance())
        .unwrap();
    let server = Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr());
    let path = path.to_owned();
    std::thread::spawn(move || {
        let ch = ControlChannel::new(ME, "control-plane", &control().public_key_hex(), ORG);
        let b = Mutex::new(b);
        serve_with_control(&b, server, 10_000, Some(&ch), &|b| {
            if fail_persist.swap(false, Ordering::SeqCst) {
                return Err(encompute_ir::Error::new(
                    Code::KeyRelease,
                    "the process died before the state was written",
                ));
            }
            b.save(&path)
        })
    });
    BrokerClient::new(&url)
        .with_pinned_key(&w.broker.grant_public_key())
        .unwrap()
}

fn deliver(
    b: &BrokerClient,
    kind: &str,
    org: &str,
    payload: serde_json::Value,
) -> (u16, serde_json::Value) {
    let cp = control();
    let m = seal(
        &cp,
        kind,
        ME,
        Scope {
            organization: Some(org.into()),
            ..Scope::default()
        },
        &payload,
        3600,
    )
    .unwrap();
    let body = serde_json::to_vec(&m).unwrap();
    let h = cp
        .sign_request("POST", "/v1/messages", ME, &Default::default(), &body)
        .unwrap();
    let mut r = ureq::post(&format!("{}/v1/messages", b.url()));
    for (k, v) in h.to_pairs() {
        r = r.set(k, &v);
    }
    match r.send_bytes(&body) {
        Ok(r) => (r.status(), r.into_json().unwrap()),
        Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap()),
        Err(e) => panic!("{e}"),
    }
}

fn attester() -> encompute_attestation::mock::MockAttester {
    hw().attester(IMAGE)
}

fn request(
    w: &World,
    b: &BrokerClient,
    ticket: Option<encompute_verification::ticket::ReleaseTicket>,
) -> GovernedKeyRequest {
    GovernedKeyRequest {
        broker: b.clone(),
        asset_id: ASSET.into(),
        authorization_id: w.authorization_id(),
        ticket,
    }
}

fn acquire(
    w: &World,
    reqs: &[GovernedKeyRequest],
) -> encompute_ir::Result<Vec<encompute_keybroker::AcquiredKey>> {
    acquire_keys_governed(
        &attester(),
        &w.session(),
        &w.spec.id().hex(),
        w.spec.policy_id.as_deref(),
        ARTIFACT,
        reqs,
    )
}

#[test]
fn governed_release_over_http() {
    let dir = tmp();
    let state = dir.join("broker.json");
    let w = saved_world(&state);
    static NEVER: AtomicBool = AtomicBool::new(false);
    let b = start(&w, &state, &NEVER);
    // Not installed yet: refused.
    let e = acquire(&w, &[request(&w, &b, Some(w.ticket()))]).unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationMissing, "{e}");
    // A forged authorization does not install.
    let forged = authorization().sign(&rogue_governance_key()).unwrap();
    let e = b.install_authorization(&forged).unwrap_err();
    assert_eq!(e.code, Code::GovernanceKeyRevoked, "{e}");
    // The owner's does, and the workload gets its key.
    assert_eq!(
        b.install_authorization(&w.authorization).unwrap(),
        w.authorization_id()
    );
    let keys = acquire(&w, &[request(&w, &b, Some(w.ticket()))]).unwrap();
    assert_eq!(keys[0].key.as_slice(), KEY);
    assert_eq!(keys[0].header.version, GRANT_VERSION_GOVERNED);
    let receipt = keys[0].receipt.as_ref().unwrap();
    receipt.verify(&w.broker.grant_public_key()).unwrap();
    // The 0.3 route refuses a governed broker's keys.
    let e = acquire_keys(
        &attester(),
        &w.session(),
        &w.spec.id().hex(),
        w.spec.policy_id.as_deref(),
        ARTIFACT,
        &[(b.clone(), ASSET.into())],
    )
    .unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationMissing, "{e}");
    // A replayed ticket, over HTTP and after a restart.
    let t = w.ticket();
    acquire(&w, &[request(&w, &b, Some(t.clone()))]).unwrap();
    let b = start(&w, &state, &NEVER);
    let e = acquire(&w, &[request(&w, &b, Some(t))]).unwrap_err();
    assert_eq!(e.code, Code::GovernanceReleaseTicket, "{e}");
    // The limit (2 releases) is persisted across the restart.
    let e = acquire(&w, &[request(&w, &b, Some(w.ticket()))]).unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationLimit, "{e}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_failed_persist_grants_nothing() {
    let dir = tmp();
    let state = dir.join("broker.json");
    let w = saved_world(&state);
    static FAIL_ONCE: AtomicBool = AtomicBool::new(false);
    static NEVER: AtomicBool = AtomicBool::new(false);
    let b = start(&w, &state, &FAIL_ONCE);
    b.install_authorization(&w.authorization).unwrap();
    FAIL_ONCE.store(true, Ordering::SeqCst);
    let t = w.ticket();
    let e = acquire(&w, &[request(&w, &b, Some(t.clone()))]).unwrap_err();
    assert_eq!(e.code, Code::KeyRelease, "{e}");
    // The ticket stays spent in the running broker (toward denial)...
    let e = acquire(&w, &[request(&w, &b, Some(t.clone()))]).unwrap_err();
    assert_eq!(e.code, Code::GovernanceReleaseTicket, "{e}");
    // ...and a restarted broker, which never recorded the release, has
    // granted nothing either.
    let b = start(&w, &state, &NEVER);
    let keys = acquire(&w, &[request(&w, &b, Some(w.ticket()))]).unwrap();
    assert_eq!(keys[0].key.as_slice(), KEY);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn owner_revokes_at_the_broker_with_a_signed_revocation() {
    let dir = tmp();
    let state = dir.join("broker.json");
    let w = saved_world(&state);
    static NEVER: AtomicBool = AtomicBool::new(false);
    let b = start(&w, &state, &NEVER);
    b.install_authorization(&w.authorization).unwrap();
    acquire(&w, &[request(&w, &b, Some(w.ticket()))]).unwrap();
    let r = RevocationV2 {
        version: 2,
        party: ORG.into(),
        authorization: w.authorization_id(),
        reason: "withdrawn".into(),
        issued_at: unix_now() - 1,
    };
    // Only the owner's governance key can revoke over HTTP.
    let e = b
        .revoke_authorization(&r.clone().sign(&rogue_governance_key()).unwrap())
        .unwrap_err();
    assert_eq!(e.code, Code::GovernanceKeyRevoked, "{e}");
    b.revoke_authorization(&r.sign(&governance_key()).unwrap())
        .unwrap();
    let e = acquire(&w, &[request(&w, &b, Some(w.ticket()))]).unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationRevoked, "{e}");
    // Persisted: still revoked after a restart.
    let b = start(&w, &state, &NEVER);
    let e = acquire(&w, &[request(&w, &b, Some(w.ticket()))]).unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationRevoked, "{e}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The control plane can only deny: `authorization.revoked` needs no owner
/// signature, `asset.expired` stops every release of the asset, and
/// neither is accepted for another organization.
#[test]
fn control_plane_messages_only_deny() {
    let dir = tmp();
    let state = dir.join("broker.json");
    let w = saved_world(&state);
    static NEVER: AtomicBool = AtomicBool::new(false);
    let b = start(&w, &state, &NEVER);
    b.install_authorization(&w.authorization).unwrap();
    let id = w.authorization_id();
    // For another organization: refused, nothing changes.
    let (s, v) = deliver(
        &b,
        "authorization.revoked",
        "benefits-agency",
        json!({"authorization_id": id}),
    );
    assert_ne!(s, 200, "{v}");
    acquire(&w, &[request(&w, &b, Some(w.ticket()))]).unwrap();
    // A malformed ID is refused.
    let (s, v) = deliver(
        &b,
        "authorization.revoked",
        ORG,
        json!({"authorization_id": "x"}),
    );
    assert_ne!(s, 200, "{v}");
    let (s, v) = deliver(
        &b,
        "authorization.revoked",
        ORG,
        json!({"authorization_id": id}),
    );
    assert_eq!(s, 200, "{v}");
    let e = acquire(&w, &[request(&w, &b, Some(w.ticket()))]).unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationRevoked, "{e}");
    // Delivered again: idempotent.
    let (s, v) = deliver(
        &b,
        "authorization.revoked",
        ORG,
        json!({"authorization_id": id}),
    );
    assert_eq!(s, 200, "{v}");

    // asset.expired, persisted.
    let dir2 = tmp();
    let state2 = dir2.join("broker.json");
    let w2 = saved_world(&state2);
    let b2 = start(&w2, &state2, &NEVER);
    b2.install_authorization(&w2.authorization).unwrap();
    let (s, v) = deliver(
        &b2,
        "asset.expired",
        "benefits-agency",
        json!({"key_ref": ASSET}),
    );
    assert_ne!(s, 200, "{v}");
    let (s, v) = deliver(&b2, "asset.expired", ORG, json!({"key_ref": ASSET}));
    assert_eq!(s, 200, "{v}");
    let b2 = start(&w2, &state2, &NEVER);
    let e = acquire(&w2, &[request(&w2, &b2, Some(w2.ticket()))]).unwrap_err();
    assert_eq!(e.code, Code::KeyRelease, "{e}");
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&dir2).unwrap();
}

/// A request under an authorization the broker does not hold is refused,
/// whatever the ticket.
#[test]
fn a_request_under_an_uninstalled_authorization_is_refused() {
    let dir = tmp();
    let state = dir.join("broker.json");
    let w = saved_world(&state);
    static NEVER: AtomicBool = AtomicBool::new(false);
    let b = start(&w, &state, &NEVER);
    b.install_authorization(&w.authorization).unwrap();
    // A request naming an authorization the ticket does not list.
    let mut r = request(&w, &b, Some(w.ticket()));
    r.authorization_id = h('5');
    let e = acquire(&w, &[r]).unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationMissing, "{e}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The control plane can only revoke what is installed here: an unknown
/// authorization ID is acknowledged and changes nothing, so a compromised
/// control plane cannot grow the broker's state.
#[test]
fn control_revocation_of_unknown_id_stores_nothing() {
    let dir = tmp();
    let state = dir.join("broker.json");
    let w = saved_world(&state);
    static NEVER: AtomicBool = AtomicBool::new(false);
    let b = start(&w, &state, &NEVER);
    b.install_authorization(&w.authorization).unwrap();
    for n in 0..20u32 {
        let (s, v) = deliver(
            &b,
            "authorization.revoked",
            ORG,
            json!({"authorization_id": format!("{n:064x}")}),
        );
        assert_eq!((s, &v["revoked"]), (200, &json!(false)), "{v}");
    }
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    assert!(saved.get("revoked_authorizations").is_none(), "{saved}");
    // The installed one is revoked.
    let (s, v) = deliver(
        &b,
        "authorization.revoked",
        ORG,
        json!({"authorization_id": w.authorization_id()}),
    );
    assert_eq!((s, &v["revoked"]), (200, &json!(true)), "{v}");
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    assert_eq!(
        saved["revoked_authorizations"].as_object().unwrap().len(),
        1,
        "{saved}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
