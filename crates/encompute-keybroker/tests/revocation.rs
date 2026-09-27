//! Control-plane revocations reach only the organization a broker serves:
//! a control-plane-signed `asset.revoked` for another organization (a
//! tenant naming someone else's key) destroys nothing.

use std::sync::{Arc, Mutex};

use encompute_attestation::{AttestationPolicy, TeeKind, Verifier};
use encompute_ir::Code;
use encompute_keybroker::{
    serve_with_control, BrokerMode, ControlChannel, DevelopmentFileStore, KeyBroker, KeyMaterial,
};
use encompute_verification::service::{seal, signed_call, Scope};
use encompute_verification::ServiceSigner;

const SPEC: &str = "11111111111111111111111111111111111111111111111111111111111111aa";

fn policy() -> AttestationPolicy {
    let mut p = AttestationPolicy::new(SPEC, None);
    p.allowed_tee = vec![TeeKind::Mock];
    p.allowed_images = vec!["sha256:".to_owned() + &"4".repeat(64)];
    p.allow_development = true;
    p
}

fn broker(org: &str) -> KeyBroker {
    let mut b = KeyBroker::new(
        "keybroker-modelco",
        BrokerMode::Development,
        Verifier::new(),
        Box::new(DevelopmentFileStore),
    )
    .unwrap();
    b.set_organization(org).unwrap();
    b.add_secret(
        "model-7",
        Some(KeyMaterial::from_bytes(b"model key").unwrap()),
        policy(),
    )
    .unwrap();
    b
}

fn revoked(b: &Mutex<KeyBroker>) -> bool {
    b.lock().unwrap().secret("model-7").unwrap().versions[&1].revoked
}

#[test]
fn revocations_for_another_organization_destroy_nothing() {
    let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
    let b = Arc::new(Mutex::new(broker("modelco")));
    let server = encompute_verification::http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr());
    let channel = ControlChannel::new(
        "keybroker-modelco",
        "control-plane",
        &control.public_key_hex(),
        "modelco",
    );
    let served = b.clone();
    std::thread::spawn(move || {
        serve_with_control(&served, server, 1000, Some(&channel), &|_| Ok(()))
    });
    let agent = ureq::AgentBuilder::new().build();
    let send = |org: Option<&str>| {
        let m = seal(
            &control,
            "asset.revoked",
            "keybroker-modelco",
            Scope {
                organization: org.map(Into::into),
                ..Scope::default()
            },
            &serde_json::json!({"asset": "ast_decoy", "key_ref": "model-7", "key_version": 1}),
            300,
        )
        .unwrap();
        signed_call(
            &agent,
            &control,
            &url,
            "keybroker-modelco",
            "POST",
            "/v1/messages",
            &Default::default(),
            &serde_json::to_value(&m).unwrap(),
        )
    };
    // hospital-a's asset named modelco's key: refused, the key survives.
    let e = send(Some("hospital-a")).unwrap_err();
    assert_eq!(e.code, Code::ServiceAuthentication, "{e}");
    assert!(!revoked(&b));
    // No organization at all: refused.
    assert!(send(None).is_err());
    assert!(!revoked(&b));
    // modelco's own revocation destroys the key.
    let v = send(Some("modelco")).unwrap();
    assert_eq!(v["revoked_versions"], serde_json::json!([1]));
    assert!(revoked(&b));
}

#[test]
fn only_keys_recorded_for_the_organization_are_revoked() {
    let mut b = broker("modelco");
    // A broker serving another organization refuses outright.
    assert_eq!(
        b.revoke_for("hospital-a", "model-7").unwrap_err().code,
        Code::ServiceAuthentication
    );
    // A key recorded for another organization is not this one's to revoke.
    let mut state = b.state().clone();
    state.secrets.get_mut("model-7").unwrap().organization = Some("hospital-a".into());
    let mut other =
        KeyBroker::from_state(state, Verifier::new(), Box::new(DevelopmentFileStore)).unwrap();
    assert_eq!(
        other.revoke_for("modelco", "model-7").unwrap_err().code,
        Code::KeyRelease
    );
    assert!(!other.secret("model-7").unwrap().versions[&1].revoked);
    // The organization is set once.
    assert!(b.set_organization("hospital-a").is_err());
    assert_eq!(b.revoke_for("modelco", "model-7").unwrap(), vec![1]);
}
