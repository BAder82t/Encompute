//! Policy-gated key release: the happy path, the two-party demo over HTTP,
//! and every workload that must receive no key.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use encompute_attestation::mock::{MockHardware, MockProvider};
use encompute_attestation::{
    AttestationEvidence, AttestationPolicy, Attester, TcbStatus, TeeKind, Verifier, WorkloadSession,
};
use encompute_ir::Code;
use encompute_keybroker::{acquire_keys, serve, BrokerClient, BrokerMode, KeyBroker, KeyMaterial};
use encompute_verification::EvaluatorSigner;

const SPEC: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const POLICY: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const ARTIFACT: &str = "33333333333333333333333333333333333333333333333333333333333333cc";
const IMAGE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const EVIL_IMAGE: &str = "sha256:6666666666666666666666666666666666666666666666666666666666666666";
const T0: u64 = 1_900_000_000;

fn hw() -> MockHardware {
    MockHardware::from_seed(&[7; 32])
}

fn policy() -> AttestationPolicy {
    let mut p = AttestationPolicy::new(SPEC, Some(POLICY));
    p.allowed_tee = vec![TeeKind::Mock];
    p.allowed_images = vec![IMAGE.into()];
    p.allow_development = true;
    p
}

struct Setup {
    broker: KeyBroker,
    clock: Arc<AtomicU64>,
    session: WorkloadSession,
    key: Vec<u8>,
}

fn setup(id: &str) -> Setup {
    let clock = Arc::new(AtomicU64::new(T0));
    let c = clock.clone();
    let verifier = Verifier::new().with(MockProvider::new(&hw().public_key()).unwrap());
    let mut broker = KeyBroker::new(id, BrokerMode::Development, verifier)
        .unwrap()
        .with_clock(move || c.load(Ordering::SeqCst));
    let key = b"hospital patient-data key 32 by.".to_vec();
    broker
        .add_secret(
            "patients",
            Some(KeyMaterial::from_bytes(&key).unwrap()),
            policy(),
        )
        .unwrap();
    let signer = EvaluatorSigner::from_seed(&[9; 32]);
    Setup {
        broker,
        clock,
        session: WorkloadSession::new(&signer.identity()),
        key,
    }
}

impl Setup {
    /// Challenge, then evidence from `attester` for the honest binding
    /// (optionally edited).
    fn evidence(
        &mut self,
        attester: &dyn Attester,
        edit: impl FnOnce(&mut encompute_attestation::WorkloadBinding),
    ) -> AttestationEvidence {
        let c = self.broker.challenge().unwrap();
        let mut b = self.session.binding(&c, SPEC, Some(POLICY), ARTIFACT);
        edit(&mut b);
        attester.attest(&c, &b).unwrap()
    }

    fn honest(&mut self) -> AttestationEvidence {
        self.evidence(&hw().attester(IMAGE).issued_at(T0), |_| {})
    }

    fn refused(&mut self, e: &AttestationEvidence) -> Code {
        match self.broker.verify_attestation(e) {
            Err(x) => x.code,
            Ok(info) => {
                self.broker
                    .release_key(&info.session, "patients")
                    .expect_err("a key was released")
                    .code
            }
        }
    }
}

#[test]
fn honest_workload_receives_its_key() {
    let mut s = setup("hospital");
    let e = s.honest();
    let info = s.broker.verify_attestation(&e).unwrap();
    assert_eq!(info.workload_session_id, s.session.session_id());
    let g = s.broker.release_key(&info.session, "patients").unwrap();
    assert_eq!(g.header.policy_id.as_deref(), Some(POLICY));
    assert_eq!(g.header.execution_spec_id, SPEC);
    assert_eq!(g.header.key_version, 1);
    assert_eq!(s.session.open(&g).unwrap().as_slice(), s.key.as_slice());
    // The grant never carries the key in the clear.
    let text = serde_json::to_string(&g).unwrap();
    assert!(!text.contains("hospital patient"));
    assert!(!text.contains(&s.key.iter().map(|b| format!("{b:02x}")).collect::<String>()));
}

/// The spec's list: each of these receives no key.
#[test]
fn untrusted_workloads_receive_no_key() {
    let mut s = setup("hospital");
    let good = || hw().attester(IMAGE).issued_at(T0);

    // Wrong image.
    let e = s.evidence(&hw().attester(EVIL_IMAGE).issued_at(T0), |_| {});
    assert_eq!(s.refused(&e), Code::WorkloadPolicy, "wrong image");
    // Wrong ExecutionSpecID (honestly attested, but not the approved one).
    let e = s.evidence(&good(), |b| b.execution_spec_id = ARTIFACT.into());
    assert_eq!(s.refused(&e), Code::WorkloadPolicy, "wrong spec");
    // Wrong PolicyID.
    let e = s.evidence(&good(), |b| b.policy_id = Some(SPEC.into()));
    assert_eq!(s.refused(&e), Code::WorkloadPolicy, "wrong policy");
    // Debug workload.
    let e = s.evidence(&good().debug(true), |_| {});
    assert_eq!(s.refused(&e), Code::WorkloadPolicy, "debug");
    // Unacceptable TCB.
    let e = s.evidence(&good().tcb(TcbStatus::OutOfDate), |_| {});
    assert_eq!(s.refused(&e), Code::WorkloadPolicy, "TCB");
    // Stale attestation: issued long before the challenge.
    let e = s.evidence(&hw().attester(IMAGE).issued_at(T0 - 7200), |_| {});
    assert_eq!(s.refused(&e), Code::Freshness, "stale");
    // Expired evidence.
    let e = s.evidence(&good().lifetime(10), |_| {});
    s.clock.store(T0 + 11, Ordering::SeqCst);
    assert_eq!(s.refused(&e), Code::Freshness, "expired");
    s.clock.store(T0, Ordering::SeqCst);
    // Replayed nonce: the first presentation succeeds, the second finds no
    // open challenge.
    let e = s.honest();
    assert!(s.broker.verify_attestation(&e).is_ok());
    assert_eq!(s.refused(&e), Code::Freshness, "replay");
    // A challenge that expired before use.
    let e = s.honest();
    s.clock.store(T0 + 301, Ordering::SeqCst);
    assert_eq!(s.refused(&e), Code::Freshness, "expired challenge");
    s.clock.store(T0, Ordering::SeqCst);
    // Wrong evaluator signing key / wrong session key: the host swaps its
    // own key into genuine evidence's binding.
    let host = WorkloadSession::new(&EvaluatorSigner::from_seed(&[1; 32]).identity());
    let mut e = s.honest();
    e.binding.evaluator_public_key = "ab".repeat(32);
    assert_eq!(s.refused(&e), Code::Attestation, "evaluator key");
    let mut e = s.honest();
    e.binding.session_public_key = host.session_public_key_hex();
    assert_eq!(s.refused(&e), Code::Attestation, "session key");
    // Tampered evidence.
    let mut e = s.honest();
    e.evidence = e.evidence.replace("\"debug\":false", "\"debug\":true");
    assert_eq!(s.refused(&e), Code::Attestation, "tampered");
    // Unknown attestation provider.
    let mut e = s.honest();
    e.provider = "acme-tee".into();
    assert_eq!(s.refused(&e), Code::Attestation, "unknown provider");
    // Evidence from an unknown "hardware root".
    let e = s.evidence(
        &MockHardware::from_seed(&[8; 32])
            .attester(IMAGE)
            .issued_at(T0),
        |_| {},
    );
    assert_eq!(s.refused(&e), Code::Attestation, "rogue root");
    // Revoked asset key.
    s.broker.revoke("patients", None).unwrap();
    let e = s.honest();
    assert_eq!(s.refused(&e), Code::KeyRelease, "revoked");
    // Rotation restores release, with the new version.
    assert_eq!(s.broker.rotate_key("patients").unwrap(), 2);
    let e = s.honest();
    let info = s.broker.verify_attestation(&e).unwrap();
    let g = s.broker.release_key(&info.session, "patients").unwrap();
    assert_eq!(g.header.key_version, 2);
    assert_ne!(s.session.open(&g).unwrap().as_slice(), s.key.as_slice());
}

#[test]
fn no_key_without_attestation() {
    let mut s = setup("hospital");
    // The operator asks directly, or guesses a session handle.
    assert_eq!(
        s.broker
            .release_key("00".repeat(32).as_str(), "patients")
            .unwrap_err()
            .code,
        Code::KeyRelease
    );
    // A genuine session cannot open another session's grant.
    let e = s.honest();
    let info = s.broker.verify_attestation(&e).unwrap();
    let g = s.broker.release_key(&info.session, "patients").unwrap();
    let other = WorkloadSession::new(&EvaluatorSigner::from_seed(&[9; 32]).identity());
    assert_eq!(other.open(&g).unwrap_err().code, Code::KeyRelease);
    // Unknown asset.
    assert_eq!(
        s.broker
            .release_key(&info.session, "weights")
            .unwrap_err()
            .code,
        Code::KeyRelease
    );
    // Sessions expire.
    s.clock.store(T0 + 601, Ordering::SeqCst);
    assert_eq!(
        s.broker
            .release_key(&info.session, "patients")
            .unwrap_err()
            .code,
        Code::KeyRelease
    );
}

#[test]
fn production_brokers_refuse_development_evidence() {
    let verifier = Verifier::new().with(MockProvider::new(&hw().public_key()).unwrap());
    let mut b = KeyBroker::new("hospital", BrokerMode::Production, verifier)
        .unwrap()
        .with_clock(|| T0);
    // No development policy can be installed...
    assert_eq!(
        b.add_secret("patients", None, policy()).unwrap_err().code,
        Code::WorkloadPolicy
    );
    // ...and mock evidence is refused before any policy is consulted.
    let session = WorkloadSession::new(&EvaluatorSigner::from_seed(&[9; 32]).identity());
    let c = b.challenge().unwrap();
    let e = hw()
        .attester(IMAGE)
        .issued_at(T0)
        .attest(&c, &session.binding(&c, SPEC, Some(POLICY), ARTIFACT))
        .unwrap();
    assert_eq!(
        b.verify_attestation(&e).unwrap_err().code,
        Code::WorkloadPolicy
    );
}

#[test]
fn state_round_trips_without_printing_keys() {
    let s = setup("hospital");
    let dir = std::env::temp_dir().join(format!("encompute-broker-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("broker.json");
    s.broker.save(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let verifier = Verifier::new().with(MockProvider::new(&hw().public_key()).unwrap());
    let back = KeyBroker::load(&path, verifier).unwrap();
    assert_eq!(back.id(), "hospital");
    let secret = back.secret("patients").unwrap();
    assert_eq!(secret.versions[&1].key.as_bytes(), s.key.as_slice());
    assert!(!format!("{secret:?}").contains("hospital patient"));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The first demo: Hospital owns the patient-data key, ModelCo the
/// model-weights key; each runs its own broker. The cloud runs the
/// workload. Only the approved workload receives both keys; a modified one
/// receives none.
#[test]
fn two_party_demo_over_http() {
    let start = |id: &str, asset: &str, key: &[u8]| {
        let verifier = Verifier::new().with(MockProvider::new(&hw().public_key()).unwrap());
        let mut b = KeyBroker::new(id, BrokerMode::Development, verifier).unwrap();
        b.add_secret(asset, Some(KeyMaterial::from_bytes(key).unwrap()), policy())
            .unwrap();
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr().to_ip().unwrap());
        let b = Arc::new(Mutex::new(b));
        std::thread::spawn(move || serve(&b, &server));
        BrokerClient::new(&url)
    };
    let hospital = start("hospital", "patients", b"patients-key");
    let modelco = start("modelco", "weights", b"weights-key");
    let requests = [
        (hospital.clone(), "patients".to_string()),
        (modelco.clone(), "weights".to_string()),
    ];
    let signer = EvaluatorSigner::generate().unwrap();
    let session = WorkloadSession::new(&signer.identity());

    let keys = acquire_keys(
        &hw().attester(IMAGE),
        &session,
        SPEC,
        Some(POLICY),
        ARTIFACT,
        &requests,
    )
    .unwrap();
    assert_eq!(keys[0].key.as_slice(), b"patients-key");
    assert_eq!(keys[1].key.as_slice(), b"weights-key");
    assert_eq!(keys[0].record.session_id().unwrap(), session.session_id());

    // A modified image, another spec, or a debug build: no keys at all.
    let attempts: [(&dyn Attester, &str); 3] = [
        (&hw().attester(EVIL_IMAGE), SPEC),
        (&hw().attester(IMAGE), ARTIFACT),
        (&hw().attester(IMAGE).debug(true), SPEC),
    ];
    for (attester, spec) in attempts {
        let e =
            acquire_keys(attester, &session, spec, Some(POLICY), ARTIFACT, &requests).unwrap_err();
        assert_eq!(e.code, Code::WorkloadPolicy, "{e}");
    }
    // Replaying captured evidence over HTTP.
    let c = hospital.challenge().unwrap();
    let e = hw()
        .attester(IMAGE)
        .attest(&c, &session.binding(&c, SPEC, Some(POLICY), ARTIFACT))
        .unwrap();
    hospital.attest(&e).unwrap();
    assert_eq!(hospital.attest(&e).unwrap_err().code, Code::Freshness);
    // Asking for a key without attesting.
    assert_eq!(
        hospital
            .release(&"00".repeat(32), "patients")
            .unwrap_err()
            .code,
        Code::KeyRelease
    );
}
