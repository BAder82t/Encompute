//! Fuzz smoke tests for attestation evidence, records and policies:
//! mutated inputs never panic, and mutated evidence never verifies.
//! Resource limits: oversized evidence, deep JSON and huge tokens are
//! typed errors.

#[path = "../../encompute-ir/tests/fuzz_support/mod.rs"]
mod fuzz_support;

use std::time::Duration;

use encompute_attestation::gcp::ConfidentialSpaceProvider;
use encompute_attestation::mock::{MockHardware, MockProvider};
use encompute_attestation::{
    AttestationChallenge, AttestationEvidence, AttestationPolicy, AttestationRecord, Attester,
    TeeKind, Verifier, WorkloadBinding, BINDING_VERSION,
};
use encompute_ir::Code;
use fuzz_support::{run, within};

fn verifier(hw: &MockHardware) -> Verifier {
    Verifier::new()
        .with(MockProvider::new(&hw.public_key()).unwrap())
        .with(ConfidentialSpaceProvider::new(r#"{"keys":[]}"#, "broker").unwrap())
}

fn evidence(hw: &MockHardware) -> AttestationEvidence {
    let binding = WorkloadBinding {
        version: BINDING_VERSION,
        execution_spec_id: "a".repeat(64),
        policy_id: None,
        artifact_digest: "b".repeat(64),
        evaluator_public_key: "c".repeat(64),
        session_public_key: "d".repeat(64),
        challenge_nonce: "e".repeat(64),
        privacy_policy_id: None,
    };
    let challenge = AttestationChallenge::new("broker", 1_700_000_000, 600).unwrap();
    hw.attester("sha256:0")
        .issued_at(1_700_000_000)
        .attest(&challenge, &binding)
        .unwrap()
}

fn policy() -> AttestationPolicy {
    let mut p = AttestationPolicy::new(&"a".repeat(64), None);
    p.allowed_tee = vec![TeeKind::Mock];
    p.allowed_images = vec!["sha256:0".into()];
    p.allow_development = true;
    p
}

#[test]
fn mutated_evidence_never_panics_or_verifies() {
    let hw = MockHardware::from_seed(&[3; 32]);
    let v = verifier(&hw);
    let e = evidence(&hw);
    v.verify_claims(&e, Some(1_700_000_100)).unwrap();
    let record = AttestationRecord::new(e.clone());
    record.verify(&v, &policy()).unwrap();
    let seeds = vec![e.to_bytes().unwrap(), record.to_bytes().unwrap()];
    run(
        "attestation",
        &seeds,
        5000,
        Duration::from_secs(1),
        |bytes| {
            if let Ok(x) = AttestationEvidence::from_bytes(bytes) {
                if v.verify_claims(&x, Some(1_700_000_100)).is_ok() {
                    assert_eq!(x.evidence, e.evidence);
                    assert_eq!(x.binding, e.binding);
                }
            }
            if let Ok(r) = AttestationRecord::from_bytes(bytes) {
                if r.verify(&v, &policy()).is_ok() {
                    assert_eq!(r.evidence.evidence, e.evidence);
                }
                let _ = r.id();
            }
        },
    );
}

#[test]
fn mutated_policies_never_panic() {
    run(
        "attestation-policy",
        &[serde_json::to_vec(&policy()).unwrap()],
        5000,
        Duration::from_secs(1),
        |bytes| {
            if let Ok(p) = serde_json::from_slice::<AttestationPolicy>(bytes) {
                let _ = p.validate();
                let again: AttestationPolicy =
                    serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
                assert_eq!(again, p);
            }
        },
    );
}

#[test]
fn resource_limits_are_typed_errors() {
    let hw = MockHardware::from_seed(&[3; 32]);
    let v = verifier(&hw);
    let limit = Duration::from_secs(1);
    let deep = fuzz_support::nested_json(100_000, "");
    for b in [deep.as_bytes(), b"\xff\xfe", b"{\"version\":4294967296}"] {
        let e = within(limit, || AttestationEvidence::from_bytes(b)).unwrap_err();
        assert_eq!(e.code, Code::Attestation);
        let e = within(limit, || AttestationRecord::from_bytes(b)).unwrap_err();
        assert_eq!(e.code, Code::Attestation);
    }
    let big = vec![b' '; 64 << 20];
    assert_eq!(
        within(limit, || AttestationEvidence::from_bytes(&big))
            .unwrap_err()
            .code,
        Code::Attestation
    );
    // Tokens that are huge, deep or not JWTs at all.
    let mut e = evidence(&hw);
    for token in [
        "a".repeat(1 << 20),
        "a.b.c".into(),
        "..".into(),
        deep.clone(),
    ] {
        e.provider = "gcp-confidential-space".into();
        e.evidence = token.clone();
        let r = within(limit, || v.verify_claims(&e, Some(1_700_000_100)));
        assert!(r.is_err());
        e.provider = "mock".into();
        let r = within(limit, || v.verify_claims(&e, Some(1_700_000_100)));
        assert!(r.is_err());
    }
}
