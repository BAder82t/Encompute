//! Attestation evidence and records: parse, verify the claims with the
//! mock provider (fixed hardware key) and Google Confidential Space (an
//! empty key set), and check records against a policy.
#![no_main]
use encompute_attestation::gcp::ConfidentialSpaceProvider;
use encompute_attestation::mock::{MockHardware, MockProvider};
use encompute_attestation::{
    AttestationEvidence, AttestationPolicy, AttestationRecord, TeeKind, Verifier,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let hw = MockHardware::from_seed(&[3; 32]);
    let verifier = Verifier::new()
        .with(MockProvider::new(&hw.public_key()).expect("key"))
        .with(ConfidentialSpaceProvider::new(r#"{"keys":[]}"#, "broker").expect("provider"));
    let mut policy = AttestationPolicy::new(&"a".repeat(64), None);
    policy.allowed_tee = vec![TeeKind::Mock];
    policy.allowed_images = vec!["sha256:0".into()];
    policy.allow_development = true;
    if let Ok(e) = AttestationEvidence::from_bytes(data) {
        let _ = verifier.verify_claims(&e, Some(1_700_000_000));
    }
    if let Ok(r) = AttestationRecord::from_bytes(data) {
        let _ = r.verify(&verifier, &policy);
        let _ = r.id();
    }
});
