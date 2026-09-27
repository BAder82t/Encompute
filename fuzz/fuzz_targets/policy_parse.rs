//! Policies: attestation policies (validated, JSON round trip), asset
//! policies and privacy budgets, and control-plane policy documents
//! (arbitrary JSON, hashed as canonical JSON).
#![no_main]
use encompute_attestation::AttestationPolicy;
use encompute_ir::confidentiality::{AssetPolicy, PrivacyBudget};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = serde_json::from_slice::<AttestationPolicy>(data) {
        let _ = p.validate();
        let again: AttestationPolicy =
            serde_json::from_slice(&serde_json::to_vec(&p).expect("serializable"))
                .expect("round trip");
        assert_eq!(again, p);
    }
    if let Ok(p) = serde_json::from_slice::<AssetPolicy>(data) {
        if let Some(b) = &p.privacy {
            let _ = b.validate();
        }
    }
    if let Ok(b) = serde_json::from_slice::<PrivacyBudget>(data) {
        if b.validate().is_ok() {
            let c = encompute_privacy::Cost::of(0.5, &b).expect("valid budget");
            assert!(c.epsilon.is_finite() && c.epsilon >= 0.0, "{c:?}");
        }
    }
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = encompute_verification::canonical::canonical_json(&v);
    }
});
