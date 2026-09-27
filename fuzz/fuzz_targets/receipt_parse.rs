//! Signed execution receipts: strict parse, canonical round trip, and the
//! signature check against the identity the receipt names.
#![no_main]
use encompute_verification::{EvaluatorIdentity, SignedExecutionReceipt};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = SignedExecutionReceipt::from_bytes(data) {
        let bytes = r.to_bytes().expect("canonical");
        assert_eq!(
            SignedExecutionReceipt::from_bytes(&bytes).expect("round trip"),
            r
        );
        if let Ok(id) = EvaluatorIdentity::from_public_key_hex(&r.evaluator_public_key) {
            let _ = r.verify_signature(&id);
        }
    }
});
