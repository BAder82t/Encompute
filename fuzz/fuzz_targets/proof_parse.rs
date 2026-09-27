//! Execution proofs (`ENCP`, header length, canonical JSON header, proof
//! bytes): anything accepted is byte-for-byte canonical.
#![no_main]
use encompute_verification::ExecutionProof;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = ExecutionProof::from_bytes(data) {
        assert_eq!(p.to_bytes().expect("encodes"), data);
        let _ = p.digest();
    }
});
