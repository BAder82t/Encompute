//! Semantic transcripts (the statement an execution proof proves): parse,
//! validate, canonical round trip.
#![no_main]
use encompute_verification::SemanticTranscript;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(t) = SemanticTranscript::from_bytes(data) {
        let bytes = t.canonical_bytes().expect("canonical");
        assert_eq!(
            SemanticTranscript::from_bytes(&bytes).expect("round trip"),
            t
        );
        let _ = t.id();
    }
});
