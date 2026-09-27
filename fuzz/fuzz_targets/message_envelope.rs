//! Signed asynchronous service messages: parse and open (version,
//! recipient, expiry, payload digest, signature).
#![no_main]
use encompute_verification::service::{open, MessageEnvelope};
use encompute_verification::ServiceSigner;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = serde_json::from_slice::<MessageEnvelope>(data) {
        let s = ServiceSigner::from_seed("evaluator-1", &encompute_fuzz::SERVICE_SEED)
            .expect("service ID");
        let _ = open(&m, &s.public_key_hex(), "control-plane", m.created_at);
        let _ = open(&m, &s.public_key_hex(), &m.recipient, u64::MAX);
        let _ = open(&m, &s.public_key_hex(), &m.recipient, 0);
    }
});
