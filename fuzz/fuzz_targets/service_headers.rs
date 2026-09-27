//! Signed service request headers: six header values and a body (joined
//! by `encompute_fuzz::SEP`) read as a request carries them, then verified.
#![no_main]
use encompute_verification::service::{
    ServiceHeaders, H_BIND, H_NONCE, H_RECIPIENT, H_SENDER, H_SIGNATURE, H_TIMESTAMP,
};
use encompute_verification::ServiceSigner;
use libfuzzer_sys::fuzz_target;

const NAMES: [&str; 6] = [
    H_SENDER,
    H_RECIPIENT,
    H_TIMESTAMP,
    H_NONCE,
    H_BIND,
    H_SIGNATURE,
];

fuzz_target!(|data: &[u8]| {
    let p = encompute_fuzz::parts(data, NAMES.len() + 1);
    let get = |h: &str| {
        let i = NAMES.iter().position(|n| *n == h)?;
        p.get(i).map(|b| String::from_utf8_lossy(b).into_owned())
    };
    let body = p.get(NAMES.len()).copied().unwrap_or_default();
    if let Ok(Some(h)) = ServiceHeaders::from_lookup(get) {
        let s = ServiceSigner::from_seed("evaluator-1", &encompute_fuzz::SERVICE_SEED)
            .expect("service ID");
        let _ = h.verify(
            &s.public_key_hex(),
            "POST",
            "/v1/messages",
            body,
            "control-plane",
            h.timestamp,
        );
        let _ = h.to_pairs();
    }
});
