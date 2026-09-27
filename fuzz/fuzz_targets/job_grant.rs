//! Job grants (the `Encompute-Job-Grant` header: hex of JSON; and the JSON
//! itself): parse, verify against the pinned control-plane key, and round
//! trip through the header form.
#![no_main]
use encompute_verification::{JobGrant, ServiceSigner};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let header = String::from_utf8_lossy(data);
    let grants = [
        JobGrant::from_header(&header).ok(),
        serde_json::from_slice::<JobGrant>(data).ok(),
    ];
    let s = ServiceSigner::from_seed("control-plane", &encompute_fuzz::SERVICE_SEED)
        .expect("service ID");
    for g in grants.into_iter().flatten() {
        let _ = g.verify(
            &s.public_key_hex(),
            &g.evaluator,
            &g.program_id,
            g.issued_at,
        );
        assert_eq!(
            JobGrant::from_header(&g.to_header()).expect("round trip"),
            g
        );
    }
});
