//! Ciphertext envelopes (`encompute-protocol`): decode, split into items,
//! re-encode; a decoded envelope re-encodes to one that decodes to itself.
//! Each input is tried as is and with a valid checksum appended, so the
//! fuzzer reaches the header and item parsing behind the checksum.
#![no_main]
use encompute_protocol::Envelope;
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};

fn check(bytes: &[u8]) {
    if let Ok(e) = Envelope::decode(bytes) {
        let total: usize = e.items().iter().map(|(_, b)| b.len()).sum();
        assert_eq!(total, e.payload.len());
        assert_eq!(Envelope::decode(&e.encode()).expect("re-encoded"), e);
    }
}

fuzz_target!(|data: &[u8]| {
    check(data);
    let mut sealed = data.to_vec();
    sealed.extend_from_slice(&Sha256::digest(data));
    check(&sealed);
});
