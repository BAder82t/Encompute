//! Canonical tensor files (`ENCTENS1`: adapters and model weights) and
//! adapter layouts. Accepted tensors lie inside the file.
#![no_main]
use encompute_training::{tensor_manifest, AdapterLayout};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(entries) = tensor_manifest(data) {
        let end = entries.last().map_or(0, |e| e.offset + e.length);
        assert!(end <= data.len() as u64);
    }
    if let Ok(l) = serde_json::from_slice::<AdapterLayout>(data) {
        if l.validate().is_ok() {
            let _ = l.parameters();
            let _ = l.digest();
        }
    }
});
