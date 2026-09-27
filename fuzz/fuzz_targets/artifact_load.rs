//! Compiled artifact loading (the `.encompute` directory: `manifest.json`
//! and the files it hashes). The input is the files joined by
//! `encompute_fuzz::SEP`, in the order of `NAMES`.
#![no_main]
use libfuzzer_sys::fuzz_target;

const NAMES: [&str; 7] = [
    "manifest.json",
    "program.eir",
    "plan.json",
    "parameters.json",
    "security.json",
    "verification.json",
    "policy.json",
];

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().expect("temp dir");
    for (name, body) in NAMES.iter().zip(encompute_fuzz::parts(data, NAMES.len())) {
        std::fs::write(dir.path().join(name), body).expect("write");
    }
    let _ = encompute_runtime::Model::load(dir.path());
});
