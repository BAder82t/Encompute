//! Sealed training artifacts (checkpoints, adapters, models, datasets):
//! the unauthenticated header peek, opening under a fixed key, and
//! checkpoint resume against an empty ledger directory.
#![no_main]
use encompute_training::{
    open, open_asset, peek, resume, AssetHeader, CheckpointHeader, ResumeExpectation,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = encompute_fuzz::SEAL_KEY;
    let _ = peek::<CheckpointHeader>(data);
    let _ = peek::<AssetHeader>(data);
    let _ = peek::<serde_json::Value>(data);
    let _ = open::<serde_json::Value>(&key, data);
    let _ = open_asset(&key, data, "prj_1", "asset_1", &"0".repeat(64));
    let dir = tempfile::tempdir().expect("temp dir");
    let _ = resume(
        &key,
        data,
        &ResumeExpectation {
            project: "prj_1",
            training_spec_id: "spec",
            policy_id: None,
            privacy_policy_id: None,
            ledger_dir: dir.path(),
            lost_rounds: &[],
            run_id: None,
        },
    );
});
