//! Fuzz smoke tests for training artifacts: sealed checkpoint and asset
//! headers, canonical tensor files and adapter layouts. Mutated inputs
//! never panic; resource limits (huge header lengths, overflowing shapes
//! and offsets, deep JSON) are typed errors.

#[path = "../../encompute-ir/tests/fuzz_support/mod.rs"]
mod fuzz_support;

use std::collections::BTreeMap;
use std::time::Duration;

use encompute_ir::Code;
use encompute_training::*;
use fuzz_support::{run, within};

const KEY: [u8; 32] = [11; 32];

fn checkpoint_header(payload: &[u8]) -> CheckpointHeader {
    CheckpointHeader {
        version: 1,
        project: "prj_1".into(),
        training_spec_id: "spec".into(),
        run_id: "run_1".into(),
        round: 3,
        adapter_id: "adp_1".into(),
        payload_digest: sha256_hex(payload),
        policy_id: None,
        privacy_policy_id: None,
        ledgers: BTreeMap::new(),
        lineage_root: None,
    }
}

fn tensors(entries: &serde_json::Value, body: usize) -> Vec<u8> {
    let h = serde_json::to_vec(entries).unwrap();
    let mut t = b"ENCTENS1".to_vec();
    t.extend_from_slice(&(h.len() as u32).to_le_bytes());
    t.extend_from_slice(&h);
    t.extend(std::iter::repeat_n(0u8, body));
    t
}

fn tensor_seed() -> Vec<u8> {
    tensors(
        &serde_json::json!([
            {"name": "a.lora_A", "dtype": "float32", "shape": [2, 2], "offset": 0, "length": 16},
            {"name": "a.lora_B", "dtype": "int64", "shape": [1], "offset": 16, "length": 8},
        ]),
        24,
    )
}

fn layout() -> AdapterLayout {
    AdapterLayout {
        version: LAYOUT_VERSION,
        entries: vec![
            LayoutEntry {
                module: "q_proj".into(),
                parameter: "lora_A".into(),
                shape: vec![2, 4],
                offset: 0,
                length: 8,
                dtype: "float32".into(),
            },
            LayoutEntry {
                module: "q_proj".into(),
                parameter: "lora_B".into(),
                shape: vec![4, 2],
                offset: 8,
                length: 8,
                dtype: "float32".into(),
            },
        ],
    }
}

#[test]
fn mutated_sealed_artifacts_never_panic() {
    let payload = b"adapter weights".to_vec();
    let seeds = vec![
        seal_checkpoint(&KEY, &checkpoint_header(&payload), &payload).unwrap(),
        seal_asset(&KEY, "model", "prj_1", "asset_1", b"weights").unwrap(),
    ];
    let ledgers = std::env::temp_dir().join(format!("encompute-fuzz-train-{}", std::process::id()));
    std::fs::create_dir_all(&ledgers).unwrap();
    run("sealed", &seeds, 6000, Duration::from_secs(1), |bytes| {
        let _ = peek::<CheckpointHeader>(bytes);
        let _ = peek::<AssetHeader>(bytes);
        let _ = open::<serde_json::Value>(&KEY, bytes);
        let _ = open_asset(&KEY, bytes, "prj_1", "asset_1", &"0".repeat(64));
        let _ = resume(
            &KEY,
            bytes,
            &ResumeExpectation {
                project: "prj_1",
                training_spec_id: "spec",
                policy_id: None,
                privacy_policy_id: None,
                ledger_dir: &ledgers,
                lost_rounds: &[],
                run_id: Some("run_1"),
            },
        );
    });
}

#[test]
fn mutated_tensor_files_and_layouts_never_panic() {
    run(
        "tensors",
        &[tensor_seed()],
        8000,
        Duration::from_secs(1),
        |bytes| {
            if let Ok(entries) = tensor_manifest(bytes) {
                let end = entries.last().map_or(0, |e| e.offset + e.length);
                assert!(end <= bytes.len() as u64);
            }
        },
    );
    run(
        "layout",
        &[serde_json::to_vec(&layout()).unwrap()],
        8000,
        Duration::from_secs(1),
        |bytes| {
            if let Ok(l) = serde_json::from_slice::<AdapterLayout>(bytes) {
                if l.validate().is_ok() {
                    let _ = l.parameters();
                    l.digest().unwrap();
                }
            }
        },
    );
}

/// Regression: offsets were summed unchecked, so two 2^63-byte tensors
/// (or layout entries) overflowed: a panic in debug builds, a wrapped
/// offset in release builds.
#[test]
fn overflowing_offsets_are_refused() {
    let big = 1u64 << 63;
    let t = tensors(
        &serde_json::json!([
            {"name": "a", "dtype": "float64", "shape": [1u64 << 60], "offset": 0, "length": big},
            {"name": "b", "dtype": "float64", "shape": [1u64 << 60], "offset": big, "length": big},
        ]),
        0,
    );
    let e = within(Duration::from_millis(500), || tensor_manifest(&t)).unwrap_err();
    assert_eq!(e.code, Code::TrainingSpec, "{e}");
    let mut l = layout();
    l.entries[0].shape = vec![big];
    l.entries[0].length = big;
    l.entries[1].shape = vec![big];
    l.entries[1].offset = big;
    l.entries[1].length = big;
    assert_eq!(l.validate().unwrap_err().code, Code::TrainingSpec);
    assert_eq!(l.parameters(), u64::MAX);
}

#[test]
fn huge_lengths_and_malformed_headers_are_typed_errors() {
    let limit = Duration::from_millis(500);
    // Header lengths near u32::MAX with a short file.
    for n in [u32::MAX, u32::MAX - 11, 1 << 31] {
        let mut t = b"ENCTENS1".to_vec();
        t.extend_from_slice(&n.to_le_bytes());
        t.extend_from_slice(b"[]");
        let e = within(limit, || tensor_manifest(&t)).unwrap_err();
        assert_eq!(e.code, Code::TrainingSpec);
        let mut s = b"ENCSEAL1".to_vec();
        s.extend_from_slice(&n.to_le_bytes());
        s.extend_from_slice(&[0; 64]);
        let e = within(limit, || peek::<AssetHeader>(&s)).unwrap_err();
        assert_eq!(e.code, Code::Checkpoint, "{e}");
    }
    // Shapes whose element count overflows u64.
    let t = tensors(
        &serde_json::json!([{"name": "a", "dtype": "float32",
            "shape": [u64::MAX, u64::MAX], "offset": 0, "length": 0}]),
        0,
    );
    assert_eq!(tensor_manifest(&t).unwrap_err().code, Code::TrainingSpec);
    // Deep, huge and non-UTF-8 JSON headers.
    for h in [
        fuzz_support::nested_json(100_000, ""),
        format!("[{}]", vec!["{\"name\":\"a\"}"; 100_000].join(",")),
    ] {
        let mut t = b"ENCTENS1".to_vec();
        t.extend_from_slice(&(h.len() as u32).to_le_bytes());
        t.extend_from_slice(h.as_bytes());
        let e = within(Duration::from_secs(2), || tensor_manifest(&t)).unwrap_err();
        assert_eq!(e.code, Code::TrainingSpec);
    }
    let mut t = b"ENCTENS1".to_vec();
    t.extend_from_slice(&3u32.to_le_bytes());
    t.extend_from_slice(b"\xff\xfe\xfd");
    assert_eq!(tensor_manifest(&t).unwrap_err().code, Code::TrainingSpec);
    // Truncated anywhere.
    let seed = tensor_seed();
    for cut in 0..seed.len() {
        assert!(tensor_manifest(&seed[..cut]).is_err());
    }
}
