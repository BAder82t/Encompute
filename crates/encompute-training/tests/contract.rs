//! The contract between this crate and the Python bindings: fixtures (same
//! bytes in) with their expected results (same result out). This test
//! checks the Rust side; `python/tests/test_training_contract.py` checks
//! the native module against the same files. Regenerate with
//! `ENCOMPUTE_WRITE_FIXTURES=1 cargo test -p encompute-training --test contract`.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use encompute_ir::confidentiality::{
    DpKind, DpMechanism, FixedPointCodec, PartyId, PrivacyBudget, PrivacyUnit,
};
use encompute_ir::parse;
use encompute_privacy::{ledger, release, Charged, Csprng, ReleaseSpec};
use encompute_secagg::identity_of;
use encompute_training::*;

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn write() -> bool {
    std::env::var("ENCOMPUTE_WRITE_FIXTURES").is_ok()
}

/// Checks `file` holds `value`, or writes it when regenerating.
fn golden(file: &str, value: &str) {
    let p = dir().join(file);
    if write() {
        std::fs::write(&p, value).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(&p).unwrap(), value, "{file}");
    }
}

fn h(c: char) -> String {
    c.to_string().repeat(64)
}

fn spec() -> TrainingSpec {
    if write() {
        std::fs::create_dir_all(dir()).unwrap();
        std::fs::write(
            dir().join("spec.json"),
            serde_json::to_string_pretty(&fixture_spec()).unwrap(),
        )
        .unwrap();
    }
    serde_json::from_str(&std::fs::read_to_string(dir().join("spec.json")).unwrap()).unwrap()
}

fn fixture_spec() -> TrainingSpec {
    TrainingSpec {
        version: 1,
        project: "contract".into(),
        purpose: "disease-training".into(),
        plan_id: h('a'),
        program_id: h('b'),
        policy_id: Some(h('c')),
        privacy_policy_id: Some(h('d')),
        aggregation_spec_id: h('e'),
        base_model: ModelCommitment {
            asset_id: "base-model".into(),
            owner: "modelco".into(),
            architecture: "{\"factory\":\"m:f\",\"kwargs\":{}}".into(),
            weights_digest: h('f'),
        },
        datasets: ["a", "b"]
            .iter()
            .enumerate()
            .map(|(i, x)| DatasetCommitment {
                asset_id: format!("patients-{x}"),
                owner: format!("hospital-{x}"),
                gradient_asset: format!("gradient-patients-{x}"),
                digest: h((b'1' + i as u8) as char),
            })
            .collect(),
        code_digest: h('3'),
        layout_digest: h('4'),
        config: TrainingConfig {
            method: "lora".into(),
            rank: 4,
            alpha: 8,
            target_modules: vec!["q".into(), "v".into()],
            optimizer: "sgd".into(),
            learning_rate: "0.1".into(),
            update_clip: "0.5".into(),
            local_steps: 10,
            batch_size: 16,
            rounds: 2,
            adapter_parameters: 256,
        },
        participants: ["hospital-a", "hospital-b"]
            .iter()
            .enumerate()
            .map(|(i, p)| {
                identity_of(
                    &PartyId::new(p).unwrap(),
                    &SigningKey::from_bytes(&[i as u8 + 1; 32]),
                )
            })
            .collect(),
    }
}

#[test]
fn spec_id_and_attestation_policy() {
    let s = spec();
    golden("spec.id", &s.id().unwrap());
    golden(
        "policy.json",
        &serde_json::to_string_pretty(&s.attestation_policy("sha256:worker", true).unwrap())
            .unwrap(),
    );
}

#[test]
fn layout_digest() {
    let l: AdapterLayout =
        serde_json::from_str(&std::fs::read_to_string(dir().join("layout.json")).unwrap()).unwrap();
    golden("layout.digest", &l.digest().unwrap());
}

#[test]
fn tensors_validate() {
    // tensors.bin is written by the Python encoder (the test there
    // regenerates it); Rust must accept it and agree on its entries.
    let b = std::fs::read(dir().join("tensors.bin")).unwrap();
    let m = tensor_manifest(&b).unwrap();
    golden("tensors.manifest.json", &serde_json::to_string(&m).unwrap());
    let mut padded = b.clone();
    padded.push(0);
    assert!(tensor_manifest(&padded).is_err());
    assert!(tensor_manifest(b"\x80\x04\x95pickle").is_err());
}

#[test]
fn sealed_asset_opens_on_both_sides() {
    let key = [7u8; 32];
    let plain = b"contract weights";
    if write() {
        std::fs::write(
            dir().join("sealed.bin"),
            seal_asset(&key, "model", "contract", "base-model", plain).unwrap(),
        )
        .unwrap();
    }
    let sealed = std::fs::read(dir().join("sealed.bin")).unwrap();
    assert_eq!(
        &*open_asset(&key, &sealed, "contract", "base-model", &sha256_hex(plain)).unwrap(),
        plain
    );
}

#[test]
fn adapter_record_signature_is_deterministic() {
    let r = AdapterRecord::new(&spec(), &h('9'), 1, None, &h('8'), "update", &h('7'))
        .unwrap()
        .sign(&SigningKey::from_bytes(&[3; 32]))
        .unwrap();
    r.verify(Some(&r.signer_key)).unwrap();
    golden(
        "adapter-record.json",
        &serde_json::to_string_pretty(&r).unwrap(),
    );
}

#[test]
fn export_decision() {
    let p = parse(&std::fs::read_to_string(dir().join("program.eir")).unwrap()).unwrap();
    let e = check_export(&p, &spec(), "adapter-1").unwrap_err();
    golden("export.txt", &format!("{}: {}", e.code, e.message));
}

#[test]
fn checkpoint_resume() {
    let ledgers = dir().join("ledgers");
    let key = [5u8; 32];
    let s = spec();
    if write() {
        let _ = std::fs::remove_dir_all(&ledgers);
        std::fs::create_dir_all(&ledgers).unwrap();
        let rs = ReleaseSpec {
            round_id: "01".repeat(32),
            output: "update".into(),
            policy_id: s.policy_id.clone(),
            privacy_policy_id: s.privacy_policy_id.clone().unwrap(),
            execution_spec_id: None,
            mechanism: DpMechanism {
                kind: DpKind::DiscreteGaussian,
                clip_norm: 1.0,
                noise_multiplier: 6.0,
            },
            codec: FixedPointCodec {
                clip_min: -1.0,
                clip_max: 1.0,
                scale: 256,
                modulus_bits: 32,
            },
            vector_len: 4,
            charged: vec![Charged {
                asset_id: "gradient-patients-a".into(),
                budget: PrivacyBudget {
                    unit: PrivacyUnit::Organization,
                    epsilon: 8.0,
                    delta: 1e-5,
                },
            }],
        };
        release(
            &rs,
            &ledgers,
            &[0; 4],
            &mut Csprng::from_os().unwrap(),
            &SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap();
        let cp = ledger::read(&ledgers.join("gradient-patients-a.ledger"))
            .unwrap()
            .checkpoint()
            .unwrap();
        let payload = b"adapter state".to_vec();
        let header = CheckpointHeader {
            version: 1,
            project: s.project.clone(),
            training_spec_id: s.id().unwrap(),
            run_id: h('9'),
            round: 1,
            adapter_id: "adapter-1".into(),
            payload_digest: sha256_hex(&payload),
            policy_id: s.policy_id.clone(),
            privacy_policy_id: s.privacy_policy_id.clone(),
            ledgers: [("gradient-patients-a".to_owned(), cp)].into(),
            lineage_root: None,
        };
        std::fs::write(
            dir().join("checkpoint.bin"),
            seal_checkpoint(&key, &header, &payload).unwrap(),
        )
        .unwrap();
    }
    let (h1, payload) = resume(
        &key,
        &std::fs::read(dir().join("checkpoint.bin")).unwrap(),
        &ResumeExpectation {
            project: &s.project,
            training_spec_id: &s.id().unwrap(),
            policy_id: s.policy_id.as_deref(),
            privacy_policy_id: s.privacy_policy_id.as_deref(),
            ledger_dir: &ledgers,
            lost_rounds: &[],
            run_id: None,
        },
    )
    .unwrap();
    assert_eq!(&*payload, b"adapter state");
    golden(
        "checkpoint.header.json",
        &serde_json::to_string(&h1).unwrap(),
    );
}
