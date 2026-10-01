//! Training specs, sealed artifacts, checkpoint resume and adapter export.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use encompute_ir::confidentiality::{
    DpKind, DpMechanism, FixedPointCodec, PartyId, PrivacyBudget, PrivacyUnit,
};
use encompute_ir::{parse, Code};
use encompute_privacy::{ledger, release, Charged, Csprng, ReleaseSpec};
use encompute_secagg::identity_of;
use encompute_training::*;

fn h(c: char) -> String {
    c.to_string().repeat(64)
}

const REFERENCE: &str =
    r#"{"factory":"encompute.torch.models:tiny_classifier","kwargs":{"dim":32,"vocab":64}}"#;
/// A package's `config.json` (its bytes are what the package binds).
const HF_CONFIG: &str = r#"{"model_type": "bert", "hidden_size": 32}"#;

fn hf_architecture() -> String {
    serde_json::json!({
        "factory": HF_FACTORY,
        "kwargs": {"config": HF_CONFIG, "num_labels": 2, "task": "sequence-classification"},
    })
    .to_string()
}

fn spec() -> TrainingSpec {
    TrainingSpec {
        version: 2,
        project: "medical-lora".into(),
        purpose: "disease-training".into(),
        plan_id: h('a'),
        program_id: h('b'),
        policy_id: Some(h('c')),
        privacy_policy_id: Some(h('d')),
        aggregation_spec_id: h('e'),
        base_model: ModelCommitment {
            asset_id: "base-model".into(),
            owner: "modelco".into(),
            architecture: REFERENCE.into(),
            weights_digest: h('f'),
            huggingface: None,
        },
        datasets: vec![
            DatasetCommitment {
                asset_id: "patients-a".into(),
                owner: "hospital-a".into(),
                gradient_asset: "gradient-patients-a".into(),
                digest: h('1'),
                privacy_units: None,
                grouping_digest: None,
                preprocessing: None,
            },
            DatasetCommitment {
                asset_id: "patients-b".into(),
                owner: "hospital-b".into(),
                gradient_asset: "gradient-patients-b".into(),
                digest: h('2'),
                privacy_units: None,
                grouping_digest: None,
                preprocessing: None,
            },
        ],
        code_digest: h('3'),
        layout_digest: h('4'),
        config: TrainingConfig {
            method: "lora".into(),
            rank: 4,
            alpha: 8,
            target_modules: vec!["attn.q".into(), "attn.v".into()],
            optimizer: "sgd".into(),
            learning_rate: "0.05".into(),
            update_clip: "0.1".into(),
            local_steps: 5,
            batch_size: 8,
            rounds: 3,
            adapter_parameters: 512,
            dp_sgd: None,
            peft: None,
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
        key_brokers: [("modelco".to_string(), h('5'))].into(),
        asset_brokers: BTreeMap::new(),
        broker_organizations: BTreeMap::new(),
        coordinator_key: hex(&SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes()),
        initial_adapter_digest: h('0'),
    }
}

fn hex(b: &[u8]) -> String {
    encompute_verification::hex(b)
}

/// INV-126: every security-relevant field changes the TrainingSpecId.
#[test]
fn every_field_changes_the_spec_id() {
    let s = spec();
    s.validate().unwrap();
    let id = s.id().unwrap();
    type Edit = fn(&mut TrainingSpec);
    let edits: Vec<(&str, Edit)> = vec![
        ("base model", |s| s.base_model.weights_digest = h('9')),
        ("architecture", |s| {
            s.base_model.architecture = "other".into()
        }),
        ("training code", |s| s.code_digest = h('8')),
        ("tensor layout", |s| s.layout_digest = h('9')),
        ("purpose", |s| s.purpose = "marketing".into()),
        ("LoRA rank", |s| s.config.rank = 16),
        ("LoRA alpha", |s| s.config.alpha = 32),
        ("target modules", |s| {
            s.config.target_modules = vec!["attn.q".into()]
        }),
        ("optimizer", |s| s.config.optimizer = "adam".into()),
        ("learning rate", |s| s.config.learning_rate = "0.5".into()),
        ("update clip", |s| s.config.update_clip = "1.0".into()),
        ("local steps", |s| s.config.local_steps = 50),
        ("batch size", |s| s.config.batch_size = 1),
        ("rounds", |s| s.config.rounds = 100),
        ("plan", |s| s.plan_id = h('7')),
        ("policy", |s| s.policy_id = None),
        ("privacy policy", |s| s.privacy_policy_id = Some(h('6'))),
        ("aggregation spec (threshold, noise)", |s| {
            s.aggregation_spec_id = h('5')
        }),
        ("dataset", |s| s.datasets[0].digest = h('4')),
        ("participants", |s| {
            s.participants.pop().map(|_| ()).unwrap_or(())
        }),
        ("key broker", |s| {
            s.key_brokers.insert("modelco".into(), h('9'));
        }),
        ("coordinator", |s| s.coordinator_key = h('9')),
        ("initial adapter", |s| s.initial_adapter_digest = h('9')),
    ];
    for (what, e) in edits {
        let mut t = spec();
        e(&mut t);
        assert_ne!(t.id().unwrap(), id, "{what}");
    }
    assert_ne!(s.run_id("1").unwrap(), s.run_id("2").unwrap());
    // Malformed configurations are refused.
    let mut t = spec();
    t.config.learning_rate = "NaN".into();
    assert_eq!(t.validate().unwrap_err().code, Code::TrainingSpec);
    let mut t = spec();
    t.config.target_modules = vec!["b".into(), "a".into()];
    assert!(t.validate().is_err());
    let mut t = spec();
    t.config.method = "full".into();
    assert!(t.validate().is_err());
}

fn dp_spec() -> TrainingSpec {
    let mut s = spec();
    s.config.local_steps = 1;
    s.config.dp_sgd = Some(DpSgdConfig {
        privacy_unit: "patient".into(),
        per_example_clip: "1.0".into(),
        sampling: "poisson".into(),
        sampling_rate: "0.05".into(),
        noise_multiplier: "1.2".into(),
        delta: "1e-6".into(),
        grouping: "unit_ids".into(),
        accountant: "rdp-poisson-zw2019".into(),
        expected_batch: "8.0".into(),
    });
    for (i, d) in s.datasets.iter_mut().enumerate() {
        d.privacy_units = Some(80 + i as u64);
        d.grouping_digest = Some(h(if i == 0 { 'a' } else { 'b' }));
    }
    s
}

#[test]
fn every_dp_sgd_setting_changes_the_spec_id() {
    let s = dp_spec();
    s.validate().unwrap();
    let id = s.id().unwrap();
    // Organization mode has no DP-SGD fields: its spec IDs are unchanged.
    assert!(!String::from_utf8(
        encompute_verification::canonical::canonical_json(&spec()).unwrap()
    )
    .unwrap()
    .contains("dp_sgd"));
    assert_ne!(id, spec().id().unwrap());
    type Edit = fn(&mut DpSgdConfig);
    let edits: Vec<(&str, Edit)> = vec![
        ("privacy unit", |d| d.privacy_unit = "user".into()),
        ("per-example clip", |d| d.per_example_clip = "0.5".into()),
        ("sampling rate", |d| d.sampling_rate = "0.1".into()),
        ("noise", |d| d.noise_multiplier = "0.8".into()),
        ("delta", |d| d.delta = "1e-5".into()),
        ("grouping", |d| d.grouping = "none".into()),
        ("expected batch", |d| d.expected_batch = "16.0".into()),
    ];
    for (what, e) in edits {
        let mut t = dp_spec();
        e(t.config.dp_sgd.as_mut().unwrap());
        assert_ne!(t.id().unwrap(), id, "{what}");
    }
    let mut t = dp_spec();
    t.datasets[0].privacy_units = Some(1);
    assert_ne!(t.id().unwrap(), id, "privacy units");
    let mut t = dp_spec();
    t.datasets[0].grouping_digest = Some(h('c'));
    assert_ne!(t.id().unwrap(), id, "grouping");

    // Refused: organization unit, other sampling or accountant, more than
    // one local step, missing unit counts, units without DP-SGD.
    type Bad = fn(&mut TrainingSpec);
    let bad: Vec<(&str, Bad)> = vec![
        ("organization", |s| {
            s.config.dp_sgd.as_mut().unwrap().privacy_unit = "organization".into()
        }),
        ("shuffle", |s| {
            s.config.dp_sgd.as_mut().unwrap().sampling = "shuffle".into()
        }),
        ("accountant", |s| {
            s.config.dp_sgd.as_mut().unwrap().accountant = "zcdp-cks2020".into()
        }),
        ("q = 1", |s| {
            s.config.dp_sgd.as_mut().unwrap().sampling_rate = "1.0".into()
        }),
        ("local steps", |s| s.config.local_steps = 5),
        ("zero units", |s| s.datasets[1].privacy_units = Some(0)),
        ("grouping digest", |s| s.datasets[1].grouping_digest = None),
        ("units without DP-SGD", |s| s.config.dp_sgd = None),
    ];
    for (what, e) in bad {
        let mut t = dp_spec();
        e(&mut t);
        assert_eq!(
            t.validate().map_err(|e| e.code),
            Err(Code::TrainingSpec),
            "{what}"
        );
    }
}

#[test]
fn attestation_policy_binds_the_spec_and_code() {
    let s = spec();
    let p = s.attestation_policy("sha256:worker", true).unwrap();
    assert_eq!(p.execution_spec_id, s.id().unwrap());
    assert_eq!(p.artifact_digest.as_deref(), Some(h('3').as_str()));
    // SF-11: keys go only to a workload bound to the spec's privacy policy.
    assert!(s.privacy_policy_id.is_some());
    assert_eq!(p.privacy_policy_id, s.privacy_policy_id);
    assert!(p.allow_development);
    let prod = s.attestation_policy("sha256:worker", false).unwrap();
    assert!(!prod.allow_development);
}

#[test]
fn sealed_assets_open_only_as_committed() {
    let key = [7u8; 32];
    let weights = b"model weights".to_vec();
    let d = sha256_hex(&weights);
    let sealed = seal_asset(&key, "model", "medical-lora", "base-model", &weights).unwrap();
    assert_eq!(
        &*open_asset(&key, &sealed, "medical-lora", "base-model", &d).unwrap(),
        &weights[..]
    );
    // The plaintext is not in the sealed bytes.
    assert!(!sealed.windows(weights.len()).any(|w| w == weights));
    // Wrong key, modified bytes, another asset or version: refused.
    assert!(open_asset(&[8u8; 32], &sealed, "medical-lora", "base-model", &d).is_err());
    for i in [9, sealed.len() / 2, sealed.len() - 1] {
        let mut t = sealed.clone();
        t[i] ^= 1;
        assert!(
            open_asset(&key, &t, "medical-lora", "base-model", &d).is_err(),
            "{i}"
        );
    }
    assert!(open_asset(&key, &sealed, "medical-lora", "other-model", &d).is_err());
    assert!(open_asset(&key, &sealed, "other-project", "base-model", &d).is_err());
    assert!(open_asset(&key, &sealed, "medical-lora", "base-model", &h('0')).is_err());
    assert!(open_asset(&key, &sealed[..20], "medical-lora", "base-model", &d).is_err());
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("encompute-train-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn release_round(d: &std::path::Path, round: u64) {
    let rs = ReleaseSpec {
        sources_per_unit: 1,
        layout_id: None,
        round_id: format!("{round:064x}"),
        output: "update".into(),
        policy_id: Some(h('c')),
        privacy_policy_id: h('d'),
        execution_spec_id: None,
        mechanism: DpMechanism {
            kind: DpKind::DiscreteGaussian,
            clip_norm: 1.0,
            noise_multiplier: 6.0,
            sampling_rate: None,
            preset: None,
        },
        codec: FixedPointCodec {
            clip_min: -1.0,
            clip_max: 1.0,
            scale: 256,
            modulus_bits: 32,
        },
        vector_len: 4,
        charged: ["gradient-patients-a", "gradient-patients-b"]
            .iter()
            .map(|a| Charged {
                asset_id: (*a).into(),
                budget: PrivacyBudget {
                    unit: PrivacyUnit::Patient,
                    epsilon: 3.0,
                    delta: 1e-6,
                },
                scoped: None,
            })
            .collect(),
    };
    let mut rng = Csprng::from_os().unwrap();
    release(&rs, d, &[0; 4], &mut rng, &SigningKey::from_bytes(&[9; 32])).unwrap();
}

fn checkpoint_at(d: &std::path::Path, round: u32, key: &[u8]) -> Vec<u8> {
    let mut ledgers = BTreeMap::new();
    for a in ["gradient-patients-a", "gradient-patients-b"] {
        ledgers.insert(
            a.to_owned(),
            ledger::read(&d.join(format!("{a}.ledger")))
                .unwrap()
                .checkpoint()
                .unwrap(),
        );
    }
    let payload = format!("adapter weights at round {round}").into_bytes();
    let s = spec();
    seal_checkpoint(
        key,
        &CheckpointHeader {
            version: 1,
            project: s.project.clone(),
            training_spec_id: s.id().unwrap(),
            run_id: s.run_id("r").unwrap(),
            round,
            adapter_id: format!("adapter-{round}"),
            payload_digest: sha256_hex(&payload),
            policy_id: s.policy_id.clone(),
            privacy_policy_id: s.privacy_policy_id.clone(),
            ledgers,
            lineage_root: None,
        },
        &payload,
    )
    .unwrap()
}

/// INV-123: resume can never roll back privacy state; checkpoints from
/// another project, spec or policy are refused.
#[test]
fn checkpoint_resume_never_rolls_back_privacy() {
    let d = dir("resume");
    let key = [5u8; 32];
    let s = spec();
    let id = s.id().unwrap();
    let expect = |d: &PathBuf| ResumeExpectation {
        project: "medical-lora",
        training_spec_id: Box::leak(id.clone().into_boxed_str()),
        policy_id: s.policy_id.as_deref(),
        privacy_policy_id: s.privacy_policy_id.as_deref(),
        ledger_dir: Box::leak(d.clone().into_boxed_path()),
        lost_rounds: &[],
        run_id: None,
    };
    release_round(&d, 1);
    let old = checkpoint_at(&d, 1, &key);
    let (h1, _) = resume(&key, &old, &expect(&d)).unwrap();
    assert_eq!(h1.round, 1);
    // Train on: round 2 spends more budget. The round-1 checkpoint is now
    // stale: restoring it would resume from before a charged release.
    release_round(&d, 2);
    let e = resume(&key, &old, &expect(&d)).unwrap_err();
    assert_eq!(e.code, Code::Checkpoint);
    assert!(e.message.contains("stale"), "{}", e.message);
    let current = checkpoint_at(&d, 2, &key);
    resume(&key, &current, &expect(&d)).unwrap();
    // Rolling the ledger back to match the old checkpoint is detected by
    // the newer checkpoint (and by owners' checkpoints, ADR-013).
    let path = d.join("gradient-patients-a.ledger");
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    std::fs::write(&path, lines[..3].join("\n") + "\n").unwrap();
    assert_eq!(
        resume(&key, &current, &expect(&d)).unwrap_err().code,
        Code::PrivacyLedger
    );
    std::fs::write(&path, text).unwrap();
    // Another project, spec or policy; a modified checkpoint; wrong key.
    // A round released after the checkpoint but never accepted (a crash
    // before the commit point): resuming from the last accepted checkpoint
    // is allowed, and that round's spend stays charged. Declaring an
    // accepted round lost does not help a stale checkpoint (round 2 is
    // the one after `old`, round 1 is not).
    let lost = vec![format!("{:064x}", 2)];
    let mut e2 = expect(&d);
    e2.lost_rounds = Box::leak(lost.into_boxed_slice());
    resume(&key, &old, &e2).unwrap();
    let wrong = vec![format!("{:064x}", 9)];
    let mut e3 = expect(&d);
    e3.lost_rounds = Box::leak(wrong.into_boxed_slice());
    assert_eq!(resume(&key, &old, &e3).unwrap_err().code, Code::Checkpoint);
    // Another run of the same spec.
    let mut e4 = expect(&d);
    e4.run_id = Some("another-run");
    assert_eq!(
        resume(&key, &current, &e4).unwrap_err().code,
        Code::Checkpoint
    );
    let run = spec().run_id("r").unwrap();
    let mut e5 = expect(&d);
    e5.run_id = Some(Box::leak(run.into_boxed_str()));
    resume(&key, &current, &e5).unwrap();
    let other = dir("resume-other");
    let mut e2 = expect(&d);
    e2.project = "other";
    assert_eq!(
        resume(&key, &current, &e2).unwrap_err().code,
        Code::Checkpoint
    );
    let mut e2 = expect(&d);
    e2.training_spec_id = "00";
    assert_eq!(
        resume(&key, &current, &e2).unwrap_err().code,
        Code::TrainingSpec
    );
    let mut e2 = expect(&d);
    e2.policy_id = None;
    assert_eq!(
        resume(&key, &current, &e2).unwrap_err().code,
        Code::TrainingSpec
    );
    let mut t = current.clone();
    let n = t.len();
    t[n - 5] ^= 1;
    assert!(resume(&key, &t, &expect(&d)).is_err());
    assert!(resume(&[6u8; 32], &current, &expect(&d)).is_err());
    // A checkpoint whose ledgers do not exist here (another deployment).
    assert!(resume(&key, &current, &expect(&other)).is_err());
}

const PROGRAM: &str = "encompute 0.1
program ft precision 0.001 purpose \"disease-training\"
party \"hospital-a\" \"A\"
party \"hospital-b\" \"B\"
party \"modelco\" \"M\"
asset \"base-model\" model owners [\"modelco\"] readers [] purposes [\"disease-training\"] release never
asset \"patients-a\" dataset owners [\"hospital-a\"] readers [] purposes [\"disease-training\"] release never
asset \"patients-b\" dataset owners [\"hospital-b\"] readers [] purposes [\"disease-training\"] release never
asset \"gradient-patients-a\" gradient owners [\"hospital-a\"] readers [\"modelco\"] purposes [\"disease-training\"] release aggregate_only
asset \"gradient-patients-b\" gradient owners [\"hospital-b\"] readers [\"modelco\"] purposes [\"disease-training\"] release aggregate_only
%0 = input \"a\" [-1.0, 1.0] asset \"gradient-patients-a\" : secret vector<4>
%1 = input \"b\" [-1.0, 1.0] asset \"gradient-patients-b\" : secret vector<4>
%2 = add %0, %1 : secret vector<4>
output \"update\" = %2 to \"modelco\"
aggregate \"update\" sum minimum 2 colluding 0 clip [-1.0, 1.0] scale 256 modulus 32
";

/// INV-125: an adapter is exportable only if every parent permits it.
#[test]
fn export_follows_every_parent() {
    let p = parse(PROGRAM).unwrap();
    let e = check_export(&p, &spec(), "adapter-3").unwrap_err();
    assert_eq!(e.code, Code::ExportDenied);
    for parent in ["base-model", "patients-a", "patients-b"] {
        assert!(e.message.contains(parent), "{}", e.message);
    }
    // Every parent permits public adapters: export allowed.
    let permit = |t: &str, asset: &str| {
        let mut out = String::new();
        for line in t.lines() {
            out.push_str(line);
            if line.starts_with(&format!("asset \"{asset}\"")) {
                out.push_str(" derive [adapter public to []]");
            }
            out.push('\n');
        }
        out
    };
    // `derive` goes before `privacy`; these assets have no budget.
    let all = [
        "base-model",
        "patients-a",
        "patients-b",
        "gradient-patients-a",
        "gradient-patients-b",
    ]
    .iter()
    .fold(PROGRAM.to_owned(), |t, a| permit(&t, a));
    check_export(&parse(&all).unwrap(), &spec(), "adapter-3").unwrap();
    // All but the base model: denied, naming only the model.
    let but_model = [
        "patients-a",
        "patients-b",
        "gradient-patients-a",
        "gradient-patients-b",
    ]
    .iter()
    .fold(PROGRAM.to_owned(), |t, a| permit(&t, a));
    let e = check_export(&parse(&but_model).unwrap(), &spec(), "adapter-3").unwrap_err();
    assert!(e.message.contains("base-model (never)"), "{}", e.message);
    assert!(!e.message.contains("patients-a"), "{}", e.message);
}

#[test]
fn adapter_records_are_signed() {
    let s = spec();
    let k = SigningKey::from_bytes(&[3; 32]);
    let r = AdapterRecord::new(&s, "run", 2, Some("adapter-1"), &h('a'), "update", &h('b'))
        .unwrap()
        .sign(&k)
        .unwrap();
    r.verify(Some(&r.signer_key)).unwrap();
    assert!(r.verify(Some(&h('0'))).is_err());
    let mut t = r.clone();
    t.record.previous = None;
    assert!(t.verify(None).is_err());
    let mut t = r.clone();
    t.record.adapter_digest = h('c');
    assert!(t.verify(None).is_err());
}

fn hf_package() -> HfModelPackage {
    let files: Vec<PackageFile> = [
        ("config.json", 'a'),
        ("model.safetensors", 'b'),
        ("tokenizer.json", 'c'),
        ("vocab.txt", 'd'),
    ]
    .iter()
    .map(|(p, c)| PackageFile {
        path: p.to_string(),
        sha256: h(*c),
        size: 10,
    })
    .collect();
    let mut p = HfModelPackage {
        version: 1,
        repo_id: "org/tiny-bert".into(),
        revision: "0123456789abcdef0123456789abcdef01234567".into(),
        model_type: "bert".into(),
        model_class: "BertForSequenceClassification".into(),
        task: "sequence-classification".into(),
        num_labels: 2,
        config_digest: h('a'),
        tokenizer_digest: String::new(),
        files,
        libraries: LibraryVersions {
            transformers: "4.46".into(),
            peft: "0.12".into(),
            torch: "2.3".into(),
        },
        license: Some("apache-2.0".into()),
    };
    let config = sha256_hex(HF_CONFIG.as_bytes());
    p.files[0].sha256 = config.clone();
    p.config_digest = config;
    p.tokenizer_digest = p.expected_tokenizer_digest();
    p
}

fn hf_spec() -> TrainingSpec {
    let mut s = spec();
    s.base_model.huggingface = Some(hf_package());
    s.base_model.architecture = hf_architecture();
    s.config.method = "peft-lora".into();
    s.config.target_modules = vec!["query".into(), "value".into()];
    s.config.peft = Some(PeftConfig {
        peft_type: "LORA".into(),
        r: s.config.rank,
        lora_alpha: s.config.alpha,
        lora_dropout: "0.0".into(),
        target_modules: vec!["query".into(), "value".into()],
        bias: "none".into(),
        modules_to_save: vec!["classifier".into()],
        task_type: "SEQ_CLS".into(),
        init_lora_weights: "true".into(),
        adapter_name: "default".into(),
        library: "0.12".into(),
    });
    let tok = hf_package().tokenizer_digest;
    for d in &mut s.datasets {
        d.preprocessing = Some(TextPreprocessing {
            tokenizer_digest: tok.clone(),
            max_length: 64,
            truncation: true,
            padding: "max_length".into(),
            stride: None,
        });
    }
    s
}

#[test]
fn hugging_face_packages_and_peft_are_bound_and_checked() {
    let s = hf_spec();
    s.validate().unwrap();
    let id = s.id().unwrap();
    type Edit = fn(&mut TrainingSpec);
    let changes: Vec<(&str, Edit)> = vec![
        ("revision", |s| {
            s.base_model.huggingface.as_mut().unwrap().revision = "f".repeat(40)
        }),
        ("weight shard", |s| {
            s.base_model.huggingface.as_mut().unwrap().files[1].sha256 = h('e')
        }),
        ("transformers", |s| {
            s.base_model
                .huggingface
                .as_mut()
                .unwrap()
                .libraries
                .transformers = "4.47".into()
        }),
        ("lora dropout", |s| {
            s.config.peft.as_mut().unwrap().lora_dropout = "0.1".into()
        }),
        ("bias", |s| {
            s.config.peft.as_mut().unwrap().bias = "all".into()
        }),
        ("modules to save", |s| {
            s.config.peft.as_mut().unwrap().modules_to_save = vec![]
        }),
        ("init", |s| {
            s.config.peft.as_mut().unwrap().init_lora_weights = "gaussian".into()
        }),
        ("adapter name", |s| {
            s.config.peft.as_mut().unwrap().adapter_name = "other".into()
        }),
        ("max length", |s| {
            s.datasets[0].preprocessing.as_mut().unwrap().max_length = 32
        }),
        ("stride", |s| {
            s.datasets[0].preprocessing.as_mut().unwrap().stride = Some(8)
        }),
    ];
    for (what, e) in changes {
        let mut t = hf_spec();
        e(&mut t);
        assert_ne!(t.id().unwrap(), id, "{what}");
    }
    let refused: Vec<(&str, Edit)> = vec![
        ("mutable revision", |s| {
            s.base_model.huggingface.as_mut().unwrap().revision = "main".into()
        }),
        ("pickle", |s| {
            let p = s.base_model.huggingface.as_mut().unwrap();
            p.files.push(PackageFile {
                path: "pytorch_model.bin".into(),
                sha256: h('f'),
                size: 1,
            });
        }),
        ("remote code", |s| {
            let p = s.base_model.huggingface.as_mut().unwrap();
            p.files.push(PackageFile {
                path: "zz_modeling.py".into(),
                sha256: h('f'),
                size: 1,
            });
        }),
        ("no safetensors", |s| {
            s.base_model
                .huggingface
                .as_mut()
                .unwrap()
                .files
                .retain(|f| f.path != "model.safetensors")
        }),
        ("unsupported architecture", |s| {
            s.base_model.huggingface.as_mut().unwrap().model_type = "llama".into()
        }),
        ("tokenizer digest", |s| {
            s.base_model.huggingface.as_mut().unwrap().tokenizer_digest = h('9')
        }),
        ("another tokenizer", |s| {
            s.datasets[0]
                .preprocessing
                .as_mut()
                .unwrap()
                .tokenizer_digest = h('9')
        }),
        ("no preprocessing", |s| s.datasets[0].preprocessing = None),
        ("PEFT without HF", |s| s.base_model.huggingface = None),
        ("HF without PEFT", |s| {
            s.config.peft = None;
            s.config.method = "lora".into();
        }),
        ("rank mismatch", |s| s.config.peft.as_mut().unwrap().r = 16),
        ("PEFT library", |s| {
            s.config.peft.as_mut().unwrap().library = "0.13".into()
        }),
        ("PEFT task", |s| {
            s.config.peft.as_mut().unwrap().task_type = "CAUSAL_LM".into()
        }),
    ];
    for (what, e) in refused {
        let mut t = hf_spec();
        e(&mut t);
        let err = t.validate().unwrap_err();
        assert!(
            matches!(err.code, Code::TrainingSpec | Code::ModelPackage),
            "{what}: {err:?}"
        );
    }
    // The package's own checks.
    use encompute_training::hf::{check_config, check_file};
    for f in [
        "pytorch_model.bin",
        "model.pt",
        "modeling_x.py",
        "weights.pkl",
        "notes.txt",
        "sub/model.safetensors",
    ] {
        assert_eq!(check_file(f).unwrap_err().code, Code::ModelPackage, "{f}");
    }
    for f in [
        "model.safetensors",
        "model-00001-of-00002.safetensors",
        "config.json",
        "vocab.txt",
    ] {
        check_file(f).unwrap();
    }
    for c in [
        r#"{"model_type": "bert", "auto_map": {"AutoModel": "x.Y"}}"#,
        r#"{"model_type": "bert", "trust_remote_code": true}"#,
        r#"{"model_type": "llama"}"#,
        r#"{}"#,
    ] {
        assert!(
            check_config(&serde_json::from_str(c).unwrap()).is_err(),
            "{c}"
        );
    }
    assert_eq!(
        check_config(&serde_json::json!({"model_type": "roberta"})).unwrap(),
        "roberta"
    );
    let files = vec!["model-1.safetensors".to_string(), "config.json".to_string()];
    let index = |f: &str| serde_json::json!({"weight_map": {"a.weight": "model-1.safetensors", "b.weight": f}});
    encompute_training::hf::check_index(&index("model-1.safetensors"), &files).unwrap();
    for f in [
        "../../etc/passwd",
        "/etc/passwd",
        "config.json",
        "model-2.safetensors",
        "pytorch_model.bin",
    ] {
        assert!(
            encompute_training::hf::check_index(&index(f), &files).is_err(),
            "{f}"
        );
    }
}

fn worker_evidence(
    s: &TrainingSpec,
    key: &SigningKey,
) -> (encompute_attestation::AttestationRecord, WorkerEvidence) {
    worker_evidence_bound(s, key, s.privacy_policy_id.as_deref(), &s.code_digest)
}

/// Evidence whose attestation binds `privacy_policy` and `artifact`.
fn worker_evidence_bound(
    s: &TrainingSpec,
    key: &SigningKey,
    privacy_policy: Option<&str>,
    artifact: &str,
) -> (encompute_attestation::AttestationRecord, WorkerEvidence) {
    use encompute_attestation::mock::MockHardware;
    use encompute_attestation::{
        AttestationChallenge, AttestationRecord, Attester, WorkloadSession,
    };
    let identity = encompute_verification::EvaluatorSigner::from_seed(&key.to_bytes()).identity();
    let session = WorkloadSession::new(&identity).with_privacy_policy(privacy_policy);
    let challenge = AttestationChallenge::new("broker", 1_000, 60).unwrap();
    let binding = session.binding(
        &challenge,
        &s.participant_execution_id(&s.datasets[0].owner).unwrap(),
        s.policy_id.as_deref(),
        artifact,
    );
    let evidence = MockHardware::from_seed(&[9; 32])
        .attester(&format!("sha256:{}", h('7')))
        .attest(&challenge, &binding)
        .unwrap();
    let record = AttestationRecord::new(evidence);
    let d = &s.datasets[0];
    let e = WorkerEvidence {
        version: WORKER_EVIDENCE_VERSION,
        project: s.project.clone(),
        training_spec_id: s.id().unwrap(),
        run_id: s.run_id("n").unwrap(),
        plan_id: s.plan_id.clone(),
        policy_id: s.policy_id.clone(),
        privacy_policy_id: s.privacy_policy_id.clone(),
        participant: d.owner.clone(),
        round: 1,
        model_asset: s.base_model.asset_id.clone(),
        model_package_id: s.base_model.huggingface.as_ref().map(|p| p.id().unwrap()),
        weights_digest: s.base_model.weights_digest.clone(),
        dataset_asset: d.asset_id.clone(),
        dataset_digest: d.digest.clone(),
        layout_digest: s.layout_digest.clone(),
        input_adapter: "adapter-0".into(),
        input_adapter_digest: s.initial_adapter_digest.clone(),
        config_digest: s.config_digest().unwrap(),
        seed: 7,
        image_digest: format!("sha256:{}", h('7')),
        attestation_record_id: record.id().unwrap(),
        session_id: record.session_id().unwrap(),
        output_asset: format!("contribution-{}-r1", d.owner),
        output_commitment: h('a'),
        step_commitment: h('b'),
        gradient_path: "vmap".into(),
        libraries: BTreeMap::new(),
    };
    (record, e)
}

#[test]
fn worker_evidence_binds_its_spec_assets_and_attestation() {
    let s = hf_spec();
    let key = SigningKey::from_bytes(&[5; 32]);
    let (record, e) = worker_evidence(&s, &key);
    let signed = e.clone().sign(&key).unwrap();
    signed.verify(&s, &record).unwrap();
    // Signed by another key than the attested one.
    let other = e.clone().sign(&SigningKey::from_bytes(&[6; 32])).unwrap();
    assert!(other.verify(&s, &record).is_err());
    // Any edited field breaks the signature; re-signed, it breaks a binding.
    type Edit = fn(&mut WorkerEvidence);
    let edits: Vec<(&str, Edit)> = vec![
        ("participant", |e| e.participant = "hospital-b".into()),
        ("dataset", |e| e.dataset_asset = "patients-b".into()),
        ("dataset digest", |e| e.dataset_digest = h('3')),
        ("model", |e| e.weights_digest = h('0')),
        ("package", |e| e.model_package_id = Some(h('0'))),
        ("layout", |e| e.layout_digest = h('0')),
        ("spec", |e| e.training_spec_id = h('0')),
        ("record", |e| e.attestation_record_id = h('0')),
        ("session", |e| e.session_id = h('0')),
        ("round", |e| e.round = 99),
        ("plan", |e| e.plan_id = h('0')),
        // Review finding TR-2 (ENC-SF-2026-050): what it trained from and with.
        ("input adapter", |e| e.input_adapter = "adapter-3".into()),
        ("input adapter digest", |e| e.input_adapter_digest = h('9')),
        ("configuration", |e| e.config_digest = h('9')),
    ];
    for (what, edit) in edits {
        let mut forged = signed.clone();
        edit(&mut forged.evidence);
        assert!(forged.verify(&s, &record).is_err(), "{what}: signature");
        let mut resigned = e.clone();
        edit(&mut resigned);
        assert!(
            resigned.sign(&key).unwrap().verify(&s, &record).is_err(),
            "{what}: binding"
        );
    }
    // The seed is committed: changing it breaks the signature.
    let mut forged = signed.clone();
    forged.evidence.seed = 8;
    assert!(forged.verify(&s, &record).is_err());
    // Evidence under another training spec (a lower rank) does not verify.
    let mut t = hf_spec();
    t.config.rank = 8;
    t.config.peft.as_mut().unwrap().r = 8;
    assert!(signed.verify(&t, &record).is_err());
    // An attestation for another spec, or of another key, does not either.
    let (record2, _) = worker_evidence(&t, &key);
    assert!(signed.verify(&s, &record2).is_err());
    let (record3, _) = worker_evidence(&s, &SigningKey::from_bytes(&[8; 32]));
    assert!(signed.verify(&s, &record3).is_err());
    // Review finding KB-5 (ENC-SF-2026-062): an attestation bound to another (or no) privacy
    // policy, or to other training code, does not back the evidence.
    for (privacy, artifact) in [
        (None, s.code_digest.clone()),
        (s.privacy_policy_id.clone(), h('9')),
    ] {
        let (r, e) = worker_evidence_bound(&s, &key, privacy.as_deref(), &artifact);
        let err = e.sign(&key).unwrap().verify(&s, &r).unwrap_err();
        assert_eq!(err.code, Code::TrainingSpec, "{err}");
    }
    // Review finding TR-2 (ENC-SF-2026-050): round 1 starts from the spec's initial adapter.
    let mut other_start = e.clone();
    other_start.input_adapter_digest = h('9');
    assert!(other_start.sign(&key).unwrap().verify(&s, &record).is_err());
    // A session attested for another participant cannot act for this one:
    // hospital-a's evidence, claimed by a session scoped to hospital-b.
    let mut as_b = e.clone();
    as_b.participant = s.datasets[1].owner.clone();
    as_b.dataset_asset = s.datasets[1].asset_id.clone();
    as_b.dataset_digest = s.datasets[1].digest.clone();
    assert!(as_b.sign(&key).unwrap().verify(&s, &record).is_err());
    assert_ne!(
        s.participant_execution_id("hospital-a").unwrap(),
        s.participant_execution_id("hospital-b").unwrap()
    );
    assert!(s.participant_execution_id("mallory").is_err());
}

/// Review finding TR-1 (ENC-SF-2026-037): a training spec names only a factory the worker
/// image ships, with arguments of its schema; a Hugging Face model is
/// built only from the package's own config.json. Anything else is refused
/// by the validator, before any key is released for the spec.
#[test]
fn a_spec_names_only_an_allowlisted_factory() {
    type Edit = fn(&mut TrainingSpec);
    let arch = |s: &mut TrainingSpec, v: serde_json::Value| {
        s.base_model.architecture = v.to_string();
    };
    let reference: Vec<(&str, Edit)> = vec![
        ("subprocess", |s| {
            s.base_model.architecture =
                r#"{"factory":"subprocess:run","kwargs":{"args":"touch /tmp/x","shell":true}}"#
                    .into()
        }),
        ("timeit", |s| {
            s.base_model.architecture =
                r#"{"factory":"timeit:timeit","kwargs":{"stmt":"import os","number":1}}"#.into()
        }),
        ("unknown kwarg", |s| {
            s.base_model.architecture =
                r#"{"factory":"encompute.torch.models:tiny_classifier","kwargs":{"stmt":"x"}}"#
                    .into()
        }),
        ("non-integer kwarg", |s| {
            s.base_model.architecture =
                r#"{"factory":"encompute.torch.models:tiny_classifier","kwargs":{"dim":"16"}}"#
                    .into()
        }),
        ("extra field", |s| {
            s.base_model.architecture =
                r#"{"factory":"encompute.torch.models:tiny_classifier","kwargs":{},"module":"os"}"#
                    .into()
        }),
        ("not JSON", |s| {
            s.base_model.architecture = "TinyTransformer(d=32)".into()
        }),
        ("the HF factory for a reference model", |s| {
            s.base_model.architecture = hf_architecture()
        }),
    ];
    spec().validate().unwrap();
    for (what, e) in reference {
        let mut t = spec();
        e(&mut t);
        assert_eq!(t.validate().unwrap_err().code, Code::TrainingSpec, "{what}");
    }
    hf_spec().validate().unwrap();
    let hf: Vec<(&str, Edit)> = vec![
        ("the reference factory", |s| {
            s.base_model.architecture = REFERENCE.into()
        }),
        ("another config", |s| {
            s.base_model.architecture = serde_json::json!({"factory": HF_FACTORY, "kwargs": {
                "config": r#"{"model_type": "bert", "hidden_size": 64}"#,
                "num_labels": 2, "task": "sequence-classification"}})
            .to_string()
        }),
        ("labels", |s| {
            s.base_model.architecture = serde_json::json!({"factory": HF_FACTORY, "kwargs": {
                "config": HF_CONFIG, "num_labels": 3, "task": "sequence-classification"}})
            .to_string()
        }),
        ("extra kwarg", |s| {
            s.base_model.architecture = serde_json::json!({"factory": HF_FACTORY, "kwargs": {
                "config": HF_CONFIG, "num_labels": 2, "task": "sequence-classification",
                "trust_remote_code": true}})
            .to_string()
        }),
    ];
    for (what, e) in hf {
        let mut t = hf_spec();
        e(&mut t);
        assert_eq!(t.validate().unwrap_err().code, Code::TrainingSpec, "{what}");
    }
    // A config.json with custom code, bound by the package's own digest,
    // is still refused.
    let mut t = hf_spec();
    let evil = r#"{"model_type": "bert", "auto_map": {"AutoModel": "x.Y"}}"#;
    arch(
        &mut t,
        serde_json::json!({"factory": HF_FACTORY, "kwargs": {"config": evil,
            "num_labels": 2, "task": "sequence-classification"}}),
    );
    let p = t.base_model.huggingface.as_mut().unwrap();
    p.config_digest = sha256_hex(evil.as_bytes());
    p.files[0].sha256 = p.config_digest.clone();
    assert!(t.validate().is_err());
}

/// The reference factory's arguments were bounded one by one (each at most
/// 2^20), not together: `dim` = 2^20 alone asks the worker for five
/// dim x dim linear layers, terabytes. The model's exact parameter count
/// (embedding, q/k/v/out/feed-forward, head) and its per-sample
/// activations are bounded too, before any worker builds it.
#[test]
fn reference_factory_arguments_are_bounded_together() {
    let parse = |kwargs: serde_json::Value| {
        Architecture::parse(
            &serde_json::json!({"factory": REFERENCE_FACTORY, "kwargs": kwargs}).to_string(),
        )
    };
    // The TinyClassifier's parameters: vocab*dim + 5*(dim*dim + dim) + dim*classes + classes.
    let params = |vocab: u64, dim: u64, classes: u64| {
        vocab * dim + 5 * (dim * dim + dim) + dim * classes + classes
    };
    for ok in [
        serde_json::json!({}),
        serde_json::json!({"vocab": 64, "dim": 16, "classes": 2, "seq": 8}),
        serde_json::json!({"dim": 4096}),
        serde_json::json!({"vocab": 1 << 20, "dim": 128}),
        serde_json::json!({"seq": 1 << 13}),
        serde_json::json!({"seq": 16000}),
        serde_json::json!({"classes": 1 << 20}),
    ] {
        parse(ok.clone()).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    assert!(params(64, 4096, 2) <= 1 << 28 && params(64, 8192, 2) > 1 << 28);
    for too_big in [
        serde_json::json!({"dim": 1 << 20}),
        serde_json::json!({"dim": 8192}),
        serde_json::json!({"vocab": 1 << 20, "dim": 256}),
        serde_json::json!({"dim": 1 << 14, "classes": 1 << 20}),
        serde_json::json!({"seq": 1 << 20}),
        serde_json::json!({"seq": 1 << 14}),
        // seq alone fits (16000 x 16016); with dim 1000 the activations do not.
        serde_json::json!({"seq": 16000, "dim": 1000}),
    ] {
        let e = parse(too_big.clone()).unwrap_err();
        assert_eq!(e.code, Code::TrainingSpec, "{too_big}");
        assert!(e.message.contains("too large"), "{too_big}: {e}");
    }
    // Through the validator too.
    let mut t = spec();
    t.base_model.architecture =
        serde_json::json!({"factory": REFERENCE_FACTORY, "kwargs": {"dim": 1 << 20}}).to_string();
    assert_eq!(t.validate().unwrap_err().code, Code::TrainingSpec);
}

/// Review finding TR-4 (ENC-SF-2026-073): a package's configuration cannot ask for
/// quantization or choose the attention implementation, and its tokenizer
/// configuration holds only known settings of a Transformers-native
/// tokenizer.
#[test]
fn package_configurations_hold_only_known_settings() {
    use encompute_training::hf::{check_config, check_tokenizer_config};
    for c in [
        r#"{"model_type": "bert", "quantization_config": {"quant_method": "bitsandbytes"}}"#,
        r#"{"model_type": "bert", "_attn_implementation": "flash_attention_2"}"#,
        r#"{"model_type": "bert", "_attn_implementation_autoset": true}"#,
        r#"{"model_type": "bert", "attn_implementation": "sdpa"}"#,
    ] {
        let e = check_config(&serde_json::from_str(c).unwrap()).unwrap_err();
        assert_eq!(e.code, Code::ModelPackage, "{c}");
    }
    let ok = serde_json::json!({"do_lower_case": true, "model_max_length": 512,
        "tokenizer_class": "BertTokenizer", "cls_token": "[CLS]", "added_tokens_decoder": {}});
    check_tokenizer_config(&ok).unwrap();
    for c in [
        serde_json::json!({"auto_map": {"AutoTokenizer": ["x.T", null]}}),
        serde_json::json!({"tokenizer_class": "EvilTokenizer"}),
        serde_json::json!({"processor_class": "x.P"}),
        // Keys naming a file: Transformers would open whatever path they name.
        serde_json::json!({"tokenizer_file": "/etc/passwd"}),
        serde_json::json!({"full_tokenizer_file": "../other/tokenizer.json"}),
        serde_json::json!({"special_tokens_map_file": "/home/x/special_tokens_map.json"}),
        serde_json::json!({"tokenizer_file": null}),
        serde_json::json!([]),
    ] {
        assert_eq!(
            check_tokenizer_config(&c).unwrap_err().code,
            Code::ModelPackage,
            "{c}"
        );
    }
}

/// Review finding KB-1 (ENC-SF-2026-036): a spec binds the key brokers whose grants its
/// workers accept.
#[test]
fn a_spec_binds_its_key_brokers() {
    let mut t = spec();
    t.key_brokers.clear();
    assert_eq!(t.validate().unwrap_err().code, Code::TrainingSpec);
    let mut t = spec();
    t.key_brokers.insert("modelco".into(), "NOTHEX".into());
    assert!(t.validate().is_err());
    let mut t = spec();
    t.coordinator_key = "x".into();
    assert!(t.validate().is_err());
    // A second broker would be trusted for every asset, so it could grant a
    // key of its choosing for the first broker's assets (a participant's
    // contribution key among them): one broker per spec.
    let mut t = spec();
    t.key_brokers.insert("colluding-broker".into(), h('7'));
    let e = t.validate().unwrap_err();
    assert_eq!(e.code, Code::TrainingSpec);
    assert!(
        e.message.contains("exactly one key broker"),
        "{}",
        e.message
    );
}

/// Review finding TR-2 (ENC-SF-2026-050): a worker trains only from the spec's initial
/// adapter (round 1) or from the adapter the coordinator recorded for the
/// previous round of the same run; never from one whoever runs the job
/// chooses (an older round's, another run's, its own).
#[test]
fn a_worker_trains_only_from_the_previous_recorded_adapter() {
    let s = spec();
    let coord = SigningKey::from_bytes(&[3; 32]);
    let init = s.initial_adapter_digest.clone();
    check_input_adapter(&s, "run", 1, "adapter-0", &init, None).unwrap();
    for (id, d) in [("adapter-0", h('9')), ("adapter-1", init.clone())] {
        assert!(check_input_adapter(&s, "run", 1, id, &d, None).is_err());
    }
    let rec = |round: u32, run: &str, key: &SigningKey| {
        AdapterRecord::new(&s, run, round, None, &h('a'), "update", &h('b'))
            .unwrap()
            .sign(key)
            .unwrap()
    };
    let r1 = rec(1, "run", &coord);
    check_input_adapter(&s, "run", 2, "adapter-1", &h('b'), Some(&r1)).unwrap();
    // No record; another digest; an older round's; another run's; a record
    // the coordinator did not sign; a round outside the spec.
    assert!(check_input_adapter(&s, "run", 2, "adapter-1", &h('b'), None).is_err());
    assert!(check_input_adapter(&s, "run", 2, "adapter-1", &h('c'), Some(&r1)).is_err());
    assert!(check_input_adapter(&s, "run", 3, "adapter-1", &h('b'), Some(&r1)).is_err());
    assert!(check_input_adapter(&s, "run-2", 2, "adapter-1", &h('b'), Some(&r1)).is_err());
    let forged = rec(1, "run", &SigningKey::from_bytes(&[4; 32]));
    assert!(check_input_adapter(&s, "run", 2, "adapter-1", &h('b'), Some(&forged)).is_err());
    assert!(check_input_adapter(&s, "run", 99, "adapter-98", &h('b'), Some(&r1)).is_err());
}

/// `spec` with a per-asset broker binding: every key its workers acquire
/// bound to its owner's broker, where the owner runs one (`brokers`: broker
/// ID -> (grant key, owner)), else to the model owner's (`modelco`).
fn bound(mut s: TrainingSpec, brokers: &[(&str, char, &str)]) -> TrainingSpec {
    for (id, key, owner) in brokers {
        s.key_brokers.insert(id.to_string(), h(*key));
        s.broker_organizations
            .insert(id.to_string(), owner.to_string());
    }
    s.broker_organizations
        .insert("modelco".into(), "modelco".into());
    let run: BTreeMap<String, String> = s
        .broker_organizations
        .iter()
        .map(|(b, o)| (o.clone(), b.clone()))
        .collect();
    s.asset_brokers = s
        .key_ids()
        .unwrap()
        .into_iter()
        .map(|(k, owner)| {
            let b = run.get(&owner).cloned().unwrap_or("modelco".into());
            (k, b)
        })
        .collect();
    s
}

/// Hospital A's keys at its own broker; hospital B's and the model owner's
/// at ModelCo's.
fn two_broker_spec() -> TrainingSpec {
    bound(spec(), &[("hospital-a-broker", '6', "hospital-a")])
}

/// Specs without a per-asset broker binding keep their IDs and bytes: the
/// field is not serialized when empty (the rc.4 spec ID).
#[test]
fn spec_ids_unchanged_without_asset_brokers() {
    let s = spec();
    assert!(s.asset_brokers.is_empty() && s.broker_organizations.is_empty());
    let text = serde_json::to_string(&s).unwrap();
    assert!(!text.contains("asset_brokers"), "{text}");
    assert!(!text.contains("broker_organizations"), "{text}");
    // The contract fixture (written by rc.4, before the fields existed)
    // parses to its recorded ID.
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let rc4: TrainingSpec =
        serde_json::from_str(&std::fs::read_to_string(fixtures.join("spec.json")).unwrap())
            .unwrap();
    assert!(rc4.asset_brokers.is_empty());
    assert_eq!(
        rc4.id().unwrap(),
        "351196f745e54546a5e1be9bad52f88d6e36bda0f2c36526d573b2553fb03723",
        "a spec without asset_brokers keeps its rc.4 ID"
    );
    let back: TrainingSpec = serde_json::from_str(&text).unwrap();
    assert_eq!(back.id().unwrap(), s.id().unwrap());
    // The binding and the brokers' owners are part of the ID.
    let one = bound(spec(), &[]);
    one.validate().unwrap();
    let two = two_broker_spec();
    two.validate().unwrap();
    assert_ne!(one.id().unwrap(), s.id().unwrap());
    assert_ne!(one.id().unwrap(), two.id().unwrap());
    // Owners without a binding are refused: they mean nothing alone.
    let mut t = spec();
    t.broker_organizations
        .insert("modelco".into(), "modelco".into());
    assert!(t.validate().is_err());
}

/// The workers' key IDs are defined once, by the spec: a participant's job
/// acquires exactly `participant_keys`, all among `key_ids`, in the names
/// its brokers already hold.
#[test]
fn worker_key_ids_match_spec_key_ids() {
    let s = spec();
    let ids = s.key_ids().unwrap();
    let a = s.participant_keys("hospital-a").unwrap();
    assert_eq!(a.model, "base-model.hospital-a");
    assert_eq!(a.dataset, "dataset-patients-a");
    assert_eq!(a.adapters, "adapters.hospital-a");
    assert_eq!(a.contribution, "contribution-hospital-a");
    let mut want: BTreeMap<String, String> = [
        ("base-model", "modelco"),
        ("checkpoints", "modelco"),
        ("adapters", "modelco"),
    ]
    .iter()
    .map(|(k, o)| (k.to_string(), o.to_string()))
    .collect();
    for p in ["hospital-a", "hospital-b"] {
        let k = s.participant_keys(p).unwrap();
        for (key, owner) in [
            (&k.model, "modelco"),
            (&k.adapters, "modelco"),
            (&k.dataset, p),
            (&k.contribution, p),
        ] {
            assert_eq!(ids.get(key).map(String::as_str), Some(owner), "{key}");
            want.insert(key.clone(), owner.to_string());
        }
    }
    assert_eq!(ids, want);
    assert!(s.participant_keys("modelco").is_err());
}

/// Several brokers are allowed only with a binding of exactly the keys the
/// spec's workers acquire, the derived per-participant keys included.
#[test]
fn asset_brokers_must_cover_derived_contribution_keys() {
    two_broker_spec().validate().unwrap();
    for missing in two_broker_spec().key_ids().unwrap().keys() {
        let mut t = two_broker_spec();
        t.asset_brokers.remove(missing);
        let e = t.validate().unwrap_err();
        assert_eq!(e.code, Code::TrainingSpec);
        assert!(
            e.message.contains(missing.as_str()),
            "{missing}: {}",
            e.message
        );
    }
    // A key no worker acquires is refused too: the binding is exact.
    let mut t = two_broker_spec();
    t.asset_brokers
        .insert("contribution-hospital-c".into(), "modelco".into());
    let e = t.validate().unwrap_err();
    assert!(
        e.message.contains("contribution-hospital-c"),
        "{}",
        e.message
    );
}

/// Without any binding, the rc.4 rule stands; with one, every broker is
/// used, and each has a declared owner among the parties.
#[test]
fn asset_brokers_must_cover_every_key() {
    let mut t = two_broker_spec();
    t.asset_brokers.clear();
    t.broker_organizations.clear();
    let e = t.validate().unwrap_err();
    assert!(
        e.message.contains("exactly one key broker"),
        "{}",
        e.message
    );
    // A broker nothing is bound to is not trusted for anything: refused.
    let mut t = two_broker_spec();
    t.key_brokers.insert("idle-broker".into(), h('7'));
    t.broker_organizations
        .insert("idle-broker".into(), "hospital-b".into());
    let e = t.validate().unwrap_err();
    assert!(e.message.contains("idle-broker"), "{}", e.message);
    // Every broker's owner is declared, and is a party of the spec.
    let mut t = two_broker_spec();
    t.broker_organizations.remove("hospital-a-broker");
    let e = t.validate().unwrap_err();
    assert!(e.message.contains("hospital-a-broker"), "{}", e.message);
    let mut t = two_broker_spec();
    t.broker_organizations
        .insert("hospital-a-broker".into(), "outsider".into());
    let e = t.validate().unwrap_err();
    assert!(e.message.contains("outsider"), "{}", e.message);
    // One broker (the model owner's) holding every key is fine.
    bound(spec(), &[]).validate().unwrap();
}

/// A participant's keys go to its own broker when it runs one (else to the
/// model owner's), never to another participant's; the model owner's keys
/// go to the model owner's broker.
#[test]
fn contribution_key_bound_to_another_parties_broker_refused() {
    let three = || {
        bound(
            spec(),
            &[
                ("hospital-a-broker", '6', "hospital-a"),
                ("hospital-b-broker", '8', "hospital-b"),
            ],
        )
    };
    three().validate().unwrap();
    let refused = |key: &str, broker: &str| {
        let mut t = three();
        t.asset_brokers.insert(key.into(), broker.into());
        let e = t.validate().unwrap_err();
        assert_eq!(e.code, Code::TrainingSpec);
        assert!(e.message.contains(key), "{key}: {}", e.message);
    };
    // Hospital B's contribution key at hospital A's broker: the rc.4 grant
    // confusion.
    refused("contribution-hospital-b", "hospital-a-broker");
    refused("dataset-patients-b", "hospital-a-broker");
    // At the model owner's, although hospital B runs its own broker.
    refused("contribution-hospital-b", "modelco");
    // The model owner's keys at a participant's broker.
    refused("base-model.hospital-a", "hospital-a-broker");
    refused("adapters.hospital-a", "hospital-a-broker");
    refused("checkpoints", "hospital-b-broker");
}

/// A key bound to two brokers is refused where it could arise: a spec's
/// JSON naming the key twice (a map keeps one silently otherwise), and
/// two brokers sharing a grant-signing key (their grants could not be told
/// apart).
#[test]
fn one_key_two_brokers_refused() {
    let s = two_broker_spec();
    let text = serde_json::to_string(&s).unwrap();
    let dup = text.replace(
        "\"contribution-hospital-b\":\"modelco\"",
        "\"contribution-hospital-b\":\"modelco\",\"contribution-hospital-a\":\"modelco\"",
    );
    assert_ne!(dup, text);
    let e = serde_json::from_str::<TrainingSpec>(&dup).unwrap_err();
    assert!(e.to_string().contains("contribution-hospital-a"), "{e}");
    // The same for the brokers' keys.
    let dup = text.replace(
        "\"hospital-a-broker\":\"6666",
        "\"modelco\":\"7777777777777777777777777777777777777777777777777777777777777777\",\"hospital-a-broker\":\"6666",
    );
    assert_ne!(dup, text);
    assert!(serde_json::from_str::<TrainingSpec>(&dup).is_err());
    let mut t = two_broker_spec();
    t.key_brokers.insert("hospital-a-broker".into(), h('5'));
    let e = t.validate().unwrap_err();
    assert!(e.message.contains("grant-signing key"), "{}", e.message);
}

/// Every broker a binding names needs its grant-signing key in the spec:
/// otherwise nothing pins who may sign its grants.
#[test]
fn unpinned_broker_in_asset_brokers_refused() {
    let mut t = two_broker_spec();
    t.asset_brokers
        .insert("contribution-hospital-b".into(), "hospital-b-broker".into());
    let e = t.validate().unwrap_err();
    assert_eq!(e.code, Code::TrainingSpec);
    assert!(e.message.contains("hospital-b-broker"), "{}", e.message);
    assert!(e.message.contains("grant-signing key"), "{}", e.message);
}
