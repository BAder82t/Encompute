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

fn spec() -> TrainingSpec {
    TrainingSpec {
        version: 1,
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
            architecture: "TinyTransformer(d=32)".into(),
            weights_digest: h('f'),
        },
        datasets: vec![
            DatasetCommitment {
                asset_id: "patients-a".into(),
                owner: "hospital-a".into(),
                gradient_asset: "gradient-patients-a".into(),
                digest: h('1'),
            },
            DatasetCommitment {
                asset_id: "patients-b".into(),
                owner: "hospital-b".into(),
                gradient_asset: "gradient-patients-b".into(),
                digest: h('2'),
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

#[test]
fn attestation_policy_binds_the_spec_and_code() {
    let s = spec();
    let p = s.attestation_policy("sha256:worker", true).unwrap();
    assert_eq!(p.execution_spec_id, s.id().unwrap());
    assert_eq!(p.artifact_digest.as_deref(), Some(h('3').as_str()));
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
        round_id: format!("{round:064x}"),
        output: "update".into(),
        policy_id: Some(h('c')),
        privacy_policy_id: h('d'),
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
        charged: ["gradient-patients-a", "gradient-patients-b"]
            .iter()
            .map(|a| Charged {
                asset_id: (*a).into(),
                budget: PrivacyBudget {
                    unit: PrivacyUnit::Patient,
                    epsilon: 3.0,
                    delta: 1e-6,
                },
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
