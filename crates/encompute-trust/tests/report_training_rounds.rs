//! The trust report checks what a later round's training worker trained
//! from (review finding TR-2): after round 1, a worker's evidence must name
//! the adapter the coordinator signed for the previous round of its run, with
//! that adapter's digest. Evidence that is validly signed and attested, but
//! trained from any other adapter, fails the Training row.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use encompute_attestation::mock::MockHardware;
use encompute_attestation::{AttestationChallenge, AttestationRecord, Attester, WorkloadSession};
use encompute_ir::confidentiality::PartyId;
use encompute_ir::parse;
use encompute_secagg::identity_of;
use encompute_training::{
    AdapterRecord, DatasetCommitment, ModelCommitment, SignedWorkerEvidence, TrainingConfig,
    TrainingSpec, WorkerEvidence, WORKER_EVIDENCE_VERSION,
};
use encompute_trust::{program_id, ReportOptions, Status, TrustGraph, TrustReport};
use encompute_verification::{hex, EvaluatorSigner};

const PROGRAM: &str = "encompute 0.1
program training precision 0.001
%0 = input \"x\" [0.0, 120.0] : secret u8
%1 = const [18.0] : public u8
%2 = add %0, %1 : secret u8
output \"y\" = %2
";

const REFERENCE: &str =
    r#"{"factory":"encompute.torch.models:tiny_classifier","kwargs":{"dim":32,"vocab":64}}"#;

fn h(c: char) -> String {
    c.to_string().repeat(64)
}

fn coordinator() -> SigningKey {
    SigningKey::from_bytes(&[3; 32])
}

fn worker_key() -> SigningKey {
    SigningKey::from_bytes(&[5; 32])
}

fn spec() -> TrainingSpec {
    TrainingSpec {
        version: 2,
        project: "medical-lora".into(),
        purpose: "disease-training".into(),
        plan_id: h('a'),
        program_id: program_id(&parse(PROGRAM).unwrap().to_string()),
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
        datasets: ["a", "b"]
            .iter()
            .enumerate()
            .map(|(i, x)| DatasetCommitment {
                asset_id: format!("patients-{x}"),
                owner: format!("hospital-{x}"),
                gradient_asset: format!("gradient-patients-{x}"),
                digest: h(char::from(b'1' + i as u8)),
                privacy_units: None,
                grouping_digest: None,
                preprocessing: None,
            })
            .collect(),
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
        coordinator_key: hex(&coordinator().verifying_key().to_bytes()),
        initial_adapter_digest: h('0'),
    }
}

/// hospital-a's attested round-2 worker, which says it trained from
/// `adapter-1` with digest `input_digest`.
fn round_two(s: &TrainingSpec, input_digest: &str) -> (AttestationRecord, SignedWorkerEvidence) {
    let key = worker_key();
    let identity = EvaluatorSigner::from_seed(&key.to_bytes()).identity();
    let session =
        WorkloadSession::new(&identity).with_privacy_policy(s.privacy_policy_id.as_deref());
    let challenge = AttestationChallenge::new("broker", 1_000, 60).unwrap();
    let d = &s.datasets[0];
    let binding = session.binding(
        &challenge,
        &s.participant_execution_id(&d.owner).unwrap(),
        s.policy_id.as_deref(),
        &s.code_digest,
    );
    let image = format!("sha256:{}", h('7'));
    let record = AttestationRecord::new(
        MockHardware::from_seed(&[9; 32])
            .attester(&image)
            .attest(&challenge, &binding)
            .unwrap(),
    );
    let e = WorkerEvidence {
        version: WORKER_EVIDENCE_VERSION,
        project: s.project.clone(),
        training_spec_id: s.id().unwrap(),
        run_id: s.run_id("n").unwrap(),
        plan_id: s.plan_id.clone(),
        policy_id: s.policy_id.clone(),
        privacy_policy_id: s.privacy_policy_id.clone(),
        participant: d.owner.clone(),
        round: 2,
        model_asset: s.base_model.asset_id.clone(),
        model_package_id: None,
        weights_digest: s.base_model.weights_digest.clone(),
        dataset_asset: d.asset_id.clone(),
        dataset_digest: d.digest.clone(),
        layout_digest: s.layout_digest.clone(),
        input_adapter: "adapter-1".into(),
        input_adapter_digest: input_digest.into(),
        config_digest: s.config_digest().unwrap(),
        seed: 7,
        image_digest: image,
        attestation_record_id: record.id().unwrap(),
        session_id: record.session_id().unwrap(),
        output_asset: format!("contribution-{}-r2", d.owner),
        output_commitment: h('a'),
        step_commitment: h('b'),
        gradient_path: "vmap".into(),
        libraries: BTreeMap::new(),
    };
    let signed = e.sign(&key).unwrap();
    // The evidence itself is sound: signed by the attested key and bound
    // to the spec. Only the report can tell whether its input adapter is
    // the one the coordinator recorded.
    signed.verify(s, &record).unwrap();
    (record, signed)
}

/// A bundle holding the spec, hospital-a's round-2 worker (trained from
/// `input_digest`) and, if given, an `adapter-1` record signed by `signer`
/// with digest `recorded_digest` for run `run`.
fn bundle(input_digest: &str, adapter: Option<(&SigningKey, &str, &str)>) -> TrustGraph {
    let s = spec();
    let mut g = TrustGraph::new();
    g.add_program(PROGRAM).unwrap();
    g.add_training_spec(s.clone()).unwrap();
    let (record, worker) = round_two(&s, input_digest);
    g.add_attestation(record).unwrap();
    g.add_worker_evidence(worker).unwrap();
    if let Some((signer, run, digest)) = adapter {
        let r = AdapterRecord::new(&s, run, 1, None, &h('6'), "update", digest)
            .unwrap()
            .sign(signer)
            .unwrap();
        g.add_adapter(r).unwrap();
    }
    g
}

fn training(g: &TrustGraph) -> (Status, Vec<String>, TrustReport) {
    let r = g.report(&ReportOptions::default()).unwrap();
    let x = r.rows.iter().find(|x| x.name == "Training").unwrap();
    (x.status, x.details.clone(), r)
}

/// The Training row's findings about the worker (not the spec or adapter).
fn worker_findings(details: &[String]) -> Vec<&String> {
    details
        .iter()
        .filter(|d| d.starts_with("worker:"))
        .collect()
}

#[test]
fn a_later_round_worker_trained_from_another_adapter_fails_the_training_row() {
    let run = spec().run_id("n").unwrap();
    // The coordinator's own record of round 1, with the digest the worker
    // trained from: the input adapter is accepted.
    let g = bundle(&h('b'), Some((&coordinator(), &run, &h('b'))));
    let (_, details, r) = training(&g);
    assert!(worker_findings(&details).is_empty(), "{r}");

    // Trained from something else than the recorded round-1 adapter: another
    // digest, a record the coordinator did not sign, another run's record,
    // or no record at all.
    let forger = SigningKey::from_bytes(&[4; 32]);
    let other_run = spec().run_id("other").unwrap();
    const MISMATCH: &str = "INPUT ADAPTER MISMATCH";
    for (what, g, why) in [
        (
            "another digest",
            bundle(&h('c'), Some((&coordinator(), &run, &h('b')))),
            MISMATCH,
        ),
        (
            "not the coordinator's record",
            bundle(&h('b'), Some((&forger, &run, &h('b')))),
            "signed by an untrusted key",
        ),
        (
            "another run's record",
            bundle(&h('b'), Some((&coordinator(), &other_run, &h('b')))),
            MISMATCH,
        ),
        ("no record", bundle(&h('b'), None), MISMATCH),
    ] {
        let (status, details, r) = training(&g);
        assert_eq!(status, Status::Failed, "{what}: {r}");
        let found = worker_findings(&details);
        assert!(found.len() == 1 && found[0].contains(why), "{what}: {r}");
        assert!(!r.satisfied, "{what}: {r}");
    }
}
