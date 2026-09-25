//! Attested evaluators (ADR-011): keys released to the attested session,
//! receipts that bind it, and verification of the chain
//! attestation → evaluator key → receipt.

use std::sync::Arc;

use encompute_evaluator::engine::Local;
use encompute_evaluator::server::{Evaluator, Limits};
use encompute_ir::{parse, Code, Program};
use encompute_runtime::attestation::mock::{MockHardware, MockProvider};
use encompute_runtime::attestation::{
    AttestationRecord, Attester, TeeKind, Verifier, WorkloadSession,
};
use encompute_runtime::attested::{attestation_policy, verify_receipt_attestation};
use encompute_runtime::keybroker::{BrokerMode, KeyBroker};
use encompute_runtime::verification::EvaluatorSigner;
use encompute_runtime::{sample_inputs, BackendKind, Backends, Mode, Model, Remote};

const IMAGE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";

fn program() -> Program {
    parse(
        r#"encompute 0.1
program step precision 0.01 purpose "disease-training"
party "hospital-a" "Hospital A"
party "modelco" "ModelCo"
party "coordinator" "Coordinator"
asset "patients" dataset owners ["hospital-a"] readers ["hospital-a"] purposes ["disease-training"] release never derive [gradient aggregate_only to ["coordinator"]]
asset "weights" model owners ["modelco"] readers ["modelco"] purposes ["disease-training"] release never derive [gradient aggregate_only to ["coordinator"]]
%0 = input "x" [-1.0, 1.0] asset "patients" : secret vector<4>
%1 = input "w" [-1.0, 1.0] asset "weights" : secret vector<4>
%2 = mul %0, %1 : secret vector<4>
derive %2 gradient aggregate_only
output "gradient" = %2
"#,
    )
    .unwrap()
}

fn verifier(hw: &MockHardware) -> Verifier {
    Verifier::new().with(MockProvider::new(&hw.public_key()).unwrap())
}

#[test]
fn receipts_bind_the_attested_session() {
    let m = Model::compile(program()).unwrap();
    let hw = MockHardware::from_seed(&[3; 32]);
    let mut policy = attestation_policy(&m, BackendKind::Mock);
    policy.allowed_tee = vec![TeeKind::Mock];
    policy.allowed_images = vec![IMAGE.into()];
    policy.allow_development = true;
    assert_eq!(policy.policy_id, m.ids().policy_id);

    // Hospital's broker releases the patient-data key to the workload.
    let mut broker = KeyBroker::new("hospital", BrokerMode::Development, verifier(&hw)).unwrap();
    broker.add_secret("patients", None, policy.clone()).unwrap();
    let signer = EvaluatorSigner::generate().unwrap();
    let session = WorkloadSession::new(&signer.identity());
    let c = broker.challenge().unwrap();
    let binding = session.binding(
        &c,
        &policy.execution_spec_id,
        policy.policy_id.as_deref(),
        &m.artifact_digest(),
    );
    let evidence = hw.attester(IMAGE).attest(&c, &binding).unwrap();
    let info = broker.verify_attestation(&evidence).unwrap();
    let grant = broker.release_key(&info.session, "patients").unwrap();
    assert_eq!(session.open(&grant).unwrap().len(), 32);
    let record = AttestationRecord::new(evidence);

    // A record for another evaluator key is refused at startup.
    let stranger = EvaluatorSigner::generate().unwrap();
    let e = Evaluator::with_engine(
        Arc::new(Local::new(Backends::MOCK)),
        Limits::default(),
        0,
        stranger,
    )
    .with_attestation(record.clone())
    .err()
    .unwrap();
    assert_eq!(e.code, Code::Attestation);

    let serve = |ev: Evaluator| {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr().to_ip().unwrap());
        std::thread::spawn(move || ev.serve(server));
        Remote::new(&url)
    };
    let ev = Evaluator::with_engine(
        Arc::new(Local::new(Backends::MOCK)),
        Limits::default(),
        0,
        signer,
    )
    .with_attestation(record.clone())
    .unwrap();
    let remote = serve(ev);
    let trusted = remote.evaluator_identity().unwrap();
    let client = m.new_client(Mode::Mock).unwrap();
    let run = remote
        .run(
            &client,
            m.program(),
            None,
            &sample_inputs(m.program(), 3, 1),
            &trusted,
        )
        .unwrap();
    let a = run.receipt.receipt.attestation.clone().unwrap();
    assert_eq!(a.attestation_id, record.id().unwrap());
    assert_eq!(a.workload_session_id, session.session_id());

    // The chain verifies...
    let w = verify_receipt_attestation(&run.receipt, &record, &verifier(&hw), &policy).unwrap();
    assert_eq!(w.image_digest.as_deref(), Some(IMAGE));
    // ...but not with another record, another policy, or a forged root.
    let c2 = broker.challenge().unwrap();
    let other = AttestationRecord::new(
        hw.attester(IMAGE)
            .attest(
                &c2,
                &session.binding(
                    &c2,
                    &policy.execution_spec_id,
                    policy.policy_id.as_deref(),
                    &m.artifact_digest(),
                ),
            )
            .unwrap(),
    );
    assert_eq!(
        verify_receipt_attestation(&run.receipt, &other, &verifier(&hw), &policy)
            .unwrap_err()
            .code,
        Code::Attestation
    );
    let mut strict = policy.clone();
    strict.allowed_images = vec!["sha256:other".into()];
    assert_eq!(
        verify_receipt_attestation(&run.receipt, &record, &verifier(&hw), &strict)
            .unwrap_err()
            .code,
        Code::WorkloadPolicy
    );
    let rogue = MockHardware::from_seed(&[4; 32]);
    assert_eq!(
        verify_receipt_attestation(&run.receipt, &record, &verifier(&rogue), &policy)
            .unwrap_err()
            .code,
        Code::Attestation
    );

    // An unattested evaluator's receipts name no attestation.
    let plain = serve(Evaluator::new(Backends::MOCK, Limits::default()));
    let t = plain.evaluator_identity().unwrap();
    let run = plain
        .run(
            &client,
            m.program(),
            None,
            &sample_inputs(m.program(), 3, 1),
            &t,
        )
        .unwrap();
    assert!(run.receipt.receipt.attestation.is_none());
    assert_eq!(
        verify_receipt_attestation(&run.receipt, &record, &verifier(&hw), &policy)
            .unwrap_err()
            .code,
        Code::Attestation
    );
}

#[test]
fn artifact_digest_is_the_manifest_hash() {
    let m = Model::compile(program()).unwrap();
    let dir = std::env::temp_dir().join(format!("encompute-attested-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    m.save(&dir).unwrap();
    use sha2::Digest;
    let want: String = sha2::Sha256::digest(std::fs::read(dir.join("manifest.json")).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(m.artifact_digest(), want);
    assert_eq!(Model::load(&dir).unwrap().artifact_digest(), want);
    std::fs::remove_dir_all(&dir).unwrap();
}
