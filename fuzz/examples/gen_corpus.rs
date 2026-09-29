//! Writes the seed corpus: a few valid samples per fuzz target, built with
//! the real encoders (so seeds track the formats). Deterministic keys; run
//! from `fuzz/`:
//!
//! ```text
//! cargo run --example gen_corpus
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use ed25519_dalek::SigningKey;
use encompute_evaluator::engine::Engine;
use encompute_evaluator::{issue_receipt, transcript_for, BackendKind, EvaluatorSession};
use encompute_fuzz::{join, mock_evaluator, PARTY_SEED, PROGRAM, SEAL_KEY, SERVICE_SEED};
use encompute_ir::confidentiality::{privacy_preset, PrivacyUnit};
use encompute_privacy::{Genesis, Ledger, PrivacyEvent};
use encompute_verification::proof::{ExecutionProof, ProofHeader, VerificationRelation};
use encompute_verification::service::{self, Scope, JOB_GRANT};
use encompute_verification::{EvaluatorSigner, JobGrant, ServiceSigner};

type R<T> = Result<T, Box<dyn std::error::Error>>;

fn write(target: &str, name: &str, bytes: &[u8]) -> R<()> {
    let dir = Path::new("corpus").join(target);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join(name), bytes)?;
    Ok(())
}

const EXACT: &str = "encompute 0.1\nprogram exact precision 0.001\n\
%0 = input \"age\" [0.0, 120.0] : secret u8\n\
%1 = const [18.0] : public u8\n\
%2 = ge %0, %1 : secret bool\n\
output \"adult\" = %2\n";

const EIR: &[(&str, &str)] = &[
    ("dot.eir", PROGRAM),
    ("exact.eir", EXACT),
    (
        "fedavg.eir",
        include_str!("../../examples/09_differential_privacy/fedavg.eir"),
    ),
    (
        "training.eir",
        include_str!("../../examples/06_confidentiality_policy/training.eir"),
    ),
    ("mixed.eir", include_str!("../../benches/exact/mixed.eir")),
    (
        "lookup.eir",
        include_str!("../../benches/exact/lookup_small.eir"),
    ),
];

fn main() -> R<()> {
    for (n, t) in EIR {
        write("eir_parse", n, t.as_bytes())?;
        let mut b = vec![0u8];
        b.extend_from_slice(t.as_bytes());
        write("evaluator_bodies", &format!("program-{n}"), &b)?;
        write(
            "control_api",
            &format!("plan-{n}.json"),
            &serde_json::to_vec(&serde_json::json!({"project": "prj_1", "program": t}))?,
        )?;
    }

    // Artifacts.
    for (n, t) in &EIR[..2] {
        let dir = tempfile::tempdir()?;
        encompute_runtime::Model::from_eir(t)?.save(dir.path())?;
        let names = [
            "manifest.json",
            "program.eir",
            "plan.json",
            "parameters.json",
            "security.json",
            "verification.json",
            "policy.json",
        ];
        let files: Vec<Vec<u8>> = names
            .iter()
            .map(|f| std::fs::read(dir.path().join(f)))
            .collect::<Result<_, _>>()?;
        let parts: Vec<&[u8]> = files.iter().map(Vec::as_slice).collect();
        write("artifact_load", n, &join(&parts))?;
    }

    // Envelopes, evaluator bodies, receipts, frames.
    let ev = mock_evaluator();
    write("envelope_decode", "keys", &ev.keys)?;
    write("envelope_decode", "inputs", &ev.inputs)?;
    // Without the checksum: the target appends a valid one.
    write(
        "envelope_decode",
        "inputs-body",
        &ev.inputs[..ev.inputs.len() - 32],
    )?;
    for (tag, name, body) in [
        (1u8, "keys", ev.keys.as_slice()),
        (2, "inputs", ev.inputs.as_slice()),
        (3, "key-id", ev.key_id.as_bytes()),
    ] {
        let mut b = vec![tag];
        b.extend_from_slice(body);
        write("evaluator_bodies", name, &b)?;
    }
    let (out, times) = ev.engine.execute(&ev.program_id, &ev.inputs)?;
    write("envelope_decode", "outputs", &out)?;
    let info = ev.engine.programs().remove(0);
    let signer = EvaluatorSigner::from_seed(&[1; 32]);
    let receipt = issue_receipt(
        &info.spec,
        info.transcript_hash.as_deref(),
        &ev.inputs,
        &out,
        None,
        None,
        &signer,
    )?;
    let receipt_bytes = receipt.to_bytes()?;
    write("receipt_parse", "receipt.json", &receipt_bytes)?;
    write("trust_evidence", "receipt.json", &receipt_bytes)?;
    write(
        "control_api",
        "complete.json",
        &serde_json::to_vec(&serde_json::json!({
            "receipt": serde_json::from_slice::<serde_json::Value>(&receipt_bytes)?,
            "request_commitment": "0".repeat(64),
            "output_commitment": "0".repeat(64),
            "key_id": ev.key_id,
        }))?,
    )?;
    let t = serde_json::to_vec(&times)?;
    let mut reply = (t.len() as u32).to_le_bytes().to_vec();
    reply.extend_from_slice(&t);
    reply.extend_from_slice(&out);
    let mut frames = vec![];
    for (tag, payload) in [
        (4u8, format!("{}\n", ev.program_id).into_bytes()),
        (0, reply),
        (1, b"ENC0301\nmalformed".to_vec()),
    ] {
        frames.push(tag);
        frames.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        frames.extend_from_slice(&payload);
    }
    write("pool_frame", "frames", &frames)?;

    // Transcripts and proofs.
    let s = EvaluatorSession::new(encompute_ir::parse(EXACT)?, BackendKind::Mock)?;
    if let Some(t) = transcript_for(s.compiled(), s.spec()) {
        write("transcript_parse", "exact.json", &t.canonical_bytes()?)?;
    }
    let proof = ExecutionProof {
        header: ProofHeader {
            version: 1,
            relation: VerificationRelation::FheEvaluationV1,
            spec_id: "a".repeat(64),
            transcript_hash: "b".repeat(64),
            request_commitment: "c".repeat(64),
            output_commitment: "d".repeat(64),
            verification_key_id: "e".repeat(64),
            protocol: "bgv-reexec-v1".into(),
            protocol_version: 1,
            proof_bytes: 4,
        },
        proof: vec![1, 2, 3, 4],
    };
    write("proof_parse", "proof", &proof.to_bytes()?)?;

    // Trust Graph records and bundles.
    let party = SigningKey::from_bytes(&PARTY_SEED);
    let mut g = encompute_trust::TrustGraph::new();
    g.add_program(PROGRAM)?;
    let text = encompute_ir::parse(PROGRAM)?.to_string();
    let auth = encompute_trust::Authorization {
        version: 1,
        party: "hospital-a".into(),
        asset: "patients".into(),
        program_id: encompute_trust::program_id(&text),
        policy_id: None,
        privacy_policy_id: None,
        purpose: Some("disease-training".into()),
        issued_at: 1_700_000_000,
        expires_at: Some(1_800_000_000),
    }
    .sign(&party)?;
    let revocation = encompute_trust::Revocation {
        version: 1,
        party: "hospital-a".into(),
        asset: "patients".into(),
        authorization: Some(auth.id()?),
        reason: "withdrawn".into(),
        issued_at: 1_750_000_000,
    }
    .sign(&party)?;
    write(
        "trust_evidence",
        "authorization.json",
        &serde_json::to_vec(&auth)?,
    )?;
    write(
        "trust_evidence",
        "revocation.json",
        &serde_json::to_vec(&revocation)?,
    )?;
    write("trust_bundle", "program.json", &g.to_bytes()?)?;
    let _ = g.add_authorization(auth);
    let _ = g.add_execution_receipt(receipt);
    write("trust_bundle", "evidence.json", &g.to_bytes()?)?;
    let _ = g.add_revocation(revocation);
    write("trust_bundle", "revoked.json", &g.to_bytes()?)?;

    // Policies.
    let mut policy = encompute_attestation::AttestationPolicy::new(&"a".repeat(64), None);
    policy.allowed_tee = vec![encompute_attestation::TeeKind::Mock];
    policy.allowed_images = vec!["sha256:0".into()];
    policy.allow_development = true;
    write(
        "policy_parse",
        "attestation.json",
        &serde_json::to_vec(&policy)?,
    )?;
    let (budget, mechanism) = privacy_preset("standard", PrivacyUnit::parse("patient")?)?;
    write("policy_parse", "budget.json", &serde_json::to_vec(&budget)?)?;
    write(
        "policy_parse",
        "mechanism.json",
        &serde_json::to_vec(&mechanism)?,
    )?;
    let program = encompute_ir::parse(include_str!(
        "../../examples/06_confidentiality_policy/training.eir"
    ))?;
    if let Some(c) = program.confidentiality() {
        for a in &c.assets {
            write(
                "policy_parse",
                &format!("asset-{}.json", a.id),
                &serde_json::to_vec(&a.policy)?,
            )?;
        }
    }

    // Service headers, messages, grants.
    let svc = ServiceSigner::from_seed("evaluator-1", &SERVICE_SEED)?;
    let bind: BTreeMap<String, String> = [("job".to_owned(), "job_1".to_owned())].into();
    let h = svc.sign_request("POST", "/v1/messages", "control-plane", &bind, b"{}")?;
    let values: Vec<String> = h.to_pairs().into_iter().map(|(_, v)| v).collect();
    let mut parts: Vec<&[u8]> = values.iter().map(|v| v.as_bytes()).collect();
    parts.push(b"{}");
    write("service_headers", "request", &join(&parts))?;
    let headers: BTreeMap<&str, String> = h.to_pairs().into_iter().collect();
    write(
        "control_api",
        "headers.json",
        &serde_json::to_vec(&headers)?,
    )?;
    let m = service::seal(
        &svc,
        "job.completed",
        "control-plane",
        Scope {
            job: Some("job_1".into()),
            ..Scope::default()
        },
        &serde_json::json!({"job": "job_1", "ms": 12}),
        300,
    )?;
    write("message_envelope", "message.json", &serde_json::to_vec(&m)?)?;
    write("control_api", "message.json", &serde_json::to_vec(&m)?)?;
    let control = ServiceSigner::from_seed("control-plane", &SERVICE_SEED)?;
    let mut grant = JobGrant {
        version: 1,
        job_id: "job_1".into(),
        organization: "modelco".into(),
        project: "prj_1".into(),
        plan_id: "pln_1".into(),
        spec_id: "s".repeat(64),
        program_id: ev.program_id.clone(),
        evaluator: "evaluator-1".into(),
        backend: "openfhe-exact".into(),
        profile: "BINFHE_STD128_GINX_BITS_V1".into(),
        issued_at: 1_700_000_000,
        expires_at: 1_700_003_600,
        issuer: "control-plane".into(),
        issuer_public_key: control.public_key_hex(),
        governance: None,
        signature: String::new(),
    };
    grant.signature = control.sign(JOB_GRANT, &grant.unsigned())?;
    write("job_grant", "header", grant.to_header().as_bytes())?;
    write("job_grant", "grant.json", &serde_json::to_vec(&grant)?)?;

    // Sealed training artifacts and tensors.
    let payload = b"adapter weights".to_vec();
    let header = encompute_training::CheckpointHeader {
        version: 1,
        project: "prj_1".into(),
        training_spec_id: "spec".into(),
        run_id: "run_1".into(),
        round: 3,
        adapter_id: "adp_1".into(),
        payload_digest: encompute_training::sha256_hex(&payload),
        policy_id: None,
        privacy_policy_id: None,
        ledgers: BTreeMap::new(),
        lineage_root: None,
    };
    write(
        "sealed_artifact",
        "checkpoint",
        &encompute_training::seal_checkpoint(&SEAL_KEY, &header, &payload)?,
    )?;
    write(
        "sealed_artifact",
        "asset",
        &encompute_training::seal_asset(&SEAL_KEY, "model", "prj_1", "asset_1", b"weights")?,
    )?;
    let entries = serde_json::json!([
        {"name": "a.lora_A", "dtype": "float32", "shape": [2, 2], "offset": 0, "length": 16},
        {"name": "a.lora_B", "dtype": "int64", "shape": [1], "offset": 16, "length": 8},
    ]);
    let h = serde_json::to_vec(&entries)?;
    let mut t = b"ENCTENS1".to_vec();
    t.extend_from_slice(&(h.len() as u32).to_le_bytes());
    t.extend_from_slice(&h);
    t.extend_from_slice(&[0u8; 24]);
    write("tensor_manifest", "tensors", &t)?;
    let layout = encompute_training::AdapterLayout {
        version: encompute_training::LAYOUT_VERSION,
        entries: vec![encompute_training::LayoutEntry {
            module: "q_proj".into(),
            parameter: "lora_A".into(),
            shape: vec![2, 4],
            offset: 0,
            length: 8,
            dtype: "float32".into(),
        }],
    };
    write(
        "tensor_manifest",
        "layout.json",
        &serde_json::to_vec(&layout)?,
    )?;

    // Privacy ledgers.
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("a.ledger");
    let genesis = Genesis {
        version: 1,
        asset_id: "patients".into(),
        budget: budget.clone(),
        privacy_policy_id: "f".repeat(64),
    };
    let mut ledger = Ledger::open(&path, &genesis)?;
    for (i, q) in [None, Some(0.01)].into_iter().enumerate() {
        let mut m = mechanism.clone();
        m.sampling_rate = q;
        let id = format!("evt_{i}");
        ledger.append(PrivacyEvent::Reserve {
            event_id: id.clone(),
            policy_id: None,
            execution_spec_id: None,
            round_id: Some(format!("round_{i}")),
            output: "global_gradient".into(),
            mechanism: m,
            sensitivity: 4096,
            sigma2: 1 << 30,
            vector_len: 16,
            rng: "csprng".into(),
        })?;
        ledger.append(PrivacyEvent::Commit {
            event_id: id,
            output_commitment: "0".repeat(64),
        })?;
    }
    drop(ledger);
    write("privacy_ledger", "ledger", &std::fs::read(&path)?)?;
    write(
        "control_api",
        "privacy-event.json",
        &serde_json::to_vec(&PrivacyEvent::Commit {
            event_id: "evt_1".into(),
            output_commitment: "0".repeat(64),
        })?,
    )?;

    // Control-plane bodies and tokens.
    for (n, v) in [
        (
            "org",
            serde_json::json!({"id": "modelco", "display_name": "ModelCo",
            "admin": {"issuer": "https://idp", "subject": "alice", "email": "a@x"}}),
        ),
        (
            "user",
            serde_json::json!({"issuer": "https://idp", "subject": "bob", "roles": ["auditor", "data_owner"]}),
        ),
        (
            "service-account",
            serde_json::json!({"id": "evaluator-1", "kind": "evaluator",
            "public_key": svc.public_key_hex(), "roles": ["operator"]}),
        ),
        (
            "project",
            serde_json::json!({"organization": "modelco", "name": "p"}),
        ),
        (
            "asset",
            serde_json::json!({"organization": "modelco", "kind": "dataset", "name": "d",
            "digest": "0".repeat(64), "size_bytes": 10, "policy": {"release": "never"},
            "parents": [], "privacy_budget": serde_json::to_value(&budget)?,
            "key_ref": {"broker": "kb", "provider": "aws-kms", "key_ref": "k", "key_version": 1}}),
        ),
        (
            "job",
            serde_json::json!({"project": "prj_1", "plan": "pln_1", "purpose": "p",
            "source_assets": ["ast_1"], "requested_output": "d"}),
        ),
        (
            "evaluator",
            serde_json::json!({"id": "evaluator-1", "url": "http://e:8080",
            "receipt_key": "0".repeat(64), "backends": ["openfhe-exact"],
            "profiles": ["CKKS"], "openfhe_version": "1.5.1", "capacity": 2,
            "logical_cores": 8, "memory_bytes": 1_i64 << 34}),
        ),
    ] {
        write(
            "control_api",
            &format!("{n}.json"),
            &serde_json::to_vec(&v)?,
        )?;
    }
    write(
        "control_api",
        "token",
        encompute_control::authn::dev_token("fuzz-secret", "alice", 3600)?.as_bytes(),
    )?;

    // Attestation evidence (mock provider).
    let hw = encompute_attestation::mock::MockHardware::from_seed(&[3; 32]);
    let binding = encompute_attestation::WorkloadBinding {
        version: encompute_attestation::BINDING_VERSION,
        execution_spec_id: "a".repeat(64),
        policy_id: None,
        artifact_digest: "b".repeat(64),
        evaluator_public_key: signer.identity().public_key_hex(),
        session_public_key: "c".repeat(64),
        challenge_nonce: "d".repeat(64),
        privacy_policy_id: None,
    };
    let challenge = encompute_attestation::AttestationChallenge::new("broker", 1_700_000_000, 600)?;
    use encompute_attestation::Attester;
    let evidence = hw
        .attester("sha256:0")
        .issued_at(1_700_000_000)
        .attest(&challenge, &binding)?;
    write(
        "attestation_evidence",
        "evidence.json",
        &evidence.to_bytes()?,
    )?;
    let record = encompute_attestation::AttestationRecord::new(evidence);
    write("attestation_evidence", "record.json", &record.to_bytes()?)?;
    write("trust_evidence", "attestation.json", &record.to_bytes()?)?;
    println!("corpus written");
    Ok(())
}
