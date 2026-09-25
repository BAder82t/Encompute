//! Execution receipts end to end (0.4 V1): CKKS and exact programs, local
//! and remote; every tampering fails closed; identities are deterministic.

mod common;

use common::logistic;
use encompute_evaluator::server::{Evaluator, Limits};
use encompute_ir::{Builder, CmpOp, Code, Elem, Inputs, Program, Range};
use encompute_runtime::verification::{
    output_commitment, request_commitment, verify_receipt, EvaluatorSigner, ExpectedExecution,
    SignedExecutionReceipt,
};
use encompute_runtime::{
    sample_inputs, verification_spec, BackendKind, Backends, Mode, Model, Remote,
};

fn adult() -> Program {
    let mut b = Builder::new("adult", 1e-3).unwrap();
    let age = b
        .input_exact("age", Elem::U8, Some(Range::new(0.0, 120.0)))
        .unwrap();
    let k = b.constant_exact(Elem::U8, 18.0).unwrap();
    let ok = b.cmp(CmpOp::Ge, age, k).unwrap();
    b.output("adult", ok).unwrap();
    b.finish().unwrap()
}

fn serve() -> (Remote, encompute_runtime::verification::EvaluatorIdentity) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    std::thread::spawn(move || Evaluator::new(Backends::MOCK, Limits::default()).serve(server));
    let remote = Remote::new(&url);
    let id = remote.evaluator_identity().unwrap();
    (remote, id)
}

fn inputs_for(m: &Model) -> Inputs {
    sample_inputs(m.program(), 3, 1)
}

/// Same program, compiler and parameters → the same identities.
#[test]
fn identities_are_deterministic() {
    for p in [logistic(8, 1), adult()] {
        let (a, b) = (
            Model::compile(p.clone()).unwrap(),
            Model::compile(p).unwrap(),
        );
        for kind in [BackendKind::Mock, BackendKind::OpenFhe, BackendKind::TfheRs] {
            let (sa, sb) = (verification_spec(&a, kind), verification_spec(&b, kind));
            assert_eq!(sa, sb);
            assert_eq!(sa.id(), sb.id());
        }
        assert_eq!(
            a.artifact_files()["verification.json"],
            b.artifact_files()["verification.json"]
        );
        // verification.json states the target spec and its ID.
        let v: serde_json::Value =
            serde_json::from_str(&a.artifact_files()["verification.json"]).unwrap();
        assert_eq!(v["spec_id"], a.target_spec().id().hex());
        assert_eq!(v["plan_kind"], a.compiled().plan_format().0);
        assert_eq!(v["scheme"], a.compiled().scheme());
    }
    // The spec separates schemes, backends and programs.
    let (c, e) = (
        Model::compile(logistic(8, 1)).unwrap(),
        Model::compile(adult()).unwrap(),
    );
    assert_ne!(c.target_spec().id(), e.target_spec().id());
    assert_ne!(
        verification_spec(&e, BackendKind::Mock).id(),
        verification_spec(&e, BackendKind::TfheRs).id()
    );
}

/// CKKS and exact programs, same receipt abstraction, remote.
#[test]
fn remote_receipts_verify_for_both_schemes() {
    let (remote, trusted) = serve();
    for p in [logistic(8, 1), adult()] {
        let m = Model::compile(p).unwrap();
        let client = m.new_client(Mode::Mock).unwrap();
        let run = remote
            .run(&client, m.program(), None, &inputs_for(&m), &trusted)
            .unwrap();
        let r = &run.receipt.receipt;
        assert_eq!(r.scheme, m.compiled().scheme());
        assert_eq!(r.spec_id, client.spec().id().hex());
        assert_eq!(r.key_id, client.key_id());
        assert_eq!(r.request_commitment, request_commitment(&run.request));
        assert_eq!(r.output_commitment, output_commitment(&run.response));
        assert!(!run.verified.has_execution_proof());
        // The wire form carries no ciphertext or plaintext: only a few
        // hundred bytes of identifiers.
        assert!(run.receipt.to_bytes().unwrap().len() < 2048);
    }
}

#[test]
fn tampering_fails_closed() {
    let (remote, trusted) = serve();
    let m = Model::compile(adult()).unwrap();
    let client = m.new_client(Mode::Mock).unwrap();
    let a = remote
        .run(&client, m.program(), None, &inputs_for(&m), &trusted)
        .unwrap();
    let b = remote
        .run(
            &client,
            m.program(),
            None,
            &sample_inputs(m.program(), 0, 2),
            &trusted,
        )
        .unwrap();
    let check = |req: &[u8], resp: &[u8], receipt: &SignedExecutionReceipt| {
        client
            .decrypt_verified(req, resp, receipt, &trusted)
            .err()
            .map(|e| e.code)
    };
    assert_eq!(check(&a.request, &a.response, &a.receipt), None);
    // Receipt from execution A with output (or request) from execution B.
    assert_eq!(
        check(&a.request, &b.response, &a.receipt),
        Some(Code::Receipt)
    );
    assert_eq!(
        check(&b.request, &a.response, &a.receipt),
        Some(Code::Receipt)
    );
    // A modified response: the receipt no longer matches (and the envelope
    // checksum fails too).
    let mut resp = a.response.clone();
    let n = resp.len();
    resp[n - 40] ^= 1;
    assert_eq!(check(&a.request, &resp, &a.receipt), Some(Code::Receipt));
    // A receipt signed by another evaluator, however consistent.
    let other = EvaluatorSigner::generate().unwrap();
    let forged = encompute_runtime::verification::ExecutionReceipt::new(
        &client.spec(),
        client.transcript().map(|t| t.id().hex()).as_deref(),
        client.key_id(),
        &a.request,
        &a.response,
        &other.identity(),
    )
    .unwrap()
    .sign(&other)
    .unwrap();
    assert_eq!(check(&a.request, &a.response, &forged), Some(Code::Receipt));
    // Receipt fields changed after signing.
    for edit in [
        |r: &mut SignedExecutionReceipt| r.receipt.plan_id = "0".repeat(64),
        |r: &mut SignedExecutionReceipt| r.receipt.key_id = "0".repeat(64),
        |r: &mut SignedExecutionReceipt| r.receipt.backend = "openfhe".into(),
    ] {
        let mut r = a.receipt.clone();
        edit(&mut r);
        assert_eq!(check(&a.request, &a.response, &r), Some(Code::Receipt));
    }
    // A receipt for program A presented for program B.
    let p2 = Model::compile(logistic(8, 2)).unwrap();
    let c2 = p2.new_client(Mode::Mock).unwrap();
    let spec2 = c2.spec();
    let (rc, oc) = (
        request_commitment(&a.request),
        output_commitment(&a.response),
    );
    assert!(verify_receipt(
        &a.receipt,
        &ExpectedExecution {
            spec: &spec2,
            key_id: client.key_id(),
            request_commitment: &rc,
            output_commitment: &oc,
            transcript_hash: None,
            trusted_evaluator: &trusted,
        }
    )
    .is_err());
    // A client that pinned a different evaluator refuses the result.
    let (_, stranger) = serve();
    assert_eq!(
        remote
            .run(&client, m.program(), None, &inputs_for(&m), &stranger)
            .err()
            .unwrap()
            .code,
        Code::Receipt
    );
}

/// Local runs take the same path: execute, issue a receipt, verify it,
/// decrypt.
#[test]
fn local_runs_verify_receipts() {
    for p in [logistic(8, 1), adult()] {
        let m = Model::compile(p).unwrap();
        let x = inputs_for(&m);
        let want = m.run(Mode::Clear, &x).unwrap();
        let got = m.run(Mode::Mock, &x).unwrap();
        for (k, v) in want {
            assert!((got[&k][0] - v[0]).abs() < 1e-2, "{k}");
        }
    }
}

/// Exact receipts bind the transcript of the client's own plan; the
/// statement a proof must satisfy follows from receipt + transcript.
#[test]
fn receipts_bind_the_transcript_and_form_a_statement() {
    use encompute_runtime::verification::ExecutionStatement;
    let (remote, trusted) = serve();
    let m = Model::compile(adult()).unwrap();
    let client = m.new_client(Mode::Mock).unwrap();
    let run = remote
        .run(&client, m.program(), None, &inputs_for(&m), &trusted)
        .unwrap();
    let t = client.transcript().unwrap();
    assert_eq!(run.receipt.receipt.transcript_hash, Some(t.id().hex()));
    let st = ExecutionStatement::new(&run.verified, &t).unwrap();
    assert_eq!(st.spec_id, client.spec().id().hex());
    assert_eq!(st.request_commitment, request_commitment(&run.request));
    assert_eq!(st.output_commitment, output_commitment(&run.response));
    assert_eq!(st.instruction_count, t.entries.len() as u64);
    assert!(st.public_inputs.is_empty());
    // Another program's transcript does not fit this receipt.
    let other = Model::compile(adult_at(21.0))
        .unwrap()
        .new_client(Mode::Mock)
        .unwrap();
    let e = ExecutionStatement::new(&run.verified, &other.transcript().unwrap()).unwrap_err();
    assert_eq!(e.code, Code::Transcript);
    // verification.json stores the target transcript's hash.
    let v: serde_json::Value =
        serde_json::from_str(&m.artifact_files()["verification.json"]).unwrap();
    assert_eq!(
        v["transcript_hash"],
        m.transcript_for_target().unwrap().id().hex()
    );
    // CKKS programs have no transcript yet.
    let c = Model::compile(logistic(8, 1)).unwrap();
    assert!(c.transcript_for_target().is_none());
    let run = remote
        .run(
            &c.new_client(Mode::Mock).unwrap(),
            c.program(),
            None,
            &inputs_for(&c),
            &trusted,
        )
        .unwrap();
    assert_eq!(run.receipt.receipt.transcript_hash, None);
}

fn adult_at(threshold: f64) -> Program {
    let text = adult()
        .to_string()
        .replace("[18.0]", &format!("[{threshold:?}]"));
    encompute_ir::parse(&text).unwrap()
}
