//! Receipts bind every identity and fail closed on any change.

use encompute_ir::Code;
use encompute_verification::canonical::canonical_json;
use encompute_verification::{
    output_commitment, request_commitment, verify_receipt, EvaluatorSigner, ExecutionReceipt,
    ExecutionSpec, ExpectedExecution, NoProofBackend, SignedExecutionReceipt, VerificationBackend,
};

fn spec() -> ExecutionSpec {
    ExecutionSpec {
        version: 1,
        program_id: "a".repeat(64),
        plan_id: "b".repeat(64),
        parameter_set_id: "c".repeat(64),
        plan_kind: "exact".into(),
        plan_version: 1,
        semantics: "exact".into(),
        scheme: "TFHE".into(),
        backend: "tfhe-rs".into(),
        backend_version: "1.8.1".into(),
        policy_id: None,
    }
}

const KEY: &str = "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f";
const TRANSCRIPT: &str = "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c";
const REQ: &[u8] = b"ENCM request envelope bytes";
const OUT: &[u8] = b"ENCM output envelope bytes";

fn signed(signer: &EvaluatorSigner) -> SignedExecutionReceipt {
    ExecutionReceipt::new(&spec(), Some(TRANSCRIPT), KEY, REQ, OUT, &signer.identity())
        .unwrap()
        .sign(signer)
        .unwrap()
}

fn check(r: &SignedExecutionReceipt, signer: &EvaluatorSigner) -> encompute_ir::Result<()> {
    let (s, id) = (spec(), signer.identity());
    let (rc, oc) = (request_commitment(REQ), output_commitment(OUT));
    verify_receipt(
        r,
        &ExpectedExecution {
            spec: &s,
            key_id: KEY,
            request_commitment: &rc,
            output_commitment: &oc,
            transcript_hash: Some(TRANSCRIPT),
            proof_expected: false,
            trusted_evaluator: &id,
        },
    )
    .map(|_| ())
}

#[test]
fn canonical_json_is_sorted_compact_and_integer_only() {
    let v = serde_json::json!({"b": [1, {"z": true, "a": null}], "a": "é\n", "c": -3});
    assert_eq!(
        String::from_utf8(canonical_json(&v).unwrap()).unwrap(),
        r#"{"a":"é\n","b":[1,{"a":null,"z":true}],"c":-3}"#
    );
    assert_eq!(
        canonical_json(&serde_json::json!({"x": 0.5}))
            .unwrap_err()
            .code,
        Code::Receipt
    );
}

#[test]
fn spec_id_is_stable_and_domain_separated() {
    let s = spec();
    assert_eq!(s.id(), spec().id());
    // Pinned: a change here breaks every stored receipt and artifact.
    assert_eq!(s.id().to_string().len(), "encspec1:".len() + 64);
    let bytes = s.canonical_bytes().unwrap();
    assert!(bytes.starts_with(b"{\"backend\":\"tfhe-rs\""));
    let mut other = spec();
    other.plan_version = 2;
    assert_ne!(other.id(), s.id());
    // The same bytes under different domains give different digests.
    assert_ne!(request_commitment(REQ), output_commitment(REQ));
}

#[test]
fn valid_receipt_verifies_and_is_not_a_proof() {
    let signer = EvaluatorSigner::generate().unwrap();
    let r = signed(&signer);
    check(&r, &signer).unwrap();
    let (s, id) = (spec(), signer.identity());
    let (rc, oc) = (request_commitment(REQ), output_commitment(OUT));
    let v = verify_receipt(
        &r,
        &ExpectedExecution {
            spec: &s,
            key_id: KEY,
            request_commitment: &rc,
            output_commitment: &oc,
            transcript_hash: Some(TRANSCRIPT),
            proof_expected: false,
            trusted_evaluator: &id,
        },
    )
    .unwrap();
    assert!(!v.has_execution_proof());
    // Round trip through the wire form.
    let bytes = r.to_bytes().unwrap();
    assert_eq!(SignedExecutionReceipt::from_bytes(&bytes).unwrap(), r);
    assert!(!String::from_utf8(bytes).unwrap().contains(' '));
    // Two executions of the same thing get different execution IDs.
    assert_ne!(signed(&signer).receipt.execution_id, r.receipt.execution_id);
}

#[test]
fn every_tampering_fails_closed() {
    let signer = EvaluatorSigner::generate().unwrap();
    let good = signed(&signer);
    type Edit = fn(&mut SignedExecutionReceipt);
    let edits: Vec<(&str, Edit)> = vec![
        ("spec ID", |r| r.receipt.spec_id = "0".repeat(64)),
        ("program ID", |r| r.receipt.program_id = "d".repeat(64)),
        ("plan ID", |r| r.receipt.plan_id = "d".repeat(64)),
        ("parameter-set ID", |r| {
            r.receipt.parameter_set_id = "d".repeat(64)
        }),
        ("key ID", |r| r.receipt.key_id = "2f".repeat(32)),
        ("request commitment", |r| {
            r.receipt.request_commitment = "0".repeat(64)
        }),
        ("output commitment", |r| {
            r.receipt.output_commitment = "0".repeat(64)
        }),
        ("scheme", |r| r.receipt.scheme = "CKKS".into()),
        ("backend", |r| r.receipt.backend = "mock".into()),
        ("backend version", |r| {
            r.receipt.backend_version = "1.8.0".into()
        }),
        ("evaluator ID", |r| r.receipt.evaluator_id = "0".repeat(64)),
        ("execution ID", |r| r.receipt.execution_id = "x".into()),
        ("signature", |r| {
            let mut s = r.signature.clone().into_bytes();
            s[0] = if s[0] == b'0' { b'1' } else { b'0' };
            r.signature = String::from_utf8(s).unwrap();
        }),
        ("signature length", |r| r.signature.truncate(10)),
    ];
    for (what, edit) in edits {
        let mut r = good.clone();
        edit(&mut r);
        let e = check(&r, &signer).unwrap_err();
        assert_eq!(e.code, Code::Receipt, "{what}: {e}");
    }
    // A consistent receipt signed by another evaluator is not trusted.
    let other = EvaluatorSigner::generate().unwrap();
    assert!(check(&signed(&other), &signer).is_err());
    // Nor is one where the public key is swapped for another evaluator's.
    let mut r = good.clone();
    r.evaluator_public_key = other.identity().public_key_hex();
    assert!(check(&r, &signer).is_err());
}

#[test]
fn receipts_do_not_transfer_between_executions() {
    let signer = EvaluatorSigner::generate().unwrap();
    let id = signer.identity();
    let a = ExecutionReceipt::new(
        &spec(),
        Some(TRANSCRIPT),
        KEY,
        b"request A",
        b"output A",
        &id,
    )
    .unwrap()
    .sign(&signer)
    .unwrap();
    let s = spec();
    let expect = |req: &[u8], out: &[u8], spec: &ExecutionSpec| {
        let (rc, oc) = (request_commitment(req), output_commitment(out));
        verify_receipt(
            &a,
            &ExpectedExecution {
                spec,
                key_id: KEY,
                request_commitment: &rc,
                output_commitment: &oc,
                transcript_hash: Some(TRANSCRIPT),
                proof_expected: false,
                trusted_evaluator: &id,
            },
        )
        .is_ok()
    };
    assert!(expect(b"request A", b"output A", &s));
    assert!(
        !expect(b"request A", b"output B", &s),
        "receipt A + output B"
    );
    assert!(
        !expect(b"request B", b"output A", &s),
        "replay with another request"
    );
    let mut program_b = spec();
    program_b.program_id = "e".repeat(64);
    assert!(!expect(b"request A", b"output A", &program_b), "program B");
}

#[test]
fn malformed_receipts_are_refused() {
    let signer = EvaluatorSigner::generate().unwrap();
    let bytes = signed(&signer).to_bytes().unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("truncated", bytes[..bytes.len() / 2].to_vec()),
        ("empty", vec![]),
        (
            "unknown version",
            text.replace("\"version\":3", "\"version\":4").into_bytes(),
        ),
        (
            "unknown field",
            text.replacen(
                "{\"evaluator_public_key\"",
                "{\"extra\":1,\"evaluator_public_key\"",
                1,
            )
            .into_bytes(),
        ),
        (
            "unknown evidence",
            text.replace("{\"kind\":\"none\"}", "{\"kind\":\"zk\"}")
                .into_bytes(),
        ),
        ("trailing data", [bytes.clone(), b"{}".to_vec()].concat()),
        ("non-hex key ID", {
            let r = signed(&signer);
            let key = r.receipt.key_id.clone();
            text.replace(&key, "k€€€€€€€€€€€€€€€€€€€€").into_bytes()
        }),
        ("oversized", vec![b' '; 20_000]),
    ];
    for (what, b) in cases {
        assert_eq!(
            SignedExecutionReceipt::from_bytes(&b).unwrap_err().code,
            Code::Receipt,
            "{what}"
        );
    }
}

#[test]
fn no_proof_backend_never_produces_evidence() {
    use encompute_verification::StatementShape;
    let t = encompute_verification::SemanticTranscript {
        format: encompute_verification::transcript::TRANSCRIPT_FORMAT.into(),
        transcript_version: 1,
        spec_id: spec().id().hex(),
        plan_kind: "exact".into(),
        plan_version: 1,
        inputs: vec![],
        outputs: vec![],
        entries: vec![],
    };
    assert!(NoProofBackend.setup(&StatementShape::of(&t)).is_err());
    assert_eq!(NoProofBackend.capabilities().coverage(&t), (0, 0));
}

#[test]
fn transcript_hash_is_bound() {
    let signer = EvaluatorSigner::generate().unwrap();
    let r = signed(&signer);
    let (s, id) = (spec(), signer.identity());
    let (rc, oc) = (request_commitment(REQ), output_commitment(OUT));
    for want in [None, Some("4d".repeat(32))] {
        let e = verify_receipt(
            &r,
            &ExpectedExecution {
                spec: &s,
                key_id: KEY,
                request_commitment: &rc,
                output_commitment: &oc,
                transcript_hash: want.as_deref(),
                proof_expected: false,
                trusted_evaluator: &id,
            },
        )
        .unwrap_err();
        assert_eq!(e.code, Code::Transcript, "{e}");
    }
}

/// The evidence must be what the verifier expects: a proof-less receipt is
/// refused when a proof is required, and a proof-naming receipt when none
/// is (checked by verify_receipt itself, not only downstream).
#[test]
fn evidence_must_match_expectation() {
    let signer = EvaluatorSigner::generate().unwrap();
    let id = signer.identity();
    let (s, rc, oc) = (spec(), request_commitment(REQ), output_commitment(OUT));
    let check = |r: &SignedExecutionReceipt, proof_expected: bool| {
        verify_receipt(
            r,
            &ExpectedExecution {
                spec: &s,
                key_id: KEY,
                request_commitment: &rc,
                output_commitment: &oc,
                transcript_hash: Some(TRANSCRIPT),
                proof_expected,
                trusted_evaluator: &id,
            },
        )
        .map(|_| ())
        .map_err(|e| e.code)
    };
    let plain = signed(&signer);
    assert_eq!(check(&plain, false), Ok(()));
    assert_eq!(check(&plain, true), Err(Code::Receipt), "stripped proof");
    let with_proof = ExecutionReceipt::with_evidence(
        &spec(),
        Some(TRANSCRIPT),
        KEY,
        REQ,
        OUT,
        &id,
        encompute_verification::VerificationEvidence::Vfhe {
            relation: encompute_verification::VerificationRelation::FheEvaluationV1,
            protocol: "reexecution-v1".into(),
            protocol_version: 1,
            verification_key_id: "5e".repeat(32),
            proof_digest: "6f".repeat(32),
        },
    )
    .unwrap()
    .sign(&signer)
    .unwrap();
    assert_eq!(check(&with_proof, true), Ok(()));
    assert_eq!(
        check(&with_proof, false),
        Err(Code::Receipt),
        "unexpected proof"
    );
}
