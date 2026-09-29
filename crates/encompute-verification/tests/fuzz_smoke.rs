//! Fuzz smoke tests for signed receipts, execution proofs, transcripts,
//! service request headers, service messages and job grants: mutated
//! inputs never panic, accepted ones round-trip, and nothing mutated is
//! accepted as validly signed. Resource limits: oversized objects, huge
//! declared lengths, deep JSON and out-of-range integers are typed errors.

#[path = "../../encompute-ir/tests/fuzz_support/mod.rs"]
mod fuzz_support;

use std::collections::BTreeMap;
use std::time::Duration;

use encompute_ir::Code;
use encompute_verification::proof::{ExecutionProof, ProofHeader, VerificationRelation};
use encompute_verification::service::{
    self, ServiceHeaders, H_BIND, H_NONCE, H_RECIPIENT, H_SENDER, H_SIGNATURE, H_TIMESTAMP,
    JOB_GRANT,
};
use encompute_verification::{
    EvaluatorSigner, ExecutionReceipt, ExecutionSpec, JobGrant, MessageEnvelope,
    SemanticTranscript, ServiceSigner, SignedExecutionReceipt,
};
use fuzz_support::{run, within};

const SEED: [u8; 32] = [7; 32];

fn receipt() -> SignedExecutionReceipt {
    let spec = ExecutionSpec {
        governance_id: None,
        version: 1,
        program_id: "a".repeat(64),
        plan_id: "b".repeat(64),
        parameter_set_id: "c".repeat(64),
        plan_kind: "exact".into(),
        plan_version: 1,
        semantics: "exact".into(),
        scheme: "BinFHE".into(),
        backend: "openfhe-exact".into(),
        backend_version: "1.5.1".into(),
        policy_id: None,
        privacy_policy_id: None,
    };
    let signer = EvaluatorSigner::from_seed(&SEED);
    ExecutionReceipt::new(
        &spec,
        Some(&"3c".repeat(32)),
        &"1f".repeat(32),
        b"request",
        b"output",
        &signer.identity(),
    )
    .unwrap()
    .sign(&signer)
    .unwrap()
}

fn proof() -> ExecutionProof {
    ExecutionProof {
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
    }
}

#[test]
fn mutated_receipts_never_panic_or_verify() {
    let r = receipt();
    let id = EvaluatorSigner::from_seed(&SEED).identity();
    let seed = r.to_bytes().unwrap();
    run(
        "receipt",
        std::slice::from_ref(&seed),
        6000,
        Duration::from_secs(1),
        |bytes| {
            if let Ok(p) = SignedExecutionReceipt::from_bytes(bytes) {
                let again = SignedExecutionReceipt::from_bytes(&p.to_bytes().unwrap()).unwrap();
                assert_eq!(again, p);
                // Only the original (or a re-encoding of it) carries a valid
                // signature.
                if p.verify_signature(&id).is_ok() {
                    assert_eq!(p, r);
                }
            }
        },
    );
}

#[test]
fn mutated_proofs_and_transcripts_never_panic() {
    run(
        "proof",
        &[proof().to_bytes().unwrap()],
        6000,
        Duration::from_secs(1),
        |bytes| {
            if let Ok(p) = ExecutionProof::from_bytes(bytes) {
                assert_eq!(p.to_bytes().unwrap(), bytes);
            }
        },
    );
    let t = include_bytes!("../../../fuzz/corpus/transcript_parse/exact.json").to_vec();
    SemanticTranscript::from_bytes(&t).unwrap();
    run("transcript", &[t], 8000, Duration::from_secs(1), |bytes| {
        if let Ok(t) = SemanticTranscript::from_bytes(bytes) {
            let again = SemanticTranscript::from_bytes(&t.canonical_bytes().unwrap()).unwrap();
            assert_eq!(again, t);
        }
    });
}

#[test]
fn mutated_service_headers_never_panic_or_verify() {
    let s = ServiceSigner::from_seed("evaluator-1", &SEED).unwrap();
    let bind: BTreeMap<String, String> = [("job".to_owned(), "job_1".to_owned())].into();
    let h = s
        .sign_request("POST", "/v1/messages", "control-plane", &bind, b"{}")
        .unwrap();
    let seed = serde_json::to_vec(&h.to_pairs().into_iter().collect::<BTreeMap<_, _>>()).unwrap();
    let pk = s.public_key_hex();
    run("headers", &[seed], 6000, Duration::from_secs(1), |bytes| {
        let Ok(m) = serde_json::from_slice::<BTreeMap<String, String>>(bytes) else {
            return;
        };
        if let Ok(Some(p)) = ServiceHeaders::from_lookup(|k| m.get(k).cloned()) {
            let ok = p
                .verify(
                    &pk,
                    "POST",
                    "/v1/messages",
                    b"{}",
                    "control-plane",
                    h.timestamp,
                )
                .is_ok();
            if ok {
                assert_eq!(p, h);
            }
        }
    });
}

#[test]
fn mutated_messages_and_grants_never_panic_or_verify() {
    let s = ServiceSigner::from_seed("evaluator-1", &SEED).unwrap();
    let m = service::seal(
        &s,
        "job.completed",
        "control-plane",
        service::Scope::default(),
        &serde_json::json!({"job": "job_1", "nested": [[1, 2], {"a": null}]}),
        300,
    )
    .unwrap();
    let pk = s.public_key_hex();
    run(
        "message",
        &[serde_json::to_vec(&m).unwrap()],
        5000,
        Duration::from_secs(1),
        |bytes| {
            if let Ok(x) = serde_json::from_slice::<MessageEnvelope>(bytes) {
                if service::open(&x, &pk, "control-plane", m.created_at).is_ok() {
                    assert_eq!(x.statement().message_id, m.message_id);
                    assert_eq!(x.payload_digest, m.payload_digest);
                }
                let _ = service::open(&x, &pk, &x.recipient, u64::MAX);
            }
        },
    );

    let control = ServiceSigner::from_seed("control-plane", &SEED).unwrap();
    let mut g = JobGrant {
        governance: None,
        version: 1,
        job_id: "job_1".into(),
        organization: "modelco".into(),
        project: "prj_1".into(),
        plan_id: "pln_1".into(),
        spec_id: "s".repeat(64),
        program_id: "p".repeat(64),
        evaluator: "evaluator-1".into(),
        backend: "openfhe-exact".into(),
        profile: "BINFHE_STD128_GINX_BITS_V1".into(),
        issued_at: 1000,
        expires_at: 2000,
        issuer: "control-plane".into(),
        issuer_public_key: control.public_key_hex(),
        signature: String::new(),
    };
    g.signature = control.sign(JOB_GRANT, &g.unsigned()).unwrap();
    let cpk = control.public_key_hex();
    let seeds = vec![g.to_header().into_bytes(), serde_json::to_vec(&g).unwrap()];
    run("grant", &seeds, 5000, Duration::from_secs(1), |bytes| {
        let parsed = [
            JobGrant::from_header(&String::from_utf8_lossy(bytes)).ok(),
            serde_json::from_slice::<JobGrant>(bytes).ok(),
        ];
        for x in parsed.into_iter().flatten() {
            assert_eq!(JobGrant::from_header(&x.to_header()).unwrap(), x);
            if x.verify(&cpk, "evaluator-1", &"p".repeat(64), 1500).is_ok() {
                assert_eq!(x, g);
            }
        }
    });
}

#[test]
fn resource_limits_are_typed_errors() {
    let limit = Duration::from_secs(2);
    // Receipts: size limit, deep JSON, integers out of range.
    let big = vec![b' '; (16 << 10) + 1];
    let e = within(limit, || SignedExecutionReceipt::from_bytes(&big)).unwrap_err();
    assert_eq!(e.code, Code::Receipt);
    let deep = fuzz_support::nested_json(8000, "");
    let e = within(limit, || {
        SignedExecutionReceipt::from_bytes(deep.as_bytes())
    })
    .unwrap_err();
    assert_eq!(e.code, Code::Receipt);
    let seed = String::from_utf8(receipt().to_bytes().unwrap()).unwrap();
    for (from, to) in [
        ("\"version\":3", "\"version\":4294967296"),
        ("\"version\":3", "\"version\":-1"),
        ("\"version\":3", "\"version\":1e400"),
    ] {
        let bad = seed.replacen(from, to, 1);
        assert_ne!(bad, seed);
        let e = SignedExecutionReceipt::from_bytes(bad.as_bytes()).unwrap_err();
        assert_eq!(e.code, Code::Receipt, "{to}: {e}");
    }
    // Proofs: header lengths near u32::MAX with a short input.
    for n in [u32::MAX, u32::MAX - 7, 1 << 31] {
        let mut b = b"ENCP".to_vec();
        b.extend_from_slice(&n.to_le_bytes());
        b.extend_from_slice(b"{}");
        let e = within(limit, || ExecutionProof::from_bytes(&b)).unwrap_err();
        assert_eq!(e.code, Code::Unverified);
    }
    // A proof header claiming 2^64-1 proof bytes.
    let mut p = proof();
    p.header.proof_bytes = u64::MAX;
    let e = ExecutionProof::from_bytes(&p.to_bytes().unwrap()).unwrap_err();
    assert_eq!(e.code, Code::Unverified);
    // Transcripts: deep JSON, huge operand indices, a 2^32-entry table.
    let e = within(limit, || {
        SemanticTranscript::from_bytes(fuzz_support::nested_json(100_000, "").as_bytes())
    })
    .unwrap_err();
    assert_eq!(e.code, Code::Transcript);
    let t = String::from_utf8(
        include_bytes!("../../../fuzz/corpus/transcript_parse/exact.json").to_vec(),
    )
    .unwrap();
    for (from, to) in [
        ("\"operands\":[0]", "\"operands\":[18446744073709551615]"),
        ("\"operands\":[0]", "\"operands\":[4294967295]"),
        (
            "{\"index\":0,\"kind\":\"input_index\"}",
            "{\"index\":18446744073709551615,\"kind\":\"input_index\"}",
        ),
        ("\"index\":1,", "\"index\":18446744073709551615,"),
        ("\"result\":1,", "\"result\":4294967295,"),
    ] {
        let bad = t.replacen(from, to, 1);
        assert_ne!(bad, t, "{from}");
        let e = within(limit, || SemanticTranscript::from_bytes(bad.as_bytes())).unwrap_err();
        assert_eq!(e.code, Code::Transcript, "{to}: {e}");
    }
    // Service headers: absurd timestamps and binds.
    let get = |ts: &'static str, bind: String| {
        move |h: &str| match h {
            x if x == H_SIGNATURE => Some("00".into()),
            x if x == H_SENDER || x == H_RECIPIENT => Some("control-plane".into()),
            x if x == H_TIMESTAMP => Some(ts.into()),
            x if x == H_NONCE => Some("0".repeat(32)),
            x if x == H_BIND => Some(bind.clone()),
            _ => None,
        }
    };
    for ts in ["18446744073709551616", "-1", "1e3", ""] {
        let e = ServiceHeaders::from_lookup(get(ts, String::new())).unwrap_err();
        assert_eq!(e.code, Code::ServiceAuthentication);
    }
    let e =
        ServiceHeaders::from_lookup(get("1", fuzz_support::nested_json(100_000, ""))).unwrap_err();
    assert_eq!(e.code, Code::ServiceAuthentication);
    let h = ServiceHeaders::from_lookup(get("18446744073709551615", String::new()))
        .unwrap()
        .unwrap();
    let e = h
        .verify(&"00".repeat(32), "GET", "/", b"", "control-plane", 0)
        .unwrap_err();
    assert_eq!(e.code, Code::ServiceAuthentication);
    // Job grant headers: odd length, non-hex, huge.
    for h in ["0", "zz", &"41".repeat(1 << 20), "\u{00e9}\u{00e9}"] {
        let e = within(limit, || JobGrant::from_header(h)).unwrap_err();
        assert_eq!(e.code, Code::ServiceAuthentication);
    }
    // Messages near the end of time. Regression: the future-dated check
    // computed `now + skew` unchecked (overflow panic in debug builds).
    let s = ServiceSigner::from_seed("evaluator-1", &SEED).unwrap();
    let mut m = service::seal(&s, "k", "control-plane", service::Scope::default(), &1, 60).unwrap();
    m.created_at = u64::MAX;
    m.expires_at = u64::MAX;
    let e = service::open(&m, &s.public_key_hex(), "control-plane", u64::MAX - 1).unwrap_err();
    assert_eq!(e.code, Code::ServiceAuthentication);
}
