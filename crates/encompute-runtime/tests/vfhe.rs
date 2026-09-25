//! Verified private execution (0.4 V3a, ADR-009): OpenFHE BGV with
//! re-execution proofs. A malicious evaluator signs valid receipts for
//! wrong results; only the execution proof exposes them.
#![cfg(feature = "vfhe-research")]

use encompute_evaluator::server::{Evaluator, Limits};
use encompute_ir::{parse, Builder, Code, Elem, Inputs, LogicOp, Program, Range, Verification};
use encompute_protocol::Envelope;
use encompute_runtime::verification::{
    EvaluatorSigner, ExecutionProof, SignedExecutionReceipt, VerificationState,
};
use encompute_runtime::{
    BackendKind, Backends, ClientSession, EvaluatorSession, Mode, Model, Remote,
};

/// Loan pre-check over the proven subset (u16 arithmetic, Boolean logic).
fn precheck(verification: Verification, threshold: f64) -> Program {
    let mut b = Builder::new("precheck", 1e-3).unwrap();
    b.verification(verification);
    let income = b
        .input_exact("income", Elem::U16, Some(Range::new(0.0, 5000.0)))
        .unwrap();
    let debt = b
        .input_exact("debt", Elem::U16, Some(Range::new(0.0, 5000.0)))
        .unwrap();
    let member = b.input_exact("member", Elem::Bool, None).unwrap();
    let flagged = b.input_exact("flagged", Elem::Bool, None).unwrap();
    let k3 = b.constant_exact(Elem::U16, 3.0).unwrap();
    let scaled = b.mul(income, k3).unwrap();
    let score = b.add(scaled, debt).unwrap();
    let kt = b.constant_exact(Elem::U16, threshold).unwrap();
    let margin = b.sub(kt, score).unwrap();
    let clean = b.not(flagged).unwrap();
    let ok = b.logic(LogicOp::And, member, clean).unwrap();
    b.output("margin", margin).unwrap();
    b.output("ok", ok).unwrap();
    b.finish().unwrap()
}

fn inputs(income: f64, debt: f64, member: f64, flagged: f64) -> Inputs {
    [
        ("income", income),
        ("debt", debt),
        ("member", member),
        ("flagged", flagged),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), vec![v]))
    .collect()
}

struct Setup {
    program: Program,
    client: ClientSession,
    ev: EvaluatorSession,
    signer: EvaluatorSigner,
}

fn setup(verification: Verification) -> Setup {
    let program = precheck(verification, 30000.0);
    let m = Model::compile(program.clone()).unwrap();
    // Receipt-only exact programs target TFHE-rs (not in this build): show
    // them on the mock, which never claims verification either.
    let (mode, kind) = match verification {
        Verification::Required => (Mode::Encrypted, BackendKind::OpenFhe),
        Verification::Receipt => (Mode::Mock, BackendKind::Mock),
    };
    let client = m.new_client(mode).unwrap();
    let mut ev = EvaluatorSession::new(program.clone(), kind).unwrap();
    ev.register_keys(client.evaluation_keys().unwrap()).unwrap();
    Setup {
        program,
        client,
        ev,
        signer: EvaluatorSigner::generate().unwrap(),
    }
}

/// What an evaluator returns: response, its proof, and its signed receipt.
fn respond(
    s: &Setup,
    request: &[u8],
    response: Vec<u8>,
) -> (Vec<u8>, Option<ExecutionProof>, SignedExecutionReceipt) {
    let proof = s.ev.proof_for(request, &response).unwrap();
    let receipt = encompute_evaluator::issue_receipt(
        s.ev.spec(),
        s.ev.transcript_hash(),
        request,
        &response,
        proof.as_ref(),
        &s.signer,
    )
    .unwrap();
    (response, proof, receipt)
}

/// Replace the ciphertexts of an honest response, keeping its header (the
/// envelope checksum is recomputed: the lie is well formed).
fn relabel(honest: &[u8], items: Vec<(String, Vec<u8>)>) -> Vec<u8> {
    Envelope::new(Envelope::decode(honest).unwrap().header, items).encode()
}

#[test]
fn compile_requires_full_coverage() {
    let p = precheck(Verification::Required, 30000.0);
    let m = Model::compile(p.clone()).unwrap();
    assert_eq!(m.compiled().scheme(), "BGV");
    assert!(m.compiled().proof_required());
    assert!(p.to_string().contains("verification required"));
    assert_eq!(parse(&p.to_string()).unwrap(), p);
    // A comparison is not in the proven subset.
    let text = p.to_string().replace(
        "output \"ok\"",
        "%99 = lt %0, %1 : secret bool\noutput \"ok\"",
    );
    let _ = text; // (constructed below through the builder instead)
    let mut b = Builder::new("cmp", 1e-3).unwrap();
    b.verification(Verification::Required);
    let x = b.input_exact("x", Elem::U8, None).unwrap();
    let k = b.constant_exact(Elem::U8, 18.0).unwrap();
    let c = b.cmp(encompute_ir::CmpOp::Ge, x, k).unwrap();
    b.output("c", c).unwrap();
    let e = Model::compile(b.finish().unwrap()).err().unwrap();
    assert_eq!(e.code, Code::Unverified);
    assert!(
        e.message.contains("GE_CONST") && e.message.contains("coverage"),
        "{e}"
    );
}

#[test]
fn honest_evaluation_is_verified() {
    let s = setup(Verification::Required);
    for (x, want_margin, want_ok) in [
        (inputs(1000.0, 200.0, 1.0, 0.0), 26800.0, 1.0),
        (inputs(5000.0, 5000.0, 1.0, 1.0), 10000.0, 0.0),
        (inputs(0.0, 0.0, 0.0, 0.0), 30000.0, 0.0),
    ] {
        let request = s.client.encrypt(&s.program, &x).unwrap();
        let (response, _) = s.ev.execute(&request).unwrap();
        let (response, proof, receipt) = respond(&s, &request, response);
        let proof = proof.expect("BGV evaluators attach a proof");
        assert_eq!(proof.header.protocol, "reexecution-v1");
        let (out, state) = s
            .client
            .decrypt_proven(
                &request,
                &response,
                &receipt,
                Some(&proof),
                &s.signer.identity(),
            )
            .unwrap();
        assert!(
            matches!(state, VerificationState::ExecutionVerified(_)),
            "{state:?}"
        );
        assert_eq!(state.label(), "EXECUTION VERIFIED");
        assert_eq!(out["margin"], vec![want_margin]);
        assert_eq!(out["ok"], vec![want_ok]);
    }
}

/// `--attack` modes of a malicious evaluator. Each produces a well-formed
/// response and a validly signed receipt; the proof check rejects all.
#[test]
fn malicious_evaluator_is_caught() {
    let s = setup(Verification::Required);
    let x = inputs(1000.0, 200.0, 1.0, 0.0);
    let request = s.client.encrypt(&s.program, &x).unwrap();
    let (honest, _) = s.ev.execute(&request).unwrap();
    let items = |r: &[u8]| {
        Envelope::decode(r)
            .unwrap()
            .items()
            .iter()
            .map(|(n, b)| (n.to_string(), b.to_vec()))
            .collect::<Vec<_>>()
    };

    // Another program on the same inputs (a different threshold), and the
    // plan with its last operations skipped, relabelled as this program.
    let other = |p: Program| {
        let mut ev = EvaluatorSession::new(p, BackendKind::OpenFhe).unwrap();
        ev.register_keys(s.client.evaluation_keys().unwrap())
            .unwrap();
        let req = relabel(&request, items(&request));
        // Re-bind the request to the other program for its evaluator.
        let mut env = Envelope::decode(&req).unwrap();
        env.header.program_id = Some(ev.ids().program_id.clone());
        let (resp, _) = ev.execute(&env.encode()).unwrap();
        relabel(&honest, items(&resp))
    };
    let skip = {
        // Skip the subtraction: return the score where the margin belongs.
        let mut b = Builder::new("precheck", 1e-3).unwrap();
        b.verification(Verification::Required);
        let income = b
            .input_exact("income", Elem::U16, Some(Range::new(0.0, 5000.0)))
            .unwrap();
        let debt = b
            .input_exact("debt", Elem::U16, Some(Range::new(0.0, 5000.0)))
            .unwrap();
        let member = b.input_exact("member", Elem::Bool, None).unwrap();
        let flagged = b.input_exact("flagged", Elem::Bool, None).unwrap();
        let k3 = b.constant_exact(Elem::U16, 3.0).unwrap();
        let scaled = b.mul(income, k3).unwrap();
        let score = b.add(scaled, debt).unwrap();
        let clean = b.not(flagged).unwrap();
        let ok = b.logic(LogicOp::And, member, clean).unwrap();
        b.output("margin", score).unwrap();
        b.output("ok", ok).unwrap();
        other(b.finish().unwrap())
    };
    let old = {
        let r = s
            .client
            .encrypt(&s.program, &inputs(1.0, 1.0, 0.0, 1.0))
            .unwrap();
        s.ev.execute(&r).unwrap().0
    };
    let mut mutated = items(&honest);
    let n = mutated[0].1.len();
    mutated[0].1[n / 2] ^= 1;
    let random: Vec<(String, Vec<u8>)> = items(&honest)
        .into_iter()
        .map(|(n, b)| {
            (
                n,
                b.iter()
                    .map(|x| x.wrapping_mul(31).wrapping_add(7))
                    .collect(),
            )
        })
        .collect();

    let attacks: Vec<(&str, Vec<u8>)> = vec![
        ("random-output", relabel(&honest, random)),
        ("replay-old-output", old),
        ("skip-operation", skip),
        (
            "substitute-program",
            other(precheck(Verification::Required, 20000.0)),
        ),
        ("mutate-ciphertext", relabel(&honest, mutated)),
    ];
    for (attack, lie) in attacks {
        let (lie, proof, receipt) = respond(&s, &request, lie);
        // The evaluator signs its own lie: the receipt checks out.
        assert!(
            s.client
                .decrypt_proven(&request, &lie, &receipt, None, &s.signer.identity())
                .err()
                .is_some_and(|e| e.code == Code::Unverified),
            "{attack}: without a proof nothing is decrypted"
        );
        let e = s
            .client
            .decrypt_proven(
                &request,
                &lie,
                &receipt,
                proof.as_ref(),
                &s.signer.identity(),
            )
            .err()
            .unwrap_or_else(|| panic!("{attack}: the lie was accepted"));
        assert!(
            matches!(
                e.code,
                Code::Unverified | Code::WrongParameters | Code::Backend
            ),
            "{attack}: {e}"
        );
        eprintln!("{attack:<20} receipt valid, proof rejected: {}", e.message);
    }
}

/// Without `verification required` the same lie is accepted: a receipt
/// only makes it attributable.
#[test]
fn receipts_alone_accept_a_signed_lie() {
    let s = setup(Verification::Receipt);
    let request = s
        .client
        .encrypt(&s.program, &inputs(1000.0, 200.0, 1.0, 0.0))
        .unwrap();
    let (honest, _) = s.ev.execute(&request).unwrap();
    let old = {
        let r = s
            .client
            .encrypt(&s.program, &inputs(1.0, 1.0, 0.0, 1.0))
            .unwrap();
        s.ev.execute(&r).unwrap().0
    };
    let (lie, proof, receipt) = respond(&s, &request, old);
    assert!(proof.is_none());
    let (out, state) = s
        .client
        .decrypt_proven(&request, &lie, &receipt, None, &s.signer.identity())
        .unwrap();
    assert_eq!(state, VerificationState::ReceiptVerified);
    assert_ne!(
        out,
        s.client.decrypt(&honest).unwrap(),
        "wrong result, validly signed"
    );
}

#[test]
fn proof_tampering_fails_closed() {
    let s = setup(Verification::Required);
    let request = s
        .client
        .encrypt(&s.program, &inputs(10.0, 20.0, 1.0, 0.0))
        .unwrap();
    let (response, _) = s.ev.execute(&request).unwrap();
    let (response, proof, receipt) = respond(&s, &request, response);
    let proof = proof.unwrap();
    let id = s.signer.identity();
    let check = |p: &ExecutionProof| {
        s.client
            .decrypt_proven(&request, &response, &receipt, Some(p), &id)
            .err()
            .map(|e| e.code)
    };
    assert_eq!(check(&proof), None);
    type Edit = fn(&mut ExecutionProof);
    let edits: Vec<(&str, Edit)> = vec![
        ("spec", |p| p.header.spec_id = "0".repeat(64)),
        ("transcript", |p| p.header.transcript_hash = "0".repeat(64)),
        ("verification key", |p| {
            p.header.verification_key_id = "0".repeat(64)
        }),
        ("request", |p| p.header.request_commitment = "0".repeat(64)),
        ("output", |p| p.header.output_commitment = "0".repeat(64)),
        ("protocol", |p| p.header.protocol = "other-v1".into()),
    ];
    for (what, edit) in edits {
        let mut p = proof.clone();
        edit(&mut p);
        assert_eq!(check(&p), Some(Code::Unverified), "{what}");
    }
    // Truncated and malformed encodings.
    let bytes = proof.to_bytes().unwrap();
    assert!(ExecutionProof::from_bytes(&bytes[..bytes.len() - 3]).is_err());
    assert!(ExecutionProof::from_bytes(b"ENCP\x05\x00\x00\x00{}").is_err());
    // A proof from another execution.
    let other = s
        .client
        .encrypt(&s.program, &inputs(11.0, 20.0, 1.0, 0.0))
        .unwrap();
    let (resp2, _) = s.ev.execute(&other).unwrap();
    let (_, proof2, _) = respond(&s, &other, resp2);
    assert_eq!(check(&proof2.unwrap()), Some(Code::Unverified));
    // Another client's evaluation keys (wrong verification key).
    let stranger = Model::compile(s.program.clone())
        .unwrap()
        .new_client(Mode::Encrypted)
        .unwrap();
    let mut restored = ClientSession::restore(
        s.client.ids().clone(),
        Model::compile(s.program.clone()).unwrap().compiled(),
        &s.client.secret_key_envelope().unwrap(),
    )
    .unwrap();
    assert_eq!(
        restored
            .attach_evaluation_keys(stranger.evaluation_keys().unwrap())
            .unwrap_err()
            .code,
        Code::WrongKey
    );
    // A restored client without its evaluation keys cannot verify.
    assert_eq!(
        restored
            .decrypt_proven(&request, &response, &receipt, Some(&proof), &id)
            .unwrap_err()
            .code,
        Code::Unverified
    );
    restored
        .attach_evaluation_keys(s.client.evaluation_keys().unwrap())
        .unwrap();
    assert!(restored
        .decrypt_proven(&request, &response, &receipt, Some(&proof), &id)
        .is_ok());
}

/// End to end over HTTP: an OpenFHE evaluator attaches proofs; the client
/// verifies before decrypting.
#[test]
fn remote_verified_execution() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    let backends = Backends {
        approx: BackendKind::OpenFhe,
        exact: BackendKind::Mock,
    };
    std::thread::spawn(move || Evaluator::new(backends, Limits::default()).serve(server));
    let remote = Remote::new(&url);
    let trusted = remote.evaluator_identity().unwrap();
    let m = Model::compile(precheck(Verification::Required, 30000.0)).unwrap();
    let client = m.new_client(Mode::Encrypted).unwrap();
    let t = std::time::Instant::now();
    let run = remote
        .run(
            &client,
            m.program(),
            None,
            &inputs(1000.0, 200.0, 1.0, 0.0),
            &trusted,
        )
        .unwrap();
    assert!(matches!(run.state, VerificationState::ExecutionVerified(_)));
    assert_eq!(run.outputs["margin"], vec![26800.0]);
    let proof = run.proof.unwrap();
    eprintln!(
        "verified remote run: {:.0} ms round trip (evaluator {:.1} ms), proof {} bytes, request {} KiB, response {} KiB",
        t.elapsed().as_secs_f64() * 1e3,
        run.stats.evaluator_ms,
        proof.to_bytes().unwrap().len(),
        run.stats.request_bytes >> 10,
        run.stats.response_bytes >> 10
    );
}

/// Cost of verified execution (release: `cargo test --release ...`).
#[test]
fn performance_report() {
    use std::time::Instant;
    let s = setup(Verification::Required);
    let x = inputs(1000.0, 200.0, 1.0, 0.0);
    let request = s.client.encrypt(&s.program, &x).unwrap();
    let reps = 5;
    let mut eval = vec![];
    let mut verify = vec![];
    let mut last = None;
    for _ in 0..reps {
        let t = Instant::now();
        let (response, _) = s.ev.execute(&request).unwrap();
        eval.push(t.elapsed());
        let (response, proof, receipt) = respond(&s, &request, response);
        let t = Instant::now();
        s.client
            .decrypt_proven(
                &request,
                &response,
                &receipt,
                proof.as_ref(),
                &s.signer.identity(),
            )
            .unwrap();
        verify.push(t.elapsed());
        last = Some((response, proof.unwrap()));
    }
    eval.sort();
    verify.sort();
    let (response, proof) = last.unwrap();
    eprintln!(
        "BGV evaluation {:?}, verification (re-execution + decryption) {:?}, ratio {:.2}; \
         proof {} bytes (header only); verification key = evaluation keys {} KiB; \
         request {} KiB, response {} KiB",
        eval[reps / 2],
        verify[reps / 2],
        verify[reps / 2].as_secs_f64() / eval[reps / 2].as_secs_f64(),
        proof.to_bytes().unwrap().len(),
        s.client.evaluation_keys().unwrap().len() >> 10,
        request.len() >> 10,
        response.len() >> 10
    );
}
