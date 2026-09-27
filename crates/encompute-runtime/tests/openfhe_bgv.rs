//! Unverified exact programs selected onto OpenFHE BGV (whole program, by
//! estimated cost): the same results as the clear reference and the mock,
//! locally and through a remote evaluator, with receipts and no proofs.
#![cfg(feature = "openfhe")]

use encompute_evaluator::cost::ExactScheme;
use encompute_evaluator::server::{Evaluator, Limits};
use encompute_ir::{Builder, Elem, Inputs, LogicOp, Program, Range};
use encompute_runtime::verification::{VerificationEvidence, VerificationState};
use encompute_runtime::{BackendKind, Backends, Mode, Model, Remote};

/// Credit scoring over u16 arithmetic and Boolean logic: every operation in
/// the BGV subset, far cheaper there than as bootstrapped gates.
fn scoring() -> Program {
    let mut b = Builder::new("scoring", 1e-3).unwrap();
    let income = b
        .input_exact("income", Elem::U16, Some(Range::new(0.0, 5000.0)))
        .unwrap();
    let debt = b
        .input_exact("debt", Elem::U16, Some(Range::new(0.0, 5000.0)))
        .unwrap();
    let years = b
        .input_exact("years", Elem::U16, Some(Range::new(0.0, 40.0)))
        .unwrap();
    let member = b.input_exact("member", Elem::Bool, None).unwrap();
    let flagged = b.input_exact("flagged", Elem::Bool, None).unwrap();
    let k3 = b.constant_exact(Elem::U16, 3.0).unwrap();
    let k7 = b.constant_exact(Elem::U16, 7.0).unwrap();
    let s = b.mul(income, k3).unwrap();
    let s = b.add(s, debt).unwrap();
    let t = b.mul(years, years).unwrap();
    let s = b.add(s, t).unwrap();
    let score = b.add(s, k7).unwrap();
    let k30000 = b.constant_exact(Elem::U16, 30000.0).unwrap();
    let margin = b.sub(k30000, score).unwrap();
    let clean = b.not(flagged).unwrap();
    let ok = b.logic(LogicOp::And, member, clean).unwrap();
    let odd = b.logic(LogicOp::Xor, member, flagged).unwrap();
    b.output("score", score).unwrap();
    b.output("margin", margin).unwrap();
    b.output("ok", ok).unwrap();
    b.output("odd", odd).unwrap();
    b.finish().unwrap()
}

fn inputs(income: f64, debt: f64, years: f64, member: f64, flagged: f64) -> Inputs {
    [
        ("income", income),
        ("debt", debt),
        ("years", years),
        ("member", member),
        ("flagged", flagged),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), vec![v]))
    .collect()
}

#[test]
fn arithmetic_programs_run_on_bgv_without_proofs() {
    let m = Model::compile(scoring()).unwrap();
    assert_eq!(m.compiled().scheme(), "BGV");
    assert_eq!(m.compiled().target_backend(), BackendKind::OpenFhe);
    assert!(!m.compiled().proof_required());
    let sel = m.compiled().exact().unwrap().selection.clone().unwrap();
    assert_eq!(sel.scheme, ExactScheme::Bgv, "{}", sel.reason);
    assert_eq!(
        m.backend_for(Mode::Encrypted).unwrap(),
        BackendKind::OpenFhe
    );

    // Local: encrypted == clear == mock.
    for x in [
        inputs(0.0, 0.0, 0.0, 0.0, 0.0),
        inputs(5000.0, 5000.0, 40.0, 1.0, 1.0),
        inputs(1234.0, 17.0, 12.0, 1.0, 0.0),
    ] {
        let clear = m.run(Mode::Clear, &x).unwrap();
        assert_eq!(m.run(Mode::Mock, &x).unwrap(), clear);
        assert_eq!(m.run(Mode::Encrypted, &x).unwrap(), clear, "{x:?}");
    }
    let rep = m.test(Mode::Encrypted, 4, 7).unwrap();
    let r = rep.exact().unwrap();
    assert!(r.passed && r.backend == "openfhe", "{r:?}");

    // Remote: an OpenFHE evaluator holding only evaluation keys; a signed
    // receipt with no proof evidence.
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    let backends = Backends::for_build();
    std::thread::spawn(move || Evaluator::new(backends, Limits::default()).serve(server));
    let remote = Remote::new(&url);
    let trusted = remote.evaluator_identity().unwrap();
    let client = m.new_client(Mode::Encrypted).unwrap();
    let x = inputs(1000.0, 200.0, 10.0, 1.0, 0.0);
    let run = remote
        .run(&client, m.program(), None, &x, &trusted)
        .unwrap();
    assert_eq!(run.outputs, m.run(Mode::Clear, &x).unwrap());
    assert_eq!(run.outputs["score"], vec![3307.0]);
    assert_eq!(run.receipt.receipt.backend, "openfhe");
    assert_eq!(run.receipt.receipt.scheme, "BGV");
    assert_eq!(run.receipt.receipt.evidence, VerificationEvidence::None);
    assert!(run.proof.is_none());
    assert_eq!(run.state, VerificationState::ReceiptVerified);
    eprintln!(
        "remote BGV: estimate {:?} ms (BinFHE {:?} ms), evaluator {:.1} ms, evaluation keys {} KiB",
        sel.bgv_ms,
        sel.binfhe_ms,
        run.stats.evaluator_ms,
        run.stats.evaluation_key_bytes_uploaded >> 10
    );
}
