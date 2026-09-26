//! Research build only: the flagship on TFHE-rs. Its own test binary,
//! because it selects TFHE-rs through the (process-wide) research
//! environment variable.
#![cfg(feature = "research-tfhe-rs")]

use encompute_evaluator::server::{Evaluator, Limits};
use encompute_ir::{Builder, CmpOp, Code, Elem, Inputs, LogicOp, Program, Range};
use encompute_runtime::{BackendKind, Backends, Mode, Model, Remote};

/// The 0.3 flagship: private eligibility.
fn approve() -> Program {
    let mut b = Builder::new("approve", 1e-3).unwrap();
    let input = |b: &mut Builder, n: &str, e: Elem, hi: f64| {
        b.input_exact(n, e, Some(Range::new(0.0, hi))).unwrap()
    };
    let age = input(&mut b, "age", Elem::U8, 120.0);
    let income = input(&mut b, "income", Elem::U32, 1e6);
    let debt = input(&mut b, "debt", Elem::U32, 5e5);
    let risk = input(&mut b, "risk", Elem::U16, 1000.0);
    let c18 = b.constant_exact(Elem::U8, 18.0).unwrap();
    let adult = b.cmp(CmpOp::Ge, age, c18).unwrap();
    let c100 = b.constant_exact(Elem::U32, 100.0).unwrap();
    let c40 = b.constant_exact(Elem::U32, 40.0).unwrap();
    let d = b.mul(debt, c100).unwrap();
    let i = b.mul(income, c40).unwrap();
    let debt_ok = b.cmp(CmpOp::Lt, d, i).unwrap();
    let c650 = b.constant_exact(Elem::U16, 650.0).unwrap();
    let risk_ok = b.cmp(CmpOp::Le, risk, c650).unwrap();
    let x = b.logic(LogicOp::And, adult, debt_ok).unwrap();
    let ok = b.logic(LogicOp::And, x, risk_ok).unwrap();
    b.output("approved", ok).unwrap();
    b.finish().unwrap()
}

fn inputs(age: f64, income: f64, debt: f64, risk: f64) -> Inputs {
    [
        ("age", age),
        ("income", income),
        ("debt", debt),
        ("risk", risk),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), vec![v]))
    .collect()
}

/// Research build: the same program on TFHE-rs, locally and through an HTTP
/// evaluator that holds only the server key. `ENCOMPUTE_EXACT_CASES` sets
/// the differential-test size (default 20).
#[cfg(feature = "research-tfhe-rs")]
#[test]
fn tfhe_rs_end_to_end() {
    // A research build asks for TFHE-rs explicitly; the default is OpenFHE.
    std::env::set_var("ENCOMPUTE_RESEARCH_EXACT_BACKEND", "tfhe-rs");
    let m = Model::compile(approve()).unwrap();
    assert_eq!(m.compiled().scheme(), "TFHE");
    let yes = inputs(35.0, 100_000.0, 20_000.0, 400.0);
    assert_eq!(m.run(Mode::Encrypted, &yes).unwrap()["approved"], vec![1.0]);
    let cases = std::env::var("ENCOMPUTE_EXACT_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let rep = m.test(Mode::Encrypted, cases, 11).unwrap();
    let r = rep.exact().unwrap();
    eprintln!(
        "tfhe-rs: {} cases, {} matches, {} mismatches",
        r.cases, r.matches, r.mismatches
    );
    assert!(r.passed && r.backend == "tfhe-rs", "{r:?}");

    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    let backends = Backends::MOCK.with(BackendKind::TfheRs);
    std::thread::spawn(move || Evaluator::new(backends, Limits::default()).serve(server));
    let remote = Remote::new(&url);
    let client = m.new_client(Mode::Encrypted).unwrap();
    let trusted = remote.evaluator_identity().unwrap();
    let run = remote
        .run(
            &client,
            m.program(),
            None,
            &inputs(31.0, 120_000.0, 21_000.0, 400.0),
            &trusted,
        )
        .unwrap();
    assert_eq!(run.receipt.receipt.backend, "tfhe-rs");
    let (out, stats) = (run.outputs, run.stats);
    assert_eq!(out["approved"], vec![1.0]);

    // Another TFHE client: its inputs are refused (keys not registered),
    // and it cannot read this client's results.
    let stranger = m.new_client(Mode::Encrypted).unwrap();
    let x = inputs(31.0, 120_000.0, 21_000.0, 400.0);
    let err = remote
        .execute(
            &m.ids().program_id,
            &stranger.encrypt(m.program(), &x).unwrap(),
        )
        .unwrap_err();
    assert_eq!(err.code, Code::WrongKey, "{err}");
    let (response, _) = remote
        .execute(
            &m.ids().program_id,
            &client.encrypt(m.program(), &x).unwrap(),
        )
        .unwrap();
    assert_eq!(
        stranger.decrypt(&response).unwrap_err().code,
        Code::WrongKey
    );
    eprintln!(
        "remote tfhe-rs: server key {} MiB, request {} KiB, response {} KiB, evaluator {:.0} ms",
        stats.evaluation_key_bytes_uploaded >> 20,
        stats.request_bytes >> 10,
        stats.response_bytes >> 10,
        stats.evaluator_ms
    );
}
