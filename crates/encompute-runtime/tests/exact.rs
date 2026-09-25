//! Exact programs end to end on the mock backend: model, differential test,
//! artifacts, envelope bindings across schemes, and remote execution.

mod common;

use std::collections::BTreeMap;

use common::{logistic, mock_sessions};
use encompute_evaluator::server::{Evaluator, Limits};
use encompute_ir::{evaluate, Builder, CmpOp, Code, Elem, Inputs, LogicOp, Program, Range};
use encompute_runtime::{
    sample_inputs, BackendKind, Backends, ClientSession, EvaluatorSession, Mode, Model, Remote,
    Semantics, TestReport,
};

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

#[test]
fn exact_model_runs_clear_and_mock() {
    let m = Model::compile(approve()).unwrap();
    assert_eq!(m.semantics(), Semantics::Exact);
    assert_eq!(m.compiled().scheme(), "TFHE");
    let yes = inputs(35.0, 100_000.0, 20_000.0, 400.0);
    let no = inputs(35.0, 100_000.0, 20_000.0, 700.0);
    for mode in [Mode::Clear, Mode::Mock] {
        assert_eq!(m.run(mode, &yes).unwrap()["approved"], vec![1.0]);
        assert_eq!(m.run(mode, &no).unwrap()["approved"], vec![0.0]);
    }
    assert_eq!(
        m.outputs_json(&m.run(Mode::Mock, &yes).unwrap()),
        serde_json::json!({"approved": true})
    );
    match m.test(Mode::Mock, 1000, 7).unwrap() {
        TestReport::Exact(r) => {
            assert!(r.passed && r.matches == 1000 && r.mismatches == 0, "{r:?}");
        }
        r => panic!("exact programs give exact reports: {r:?}"),
    }
    let json = serde_json::to_value(m.test(Mode::Mock, 3, 1).unwrap()).unwrap();
    assert_eq!(json["semantics"], "exact");
    assert!(
        json.get("max_error").is_none(),
        "no error metrics for exact programs"
    );
    // Without the research feature there is no exact cryptographic backend.
    if !encompute_runtime::has_tfhe() {
        assert_eq!(
            m.run(Mode::Encrypted, &yes).unwrap_err().code,
            Code::Backend
        );
    }
}

#[test]
fn exact_sampling_hits_boundaries() {
    let p = approve();
    let mut seen: BTreeMap<i64, usize> = BTreeMap::new();
    for case in 0..400 {
        let v = sample_inputs(&p, case, 3)["age"][0];
        assert_eq!(v.fract(), 0.0, "integers only");
        *seen.entry(v as i64).or_default() += 1;
    }
    for b in [0, 1, 119, 120] {
        assert!(seen.contains_key(&b), "age {b} never sampled: {seen:?}");
    }
}

#[test]
fn exact_artifacts_round_trip_deterministically() {
    let dir = std::env::temp_dir().join(format!("encompute-exact-{}", std::process::id()));
    let (a, b) = (dir.join("a.encompute"), dir.join("b.encompute"));
    let m = Model::compile(approve()).unwrap();
    m.save(&a).unwrap();
    Model::compile(approve()).unwrap().save(&b).unwrap();
    for f in [
        "program.eir",
        "plan.json",
        "parameters.json",
        "security.json",
        "manifest.json",
    ] {
        assert_eq!(
            std::fs::read(a.join(f)).unwrap(),
            std::fs::read(b.join(f)).unwrap(),
            "{f} is deterministic"
        );
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(a.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["compiler"]["plan"]["kind"], "exact");
    assert_eq!(manifest["crypto"]["semantics"], "exact");
    assert_eq!(manifest["crypto"]["scheme"], "TFHE");
    let security: serde_json::Value =
        serde_json::from_slice(&std::fs::read(a.join("security.json")).unwrap()).unwrap();
    assert_eq!(security["result_semantics"], "exact");
    assert_eq!(security["evaluator_receives_secret_key"], false);
    assert!(security.get("security_table").is_none(), "no CKKS fields");

    let loaded = Model::load(&a).unwrap();
    assert_eq!(loaded.compiled(), m.compiled());

    // Corruption and a changed plan kind are refused.
    let plan = a.join("plan.json");
    let text = std::fs::read_to_string(&plan).unwrap();
    std::fs::write(&plan, text.replace("\"cmp_scalar\"", "\"cmp\"")).unwrap();
    assert_eq!(Model::load(&a).err().unwrap().code, Code::Artifact);
    std::fs::write(&plan, &text).unwrap();
    let mpath = a.join("manifest.json");
    let mtext = std::fs::read_to_string(&mpath).unwrap();
    std::fs::write(&mpath, mtext.replace("\"exact\"", "\"ckks\"")).unwrap();
    let e = Model::load(&a).err().unwrap();
    assert_eq!(e.code, Code::Artifact);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Envelopes carry their scheme: CKKS data never enters an exact program
/// and exact data never enters a CKKS program, whatever the backend says.
#[test]
fn schemes_do_not_cross() {
    let exact = approve();
    let ex = Model::compile(exact.clone()).unwrap();
    let ex_client = ex.new_client(Mode::Mock).unwrap();
    let mut ex_eval = EvaluatorSession::new(exact.clone(), BackendKind::Mock).unwrap();
    ex_eval
        .register_keys(ex_client.evaluation_keys().unwrap())
        .unwrap();

    let approx = logistic(8, 1);
    let (ckks_client, ckks_eval) = mock_sessions(&approx, None, 1);

    // CKKS evaluation keys and inputs → exact program.
    assert_eq!(
        ex_eval
            .register_keys(ckks_client.evaluation_keys().unwrap())
            .unwrap_err()
            .code,
        Code::Incompatible
    );
    let ckks_req = ckks_client
        .encrypt(&approx, &sample_inputs(&approx, 2, 0))
        .unwrap();
    assert_eq!(
        ex_eval.execute(&ckks_req).unwrap_err().code,
        Code::Incompatible
    );
    // Exact inputs → CKKS program.
    let ex_req = ex_client
        .encrypt(&exact, &inputs(30.0, 1e5, 1e3, 100.0))
        .unwrap();
    assert_eq!(
        ckks_eval.execute(&ex_req).unwrap_err().code,
        Code::Incompatible
    );
    // An exact secret key does not restore as a CKKS client.
    let ckks_model = Model::compile(approx).unwrap();
    assert!(ClientSession::restore(
        ckks_model.ids(),
        ckks_model.compiled(),
        &ex_client.secret_key_envelope().unwrap()
    )
    .is_err());
    // The mock cannot pretend to be OpenFHE or TFHE-rs for the wrong scheme.
    assert_eq!(
        EvaluatorSession::new(exact, BackendKind::OpenFhe)
            .err()
            .unwrap()
            .code,
        Code::Backend
    );
}

#[test]
fn exact_bindings_key_program_parameters() {
    let p = approve();
    let m = Model::compile(p.clone()).unwrap();
    let client = m.new_client(Mode::Mock).unwrap();
    let mut ev = EvaluatorSession::new(p.clone(), BackendKind::Mock).unwrap();
    ev.register_keys(client.evaluation_keys().unwrap()).unwrap();
    let x = inputs(40.0, 5e5, 1e3, 10.0);
    let request = client.encrypt(&p, &x).unwrap();
    let (response, _) = ev.execute(&request).unwrap();
    assert_eq!(client.decrypt(&response).unwrap()["approved"], vec![1.0]);

    // Another client's key.
    let other = m.new_client(Mode::Mock).unwrap();
    assert_ne!(other.key_id(), client.key_id());
    assert_eq!(
        ev.execute(&other.encrypt(&p, &x).unwrap())
            .unwrap_err()
            .code,
        Code::WrongKey
    );
    assert_eq!(other.decrypt(&response).unwrap_err().code, Code::WrongKey);

    // Another program (a different threshold).
    let p2 = Program::to_string(&p).replace("[18.0]", "[21.0]");
    let p2 = encompute_ir::parse(&p2).unwrap();
    let mut ev2 = EvaluatorSession::new(p2, BackendKind::Mock).unwrap();
    ev2.register_keys(client.evaluation_keys().unwrap())
        .unwrap();
    assert_eq!(ev2.execute(&request).unwrap_err().code, Code::WrongProgram);

    // Corrupted request.
    let mut bad = request.clone();
    let n = bad.len();
    bad[n - 40] ^= 1;
    assert_eq!(ev.execute(&bad).unwrap_err().code, Code::Envelope);

    // Out-of-range and non-integer inputs never get encrypted.
    assert_eq!(
        client
            .encrypt(&p, &inputs(121.0, 1.0, 1.0, 1.0))
            .unwrap_err()
            .code,
        Code::BadInput
    );
    assert_eq!(
        client
            .encrypt(&p, &inputs(20.5, 1.0, 1.0, 1.0))
            .unwrap_err()
            .code,
        Code::BadInput
    );
    assert_eq!(
        evaluate(&p, &x).unwrap()["approved"],
        client.decrypt(&response).unwrap()["approved"]
    );
}

#[test]
fn exact_remote_round_trip() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    std::thread::spawn(move || Evaluator::new(Backends::MOCK, Limits::default()).serve(server));
    let remote = Remote::new(&url);
    let info = remote.info().unwrap();
    assert_eq!(info["backends"]["exact"]["scheme"], "TFHE");

    let m = Model::compile(approve()).unwrap();
    let client = m.new_client(Mode::Mock).unwrap();
    let trusted = remote.evaluator_identity().unwrap();
    for (x, want) in [
        (inputs(31.0, 120_000.0, 21_000.0, 400.0), 1.0),
        (inputs(17.0, 120_000.0, 21_000.0, 400.0), 0.0),
    ] {
        let run = remote
            .run(&client, m.program(), None, &x, &trusted)
            .unwrap();
        assert_eq!(run.outputs["approved"], vec![want]);
        assert!(run.stats.request_bytes > 0);
        assert_eq!(run.receipt.receipt.scheme, "TFHE");
    }
    let programs = remote.info().unwrap()["programs"].clone();
    assert_eq!(programs[0]["scheme"], "TFHE");
    assert_eq!(programs[0]["backend"], "mock");
}

/// Research build: the same program on TFHE-rs, locally and through an HTTP
/// evaluator that holds only the server key. `ENCOMPUTE_EXACT_CASES` sets
/// the differential-test size (default 20).
#[cfg(feature = "tfhe-rs")]
#[test]
fn tfhe_rs_end_to_end() {
    let m = Model::compile(approve()).unwrap();
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

/// Integer sampling stays inside ranges wider than 2^53.
#[test]
fn wide_exact_ranges_sample_in_range() {
    let mut b = Builder::new("wide", 1e-3).unwrap();
    let (lo, hi) = (-9007199254740992.0, 9007199254740987.0);
    let x = b
        .input_exact("x", Elem::I64, Some(Range::new(lo, hi)))
        .unwrap();
    let k = b.constant_exact(Elem::I64, 2.0).unwrap();
    let y = b.div(x, k).unwrap();
    b.output("y", y).unwrap();
    let p = b.finish().unwrap();
    for case in 0..5000 {
        let v = sample_inputs(&p, case, 9)["x"][0];
        assert!(
            (lo..=hi).contains(&v) && v.fract() == 0.0,
            "case {case}: {v}"
        );
    }
}
