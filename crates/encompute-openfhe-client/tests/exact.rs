//! OpenFHE exact (BinFHE) executes exact plans with results equal to the
//! clear reference and the mock, bit for bit.
//!
//! - `ENCOMPUTE_EXACT_CASES=N` runs the flagship on N inputs (default 3);
//! - `ENCOMPUTE_EXACT_PROGRAMS=N` runs N random programs (the mock tests'
//!   generator; default 0: each is minutes of gates).

#[path = "../../encompute-exact/tests/gen/mod.rs"]
mod gen;

use encompute_backend::{ExactClient, ExactEvaluator, PlainExactClient, PlainExactEvaluator};
use encompute_exact::{compile, evaluate_exact};
use encompute_ir::{evaluate, Builder, CmpOp, Code, Elem, Inputs, LogicOp, Program, Range};
use encompute_openfhe_client::OpenFheExactClient;
use encompute_openfhe_exact::{default_profile, evaluator, OpenFheExactEvaluator};

fn approve() -> Program {
    let mut b = Builder::new("approve", 1e-3).unwrap();
    let age = b
        .input_exact("age", Elem::U8, Some(Range::new(0.0, 120.0)))
        .unwrap();
    let income = b
        .input_exact("income", Elem::U32, Some(Range::new(0.0, 1e6)))
        .unwrap();
    let debt = b
        .input_exact("debt", Elem::U32, Some(Range::new(0.0, 1e6)))
        .unwrap();
    let risk = b
        .input_exact("risk", Elem::U16, Some(Range::new(0.0, 1000.0)))
        .unwrap();
    let c18 = b.constant_exact(Elem::U8, 18.0).unwrap();
    let c100 = b.constant_exact(Elem::U32, 100.0).unwrap();
    let c35 = b.constant_exact(Elem::U32, 35.0).unwrap();
    let c650 = b.constant_exact(Elem::U16, 650.0).unwrap();
    let adult = b.cmp(CmpOp::Ge, age, c18).unwrap();
    let d = b.mul(debt, c100).unwrap();
    let i = b.mul(income, c35).unwrap();
    let ok_debt = b.cmp(CmpOp::Lt, d, i).unwrap();
    let ok_risk = b.cmp(CmpOp::Lt, risk, c650).unwrap();
    let x = b.logic(LogicOp::And, adult, ok_debt).unwrap();
    let x = b.logic(LogicOp::And, x, ok_risk).unwrap();
    b.output("approved", x).unwrap();
    b.finish().unwrap()
}

/// Every exact op on one narrow type (ranges keep results in the type).
fn narrow(elem: Elem) -> Program {
    let signed = elem.is_signed();
    let (lo, hi) = if signed { (-5.0, 5.0) } else { (0.0, 10.0) };
    let mut b = Builder::new("narrow", 1e-3).unwrap();
    let x = b.input_exact("x", elem, Some(Range::new(lo, hi))).unwrap();
    let y = b.input_exact("y", elem, Some(Range::new(lo, hi))).unwrap();
    let k3 = b.constant_exact(elem, 3.0).unwrap();
    let k7 = b.constant_exact(elem, 7.0).unwrap();
    let k20 = b.constant_exact(elem, 20.0).unwrap();
    let mut outs = vec![];
    outs.push(("add", b.add(x, y).unwrap()));
    let xo = b.add(x, k20).unwrap();
    outs.push(("sub", b.sub(xo, y).unwrap()));
    outs.push(("mul", b.mul(x, y).unwrap()));
    outs.push(("mulc", b.mul(x, k3).unwrap()));
    outs.push(("csub", b.sub(k20, x).unwrap()));
    outs.push(("div", b.div(x, k3).unwrap()));
    outs.push(("rem", b.rem(x, k3).unwrap()));
    outs.push(("min", b.min(x, y).unwrap()));
    outs.push(("max", b.max(x, y).unwrap()));
    outs.push(("and", b.logic(LogicOp::And, x, y).unwrap()));
    outs.push(("xor", b.logic(LogicOp::Xor, x, y).unwrap()));
    outs.push(("shl", b.shift(x, true, 2).unwrap()));
    outs.push(("shr", b.shift(x, false, 1).unwrap()));
    let lt = b.cmp(CmpOp::Lt, x, y).unwrap();
    let eq = b.cmp(CmpOp::Eq, x, y).unwrap();
    let ge = b.cmp(CmpOp::Ge, x, k7).unwrap();
    outs.push(("lt", lt));
    outs.push(("eq", eq));
    outs.push(("ge", ge));
    outs.push(("or", b.logic(LogicOp::Or, lt, eq).unwrap()));
    outs.push(("nlt", b.not(lt).unwrap()));
    outs.push(("sel", b.select(lt, x, k7).unwrap()));
    outs.push(("b2i", b.cast(lt, Elem::U8).unwrap()));
    let idx = if signed { b.add(x, k7).unwrap() } else { x };
    let off = if signed { 5.0 } else { 0.0 };
    let table: Vec<f64> = (0..16).map(|i| ((i * 13) % 29) as f64 - off).collect();
    outs.push(("lut", b.lookup(idx, table).unwrap()));
    for (n, v) in outs {
        b.output(n, v).unwrap();
    }
    b.finish().unwrap()
}

fn run(
    client: &OpenFheExactClient,
    ev: &OpenFheExactEvaluator,
    p: &Program,
    inputs: &Inputs,
) -> Inputs {
    let c = compile(p).unwrap_or_else(|e| panic!("{e}\n{p}"));
    encompute_openfhe_exact::check_capabilities(&c.plan).unwrap();
    let cts = c
        .plan
        .inputs
        .iter()
        .map(|i| {
            ev.load(
                i.elem,
                &client.encrypt(i.elem, inputs[&i.name][0] as i128).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let outs = evaluate_exact(ev, &c.plan, cts).unwrap();
    c.plan
        .outputs
        .iter()
        .zip(outs)
        .map(|(o, ct)| {
            let v = client
                .decrypt(o.elem, &ev.store(&ct).unwrap())
                .unwrap_or_else(|e| panic!("output {} ({}): {e}", o.name, o.elem));
            (o.name.clone(), vec![v as f64])
        })
        .collect()
}

/// The mock on the same plan: clear == mock == OpenFHE.
fn mock(p: &Program, inputs: &Inputs) -> Inputs {
    let client = PlainExactClient::new(1);
    let ev = PlainExactEvaluator::new(&client.evaluation_keys().unwrap()).unwrap();
    let c = compile(p).unwrap();
    let cts = c
        .plan
        .inputs
        .iter()
        .map(|i| {
            ev.load(
                i.elem,
                &client.encrypt(i.elem, inputs[&i.name][0] as i128).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let outs = evaluate_exact(&ev, &c.plan, cts).unwrap();
    c.plan
        .outputs
        .iter()
        .zip(outs)
        .map(|(o, ct)| {
            (
                o.name.clone(),
                vec![client.decrypt(o.elem, &ev.store(&ct).unwrap()).unwrap() as f64],
            )
        })
        .collect()
}

fn lcg(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *s >> 33
}

fn setup() -> (OpenFheExactClient, OpenFheExactEvaluator) {
    let client = OpenFheExactClient::generate().unwrap();
    let keys = client.evaluation_keys().unwrap();
    eprintln!("evaluation keys: {} MiB", keys.len() >> 20);
    let ev = evaluator(&default_profile(), &keys).unwrap();
    (client, ev)
}

#[test]
fn openfhe_exact_equals_clear_reference_and_mock() {
    let (client, ev) = setup();
    for elem in [Elem::U8, Elem::I8] {
        let p = narrow(elem);
        let (lo, hi) = if elem.is_signed() { (-5, 5) } else { (0, 10) };
        for (x, y) in [(lo, hi), (hi, lo), (3, 3)] {
            let t = std::time::Instant::now();
            let g0 = ev.gate_count();
            let inputs: Inputs = [("x", x), ("y", y)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), vec![v as f64]))
                .collect();
            let got = run(&client, &ev, &p, &inputs);
            assert_eq!(got, evaluate(&p, &inputs).unwrap(), "{elem} x={x} y={y}");
            assert_eq!(got, mock(&p, &inputs), "{elem} x={x} y={y}");
            eprintln!(
                "{elem} x={x} y={y}: exact, {} gates in {:.1?}",
                ev.gate_count() - g0,
                t.elapsed()
            );
        }
    }
    let cases: usize = std::env::var("ENCOMPUTE_EXACT_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let p = approve();
    let mut s = 42u64;
    for case in 0..cases {
        let v = |s: &mut u64, hi: u64| match case {
            0 => 0,
            1 => hi,
            _ => lcg(s) % (hi + 1),
        } as f64;
        let inputs: Inputs = [
            ("age", v(&mut s, 120)),
            ("income", v(&mut s, 1_000_000)),
            ("debt", v(&mut s, 400_000)),
            ("risk", v(&mut s, 1000)),
        ]
        .into_iter()
        .map(|(k, x)| (k.to_string(), vec![x]))
        .collect();
        let t = std::time::Instant::now();
        let g0 = ev.gate_count();
        let got = run(&client, &ev, &p, &inputs);
        assert_eq!(
            got,
            evaluate(&p, &inputs).unwrap(),
            "case {case}: {inputs:?}"
        );
        eprintln!(
            "flagship case {case}: {} ({} gates in {:.1?})",
            got["approved"][0],
            ev.gate_count() - g0,
            t.elapsed()
        );
    }
}

/// The mock tests' random programs, on OpenFHE exact.
#[test]
fn random_programs_on_openfhe_exact() {
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
    let n: usize = std::env::var("ENCOMPUTE_EXACT_PROGRAMS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if n == 0 {
        return;
    }
    let (client, ev) = setup();
    let mut runner = TestRunner::new_with_rng(
        Config::default(),
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let mut done = 0;
    while done < n {
        let (p, decl) = gen::arb_program().new_tree(&mut runner).unwrap().current();
        let Ok(c) = compile(&p) else { continue };
        if encompute_openfhe_exact::check_capabilities(&c.plan).is_err() {
            continue;
        }
        let inputs = gen::inputs_for(&decl, 0, done as u64);
        assert_eq!(
            run(&client, &ev, &p, &inputs),
            evaluate(&p, &inputs).unwrap(),
            "{p}\n{inputs:?}"
        );
        done += 1;
    }
}

#[test]
fn wrong_keys_parameters_backends_and_corruption_fail_closed() {
    let (client, ev) = setup();
    let ct = client.encrypt(Elem::U8, 7).unwrap();
    assert_eq!(client.decrypt(Elem::U8, &ct).unwrap(), 7);
    // Truncated, corrupted, wrong type, garbage.
    assert_eq!(
        ev.load(Elem::U8, &ct[..ct.len() / 2]).err().unwrap().code,
        Code::Envelope
    );
    let mut bad = ct.clone();
    bad[ct.len() / 2] ^= 1;
    assert_eq!(
        ev.load(Elem::U8, &bad).err().unwrap().code,
        Code::Envelope,
        "corrupted"
    );
    assert!(ev.load(Elem::U16, &ct).is_err(), "wrong type");
    assert!(ev.load(Elem::U8, b"garbage").is_err());
    // Another key's ciphertext.
    let other = OpenFheExactClient::generate().unwrap();
    let foreign = other.encrypt(Elem::U8, 7).unwrap();
    assert_eq!(
        ev.load(Elem::U8, &foreign).err().unwrap().code,
        Code::WrongKey
    );
    assert_eq!(
        client.decrypt(Elem::U8, &foreign).err().unwrap().code,
        Code::WrongKey
    );
    // Another backend's or profile's objects.
    let mock_ct = PlainExactClient::new(1).encrypt(Elem::U8, 7).unwrap();
    assert!(ev.load(Elem::U8, &mock_ct).is_err());
    let mut profile = default_profile();
    profile.profile = "TOY".into();
    assert_eq!(
        evaluator(&profile, &client.evaluation_keys().unwrap())
            .err()
            .unwrap()
            .code,
        Code::WrongParameters
    );
    assert!(evaluator(&default_profile(), b"not keys").is_err());
    // Restore: decrypts, and does not re-export keys.
    let restored = OpenFheExactClient::restore(&client.secret_key().unwrap()).unwrap();
    assert_eq!(restored.decrypt(Elem::U8, &ct).unwrap(), 7);
    assert!(restored.evaluation_keys().is_err());
    assert!(OpenFheExactClient::restore(b"not a key").is_err());
    // Signed values round-trip through two's complement.
    for v in [-128i128, -1, 0, 1, 127] {
        assert_eq!(
            client
                .decrypt(Elem::I8, &client.encrypt(Elem::I8, v).unwrap())
                .unwrap(),
            v
        );
    }
}

/// Semantic transcripts describe the plan, not the backend: OpenFHE exact,
/// the mock and the plan alone give the same transcript.
#[test]
fn transcripts_are_backend_independent() {
    use encompute_exact::{
        evaluate_exact_observed, semantic_transcript, ExecutionContext, TranscriptObserver,
    };
    let (client, ev) = setup();
    let p = approve();
    let c = compile(&p).unwrap();
    let ctx = ExecutionContext {
        spec_id: "ab".repeat(32),
    };
    let inputs = [31i128, 120_000, 21_000, 400];
    let mut on_openfhe = TranscriptObserver::default();
    let cts = c
        .plan
        .inputs
        .iter()
        .zip(inputs)
        .map(|(i, v)| {
            ev.load(i.elem, &client.encrypt(i.elem, v).unwrap())
                .unwrap()
        })
        .collect();
    evaluate_exact_observed(&ev, &c.plan, cts, &ctx, &mut on_openfhe).unwrap();
    let mclient = PlainExactClient::new(3);
    let mev = PlainExactEvaluator::new(&mclient.evaluation_keys().unwrap()).unwrap();
    let mut on_mock = TranscriptObserver::default();
    let mcts = c
        .plan
        .inputs
        .iter()
        .zip(inputs)
        .map(|(i, v)| {
            mev.load(i.elem, &mclient.encrypt(i.elem, v).unwrap())
                .unwrap()
        })
        .collect();
    evaluate_exact_observed(&mev, &c.plan, mcts, &ctx, &mut on_mock).unwrap();
    let a = on_openfhe.into_transcript().unwrap();
    assert_eq!(a, on_mock.into_transcript().unwrap());
    assert_eq!(a, semantic_transcript(&c.plan, &ctx.spec_id));
}
