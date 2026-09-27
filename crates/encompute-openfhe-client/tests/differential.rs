//! Release gate: the four executions of an exact program agree bit for bit.
//!
//!   clear interpreter == mock == OpenFHE optimized circuit == OpenFHE
//!   reference lowering
//!
//! on three program sets: a fixed seed set of random exact programs (the
//! generator of `encompute-exact/tests/gen`), the exact benchmark corpus
//! (`benches/exact`, the golden programs included), and boundary programs
//! whose inputs sit at the types' extremes. Every case is also checked on
//! plaintext bits (the reference lowering and the optimized circuit on
//! clear gates), which is cheap and covers every input case.
//!
//! The OpenFHE part is bounded (about ten minutes in release on eight
//! threads) and runs from `scripts/release/differential-gate.sh`:
//!
//! - `ENCOMPUTE_GATE_PROGRAMS` random programs (default 6), each with at
//!   most `ENCOMPUTE_GATE_MAX_GATES` reference gates (default 250);
//! - `ENCOMPUTE_GATE_WORKERS` gate workers (default 8);
//! - `ENCOMPUTE_GATE_CORPUS=all` runs the whole corpus (default: the three
//!   golden programs).
//!
//! With `--features research-tfhe-rs` (research CI only), TFHE-rs runs the
//! same plans too; production builds never reference TFHE-rs.

#[path = "../../encompute-exact/tests/corpus/mod.rs"]
mod corpus;
#[path = "../../encompute-exact/tests/gen/mod.rs"]
mod gen;

use std::time::Instant;

use encompute_backend::{ExactClient, ExactEvaluator, PlainExactClient, PlainExactEvaluator};
use encompute_exact::bits::{gate_count, BitEvaluator, PlainGates, Strategy};
use encompute_exact::circuit::{
    build, execute, optimize, plain_bits, plain_value, Circuit, Interval, PlainCircuitGates,
};
use encompute_exact::{compile, evaluate_exact, ExactPlan};
use encompute_ir::{evaluate, Builder, CmpOp, Elem, Inputs, LogicOp, Program, Range};

/// One program of the gate, compiled, with its input cases. On OpenFHE,
/// the optimized circuits run the first `openfhe_cases` cases and the
/// reference lowering (sequential, the slowest execution) the first
/// `reference_cases`; on plaintext bits every execution runs all of them.
struct GateCase {
    set: &'static str,
    name: String,
    program: Program,
    plan: ExactPlan,
    ranges: Vec<Option<Interval>>,
    cases: Vec<Inputs>,
    openfhe_cases: usize,
    reference_cases: usize,
}

fn env_num(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn ranges(p: &Program, plan: &ExactPlan) -> Vec<Option<Interval>> {
    corpus::input_ranges(p, plan)
}

fn named(vals: &[(&str, i128)]) -> Inputs {
    vals.iter()
        .map(|(k, v)| (k.to_string(), vec![*v as f64]))
        .collect()
}

// --- the program sets ------------------------------------------------------------

/// A fixed seed set of random programs, each at most `max_gates` reference
/// gates (so the sequential OpenFHE reference stays bounded).
fn random_programs(count: usize, max_gates: u64) -> Vec<GateCase> {
    use proptest::strategy::{Strategy as _, ValueTree};
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
    let mut runner = TestRunner::new_with_rng(
        Config::default(),
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let mut out = vec![];
    let mut drawn = 0u64;
    while out.len() < count {
        drawn += 1;
        assert!(
            drawn < 100_000,
            "the generator yields too few small programs"
        );
        let (p, decl) = gen::arb_program().new_tree(&mut runner).unwrap().current();
        let Ok(c) = compile(&p) else { continue };
        if encompute_exact::bits::check_capabilities(&c.plan).is_err() {
            continue;
        }
        let g = gate_count(&c.plan).unwrap();
        // Programs whose outputs are all constants test nothing encrypted.
        if g == 0 || g > max_gates {
            continue;
        }
        let rg = ranges(&p, &c.plan);
        let seed = 0x6a7e_u64 ^ drawn;
        // Low ends, high ends, then pseudo-random (a quarter at the ends).
        let cases = (0..4).map(|k| gen::inputs_for(&decl, k, seed)).collect();
        out.push(GateCase {
            set: "random",
            name: format!("random-{}", out.len()),
            program: p,
            plan: c.plan,
            ranges: rg,
            cases,
            openfhe_cases: 4,
            reference_cases: 1,
        });
    }
    out
}

/// The benchmark corpus: its own deterministic cases (low ends, high ends,
/// alternating ends, then pseudo-random); the first three on OpenFHE.
fn corpus_programs(all: bool) -> Vec<GateCase> {
    corpus::load()
        .into_iter()
        .filter(|e| all || corpus::GOLDEN.contains(&e.name.as_str()))
        .map(|e| GateCase {
            set: "corpus",
            name: e.name.clone(),
            cases: corpus::cases(&e),
            program: e.program,
            plan: e.plan,
            ranges: e.ranges,
            openfhe_cases: 3,
            reference_cases: 1,
        })
        .collect()
}

/// Two-input programs at the types' extremes: the full range of `i8`,
/// `u8` and `i64`, where sign handling, carries out of the top bit and
/// truncating division are easiest to get wrong.
fn boundary_programs() -> Vec<GateCase> {
    let mut out = vec![];

    // i8, full range: order, equality, min/max, bitwise, shifts, and
    // widened arithmetic (i8 op i8 fits i16), division toward zero,
    // remainder with the dividend's sign, negation of -128 (widened).
    let mut b = Builder::new("boundary_i8", 1e-3).unwrap();
    let x = b
        .input_exact("x", Elem::I8, Some(Range::new(-128.0, 127.0)))
        .unwrap();
    let y = b
        .input_exact("y", Elem::I8, Some(Range::new(-128.0, 127.0)))
        .unwrap();
    let outs = [
        ("lt", b.cmp(CmpOp::Lt, x, y).unwrap()),
        ("ge", b.cmp(CmpOp::Ge, x, y).unwrap()),
        ("eq", b.cmp(CmpOp::Eq, x, y).unwrap()),
        ("min", b.min(x, y).unwrap()),
        ("max", b.max(x, y).unwrap()),
        ("xor", b.logic(LogicOp::Xor, x, y).unwrap()),
        ("not", b.not(x).unwrap()),
        ("shr", b.shift(x, false, 7).unwrap()),
    ];
    for (n, v) in outs {
        b.output(n, v).unwrap();
    }
    let xw = b.cast(x, Elem::I16).unwrap();
    let yw = b.cast(y, Elem::I16).unwrap();
    let k7 = b.constant_exact(Elem::I16, 7.0).unwrap();
    let km7 = b.constant_exact(Elem::I16, -7.0).unwrap();
    let wide = [
        ("add", b.add(xw, yw).unwrap()),
        ("sub", b.sub(xw, yw).unwrap()),
        ("neg", b.neg(xw).unwrap()),
        ("div", b.div(xw, km7).unwrap()),
        ("rem", b.rem(xw, k7).unwrap()),
    ];
    for (n, v) in wide {
        b.output(n, v).unwrap();
    }
    let p = b.finish().unwrap();
    let vals = [-128i128, 127, -1, 0, 1, -127];
    let mut cases = vec![
        named(&[("x", -128), ("y", 127)]),
        named(&[("x", 127), ("y", -128)]),
    ];
    for &x in &vals {
        for &y in &[-128i128, 127, 0, -1] {
            let c = named(&[("x", x), ("y", y)]);
            if !cases.contains(&c) {
                cases.push(c);
            }
        }
    }
    out.push(boundary_case(p, cases, 8, 1));

    // u8, full range: unsigned order at 0 and 255, carries out of the top
    // bit (widened), a constant subtraction, division, a lookup at the
    // table's ends.
    let mut b = Builder::new("boundary_u8", 1e-3).unwrap();
    let x = b
        .input_exact("x", Elem::U8, Some(Range::new(0.0, 255.0)))
        .unwrap();
    let y = b
        .input_exact("y", Elem::U8, Some(Range::new(0.0, 255.0)))
        .unwrap();
    let k15 = b.constant_exact(Elem::U8, 15.0).unwrap();
    let k255 = b.constant_exact(Elem::U8, 255.0).unwrap();
    let k3 = b.constant_exact(Elem::U8, 3.0).unwrap();
    let low = b.logic(LogicOp::And, x, k15).unwrap();
    let table: Vec<f64> = (0..16).map(|i| ((i * 37) % 251) as f64).collect();
    let outs = [
        ("lt", b.cmp(CmpOp::Lt, x, y).unwrap()),
        ("le", b.cmp(CmpOp::Le, x, y).unwrap()),
        ("ne", b.cmp(CmpOp::Ne, x, y).unwrap()),
        ("max", b.max(x, y).unwrap()),
        ("csub", b.sub(k255, x).unwrap()),
        ("div", b.div(x, k3).unwrap()),
        ("rem", b.rem(y, k3).unwrap()),
        ("shl", b.shift(low, true, 4).unwrap()),
        ("lut", b.lookup(low, table).unwrap()),
    ];
    for (n, v) in outs {
        b.output(n, v).unwrap();
    }
    let xw = b.cast(x, Elem::U16).unwrap();
    let yw = b.cast(y, Elem::U16).unwrap();
    let s = b.add(xw, yw).unwrap();
    b.output("sum", s).unwrap();
    let p = b.finish().unwrap();
    let mut cases = vec![
        named(&[("x", 255), ("y", 255)]),
        named(&[("x", 0), ("y", 255)]),
    ];
    for &x in &[0i128, 1, 254, 255, 128, 127] {
        for &y in &[0i128, 255, 128] {
            let c = named(&[("x", x), ("y", y)]);
            if !cases.contains(&c) {
                cases.push(c);
            }
        }
    }
    out.push(boundary_case(p, cases, 7, 1));

    // i64 near the extremes the API admits (±2^53: exact in an f64):
    // signed order and equality at 64 bits, min, and an arithmetic shift.
    let lim = (1i128 << 53) as f64;
    let mut b = Builder::new("boundary_i64", 1e-3).unwrap();
    let x = b
        .input_exact("x", Elem::I64, Some(Range::new(-lim, lim)))
        .unwrap();
    let y = b
        .input_exact("y", Elem::I64, Some(Range::new(-lim, lim)))
        .unwrap();
    let outs = [
        ("lt", b.cmp(CmpOp::Lt, x, y).unwrap()),
        ("eq", b.cmp(CmpOp::Eq, x, y).unwrap()),
        ("min", b.min(x, y).unwrap()),
        ("shr", b.shift(x, false, 52).unwrap()),
    ];
    for (n, v) in outs {
        b.output(n, v).unwrap();
    }
    let p = b.finish().unwrap();
    let m = 1i128 << 53;
    let cases = vec![
        named(&[("x", -m), ("y", m)]),
        named(&[("x", m), ("y", -m)]),
        named(&[("x", -1), ("y", 0)]),
        named(&[("x", m), ("y", m)]),
        named(&[("x", -m), ("y", -m + 1)]),
    ];
    out.push(boundary_case(p, cases, 5, 1));
    out
}

fn boundary_case(
    p: Program,
    cases: Vec<Inputs>,
    openfhe_cases: usize,
    reference_cases: usize,
) -> GateCase {
    let plan = compile(&p)
        .unwrap_or_else(|e| panic!("{}: {e}", p.name()))
        .plan;
    for inputs in &cases {
        encompute_ir::check_inputs(&p, inputs)
            .unwrap_or_else(|e| panic!("{}: {inputs:?}: {e}", p.name()));
    }
    GateCase {
        set: "boundary",
        name: p.name().to_owned(),
        ranges: ranges(&p, &plan),
        program: p,
        plan,
        cases,
        openfhe_cases,
        reference_cases,
    }
}

// --- executions without OpenFHE ------------------------------------------------------

fn mock(case: &GateCase, inputs: &Inputs) -> Inputs {
    let client = PlainExactClient::new(7);
    let ev = PlainExactEvaluator::new(&client.evaluation_keys().unwrap()).unwrap();
    let cts = case
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
    let outs = evaluate_exact(&ev, &case.plan, cts).unwrap();
    case.plan
        .outputs
        .iter()
        .zip(outs)
        .map(|(o, ct)| {
            let v = client.decrypt(o.elem, &ev.store(&ct).unwrap()).unwrap();
            (o.name.clone(), vec![v as f64])
        })
        .collect()
}

/// The reference lowering on plaintext bits.
fn plain_reference(case: &GateCase, inputs: &Inputs) -> Inputs {
    let ev = BitEvaluator::with_strategy(PlainGates, Strategy::REFERENCE);
    let words = case
        .plan
        .inputs
        .iter()
        .map(|i| encompute_exact::bits::plain_word(i.elem, inputs[&i.name][0] as i128))
        .collect();
    let outs = evaluate_exact(&ev, &case.plan, words).unwrap();
    case.plan
        .outputs
        .iter()
        .zip(outs)
        .map(|(o, w)| {
            (
                o.name.clone(),
                vec![encompute_exact::bits::plain_value(&w) as f64],
            )
        })
        .collect()
}

/// A circuit on plaintext bits.
fn plain_circuit(case: &GateCase, c: &Circuit, inputs: &Inputs, workers: usize) -> Inputs {
    let bits: Vec<Vec<bool>> = case
        .plan
        .inputs
        .iter()
        .map(|i| plain_bits(i.elem, inputs[&i.name][0] as i128))
        .collect();
    let out = execute(c, &PlainCircuitGates, &bits, workers).unwrap();
    case.plan
        .outputs
        .iter()
        .zip(out)
        .map(|(o, b)| (o.name.clone(), vec![plain_value(o.elem, &b) as f64]))
        .collect()
}

/// The circuits the gate runs: the optimizer's choice for `workers`, and
/// the parallel strategy when the optimizer chose the reference one (so
/// the prefix adders and tree comparators always run).
fn circuits(case: &GateCase, workers: u32) -> Vec<Circuit> {
    let best = optimize(&case.plan, &case.ranges, workers).unwrap();
    let mut out = vec![best];
    if out[0].strategy != Strategy::PARALLEL {
        out.push(build(&case.plan, &case.ranges, Strategy::PARALLEL).unwrap());
    }
    out
}

/// Clear == mock == reference lowering (plain bits) == every circuit
/// (plain bits, one and several workers), on every case.
fn check_plain(case: &GateCase) {
    let cs = circuits(case, 8);
    for inputs in &case.cases {
        let want = evaluate(&case.program, inputs).unwrap();
        let what = format!("{} {} {inputs:?}", case.set, case.name);
        assert_eq!(mock(case, inputs), want, "mock: {what}");
        assert_eq!(
            plain_reference(case, inputs),
            want,
            "reference lowering: {what}"
        );
        for c in &cs {
            for w in [1, 8] {
                assert_eq!(
                    plain_circuit(case, c, inputs, w),
                    want,
                    "circuit {:?}, {w} workers: {what}",
                    c.strategy
                );
            }
        }
    }
}

fn all_cases() -> Vec<GateCase> {
    let mut v = random_programs(
        env_num("ENCOMPUTE_GATE_PROGRAMS", 6),
        env_num("ENCOMPUTE_GATE_MAX_GATES", 250) as u64,
    );
    v.extend(corpus_programs(
        std::env::var("ENCOMPUTE_GATE_CORPUS").as_deref() == Ok("all"),
    ));
    v.extend(boundary_programs());
    v
}

/// The gate's program set without OpenFHE (fast; runs in every test run):
/// clear == mock == reference lowering == optimized circuits, on plaintext
/// bits, for every case of every program the OpenFHE gate runs.
#[test]
fn gate_programs_agree_on_plaintext_bits() {
    let set = all_cases();
    let mut n = 0;
    let (mut ref_gates, mut opt_gates) = (0u64, 0u64);
    for case in &set {
        check_plain(case);
        n += case.cases.len();
        let cs = circuits(case, 8);
        let k = case.openfhe_cases.min(case.cases.len()) as u64;
        ref_gates +=
            gate_count(&case.plan).unwrap() * case.reference_cases.min(case.cases.len()) as u64;
        opt_gates += cs[0].stats.gates * k + cs[1..].iter().map(|c| c.stats.gates).sum::<u64>();
    }
    // The OpenFHE gate's work: the reference is sequential (about 60 ms
    // per gate on an Apple M3 Max), the optimized circuits levelized.
    eprintln!(
        "OpenFHE gate budget: reference lowering {ref_gates} gates, optimized circuits {opt_gates} gates"
    );
    // The whole corpus too (its six cases each): cheap on plaintext.
    for e in corpus::load() {
        let case = GateCase {
            set: "corpus",
            name: e.name.clone(),
            cases: corpus::cases(&e),
            program: e.program,
            plan: e.plan,
            ranges: e.ranges,
            openfhe_cases: 0,
            reference_cases: 0,
        };
        check_plain(&case);
        n += case.cases.len();
    }
    eprintln!("plaintext gate: {} programs, {n} cases agree", set.len());
    assert!(set.iter().any(|c| c.set == "random"));
    assert!(set.iter().filter(|c| c.set == "corpus").count() >= 3);
    assert!(set.iter().filter(|c| c.set == "boundary").count() >= 3);
}

// --- the OpenFHE gate ------------------------------------------------------------

#[cfg(feature = "research-tfhe-rs")]
mod research {
    //! TFHE-rs (research only: Zama's patent license) on the same plans.
    use super::*;
    use encompute_tfhe::tfhe_rs::TfheRsEvaluator;
    use encompute_tfhe_client::TfheRsClient;

    pub(super) struct Tfhe {
        client: TfheRsClient,
        ev: TfheRsEvaluator,
    }

    impl Tfhe {
        pub(super) fn new() -> Self {
            let client = TfheRsClient::generate().unwrap();
            let ev = TfheRsEvaluator::new(&client.evaluation_keys().unwrap()).unwrap();
            Self { client, ev }
        }

        pub(super) fn run(&self, case: &GateCase, inputs: &Inputs) -> Inputs {
            let cts = case
                .plan
                .inputs
                .iter()
                .map(|i| {
                    self.ev
                        .load(
                            i.elem,
                            &self
                                .client
                                .encrypt(i.elem, inputs[&i.name][0] as i128)
                                .unwrap(),
                        )
                        .unwrap()
                })
                .collect();
            let outs = evaluate_exact(&self.ev, &case.plan, cts).unwrap();
            case.plan
                .outputs
                .iter()
                .zip(outs)
                .map(|(o, ct)| {
                    let v = self
                        .client
                        .decrypt(o.elem, &self.ev.store(&ct).unwrap())
                        .unwrap();
                    (o.name.clone(), vec![v as f64])
                })
                .collect()
        }
    }
}

/// The release gate on OpenFHE (minutes: run it with
/// `scripts/release/differential-gate.sh`).
#[test]
#[ignore = "release gate (about ten minutes in release): scripts/release/differential-gate.sh"]
fn openfhe_differential_gate() {
    use encompute_openfhe_client::OpenFheExactClient;
    use encompute_openfhe_exact::{default_profile, evaluator};

    let workers = env_num("ENCOMPUTE_GATE_WORKERS", 8);
    let start = Instant::now();
    let set = all_cases();
    for case in &set {
        check_plain(case);
    }
    let client = OpenFheExactClient::generate().unwrap();
    let keys = client.evaluation_keys().unwrap();
    let ev = evaluator(&default_profile(), &keys).unwrap();
    eprintln!(
        "keys: {} MiB, ready in {:.1?}",
        keys.len() >> 20,
        start.elapsed()
    );
    #[cfg(feature = "research-tfhe-rs")]
    let tfhe = research::Tfhe::new();

    let (mut ref_runs, mut opt_runs, mut ref_gates, mut opt_gates) = (0u64, 0u64, 0u64, 0u64);
    let decrypt = |plan: &ExactPlan, outs: &[Vec<u8>]| -> Inputs {
        plan.outputs
            .iter()
            .zip(outs)
            .map(|(o, b)| {
                let v = client
                    .decrypt(o.elem, b)
                    .unwrap_or_else(|e| panic!("output {} ({}): {e}", o.name, o.elem));
                (o.name.clone(), vec![v as f64])
            })
            .collect()
    };
    for case in &set {
        let t = Instant::now();
        encompute_openfhe_exact::check_capabilities(&case.plan).unwrap();
        let cs = circuits(case, workers as u32);
        for (k, inputs) in case.cases.iter().take(case.openfhe_cases).enumerate() {
            let what = format!("{} {} {inputs:?}", case.set, case.name);
            let want = evaluate(&case.program, inputs).unwrap();
            assert_eq!(mock(case, inputs), want, "mock: {what}");
            let enc: Vec<Vec<u8>> = case
                .plan
                .inputs
                .iter()
                .map(|i| client.encrypt(i.elem, inputs[&i.name][0] as i128).unwrap())
                .collect();
            // The reference lowering, instruction by instruction.
            if k < case.reference_cases {
                let g0 = ev.gate_count();
                let cts = case
                    .plan
                    .inputs
                    .iter()
                    .zip(&enc)
                    .map(|(i, b)| ev.load(i.elem, b).unwrap())
                    .collect();
                let outs: Vec<Vec<u8>> = evaluate_exact(&ev, &case.plan, cts)
                    .unwrap()
                    .iter()
                    .map(|ct| ev.store(ct).unwrap())
                    .collect();
                assert_eq!(
                    decrypt(&case.plan, &outs),
                    want,
                    "OpenFHE reference: {what}"
                );
                ref_runs += 1;
                ref_gates += ev.gate_count() - g0;
            }
            // The optimized circuits, levelized on `workers` threads.
            let refs: Vec<(Elem, &[u8])> = case
                .plan
                .inputs
                .iter()
                .zip(&enc)
                .map(|(i, b)| (i.elem, b.as_slice()))
                .collect();
            // Every case on the optimizer's choice; the extra parallel
            // circuit on the first case.
            for c in cs.iter().take(if k == 0 { cs.len() } else { 1 }) {
                let outs = ev.gates.run_circuit(c, &refs, workers).unwrap();
                assert_eq!(
                    decrypt(&case.plan, &outs),
                    want,
                    "OpenFHE optimized ({:?}, {workers} workers): {what}",
                    c.strategy
                );
                opt_runs += 1;
                opt_gates += c.stats.gates;
            }
            #[cfg(feature = "research-tfhe-rs")]
            assert_eq!(tfhe.run(case, inputs), want, "TFHE-rs: {what}");
        }
        eprintln!(
            "{:<9} {:<20} {} cases ({} on the reference): clear == mock == OpenFHE reference == OpenFHE optimized [{:.1?}]",
            case.set,
            case.name,
            case.openfhe_cases.min(case.cases.len()),
            case.reference_cases.min(case.cases.len()),
            t.elapsed()
        );
    }
    eprintln!(
        "DIFFERENTIAL GATE PASSED: {} programs; OpenFHE reference {ref_runs} runs ({ref_gates} gates), optimized {opt_runs} runs ({opt_gates} gates), {workers} workers, {:.1?}",
        set.len(),
        start.elapsed()
    );
}
