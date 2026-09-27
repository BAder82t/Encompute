//! The optimized execution plan (circuit DAG) against the reference
//! semantics: random programs under every strategy and worker count,
//! adversarial boundary cases, and the optimizations' effects.

mod gen;

use encompute_exact::bits::{gate_count, Strategy};
use encompute_exact::circuit::{
    build, execute, optimize, plain_bits, plain_value, Circuit, Interval, PlainCircuitGates,
};
use encompute_exact::compile;
use encompute_ir::{evaluate, Builder, CmpOp, Elem, Inputs, LogicOp, Outputs, Program, Range};

fn input_ranges(p: &Program, plan: &encompute_exact::ExactPlan) -> Vec<Option<Interval>> {
    plan.inputs
        .iter()
        .map(|i| {
            p.inputs()
                .find(|(_, n, _, _)| *n == i.name)
                .map(|(_, _, _, r)| (r.lo.ceil() as i128, r.hi.floor() as i128))
        })
        .collect()
}

fn run(p: &Program, c: &Circuit, inputs: &Inputs, workers: usize) -> Outputs {
    let plan = compile(p).unwrap().plan;
    let bits: Vec<Vec<bool>> = plan
        .inputs
        .iter()
        .map(|i| plain_bits(i.elem, inputs[&i.name][0] as i128))
        .collect();
    let out = execute(c, &PlainCircuitGates, &bits, workers).unwrap();
    plan.outputs
        .iter()
        .zip(out)
        .map(|(o, b)| (o.name.clone(), vec![plain_value(o.elem, &b) as f64]))
        .collect()
}

#[test]
fn random_programs_are_identical_under_every_strategy_and_worker_count() {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
    use std::cell::Cell;
    let n = gen::programs(192);
    let mut runner = TestRunner::new_with_rng(
        Config {
            cases: n,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let (compiled, cases) = (Cell::new(0u32), Cell::new(0u64));
    runner
        .run(&(gen::arb_program(), any::<u64>()), |((p, decl), seed)| {
            let Ok(c) = compile(&p) else { return Ok(()) };
            compiled.set(compiled.get() + 1);
            let ranges = input_ranges(&p, &c.plan);
            let reference_gates = gate_count(&c.plan).unwrap();
            let circuits = [
                build(&c.plan, &ranges, encompute_exact::bits::Strategy::REFERENCE).unwrap(),
                build(&c.plan, &ranges, encompute_exact::bits::Strategy::PARALLEL).unwrap(),
                optimize(&c.plan, &ranges, 1).unwrap(),
                optimize(&c.plan, &ranges, 8).unwrap(),
            ];
            // Range analysis, simplification and CSE never add gates to the
            // reference circuits.
            prop_assert!(circuits[0].stats.gates <= reference_gates, "{}", p);
            for case in 0..4 {
                let inputs = gen::inputs_for(&decl, case, seed);
                let want = evaluate(&p, &inputs).unwrap();
                for (k, circ) in circuits.iter().enumerate() {
                    for workers in [1usize, 3] {
                        prop_assert_eq!(
                            &run(&p, circ, &inputs, workers),
                            &want,
                            "circuit {} workers {} {}",
                            k,
                            workers,
                            p
                        );
                    }
                }
                cases.set(cases.get() + 1);
            }
            Ok(())
        })
        .unwrap();
    eprintln!(
        "optimized circuits: {} programs, {} input cases, identical to the interpreter",
        compiled.get(),
        cases.get()
    );
    assert!(compiled.get() >= n / 3);
}

/// One-output programs at the boundaries an incorrect optimizer would get
/// wrong: every input case must match the interpreter.
#[test]
fn adversarial_boundaries() {
    type Make =
        fn(&mut Builder, encompute_ir::ValueId, encompute_ir::ValueId) -> encompute_ir::ValueId;
    let cases: Vec<(&str, Elem, (f64, f64), Make)> = vec![
        (
            "signed minimum negation",
            Elem::I8,
            (-127.0, 127.0),
            |b, x, _| b.neg(x).unwrap(),
        ),
        (
            "signed/unsigned order (i8 lt)",
            Elem::I8,
            (-128.0, 127.0),
            |b, x, y| b.cmp(CmpOp::Lt, x, y).unwrap(),
        ),
        (
            "unsigned order (u8 ge)",
            Elem::U8,
            (0.0, 255.0),
            |b, x, y| b.cmp(CmpOp::Ge, x, y).unwrap(),
        ),
        (
            "narrow cast i16 -> i8",
            Elem::I16,
            (-100.0, 100.0),
            |b, x, _| b.cast(x, Elem::I8).unwrap(),
        ),
        (
            "widening cast i8 -> i32",
            Elem::I8,
            (-128.0, 127.0),
            |b, x, _| b.cast(x, Elem::I32).unwrap(),
        ),
        (
            "arithmetic right shift",
            Elem::I16,
            (-1000.0, 1000.0),
            |b, x, _| b.shift(x, false, 3).unwrap(),
        ),
        (
            "left shift at the edge",
            Elem::U16,
            (0.0, 255.0),
            |b, x, _| b.shift(x, true, 8).unwrap(),
        ),
        (
            "division rounding toward zero",
            Elem::I16,
            (-1000.0, 1000.0),
            |b, x, _| {
                let c = b.constant_exact(Elem::I16, -7.0).unwrap();
                b.div(x, c).unwrap()
            },
        ),
        (
            "remainder takes the dividend's sign",
            Elem::I16,
            (-1000.0, 1000.0),
            |b, x, _| {
                let c = b.constant_exact(Elem::I16, 7.0).unwrap();
                b.rem(x, c).unwrap()
            },
        ),
        (
            "lookup at the table's ends",
            Elem::U8,
            (0.0, 15.0),
            |b, x, _| {
                b.lookup(x, (0..16).map(|v| (v * 37 % 23) as f64).collect())
                    .unwrap()
            },
        ),
        (
            "select with identical branches",
            Elem::U8,
            (0.0, 200.0),
            |b, x, y| {
                let c = b.cmp(CmpOp::Lt, x, y).unwrap();
                b.select(c, x, x).unwrap()
            },
        ),
        (
            "x * x (one ciphertext twice)",
            Elem::U16,
            (0.0, 200.0),
            |b, x, _| b.mul(x, x).unwrap(),
        ),
        ("x xor x", Elem::U8, (0.0, 255.0), |b, x, _| {
            b.logic(LogicOp::Xor, x, x).unwrap()
        }),
        (
            "range extremes: sum at the type's top",
            Elem::U8,
            (0.0, 127.0),
            |b, x, y| b.add(x, y).unwrap(),
        ),
        (
            "mixed-sign sign extension",
            Elem::I32,
            (-3.0, 5.0),
            |b, x, y| b.mul(x, y).unwrap(),
        ),
        (
            "negative-only range",
            Elem::I16,
            (-300.0, -200.0),
            |b, x, y| b.sub(x, y).unwrap(),
        ),
        ("min and max", Elem::I16, (-500.0, 500.0), |b, x, y| {
            let m = b.min(x, y).unwrap();
            let n = b.max(x, y).unwrap();
            b.sub(n, m).unwrap()
        }),
    ];
    for (name, e, (lo, hi), make) in cases {
        let mut b = Builder::new("adv", 1e-3).unwrap();
        let x = b.input_exact("x", e, Some(Range::new(lo, hi))).unwrap();
        let y = b.input_exact("y", e, Some(Range::new(lo, hi))).unwrap();
        let r = make(&mut b, x, y);
        b.output("r", r).unwrap();
        let p = b.finish().unwrap();
        let Ok(c) = compile(&p) else {
            panic!("{name}: the program should compile");
        };
        let ranges = input_ranges(&p, &c.plan);
        let circuits = [
            build(&c.plan, &ranges, Strategy::REFERENCE).unwrap(),
            build(&c.plan, &ranges, Strategy::PARALLEL).unwrap(),
        ];
        let (l, h) = (lo as i128, hi as i128);
        let mut values: Vec<i128> = vec![l, l + 1, h - 1, h, 0, 1, -1];
        values.retain(|v| (l..=h).contains(v));
        for &xv in &values {
            for &yv in &values {
                let inputs: Inputs = [
                    ("x".to_owned(), vec![xv as f64]),
                    ("y".to_owned(), vec![yv as f64]),
                ]
                .into();
                let want = evaluate(&p, &inputs).unwrap();
                for c in &circuits {
                    assert_eq!(run(&p, c, &inputs, 2), want, "{name}: x={xv} y={yv}");
                }
            }
        }
    }
}

fn gates_of(p: &Program) -> u64 {
    let c = compile(p).unwrap();
    build(&c.plan, &input_ranges(p, &c.plan), Strategy::REFERENCE)
        .unwrap()
        .stats
        .gates
}

#[test]
fn folding_simplification_cse_and_range_width() {
    // (x > 18) & ((10 * 40) == 400) costs what x > 18 costs.
    let alone = {
        let mut b = Builder::new("a", 1e-3).unwrap();
        let x = b
            .input_exact("x", Elem::U8, Some(Range::new(0.0, 120.0)))
            .unwrap();
        let k = b.constant_exact(Elem::U8, 18.0).unwrap();
        let r = b.cmp(CmpOp::Gt, x, k).unwrap();
        b.output("r", r).unwrap();
        b.finish().unwrap()
    };
    let with_public = {
        let mut b = Builder::new("b", 1e-3).unwrap();
        let x = b
            .input_exact("x", Elem::U8, Some(Range::new(0.0, 120.0)))
            .unwrap();
        let k = b.constant_exact(Elem::U8, 18.0).unwrap();
        let big = b.cmp(CmpOp::Gt, x, k).unwrap();
        // Public-only expressions are folded before tracing (the IR
        // refuses them); what reaches the plan is a public constant.
        let t = b.constant_exact(Elem::Bool, 1.0).unwrap();
        let r = b.logic(LogicOp::And, big, t).unwrap();
        b.output("r", r).unwrap();
        b.finish().unwrap()
    };
    assert_eq!(
        gates_of(&with_public),
        gates_of(&alone),
        "public-only work costs nothing"
    );
    // risk <= 650 used three times is evaluated once.
    let thrice = {
        let mut b = Builder::new("c", 1e-3).unwrap();
        let risk = b
            .input_exact("risk", Elem::U16, Some(Range::new(0.0, 1000.0)))
            .unwrap();
        let mut acc = None;
        for _ in 0..3 {
            let k = b.constant_exact(Elem::U16, 650.0).unwrap();
            let ok = b.cmp(CmpOp::Le, risk, k).unwrap();
            acc = Some(match acc {
                None => ok,
                Some(a) => b.logic(LogicOp::And, a, ok).unwrap(),
            });
        }
        b.output("r", acc.unwrap()).unwrap();
        b.finish().unwrap()
    };
    let once = {
        let mut b = Builder::new("d", 1e-3).unwrap();
        let risk = b
            .input_exact("risk", Elem::U16, Some(Range::new(0.0, 1000.0)))
            .unwrap();
        let k = b.constant_exact(Elem::U16, 650.0).unwrap();
        let ok = b.cmp(CmpOp::Le, risk, k).unwrap();
        b.output("r", ok).unwrap();
        b.finish().unwrap()
    };
    assert_eq!(
        gates_of(&thrice),
        gates_of(&once),
        "common subexpressions are reused"
    );
    // A u16 in [0, 100] compares with fewer gates than a full-range u16.
    let cmp = |hi: f64| {
        let mut b = Builder::new("e", 1e-3).unwrap();
        let x = b
            .input_exact("x", Elem::U16, Some(Range::new(0.0, hi)))
            .unwrap();
        let y = b
            .input_exact("y", Elem::U16, Some(Range::new(0.0, hi)))
            .unwrap();
        let r = b.cmp(CmpOp::Lt, x, y).unwrap();
        b.output("r", r).unwrap();
        b.finish().unwrap()
    };
    let narrow = compile(&cmp(100.0)).unwrap();
    let c = build(
        &narrow.plan,
        &input_ranges(&cmp(100.0), &narrow.plan),
        Strategy::REFERENCE,
    )
    .unwrap();
    assert!(c.stats.gates < gates_of(&cmp(65535.0)), "range-aware width");
    assert_eq!(c.stats.input_bits_used, 14, "7 active bits per input");
    assert!(c.stats.range_bits_folded >= 18);
    // The parallel strategy has a shorter critical path on wide adders.
    let wide = {
        let mut b = Builder::new("f", 1e-3).unwrap();
        let x = b.input_exact("x", Elem::U32, None).unwrap();
        let y = b.input_exact("y", Elem::U32, None).unwrap();
        let r = b.add(x, y).unwrap();
        b.output("r", r).unwrap();
        b.finish().unwrap()
    };
    let wc = compile(&wide);
    if let Ok(wc) = wc {
        let r = build(&wc.plan, &[None, None], Strategy::REFERENCE).unwrap();
        let p = build(&wc.plan, &[None, None], Strategy::PARALLEL).unwrap();
        assert!(
            p.stats.depth * 2 < r.stats.depth,
            "prefix adder depth {} vs ripple {}",
            p.stats.depth,
            r.stats.depth
        );
        assert!(optimize(&wc.plan, &[None, None], 8).unwrap().rounds(8) <= r.rounds(8));
    }
}

/// The optimizer narrows widths only by the declared input ranges, which
/// the client enforces before encrypting, and only for plans that passed
/// overflow analysis: it never makes a refused program or input run.
#[test]
fn optimization_cannot_bypass_range_or_overflow_validation() {
    // A possible overflow is refused before any circuit exists.
    let mut b = Builder::new("o", 1e-3).unwrap();
    let x = b.input_exact("x", Elem::U16, None).unwrap();
    let y = b.mul(x, x).unwrap();
    b.output("y", y).unwrap();
    assert_eq!(
        compile(&b.finish().unwrap()).unwrap_err().code,
        encompute_ir::Code::Overflow
    );

    // The same multiplication fits once ranges bound it; the optimizer's
    // ranges are the declared ones, and a value outside them is refused
    // before encryption.
    let mut b = Builder::new("r", 1e-3).unwrap();
    let x = b
        .input_exact("x", Elem::U16, Some(Range::new(0.0, 200.0)))
        .unwrap();
    let y = b.mul(x, x).unwrap();
    b.output("y", y).unwrap();
    let p = b.finish().unwrap();
    let plan = compile(&p).unwrap().plan;
    assert_eq!(input_ranges(&p, &plan), vec![Some((0, 200))]);
    let inputs = |v: f64| Inputs::from([("x".to_owned(), vec![v])]);
    for bad in [-1.0, 201.0, 65535.0] {
        assert_eq!(
            encompute_ir::check_inputs(&p, &inputs(bad))
                .unwrap_err()
                .code,
            encompute_ir::Code::BadInput,
            "{bad}"
        );
    }
    // Every admitted value, including both bounds, matches the reference.
    for workers in [1usize, 8] {
        let c = optimize(&plan, &input_ranges(&p, &plan), workers as u32).unwrap();
        for v in 0..=200 {
            let v = v as f64;
            assert_eq!(
                run(&p, &c, &inputs(v), workers),
                evaluate(&p, &inputs(v)).unwrap(),
                "x = {v}"
            );
        }
    }
}

/// Building and scheduling are deterministic: the same plan, ranges and
/// worker count give the same circuit, and repeated parallel runs give the
/// same bits.
#[test]
fn parallel_scheduling_is_deterministic() {
    let p = {
        let mut b = Builder::new("d", 1e-3).unwrap();
        let x = b
            .input_exact("x", Elem::I16, Some(Range::new(-150.0, 150.0)))
            .unwrap();
        let y = b
            .input_exact("y", Elem::I16, Some(Range::new(-150.0, 150.0)))
            .unwrap();
        let s = b.add(x, y).unwrap();
        let m = b.mul(x, y).unwrap();
        let lt = b.cmp(CmpOp::Lt, s, m).unwrap();
        b.output("s", s).unwrap();
        b.output("m", m).unwrap();
        b.output("lt", lt).unwrap();
        b.finish().unwrap()
    };
    let plan = compile(&p).unwrap().plan;
    let ranges = input_ranges(&p, &plan);
    for workers in [1, 2, 8, 16] {
        let a = serde_json::to_string(&optimize(&plan, &ranges, workers).unwrap()).unwrap();
        let b = serde_json::to_string(&optimize(&plan, &ranges, workers).unwrap()).unwrap();
        assert_eq!(a, b, "{workers} workers");
    }
    let c = optimize(&plan, &ranges, 8).unwrap();
    let inputs = Inputs::from([
        ("x".to_owned(), vec![-149.0]),
        ("y".to_owned(), vec![123.0]),
    ]);
    let want = evaluate(&p, &inputs).unwrap();
    for _ in 0..50 {
        assert_eq!(run(&p, &c, &inputs, 8), want);
    }
}
