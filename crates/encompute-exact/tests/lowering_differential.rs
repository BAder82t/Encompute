//! The bit-level lowering against the clear interpreter, value by value:
//! every 8-bit operation over its whole domain (with every constant when
//! `ENCOMPUTE_EXACT_EXHAUSTIVE=1`, nightly; every 17th by default), 8-bit
//! binary operations on a grid, and 64-bit edge cases; on the reference
//! evaluator and on optimized circuits of both strategies.

use encompute_exact::bits::{
    gate_count, plain_value as bits_value, plain_word, BitEvaluator, PlainGates, Strategy,
};
use encompute_exact::circuit::{
    build, execute, plain_bits, plain_value, Interval, PlainCircuitGates,
};
use encompute_exact::{compile, evaluate_exact, ExactInput, ExactInstr, ExactOutput, ExactPlan};
use encompute_ir::{
    evaluate, Builder, CmpOp, Code, Elem, Inputs, LogicOp, Program, Range, ValueId,
};

/// Every constant, or a stride through them (see the module doc).
fn constant_stride() -> usize {
    if std::env::var_os("ENCOMPUTE_EXACT_EXHAUSTIVE").is_some() {
        1
    } else {
        17
    }
}

fn ranges_of(p: &Program, plan: &encompute_exact::ExactPlan) -> Vec<Option<Interval>> {
    plan.inputs
        .iter()
        .map(|i| {
            p.inputs()
                .find(|(_, n, _, _)| *n == i.name)
                .map(|(_, _, _, r)| (r.lo.ceil() as i128, r.hi.floor() as i128))
        })
        .collect()
}

/// Checks reference bit evaluator + optimized circuits (both strategies)
/// against IR evaluate for the given input vectors. Returns number checked.
fn check(p: &Program, cases: &[Vec<(String, i128)>]) -> usize {
    let Ok(c) = compile(p) else { return 0 };
    let plan = c.plan;
    let ranges = ranges_of(p, &plan);
    let circs = [
        build(&plan, &ranges, Strategy::REFERENCE).unwrap(),
        build(&plan, &ranges, Strategy::PARALLEL).unwrap(),
    ];
    let mut n = 0;
    for case in cases {
        let inputs: Inputs = case
            .iter()
            .map(|(k, v)| (k.clone(), vec![*v as f64]))
            .collect();
        let Ok(want) = evaluate(p, &inputs) else {
            continue;
        };
        // reference instruction-by-instruction
        let ev = BitEvaluator::new(PlainGates);
        let words = plan
            .inputs
            .iter()
            .map(|i| plain_word(i.elem, case.iter().find(|(k, _)| *k == i.name).unwrap().1))
            .collect();
        let out = evaluate_exact(&ev, &plan, words).unwrap();
        for (o, w) in plan.outputs.iter().zip(&out) {
            assert_eq!(
                bits_value(w) as f64,
                want[&o.name][0],
                "reference {p} {case:?}"
            );
        }
        let bits: Vec<Vec<bool>> = plan
            .inputs
            .iter()
            .map(|i| plain_bits(i.elem, case.iter().find(|(k, _)| *k == i.name).unwrap().1))
            .collect();
        for c in &circs {
            let out = execute(c, &PlainCircuitGates, &bits, 2).unwrap();
            for (o, b) in plan.outputs.iter().zip(out) {
                assert_eq!(
                    plain_value(o.elem, &b) as f64,
                    want[&o.name][0],
                    "circuit {p} {case:?}"
                );
            }
        }
        n += 1;
    }
    n
}

fn unary(
    name: &str,
    elem: Elem,
    lo: i128,
    hi: i128,
    f: impl Fn(&mut Builder, ValueId) -> encompute_ir::Result<ValueId>,
) -> Option<Program> {
    let mut b = Builder::new(name, 1e-3).unwrap();
    let x = b
        .input_exact("x", elem, Some(Range::new(lo as f64, hi as f64)))
        .unwrap();
    let y = f(&mut b, x).ok()?;
    b.output("y", y).ok()?;
    b.finish().ok()
}

fn all(_elem: Elem, lo: i128, hi: i128) -> Vec<Vec<(String, i128)>> {
    (lo..=hi).map(|v| vec![("x".to_string(), v)]).collect()
}

#[test]
fn unary_8bit_operations_match_the_interpreter_on_every_value() {
    let mut total = 0;
    for elem in [Elem::I8, Elem::U8] {
        let (lo, hi) = elem.bounds();
        let cases = all(elem, lo, hi);
        for c in (lo..=hi).step_by(constant_stride()).chain([-1, 1, hi]) {
            if c == 0 || c < lo {
                continue;
            }
            for which in 0..8 {
                let p = unary("t", elem, lo, hi, |b, x| {
                    let k = b.constant_exact(elem, c as f64)?;
                    match which {
                        0 => b.div(x, k),
                        1 => b.rem(x, k),
                        2 => b.min(x, k),
                        3 => b.max(x, k),
                        4 => {
                            let t = b.cmp(CmpOp::Lt, k, x)?;
                            b.select(t, x, k)
                        }
                        5 => {
                            let t = b.cmp(CmpOp::Ge, x, k)?;
                            b.select(t, k, x)
                        }
                        6 => b.logic(LogicOp::Xor, x, k),
                        _ => b.logic(LogicOp::And, k, x),
                    }
                });
                if let Some(p) = p {
                    total += check(&p, &cases);
                }
            }
        }
        for by in 0..8 {
            for left in [false, true] {
                // narrow range so that left shifts compile
                for (l, h) in [(lo, hi), (lo >> by, hi >> by)] {
                    if let Some(p) = unary("s", elem, l, h, |b, x| b.shift(x, left, by)) {
                        total += check(&p, &all(elem, l, h));
                    }
                }
            }
        }
        for to in [
            Elem::I8,
            Elem::U8,
            Elem::I16,
            Elem::U16,
            Elem::I32,
            Elem::U32,
            Elem::I64,
            Elem::U64,
        ] {
            for (l, h) in [(lo, hi), (0, hi.min(127)), (lo.max(-1), 0)] {
                if let Some(p) = unary("c", elem, l, h, |b, x| b.cast(x, to)) {
                    total += check(&p, &all(elem, l, h));
                }
            }
        }
        if let Some(p) = unary("n", elem, lo + 1, hi, |b, x| b.neg(x)) {
            total += check(&p, &cases);
        }
        if let Some(p) = unary("nt", elem, lo, hi, |b, x| b.not(x)) {
            total += check(&p, &cases);
        }
        // lookup, identity-like table on the non-negative part
        let table: Vec<f64> = (0..=hi.min(255))
            .map(|i| ((i * 7) % (hi + 1)) as f64)
            .collect();
        if let Some(p) = unary("l", elem, 0, hi.min(255), |b, x| b.lookup(x, table.clone())) {
            total += check(&p, &all(elem, 0, hi.min(255)));
        }
    }
    eprintln!("checked {total} cases");
    assert!(total > 10_000);
}

#[test]
fn binary_8bit_operations_match_the_interpreter() {
    let mut total = 0;
    for elem in [Elem::I8, Elem::U8] {
        let (lo, hi) = elem.bounds();
        let cases: Vec<_> = (lo..=hi)
            .step_by(3)
            .flat_map(|a| {
                (lo..=hi)
                    .step_by(5)
                    .map(move |b| vec![("x".to_string(), a), ("y".to_string(), b)])
            })
            .collect();
        for which in 0..12 {
            let mut b = Builder::new("b", 1e-3).unwrap();
            let x = b.input_exact("x", elem, None).unwrap();
            let y = b.input_exact("y", elem, None).unwrap();
            let r = match which {
                0 => b.min(x, y),
                1 => b.max(x, y),
                2 => b.cmp(CmpOp::Lt, x, y),
                3 => b.cmp(CmpOp::Le, x, y),
                4 => b.cmp(CmpOp::Gt, x, y),
                5 => b.cmp(CmpOp::Ge, x, y),
                6 => b.cmp(CmpOp::Eq, x, y),
                7 => b.logic(LogicOp::Or, x, y),
                8 => {
                    let c = b.cmp(CmpOp::Ne, x, y).unwrap();
                    b.select(c, x, y)
                }
                _ => b.logic(LogicOp::And, x, y),
            }
            .unwrap();
            b.output("r", r).unwrap();
            let p = b.finish().unwrap();
            total += check(&p, &cases);
        }
        // add/sub/mul under narrowed ranges
        for which in 0..3 {
            let mut b = Builder::new("b", 1e-3).unwrap();
            let (l, h) = if elem.is_signed() { (-11, 11) } else { (0, 15) };
            let x = b
                .input_exact("x", elem, Some(Range::new(l as f64, h as f64)))
                .unwrap();
            let y = b
                .input_exact("y", elem, Some(Range::new(l as f64, h as f64)))
                .unwrap();
            let r = match which {
                0 => b.mul(x, y),
                1 => b.add(x, y),
                _ => b.sub(x, y),
            };
            let Ok(r) = r else { continue };
            if b.output("r", r).is_err() {
                continue;
            }
            let Ok(p) = b.finish() else { continue };
            let cases: Vec<_> = (l..=h)
                .flat_map(|a| {
                    (l..=h).map(move |bb| vec![("x".to_string(), a), ("y".to_string(), bb)])
                })
                .collect();
            total += check(&p, &cases);
        }
    }
    eprintln!("checked {total}");
    assert!(total > 10_000);
}

#[test]
fn wide_division_remainder_and_shift_edges_match_the_interpreter() {
    // 64-bit divisions/remainders/shifts at ±2^53 edges
    let edges: Vec<i128> = vec![
        -(1 << 53),
        -(1 << 53) + 1,
        -(1 << 40) - 3,
        -7,
        -1,
        0,
        1,
        7,
        (1 << 40) + 3,
        (1 << 53) - 1,
        1 << 53,
    ];
    let mut total = 0;
    for elem in [Elem::I64, Elem::U64, Elem::I32, Elem::U32] {
        let (tlo, thi) = elem.bounds();
        let lo = tlo.max(-(1 << 53));
        let hi = thi.min(1 << 53);
        let cases: Vec<_> = edges
            .iter()
            .filter(|v| **v >= lo && **v <= hi)
            .map(|v| vec![("x".to_string(), *v)])
            .collect();
        for c in &edges {
            if *c == 0 || *c < lo || *c > hi {
                continue;
            }
            for which in 0..2 {
                if let Some(p) = unary("w", elem, lo, hi, |b, x| {
                    let k = b.constant_exact(elem, *c as f64)?;
                    if which == 0 {
                        b.div(x, k)
                    } else {
                        b.rem(x, k)
                    }
                }) {
                    total += check(&p, &cases);
                }
            }
        }
        for by in [0u32, 1, 10, 31, 63] {
            if let Some(p) = unary("sr", elem, lo, hi, |b, x| b.shift(x, false, by)) {
                total += check(&p, &cases);
            }
        }
    }
    eprintln!("checked {total}");
    assert!(total > 50);
}

/// Review finding EX-1 (ENC-SF-2026-051): a lookup indexed by a Boolean with a table of three
/// or more entries passed range analysis and panicked in the lowering
/// (`bits[1]` of a one-bit word) in every compile path. The builder (and
/// so the parser) refuses tables longer than the index type reaches, plan
/// validation refuses them in plans from elsewhere, and the lowering never
/// reads an index bit the word lacks.
#[test]
fn lookups_never_read_index_bits_the_index_lacks() {
    let lookup = |elem: Elem, n: usize| {
        let mut b = Builder::new("bl", 1e-3).unwrap();
        let x = b
            .input_exact("x", elem, Some(Range::new(0.0, 1.0)))
            .unwrap();
        let v = b.lookup(x, vec![1.0; n])?;
        b.output("y", v)?;
        b.finish()
    };
    for (elem, n, ok) in [
        (Elem::Bool, 2, true),
        (Elem::Bool, 3, false),
        (Elem::Bool, 256, false),
        (Elem::U8, 256, true),
        (Elem::U8, 257, false),
        (Elem::I8, 256, true),
    ] {
        match (lookup(elem, n), ok) {
            (Ok(p), true) => {
                let plan = compile(&p).unwrap().plan;
                plan.validate().unwrap();
                gate_count(&plan).unwrap();
            }
            (Err(e), false) => assert_eq!(e.code, Code::Type, "{elem} {n}: {e}"),
            (r, _) => panic!("{elem} index, {n} entries: {:?}", r.map(|_| ())),
        }
    }
    // A plan from elsewhere with a Boolean-indexed table of three.
    let plan = ExactPlan {
        inputs: vec![ExactInput {
            name: "x".into(),
            elem: Elem::Bool,
        }],
        instrs: vec![
            ExactInstr::Input { index: 0 },
            ExactInstr::Lookup {
                x: 0,
                table: vec![1, 0, 1],
            },
        ],
        elems: vec![Elem::Bool, Elem::Bool],
        outputs: vec![ExactOutput {
            name: "y".into(),
            reg: 1,
            elem: Elem::Bool,
        }],
    };
    assert_eq!(plan.validate().unwrap_err().code, Code::Artifact);
    // Lowered anyway (it is never, after validation): no panic.
    let r = std::panic::catch_unwind(|| {
        gate_count(&plan).map(|_| ())?;
        build(&plan, &[None], Strategy::REFERENCE).map(|_| ())
    });
    assert!(r.is_ok(), "the lowering panicked");
}
