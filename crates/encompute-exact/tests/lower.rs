//! Lowering + mock evaluator equals the clear interpreter exactly.

use encompute_backend::{ExactClient, ExactEvaluator, PlainExactClient, PlainExactEvaluator};
use encompute_exact::{compile, evaluate_exact, ExactInstr};
use encompute_ir::{
    evaluate, Builder, CmpOp, Code, Elem, Inputs, LogicOp, Program, Range, ValueId,
};
use proptest::prelude::*;

pub fn approve() -> Program {
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
    let i = b.mul(c35, income).unwrap();
    let ok_debt = b.cmp(CmpOp::Lt, d, i).unwrap();
    let ok_risk = b.cmp(CmpOp::Gt, c650, risk).unwrap();
    let x = b.logic(LogicOp::And, adult, ok_debt).unwrap();
    let x = b.logic(LogicOp::And, x, ok_risk).unwrap();
    b.output("approved", x).unwrap();
    b.output("approved_again", x).unwrap();
    b.finish().unwrap()
}

fn run_mock(p: &Program, inputs: &Inputs) -> Inputs {
    let c = compile(p).unwrap();
    let client = PlainExactClient::new(7);
    let ev = PlainExactEvaluator::new(&client.evaluation_keys().unwrap()).unwrap();
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
            let v = client.decrypt(o.elem, &ev.store(&ct).unwrap()).unwrap();
            (o.name.clone(), vec![v as f64])
        })
        .collect()
}

#[test]
fn flagship_lowers_and_runs() {
    let p = approve();
    let c = compile(&p).unwrap();
    let counts: std::collections::BTreeMap<_, _> = c.plan.op_counts().into_iter().collect();
    assert_eq!(counts["comparison"], 3);
    assert_eq!(counts["multiply by constant"], 2);
    assert_eq!(counts["logic"], 2);
    assert!(!counts.contains_key("multiply"), "constants use scalar ops");
    for (age, income, debt, risk) in [
        (35.0, 1e5, 2e4, 420.0),
        (17.0, 1e5, 2e4, 420.0),
        (35.0, 1e5, 3.5e4, 420.0),
        (35.0, 1e5, 2e4, 650.0),
        (120.0, 1e6, 0.0, 0.0),
        (0.0, 0.0, 0.0, 1000.0),
    ] {
        let inputs: Inputs = [
            ("age", age),
            ("income", income),
            ("debt", debt),
            ("risk", risk),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), vec![v]))
        .collect();
        assert_eq!(run_mock(&p, &inputs), evaluate(&p, &inputs).unwrap());
    }
    let json = serde_json::to_string(&c.plan).unwrap();
    assert_eq!(
        serde_json::from_str::<encompute_exact::ExactPlan>(&json).unwrap(),
        c.plan
    );
}

#[test]
fn wrong_scheme_and_overflow_are_refused() {
    let mut b = Builder::new("p", 1e-3).unwrap();
    let x = b
        .input("x", encompute_ir::Shape::Scalar, Range::new(0.0, 1.0))
        .unwrap();
    let y = b.mul(x, x).unwrap();
    b.output("y", y).unwrap();
    assert_eq!(compile(&b.finish().unwrap()).unwrap_err().code, Code::Type);
    let mut b = Builder::new("p", 1e-3).unwrap();
    let x = b.input_exact("x", Elem::U16, None).unwrap();
    let y = b.mul(x, x).unwrap();
    b.output("y", y).unwrap();
    assert_eq!(
        compile(&b.finish().unwrap()).unwrap_err().code,
        Code::Overflow
    );
}

const WIDTHS: [Elem; 6] = [
    Elem::U8,
    Elem::U16,
    Elem::U32,
    Elem::I8,
    Elem::I16,
    Elem::I32,
];

fn arb() -> impl Strategy<Value = (Program, Vec<(String, i64, i64)>)> {
    (
        0usize..WIDTHS.len(),
        prop::collection::vec((0u8..17, any::<u32>(), any::<u32>(), any::<i16>()), 1..12),
        prop::collection::vec((any::<i16>(), 0u16..300), 3),
    )
        .prop_map(|(w, steps, ranges)| {
            let elem = WIDTHS[w];
            let (min, max) = elem.bounds();
            let clamp = |v: i128| v.clamp(min.max(-30000), max.min(30000));
            let mut b = Builder::new("p", 1e-3).unwrap();
            let mut decl = vec![];
            let mut ints: Vec<ValueId> = vec![];
            for (i, (lo, span)) in ranges.iter().enumerate() {
                let lo = clamp(*lo as i128);
                let hi = clamp(lo + *span as i128);
                let name = format!("x{i}");
                ints.push(
                    b.input_exact(&name, elem, Some(Range::new(lo as f64, hi as f64)))
                        .unwrap(),
                );
                decl.push((name, lo as i64, hi as i64));
            }
            let mut bools: Vec<ValueId> = vec![];
            for (kind, i, j, c) in steps {
                let a = ints[i as usize % ints.len()];
                let o = ints[j as usize % ints.len()];
                let k = b
                    .constant_exact(elem, clamp(c as i128 % 9 + 1) as f64)
                    .unwrap();
                let r = match kind {
                    0 => b.add(a, o),
                    1 => b.sub(a, k),
                    2 => b.sub(k, a),
                    3 => b.mul(a, k),
                    4 => b.min(a, o),
                    5 => b.max(k, a),
                    6 => b.logic(LogicOp::And, a, o),
                    7 => b.logic(LogicOp::Xor, a, k),
                    8 => b.not(a),
                    9 => b.shift(a, c % 2 == 0, (c.unsigned_abs() as u32) % 3),
                    10 => {
                        if c % 2 == 0 {
                            b.div(a, k)
                        } else {
                            b.rem(a, k)
                        }
                    }
                    11 => b.mul(a, o),
                    12 | 13 => {
                        let op = [CmpOp::Lt, CmpOp::Ge, CmpOp::Eq, CmpOp::Ne][(c as usize) % 4];
                        let r = if kind == 12 {
                            b.cmp(op, a, o)
                        } else {
                            b.cmp(op, k, a)
                        };
                        if let Ok(t) = r {
                            bools.push(t);
                        }
                        r
                    }
                    14 if !bools.is_empty() => b.select(bools[i as usize % bools.len()], a, k),
                    15 if bools.len() > 1 => {
                        let t = b.logic(LogicOp::Or, bools[0], bools[1]);
                        if let Ok(t) = t {
                            bools.push(t);
                        }
                        t
                    }
                    16 => {
                        let lo = ranges[0].0.max(0) as usize % 4;
                        let t: Vec<f64> = (0..64)
                            .map(|v| clamp(((v * 7 + lo) % 50) as i128) as f64)
                            .collect();
                        let m = b.constant_exact(elem, 64.0).ok().unwrap_or(k);
                        let idx = b.rem(a, m).ok();
                        match idx {
                            Some(ix) => b.lookup(ix, t),
                            None => b.neg(a),
                        }
                    }
                    _ => b.neg(a),
                };
                if let Ok(id) = r {
                    if b.ty(id).unwrap().elem == elem {
                        ints.push(id);
                    }
                }
            }
            for (k, id) in ints.iter().enumerate().skip(3) {
                b.output(&format!("v{k}"), *id).unwrap();
            }
            for (k, id) in bools.iter().enumerate() {
                b.output(&format!("b{k}"), *id).unwrap();
            }
            b.output("x0", ints[0]).unwrap();
            (b.finish().unwrap(), decl)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn lowering_matches_interpreter_exactly((p, decl) in arb(), seed in any::<u64>()) {
        if compile(&p).is_err() {
            return Ok(()); // overflow refusals are covered by the analysis tests
        }
        let mut s = seed;
        for case in 0..6 {
            let inputs: Inputs = decl.iter().map(|(n, lo, hi)| {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let v = match case { 0 => *lo, 1 => *hi, _ => lo + (s >> 33) as i64 % (hi - lo + 1) };
                (n.clone(), vec![v as f64])
            }).collect();
            prop_assert_eq!(run_mock(&p, &inputs), evaluate(&p, &inputs).unwrap(), "{}", p);
        }
    }
}

/// Plans from outside the process are validated, never trusted.
#[test]
fn malformed_plans_are_rejected_not_executed() {
    let good = compile(&approve()).unwrap().plan;
    let client = PlainExactClient::new(7);
    let ev = PlainExactEvaluator::new(&client.evaluation_keys().unwrap()).unwrap();
    let inputs = |ev: &PlainExactEvaluator| {
        good.inputs
            .iter()
            .map(|i| {
                ev.load(i.elem, &client.encrypt(i.elem, 1).unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>()
    };
    let n = good.instrs.len();
    let mut cases = vec![];
    let mut p = good.clone();
    p.instrs.push(ExactInstr::Not(n as u32 + 5));
    p.elems.push(Elem::Bool);
    cases.push(("forward register", p));
    let mut p = good.clone();
    p.instrs.push(ExactInstr::Lookup {
        x: 0,
        table: vec![],
    });
    p.elems.push(Elem::U8);
    cases.push(("empty table", p));
    let mut p = good.clone();
    p.instrs.push(ExactInstr::Shift {
        x: 0,
        left: true,
        by: 200,
    });
    p.elems.push(Elem::U8);
    cases.push(("oversized shift", p));
    let mut p = good.clone();
    p.instrs.push(ExactInstr::DivScalar(0, 0));
    p.elems.push(Elem::U8);
    cases.push(("division by zero", p));
    let mut p = good.clone();
    p.instrs.push(ExactInstr::Input { index: 0 });
    p.elems.push(p.inputs[0].elem);
    cases.push(("input read twice", p));
    let mut p = good.clone();
    p.elems[0] = Elem::F64;
    cases.push(("approximate type", p));
    let mut p = good.clone();
    p.elems.pop();
    cases.push(("missing type", p));
    let mut p = good.clone();
    p.outputs[0].reg = 10_000;
    cases.push(("bad output register", p));
    let mut p = good.clone();
    p.instrs.push(ExactInstr::DivScalar(0, 256));
    p.elems.push(p.elems[0]);
    cases.push(("divisor outside the type", p));
    let mut p = good.clone();
    p.instrs.push(ExactInstr::Add(0, 1));
    p.elems.push(Elem::U64);
    cases.push(("mistyped register", p));
    for (what, p) in cases {
        let e = evaluate_exact(&ev, &p, inputs(&ev)).unwrap_err();
        assert_eq!(e.code, Code::Artifact, "{what}: {e}");
    }
    let mut wrong = inputs(&ev);
    wrong[0] = ev
        .load(Elem::U64, &client.encrypt(Elem::U64, 1).unwrap())
        .unwrap();
    assert_eq!(
        evaluate_exact(&ev, &good, wrong).unwrap_err().code,
        Code::BadInput
    );
    let mut few = inputs(&ev);
    few.pop();
    assert_eq!(
        evaluate_exact(&ev, &good, few).unwrap_err().code,
        Code::BadInput
    );
}
