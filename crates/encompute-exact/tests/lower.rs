//! Lowering + mock evaluator equals the clear interpreter exactly.

use encompute_backend::{ExactClient, ExactEvaluator, PlainExactClient, PlainExactEvaluator};
use encompute_exact::{compile, evaluate_exact, ExactInstr};
use encompute_ir::{evaluate, Builder, CmpOp, Code, Elem, Inputs, LogicOp, Program, Range};
use proptest::prelude::*;

mod gen;

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

/// Random programs over every integer width (plus a bool input): the plan
/// on the mock equals the interpreter exactly. `ENCOMPUTE_EXACT_PROGRAMS`
/// sets the number of programs (nightly: 10 000); six input cases each.
#[test]
fn random_programs_match_interpreter_exactly() {
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
    use std::cell::Cell;
    let n = gen::programs(512);
    let mut runner = TestRunner::new_with_rng(
        Config {
            cases: n,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let (compiled, refused, cases) = (Cell::new(0u32), Cell::new(0u32), Cell::new(0u64));
    runner
        .run(&(gen::arb_program(), any::<u64>()), |((p, decl), seed)| {
            if compile(&p).is_err() {
                // Possible overflow: refused at compile time (ENC1303),
                // covered by the analysis tests.
                refused.set(refused.get() + 1);
                return Ok(());
            }
            compiled.set(compiled.get() + 1);
            for case in 0..6 {
                let inputs = gen::inputs_for(&decl, case, seed);
                prop_assert_eq!(
                    run_mock(&p, &inputs),
                    evaluate(&p, &inputs).unwrap(),
                    "{}",
                    p
                );
                cases.set(cases.get() + 1);
            }
            Ok(())
        })
        .unwrap();
    eprintln!(
        "random programs: {} compiled and matched exactly on {} input cases, {} refused (overflow)",
        compiled.get(),
        cases.get(),
        refused.get()
    );
    assert!(
        compiled.get() >= n / 3,
        "the generator mostly makes valid programs"
    );
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

/// The observer sees every instruction in order and nothing else; results
/// are the same as without it.
#[test]
fn observer_sees_structure_only_and_changes_nothing() {
    use encompute_exact::{
        evaluate_exact_observed, ExactPlan, ExecutionContext, ExecutionObserver, InstructionEvent,
        Reg,
    };
    #[derive(Default)]
    struct Record {
        began: usize,
        steps: Vec<(usize, Reg)>,
        outputs: Vec<Reg>,
    }
    impl ExecutionObserver for Record {
        fn begin(&mut self, plan: &ExactPlan, _: &ExecutionContext) -> encompute_ir::Result<()> {
            self.began = plan.instrs.len();
            Ok(())
        }
        fn instruction(&mut self, e: &InstructionEvent<'_>) -> encompute_ir::Result<()> {
            self.steps.push((e.index, e.result));
            Ok(())
        }
        fn finish(&mut self, outputs: &[Reg]) -> encompute_ir::Result<()> {
            self.outputs = outputs.to_vec();
            Ok(())
        }
    }
    let p = approve();
    let plan = compile(&p).unwrap().plan;
    let client = PlainExactClient::new(3);
    let ev = PlainExactEvaluator::new(&client.evaluation_keys().unwrap()).unwrap();
    let load = |v: i128| {
        plan.inputs
            .iter()
            .map(|i| {
                ev.load(i.elem, &client.encrypt(i.elem, v).unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>()
    };
    let mut rec = Record::default();
    let a = evaluate_exact_observed(&ev, &plan, load(30), &ExecutionContext::default(), &mut rec)
        .unwrap();
    let b = evaluate_exact(&ev, &plan, load(30)).unwrap();
    let dec = |v: &[_]| {
        v.iter()
            .map(|ct| client.decrypt(Elem::Bool, &ev.store(ct).unwrap()).unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(dec(&a), dec(&b));
    assert_eq!(rec.began, plan.instrs.len());
    let want: Vec<(usize, Reg)> = (0..plan.instrs.len()).map(|i| (i, i as Reg)).collect();
    assert_eq!(rec.steps, want);
    assert_eq!(
        rec.outputs,
        plan.outputs.iter().map(|o| o.reg).collect::<Vec<_>>()
    );
}
