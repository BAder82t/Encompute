//! OpenFHE BGV exact backend (0.4 V3): results equal the clear reference,
//! and evaluation is byte-for-byte reproducible (the basis of re-execution
//! verification, ADR-009).

use encompute_backend::{ExactClient, ExactEvaluator};
use encompute_exact::{bgv, compile, evaluate_exact};
use encompute_ir::{evaluate, Builder, Elem, Inputs, LogicOp, Program, Range};
use encompute_openfhe::BgvEvaluator;
use encompute_openfhe_client::BgvClient;

/// Loan pre-check over the BGV subset: u16 arithmetic and Boolean logic.
fn precheck() -> Program {
    let mut b = Builder::new("precheck", 1e-3).unwrap();
    let income = b
        .input_exact("income", Elem::U16, Some(Range::new(0.0, 5000.0)))
        .unwrap();
    let debt = b
        .input_exact("debt", Elem::U16, Some(Range::new(0.0, 5000.0)))
        .unwrap();
    let member = b.input_exact("member", Elem::Bool, None).unwrap();
    let flagged = b.input_exact("flagged", Elem::Bool, None).unwrap();
    let k3 = b.constant_exact(Elem::U16, 3.0).unwrap();
    let k7 = b.constant_exact(Elem::U16, 7.0).unwrap();
    let scaled = b.mul(income, k3).unwrap();
    let score = b.add(scaled, debt).unwrap();
    let score = b.add(score, k7).unwrap();
    let k20000 = b.constant_exact(Elem::U16, 30000.0).unwrap();
    let margin = b.sub(k20000, score).unwrap();
    let clean = b.not(flagged).unwrap();
    let ok = b.logic(LogicOp::And, member, clean).unwrap();
    let either = b.logic(LogicOp::Or, member, flagged).unwrap();
    let odd = b.logic(LogicOp::Xor, member, flagged).unwrap();
    b.output("score", score).unwrap();
    b.output("margin", margin).unwrap();
    b.output("ok", ok).unwrap();
    b.output("either", either).unwrap();
    b.output("odd", odd).unwrap();
    b.finish().unwrap()
}

#[test]
fn bgv_equals_clear_and_is_reproducible() {
    let p = precheck();
    let plan = compile(&p).unwrap().plan;
    let caps = bgv::capabilities();
    let t = encompute_exact::semantic_transcript(&plan, &"00".repeat(32));
    assert_eq!(caps.first_unsupported(&t), None, "{}", t.listing());
    let depth = bgv::mult_depth(&plan);
    let client = BgvClient::generate(depth).unwrap();
    let keys = client.evaluation_keys().unwrap();
    for (income, debt, member, flagged) in [
        (0, 0, 0, 0),
        (5000, 5000, 1, 1),
        (1234, 17, 1, 0),
        (1, 4999, 0, 1),
    ] {
        let inputs: Inputs = [
            ("income", income),
            ("debt", debt),
            ("member", member),
            ("flagged", flagged),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), vec![v as f64]))
        .collect();
        let request: Vec<Vec<u8>> = plan
            .inputs
            .iter()
            .map(|i| client.encrypt(i.elem, inputs[&i.name][0] as i128).unwrap())
            .collect();
        // Two independent evaluators on the same request.
        let run = || {
            let mut ev = BgvEvaluator::new(depth).unwrap();
            ev.load_keys(&keys).unwrap();
            let cts = plan
                .inputs
                .iter()
                .zip(&request)
                .map(|(i, b)| ev.load(i.elem, b).unwrap())
                .collect();
            evaluate_exact(&ev, &plan, cts)
                .unwrap()
                .iter()
                .map(|ct| ev.store(ct).unwrap())
                .collect::<Vec<_>>()
        };
        let (a, b) = (run(), run());
        assert_eq!(a, b, "evaluation is byte-for-byte reproducible");
        let want = evaluate(&p, &inputs).unwrap();
        for (o, bytes) in plan.outputs.iter().zip(&a) {
            let got = client.decrypt(o.elem, bytes).unwrap();
            assert_eq!(got as f64, want[&o.name][0], "{} {inputs:?}", o.name);
        }
    }
}
