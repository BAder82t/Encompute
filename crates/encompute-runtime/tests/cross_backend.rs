//! Research CI: the same exact programs on OpenFHE exact (production) and
//! TFHE-rs (research), as independent implementations: identical results,
//! equal to the clear reference. Needs both backends:
//! `--features openfhe,research-tfhe-rs`. Its own test binary, because it
//! switches the (process-wide) research backend variable.
#![cfg(all(feature = "openfhe", feature = "research-tfhe-rs"))]

use encompute_ir::{evaluate, Builder, CmpOp, Elem, Inputs, LogicOp, Program, Range};
use encompute_runtime::{Mode, Model};

fn program() -> Program {
    let mut b = Builder::new("cross", 1e-3).unwrap();
    let x = b
        .input_exact("x", Elem::U8, Some(Range::new(0.0, 100.0)))
        .unwrap();
    let y = b
        .input_exact("y", Elem::U8, Some(Range::new(0.0, 100.0)))
        .unwrap();
    let k = b.constant_exact(Elem::U8, 50.0).unwrap();
    let s = b.add(x, y).unwrap();
    let big = b.cmp(CmpOp::Gt, s, k).unwrap();
    let eq = b.cmp(CmpOp::Eq, x, y).unwrap();
    let m = b.max(x, y).unwrap();
    let either = b.logic(LogicOp::Or, big, eq).unwrap();
    b.output("sum", s).unwrap();
    b.output("big_or_eq", either).unwrap();
    b.output("max", m).unwrap();
    b.finish().unwrap()
}

#[test]
fn openfhe_exact_equals_tfhe_rs() {
    let p = program();
    let cases: Vec<Inputs> = [(0, 0), (100, 100), (37, 13), (25, 25)]
        .iter()
        .map(|(x, y)| {
            [("x", *x), ("y", *y)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), vec![v as f64]))
                .collect()
        })
        .collect();
    // OpenFHE exact first: sessions recompile the program, so the research
    // switch is set only afterwards.
    let openfhe = Model::compile(p.clone()).unwrap();
    assert_eq!(openfhe.compiled().scheme(), "BinFHE");
    let a: Vec<_> = cases
        .iter()
        .map(|i| openfhe.run(Mode::Encrypted, i).unwrap())
        .collect();
    std::env::set_var("ENCOMPUTE_RESEARCH_EXACT_BACKEND", "tfhe-rs");
    let tfhe = Model::compile(p.clone()).unwrap();
    assert_eq!(tfhe.compiled().scheme(), "TFHE");
    for (i, inputs) in cases.iter().enumerate() {
        let b = tfhe.run(Mode::Encrypted, inputs).unwrap();
        assert_eq!(a[i], b, "OpenFHE exact vs TFHE-rs on {inputs:?}");
        assert_eq!(a[i], evaluate(&p, inputs).unwrap());
    }
}
