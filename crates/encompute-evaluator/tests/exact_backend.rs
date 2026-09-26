//! Which exact backend a build selects: OpenFHE exact by default; TFHE-rs
//! never in a production build, even when asked; programs outside OpenFHE
//! exact's capability matrix refused at compile time. One test function,
//! because it switches a process-wide variable.
#![cfg(not(feature = "research-tfhe-rs"))]

use encompute_evaluator::{compile_program, BackendKind, Backends};
use encompute_ir::{Builder, Code, Elem, Program, Range};

fn lookup(entries: usize) -> Program {
    let mut b = Builder::new("tier", 1e-3).unwrap();
    let hi = (entries - 1) as f64;
    let x = b
        .input_exact("x", Elem::U16, Some(Range::new(0.0, hi)))
        .unwrap();
    let t = b
        .lookup(x, (0..entries).map(|v| (v % 7) as f64).collect())
        .unwrap();
    b.output("t", t).unwrap();
    b.finish().unwrap()
}

#[test]
fn production_builds_select_openfhe_exact_and_refuse_tfhe_rs() {
    // Default: OpenFHE exact (BinFHE), never TFHE-rs.
    let c = compile_program(&lookup(256)).unwrap();
    assert_eq!(c.scheme(), "BinFHE");
    assert_eq!(c.target_backend(), BackendKind::OpenFheExact);
    assert_ne!(Backends::for_build().exact, BackendKind::TfheRs);
    assert!(!BackendKind::TfheRs.built());

    // Outside the capability matrix: refused when compiling, not later.
    let e = compile_program(&lookup(257)).unwrap_err();
    assert_eq!(e.code, Code::Backend, "{e}");
    assert!(e.message.contains("up to 256 entries"), "{e}");

    // Asking for TFHE-rs in a production build is an error, not a fallback.
    std::env::set_var("ENCOMPUTE_RESEARCH_EXACT_BACKEND", "tfhe-rs");
    let e = compile_program(&lookup(4)).unwrap_err();
    std::env::remove_var("ENCOMPUTE_RESEARCH_EXACT_BACKEND");
    assert_eq!(e.code, Code::Backend);
    assert!(e.message.starts_with("BACKEND UNAVAILABLE"), "{e}");
}
