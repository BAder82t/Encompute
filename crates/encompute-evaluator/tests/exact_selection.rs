//! Exact programs and the backend they compile to: programs outside what a
//! backend runs correctly are refused at compile time with a typed error,
//! never selected for it and never a panic.

use encompute_evaluator::{compile_program, proof_coverable};
use encompute_ir::{parse, Builder, Code, Elem, Program, Range};

fn eir(body: &str, verified: bool) -> Program {
    let header = if verified {
        "program p precision 0.001 verification required"
    } else {
        "program p precision 0.001"
    };
    parse(&format!("encompute 0.1\n{header}\n{body}")).unwrap_or_else(|e| panic!("{e}"))
}

/// Review finding EX-2 (ENC-SF-2026-066): the BGV subset admitted bitwise logic on u8/u16,
/// which the BGV evaluator refuses at run time; a `verification required`
/// program using it compiled to BGV and could never run. Bitwise logic
/// counts as BGV-supported on Booleans only.
#[test]
fn integer_bitwise_logic_is_not_selected_for_bgv() {
    let body = "%0 = input \"x\" [0.0, 255.0] : secret u8\n\
                %1 = input \"y\" [0.0, 255.0] : secret u8\n\
                %2 = and %0, %1 : secret u8\n\
                output \"z\" = %2\n";
    let c = compile_program(&eir(body, false)).unwrap();
    let e = c.exact().unwrap();
    assert!(!proof_coverable(&e.plan));
    assert!(
        !e.profile.profile.starts_with("BGVRNS"),
        "{}",
        e.profile.profile
    );
    let err = compile_program(&eir(body, true)).unwrap_err();
    assert_eq!(err.code, Code::Unverified, "{err}");
    // On Booleans it stays in the subset.
    let body = "%0 = input \"x\" [0.0, 1.0] : secret bool\n\
                %1 = input \"y\" [0.0, 1.0] : secret bool\n\
                %2 = xor %0, %1 : secret bool\n\
                output \"z\" = %2\n";
    let c = compile_program(&eir(body, true)).unwrap();
    assert!(c.exact().unwrap().profile.profile.starts_with("BGVRNS"));
}

/// Review finding EX-1 (ENC-SF-2026-051): a lookup indexed by a Boolean with a table of three
/// or more entries passed every check and then panicked in the lowering
/// (a 500 over HTTP; an abort in worker processes, the CLI and Python).
#[test]
fn a_bool_indexed_lookup_longer_than_two_is_a_type_error() {
    for (table, ok) in [
        ("[1.0, 0.0]", true),
        ("[1.0, 0.0, 1.0]", false),
        (&format!("[{}]", vec!["1.0"; 256].join(", ")) as &str, false),
    ] {
        let src = format!(
            "encompute 0.1\nprogram p precision 0.001\n\
             %0 = input \"x\" [0.0, 1.0] : secret bool\n\
             %1 = lookup %0 {table} : secret bool\n\
             output \"z\" = %1\n"
        );
        let r = std::panic::catch_unwind(|| parse(&src).and_then(|p| compile_program(&p)));
        let r = r.expect("no panic");
        match (r, ok) {
            (Ok(_), true) => {}
            (Err(e), false) => assert_eq!(e.code, Code::Type, "{e}"),
            (r, _) => panic!("table {table}: {:?}", r.map(|_| ())),
        }
    }
}

/// `a * b` then `z + z` `doublings` times, plus `y`: the doublings leave the
/// value (0) and its range alone but double its noise each time.
fn doubled(doublings: u32, verified: bool) -> Program {
    let mut b = Builder::new("noise", 1e-3).unwrap();
    let zero = b
        .input_exact("zero", Elem::U16, Some(Range::new(0.0, 0.0)))
        .unwrap();
    let y = b
        .input_exact("y", Elem::U16, Some(Range::new(0.0, 100.0)))
        .unwrap();
    let mut z = b.mul(zero, y).unwrap();
    for _ in 0..doublings {
        z = b.add(z, z).unwrap();
    }
    let out = b.add(z, y).unwrap();
    b.output("out", out).unwrap();
    if verified {
        b.verification(encompute_ir::Verification::Required);
    }
    b.finish().unwrap()
}

/// Review finding EX-3 (ENC-SF-2026-065): BGV's noise model counted products only, so a
/// program with 18 or more chained doublings compiled to BGV and decrypted
/// to garbage (e.g. 18211 for 77) with no error. Programs whose noise can
/// exceed the calibrated budget no longer run on BGV.
#[test]
fn programs_beyond_the_bgv_noise_budget_do_not_run_on_bgv() {
    let within = compile_program(&doubled(12, false)).unwrap();
    assert!(within
        .exact()
        .unwrap()
        .profile
        .profile
        .starts_with("BGVRNS"));
    for k in [14, 18, 40, 200] {
        let c = compile_program(&doubled(k, false)).unwrap();
        let e = c.exact().unwrap();
        assert!(
            !e.profile.profile.starts_with("BGVRNS"),
            "{k} doublings on BGV"
        );
        assert!(!proof_coverable(&e.plan));
        let err = compile_program(&doubled(k, true)).unwrap_err();
        assert_eq!(err.code, Code::Unverified, "{err}");
        assert!(err.message.contains("noise"), "{err}");
    }
    // Honest sums stay on BGV: 256 products (calibrated correct up to 8192).
    let mut b = Builder::new("sop", 1e-3).unwrap();
    let mut acc = None;
    for i in 0..256 {
        let r = Some(Range::new(0.0, 1.0));
        let x = b.input_exact(&format!("x{i}"), Elem::U16, r).unwrap();
        let y = b.input_exact(&format!("y{i}"), Elem::U16, r).unwrap();
        let p = b.mul(x, y).unwrap();
        acc = Some(match acc {
            None => p,
            Some(a) => b.add(a, p).unwrap(),
        });
    }
    b.output("s", acc.unwrap()).unwrap();
    b.verification(encompute_ir::Verification::Required);
    assert!(compile_program(&b.finish().unwrap()).is_ok());
}
