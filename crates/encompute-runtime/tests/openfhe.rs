//! Differential tests against OpenFHE. Run with `--features openfhe`.
#![cfg(feature = "openfhe")]

mod common;

use std::time::Instant;

use encompute_ckks::compile;
use encompute_runtime::diff_test;

fn check(p: &encompute_ir::Program, cases: usize) {
    let c = compile(p).unwrap();
    let t = Instant::now();
    let (client, ev) = common::openfhe_sessions(p);
    let keygen = t.elapsed();
    let t = Instant::now();
    let rep = diff_test(&client, &ev, p, cases, 42).unwrap();
    eprintln!(
        "{}: N={} depth={} scale={} keygen={:.2?} per-case={:.2?} max_error={:.3e} (estimate {:.3e}, target {:e})",
        p.name(),
        c.params.ring_dim,
        c.plan.depth,
        c.params.scale_bits,
        keygen,
        t.elapsed() / cases as u32,
        rep.max_error,
        c.estimate.total,
        rep.precision
    );
    assert!(rep.passed, "{rep:#?}");
}

#[test]
fn logistic_encrypted() {
    check(&common::logistic(32, 3), 20);
}

#[test]
fn similarity_encrypted() {
    check(&common::similarity(384, 64, 5), 5);
}

#[test]
fn masking_and_broadcast_encrypted() {
    let mut b = encompute_ir::Builder::new("mixed", 1e-3).unwrap();
    let x = b
        .input(
            "x",
            encompute_ir::Shape::Vector(3),
            encompute_ir::Range::new(-1.0, 1.0),
        )
        .unwrap();
    let s = b
        .input(
            "s",
            encompute_ir::Shape::Scalar,
            encompute_ir::Range::new(-1.0, 1.0),
        )
        .unwrap();
    let m = b
        .constant(
            encompute_ir::Shape::Matrix(3, 3),
            vec![1.0, 2.0, 0.0, 0.0, 1.0, -1.0, 3.0, 0.5, 1.0],
        )
        .unwrap();
    let v = b.add(x, s).unwrap();
    let t = b.sum(v).unwrap();
    let y = b.matvec(m, v).unwrap();
    let z = b.dot(y, x).unwrap();
    let p = b.poly(z, vec![0.5, -1.0, 0.25]).unwrap();
    b.output("t", t).unwrap();
    b.output("p", p).unwrap();
    check(&b.finish().unwrap(), 10);
}
