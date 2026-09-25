//! Parameter conformance, run tier: random programs with random ranges and
//! precision targets are compiled and executed encrypted on OpenFHE, and
//! every accepted program must meet its own precision target.
//!
//! `ENCOMPUTE_CONFORMANCE=full` runs 200 programs (scheduled CI); default 6.
#![cfg(feature = "openfhe")]

mod common;

use encompute_backend::rng::Rng;
use encompute_ckks::compile;
use encompute_ir::{Builder, Code, Program, Range, Shape, ValueId};
use encompute_runtime::diff_test;

fn program(seed: u64) -> Program {
    let mut rng = Rng::new(seed);
    let precision = [1e-2, 1e-3, 1e-4, 1e-5][(rng.next_u64() % 4) as usize];
    let n = 1 + (rng.next_u64() % 64) as usize;
    let span = 10f64.powf(rng.uniform(-1.0, 1.5));
    let mut b = Builder::new("conf", precision).unwrap();
    let x = b
        .input("x", Shape::Vector(n), Range::new(-span, span))
        .unwrap();
    let s = b.input("s", Shape::Scalar, Range::new(-1.0, 1.0)).unwrap();
    let mut vals: Vec<ValueId> = vec![x, s];
    for _ in 0..(2 + rng.next_u64() % 5) {
        let a = vals[(rng.next_u64() as usize) % vals.len()];
        let o = vals[(rng.next_u64() as usize) % vals.len()];
        let r = match rng.next_u64() % 8 {
            0 => b.add(a, o),
            1 => b.mul(a, o),
            2 => b.sub(a, o),
            3 => b.sum(a),
            4 => {
                let c: Vec<f64> = (0..n).map(|_| rng.uniform(-1.0, 1.0)).collect();
                let c = b.constant(Shape::Vector(n), c).unwrap();
                b.dot(c, a)
            }
            5 => {
                let rows = 1 + (rng.next_u64() % 16) as usize;
                let m: Vec<f64> = (0..rows * n).map(|_| rng.uniform(-0.5, 0.5)).collect();
                let m = b.constant(Shape::Matrix(rows, n), m).unwrap();
                b.matvec(m, a)
            }
            6 => b.sigmoid(a),
            _ => b.poly(
                a,
                vec![
                    rng.uniform(-1.0, 1.0),
                    rng.uniform(-1.0, 1.0),
                    rng.uniform(-0.5, 0.5),
                ],
            ),
        };
        if let Ok(id) = r {
            vals.push(id);
        }
    }
    b.output("out", *vals.last().unwrap()).unwrap();
    b.finish().unwrap()
}

#[test]
fn accepted_programs_meet_their_precision_encrypted() {
    let count = if std::env::var("ENCOMPUTE_CONFORMANCE").is_ok_and(|v| v == "full") {
        200
    } else {
        6
    };
    let (mut ran, mut refused) = (0, 0);
    for seed in 0..count {
        let p = program(seed);
        let c = match compile(&p) {
            Ok(c) => c,
            Err(e) => {
                assert!(
                    matches!(e.code, Code::DepthExceeded | Code::PrecisionUnreachable),
                    "seed {seed}: unexpected {e}\n{p}"
                );
                refused += 1;
                continue;
            }
        };
        let (client, ev) = common::openfhe_sessions(&p);
        let rep = diff_test(&client, &ev, &p, 3, seed)
            .unwrap()
            .approx()
            .unwrap()
            .clone();
        assert!(
            rep.passed,
            "seed {seed}: max error {:.3e} > {:e} with {:?}\n{p}",
            rep.max_error, rep.precision, c.params
        );
        ran += 1;
    }
    eprintln!("run tier: {ran} executed encrypted, {refused} refused");
    assert!(ran > 0);
}
