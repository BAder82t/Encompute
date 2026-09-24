mod common;

use common::{logistic, similarity};
use encompute_backend::{CkksBackend, MockBackend, MockConfig};
use encompute_ckks::compile;
use encompute_ir::{evaluate, Builder, Code, Program, Range, Shape};
use encompute_runtime::{diff_test, run, sample_inputs};
use proptest::prelude::*;

fn exact_mock(c: &encompute_ckks::Compiled) -> (MockBackend, encompute_backend::MockSecretKey) {
    MockBackend::new(
        &c.params,
        &c.plan.rotations,
        MockConfig {
            seed: 1,
            noise: false,
        },
    )
}

/// Max |reference − plan| over sampled cases, noise off.
fn plan_error(p: &Program, cases: usize) -> f64 {
    let c = compile(p).unwrap();
    let (b, sk) = exact_mock(&c);
    (0..cases)
        .map(|case| {
            let inputs = sample_inputs(p, case, 7);
            let want = evaluate(p, &inputs).unwrap();
            let got = run(&b, &sk, &c.plan, p, &inputs).unwrap();
            want.iter()
                .flat_map(|(k, v)| v.iter().zip(&got[k]).map(|(x, y)| (x - y).abs()))
                .fold(0.0, f64::max)
        })
        .fold(0.0, f64::max)
}

#[test]
fn logistic_demo_on_mock() {
    let p = logistic(32, 3);
    let c = compile(&p).unwrap();
    assert_eq!(c.plan.slots, 32);
    assert_eq!(c.plan.rotations, vec![1, 2, 4, 8, 16]);
    let cheb = &c.plan.approximations[0].chebyshev;
    assert!(cheb.max_error <= 5e-4);
    assert!(c.plan.depth <= 10, "depth {}", c.plan.depth);
    assert!(plan_error(&p, 20) <= cheb.max_error + 1e-9);

    let (b, sk) = MockBackend::new(&c.params, &c.plan.rotations, MockConfig::default());
    let rep = diff_test(&b, &sk, &c.plan, &p, 200, 42).unwrap();
    assert!(rep.passed, "{rep:#?}");
}

#[test]
fn similarity_demo_on_mock() {
    let p = similarity(384, 64, 5);
    let c = compile(&p).unwrap();
    assert_eq!(c.plan.slots, 512);
    assert_eq!(c.plan.depth, 1);
    let mul_plain = c
        .plan
        .op_counts()
        .into_iter()
        .find(|(k, _)| *k == "mul_plain")
        .unwrap()
        .1;
    assert_eq!(mul_plain, 64, "one hybrid diagonal per padded row");
    assert!(c.plan.rotations.len() <= 20, "{:?}", c.plan.rotations);
    assert!(plan_error(&p, 5) < 1e-12);

    let (b, sk) = MockBackend::new(&c.params, &c.plan.rotations, MockConfig::default());
    let rep = diff_test(&b, &sk, &c.plan, &p, 20, 42).unwrap();
    assert!(rep.passed, "{rep:#?}");
}

#[test]
fn dirty_padding_is_masked_before_reductions() {
    let mut b = Builder::new("p", 1e-6).unwrap();
    let x = b
        .input("x", Shape::Vector(3), Range::new(-1.0, 1.0))
        .unwrap();
    let s = b.input("s", Shape::Scalar, Range::new(-1.0, 1.0)).unwrap();
    let m = b
        .constant(
            Shape::Matrix(3, 3),
            vec![1.0, 2.0, 0.0, 0.0, 1.0, -1.0, 3.0, 0.5, 1.0],
        )
        .unwrap();
    let v = b.add(x, s).unwrap(); // padding = s: dirty
    let t = b.sum(v).unwrap(); // must mask first
    let y = b.matvec(m, v).unwrap(); // must mask first; 3 rows in 4 slots
    let z = b.dot(y, x).unwrap();
    let w = b.mul(y, s).unwrap();
    b.output("t", t).unwrap();
    b.output("z", z).unwrap();
    b.output("w", w).unwrap();
    b.output("t_again", t).unwrap();
    let p = b.finish().unwrap();
    assert!(plan_error(&p, 30) < 1e-12);
}

#[test]
fn mock_enforces_rotation_keys_and_depth() {
    let p = logistic(4, 1);
    let c = compile(&p).unwrap();
    let inputs = sample_inputs(&p, 2, 0);

    let (b, sk) = MockBackend::new(&c.params, &[1], MockConfig::default());
    let e = run(&b, &sk, &c.plan, &p, &inputs).unwrap_err();
    assert_eq!(e.code, Code::Backend);
    assert!(e.message.contains("no rotation key for 2"), "{}", e.message);

    let mut shallow = c.params.clone();
    shallow.mult_depth = c.plan.depth - 1;
    let (b, sk) = MockBackend::new(&shallow, &c.plan.rotations, MockConfig::default());
    let e = run(&b, &sk, &c.plan, &p, &inputs).unwrap_err();
    assert!(
        e.message.contains("depth budget exhausted"),
        "{}",
        e.message
    );

    let (_, other_sk) = MockBackend::new(
        &c.params,
        &c.plan.rotations,
        MockConfig {
            seed: 9,
            noise: true,
        },
    );
    let (b, _) = MockBackend::new(&c.params, &c.plan.rotations, MockConfig::default());
    let ct = b.encrypt(&vec![0.0; b.slots()]).unwrap();
    assert!(b.decrypt(&other_sk, &ct).is_err(), "wrong secret key");
}

#[test]
fn diff_test_reports_failures() {
    let p = logistic(8, 2);
    let c = compile(&p).unwrap();
    let mut params = c.params.clone();
    params.scale_bits = 20; // noise σ = 2^-3, far above 1e-3
    let (b, sk) = MockBackend::new(&params, &c.plan.rotations, MockConfig::default());
    let rep = diff_test(&b, &sk, &c.plan, &p, 10, 1).unwrap();
    assert!(!rep.passed);
    assert!(rep.failing.is_some());
}

/// Random programs with bounded depth: plan semantics equal the reference.
fn arb_program() -> impl Strategy<Value = Program> {
    (
        1usize..9,
        prop::collection::vec((0u8..9, any::<u32>(), any::<u32>(), -1.0f64..1.0), 1..10),
        prop::collection::vec(-1.0f64..1.0, 16),
    )
        .prop_map(|(n, steps, pool)| {
            let mut b = Builder::new("p", 1e-2).unwrap();
            let v = b
                .input("v", Shape::Vector(n), Range::new(-1.0, 1.0))
                .unwrap();
            let s = b.input("s", Shape::Scalar, Range::new(-0.5, 0.5)).unwrap();
            let mut vals = vec![v, s];
            for (kind, i, j, x) in steps {
                let a = vals[i as usize % vals.len()];
                let o = vals[j as usize % vals.len()];
                let r = match kind {
                    0 => b.add(a, o),
                    1 => b.sub(a, o),
                    2 => b.mul(a, o),
                    3 => b.neg(a),
                    4 => b.sum(a),
                    5 => b.poly(a, vec![x, pool[0], pool[1]]),
                    6 => {
                        let c = b.constant(Shape::Vector(n), pool[..n].to_vec()).unwrap();
                        if x > 0.0 {
                            b.dot(c, a)
                        } else {
                            b.sub(c, a)
                        }
                    }
                    7 => {
                        let c = b.constant(Shape::Scalar, vec![x]).unwrap();
                        if x > 0.0 {
                            b.add(a, c)
                        } else {
                            b.mul(c, a)
                        }
                    }
                    _ => {
                        let rows = 1 + (j as usize % 5);
                        let data = pool.iter().cycle().take(rows * n).copied().collect();
                        let c = b.constant(Shape::Matrix(rows, n), data).unwrap();
                        b.matvec(c, a)
                    }
                };
                if let Ok(id) = r {
                    vals.push(id);
                }
            }
            let last = *vals.last().unwrap();
            b.output("out", last).unwrap();
            b.finish().unwrap()
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn lowering_preserves_semantics(p in arb_program()) {
        match compile(&p) {
            Ok(_) => {
                let err = plan_error(&p, 4);
                let scale = encompute_analysis::ranges(&p).unwrap().max_abs().max(1.0);
                prop_assert!(err <= 1e-9 * scale, "error {err}\n{p}");
            }
            Err(e) => prop_assert!(
                matches!(e.code, Code::DepthExceeded | Code::PrecisionUnreachable),
                "{e}"
            ),
        }
    }
}
