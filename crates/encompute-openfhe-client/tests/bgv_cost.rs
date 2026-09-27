//! Calibration of the exact-backend cost model (encompute-evaluator's
//! `cost` module): OpenFHE BGV per-operation costs by multiplicative depth,
//! and whole-program times to check the fitted model against. Ignored by
//! default (it takes about a minute); run with
//!
//! ```text
//! cargo test -q --release -p encompute-openfhe-client --test bgv_cost -- --ignored --nocapture
//! ```
//!
//! and copy the numbers into `docs/benchmarks.md` and the constants.

use std::time::{Duration, Instant};

use encompute_backend::{ExactClient, ExactEvaluator};
use encompute_exact::{bgv, compile, evaluate_exact};
use encompute_ir::{Builder, Elem, Range};
use encompute_openfhe::BgvEvaluator;
use encompute_openfhe_client::BgvClient;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

/// Median of `n` timings of `f`, in ms.
fn median(n: usize, mut f: impl FnMut()) -> f64 {
    let mut v: Vec<f64> = (0..n)
        .map(|_| {
            let t = Instant::now();
            f();
            ms(t.elapsed())
        })
        .collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[n / 2]
}

#[test]
#[ignore]
fn bgv_operation_costs() {
    println!(
        "depth | keygen | ctx+load keys | encrypt | decrypt | load | store | add | add const | \
         mul const | mul (relin)"
    );
    for depth in [1u32, 2, 3, 4, 6, 8] {
        let t = Instant::now();
        let client = BgvClient::generate(depth).unwrap();
        let keys = client.evaluation_keys().unwrap();
        let keygen = ms(t.elapsed());
        let t = Instant::now();
        let mut ev = BgvEvaluator::new(depth).unwrap();
        ev.load_keys(&keys).unwrap();
        let setup = ms(t.elapsed());
        let enc = median(9, || {
            client.encrypt(Elem::U16, 1234).unwrap();
        });
        let a = client.encrypt(Elem::U16, 12).unwrap();
        let b = client.encrypt(Elem::U16, 34).unwrap();
        let (ca, cb) = (
            ev.load(Elem::U16, &a).unwrap(),
            ev.load(Elem::U16, &b).unwrap(),
        );
        let dec = median(9, || {
            client.decrypt(Elem::U16, &a).unwrap();
        });
        let load = median(9, || {
            ev.load(Elem::U16, &a).unwrap();
        });
        let store = median(9, || {
            ev.store(&ca).unwrap();
        });
        let add = median(21, || {
            ev.add(&ca, &cb).unwrap();
        });
        let addc = median(21, || {
            ev.add_scalar(&ca, 7).unwrap();
        });
        let mulc = median(21, || {
            ev.mul_scalar(&ca, 7).unwrap();
        });
        let mul = median(21, || {
            ev.mul(&ca, &cb).unwrap();
        });
        println!(
            "{depth} | {keygen:.1} | {setup:.1} | {enc:.2} | {dec:.2} | {load:.2} | {store:.2} | {add:.3} | {addc:.3} | \
             {mulc:.3} | {mul:.2}"
        );
    }
}

/// Whole programs: a chain of `n` products (depth `n`) and a sum of `n`
/// scaled inputs (depth 1), evaluator time only.
#[test]
#[ignore]
fn bgv_program_costs() {
    for (kind, n) in [
        ("chain", 2usize),
        ("chain", 4),
        ("chain", 6),
        ("sum", 8),
        ("sum", 32),
    ] {
        let mut b = Builder::new("p", 1e-3).unwrap();
        let xs: Vec<_> = (0..n.max(2))
            .map(|i| {
                b.input_exact(&format!("x{i}"), Elem::U16, Some(Range::new(0.0, 1.0)))
                    .unwrap()
            })
            .collect();
        let mut acc = xs[0];
        for x in &xs[1..n.max(2)] {
            acc = if kind == "chain" {
                b.mul(acc, *x).unwrap()
            } else {
                let k = b.constant_exact(Elem::U16, 3.0).unwrap();
                let s = b.mul(*x, k).unwrap();
                b.add(acc, s).unwrap()
            };
        }
        b.output("y", acc).unwrap();
        let p = b.finish().unwrap();
        let plan = compile(&p).unwrap().plan;
        let depth = bgv::mult_depth(&plan);
        let client = BgvClient::generate(depth).unwrap();
        let mut ev = BgvEvaluator::new(depth).unwrap();
        ev.load_keys(&client.evaluation_keys().unwrap()).unwrap();
        let req: Vec<Vec<u8>> = plan
            .inputs
            .iter()
            .map(|i| client.encrypt(i.elem, 1).unwrap())
            .collect();
        let t = median(5, || {
            let cts = plan
                .inputs
                .iter()
                .zip(&req)
                .map(|(i, b)| ev.load(i.elem, b).unwrap())
                .collect();
            evaluate_exact(&ev, &plan, cts).unwrap();
        });
        println!(
            "{kind} n={n}: depth {depth}, ops {:?}, evaluate {t:.2} ms",
            plan.op_counts()
        );
    }
}
