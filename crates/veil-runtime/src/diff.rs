use serde::Serialize;
use veil_backend::rng::Rng;
use veil_backend::CkksBackend;
use veil_ckks::CkksPlan;
use veil_ir::{evaluate, Inputs, Outputs, Program, Result};

use crate::exec::run;

/// Inputs for test case `case`: case 0 puts every element at its range's
/// low end, case 1 at the high end, later cases are uniform samples.
pub fn sample_inputs(program: &Program, case: usize, seed: u64) -> Inputs {
    let mut rng = Rng::new(seed ^ (case as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    program
        .inputs()
        .map(|(_, name, shape, range)| {
            let v = (0..shape.len())
                .map(|_| match case {
                    0 => range.lo,
                    1 => range.hi,
                    _ => rng.uniform(range.lo, range.hi),
                })
                .collect();
            (name.to_owned(), v)
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OutputError {
    pub name: String,
    pub max_abs: f64,
    pub mean_abs: f64,
    /// Case index with the largest error.
    pub worst_case: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FailingCase {
    pub case: usize,
    pub inputs: Inputs,
    pub expected: Outputs,
    pub got: Outputs,
}

/// Plaintext reference vs backend, per output.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DiffReport {
    pub backend: String,
    pub cases: usize,
    pub seed: u64,
    pub precision: f64,
    pub outputs: Vec<OutputError>,
    pub max_error: f64,
    pub passed: bool,
    /// The worst case, recorded when the test fails.
    pub failing: Option<FailingCase>,
}

/// Run `cases` sampled inputs through the reference semantics and through
/// `backend`, and compare every output element against the program's precision.
pub fn diff_test<B: CkksBackend>(
    backend: &B,
    sk: &B::SecretKey,
    plan: &CkksPlan,
    program: &Program,
    cases: usize,
    seed: u64,
) -> Result<DiffReport> {
    let mut errs: Vec<OutputError> = program
        .outputs()
        .iter()
        .map(|o| OutputError {
            name: o.name.clone(),
            max_abs: 0.0,
            mean_abs: 0.0,
            worst_case: 0,
        })
        .collect();
    let mut worst: Option<(f64, FailingCase)> = None;
    let mut elements = vec![0usize; errs.len()];

    for case in 0..cases {
        let inputs = sample_inputs(program, case, seed);
        let expected = evaluate(program, &inputs)?;
        let got = run(backend, sk, plan, program, &inputs)?;
        let mut case_max: f64 = 0.0;
        for (i, e) in errs.iter_mut().enumerate() {
            for (x, y) in expected[&e.name].iter().zip(&got[&e.name]) {
                let d = (x - y).abs();
                e.mean_abs += d;
                elements[i] += 1;
                if d > e.max_abs {
                    e.max_abs = d;
                    e.worst_case = case;
                }
                case_max = case_max.max(d);
            }
        }
        if worst.as_ref().is_none_or(|(m, _)| case_max > *m) {
            worst = Some((
                case_max,
                FailingCase {
                    case,
                    inputs,
                    expected,
                    got,
                },
            ));
        }
    }
    for (e, n) in errs.iter_mut().zip(elements) {
        e.mean_abs /= n.max(1) as f64;
    }
    let max_error = errs.iter().map(|e| e.max_abs).fold(0.0, f64::max);
    let passed = max_error <= program.precision();
    Ok(DiffReport {
        backend: backend.name().to_owned(),
        cases,
        seed,
        precision: program.precision(),
        outputs: errs,
        max_error,
        passed,
        failing: if passed { None } else { worst.map(|(_, c)| c) },
    })
}
