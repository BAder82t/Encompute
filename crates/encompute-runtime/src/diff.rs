use encompute_backend::rng::Rng;
use encompute_evaluator::{EvaluatorSession, Semantics};
use encompute_ir::{evaluate, Inputs, Outputs, Program, Range, Result};
use serde::Serialize;

use crate::client::ClientSession;

/// Boundary values of an exact input's range: the ends, their neighbours,
/// and -1, 0, 1 where in range.
fn boundaries(r: Range) -> Vec<f64> {
    let (lo, hi) = (r.lo as i128, r.hi as i128);
    let mut v: Vec<i128> = [lo, lo + 1, hi - 1, hi, -1, 0, 1]
        .into_iter()
        .filter(|x| (lo..=hi).contains(x))
        .collect();
    v.sort_unstable();
    v.dedup();
    v.into_iter().map(|x| x as f64).collect()
}

/// Inputs for test case `case`: case 0 puts every element at its range's
/// low end, case 1 at the high end, later cases are uniform samples. Exact
/// (integer) inputs are integers; after the two end cases, a quarter of
/// their values are boundary values (see [`boundaries`]).
pub fn sample_inputs(program: &Program, case: usize, seed: u64) -> Inputs {
    let mut rng = Rng::new(seed ^ (case as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    program
        .inputs()
        .map(|(id, name, shape, range)| {
            let exact = program.node(id).ty.elem.is_exact();
            let v = (0..shape.len())
                .map(|_| match case {
                    0 => range.lo,
                    1 => range.hi,
                    _ if exact => {
                        let b = boundaries(range);
                        if rng.next_u64().is_multiple_of(4) {
                            b[(rng.next_u64() % b.len() as u64) as usize]
                        } else {
                            // Uniform integer in [lo, hi], in integers:
                            // spans reach 2^54, beyond exact f64.
                            let (lo, hi) = (range.lo as i128, range.hi as i128);
                            let span = (hi - lo + 1) as u64;
                            (lo + i128::from(rng.next_u64() % span)) as f64
                        }
                    }
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
    /// Max of |error| / max(|expected|, precision).
    pub max_relative: f64,
    /// Case index with the largest error.
    pub worst_case: usize,
    /// Vector outputs: fraction of cases whose argmax matches plaintext.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argmax_agreement: Option<f64>,
    /// Vector outputs of length ≥ 5: mean overlap of the top-5 sets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top5_overlap: Option<f64>,
}

fn top_k(v: &[f64], k: usize) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..v.len()).collect();
    idx.sort_by(|&a, &b| v[b].total_cmp(&v[a]));
    idx.truncate(k);
    idx
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FailingCase {
    pub case: usize,
    pub inputs: Inputs,
    pub expected: Outputs,
    pub got: Outputs,
}

/// Plaintext reference vs backend, per output, for approximate programs.
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

/// Exact programs: every output must equal the reference exactly.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExactReport {
    pub backend: String,
    pub cases: usize,
    pub seed: u64,
    pub matches: usize,
    pub mismatches: usize,
    /// Mismatching cases per output.
    pub outputs: Vec<ExactOutput>,
    pub passed: bool,
    /// The first mismatching case.
    pub failing: Option<FailingCase>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExactOutput {
    pub name: String,
    pub mismatches: usize,
}

/// Result of a differential test, by program semantics.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "semantics", rename_all = "lowercase")]
pub enum TestReport {
    Approximate(DiffReport),
    Exact(ExactReport),
}

impl TestReport {
    pub fn passed(&self) -> bool {
        match self {
            TestReport::Approximate(r) => r.passed,
            TestReport::Exact(r) => r.passed,
        }
    }

    pub fn cases(&self) -> usize {
        match self {
            TestReport::Approximate(r) => r.cases,
            TestReport::Exact(r) => r.cases,
        }
    }

    pub fn backend(&self) -> &str {
        match self {
            TestReport::Approximate(r) => &r.backend,
            TestReport::Exact(r) => &r.backend,
        }
    }

    pub fn failing(&self) -> Option<&FailingCase> {
        match self {
            TestReport::Approximate(r) => r.failing.as_ref(),
            TestReport::Exact(r) => r.failing.as_ref(),
        }
    }

    /// The approximate report, for CKKS programs.
    pub fn approx(&self) -> Option<&DiffReport> {
        match self {
            TestReport::Approximate(r) => Some(r),
            TestReport::Exact(_) => None,
        }
    }

    pub fn exact(&self) -> Option<&ExactReport> {
        match self {
            TestReport::Approximate(_) => None,
            TestReport::Exact(r) => Some(r),
        }
    }
}

/// Run `cases` sampled inputs through the reference semantics and through
/// client → evaluator → client (envelopes included). Approximate outputs
/// must be within the program's precision; exact outputs must be equal.
pub fn diff_test(
    client: &ClientSession,
    evaluator: &EvaluatorSession,
    program: &Program,
    cases: usize,
    seed: u64,
) -> Result<TestReport> {
    Ok(match evaluator.compiled().semantics() {
        Semantics::Approximate => {
            TestReport::Approximate(diff_approx(client, evaluator, program, cases, seed)?)
        }
        Semantics::Exact => TestReport::Exact(diff_exact(client, evaluator, program, cases, seed)?),
    })
}

fn diff_exact(
    client: &ClientSession,
    evaluator: &EvaluatorSession,
    program: &Program,
    cases: usize,
    seed: u64,
) -> Result<ExactReport> {
    let mut outputs: Vec<ExactOutput> = program
        .outputs()
        .iter()
        .map(|o| ExactOutput {
            name: o.name.clone(),
            mismatches: 0,
        })
        .collect();
    let (mut matches, mut failing) = (0, None);
    for case in 0..cases {
        let inputs = sample_inputs(program, case, seed);
        let expected = evaluate(program, &inputs)?;
        let (response, _) = evaluator.execute(&client.encrypt(program, &inputs)?)?;
        let got = client.decrypt(&response)?;
        let mut ok = true;
        for o in &mut outputs {
            if expected[&o.name] != got[&o.name] {
                o.mismatches += 1;
                ok = false;
            }
        }
        if ok {
            matches += 1;
        } else if failing.is_none() {
            failing = Some(FailingCase {
                case,
                inputs,
                expected,
                got,
            });
        }
    }
    Ok(ExactReport {
        backend: client.kind().label().0.to_owned(),
        cases,
        seed,
        matches,
        mismatches: cases - matches,
        outputs,
        passed: matches == cases,
        failing,
    })
}

fn diff_approx(
    client: &ClientSession,
    evaluator: &EvaluatorSession,
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
            max_relative: 0.0,
            worst_case: 0,
            argmax_agreement: None,
            top5_overlap: None,
        })
        .collect();
    let mut worst: Option<(f64, FailingCase)> = None;
    let mut elements = vec![0usize; errs.len()];
    let mut argmax_hits = vec![0usize; errs.len()];
    let mut top5 = vec![0f64; errs.len()];

    for case in 0..cases {
        let inputs = sample_inputs(program, case, seed);
        let expected = evaluate(program, &inputs)?;
        let (response, _) = evaluator.execute(&client.encrypt(program, &inputs)?)?;
        let got = client.decrypt(&response)?;
        let mut case_max: f64 = 0.0;
        for (i, e) in errs.iter_mut().enumerate() {
            let (want, have) = (&expected[&e.name], &got[&e.name]);
            if want.len() > 1 {
                argmax_hits[i] += usize::from(top_k(want, 1) == top_k(have, 1));
                if want.len() >= 5 {
                    let (a, b) = (top_k(want, 5), top_k(have, 5));
                    top5[i] += a.iter().filter(|j| b.contains(j)).count() as f64 / 5.0;
                }
            }
            for (x, y) in want.iter().zip(have) {
                let d = (x - y).abs();
                e.max_relative = e.max_relative.max(d / x.abs().max(program.precision()));
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
    for (i, (e, n)) in errs.iter_mut().zip(elements).enumerate() {
        e.mean_abs /= n.max(1) as f64;
        let len = program.node(program.outputs()[i].value).ty.shape.len();
        if len > 1 && cases > 0 {
            e.argmax_agreement = Some(argmax_hits[i] as f64 / cases as f64);
        }
        if len >= 5 && cases > 0 {
            e.top5_overlap = Some(top5[i] / cases as f64);
        }
    }
    let max_error = errs.iter().map(|e| e.max_abs).fold(0.0, f64::max);
    let passed = max_error <= program.precision();
    Ok(DiffReport {
        backend: client.kind().label().0.to_owned(),
        cases,
        seed,
        precision: program.precision(),
        outputs: errs,
        max_error,
        passed,
        failing: if passed { None } else { worst.map(|(_, c)| c) },
    })
}
