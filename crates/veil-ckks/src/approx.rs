//! Chebyshev approximation of elementwise functions over an interval.

use serde::{Deserialize, Serialize};

/// `f(x) ≈ Σ c_k T_k(y)` with `y = (2x − (lo + hi)) / (hi − lo)`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Chebyshev {
    pub lo: f64,
    pub hi: f64,
    pub coeffs: Vec<f64>,
    /// Max |f − approximation| over a dense grid on `[lo, hi]`.
    pub max_error: f64,
}

impl Chebyshev {
    pub fn degree(&self) -> usize {
        self.coeffs.len() - 1
    }

    /// Clenshaw evaluation.
    pub fn eval(&self, x: f64) -> f64 {
        let y = (2.0 * x - (self.lo + self.hi)) / (self.hi - self.lo);
        let (mut b1, mut b2) = (0.0, 0.0);
        for &c in self.coeffs.iter().skip(1).rev() {
            let b0 = 2.0 * y * b1 - b2 + c;
            b2 = b1;
            b1 = b0;
        }
        y * b1 - b2 + self.coeffs[0]
    }
}

const GRID: usize = 4096;

/// Interpolate `f` at the Chebyshev nodes of degree `d`.
fn interpolate(f: &impl Fn(f64) -> f64, lo: f64, hi: f64, d: usize) -> Vec<f64> {
    let n = d + 1;
    let fx: Vec<f64> = (0..n)
        .map(|j| {
            let t = std::f64::consts::PI * (j as f64 + 0.5) / n as f64;
            f(0.5 * (hi - lo) * t.cos() + 0.5 * (hi + lo))
        })
        .collect();
    (0..n)
        .map(|k| {
            let s: f64 = (0..n)
                .map(|j| {
                    let t = std::f64::consts::PI * (j as f64 + 0.5) / n as f64;
                    fx[j] * (k as f64 * t).cos()
                })
                .sum();
            let c = 2.0 * s / n as f64;
            if k == 0 {
                c / 2.0
            } else {
                c
            }
        })
        .collect()
}

/// Lowest-degree Chebyshev interpolant of `f` on `[lo, hi]` whose error on a
/// dense grid is at most `tolerance`, or `None` if `max_degree` is not enough.
pub fn chebyshev_fit(
    f: impl Fn(f64) -> f64,
    lo: f64,
    hi: f64,
    tolerance: f64,
    max_degree: usize,
) -> Option<Chebyshev> {
    for d in 1..=max_degree {
        let mut c = Chebyshev {
            lo,
            hi,
            coeffs: interpolate(&f, lo, hi, d),
            max_error: 0.0,
        };
        c.max_error = (0..=GRID)
            .map(|i| {
                let x = lo + (hi - lo) * i as f64 / GRID as f64;
                (f(x) - c.eval(x)).abs()
            })
            .fold(0.0, f64::max);
        if c.max_error <= tolerance {
            return Some(c);
        }
    }
    None
}
