//! Privacy accounting under zero-concentrated DP (Bun and Steinke, TCC
//! 2016): a release with discrete Gaussian noise `sigma^2` on a query of L2
//! sensitivity `Delta` costs `rho = Delta^2 / (2 sigma^2)` (Canonne, Kamath
//! and Steinke 2020, Theorem 14); costs compose by addition; and the
//! composed `rho` converts to `(epsilon, delta)` with CKS Corollary 13
//! (`cdp_delta`/`cdp_eps`, ported from their reference `cdp2adp.py`).
//!
//! Every party must reach the same decision, so the arithmetic is the
//! pure-Rust `libm` (identical bits on every platform, unlike the system
//! maths library), and each result is rounded up a few ulps so accounting
//! is never optimistic.

use serde::{Deserialize, Serialize};

use encompute_ir::confidentiality::PrivacyBudget;
use encompute_ir::{Code, Error, Result};

/// Composes zCDP costs and converts them to `(epsilon, delta)`.
pub trait PrivacyAccountant {
    fn name(&self) -> &'static str;
    /// The combined cost of releases costing `rhos`, in order.
    fn compose(&self, rhos: &[f64]) -> f64;
    /// The smallest epsilon (rounded up) with the composed cost satisfying
    /// `(epsilon, delta)`-DP.
    fn epsilon(&self, rho: f64, delta: f64) -> f64;
}

/// zCDP composition with the CKS conversion.
pub struct Zcdp;

fn up(x: f64, ulps: u32) -> f64 {
    (0..ulps).fold(x, |x, _| x.next_up())
}

impl PrivacyAccountant for Zcdp {
    fn name(&self) -> &'static str {
        "zcdp-cks2020"
    }

    fn compose(&self, rhos: &[f64]) -> f64 {
        rhos.iter().fold(0.0, |a, r| up(a + r, 1))
    }

    fn epsilon(&self, rho: f64, delta: f64) -> f64 {
        if rho == 0.0 {
            return 0.0;
        }
        up(cdp_eps(rho, delta), 8)
    }
}

/// `cdp_delta(rho, eps)` (CKS reference).
pub fn cdp_delta(rho: f64, eps: f64) -> f64 {
    assert!(rho >= 0.0 && eps >= 0.0);
    if rho == 0.0 {
        return 0.0;
    }
    let mut amin = 1.01;
    let mut amax = (eps + 1.0) / (2.0 * rho) + 2.0;
    let mut alpha = amin;
    for _ in 0..1000 {
        alpha = (amin + amax) / 2.0;
        let derivative = (2.0 * alpha - 1.0) * rho - eps + libm::log1p(-1.0 / alpha);
        if derivative < 0.0 {
            amin = alpha;
        } else {
            amax = alpha;
        }
    }
    let delta = libm::exp((alpha - 1.0) * (alpha * rho - eps) + alpha * libm::log1p(-1.0 / alpha))
        / (alpha - 1.0);
    delta.min(1.0)
}

/// `cdp_eps(rho, delta)` (CKS reference): the upper end of a bisection
/// that maintains `cdp_delta(rho, eps) <= delta`.
pub fn cdp_eps(rho: f64, delta: f64) -> f64 {
    assert!(rho >= 0.0 && delta > 0.0);
    if delta >= 1.0 || rho == 0.0 {
        return 0.0;
    }
    let mut epsmin = 0.0;
    let mut epsmax = rho + 2.0 * libm::sqrt(rho * libm::log(1.0 / delta));
    for _ in 0..1000 {
        let eps = (epsmin + epsmax) / 2.0;
        if cdp_delta(rho, eps) <= delta {
            epsmax = eps;
        } else {
            epsmin = eps;
        }
    }
    epsmax
}

/// The zCDP cost of one discrete Gaussian release: `Delta^2 / (2 sigma^2)`,
/// rounded up.
pub fn gaussian_rho(sensitivity: u64, sigma2: u64) -> Result<f64> {
    if sigma2 == 0 {
        return Err(Error::new(Code::PrivacyMechanism, "zero noise: no privacy"));
    }
    let s = sensitivity as f64;
    Ok(up((s * s) / (2.0 * sigma2 as f64), 2))
}

/// Accumulated cost against a budget.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Cost {
    pub rho: f64,
    /// Epsilon at the budget's delta.
    pub epsilon: f64,
    pub delta: f64,
}

impl Cost {
    pub fn of(rho: f64, budget: &PrivacyBudget) -> Result<Self> {
        budget.validate()?;
        Ok(Self {
            rho,
            epsilon: Zcdp.epsilon(rho, budget.delta),
            delta: budget.delta,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values from the reference implementation (Python) for the same
    /// inputs.
    #[test]
    fn matches_the_reference() {
        let e = cdp_eps(0.005, 1e-6);
        assert!((e - 0.4299414688369493).abs() < 1e-12, "{e}");
        let d = cdp_delta(0.005, 1.0);
        assert!((d - 1.1626191118257529e-24).abs() / 1.16e-24 < 1e-9, "{d}");
    }

    #[test]
    fn monotone_and_conservative() {
        let mut last = 0.0;
        for i in 1..50 {
            let e = Zcdp.epsilon(0.01 * i as f64, 1e-6);
            assert!(e > last);
            last = e;
            assert!(cdp_delta(0.01 * i as f64, e) <= 1e-6);
        }
        assert_eq!(Zcdp.epsilon(0.0, 1e-6), 0.0);
    }
}
