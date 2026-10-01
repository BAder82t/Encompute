//! Rényi DP accounting for Poisson-subsampled releases (DP-SGD).
//!
//! A sampled release includes each privacy unit independently with
//! probability `q`, sums the units' clipped contributions, and adds discrete
//! Gaussian noise. The pieces:
//!
//! - **The base mechanism.** The discrete Gaussian with L2 sensitivity `Δ`
//!   and variance `σ²` is `ρ`-zCDP with `ρ = Δ²/(2σ²)` (Canonne, Kamath and
//!   Steinke 2020, Theorem 14). So its Rényi DP is `ε(α) ≤ αρ` for every
//!   order `α > 1`.
//! - **Subsampling.** Poisson sampling amplifies any mechanism with a known
//!   RDP curve. We use the *general* upper bound of Zhu and Wang (2019,
//!   "Poisson subsampled Rényi differential privacy", Theorem 6), which
//!   holds for every mechanism. We deliberately avoid the tighter
//!   Gaussian-specific formula: it is derived for the continuous Gaussian,
//!   and our noise is discrete. For an integer order `α ≥ 2`:
//!
//!   ```text
//!   ε'(α) ≤ 1/(α-1) · log( (1-q)^(α-1) (αq - q + 1)
//!                          + C(α,2) q² (1-q)^(α-2) e^(ε(2))
//!                          + 3 Σ_{j=3..α} C(α,j) q^j (1-q)^(α-j) e^((j-1)ε(j)) )
//!   ```
//!
//!   Subsampling never hurts, so we take `min(ε'(α), αρ)`.
//! - **Composition.** Releases compose by adding their curves order by
//!   order.
//! - **Conversion.** The composed curve converts to `(ε, δ)` with
//!   `ε = min_α [ r(α) + (ln(1/δ) + (α-1) ln(1-1/α) - ln α) / (α-1) ]`
//!   (Canonne, Kamath and Steinke 2020, Proposition 12).
//!
//! The neighbouring relation is adding or removing one privacy unit (one
//! patient, or all of one patient's grouped records). The arithmetic is
//! `libm`, so every party computes identical bits, and the results round
//! up: each curve value by an allowance for its rounding error, and each
//! epsilon by a relative margin ([`crate::accountant::RELATIVE_MARGIN`]),
//! then a few ulps.

use crate::accountant::conservative;

/// The integer Rényi orders the accountant evaluates: every order to 256,
/// then a spread to 1024. High orders matter when a release is heavily
/// subsampled: they let the conversion reach small epsilons.
pub const ORDERS: [u32; N_ORDERS] = orders();
pub const N_ORDERS: usize = 255 + 8;

const fn orders() -> [u32; N_ORDERS] {
    let mut o = [0u32; N_ORDERS];
    let mut i = 0;
    while i < 255 {
        o[i] = i as u32 + 2;
        i += 1;
    }
    let tail = [288, 320, 384, 448, 512, 640, 768, 1024];
    let mut j = 0;
    while j < 8 {
        o[255 + j] = tail[j];
        j += 1;
    }
    o
}

fn up(x: f64, ulps: u32) -> f64 {
    (0..ulps).fold(x, |x, _| x.next_up())
}

fn ln_binom(n: u32, k: u32) -> f64 {
    let (n, k) = (n as f64, k as f64);
    libm::lgamma(n + 1.0) - libm::lgamma(k + 1.0) - libm::lgamma(n - k + 1.0)
}

/// A bound on the absolute rounding error of a `libm` evaluation whose
/// intermediate values sum, in magnitude, to `magnitude`: each operation
/// is accurate to an ulp or two, so a multiple of machine epsilon.
fn rounding_allowance(magnitude: f64) -> f64 {
    8.0 * f64::EPSILON * magnitude
}

/// The Zhu–Wang Theorem 6 bound on the RDP at order `alpha` of a release
/// Poisson-sampled at rate `q`, whose base mechanism has RDP `alpha * rho`
/// (not yet capped by the unsampled curve).
///
/// Rounded up: the log-sum is taken around its largest term with `log1p`
/// (no cancellation in `log(1 + small)`), and raised by an allowance for
/// the rounding error of every term (weighted by its share of the sum) and
/// of the sum. Before, low orders came out up to about 3e-11 relative too
/// small (review finding DP-7).
pub fn subsampled_bound(rho: f64, q: f64, alpha: u32) -> f64 {
    assert!(alpha >= 2 && (0.0..=1.0).contains(&q) && rho >= 0.0);
    let a = alpha as f64;
    if q == 0.0 {
        return 0.0;
    }
    if q == 1.0 {
        return a * rho;
    }
    let (lq, l1q) = (libm::log(q), libm::log1p(-q));
    let eps = |j: u32| j as f64 * rho;
    // Each term with the magnitude of the values it is computed from.
    let lgammas = |j: u32| {
        let lg = |x: u32| libm::lgamma(x as f64 + 1.0).abs();
        lg(alpha) + lg(j) + lg(alpha - j)
    };
    // log(aq - q + 1), without rounding 1 + (a-1)q first.
    let log_first = libm::log1p((a - 1.0) * q);
    let mut terms = vec![(
        (a - 1.0) * l1q + log_first,
        ((a - 1.0) * l1q).abs() + log_first.abs(),
    )];
    terms.push((
        ln_binom(alpha, 2) + 2.0 * lq + (a - 2.0) * l1q + eps(2),
        lgammas(2) + (2.0 * lq).abs() + ((a - 2.0) * l1q).abs() + eps(2),
    ));
    for j in 3..=alpha {
        let jf = j as f64;
        terms.push((
            libm::log(3.0) + ln_binom(alpha, j) + jf * lq + (a - jf) * l1q + (jf - 1.0) * eps(j),
            2.0 + lgammas(j) + (jf * lq).abs() + ((a - jf) * l1q).abs() + (jf - 1.0) * eps(j),
        ));
    }
    // log(sum e^t) = m + log1p(sum of the others' e^(t - m)).
    let top = (0..terms.len())
        .max_by(|&i, &k| terms[i].0.total_cmp(&terms[k].0))
        .expect("at least two terms");
    let m = terms[top].0;
    let w: Vec<f64> = terms.iter().map(|(t, _)| libm::exp(t - m)).collect();
    let rest: f64 = w
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != top)
        .map(|(_, w)| w)
        .sum();
    let total = 1.0 + rest;
    let weighted: f64 = terms
        .iter()
        .zip(&w)
        .map(|((_, mag), w)| w / total * mag)
        .sum();
    let allowance = rounding_allowance(m.abs() + weighted + terms.len() as f64 * rest / total);
    (m + libm::log1p(rest) + allowance) / (a - 1.0)
}

/// One release's RDP curve over [`ORDERS`], rounded up (the subsampled
/// bound carries its own rounding allowance; `alpha * rho` is exact to an
/// ulp).
pub fn release_curve(rho: f64, sampling_rate: Option<f64>) -> [f64; N_ORDERS] {
    let mut c = [0.0; N_ORDERS];
    for (i, &alpha) in ORDERS.iter().enumerate() {
        let full = alpha as f64 * rho;
        let r = match sampling_rate {
            Some(q) => subsampled_bound(rho, q, alpha).min(full),
            None => full,
        };
        c[i] = up(r, 4);
    }
    c
}

/// `n` compositions of one curve, rounded up.
pub fn scaled(curve: &[f64; N_ORDERS], n: u64) -> [f64; N_ORDERS] {
    let mut c = [0.0; N_ORDERS];
    for (a, b) in c.iter_mut().zip(curve) {
        *a = up(b * n as f64, 4);
    }
    c
}

/// Composes curves (adds them order by order), rounding up.
pub fn compose(curves: &[[f64; N_ORDERS]]) -> [f64; N_ORDERS] {
    let mut t = [0.0; N_ORDERS];
    for c in curves {
        for (a, b) in t.iter_mut().zip(c) {
            *a = up(*a + b, 1);
        }
    }
    t
}

/// The smallest `ε` such that the composed curve satisfies `(ε, δ)`-DP
/// (CKS 2020, Proposition 12), rounded up (with the relative margin).
pub fn epsilon(curve: &[f64; N_ORDERS], delta: f64) -> f64 {
    assert!(delta > 0.0 && delta < 1.0);
    if curve.iter().all(|&r| r == 0.0) {
        return 0.0;
    }
    let mut best = f64::INFINITY;
    for (i, &alpha) in ORDERS.iter().enumerate() {
        let a = alpha as f64;
        let (ld, la, lb) = (
            libm::log(1.0 / delta),
            (a - 1.0) * libm::log1p(-1.0 / a),
            libm::log(a),
        );
        let e = curve[i]
            + (ld + la - lb) / (a - 1.0)
            + rounding_allowance(curve[i] + (ld.abs() + la.abs() + lb + 1.0) / (a - 1.0));
        best = best.min(e);
    }
    conservative(up(best.max(0.0), 8))
}
