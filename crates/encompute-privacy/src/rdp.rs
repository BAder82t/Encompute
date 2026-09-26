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
//! up.

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

fn logsumexp(xs: &[f64]) -> f64 {
    let m = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if m == f64::NEG_INFINITY {
        return m;
    }
    m + libm::log(xs.iter().map(|x| libm::exp(x - m)).sum::<f64>())
}

/// The Zhu–Wang Theorem 6 bound on the RDP at order `alpha` of a release
/// Poisson-sampled at rate `q`, whose base mechanism has RDP `alpha * rho`
/// (not yet capped by the unsampled curve).
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
    let mut terms = vec![(a - 1.0) * l1q + libm::log(a * q - q + 1.0)];
    terms.push(ln_binom(alpha, 2) + 2.0 * lq + (a - 2.0) * l1q + eps(2));
    for j in 3..=alpha {
        let jf = j as f64;
        terms.push(
            libm::log(3.0) + ln_binom(alpha, j) + jf * lq + (a - jf) * l1q + (jf - 1.0) * eps(j),
        );
    }
    logsumexp(&terms) / (a - 1.0)
}

/// One release's RDP curve over [`ORDERS`], rounded up.
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
/// (CKS 2020, Proposition 12), rounded up.
pub fn epsilon(curve: &[f64; N_ORDERS], delta: f64) -> f64 {
    assert!(delta > 0.0 && delta < 1.0);
    if curve.iter().all(|&r| r == 0.0) {
        return 0.0;
    }
    let mut best = f64::INFINITY;
    for (i, &alpha) in ORDERS.iter().enumerate() {
        let a = alpha as f64;
        let e = curve[i]
            + (libm::log(1.0 / delta) + (a - 1.0) * libm::log1p(-1.0 / a) - libm::log(a))
                / (a - 1.0);
        best = best.min(e);
    }
    up(best.max(0.0), 8)
}
