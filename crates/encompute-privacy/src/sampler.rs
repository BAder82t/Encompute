//! Exact discrete Gaussian sampling: a line-by-line port of the reference
//! implementation by Canonne, Kamath and Steinke, "The Discrete Gaussian
//! for Differential Privacy" (NeurIPS 2020; github.com/IBM/
//! discrete-gaussian-differential-privacy, discretegauss.py, Apache-2.0).
//! Rational arithmetic is exact (big integers), so no floating-point value
//! ever shapes the output distribution.
//!
//! Randomness comes from [`Csprng`]: the ChaCha20 keystream under a key
//! from the operating system. A seeded generator exists only behind the
//! `insecure-deterministic-noise` feature, and every sample it produces is
//! labelled as such in the ledger, where production verification refuses
//! it.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_rational::BigRational;
use num_traits::{One, Signed, Zero};

use encompute_ir::{Code, Error, Result};

/// The label production randomness carries in the ledger.
pub const CSPRNG: &str = "csprng";
/// The label deterministic test randomness carries; never accepted in
/// production verification.
pub const INSECURE_TESTING: &str = "INSECURE-DETERMINISTIC-TESTING-ONLY";

/// A cryptographically secure generator: ChaCha20 under an OS-random key.
pub struct Csprng {
    cipher: chacha20::ChaCha20,
    label: &'static str,
}

impl Csprng {
    pub fn from_os() -> Result<Self> {
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::getrandom(key.as_mut())
            .map_err(|e| Error::new(Code::PrivacyMechanism, format!("no randomness: {e}")))?;
        Ok(Self {
            cipher: chacha20::ChaCha20::new((&*key).into(), &[0u8; 12].into()),
            label: CSPRNG,
        })
    }

    /// Reproducible noise, for tests only. Everything it produces is
    /// labelled [`INSECURE_TESTING`].
    #[cfg(feature = "insecure-deterministic-noise")]
    pub fn insecure_from_seed(seed: [u8; 32]) -> Self {
        Self {
            cipher: chacha20::ChaCha20::new((&seed).into(), &[0u8; 12].into()),
            label: INSECURE_TESTING,
        }
    }

    pub fn label(&self) -> &'static str {
        self.label
    }

    fn fill(&mut self, buf: &mut [u8]) {
        buf.fill(0);
        self.cipher.apply_keystream(buf);
    }

    /// Uniform in `[0, m)`, by rejection (unbiased).
    fn uniform(&mut self, m: &BigUint) -> BigUint {
        debug_assert!(!m.is_zero());
        let bits = m.bits();
        let bytes = bits.div_ceil(8) as usize;
        let top = if bits.is_multiple_of(8) {
            0xff
        } else {
            (1u16 << (bits % 8)) as u8 - 1
        };
        let mut buf = vec![0u8; bytes];
        loop {
            self.fill(&mut buf);
            buf[0] &= top;
            let v = BigUint::from_bytes_be(&buf);
            if &v < m {
                return v;
            }
        }
    }
}

fn numer_denom(x: &BigRational) -> (BigUint, BigUint) {
    (
        x.numer().to_biguint().expect("non-negative"),
        x.denom().to_biguint().expect("positive"),
    )
}

/// `sample_bernoulli(p)`, `0 <= p <= 1`.
fn bernoulli(p: &BigRational, rng: &mut Csprng) -> bool {
    let (n, d) = numer_denom(p);
    rng.uniform(&d) < n
}

/// `sample_bernoulli_exp1(x)`: `Bernoulli(exp(-x))` for `0 <= x <= 1`.
fn bernoulli_exp1(x: &BigRational, rng: &mut Csprng) -> bool {
    let mut k = BigInt::one();
    loop {
        if bernoulli(&(x / BigRational::from_integer(k.clone())), rng) {
            k += 1;
        } else {
            break;
        }
    }
    k.is_odd()
}

/// `sample_bernoulli_exp(x)`: `Bernoulli(exp(-x))` for `x >= 0`.
fn bernoulli_exp(x: &BigRational, rng: &mut Csprng) -> bool {
    let one = BigRational::one();
    let mut x = x.clone();
    while x > one {
        if bernoulli_exp1(&one, rng) {
            x -= &one;
        } else {
            return false;
        }
    }
    bernoulli_exp1(&x, rng)
}

/// `sample_geometric_exp_slow(x)`.
fn geometric_exp_slow(x: &BigRational, rng: &mut Csprng) -> BigInt {
    let mut k = BigInt::zero();
    loop {
        if bernoulli_exp(x, rng) {
            k += 1;
        } else {
            return k;
        }
    }
}

/// `sample_geometric_exp_fast(x)`.
fn geometric_exp_fast(x: &BigRational, rng: &mut Csprng) -> BigInt {
    if x.is_zero() {
        return BigInt::zero();
    }
    let (s, t) = numer_denom(x);
    let u = loop {
        let u = rng.uniform(&t);
        let b = bernoulli_exp(
            &BigRational::new(BigInt::from(u.clone()), BigInt::from(t.clone())),
            rng,
        );
        if b {
            break u;
        }
    };
    let v = geometric_exp_slow(&BigRational::one(), rng);
    let value = v * BigInt::from(t) + BigInt::from(u);
    value.div_floor(&BigInt::from(s))
}

/// `sample_dlaplace(scale)`.
fn dlaplace(scale: &BigRational, rng: &mut Csprng) -> BigInt {
    let half = BigRational::new(BigInt::one(), BigInt::from(2));
    let inv = scale.recip();
    loop {
        let sign = bernoulli(&half, rng);
        let magnitude = geometric_exp_fast(&inv, rng);
        if sign && magnitude.is_zero() {
            continue;
        }
        return if sign { -magnitude } else { magnitude };
    }
}

/// `floorsqrt(x)`: exact integer square root.
fn floorsqrt(x: &BigUint) -> BigUint {
    let (mut a, mut b) = (BigUint::zero(), BigUint::one());
    while &(&b * &b) <= x {
        b *= 2u32;
    }
    while &a + 1u32 < b {
        let c = (&a + &b) >> 1;
        if &(&c * &c) <= x {
            a = c;
        } else {
            b = c;
        }
    }
    a
}

/// `sample_dgauss(sigma2)`: one sample of the discrete Gaussian
/// `N_Z(0, sigma2)`.
pub fn discrete_gaussian(sigma2: u64, rng: &mut Csprng) -> Result<i64> {
    if sigma2 == 0 {
        return Ok(0);
    }
    let s2 = BigRational::from_integer(BigInt::from(sigma2));
    let t = floorsqrt(&BigUint::from(sigma2)) + 1u32;
    let t = BigRational::from_integer(BigInt::from_biguint(Sign::Plus, t));
    loop {
        let candidate = dlaplace(&t, rng);
        let y = BigRational::from_integer(candidate.abs());
        let d = &y - &s2 / &t;
        let bias = (&d * &d) / (BigRational::from_integer(BigInt::from(2)) * &s2);
        if bernoulli_exp(&bias, rng) {
            return i64::try_from(candidate)
                .map_err(|_| Error::new(Code::PrivacyMechanism, "noise sample out of range"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floorsqrt_is_exact() {
        for x in [
            0u64,
            1,
            2,
            3,
            4,
            15,
            16,
            17,
            1 << 40,
            (1 << 40) + 1,
            u64::MAX,
        ] {
            let r = floorsqrt(&BigUint::from(x));
            let r2 = &r * &r;
            let r1 = (&r + 1u32) * (&r + 1u32);
            assert!(r2 <= BigUint::from(x) && r1 > BigUint::from(x), "{x}");
        }
    }

    #[test]
    fn uniform_is_in_range() {
        let mut rng = Csprng::from_os().unwrap();
        for m in [1u32, 2, 3, 7, 255, 256, 257, 1000] {
            for _ in 0..200 {
                assert!(rng.uniform(&BigUint::from(m)) < BigUint::from(m));
            }
        }
    }
}
