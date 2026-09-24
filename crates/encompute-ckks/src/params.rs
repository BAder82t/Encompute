use encompute_ir::{Code, Error, Result};
use serde::{Deserialize, Serialize};

/// Maximum log2(Q·P) per ring dimension for 128-bit classical security.
#[derive(Debug)]
pub struct SecurityTable {
    pub source: &'static str,
    /// `(ring dimension N, max log2 QP)`, ascending.
    pub entries: &'static [(u32, u32)],
}

/// HE Standard 128-bit classical, uniform ternary secret, as pinned in
/// OpenFHE v1.5.1 (`src/core/lib/lattice/stdlatticeparms.cpp`,
/// `HEStd_ternary` / `HEStd_128_classic`). Capped at N = 2^16 (plan D8).
pub const SECURITY_TABLE: SecurityTable = SecurityTable {
    source: "HE Standard 128-bit classical, ternary secret (OpenFHE v1.5.1 stdlatticeparms.cpp)",
    entries: &[
        (1024, 27),
        (2048, 54),
        (4096, 109),
        (8192, 218),
        (16384, 438),
        (32768, 881),
        (65536, 1747),
    ],
};

/// Largest prime OpenFHE uses for the first and auxiliary moduli on 64-bit words.
const MAX_MOD_BITS: u32 = 60;
/// Largest scaling prime OpenFHE accepts for CKKS on 64-bit words.
const MAX_SCALE_BITS: u32 = 59;
const MIN_SCALE_BITS: u32 = 30;
/// Bits of headroom above the precision target for CKKS noise. Calibrated
/// against measured error in the OpenFHE tests; `encompute test` is the gate.
const NOISE_MARGIN_BITS: u32 = 22;

/// CKKS parameters. Scaling is OpenFHE `FLEXIBLEAUTO`, key switching `HYBRID`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CkksParams {
    pub ring_dim: u32,
    /// Batch size: slots used per ciphertext (power of two, ≤ ring_dim / 2).
    pub slots: u32,
    pub mult_depth: u32,
    pub scale_bits: u32,
    pub first_mod_bits: u32,
    /// Hybrid key-switching digits (dnum).
    pub num_large_digits: u32,
    /// Estimated log2(Q·P), computed the way OpenFHE v1.5.1 bounds it.
    pub log_qp: u32,
    /// Security-table limit for `ring_dim`.
    pub max_log_qp: u32,
    pub security: String,
    pub table_source: String,
}

/// Choose parameters for a plan of multiplicative `depth` whose values are
/// bounded by `max_abs`, meeting absolute `precision`, on `slots` slots.
pub fn select_params(depth: u32, max_abs: f64, precision: f64, slots: usize) -> Result<CkksParams> {
    let p = (1.0 / precision).log2().ceil().max(0.0) as u32;
    let m = max_abs.max(1.0).log2().ceil() as u32;
    let scale_bits = (p + m + NOISE_MARGIN_BITS).max(MIN_SCALE_BITS);
    if scale_bits > MAX_SCALE_BITS {
        return Err(Error::new(
            Code::PrecisionUnreachable,
            format!(
                "precision {precision} with values up to {max_abs:.3e} needs a {scale_bits}-bit scale; \
                 the maximum is {MAX_SCALE_BITS}. Relax the precision or narrow the input ranges"
            ),
        ));
    }
    // Decryption at the last level needs |value| · 2^scale < q0 / 2.
    let first_mod_bits = scale_bits + m + 3;
    if first_mod_bits > MAX_MOD_BITS {
        return Err(Error::new(
            Code::PrecisionUnreachable,
            format!(
                "values up to {max_abs:.3e} at a {scale_bits}-bit scale need a {first_mod_bits}-bit \
                 first modulus; the maximum is {MAX_MOD_BITS}. Relax the precision or narrow the input ranges"
            ),
        ));
    }

    let mult_depth = depth.max(1);
    let num_primes = mult_depth + 1;
    let num_large_digits = [3, 2, 1]
        .into_iter()
        .find(|&d| valid_digits(num_primes, d))
        .expect("one digit is always valid");
    let log_qp = estimate_log_qp(first_mod_bits, scale_bits, num_primes, num_large_digits);

    let slots = slots.next_power_of_two().max(2) as u32;
    let Some(&(ring_dim, max_log_qp)) = SECURITY_TABLE
        .entries
        .iter()
        .find(|(n, max)| *max >= log_qp && n / 2 >= slots)
    else {
        return Err(Error::new(
            Code::DepthExceeded,
            format!(
                "depth {depth} needs log2(QP) ≈ {log_qp} bits with {slots} slots; the largest \
                 128-bit parameter set (N = 65536) allows 1747. Reduce the depth (lower-degree \
                 approximations, fewer chained multiplications) — bootstrapping arrives in 0.2"
            ),
        ));
    };

    Ok(CkksParams {
        ring_dim,
        slots,
        mult_depth,
        scale_bits,
        first_mod_bits,
        num_large_digits,
        log_qp,
        max_log_qp,
        security: "128-bit classical".into(),
        table_source: SECURITY_TABLE.source.into(),
    })
}

/// OpenFHE rejects digit counts that leave a digit empty.
fn valid_digits(size_q: u32, dnum: u32) -> bool {
    if dnum > size_q {
        return false;
    }
    let per = size_q.div_ceil(dnum);
    size_q > per * (dnum - 1)
}

/// Mirrors `ParameterGenerationCKKSRNS::ParamsGenCKKSRNSInternal` and
/// `CryptoParametersRNS::EstimateLogP` in OpenFHE v1.5.1 for FLEXIBLEAUTO
/// scaling and HYBRID key switching.
fn estimate_log_qp(first: u32, scale: u32, num_primes: u32, dnum: u32) -> u32 {
    let mut log_q = first + (num_primes - 1) * scale;
    if log_q != MAX_MOD_BITS {
        log_q += 1;
    }
    let per = num_primes.div_ceil(dnum);
    let bits: Vec<u32> = (0..num_primes)
        .map(|i| if i == 0 { first } else { scale })
        .collect();
    let mut max_bits = bits
        .chunks(per as usize)
        .map(|c| c.iter().sum::<u32>())
        .max()
        .unwrap();
    if max_bits != MAX_MOD_BITS {
        max_bits += 1;
    }
    let size_p = max_bits.div_ceil(MAX_MOD_BITS);
    log_q + size_p * MAX_MOD_BITS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shallow_circuit_fits_small_ring() {
        let p = select_params(1, 1.0, 1e-3, 8).unwrap();
        assert_eq!(p.scale_bits, 32);
        assert_eq!(p.first_mod_bits, 35);
        // log QP = (35 + 32 + 1) + 60 = 128 > 109, so N = 8192.
        assert_eq!(p.log_qp, 128);
        assert_eq!(p.ring_dim, 8192);
        assert!(p.log_qp <= p.max_log_qp);
    }

    #[test]
    fn slots_force_larger_ring() {
        let p = select_params(1, 1.0, 1e-3, 5000).unwrap();
        assert_eq!(p.slots, 8192);
        assert_eq!(p.ring_dim, 16384);
    }

    #[test]
    fn errors_have_codes() {
        assert_eq!(
            select_params(200, 1.0, 1e-3, 8).unwrap_err().code,
            Code::DepthExceeded
        );
        assert_eq!(
            select_params(1, 1.0, 1e-12, 8).unwrap_err().code,
            Code::PrecisionUnreachable
        );
        assert_eq!(
            select_params(1, 1e9, 1e-3, 8).unwrap_err().code,
            Code::PrecisionUnreachable
        );
    }

    #[test]
    fn digits_match_openfhe_rule() {
        assert!(valid_digits(9, 3));
        assert!(!valid_digits(4, 3), "OpenFHE rejects 4 towers in 3 digits");
        assert!(valid_digits(4, 2));
        assert!(!valid_digits(2, 3));
    }
}
