//! TFHE-rs implementation of [`encompute_backend::ExactEvaluator`] (feature
//! `tfhe-rs`). Research use: TFHE-rs source is BSD-3-Clause-Clear, and Zama
//! states that commercial use of its technology requires a separate patent
//! license; the off-by-default feature does not change that. No TFHE-rs type
//! leaves this crate.

use encompute_exact::ExactProfile;

#[cfg(feature = "tfhe-rs")]
pub mod tfhe_rs;

/// TFHE-rs 1.8.1 default: 2-bit message / 2-bit carry blocks, KS-PBS,
/// TUniform noise, failure probability 2^-128, 128-bit security.
pub fn default_profile() -> ExactProfile {
    ExactProfile {
        backend: "tfhe-rs".into(),
        backend_version: "1.8.1".into(),
        profile: "PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128".into(),
        security: "128-bit".into(),
        failure_probability: "2^-128".into(),
        parameter_selector_version: "tfhe-v1".into(),
    }
}
