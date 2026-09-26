//! The TFHE-rs research backend's identity, as pure constants: artifacts
//! and envelopes name it, and production builds recognize (and refuse) it,
//! without linking TFHE-rs. TFHE-rs itself is only in research builds
//! (`encompute-tfhe`, feature `research-tfhe-rs`): commercial use of Zama's
//! technology needs a patent license from Zama.

use crate::ExactProfile;

pub const TFHE_RS_BACKEND: &str = "tfhe-rs";
pub const TFHE_RS_VERSION: &str = "1.8.1";

/// TFHE-rs 1.8.1 default: 2-bit message / 2-bit carry blocks, KS-PBS,
/// TUniform noise, failure probability 2^-128, 128-bit security.
pub fn tfhe_rs_profile() -> ExactProfile {
    ExactProfile {
        backend: TFHE_RS_BACKEND.into(),
        backend_version: TFHE_RS_VERSION.into(),
        profile: "PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128".into(),
        security: "128-bit".into(),
        failure_probability: "2^-128".into(),
        parameter_selector_version: "tfhe-v1".into(),
    }
}
