//! CKKS compilation: lowers Encompute IR to a [`CkksPlan`] and selects
//! [`CkksParams`] against a pinned 128-bit security table.
//!
//! Packing (v0.1, ADR-002): one value per ciphertext over `slots` slots.
//! A vector of length n occupies slots `0..n`; a scalar is replicated in
//! every slot. Vectors keep zeros in their padding slots ("clean") so that
//! sums and matrix products need no masking; the lowering tracks this and
//! masks only when an op would otherwise read dirty padding.

mod approx;
mod lower;
mod params;
mod plan;

pub use approx::{chebyshev_fit, Chebyshev};
pub use lower::{compile, Compiled, PrecisionEstimate};
pub use params::{select_params, CkksParams, SecurityTable, SECURITY_TABLE};
pub use plan::{Approximation, CkksPlan, Instr, Plain, PlanInput, PlanOutput, Reg};
