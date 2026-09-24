//! Analyses over Veil IR.
//!
//! - [`ranges`]: sound per-element interval bounds for every value, from the
//!   declared input ranges.
//! - [`privacy`]: which inputs each output depends on, and what the
//!   evaluator can observe.
//!
//! Depth and precision depend on how a program is lowered, so they live in
//! `veil-ckks`.

mod privacy;
mod range;

pub use privacy::{privacy, PrivacyReport};
pub use range::{ranges, Interval, RangeMap};
