//! TFHE-rs client for Encompute exact programs (feature `tfhe-rs`): the only
//! code holding the TFHE-rs client key. The evaluator never links it.
//! TFHE-rs source is BSD-3-Clause-Clear; Zama states that commercial use of
//! its technology requires a separate patent license.

#[cfg(feature = "tfhe-rs")]
mod client;

#[cfg(feature = "tfhe-rs")]
pub use client::TfheRsClient;
