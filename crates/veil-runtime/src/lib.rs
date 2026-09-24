//! Executes CKKS plans on a backend, runs clear-vs-encrypted differential
//! tests, and reads and writes compiled artifacts.

mod diff;
mod exec;

pub use diff::{diff_test, sample_inputs, DiffReport, FailingCase, OutputError};
pub use exec::{decrypt_outputs, encrypt_inputs, evaluate_encrypted, run};
