//! Executes CKKS plans on a backend, runs clear-vs-encrypted differential
//! tests, explains plans, and reads and writes compiled artifacts.

mod artifact;
mod diff;
mod exec;
mod explain;
mod model;

pub use artifact::FORMAT as ARTIFACT_FORMAT;
pub use diff::{diff_test, sample_inputs, DiffReport, FailingCase, OutputError};
pub use exec::{decrypt_outputs, encrypt_inputs, evaluate_encrypted, run};
pub use model::{has_openfhe, BenchReport, Mode, Model};
