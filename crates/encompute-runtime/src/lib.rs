//! Executes CKKS plans on a backend, runs clear-vs-encrypted differential
//! tests, explains plans, and reads and writes compiled artifacts.

mod artifact;
mod client;
mod diff;
mod explain;
mod model;

pub use artifact::FORMAT as ARTIFACT_FORMAT;
pub use client::ClientSession;
pub use diff::{diff_test, sample_inputs, DiffReport, FailingCase, OutputError};
pub use encompute_evaluator::{BackendKind, EvaluatorSession, Ids};
pub use model::{has_openfhe, BenchReport, Mode, Model};
