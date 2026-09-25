//! Executes compiled programs (CKKS or exact) on a backend, runs
//! clear-vs-encrypted differential tests, explains plans, and reads and
//! writes compiled artifacts.

mod artifact;
pub mod audit;
mod client;
mod diff;
mod explain;
mod model;
mod remote;

pub use artifact::FORMAT as ARTIFACT_FORMAT;
pub use client::ClientSession;
pub use diff::{
    diff_test, sample_inputs, DiffReport, ExactOutput, ExactReport, FailingCase, OutputError,
    TestReport,
};
pub use encompute_evaluator::{
    BackendKind, Backends, CompiledProgram, EvaluatorSession, ExactProgram, Ids, Semantics,
};
pub use explain::Measurement;
pub use model::{has_openfhe, has_tfhe, BenchDetail, BenchReport, Mode, Model};
pub use remote::{Remote, RemoteStats};
