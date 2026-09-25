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
pub use encompute_verification as verification;
pub use explain::Measurement;
pub use model::{has_openfhe, has_tfhe, BenchDetail, BenchReport, Mode, Model};
pub use remote::{Remote, RemoteRun, RemoteStats};

/// The execution spec for `model` on backend `kind` (what its receipts
/// must state).
pub fn verification_spec(model: &Model, kind: BackendKind) -> verification::ExecutionSpec {
    encompute_evaluator::execution_spec(&model.ids(), model.compiled(), kind)
}

/// The semantic transcript of `model` on backend `kind` (exact programs).
pub fn verification_transcript(
    model: &Model,
    kind: BackendKind,
) -> Option<verification::SemanticTranscript> {
    encompute_evaluator::transcript_for(model.compiled(), &verification_spec(model, kind))
}
