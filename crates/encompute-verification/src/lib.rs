//! Execution identity and signed execution receipts (0.4 V1, ADR-007).
//!
//! An [`ExecutionReceipt`](ExecutionReceipt) is what an evaluator *claims*
//! it executed, with cryptographic bindings to the execution specification
//! (program, plan, parameters, scheme, backend), the evaluation key, the
//! exact encrypted request and response, and the evaluator's identity. It is
//! signed by the evaluator.
//!
//! A receipt is **not** an execution proof: it does not show that the
//! evaluator computed every operation honestly, or that the output is
//! correct. That needs [`VerificationEvidence`] from a future
//! [`VerificationBackend`]; receipts carry `VerificationEvidence::None`.
//!
//! A [`SemanticTranscript`] (0.4 V2) is the canonical statement of which
//! operations connect an execution's inputs to its outputs; receipts bind
//! its hash. It fixes what a proof must show; it is not a proof either.

mod backend;
pub mod canonical;
mod hash;
mod identity;
mod receipt;
mod reference;
mod spec;
pub mod transcript;
mod verify;

pub use backend::{
    ExecutionStatement, NoProofBackend, PublicValue, StatementShape, VerificationBackend,
    VerificationCapabilities, STATEMENT_VERSION,
};
pub use hash::{output_commitment, request_commitment, Digest32};
pub use identity::{EvaluatorIdentity, EvaluatorSigner};
pub use receipt::{
    ExecutionReceipt, SignedExecutionReceipt, VerificationEvidence, RECEIPT_VERSION,
};
pub use reference::ReferenceTranscriptEvaluator;
pub use spec::{ExecutionSpec, ExecutionSpecId, SPEC_VERSION};
pub use transcript::{SemanticTranscript, TranscriptId, TRANSCRIPT_VERSION};
pub use verify::{verify_receipt, ExpectedExecution, VerifiedReceipt};
