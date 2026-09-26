//! Execution identity and signed execution receipts (ADR-007).
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
//! A [`SemanticTranscript`] is the canonical statement of which
//! operations connect an execution's inputs to its outputs; receipts bind
//! its hash. It fixes what a proof must show; it is not a proof either.

mod backend;
pub mod canonical;
mod hash;
mod identity;
pub mod proof;
mod receipt;
mod reference;
pub mod service;
mod spec;
pub mod transcript;
mod verify;

pub use backend::{
    ExecutionStatement, NoProofBackend, PublicValue, StatementShape, VerificationBackend,
    VerificationCapabilities, STATEMENT_VERSION,
};
pub use hash::{hex, output_commitment, request_commitment, unhex, Digest32};
pub use identity::{EvaluatorIdentity, EvaluatorSigner};
pub use proof::{
    verify_execution, CiphertextBinding, ExecutionProof, ExecutionVerified, ProofHeader,
    VerificationKeyId, VerificationRelation, VerificationState, PROOF_VERSION,
};
pub use receipt::{
    ExecutionReceipt, SignedExecutionReceipt, VerificationEvidence, WorkloadAttestationRef,
    RECEIPT_VERSION,
};
pub use reference::ReferenceTranscriptEvaluator;
pub use service::{JobGrant, MessageEnvelope, ServiceHeaders, ServiceSigner};
pub use spec::{ExecutionSpec, ExecutionSpecId, PolicyId, PrivacyPolicyId, SPEC_VERSION};
pub use transcript::{SemanticTranscript, TranscriptId, TRANSCRIPT_VERSION};
pub use verify::{verify_receipt, ExpectedExecution, VerifiedReceipt};
