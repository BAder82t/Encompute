//! Execution identity and signed execution receipts (0.4 V1, ADR-007).
//!
//! An [`ExecutionReceipt`](ExecutionReceiptV1) is what an evaluator *claims*
//! it executed, with cryptographic bindings to the execution specification
//! (program, plan, parameters, scheme, backend), the evaluation key, the
//! exact encrypted request and response, and the evaluator's identity. It is
//! signed by the evaluator.
//!
//! A receipt is **not** an execution proof: it does not show that the
//! evaluator computed every operation honestly, or that the output is
//! correct. That needs [`VerificationEvidence`] from a future
//! [`VerificationBackend`]; V1 carries `VerificationEvidence::None`.

mod backend;
pub mod canonical;
mod hash;
mod identity;
mod receipt;
mod spec;
mod verify;

pub use backend::{ExecutionStatement, ExecutionWitness, NoProofBackend, VerificationBackend};
pub use hash::{output_commitment, request_commitment, Digest32};
pub use identity::{EvaluatorIdentity, EvaluatorSigner};
pub use receipt::{
    ExecutionReceiptV1, SignedExecutionReceipt, VerificationEvidence, RECEIPT_VERSION,
};
pub use spec::{ExecutionSpec, ExecutionSpecId, SPEC_VERSION};
pub use verify::{verify_receipt, ExpectedExecution, VerifiedReceipt};
