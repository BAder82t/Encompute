//! The interface a future execution-proof engine implements (0.4 V3).
//! Nothing here produces evidence yet.

use encompute_ir::{Code, Error, Result};

use crate::receipt::ExecutionReceiptV1;

/// The public statement a proof is about: the receipt's bindings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionStatement {
    pub receipt: ExecutionReceiptV1,
}

/// Private inputs to a prover (the execution transcript, 0.4 V2). Empty in
/// V1; never contains plaintext.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionWitness {}

pub trait VerificationBackend {
    type Evidence;

    fn prove(
        &self,
        statement: &ExecutionStatement,
        witness: &ExecutionWitness,
    ) -> Result<Self::Evidence>;

    fn verify(&self, statement: &ExecutionStatement, evidence: &Self::Evidence) -> Result<()>;
}

/// Placeholder: proves nothing, and says so. It never produces evidence.
pub struct NoProofBackend;

impl VerificationBackend for NoProofBackend {
    type Evidence = std::convert::Infallible;

    fn prove(&self, _: &ExecutionStatement, _: &ExecutionWitness) -> Result<Self::Evidence> {
        Err(Error::new(
            Code::Unsupported,
            "no execution-proof backend: receipts are signed claims, not proofs",
        ))
    }

    fn verify(&self, _: &ExecutionStatement, evidence: &Self::Evidence) -> Result<()> {
        match *evidence {}
    }
}
