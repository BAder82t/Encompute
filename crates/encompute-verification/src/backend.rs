//! The proof boundary (0.4 V2): the public statement an execution proof is
//! about, and the interface a proof engine implements (0.4 V3). Nothing
//! here produces evidence yet. No FHE library type appears in this API.

use std::collections::BTreeSet;

use encompute_ir::{Code, Elem, Error, Result};

use crate::transcript::{ProofOp, SemanticTranscript, TRANSCRIPT_VERSION};
use crate::verify::VerifiedReceipt;

pub const STATEMENT_VERSION: u32 = 1;

/// A runtime-public input value (public inputs are compile-time constants
/// in the programs Encompute makes today, so this is empty for now).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicValue {
    pub name: String,
    pub ty: Elem,
    pub value: i128,
}

/// The public statement a proof must establish:
///
/// given spec `S`, request commitment `R`, output commitment `O` and
/// semantic transcript `T`, there exist secret inputs `X` and an encrypted
/// execution state `W` such that `X` corresponds to the request committed
/// by `R`, execution follows `T` from `X` under exact-plan semantics, and
/// produces outputs whose encryption is committed by `O`.
///
/// Contains no secret value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionStatement {
    pub version: u32,
    pub spec_id: String,
    pub request_commitment: String,
    pub output_commitment: String,
    pub transcript_hash: String,
    pub instruction_count: u64,
    pub public_inputs: Vec<PublicValue>,
}

impl ExecutionStatement {
    /// The statement of a verified receipt, given the transcript it must
    /// bind (the verifier builds the transcript from its own plan).
    pub fn new(receipt: &VerifiedReceipt, transcript: &SemanticTranscript) -> Result<Self> {
        let r = receipt.receipt();
        let hash = transcript.id().hex();
        if transcript.spec_id != r.spec_id {
            return Err(Error::new(
                Code::Transcript,
                "transcript belongs to another execution spec",
            ));
        }
        if r.transcript_hash.as_deref() != Some(hash.as_str()) {
            return Err(Error::new(
                Code::Transcript,
                "transcript commitment mismatch: the receipt binds another transcript",
            ));
        }
        Ok(Self {
            version: STATEMENT_VERSION,
            spec_id: r.spec_id.clone(),
            request_commitment: r.request_commitment.clone(),
            output_commitment: r.output_commitment.clone(),
            transcript_hash: hash,
            instruction_count: transcript.entries.len() as u64,
            public_inputs: vec![],
        })
    }
}

/// What a proof system must be set up for: which operations and types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementShape {
    pub transcript_version: u32,
    pub ops: BTreeSet<ProofOp>,
    pub types: BTreeSet<Elem>,
    pub instruction_count: u64,
}

impl StatementShape {
    pub fn of(t: &SemanticTranscript) -> Self {
        Self {
            transcript_version: TRANSCRIPT_VERSION,
            ops: t.entries.iter().map(|e| e.op).collect(),
            types: t.entries.iter().map(|e| e.ty.0).collect(),
            instruction_count: t.entries.len() as u64,
        }
    }
}

/// Which operations and types a proof backend can prove.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerificationCapabilities {
    pub supported_ops: BTreeSet<ProofOp>,
    pub supported_types: BTreeSet<Elem>,
}

impl VerificationCapabilities {
    /// `(covered, total)` instructions of `t` this backend could prove.
    pub fn coverage(&self, t: &SemanticTranscript) -> (usize, usize) {
        let covered = t
            .entries
            .iter()
            .filter(|e| {
                self.supported_ops.contains(&e.op) && self.supported_types.contains(&e.ty.0)
            })
            .count();
        (covered, t.entries.len())
    }
}

/// A proof engine. Backends own their witness (built from their own
/// execution, e.g. a TFHE-rs witness provider); the statement is shared.
pub trait VerificationBackend {
    type ProvingKey;
    type VerificationKey;
    type Witness;
    type Evidence;

    fn capabilities(&self) -> VerificationCapabilities;

    fn setup(&self, shape: &StatementShape) -> Result<(Self::ProvingKey, Self::VerificationKey)>;

    fn prove(
        &self,
        key: &Self::ProvingKey,
        statement: &ExecutionStatement,
        witness: &Self::Witness,
    ) -> Result<Self::Evidence>;

    fn verify(
        &self,
        key: &Self::VerificationKey,
        statement: &ExecutionStatement,
        evidence: &Self::Evidence,
    ) -> Result<()>;
}

/// Placeholder: proves nothing, supports nothing, and says so.
pub struct NoProofBackend;

fn no_proof() -> Error {
    Error::new(
        Code::Unsupported,
        "no execution-proof backend: receipts are signed claims, not proofs",
    )
}

impl VerificationBackend for NoProofBackend {
    type ProvingKey = std::convert::Infallible;
    type VerificationKey = std::convert::Infallible;
    type Witness = ();
    type Evidence = std::convert::Infallible;

    fn capabilities(&self) -> VerificationCapabilities {
        VerificationCapabilities::default()
    }

    fn setup(&self, _: &StatementShape) -> Result<(Self::ProvingKey, Self::VerificationKey)> {
        Err(no_proof())
    }

    fn prove(
        &self,
        key: &Self::ProvingKey,
        _: &ExecutionStatement,
        _: &(),
    ) -> Result<Self::Evidence> {
        match *key {}
    }

    fn verify(
        &self,
        key: &Self::VerificationKey,
        _: &ExecutionStatement,
        _: &Self::Evidence,
    ) -> Result<()> {
        match *key {}
    }
}
