//! Execution proofs (0.4 V3 groundwork): the object a proof backend returns,
//! the ciphertext bindings it must be checked against, and the verification
//! states a client can reach. No proof backend ships in the default build;
//! nothing here turns a receipt into a proof.

use std::fmt;

use encompute_ir::{Code, Error, Result};
use serde::{Deserialize, Serialize};

use crate::backend::{ExecutionStatement, VerificationBackend};
use crate::canonical::canonical_json;
use crate::hash::{hex, tagged, EXECUTION_PROOF, VERIFICATION_KEY};
use crate::verify::VerifiedReceipt;

pub const PROOF_VERSION: u32 = 1;
/// Magic of the binary `ExecutionProof` encoding.
pub const PROOF_MAGIC: &[u8; 4] = b"ENCP";
/// Largest proof accepted on parse.
pub const MAX_PROOF_BYTES: usize = 256 << 20;

/// Which relation a proof establishes. Versioned so that attestation, MPC
/// or policy evidence can never be read as an FHE correctness proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationRelation {
    /// `C_out` is a valid homomorphic evaluation of the transcript over
    /// `C_in` under the context bound by the spec and the evaluation key.
    FheEvaluationV1,
}

impl fmt::Display for VerificationRelation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            VerificationRelation::FheEvaluationV1 => "FHE evaluation (v1)",
        })
    }
}

/// `SHA256("encompute.verification-key.v1" || 0x00 || verification key)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VerificationKeyId(pub [u8; 32]);

impl VerificationKeyId {
    pub fn of(verification_key: &[u8]) -> Self {
        Self(tagged(VERIFICATION_KEY, verification_key))
    }

    pub fn hex(&self) -> String {
        hex(&self.0)
    }
}

impl fmt::Display for VerificationKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "encvk1:{}", self.hex())
    }
}

/// The exact envelopes a receipt commits to, checked against those
/// commitments before any proof backend sees them: a backend is never
/// handed unrelated ciphertexts.
#[derive(Clone, Copy, Debug)]
pub struct CiphertextBinding<'a> {
    pub request_envelope: &'a [u8],
    pub response_envelope: &'a [u8],
}

impl<'a> CiphertextBinding<'a> {
    /// Bind `request`/`response` to the statement's commitments.
    pub fn new(
        request: &'a [u8],
        response: &'a [u8],
        statement: &ExecutionStatement,
    ) -> Result<Self> {
        if crate::request_commitment(request) != statement.request_commitment {
            return Err(Error::new(
                Code::Receipt,
                "request envelope does not match the request commitment",
            ));
        }
        if crate::output_commitment(response) != statement.output_commitment {
            return Err(Error::new(
                Code::Receipt,
                "response envelope does not match the output commitment",
            ));
        }
        Ok(Self {
            request_envelope: request,
            response_envelope: response,
        })
    }
}

/// Public fields of an [`ExecutionProof`]; they deliberately repeat the
/// receipt's bindings, and verification checks they match the statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofHeader {
    pub version: u32,
    pub relation: VerificationRelation,
    pub spec_id: String,
    pub transcript_hash: String,
    pub request_commitment: String,
    pub output_commitment: String,
    pub verification_key_id: String,
    /// The proof protocol (e.g. `vfhe-research-v1`); implementation details
    /// stay out of the receipt.
    pub protocol: String,
    pub protocol_version: u32,
    pub proof_bytes: u64,
}

/// A cryptographic proof that an execution satisfied its statement.
/// Encoding: `"ENCP" | header length u32 LE | canonical JSON header | proof`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionProof {
    pub header: ProofHeader,
    pub proof: Vec<u8>,
}

fn bad(msg: impl Into<String>) -> Error {
    Error::new(Code::Unverified, msg)
}

impl ExecutionProof {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let header = canonical_json(&self.header)?;
        let mut out = PROOF_MAGIC.to_vec();
        out.extend_from_slice(&(header.len() as u32).to_le_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.proof);
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(bad("execution proof is too large"));
        }
        if bytes.len() < 8 || &bytes[..4] != PROOF_MAGIC {
            return Err(bad("not an execution proof"));
        }
        let n = u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")) as usize;
        let header_bytes = bytes
            .get(8..8 + n)
            .ok_or_else(|| bad("execution proof is truncated"))?;
        let header: ProofHeader = serde_json::from_slice(header_bytes)
            .map_err(|e| bad(format!("malformed proof header: {e}")))?;
        let proof = bytes[8 + n..].to_vec();
        if header.version != PROOF_VERSION || header.proof_bytes != proof.len() as u64 {
            return Err(bad("unknown proof version or wrong proof length"));
        }
        let p = Self { header, proof };
        // The header must be exactly the canonical one.
        if canonical_json(&p.header)? != header_bytes {
            return Err(bad("proof header is not canonical"));
        }
        Ok(p)
    }

    /// `SHA256("encompute.execution-proof.v1" || 0x00 || encoding)`: what a
    /// receipt's evidence binds.
    pub fn digest(&self) -> Result<String> {
        Ok(hex(&tagged(EXECUTION_PROOF, &self.to_bytes()?)))
    }
}

/// How far a result was verified. The three states are never conflated:
/// only [`verify_execution`] reaches `ExecutionVerified`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationState {
    /// No receipt.
    Unverified,
    /// The evaluator's signed receipt and all bindings check out; says
    /// nothing about whether the computation was correct.
    ReceiptVerified,
    /// A cryptographic proof establishes the FHE evaluation relation.
    ExecutionVerified(ExecutionVerified),
}

/// Evidence that a proof verified; only [`verify_execution`] builds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionVerified {
    relation: VerificationRelation,
    protocol: String,
    verification_key_id: String,
}

impl ExecutionVerified {
    pub fn relation(&self) -> VerificationRelation {
        self.relation
    }

    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    pub fn verification_key_id(&self) -> &str {
        &self.verification_key_id
    }
}

impl VerificationState {
    pub fn label(&self) -> &'static str {
        match self {
            VerificationState::Unverified => "UNVERIFIED",
            VerificationState::ReceiptVerified => "RECEIPT VERIFIED",
            VerificationState::ExecutionVerified(_) => "EXECUTION VERIFIED",
        }
    }
}

/// Verify an execution proof for a verified receipt: the receipt's evidence
/// must name this proof; the proof header must match the statement, the
/// ciphertext binding and the verification key `key`; then `backend` checks
/// the proof itself.
pub fn verify_execution<B: VerificationBackend>(
    receipt: &VerifiedReceipt,
    statement: &ExecutionStatement,
    binding: &CiphertextBinding<'_>,
    proof: &ExecutionProof,
    backend: &B,
    key: &B::VerificationKey,
) -> Result<VerificationState> {
    let expected_verification_key = &backend.verification_key_id(key);
    let h = &proof.header;
    let r = receipt.receipt();
    let digest = proof.digest()?;
    match &r.evidence {
        crate::VerificationEvidence::Vfhe {
            relation,
            verification_key_id,
            proof_digest,
            ..
        } if *relation == h.relation
            && *verification_key_id == h.verification_key_id
            && *proof_digest == digest => {}
        _ => return Err(bad("the receipt does not bind this execution proof")),
    }
    let checks = [
        (h.relation == statement.relation, "relation"),
        (h.spec_id == statement.spec_id, "spec ID"),
        (h.transcript_hash == statement.transcript_hash, "transcript"),
        (
            h.request_commitment == statement.request_commitment,
            "request commitment",
        ),
        (
            h.output_commitment == statement.output_commitment,
            "output commitment",
        ),
        (
            h.verification_key_id == expected_verification_key.hex(),
            "verification key",
        ),
        (
            crate::request_commitment(binding.request_envelope) == statement.request_commitment,
            "request ciphertext",
        ),
        (
            crate::output_commitment(binding.response_envelope) == statement.output_commitment,
            "response ciphertext",
        ),
    ];
    if let Some((_, what)) = checks.iter().find(|(ok, _)| !ok) {
        return Err(bad(format!("execution proof {what} does not match")));
    }
    let evidence = backend.decode_evidence(&proof.proof)?;
    backend.verify(key, statement, binding, &evidence)?;
    Ok(VerificationState::ExecutionVerified(ExecutionVerified {
        relation: h.relation,
        protocol: h.protocol.clone(),
        verification_key_id: h.verification_key_id.clone(),
    }))
}
