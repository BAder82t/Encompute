use encompute_ir::{Code, Error, Result};
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json;
use crate::hash::{hex, tagged, unhex, RECEIPT};
use crate::identity::{EvaluatorIdentity, EvaluatorSigner};
use crate::spec::ExecutionSpec;

/// 2 adds `transcript_hash` (0.4 V2).
pub const RECEIPT_VERSION: u32 = 2;

/// Largest receipt accepted on parse (receipts are ~1 KiB).
pub const MAX_RECEIPT_BYTES: usize = 16 << 10;

/// Evidence that the claimed execution was actually correct. V1 has none:
/// a receipt is a signed claim, not a proof. Future variants (ZK proofs,
/// FHE verification, attestation) attach here without changing what the
/// receipt states.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerificationEvidence {
    None,
    /// A verifiable-FHE correctness proof exists for this execution; the
    /// receipt binds it by digest (the `ExecutionProof` travels separately,
    /// so receipts stay small). Names the property, not the library.
    Vfhe {
        relation: crate::proof::VerificationRelation,
        protocol: String,
        protocol_version: u32,
        verification_key_id: String,
        proof_digest: String,
    },
}

/// What an evaluator states it executed. Only commitments and public
/// metadata: no plaintext, no key, no ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    pub version: u32,
    /// Opaque and unique (random UUIDv4); not a security commitment.
    pub execution_id: String,
    pub spec_id: String,
    pub program_id: String,
    pub plan_id: String,
    pub parameter_set_id: String,
    pub key_id: String,
    pub request_commitment: String,
    pub output_commitment: String,
    pub scheme: String,
    pub backend: String,
    pub backend_version: String,
    /// Hash of the semantic transcript the execution follows (exact plans;
    /// absent for CKKS). Fixes the statement a future proof must satisfy;
    /// proves nothing by itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_hash: Option<String>,
    pub evaluator_id: String,
    pub evidence: VerificationEvidence,
}

/// A receipt with the evaluator's Ed25519 signature over
/// `SHA256("encompute.execution-receipt.v1" || 0x00 || canonical receipt)`.
/// Wire form: canonical JSON (`result.receipt.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedExecutionReceipt {
    pub receipt: ExecutionReceipt,
    /// Lowercase hex, 32 bytes.
    pub evaluator_public_key: String,
    /// Lowercase hex, 64 bytes.
    pub signature: String,
}

fn random_uuid_v4() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b)
        .map_err(|e| Error::new(Code::Receipt, format!("no randomness: {e}")))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

impl ExecutionReceipt {
    /// The receipt for one execution of `spec` under `key_id`, binding the
    /// exact request and response envelope bytes.
    pub fn new(
        spec: &ExecutionSpec,
        transcript_hash: Option<&str>,
        key_id: &str,
        request: &[u8],
        response: &[u8],
        evaluator: &EvaluatorIdentity,
    ) -> Result<Self> {
        Self::with_evidence(
            spec,
            transcript_hash,
            key_id,
            request,
            response,
            evaluator,
            VerificationEvidence::None,
        )
    }

    /// A receipt carrying `evidence` (e.g. the digest of an execution proof).
    pub fn with_evidence(
        spec: &ExecutionSpec,
        transcript_hash: Option<&str>,
        key_id: &str,
        request: &[u8],
        response: &[u8],
        evaluator: &EvaluatorIdentity,
        evidence: VerificationEvidence,
    ) -> Result<Self> {
        Ok(Self {
            version: RECEIPT_VERSION,
            execution_id: random_uuid_v4()?,
            spec_id: spec.id().hex(),
            program_id: spec.program_id.clone(),
            plan_id: spec.plan_id.clone(),
            parameter_set_id: spec.parameter_set_id.clone(),
            key_id: key_id.to_owned(),
            request_commitment: crate::request_commitment(request),
            output_commitment: crate::output_commitment(response),
            scheme: spec.scheme.clone(),
            backend: spec.backend.clone(),
            backend_version: spec.backend_version.clone(),
            transcript_hash: transcript_hash.map(str::to_owned),
            evaluator_id: evaluator.evaluator_id(),
            evidence,
        })
    }

    pub(crate) fn digest(&self) -> Result<[u8; 32]> {
        Ok(tagged(RECEIPT, &canonical_json(self)?))
    }

    pub fn sign(self, signer: &EvaluatorSigner) -> Result<SignedExecutionReceipt> {
        let signature = hex(&signer.sign(&self.digest()?));
        Ok(SignedExecutionReceipt {
            receipt: self,
            evaluator_public_key: signer.identity().public_key_hex(),
            signature,
        })
    }
}

impl SignedExecutionReceipt {
    /// Canonical JSON bytes (the file and wire form).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }

    /// Parse strictly: unknown fields, trailing data, and identifiers that
    /// are not lowercase hex of the right length are refused. The signature
    /// is checked by [`crate::verify_receipt`], not here.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(Error::new(Code::Receipt, "receipt is too large"));
        }
        let r: Self = serde_json::from_slice(bytes)
            .map_err(|e| Error::new(Code::Receipt, format!("malformed receipt: {e}")))?;
        r.check_form()?;
        Ok(r)
    }

    /// Field formats: 32-byte hex digests, a 32-byte public key, a 64-byte
    /// signature, a version this build reads, and short printable metadata.
    pub fn check_form(&self) -> Result<()> {
        let r = &self.receipt;
        let hex_of = |what: &str, s: &str, bytes: usize| {
            if s.len() == 2 * bytes && unhex(s).is_some() {
                Ok(())
            } else {
                Err(Error::new(
                    Code::Receipt,
                    format!("receipt {what} is not {bytes} bytes of lowercase hex"),
                ))
            }
        };
        for (what, v) in [
            ("spec ID", &r.spec_id),
            ("program ID", &r.program_id),
            ("plan ID", &r.plan_id),
            ("parameter-set ID", &r.parameter_set_id),
            ("key ID", &r.key_id),
            ("request commitment", &r.request_commitment),
            ("output commitment", &r.output_commitment),
            ("evaluator ID", &r.evaluator_id),
        ] {
            hex_of(what, v, 32)?;
        }
        if let Some(t) = &r.transcript_hash {
            hex_of("transcript hash", t, 32)?;
        }
        if let VerificationEvidence::Vfhe {
            protocol,
            verification_key_id,
            proof_digest,
            ..
        } = &r.evidence
        {
            hex_of("verification key ID", verification_key_id, 32)?;
            hex_of("proof digest", proof_digest, 32)?;
            if protocol.is_empty()
                || protocol.len() > 64
                || !protocol.bytes().all(|c| c.is_ascii_graphic())
            {
                return Err(Error::new(
                    Code::Receipt,
                    "receipt proof protocol is malformed",
                ));
            }
        }
        hex_of("public key", &self.evaluator_public_key, 32)?;
        hex_of("signature", &self.signature, 64)?;
        for (what, v) in [
            ("execution ID", &r.execution_id),
            ("scheme", &r.scheme),
            ("backend", &r.backend),
            ("backend version", &r.backend_version),
        ] {
            if v.is_empty() || v.len() > 64 || !v.bytes().all(|c| c.is_ascii_graphic()) {
                return Err(Error::new(
                    Code::Receipt,
                    format!("receipt {what} is not short printable ASCII"),
                ));
            }
        }
        if r.version != RECEIPT_VERSION {
            return Err(Error::new(
                Code::Receipt,
                format!(
                    "receipt version {} (this Encompute reads {RECEIPT_VERSION})",
                    r.version
                ),
            ));
        }
        Ok(())
    }

    pub(crate) fn signature_bytes(&self) -> Result<Vec<u8>> {
        unhex(&self.signature).ok_or_else(|| Error::new(Code::Receipt, "signature is not hex"))
    }
}
