use encompute_ir::{Code, Error, Result};

use crate::identity::EvaluatorIdentity;
use crate::receipt::{
    ExecutionReceiptV1, SignedExecutionReceipt, VerificationEvidence, RECEIPT_VERSION,
};
use crate::spec::ExecutionSpec;

/// What the verifier expects, from its own compilation and its own copy of
/// the bytes it sent and received.
pub struct ExpectedExecution<'a> {
    pub spec: &'a ExecutionSpec,
    pub key_id: &'a str,
    pub request_commitment: &'a str,
    pub output_commitment: &'a str,
    pub trusted_evaluator: &'a EvaluatorIdentity,
}

/// A receipt whose signature and every binding checked out. Only
/// [`verify_receipt`] constructs it. It attests *what the evaluator
/// claims*; it is not an execution proof (`evidence` is `None` in V1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReceipt {
    receipt: ExecutionReceiptV1,
}

impl VerifiedReceipt {
    pub fn receipt(&self) -> &ExecutionReceiptV1 {
        &self.receipt
    }

    /// Whether an execution proof is attached (never, in V1).
    pub fn has_execution_proof(&self) -> bool {
        !matches!(self.receipt.evidence, VerificationEvidence::None)
    }
}

fn mismatch(what: &str) -> Error {
    Error::new(
        Code::Receipt,
        format!("receipt {what} does not match this execution"),
    )
}

impl SignedExecutionReceipt {
    /// Only the signature and identity: the receipt is version 1, was signed
    /// by `trusted`, and names it. Says nothing about which execution it
    /// binds; use [`verify_receipt`] for that.
    pub fn verify_signature(&self, trusted: &EvaluatorIdentity) -> Result<()> {
        self.check_form()?;
        let r = &self.receipt;
        if r.version != RECEIPT_VERSION {
            return Err(Error::new(
                Code::Receipt,
                format!(
                    "receipt version {} (this Encompute reads {RECEIPT_VERSION})",
                    r.version
                ),
            ));
        }
        if self.evaluator_public_key != trusted.public_key_hex() {
            return Err(Error::new(
                Code::Receipt,
                "receipt was signed by an untrusted evaluator key",
            ));
        }
        if r.evaluator_id != trusted.evaluator_id() {
            return Err(mismatch("evaluator ID"));
        }
        trusted.verify(&r.digest()?, &self.signature_bytes()?)
    }
}

/// Check the signature, the evaluator identity and every binding; fail
/// closed on any mismatch.
pub fn verify_receipt(
    signed: &SignedExecutionReceipt,
    expected: &ExpectedExecution<'_>,
) -> Result<VerifiedReceipt> {
    signed.verify_signature(expected.trusted_evaluator)?;
    let r = &signed.receipt;
    let spec = expected.spec;
    let checks: [(&str, &str, String); 11] = [
        ("spec ID", &r.spec_id, spec.id().hex()),
        ("program ID", &r.program_id, spec.program_id.clone()),
        ("plan ID", &r.plan_id, spec.plan_id.clone()),
        (
            "parameter-set ID",
            &r.parameter_set_id,
            spec.parameter_set_id.clone(),
        ),
        ("key ID", &r.key_id, expected.key_id.to_owned()),
        (
            "request commitment",
            &r.request_commitment,
            expected.request_commitment.to_owned(),
        ),
        (
            "output commitment",
            &r.output_commitment,
            expected.output_commitment.to_owned(),
        ),
        ("scheme", &r.scheme, spec.scheme.clone()),
        ("backend", &r.backend, spec.backend.clone()),
        (
            "backend version",
            &r.backend_version,
            spec.backend_version.clone(),
        ),
        ("evidence", evidence_kind(&r.evidence), "none".to_owned()),
    ];
    for (what, got, want) in checks {
        if got != want {
            return Err(mismatch(what));
        }
    }
    Ok(VerifiedReceipt { receipt: r.clone() })
}

fn evidence_kind(e: &VerificationEvidence) -> &'static str {
    match e {
        VerificationEvidence::None => "none",
    }
}
