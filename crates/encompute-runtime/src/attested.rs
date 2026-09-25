//! Attested workloads (ADR-011): the attestation policy for an artifact,
//! and checking that a receipt was signed inside an approved workload.

use encompute_attestation::{AttestationPolicy, AttestationRecord, VerifiedWorkload, Verifier};
use encompute_ir::{Code, Error, Result};

use crate::verification::SignedExecutionReceipt;
use crate::{verification_spec, BackendKind, Model};

/// An attestation policy binding `model` on backend `kind`: its execution
/// spec, confidentiality policy and artifact digest. TEEs and images must
/// still be listed before it validates.
pub fn attestation_policy(model: &Model, kind: BackendKind) -> AttestationPolicy {
    let spec = verification_spec(model, kind);
    let mut p = AttestationPolicy::new(&spec.id().hex(), spec.policy_id.as_deref());
    p.artifact_digest = Some(model.artifact_digest());
    p
}

/// The receipt was signed in the attested workload session of `record`,
/// and that workload satisfies `policy`: the receipt names the record and
/// its session, the attestation binds the receipt's signing key and
/// execution spec, and the evidence verifies (as history: expiry is not
/// checked). The receipt's own signature is checked separately.
pub fn verify_receipt_attestation(
    receipt: &SignedExecutionReceipt,
    record: &AttestationRecord,
    verifier: &Verifier,
    policy: &AttestationPolicy,
) -> Result<VerifiedWorkload> {
    let bad = |m: &str| Err(Error::new(Code::Attestation, m.to_owned()));
    let Some(a) = &receipt.receipt.attestation else {
        return bad("the receipt names no attested workload");
    };
    if a.attestation_id != record.id()? {
        return bad("the receipt binds another attestation record");
    }
    if a.workload_session_id != record.session_id()? {
        return bad("the receipt binds another workload session");
    }
    let b = &record.evidence.binding;
    if b.evaluator_public_key != receipt.evaluator_public_key {
        return bad("the attestation binds another evaluator key");
    }
    if b.execution_spec_id != receipt.receipt.spec_id {
        return bad("the attestation binds another execution spec");
    }
    record.verify(verifier, policy)
}

/// Google's current Confidential Space token-signing keys.
pub fn fetch_google_jwks() -> Result<String> {
    ureq::get(encompute_attestation::gcp::JWKS_URL)
        .timeout(std::time::Duration::from_secs(30))
        .call()
        .map_err(|e| Error::new(Code::Remote, format!("fetching Google's JWKS: {e}")))?
        .into_string()
        .map_err(|e| Error::new(Code::Remote, format!("reading Google's JWKS: {e}")))
}
