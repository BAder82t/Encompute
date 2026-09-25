//! Domain-separated SHA-256: `SHA256(domain || 0x00 || bytes)`. Every
//! object type has its own domain, so one can never be read as another.

use sha2::{Digest, Sha256};

pub(crate) const SPEC: &str = "encompute.execution-spec.v1";
pub(crate) const REQUEST: &str = "encompute.execution-request.v1";
pub(crate) const OUTPUT: &str = "encompute.execution-output.v1";
pub(crate) const RECEIPT: &str = "encompute.execution-receipt.v1";
pub(crate) const EVALUATOR: &str = "encompute.evaluator.v1";
pub(crate) const TRANSCRIPT: &str = "encompute.execution-transcript.v1";
pub(crate) const VERIFICATION_KEY: &str = "encompute.verification-key.v1";
pub(crate) const EXECUTION_PROOF: &str = "encompute.execution-proof.v1";
pub(crate) const POLICY: &str = "encompute.confidentiality-policy.v1";
pub(crate) const PRIVACY_POLICY: &str = "encompute.privacy-policy.v1";

/// A 32-byte SHA-256 digest.
pub type Digest32 = [u8; 32];

pub(crate) fn tagged(domain: &str, bytes: &[u8]) -> Digest32 {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    h.update(bytes);
    h.finalize().into()
}

/// Lowercase hex.
pub fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Strict lowercase hex; `None` for anything else.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Commitment to the exact encoded inputs envelope the evaluator received
/// (lowercase hex). It covers ciphertexts, program ID, scheme, backend,
/// parameter set, key ID, item names and lengths, since the envelope
/// carries them all.
pub fn request_commitment(envelope: &[u8]) -> String {
    hex(&tagged(REQUEST, envelope))
}

/// Commitment to the exact encoded outputs envelope sent to the client.
pub fn output_commitment(envelope: &[u8]) -> String {
    hex(&tagged(OUTPUT, envelope))
}
