use encompute_ir::{Code, Error, Result};
pub(crate) use encompute_verification::{hex, unhex};
use sha2::{Digest, Sha256};

pub type Digest32 = [u8; 32];

pub(crate) const BINDING: &str = "encompute.workload-binding.v1";
pub(crate) const SESSION: &str = "encompute.workload-session.v1";
pub(crate) const EVIDENCE: &str = "encompute.attestation-evidence.v1";
pub(crate) const MEASUREMENT: &str = "encompute.workload-measurement.v1";
pub(crate) const RECORD: &str = "encompute.attestation-record.v1";
pub(crate) const MOCK_CLAIMS: &str = "encompute.mock-attestation.v1";
pub(crate) const GRANT_INFO: &[u8] = b"encompute.key-grant.v1";

/// `SHA256(domain || 0x00 || bytes)`.
pub(crate) fn tagged(domain: &str, bytes: &[u8]) -> Digest32 {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    h.update(bytes);
    h.finalize().into()
}

/// Lowercase hex of exactly `bytes` bytes.
pub(crate) fn check_hex(code: Code, what: &str, s: &str, bytes: usize) -> Result<Vec<u8>> {
    match unhex(s) {
        Some(b) if b.len() == bytes => Ok(b),
        _ => Err(Error::new(
            code,
            format!("{what} is not {bytes} bytes of lowercase hex"),
        )),
    }
}

pub(crate) fn random32(code: Code) -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| Error::new(code, format!("no randomness: {e}")))?;
    Ok(b)
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn err(code: Code, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}
