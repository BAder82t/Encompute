//! Differential privacy for Encompute (ADR-013): budgets per asset and
//! privacy unit, the discrete Gaussian mechanism, zCDP accounting, a
//! tamper-evident persistent ledger, and signed privacy receipts.
//!
//! Secure aggregation hides individual contributions; differential privacy
//! limits what the released aggregates reveal, across all of them.

pub mod accountant;
pub mod ledger;
pub mod rdp;
pub mod release;
pub mod sampler;

pub use accountant::{Cost, PrivacyAccountant, Zcdp};
pub use ledger::{Checkpoint, Entry, Genesis, Ledger, LedgerView, PrivacyEvent};
pub use release::{
    release, sensitivity, sigma2, verify_privacy_receipt, Charged, PrivacyReceipt, ReleaseSpec,
    Released,
};
pub use sampler::{discrete_gaussian, Csprng, CSPRNG};

use encompute_ir::{Code, Error, Result};
use sha2::{Digest, Sha256};

/// `SHA256(domain || 0x00 || len-prefixed parts)`.
pub(crate) fn tagged(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}

/// Crash injection for the assurance suite: with the `failpoints` feature,
/// aborts the process when `ENCOMPUTE_FAILPOINT` names this point. Compiled
/// out otherwise.
#[inline]
pub fn failpoint(_name: &str) {
    #[cfg(feature = "failpoints")]
    if std::env::var("ENCOMPUTE_FAILPOINT").as_deref() == Ok(_name) {
        std::process::abort();
    }
}

/// Asset IDs name ledger files: refuse anything that is not a plain ID.
pub(crate) fn check_asset_file_name(id: &str) -> Result<()> {
    encompute_ir::confidentiality::check_id("asset", id)
        .map_err(|e| Error::new(Code::PrivacyLedger, e.message))
}
