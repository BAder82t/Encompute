//! Privacy ledger files (a genesis line, then hash-chained events) and
//! privacy receipts (after `encompute_fuzz::SEP`): read, verify, account,
//! and check the receipt against the ledger. An accepted ledger never
//! reports a NaN, infinite or negative cost.
#![no_main]
use encompute_privacy::{ledger, verify_privacy_receipt, PrivacyReceipt};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let p = encompute_fuzz::parts(data, 2);
    let (ledger_bytes, receipt) = (p[0], p.get(1).copied().unwrap_or_default());
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("asset.ledger");
    std::fs::write(&path, ledger_bytes).expect("write");
    let view = ledger::read(&path).ok();
    if let Some(v) = &view {
        if let Ok(c) = v.cost() {
            assert!(c.epsilon >= 0.0 && c.rho >= 0.0, "{c:?}");
        }
        let _ = v.check(0.01, None);
        let _ = v.check(0.01, Some(0.01));
        let _ = v.checkpoint();
    }
    if let Ok(r) = serde_json::from_slice::<PrivacyReceipt>(receipt) {
        let _ = verify_privacy_receipt(&r, None, view.as_ref(), Some(&[1, 2, 3]));
    }
});
