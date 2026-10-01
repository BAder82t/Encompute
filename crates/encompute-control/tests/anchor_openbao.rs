//! The OpenBao/Vault KV anchor store: the anchor's compare-and-set and
//! the governance log mirror's immutable segments (create only, one name
//! per segment, replaced only while open). Needs `ENCOMPUTE_TEST_BAO_ADDR` and
//! `ENCOMPUTE_TEST_BAO_TOKEN` (a KV version 2 engine at `secret/`);
//! skipped without them unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

use encompute_control::anchor::{AnchorStore, OpenBaoKvAnchor, StateAnchor, StoredAnchor};
use encompute_verification::ServiceSigner;

fn store() -> Option<OpenBaoKvAnchor> {
    let (addr, token) = match (
        std::env::var("ENCOMPUTE_TEST_BAO_ADDR"),
        std::env::var("ENCOMPUTE_TEST_BAO_TOKEN"),
    ) {
        (Ok(a), Ok(t)) => (a, t),
        _ if std::env::var("ENCOMPUTE_REQUIRE_SERVICES").is_ok() => {
            panic!("ENCOMPUTE_REQUIRE_SERVICES is set but ENCOMPUTE_TEST_BAO_ADDR is not")
        }
        _ => {
            eprintln!("SKIPPED: set ENCOMPUTE_TEST_BAO_ADDR and ENCOMPUTE_TEST_BAO_TOKEN");
            return None;
        }
    };
    let path = format!(
        "encompute-test/anchor-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    Some(OpenBaoKvAnchor::new(
        &addr,
        "secret",
        &path,
        zeroize::Zeroizing::new(token),
    ))
}

#[test]
fn the_openbao_store_keeps_the_anchor_and_an_immutable_mirror() {
    let Some(s) = store() else { return };
    assert!(s.load().unwrap().is_none());
    assert!(s.mirror_list().unwrap().is_empty());
    let signer = ServiceSigner::from_seed("control-plane", &[3; 32]).unwrap();
    let (anchor, _) = encompute_control::anchor::Anchor::open(Box::new(s), &signer).unwrap();
    anchor.update(&signer, |_| {}).unwrap();
    let s = anchor.store();
    assert!(matches!(
        s.load().unwrap(),
        Some(StoredAnchor::V2(StateAnchor { counter: 1, .. }))
    ));
    s.mirror_create(1, "a\nb\n").unwrap();
    s.mirror_create(2, "c\n").unwrap();
    // Create is one atomic create of one name: a second writer fails closed.
    let e = s.mirror_create(1, "x\n").unwrap_err();
    assert!(e.message.contains("written concurrently"), "{e}");
    let mut l = s.mirror_list().unwrap();
    l.sort();
    assert_eq!(l, vec![1, 2]);
    assert_eq!(s.mirror_read(1).unwrap(), "a\nb\n");
    // The open segment is replaced whole, never partly.
    s.mirror_replace(2, "c\nd\n", &|_| Ok(())).unwrap();
    assert_eq!(s.mirror_read(2).unwrap(), "c\nd\n");
    assert!(s.mirror_replace(9, "z\n", &|_| Ok(())).is_err());
}
