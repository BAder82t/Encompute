//! The governance event log's formats: RFC 6962 trees and proofs (checked
//! against the published test vectors and an independent reference
//! construction), partition-bound leaves, signed checkpoints, witnesses,
//! revocation heads and equivocation evidence.

use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use sha2::{Digest, Sha256};

use encompute_trust::govlog::{
    chain_hash, check_extension, completed_nodes, empty_root, hash_hex, kind, members_at,
    rfc6962_leaf, root, root_with, CheckpointWitness, ConsistencyProof, Equivocation,
    EquivocationProof, Extension, GovEvent, Hash, InclusionProof, Nodes, Partition,
    ProjectCheckpoint, RevocationHead, RollbackProof, SignedProjectCheckpoint, Verdict,
    CHAIN_GENESIS, GOVLOG_VERSION,
};
use encompute_verification::service::ServiceSigner;
use encompute_verification::{hex, unhex};

// --- an independent reference: RFC 6962 section 2.1, on slices -------------

fn ref_leaf(d: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(d);
    h.finalize().into()
}

fn ref_node(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// The largest power of two smaller than n, by counting.
fn ref_k(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn mth(d: &[Hash]) -> Hash {
    match d.len() {
        0 => Sha256::digest([]).into(),
        1 => d[0],
        n => {
            let k = ref_k(n);
            ref_node(&mth(&d[..k]), &mth(&d[k..]))
        }
    }
}

fn ref_path(m: usize, d: &[Hash]) -> Vec<Hash> {
    let n = d.len();
    if n <= 1 {
        return vec![];
    }
    let k = ref_k(n);
    if m < k {
        let mut p = ref_path(m, &d[..k]);
        p.push(mth(&d[k..]));
        p
    } else {
        let mut p = ref_path(m - k, &d[k..]);
        p.push(mth(&d[..k]));
        p
    }
}

fn ref_subproof(m: usize, d: &[Hash], b: bool) -> Vec<Hash> {
    let n = d.len();
    if m == n {
        return if b { vec![] } else { vec![mth(d)] };
    }
    let k = ref_k(n);
    if m <= k {
        let mut p = ref_subproof(m, &d[..k], b);
        p.push(mth(&d[k..]));
        p
    } else {
        let mut p = ref_subproof(m - k, &d[k..], false);
        p.push(mth(&d[..k]));
        p
    }
}

fn ref_proof(m: usize, d: &[Hash]) -> Vec<Hash> {
    if m == 0 || m == d.len() {
        vec![]
    } else {
        ref_subproof(m, d, true)
    }
}

fn hexes(v: &[Hash]) -> Vec<String> {
    v.iter().map(|h| hex(h)).collect()
}

// --- a store of complete subtrees, as the control plane keeps them ---------

#[derive(Default)]
struct Store(HashMap<(u32, u64), Hash>, u64);

impl Nodes for Store {
    fn node(&mut self, level: u32, index: u64) -> encompute_ir::Result<Hash> {
        self.0.get(&(level, index)).copied().ok_or_else(|| {
            encompute_ir::Error::new(encompute_ir::Code::TrustEvidence, "missing node")
        })
    }
}

impl Store {
    fn append(&mut self, leaf: Hash) {
        let i = self.1;
        for (l, x, h) in completed_nodes(i, leaf, self).unwrap() {
            assert!(
                self.0.insert((l, x), h).is_none(),
                "a stored node never changes"
            );
        }
        self.1 += 1;
    }

    fn of(leaves: &[Hash]) -> Self {
        let mut s = Store::default();
        for l in leaves {
            s.append(*l);
        }
        s
    }
}

fn leaves(n: usize) -> Vec<Hash> {
    (0..n)
        .map(|i| ref_leaf(&(i as u64).to_be_bytes()))
        .collect()
}

const P: &str = "p:prj_a";

/// One change to a value.
type Edit<T> = Box<dyn Fn(&mut T)>;

// --- RFC 6962 ---------------------------------------------------------------

/// The roots of the certificate-transparency reference test vectors.
#[test]
fn rfc6962_test_vectors() {
    let inputs = [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ];
    let roots = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];
    let ls: Vec<Hash> = inputs
        .iter()
        .map(|h| rfc6962_leaf(&unhex(h).unwrap()))
        .collect();
    assert_eq!(
        hash_hex(&empty_root()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    for (n, want) in roots.iter().enumerate() {
        assert_eq!(hash_hex(&root(&ls[..=n])), *want, "size {}", n + 1);
        let mut s = Store::of(&ls[..=n]);
        assert_eq!(hash_hex(&root_with(n as u64 + 1, &mut s).unwrap()), *want);
    }
}

/// Every pair of sizes up to 40: proofs equal the reference's, verify,
/// and fail for any other leaf, index, size or root.
#[test]
fn exhaustive_small_trees() {
    let all = leaves(41);
    for n in 1..=40usize {
        let d = &all[..n];
        let mut s = Store::of(d);
        let r = mth(d);
        assert_eq!(root_with(n as u64, &mut s).unwrap(), r);
        for m in 0..n {
            let p = InclusionProof::build(P, m as u64, n as u64, &mut s).unwrap();
            assert_eq!(p.path, hexes(&ref_path(m, d)), "path {m} of {n}");
            p.verify(&d[m], &r).unwrap();
            assert!(p.verify(&d[(m + 1) % n], &r).is_err() || n == 1);
            let mut q = p.clone();
            q.leaf_index = (m as u64 + 1) % n as u64;
            assert!(q.verify(&d[m], &r).is_err() || n == 1, "index {m} of {n}");
            let mut q = p.clone();
            q.tree_size = n as u64 + 1;
            assert!(
                q.verify(&d[m], &mth(&all[..=n])).is_err(),
                "size {m} of {n}"
            );
        }
        for m in 0..=n {
            let c = ConsistencyProof::build(P, m as u64, n as u64, &mut s).unwrap();
            assert_eq!(c.path, hexes(&ref_proof(m, d)), "proof {m} {n}");
            assert_eq!(c.first_root, hex(&mth(&d[..m])));
            assert_eq!(c.second_root, hex(&r));
            c.verify().unwrap();
        }
    }
}

fn swap(d: &[Hash], i: usize, j: usize) -> Vec<Hash> {
    let mut v = d.to_vec();
    v.swap(i, j);
    v
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Stored complete subtrees give the reference root, and every
    /// inclusion proof round-trips (sizes 1 to 300).
    #[test]
    fn inclusion_round_trips(n in 1usize..=300, pick in any::<prop::sample::Index>()) {
        let d = leaves(n);
        let mut s = Store::of(&d);
        let r = mth(&d);
        prop_assert_eq!(root_with(n as u64, &mut s).unwrap(), r);
        prop_assert_eq!(root(&d), r);
        let m = pick.index(n);
        let p = InclusionProof::build(P, m as u64, n as u64, &mut s).unwrap();
        prop_assert_eq!(&p, &InclusionProof::from_leaves(P, &d, m as u64).unwrap());
        prop_assert_eq!(&p.path, &hexes(&ref_path(m, &d)));
        p.verify(&d[m], &r).unwrap();
        let other = ref_leaf(b"not in the tree");
        prop_assert!(p.verify(&other, &r).is_err());
        if !p.path.is_empty() {
            let mut q = p.clone();
            q.path.pop();
            prop_assert!(q.verify(&d[m], &r).is_err());
            let mut q = p.clone();
            q.path.push(hex(&other));
            prop_assert!(q.verify(&d[m], &r).is_err());
        }
    }

    /// Consistency proofs round-trip; a truncated size, a changed root or
    /// a reordered leaf fails (sizes 1 to 300).
    #[test]
    fn consistency_round_trips(
        n in 1usize..=300,
        pick in any::<prop::sample::Index>(),
        a in any::<prop::sample::Index>(),
        b in any::<prop::sample::Index>(),
    ) {
        let d = leaves(n);
        let mut s = Store::of(&d);
        let m = pick.index(n + 1);
        let c = ConsistencyProof::build(P, m as u64, n as u64, &mut s).unwrap();
        prop_assert_eq!(&c, &ConsistencyProof::from_leaves(P, &d, m as u64).unwrap());
        prop_assert_eq!(&c.path, &hexes(&ref_proof(m, &d)));
        c.verify().unwrap();
        if m > 0 && m < n {
            // The larger tree truncated by one.
            let mut q = c.clone();
            q.second = n as u64 - 1;
            q.second_root = hex(&mth(&d[..n - 1]));
            prop_assert!(q.verify().is_err() || m == n - 1 && q.path.is_empty());
            // A first tree that is not a prefix.
            let mut q = c.clone();
            q.first_root = hex(&ref_leaf(b"forged"));
            prop_assert!(q.verify().is_err());
            // A reordered leaf inside the first tree.
            let (i, j) = (a.index(n), b.index(n));
            if i != j && (i < m || j < m) {
                let mut q = c.clone();
                q.second_root = hex(&mth(&swap(&d, i, j)));
                prop_assert!(q.verify().is_err());
            }
        }
    }
}

// --- events -----------------------------------------------------------------

fn event(partition: &str, pseq: u64) -> GovEvent {
    GovEvent {
        v: GOVLOG_VERSION,
        partition: partition.into(),
        pseq,
        kind: kind::AUTHORIZATION_REVOKED.into(),
        subject: format!("auth_{pseq}"),
        org: Some("org_tax".into()),
        at: 1_800_000_000 + pseq,
        refs: BTreeMap::from([("authorization_id".into(), "ab".repeat(32))]),
    }
}

fn signer() -> ServiceSigner {
    ServiceSigner::from_seed("encompute-control", &[7u8; 32]).unwrap()
}

fn tree(partition: &str, n: u64) -> (Vec<GovEvent>, Vec<Hash>, Store) {
    let es: Vec<GovEvent> = (1..=n).map(|i| event(partition, i)).collect();
    let ls: Vec<Hash> = es.iter().map(|e| e.leaf_hash().unwrap()).collect();
    let s = Store::of(&ls);
    (es, ls, s)
}

fn checkpoint(partition: &str, ls: &[Hash], gseq: u64) -> SignedProjectCheckpoint {
    ProjectCheckpoint {
        version: GOVLOG_VERSION,
        partition: partition.into(),
        size: ls.len() as u64,
        root: hex(&root(ls)),
        gseq,
        at: 1_800_000_100,
    }
    .sign(&signer())
    .unwrap()
}

#[test]
fn partitions_parse_and_print() {
    for s in ["p:prj_1", "o:org_1", "platform"] {
        assert_eq!(Partition::parse(s).unwrap().to_string(), s);
    }
    for bad in ["", "x:1", "p:", "o:has space", "PLATFORM"] {
        assert!(Partition::parse(bad).is_err(), "{bad}");
    }
}

/// The leaf names its partition: the same event in another partition has
/// another leaf hash, and a proof for project B's event never verifies
/// against project A's checkpoint.
#[test]
fn proof_for_another_projects_event_fails() {
    let (ea, la, _) = tree("p:prj_a", 5);
    let (eb, lb, mut sb) = tree("p:prj_b", 5);
    assert_ne!(la[2], lb[2]);
    let cp_a = checkpoint("p:prj_a", &la, 10);
    cp_a.verify(&signer().public_key_hex()).unwrap();
    let pa = InclusionProof::from_leaves("p:prj_a", &la, 2).unwrap();
    cp_a.includes(&ea[2], &pa).unwrap();
    // B's event with B's (valid) proof against A's checkpoint.
    let pb = InclusionProof::build("p:prj_b", 2, 5, &mut sb).unwrap();
    assert!(cp_a.includes(&eb[2], &pb).is_err());
    // Relabelled as A's: the leaf hash changes, so the proof fails.
    let mut relabelled = eb[2].clone();
    relabelled.partition = "p:prj_a".into();
    let mut pb_as_a = pb.clone();
    pb_as_a.partition = "p:prj_a".into();
    assert!(cp_a.includes(&relabelled, &pb_as_a).is_err());
    // A's own proof for another index, or another tree size, fails.
    let mut wrong = pa.clone();
    wrong.leaf_index = 3;
    assert!(cp_a.includes(&ea[2], &wrong).is_err());
}

/// Events carry identifiers only: free text, a storage location with
/// spaces or an unknown version is refused before it is hashed.
#[test]
fn events_are_identifiers_only() {
    let ok = event(P, 1);
    ok.check().unwrap();
    let edits: Vec<(&str, Edit<GovEvent>)> = vec![
        ("version", Box::new(|e| e.v = 2)),
        ("pseq 0", Box::new(|e| e.pseq = 0)),
        ("partition", Box::new(|e| e.partition = "nowhere".into())),
        ("kind", Box::new(|e| e.kind = "Revoked Because".into())),
        (
            "subject",
            Box::new(|e| e.subject = "patient John Smith".into()),
        ),
        ("org", Box::new(|e| e.org = Some(String::new()))),
        (
            "ref value",
            Box::new(|e| {
                e.refs.insert("reason".into(), "free text reason".into());
            }),
        ),
        (
            "ref name",
            Box::new(|e| {
                e.refs.insert("Storage-URI".into(), "s3".into());
            }),
        ),
    ];
    for (what, f) in edits {
        let mut e = ok.clone();
        f(&mut e);
        assert!(e.check().is_err(), "{what}");
        assert!(e.leaf_hash().is_err(), "{what}");
    }
    for k in kind::ALL {
        let mut e = ok.clone();
        e.kind = (*k).into();
        e.check().unwrap();
    }
}

#[test]
fn chain_hash_binds_order_and_position() {
    let (a, b) = (ref_leaf(b"a"), ref_leaf(b"b"));
    let ab = chain_hash(&chain_hash(&CHAIN_GENESIS, 1, &a), 2, &b);
    let ba = chain_hash(&chain_hash(&CHAIN_GENESIS, 1, &b), 2, &a);
    assert_ne!(ab, ba);
    assert_ne!(
        chain_hash(&CHAIN_GENESIS, 1, &a),
        chain_hash(&CHAIN_GENESIS, 2, &a)
    );
}

// --- equivocation -------------------------------------------------------------

/// Two checkpoints of the same size with different roots, or a smaller one
/// the control plane's own signed consistency proof does not extend, prove
/// equivocation; consistent or forged ones do not.
#[test]
fn equivocation_detected_in_both_shapes() {
    let ck = signer().public_key_hex();
    let (_, ls, mut s) = tree(P, 9);
    // A fork: the same first 6 events, then others.
    let mut forked = ls.clone();
    forked[6] = ref_leaf(b"fork");
    let honest_9 = checkpoint(P, &ls, 20);
    let forked_9 = checkpoint(P, &forked, 20);
    let shape1 = EquivocationProof {
        a: honest_9.clone(),
        b: forked_9.clone(),
        consistency: None,
    };
    assert_eq!(
        shape1.check(&ck).unwrap(),
        Equivocation::SameSizeDifferentRoots
    );
    // Same checkpoint twice: not an equivocation.
    let same = EquivocationProof {
        a: honest_9.clone(),
        b: honest_9.clone(),
        consistency: None,
    };
    assert!(same.check(&ck).is_err());

    // Shape 2: a 7-event checkpoint of the fork, a 9-event honest one, and
    // the proof the control plane signed between them (it cannot make one
    // that verifies).
    let forked_7 = checkpoint(P, &forked[..7], 18);
    let mut served = ConsistencyProof::build(P, 7, 9, &mut s).unwrap();
    served.first_root = forked_7.body.root.clone();
    let served = served.sign(&signer()).unwrap();
    let shape2 = EquivocationProof {
        a: honest_9.clone(),
        b: forked_7.clone(),
        consistency: Some(served),
    };
    assert_eq!(shape2.check(&ck).unwrap(), Equivocation::Inconsistent);
    // Without the proof it is not evidence.
    let bare = EquivocationProof {
        consistency: None,
        ..shape2.clone()
    };
    assert!(bare.check(&ck).is_err());

    // Consistent checkpoints with their valid proof: no equivocation.
    let honest_7 = checkpoint(P, &ls[..7], 18);
    let good = ConsistencyProof::build(P, 7, 9, &mut s)
        .unwrap()
        .sign(&signer())
        .unwrap();
    let fine = EquivocationProof {
        a: honest_7.clone(),
        b: honest_9.clone(),
        consistency: Some(good.clone()),
    };
    assert!(fine.check(&ck).is_err());

    // A proof for other checkpoints is not evidence either.
    let mismatched = EquivocationProof {
        a: forked_7.clone(),
        b: honest_9.clone(),
        consistency: Some(good),
    };
    assert!(mismatched.check(&ck).is_err());

    // Forged: a checkpoint signed by someone else.
    let other = ServiceSigner::from_seed("encompute-control", &[8u8; 32]).unwrap();
    let mut forged = forked_9.clone();
    forged = forged.body.sign(&other).unwrap();
    let f = EquivocationProof {
        a: honest_9.clone(),
        b: forged,
        consistency: None,
    };
    assert!(f.check(&ck).is_err());
    // Edited after signing.
    let mut edited = honest_9.clone();
    edited.body.root = forked_9.body.root.clone();
    let e = EquivocationProof {
        a: honest_9.clone(),
        b: edited,
        consistency: None,
    };
    assert!(e.check(&ck).is_err());
    // Different partitions are not comparable.
    let other_p = checkpoint("p:prj_b", &forked, 20);
    let d = EquivocationProof {
        a: honest_9,
        b: other_p,
        consistency: None,
    };
    assert!(d.check(&ck).is_err());
}

/// What a member concludes from the latest checkpoint and the proof the
/// control plane served: consistent, equivocation (with evidence that
/// checks), rollback, or an error that is no evidence.
#[test]
fn a_member_checks_that_the_latest_checkpoint_extends_the_witnessed_one() {
    let ck = signer().public_key_hex();
    let (_, ls, mut s) = tree(P, 9);
    let honest_7 = checkpoint(P, &ls[..7], 18);
    let honest_9 = checkpoint(P, &ls, 20);
    let proof = ConsistencyProof::build(P, 7, 9, &mut s)
        .unwrap()
        .sign(&signer())
        .unwrap();
    assert_eq!(
        check_extension(&ck, &honest_7, &honest_9, Some(&proof)).unwrap(),
        Extension::Consistent
    );
    assert_eq!(
        check_extension(&ck, &honest_9, &honest_9, None).unwrap(),
        Extension::Consistent
    );
    // No proof for a larger tree: an error, not evidence.
    assert!(check_extension(&ck, &honest_7, &honest_9, None).is_err());
    // A proof between other checkpoints: an error.
    let other = ConsistencyProof::build(P, 5, 9, &mut s)
        .unwrap()
        .sign(&signer())
        .unwrap();
    assert!(check_extension(&ck, &honest_7, &honest_9, Some(&other)).is_err());

    // A fork at the same size.
    let mut forked = ls.clone();
    forked[6] = ref_leaf(b"fork");
    let forked_9 = checkpoint(P, &forked, 20);
    let Extension::Equivocation(e) = check_extension(&ck, &honest_9, &forked_9, None).unwrap()
    else {
        panic!("a fork at one size is equivocation")
    };
    assert_eq!(e.check(&ck).unwrap(), Equivocation::SameSizeDifferentRoots);

    // A larger tree that does not extend the witnessed one, with the
    // control plane's own failing proof.
    let forked_7 = checkpoint(P, &forked[..7], 18);
    let mut served = ConsistencyProof::build(P, 7, 9, &mut s).unwrap();
    served.first_root = forked_7.body.root.clone();
    let served = served.sign(&signer()).unwrap();
    let Extension::Equivocation(e) =
        check_extension(&ck, &forked_7, &honest_9, Some(&served)).unwrap()
    else {
        panic!("an inconsistent proof is equivocation")
    };
    assert_eq!(e.check(&ck).unwrap(), Equivocation::Inconsistent);

    // A smaller tree than the one witnessed.
    assert!(matches!(
        check_extension(&ck, &honest_9, &honest_7, None).unwrap(),
        Extension::Rollback(_)
    ));

    // Not the control plane's: no evidence, an error.
    let stranger = ServiceSigner::from_seed("encompute-control", &[8u8; 32]).unwrap();
    let fake = forked_9.body.clone().sign(&stranger).unwrap();
    assert!(check_extension(&ck, &honest_9, &fake, None).is_err());
    // Another partition.
    let elsewhere = checkpoint("p:prj_b", &ls, 20);
    assert!(check_extension(&ck, &honest_9, &elsewhere, None).is_err());
}

fn at(cp: &SignedProjectCheckpoint, at: u64) -> SignedProjectCheckpoint {
    let mut b = cp.body.clone();
    b.at = at;
    b.sign(&signer()).unwrap()
}

/// A control plane that signs a smaller checkpoint after a larger one lost
/// events: provable by anyone with its key. An older one served again is
/// stale, not evidence.
#[test]
fn control_plane_rollback_is_detected_and_provable() {
    let ck = signer().public_key_hex();
    let (_, ls, _) = tree(P, 9);
    let big = at(&checkpoint(P, &ls, 20), 1_000);
    let small = at(&checkpoint(P, &ls[..5], 14), 2_000);
    let Extension::Rollback(r) = check_extension(&ck, &big, &small, None).unwrap() else {
        panic!("a smaller checkpoint signed later is a rollback")
    };
    r.check(&ck).unwrap();
    assert_eq!(r.previous, big);
    // Signed earlier than the larger: stale, no evidence.
    let old = at(&checkpoint(P, &ls[..5], 14), 500);
    assert_eq!(
        check_extension(&ck, &big, &old, None).unwrap(),
        Extension::Stale
    );
    assert!(RollbackProof {
        previous: big.clone(),
        latest: old
    }
    .check(&ck)
    .is_err());
}

#[test]
fn forged_rollback_evidence_refused() {
    let ck = signer().public_key_hex();
    let (_, ls, _) = tree(P, 9);
    let big = at(&checkpoint(P, &ls, 20), 1_000);
    let small = at(&checkpoint(P, &ls[..5], 14), 2_000);
    let ok = RollbackProof {
        previous: big.clone(),
        latest: small.clone(),
    };
    ok.check(&ck).unwrap();
    // Wrong key, edited body, swapped order, same size, other partition.
    assert!(ok.check(&"0".repeat(64)).is_err());
    let stranger = ServiceSigner::from_seed("encompute-control", &[9u8; 32]).unwrap();
    let forged = small.body.clone().sign(&stranger).unwrap();
    assert!(RollbackProof {
        previous: big.clone(),
        latest: forged
    }
    .check(&ck)
    .is_err());
    let mut edited = small.clone();
    edited.body.size = 4;
    assert!(RollbackProof {
        previous: big.clone(),
        latest: edited
    }
    .check(&ck)
    .is_err());
    assert!(RollbackProof {
        previous: small.clone(),
        latest: big.clone()
    }
    .check(&ck)
    .is_err());
    assert!(RollbackProof {
        previous: big.clone(),
        latest: big.clone()
    }
    .check(&ck)
    .is_err());
    let elsewhere = at(&checkpoint("p:prj_b", &ls[..5], 14), 2_000);
    assert!(RollbackProof {
        previous: big,
        latest: elsewhere
    }
    .check(&ck)
    .is_err());
}

#[test]
fn assess_gives_a_typed_verdict() {
    let ck = signer().public_key_hex();
    let (_, ls, _) = tree(P, 4);
    let a = checkpoint(P, &ls, 9);
    let same = EquivocationProof {
        a: a.clone(),
        b: a.clone(),
        consistency: None,
    };
    assert_eq!(same.assess(&ck).unwrap(), Verdict::Consistent);
    assert!(same.check(&ck).is_err());
    let mut f = ls.clone();
    f[3] = ref_leaf(b"x");
    let fork = EquivocationProof {
        a,
        b: checkpoint(P, &f, 9),
        consistency: None,
    };
    assert_eq!(
        fork.assess(&ck).unwrap(),
        Verdict::Equivocation(Equivocation::SameSizeDifferentRoots)
    );
    assert!(fork.assess(&"0".repeat(64)).is_err());
}

fn membership(pseq: u64, kind: &str, org: &str, refs: &[(&str, &str)]) -> GovEvent {
    GovEvent {
        v: GOVLOG_VERSION,
        partition: P.into(),
        pseq,
        kind: kind.into(),
        subject: format!("pmb_{pseq}"),
        org: Some(org.into()),
        at: 1_800_000_000 + pseq,
        refs: refs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

#[test]
fn members_at_follows_the_membership_events() {
    let owner = vec!["tax".to_string()];
    let es = vec![
        membership(
            1,
            kind::MEMBERSHIP_ADDED,
            "ben",
            &[("participation", "member")],
        ),
        membership(
            3,
            kind::MEMBERSHIP_ADDED,
            "other",
            &[("participation", "member")],
        ),
        membership(
            4,
            kind::MEMBERSHIP_REMOVED,
            "other",
            &[("participation", "member"), ("status", "active")],
        ),
        // An invitation withdrawn, an auditor organization removed.
        membership(
            5,
            kind::MEMBERSHIP_REMOVED,
            "guest",
            &[("participation", "member"), ("status", "invited")],
        ),
        membership(
            6,
            kind::MEMBERSHIP_REMOVED,
            "audit",
            &[("participation", "auditor"), ("status", "active")],
        ),
        // Joined before the events existed, removed later.
        membership(
            7,
            kind::MEMBERSHIP_REMOVED,
            "old",
            &[("participation", "member"), ("status", "active")],
        ),
    ];
    assert_eq!(members_at(&es, 0, &owner), ["old", "tax"]);
    assert_eq!(members_at(&es, 1, &owner), ["ben", "old", "tax"]);
    assert_eq!(members_at(&es, 3, &owner), ["ben", "old", "other", "tax"]);
    assert_eq!(members_at(&es, 4, &owner), ["ben", "old", "tax"]);
    assert_eq!(members_at(&es, 7, &owner), ["ben", "tax"]);
    assert_eq!(members_at(&[], 9, &owner), ["tax"]);
}

// --- witnesses and revocation heads -------------------------------------------

fn gov_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(k: &SigningKey) -> String {
    hex(&k.verifying_key().to_bytes())
}

/// Any edit to a signed witness or revocation head, or the wrong
/// governance key, fails verification.
#[test]
fn head_and_witness_signature_edits_fail() {
    let k = gov_key(3);
    let (_, ls, _) = tree(P, 4);
    let cp = checkpoint(P, &ls, 4);
    let w = CheckpointWitness {
        version: GOVLOG_VERSION,
        organization: "org_tax".into(),
        partition: P.into(),
        size: 4,
        root: cp.body.root.clone(),
        at: 1_800_000_200,
    };
    assert!(w.witnesses(&cp.body));
    let sw = w.sign(&k).unwrap();
    sw.verify(&pk(&k)).unwrap();
    assert!(sw.verify(&pk(&gov_key(4))).is_err());
    let edits: Vec<Edit<CheckpointWitness>> = vec![
        Box::new(|w| w.organization = "org_other".into()),
        Box::new(|w| w.partition = "p:prj_b".into()),
        Box::new(|w| w.size += 1),
        Box::new(|w| w.root = "00".repeat(32)),
        Box::new(|w| w.at += 1),
    ];
    for f in &edits {
        let mut x = sw.clone();
        f(&mut x.body);
        assert!(x.verify(&pk(&k)).is_err());
    }

    let h = RevocationHead {
        version: GOVLOG_VERSION,
        organization: "org_tax".into(),
        project: "prj_a".into(),
        seq: 1,
        root: hex(&root(&ls)),
        at: 1_800_000_300,
    };
    let sh = h.sign(&k).unwrap();
    sh.verify(&pk(&k)).unwrap();
    assert!(sh.verify(&pk(&gov_key(4))).is_err());
    let edits: Vec<Edit<RevocationHead>> = vec![
        Box::new(|h| h.organization = "org_other".into()),
        Box::new(|h| h.project = "prj_b".into()),
        Box::new(|h| h.seq += 1),
        Box::new(|h| h.root = "00".repeat(32)),
        Box::new(|h| h.at += 1),
    ];
    for f in &edits {
        let mut x = sh.clone();
        f(&mut x.body);
        assert!(x.verify(&pk(&k)).is_err());
    }
    // Malformed before signing.
    let mut bad = sh.body.clone();
    bad.seq = 0;
    assert!(bad.sign(&k).is_err());
}

/// Every format refuses a field it does not know.
#[test]
fn unknown_fields_refused() {
    fn extra<T: serde::Serialize + serde::de::DeserializeOwned>(v: &T) -> bool {
        let mut j = serde_json::to_value(v).unwrap();
        j.as_object_mut()
            .unwrap()
            .insert("storage_uri".into(), "s3://bucket/x".into());
        serde_json::from_value::<T>(j).is_err()
    }
    let k = gov_key(3);
    let (_, ls, mut s) = tree(P, 4);
    let cp = checkpoint(P, &ls, 4);
    let ev = event(P, 1);
    let ip = InclusionProof::build(P, 1, 4, &mut s).unwrap();
    let cons = ConsistencyProof::build(P, 2, 4, &mut s).unwrap();
    let w = CheckpointWitness {
        version: GOVLOG_VERSION,
        organization: "org_tax".into(),
        partition: P.into(),
        size: 4,
        root: cp.body.root.clone(),
        at: 1,
    };
    let h = RevocationHead {
        version: GOVLOG_VERSION,
        organization: "org_tax".into(),
        project: "prj_a".into(),
        seq: 1,
        root: cp.body.root.clone(),
        at: 1,
    };
    let eq = EquivocationProof {
        a: cp.clone(),
        b: cp.clone(),
        consistency: None,
    };
    assert!(extra(&ev));
    assert!(extra(&ip));
    assert!(extra(&cons));
    assert!(extra(&cons.clone().sign(&signer()).unwrap()));
    assert!(extra(&cp.body));
    assert!(extra(&cp));
    assert!(extra(&w));
    assert!(extra(&w.clone().sign(&k).unwrap()));
    assert!(extra(&h));
    assert!(extra(&h.clone().sign(&k).unwrap()));
    assert!(extra(&eq));
}

/// A checkpoint is only as good as its signature under the pinned
/// control-plane key.
#[test]
fn checkpoint_signature_and_shape() {
    let (_, ls, _) = tree(P, 3);
    let cp = checkpoint(P, &ls, 3);
    cp.verify(&signer().public_key_hex()).unwrap();
    let other = ServiceSigner::from_seed("encompute-control", &[9u8; 32]).unwrap();
    assert!(cp.verify(&other.public_key_hex()).is_err());
    let mut x = cp.clone();
    x.body.size = 2;
    assert!(x.verify(&signer().public_key_hex()).is_err());
    let empty = ProjectCheckpoint {
        version: GOVLOG_VERSION,
        partition: P.into(),
        size: 0,
        root: "11".repeat(32),
        gseq: 0,
        at: 0,
    };
    assert!(empty.sign(&signer()).is_err());
}

/// Consistency proofs at the edges: from the empty tree only with the
/// empty root and no path; between equal sizes only with equal roots and
/// no path.
#[test]
fn consistency_proof_edge_cases_refused() {
    for n in [1usize, 2, 3, 8, 13] {
        let d = leaves(n);
        let mut s = Store::of(&d);
        let other = hex(&ref_leaf(b"forged"));
        // first == 0
        let zero = ConsistencyProof::build(P, 0, n as u64, &mut s).unwrap();
        zero.verify().unwrap();
        let mut q = zero.clone();
        q.first_root = other.clone();
        assert!(q.verify().is_err(), "forged empty root, {n}");
        let mut q = zero.clone();
        q.path.push(other.clone());
        assert!(q.verify().is_err(), "path from the empty tree, {n}");
        // first == second
        let same = ConsistencyProof::build(P, n as u64, n as u64, &mut s).unwrap();
        same.verify().unwrap();
        let mut q = same.clone();
        q.path.push(same.second_root.clone());
        assert!(q.verify().is_err(), "path between equal sizes, {n}");
        let mut q = same.clone();
        q.first_root = other.clone();
        assert!(q.verify().is_err(), "forged root at equal sizes, {n}");
        let mut q = same.clone();
        q.second_root = other.clone();
        assert!(
            q.verify().is_err(),
            "forged second root at equal sizes, {n}"
        );
        // first > second
        let mut q = same.clone();
        q.first = n as u64 + 1;
        assert!(q.verify().is_err(), "first after second, {n}");
        // An extra trailing element on a real proof.
        if n > 1 {
            let mut q = ConsistencyProof::build(P, 1, n as u64, &mut s).unwrap();
            q.verify().unwrap();
            q.path.push(other.clone());
            assert!(q.verify().is_err(), "trailing element, {n}");
        }
    }
}

/// Inclusion proofs at the edges: a one-leaf tree, the last leaf, an
/// extra trailing element, and an index outside the tree.
#[test]
fn inclusion_proof_edge_cases_refused() {
    let other = ref_leaf(b"forged");
    for n in [1usize, 2, 3, 5, 8, 9, 31] {
        let d = leaves(n);
        let mut s = Store::of(&d);
        let r = mth(&d);
        let last = InclusionProof::build(P, n as u64 - 1, n as u64, &mut s).unwrap();
        last.verify(&d[n - 1], &r).unwrap();
        if n == 1 {
            assert!(last.path.is_empty());
            assert_eq!(r, d[0]);
        }
        let mut q = last.clone();
        q.path.push(hex(&other));
        assert!(q.verify(&d[n - 1], &r).is_err(), "trailing element, {n}");
        let mut q = last.clone();
        q.leaf_index = n as u64;
        assert!(q.verify(&d[n - 1], &r).is_err(), "index outside, {n}");
        let mut q = last.clone();
        q.tree_size = 0;
        assert!(q.verify(&d[n - 1], &r).is_err(), "empty tree, {n}");
        assert!(InclusionProof::build(P, n as u64, n as u64, &mut s).is_err());
        let mut q = last.clone();
        q.path.push("zz".repeat(32));
        assert!(q.verify(&d[n - 1], &r).is_err(), "malformed hash, {n}");
    }
}

/// An event carries at most 32 references.
#[test]
fn event_references_are_capped() {
    let mut e = event(P, 1);
    e.refs = (0..32)
        .map(|i| (format!("ref_{}", "x".repeat(i + 1)), "x".into()))
        .collect();
    assert_eq!(e.refs.len(), 32);
    e.check().unwrap();
    e.refs.insert("one_more".into(), "x".into());
    assert!(e.check().is_err());
}
