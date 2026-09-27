//! Fuzz smoke tests for Trust Graph bundles and records: mutated bundles,
//! authorizations and revocations never panic; a mutated record never
//! verifies; rebuilding and reporting finish in bounded time. Resource
//! limits: deep JSON, huge graphs and cyclic edges are bounded.

#[path = "../../encompute-ir/tests/fuzz_support/mod.rs"]
mod fuzz_support;

use std::time::Duration;

use ed25519_dalek::SigningKey;
use encompute_ir::Code;
use encompute_trust::{
    program_id, Authorization, Edge, EdgeKind, Node, NodeKind, ReportOptions, Revocation,
    SignedAuthorization, SignedRevocation, TrustGraph,
};
use fuzz_support::{run, within};

const PROGRAM: &str = include_str!("../../../examples/06_confidentiality_policy/training.eir");

fn records() -> (SignedAuthorization, SignedRevocation) {
    let key = SigningKey::from_bytes(&[9; 32]);
    let text = encompute_ir::parse(PROGRAM).unwrap().to_string();
    let a = Authorization {
        version: 1,
        party: "hospital-a".into(),
        asset: "patients".into(),
        program_id: program_id(&text),
        policy_id: None,
        privacy_policy_id: None,
        purpose: Some("disease-training".into()),
        issued_at: 1_700_000_000,
        expires_at: Some(1_800_000_000),
    }
    .sign(&key)
    .unwrap();
    let r = Revocation {
        version: 1,
        party: "hospital-a".into(),
        asset: "patients".into(),
        authorization: Some(a.id().unwrap()),
        reason: "withdrawn".into(),
        issued_at: 1_750_000_000,
    }
    .sign(&key)
    .unwrap();
    (a, r)
}

fn bundles() -> Vec<Vec<u8>> {
    let (a, r) = records();
    let mut g = TrustGraph::new();
    g.add_program(PROGRAM).unwrap();
    let mut out = vec![g.to_bytes().unwrap()];
    let _ = g.add_authorization(a);
    out.push(g.to_bytes().unwrap());
    let _ = g.add_revocation(r);
    out.push(g.to_bytes().unwrap());
    out
}

fn report(g: &TrustGraph) {
    let _ = g.report(&ReportOptions {
        now: Some(1_760_000_000),
        ..ReportOptions::default()
    });
}

#[test]
fn mutated_bundles_never_panic() {
    run(
        "bundle",
        &bundles(),
        1500,
        Duration::from_secs(3),
        |bytes| {
            let Ok(g) = TrustGraph::from_bytes(bytes) else {
                return;
            };
            let _ = g.check_edges();
            if let Some(id) = g.nodes.keys().next() {
                let _ = g.upstream(id);
                let _ = g.downstream(id);
            }
            let (rebuilt, _) = g.rebuild();
            report(&g);
            let _ = rebuilt.to_bytes();
        },
    );
}

#[test]
fn mutated_records_never_panic_or_verify() {
    let (a, r) = records();
    let pk = a.public_key.clone();
    let seeds = vec![
        serde_json::to_vec(&a).unwrap(),
        serde_json::to_vec(&r).unwrap(),
    ];
    run("records", &seeds, 5000, Duration::from_secs(2), |bytes| {
        let mut g = TrustGraph::new();
        g.add_program(PROGRAM).unwrap();
        if let Ok(x) = serde_json::from_slice::<SignedAuthorization>(bytes) {
            if x.verify(&pk).is_ok() {
                assert_eq!(x.body, a.body);
            }
            let _ = g.add_authorization(x);
        }
        if let Ok(x) = serde_json::from_slice::<SignedRevocation>(bytes) {
            if x.verify(&pk).is_ok() {
                assert_eq!(x.body, r.body);
            }
            let _ = g.add_revocation(x);
        }
        let _ = g.rebuild();
    });
}

#[test]
fn large_and_malformed_bundles_are_bounded() {
    let limit = Duration::from_secs(2);
    for b in [
        fuzz_support::nested_json(100_000, ""),
        "{\"version\":4294967296,\"nodes\":{},\"edges\":[]}".into(),
        "{\"version\":1,\"nodes\":{},\"edges\":[{}]}".into(),
        "\u{feff}{}".into(),
    ] {
        let e = within(limit, || TrustGraph::from_bytes(b.as_bytes())).unwrap_err();
        assert_eq!(e.code, Code::TrustGraph, "{e}");
    }
    assert_eq!(
        TrustGraph::from_bytes(b"\xff\xfe").unwrap_err().code,
        Code::TrustGraph
    );
    // A 3000-node chain with a cycle back to the start: walks terminate.
    let mut g = TrustGraph::new();
    let n = 3000;
    let ids: Vec<String> = (0..n).map(|i| format!("n{i}")).collect();
    for id in &ids {
        g.nodes.insert(
            id.clone(),
            Node {
                kind: NodeKind::Asset,
                label: id.clone(),
                attrs: Default::default(),
                evidence: None,
            },
        );
    }
    let edge = |from: &str, to: &str| Edge {
        from: from.into(),
        kind: EdgeKind::DerivedFrom,
        to: to.into(),
    };
    for w in ids.windows(2) {
        g.edges.insert(edge(&w[0], &w[1]));
    }
    g.edges.insert(edge(&ids[n - 1], &ids[0]));
    let bytes = g.to_bytes().unwrap();
    let g = within(limit, || TrustGraph::from_bytes(&bytes)).unwrap();
    within(Duration::from_secs(20), || {
        assert_eq!(g.upstream(&ids[0]).len(), n);
        assert_eq!(g.downstream(&ids[0]).len(), n);
    });
    within(Duration::from_secs(20), || report(&g));
    g.check_edges().unwrap();
}
