//! Evidence written straight into a bundle (not through `add_*`) gets the
//! checks evidence added through `add_*` gets: the report re-checks every
//! piece while rebuilding the graph (review finding TG-2), and honours a
//! revocation only from the asset's owner or the authorization's signer
//! (review finding TG-1).

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use encompute_ir::confidentiality::PartyId;
use encompute_ir::parse;
use encompute_runtime::secagg::{
    identity_of, AggregationReceipt, AggregationSpec, JoinOptions, RoundCoordinator,
    RoundParticipant,
};
use encompute_runtime::trust::{
    node_id, Anchors, Authorization, Edge, EdgeKind, Evidence, Node, NodeKind, ReportOptions,
    Revocation, Status, TrustGraph, TrustReport, AUTHORIZATION_VERSION,
};
use encompute_runtime::Model;

const T0: u64 = 1_900_000_000;
const LEN: usize = 16;

fn eir() -> String {
    let mut s = String::from(
        "encompute 0.1\nprogram fedavg precision 0.001 purpose \"disease-training\"\n\
         party \"coordinator\" \"Coordinator\"\n",
    );
    for x in ["a", "b", "c"] {
        s.push_str(&format!("party \"hospital-{x}\" \"Hospital {x}\"\n"));
    }
    for x in ["a", "b", "c"] {
        s.push_str(&format!(
            "asset \"gradient-{x}\" gradient owners [\"hospital-{x}\"] readers [\"coordinator\"] \
             purposes [\"disease-training\"] release aggregate_only \
             privacy unit \"patient\" epsilon 3.0 delta 1e-6\n"
        ));
    }
    for (i, x) in ["a", "b", "c"].iter().enumerate() {
        s.push_str(&format!(
            "%{i} = input \"g{x}\" [-1.0, 1.0] asset \"gradient-{x}\" : secret vector<{LEN}>\n"
        ));
    }
    s.push_str(&format!(
        "%3 = add %0, %1 : secret vector<{LEN}>\n%4 = add %3, %2 : secret vector<{LEN}>\n\
         output \"global_gradient\" = %4 to \"coordinator\"\n\
         aggregate \"global_gradient\" sum minimum 3 colluding 2 clip [-1.0, 1.0] scale 4096 \
         modulus 40 dp discrete_gaussian clip_norm 1.0 noise_multiplier 6.0\n"
    ));
    s
}

fn party(i: usize) -> PartyId {
    PartyId::new(&format!("hospital-{}", (b'a' + i as u8) as char)).unwrap()
}

fn key(i: usize) -> SigningKey {
    SigningKey::from_bytes(&[i as u8 + 1; 32])
}

fn coordinator() -> SigningKey {
    SigningKey::from_bytes(&[200; 32])
}

fn hexkey(k: &SigningKey) -> String {
    k.verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What the verifier knows out of band: the three hospitals' keys and the
/// coordinator's.
fn anchors() -> Anchors {
    Anchors {
        parties: (0..3)
            .map(|i| (party(i).to_string(), hexkey(&key(i))))
            .collect(),
        coordinators: [hexkey(&coordinator())].into(),
        ..Anchors::default()
    }
}

fn report(g: &TrustGraph) -> TrustReport {
    g.report(&ReportOptions {
        anchors: anchors(),
        now: Some(T0 + 100),
        ..Default::default()
    })
    .unwrap()
}

fn spec_of(m: &Model) -> AggregationSpec {
    let plan = m.aggregation_plan(None).unwrap();
    AggregationSpec::new(
        plan,
        (0..3).map(|i| identity_of(&party(i), &key(i))).collect(),
    )
    .unwrap()
}

/// A fresh directory per call: tests run in parallel, and a ledger shared
/// between them would mix their spend.
fn dir(name: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("encompute-trust-{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// One DP round with all three hospitals.
fn round(m: &Model, seq: u64, ledger: &Path, opened_at: u64) -> AggregationReceipt {
    round_with(spec_of(m), seq, ledger, opened_at)
}

fn round_with(
    spec: AggregationSpec,
    seq: u64,
    ledger: &Path,
    opened_at: u64,
) -> AggregationReceipt {
    let mut c = RoundCoordinator::open(spec.clone(), seq, coordinator(), None, opened_at)
        .unwrap()
        .with_ledger(ledger)
        .unwrap();
    let views = c.ledger_views().unwrap();
    let mut ps: Vec<RoundParticipant> = (0..3)
        .map(|i| {
            let asset = format!("gradient-{}", (b'a' + i as u8) as char);
            RoundParticipant::join_with(
                &spec,
                &c.spec,
                &c.round,
                &party(i),
                key(i),
                &[0.01 * i as f64; LEN],
                JoinOptions {
                    ledger: views.get(&asset),
                    ..JoinOptions::default()
                },
            )
            .unwrap()
        })
        .collect();
    for p in ps.iter_mut() {
        c.receive_advertise(p.advertise().unwrap()).unwrap();
    }
    let k = c.close_advertise().unwrap();
    for p in ps.iter_mut() {
        c.receive_shares(p.share_keys(&k).unwrap()).unwrap();
    }
    let inbox = c.close_shares().unwrap();
    for p in ps.iter_mut() {
        let who = p.party().clone();
        c.receive_masked(p.masked_input(&inbox[&who]).unwrap())
            .unwrap();
    }
    let s = c.close_masked().unwrap();
    for p in ps.iter_mut() {
        c.receive_consistency(p.consistency(&s).unwrap()).unwrap();
    }
    let u = c.close_consistency().unwrap();
    for p in ps.iter_mut() {
        c.receive_reveal(p.unmask(&u).unwrap()).unwrap();
    }
    c.finalize().unwrap().1
}

/// The graph after two rounds, every owner having approved the program.
fn collaboration() -> (Model, TrustGraph, PathBuf) {
    let text = eir();
    let m = Model::compile(parse(&text).unwrap()).unwrap();
    let mut g = TrustGraph::new();
    let prog = g.add_program(&m.program().to_string()).unwrap();
    assert_eq!(prog, node_id(NodeKind::Program, &m.ids().program_id));
    g.add_aggregation_spec(spec_of(&m)).unwrap();
    for i in 0..3 {
        g.add_authorization(authorize(&m, i, T0 - 10)).unwrap();
    }
    let ledger = dir("ledger");
    for seq in 1..=2 {
        g.add_aggregation(round(&m, seq, &ledger, T0 + seq))
            .unwrap();
    }
    (m, g, ledger)
}

fn authorize(m: &Model, i: usize, at: u64) -> encompute_runtime::trust::SignedAuthorization {
    let ids = m.ids();
    Authorization {
        version: AUTHORIZATION_VERSION,
        party: party(i).to_string(),
        asset: format!("gradient-{}", (b'a' + i as u8) as char),
        program_id: ids.program_id.clone(),
        policy_id: ids.policy_id.clone(),
        privacy_policy_id: ids.privacy_policy_id.clone(),
        purpose: Some("disease-training".into()),
        issued_at: at,
        expires_at: None,
    }
    .sign(&key(i))
    .unwrap()
}

fn row(r: &TrustReport, name: &str) -> (Status, Vec<String>) {
    let x = r.rows.iter().find(|x| x.name == name).unwrap();
    (x.status, x.details.clone())
}

/// `g` with `evidence` written straight into it, as a bundle file could
/// carry it, bypassing every `add_*` check: the node, with the label and
/// edges linking would give it, so the bundle's cache agrees with its
/// evidence and only the checks can tell.
fn forced(
    g: &TrustGraph,
    kind: NodeKind,
    id: &str,
    label: &str,
    edges: &[(String, EdgeKind, String)],
    evidence: Evidence,
) -> TrustGraph {
    let mut raw = g.clone();
    let id = node_id(kind, id);
    raw.nodes.insert(
        id.clone(),
        Node {
            kind,
            label: label.into(),
            attrs: Default::default(),
            evidence: Some(evidence),
        },
    );
    for (from, kind, to) in edges {
        let f = |x: &str| if x == "@" { id.clone() } else { x.to_owned() };
        raw.edges.insert(Edge {
            from: f(from),
            kind: *kind,
            to: f(to),
        });
    }
    raw
}

fn e(from: &str, kind: EdgeKind, to: &str) -> (String, EdgeKind, String) {
    (from.into(), kind, to.into())
}

fn revocation(signer: usize, asset: &str, authorization: Option<String>) -> Revocation {
    Revocation {
        version: AUTHORIZATION_VERSION,
        party: party(signer).to_string(),
        asset: asset.into(),
        authorization,
        reason: "griefing".into(),
        issued_at: T0,
    }
}

/// Review finding TG-1 (ENC-SF-2026-075): a revocation signed by a party that does not own
/// the asset is refused by `add_revocation`, and when forced into a bundle
/// the report ignores it, with a note, instead of voiding the owner's
/// approvals (which blocked `encompute export` and training resume).
#[test]
fn a_revocation_by_a_non_owner_is_ignored_with_a_note() {
    let (_, g, _) = collaboration();
    assert!(report(&g).satisfied);
    let r = revocation(1, "gradient-a", None).sign(&key(1)).unwrap();
    assert!(
        g.clone().add_revocation(r.clone()).is_err(),
        "ingest refuses a non-owner"
    );
    let bundle = forced(
        &g,
        NodeKind::Revocation,
        &r.id().unwrap(),
        "hospital-b revokes gradient-a",
        &[
            e("party:hospital-b", EdgeKind::Signed, "@"),
            e("@", EdgeKind::Revokes, "asset:gradient-a"),
        ],
        Evidence::Revocation(r),
    );
    let rep = report(&bundle);
    assert_eq!(row(&rep, "Evidence").0, Status::Verified, "{rep}");
    let (status, details) = row(&rep, "Owner authorization");
    assert_eq!(status, Status::Authorized, "{rep}");
    assert!(
        details
            .iter()
            .any(|d| d.contains("ignored") && d.contains("hospital-b does not own gradient-a")),
        "{rep}"
    );
    assert!(rep.revoked.is_empty(), "{rep}");
    assert!(rep.satisfied, "{rep}");
    // The owner's own revocation is still honoured.
    let own = revocation(0, "gradient-a", None).sign(&key(0)).unwrap();
    let mut g2 = g.clone();
    g2.add_revocation(own).unwrap();
    let rep = report(&g2);
    assert!(rep.revoked.contains_key("asset:gradient-a"), "{rep}");
    assert_eq!(row(&rep, "Owner authorization").0, Status::Failed, "{rep}");
}

/// Review finding TG-1 (ENC-SF-2026-075): only the party that signed an authorization may
/// revoke it, even naming the authorization's own asset.
#[test]
fn an_authorization_is_revoked_only_by_its_signer() {
    let (m, g, _) = collaboration();
    let approval = authorize(&m, 0, T0 - 10).id().unwrap();
    let r = revocation(1, "gradient-a", Some(approval.clone()))
        .sign(&key(1))
        .unwrap();
    assert!(g.clone().add_revocation(r.clone()).is_err());
    let an = node_id(NodeKind::Authorization, &approval);
    let bundle = forced(
        &g,
        NodeKind::Revocation,
        &r.id().unwrap(),
        "hospital-b revokes gradient-a",
        &[
            e("party:hospital-b", EdgeKind::Signed, "@"),
            e("@", EdgeKind::Revokes, "asset:gradient-a"),
            e("@", EdgeKind::Revokes, &an),
        ],
        Evidence::Revocation(r),
    );
    let rep = report(&bundle);
    assert_eq!(row(&rep, "Evidence").0, Status::Verified, "{rep}");
    let (status, details) = row(&rep, "Owner authorization");
    assert_eq!(status, Status::Authorized, "{rep}");
    assert!(
        details
            .iter()
            .any(|d| d.contains("did not sign the authorization it revokes")),
        "{rep}"
    );
    assert!(rep.satisfied, "{rep}");
    // Its signer's revocation voids it.
    let own = revocation(0, "gradient-a", Some(approval))
        .sign(&key(0))
        .unwrap();
    let mut g2 = g.clone();
    g2.add_revocation(own).unwrap();
    let rep = report(&g2);
    assert_eq!(row(&rep, "Owner authorization").0, Status::Failed, "{rep}");
    assert!(!rep.satisfied);
}

/// Review finding TG-2 (ENC-SF-2026-076): `add_training_spec` validates, and so does the
/// report when it reads a bundle: a spec every worker and ingest refuses
/// fails the report's evidence check, with the reason.
#[test]
fn an_invalid_training_spec_in_a_bundle_fails_the_report() {
    use encompute_runtime::training::*;
    let (m, g, _) = collaboration();
    let h = |c: char| c.to_string().repeat(64);
    let spec = TrainingSpec {
        version: 1,
        project: "p".into(),
        purpose: "disease-training".into(),
        plan_id: h('a'),
        program_id: m.ids().program_id.clone(),
        policy_id: None,
        privacy_policy_id: None,
        aggregation_spec_id: h('e'),
        base_model: ModelCommitment {
            asset_id: "gradient-a".into(),
            owner: "hospital-a".into(),
            architecture: "{\"factory\":\"subprocess:run\",\"kwargs\":{}}".into(),
            weights_digest: h('f'),
            huggingface: None,
        },
        // One dataset only, and DP-SGD with 7 local steps: validate() refuses both.
        datasets: vec![DatasetCommitment {
            asset_id: "gradient-b".into(),
            owner: "hospital-b".into(),
            gradient_asset: "gradient-b".into(),
            digest: h('1'),
            privacy_units: None,
            grouping_digest: None,
            preprocessing: None,
        }],
        code_digest: h('3'),
        layout_digest: h('4'),
        config: TrainingConfig {
            method: "lora".into(),
            rank: 4,
            alpha: 8,
            target_modules: vec!["q".into()],
            optimizer: "sgd".into(),
            learning_rate: "0.05".into(),
            update_clip: "0.1".into(),
            local_steps: 7,
            batch_size: 8,
            rounds: 3,
            adapter_parameters: 512,
            dp_sgd: None,
            peft: None,
        },
        participants: vec![],
        key_brokers: [("broker".to_owned(), h('9'))].into(),
        coordinator_key: h('8'),
        initial_adapter_digest: h('7'),
    };
    let why = spec.validate().unwrap_err().message;
    assert!(g.clone().add_training_spec(spec.clone()).is_err());
    let id = spec.id().unwrap();
    let bundle = forced(
        &g,
        NodeKind::Training,
        &id,
        "lora fine-tuning of gradient-a",
        &[],
        Evidence::TrainingSpec(Box::new(spec)),
    );
    let (_, problems) = bundle.rebuild();
    assert!(
        problems
            .iter()
            .any(|p| p.contains("invalid evidence") && p.contains(&why)),
        "{problems:?}"
    );
    let rep = report(&bundle);
    let (status, details) = row(&rep, "Evidence");
    assert_eq!(status, Status::Failed, "{rep}");
    assert!(
        details
            .iter()
            .any(|d| d.contains("invalid evidence") && d.contains(&why)),
        "{rep}"
    );
    assert!(!rep.satisfied);
}

/// Review finding TG-2 (ENC-SF-2026-076): an authorization signed by a party that does not
/// own the asset is refused on the way in and fails the report when forced
/// into a bundle.
#[test]
fn a_non_owner_authorization_in_a_bundle_fails_the_report() {
    let (m, g, _) = collaboration();
    let mut a = authorize(&m, 1, T0 - 10).body;
    a.asset = "gradient-a".into();
    let a = a.sign(&key(1)).unwrap();
    assert!(g.clone().add_authorization(a.clone()).is_err());
    let program = node_id(NodeKind::Program, &m.ids().program_id);
    let bundle = forced(
        &g,
        NodeKind::Authorization,
        &a.id().unwrap(),
        "hospital-b approves gradient-a",
        &[
            e("party:hospital-b", EdgeKind::Signed, "@"),
            e("@", EdgeKind::Authorizes, &program),
            e("@", EdgeKind::Covers, "asset:gradient-a"),
        ],
        Evidence::Authorization(a),
    );
    let rep = report(&bundle);
    let (status, details) = row(&rep, "Evidence");
    assert_eq!(status, Status::Failed, "{rep}");
    assert!(
        details
            .iter()
            .any(|d| d.contains("invalid evidence") && d.contains("does not own gradient-a")),
        "{rep}"
    );
    assert!(!rep.satisfied);
}
