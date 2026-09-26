//! The trust graph (ADR-014): a real multi-party, differentially private
//! collaboration recorded as one graph, and a trust report that fails on
//! every missing, forged or revoked piece.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use encompute_ir::confidentiality::PartyId;
use encompute_ir::parse;
use encompute_runtime::secagg::{
    identity_of, AggregationReceipt, AggregationSpec, JoinOptions, RoundCoordinator,
    RoundParticipant,
};
use encompute_runtime::trust::{
    node_id, Anchors, Authorization, NodeKind, ReportOptions, Revocation, Status, TrustGraph,
    TrustReport, AUTHORIZATION_VERSION,
};
use encompute_runtime::{sample_inputs, Backends, Mode, Model, Remote};

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

fn status(g: &TrustGraph, row: &str) -> Status {
    report(g)
        .rows
        .iter()
        .find(|x| x.name == row)
        .unwrap()
        .status
}

#[test]
fn a_whole_collaboration_verifies() {
    let (_, g, _) = collaboration();
    let r = report(&g);
    let text = r.to_string();
    assert!(r.satisfied, "{text}");
    for (row, want) in [
        ("Evidence", Status::Verified),
        ("Program", Status::Verified),
        ("Policy", Status::Verified),
        ("Owner authorization", Status::Authorized),
        ("Private aggregation", Status::Verified),
        ("Privacy budget", Status::Satisfied),
        ("Lineage", Status::Complete),
        ("Workload", Status::NotPresent),
        ("Execution", Status::NotPresent),
    ] {
        assert_eq!(
            r.rows.iter().find(|x| x.name == row).unwrap().status,
            want,
            "{row}\n{text}"
        );
    }
    assert!(text.contains("TRUST REQUIREMENTS SATISFIED"), "{text}");
    // Lineage: each aggregate derives from all three hospitals' gradients.
    let aggs: Vec<String> = g
        .of(NodeKind::Aggregate)
        .map(|(id, _)| id.clone())
        .collect();
    assert_eq!(aggs.len(), 2);
    let up = g.upstream(&aggs[0]);
    for x in ["a", "b", "c"] {
        assert!(up.contains(&format!("asset:gradient-{x}")), "{up:?}");
    }
    assert_eq!(g.downstream("asset:gradient-a").len(), 2);
    // The bundle round-trips and is content-addressed.
    let back = TrustGraph::from_bytes(&g.to_bytes().unwrap()).unwrap();
    assert_eq!(back.root().unwrap(), g.root().unwrap());
}

#[test]
fn owners_must_approve_the_program() {
    // Hospital C never approved.
    let text = eir();
    let m = Model::compile(parse(&text).unwrap()).unwrap();
    let mut g = TrustGraph::new();
    g.add_program(&m.program().to_string()).unwrap();
    g.add_aggregation_spec(spec_of(&m)).unwrap();
    for i in 0..2 {
        g.add_authorization(authorize(&m, i, T0)).unwrap();
    }
    assert_eq!(status(&g, "Owner authorization"), Status::Failed);
    // An approval of another program does not count, and one signed by
    // another party's key is refused on the way in.
    let mut other = authorize(&m, 2, T0);
    other.body.program_id = "ab".repeat(32);
    assert!(g.add_authorization(other).is_err(), "unknown program");
    let forged = Authorization {
        party: "hospital-c".into(),
        ..authorize(&m, 2, T0).body
    }
    .sign(&key(0))
    .unwrap();
    assert_eq!(
        g.add_authorization(forged).unwrap_err().code,
        encompute_ir::Code::TrustAuthorization
    );
    // Nor can a party approve an asset it does not own.
    let foreign = Authorization {
        asset: "gradient-a".into(),
        ..authorize(&m, 2, T0).body
    }
    .sign(&key(2))
    .unwrap();
    assert!(g.add_authorization(foreign).is_err());
    // An expired approval fails.
    let expired = Authorization {
        expires_at: Some(T0 + 50),
        ..authorize(&m, 2, T0).body
    }
    .sign(&key(2))
    .unwrap();
    g.add_authorization(expired).unwrap();
    assert_eq!(status(&g, "Owner authorization"), Status::Failed);
    g.add_authorization(authorize(&m, 2, T0 + 1)).unwrap();
    assert_eq!(status(&g, "Owner authorization"), Status::Authorized);
}

#[test]
fn revocation_shows_its_reach_and_forbids_later_use() {
    let (m, mut g, ledger) = collaboration();
    // Hospital A withdraws its data after round 2.
    let r = Revocation {
        version: AUTHORIZATION_VERSION,
        party: "hospital-a".into(),
        asset: "gradient-a".into(),
        authorization: None,
        reason: "consent withdrawn".into(),
        issued_at: T0 + 50,
    }
    .sign(&key(0))
    .unwrap();
    g.add_revocation(r).unwrap();
    let report = report(&g);
    // Past rounds stay valid, but everything derived from A is listed.
    assert!(
        !report.satisfied,
        "authorizations after revocation are void"
    );
    assert_eq!(report.revoked["asset:gradient-a"].len(), 2);
    assert!(report.to_string().contains("retrain or unlearn"));
    // A round after the revocation is a lineage failure.
    g.add_aggregation(round(&m, 3, &ledger, T0 + 60)).unwrap();
    assert_eq!(status(&g, "Lineage"), Status::Failed);
}

#[test]
fn tampered_evidence_fails_the_report() {
    let (_, g, _) = collaboration();
    let mut v: serde_json::Value = serde_json::from_slice(&g.to_bytes().unwrap()).unwrap();
    // Claim fewer dropped parties / another contributor list in a receipt.
    let rounds = v["nodes"].as_object_mut().unwrap();
    let (_, n) = rounds
        .iter_mut()
        .find(|(k, _)| k.starts_with("round:"))
        .unwrap();
    n["evidence"]["value"]["manifest"]["contributors"]
        .as_array_mut()
        .unwrap()
        .pop();
    let t = TrustGraph::from_bytes(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert_ne!(t.root().unwrap(), g.root().unwrap());
    assert_eq!(status(&t, "Private aggregation"), Status::Failed);
    // A privacy receipt claiming less spend.
    let mut v: serde_json::Value = serde_json::from_slice(&g.to_bytes().unwrap()).unwrap();
    let nodes = v["nodes"].as_object_mut().unwrap();
    let (_, n) = nodes
        .iter_mut()
        .find(|(k, _)| k.starts_with("privacy:"))
        .unwrap();
    n["evidence"]["value"]["cumulative_epsilon"] = serde_json::json!("0.001");
    let t = TrustGraph::from_bytes(&serde_json::to_vec(&v).unwrap()).unwrap();
    // The round's signed receipt carries the authentic release: the edited
    // copy contradicts it.
    let r = report(&t);
    assert_eq!(row(&r, "Evidence"), Status::Failed, "{r}");
    assert!(!r.satisfied);
    // A program text that is not the program.
    let mut v: serde_json::Value = serde_json::from_slice(&g.to_bytes().unwrap()).unwrap();
    let nodes = v["nodes"].as_object_mut().unwrap();
    let (_, n) = nodes
        .iter_mut()
        .find(|(k, _)| k.starts_with("program:"))
        .unwrap();
    let text = n["evidence"]["value"]
        .as_str()
        .unwrap()
        .replace("epsilon 3.0", "epsilon 30.0");
    n["evidence"]["value"] = serde_json::json!(text);
    let t = TrustGraph::from_bytes(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert_eq!(status(&t, "Program"), Status::Failed);
}

#[test]
fn execution_receipts_join_the_graph() {
    let m = Model::compile(
        parse(
            "encompute 0.1\nprogram score precision 0.01\n\
             %0 = input \"x\" [-1.0, 1.0] : secret vector<4>\n%1 = sum %0 : secret scalar\n\
             output \"y\" = %1\n",
        )
        .unwrap(),
    )
    .unwrap();
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    std::thread::spawn(move || {
        encompute_evaluator::server::Evaluator::new(Backends::MOCK, Default::default())
            .serve(server)
    });
    let remote = Remote::new(&url);
    let trusted = remote.evaluator_identity().unwrap();
    let client = m.new_client(Mode::Mock).unwrap();
    let run = remote
        .run(
            &client,
            m.program(),
            None,
            &sample_inputs(m.program(), 1, 1),
            &trusted,
        )
        .unwrap();
    let mut g = TrustGraph::new();
    g.add_program(&m.program().to_string()).unwrap();
    let e = g.add_execution_receipt(run.receipt.clone()).unwrap();
    assert!(g
        .out(&e, encompute_runtime::trust::EdgeKind::Runs)
        .next()
        .is_some());
    // An evaluator the verifier does not trust (nor has seen attested) is
    // unchecked; once trusted, verified.
    assert_eq!(status(&g, "Execution"), Status::Unchecked);
    let mut a = anchors();
    a.evaluators
        .insert(run.receipt.evaluator_public_key.clone());
    let r = g
        .report(&ReportOptions {
            anchors: a,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        r.rows
            .iter()
            .find(|x| x.name == "Execution")
            .unwrap()
            .status,
        Status::Verified
    );
    let mut forged = run.receipt.clone();
    forged.receipt.output_commitment = "00".repeat(32);
    assert!(g.add_execution_receipt(forged).is_err());
}

fn row(r: &TrustReport, name: &str) -> Status {
    r.rows.iter().find(|x| x.name == name).unwrap().status
}

fn edit(g: &TrustGraph, f: impl FnOnce(&mut serde_json::Value)) -> TrustGraph {
    let mut v: serde_json::Value = serde_json::from_slice(&g.to_bytes().unwrap()).unwrap();
    f(&mut v);
    TrustGraph::from_bytes(&serde_json::to_vec(&v).unwrap()).unwrap()
}

/// Review finding 1: keys come from the verifier, never from the bundle.
#[test]
fn nothing_vouches_for_itself() {
    let (m, g, _) = collaboration();
    // No anchors: everything present, nothing checked, not satisfied.
    let r = g
        .report(&ReportOptions {
            now: Some(T0 + 100),
            ..Default::default()
        })
        .unwrap();
    assert!(!r.satisfied, "{r}");
    for name in [
        "Owner authorization",
        "Private aggregation",
        "Privacy budget",
    ] {
        assert_eq!(row(&r, name), Status::Unchecked, "{name}\n{r}");
    }
    assert!(r.to_string().contains("not checked against trusted keys"));
    // A bundle built with an attacker's key for hospital C (its spec, its
    // parties' keys and C's approval all agree with each other) fails
    // against the consortium's real keys.
    let evil = SigningKey::from_bytes(&[66; 32]);
    let mut g2 = TrustGraph::new();
    g2.add_program(&m.program().to_string()).unwrap();
    let plan = m.aggregation_plan(None).unwrap();
    let ids = (0..3)
        .map(|i| identity_of(&party(i), &if i == 2 { evil.clone() } else { key(i) }))
        .collect();
    g2.add_aggregation_spec(AggregationSpec::new(plan, ids).unwrap())
        .unwrap();
    for i in 0..2 {
        g2.add_authorization(authorize(&m, i, T0)).unwrap();
    }
    g2.add_authorization(
        Authorization {
            ..authorize(&m, 2, T0).body
        }
        .sign(&evil)
        .unwrap(),
    )
    .unwrap();
    let r = report(&g2);
    assert_eq!(row(&r, "Owner authorization"), Status::Failed, "{r}");
    // A coordinator the verifier does not trust.
    let mut a = anchors();
    a.coordinators = ["ab".repeat(32)].into();
    let r = g
        .report(&ReportOptions {
            anchors: a,
            now: Some(T0 + 100),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(row(&r, "Private aggregation"), Status::Failed);
    assert_eq!(row(&r, "Privacy budget"), Status::Failed);
}

/// Review finding 2: edges, nodes and attributes come from the evidence.
#[test]
fn edges_come_from_the_evidence() {
    let (_, g, _) = collaboration();
    // Hospital C claims to own A's gradient.
    let t = edit(&g, |v| {
        v["edges"].as_array_mut().unwrap().push(serde_json::json!({
            "from": "party:hospital-c", "kind": "owns", "to": "asset:gradient-a"
        }))
    });
    assert_eq!(row(&report(&t), "Evidence"), Status::Failed);
    // The program's use of an asset is dropped, to skip its owner's
    // approval.
    let t = edit(&g, |v| {
        v["edges"]
            .as_array_mut()
            .unwrap()
            .retain(|e| !(e["kind"] == "uses" && e["to"] == "asset:gradient-c"))
    });
    assert_eq!(row(&report(&t), "Evidence"), Status::Failed);
    // An aggregate's lineage is pruned.
    let t = edit(&g, |v| {
        v["edges"]
            .as_array_mut()
            .unwrap()
            .retain(|e| e["kind"] != "derived_from")
    });
    assert!(!report(&t).satisfied);
    // Review finding 7: a round's time is read from its signed receipt,
    // and an edited attribute fails.
    let t = edit(&g, |v| {
        for (k, n) in v["nodes"].as_object_mut().unwrap() {
            if k.starts_with("round:") {
                n["attrs"]["opened_at"] = serde_json::json!("0");
            }
        }
    });
    let r = report(&t);
    assert_eq!(row(&r, "Evidence"), Status::Failed, "{r}");
    assert_eq!(row(&r, "Lineage"), Status::Complete, "{r}");
}

/// A standalone privacy receipt from the trusted coordinator key, as a
/// malicious (or buggy) coordinator could sign it.
fn signed_release(
    g: &TrustGraph,
    edit: impl FnOnce(&mut encompute_runtime::dp::PrivacyReceipt),
    signer: &SigningKey,
) -> TrustGraph {
    let (_, n) = g
        .nodes
        .iter()
        .find(|(k, _)| k.starts_with("privacy:"))
        .unwrap();
    let Some(encompute_runtime::trust::Evidence::PrivacyReceipt(r)) = &n.evidence else {
        panic!()
    };
    let mut r = (**r).clone();
    r.event_id = "ee".repeat(32);
    r.ledger_seq = 1000;
    edit(&mut r);
    let mut t = g.clone();
    t.add_privacy_receipt(r.sign(signer).unwrap()).unwrap();
    t
}

/// Review findings 3, 4 and 5: budgets are the program's, numbers must be
/// finite, and every release is signed by a trusted coordinator.
#[test]
fn privacy_releases_answer_to_the_declared_budget() {
    let (_, g, _) = collaboration();
    // A well-formed later release still verifies.
    let ok = signed_release(&g, |r| r.cumulative_epsilon = "2.9".into(), &coordinator());
    let r = report(&ok);
    assert_eq!(row(&r, "Privacy budget"), Status::Satisfied, "{r}");
    // NaN spend.
    let t = signed_release(&g, |r| r.cumulative_epsilon = "NaN".into(), &coordinator());
    assert_eq!(row(&report(&t), "Privacy budget"), Status::Failed);
    // The receipt claims a larger budget than the program declares (3.0).
    let t = signed_release(
        &g,
        |r| {
            r.budget_epsilon = "30.0".into();
            r.cumulative_epsilon = "20.0".into();
        },
        &coordinator(),
    );
    let r = report(&t);
    assert_eq!(row(&r, "Privacy budget"), Status::Failed);
    assert!(r.to_string().contains("declared budget"), "{r}");
    // A release of an asset no program declares.
    let t = signed_release(&g, |r| r.asset_id = "gradient-z".into(), &coordinator());
    assert!(!report(&t).satisfied);
    // Self-signed by an unknown key.
    let t = signed_release(&g, |_| {}, &SigningKey::from_bytes(&[9; 32]));
    assert_eq!(row(&report(&t), "Privacy budget"), Status::Failed);
}

/// Review finding 6: an empty or partial bundle is never SATISFIED.
#[test]
fn absent_evidence_is_not_satisfied() {
    let r = report(&TrustGraph::new());
    assert!(!r.satisfied);
    assert!(r.to_string().contains("Program is required"), "{r}");
    // Required rows that are absent are unmet.
    let text = eir();
    let m = Model::compile(parse(&text).unwrap()).unwrap();
    let mut g = TrustGraph::new();
    g.add_program(&m.program().to_string()).unwrap();
    let r = g
        .report(&ReportOptions {
            anchors: anchors(),
            require: vec!["Private aggregation".into(), "Privacy budget".into()],
            now: Some(T0 + 100),
            ..Default::default()
        })
        .unwrap();
    assert!(!r.satisfied);
    assert!(
        r.unmet
            .iter()
            .any(|u| u.contains("Privacy budget is required")),
        "{r}"
    );
}

/// The approved plan for the collaboration (standard profile: secure
/// aggregation with DP), and the spec bound to it.
fn planned(
    m: &Model,
) -> (
    encompute_runtime::planner::ConfidentialExecutionPlan,
    AggregationSpec,
) {
    use encompute_runtime::planner::*;
    let ctx = encompute_runtime::planning::planning_context(
        m.program(),
        Profile::Standard,
        Infrastructure::default(),
        Preferences::default(),
        None,
    )
    .unwrap();
    let plan = plan_or_fail(m.program(), &ctx).unwrap();
    let id = plan.id().unwrap().hex();
    let p = m.aggregation_plan(None).unwrap().with_execution_plan(&id);
    let spec =
        AggregationSpec::new(p, (0..3).map(|i| identity_of(&party(i), &key(i))).collect()).unwrap();
    (plan, spec)
}

/// INV-115 end to end: planned → executed → evidence verified → the plan
/// satisfied by observed execution; and every runtime deviation fails.
#[test]
fn observed_execution_matches_the_approved_plan() {
    let text = eir();
    let m = Model::compile(parse(&text).unwrap()).unwrap();
    let (plan, spec) = planned(&m);
    let build = |spec: AggregationSpec, with_plan: bool| {
        let mut g = TrustGraph::new();
        g.add_program(&m.program().to_string()).unwrap();
        if with_plan {
            g.add_plan(plan.clone()).unwrap();
        }
        g.add_aggregation_spec(spec.clone()).unwrap();
        for i in 0..3 {
            g.add_authorization(authorize(&m, i, T0 - 10)).unwrap();
        }
        let ledger = dir("plan-ledger");
        g.add_aggregation(round_with(spec, 1, &ledger, T0 + 1))
            .unwrap();
        g
    };
    let g = build(spec.clone(), true);
    let r = report(&g);
    assert!(r.satisfied, "{r}");
    assert_eq!(row(&r, "Plan"), Status::Satisfied, "{r}");
    assert!(r
        .to_string()
        .contains("PLAN SATISFIED BY OBSERVED EXECUTION"));
    // Planned but not yet executed: unchecked, not satisfied.
    let mut g0 = TrustGraph::new();
    g0.add_program(&m.program().to_string()).unwrap();
    g0.add_plan(plan.clone()).unwrap();
    assert_eq!(row(&report(&g0), "Plan"), Status::Unchecked);
    // A round under another plan ID.
    let mut other = spec.clone();
    other.plan.execution_plan_id = Some("ab".repeat(32));
    let r = report(&build(other, true));
    assert!(!r.satisfied);
    assert_eq!(row(&r, "Plan"), Status::Failed, "{r}");
    // A round with no plan at all, while one was approved.
    let mut none = spec.clone();
    none.plan.execution_plan_id = None;
    assert_eq!(row(&report(&build(none, true)), "Plan"), Status::Failed);
    // DP removed from the round (its own spec, bound to the plan).
    let mut no_dp = spec.clone();
    no_dp.plan.dp = None;
    no_dp.plan.privacy_policy_id = None;
    for p in no_dp.plan.participants.iter_mut() {
        p.budget = None;
    }
    let r = report(&build(no_dp, true));
    assert_eq!(row(&r, "Plan"), Status::Failed, "{r}");
    // A tampered plan (the approved one, with its threshold lowered) is
    // refused on the way in, and by the report if forced into a bundle.
    let mut weak = plan.clone();
    for s in weak.steps.iter_mut() {
        for x in s.mechanisms.iter_mut() {
            if let encompute_runtime::planner::Mechanism::SecureAggregation { threshold, .. } = x {
                *threshold = 2;
            }
        }
    }
    let mut g2 = TrustGraph::new();
    g2.add_program(&m.program().to_string()).unwrap();
    assert!(g2.add_plan(weak).is_err());
}
