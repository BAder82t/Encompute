//! Confidentiality analysis: the training scenario of ADR-010, and every
//! rejected flow.

use encompute_analysis::confidentiality::{analyze, Policy};
use encompute_ir::confidentiality::{AssetKind, OutputRelease, PartyId, Release};
use encompute_ir::{parse, Builder, Code, Program};

/// Hospital A owns patient data; ModelCo owns the weights; neither may see
/// the other's asset. A training step derives a gradient, releasable only
/// in aggregate (to the coordinator), for "disease-training".
fn training(outputs: &str, purpose: &str, derive: &str) -> String {
    format!(
        r#"encompute 0.1
program step precision 0.001 purpose "{purpose}"
party "hospital-a" "Hospital A"
party "modelco" "ModelCo"
party "coordinator" "Training coordinator"
asset "patients" dataset owners ["hospital-a"] readers ["hospital-a"] purposes ["disease-training"] release never derive [gradient aggregate_only to ["coordinator", "modelco"]]
asset "weights" model owners ["modelco"] readers ["modelco"] purposes ["disease-training"] release never derive [gradient aggregate_only to ["coordinator"]]
%0 = input "x" [-1.0, 1.0] asset "patients" : secret vector<4>
%1 = input "w" [-1.0, 1.0] asset "weights" : secret vector<4>
%2 = dot %0, %1 : secret scalar
%3 = mul %0, %1 : secret vector<4>
{derive}{outputs}"#
    )
}

fn program(outputs: &str) -> Program {
    parse(&training(
        outputs,
        "disease-training",
        "derive %3 gradient aggregate_only\n",
    ))
    .unwrap()
}

fn code(p: &Program) -> Code {
    analyze(p).unwrap_err().code
}

#[test]
fn text_round_trips() {
    let p = program("output \"g\" = %3\noutput \"s\" = %2\n");
    let text = p.to_string();
    assert_eq!(parse(&text).unwrap(), p);
    assert_eq!(parse(&text).unwrap().to_string(), text, "canonical");
    assert!(text.contains("purpose \"disease-training\""), "{text}");
    assert!(text.contains("derive %3 gradient aggregate_only"), "{text}");
}

#[test]
fn the_training_scenario() {
    let p = program("output \"g\" = %3\noutput \"s\" = %2\n");
    let r = analyze(&p).unwrap().unwrap();
    let node = |l: &str| r.nodes.iter().find(|n| n.label == l).unwrap();
    // Declared assets.
    assert_eq!(node("patients").policy.release, Release::Never);
    assert_eq!(node("weights").policy.kind, AssetKind::Model);
    // The gradient: derived from both, owned by both, aggregate only, to
    // the coordinator (the only recipient both sources allow).
    let g = &node("derived:%3").policy;
    assert_eq!(g.kind, AssetKind::Gradient);
    assert_eq!(g.release, Release::AggregateOnly);
    assert_eq!(g.sources, ["patients".into(), "weights".into()].into());
    assert_eq!(
        g.owners,
        [
            PartyId::new("hospital-a").unwrap(),
            PartyId::new("modelco").unwrap()
        ]
        .into()
    );
    assert_eq!(
        g.audience,
        Some([PartyId::new("coordinator").unwrap()].into())
    );
    // The score: never releasable, to nobody.
    let s = &node("output:s").policy;
    assert_eq!(s.release, Release::Never);
    assert_eq!(s.audience, Some(Default::default()));
    // Graph and warning.
    assert!(r
        .flows
        .iter()
        .any(|f| f.from == "patients" && f.to == "derived:%3"));
    assert!(r
        .flows
        .iter()
        .any(|f| f.from == "weights" && f.to == "derived:%3"));
    assert!(r
        .flows
        .iter()
        .any(|f| f.from == "derived:%3" && f.to == "output:g"));
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("aggregation boundary")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn neither_party_sees_the_other() {
    for party in ["hospital-a", "modelco", "coordinator"] {
        let p = program(&format!("output \"s\" = %2 to \"{party}\"\n"));
        assert_eq!(code(&p), Code::UnauthorizedParty, "{party}");
    }
    // The raw patient data is not revealed to its own owner either
    // (release never).
    let p = program("output \"x\" = %3 to \"hospital-a\"\n");
    assert_eq!(code(&p), Code::AggregationRequired);
}

#[test]
fn illegal_flows_are_compile_errors() {
    // Public output of a confidential value.
    assert_eq!(
        code(&program("output \"s\" = %2 public\n")),
        Code::PublicRelease
    );
    // The gradient sent straight to the coordinator (no aggregation).
    assert_eq!(
        code(&program("output \"g\" = %3 to \"coordinator\"\n")),
        Code::AggregationRequired
    );
    // Purpose violation.
    let p = parse(&training(
        "output \"g\" = %3\n",
        "advertising",
        "derive %3 gradient aggregate_only\n",
    ))
    .unwrap();
    assert_eq!(code(&p), Code::PurposeViolation);
    // A derivation the sources do not permit.
    let p = parse(&training(
        "output \"g\" = %3\n",
        "disease-training",
        "derive %3 embedding aggregate_only\n",
    ))
    .unwrap();
    assert_eq!(code(&p), Code::Declassification);
    let p = parse(&training(
        "output \"g\" = %3\n",
        "disease-training",
        "derive %3 gradient public\n",
    ))
    .unwrap();
    assert_eq!(code(&p), Code::Declassification);
    // Restricting is always allowed.
    let p = parse(&training(
        "output \"g\" = %3\n",
        "disease-training",
        "derive %3 checkpoint never\n",
    ))
    .unwrap();
    assert!(analyze(&p).is_ok());
}

#[test]
fn declaration_errors() {
    let bad = |text: &str| parse(text).err().map(|e| e.code);
    let base = training("output \"g\" = %3\n", "disease-training", "");
    assert_eq!(
        bad(&base.replace("owners [\"hospital-a\"]", "owners [\"nobody\"]")),
        Some(Code::PolicyDeclaration)
    );
    assert_eq!(
        bad(&base.replace("asset \"patients\" : secret", "asset \"missing\" : secret")),
        Some(Code::PolicyDeclaration)
    );
    // An unbound secret input.
    let p = parse(&base.replace(" asset \"weights\"", "")).unwrap();
    assert_eq!(code(&p), Code::PolicyDeclaration);
}

/// The join is at least as restrictive as each side, commutative and
/// idempotent; public data is its identity.
#[test]
fn join_is_a_lattice_meet() {
    let p = program("output \"g\" = %3\n");
    let r = analyze(&p).unwrap().unwrap();
    let a = r
        .nodes
        .iter()
        .find(|n| n.label == "patients")
        .unwrap()
        .policy
        .clone();
    let b = r
        .nodes
        .iter()
        .find(|n| n.label == "weights")
        .unwrap()
        .policy
        .clone();
    let ab = a.join(&b);
    assert_eq!(ab, b.join(&a));
    assert_eq!(a.join(&a).release, a.release);
    assert_eq!(a.join(&Policy::public()).audience, a.audience);
    assert!(ab.release <= a.release && ab.release <= b.release);
    assert!(ab.owners.is_superset(&a.owners) && ab.owners.is_superset(&b.owners));
    assert_eq!(
        ab.derive.as_ref().unwrap()[&AssetKind::Gradient].to,
        [PartyId::new("coordinator").unwrap()].into()
    );
    assert_eq!(OutputRelease::default(), OutputRelease::Sealed);
}

/// A label cannot borrow another kind's permission: raw inputs cannot be
/// weakened, and a kind, once assigned, is fixed.
#[test]
fn kinds_cannot_be_laundered() {
    // The owner consents to publishing model updates, not the raw data.
    let single = |body: &str| {
        parse(&format!(
            r#"encompute 0.1
program p precision 0.001 purpose "t"
party "a" "A"
asset "data" dataset owners ["a"] readers ["a"] purposes ["t"] release never derive [model_update public to []]
%0 = input "x" [-1.0, 1.0] asset "data" : secret vector<4>
{body}"#
        ))
        .unwrap()
    };
    // The raw input relabelled and published.
    let p = single("derive %0 model_update public\noutput \"u\" = %0 public\n");
    assert_eq!(code(&p), Code::Declassification);
    // A computed value is fine.
    let p = single(
        "%1 = mul %0, %0 : secret vector<4>\nderive %1 model_update public\noutput \"u\" = %1 public\n",
    );
    assert!(analyze(&p).is_ok(), "{:?}", analyze(&p).err());
    // A value that already has a kind (the input's `dataset`) cannot be
    // relabelled, even as a restriction.
    let p = parse(&training(
        "output \"g\" = %0\n",
        "disease-training",
        "derive %0 gradient never\n",
    ))
    .unwrap();
    assert_eq!(code(&p), Code::Declassification);
}

/// A public derivation cannot also name recipients, and declared strings
/// cannot carry quotes or control characters.
#[test]
fn contradictory_or_unsafe_declarations() {
    let base = training("output \"g\" = %3\n", "disease-training", "");
    let bad = |text: &str| parse(text).err().map(|e| e.code);
    assert_eq!(
        bad(&base.replace(
            "derive [gradient aggregate_only to [\"coordinator\", \"modelco\"]]",
            "derive [gradient public to [\"coordinator\"]]"
        )),
        Some(Code::PolicyDeclaration)
    );
    let mut b = Builder::new("p", 0.01).unwrap();
    assert_eq!(
        b.party("a", "Evil\u{7}").unwrap_err().code,
        Code::PolicyDeclaration
    );
    assert_eq!(
        b.purpose("x\"] release public").unwrap_err().code,
        Code::PolicyDeclaration
    );
}
