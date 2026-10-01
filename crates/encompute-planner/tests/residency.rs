//! INV-234: operator separation. The evaluator holds no decryption key and
//! its operator differs from every source owner and decryptor; a SecAgg
//! coordinator is not a contributor; plan validation refuses otherwise.

use std::collections::BTreeSet;

use encompute_ir::{parse, Code};
use encompute_planner::placement::admission;
use encompute_planner::*;

const PROGRAM: &str = "encompute 0.1
program eligibility precision 0.001
%0 = input \"age\" [0.0, 120.0] : secret u8
%1 = const [18.0] : public u8
%2 = ge %0, %1 : secret bool
output \"x\" = %2
";

fn offer(id: &str, operator: &str) -> EvaluatorOffer {
    EvaluatorOffer {
        id: id.into(),
        operator: operator.into(),
        backends: vec!["openfhe-exact".into()],
        profiles: vec![],
        location: Some(Location::resolve("onprem", "de", None).unwrap()),
        evidence: LocationEvidence::OperatorDeclared,
        evidence_digest: None,
        endpoint_digest: None,
    }
}

fn context(offers: Vec<EvaluatorOffer>, roles: Roles) -> PlanningContext {
    PlanningContext {
        profile: Profile::Standard,
        catalog: BackendCatalog {
            ckks: true,
            tfhe: false,
            openfhe_exact: true,
            bgv: true,
            verified_execution: false,
        },
        infrastructure: Infrastructure {
            evaluators: offers,
            tees: vec![],
            key_broker: true,
            host_cloud: true,
            host_region: None,
        },
        preferences: Preferences::default(),
        facts: ProgramFacts {
            semantics: "exact".into(),
            fhe_supported: true,
            proof_covered: false,
            operations: 1,
            binfhe_ms: None,
            bgv_ms: None,
        },
        training: None,
        custody: Vec::new(),
        placement: Some(PlacementContext {
            constraints: vec![],
            locations_digest: locations::digest(),
            production: false,
            roles,
        }),
    }
}

fn roles(owners: &[&str], decryptors: &[&str]) -> Roles {
    Roles {
        source_owners: owners.iter().map(|s| s.to_string()).collect(),
        decryptors: decryptors.iter().map(|s| s.to_string()).collect(),
        coordinator: None,
        // The project's members: every operator these tests use but the
        // platform takes part (the exception is tested in placement.rs).
        participants: ["tax", "benefits", "registry", "reader", "opco", "other"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

#[test]
fn a_separate_operator_is_selected() {
    // The tax agency and the benefits agency each run an evaluator; a third
    // organization and the platform run the others. Only the evaluators
    // run by neither a source owner nor a decryptor are admitted.
    let ctx = context(
        vec![
            offer("ev-tax", "tax"),
            offer("ev-benefits", "benefits"),
            offer("ev-registry", "registry"),
            offer("ev-platform", "platform"),
        ],
        roles(&["tax", "benefits"], &["registry-reader"]),
    );
    let a = admission(&ctx, None, &[], &BTreeSet::new());
    let ids: Vec<&str> = a.admitted.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids, ["ev-platform", "ev-registry"]);
    let program = parse(PROGRAM).unwrap();
    let plan = plan_or_fail(&program, &ctx).unwrap();
    verify_plan(&program, &plan).unwrap();
    assert_eq!(plan.placement.as_ref().unwrap().admissible.len(), 2);
}

#[test]
fn a_data_owner_operated_evaluator_is_refused() {
    // The only evaluator belongs to a source owner: no plan.
    let ctx = context(
        vec![offer("ev-tax", "tax")],
        roles(&["tax", "benefits"], &[]),
    );
    let program = parse(PROGRAM).unwrap();
    let e = plan_or_fail(&program, &ctx).unwrap_err();
    assert_eq!(e.code, Code::PlanningFailed);
    assert!(e.message.contains("operator separation"), "{}", e.message);
    assert!(e.message.contains("owns a source"), "{}", e.message);
}

#[test]
fn an_evaluator_operated_by_a_decryptor_is_refused() {
    let ctx = context(
        vec![offer("ev-reader", "reader")],
        roles(&["tax"], &["reader"]),
    );
    let e = plan_or_fail(&parse(PROGRAM).unwrap(), &ctx).unwrap_err();
    assert!(e.message.contains("decryption key"), "{}", e.message);
    // The decryptors named when the job is bound refuse it too, though the
    // plan did not know them.
    let ctx = context(vec![offer("ev-reader", "reader")], roles(&["tax"], &[]));
    let a = admission(&ctx, None, &[], &BTreeSet::new());
    assert_eq!(a.admitted.len(), 1);
    let a = admission(&ctx, None, &[], &["reader".to_owned()].into());
    assert!(a.admitted.is_empty());
}

#[test]
fn the_validator_refuses_a_plan_that_admits_a_key_holders_evaluator() {
    let program = parse(PROGRAM).unwrap();
    let ctx = context(vec![offer("ev-platform", "platform")], roles(&["tax"], &[]));
    let good = plan_or_fail(&program, &ctx).unwrap();
    verify_plan(&program, &good).unwrap();
    // A plan that lists a source owner's evaluator as admissible, with the
    // roles and the offers the same: the validator recomputes.
    let mut bad = good.clone();
    bad.context
        .infrastructure
        .evaluators
        .push(offer("ev-tax", "tax"));
    bad.placement
        .as_mut()
        .unwrap()
        .admissible
        .push(AdmittedEvaluator {
            id: "ev-tax".into(),
            operator: "tax".into(),
            location: Some(Location::resolve("onprem", "de", None).unwrap()),
            evidence: LocationEvidence::OperatorDeclared,
            evidence_digest: None,
            endpoint_digest: None,
        });
    bad.placement.as_mut().unwrap().admissible.sort();
    let e = verify_plan(&program, &bad).unwrap_err();
    assert_eq!(e.code, Code::PlanInvalid);
    assert!(e.message.contains("admissible evaluators"), "{}", e.message);
}

#[test]
fn dropping_a_source_owner_from_the_roles_does_not_hide_its_evaluator() {
    // The tax agency's source is in the plan's custody, so its evaluator
    // cannot be admitted by leaving the agency out of the roles.
    let program = parse(PROGRAM).unwrap();
    let mut ctx = context(vec![offer("ev-platform", "platform")], roles(&["tax"], &[]));
    ctx.custody = vec![SourceCustody {
        asset: "input:age".into(),
        organization: "tax".into(),
        broker: "tax-broker".into(),
    }];
    // (`input:age` is not a custodied asset of this program: the validator
    // refuses that on its own; the point is the roles check below.)
    let mut bad = ctx.clone();
    bad.placement.as_mut().unwrap().roles = Roles::default();
    bad.infrastructure.evaluators.push(offer("ev-tax", "tax"));
    let planned = plan_or_fail(&program, &bad);
    // The planner, given the doctored roles, plans...
    let plan = planned.unwrap();
    // ...and the validator refuses the plan for the omitted owner.
    let e = verify_plan(&program, &plan).unwrap_err();
    assert!(
        e.message.contains("missing from the plan's source owners"),
        "{}",
        e.message
    );
}

fn fedavg() -> String {
    let mut s = String::from(
        "encompute 0.1\nprogram fedavg precision 0.001 purpose \"training\"\n\
         party \"modelco\" \"ModelCo\"\n",
    );
    for x in ["a", "b", "c"] {
        s.push_str(&format!("party \"hospital-{x}\" \"Hospital {x}\"\n"));
        s.push_str(&format!(
            "asset \"gradient-{x}\" gradient owners [\"hospital-{x}\"] readers [\"modelco\"] \
             purposes [\"training\"] release aggregate_only\n"
        ));
    }
    for (i, x) in ["a", "b", "c"].iter().enumerate() {
        s.push_str(&format!(
            "%{i} = input \"g{x}\" [-1.0, 1.0] asset \"gradient-{x}\" : secret vector<8>\n"
        ));
    }
    s.push_str(
        "%3 = add %0, %1 : secret vector<8>\n%4 = add %3, %2 : secret vector<8>\n\
         output \"update\" = %4 to \"modelco\"\n\
         aggregate \"update\" sum minimum 3 colluding 1 clip [-1.0, 1.0] scale 4096 modulus 40\n",
    );
    s
}

#[test]
fn a_coordinator_is_not_a_contributor() {
    let program = parse(&fedavg()).unwrap();
    let mut r = roles(&["hospital-a", "hospital-b", "hospital-c"], &["modelco"]);
    r.coordinator = Some("hospital-a".into());
    let mut ctx = context(vec![], r.clone());
    ctx.facts.semantics = "approximate".into();
    let e = plan_or_fail(&program, &ctx).unwrap_err();
    assert_eq!(e.code, Code::PlanningFailed);
    assert!(e.message.contains("coordinator"), "{}", e.message);
    // A coordinator that contributes nothing is fine.
    r.coordinator = Some("opco".into());
    let mut ctx = context(vec![], r);
    ctx.facts.semantics = "approximate".into();
    let plan = plan_or_fail(&program, &ctx).unwrap();
    verify_plan(&program, &plan).unwrap();
    // And a plan that smuggles the conflicting coordinator in afterwards
    // is refused by the validator.
    let mut bad = plan.clone();
    bad.context.placement.as_mut().unwrap().roles.coordinator = Some("hospital-b".into());
    let e = verify_plan(&program, &bad).unwrap_err();
    assert!(e.message.contains("coordinator"), "{}", e.message);
}

#[test]
fn the_platform_may_operate_when_nobody_else_does() {
    let ctx = context(
        vec![offer("ev", "platform")],
        roles(&["tax", "benefits"], &["tax"]),
    );
    assert_eq!(
        admission(&ctx, None, &[], &BTreeSet::new()).admitted.len(),
        1
    );
}
