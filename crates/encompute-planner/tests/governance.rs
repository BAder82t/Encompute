//! A governed plan binds its GovernanceId into the PlanId; standard plans
//! do not serialize the field, so their PlanIds are unchanged.

use encompute_ir::parse;
use encompute_planner::*;

const PROGRAM: &str = "encompute 0.1
program eligibility precision 0.001
%0 = input \"age\" [0.0, 120.0] : secret u8
%1 = const [18.0] : public u8
%2 = ge %0, %1 : secret bool
output \"x\" = %2
";

fn context() -> PlanningContext {
    PlanningContext {
        profile: Profile::Standard,
        catalog: BackendCatalog {
            ckks: true,
            tfhe: true,
            openfhe_exact: true,
            bgv: true,
            verified_execution: false,
        },
        infrastructure: Infrastructure {
            evaluators: vec![],
            tees: vec![],
            key_broker: true,
            host_cloud: true,
            host_region: Some("eu".into()),
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
        placement: None,
    }
}

#[test]
fn the_plan_id_binds_the_governance_id() {
    let program = parse(PROGRAM).unwrap();
    let plan = plan_or_fail(&program, &context()).unwrap();
    assert_eq!(plan.governance_id, None);
    let text = String::from_utf8(plan.to_bytes().unwrap()).unwrap();
    assert!(
        !text.contains("governance_id"),
        "standard plans are unchanged"
    );

    let g1 = plan.clone().governed(&"1".repeat(64));
    let g2 = plan.clone().governed(&"2".repeat(64));
    assert_ne!(g1.id().unwrap(), plan.id().unwrap());
    assert_ne!(g1.id().unwrap(), g2.id().unwrap());
    // Still a valid plan of the program, and it round-trips.
    verify_plan(&program, &g1).unwrap();
    let back = ConfidentialExecutionPlan::from_bytes(&g1.to_bytes().unwrap()).unwrap();
    assert_eq!(back.id().unwrap(), g1.id().unwrap());
}

const SOURCED: &str = "encompute 0.1
program adult precision 0.001 purpose \"eligibility\"
party \"tax-agency\" \"Tax\"
party \"benefits-agency\" \"Benefits\"
asset \"income\" dataset owners [\"tax-agency\"] readers [\"tax-agency\"] purposes [\"eligibility\"] release allowed_parties
asset \"claims\" dataset owners [\"benefits-agency\"] readers [\"benefits-agency\", \"tax-agency\"] purposes [\"eligibility\"] release allowed_parties
%0 = input \"age\" [0.0, 120.0] asset \"income\" : secret u8
%1 = input \"min\" [0.0, 120.0] asset \"claims\" : secret u8
%2 = ge %0, %1 : secret bool
output \"out\" = %2 to \"tax-agency\"
";

fn custody(asset: &str, organization: &str, broker: &str) -> SourceCustody {
    SourceCustody {
        asset: asset.into(),
        organization: organization.into(),
        broker: broker.into(),
    }
}

/// Sovereign custody: a KeyCustody requirement per source, bound into the
/// PlanId (through the context and the requirements), re-derived by the
/// validator; a plan without custody is unchanged.
#[test]
fn key_custody_changes_plan_id() {
    let program = parse(SOURCED).unwrap();
    let standard = plan_or_fail(&program, &context()).unwrap();
    let text = String::from_utf8(standard.to_bytes().unwrap()).unwrap();
    assert!(!text.contains("custody"), "standard plans are unchanged");
    assert!(!standard
        .requirements
        .iter()
        .any(|r| matches!(r, TrustRequirement::KeyCustody { .. })));

    let sovereign = |brokers: [&str; 2]| {
        let mut ctx = context();
        ctx.custody = vec![
            custody("claims", "benefits-agency", brokers[1]),
            custody("income", "tax-agency", brokers[0]),
        ];
        plan_or_fail(&program, &ctx).unwrap()
    };
    let p = sovereign(["tax-broker", "ben-broker"]);
    verify_plan(&program, &p).unwrap();
    let want = TrustRequirement::KeyCustody {
        asset: "income".into(),
        organization: "tax-agency".into(),
        broker: "tax-broker".into(),
    };
    assert!(p.requirements.contains(&want), "{:?}", p.requirements);
    assert!(p.satisfaction.iter().any(|s| s.requirement == want));
    assert_eq!(
        p.requirements
            .iter()
            .filter(|r| matches!(r, TrustRequirement::KeyCustody { .. }))
            .count(),
        2
    );
    assert_ne!(p.id().unwrap(), standard.id().unwrap());
    // Another broker for one source is another plan.
    let q = sovereign(["tax-broker-2", "ben-broker"]);
    assert_ne!(p.id().unwrap(), q.id().unwrap());
    // Round-trips, and still verifies.
    let back = ConfidentialExecutionPlan::from_bytes(&p.to_bytes().unwrap()).unwrap();
    assert_eq!(back.id().unwrap(), p.id().unwrap());

    // A requirement dropped, or custody the program does not imply, is
    // refused by the validator.
    let mut dropped = p.clone();
    dropped.requirements.retain(|r| r != &want);
    assert!(verify_plan(&program, &dropped).is_err());
    let mut swapped = p.clone();
    swapped.context.custody[1].broker = "other-broker".into();
    assert!(verify_plan(&program, &swapped).is_err());
    let mut ctx = context();
    ctx.custody = vec![custody("elsewhere", "tax-agency", "tax-broker")];
    let e = verify_plan(&program, &plan_or_fail(&program, &ctx).unwrap()).unwrap_err();
    assert!(e.message.contains("does not read"), "{e}");
    let mut ctx = context();
    ctx.custody = vec![
        custody("income", "tax-agency", "tax-broker"),
        custody("income", "tax-agency", "tax-broker-2"),
    ];
    let e = verify_plan(&program, &plan_or_fail(&program, &ctx).unwrap()).unwrap_err();
    assert!(e.message.contains("more than once"), "{e}");
}
