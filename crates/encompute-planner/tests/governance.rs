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
