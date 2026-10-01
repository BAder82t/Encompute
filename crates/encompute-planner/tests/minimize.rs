//! `Objective::Minimize`: among the candidates that satisfy every hard
//! requirement, the one that releases least; never a trade of a
//! requirement for a narrower release, and never a rewrite of the program.

use encompute_ir::parse;
use encompute_planner::*;

/// `abe` owns the income and may read it; `zed` may read it too and is the
/// only recipient of the answer.
const PROGRAM: &str = "encompute 0.1
program eligibility precision 0.001 purpose \"eligibility\"
party \"abe\" \"Abe\"
party \"zed\" \"Zed\"
asset \"income\" dataset owners [\"abe\"] readers [\"zed\"] purposes [\"eligibility\"] release allowed_parties
%0 = input \"x\" [0.0, 120.0] asset \"income\" : secret u8
%1 = const [18.0] : public u8
%2 = ge %0, %1 : secret bool
output \"out\" = %2 to \"zed\"
";

fn tdx() -> TeeOffer {
    TeeOffer {
        tee: "intel-tdx".into(),
        provider: "gcp-confidential-space".into(),
        gpu: false,
        debug_only: false,
        cloud: true,
        region: None,
    }
}

fn context(objective: Objective) -> PlanningContext {
    PlanningContext {
        profile: Profile::Standard,
        catalog: BackendCatalog {
            ckks: true,
            tfhe: false,
            openfhe_exact: true,
            bgv: false,
            verified_execution: false,
        },
        infrastructure: Infrastructure {
            evaluators: vec![],
            tees: vec![tdx()],
            key_broker: true,
            host_cloud: true,
            host_region: None,
        },
        preferences: Preferences {
            objective,
            ..Preferences::default()
        },
        facts: ProgramFacts {
            semantics: "exact".into(),
            fhe_supported: true,
            proof_covered: false,
            operations: 1,
            binfhe_ms: Some(900_000),
            bgv_ms: None,
        },
        training: None,
        custody: Vec::new(),
        placement: None,
    }
}

fn evaluate(p: &ConfidentialExecutionPlan) -> &ExecutionStep {
    p.steps.iter().find(|s| s.id == "evaluate").unwrap()
}

#[test]
fn minimize_does_not_have_a_party_that_is_not_a_recipient_run_it() {
    let program = parse(PROGRAM).unwrap();
    // Both parties may run it at no cost, and latency does not tell them
    // apart: it takes the first, abe, who would learn the plaintext
    // although the answer is not his.
    let fast = plan_or_fail(&program, &context(Objective::Latency)).unwrap();
    assert_eq!(evaluate(&fast).placement, Placement::Party("abe".into()));
    // Minimize runs it where nobody beyond the recipient learns anything.
    let least = plan_or_fail(&program, &context(Objective::Minimize)).unwrap();
    assert_eq!(evaluate(&least).placement, Placement::Party("zed".into()));
    verify_plan(&program, &least).unwrap();
    // The same requirements either way.
    assert_eq!(least.requirements, fast.requirements);
}

#[test]
fn minimize_never_picks_the_tee_over_encrypted_evaluation() {
    let program = parse(PROGRAM).unwrap();
    // Encrypted evaluation (nobody learns anything but the recipient) and
    // the recipient's own premises tie; a TEE, whose workload sees the
    // plaintext, never wins, however fast.
    let ctx = context(Objective::Minimize);
    let p = plan_or_fail(&program, &ctx).unwrap();
    assert!(
        !matches!(evaluate(&p).placement, Placement::Tee(_)),
        "{:?}",
        evaluate(&p)
    );
    let candidates = plan(&program, &ctx).unwrap().candidates;
    let tee = candidates
        .iter()
        .find(|c| matches!(c.placement, Placement::Tee(_)))
        .expect("the TEE was considered");
    assert!(!tee.selected);
}

#[test]
fn minimize_never_trades_a_requirement_for_a_narrower_release() {
    let program = parse(PROGRAM).unwrap();
    // Nothing may leave the premises: the cloud host and the cloud TEE are
    // refused outright, so the answer is computed at a party. Minimize
    // never reaches for a placement the requirements forbid.
    let mut ctx = context(Objective::Minimize);
    ctx.preferences.local_only = true;
    let p = plan_or_fail(&program, &ctx).unwrap();
    assert!(matches!(evaluate(&p).placement, Placement::Party(_)));
    verify_plan(&program, &p).unwrap();
}

#[test]
fn minimize_is_a_distinct_objective_with_its_own_id() {
    let program = parse(PROGRAM).unwrap();
    let a = plan_or_fail(&program, &context(Objective::Minimize)).unwrap();
    let b = plan_or_fail(&program, &context(Objective::Latency)).unwrap();
    assert_ne!(a.id().unwrap(), b.id().unwrap());
    let text = String::from_utf8(a.to_bytes().unwrap()).unwrap();
    assert!(text.contains("\"objective\":\"minimize\""), "{text}");
}
