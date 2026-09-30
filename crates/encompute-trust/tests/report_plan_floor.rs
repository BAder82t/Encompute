//! The trust report's plan checks trust neither the context a plan
//! declares about itself nor a receipt's claim of an execution proof
//! (review finding TG-3): the caller's floor, the caller's compiler facts
//! and the caller's proof check decide.

use encompute_ir::{parse, Code, Error, Program};
use encompute_planner::{
    plan_or_fail, BackendCatalog, ConfidentialExecutionPlan, Infrastructure, Mechanism, PlanFloor,
    PlanningContext, Preferences, Profile, ProgramFacts, Scheme,
};
use encompute_trust::{Anchors, ReportOptions, Status, TrustGraph, TrustReport};
use encompute_verification::{
    EvaluatorSigner, ExecutionReceipt, SignedExecutionReceipt, VerificationEvidence,
    VerificationRelation, RECEIPT_VERSION,
};

const ELIGIBILITY: &str = "encompute 0.1
program eligibility precision 0.001 verification required
%0 = input \"age\" [0.0, 120.0] : secret u8
%1 = const [18.0] : public u8
%2 = add %0, %1 : secret u8
output \"x\" = %2
";

fn facts(proof_covered: bool) -> ProgramFacts {
    ProgramFacts {
        semantics: "exact".into(),
        fhe_supported: true,
        proof_covered,
        operations: 3,
        binfhe_ms: Some(54_000),
        bgv_ms: Some(8),
    }
}

fn context(profile: Profile) -> PlanningContext {
    PlanningContext {
        profile,
        catalog: BackendCatalog {
            ckks: true,
            tfhe: false,
            openfhe_exact: true,
            bgv: true,
            verified_execution: true,
        },
        infrastructure: Infrastructure {
            host_cloud: true,
            ..Infrastructure::default()
        },
        preferences: Preferences::default(),
        facts: facts(true),
        training: None,
        custody: Vec::new(),
    }
}

fn hex(c: char) -> String {
    c.to_string().repeat(64)
}

fn signer() -> EvaluatorSigner {
    EvaluatorSigner::from_seed(&[7; 32])
}

/// A signed receipt of the planned BGV execution, claiming an execution
/// proof by digest (the proof itself is not in the bundle).
fn receipt(plan: &ConfidentialExecutionPlan) -> SignedExecutionReceipt {
    let s = signer();
    ExecutionReceipt {
        grant_digest: None,
        version: RECEIPT_VERSION,
        execution_id: "00000000-0000-4000-8000-000000000000".into(),
        spec_id: hex('1'),
        program_id: plan.program_id.clone(),
        plan_id: hex('2'),
        parameter_set_id: hex('3'),
        key_id: hex('4'),
        request_commitment: hex('5'),
        output_commitment: hex('6'),
        scheme: "BGV".into(),
        backend: "openfhe".into(),
        backend_version: "1.5.1".into(),
        transcript_hash: None,
        evaluator_id: s.identity().evaluator_id(),
        evidence: VerificationEvidence::Vfhe {
            relation: VerificationRelation::FheEvaluationV1,
            protocol: "re-execution".into(),
            protocol_version: 1,
            verification_key_id: hex('7'),
            proof_digest: hex('8'),
        },
        attestation: None,
    }
    .sign(&s)
    .unwrap()
}

/// A planned, executed verified program: the graph and the plan.
fn executed(profile: Profile) -> (TrustGraph, Program, ConfidentialExecutionPlan) {
    let program = parse(ELIGIBILITY).unwrap();
    let plan = plan_or_fail(&program, &context(profile)).unwrap();
    assert!(plan.steps[0]
        .mechanisms
        .contains(&Mechanism::VerifiedExecution));
    assert!(plan.steps[0].mechanisms.contains(&Mechanism::Fhe {
        scheme: Scheme::Bgv,
        backend: "openfhe".into()
    }));
    let mut g = TrustGraph::new();
    g.add_program(&program.to_string()).unwrap();
    g.add_plan(plan.clone()).unwrap();
    g.add_execution_receipt(receipt(&plan)).unwrap();
    (g, program, plan)
}

fn anchors() -> Anchors {
    Anchors {
        evaluators: [signer().identity().public_key_hex()].into(),
        ..Anchors::default()
    }
}

fn row(r: &TrustReport, name: &str) -> (Status, Vec<String>) {
    let x = r.rows.iter().find(|x| x.name == name).unwrap();
    (x.status, x.details.clone())
}

fn proof_ok(_: &SignedExecutionReceipt) -> encompute_ir::Result<()> {
    Ok(())
}

fn proof_bad(_: &SignedExecutionReceipt) -> encompute_ir::Result<()> {
    Err(Error::new(Code::Receipt, "the proof does not verify"))
}

/// Review finding TG-3 (ENC-SF-2026-077): a receipt that merely claims an execution proof no
/// longer satisfies a correctness requirement; the proof must be checked.
#[test]
fn a_claimed_execution_proof_is_unchecked_until_the_proof_is_checked() {
    let (g, _, _) = executed(Profile::Standard);
    let r = g
        .report(&ReportOptions {
            anchors: anchors(),
            ..ReportOptions::default()
        })
        .unwrap();
    let (status, details) = row(&r, "Plan");
    assert_eq!(status, Status::Unchecked, "{r}");
    assert!(
        details
            .iter()
            .any(|d| d.contains("claims an execution proof, which was not checked")),
        "{r}"
    );
    assert!(!r.satisfied, "{r}");
    // Checked by the caller: satisfied.
    let r = g
        .report(&ReportOptions {
            anchors: anchors(),
            proof_check: Some(&proof_ok),
            ..ReportOptions::default()
        })
        .unwrap();
    assert_eq!(row(&r, "Plan").0, Status::Satisfied, "{r}");
    assert!(r.satisfied, "{r}");
    // A proof that does not verify fails.
    let r = g
        .report(&ReportOptions {
            anchors: anchors(),
            proof_check: Some(&proof_bad),
            ..ReportOptions::default()
        })
        .unwrap();
    let (status, details) = row(&r, "Plan");
    assert_eq!(status, Status::Failed, "{r}");
    assert!(details.iter().any(|d| d.contains("does not verify")), "{r}");
}

/// Review finding TG-3 (ENC-SF-2026-077): the plan's facts about its program are checked
/// against the caller's compiler, not trusted.
#[test]
fn a_plan_claiming_facts_the_compiler_does_not_produce_fails_the_report() {
    let (g, _, _) = executed(Profile::Standard);
    let honest = |_: &Program| Ok(facts(true));
    let lying = |_: &Program| Ok(facts(false));
    let report = |f: &dyn Fn(&Program) -> encompute_ir::Result<ProgramFacts>| {
        g.report(&ReportOptions {
            anchors: anchors(),
            proof_check: Some(&proof_ok),
            program_facts: Some(f),
            ..ReportOptions::default()
        })
        .unwrap()
    };
    assert_eq!(row(&report(&honest), "Plan").0, Status::Satisfied);
    let r = report(&lying);
    let (status, details) = row(&r, "Plan");
    assert_eq!(status, Status::Failed, "{r}");
    assert!(
        details.iter().any(|d| d.contains("are not the compiler's")),
        "{r}"
    );
    assert!(!r.satisfied);
}

/// Review finding TG-3 (ENC-SF-2026-077): the report applies the caller's floor (a minimum
/// profile, production attestation and backends), not the plan's own
/// profile.
#[test]
fn the_report_applies_the_callers_plan_floor() {
    let (g, _, _) = executed(Profile::Standard);
    let report = |floor: PlanFloor| {
        g.report(&ReportOptions {
            anchors: anchors(),
            proof_check: Some(&proof_ok),
            plan_floor: floor,
            ..ReportOptions::default()
        })
        .unwrap()
    };
    assert!(report(PlanFloor::production(Profile::Standard)).satisfied);
    let r = report(PlanFloor::production(Profile::Maximum));
    let (status, details) = row(&r, "Plan");
    assert_eq!(status, Status::Failed, "{r}");
    assert!(
        details
            .iter()
            .any(|d| d.contains("weaker than the required maximum")),
        "{r}"
    );
    assert!(!r.satisfied);
    // A plan made under the maximum profile meets that floor.
    let (g, _, _) = executed(Profile::Maximum);
    let r = g
        .report(&ReportOptions {
            anchors: anchors(),
            proof_check: Some(&proof_ok),
            plan_floor: PlanFloor::production(Profile::Maximum),
            ..ReportOptions::default()
        })
        .unwrap();
    assert!(r.satisfied, "{r}");
}
