//! The planner on known workloads (golden plans), its refusals, and the
//! validator's independence: a plan with any required mechanism removed,
//! or any requirement weakened, is invalid.

use encompute_ir::{parse, Code, Program};
use encompute_planner::*;

const ELIGIBILITY: &str = "encompute 0.1
program eligibility precision 0.001 verification required
%0 = input \"age\" [0.0, 120.0] : secret u8
%1 = const [18.0] : public u8
%2 = add %0, %1 : secret u8
output \"x\" = %2
";

fn fedavg(dp: bool, extra: &str, training: bool) -> String {
    let mut s = String::from(
        "encompute 0.1\nprogram fedavg precision 0.001 purpose \"training\"\n\
         party \"modelco\" \"ModelCo\"\n",
    );
    for x in ["a", "b", "c"] {
        s.push_str(&format!("party \"hospital-{x}\" \"Hospital {x}\"\n"));
    }
    if training {
        s.push_str(
            "asset \"base-model\" model owners [\"modelco\"] readers [] purposes [\"training\"] release never\n",
        );
        for x in ["a", "b", "c"] {
            s.push_str(&format!(
                "asset \"patients-{x}\" dataset owners [\"hospital-{x}\"] readers [] purposes \
                 [\"training\"] release never\n"
            ));
        }
    }
    let privacy = if dp {
        " privacy unit \"patient\" epsilon 3.0 delta 1e-6"
    } else {
        ""
    };
    for x in ["a", "b", "c"] {
        s.push_str(&format!(
            "asset \"gradient-{x}\" gradient owners [\"hospital-{x}\"] readers [\"modelco\"] \
             purposes [\"training\"] release aggregate_only{privacy}\n"
        ));
    }
    for (i, x) in ["a", "b", "c"].iter().enumerate() {
        s.push_str(&format!(
            "%{i} = input \"g{x}\" [-1.0, 1.0] asset \"gradient-{x}\" : secret vector<8>\n"
        ));
    }
    s.push_str(&format!(
        "%3 = add %0, %1 : secret vector<8>\n%4 = add %3, %2 : secret vector<8>\n\
         output \"update\" = %4 to \"modelco\"\n\
         aggregate \"update\" sum minimum 3 colluding 1 clip [-1.0, 1.0] scale 4096 \
         modulus 40{}{extra}\n",
        if dp {
            " dp discrete_gaussian clip_norm 1.0 noise_multiplier 6.0"
        } else {
            ""
        }
    ));
    s
}

fn prog(t: &str) -> Program {
    parse(t).unwrap_or_else(|e| panic!("{e}\n{t}"))
}

fn tdx() -> TeeOffer {
    TeeOffer {
        tee: "intel-tdx".into(),
        provider: "gcp-confidential-space".into(),
        gpu: true,
        debug_only: false,
        cloud: true,
        region: Some("eu".into()),
    }
}

fn ctx(semantics: &str, profile: Profile) -> PlanningContext {
    PlanningContext {
        profile,
        catalog: BackendCatalog {
            ckks: true,
            tfhe: true,
            openfhe_exact: false,
            bgv: true,
            verified_execution: true,
        },
        infrastructure: Infrastructure {
            tees: vec![],
            key_broker: true,
            host_cloud: true,
            host_region: Some("eu".into()),
        },
        preferences: Preferences::default(),
        facts: ProgramFacts {
            semantics: semantics.into(),
            fhe_supported: true,
            proof_covered: true,
            operations: 3,
            binfhe_ms: None,
            bgv_ms: None,
        },
        training: None,
    }
}

fn step<'a>(p: &'a ConfidentialExecutionPlan, id: &str) -> &'a ExecutionStep {
    p.steps.iter().find(|s| s.id == id).unwrap()
}

fn planned(program: &Program, c: &PlanningContext) -> ConfidentialExecutionPlan {
    let p = plan_or_fail(program, c).unwrap();
    verify_plan(program, &p).unwrap();
    p
}

#[test]
fn private_exact_eligibility_is_verified_fhe() {
    let p = prog(ELIGIBILITY);
    let plan = planned(&p, &ctx("exact", Profile::Standard));
    assert_eq!(
        step(&plan, "evaluate").mechanisms,
        vec![
            Mechanism::Fhe {
                scheme: Scheme::Bgv,
                backend: "openfhe".into()
            },
            Mechanism::VerifiedExecution
        ]
    );
    assert!(plan
        .evidence_required
        .contains(&EvidenceKind::ExecutionProof));
    // Proofs unavailable: no weaker plan.
    let mut c = ctx("exact", Profile::Standard);
    c.catalog.verified_execution = false;
    let e = plan_or_fail(&p, &c).unwrap_err();
    assert_eq!(e.code, Code::PlanningFailed);
    assert!(
        e.message.contains("verified execution is not available"),
        "{}",
        e.message
    );
    // Partial proof coverage: refused too.
    let mut c = ctx("exact", Profile::Standard);
    c.facts.proof_covered = false;
    assert!(plan_or_fail(&p, &c).is_err());
}

#[test]
fn gradients_need_secure_aggregation_and_budgets_need_dp() {
    let p = prog(&fedavg(false, "", false));
    let plan = planned(&p, &ctx("approximate", Profile::Standard));
    assert_eq!(
        step(&plan, "aggregate:update").mechanisms,
        vec![Mechanism::SecureAggregation {
            threshold: 3,
            colluding: 1
        }]
    );
    let p = prog(&fedavg(true, "", false));
    let plan = planned(&p, &ctx("approximate", Profile::Standard));
    let m = &step(&plan, "aggregate:update").mechanisms;
    assert!(m.contains(&Mechanism::DifferentialPrivacy {
        noise_multiplier: "6.0".into(),
        clip_norm: "1.0".into(),
        sampling_rate: None,
    }));
    assert!(plan
        .evidence_required
        .contains(&EvidenceKind::PrivacyReceipt));
    // Every decision explains itself.
    let why = plan
        .satisfaction
        .iter()
        .find(|s| {
            matches!(&s.requirement, TrustRequirement::AggregateOnly { asset, .. } if asset == "gradient-a")
        })
        .unwrap();
    assert!(why.reason.contains("threshold 3"), "{}", why.reason);
    assert!(why.evidence.contains(&EvidenceKind::AggregationReceipt));
}

#[test]
fn strong_profile_attests_the_coordinator_or_fails() {
    let p = prog(&fedavg(true, "", false));
    let e = plan_or_fail(&p, &ctx("approximate", Profile::Strong)).unwrap_err();
    assert_eq!(e.code, Code::PlanningFailed);
    let mut c = ctx("approximate", Profile::Strong);
    c.infrastructure.tees.push(tdx());
    let plan = planned(&p, &c);
    assert!(step(&plan, "aggregate:update")
        .mechanisms
        .contains(&Mechanism::Attestation {
            provider: "gcp-confidential-space".into()
        }));
}

#[test]
fn private_model_training_needs_attested_confidential_compute() {
    let p = prog(&fedavg(true, "", true));
    let mut c = ctx("approximate", Profile::Standard);
    c.training = Some(TrainingDeclaration {
        model: "base-model".into(),
        data: vec![
            "patients-a".into(),
            "patients-b".into(),
            "patients-c".into(),
        ],
        verified: false,
        privacy_unit: None,
        per_example_clipping: false,
        framework: None,
    });
    // Normal hardware only: the model cannot meet the data anywhere.
    let e = plan_or_fail(&p, &c).unwrap_err();
    assert_eq!(e.code, Code::PlanningFailed);
    assert!(
        e.message.contains("not supported under FHE"),
        "{}",
        e.message
    );
    c.infrastructure.tees.push(tdx());
    let plan = planned(&p, &c);
    let t = step(&plan, "train:patients-a");
    assert!(matches!(t.placement, Placement::Tee(_)));
    assert!(t.mechanisms.contains(&Mechanism::AttestedKeyRelease));
    // Debug-only or unknown-provider TEEs do not count.
    for bad in [
        TeeOffer {
            debug_only: true,
            ..tdx()
        },
        TeeOffer {
            provider: "acme-attest".into(),
            ..tdx()
        },
    ] {
        c.infrastructure.tees = vec![bad];
        assert!(plan_or_fail(&p, &c).is_err());
    }
    // Cloud forbidden and only cloud TEEs available.
    c.infrastructure.tees = vec![tdx()];
    c.preferences.local_only = true;
    assert!(plan_or_fail(&p, &c).is_err());
}

#[test]
fn a_model_the_data_owners_may_read_trains_locally() {
    let t = fedavg(true, "", true).replace(
        "asset \"base-model\" model owners [\"modelco\"] readers []",
        "asset \"base-model\" model owners [\"modelco\"] readers [\"hospital-a\", \
         \"hospital-b\", \"hospital-c\"]",
    );
    let p = prog(&t);
    let mut c = ctx("approximate", Profile::Standard);
    c.training = Some(TrainingDeclaration {
        model: "base-model".into(),
        data: vec!["patients-a".into()],
        verified: false,
        privacy_unit: None,
        per_example_clipping: false,
        framework: None,
    });
    let plan = planned(&p, &c);
    assert_eq!(
        step(&plan, "train:patients-a").placement,
        Placement::Party("hospital-a".into())
    );
}

#[test]
fn plans_are_deterministic_and_identified() {
    let p = prog(&fedavg(true, "", false));
    let c = ctx("approximate", Profile::Standard);
    let a = planned(&p, &c);
    let b = planned(&p, &c);
    assert_eq!(a, b);
    assert_eq!(a.id().unwrap(), b.id().unwrap());
    assert!(a.id().unwrap().to_string().starts_with("encplan1:"));
    let back = ConfidentialExecutionPlan::from_bytes(&a.to_bytes().unwrap()).unwrap();
    assert_eq!(back.id().unwrap(), a.id().unwrap());
    // Another context, another ID.
    let mut c2 = c.clone();
    c2.preferences.objective = Objective::Cost;
    assert_ne!(planned(&p, &c2).id().unwrap(), a.id().unwrap());
}

/// Removes one mechanism from one step, keeping the summary consistent (the
/// strongest forgery: nothing but the protection is missing).
fn without(plan: &ConfidentialExecutionPlan, s: usize, m: usize) -> ConfidentialExecutionPlan {
    let mut p = plan.clone();
    p.steps[s].mechanisms.remove(m);
    let mut sel: std::collections::BTreeSet<Mechanism> = p
        .steps
        .iter()
        .flat_map(|s| s.mechanisms.iter().cloned())
        .collect();
    for g in [
        Mechanism::PolicyEnforcement,
        Mechanism::SignedReceipts,
        Mechanism::OwnerAuthorization,
    ] {
        if plan.selected_mechanisms.contains(&g) {
            sel.insert(g);
        }
    }
    p.evidence_required = sel.iter().flat_map(Mechanism::evidence).collect();
    p.selected_mechanisms = sel;
    p
}

#[test]
fn the_validator_refuses_weakened_plans() {
    let p = prog(&fedavg(true, "", true));
    let mut c = ctx("approximate", Profile::Strong);
    c.infrastructure.tees.push(tdx());
    c.training = Some(TrainingDeclaration {
        model: "base-model".into(),
        data: vec!["patients-a".into()],
        verified: false,
        privacy_unit: None,
        per_example_clipping: false,
        framework: None,
    });
    let plan = planned(&p, &c);
    for (s, st) in plan.steps.iter().enumerate() {
        for m in 0..st.mechanisms.len() {
            assert_eq!(
                verify_plan(&p, &without(&plan, s, m)).unwrap_err().code,
                Code::PlanInvalid,
                "removing {:?} from {}",
                st.mechanisms[m],
                st.id
            );
        }
    }
    // A dropped requirement.
    let mut w = plan.clone();
    w.requirements
        .retain(|r| !matches!(r, TrustRequirement::PrivacyBudget { .. }));
    assert!(verify_plan(&p, &w).is_err());
    // A lower threshold.
    let mut w = plan.clone();
    for st in w.steps.iter_mut() {
        for m in st.mechanisms.iter_mut() {
            if let Mechanism::SecureAggregation { threshold, .. } = m {
                *threshold = 2;
            }
        }
    }
    assert!(verify_plan(&p, &w).is_err());
    // An unprotected host placement.
    let mut w = plan.clone();
    w.steps[0].placement = Placement::UntrustedHost;
    assert!(verify_plan(&p, &w).is_err());
    // A plan for another program.
    let other = prog(&fedavg(false, "", true));
    assert!(verify_plan(&other, &plan).is_err());
    // A context claiming proofs cover a program they do not.
    let e = prog(ELIGIBILITY);
    let good = planned(&e, &ctx("exact", Profile::Standard));
    let mut w = good.clone();
    w.context.facts.proof_covered = false;
    assert!(verify_plan(&e, &w).is_err());
}

#[test]
fn nothing_to_hide_runs_plainly() {
    let p = prog(
        "encompute 0.1\nprogram open precision 0.001\nparty \"a\" \"A\"\n\
         asset \"x\" dataset owners [\"a\"] readers [] purposes [] release public\n\
         %0 = input \"x\" [0.0, 1.0] asset \"x\" : secret scalar\n\
         output \"y\" = %0 public\n",
    );
    let plan = planned(&p, &ctx("approximate", Profile::Standard));
    assert_eq!(step(&plan, "evaluate").placement, Placement::UntrustedHost);
    assert!(step(&plan, "evaluate").mechanisms.is_empty());
}

/// Verified training: no proof covers training, so each training workload
/// must be attested, visibly; local training at the owner does not do.
#[test]
fn verified_training_requires_attested_workloads() {
    let t = fedavg(true, "", true).replace(
        "asset \"base-model\" model owners [\"modelco\"] readers []",
        "asset \"base-model\" model owners [\"modelco\"] readers [\"hospital-a\"]",
    );
    let p = prog(&t);
    let mut c = ctx("approximate", Profile::Standard);
    c.training = Some(TrainingDeclaration {
        model: "base-model".into(),
        data: vec!["patients-a".into()],
        verified: true,
        privacy_unit: None,
        per_example_clipping: false,
        framework: None,
    });
    assert!(
        plan_or_fail(&p, &c).is_err(),
        "local training is not attested"
    );
    c.infrastructure.tees.push(tdx());
    let plan = planned(&p, &c);
    assert!(plan
        .requirements
        .contains(&TrustRequirement::RequireAttestation {
            step: "train:patients-a".into()
        }));
    assert!(matches!(
        step(&plan, "train:patients-a").placement,
        Placement::Tee(_)
    ));
}

#[test]
fn exact_programs_plan_openfhe_exact_never_tfhe_rs_by_default() {
    let p = prog(&ELIGIBILITY.replace(" verification required", ""));
    let fhe = |plan: &ConfidentialExecutionPlan| {
        step(plan, "evaluate")
            .mechanisms
            .iter()
            .find(|m| matches!(m, Mechanism::Fhe { .. }))
            .cloned()
    };
    let openfhe_exact = Some(Mechanism::Fhe {
        scheme: Scheme::BinFhe,
        backend: "openfhe-exact".into(),
    });
    // Production catalog: OpenFHE exact, no TFHE-rs.
    let mut c = ctx("exact", Profile::Standard);
    c.catalog.tfhe = false;
    c.catalog.openfhe_exact = true;
    assert_eq!(fhe(&planned(&p, &c)), openfhe_exact);
    // A research build offering both still prefers OpenFHE exact.
    c.catalog.tfhe = true;
    assert_eq!(fhe(&planned(&p, &c)), openfhe_exact);
    // Without OpenFHE exact, a production catalog never falls back to TFHE-rs
    // (and unverified BGV needs a calibrated estimate, absent here).
    c.catalog.tfhe = false;
    c.catalog.openfhe_exact = false;
    if let Ok(plan) = plan_or_fail(&p, &c) {
        assert!(
            !matches!(
                fhe(&plan),
                Some(Mechanism::Fhe {
                    scheme: Scheme::Tfhe,
                    ..
                })
            ),
            "{plan:?}"
        );
    }
}

fn fhe_of(plan: &ConfidentialExecutionPlan) -> Vec<Mechanism> {
    step(plan, "evaluate").mechanisms.clone()
}

/// A production catalog with the runtime's calibrated estimates.
fn production(binfhe_ms: Option<u64>, bgv_ms: Option<u64>, covered: bool) -> PlanningContext {
    let mut c = ctx("exact", Profile::Standard);
    c.catalog.tfhe = false;
    c.catalog.openfhe_exact = true;
    c.facts.proof_covered = covered;
    c.facts.binfhe_ms = binfhe_ms;
    c.facts.bgv_ms = bgv_ms;
    c
}

fn bgv() -> Mechanism {
    Mechanism::Fhe {
        scheme: Scheme::Bgv,
        backend: "openfhe".into(),
    }
}

fn binfhe() -> Mechanism {
    Mechanism::Fhe {
        scheme: Scheme::BinFhe,
        backend: "openfhe-exact".into(),
    }
}

#[test]
fn unverified_exact_programs_take_the_cheaper_calibrated_backend() {
    let p = prog(&ELIGIBILITY.replace(" verification required", ""));
    // In the subset and cheaper on BGV: BGV, without proofs.
    let c = production(Some(54_000), Some(8), true);
    let plan = planned(&p, &c);
    assert_eq!(fhe_of(&plan), vec![bgv()]);
    assert_eq!(step(&plan, "evaluate").estimated_ms, 1 + 8);
    assert!(!plan
        .evidence_required
        .contains(&EvidenceKind::ExecutionProof));
    // Both candidates are listed with their costs.
    let all = encompute_planner::plan(&p, &c).unwrap().candidates;
    assert!(all.iter().any(|c| c.mechanisms == vec![binfhe()]
        && c.rejected.is_none()
        && c.estimated_ms == 1 + 54_000
        && !c.selected));
    assert!(all
        .iter()
        .any(|c| c.mechanisms == vec![bgv()] && c.selected));
    // Cheaper on BinFHE: BinFHE.
    let plan = planned(&p, &production(Some(3), Some(9), true));
    assert_eq!(fhe_of(&plan), vec![binfhe()]);
    // A tie goes to BGV, as compile_program's rule does.
    let plan = planned(&p, &production(Some(9), Some(9), true));
    assert_eq!(fhe_of(&plan), vec![bgv()]);
    // Outside the BGV subset: BinFHE whatever the numbers say.
    let plan = planned(&p, &production(Some(54_000), Some(8), false));
    assert_eq!(fhe_of(&plan), vec![binfhe()]);
    // No calibrated estimates (facts from an older runtime): BinFHE.
    let plan = planned(&p, &production(None, None, true));
    assert_eq!(fhe_of(&plan), vec![binfhe()]);
    // BinFHE cannot lower it to gates: BGV.
    let plan = planned(&p, &production(None, Some(8), true));
    assert_eq!(fhe_of(&plan), vec![bgv()]);
}

#[test]
fn correctness_overrides_cost() {
    // Verification required: BGV with proofs even where BinFHE is cheaper,
    // never unverified BGV or BinFHE.
    let p = prog(ELIGIBILITY);
    let plan = planned(&p, &production(Some(1), Some(9), true));
    assert_eq!(fhe_of(&plan), vec![bgv(), Mechanism::VerifiedExecution]);
    let mut c = production(Some(54_000), Some(8), true);
    c.catalog.verified_execution = false;
    assert!(plan_or_fail(&p, &c).is_err(), "no weaker plan");
}

#[test]
fn the_validator_accepts_unverified_bgv_only_in_the_subset() {
    let p = prog(&ELIGIBILITY.replace(" verification required", ""));
    let plan = planned(&p, &production(Some(54_000), Some(8), true));
    // The same plan claiming a program outside the subset is invalid.
    let mut bad = plan.clone();
    bad.context.facts.proof_covered = false;
    let e = verify_plan(&p, &bad).unwrap_err();
    assert!(e.message.contains("FHE (BGV, openfhe)"), "{}", e.message);
    // A verified program's plan without its proofs is invalid.
    let v = prog(ELIGIBILITY);
    let mut plan = planned(&v, &production(Some(54_000), Some(8), true));
    let s = plan.steps.iter_mut().find(|s| s.id == "evaluate").unwrap();
    s.mechanisms.retain(|m| *m != Mechanism::VerifiedExecution);
    let e = verify_plan(&v, &plan).unwrap_err();
    assert!(e.message.contains("RequireCorrectness"), "{}", e.message);
}

/// Review finding TG-3 (ENC-SF-2026-077): a plan carries the context it was made in, and that
/// context is the plan's own claim. The validator recomputes the semantics
/// from the program, and a verifier's floor (its compiler's facts, the
/// backends it accepts, a minimum profile, production) refuses a plan whose
/// self-declared context would weaken it.
#[test]
fn the_validator_checks_the_plans_own_context_against_the_verifiers_floor() {
    let v = prog(ELIGIBILITY);
    let c = production(Some(54_000), Some(8), true);
    let plan = planned(&v, &c);
    assert_eq!(fhe_of(&plan), vec![bgv(), Mechanism::VerifiedExecution]);
    let with = |f: PlanFloor| verify_plan_with(&v, &plan, &f);
    // The facts the verifier's compiler computes: the same pass; a plan
    // claiming proof coverage the compiler does not see is refused.
    with(PlanFloor {
        facts: Some(c.facts.clone()),
        catalog: Some(c.catalog.clone()),
        ..PlanFloor::default()
    })
    .unwrap();
    let mut compiler = c.facts.clone();
    compiler.proof_covered = false;
    let e = with(PlanFloor {
        facts: Some(compiler),
        ..PlanFloor::default()
    })
    .unwrap_err();
    assert_eq!(e.code, Code::PlanInvalid);
    assert!(
        e.message.contains("are not the compiler's"),
        "{}",
        e.message
    );
    // The semantics follow from the program, with or without a floor.
    let mut bad = plan.clone();
    bad.context.facts.semantics = "approximate".into();
    let e = verify_plan(&v, &bad).unwrap_err();
    assert!(
        e.message.contains("but the program is exact"),
        "{}",
        e.message
    );
    // A backend the verifier does not accept.
    let e = with(PlanFloor {
        catalog: Some(BackendCatalog {
            verified_execution: false,
            ..c.catalog.clone()
        }),
        ..PlanFloor::default()
    })
    .unwrap_err();
    assert!(
        e.message.contains("verified execution backend"),
        "{}",
        e.message
    );
    // A minimum profile: a standard plan is weaker than strong.
    let e = with(PlanFloor::production(Profile::Strong)).unwrap_err();
    assert!(
        e.message.contains("weaker than the required strong"),
        "{}",
        e.message
    );
    with(PlanFloor::production(Profile::Standard)).unwrap();
    // Production: no research backend in the plan's catalog.
    let a = prog(&fedavg(true, "", false));
    let research = planned(&a, &ctx("approximate", Profile::Standard));
    assert!(research.context.catalog.tfhe);
    let e = verify_plan_with(&a, &research, &PlanFloor::production(Profile::Standard)).unwrap_err();
    assert!(e.message.contains("TFHE-rs"), "{}", e.message);
}

/// Review finding TG-3 (ENC-SF-2026-077): development (mock) attestation, which a plan may
/// accept for itself, is refused by a production floor.
#[test]
fn a_production_floor_refuses_plans_that_accept_development_attestation() {
    let p = prog(&fedavg(true, "", true));
    let mut c = ctx("approximate", Profile::Standard);
    c.catalog.tfhe = false;
    c.preferences.allow_development = true;
    c.infrastructure.tees = vec![TeeOffer {
        tee: "mock".into(),
        provider: "mock".into(),
        gpu: false,
        debug_only: false,
        cloud: false,
        region: None,
    }];
    c.training = Some(TrainingDeclaration {
        model: "base-model".into(),
        data: vec![
            "patients-a".into(),
            "patients-b".into(),
            "patients-c".into(),
        ],
        verified: false,
        privacy_unit: None,
        per_example_clipping: false,
        framework: None,
    });
    let plan = planned(&p, &c);
    assert!(plan
        .steps
        .iter()
        .any(|s| matches!(&s.placement, Placement::Tee(t) if t.provider == "mock")));
    verify_plan_with(&p, &plan, &PlanFloor::default()).unwrap();
    let e = verify_plan_with(&p, &plan, &PlanFloor::production(Profile::Standard)).unwrap_err();
    assert!(
        e.message.contains("accepts development attestation"),
        "{}",
        e.message
    );
    assert!(
        e.message.contains("is not production attestation"),
        "{}",
        e.message
    );
}

/// Review finding TG-3 (ENC-SF-2026-077): the validator derives a floor of requirements with
/// its own rules, not only with the planner's `derive`.
#[test]
fn the_validator_has_its_own_floor_of_requirements() {
    let p = prog(&fedavg(true, "", false));
    let mut plan = planned(&p, &ctx("approximate", Profile::Standard));
    plan.requirements
        .retain(|r| !matches!(r, TrustRequirement::MinimumParticipants { .. }));
    let e = verify_plan(&p, &plan).unwrap_err();
    assert!(
        e.message
            .contains("requirement missing: MinimumParticipants"),
        "{}",
        e.message
    );
}
