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
    // Without OpenFHE exact, a production catalog never falls back to TFHE-rs.
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
