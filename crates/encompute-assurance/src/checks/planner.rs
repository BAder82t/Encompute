//! The planner under generated and adversarial scenarios: every accepted
//! plan satisfies every requirement (by the independent validator), no
//! required mechanism can be removed, requirements are never weakened,
//! impossible scenarios produce no plan, and the plan ID binds every
//! security-relevant field.

use std::collections::BTreeSet;

use encompute_ir::{parse, Program};
use encompute_planner::*;

use crate::{ensure, mutate, CheckResult, Outcome, Scale};

/// Seeds that once failed, replayed on every run.
pub const REGRESSION_SEEDS: &[u64] = &[
    // A party placement accepted without its local-execution mechanism.
    8_916_706_093_011_203_299,
];

/// splitmix64: a reproducible scenario from its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

/// A generated scenario: program, context, and what it declares.
pub struct Scenario {
    pub program: Program,
    pub ctx: PlanningContext,
    pub aggregate_only: Vec<String>,
    pub budgeted: Vec<String>,
    pub verification_required: bool,
}

fn tee_pool() -> Vec<TeeOffer> {
    let base = TeeOffer {
        tee: "intel-tdx".into(),
        provider: "gcp-confidential-space".into(),
        gpu: false,
        debug_only: false,
        cloud: true,
        region: Some("eu".into()),
    };
    vec![
        base.clone(),
        TeeOffer {
            tee: "amd-sev-snp".into(),
            cloud: false,
            region: Some("us".into()),
            ..base.clone()
        },
        TeeOffer {
            debug_only: true,
            ..base.clone()
        },
        TeeOffer {
            tee: "mock".into(),
            provider: "mock".into(),
            cloud: false,
            ..base.clone()
        },
        TeeOffer {
            provider: "acme-attest".into(),
            ..base
        },
    ]
}

pub fn scenario(seed: u64) -> Option<Scenario> {
    let mut r = Rng(seed);
    let mut aggregate_only = vec![];
    let mut budgeted = vec![];
    let mut training = None;
    let (text, semantics, verification_required) = if r.below(4) == 0 {
        // A single-step computation.
        let exact = r.coin();
        let required = exact && r.coin();
        let t = if exact {
            format!(
                "encompute 0.1\nprogram p precision 0.001{}\n\
                 %0 = input \"x\" [0.0, 100.0] : secret u8\n%1 = const [1.0] : public u8\n\
                 %2 = add %0, %1 : secret u8\noutput \"y\" = %2\n",
                if required {
                    " verification required"
                } else {
                    ""
                }
            )
        } else {
            "encompute 0.1\nprogram p precision 0.001\n\
             %0 = input \"x\" [-1.0, 1.0] : secret vector<4>\n%1 = sum %0 : secret scalar\n\
             output \"y\" = %1\n"
                .to_owned()
        };
        (t, if exact { "exact" } else { "approximate" }, required)
    } else {
        // A multi-party aggregation, optionally with training.
        let n = 2 + r.below(4) as usize;
        let colluding = r.below(n as u64 - 1) as usize;
        let minimum = 2 + r.below(n as u64 - 1) as usize;
        let budget = r.coin();
        let dp = budget || r.coin();
        let with_training = r.coin();
        let shared = r.coin();
        let mut s = String::from(
            "encompute 0.1\nprogram fed precision 0.001 purpose \"t\"\nparty \"modelco\" \"M\"\n",
        );
        for i in 0..n {
            s.push_str(&format!("party \"h{i}\" \"H\"\n"));
        }
        if with_training {
            let readers: Vec<String> = (0..n).map(|i| format!("\"h{i}\"")).collect();
            s.push_str(&format!(
                "asset \"model\" model owners [\"modelco\"] readers [{}] purposes [\"t\"] \
                 release never\n",
                if shared {
                    readers.join(", ")
                } else {
                    String::new()
                }
            ));
            for i in 0..n {
                s.push_str(&format!(
                    "asset \"data{i}\" dataset owners [\"h{i}\"] readers [] purposes [\"t\"] \
                     release never\n"
                ));
            }
            training = Some(TrainingDeclaration {
                model: "model".into(),
                data: (0..n).map(|i| format!("data{i}")).collect(),
                verified: r.coin(),
                privacy_unit: None,
                per_example_clipping: false,
            });
        }
        for i in 0..n {
            s.push_str(&format!(
                "asset \"g{i}\" gradient owners [\"h{i}\"] readers [\"modelco\"] purposes [\"t\"] \
                 release aggregate_only{}\n",
                if budget {
                    " privacy unit \"patient\" epsilon 3.0 delta 1e-6"
                } else {
                    ""
                }
            ));
            aggregate_only.push(format!("g{i}"));
            if budget {
                budgeted.push(format!("g{i}"));
            }
        }
        for i in 0..n {
            s.push_str(&format!(
                "%{i} = input \"x{i}\" [-1.0, 1.0] asset \"g{i}\" : secret vector<4>\n"
            ));
        }
        let mut acc = 0;
        for i in 1..n {
            s.push_str(&format!(
                "%{} = add %{acc}, %{i} : secret vector<4>\n",
                n + i - 1
            ));
            acc = n + i - 1;
        }
        s.push_str(&format!(
            "output \"u\" = %{acc} to \"modelco\"\naggregate \"u\" sum minimum {minimum} \
             colluding {colluding} clip [-1.0, 1.0] scale 1000 modulus 40{}\n",
            if dp {
                " dp discrete_gaussian clip_norm 1.0 noise_multiplier 5.0"
            } else {
                ""
            }
        ));
        (s, "approximate", false)
    };
    let program = parse(&text).ok()?;
    let pool = tee_pool();
    let tees = pool.into_iter().filter(|_| r.below(3) == 0).collect();
    let regions = [None, Some("eu".to_owned()), Some("us".to_owned())];
    let ctx = PlanningContext {
        profile: [Profile::Standard, Profile::Strong, Profile::Maximum][r.below(3) as usize],
        catalog: BackendCatalog {
            ckks: r.coin(),
            tfhe: r.coin(),
            bgv: r.coin(),
            verified_execution: r.coin(),
        },
        infrastructure: Infrastructure {
            tees,
            key_broker: r.coin(),
            host_cloud: r.coin(),
            host_region: regions[r.below(3) as usize].clone(),
        },
        preferences: Preferences {
            objective: if r.coin() {
                Objective::Latency
            } else {
                Objective::Cost
            },
            local_only: r.below(4) == 0,
            region: if r.below(4) == 0 {
                regions[1 + r.below(2) as usize].clone()
            } else {
                None
            },
            allow_development: r.coin(),
        },
        facts: ProgramFacts {
            semantics: semantics.into(),
            fhe_supported: r.below(5) != 0,
            proof_covered: r.coin(),
            operations: 1 + r.below(50),
        },
        training,
    };
    Some(Scenario {
        program,
        ctx,
        aggregate_only,
        budgeted,
        verification_required,
    })
}

/// Removes mechanism `m` of step `s`, keeping the summary consistent.
pub fn without(plan: &ConfidentialExecutionPlan, s: usize, m: usize) -> ConfidentialExecutionPlan {
    let mut p = plan.clone();
    p.steps[s].mechanisms.remove(m);
    let mut sel: BTreeSet<Mechanism> = p
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

fn one(seed: u64, stats: &mut [usize; 3]) -> Result<(), String> {
    let Some(sc) = scenario(seed) else {
        return Ok(());
    };
    let planned = match plan(&sc.program, &sc.ctx) {
        Ok(p) => p,
        // The compiler refused the declarations: nothing to plan.
        Err(_) => return Ok(()),
    };
    let Some(p) = planned.plan else {
        // INV-113: no plan means every candidate of some step was refused,
        // each with a reason.
        stats[1] += 1;
        ensure!(
            !planned.failures.is_empty() && planned.failures.iter().all(|(_, rs)| !rs.is_empty()),
            "seed {seed}: no plan and no reason"
        );
        return Ok(());
    };
    stats[0] += 1;
    // INV-110: the independent validator accepts it.
    verify_plan(&sc.program, &p).map_err(|e| format!("seed {seed}: {}", e.message))?;
    // INV-112: never weaker than the declarations (restated here,
    // independently of the planner and validator).
    let has = |r: &TrustRequirement| p.requirements.contains(r);
    for a in &sc.aggregate_only {
        ensure!(
            has(&TrustRequirement::AggregateOnly {
                asset: a.clone(),
                output: "u".into()
            }),
            "seed {seed}: {a}'s aggregate-only requirement is missing"
        );
        ensure!(
            has(&TrustRequirement::HideFrom {
                asset: a.clone(),
                principal: Principal::ComputeHost
            }),
            "seed {seed}: {a} is not hidden from the host"
        );
    }
    for a in &sc.budgeted {
        ensure!(
            p.requirements
                .iter()
                .any(|r| matches!(r, TrustRequirement::PrivacyBudget { asset, .. } if asset == a)),
            "seed {seed}: {a}'s budget is missing"
        );
    }
    if (sc.verification_required || sc.ctx.profile == Profile::Maximum)
        && p.steps.iter().any(|s| s.id == "evaluate")
    {
        ensure!(
            has(&TrustRequirement::RequireCorrectness {
                step: "evaluate".into()
            }),
            "seed {seed}: correctness requirement is missing"
        );
    }
    // INV-111: removing any selected mechanism invalidates the plan.
    for (s, st) in p.steps.iter().enumerate() {
        for m in 0..st.mechanisms.len() {
            stats[2] += 1;
            ensure!(
                verify_plan(&sc.program, &without(&p, s, m)).is_err(),
                "seed {seed}: the plan stays valid without {} in {}",
                st.mechanisms[m].name(),
                st.id
            );
        }
    }
    Ok(())
}

/// INV-110..113 over generated scenarios (2 000 quick, 50 000 nightly).
pub fn property(scale: Scale) -> CheckResult {
    let n = scale.pick(2_000, 50_000) as u64;
    let base = crate::rand_u64();
    let mut stats = [0usize; 3];
    for &s in REGRESSION_SEEDS {
        one(s, &mut stats)?;
    }
    for i in 0..n {
        one(base.wrapping_add(i), &mut stats)?;
    }
    ensure!(
        stats[0] > 0 && stats[1] > 0,
        "the generator produced no accepted ({}) or no refused ({}) scenarios",
        stats[0],
        stats[1]
    );
    Ok(Outcome::new(n as usize).note(format!(
        "{} plans accepted and validated, {} scenarios correctly unplannable, {} mechanism \
         removals refused (seeds from {base})",
        stats[0], stats[1], stats[2]
    )))
}

fn fed(dp: bool) -> Program {
    let mut s = String::from(
        "encompute 0.1\nprogram fed precision 0.001 purpose \"t\"\nparty \"modelco\" \"M\"\n\
         party \"h0\" \"H\"\nparty \"h1\" \"H\"\nparty \"h2\" \"H\"\n\
         asset \"model\" model owners [\"modelco\"] readers [] purposes [\"t\"] release never\n",
    );
    for i in 0..3 {
        s.push_str(&format!(
            "asset \"data{i}\" dataset owners [\"h{i}\"] readers [] purposes [\"t\"] release \
             never\nasset \"g{i}\" gradient owners [\"h{i}\"] readers [\"modelco\"] purposes \
             [\"t\"] release aggregate_only{}\n",
            if dp {
                " privacy unit \"patient\" epsilon 3.0 delta 1e-6"
            } else {
                ""
            }
        ));
    }
    for i in 0..3 {
        s.push_str(&format!(
            "%{i} = input \"x{i}\" [-1.0, 1.0] asset \"g{i}\" : secret vector<4>\n"
        ));
    }
    s.push_str(&format!(
        "%3 = add %0, %1 : secret vector<4>\n%4 = add %3, %2 : secret vector<4>\n\
         output \"u\" = %4 to \"modelco\"\naggregate \"u\" sum minimum 3 colluding 1 clip \
         [-1.0, 1.0] scale 1000 modulus 40{}\n",
        if dp {
            " dp discrete_gaussian clip_norm 1.0 noise_multiplier 5.0"
        } else {
            ""
        }
    ));
    parse(&s).expect("fed")
}

fn ctx() -> PlanningContext {
    PlanningContext {
        profile: Profile::Standard,
        catalog: BackendCatalog {
            ckks: true,
            tfhe: true,
            bgv: true,
            verified_execution: true,
        },
        infrastructure: Infrastructure {
            tees: vec![tee_pool()[0].clone()],
            key_broker: true,
            host_cloud: true,
            host_region: Some("eu".into()),
        },
        preferences: Preferences::default(),
        facts: ProgramFacts {
            semantics: "approximate".into(),
            fhe_supported: true,
            proof_covered: true,
            operations: 4,
        },
        training: None,
    }
}

const EXACT_REQUIRED: &str = "encompute 0.1\nprogram p precision 0.001 verification required\n\
     %0 = input \"x\" [0.0, 100.0] : secret u8\n%1 = const [1.0] : public u8\n\
     %2 = add %0, %1 : secret u8\noutput \"y\" = %2\n";

/// INV-113: each adversarial scenario from the milestone produces no plan
/// (or an invalid one), never a weaker one.
pub fn adversarial(_: Scale) -> CheckResult {
    let training = |c: &mut PlanningContext| {
        c.training = Some(TrainingDeclaration {
            model: "model".into(),
            data: vec!["data0".into(), "data1".into(), "data2".into()],
            verified: false,
            privacy_unit: None,
            per_example_clipping: false,
        })
    };
    let exact = parse(EXACT_REQUIRED).expect("exact");
    let exact_ctx = || {
        let mut c = ctx();
        c.facts.semantics = "exact".into();
        c
    };
    type Setup = Box<dyn Fn() -> (Program, PlanningContext)>;
    let refused: Vec<(&str, Setup)> = vec![
        (
            "FHE backend cannot run the program",
            Box::new(move || {
                let mut c = exact_ctx();
                c.facts.fhe_supported = false;
                (parse(EXACT_REQUIRED).expect("exact"), c)
            }),
        ),
        (
            "TEE debug mode only",
            Box::new(move || {
                let mut c = ctx();
                training(&mut c);
                c.infrastructure.tees = vec![tee_pool()[2].clone()];
                (fed(true), c)
            }),
        ),
        (
            "verification required but proof coverage partial",
            Box::new(move || {
                let mut c = exact_ctx();
                c.facts.proof_covered = false;
                (parse(EXACT_REQUIRED).expect("exact"), c)
            }),
        ),
        (
            "wrong attestation provider",
            Box::new(move || {
                let mut c = ctx();
                training(&mut c);
                c.infrastructure.tees = vec![tee_pool()[4].clone()];
                (fed(true), c)
            }),
        ),
        (
            "cloud forbidden but only cloud execution available",
            Box::new(move || {
                let mut c = ctx();
                training(&mut c);
                c.preferences.local_only = true;
                (fed(true), c)
            }),
        ),
        (
            "model must be hidden but only normal hardware",
            Box::new(move || {
                let mut c = ctx();
                training(&mut c);
                c.infrastructure.tees.clear();
                (fed(true), c)
            }),
        ),
        (
            "attested coordinator required but no TEE",
            Box::new(move || {
                let mut c = ctx();
                c.profile = Profile::Strong;
                c.infrastructure.tees.clear();
                (fed(true), c)
            }),
        ),
        (
            "development attestation under the maximum profile",
            Box::new(move || {
                let mut c = ctx();
                c.profile = Profile::Maximum;
                c.preferences.allow_development = true;
                c.infrastructure.tees = vec![tee_pool()[3].clone()];
                (fed(true), c)
            }),
        ),
    ];
    let mut cases = 0;
    for (what, setup) in &refused {
        let (p, c) = setup();
        ensure!(plan_or_fail(&p, &c).is_err(), "planned despite: {what}");
        cases += 1;
    }
    // No DP mechanism for a budgeted asset: refused before planning.
    let budget_without_dp = fed(true).to_string().replace(
        " dp discrete_gaussian clip_norm 1.0 noise_multiplier 5.0",
        "",
    );
    ensure!(
        parse(&budget_without_dp)
            .map(|p| plan(&p, &ctx()).is_err())
            .unwrap_or(true),
        "a budgeted asset without a privacy mechanism was planned"
    );
    cases += 1;
    // Forged plans: threshold too small, budget dropped, aggregate-only
    // without secure aggregation, verification skipped.
    let good = plan_or_fail(&fed(true), &ctx()).map_err(|e| e.message)?;
    let agg = good
        .steps
        .iter()
        .position(|s| s.id == "aggregate:u")
        .ok_or("no aggregate step")?;
    let mut forged: Vec<(&str, ConfidentialExecutionPlan)> = vec![];
    let mut t = good.clone();
    for m in t.steps[agg].mechanisms.iter_mut() {
        if let Mechanism::SecureAggregation { threshold, .. } = m {
            *threshold = 2;
        }
    }
    forged.push(("threshold too small", t));
    let mut t = good.clone();
    t.requirements
        .retain(|r| !matches!(r, TrustRequirement::PrivacyBudget { .. }));
    forged.push(("privacy budget absent", t));
    let secagg = good.steps[agg]
        .mechanisms
        .iter()
        .position(|m| matches!(m, Mechanism::SecureAggregation { .. }))
        .ok_or("no secure aggregation")?;
    forged.push(("aggregate_only without SecAgg", without(&good, agg, secagg)));
    let vgood = plan_or_fail(&exact, &exact_ctx()).map_err(|e| e.message)?;
    let v = vgood.steps[0]
        .mechanisms
        .iter()
        .position(|m| *m == Mechanism::VerifiedExecution)
        .ok_or("no verified execution")?;
    forged.push(("execution proof skipped", without(&vgood, 0, v)));
    for (what, f) in &forged {
        let program = if f.program_id == good.program_id {
            fed(true)
        } else {
            parse(EXACT_REQUIRED).expect("exact")
        };
        ensure!(
            verify_plan(&program, f).is_err(),
            "the validator accepted a forged plan: {what}"
        );
        cases += 1;
    }
    Ok(Outcome::new(cases))
}

/// INV-114: every single-field change of a plan changes its PlanId, and
/// every change to a security-relevant field is refused by the validator.
pub fn plan_id_binding(_: Scale) -> CheckResult {
    let mut c = ctx();
    c.profile = Profile::Strong;
    c.training = Some(TrainingDeclaration {
        model: "model".into(),
        data: vec!["data0".into(), "data1".into(), "data2".into()],
        verified: true,
        privacy_unit: None,
        per_example_clipping: false,
    });
    let program = fed(true);
    let p = plan_or_fail(&program, &c).map_err(|e| e.message)?;
    let id = p.id().map_err(|e| e.message)?;
    let v = serde_json::to_value(&p).map_err(|e| e.to_string())?;
    let security = [
        "/program_id",
        "/policy_id",
        "/privacy_policy_id",
        "/requirements",
        "/steps",
        "/selected_mechanisms",
        "/evidence_required",
        "/version",
    ];
    let mut n = 0;
    let mut problems = vec![];
    for m in mutate::mutants(&v) {
        let Ok(q) = serde_json::from_value::<ConfidentialExecutionPlan>(m.value) else {
            continue;
        };
        // Dropping a field that holds its default is the same plan.
        if q == p {
            continue;
        }
        n += 1;
        if q.id().map_err(|e| e.message)? == id {
            problems.push(format!("{}: same PlanId", m.path));
        }
        let relevant =
            security.iter().any(|s| m.path.starts_with(s)) && !m.path.ends_with("/estimated_ms");
        if relevant && verify_plan(&program, &q).is_ok() {
            problems.push(format!("{}: accepted by the validator", m.path));
        }
    }
    ensure!(
        problems.is_empty(),
        "plan mutations not caught: {problems:?}"
    );
    Ok(Outcome::new(n))
}
