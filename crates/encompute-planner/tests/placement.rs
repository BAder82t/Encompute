//! INV-233: residency and location decide placement. Effective constraints
//! are intersected; prohibited beats allowed; unknown regions fail closed;
//! unsatisfiable constraints give no plan; a self-declared location never
//! satisfies production; the PlanId binds the constraints; the validator
//! recomputes the admissible evaluators and refuses a plan that says
//! otherwise.

use std::collections::BTreeSet;

use encompute_ir::{parse, Code};
use encompute_planner::placement::{admission, evaluator_unusable, Admission};
use encompute_planner::*;
use encompute_verification::placement::Machine;

const PROGRAM: &str = "encompute 0.1
program eligibility precision 0.001
%0 = input \"age\" [0.0, 120.0] : secret u8
%1 = const [18.0] : public u8
%2 = ge %0, %1 : secret bool
output \"x\" = %2
";

fn loc(provider: &str, region: &str) -> Location {
    Location::resolve(provider, region, None).unwrap()
}

fn offer(id: &str, operator: &str, l: Option<Location>, ev: LocationEvidence) -> EvaluatorOffer {
    EvaluatorOffer {
        id: id.into(),
        operator: operator.into(),
        backends: vec!["openfhe-exact".into(), "openfhe".into()],
        profiles: vec!["exact-default".into()],
        location: l,
        evidence: ev,
        evidence_digest: Some("a".repeat(64)),
    }
}

fn project(c: PlacementConstraints) -> PlacementSource {
    PlacementSource {
        origin: Origin::Project("p1".into()),
        constraints: c,
    }
}

fn owner(org: &str, c: PlacementConstraints) -> PlacementSource {
    PlacementSource {
        origin: Origin::Organization(org.into()),
        constraints: c,
    }
}

fn allow(patterns: &[LocationPattern]) -> PlacementConstraints {
    PlacementConstraints {
        allowed_regions: Some(patterns.iter().cloned().collect()),
        ..PlacementConstraints::default()
    }
}

fn context(
    sources: Vec<PlacementSource>,
    offers: Vec<EvaluatorOffer>,
    production: bool,
) -> PlanningContext {
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
            constraints: sources,
            locations_digest: locations::digest(),
            production,
            roles: Roles::default(),
        }),
    }
}

fn ids(a: &Admission) -> Vec<&str> {
    a.admitted.iter().map(|e| e.id.as_str()).collect()
}

fn de() -> LocationPattern {
    LocationPattern::jurisdiction("DE")
}

fn two_regions() -> Vec<EvaluatorOffer> {
    vec![
        offer(
            "ev-de",
            "platform",
            Some(loc("gcp", "europe-west3")),
            LocationEvidence::OperatorDeclared,
        ),
        offer(
            "ev-us",
            "platform",
            Some(loc("gcp", "us-central1")),
            LocationEvidence::OperatorDeclared,
        ),
    ]
}

#[test]
fn allowed_regions_choose_the_evaluator() {
    let ctx = context(vec![project(allow(&[de()]))], two_regions(), false);
    let a = admission(&ctx, Some("openfhe-exact"), &[], &BTreeSet::new());
    assert_eq!(ids(&a), ["ev-de"]);
    assert_eq!(a.excluded.len(), 1);
    assert!(
        a.excluded[0].1.contains("allowed_regions"),
        "{:?}",
        a.excluded
    );

    let program = parse(PROGRAM).unwrap();
    let plan = plan_or_fail(&program, &ctx).unwrap();
    verify_plan(&program, &plan).unwrap();
    let placement = plan.placement.as_ref().unwrap();
    assert_eq!(placement.admissible.len(), 1);
    assert_eq!(placement.admissible[0].id, "ev-de");
    assert_eq!(
        placement.admissible[0].location,
        Some(loc("gcp", "europe-west3"))
    );
    assert!(plan.requirements.contains(&TrustRequirement::Placement));
    assert!(plan
        .requirements
        .contains(&TrustRequirement::OperatorSeparation));
}

#[test]
fn prohibited_beats_allowed() {
    // Germany is allowed, and one German region is prohibited: deny wins,
    // whatever the order or the number of allowed patterns that match.
    let mut c = allow(&[de(), LocationPattern::region("gcp", "europe-west3")]);
    c.prohibited_locations
        .insert(LocationPattern::region("gcp", "europe-west3"));
    let offers = vec![
        offer(
            "ev-west3",
            "platform",
            Some(loc("gcp", "europe-west3")),
            LocationEvidence::Attested,
        ),
        offer(
            "ev-west10",
            "platform",
            Some(loc("gcp", "europe-west10")),
            LocationEvidence::Attested,
        ),
    ];
    let ctx = context(vec![project(c)], offers, false);
    let a = admission(&ctx, None, &[], &BTreeSet::new());
    assert_eq!(ids(&a), ["ev-west10"]);
    assert!(a.excluded[0].1.contains("prohibited_locations"));
}

#[test]
fn a_prohibited_zone_also_refuses_a_machine_that_does_not_say_its_zone() {
    // The machine declared only its region, which contains the prohibited
    // zone: it might be in it, so deny wins.
    let mut c = PlacementConstraints::default();
    c.prohibited_locations.insert(LocationPattern {
        jurisdiction: None,
        provider: Some("gcp".into()),
        region: Some("europe-west3".into()),
        zone: Some("europe-west3-a".into()),
    });
    let ctx = context(
        vec![project(c)],
        vec![
            offer(
                "region-only",
                "platform",
                Some(loc("gcp", "europe-west3")),
                LocationEvidence::Attested,
            ),
            offer(
                "other-zone",
                "platform",
                Some(Location::resolve("gcp", "europe-west3", Some("europe-west3-b")).unwrap()),
                LocationEvidence::Attested,
            ),
            offer(
                "that-zone",
                "platform",
                Some(Location::resolve("gcp", "europe-west3", Some("europe-west3-a")).unwrap()),
                LocationEvidence::Attested,
            ),
        ],
        false,
    );
    let a = admission(&ctx, None, &[], &BTreeSet::new());
    assert_eq!(ids(&a), ["other-zone"]);
}

#[test]
fn unsatisfiable_constraints_produce_no_plan() {
    // Everyone is in Germany or the US; the project allows France only.
    let ctx = context(
        vec![project(allow(&[LocationPattern::jurisdiction("FR")]))],
        two_regions(),
        false,
    );
    let program = parse(PROGRAM).unwrap();
    let p = plan(&program, &ctx).unwrap();
    assert!(p.plan.is_none(), "an unsatisfiable placement has no plan");
    let e = plan_or_fail(&program, &ctx).unwrap_err();
    assert_eq!(e.code, Code::PlanningFailed);
    assert!(
        e.message.contains("no admissible evaluator"),
        "{}",
        e.message
    );
    assert!(e.message.contains("ev-de") && e.message.contains("ev-us"));

    // Two sources that each admit a different evaluator: the combination
    // admits none, and there is still no plan.
    let ctx = context(
        vec![
            project(allow(&[de()])),
            project(allow(&[LocationPattern::jurisdiction("US")])),
        ],
        two_regions(),
        false,
    );
    assert!(plan(&program, &ctx).unwrap().plan.is_none());
}

#[test]
fn no_registered_evaluator_gives_no_plan() {
    let ctx = context(vec![], vec![], false);
    let e = plan_or_fail(&parse(PROGRAM).unwrap(), &ctx).unwrap_err();
    assert!(
        e.message.contains("no evaluator is registered"),
        "{}",
        e.message
    );
}

#[test]
fn unknown_region_fails_closed() {
    // A region the table does not know cannot be declared...
    assert!(Location::resolve("gcp", "europe-west99", None).is_err());
    assert!(Location::resolve("nowhere", "x", None).is_err());
    assert!(Location::resolve("gcp", "europe-west3", Some("us-central1-a")).is_err());
    // ...nor named in a constraint (a typo would silently admit or fail to
    // prohibit).
    let mut bad = allow(&[LocationPattern::region("gcp", "europe-west99")]);
    assert!(bad.check().is_err());
    bad.allowed_regions = None;
    bad.prohibited_locations
        .insert(LocationPattern::jurisdiction("XX"));
    assert!(bad.check().is_err());
    assert!(
        allow(&[]).check().is_err(),
        "an empty allow list admits nothing"
    );

    // A forged jurisdiction: a German region claiming to be American is
    // as good as unknown, under any location rule.
    let forged = Location {
        jurisdiction: "US".into(),
        provider: "gcp".into(),
        region: "europe-west3".into(),
        zone: None,
    };
    assert!(forged.check().is_err());
    let unknown = Location {
        jurisdiction: "DE".into(),
        provider: "gcp".into(),
        region: "europe-west99".into(),
        zone: None,
    };
    let ctx = context(
        vec![project(allow(&[LocationPattern::jurisdiction("US")]))],
        vec![
            offer(
                "forged",
                "platform",
                Some(forged),
                LocationEvidence::Attested,
            ),
            offer(
                "unknown",
                "platform",
                Some(unknown),
                LocationEvidence::Attested,
            ),
            offer("absent", "platform", None, LocationEvidence::Attested),
        ],
        false,
    );
    let a = admission(&ctx, None, &[], &BTreeSet::new());
    assert!(a.admitted.is_empty(), "{a:?}");
    assert_eq!(a.excluded.len(), 3);
    // And a prohibition is just as unable to be dodged by an unknown
    // location.
    let mut c = PlacementConstraints::default();
    c.prohibited_locations
        .insert(LocationPattern::jurisdiction("DE"));
    let ctx = context(
        vec![project(c)],
        vec![offer(
            "absent",
            "platform",
            None,
            LocationEvidence::Attested,
        )],
        false,
    );
    assert!(admission(&ctx, None, &[], &BTreeSet::new())
        .admitted
        .is_empty());
}

#[test]
fn a_self_declared_location_never_satisfies_production() {
    let offers = |ev| {
        vec![offer(
            "ev-de",
            "platform",
            Some(loc("gcp", "europe-west3")),
            ev,
        )]
    };
    let c = || vec![project(allow(&[de()]))];
    // Development: the project asks for nothing stronger, so it passes.
    let a = admission(
        &context(c(), offers(LocationEvidence::SelfDeclared), false),
        None,
        &[],
        &BTreeSet::new(),
    );
    assert_eq!(ids(&a), ["ev-de"]);
    // Production: self-declared is refused although the constraint's own
    // minimum says nothing.
    let a = admission(
        &context(c(), offers(LocationEvidence::SelfDeclared), true),
        None,
        &[],
        &BTreeSet::new(),
    );
    assert!(a.admitted.is_empty(), "{a:?}");
    assert!(a.excluded[0].1.contains("min_evidence"));
    // Operator-declared is the floor; attested is above it.
    for ev in [
        LocationEvidence::OperatorDeclared,
        LocationEvidence::Attested,
    ] {
        let a = admission(&context(c(), offers(ev), true), None, &[], &BTreeSet::new());
        assert_eq!(ids(&a), ["ev-de"], "{ev}");
    }
}

#[test]
fn the_strongest_minimum_evidence_among_sources_wins() {
    let strict = PlacementConstraints {
        min_evidence: LocationEvidence::Attested,
        ..PlacementConstraints::default()
    };
    let offers = vec![offer(
        "ev",
        "platform",
        Some(loc("gcp", "europe-west3")),
        LocationEvidence::OperatorDeclared,
    )];
    let ctx = context(
        vec![project(PlacementConstraints::default())],
        offers.clone(),
        false,
    );
    assert_eq!(ids(&admission(&ctx, None, &[], &BTreeSet::new())), ["ev"]);
    // The same project constraints plus an owner's strict one.
    let a = admission(&ctx, None, &[owner("tax", strict)], &BTreeSet::new());
    assert!(a.admitted.is_empty());
    // The refusal names the organization and the field, not its values.
    let why = &a.excluded[0].1;
    assert!(why.contains("tax") && why.contains("min_evidence"), "{why}");
}

#[test]
fn an_owners_constraint_can_only_shrink_the_set() {
    let ctx = context(
        vec![project(allow(&[de()]))],
        {
            let mut o = two_regions();
            o.push(offer(
                "ev-de-2",
                "platform",
                Some(loc("gcp", "europe-west10")),
                LocationEvidence::OperatorDeclared,
            ));
            o
        },
        false,
    );
    let none = BTreeSet::new();
    assert_eq!(
        ids(&admission(&ctx, None, &[], &none)),
        ["ev-de", "ev-de-2"]
    );
    // An owner that allows the US as well as one German region: the
    // project's Germany-only rule still holds, and the owner's narrows it.
    let o = owner(
        "tax",
        allow(&[
            LocationPattern::jurisdiction("US"),
            LocationPattern::region("gcp", "europe-west3"),
        ]),
    );
    assert_eq!(ids(&admission(&ctx, None, &[o], &none)), ["ev-de"]);
    // An owner cannot widen: allowing everything changes nothing.
    let o = owner("tax", PlacementConstraints::default());
    assert_eq!(
        ids(&admission(&ctx, None, &[o], &none)),
        ["ev-de", "ev-de-2"]
    );
    // The refusal by another organization never shows its values.
    let o = owner("tax", allow(&[LocationPattern::jurisdiction("FR")]));
    let a = admission(&ctx, None, &[o], &none);
    assert!(a.admitted.is_empty());
    for (_, why) in &a.excluded {
        assert!(why.contains("an input owned by tax"), "{why}");
        assert!(!why.contains("FR"), "private values leaked: {why}");
    }
}

#[test]
fn allowed_operators_and_evaluators_intersect() {
    let c = PlacementConstraints {
        allowed_operators: Some(["opco".to_owned(), "platform".to_owned()].into()),
        ..PlacementConstraints::default()
    };
    let d = PlacementConstraints {
        allowed_evaluators: Some(["ev-1".to_owned(), "ev-3".to_owned()].into()),
        ..PlacementConstraints::default()
    };
    let offers = vec![
        offer("ev-1", "opco", None, LocationEvidence::SelfDeclared),
        offer("ev-2", "opco", None, LocationEvidence::SelfDeclared),
        offer("ev-3", "other", None, LocationEvidence::SelfDeclared),
        offer("ev-4", "platform", None, LocationEvidence::SelfDeclared),
    ];
    let ctx = context(vec![project(c), project(d)], offers, false);
    assert_eq!(ids(&admission(&ctx, None, &[], &BTreeSet::new())), ["ev-1"]);
}

#[test]
fn a_constraint_covers_only_the_scopes_it_names() {
    // A plaintext-only rule says nothing about an evaluator, which sees
    // ciphertexts.
    let mut c = allow(&[LocationPattern::jurisdiction("FR")]);
    c.applies_to = [Scope::Plaintext].into();
    let ctx = context(vec![project(c.clone())], two_regions(), false);
    assert_eq!(
        ids(&admission(&ctx, None, &[], &BTreeSet::new())),
        ["ev-de", "ev-us"]
    );
    c.applies_to = [Scope::Ciphertext].into();
    let ctx = context(vec![project(c)], two_regions(), false);
    assert!(admission(&ctx, None, &[], &BTreeSet::new())
        .admitted
        .is_empty());
}

#[test]
fn the_backend_must_be_offered() {
    let ctx = context(vec![], two_regions(), false);
    let o = &ctx.infrastructure.evaluators[0];
    let why = evaluator_unusable(
        o,
        Some("tfhe-rs"),
        ctx.placement.as_ref().unwrap(),
        &[],
        &BTreeSet::new(),
    )
    .unwrap();
    assert!(why.contains("tfhe-rs"));
}

#[test]
fn the_plan_id_binds_the_constraints_and_the_admissible_set() {
    let program = parse(PROGRAM).unwrap();
    let id = |ctx: &PlanningContext| plan_or_fail(&program, ctx).unwrap().id().unwrap();
    let base = id(&context(vec![], two_regions(), false));
    let de_only = id(&context(
        vec![project(allow(&[de()]))],
        two_regions(),
        false,
    ));
    let de_and_us = id(&context(
        vec![project(allow(&[de(), LocationPattern::jurisdiction("US")]))],
        two_regions(),
        false,
    ));
    assert_ne!(base, de_only);
    assert_ne!(de_only, de_and_us);
    // The same admissible set under different constraints still differs:
    // the constraints themselves are bound.
    assert_ne!(base, de_and_us);
    // And so do the evidence levels.
    let weaker = id(&context(
        vec![],
        vec![offer(
            "ev-de",
            "platform",
            Some(loc("gcp", "europe-west3")),
            LocationEvidence::SelfDeclared,
        )],
        false,
    ));
    let stronger = id(&context(
        vec![],
        vec![offer(
            "ev-de",
            "platform",
            Some(loc("gcp", "europe-west3")),
            LocationEvidence::Attested,
        )],
        false,
    ));
    assert_ne!(weaker, stronger);
}

#[test]
fn the_validator_recomputes_the_admissible_set() {
    let program = parse(PROGRAM).unwrap();
    let ctx = context(vec![project(allow(&[de()]))], two_regions(), false);
    let good = plan_or_fail(&program, &ctx).unwrap();
    verify_plan(&program, &good).unwrap();

    let fails = |p: &ConfidentialExecutionPlan, what: &str| {
        let Err(e) = verify_plan(&program, p) else {
            panic!("{what}: the plan was accepted");
        };
        assert_eq!(e.code, Code::PlanInvalid, "{what}");
        e.message
    };
    // The excluded evaluator added to the recorded set.
    let mut p = good.clone();
    let mut extra = p.placement.as_ref().unwrap().admissible[0].clone();
    extra.id = "ev-us".into();
    extra.location = Some(loc("gcp", "us-central1"));
    p.placement.as_mut().unwrap().admissible.push(extra);
    assert!(fails(&p, "an evaluator the constraints exclude").contains("admissible evaluators"));
    // The record dropped.
    let mut p = good.clone();
    p.placement = None;
    assert!(fails(&p, "no record").contains("admissible evaluators"));
    // The constraints dropped from the context: the context is another
    // one, the requirements and the record no longer follow.
    let mut p = good.clone();
    p.context.placement = None;
    fails(&p, "the placement context removed");
    // The requirements removed.
    let mut p = good.clone();
    p.requirements.retain(|r| *r != TrustRequirement::Placement);
    assert!(fails(&p, "requirement removed").contains("requirement dropped"));
    // Another locations table.
    let mut p = good.clone();
    p.context.placement.as_mut().unwrap().locations_digest = "0".repeat(64);
    assert!(fails(&p, "another table").contains("locations table"));
    // A constraint naming an unknown region.
    let mut p = good.clone();
    p.context.placement.as_mut().unwrap().constraints[0]
        .constraints
        .prohibited_locations
        .insert(LocationPattern::region("gcp", "europe-west99"));
    assert!(fails(&p, "unknown region").contains("invalid"));
    // An owner's private constraint never rides in a plan.
    let mut p = good.clone();
    p.context
        .placement
        .as_mut()
        .unwrap()
        .constraints
        .push(owner("tax", PlacementConstraints::default()));
    assert!(fails(&p, "owner constraint in a plan").contains("only the project's placement"));
    // A TEE cannot stand in under constraints: it has no attested location.
    let tee = TeeOffer {
        tee: "intel-tdx".into(),
        provider: "gcp-confidential-space".into(),
        gpu: false,
        debug_only: false,
        cloud: true,
        region: Some("eu".into()),
    };
    let mut p = good.clone();
    p.context.infrastructure.tees.push(tee.clone());
    p.steps[0].placement = Placement::Tee(tee.clone());
    p.steps[0].mechanisms = vec![
        Mechanism::ConfidentialCompute {
            tee: tee.tee.clone(),
            provider: tee.provider.clone(),
        },
        Mechanism::Attestation {
            provider: tee.provider.clone(),
        },
        Mechanism::AttestedKeyRelease,
    ];
    assert!(fails(&p, "a TEE offer under constraints").contains("attested location"));
}

#[test]
fn production_floor_refuses_a_plan_that_accepts_self_declared_locations() {
    let program = parse(PROGRAM).unwrap();
    let dev = plan_or_fail(
        &program,
        &context(vec![project(allow(&[de()]))], two_regions(), false),
    )
    .unwrap();
    let floor = PlanFloor::production(Profile::Standard);
    let e = verify_plan_with(&program, &dev, &floor).unwrap_err();
    assert!(e.message.contains("self-declared"), "{}", e.message);
    let prod = plan_or_fail(
        &program,
        &context(vec![project(allow(&[de()]))], two_regions(), true),
    )
    .unwrap();
    verify_plan_with(&program, &prod, &floor).unwrap();
}

#[test]
fn combining_constraints_never_admits_what_either_refuses() {
    // The monotone property over a grid of constraints and machines: a
    // location admitted by the combination is admitted by both.
    let patterns = [
        LocationPattern::jurisdiction("DE"),
        LocationPattern::jurisdiction("US"),
        LocationPattern::provider("gcp"),
        LocationPattern::provider("aws"),
        LocationPattern::region("gcp", "europe-west3"),
        LocationPattern::region("aws", "eu-central-1"),
    ];
    let mut cs = vec![PlacementConstraints::default()];
    for (i, a) in patterns.iter().enumerate() {
        cs.push(allow(std::slice::from_ref(a)));
        cs.push(allow(&[
            a.clone(),
            patterns[(i + 1) % patterns.len()].clone(),
        ]));
        let mut c = PlacementConstraints::default();
        c.prohibited_locations.insert(a.clone());
        cs.push(c);
    }
    let strict = PlacementConstraints {
        min_evidence: LocationEvidence::OperatorDeclared,
        allowed_operators: Some(["platform".to_owned()].into()),
        ..PlacementConstraints::default()
    };
    cs.push(strict);
    let machines: Vec<Location> = [
        ("gcp", "europe-west3"),
        ("gcp", "europe-west10"),
        ("gcp", "us-central1"),
        ("aws", "eu-central-1"),
        ("aws", "us-east-1"),
        ("azure", "westeurope"),
        ("onprem", "de"),
    ]
    .iter()
    .map(|(p, r)| loc(p, r))
    .collect();
    for a in &cs {
        for b in &cs {
            let both = a.combine(b);
            for l in &machines {
                for ev in [LocationEvidence::SelfDeclared, LocationEvidence::Attested] {
                    for operator in ["platform", "opco"] {
                        let m = Machine {
                            id: "ev",
                            operator,
                            location: Some(l),
                            evidence: ev,
                        };
                        if both.refusals(&m).is_empty() {
                            assert!(
                                a.refusals(&m).is_empty(),
                                "{a:?} refuses what {both:?} admits"
                            );
                            assert!(
                                b.refusals(&m).is_empty(),
                                "{b:?} refuses what {both:?} admits"
                            );
                        }
                    }
                }
            }
            // And tightening is consistent with combining.
            assert!(both.tightens(a) && both.tightens(b));
        }
    }
}

#[test]
fn tightening_and_loosening_are_told_apart() {
    let open = PlacementConstraints::default();
    let de_only = allow(&[de()]);
    let de_west3 = allow(&[LocationPattern::region("gcp", "europe-west3")]);
    assert!(de_only.tightens(&open));
    assert!(!open.tightens(&de_only));
    assert!(
        de_west3.tightens(&de_only),
        "a region is within its country"
    );
    assert!(!de_only.tightens(&de_west3));
    let mut prohibit = de_only.clone();
    prohibit
        .prohibited_locations
        .insert(LocationPattern::provider("aws"));
    assert!(prohibit.tightens(&de_only));
    assert!(
        !de_only.tightens(&prohibit),
        "dropping a prohibition loosens"
    );
    let mut evidence = de_only.clone();
    evidence.min_evidence = LocationEvidence::Attested;
    assert!(evidence.tightens(&de_only) && !de_only.tightens(&evidence));
    // Narrowing the covered scopes loosens.
    let mut fewer = de_only.clone();
    fewer.applies_to = [Scope::Plaintext].into();
    assert!(!fewer.tightens(&de_only));
}

#[test]
fn standard_plans_are_unchanged() {
    // No placement context: no new fields, no new requirements, the same
    // plan the planner always made.
    let program = parse(PROGRAM).unwrap();
    let mut ctx = context(vec![], vec![], false);
    ctx.placement = None;
    let plan = plan_or_fail(&program, &ctx).unwrap();
    let text = String::from_utf8(plan.to_bytes().unwrap()).unwrap();
    for new in [
        "locations_digest",
        "constraints_digest",
        "evaluators",
        "operator_separation",
    ] {
        assert!(!text.contains(new), "{new} in a standard plan: {text}");
    }
    assert!(!plan.requirements.contains(&TrustRequirement::Placement));
    assert!(plan.placement.is_none());
    verify_plan(&program, &plan).unwrap();
}

#[test]
fn the_report_labels_attested_and_declared() {
    let ctx = context(
        vec![],
        vec![
            offer(
                "a",
                "platform",
                Some(loc("gcp", "europe-west3")),
                LocationEvidence::Attested,
            ),
            offer(
                "b",
                "platform",
                Some(loc("gcp", "europe-west1")),
                LocationEvidence::OperatorDeclared,
            ),
        ],
        false,
    );
    let plan = plan_or_fail(&parse(PROGRAM).unwrap(), &ctx).unwrap();
    let text = render::plan(&plan);
    assert!(
        text.contains("(DE)) (attested)") || text.contains("(attested)"),
        "{text}"
    );
    assert!(text.contains("(declared)"), "{text}");
}
