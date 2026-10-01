//! Aggregate mode (INV-241): the sensitivity is multiplied by the number of
//! sources one privacy unit may span, an exhausted scope or population
//! stops the release before any noise exists, the strata layout is bound
//! into every contribution, and scoped rounds charge a scope and its
//! population (never a per-asset ledger a new version would reset).

use super::*;
use encompute_ir::confidentiality::PrivacyUnit;
use encompute_privacy::accountant::gaussian_rho;
use encompute_privacy::scoped::{population_genesis, scope_genesis};
use encompute_privacy::PrivacyAccountant;
use encompute_privacy::{ledger, Zcdp};

const T0: u64 = 1_900_000_000;

fn party(i: usize) -> PartyId {
    PartyId::new(&format!("region-{}", (b'a' + i as u8) as char)).unwrap()
}

fn key(i: usize) -> SigningKey {
    SigningKey::from_bytes(&[i as u8 + 1; 32])
}

fn identities() -> Vec<PartyIdentity> {
    (0..3).map(|i| identity_of(&party(i), &key(i))).collect()
}

fn budget(eps: f64) -> PrivacyBudget {
    PrivacyBudget {
        unit: PrivacyUnit::Patient,
        epsilon: eps,
        delta: 1e-6,
    }
}

/// Three regional authorities, each with a patient-level budget of
/// epsilon 3; `extra` is appended to the aggregate declaration
/// (`max_sources_per_unit 2`, `layout ["a", "b"]`, ...).
fn plan(extra: &str) -> AggregationPlan {
    try_plan(extra).unwrap()
}

fn try_plan(extra: &str) -> Result<AggregationPlan> {
    let mut s = String::from(
        "encompute 0.1\nprogram weekly precision 0.001 purpose \"surveillance\"\n\
         party \"ministry\" \"Ministry\"\n",
    );
    for x in ["a", "b", "c"] {
        s.push_str(&format!("party \"region-{x}\" \"Region {x}\"\n"));
    }
    for x in ["a", "b", "c"] {
        s.push_str(&format!(
            "asset \"counts-{x}\" gradient owners [\"region-{x}\"] readers [\"ministry\"] \
             purposes [\"surveillance\"] release aggregate_only privacy unit \"patient\" epsilon 3.0 delta 1e-6\n"
        ));
    }
    for (i, x) in ["a", "b", "c"].iter().enumerate() {
        s.push_str(&format!(
            "%{i} = input \"c{x}\" [-1.0, 1.0] asset \"counts-{x}\" : secret vector<4>\n"
        ));
    }
    s.push_str(&format!(
        "%3 = add %0, %1 : secret vector<4>\n%4 = add %3, %2 : secret vector<4>\n\
         output \"c\" = %4 to \"ministry\"\n\
         aggregate \"c\" sum minimum 3 colluding 1 clip [-1.0, 1.0] scale 4096 modulus 40 \
         dp discrete_gaussian clip_norm 1.0 noise_multiplier 40.0{extra}\n"
    ));
    let program = encompute_ir::parse(&s)?;
    let report = encompute_analysis::confidentiality::analyze(&program)?.unwrap();
    Ok(AggregationPlan::from_boundary(
        &"aa".repeat(32),
        None,
        Some(&"bb".repeat(32)),
        &report.aggregations[0],
    ))
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("encompute-agg-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The owners allocate each region's population (cap epsilon `pop_eps`)
/// and this project's scope of it (`scope_eps`) in `d`, and the plan
/// charges them.
fn scoped(p: AggregationPlan, d: &Path, pop_eps: f64, scope_eps: f64) -> AggregationPlan {
    try_scoped(p, d, pop_eps, scope_eps).unwrap()
}

fn try_scoped(
    p: AggregationPlan,
    d: &Path,
    pop_eps: f64,
    scope_eps: f64,
) -> Result<AggregationPlan> {
    let mut scopes = BTreeMap::new();
    for (i, x) in ["a", "b", "c"].iter().enumerate() {
        let pop = population_genesis(
            &format!("pop-{x}"),
            party(i).as_str(),
            "residents",
            budget(pop_eps),
        )
        .unwrap();
        let scope = scope_genesis(
            &format!("scp-{x}"),
            &pop,
            "health-project",
            "surveillance",
            None,
            budget(scope_eps),
        )
        .unwrap();
        for g in [&pop, &scope] {
            drop(
                encompute_privacy::Ledger::open(&d.join(format!("{}.ledger", g.asset_id)), g)
                    .unwrap(),
            );
        }
        scopes.insert(
            format!("counts-{x}"),
            ScopedBudget {
                population: pop,
                scope,
            },
        );
    }
    p.with_scopes(scopes)
}

/// One round through every stage, parties joining with what the
/// coordinator shows of every ledger.
fn round(
    coord: &mut RoundCoordinator,
    tamper: impl FnOnce(&mut [RoundParticipant], &mut RoundCoordinator),
) -> Result<(AggregateAsset, AggregationReceipt)> {
    let approved = coord.spec.clone();
    let shown = coord.ledger_views()?;
    let mut ps = vec![];
    for i in 0..3 {
        ps.push(RoundParticipant::join_with(
            &approved,
            &coord.spec,
            &coord.round,
            &party(i),
            key(i),
            &[0.25, -0.5, 0.125, 0.0],
            JoinOptions {
                all_ledgers: Some(&shown),
                ..JoinOptions::default()
            },
        )?);
    }
    tamper(&mut ps, coord);
    for p in ps.iter_mut() {
        coord.receive_advertise(p.advertise()?)?;
    }
    let k = coord.close_advertise()?;
    for p in ps.iter_mut() {
        coord.receive_shares(p.share_keys(&k)?)?;
    }
    let inbox = coord.close_shares()?;
    for p in ps.iter_mut() {
        let who = p.party().clone();
        coord.receive_masked(p.masked_input(&inbox[&who])?)?;
    }
    let s = coord.close_masked()?;
    for p in ps.iter_mut() {
        coord.receive_consistency(p.consistency(&s)?)?;
    }
    let u = coord.close_consistency()?;
    for p in ps.iter_mut() {
        coord.receive_reveal(p.unmask(&u)?)?;
    }
    coord.finalize()
}

fn open(plan: AggregationPlan, d: &Path, seq: u64) -> Result<RoundCoordinator> {
    RoundCoordinator::open(
        AggregationSpec::new(plan, identities())?,
        seq,
        key(9),
        None,
        T0,
    )?
    .with_ledger(d)
}

// --- sensitivity --------------------------------------------------------------

#[test]
fn sensitivity_scaled() {
    let p = plan("");
    // rc.4 behaviour: no declaration and no scopes is one source per unit.
    let base = p.release_spec("r", None, &[party(0)]).unwrap().unwrap();
    assert_eq!(base.sources_per_unit, 1);
    let c = &base.charged[0];
    // Patient-level, no sampling: the whole contribution moves by 2 x clip
    // (2 x 4096 codes) and rounding by ceil(sqrt(4)) = 2: 8194.
    assert_eq!(base.sensitivity(c), 8194);
    let sigma2 = encompute_privacy::sigma2(&base.mechanism, &base.codec).unwrap();
    assert_eq!(sigma2, 26_843_545_600);
    let rho1 = base.rho(c).unwrap();
    assert_eq!(rho1, gaussian_rho(8194, sigma2).unwrap());
    for m in [2u32, 3, 4, 7] {
        let q = plan(&format!(" max_sources_per_unit {m}"));
        let r = q.release_spec("r", None, &[party(0)]).unwrap().unwrap();
        assert_eq!(r.sources_per_unit, m);
        assert_eq!(r.sensitivity(&r.charged[0]), 8194 * u64::from(m));
        // The cost is quadratic in the sensitivity.
        let rho = r.rho(&r.charged[0]).unwrap();
        assert!(
            (rho / rho1 - f64::from(m * m)).abs() < 1e-9,
            "m {m}: {}",
            rho / rho1
        );
        // And so is the epsilon the accountant reports for it.
        assert!(Zcdp.epsilon(rho, 1e-6) > Zcdp.epsilon(rho1, 1e-6));
    }
    // Sampled (DP-SGD) releases scale too: one clip per unit and source.
    let sampled = plan(" max_sources_per_unit 3");
    let mut r = sampled
        .release_spec("r", None, &[party(0)])
        .unwrap()
        .unwrap();
    r.mechanism.sampling_rate = Some(0.1);
    assert_eq!(r.sensitivity(&r.charged[0]), (4096 + 2) * 3);
    // Declared in the program's text and round-tripped.
    assert!(encompute_ir::parse(&format!(
        "{}",
        encompute_ir::parse(&text(" max_sources_per_unit 5")).unwrap()
    ))
    .is_ok());
}

fn text(extra: &str) -> String {
    format!(
        "encompute 0.1\nprogram weekly precision 0.001 purpose \"s\"\nparty \"m\" \"M\"\n\
         party \"region-a\" \"A\"\nparty \"region-b\" \"B\"\n\
         asset \"x\" gradient owners [\"region-a\"] readers [\"m\"] purposes [\"s\"] release aggregate_only privacy unit \"patient\" epsilon 3.0 delta 1e-6\n\
         asset \"y\" gradient owners [\"region-b\"] readers [\"m\"] purposes [\"s\"] release aggregate_only privacy unit \"patient\" epsilon 3.0 delta 1e-6\n\
         %0 = input \"i\" [-1.0, 1.0] asset \"x\" : secret vector<4>\n\
         %1 = input \"j\" [-1.0, 1.0] asset \"y\" : secret vector<4>\n\
         %2 = add %0, %1 : secret vector<4>\noutput \"o\" = %2 to \"m\"\n\
         aggregate \"o\" sum minimum 2 colluding 0 clip [-1.0, 1.0] scale 4096 modulus 40 \
         dp discrete_gaussian clip_norm 1.0 noise_multiplier 8.0{extra}\n"
    )
}

#[test]
fn a_scoped_release_defaults_to_every_participant() {
    let d = dir("default");
    let p = scoped(plan(""), &d, 3.0, 3.0);
    // Undeclared, a scoped (governed) aggregate assumes the worst case: a
    // unit in every one of the three sources.
    let r = p.release_spec("r", None, &[party(0)]).unwrap().unwrap();
    assert_eq!(r.sources_per_unit, 3);
    assert_eq!(r.sensitivity(&r.charged[0]), 3 * 8194);
    // One participant's release charges its scope and its population.
    let subjects: Vec<&str> = r.charged.iter().map(|c| c.asset_id.as_str()).collect();
    assert_eq!(subjects, ["scp-a", "pop-a"]);
    // Declaring fewer is the owners' explicit claim, and part of the spec ID.
    let two = scoped(plan(" max_sources_per_unit 2"), &d, 3.0, 3.0);
    assert_eq!(
        two.release_spec("r", None, &[party(0)])
            .unwrap()
            .unwrap()
            .sources_per_unit,
        2
    );
    assert_ne!(p.id().unwrap(), two.id().unwrap());
}

#[test]
fn undeclared_sources_per_unit_refused() {
    // The declaration itself is checked.
    for bad in [" max_sources_per_unit 0", " max_sources_per_unit 4097"] {
        let e = try_plan(bad).unwrap_err();
        assert_eq!(e.code, Code::AggregationPlan, "{bad}: {e}");
    }
    // Without dp it scales nothing: refused rather than ignored.
    let e = encompute_ir::parse(&text(" max_sources_per_unit 2").replace(
        " dp discrete_gaussian clip_norm 1.0 noise_multiplier 8.0",
        "",
    ))
    .unwrap_err();
    assert_eq!(e.code, Code::AggregationPlan, "{e}");
    // A coordinator that charges a unit in one source, where the approved
    // plan assumes three, signs a receipt no party accepts: the receipt
    // names the sensitivity it charged.
    let d = dir("undeclared");
    let approved = AggregationSpec::new(scoped(plan(""), &d, 3.0, 3.0), identities()).unwrap();
    let mut coord = open(approved.plan.clone(), &d, 1).unwrap();
    let (_asset, receipt) = round(&mut coord, |_, c| {
        c.spec.plan.max_sources_per_unit = Some(1);
    })
    .unwrap();
    // The receipt is for another spec (the unit count is part of the spec
    // ID every party approved)...
    let e = verify_aggregation_receipt(&receipt, &approved, None, None).unwrap_err();
    assert_eq!(e.code, Code::AggregationBinding, "{e}");
    // ...and, were that check skipped, the privacy receipts alone refuse
    // it: each names the sensitivity it charged.
    let e = verify_release_privacy(&receipt, &approved, None).unwrap_err();
    assert_eq!(e.code, Code::PrivacyMechanism, "{e}");
    assert!(e.message.contains("not for this release"), "{e}");
}

#[test]
fn exhaustion_denies_and_reserves_nothing() {
    let d = dir("exhaust");
    // Scopes of epsilon 1.0 in populations of epsilon 3.0: the scope binds.
    let p = scoped(plan(""), &d, 3.0, 1.0);
    let mut rounds = 0;
    let err = loop {
        rounds += 1;
        let mut coord = match open(p.clone(), &d, rounds) {
            Ok(c) => c,
            Err(e) => break e,
        };
        match round(&mut coord, |_, _| {}) {
            Ok((asset, receipt)) => {
                assert_eq!(
                    receipt.manifest.privacy.len(),
                    6,
                    "a scope and a population each, for three"
                );
                assert_eq!(asset.privacy.len(), 6);
            }
            Err(e) => break e,
        }
        assert!(rounds < 50);
    };
    assert_eq!(err.code, Code::PrivacyBudgetExceeded, "{err}");
    assert!(
        err.message.contains("RELEASE DENIED") && err.message.contains("scope scp-"),
        "{err}"
    );
    assert!(rounds >= 2, "{rounds}");
    // Nothing was reserved by the denied attempt, in any ledger.
    for x in ["a", "b", "c"] {
        for id in [format!("scp-{x}"), format!("pop-{x}")] {
            let v = ledger::read(&d.join(format!("{id}.ledger"))).unwrap();
            assert_eq!(v.entries.len(), 2 * (rounds as usize - 1), "{id}");
            v.verify().unwrap();
        }
        let s = ledger::read(&d.join(format!("scp-{x}.ledger"))).unwrap();
        assert!(s.cost().unwrap().epsilon <= 1.0);
    }
    // A fresh process finds the same state: still denied.
    assert!(open(p, &d, 99).is_err());
}

#[test]
fn the_population_stops_a_release_the_scope_would_allow() {
    let d = dir("population");
    // The scope's epsilon equals the population's, and another project's
    // scope has already used some of the population.
    let p = scoped(plan(""), &d, 1.0, 1.0);
    let pop_a = ledger::read(&d.join("pop-a.ledger")).unwrap();
    let other = scope_genesis(
        "scp-other",
        &pop_a.genesis,
        "other-project",
        "surveillance",
        None,
        budget(1.0),
    )
    .unwrap();
    drop(encompute_privacy::Ledger::open(&d.join("scp-other.ledger"), &other).unwrap());
    // Spend most of the population through the other project's scope, as a
    // coordinator of that project would (a spec of its own).
    let mut other_plan = plan("");
    let mut sc = BTreeMap::new();
    for (i, x) in ["a", "b", "c"].iter().enumerate() {
        let pop = ledger::read(&d.join(format!("pop-{x}.ledger")))
            .unwrap()
            .genesis;
        let s = if i == 0 {
            other.clone()
        } else {
            let g = scope_genesis(
                &format!("scp-o{x}"),
                &pop,
                "other-project",
                "surveillance",
                None,
                budget(1.0),
            )
            .unwrap();
            drop(encompute_privacy::Ledger::open(&d.join(format!("scp-o{x}.ledger")), &g).unwrap());
            g
        };
        sc.insert(
            format!("counts-{x}"),
            ScopedBudget {
                population: pop,
                scope: s,
            },
        );
    }
    other_plan = other_plan.with_scopes(sc).unwrap();
    let mut n = 0;
    loop {
        n += 1;
        let Ok(mut coord) = open(other_plan.clone(), &d, n) else {
            break;
        };
        if round(&mut coord, |_, _| {}).is_err() {
            break;
        }
        assert!(n < 50);
    }
    assert!(n >= 2, "{n}");
    // This project's own scope has never been charged, yet the population,
    // which is authoritative, refuses its release.
    let mine = ledger::read(&d.join("scp-a.ledger")).unwrap();
    assert_eq!(mine.entries.len(), 0);
    let e = open(p, &d, 1).err().expect("the round opened");
    assert_eq!(e.code, Code::PrivacyBudgetExceeded, "{e}");
    assert!(e.message.contains("population pop-"), "{e}");
}

#[test]
fn a_round_of_an_unrelated_project_cannot_spend() {
    let d = dir("unrelated");
    let allocated = scoped(plan(""), &d, 3.0, 3.0);
    // Another project's plan names scopes nobody allocated: its coordinator
    // is refused before a round exists, and nothing is created.
    let mut sc = BTreeMap::new();
    for (i, x) in ["a", "b", "c"].iter().enumerate() {
        let ScopedBudget { population, .. } = allocated.participants[i].scoped.clone().unwrap();
        let g = scope_genesis(
            &format!("scp-x{x}"),
            &population,
            "unrelated-project",
            "surveillance",
            None,
            budget(3.0),
        )
        .unwrap();
        sc.insert(
            format!("counts-{x}"),
            ScopedBudget {
                population,
                scope: g,
            },
        );
    }
    let intruder = plan("").with_scopes(sc).unwrap();
    let e = open(intruder, &d, 1).err().expect("the round opened");
    assert_eq!(e.code, Code::GovernancePrivacyScope, "{e}");
    assert!(!d.join("scp-xa.ledger").exists());
    // The allocated project still can.
    open(allocated, &d, 1).unwrap();
}

#[test]
fn a_plan_scopes_every_budgeted_party_consistently() {
    let d = dir("consistent");
    let p = scoped(plan(""), &d, 3.0, 3.0);
    let d2 = dir("consistent-wide");
    // One participant left on its per-asset budget: refused.
    let mut partial = p.clone();
    partial.participants[1].scoped = None;
    assert_eq!(
        partial.check_scopes().unwrap_err().code,
        Code::GovernancePrivacyScope
    );
    // A population above the asset's declared epsilon: refused.
    let wide = try_scoped(plan(""), &d2, 5.0, 3.0).unwrap_err();
    assert_eq!(wide.code, Code::GovernancePrivacyScope, "{wide}");
    // Scopes of different projects in one aggregation: refused.
    let mut mixed = p.clone();
    let pop = mixed.participants[2]
        .scoped
        .as_ref()
        .unwrap()
        .population
        .clone();
    mixed.participants[2].scoped.as_mut().unwrap().scope = scope_genesis(
        "scp-m",
        &pop,
        "elsewhere",
        "surveillance",
        None,
        budget(1.0),
    )
    .unwrap();
    assert_eq!(
        mixed.check_scopes().unwrap_err().code,
        Code::GovernancePrivacyScope
    );
    // Scopes the plan names that the program does not read: refused.
    let e = plan("")
        .with_scopes(BTreeMap::from([(
            "no-such-asset".to_owned(),
            p.participants[0].scoped.clone().unwrap(),
        )]))
        .unwrap_err();
    assert_eq!(e.code, Code::AggregationPlan);
    // The scopes are part of what each party approves.
    let spec = AggregationSpec::new(p.clone(), identities()).unwrap();
    let mut other = spec.clone();
    other.plan.participants[0]
        .scoped
        .as_mut()
        .unwrap()
        .scope
        .budget
        .epsilon = 2.0;
    assert!(spec.difference(&other).unwrap().contains("participants"));
}

// --- layout --------------------------------------------------------------------

#[test]
fn layout_mismatch_refused() {
    let p = plan(" layout [\"under-5\", \"5-17\", \"18-64\", \"65-plus\"]");
    assert_eq!(
        p.layout_id.as_deref(),
        Some(
            layout_id(&["under-5", "5-17", "18-64", "65-plus"].map(String::from))
                .unwrap()
                .as_str()
        )
    );
    // The same strata in another order are another layout.
    assert_ne!(
        layout_id(&["5-17", "under-5", "18-64", "65-plus"].map(String::from)).unwrap(),
        p.layout_id.clone().unwrap()
    );
    // The layout must list as many strata as the aggregate has values.
    let e = try_plan(" layout [\"a\", \"b\"]").unwrap_err();
    assert_eq!(e.code, Code::AggregationPlan, "{e}");
    // A party whose strata differ names another layout in its signed
    // metadata: the coordinator refuses its contribution (ENC2722).
    let d = dir("layout-mismatch");
    let mut coord = open(scoped(p, &d, 3.0, 3.0), &d, 1).unwrap();
    let e = round(&mut coord, |ps, _| {
        ps[1].spec.plan.layout_id =
            Some(layout_id(&["5-17", "under-5", "18-64", "65-plus"].map(String::from)).unwrap());
    })
    .expect_err("a mismatched layout was summed");
    assert_eq!(e.code, Code::GovernanceAggregateLayout, "{e}");
    // Matching layouts run, and the receipt binds the layout in every
    // contribution's metadata.
    let d = dir("layout");
    let layout = ["u5", "5-17", "18-64", "65"].map(String::from);
    let p = scoped(
        plan(" layout [\"u5\", \"5-17\", \"18-64\", \"65\"]"),
        &d,
        3.0,
        3.0,
    );
    let mut coord = open(p, &d, 1).unwrap();
    let (_asset, receipt) = round(&mut coord, |_, _| {}).unwrap();
    let want = layout_id(&layout).unwrap();
    assert_eq!(receipt.manifest.metadata.len(), 3);
    assert!(receipt
        .manifest
        .metadata
        .iter()
        .all(|m| m.body.layout_id.as_deref() == Some(want.as_str())));
    let spec = coord.spec.clone();
    verify_aggregation_receipt(&receipt, &spec, None, None).unwrap();
    // A receipt whose metadata names another layout does not verify.
    let mut forged = spec.clone();
    forged.plan.layout_id = Some(layout_id(&["x".to_owned()]).unwrap());
    assert!(verify_aggregation_receipt(&receipt, &forged, None, None).is_err());
}
