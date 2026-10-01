//! Privacy populations and scopes: the population's cap is authoritative,
//! a scope is a sub-ledger of exactly one population for one project,
//! purpose and program, and nothing is charged unless both afford it.

use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use ed25519_dalek::SigningKey;
use encompute_ir::confidentiality::{
    DpKind, DpMechanism, FixedPointCodec, PrivacyBudget, PrivacyUnit,
};
use encompute_ir::Code;
use encompute_privacy::accountant::{gaussian_rho, rho_cap, Zcdp};
use encompute_privacy::ledger::{ScopeRef, LEDGER_VERSION_SCOPED};
use encompute_privacy::scoped::{
    append_scoped, check_genesis_pair, check_scope_ref, check_spend, population_genesis,
    scope_genesis, ScopeBinding,
};
use encompute_privacy::{
    ledger, release, Charged, ChargedScope, Csprng, Genesis, LedgerView, PrivacyAccountant,
    PrivacyEvent, ReleaseSpec,
};

fn budget(epsilon: f64) -> PrivacyBudget {
    PrivacyBudget {
        unit: PrivacyUnit::Patient,
        epsilon,
        delta: 1e-6,
    }
}

fn population(eps: f64) -> Genesis {
    population_genesis("pop-regional", "region-a", "residents", budget(eps)).unwrap()
}

fn scope_of(pop: &Genesis, id: &str, project: &str, eps: f64) -> Genesis {
    scope_genesis(id, pop, project, "surveillance-2027", None, budget(eps)).unwrap()
}

fn empty(g: &Genesis) -> LedgerView {
    LedgerView {
        genesis: g.clone(),
        entries: vec![],
    }
}

fn mechanism() -> DpMechanism {
    DpMechanism {
        kind: DpKind::DiscreteGaussian,
        clip_norm: 1.0,
        noise_multiplier: 20.0,
        sampling_rate: None,
        preset: None,
    }
}

fn scope_ref(scope: &Genesis, pop: &Genesis) -> ScopeRef {
    ScopeRef {
        scope_id: scope.asset_id.clone(),
        population_id: pop.asset_id.clone(),
        job_id: None,
        max_sources_per_unit: 1,
        layout_id: None,
        linkage: "none".into(),
    }
}

/// A reservation costing rho 0.0025 (sensitivity 50, variance 500000).
fn reserve(id: &str, scope: &Genesis, pop: &Genesis) -> PrivacyEvent {
    PrivacyEvent::Reserve {
        event_id: id.into(),
        policy_id: None,
        execution_spec_id: None,
        round_id: Some(format!("round-{id}")),
        output: "counts".into(),
        mechanism: mechanism(),
        sensitivity: 50,
        sigma2: 500_000,
        vector_len: 8,
        rng: encompute_privacy::CSPRNG.into(),
        scope: Some(Box::new(scope_ref(scope, pop))),
    }
}

fn commit(id: &str) -> PrivacyEvent {
    PrivacyEvent::Commit {
        event_id: id.into(),
        output_commitment: "cd".repeat(32),
    }
}

#[test]
fn a_version_1_ledger_is_byte_for_byte_what_it_was() {
    let g = Genesis {
        version: 1,
        asset_id: "patients".into(),
        budget: budget(3.0),
        privacy_policy_id: "f".repeat(64),
        scoping: None,
    };
    let json =
        String::from_utf8(encompute_verification::canonical::canonical_json(&g).unwrap()).unwrap();
    assert!(!json.contains("scop"), "{json}");
    let v = LedgerView {
        genesis: g,
        entries: vec![],
    };
    let (v, e) = v
        .append_event(PrivacyEvent::Reserve {
            event_id: "e".into(),
            policy_id: None,
            execution_spec_id: None,
            round_id: None,
            output: "o".into(),
            mechanism: mechanism(),
            sensitivity: 50,
            sigma2: 500_000,
            vector_len: 8,
            rng: "csprng".into(),
            scope: None,
        })
        .unwrap();
    v.verify().unwrap();
    let entry =
        String::from_utf8(encompute_verification::canonical::canonical_json(&e).unwrap()).unwrap();
    assert!(!entry.contains("scope"), "{entry}");
    // A scoped event never lands in a plain asset ledger.
    let p = population(1.0);
    let s = scope_of(&p, "scp-1", "proj", 1.0);
    let err = v.append_event(reserve("x", &s, &p)).unwrap_err();
    assert_eq!(err.code, Code::PrivacyLedger, "{err}");
}

#[test]
fn rho_cap_is_the_most_the_budget_affords() {
    for (eps, delta) in [(1.0, 1e-6), (0.25, 1e-9), (8.0, 1e-5), (0.01, 1e-6)] {
        let b = PrivacyBudget {
            unit: PrivacyUnit::Patient,
            epsilon: eps,
            delta,
        };
        let cap = rho_cap(&b).unwrap();
        assert!(cap > 0.0 && cap < eps);
        // At the cap the budget holds; a hair above, it does not.
        assert!(Zcdp.epsilon(cap, delta) <= eps, "{eps}");
        assert!(Zcdp.epsilon(cap * (1.0 + 1e-6), delta) > eps, "{eps}");
    }
}

#[test]
fn the_population_cap_is_authoritative_over_scopes_that_add_up_to_more() {
    let pop = population(1.0);
    // Two projects, each allocated the whole epsilon: over-allocated on purpose.
    let (a, b) = (
        scope_of(&pop, "scp-a", "proj-a", 1.0),
        scope_of(&pop, "scp-b", "proj-b", 1.0),
    );
    let (mut p, mut sa, mut sb) = (empty(&pop), empty(&a), empty(&b));
    let affordable =
        ledger::affordable(gaussian_rho(50, 500_000).unwrap(), None, &pop.budget).unwrap();
    assert!(affordable >= 4, "{affordable}");
    // Project A spends two thirds of the population.
    let spent_a = affordable * 2 / 3;
    for i in 0..spent_a {
        let id = format!("a{i}");
        let (np, nsa, ..) = append_scoped(&p, &sa, reserve(&id, &a, &pop)).unwrap();
        let (np, nsa, ..) = append_scoped(&np, &nsa, commit(&id)).unwrap();
        (p, sa) = (np, nsa);
    }
    // Project B's own scope is untouched, yet the population refuses first.
    let mut spent_b = 0;
    let err = loop {
        let id = format!("b{spent_b}");
        match append_scoped(&p, &sb, reserve(&id, &b, &pop)) {
            Ok((np, nsb, ..)) => {
                (p, sb) = (np, nsb);
                spent_b += 1;
            }
            Err(e) => break e,
        }
    };
    assert_eq!(err.code, Code::PrivacyBudgetExceeded);
    assert!(err.message.contains("population pop-regional"), "{err}");
    assert!(
        spent_b >= 1 && spent_a + spent_b <= affordable,
        "{spent_a} {spent_b} {affordable}"
    );
    // The refusal reserved nothing in either ledger.
    let before = (p.entries.len(), sb.entries.len());
    assert!(append_scoped(&p, &sb, reserve("b-more", &b, &pop)).is_err());
    assert_eq!(before, (p.entries.len(), sb.entries.len()));
    // Across scopes the population holds exactly every release.
    assert_eq!(p.entries.len(), sa.entries.len() + sb.entries.len());
    let total = p.cost().unwrap();
    assert!(total.epsilon <= 1.0, "{}", total.epsilon);
    // Composition is the sum of the scopes' rho, at the population.
    let rho = gaussian_rho(50, 500_000).unwrap();
    assert!((total.rho - (spent_a + spent_b) as f64 * rho).abs() < 1e-12);
}

#[test]
fn a_scopes_own_cap_binds_below_the_population() {
    let pop = population(1.0);
    let small = scope_of(&pop, "scp-small", "proj", 0.3);
    let (p, s) = (empty(&pop), empty(&small));
    let (mut p, mut s) = (p, s);
    let mut n = 0;
    let err = loop {
        let id = format!("e{n}");
        match append_scoped(&p, &s, reserve(&id, &small, &pop)) {
            Ok((np, ns, ..)) => {
                (p, s) = (np, ns);
                n += 1;
            }
            Err(e) => break e,
        }
    };
    assert_eq!(err.code, Code::PrivacyBudgetExceeded);
    assert!(err.message.contains("scope scp-small"), "{err}");
    assert!(p.cost().unwrap().epsilon < 1.0);
    assert!(s.cost().unwrap().epsilon <= 0.3);
}

#[test]
fn allocation_is_refused_above_the_population_or_at_another_unit_or_delta() {
    let pop = population(1.0);
    let ok = |b: PrivacyBudget| scope_genesis("s", &pop, "p", "q", None, b);
    assert!(ok(budget(1.0)).is_ok());
    let e = ok(budget(1.5)).unwrap_err();
    assert_eq!(e.code, Code::GovernancePrivacyAllocation);
    assert!(e.message.contains("authoritative"), "{e}");
    let e = ok(PrivacyBudget {
        unit: PrivacyUnit::User,
        ..budget(0.5)
    })
    .unwrap_err();
    assert_eq!(e.code, Code::GovernancePrivacyAllocation);
    let e = ok(PrivacyBudget {
        delta: 1e-5,
        ..budget(0.5)
    })
    .unwrap_err();
    assert_eq!(e.code, Code::GovernancePrivacyAllocation);
    // A scope of a scope is refused.
    let s = ok(budget(0.5)).unwrap();
    assert!(scope_genesis("s2", &s, "p", "q", None, budget(0.1)).is_err());
}

#[test]
fn a_scope_belongs_to_exactly_one_population() {
    let pop = population(1.0);
    let other = population_genesis("pop-regional", "region-a", "residents", budget(2.0)).unwrap();
    let s = scope_of(&pop, "scp", "proj", 1.0);
    check_genesis_pair(&pop, &s).unwrap();
    // The same ID with another cap is another population (its digest differs).
    assert_eq!(
        check_genesis_pair(&other, &s).unwrap_err().code,
        Code::GovernancePrivacyScope
    );
    // A population's series is part of it.
    let lookalike =
        population_genesis("pop-regional", "region-a", "other-series", budget(1.0)).unwrap();
    assert!(check_genesis_pair(&lookalike, &s).is_err());
    // A spend through the wrong pair is refused.
    assert!(check_spend(&empty(&other), &empty(&s), 0.001, None).is_err());
}

#[test]
fn a_scope_serves_only_its_own_project_purpose_and_program() {
    let pop = population(1.0);
    let any_program = scope_of(&pop, "s1", "proj", 0.5);
    let pinned = scope_genesis(
        "s2",
        &pop,
        "proj",
        "surveillance-2027",
        Some("prog-1"),
        budget(0.5),
    )
    .unwrap();
    let want = |p, q, r| ScopeBinding {
        project: p,
        purpose: q,
        program: r,
    };
    assert!(any_program.serves(&want("proj", "surveillance-2027", None)));
    assert!(any_program.serves(&want("proj", "surveillance-2027", Some("prog-9"))));
    assert!(!any_program.serves(&want("other", "surveillance-2027", None)));
    assert!(!any_program.serves(&want("proj", "debt-collection", None)));
    assert!(pinned.serves(&want("proj", "surveillance-2027", Some("prog-1"))));
    assert!(!pinned.serves(&want("proj", "surveillance-2027", Some("prog-2"))));
    assert!(!pinned.serves(&want("proj", "surveillance-2027", None)));
    assert!(!pop.serves(&want("proj", "surveillance-2027", None)));
}

#[test]
fn a_reservation_must_name_its_scope_and_declare_no_linkage() {
    let pop = population(1.0);
    let s = scope_of(&pop, "scp", "proj", 1.0);
    let (p, sc) = (empty(&pop), empty(&s));
    // No scope reference: refused.
    let mut e = reserve("e1", &s, &pop);
    if let PrivacyEvent::Reserve { scope, .. } = &mut e {
        *scope = None;
    }
    assert_eq!(
        append_scoped(&p, &sc, e).unwrap_err().code,
        Code::GovernancePrivacyScope
    );
    // Another scope's reference: refused.
    let mut e = reserve("e2", &s, &pop);
    if let PrivacyEvent::Reserve { scope: Some(r), .. } = &mut e {
        r.scope_id = "scp-other".into();
    }
    assert_eq!(
        append_scoped(&p, &sc, e).unwrap_err().code,
        Code::GovernancePrivacyScope
    );
    // A linkage other than none: refused (ENC2721).
    let mut e = reserve("e3", &s, &pop);
    if let PrivacyEvent::Reserve { scope: Some(r), .. } = &mut e {
        r.linkage = "hmac-sha256-v1".into();
    }
    assert_eq!(
        append_scoped(&p, &sc, e).unwrap_err().code,
        Code::GovernanceAggregateDeclaration
    );
    // No sources per unit declared (zero): refused (ENC2721).
    let r = ScopeRef {
        max_sources_per_unit: 0,
        ..scope_ref(&s, &pop)
    };
    assert_eq!(
        check_scope_ref(&r, &pop, &s).unwrap_err().code,
        Code::GovernanceAggregateDeclaration
    );
    // A commit needs an open reservation in both.
    assert!(append_scoped(&p, &sc, commit("never-reserved")).is_err());
}

#[test]
fn a_ledger_of_one_kind_refuses_the_other_kinds_events() {
    let pop = population(1.0);
    let s = scope_of(&pop, "scp", "proj", 1.0);
    // A reservation for this scope cannot be appended to the population
    // alone, nor one for another scope to this scope.
    let v = empty(&pop);
    let e = reserve("x", &s, &pop);
    v.append_event(e.clone()).unwrap();
    let other_pop = population_genesis("pop-two", "region-b", "residents", budget(1.0)).unwrap();
    assert!(empty(&other_pop).append_event(e.clone()).is_err());
    let sc = empty(&s);
    let other = scope_of(&pop, "scp-2", "proj", 1.0);
    assert!(empty(&other).append_event(e).is_err());
    sc.verify().unwrap();
    assert_eq!(pop.version, LEDGER_VERSION_SCOPED);
}

// --- files: releases through population and scope ledgers ------------------------

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("encompute-scoped-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[4; 32])
}

fn charges(scope: &Genesis, pop: &Genesis) -> Vec<Charged> {
    [scope, pop]
        .map(|g| Charged {
            asset_id: g.asset_id.clone(),
            budget: g.budget.clone(),
            scoped: Some(ChargedScope {
                genesis: g.clone(),
                scope_id: scope.asset_id.clone(),
                population_id: pop.asset_id.clone(),
            }),
        })
        .to_vec()
}

fn spec(round: u64, charged: Vec<Charged>, sources: u32) -> ReleaseSpec {
    ReleaseSpec {
        round_id: format!("{round:064x}"),
        output: "counts".into(),
        policy_id: None,
        privacy_policy_id: "bb".repeat(32),
        execution_spec_id: None,
        mechanism: mechanism(),
        codec: FixedPointCodec {
            clip_min: -1.0,
            clip_max: 1.0,
            scale: 64,
            modulus_bits: 32,
        },
        vector_len: 8,
        charged,
        sources_per_unit: sources,
        layout_id: None,
    }
}

fn seed(d: &std::path::Path, g: &Genesis) {
    // Allocation by the owners: the ledger exists with its genesis.
    let l = ledger::Ledger::open(&d.join(format!("{}.ledger", g.asset_id)), g).unwrap();
    drop(l);
}

#[test]
fn a_release_never_creates_a_scope_or_a_population() {
    let d = dir("missing");
    let pop = population(1.0);
    let s = scope_of(&pop, "scp-a", "proj", 1.0);
    let mut rng = Csprng::from_os().unwrap();
    let err = release(
        &spec(1, charges(&s, &pop), 1),
        &d,
        &[0; 8],
        &mut rng,
        &key(),
    )
    .unwrap_err();
    assert_eq!(err.code, Code::GovernancePrivacyScope, "{err}");
    // Only the population allocated: an unrelated project's scope is still absent.
    seed(&d, &pop);
    let err = release(
        &spec(1, charges(&s, &pop), 1),
        &d,
        &[0; 8],
        &mut rng,
        &key(),
    )
    .unwrap_err();
    assert_eq!(err.code, Code::GovernancePrivacyScope, "{err}");
    // Nothing was written anywhere.
    assert!(!d.join("scp-a.ledger").exists());
    assert_eq!(
        ledger::read(&d.join("pop-regional.ledger"))
            .unwrap()
            .entries
            .len(),
        0
    );
    // Allocated: the release goes through and charges both.
    seed(&d, &s);
    let out = release(
        &spec(1, charges(&s, &pop), 1),
        &d,
        &[0; 8],
        &mut rng,
        &key(),
    )
    .unwrap();
    assert_eq!(out.receipts.len(), 2);
    for f in ["pop-regional", "scp-a"] {
        let v = ledger::read(&d.join(format!("{f}.ledger"))).unwrap();
        assert_eq!(v.entries.len(), 2, "{f}: a reserve and a commit");
        assert!(
            matches!(&v.entries[0].event, PrivacyEvent::Reserve { scope: Some(r), .. } if r.scope_id == "scp-a" && r.linkage == "none")
        );
    }
}

#[test]
fn concurrent_releases_through_two_scopes_never_exceed_the_population() {
    let d = dir("concurrent");
    let pop = population(1.0);
    let (a, b) = (
        scope_of(&pop, "scp-a", "proj-a", 1.0),
        scope_of(&pop, "scp-b", "proj-b", 1.0),
    );
    for g in [&pop, &a, &b] {
        seed(&d, g);
    }
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8u64)
        .map(|i| {
            let (d, barrier) = (d.clone(), barrier.clone());
            let scope = if i % 2 == 0 { a.clone() } else { b.clone() };
            let pop = pop.clone();
            std::thread::spawn(move || {
                let mut rng = Csprng::from_os().unwrap();
                barrier.wait();
                let mut ok = 0u32;
                for r in 0..6 {
                    let s = spec(i * 100 + r + 1, charges(&scope, &pop), 1);
                    match release(&s, &d, &[0; 8], &mut rng, &key()) {
                        Ok(_) => ok += 1,
                        Err(e) => assert_eq!(e.code, Code::PrivacyBudgetExceeded, "{e}"),
                    }
                }
                ok
            })
        })
        .collect();
    let granted: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    let p = ledger::read(&d.join("pop-regional.ledger")).unwrap();
    let (sa, sb) = (
        ledger::read(&d.join("scp-a.ledger")).unwrap(),
        ledger::read(&d.join("scp-b.ledger")).unwrap(),
    );
    p.verify().unwrap();
    assert!(
        p.cost().unwrap().epsilon <= 1.0,
        "{}",
        p.cost().unwrap().epsilon
    );
    assert_eq!(p.entries.len() as u32, 2 * granted);
    assert_eq!(p.entries.len(), sa.entries.len() + sb.entries.len());
    assert!(granted >= 2, "{granted}");
    // The population was the one that ran out: it would refuse one more.
    let mut rng = Csprng::from_os().unwrap();
    let e = release(
        &spec(9999, charges(&a, &pop), 1),
        &d,
        &[0; 8],
        &mut rng,
        &key(),
    )
    .unwrap_err();
    assert_eq!(e.code, Code::PrivacyBudgetExceeded);
}

#[test]
fn a_restored_older_scope_is_refused_by_what_the_parties_saw() {
    let d = dir("restore");
    let pop = population(1.0);
    let s = scope_of(&pop, "scp-a", "proj", 1.0);
    seed(&d, &pop);
    seed(&d, &s);
    let mut rng = Csprng::from_os().unwrap();
    let one = release(
        &spec(1, charges(&s, &pop), 1),
        &d,
        &[0; 8],
        &mut rng,
        &key(),
    )
    .unwrap();
    let seen = one.receipts[0].clone();
    release(
        &spec(2, charges(&s, &pop), 1),
        &d,
        &[0; 8],
        &mut rng,
        &key(),
    )
    .unwrap();
    // The coordinator restores the scope ledger from before the second round.
    let path = d.join(format!("{}.ledger", seen.asset_id));
    let full = ledger::read(&path).unwrap();
    assert_eq!(full.entries.len(), 4);
    let old = LedgerView {
        genesis: full.genesis.clone(),
        entries: full.entries[..2].to_vec(),
    };
    // A party that saw round 2 refuses it.
    let cp = full.checkpoint().unwrap();
    old.extends(&cp).unwrap_err();
    // And one that only saw round 1 still accepts the restored one but not a reset.
    old.extends(&ledger::Checkpoint {
        seq: seen.ledger_seq,
        root: seen.ledger_root.clone(),
    })
    .unwrap();
    empty(&full.genesis)
        .extends(&ledger::Checkpoint {
            seq: seen.ledger_seq,
            root: seen.ledger_root,
        })
        .unwrap_err();
}
