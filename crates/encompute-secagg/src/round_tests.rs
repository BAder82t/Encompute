//! Review finding DP-1 (ENC-SF-2026-047): every secure-aggregation aggregate is a release.
//! A plan with a privacy-budgeted contributor and no DP mechanism (what
//! rc.3 compiled for a `Sealed` aggregate) is refused by the spec, the
//! coordinator, each budgeted party, the release and the receipt check.

use super::*;
use encompute_ir::confidentiality::PrivacyUnit;

const T0: u64 = 1_900_000_000;

fn party(i: usize) -> PartyId {
    PartyId::new(&format!("hospital-{}", (b'a' + i as u8) as char)).unwrap()
}

fn key(i: usize) -> SigningKey {
    SigningKey::from_bytes(&[i as u8 + 1; 32])
}

/// Three hospitals; `budget` gives each asset a patient-level budget and
/// `dp` adds the mechanism (released to the coordinator), else sealed.
fn plan(budget: bool, dp: bool) -> AggregationPlan {
    let mut s = String::from(
        "encompute 0.1\nprogram fedavg precision 0.001 purpose \"t\"\n\
         party \"coordinator\" \"Coordinator\"\n",
    );
    for x in ["a", "b", "c"] {
        s.push_str(&format!("party \"hospital-{x}\" \"Hospital {x}\"\n"));
    }
    for x in ["a", "b", "c"] {
        s.push_str(&format!(
            "asset \"gradient-{x}\" gradient owners [\"hospital-{x}\"] readers [\"coordinator\"] \
             purposes [\"t\"] release aggregate_only{}\n",
            if budget {
                " privacy unit \"patient\" epsilon 3.0 delta 1e-6"
            } else {
                ""
            }
        ));
    }
    for (i, x) in ["a", "b", "c"].iter().enumerate() {
        s.push_str(&format!(
            "%{i} = input \"g{x}\" [-1.0, 1.0] asset \"gradient-{x}\" : secret vector<4>\n"
        ));
    }
    s.push_str(&format!(
        "%3 = add %0, %1 : secret vector<4>\n%4 = add %3, %2 : secret vector<4>\n\
         output \"g\" = %4{}\n\
         aggregate \"g\" sum minimum 3 colluding 2 clip [-1.0, 1.0] scale 4096 modulus 40{}\n",
        if dp { " to \"coordinator\"" } else { "" },
        if dp {
            " dp discrete_gaussian clip_norm 1.0 noise_multiplier 8.0"
        } else {
            ""
        }
    ));
    let report = encompute_analysis::confidentiality::analyze(&encompute_ir::parse(&s).unwrap())
        .unwrap()
        .unwrap();
    AggregationPlan::from_boundary(
        &"aa".repeat(32),
        None,
        Some(&"bb".repeat(32)),
        &report.aggregations[0],
    )
}

/// What rc.3 compiled for a budgeted aggregate with no `to` and no `dp`:
/// budgeted contributors, a sealed destination, no mechanism.
fn sealed_without_dp() -> AggregationPlan {
    let mut p = plan(true, true);
    p.dp = None;
    p.recipient = OutputRelease::Sealed;
    p
}

fn identities() -> Vec<PartyIdentity> {
    (0..3).map(|i| identity_of(&party(i), &key(i))).collect()
}

/// The spec as a struct, skipping `validate` (a spec approved by an older
/// release, or built by hand).
fn unvalidated(plan: AggregationPlan) -> AggregationSpec {
    AggregationSpec {
        version: SPEC_VERSION,
        threshold: 3,
        plan,
        parties: identities(),
        protocol: PROTOCOL.into(),
        protocol_version: PROTOCOL_VERSION,
        training_execution_spec_id: None,
        attestation: None,
        coordinator_attestation: None,
    }
}

fn budget() -> PrivacyBudget {
    PrivacyBudget {
        unit: PrivacyUnit::Patient,
        epsilon: 3.0,
        delta: 1e-6,
    }
}

/// Runs every protocol stage of one round, then `tamper`, then finalizes.
fn run(
    coord: &mut RoundCoordinator,
    tamper: impl FnOnce(&mut RoundCoordinator),
) -> Result<(AggregateAsset, AggregationReceipt)> {
    let approved = coord.spec.clone();
    let mut ps = vec![];
    for i in 0..3 {
        ps.push(RoundParticipant::join(
            &approved,
            &coord.spec,
            &coord.round,
            &party(i),
            key(i),
            &[0.25, -0.5, 0.125, 0.0],
            None,
            None,
        )?);
    }
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
    tamper(coord);
    coord.finalize()
}

#[test]
fn a_sealed_budgeted_aggregate_without_dp_is_not_a_valid_spec() {
    let e = AggregationSpec::new(sealed_without_dp(), identities()).unwrap_err();
    assert_eq!(e.code, Code::PrivacyPolicy, "{}", e.message);
    // Nor does a coordinator open a round of it (no --out is ever written).
    let e = RoundCoordinator::open(unvalidated(sealed_without_dp()), 1, key(9), None, T0)
        .err()
        .expect("the coordinator opened a round");
    assert_eq!(e.code, Code::PrivacyPolicy);
    // The DP plan, and a plan with no budgets at all, stay valid.
    AggregationSpec::new(plan(true, true), identities()).unwrap();
    AggregationSpec::new(plan(false, false), identities()).unwrap();
}

#[test]
fn a_budgeted_party_does_not_join_a_round_without_dp() {
    // The party approved the rc.3-compiled spec itself, and the coordinator
    // offers exactly that round: the party still refuses, before any
    // contribution exists.
    let spec = unvalidated(sealed_without_dp());
    let round = AggregationRound::new(&spec, 1, &key(9), T0).unwrap();
    let e = RoundParticipant::join(
        &spec,
        &spec,
        &round,
        &party(0),
        key(0),
        &[0.0; 4],
        None,
        None,
    )
    .err()
    .expect("the budgeted party joined");
    assert_eq!(e.code, Code::PrivacyPolicy);
    assert!(e.message.contains("privacy budget"), "{}", e.message);
}

#[test]
fn a_coordinator_never_releases_budgeted_contributions_without_noise() {
    let mut coord = RoundCoordinator::open(
        AggregationSpec::new(plan(false, false), identities()).unwrap(),
        1,
        key(9),
        None,
        T0,
    )
    .unwrap();
    // The coordinator's plan gains budgets after every check before the
    // release (a coordinator built around them): the release is refused.
    let e = run(&mut coord, |c| {
        for p in &mut c.spec.plan.participants {
            p.budget = Some(budget());
        }
    })
    .expect_err("the exact aggregate was released");
    assert_eq!(e.code, Code::PrivacyPolicy);
}

#[test]
fn a_receipt_of_budgeted_assets_without_privacy_receipts_does_not_verify() {
    let mut coord = RoundCoordinator::open(
        AggregationSpec::new(plan(false, false), identities()).unwrap(),
        1,
        key(9),
        None,
        T0,
    )
    .unwrap();
    let (asset, receipt) = run(&mut coord, |_| {}).unwrap();
    let spec = coord.spec.clone();
    verify_release_privacy(&receipt, &spec, Some(&asset)).unwrap();
    // The same exact release, read under the budgeted sealed plan: rc.3
    // accepted it because the destination was `Sealed`.
    let mut budgeted = spec.clone();
    for p in &mut budgeted.plan.participants {
        p.budget = Some(budget());
    }
    assert_eq!(budgeted.plan.recipient, OutputRelease::Sealed);
    let e = verify_release_privacy(&receipt, &budgeted, Some(&asset)).unwrap_err();
    assert_eq!(e.code, Code::PrivacyMechanism);
}
