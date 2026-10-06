//! What the control plane works out for itself about a privacy reservation,
//! and what it can only take from the spender (ENC-SF-2026-048).
//!
//! A standard reservation (one charged to an asset's own ledger) arrives
//! with its mechanism, sensitivity and noise variance declared by whoever
//! spends: the aggregation coordinator or the owner. The control plane
//! recomputes what it can:
//!
//! - the **cost** (rho, then epsilon at the ledger's delta) from the
//!   declared sensitivity and noise variance, by its own accountant, never
//!   from a declared epsilon or a receipt;
//! - the **least sensitivity** the declared noise implies for the ledger's
//!   privacy unit (the release's own rule, [`least_sensitivity`]);
//! - the **mechanism's own consistency**: a valid mechanism, a named
//!   privacy level only with that level's noise, no sampling for an
//!   organization unit (which parties contribute is public: an
//!   organization is never sampled), a positive noise and a cost of at
//!   least [`MIN_RESERVATION_RHO`], production randomness in production.
//!
//! It cannot work out the noise multiplier, the clip norm or the sampling
//! rate of a release it did not plan: those are the coordinator's
//! declarations, vouched for by its attestation, not by this check. (A
//! governed job's reservation is the control plane's own, derived from the
//! job's program: `ops/privacy_scopes.rs` `job_releases`; there nothing is
//! declared.)
//!
//! The golden vectors below come from an independent reference (Python:
//! the same closed forms, and the Canonne-Kamath-Steinke conversion of
//! zCDP to epsilon), not from this code.

use encompute_control::{check_reservation, least_sensitivity, MIN_RESERVATION_RHO};
use encompute_ir::confidentiality::{
    preset_mechanism, DpKind, DpMechanism, FixedPointCodec, PrivacyBudget, PrivacyUnit,
};
use encompute_ir::Code;
use encompute_privacy::{Charged, Genesis, PrivacyEvent, ReleaseSpec, Zcdp, CSPRNG};

const SCALE: u64 = 1000;

fn codec(scale: u64) -> FixedPointCodec {
    FixedPointCodec {
        clip_min: -1.0,
        clip_max: 1.0,
        scale,
        modulus_bits: 64,
    }
}

fn genesis(unit: PrivacyUnit, delta: f64) -> Genesis {
    Genesis {
        version: 1,
        asset_id: "asset".into(),
        budget: PrivacyBudget {
            unit,
            epsilon: 100.0,
            delta,
        },
        privacy_policy_id: "p".repeat(64),
        scoping: None,
    }
}

/// The reservation the release itself writes for one asset.
fn derived(
    unit: PrivacyUnit,
    delta: f64,
    mechanism: DpMechanism,
    scale: u64,
    d: usize,
    sources: u32,
) -> (Genesis, PrivacyEvent) {
    let g = genesis(unit, delta);
    let spec = ReleaseSpec {
        round_id: "r".into(),
        output: "sum".into(),
        policy_id: None,
        privacy_policy_id: g.privacy_policy_id.clone(),
        execution_spec_id: None,
        mechanism,
        codec: codec(scale),
        vector_len: d,
        charged: vec![Charged::asset("asset", g.budget.clone())],
        sources_per_unit: sources,
        layout_id: None,
        job_id: None,
    };
    let event = spec.reserve_event(&spec.charged[0], CSPRNG).unwrap();
    (g, event)
}

fn gaussian(nm: f64, sampling_rate: Option<f64>) -> DpMechanism {
    DpMechanism {
        kind: DpKind::DiscreteGaussian,
        clip_norm: 1.0,
        noise_multiplier: nm,
        sampling_rate,
        preset: None,
    }
}

fn fields(e: &PrivacyEvent) -> (u64, u64) {
    match e {
        PrivacyEvent::Reserve {
            sensitivity,
            sigma2,
            ..
        } => (*sensitivity, *sigma2),
        _ => unreachable!(),
    }
}

fn edit(e: &PrivacyEvent, f: impl FnOnce(&mut u64, &mut u64, &mut DpMechanism)) -> PrivacyEvent {
    let mut e = e.clone();
    if let PrivacyEvent::Reserve {
        sensitivity,
        sigma2,
        mechanism,
        ..
    } = &mut e
    {
        f(sensitivity, sigma2, mechanism);
    }
    e
}

/// One release with the reference values of what is derived from it.
struct Golden {
    name: &'static str,
    unit: PrivacyUnit,
    mechanism: DpMechanism,
    scale: u64,
    vector_len: usize,
    sources_per_unit: u32,
    delta: f64,
    sensitivity: u64,
    sigma2: u64,
    rho: f64,
    epsilon: f64,
}

/// The derived reservation of three releases: its sensitivity, noise
/// variance, cost and epsilon are the reference values, and the control
/// plane accepts it.
#[test]
fn golden_vectors_of_derived_reservations() {
    let cases = [
        Golden {
            name: "level standard, organization",
            unit: PrivacyUnit::Organization,
            mechanism: preset_mechanism("standard", &[PrivacyUnit::Organization]).unwrap(),
            scale: SCALE,
            vector_len: 16,
            sources_per_unit: 1,
            delta: 1e-5,
            sensitivity: 2004,
            sigma2: 4_840_000,
            rho: 0.41487768595041324,
            epsilon: 4.249155006759995,
        },
        Golden {
            name: "level strong, patients inside a party",
            unit: PrivacyUnit::Patient,
            mechanism: preset_mechanism("strong", &[PrivacyUnit::Patient]).unwrap(),
            scale: SCALE,
            vector_len: 16,
            sources_per_unit: 1,
            delta: 1e-6,
            sensitivity: 2004,
            sigma2: 144_000_000,
            rho: 0.0139445,
            epsilon: 0.7422623913032539,
        },
        Golden {
            name: "level maximum, an organization in three sources",
            unit: PrivacyUnit::Organization,
            mechanism: preset_mechanism("maximum", &[PrivacyUnit::Organization]).unwrap(),
            scale: 100,
            vector_len: 10,
            sources_per_unit: 3,
            delta: 1e-7,
            sensitivity: 612,
            sigma2: 3_240_000,
            rho: 0.0578,
            epsilon: 1.7498202649625432,
        },
    ];
    for c in cases {
        let (g, e) = derived(
            c.unit,
            c.delta,
            c.mechanism,
            c.scale,
            c.vector_len,
            c.sources_per_unit,
        );
        assert_eq!(fields(&e), (c.sensitivity, c.sigma2), "{}", c.name);
        let rho = e.rho().unwrap();
        // Rounded up, never down, by a few ulps.
        assert!(
            rho >= c.rho && rho <= c.rho * (1.0 + 1e-12),
            "{}: rho {rho} vs {}",
            c.name,
            c.rho
        );
        let epsilon = encompute_privacy::PrivacyAccountant::epsilon(&Zcdp, rho, c.delta);
        assert!(
            (epsilon - c.epsilon).abs() <= c.epsilon * 1e-9 && epsilon >= c.epsilon * (1.0 - 1e-12),
            "{}: epsilon {epsilon} vs {}",
            c.name,
            c.epsilon
        );
        check_reservation(&g, &e, true).unwrap_or_else(|e| panic!("{}: {e}", c.name));
    }
}

/// Poisson-sampled (DP-SGD) release of a unit inside a party: one unit
/// moves the sum by the clip norm (factor 1), not twice it.
#[test]
fn a_sampled_release_of_an_inner_unit_charges_the_clip_norm_once() {
    let (g, e) = derived(
        PrivacyUnit::Patient,
        1e-5,
        gaussian(1.0, Some(0.01)),
        SCALE,
        100,
        1,
    );
    // ceil(1 * 1 * 1000) + ceil(sqrt(100)) = 1010; (1 * 1 * 1000)^2.
    assert_eq!(fields(&e), (1010, 1_000_000));
    check_reservation(&g, &e, true).unwrap();
    // One short of it is refused: sampling does not make a unit cheaper
    // than its own clip norm.
    let short = edit(&e, |s, _, _| *s -= 1);
    let r = check_reservation(&g, &short, true).unwrap_err();
    assert_eq!(r.code, Code::PrivacyMechanism, "{r}");
}

/// Every way of declaring less than the noise implies is refused, and the
/// ways of declaring more are not a way to be charged less.
#[test]
fn tampered_declarations_are_refused() {
    let (g, honest) = derived(
        PrivacyUnit::Organization,
        1e-5,
        preset_mechanism("standard", &[PrivacyUnit::Organization]).unwrap(),
        SCALE,
        16,
        1,
    );
    check_reservation(&g, &honest, true).unwrap();
    let refused = |what: &str, e: PrivacyEvent, code: Code| {
        let r = check_reservation(&g, &e, true).expect_err(what);
        assert_eq!(r.code, code, "{what}: {r}");
    };
    // Sensitivity below what the noise implies, by one and by a lot.
    refused(
        "one short",
        edit(&honest, |s, _, _| *s -= 1),
        Code::PrivacyMechanism,
    );
    refused(
        "one unit",
        edit(&honest, |s, _, _| *s = 1),
        Code::PrivacyMechanism,
    );
    // More noise claimed than the declared multiplier, clip norm and the
    // same sensitivity can have produced.
    refused(
        "noisier",
        edit(&honest, |_, s2, _| *s2 *= 2),
        Code::PrivacyMechanism,
    );
    // A named privacy level with another level's noise, clip norm or
    // sampling.
    refused(
        "level with other noise",
        edit(&honest, |_, _, m| m.noise_multiplier = 22.0),
        Code::PrivacyPolicy,
    );
    refused(
        "level with a clip norm of its own",
        edit(&honest, |_, _, m| m.clip_norm = 2.0),
        Code::PrivacyPolicy,
    );
    // Zero everything.
    refused(
        "no noise",
        edit(&honest, |_, s2, _| *s2 = 0),
        Code::PrivacyMechanism,
    );
    refused(
        "no sensitivity",
        edit(&honest, |s, _, _| *s = 0),
        Code::PrivacyMechanism,
    );
    // An organization is never sampled: which parties contribute is
    // public, so a sampling rate buys no amplification. Declared anyway it
    // would have: the same sensitivity and noise cost far less.
    let sampled = edit(&honest, |_, _, m| {
        m.preset = None;
        m.sampling_rate = Some(0.001);
    });
    refused(
        "an organization, sampled",
        sampled.clone(),
        Code::PrivacyMechanism,
    );
    // Whereas a unit inside a party may be (its sensitivity then follows the
    // sampled rule, and the same declaration is accepted there).
    let (gp, ep) = derived(
        PrivacyUnit::Patient,
        1e-5,
        gaussian(2.2, Some(0.001)),
        SCALE,
        16,
        1,
    );
    check_reservation(&gp, &ep, true).unwrap();
    // Not the production source of randomness.
    let mut test_rng = honest.clone();
    if let PrivacyEvent::Reserve { rng, .. } = &mut test_rng {
        *rng = "testing-not-secure".into();
    }
    refused(
        "a testing generator in production",
        test_rng.clone(),
        Code::PrivacyMechanism,
    );
    check_reservation(&g, &test_rng, false).unwrap();
    // An over-declaration is only ever dearer: it is accepted and charged
    // more, never less.
    let dearer = edit(&honest, |s, _, _| *s += 500);
    check_reservation(&g, &dearer, true).unwrap();
    assert!(dearer.rho().unwrap() > honest.rho().unwrap());
}

/// What the control plane does not derive. The noise multiplier is an
/// input to the floor on the sensitivity, and the charge is the declared
/// sensitivity and noise variance and nothing else, so a reservation that
/// declares a very large noise multiplier lowers its own floor. What holds
/// is that the charge is computed by the control plane from the declared
/// sensitivity and noise, never below [`MIN_RESERVATION_RHO`], and that no
/// declared epsilon is trusted. (A governed job has no such input: its
/// reservation is derived from its program.)
#[test]
fn the_declared_noise_multiplier_is_the_unverified_input() {
    let (g, honest) = derived(
        PrivacyUnit::Organization,
        1e-5,
        gaussian(2.2, None),
        SCALE,
        16,
        1,
    );
    let honest_rho = honest.rho().unwrap();
    // Declare a noise multiplier 400 million times larger and the least
    // sensitivity that multiplier allows (5: one coordinate's rounding for
    // each of 16 coordinates adds 4).
    let lie = edit(&honest, |s, s2, m| {
        m.noise_multiplier = 1e9;
        *s = 5;
        *s2 = 1_000_000_000;
    });
    let floor = least_sensitivity(&g.budget.unit, &gaussian(1e9, None), 1_000_000_000, 16);
    assert_eq!(floor, 5, "the floor follows the declared multiplier");
    check_reservation(&g, &lie, true).expect("this is the limit, documented");
    // It is charged what it declares: far less than the honest release,
    // but at least the floor.
    let rho = lie.rho().unwrap();
    assert!(rho < honest_rho * 1e-6, "{rho} vs {honest_rho}");
    assert!(rho >= MIN_RESERVATION_RHO, "{rho}");
    // Declaring a noise variance so large that the cost falls below the
    // floor is refused.
    let free = edit(&lie, |_, s2, _| *s2 = u64::MAX >> 4);
    let r = check_reservation(&g, &free, true).unwrap_err();
    assert_eq!(r.code, Code::PrivacyMechanism, "{r}");
    assert!(r.message.contains("at least rho"), "{r}");
}
