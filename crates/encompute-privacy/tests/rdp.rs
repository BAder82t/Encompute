//! The Rényi DP accountant against independent reference vectors
//! (tests/reference/rdp_vectors.json, from autodp and a 60-digit mpmath
//! implementation of Zhu and Wang 2019, Theorem 6; see rdp_reference.py).
//! The accountant must agree closely and never be optimistic.

use encompute_ir::confidentiality::{PrivacyBudget, PrivacyUnit};
use encompute_privacy::ledger::{affordable, cost_of};
use encompute_privacy::rdp::{compose, epsilon, release_curve, scaled, ORDERS};

#[derive(serde::Deserialize)]
struct Case {
    rho: f64,
    q: f64,
    steps: u64,
    delta: f64,
    curve: Vec<f64>,
    epsilon: f64,
}

#[derive(serde::Deserialize)]
struct Vectors {
    orders: Vec<u32>,
    cases: Vec<Case>,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("reference/rdp_vectors.json")).unwrap()
}

#[test]
fn curves_match_the_reference_and_are_never_optimistic() {
    let v = vectors();
    assert_eq!(v.orders, ORDERS.to_vec());
    for c in &v.cases {
        let mine = release_curve(c.rho, Some(c.q));
        for (i, (m, r)) in mine.iter().zip(&c.curve).enumerate() {
            assert!(
                m >= r,
                "optimistic at order {}: {m} < {r} ({}, {})",
                ORDERS[i],
                c.rho,
                c.q
            );
            assert!(
                (m - r).abs() <= 1e-7 * r.abs().max(1e-9),
                "order {}: {m} vs {r}",
                ORDERS[i]
            );
        }
    }
}

#[test]
fn epsilon_matches_the_reference_and_is_never_optimistic() {
    for c in &vectors().cases {
        let e = epsilon(&scaled(&release_curve(c.rho, Some(c.q)), c.steps), c.delta);
        assert!(e >= c.epsilon, "optimistic: {e} < {}", c.epsilon);
        assert!(
            (e - c.epsilon).abs() <= 1e-7 * c.epsilon.max(1e-9),
            "rho {} q {} steps {}: {e} vs {}",
            c.rho,
            c.q,
            c.steps,
            c.epsilon
        );
    }
}

/// Review finding DP-7 (ENC-SF-2026-085): long compositions and extreme sampling rates, off
/// the reference grid, against a 60-digit mpmath evaluation of the same
/// bound (scratch `rdp_check.py`, the method of rdp_reference.py). Before
/// the relative margin, the 100000-step case came out 4e-14 relative
/// *below* the reference: accounting was optimistic.
#[test]
// The references keep their 20 significant digits, as computed.
#[allow(clippy::excessive_precision)]
fn long_compositions_are_never_optimistic() {
    let cases = [
        (0.5, 0.9, 10, 1e-6, 20.952984026539917847),
        (2.0, 0.01, 100, 1e-6, 12.963766428278909081),
        (8.0, 0.001, 1000, 1e-5, 2301.2573242711613421),
        (0.03125, 1e-5, 100_000, 1e-6, 0.022203701801909525954),
        (0.3472222222222222, 0.032, 20, 1e-6, 1.6756097003442723407),
        (50.0, 0.2, 5, 1e-6, 496.33483707250338034),
        (0.001, 0.99, 3, 1e-9, 0.43327667863286067805),
    ];
    for (rho, q, n, delta, reference) in cases {
        let e = epsilon(&scaled(&release_curve(rho, Some(q)), n), delta);
        assert!(
            e >= reference,
            "optimistic: rho {rho} q {q} steps {n}: {e} < {reference}"
        );
        assert!(
            (e - reference) / reference <= 1e-9,
            "rho {rho} q {q} steps {n}: {e} vs {reference}"
        );
    }
}

/// The zCDP path is conservative too: never below the CKS reference value.
#[test]
fn zcdp_epsilon_is_never_below_the_reference() {
    use encompute_privacy::PrivacyAccountant;
    let e = encompute_privacy::Zcdp.epsilon(0.005, 1e-6);
    assert!(e >= 0.4299414688369493, "{e}");
    assert!(e - 0.4299414688369493 <= 1e-9, "{e}");
}

#[test]
fn subsampling_helps_and_composition_adds_up() {
    let rho = 1.0 / (2.0 * 1.2 * 1.2);
    let full = release_curve(rho, None);
    let sampled = release_curve(rho, Some(0.01));
    assert!(sampled.iter().zip(&full).all(|(s, f)| s <= f));
    assert!(epsilon(&sampled, 1e-6) < epsilon(&full, 1e-6));
    // Composing ten curves equals scaling one by ten.
    let ten = compose(&vec![sampled; 10]);
    let scaled10 = scaled(&sampled, 10);
    for (a, b) in ten.iter().zip(&scaled10) {
        assert!((a - b).abs() <= 1e-12 * a.max(1e-12));
    }
    // More steps never cost less; more sampling never costs less.
    assert!(epsilon(&scaled(&sampled, 100), 1e-6) > epsilon(&sampled, 1e-6));
    assert!(epsilon(&release_curve(rho, Some(0.1)), 1e-6) > epsilon(&sampled, 1e-6));
}

#[test]
fn ledger_costs_use_rdp_only_with_sampled_releases() {
    let b = PrivacyBudget {
        unit: PrivacyUnit::Patient,
        epsilon: 3.0,
        delta: 1e-6,
    };
    let rho = 1.0 / (2.0 * 1.2 * 1.2);
    // Unsampled: zCDP, exactly as before.
    let z = cost_of(&[(rho, None)], &b).unwrap();
    assert_eq!(
        z.epsilon,
        encompute_privacy::Cost::of(rho, &b).unwrap().epsilon
    );
    // Sampled: RDP, and far cheaper per release.
    let s = cost_of(&[(rho, Some(0.0128))], &b).unwrap();
    assert!(s.epsilon < z.epsilon);
    let n_sampled = affordable(rho, Some(0.0128), &b).unwrap();
    let n_full = affordable(rho, None, &b).unwrap();
    assert!(n_sampled > 10 * n_full, "{n_sampled} vs {n_full}");
    // The budget holds at the boundary.
    let at = cost_of(&vec![(rho, Some(0.0128)); n_sampled as usize], &b).unwrap();
    let over = cost_of(&vec![(rho, Some(0.0128)); n_sampled as usize + 1], &b).unwrap();
    assert!(at.epsilon <= 3.0 && over.epsilon > 3.0);
}
