//! Differential-privacy accounting and releases: budgets, composition,
//! exhaustion, concurrency, persistence, tampering and receipts.

use std::path::PathBuf;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use encompute_ir::confidentiality::{
    DpKind, DpMechanism, FixedPointCodec, PrivacyBudget, PrivacyUnit,
};
use encompute_ir::Code;
use encompute_privacy::{
    discrete_gaussian, ledger, release, verify_privacy_receipt, Charged, Checkpoint, Csprng,
    ReleaseSpec,
};

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("encompute-dp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn budget(epsilon: f64) -> PrivacyBudget {
    PrivacyBudget {
        unit: PrivacyUnit::Patient,
        epsilon,
        delta: 1e-6,
    }
}

fn spec(round: u32, epsilon: f64) -> ReleaseSpec {
    ReleaseSpec {
        sources_per_unit: 1,
        layout_id: None,
        round_id: format!("{round:064x}"),
        output: "global_gradient".into(),
        policy_id: Some("aa".repeat(32)),
        privacy_policy_id: "bb".repeat(32),
        execution_spec_id: None,
        mechanism: DpMechanism {
            kind: DpKind::DiscreteGaussian,
            clip_norm: 1.0,
            noise_multiplier: 10.0,
            sampling_rate: None,
            preset: None,
        },
        codec: FixedPointCodec {
            clip_min: -1.0,
            clip_max: 1.0,
            scale: 256,
            modulus_bits: 32,
        },
        vector_len: 16,
        charged: vec![
            Charged {
                asset_id: "gradient-a".into(),
                budget: budget(epsilon),
                scoped: None,
            },
            Charged {
                asset_id: "gradient-b".into(),
                budget: budget(epsilon),
                scoped: None,
            },
        ],
    }
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[4; 32])
}

#[test]
fn discrete_gaussian_statistics() {
    let mut rng = Csprng::from_os().unwrap();
    let s2 = 10_000u64;
    let n = 20_000;
    let xs: Vec<f64> = (0..n)
        .map(|_| discrete_gaussian(s2, &mut rng).unwrap() as f64)
        .collect();
    let mean = xs.iter().sum::<f64>() / n as f64;
    let var = xs.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / n as f64;
    // Mean within 5 standard errors; variance within 10% (N_Z variance is
    // at most sigma^2).
    assert!(mean.abs() < 5.0 * 100.0 / (n as f64).sqrt(), "mean {mean}");
    assert!((var - s2 as f64).abs() < 0.1 * s2 as f64, "variance {var}");
    assert_eq!(discrete_gaussian(0, &mut rng).unwrap(), 0);
}

#[test]
fn rounds_until_the_budget_is_spent() {
    let d = dir("rounds");
    let sum = vec![1000u64; 16];
    let mut rng = Csprng::from_os().unwrap();
    let mut permitted = 0;
    let mut last_eps = 0.0;
    let err = loop {
        match release(&spec(permitted + 1, 3.0), &d, &sum, &mut rng, &key()) {
            Ok(r) => {
                permitted += 1;
                assert_eq!(r.receipts.len(), 2);
                let eps: f64 = r.receipts[0].cumulative_epsilon.parse().unwrap();
                assert!(
                    eps > last_eps && eps <= 3.0,
                    "composition grows within budget"
                );
                last_eps = eps;
                assert_ne!(r.noisy, vec![1000; 16], "noise was added");
            }
            Err(e) => break e,
        }
        assert!(permitted < 1000, "the budget never ran out");
    };
    assert!(permitted >= 2, "{permitted}");
    assert_eq!(err.code, Code::PrivacyBudgetExceeded);
    assert!(err.message.contains("RELEASE DENIED"), "{}", err.message);
    // Denial reserved nothing: the ledger has exactly two entries per round.
    let v = ledger::read(&d.join("gradient-a.ledger")).unwrap();
    assert_eq!(v.entries.len(), 2 * permitted as usize);
    // Restart: a fresh process sees the same spent budget.
    let again = release(&spec(permitted + 1, 3.0), &d, &sum, &mut rng, &key()).unwrap_err();
    assert_eq!(again.code, Code::PrivacyBudgetExceeded);
}

#[test]
fn accounting_is_deterministic_and_composes() {
    let s = spec(1, 3.0);
    let rho = s.rho(&s.charged[0]).unwrap();
    assert_eq!(rho, s.rho(&s.charged[0]).unwrap());
    let d = dir("compose");
    let mut rng = Csprng::from_os().unwrap();
    for r in 1..=3 {
        release(&spec(r, 3.0), &d, &[0; 16], &mut rng, &key()).unwrap();
    }
    let v = ledger::read(&d.join("gradient-a.ledger")).unwrap();
    let c = v.cost().unwrap();
    assert!((c.rho - 3.0 * rho).abs() < 1e-12);
    // Without per-unit clipping, a patient is charged for replacing a whole
    // contribution, like an organization (review finding DP-4); a sampled
    // (DP-SGD) patient, clipped per unit, for about half the swing.
    let mut org = spec(1, 3.0);
    org.charged[0].budget.unit = PrivacyUnit::Organization;
    assert_eq!(org.rho(&org.charged[0]).unwrap(), rho);
    let mut sampled = spec(1, 3.0);
    sampled.mechanism.sampling_rate = Some(0.01);
    assert!(sampled.rho(&sampled.charged[0]).unwrap() < rho / 3.5);
}

#[test]
fn concurrent_releases_cannot_double_spend() {
    let d = Arc::new(dir("race"));
    // A budget that affords exactly one release: between the cost of one
    // and of two (composition grows about as the square root).
    let s = spec(1, 1.0);
    let one = s.rho(&s.charged[0]).unwrap();
    let e1 = encompute_privacy::Cost::of(one, &budget(1.0))
        .unwrap()
        .epsilon;
    let e2 = encompute_privacy::Cost::of(2.0 * one, &budget(1.0))
        .unwrap()
        .epsilon;
    let eps = (e1 + e2) / 2.0;
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let d = d.clone();
            std::thread::spawn(move || {
                let mut rng = Csprng::from_os().unwrap();
                release(&spec(100 + i, eps), &d, &[0; 16], &mut rng, &key())
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let ok = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(ok, 1, "exactly one release fits the budget");
    for r in results.iter().filter_map(|r| r.as_ref().err()) {
        assert_eq!(r.code, Code::PrivacyBudgetExceeded);
    }
}

#[test]
fn duplicate_release_is_refused() {
    let d = dir("dup");
    let mut rng = Csprng::from_os().unwrap();
    release(&spec(1, 3.0), &d, &[0; 16], &mut rng, &key()).unwrap();
    let e = release(&spec(1, 3.0), &d, &[0; 16], &mut rng, &key()).unwrap_err();
    assert_eq!(e.code, Code::PrivacyLedger);
}

#[test]
fn tampering_rollback_and_reset_are_detected() {
    let d = dir("tamper");
    let mut rng = Csprng::from_os().unwrap();
    let mut seen = Checkpoint {
        seq: 0,
        root: String::new(),
    };
    for r in 1..=3 {
        let out = release(&spec(r, 3.0), &d, &[0; 16], &mut rng, &key()).unwrap();
        let rc = &out.receipts[0];
        seen = Checkpoint {
            seq: rc.ledger_seq,
            root: rc.ledger_root.clone(),
        };
    }
    let path = d.join("gradient-a.ledger");
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let v = ledger::read(&path).unwrap();
    v.extends(&seen).unwrap();
    let write = |ls: &[&str]| std::fs::write(&path, ls.join("\n") + "\n").unwrap();
    // Delete an event.
    let mut del = lines.clone();
    del.remove(2);
    write(&del);
    assert_eq!(ledger::read(&path).unwrap_err().code, Code::PrivacyLedger);
    // Reorder.
    let mut re = lines.clone();
    re.swap(1, 3);
    write(&re);
    assert_eq!(ledger::read(&path).unwrap_err().code, Code::PrivacyLedger);
    // Edit a cost (lower the sensitivity).
    write(
        &lines
            .iter()
            .map(|l| l.replace("\"sensitivity\":516", "\"sensitivity\":1"))
            .collect::<Vec<_>>()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    assert_eq!(ledger::read(&path).unwrap_err().code, Code::PrivacyLedger);
    // Roll back to after round 1: a valid chain, but not what was seen.
    write(&lines[..3]);
    let rolled = ledger::read(&path).unwrap();
    assert_eq!(rolled.extends(&seen).unwrap_err().code, Code::PrivacyLedger);
    // Reset: a fresh, empty ledger.
    std::fs::remove_file(&path).unwrap();
    // The coordinator starts over happily; the owner's checkpoint does not.
    let mut rng2 = Csprng::from_os().unwrap();
    release(&spec(9, 3.0), &d, &[0; 16], &mut rng2, &key()).unwrap();
    let fresh = ledger::read(&path).unwrap();
    assert_eq!(fresh.extends(&seen).unwrap_err().code, Code::PrivacyLedger);
    // Another asset's ledger does not stand in for this one.
    std::fs::copy(d.join("gradient-b.ledger"), &path).unwrap();
    let e = release(&spec(10, 3.0), &d, &[0; 16], &mut rng2, &key()).unwrap_err();
    assert_eq!(e.code, Code::PrivacyLedger);
}

#[test]
fn receipts_bind_output_ledger_and_parameters() {
    let d = dir("receipt");
    let mut rng = Csprng::from_os().unwrap();
    let out = release(&spec(1, 3.0), &d, &[5; 16], &mut rng, &key()).unwrap();
    let r = &out.receipts[0];
    let v = ledger::read(&d.join("gradient-a.ledger")).unwrap();
    let pk: String = key()
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    verify_privacy_receipt(r, Some(&pk), Some(&v), Some(&out.noisy)).unwrap();
    // Wrong output.
    let mut other = out.noisy.clone();
    other[0] += 1;
    assert_eq!(
        verify_privacy_receipt(r, None, None, Some(&other))
            .unwrap_err()
            .code,
        Code::PrivacyMechanism
    );
    // Tampered parameters (less noise claimed), or another asset.
    let mut t = r.clone();
    t.mechanism.noise_multiplier = 50.0;
    assert_eq!(
        verify_privacy_receipt(&t, None, None, None)
            .unwrap_err()
            .code,
        Code::PrivacyMechanism
    );
    let mut t = r.clone();
    t.asset_id = "gradient-b".into();
    assert!(verify_privacy_receipt(&t, None, None, None).is_err());
    // Another asset's ledger.
    let vb = ledger::read(&d.join("gradient-b.ledger")).unwrap();
    assert_eq!(
        verify_privacy_receipt(r, None, Some(&vb), None)
            .unwrap_err()
            .code,
        Code::PrivacyLedger
    );
    // A replayed old receipt does not match a later release.
    let later = release(&spec(2, 3.0), &d, &[5; 16], &mut rng, &key()).unwrap();
    assert!(verify_privacy_receipt(r, None, None, Some(&later.noisy)).is_err());
    // Untrusted signer.
    assert!(verify_privacy_receipt(r, Some(&"00".repeat(32)), None, None).is_err());
}

#[test]
fn invalid_budgets_and_mechanisms() {
    for (e, d) in [
        (0.0, 1e-6),
        (-1.0, 1e-6),
        (f64::NAN, 1e-6),
        (1.0, 0.0),
        (1.0, 1.0),
        (1.0, -0.1),
    ] {
        let b = PrivacyBudget {
            unit: PrivacyUnit::Record,
            epsilon: e,
            delta: d,
        };
        assert_eq!(
            b.validate().unwrap_err().code,
            Code::PrivacyPolicy,
            "{e} {d}"
        );
    }
    let mut s = spec(1, 1.0);
    s.mechanism.noise_multiplier = 0.0;
    assert!(
        encompute_privacy::sigma2(&s.mechanism, &s.codec).is_err(),
        "no noise, no release"
    );
}

/// Review finding DP-4 (ENC-SF-2026-068): without per-unit clipping (no Poisson sampling),
/// one patient's records can move a party's clipped contribution from one
/// side of the clipping ball to the other. The charged sensitivity must
/// cover that full swing, as for an organization; before the fix a
/// patient-level budget was charged half of it.
#[test]
fn an_unsampled_patient_is_charged_the_whole_contribution_swing() {
    let s = spec(1, 3.0);
    let m = &s.mechanism;
    // Two contributions, each clipped to clip_norm, pointing in opposite
    // directions: one patient's data decides which is sent.
    let d = s.vector_len;
    let c = m.clip_norm / (d as f64).sqrt();
    let x = vec![c; d];
    let y = vec![-c; d];
    let code = |v: &[f64]| -> Vec<f64> { v.iter().map(|&a| s.codec.encode(a) as f64).collect() };
    let (cx, cy) = (code(&x), code(&y));
    let moved = cx
        .iter()
        .zip(&cy)
        .map(|(a, b)| (a - b).powi(2))
        .sum::<f64>()
        .sqrt();
    let patient = encompute_privacy::sensitivity(&PrivacyUnit::Patient, m, &s.codec, d);
    let organization = encompute_privacy::sensitivity(&PrivacyUnit::Organization, m, &s.codec, d);
    assert!(
        moved <= patient as f64,
        "one patient moved the sum by {moved} but was charged sensitivity {patient}"
    );
    assert_eq!(patient, organization);
    // The receipt carries the charged sensitivity: a receipt claiming the
    // old, halved one is not this release's.
    let one = (m.clip_norm * s.codec.scale as f64).ceil() as u64 + 4;
    assert!(
        moved > one as f64,
        "the old sensitivity {one} did not cover {moved}"
    );
}

/// The charged sensitivity bounds how far the encoded sum can move when one
/// unit's data changes (the contributors fixed): codes of two vectors whose
/// L2 distance is at most k * clip_norm differ by at most the sensitivity,
/// whatever the encoding offset.
#[test]
fn sensitivity_bounds_the_encoded_difference() {
    let s = spec(1, 3.0);
    let u = || {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).unwrap();
        (u64::from_le_bytes(b) as f64 / u64::MAX as f64) * 2.0 - 1.0
    };
    let mut sampled = s.mechanism.clone();
    sampled.sampling_rate = Some(0.01);
    for (unit, mechanism, k) in [
        // DP-SGD: the attested workload clips each sampled patient.
        (PrivacyUnit::Patient, &sampled, 1.0),
        // Unsampled: only the party's whole contribution is clipped.
        (PrivacyUnit::Patient, &s.mechanism, 2.0),
        (PrivacyUnit::Organization, &s.mechanism, 2.0),
    ] {
        let delta = encompute_privacy::sensitivity(&unit, mechanism, &s.codec, s.vector_len);
        for _ in 0..2000 {
            // x in the clip box; x' = x + v with |v| <= k * clip_norm; the
            // codec clips each coordinate.
            let x: Vec<f64> = (0..s.vector_len).map(|_| u()).collect();
            let mut v: Vec<f64> = (0..s.vector_len).map(|_| u()).collect();
            let n = v.iter().map(|a| a * a).sum::<f64>().sqrt();
            let r = k * s.mechanism.clip_norm * u().abs();
            v.iter_mut().for_each(|a| *a *= r / n);
            let code = |y: f64| s.codec.encode(y) as f64;
            let d2: f64 = x
                .iter()
                .zip(&v)
                .map(|(a, b)| (code(a + b) - code(*a)).powi(2))
                .sum();
            assert!(d2.sqrt() <= delta as f64, "{} > {delta}", d2.sqrt());
        }
    }
}

/// Review finding DP-4: without sampling a patient is charged twice the
/// clip norm, so a named level uses twice its listed noise for it. The
/// release samples and charges that one effective noise, and each release
/// then costs what it did when a patient was (wrongly) charged one clip
/// norm at the listed noise: a level's budget affords about as many
/// releases as before. An organization's noise and cost are unchanged.
#[test]
fn preset_levels_charge_their_effective_noise() {
    use encompute_ir::confidentiality::{privacy_preset, PRIVACY_PRESETS};
    use encompute_privacy::accountant::gaussian_rho;
    let base = spec(1, 3.0);
    for (name, _, _, listed) in PRIVACY_PRESETS {
        for unit in [PrivacyUnit::Patient, PrivacyUnit::Organization] {
            let (budget, mechanism) = privacy_preset(name, unit.clone()).unwrap();
            let organization = unit == PrivacyUnit::Organization;
            let s = ReleaseSpec {
                mechanism: mechanism.clone(),
                charged: vec![Charged {
                    asset_id: "gradient-a".into(),
                    budget: budget.clone(),
                    scoped: None,
                }],
                ..base.clone()
            };
            let rho = s.rho(&s.charged[0]).unwrap();
            // Before the fix: the listed noise, and a patient's
            // sensitivity one clip norm (an organization's two). Within 2%:
            // the rounding term does not scale with k.
            let listed_mech = DpMechanism {
                noise_multiplier: listed,
                preset: None,
                ..mechanism.clone()
            };
            let r = (s.vector_len as f64).sqrt().ceil() as u64;
            let k = if organization { 2.0 } else { 1.0 };
            let old_sensitivity = (k * s.codec.scale as f64).ceil() as u64 + r;
            let old = gaussian_rho(
                old_sensitivity,
                release::sigma2(&listed_mech, &s.codec).unwrap(),
            )
            .unwrap();
            assert!(
                (rho - old).abs() <= 0.02 * old,
                "{name} {unit}: rho {rho} vs pre-fix {old}"
            );
            let n = ledger::affordable(rho, None, &budget).unwrap();
            let n_old = ledger::affordable(old, None, &budget).unwrap();
            assert!(
                n.abs_diff(n_old) <= 1,
                "{name} {unit}: {n} vs pre-fix {n_old}"
            );
            // About ten releases of a patient-level budget, 2.5 of an
            // organization's (the level's documented meaning).
            let expected = if organization { 2..=3 } else { 9..=13 };
            assert!(expected.contains(&n), "{name} {unit}: {n} releases");
            // Without the compensation a patient would pay about 4x.
            if !organization {
                let uncompensated = gaussian_rho(
                    encompute_privacy::sensitivity(&unit, &listed_mech, &s.codec, s.vector_len),
                    release::sigma2(&listed_mech, &s.codec).unwrap(),
                )
                .unwrap();
                assert!(uncompensated > 3.5 * rho, "{name}");
            }
        }
    }
    // The release itself samples and charges the effective noise, and its
    // receipt names the level.
    let d = dir("preset-effective");
    let (budget, mechanism) = privacy_preset("strong", PrivacyUnit::Patient).unwrap();
    assert_eq!(mechanism.noise_multiplier, 12.0);
    let s = ReleaseSpec {
        mechanism: mechanism.clone(),
        charged: vec![Charged {
            asset_id: "gradient-a".into(),
            budget,
            scoped: None,
        }],
        ..base
    };
    let mut rng = Csprng::from_os().unwrap();
    let out = release(&s, &d, &[0; 16], &mut rng, &key()).unwrap();
    let receipt = &out.receipts[0];
    assert_eq!(receipt.mechanism, mechanism);
    assert_eq!(receipt.mechanism.preset.as_deref(), Some("strong"));
    assert_eq!(
        receipt.sigma2,
        release::sigma2(&mechanism, &s.codec).unwrap()
    );
    let rho = s.rho(&s.charged[0]).unwrap();
    assert_eq!(receipt.rho_cost.parse::<f64>().unwrap(), rho);
}
