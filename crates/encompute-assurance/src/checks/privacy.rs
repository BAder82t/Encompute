//! Differential-privacy accounting under attack and failure: multi-parent
//! atomicity, crash injection at every step of the release transaction,
//! multi-process double spending, ledger tampering, and every-field
//! receipt mutation.

use std::path::{Path, PathBuf};
use std::process::Command;

use ed25519_dalek::SigningKey;
use encompute_ir::confidentiality::{
    DpKind, DpMechanism, FixedPointCodec, PrivacyBudget, PrivacyUnit,
};
use encompute_ir::Code;
use encompute_privacy::{
    ledger, release, verify_privacy_receipt, Charged, Cost, Csprng, LedgerView, PrivacyEvent,
    PrivacyReceipt, ReleaseSpec,
};

use crate::{ensure, mutate, CheckResult, Outcome, Scale};

pub const VECTOR_LEN: usize = 8;

/// A release of round `round` charged to `assets` (name, epsilon budget).
pub fn spec(round: u64, assets: &[(&str, f64)]) -> ReleaseSpec {
    ReleaseSpec {
        round_id: format!("{round:064x}"),
        output: "global_gradient".into(),
        policy_id: Some("aa".repeat(32)),
        privacy_policy_id: "bb".repeat(32),
        execution_spec_id: None,
        mechanism: DpMechanism {
            kind: DpKind::DiscreteGaussian,
            clip_norm: 1.0,
            noise_multiplier: 5.0,
            sampling_rate: None,
        },
        codec: FixedPointCodec {
            clip_min: -1.0,
            clip_max: 1.0,
            scale: 256,
            modulus_bits: 32,
        },
        vector_len: VECTOR_LEN,
        charged: assets
            .iter()
            .map(|(a, e)| Charged {
                asset_id: (*a).into(),
                budget: PrivacyBudget {
                    unit: PrivacyUnit::Patient,
                    epsilon: *e,
                    delta: 1e-6,
                },
            })
            .collect(),
    }
}

pub fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

/// Epsilon of `k` releases of [`spec`] against one asset.
pub fn epsilon_of(k: u32) -> f64 {
    let s = spec(0, &[("a", 1.0)]);
    let one = s.rho(&s.charged[0]).expect("rho");
    Cost::of(k as f64 * one, &s.charged[0].budget)
        .expect("cost")
        .epsilon
}

/// A budget that affords exactly `k` releases.
pub fn affording(k: u32) -> f64 {
    (epsilon_of(k) + epsilon_of(k + 1)) / 2.0
}

fn view(dir: &Path, asset: &str) -> Option<LedgerView> {
    let p = dir.join(format!("{asset}.ledger"));
    p.exists().then(|| ledger::read(&p).expect("ledger reads"))
}

fn reserves(v: &LedgerView) -> usize {
    v.entries
        .iter()
        .filter(|e| matches!(e.event, PrivacyEvent::Reserve { .. }))
        .count()
}

fn commits(v: &LedgerView) -> usize {
    v.entries.len() - reserves(v)
}

/// INV-069: a release charged to several assets is all-or-nothing. When
/// any one asset cannot afford it, no asset is charged, whichever position
/// the poor asset sorts to.
pub fn multi_parent_atomicity(scale: Scale) -> CheckResult {
    let parents = scale.pick(4, 12);
    let mut rng = Csprng::from_os().map_err(|e| e.to_string())?;
    let mut cases = 0;
    for poor in 0..parents {
        let d = crate::scratch("atomic");
        let names: Vec<String> = (0..parents).map(|i| format!("asset-{i:02}")).collect();
        // Everyone affords 3 releases except `poor`, which affords 1.
        let assets: Vec<(&str, f64)> = names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.as_str(), affording(if i == poor { 1 } else { 3 })))
            .collect();
        release(&spec(1, &assets), &d, &[0; VECTOR_LEN], &mut rng, &key())
            .map_err(|e| format!("the first release was refused: {e}"))?;
        let e = release(&spec(2, &assets), &d, &[0; VECTOR_LEN], &mut rng, &key())
            .err()
            .ok_or("a release exceeding one parent's budget was allowed")?;
        ensure!(
            e.code == Code::PrivacyBudgetExceeded,
            "denied with {:?}, not a budget error",
            e.code
        );
        for n in &names {
            let v = view(&d, n).ok_or("ledger missing")?;
            ensure!(
                v.entries.len() == 2,
                "{n} (poor parent at {poor}) has {} entries after a denied release: a partial \
                 charge",
                v.entries.len()
            );
        }
        // A release charged only to the rich parents still goes through.
        let rich: Vec<(&str, f64)> = assets
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != poor)
            .map(|(_, a)| *a)
            .collect();
        release(&spec(3, &rich), &d, &[0; VECTOR_LEN], &mut rng, &key())
            .map_err(|e| format!("an affordable release was refused: {e}"))?;
        cases += 1;
        let _ = std::fs::remove_dir_all(&d);
    }
    Ok(Outcome::new(cases).note(format!("{parents} parents, each in turn the poor one")))
}

/// Failpoints in the release transaction, in order.
pub const FAILPOINTS: &[&str] = &[
    "after-lock",
    "after-reserve",
    "during-noise",
    "before-commit",
    "after-first-commit",
];

/// The crash and race child process (the `assurance-helper` example).
pub fn helper() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("ENCOMPUTE_ASSURANCE_HELPER") {
        return Ok(p.into());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let name = format!("assurance-helper{}", std::env::consts::EXE_SUFFIX);
    for dir in exe.ancestors().skip(1).take(3) {
        let p = dir.join("examples").join(&name);
        if p.exists() {
            return Ok(p);
        }
    }
    Err(format!(
        "{name} not found: build it with `cargo build -p encompute-assurance --examples` or set \
         ENCOMPUTE_ASSURANCE_HELPER"
    ))
}

/// Runs one release in a child process: `release <dir> <round> <asset=eps>...`.
/// It writes `<dir>/out-<round>.json` only after the release returns.
fn child(dir: &Path, round: u64, assets: &[(&str, f64)], failpoint: Option<&str>) -> Command {
    let mut c = Command::new(helper().expect("helper"));
    c.arg("release").arg(dir).arg(round.to_string());
    for (a, e) in assets {
        c.arg(format!("{a}={e:?}"));
    }
    match failpoint {
        Some(f) => c.env("ENCOMPUTE_FAILPOINT", f),
        None => c.env_remove("ENCOMPUTE_FAILPOINT"),
    };
    c
}

/// INV-070: a crash at any point of a release leaves every ledger valid,
/// never an unaccounted output: an output exists only if every charged
/// ledger committed it, and a reservation without its commit stays charged
/// (the crashed round cannot be replayed to spend again).
pub fn crash_injection(scale: Scale) -> CheckResult {
    helper()?;
    let reps = scale.pick(1, 5);
    let assets = [("crash-a", affording(4)), ("crash-b", affording(4))];
    let mut cases = 0;
    for fp in FAILPOINTS {
        for _ in 0..reps {
            let d = crate::scratch("crash");
            // One committed round first, so the crash is not on a fresh file.
            let ok = child(&d, 1, &assets, None)
                .status()
                .map_err(|e| e.to_string())?;
            ensure!(ok.success(), "the helper failed without a failpoint");
            let st = child(&d, 2, &assets, Some(fp))
                .status()
                .map_err(|e| e.to_string())?;
            ensure!(!st.success(), "failpoint {fp} did not crash the helper");
            let output = d.join("out-2.json").exists();
            ensure!(
                !output,
                "{fp}: an output survived a crash inside the release"
            );
            let mut charged = vec![];
            for (a, _) in &assets {
                let v = view(&d, a).ok_or("ledger missing")?;
                v.verify()
                    .map_err(|e| format!("{fp}: the ledger is invalid after a crash: {e}"))?;
                charged.push(reserves(&v));
                // Committed entries never outnumber reservations.
                ensure!(commits(&v) <= reserves(&v), "{fp}: commit without reserve");
            }
            // Before the reservations nothing is charged; after, every
            // ledger is.
            let want = if *fp == "after-lock" { 1 } else { 2 };
            ensure!(
                charged.iter().all(|&c| c == want),
                "{fp}: reservations {charged:?}, expected {want} in every ledger"
            );
            // Restart: the crashed round cannot be run again (its
            // reservation stands), a new round can.
            let again = child(&d, 2, &assets, None)
                .output()
                .map_err(|e| e.to_string())?;
            if want == 2 {
                ensure!(
                    !again.status.success(),
                    "{fp}: the crashed round ran again after restart"
                );
            }
            let next = child(&d, 3, &assets, None)
                .status()
                .map_err(|e| e.to_string())?;
            ensure!(next.success(), "{fp}: the ledger is unusable after a crash");
            cases += 1;
            let _ = std::fs::remove_dir_all(&d);
        }
    }
    Ok(Outcome::new(cases).note(format!("failpoints: {}", FAILPOINTS.join(", "))))
}

/// INV-065: concurrent releases from separate processes cannot spend the
/// same budget twice.
pub fn multi_process_double_spend(scale: Scale) -> CheckResult {
    helper()?;
    let workers = scale.pick(8, 100);
    let afford = 2;
    let d = crate::scratch("race");
    let assets = [("race-a", affording(afford)), ("race-b", affording(afford))];
    let kids: Vec<_> = (0..workers as u64)
        .map(|i| {
            child(&d, 100 + i, &assets, None)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|e| e.to_string())
        })
        .collect::<Result<_, _>>()?;
    let mut ok = 0;
    for mut k in kids {
        if k.wait().map_err(|e| e.to_string())?.success() {
            ok += 1;
        }
    }
    ensure!(
        ok == afford as usize,
        "{ok} of {workers} concurrent releases succeeded; the budget affords {afford}"
    );
    for (a, _) in &assets {
        let v = view(&d, a).ok_or("ledger missing")?;
        v.verify().map_err(|e| e.to_string())?;
        ensure!(
            reserves(&v) == afford as usize && commits(&v) == afford as usize,
            "{a}: {} reservations, {} commits",
            reserves(&v),
            commits(&v)
        );
        ensure!(
            v.cost().map_err(|e| e.to_string())?.epsilon <= affording(afford),
            "{a} is over budget"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
    Ok(Outcome::new(workers).note(format!("{workers} processes, budget for {afford}")))
}

/// INV-066: every structural edit of a ledger file is refused (or, for a
/// rollback, caught by a later checkpoint).
pub fn ledger_tampering(_: Scale) -> CheckResult {
    let d = crate::scratch("tamper");
    let assets = [("tamper-a", affording(6))];
    let mut rng = Csprng::from_os().map_err(|e| e.to_string())?;
    let mut seen = None;
    for r in 1..=3 {
        let out = release(&spec(r, &assets), &d, &[1; VECTOR_LEN], &mut rng, &key())
            .map_err(|e| e.to_string())?;
        seen = Some(out.receipts[0].clone());
    }
    let seen = seen.expect("released");
    let cp = encompute_privacy::Checkpoint {
        seq: seen.ledger_seq,
        root: seen.ledger_root.clone(),
    };
    let path = d.join("tamper-a.ledger");
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let n = lines.len();
    // A reservation line and a commit line.
    let (res, com) = (1, 2);
    let mut edits: Vec<(&str, Vec<String>)> = vec![];
    let mut e = lines.clone();
    e.insert(res + 1, lines[res].clone());
    edits.push(("duplicate reservation", e));
    let mut e = lines.clone();
    e.insert(com + 1, lines[com].clone());
    edits.push(("duplicate commit", e));
    let mut e = lines.clone();
    e.remove(res);
    edits.push(("commit without its reservation", e));
    let mut e = lines.clone();
    e.swap(res, com);
    edits.push(("commit before reservation", e));
    let mut e = lines.clone();
    e.remove(n - 2);
    edits.push(("deleted reservation", e));
    let mut e = lines.clone();
    e[com] = e[com].replace("\"seq\":2", "\"seq\":9");
    edits.push(("renumbered", e));
    let mut e = lines.clone();
    e[res] = e[res].replace("\"sigma2\":", "\"sigma2\":9");
    edits.push(("more noise claimed", e));
    let mut e = lines.clone();
    e[0] = e[0].replace("\"epsilon\":", "\"epsilon\":9");
    edits.push(("budget raised in the genesis", e));
    let mut e = lines.clone();
    let half = e[n - 1].len() / 2;
    e[n - 1].truncate(half);
    edits.push(("torn last line", e));
    let mut e = lines.clone();
    e.push("garbage".into());
    edits.push(("trailing garbage", e));
    let mut e = lines.clone();
    e.insert(1, lines[n - 1].clone());
    edits.push(("entry moved to the front", e));
    edits.push(("genesis only (reset)", lines[..1].to_vec()));
    let mut cases = 0;
    for (what, ls) in &edits {
        std::fs::write(&path, ls.join("\n") + "\n").map_err(|e| e.to_string())?;
        let refused = match ledger::read(&path) {
            Err(_) => true,
            // A valid-looking chain must still fail the owner's checkpoint.
            Ok(v) => v.extends(&cp).is_err(),
        };
        ensure!(refused, "ledger edit '{what}' was accepted");
        // And the coordinator cannot release on it.
        let next = release(&spec(50, &assets), &d, &[1; VECTOR_LEN], &mut rng, &key());
        if next.is_ok() {
            // Only acceptable when the file is a valid chain (a reset
            // restarts accounting); the owner's checkpoint then refuses it.
            let v = ledger::read(&path).map_err(|e| e.to_string())?;
            ensure!(
                v.extends(&cp).is_err(),
                "a release ran on the tampered ledger '{what}' undetected"
            );
        }
        cases += 1;
    }
    let _ = std::fs::remove_dir_all(&d);
    Ok(Outcome::new(cases))
}

/// INV-068: changing any field of a privacy receipt breaks it.
pub fn receipt_mutation(_: Scale) -> CheckResult {
    let d = crate::scratch("dpreceipt");
    let assets = [("receipt-a", affording(3))];
    let mut rng = Csprng::from_os().map_err(|e| e.to_string())?;
    let out = release(&spec(1, &assets), &d, &[3; VECTOR_LEN], &mut rng, &key())
        .map_err(|e| e.to_string())?;
    let r = &out.receipts[0];
    let v = ledger::read(&d.join("receipt-a.ledger")).map_err(|e| e.to_string())?;
    let pk = r.signer_key.clone();
    verify_privacy_receipt(r, Some(&pk), Some(&v), Some(&out.noisy))
        .map_err(|e| format!("the honest receipt fails: {e}"))?;
    let json = serde_json::to_value(r).map_err(|e| e.to_string())?;
    let (n, bad) = mutate::accepted(&json, &[], |m| {
        serde_json::from_value::<PrivacyReceipt>(m.clone())
            .ok()
            .is_some_and(|m| {
                verify_privacy_receipt(&m, Some(&pk), Some(&v), Some(&out.noisy)).is_ok()
            })
    });
    ensure!(bad.is_empty(), "mutated privacy receipts accepted: {bad:?}");
    let _ = std::fs::remove_dir_all(&d);
    Ok(Outcome::new(n))
}

/// INV-061: the discrete Gaussian sampler has mean 0 and variance at most
/// (and close to) sigma^2, at several scales.
pub fn sampler_statistics(scale: Scale) -> CheckResult {
    let n = scale.pick(20_000, 400_000);
    let mut rng = Csprng::from_os().map_err(|e| e.to_string())?;
    let mut cases = 0;
    for s2 in [1u64, 25, 10_000, 1 << 20] {
        let xs: Vec<f64> = (0..n)
            .map(|_| encompute_privacy::discrete_gaussian(s2, &mut rng).map(|x| x as f64))
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        let mean = xs.iter().sum::<f64>() / n as f64;
        let var = xs.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / n as f64;
        let sd = (s2 as f64).sqrt();
        ensure!(
            mean.abs() < 6.0 * sd / (n as f64).sqrt(),
            "sigma^2 {s2}: mean {mean}"
        );
        // Variance of the sample variance ~ 2 sigma^4 / n.
        let tol = 6.0 * (2.0f64).sqrt() * s2 as f64 / (n as f64).sqrt();
        ensure!(
            (var - s2 as f64).abs() < tol.max(0.05 * s2 as f64),
            "sigma^2 {s2}: variance {var}"
        );
        cases += n;
    }
    Ok(Outcome::new(cases))
}

/// INV-062: no release without noise; negligible noise is charged at its
/// true (prohibitive) cost, so it is denied rather than under-accounted.
pub fn invalid_noise(_: Scale) -> CheckResult {
    let mut cases = 0;
    for nm in [0.0, -1.0, f64::NAN, f64::INFINITY, 1e-12] {
        let mut s = spec(1, &[("n", 8.0)]);
        s.mechanism.noise_multiplier = nm;
        ensure!(
            nm == 1e-12 || encompute_privacy::sigma2(&s.mechanism, &s.codec).is_err(),
            "noise multiplier {nm} accepted"
        );
        let d = crate::scratch("noise");
        let mut rng = Csprng::from_os().map_err(|e| e.to_string())?;
        ensure!(
            release(&s, &d, &[0; VECTOR_LEN], &mut rng, &key()).is_err(),
            "released with noise multiplier {nm}"
        );
        ensure!(
            !d.join("n.ledger").exists() || view(&d, "n").is_some_and(|v| v.entries.is_empty()),
            "a refused release charged the ledger"
        );
        let _ = std::fs::remove_dir_all(&d);
        cases += 1;
    }
    Ok(Outcome::new(cases))
}

/// INV-131: the Rényi DP accountant for Poisson-sampled releases is
/// conservative and consistent over random parameters:
/// - sampling never costs more than releasing to everyone, and each order's
///   curve stays in `[0, alpha * rho]`;
/// - more steps, a higher sampling rate or less noise never cost less;
/// - composing `n` copies equals scaling one curve by `n`;
/// - the affordable number of releases is exactly the budget's boundary.
pub fn rdp_accountant_properties(scale: Scale) -> CheckResult {
    use encompute_ir::confidentiality::{PrivacyBudget, PrivacyUnit};
    use encompute_privacy::ledger::{affordable, cost_of};
    use encompute_privacy::rdp::{compose, epsilon, release_curve, scaled, ORDERS};
    let n = scale.pick(40, 400);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state >> 11) as f64 / (1u64 << 53) as f64
    };
    for _ in 0..n {
        let z = 0.6 + 4.0 * next();
        let rho = 1.0 / (2.0 * z * z);
        let q = 10f64.powf(-3.0 + 2.9 * next()).min(0.9);
        let steps = 1 + (next() * 500.0) as u64;
        let delta = 10f64.powf(-5.0 - 3.0 * next());
        let curve = release_curve(rho, Some(q));
        for (i, &a) in ORDERS.iter().enumerate() {
            ensure!(
                curve[i] >= 0.0
                    && curve[i] <= (a as f64 * rho).next_up().next_up().next_up().next_up(),
                "order {a}: {} outside [0, {}] (z {z}, q {q})",
                curve[i],
                a as f64 * rho
            );
        }
        let e = epsilon(&scaled(&curve, steps), delta);
        let full = epsilon(&scaled(&release_curve(rho, None), steps), delta);
        ensure!(
            e.is_finite() && e > 0.0 && e <= full,
            "z {z} q {q} steps {steps}: {e} > {full}"
        );
        ensure!(
            epsilon(&scaled(&curve, steps + 1), delta) >= e,
            "one more step cost less (z {z}, q {q})"
        );
        let q2 = (q * 1.5).min(0.95);
        ensure!(
            epsilon(&scaled(&release_curve(rho, Some(q2)), steps), delta) >= e,
            "a higher sampling rate cost less (z {z}, q {q})"
        );
        let rho2 = 1.0 / (2.0 * (z * 1.2) * (z * 1.2));
        ensure!(
            epsilon(&scaled(&release_curve(rho2, Some(q)), steps), delta) <= e,
            "more noise cost more (z {z}, q {q})"
        );
        let k = 1 + steps % 7;
        let composed = compose(&vec![curve; k as usize]);
        let s = scaled(&curve, k);
        ensure!(
            composed
                .iter()
                .zip(&s)
                .all(|(a, b)| (a - b).abs() <= 1e-12 * a.abs().max(1e-12)),
            "composition differs from scaling"
        );
    }
    // The affordable count is the boundary.
    for (z, q, eps) in [(1.2, 0.01, 3.0), (1.0, 0.05, 8.0), (1.5, 0.002, 1.0)] {
        let rho = 1.0 / (2.0 * z * z);
        let b = PrivacyBudget {
            unit: PrivacyUnit::Patient,
            epsilon: eps,
            delta: 1e-6,
        };
        let k = affordable(rho, Some(q), &b).map_err(|e| e.to_string())? as usize;
        let at = cost_of(&vec![(rho, Some(q)); k], &b).map_err(|e| e.to_string())?;
        let over = cost_of(&vec![(rho, Some(q)); k + 1], &b).map_err(|e| e.to_string())?;
        ensure!(
            at.epsilon <= eps
                && (over.epsilon > eps || k as u64 == encompute_privacy::ledger::MAX_AFFORDABLE),
            "z {z} q {q}: {k} releases is not the boundary"
        );
    }
    Ok(Outcome::new(n))
}
