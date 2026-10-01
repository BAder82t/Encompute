//! Fuzz smoke tests for privacy ledgers and events: mutated ledger files
//! and mutated events (as the control plane receives them) never panic,
//! and an accepted ledger never reports a NaN or negative cost. Resource
//! limits: oversized ledgers, huge lines, deep JSON and out-of-range
//! numbers are typed errors.

#[path = "../../encompute-ir/tests/fuzz_support/mod.rs"]
mod fuzz_support;

use std::path::PathBuf;
use std::time::Duration;

use encompute_ir::confidentiality::{DpKind, DpMechanism, PrivacyBudget, PrivacyUnit};
use encompute_ir::Code;
use encompute_privacy::{ledger, Genesis, Ledger, LedgerView, PrivacyEvent, PrivacyReceipt};
use fuzz_support::{run, within};

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("encompute-dp-fuzz-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn genesis() -> Genesis {
    Genesis {
        version: 1,
        asset_id: "patients".into(),
        budget: PrivacyBudget {
            unit: PrivacyUnit::Patient,
            epsilon: 3.0,
            delta: 1e-6,
        },
        privacy_policy_id: "f".repeat(64),
        scoping: None,
    }
}

fn reserve(i: usize, sampling_rate: Option<f64>) -> PrivacyEvent {
    PrivacyEvent::Reserve {
        event_id: format!("evt_{i}"),
        policy_id: None,
        execution_spec_id: None,
        round_id: Some(format!("round_{i}")),
        output: "global_gradient".into(),
        mechanism: DpMechanism {
            kind: DpKind::DiscreteGaussian,
            clip_norm: 1.0,
            noise_multiplier: 5.0,
            sampling_rate,
            preset: None,
        },
        sensitivity: 4096,
        sigma2: 1 << 30,
        vector_len: 16,
        rng: "csprng".into(),
        scope: None,
    }
}

fn commit(i: usize) -> PrivacyEvent {
    PrivacyEvent::Commit {
        event_id: format!("evt_{i}"),
        output_commitment: "0".repeat(64),
    }
}

/// A valid ledger file with sampled and unsampled releases.
fn ledger_file(name: &str) -> Vec<u8> {
    let d = dir(name);
    let p = d.join("a.ledger");
    let mut l = Ledger::open(&p, &genesis()).unwrap();
    for (i, q) in [None, Some(0.01), None].into_iter().enumerate() {
        l.append(reserve(i, q)).unwrap();
        l.append(commit(i)).unwrap();
    }
    std::fs::read(&p).unwrap()
}

fn assert_sane(v: &LedgerView) {
    if let Ok(c) = v.cost() {
        assert!(c.epsilon >= 0.0 && c.rho >= 0.0, "{c:?}");
    }
    if let Ok(c) = v.check(0.01, Some(0.5)) {
        assert!(
            c.epsilon >= 0.0 && c.epsilon <= v.genesis.budget.epsilon,
            "{c:?}"
        );
    }
}

#[test]
fn mutated_ledger_files_never_panic() {
    let d = dir("files");
    let path = d.join("x.ledger");
    run(
        "ledger-file",
        &[ledger_file("seed-files")],
        3000,
        Duration::from_secs(2),
        |bytes| {
            std::fs::write(&path, bytes).unwrap();
            if let Ok(v) = ledger::read(&path) {
                assert_sane(&v);
            }
        },
    );
}

#[test]
fn mutated_events_never_panic() {
    // Events as the control plane receives them: checked against the
    // budget, then appended (which verifies the chain).
    let base = LedgerView {
        genesis: genesis(),
        entries: vec![],
    };
    let (base, _) = base.append_event(reserve(0, Some(0.01))).unwrap();
    let seeds: Vec<Vec<u8>> = [reserve(1, None), reserve(2, Some(0.02)), commit(0)]
        .iter()
        .map(|e| serde_json::to_vec(e).unwrap())
        .collect();
    run(
        "ledger-event",
        &seeds,
        5000,
        Duration::from_secs(2),
        |bytes| {
            let Ok(event) = serde_json::from_slice::<PrivacyEvent>(bytes) else {
                return;
            };
            if let PrivacyEvent::Reserve { mechanism, .. } = &event {
                if let Ok(rho) = event.rho() {
                    let _ = base.check(rho, mechanism.sampling_rate);
                }
            }
            if let Ok((next, _)) = base.append_event(event) {
                assert_sane(&next);
            }
        },
    );
}

#[test]
fn mutated_receipts_never_panic() {
    let seed = serde_json::json!({
        "version": 1, "asset_id": "patients", "round_id": "r", "output": "o",
        "event_id": "evt_0", "privacy_policy_id": "f", "policy_id": null,
        "execution_spec_id": null, "mechanism": {"kind": "discrete_gaussian",
        "clip_norm": "1.0", "noise_multiplier": "5.0"}, "unit": "patient",
        "sensitivity": 1, "sigma2": 2, "rho_cost": "0.1", "epsilon_cost": "0.1",
        "cumulative_rho": "0.1", "cumulative_epsilon": "0.1", "delta": "1e-6",
        "budget_epsilon": "3.0", "output_commitment": "0", "ledger_seq": 18446744073709551615u64,
        "ledger_root": "0", "rng": "csprng", "signer_key": "00", "signature": "00"
    });
    let view = ledger::read(&{
        let p = dir("receipts").join("a.ledger");
        std::fs::write(&p, ledger_file("seed-receipts")).unwrap();
        p
    })
    .unwrap();
    run(
        "privacy-receipt",
        &[serde_json::to_vec(&seed).unwrap()],
        3000,
        Duration::from_secs(1),
        |bytes| {
            if let Ok(r) = serde_json::from_slice::<PrivacyReceipt>(bytes) {
                let _ =
                    encompute_privacy::verify_privacy_receipt(&r, None, Some(&view), Some(&[1]));
            }
        },
    );
}

/// Regression: a reservation with a sampling rate outside (0, 1) reached
/// the accountant's assertion and panicked the control plane's request
/// thread (and any reader of a ledger holding it).
#[test]
fn out_of_range_sampling_rates_are_refused() {
    let view = LedgerView {
        genesis: genesis(),
        entries: vec![],
    };
    for q in [5.0, 1.0, 0.0, -0.5, 1e300] {
        let e = view.check(0.01, Some(q)).unwrap_err();
        assert_eq!(e.code, Code::PrivacyMechanism, "{q}: {e}");
        // Appended anyway (the chain itself is valid): accounting refuses.
        let (next, _) = view.append_event(reserve(0, Some(q))).unwrap();
        assert_eq!(next.cost().unwrap_err().code, Code::PrivacyMechanism);
    }
    for rho in [f64::NAN, f64::INFINITY, -1.0] {
        assert_eq!(
            view.check(rho, None).unwrap_err().code,
            Code::PrivacyMechanism
        );
    }
    // Enormous but finite costs are simply over budget.
    let e = view.check(f64::MAX, Some(0.5)).unwrap_err();
    assert_eq!(e.code, Code::PrivacyBudgetExceeded, "{e}");
    let e = view.check(f64::MAX, None).unwrap_err();
    assert_eq!(e.code, Code::PrivacyBudgetExceeded, "{e}");
}

#[test]
fn oversized_and_malformed_ledgers_are_typed_errors() {
    let d = dir("limits");
    let p = d.join("big.ledger");
    // Above the 64 MiB limit: refused before reading. Regression: a
    // reader loaded the whole (here 2 GiB, sparse) file first.
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(2 << 30).unwrap();
    drop(f);
    let e = within(Duration::from_secs(1), || ledger::read(&p)).unwrap_err();
    assert_eq!(e.code, Code::PrivacyLedger, "{e}");
    let g = serde_json::to_string(&genesis()).unwrap();
    for body in [
        String::new(),
        "\n".into(),
        fuzz_support::nested_json(100_000, ""),
        format!("{g}\n{}", fuzz_support::nested_json(100_000, "")),
        format!("{g}\n{{\"seq\":18446744073709551616}}"),
        format!("{g}\n{{\"seq\":-1}}"),
        format!("{g}\n{}", "x".repeat(8 << 20)),
        g.replace("\"3.0\"", "\"NaN\""),
        g.replace("\"1e-6\"", "\"1e-999\""),
    ] {
        std::fs::write(&p, &body).unwrap();
        let e = within(Duration::from_secs(5), || ledger::read(&p)).unwrap_err();
        assert!(
            matches!(e.code, Code::PrivacyLedger | Code::PrivacyPolicy),
            "{e}"
        );
    }
    std::fs::write(&p, b"\xff\xfe\n").unwrap();
    assert_eq!(ledger::read(&p).unwrap_err().code, Code::PrivacyLedger);
    // A checkpoint claiming 2^64-1 entries is a rollback, not a panic.
    let v = LedgerView {
        genesis: genesis(),
        entries: vec![],
    };
    let e = v
        .extends(&encompute_privacy::Checkpoint {
            seq: u64::MAX,
            root: "0".repeat(64),
        })
        .unwrap_err();
    assert_eq!(e.code, Code::PrivacyLedger);
}
