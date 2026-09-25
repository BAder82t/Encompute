//! The assurance suite on every pull request: each check at quick scale,
//! the catalog's integrity, and the gate itself (a violated invariant fails
//! the report).

use std::path::PathBuf;

use encompute_assurance::catalog::{Invariant, Kind, INVARIANTS};
use encompute_assurance::checks::{Check, CHECKS};
use encompute_assurance::{mutate, report, run_check, Outcome, Scale};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn check(name: &str) {
    let c = encompute_assurance::checks::find(name).expect("check exists");
    if let Err(v) = run_check(c, Scale::Quick) {
        panic!("{name}: {v}");
    }
}

#[test]
fn execution_receipt_mutation() {
    check("execution_receipt_mutation");
}

#[test]
fn secagg_sum_sweep() {
    check("secagg_sum_sweep");
}

#[test]
fn secagg_collusion_bound() {
    check("secagg_collusion_bound");
}

#[test]
fn secagg_coordinator_sees_no_input() {
    check("secagg_coordinator_sees_no_input");
}

#[test]
fn dp_sampler_statistics() {
    check("dp_sampler_statistics");
}

#[test]
fn dp_invalid_noise() {
    check("dp_invalid_noise");
}

#[test]
fn dp_multi_parent_atomicity() {
    check("dp_multi_parent_atomicity");
}

#[test]
fn dp_ledger_tampering() {
    check("dp_ledger_tampering");
}

#[test]
fn dp_receipt_mutation() {
    check("dp_receipt_mutation");
}

#[test]
fn dp_crash_injection() {
    check("dp_crash_injection");
}

#[test]
fn dp_multi_process_double_spend() {
    check("dp_multi_process_double_spend");
}

#[test]
fn every_check_has_a_test_here() {
    let me = include_str!("assurance.rs");
    for c in CHECKS {
        assert!(
            me.contains(&format!("fn {}()", c.name)),
            "{} has no test",
            c.name
        );
    }
}

/// IDs are unique and well formed, every reference resolves, and every
/// check backs some invariant.
#[test]
fn catalog_is_consistent() {
    let mut ids = std::collections::BTreeSet::new();
    for i in INVARIANTS {
        assert!(ids.insert(i.id), "duplicate {}", i.id);
        assert!(
            i.id.len() == 7 && i.id.starts_with("INV-") && i.id[4..].parse::<u16>().is_ok(),
            "{}",
            i.id
        );
        assert!(!i.evidence.is_empty(), "{} has no evidence", i.id);
        for (_, e) in i.evidence {
            report::reference_exists(&root(), CHECKS, e)
                .unwrap_or_else(|p| panic!("{}: {p}", i.id));
        }
        assert!(
            !i.claim.contains("proven") && !i.claim.contains("guarantee"),
            "{}",
            i.id
        );
    }
    for c in CHECKS {
        assert!(
            INVARIANTS.iter().any(|i| i
                .evidence
                .iter()
                .any(|(_, e)| *e == format!("check:{}", c.name))),
            "check {} backs no invariant",
            c.name
        );
    }
}

/// docs/assurance.md lists every invariant.
#[test]
fn the_matrix_documents_every_invariant() {
    let doc = std::fs::read_to_string(root().join("docs/assurance.md")).unwrap();
    for i in INVARIANTS {
        assert!(doc.contains(i.id), "docs/assurance.md lacks {}", i.id);
    }
}

fn passes(_: Scale) -> encompute_assurance::CheckResult {
    Ok(Outcome::new(1))
}

fn fails(_: Scale) -> encompute_assurance::CheckResult {
    Err("the invariant was bypassed".into())
}

fn panics(_: Scale) -> encompute_assurance::CheckResult {
    panic!("boom")
}

const TOY: &[Invariant] = &[
    Invariant {
        id: "INV-900",
        area: "toy",
        claim: "holds",
        evidence: &[(Kind::Adversarial, "check:passes")],
    },
    Invariant {
        id: "INV-901",
        area: "toy",
        claim: "is broken",
        evidence: &[(Kind::Adversarial, "check:fails")],
    },
];

/// The release gate: one violated invariant fails the whole report, a
/// panicking check counts as a violation, a missing reference fails, and
/// the success wording is never a security proof.
#[test]
fn the_gate_blocks_on_any_violation() {
    let ok = [Check {
        name: "passes",
        run: passes,
    }];
    let r = report::build(Scale::Quick, &root(), &ok, &TOY[..1], None);
    assert!(r.passed);
    assert_eq!(r.summary, report::PASS);
    assert!(!r.markdown().to_lowercase().contains("proven secure"));

    let bad = [
        Check {
            name: "passes",
            run: passes,
        },
        Check {
            name: "fails",
            run: fails,
        },
    ];
    let r = report::build(Scale::Quick, &root(), &bad, TOY, None);
    assert!(!r.passed);
    assert!(r.summary.contains("INV-901") && !r.summary.contains("INV-900"));
    assert!(r.markdown().contains("**FAIL**"));

    let boom = [
        Check {
            name: "passes",
            run: passes,
        },
        Check {
            name: "fails",
            run: panics,
        },
    ];
    assert!(!report::build(Scale::Quick, &root(), &boom, TOY, None).passed);

    // A reference to a test that no longer exists.
    let stale = [Invariant {
        id: "INV-902",
        area: "toy",
        claim: "is stale",
        evidence: &[(
            Kind::Negative,
            "test:crates/encompute-privacy/tests/privacy.rs::deleted_test",
        )],
    }];
    assert!(!report::build(Scale::Quick, &root(), &ok, &stale, None).passed);
    // A check that did not run.
    assert!(!report::build(Scale::Quick, &root(), &[], &TOY[..1], None).passed);
}

/// The mutator's own negative control: a verifier that ignores a field is
/// caught at exactly that field.
#[test]
fn mutation_catches_an_unbound_field() {
    let v = serde_json::json!({"a": "00ff", "b": {"c": 3, "d": [true, null]}, "e": null});
    let (n, bad) = mutate::accepted(&v, &[], |m| m["a"] == v["a"] && m["b"] == v["b"]);
    assert!(n >= 8, "{n}");
    assert_eq!(bad, vec!["/e".to_owned()]);
    // Every mutant differs from the original.
    for m in mutate::mutants(&v) {
        assert_ne!(m.value, v, "{}", m.path);
    }
}
