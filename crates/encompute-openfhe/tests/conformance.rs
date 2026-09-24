//! Parameter conformance, check tier: Encompute's parameter selection against
//! the pinned security table and against OpenFHE's own choice, over a grid of
//! depth × precision × value range × slots. No encryption is executed here;
//! see `encompute-runtime/tests/conformance.rs` for the run tier.
//!
//! `ENCOMPUTE_CONFORMANCE=full` runs the full 10 080-point grid (scheduled CI);
//! the default is a 216-point subset.

use std::collections::HashMap;

use encompute_ckks::{select_params, CkksParams, SECURITY_TABLE};
use encompute_ir::Code;
use encompute_openfhe::{openfhe_choice, openfhe_validate};

fn full() -> bool {
    std::env::var("ENCOMPUTE_CONFORMANCE").is_ok_and(|v| v == "full")
}

struct Grid {
    depths: Vec<u32>,
    precisions: Vec<f64>,
    max_abs: Vec<f64>,
    slots: Vec<usize>,
}

fn grid() -> Grid {
    if full() {
        Grid {
            depths: (1..=30).collect(),
            precisions: vec![1e-2, 1e-3, 1e-4, 1e-5, 1e-6, 1e-7, 1e-8, 1e-10],
            max_abs: vec![0.01, 1.0, 10.0, 100.0, 1e3, 1e4, 1e6],
            slots: vec![1, 2, 16, 256, 4096, 32768],
        }
    } else {
        Grid {
            depths: vec![1, 2, 5, 10, 20, 30],
            precisions: vec![1e-2, 1e-4, 1e-6, 1e-10],
            max_abs: vec![1.0, 100.0, 1e6],
            slots: vec![1, 256, 32768],
        }
    }
}

/// Invariants that must hold for every accepted parameter set, without
/// asking OpenFHE.
fn check_invariants(p: &CkksParams, depth: u32, max_abs: f64, precision: f64, slots: usize) {
    let ctx =
        format!("depth {depth}, max_abs {max_abs}, precision {precision}, slots {slots}: {p:?}");
    let entry = SECURITY_TABLE
        .entries
        .iter()
        .find(|(n, _)| *n == p.ring_dim)
        .unwrap_or_else(|| panic!("ring dimension not in the security table; {ctx}"));
    assert_eq!(p.max_log_qp, entry.1, "{ctx}");
    assert!(
        p.log_qp <= p.max_log_qp,
        "log QP above the 128-bit limit; {ctx}"
    );
    // Smallest compliant ring: the next smaller one must not have fit.
    if let Some(prev) = SECURITY_TABLE
        .entries
        .iter()
        .rev()
        .find(|(n, _)| *n < p.ring_dim)
    {
        assert!(
            prev.1 < p.log_qp || prev.0 / 2 < p.slots,
            "a smaller ring would have fit; {ctx}"
        );
    }
    assert!(
        p.slots.is_power_of_two() && p.slots as usize >= slots,
        "{ctx}"
    );
    assert!(p.slots <= p.ring_dim / 2, "{ctx}");
    assert!(p.mult_depth >= depth, "{ctx}");
    assert!((30..=59).contains(&p.scale_bits), "{ctx}");
    assert!(p.first_mod_bits <= 60, "{ctx}");
    // Headroom: the scale covers the precision target, and values fit under q0.
    let precision_bits = (1.0 / precision).log2().ceil();
    assert!(p.scale_bits as f64 >= precision_bits + 20.0, "{ctx}");
    let magnitude_bits = max_abs.max(1.0).log2().ceil();
    assert!(
        p.first_mod_bits as f64 >= p.scale_bits as f64 + magnitude_bits + 2.0,
        "{ctx}"
    );
}

#[test]
fn parameter_selection_conforms_to_table_and_openfhe() {
    let g = grid();
    let mut openfhe: HashMap<CkksParams, (u32, u32, u32)> = HashMap::new();
    let (mut accepted, mut refused) = (0usize, 0usize);
    for &slots in &g.slots {
        for &max_abs in &g.max_abs {
            for &precision in &g.precisions {
                let mut refused_at: Option<u32> = None;
                for &depth in &g.depths {
                    match select_params(depth, max_abs, precision, slots) {
                        Ok(p) => {
                            assert!(
                                refused_at.is_none(),
                                "depth {depth} accepted after depth {refused_at:?} was refused \
                                 (max_abs {max_abs}, precision {precision}, slots {slots})"
                            );
                            check_invariants(&p, depth, max_abs, precision, slots);
                            let (min_n, min_log_qp, log_qp) =
                                *openfhe.entry(p.clone()).or_insert_with(|| {
                                    let (n, l) = openfhe_choice(&p)
                                        .unwrap_or_else(|e| panic!("OpenFHE: {e} for {p:?}"));
                                    let actual = openfhe_validate(&p).unwrap_or_else(|e| {
                                        panic!(
                                            "OpenFHE rejected the selected parameters {p:?}: {e}"
                                        )
                                    });
                                    (n, l, actual)
                                });
                            // Same security minimum as OpenFHE; larger only for slots.
                            assert_eq!(
                                p.ring_dim,
                                min_n.max(2 * p.slots),
                                "ring differs from OpenFHE's minimum {min_n} for {p:?}"
                            );
                            assert!(
                                min_log_qp <= p.log_qp && log_qp <= p.log_qp,
                                "OpenFHE log QP {log_qp} above Encompute's estimate for {p:?}"
                            );
                            assert!(log_qp <= p.max_log_qp, "above the security limit: {p:?}");
                            accepted += 1;
                        }
                        Err(e) => {
                            assert!(
                                matches!(e.code, Code::DepthExceeded | Code::PrecisionUnreachable),
                                "unexpected refusal {e}"
                            );
                            if e.code == Code::DepthExceeded {
                                refused_at.get_or_insert(depth);
                            }
                            refused += 1;
                        }
                    }
                }
            }
        }
    }
    eprintln!(
        "conformance: {accepted} accepted, {refused} refused, {} distinct parameter sets checked against OpenFHE",
        openfhe.len()
    );
    assert!(
        accepted > 0 && refused > 0,
        "grid must exercise both outcomes"
    );
}

#[test]
fn refusals_are_justified() {
    // Precision beyond a 59-bit scale is refused, not silently weakened.
    assert_eq!(
        select_params(1, 1.0, 1e-12, 8).unwrap_err().code,
        Code::PrecisionUnreachable
    );
    // The deepest accepted circuit at a given scale uses the largest ring;
    // one level more exceeds it.
    let deepest = (1..200)
        .take_while(|&d| select_params(d, 1.0, 1e-3, 8).is_ok())
        .last()
        .unwrap();
    let p = select_params(deepest, 1.0, 1e-3, 8).unwrap();
    assert_eq!(p.ring_dim, 65536);
    assert_eq!(
        select_params(deepest + 1, 1.0, 1e-3, 8).unwrap_err().code,
        Code::DepthExceeded
    );
}
