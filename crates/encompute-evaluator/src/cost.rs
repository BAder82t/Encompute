//! Whole-program backend selection for exact programs: OpenFHE BGV or
//! OpenFHE BinFHE, chosen by calibrated cost estimates.
//!
//! An exact program whose every operation is in the BGV subset (u8, u16 and
//! bool; add, sub, mul, constants, and/or/xor/not; see
//! [`encompute_exact::bgv`]) and that is estimated no slower on BGV runs on
//! OpenFHE BGV as a whole; everything else runs on OpenFHE BinFHE. Schemes
//! are never mixed inside one program. The choice depends only on the plan
//! and the constants below, so every party compiling the same program
//! selects the same backend.
//!
//! # Provenance of the constants
//!
//! OpenFHE 1.5.1 (static build, `scripts/install-openfhe.sh`), Apple M3 Max
//! (14 cores), macOS 26, `--release`, **one thread** (`OMP_NUM_THREADS=1`:
//! the evaluator's worker pool runs one execution per core, and BinFHE
//! gates are single-threaded). Measured 2026-09-27 on a machine under
//! background load; each cell is the minimum over three runs of a median of
//! 9–21 repetitions.
//!
//! - BinFHE: `BINFHE_STD128_GINX_BITS_V1` (paramset `STD128`, GINX
//!   bootstrapping), a chain of 21 bootstrapped gates:
//!   `cargo test -q --release -p encompute-openfhe-client --test binfhe --
//!   --include-ignored --nocapture` (`measure_paramsets`, STD128 line).
//! - BGV: `BGVRNS_T65537_DEPTH{d}_HEStd128_FIXEDAUTO_HYBRID` (the context of
//!   [`encompute_exact::bgv::profile`]), each operation on fresh ciphertexts
//!   at the top level (an upper bound: lower levels are cheaper):
//!   `cargo test -q --release -p encompute-openfhe-client --test bgv_cost --
//!   --ignored --nocapture`.
//!
//! The estimates are evaluator time (loading inputs, evaluating, storing
//! outputs). Client key generation and encryption are not included; they
//! favour BGV further (BinFHE key generation takes about 2.6 s, BGV's
//! 12–370 ms).

use encompute_exact::{bgv, ExactInstr, ExactPlan};
use encompute_ir::LogicOp;
use serde::Serialize;

/// Milliseconds per bootstrapped BinFHE gate (STD128, GINX, one thread).
pub const BINFHE_MS_PER_GATE: f64 = 54.0;

/// Measured cost of each BGV operation (ms, one thread) at one
/// multiplicative depth of the context.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BgvOpCosts {
    pub depth: u32,
    /// Deserializing one input ciphertext.
    pub load: f64,
    /// Serializing one output ciphertext.
    pub store: f64,
    /// Ciphertext + ciphertext (also sub and negation).
    pub add: f64,
    /// Ciphertext + public constant.
    pub add_const: f64,
    /// Ciphertext × public constant.
    pub mul_const: f64,
    /// Ciphertext × ciphertext, relinearized.
    pub mul: f64,
}

/// The calibration table, by depth (see the module documentation). Depths
/// in between are interpolated linearly; deeper contexts extrapolate the
/// last segment.
#[rustfmt::skip]
pub const BGV_OP_COSTS: &[BgvOpCosts] = &[
    BgvOpCosts { depth: 1, load: 0.76, store: 1.05, add: 0.015, add_const: 0.187, mul_const: 0.220, mul: 1.27 },
    BgvOpCosts { depth: 2, load: 2.49, store: 3.06, add: 0.039, add_const: 0.519, mul_const: 0.635, mul: 4.24 },
    BgvOpCosts { depth: 3, load: 2.72, store: 4.24, add: 0.059, add_const: 0.687, mul_const: 0.778, mul: 5.19 },
    BgvOpCosts { depth: 4, load: 2.62, store: 5.27, add: 0.077, add_const: 0.827, mul_const: 1.033, mul: 7.65 },
    BgvOpCosts { depth: 6, load: 7.82, store: 14.74, add: 0.201, add_const: 2.327, mul_const: 2.813, mul: 23.41 },
    BgvOpCosts { depth: 8, load: 8.23, store: 19.05, add: 0.267, add_const: 2.947, mul_const: 3.603, mul: 31.14 },
];

/// Per-operation costs of a BGV context of depth `depth`.
pub fn bgv_op_costs(depth: u32) -> BgvOpCosts {
    let t = BGV_OP_COSTS;
    let depth = depth.max(t[0].depth);
    let (a, b) = match t.iter().position(|c| c.depth >= depth) {
        Some(i) if t[i].depth == depth => return t[i],
        Some(i) => (t[i - 1], t[i]),
        None => (t[t.len() - 2], t[t.len() - 1]),
    };
    let f = (depth - a.depth) as f64 / (b.depth - a.depth) as f64;
    let lerp = |x: f64, y: f64| (x + f * (y - x)).max(x.min(y));
    BgvOpCosts {
        depth,
        load: lerp(a.load, b.load),
        store: lerp(a.store, b.store),
        add: lerp(a.add, b.add),
        add_const: lerp(a.add_const, b.add_const),
        mul_const: lerp(a.mul_const, b.mul_const),
        mul: lerp(a.mul, b.mul),
    }
}

/// Estimated BinFHE evaluation time of `plan` (ms): bootstrapped gates ×
/// [`BINFHE_MS_PER_GATE`]. Infinite when the plan cannot be lowered to
/// gates (outside the BinFHE capability matrix).
///
/// The single place the BinFHE estimate is made: a gate count from an
/// optimized circuit replaces [`encompute_exact::bits::gate_count`] here.
pub fn estimate_binfhe_ms(plan: &ExactPlan) -> f64 {
    binfhe_gates(plan).map_or(f64::INFINITY, |g| g as f64 * BINFHE_MS_PER_GATE)
}

fn binfhe_gates(plan: &ExactPlan) -> Option<u64> {
    encompute_exact::bits::gate_count(plan).ok()
}

/// Estimated BGV evaluation time of `plan` (ms): every operation at the
/// context's depth ([`bgv::mult_depth`]), plus loading the inputs and
/// storing the outputs. `None` when the plan is not in the BGV subset.
pub fn estimate_bgv_ms(plan: &ExactPlan) -> Option<f64> {
    if crate::compiled::bgv_unsupported(plan).is_some() {
        return None;
    }
    let c = bgv_op_costs(bgv::mult_depth(plan));
    let mut ms = plan.outputs.len() as f64 * c.store;
    for i in &plan.instrs {
        use ExactInstr::*;
        ms += match i {
            Input { .. } => c.load,
            Add(..) | Sub(..) | Neg(..) => c.add,
            AddScalar(..) | SubScalar(..) => c.add_const,
            // Negation, then the constant.
            ScalarSub(..) | Not(..) => c.add + c.add_const,
            MulScalar(..) => c.mul_const,
            Mul(..) => c.mul,
            // and = ab; or = a + b - ab; xor = a + b - 2ab.
            Logic(LogicOp::And, ..) => c.mul,
            Logic(LogicOp::Or, ..) => c.mul + 2.0 * c.add,
            Logic(LogicOp::Xor, ..) => c.mul + 3.0 * c.add,
            // Not in the subset (excluded above).
            _ => return None,
        };
    }
    Some(ms)
}

/// The exact backend a whole program runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactScheme {
    /// OpenFHE BGV (plaintext modulus 65537).
    Bgv,
    /// OpenFHE BinFHE bootstrapped gates.
    BinFhe,
}

impl ExactScheme {
    pub fn name(self) -> &'static str {
        match self {
            ExactScheme::Bgv => "BGV",
            ExactScheme::BinFhe => "BinFHE",
        }
    }
}

/// The selection for one plan, with the estimates it was made from (whole
/// milliseconds, rounded up: these are what the planner compares too).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExactSelection {
    pub scheme: ExactScheme,
    /// `None` when the plan cannot be lowered to gates.
    pub binfhe_ms: Option<u64>,
    pub binfhe_gates: Option<u64>,
    /// `None` when the plan is outside the BGV subset.
    pub bgv_ms: Option<u64>,
    pub bgv_depth: u32,
    /// Why, in words.
    pub reason: String,
}

fn whole_ms(ms: f64) -> Option<u64> {
    ms.is_finite().then(|| ms.ceil().max(1.0) as u64)
}

/// Estimated evaluation times on both backends, in whole milliseconds:
/// `(binfhe_ms, bgv_ms)`.
pub fn estimates(plan: &ExactPlan) -> (Option<u64>, Option<u64>) {
    (
        whole_ms(estimate_binfhe_ms(plan)),
        estimate_bgv_ms(plan).and_then(whole_ms),
    )
}

/// The one selection rule, on whole-millisecond estimates: BGV when the
/// plan is in the BGV subset and its estimate is no larger than BinFHE's
/// (a tie goes to BGV: exact arithmetic with no bootstrapping failure
/// probability), BinFHE otherwise. The planner applies the same rule to
/// the same numbers (`ProgramFacts::bgv_ms` / `binfhe_ms`).
pub fn prefer_bgv(binfhe_ms: Option<u64>, bgv_ms: Option<u64>) -> bool {
    match (bgv_ms, binfhe_ms) {
        (Some(b), Some(g)) => b <= g,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// Selects the backend for an unverified exact `plan`.
pub fn select_exact_scheme(plan: &ExactPlan) -> ExactSelection {
    let gates = binfhe_gates(plan);
    let (binfhe_ms, bgv_ms) = estimates(plan);
    let depth = bgv::mult_depth(plan);
    let binfhe = match (binfhe_ms, gates) {
        (Some(ms), Some(g)) => format!("~{ms} ms on BinFHE ({g} bootstrapped gates)"),
        _ => "BinFHE cannot lower it to gates".to_owned(),
    };
    let bgv_est = |ms: u64| format!("~{ms} ms on BGV (depth {depth})");
    let (scheme, reason) = match bgv_ms {
        None => (
            ExactScheme::BinFhe,
            format!(
                "{}, outside the BGV subset: {binfhe}",
                crate::compiled::bgv_unsupported(plan).unwrap_or_else(|| "an operation".to_owned())
            ),
        ),
        Some(b) if prefer_bgv(binfhe_ms, bgv_ms) => (
            ExactScheme::Bgv,
            format!(
                "every operation is in the BGV subset and BGV is estimated cheaper: {} vs {binfhe}",
                bgv_est(b)
            ),
        ),
        Some(b) => (
            ExactScheme::BinFhe,
            format!("BinFHE is estimated cheaper: {binfhe} vs {}", bgv_est(b)),
        ),
    };
    ExactSelection {
        scheme,
        binfhe_ms,
        binfhe_gates: gates,
        bgv_ms,
        bgv_depth: depth,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_interpolates() {
        assert!(BGV_OP_COSTS.windows(2).all(|w| w[0].depth < w[1].depth));
        assert_eq!(bgv_op_costs(3), BGV_OP_COSTS[2]);
        let five = bgv_op_costs(5);
        assert!(five.mul > bgv_op_costs(4).mul && five.mul < bgv_op_costs(6).mul);
        // Deeper than the table: extrapolated, still growing.
        assert!(bgv_op_costs(12).mul > bgv_op_costs(8).mul);
        assert_eq!(bgv_op_costs(0), BGV_OP_COSTS[0]);
    }

    use crate::compiled::{compile_program, CompiledProgram};
    use encompute_ir::{Builder, CmpOp, Elem, Program, Range, Verification};

    fn input(b: &mut Builder, n: &str, e: Elem, hi: f64) -> encompute_ir::ValueId {
        b.input_exact(n, e, Some(Range::new(0.0, hi))).unwrap()
    }

    /// Credit scoring over u16: products, sums, constants.
    fn scoring(verified: bool) -> Program {
        let mut b = Builder::new("scoring", 1e-3).unwrap();
        let income = input(&mut b, "income", Elem::U16, 5000.0);
        let debt = input(&mut b, "debt", Elem::U16, 5000.0);
        let years = input(&mut b, "years", Elem::U16, 40.0);
        let k3 = b.constant_exact(Elem::U16, 3.0).unwrap();
        let k7 = b.constant_exact(Elem::U16, 7.0).unwrap();
        let s = b.mul(income, k3).unwrap();
        let s = b.add(s, debt).unwrap();
        let t = b.mul(years, years).unwrap();
        let s = b.add(s, t).unwrap();
        let s = b.add(s, k7).unwrap();
        b.output("score", s).unwrap();
        if verified {
            b.verification(Verification::Required);
        }
        b.finish().unwrap()
    }

    fn exact(p: Program) -> crate::ExactProgram {
        match compile_program(&p).unwrap() {
            CompiledProgram::Exact(e) => e,
            CompiledProgram::Approx(_) => panic!("exact program"),
        }
    }

    #[test]
    fn arithmetic_scoring_runs_on_bgv() {
        let e = exact(scoring(false));
        let sel = e.selection.clone().unwrap();
        eprintln!("{}", sel.reason);
        assert_eq!(sel.scheme, ExactScheme::Bgv, "{}", sel.reason);
        assert!(sel.bgv_ms.unwrap() * 10 < sel.binfhe_ms.unwrap(), "{sel:?}");
        assert!(
            sel.reason.contains("BGV is estimated cheaper"),
            "{}",
            sel.reason
        );
        assert_eq!(e.profile, bgv::profile(&e.plan));
        assert!(!e.proof_required);
        let c = CompiledProgram::Exact(e);
        assert_eq!(c.scheme(), "BGV");
        assert_eq!(c.target_backend(), crate::BackendKind::OpenFhe);
        assert!(!c.proof_required());
    }

    #[test]
    fn comparisons_stay_on_binfhe() {
        let mut b = Builder::new("eligible", 1e-3).unwrap();
        let age = input(&mut b, "age", Elem::U8, 120.0);
        let risk = input(&mut b, "risk", Elem::U16, 1000.0);
        let k18 = b.constant_exact(Elem::U8, 18.0).unwrap();
        let k650 = b.constant_exact(Elem::U16, 650.0).unwrap();
        let adult = b.cmp(CmpOp::Ge, age, k18).unwrap();
        let low = b.cmp(CmpOp::Le, risk, k650).unwrap();
        let ok = b.logic(LogicOp::And, adult, low).unwrap();
        let r = b.select(ok, risk, k650).unwrap();
        b.output("ok", ok).unwrap();
        b.output("r", r).unwrap();
        let e = exact(b.finish().unwrap());
        let sel = e.selection.unwrap();
        assert_eq!(sel.scheme, ExactScheme::BinFhe);
        assert_eq!(sel.bgv_ms, None);
        assert!(
            sel.reason.contains("outside the BGV subset"),
            "{}",
            sel.reason
        );
        assert_eq!(e.profile, encompute_exact::bits::openfhe_exact_profile());
    }

    #[test]
    fn one_op_outside_the_subset_keeps_the_whole_program_on_binfhe() {
        // Arithmetic-heavy, but one `min`: no scheme mixing.
        let mut b = Builder::new("heavy", 1e-3).unwrap();
        let x = input(&mut b, "x", Elem::U16, 10.0);
        let y = input(&mut b, "y", Elem::U16, 10.0);
        let mut acc = b.mul(x, y).unwrap();
        for _ in 0..8 {
            let k = b.constant_exact(Elem::U16, 2.0).unwrap();
            let t = b.mul(x, k).unwrap();
            acc = b.add(acc, t).unwrap();
        }
        let m = b.min(acc, y).unwrap();
        b.output("m", m).unwrap();
        b.output("acc", acc).unwrap();
        let e = exact(b.finish().unwrap());
        let sel = e.selection.unwrap();
        assert_eq!(sel.scheme, ExactScheme::BinFhe);
        assert_eq!(estimate_bgv_ms(&e.plan), None);
        assert!(sel.reason.starts_with("MIN on u16"), "{}", sel.reason);
    }

    #[test]
    fn binfhe_wins_when_it_needs_no_bootstrapping() {
        // `not` is free on BinFHE; BGV still loads and stores.
        let mut b = Builder::new("flip", 1e-3).unwrap();
        let x = b.input_exact("x", Elem::Bool, None).unwrap();
        let y = b.not(x).unwrap();
        b.output("y", y).unwrap();
        let e = exact(b.finish().unwrap());
        let sel = e.selection.unwrap();
        assert_eq!(sel.scheme, ExactScheme::BinFhe, "{sel:?}");
        assert!(
            sel.reason.contains("BinFHE is estimated cheaper"),
            "{}",
            sel.reason
        );
    }

    #[test]
    fn verified_programs_run_on_bgv_with_proofs() {
        let e = exact(scoring(true));
        assert!(e.proof_required);
        assert_eq!(e.selection, None);
        assert_eq!(e.profile, bgv::profile(&e.plan));
    }

    #[test]
    fn selection_is_deterministic() {
        let a = exact(scoring(false)).selection;
        let b = exact(scoring(false)).selection;
        assert_eq!(a, b);
    }

    #[test]
    fn rule() {
        assert!(prefer_bgv(Some(10), Some(10)));
        assert!(prefer_bgv(Some(10), Some(9)));
        assert!(!prefer_bgv(Some(10), Some(11)));
        assert!(!prefer_bgv(Some(10), None));
        assert!(prefer_bgv(None, Some(1)));
    }
}
