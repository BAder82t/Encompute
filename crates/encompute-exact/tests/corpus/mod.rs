//! The exact performance corpus (`benches/exact/*.eir`), shared by the
//! regression gate (`tests/bench_baseline.rs`), the stats tool
//! (`examples/exact_stats.rs`) and the timed OpenFHE runner
//! (`encompute-openfhe-client/examples/exact_bench.rs`).
//!
//! The stable quantities (gate counts, depth, rounds) are pure functions
//! of the program, its declared input ranges and the optimizer: they are
//! the same on every machine.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use encompute_exact::bits::{gate_count, Strategy};
use encompute_exact::circuit::{build, optimize, Circuit, Interval, OPTIMIZER_VERSION};
use encompute_exact::{compile, ExactPlan};
use encompute_ir::{Elem, Inputs, Program};

/// The three commercial golden benchmarks.
pub const GOLDEN: [&str; 3] = ["golden_eligibility", "golden_policy", "golden_scoring"];

/// Worker counts whose optimized circuits the baseline records.
pub const STAT_WORKERS: [u32; 2] = [1, 8];

/// The command that regenerates the baseline after an improvement.
pub const UPDATE_COMMAND: &str =
    "ENCOMPUTE_UPDATE_BASELINE=1 cargo test -p encompute-exact --test bench_baseline";

pub fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benches/exact")
}

pub fn baseline_path() -> PathBuf {
    dir().join("baseline.json")
}

/// A corpus program, compiled, with its declared input ranges.
pub struct Entry {
    pub name: String,
    pub text: String,
    pub program: Program,
    pub plan: ExactPlan,
    pub ranges: Vec<Option<Interval>>,
}

/// The inputs' declared ranges, as the evaluator session reads them:
/// `[ceil(lo), floor(hi)]`.
pub fn input_ranges(program: &Program, plan: &ExactPlan) -> Vec<Option<Interval>> {
    plan.inputs
        .iter()
        .map(|i| {
            program
                .inputs()
                .find(|(_, n, _, _)| *n == i.name)
                .map(|(_, _, _, r)| (r.lo.ceil() as i128, r.hi.floor() as i128))
        })
        .collect()
}

/// Parses and compiles one corpus file.
pub fn entry(path: &Path) -> Result<Entry, String> {
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("{}: bad file name", path.display()))?
        .to_owned();
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let program = encompute_ir::parse(&text).map_err(|e| format!("{name}: {e}"))?;
    if program.name() != name {
        return Err(format!(
            "{name}: the program is named {:?}; name it after its file",
            program.name()
        ));
    }
    let plan = compile(&program).map_err(|e| format!("{name}: {e}"))?.plan;
    encompute_exact::bits::check_capabilities(&plan).map_err(|e| format!("{name}: {e}"))?;
    let ranges = input_ranges(&program, &plan);
    Ok(Entry {
        name,
        text,
        program,
        plan,
        ranges,
    })
}

/// Every corpus program, in file-name order.
pub fn load() -> Vec<Entry> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir())
        .unwrap_or_else(|e| panic!("{}: {e}", dir().display()))
        .map(|d| d.expect("a directory entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "eir"))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|p| entry(p).unwrap_or_else(|e| panic!("{e}")))
        .collect()
}

/// The named programs (all when `names` is empty); unknown names fail.
pub fn select(names: &[String]) -> Result<Vec<Entry>, String> {
    let all = load();
    if names.is_empty() {
        return Ok(all);
    }
    for n in names {
        if !all.iter().any(|e| &e.name == n) {
            let known: Vec<&str> = all.iter().map(|e| e.name.as_str()).collect();
            return Err(format!(
                "no corpus program {n:?}; known: {}",
                known.join(", ")
            ));
        }
    }
    Ok(all
        .into_iter()
        .filter(|e| names.contains(&e.name))
        .collect())
}

/// The reference lowering as a circuit: the reference strategy with no
/// range information (every input bit treated as live).
pub fn reference_circuit(e: &Entry) -> Circuit {
    build(
        &e.plan,
        &vec![None; e.plan.inputs.len()],
        Strategy::REFERENCE,
    )
    .unwrap_or_else(|err| panic!("{}: {err}", e.name))
}

pub fn strategy_name(s: Strategy) -> String {
    if s == Strategy::REFERENCE {
        "reference".into()
    } else if s == Strategy::PARALLEL {
        "parallel".into()
    } else {
        format!("{s:?}")
    }
}

pub fn circuit_stats(c: &Circuit, workers: u32) -> Value {
    let s = &c.stats;
    json!({
        "strategy": strategy_name(c.strategy),
        "gates": s.gates,
        "nots": s.nots,
        "depth": s.depth,
        "width": s.width,
        "input_bits_used": s.input_bits_used,
        "input_bits_total": s.input_bits_total,
        "range_bits_folded": s.range_bits_folded,
        "cse_hits": s.cse_hits,
        "simplifications": s.simplifications,
        "dead_gates": s.dead_gates,
        "rounds": c.rounds(workers),
        "rounds_8": c.rounds(8),
    })
}

/// The stable quantities of one program.
pub fn stats(e: &Entry) -> Value {
    let reference_gates = gate_count(&e.plan).unwrap_or_else(|err| panic!("{}: {err}", e.name));
    let rc = reference_circuit(e);
    let ranged_reference = build(&e.plan, &e.ranges, Strategy::REFERENCE)
        .unwrap_or_else(|err| panic!("{}: {err}", e.name));
    let mut optimized = BTreeMap::new();
    for w in STAT_WORKERS {
        let c = optimize(&e.plan, &e.ranges, w).unwrap_or_else(|err| panic!("{}: {err}", e.name));
        optimized.insert(w.to_string(), circuit_stats(&c, w));
    }
    json!({
        "reference": {
            "gates": reference_gates,
            "circuit_gates": rc.stats.gates,
            "circuit_depth": rc.stats.depth,
            "circuit_rounds_8": rc.rounds(8),
            "ranged_gates": ranged_reference.stats.gates,
        },
        "optimized": optimized,
    })
}

/// The stats of every program, as the baseline file stores them.
pub fn all_stats(entries: &[Entry]) -> Value {
    let programs: BTreeMap<String, Value> =
        entries.iter().map(|e| (e.name.clone(), stats(e))).collect();
    json!({
        "optimizer_version": OPTIMIZER_VERSION,
        "programs": programs,
    })
}

fn lcg(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *s >> 11
}

/// Deterministic in-range inputs: every input at its low end, at its high
/// end, alternating ends, and three pseudo-random draws.
pub fn cases(e: &Entry) -> Vec<Inputs> {
    let decl: Vec<(String, Elem, i128, i128)> = e
        .plan
        .inputs
        .iter()
        .zip(&e.ranges)
        .map(|(i, r)| {
            let (lo, hi) = r.unwrap_or_else(|| i.elem.bounds());
            (i.name.clone(), i.elem, lo, hi)
        })
        .collect();
    let mut seed = 0x5eed_u64 ^ e.name.len() as u64;
    let mut out = vec![];
    for case in 0..6 {
        let inputs: Inputs = decl
            .iter()
            .enumerate()
            .map(|(k, (n, _, lo, hi))| {
                let v = match case {
                    0 => *lo,
                    1 => *hi,
                    2 => {
                        if k % 2 == 0 {
                            *lo
                        } else {
                            *hi
                        }
                    }
                    _ => lo + (lcg(&mut seed) as i128).rem_euclid(hi - lo + 1),
                };
                (n.clone(), vec![v as f64])
            })
            .collect();
        out.push(inputs);
    }
    out
}

/// The benchmark's input: the first pseudo-random case.
pub fn bench_case(e: &Entry) -> Inputs {
    cases(e).swap_remove(3)
}
