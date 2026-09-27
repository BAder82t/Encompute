//! The exact performance regression gate. For every corpus program
//! (`benches/exact/*.eir`) it recomputes the stable quantities (gate
//! counts, depth, rounds, active input bits: machine-independent) and
//! fails if any got worse than `benches/exact/baseline.json`.
//!
//! An improvement is accepted by regenerating the baseline:
//!
//! ```text
//! ENCOMPUTE_UPDATE_BASELINE=1 cargo test -p encompute-exact --test bench_baseline
//! ```
//!
//! It also checks the optimizer's invariants (never more rounds than the
//! reference circuit, never more gates than the reference lowering) and
//! that every optimized circuit computes what the clear interpreter does.

mod corpus;

use serde_json::Value;

use encompute_exact::bits::Strategy;
use encompute_exact::circuit::{
    build, execute, optimize, plain_bits, plain_value, Circuit, PlainCircuitGates,
};
use encompute_ir::{evaluate, Inputs, Outputs};

/// Quantities gated per optimized circuit: none may grow.
const GATED: [&str; 4] = ["gates", "depth", "rounds_8", "input_bits_used"];

fn num(v: &Value, what: &str) -> u64 {
    v.as_u64().unwrap_or_else(|| panic!("{what}: not a number"))
}

#[test]
fn stable_quantities_do_not_regress() {
    let entries = corpus::load();
    assert!(
        entries.len() >= 16,
        "the corpus has {} programs",
        entries.len()
    );
    let current = corpus::all_stats(&entries);
    let path = corpus::baseline_path();
    if std::env::var_os("ENCOMPUTE_UPDATE_BASELINE").is_some() {
        let text = serde_json::to_string_pretty(&current).unwrap() + "\n";
        std::fs::write(&path, text).unwrap();
        eprintln!("wrote {}", path.display());
        return;
    }
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}; create it with {}",
            path.display(),
            corpus::UPDATE_COMMAND
        )
    });
    let baseline: Value = serde_json::from_str(&text).unwrap();
    let (cur, base) = (&current["programs"], &baseline["programs"]);
    let mut regressions = vec![];
    let mut improvements = vec![];
    for (name, c) in cur.as_object().unwrap() {
        let Some(b) = base.get(name) else {
            regressions.push(format!("{name}: not in the baseline (a new program)"));
            continue;
        };
        for w in corpus::STAT_WORKERS {
            let w = w.to_string();
            for k in GATED {
                let what = format!("{name} optimized[{w}].{k}");
                let (now, was) = (
                    num(&c["optimized"][&w][k], &what),
                    num(&b["optimized"][&w][k], &what),
                );
                if now > was {
                    regressions.push(format!("{what}: {was} -> {now}"));
                } else if now < was {
                    improvements.push(format!("{what}: {was} -> {now}"));
                }
            }
        }
    }
    for name in base.as_object().unwrap().keys() {
        if cur.get(name).is_none() {
            regressions.push(format!("{name}: in the baseline but not in the corpus"));
        }
    }
    for i in &improvements {
        eprintln!("improved: {i}");
    }
    assert!(
        regressions.is_empty(),
        "exact performance regressions against {}:\n  {}\n(an intended change: regenerate with {})",
        path.display(),
        regressions.join("\n  "),
        corpus::UPDATE_COMMAND
    );
    if !improvements.is_empty() {
        eprintln!(
            "{} quantities improved; accept them with {}",
            improvements.len(),
            corpus::UPDATE_COMMAND
        );
    }
}

#[test]
fn optimized_circuits_never_cost_more_than_the_reference() {
    for e in corpus::load() {
        let s = corpus::stats(&e);
        let r = &s["reference"];
        let reference_gates = num(&r["gates"], "reference gates");
        let o8 = &s["optimized"]["8"];
        let o1 = &s["optimized"]["1"];
        assert!(
            num(&o8["rounds_8"], "rounds") <= num(&r["circuit_rounds_8"], "rounds"),
            "{}: optimized rounds(8) {} > reference circuit rounds(8) {}",
            e.name,
            o8["rounds_8"],
            r["circuit_rounds_8"]
        );
        // The reference strategy with ranges, and the cheapest circuit for
        // one worker, never exceed the reference lowering's gates.
        for (what, g) in [
            ("reference-strategy build", num(&r["ranged_gates"], "gates")),
            ("optimized for 1 worker", num(&o1["gates"], "gates")),
            ("reference circuit", num(&r["circuit_gates"], "gates")),
        ] {
            assert!(
                g <= reference_gates,
                "{}: {what} has {g} gates > reference gate count {reference_gates}",
                e.name
            );
        }
    }
}

fn run(e: &corpus::Entry, c: &Circuit, inputs: &Inputs, workers: usize) -> Outputs {
    let bits: Vec<Vec<bool>> = e
        .plan
        .inputs
        .iter()
        .map(|i| plain_bits(i.elem, inputs[&i.name][0] as i128))
        .collect();
    let out = execute(c, &PlainCircuitGates, &bits, workers).unwrap();
    e.plan
        .outputs
        .iter()
        .zip(out)
        .map(|(o, b)| (o.name.clone(), vec![plain_value(o.elem, &b) as f64]))
        .collect()
}

#[test]
fn optimized_circuits_equal_the_interpreter() {
    for e in corpus::load() {
        let mut circuits = vec![];
        for w in corpus::STAT_WORKERS {
            circuits.push((
                format!("optimized for {w}"),
                optimize(&e.plan, &e.ranges, w),
            ));
        }
        for s in [Strategy::REFERENCE, Strategy::PARALLEL] {
            circuits.push((format!("{s:?}"), build(&e.plan, &e.ranges, s)));
        }
        for inputs in corpus::cases(&e) {
            let want = evaluate(&e.program, &inputs)
                .unwrap_or_else(|err| panic!("{}: {err} on {inputs:?}", e.name));
            for (what, c) in &circuits {
                let c = c.as_ref().unwrap();
                for workers in [1usize, 3] {
                    assert_eq!(
                        run(&e, c, &inputs, workers),
                        want,
                        "{} ({what}, {workers} workers) on {inputs:?}",
                        e.name
                    );
                }
            }
        }
    }
}

#[test]
fn the_golden_benchmarks_are_in_the_corpus() {
    let names: Vec<String> = corpus::load().into_iter().map(|e| e.name).collect();
    for g in corpus::GOLDEN {
        assert!(names.iter().any(|n| n == g), "{g} is missing");
    }
}
