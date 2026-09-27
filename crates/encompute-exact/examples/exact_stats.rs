//! Stable performance quantities of the exact corpus (`benches/exact`):
//! the reference gate count and, for the optimized circuit at 1 and 8
//! workers, gates, NOTs, depth, width, input bits, folded range bits, CSE
//! hits, simplifications, dead gates, rounds and the chosen strategy.
//! They depend only on the program, its declared input ranges and the
//! optimizer, never on the machine.
//!
//! ```text
//! cargo run --release -p encompute-exact --example exact_stats [-- [--json PATH] [NAME...]]
//! ```
//!
//! `--json benches/exact/baseline.json` rewrites the regression baseline
//! (as `ENCOMPUTE_UPDATE_BASELINE=1 cargo test -p encompute-exact --test
//! bench_baseline` does).

#[path = "../tests/corpus/mod.rs"]
mod corpus;

use serde_json::Value;

fn main() {
    let mut json_out: Option<String> = None;
    let mut names = vec![];
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--json" => json_out = Some(args.next().expect("--json needs a path")),
            "-h" | "--help" => {
                println!("exact_stats [--json PATH] [PROGRAM...]");
                return;
            }
            _ => names.push(a),
        }
    }
    let entries = corpus::select(&names).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    let all = corpus::all_stats(&entries);
    println!(
        "| program | reference gates | ref. circuit depth | ref. rounds(8) | w | strategy | gates | NOTs | depth | width | rounds(w) | rounds(8) | input bits | folded | CSE | simplified | dead |"
    );
    println!(
        "|---|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    );
    for (name, s) in all["programs"].as_object().expect("programs") {
        let r = &s["reference"];
        for (w, o) in s["optimized"].as_object().expect("optimized") {
            let n = |v: &Value, k: &str| v[k].to_string();
            println!(
                "| {name} | {} | {} | {} | {w} | {} | {} | {} | {} | {} | {} | {} | {}/{} | {} | {} | {} | {} |",
                n(r, "gates"),
                n(r, "circuit_depth"),
                n(r, "circuit_rounds_8"),
                o["strategy"].as_str().unwrap_or("?"),
                n(o, "gates"),
                n(o, "nots"),
                n(o, "depth"),
                n(o, "width"),
                n(o, "rounds"),
                n(o, "rounds_8"),
                n(o, "input_bits_used"),
                n(o, "input_bits_total"),
                n(o, "range_bits_folded"),
                n(o, "cse_hits"),
                n(o, "simplifications"),
                n(o, "dead_gates"),
            );
        }
    }
    if let Some(path) = json_out {
        let text = serde_json::to_string_pretty(&all).expect("json") + "\n";
        std::fs::write(&path, text).unwrap_or_else(|e| panic!("{path}: {e}"));
        eprintln!("wrote {path}");
    }
}
