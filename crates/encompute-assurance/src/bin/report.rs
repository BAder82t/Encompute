//! `assurance-report [--nightly] [--root DIR] [--json FILE] [--md FILE]
//! [--only CHECK]...`: runs the assurance checks and writes the report.
//! Exits 1 when any invariant is violated (the release gate).

use std::path::PathBuf;

use encompute_assurance::{report, Scale};

fn main() {
    let mut scale = Scale::Quick;
    let mut root = PathBuf::from(".");
    let (mut json, mut md) = (None, None);
    let mut only = vec![];
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().unwrap_or_else(|| usage(&a));
        match a.as_str() {
            "--nightly" => scale = Scale::Nightly,
            "--root" => root = val().into(),
            "--json" => json = Some(PathBuf::from(val())),
            "--md" => md = Some(PathBuf::from(val())),
            "--only" => only.push(val()),
            _ => usage(&a),
        }
    }
    // A misspelled check must not run nothing and report success.
    for name in &only {
        if encompute_assurance::checks::find(name).is_none() {
            eprintln!(
                "unknown check {name}; checks: {}",
                encompute_assurance::checks::CHECKS
                    .iter()
                    .map(|c| c.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            std::process::exit(2);
        }
    }
    let r = report::run(scale, &root, (!only.is_empty()).then_some(&only[..]));
    if let Some(p) = json {
        std::fs::write(&p, serde_json::to_string_pretty(&r).expect("json") + "\n")
            .expect("write the JSON report");
    }
    let text = r.markdown();
    if let Some(p) = md {
        std::fs::write(&p, &text).expect("write the Markdown report");
    }
    println!("{}", r.summary);
    for i in r.invariants.iter().filter(|i| !i.passed) {
        for p in &i.problems {
            println!("  {}: {p}", i.id);
        }
    }
    std::process::exit(if r.passed { 0 } else { 1 });
}

fn usage(arg: &str) -> ! {
    eprintln!(
        "unexpected argument {arg}\nusage: assurance-report [--nightly] [--root DIR] [--json FILE] \
         [--md FILE] [--only CHECK]..."
    );
    std::process::exit(2)
}
