//! Timed benchmark of the exact corpus (`benches/exact`) on OpenFHE exact
//! (BinFHE STD128/GINX): compile, key generation, encryption, the
//! reference evaluation (instruction by instruction) and the optimized
//! circuit at several worker counts, decryption, sizes and peak RSS. Every
//! result is decrypted and compared with the clear interpreter.
//!
//! ```text
//! OPENFHE_ROOT=... cargo run --release -p encompute-openfhe-client --example exact_bench -- \
//!     [--golden] [--workers 1,2,4,8] [--budget SECS] [--no-reference] \
//!     [--history PATH | --no-history] [PROGRAM...]
//! ```
//!
//! One JSON line per program is appended to `benches/exact/history.jsonl`
//! (the published history) and a markdown table is printed. A reference
//! run (or an optimized run below 8 workers) whose estimate (gates or
//! rounds × the measured time per gate) exceeds `--budget` seconds
//! (default 180) is skipped and recorded as `null`; the optimized run at 8
//! workers always runs.

#[path = "../../encompute-exact/tests/corpus/mod.rs"]
mod corpus;

use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use encompute_backend::{ExactClient, ExactEvaluator};
use encompute_exact::bits::{Gates, OPENFHE_EXACT_PROFILE, OPENFHE_EXACT_VERSION};
use encompute_exact::circuit::{optimize, OPTIMIZER_VERSION};
use encompute_exact::evaluate_exact;
use encompute_ir::{evaluate, Elem, Inputs};
use encompute_openfhe_client::OpenFheExactClient;
use encompute_openfhe_exact::{default_profile, evaluator, OpenFheExactEvaluator};

struct Args {
    names: Vec<String>,
    workers: Vec<u32>,
    budget: f64,
    reference: bool,
    history: Option<PathBuf>,
}

fn args() -> Args {
    let mut a = Args {
        names: vec![],
        workers: vec![1, 2, 4, 8],
        budget: 180.0,
        reference: true,
        history: Some(corpus::dir().join("history.jsonl")),
    };
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--golden" => a.names.extend(corpus::GOLDEN.iter().map(|s| s.to_string())),
            "--workers" => {
                a.workers = it
                    .next()
                    .expect("--workers 1,2,4,8")
                    .split(',')
                    .map(|w| w.trim().parse().expect("a worker count"))
                    .collect();
            }
            "--budget" => a.budget = it.next().expect("--budget SECS").parse().expect("seconds"),
            "--no-reference" => a.reference = false,
            "--history" => a.history = Some(it.next().expect("--history PATH").into()),
            "--no-history" => a.history = None,
            "-h" | "--help" => {
                println!(
                    "exact_bench [--golden] [--workers 1,2,4,8] [--budget SECS] [--no-reference] \
                     [--history PATH | --no-history] [PROGRAM...]"
                );
                std::process::exit(0);
            }
            _ => a.names.push(x),
        }
    }
    if !a.workers.contains(&8) {
        a.workers.push(8);
    }
    a.workers.sort_unstable();
    a.workers.dedup();
    a
}

fn ms(t: Instant) -> f64 {
    (t.elapsed().as_secs_f64() * 1e6).round() / 1e3
}

fn command(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .current_dir(corpus::dir())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn cpu_model() -> String {
    if let Some(m) = command("sysctl", &["-n", "machdep.cpu.brand_string"]) {
        return m;
    }
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|m| m.trim().to_owned())
        })
        .unwrap_or_else(|| "unknown".into())
}

fn machine() -> Value {
    json!({
        "cpu": cpu_model(),
        "logical_cores": std::thread::available_parallelism().map_or(0, |n| n.get()),
        "os": std::env::consts::OS,
        "os_release": command("uname", &["-r"]),
        "arch": std::env::consts::ARCH,
    })
}

/// `YYYY-MM-DDTHH:MM:SSZ` (UTC) for seconds since the epoch.
fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Peak resident set size of this process, in MiB.
#[allow(unsafe_code)]
fn peak_rss_mib() -> f64 {
    // `struct rusage` on 64-bit Linux and macOS: two `timeval`s (16 bytes
    // each), then 14 longs, the first being `ru_maxrss`.
    #[repr(C)]
    struct Rusage {
        times: [i64; 4],
        maxrss: i64,
        rest: [i64; 13],
    }
    extern "C" {
        fn getrusage(who: i32, usage: *mut Rusage) -> i32;
    }
    let mut u = Rusage {
        times: [0; 4],
        maxrss: 0,
        rest: [0; 13],
    };
    // SAFETY: `u` is a valid, writable `struct rusage`; RUSAGE_SELF = 0.
    if unsafe { getrusage(0, &mut u) } != 0 {
        return f64::NAN;
    }
    // Bytes on macOS, KiB on Linux.
    let bytes = if cfg!(target_os = "macos") {
        u.maxrss as f64
    } else {
        u.maxrss as f64 * 1024.0
    };
    (bytes / 1_048_576.0 * 10.0).round() / 10.0
}

/// Seconds per bootstrapped gate, measured on 32 ANDs.
fn calibrate(client: &OpenFheExactClient, ev: &OpenFheExactEvaluator) -> f64 {
    let a = ev
        .gates
        .load(Elem::U8, &client.encrypt(Elem::U8, 0x5a).unwrap());
    let b = ev
        .gates
        .load(Elem::U8, &client.encrypt(Elem::U8, 0x3c).unwrap());
    let (a, b) = (a.unwrap(), b.unwrap());
    let t = Instant::now();
    for i in 0..32 {
        ev.gates.and(&a[i % 8], &b[(i / 8) % 8]).unwrap();
    }
    t.elapsed().as_secs_f64() / 32.0
}

fn decrypt_all(
    client: &OpenFheExactClient,
    e: &corpus::Entry,
    outs: &[Vec<u8>],
    what: &str,
) -> Inputs {
    e.plan
        .outputs
        .iter()
        .zip(outs)
        .map(|(o, b)| {
            let v = client
                .decrypt(o.elem, b)
                .unwrap_or_else(|err| panic!("{} {what}: output {}: {err}", e.name, o.name));
            (o.name.clone(), vec![v as f64])
        })
        .collect()
}

fn check(e: &corpus::Entry, what: &str, got: &Inputs, want: &Inputs) {
    if got != want {
        eprintln!(
            "MISMATCH {} ({what}): got {got:?}, expected {want:?}",
            e.name
        );
        std::process::exit(1);
    }
}

fn secs(v: &Value) -> String {
    v.as_f64()
        .map_or_else(|| "–".into(), |x| format!("{:.2}", x / 1000.0))
}

fn speedup(r: &Value, o: &Value) -> String {
    match (r.as_f64(), o.as_f64()) {
        (Some(r), Some(o)) if o > 0.0 => format!("{:.1}×", r / o),
        _ => "–".into(),
    }
}

fn main() {
    let a = args();
    let entries = corpus::select(&a.names).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let git_commit = command("git", &["rev-parse", "HEAD"]);
    let git_dirty = command(
        "git",
        &[
            "status",
            "--porcelain",
            "--untracked-files=no",
            "--",
            ".",
            ":!history.jsonl",
        ],
    )
    .map(|s| !s.is_empty());
    let machine = machine();

    eprintln!("generating keys (OpenFHE {OPENFHE_EXACT_VERSION}, {OPENFHE_EXACT_PROFILE})...");
    let t = Instant::now();
    let client = OpenFheExactClient::generate().expect("key generation");
    let keys = client.evaluation_keys().expect("evaluation keys");
    let keygen_ms = ms(t);
    let t = Instant::now();
    let ev = evaluator(&default_profile(), &keys).expect("evaluator");
    let evaluator_setup_ms = ms(t);
    let gate_s = calibrate(&client, &ev);
    eprintln!(
        "keys {:.0} MiB in {:.1}s; {:.1} ms per gate",
        keys.len() as f64 / 1_048_576.0,
        keygen_ms / 1000.0,
        gate_s * 1000.0
    );

    let mut records = vec![];
    for e in &entries {
        let inputs = corpus::bench_case(e);
        let want = evaluate(&e.program, &inputs).expect("the clear interpreter");
        let stats = corpus::stats(e);
        let t = Instant::now();
        let compiled = encompute_exact::compile(&e.program).expect("compile");
        let compile_ms = ms(t);
        let plan = &compiled.plan;

        let t = Instant::now();
        let enc: Vec<Vec<u8>> = plan
            .inputs
            .iter()
            .map(|i| client.encrypt(i.elem, inputs[&i.name][0] as i128).unwrap())
            .collect();
        let encrypt_ms = ms(t);
        let request_bytes: usize = enc.iter().map(Vec::len).sum();
        let refs: Vec<(Elem, &[u8])> = plan
            .inputs
            .iter()
            .zip(&enc)
            .map(|(i, b)| (i.elem, b.as_slice()))
            .collect();

        // Reference: instruction by instruction (BitEvaluator, reference
        // strategy), including loading inputs and storing outputs.
        let reference_gates = stats["reference"]["gates"].as_u64().unwrap();
        let ref_estimate = reference_gates as f64 * gate_s;
        let reference_ms = if a.reference && ref_estimate <= a.budget {
            eprintln!(
                "{}: reference, {reference_gates} gates (~{ref_estimate:.0}s)...",
                e.name
            );
            let t = Instant::now();
            let cts = refs
                .iter()
                .map(|(el, b)| ev.load(*el, b).unwrap())
                .collect();
            let outs = evaluate_exact(&ev, plan, cts).expect("reference evaluation");
            let stored: Vec<Vec<u8>> = outs.iter().map(|c| ev.store(c).unwrap()).collect();
            let m = ms(t);
            check(
                e,
                "reference",
                &decrypt_all(&client, e, &stored, "reference"),
                &want,
            );
            json!(m)
        } else {
            eprintln!(
                "{}: reference skipped ({reference_gates} gates, ~{ref_estimate:.0}s)",
                e.name
            );
            Value::Null
        };

        let mut optimized = vec![];
        let mut last_outs: Vec<Vec<u8>> = vec![];
        for &w in &a.workers {
            let t = Instant::now();
            let c = optimize(plan, &e.ranges, w).expect("optimize");
            let plan_ms = ms(t);
            let estimate = c.rounds(w) as f64 * gate_s;
            let eval_ms = if w == 8 || estimate <= a.budget {
                eprintln!(
                    "{}: optimized, {w} workers, {} gates, {} rounds (~{estimate:.0}s)...",
                    e.name,
                    c.stats.gates,
                    c.rounds(w)
                );
                let t = Instant::now();
                let outs = ev
                    .gates
                    .run_circuit(&c, &refs, w as usize)
                    .expect("optimized evaluation");
                let m = ms(t);
                let what = format!("optimized, {w} workers");
                check(e, &what, &decrypt_all(&client, e, &outs, &what), &want);
                last_outs = outs;
                json!(m)
            } else {
                Value::Null
            };
            optimized.push(json!({
                "workers": w,
                "strategy": corpus::strategy_name(c.strategy),
                "gates": c.stats.gates,
                "depth": c.stats.depth,
                "rounds": c.rounds(w),
                "plan_ms": plan_ms,
                "eval_ms": eval_ms,
            }));
        }
        let t = Instant::now();
        decrypt_all(&client, e, &last_outs, "decrypt");
        let decrypt_ms = ms(t);
        let response_bytes: usize = last_outs.iter().map(Vec::len).sum();

        let record = json!({
            "timestamp": rfc3339(started),
            "git_commit": git_commit,
            "git_dirty": git_dirty,
            "machine": machine,
            "openfhe_version": OPENFHE_EXACT_VERSION,
            "profile": OPENFHE_EXACT_PROFILE,
            "optimizer_version": OPTIMIZER_VERSION,
            "program": e.name,
            "golden": corpus::GOLDEN.contains(&e.name.as_str()),
            "inputs": inputs,
            "verified": true,
            "compile_ms": compile_ms,
            "keygen_ms": keygen_ms,
            "evaluator_setup_ms": evaluator_setup_ms,
            "evaluation_key_bytes": keys.len(),
            "gate_ms": (gate_s * 1e6).round() / 1e3,
            "encrypt_ms": encrypt_ms,
            "request_bytes": request_bytes,
            "decrypt_ms": decrypt_ms,
            "response_bytes": response_bytes,
            "peak_rss_mib": peak_rss_mib(),
            "reference": {
                "gates": reference_gates,
                "circuit_depth": stats["reference"]["circuit_depth"],
                "eval_ms": reference_ms,
            },
            "optimized": optimized,
        });
        if let Some(path) = &a.history {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
            writeln!(f, "{record}").expect("history");
        }
        records.push(record);
    }

    let at = |r: &Value, w: u32| -> Value {
        r["optimized"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["workers"] == w)
            .cloned()
            .unwrap_or(Value::Null)
    };
    println!();
    print!("| program | ref. gates | ref. depth | ref. s |");
    for w in &a.workers {
        print!(" w={w} s |");
    }
    println!(" opt. gates (1 / 8) | opt. depth (1 / 8) | speedup 1 | speedup 8 |");
    println!(
        "|---|---:|---:|---:|{}---:|---:|---:|---:|",
        "---:|".repeat(a.workers.len())
    );
    for r in &records {
        let (o1, o8) = (at(r, 1), at(r, 8));
        print!(
            "| {} | {} | {} | {} |",
            r["program"].as_str().unwrap(),
            r["reference"]["gates"],
            r["reference"]["circuit_depth"],
            secs(&r["reference"]["eval_ms"])
        );
        for w in &a.workers {
            print!(" {} |", secs(&at(r, *w)["eval_ms"]));
        }
        println!(
            " {} / {} | {} / {} | {} | {} |",
            o1["gates"],
            o8["gates"],
            o1["depth"],
            o8["depth"],
            speedup(&r["reference"]["eval_ms"], &o1["eval_ms"]),
            speedup(&r["reference"]["eval_ms"], &o8["eval_ms"]),
        );
    }
    if let Some(p) = &a.history {
        eprintln!("appended {} records to {}", records.len(), p.display());
    }
}
