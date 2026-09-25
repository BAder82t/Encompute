//! Cost of each exact operation on TFHE-rs, per integer width: median of
//! `REPS` runs on this machine, as a Markdown table for docs/benchmarks.md.
//!
//!     cargo run --release -p encompute-tfhe-client --features tfhe-rs --example exact_ops

use std::time::{Duration, Instant};

use encompute_backend::{ExactClient, ExactEvaluator};
use encompute_ir::{CmpOp, Elem, LogicOp, Result};
use encompute_tfhe::tfhe_rs::TfheRsEvaluator;
use encompute_tfhe_client::TfheRsClient;

const REPS: usize = 3;
const WIDTHS: [Elem; 8] = [
    Elem::U8,
    Elem::U16,
    Elem::U32,
    Elem::U64,
    Elem::I8,
    Elem::I16,
    Elem::I32,
    Elem::I64,
];

fn median(mut f: impl FnMut() -> Result<()>) -> Duration {
    let mut v: Vec<Duration> = (0..REPS)
        .map(|_| {
            let t = Instant::now();
            f().expect("operation");
            t.elapsed()
        })
        .collect();
    v.sort();
    v[REPS / 2]
}

fn ms(d: Duration) -> String {
    format!("{:.0}", d.as_secs_f64() * 1e3)
}

fn main() -> Result<()> {
    let t = Instant::now();
    let client = TfheRsClient::generate()?;
    let keygen = t.elapsed();
    let keys = client.evaluation_keys()?;
    let t = Instant::now();
    let ev = TfheRsEvaluator::new(&keys)?;
    let load = t.elapsed();
    println!(
        "keygen {} ms; compressed server key {:.1} MiB, loaded (decompressed) in {} ms; \
         client key {:.1} KiB\n",
        ms(keygen),
        keys.len() as f64 / (1 << 20) as f64,
        ms(load),
        client.secret_key()?.len() as f64 / 1024.0
    );
    println!(
        "| type | ciphertext | encrypt | decrypt | add | mul | mul by const | compare | compare to const \
         | and | select | min | div by const | shift | lookup (16) | cast (widen) |"
    );
    println!("|{}", "---|".repeat(16));
    let tbl: Vec<i128> = (0..16).map(|i| (i * 5) % 16).collect();
    for elem in WIDTHS {
        let wide = match elem {
            Elem::U8 => Elem::U16,
            Elem::U16 => Elem::U32,
            Elem::U32 | Elem::U64 => Elem::U64,
            Elem::I8 => Elem::I16,
            Elem::I16 => Elem::I32,
            _ => Elem::I64,
        };
        let t = Instant::now();
        let raw = client.encrypt(elem, 9)?;
        let enc = t.elapsed();
        let a = ev.load(elem, &raw)?;
        let b = ev.load(elem, &client.encrypt(elem, 5)?)?;
        let c = ev.load(Elem::Bool, &client.encrypt(Elem::Bool, 1)?)?;
        let out = ev.store(&a)?;
        let dec = median(|| client.decrypt(elem, &out).map(|_| ()));
        let row = [
            median(|| ev.add(&a, &b).map(|_| ())),
            median(|| ev.mul(&a, &b).map(|_| ())),
            median(|| ev.mul_scalar(&a, 3).map(|_| ())),
            median(|| ev.cmp(CmpOp::Lt, &a, &b).map(|_| ())),
            median(|| ev.cmp_scalar(CmpOp::Ge, &a, 7).map(|_| ())),
            median(|| ev.logic(LogicOp::And, &a, &b).map(|_| ())),
            median(|| ev.select(&c, &a, &b).map(|_| ())),
            median(|| ev.min(&a, &b).map(|_| ())),
            median(|| ev.div_scalar(&a, 7).map(|_| ())),
            median(|| ev.shift(&a, true, 2).map(|_| ())),
            median(|| ev.lookup(&b, &tbl, elem).map(|_| ())),
            median(|| ev.cast(&a, wide).map(|_| ())),
        ];
        println!(
            "| {elem} | {:.0} KiB | {} | {} | {} |",
            raw.len() as f64 / 1024.0,
            ms(enc),
            ms(dec),
            row.map(ms).join(" | ")
        );
    }
    println!("\nmilliseconds, median of {REPS}; one machine, all cores (TFHE-rs uses rayon)");
    Ok(())
}
