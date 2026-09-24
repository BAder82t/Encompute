//! Reproducible benchmark suite (0.2 P5). Each workload runs in a fresh
//! process so peak memory is its own.
//!
//!     cargo run --release --features openfhe -p encompute-runtime --example suite

use std::process::Command;
use std::time::Instant;

use encompute_backend::rng::Rng;
use encompute_ir::{Builder, Program, Range, Shape};
use encompute_runtime::{Mode, Model};

fn scalar() -> Program {
    let mut b = Builder::new("scalar_arith", 1e-3).unwrap();
    let x = b.input("x", Shape::Scalar, Range::new(-1.0, 1.0)).unwrap();
    let y = b.input("y", Shape::Scalar, Range::new(-1.0, 1.0)).unwrap();
    let xy = b.mul(x, y).unwrap();
    let c = b.constant(Shape::Scalar, vec![0.5]).unwrap();
    let z = b.add(xy, c).unwrap();
    let z = b.mul(z, x).unwrap();
    b.output("z", z).unwrap();
    b.finish().unwrap()
}

fn dot(n: usize) -> Program {
    let mut r = Rng::new(1);
    let mut b = Builder::new("dot_1024", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(n), Range::new(-1.0, 1.0))
        .unwrap();
    let w = b
        .constant(
            Shape::Vector(n),
            (0..n).map(|_| r.uniform(-0.05, 0.05)).collect(),
        )
        .unwrap();
    let d = b.dot(w, x).unwrap();
    b.output("d", d).unwrap();
    b.finish().unwrap()
}

fn matvec(rows: usize, cols: usize, name: &str, normalize: bool) -> Program {
    let mut r = Rng::new(2);
    let mut m = Vec::with_capacity(rows * cols);
    for _ in 0..rows {
        let row: Vec<f64> = (0..cols).map(|_| r.normal()).collect();
        let n = if normalize {
            row.iter().map(|x| x * x).sum::<f64>().sqrt()
        } else {
            cols as f64
        };
        m.extend(row.iter().map(|x| x / n));
    }
    let mut b = Builder::new(name, 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(cols), Range::new(-1.0, 1.0))
        .unwrap();
    let m = b.constant(Shape::Matrix(rows, cols), m).unwrap();
    let y = b.matvec(m, x).unwrap();
    b.output("y", y).unwrap();
    b.finish().unwrap()
}

fn logistic() -> Program {
    let mut r = Rng::new(3);
    let mut b = Builder::new("logistic_32", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(32), Range::new(-1.0, 1.0))
        .unwrap();
    let w = b
        .constant(
            Shape::Vector(32),
            (0..32).map(|_| r.uniform(-0.3, 0.3)).collect(),
        )
        .unwrap();
    let c = b.constant(Shape::Scalar, vec![0.1]).unwrap();
    let z = b.dot(w, x).unwrap();
    let z = b.add(z, c).unwrap();
    let s = b.sigmoid(z).unwrap();
    b.output("p", s).unwrap();
    b.finish().unwrap()
}

fn workload(name: &str) -> Program {
    match name {
        "scalar_arith" => scalar(),
        "dot_1024" => dot(1024),
        "matvec_128x128" => matvec(128, 128, "matvec_128x128", false),
        "logistic_32" => logistic(),
        "similarity_384x64" => matvec(64, 384, "similarity_384x64", true),
        _ => panic!("unknown workload {name}"),
    }
}

const WORKLOADS: [&str; 5] = [
    "scalar_arith",
    "dot_1024",
    "matvec_128x128",
    "logistic_32",
    "similarity_384x64",
];

fn one(name: &str) {
    let t = Instant::now();
    let m = Model::compile(workload(name)).unwrap();
    let compile_ms = t.elapsed().as_secs_f64() * 1e3;
    let c = m.compiled();
    let measured = m.measure(Mode::Encrypted, 20, 5).unwrap();
    let (b, r) = (&measured.cost, &measured.accuracy);
    let rel = r.outputs.iter().map(|o| o.max_relative).fold(0.0, f64::max);
    println!(
        "| {name} | {} | {} | {} | {:.1} | {:.0} | {:.1} | {:.1} | {:.1} | {:.2} | {:.2} | {:.2} | {} | {:.1e} | {:.1e} |",
        c.params.ring_dim,
        c.plan.depth,
        c.plan.rotations.len(),
        compile_ms,
        b.keygen_ms,
        b.encrypt_ms,
        b.evaluate_ms,
        b.decrypt_ms,
        b.evaluation_key_bytes as f64 / (1 << 20) as f64,
        b.request_bytes as f64 / (1 << 20) as f64,
        b.response_bytes as f64 / (1 << 20) as f64,
        b.peak_rss_bytes >> 20,
        r.max_error,
        rel,
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(name) = args.get(2).filter(|_| args[1] == "--one") {
        one(name);
        return;
    }
    println!("| workload | N | depth | rot keys | compile ms | keygen ms | encrypt ms | eval ms | decrypt ms | eval keys MiB | request MiB | response MiB | peak RSS MiB | max abs err | max rel err |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|");
    let me = std::env::current_exe().unwrap();
    for w in WORKLOADS {
        let out = Command::new(&me).args(["--one", w]).output().unwrap();
        print!("{}", String::from_utf8_lossy(&out.stdout));
        if !out.status.success() {
            eprintln!("{w} failed: {}", String::from_utf8_lossy(&out.stderr));
        }
    }
}
