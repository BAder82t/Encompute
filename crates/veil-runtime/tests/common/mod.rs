//! Demo workloads shared by the mock and OpenFHE tests.

use veil_backend::rng::Rng;
use veil_ir::{Builder, Program, Range, Shape};

pub fn logistic(features: usize, seed: u64) -> Program {
    let mut rng = Rng::new(seed);
    let mut b = Builder::new("logistic", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(features), Range::new(-1.0, 1.0))
        .unwrap();
    let w: Vec<f64> = (0..features).map(|_| rng.uniform(-0.4, 0.4)).collect();
    let w = b.constant(Shape::Vector(features), w).unwrap();
    let bias = b.constant(Shape::Scalar, vec![0.25]).unwrap();
    let z = b.dot(w, x).unwrap();
    let z = b.add(z, bias).unwrap();
    let y = b.sigmoid(z).unwrap();
    b.output("score", y).unwrap();
    b.finish().unwrap()
}

pub fn similarity(dim: usize, docs: usize, seed: u64) -> Program {
    let mut rng = Rng::new(seed);
    let mut m = Vec::with_capacity(dim * docs);
    for _ in 0..docs {
        let row: Vec<f64> = (0..dim).map(|_| rng.normal()).collect();
        let norm = row.iter().map(|x| x * x).sum::<f64>().sqrt();
        m.extend(row.iter().map(|x| x / norm));
    }
    let mut b = Builder::new("similarity", 1e-3).unwrap();
    let q = b
        .input("q", Shape::Vector(dim), Range::new(-1.0, 1.0))
        .unwrap();
    let m = b.constant(Shape::Matrix(docs, dim), m).unwrap();
    let s = b.matvec(m, q).unwrap();
    b.output("scores", s).unwrap();
    b.finish().unwrap()
}

