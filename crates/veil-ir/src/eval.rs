//! Plaintext reference semantics. Every backend is tested against this.

use std::collections::BTreeMap;

use crate::error::{Code, Error, Result};
use crate::program::{Op, Program};
use crate::types::{Shape, Visibility};

/// Input values by name; a scalar is a one-element vector.
pub type Inputs = BTreeMap<String, Vec<f64>>;
/// Output values by name; a scalar is a one-element vector.
pub type Outputs = BTreeMap<String, Vec<f64>>;

/// Check that `inputs` names exactly the program's inputs, with the right
/// lengths and every element inside its declared range.
pub fn check_inputs(program: &Program, inputs: &Inputs) -> Result<()> {
    let mut expected = 0;
    for (_, name, shape, range) in program.inputs() {
        expected += 1;
        let v = inputs
            .get(name)
            .ok_or_else(|| Error::new(Code::BadInput, format!("missing input {name:?}")))?;
        if v.len() != shape.len() {
            return Err(Error::new(
                Code::BadInput,
                format!(
                    "input {name:?} needs {} values, got {}",
                    shape.len(),
                    v.len()
                ),
            ));
        }
        if let Some((i, x)) = v.iter().enumerate().find(|(_, x)| !range.contains(**x)) {
            return Err(Error::new(
                Code::BadInput,
                format!(
                    "input {name:?}[{i}] = {x} is outside its declared range [{}, {}]",
                    range.lo, range.hi
                ),
            ));
        }
    }
    if inputs.len() != expected {
        let known: Vec<&str> = program.inputs().map(|(_, n, _, _)| n).collect();
        let extra: Vec<&String> = inputs
            .keys()
            .filter(|k| !known.contains(&k.as_str()))
            .collect();
        return Err(Error::new(
            Code::BadInput,
            format!("unknown inputs {extra:?}"),
        ));
    }
    Ok(())
}

pub fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

/// Evaluate `program` exactly in `f64`.
pub fn evaluate(program: &Program, inputs: &Inputs) -> Result<Outputs> {
    check_inputs(program, inputs)?;
    let mut values: Vec<Vec<f64>> = Vec::with_capacity(program.nodes().len());
    for (_, node) in program.iter() {
        let get = |id: crate::ValueId| &values[id.index()];
        let v = match &node.op {
            Op::Input { name, .. } => inputs[name].clone(),
            Op::Const { data } => data.clone(),
            Op::Add(a, b) => zip(get(*a), get(*b), |x, y| x + y),
            Op::Sub(a, b) => zip(get(*a), get(*b), |x, y| x - y),
            Op::Mul(a, b) => zip(get(*a), get(*b), |x, y| x * y),
            Op::Neg(a) => get(*a).iter().map(|x| -x).collect(),
            Op::Sum(a) => vec![get(*a).iter().sum()],
            Op::Dot(a, b) => vec![get(*a).iter().zip(get(*b)).map(|(x, y)| x * y).sum()],
            Op::MatVec(m, v) => {
                let Shape::Matrix(rows, cols) = program.node(*m).ty.shape else {
                    unreachable!("verified by the builder")
                };
                let (m, v) = (get(*m), get(*v));
                (0..rows)
                    .map(|r| (0..cols).map(|c| m[r * cols + c] * v[c]).sum())
                    .collect()
            }
            Op::Poly { x, coeffs } => get(*x).iter().map(|&x| horner(coeffs, x)).collect(),
            Op::Sigmoid(x) => get(*x).iter().map(|&x| sigmoid(x)).collect(),
        };
        debug_assert!(node.ty.visibility == Visibility::Public || !v.is_empty());
        values.push(v);
    }
    Ok(program
        .outputs()
        .iter()
        .map(|o| (o.name.clone(), values[o.value.index()].clone()))
        .collect())
}

/// `c0 + c1·x + …` by Horner's rule.
pub fn horner(coeffs: &[f64], x: f64) -> f64 {
    coeffs.iter().rev().fold(0.0, |acc, c| acc * x + c)
}

/// Elementwise with scalar broadcast.
fn zip(a: &[f64], b: &[f64], f: impl Fn(f64, f64) -> f64) -> Vec<f64> {
    match (a.len(), b.len()) {
        (1, _) => b.iter().map(|&y| f(a[0], y)).collect(),
        (_, 1) => a.iter().map(|&x| f(x, b[0])).collect(),
        _ => a.iter().zip(b).map(|(&x, &y)| f(x, y)).collect(),
    }
}
