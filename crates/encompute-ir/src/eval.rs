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
        let exact = program
            .node(program.inputs().find(|(_, n, _, _)| *n == name).unwrap().0)
            .ty
            .elem
            .is_exact();
        if exact {
            if let Some(x) = v.iter().find(|x| x.fract() != 0.0 || !x.is_finite()) {
                return Err(Error::new(
                    Code::BadInput,
                    format!("input {name:?} = {x} must be an integer"),
                ));
            }
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

/// Exact semantics of one exact scalar node over 128-bit integers. Range
/// analysis has proven every value fits its type.
fn eval_exact(node: &crate::Node, inputs: &Inputs, x: &[i128]) -> Result<i128> {
    use crate::program::{CmpOp, LogicOp};
    let g = |id: crate::ValueId| x[id.index()];
    let elem = node.ty.elem;
    let mask = |v: i128| {
        if elem.is_signed() || elem == crate::Elem::Bool {
            v
        } else {
            v & ((1i128 << elem.bits()) - 1)
        }
    };
    let overflow = || {
        Error::new(
            Code::Overflow,
            format!("{} overflows {elem}", node.op.mnemonic()),
        )
    };
    let c = |v: Option<i128>| v.ok_or_else(overflow);
    let v = match &node.op {
        Op::Input { name, .. } => inputs[name][0] as i128,
        Op::Const { data } => data[0] as i128,
        Op::Add(a, b) => c(g(*a).checked_add(g(*b)))?,
        Op::Sub(a, b) => c(g(*a).checked_sub(g(*b)))?,
        Op::Mul(a, b) => c(g(*a).checked_mul(g(*b)))?,
        Op::Neg(a) => c(g(*a).checked_neg())?,
        Op::Cmp(c, a, b) => {
            let (a, b) = (g(*a), g(*b));
            i128::from(match c {
                CmpOp::Eq => a == b,
                CmpOp::Ne => a != b,
                CmpOp::Lt => a < b,
                CmpOp::Le => a <= b,
                CmpOp::Gt => a > b,
                CmpOp::Ge => a >= b,
            })
        }
        Op::Logic(l, a, b) => match l {
            LogicOp::And => g(*a) & g(*b),
            LogicOp::Or => g(*a) | g(*b),
            LogicOp::Xor => g(*a) ^ g(*b),
        },
        Op::Not(a) if elem == crate::Elem::Bool => 1 - g(*a),
        Op::Not(a) => mask(!g(*a)),
        Op::Shift {
            x: a,
            left: true,
            by,
        } => c(g(*a).checked_mul(1 << by))?,
        Op::Shift {
            x: a,
            left: false,
            by,
        } => g(*a) >> by,
        Op::Min(a, b) => g(*a).min(g(*b)),
        Op::Max(a, b) => g(*a).max(g(*b)),
        Op::Select(c, a, b) => {
            if g(*c) != 0 {
                g(*a)
            } else {
                g(*b)
            }
        }
        Op::Lookup { x: a, table } => {
            let i = g(*a);
            match usize::try_from(i).ok().and_then(|i| table.get(i)) {
                Some(v) => *v as i128,
                None => {
                    return Err(Error::new(
                        Code::BadInput,
                        format!("lookup index {i} is outside the table (0..{})", table.len()),
                    ))
                }
            }
        }
        Op::Cast(a) => g(*a),
        Op::Div(a, b) => g(*a) / g(*b),
        Op::Rem(a, b) => g(*a) % g(*b),
        op => unreachable!("{} is not an exact scalar op", op.mnemonic()),
    };
    // Checked semantics even when range analysis was skipped.
    let (min, max) = elem.bounds();
    if v < min || v > max {
        return Err(overflow());
    }
    Ok(v)
}

/// Evaluate `program`: `f64` for approximate values, 128-bit integers for
/// exact ones (reported as `f64`, exact within ±2^53).
pub fn evaluate(program: &Program, inputs: &Inputs) -> Result<Outputs> {
    check_inputs(program, inputs)?;
    let mut values: Vec<Vec<f64>> = Vec::with_capacity(program.nodes().len());
    let mut exact: Vec<i128> = Vec::with_capacity(program.nodes().len());
    for (_, node) in program.iter() {
        if node.ty.elem.is_exact() {
            let v = eval_exact(node, inputs, &exact)?;
            exact.push(v);
            values.push(vec![v as f64]);
            continue;
        }
        exact.push(0);
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
            op => unreachable!("{} has an exact result type", op.mnemonic()),
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
