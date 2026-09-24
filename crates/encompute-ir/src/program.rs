use std::collections::HashSet;

use crate::error::{type_error, Code, Error, Result};
use crate::types::{Range, Shape, Type, ValueId, Visibility};

/// An IR operation. Operands always refer to earlier nodes.
#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    /// Encrypted program input; every element lies in `range`.
    /// MLIR: a `secret.secret<tensor<…xf64>>` block argument of `secret.generic`.
    Input { name: String, range: Range },
    /// Public constant, row-major. MLIR: `arith.constant dense<…>`.
    Const { data: Vec<f64> },
    /// Elementwise; a scalar operand broadcasts. MLIR: `arith.addf`.
    Add(ValueId, ValueId),
    /// Elementwise; a scalar operand broadcasts. MLIR: `arith.subf`.
    Sub(ValueId, ValueId),
    /// Elementwise; a scalar operand broadcasts. MLIR: `arith.mulf`.
    Mul(ValueId, ValueId),
    /// MLIR: `arith.negf`.
    Neg(ValueId),
    /// Vector → scalar. MLIR: `linalg.reduce { arith.addf }`.
    Sum(ValueId),
    /// Vector · vector → scalar. MLIR: `linalg.dot`.
    Dot(ValueId, ValueId),
    /// Public matrix × vector → vector. MLIR: `linalg.matvec`.
    MatVec(ValueId, ValueId),
    /// Elementwise `c0 + c1·x + c2·x² + …`. MLIR: `polynomial.eval`, or
    /// expanded to `arith` ops.
    Poly { x: ValueId, coeffs: Vec<f64> },
    /// Elementwise `1 / (1 + e^-x)`. Lowered to a Chebyshev approximation over
    /// the analyzed input range. MLIR: `math` ops, approximated by HEIR's
    /// `polynomial-approximation` pass.
    Sigmoid(ValueId),
}

impl Op {
    /// Mnemonic used in the textual form.
    pub fn mnemonic(&self) -> &'static str {
        match self {
            Op::Input { .. } => "input",
            Op::Const { .. } => "const",
            Op::Add(..) => "add",
            Op::Sub(..) => "sub",
            Op::Mul(..) => "mul",
            Op::Neg(..) => "neg",
            Op::Sum(..) => "sum",
            Op::Dot(..) => "dot",
            Op::MatVec(..) => "matvec",
            Op::Poly { .. } => "poly",
            Op::Sigmoid(..) => "sigmoid",
        }
    }

    pub fn operands(&self) -> Vec<ValueId> {
        match self {
            Op::Input { .. } | Op::Const { .. } => vec![],
            Op::Add(a, b) | Op::Sub(a, b) | Op::Mul(a, b) | Op::Dot(a, b) | Op::MatVec(a, b) => {
                vec![*a, *b]
            }
            Op::Neg(a) | Op::Sum(a) | Op::Sigmoid(a) | Op::Poly { x: a, .. } => vec![*a],
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub op: Op,
    pub ty: Type,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Output {
    pub name: String,
    pub value: ValueId,
}

/// A verified Encompute program. Construct with [`Builder`] or [`crate::parse`].
#[derive(Clone, Debug, PartialEq)]
pub struct Program {
    name: String,
    precision: f64,
    nodes: Vec<Node>,
    outputs: Vec<Output>,
}

impl Program {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Maximum absolute error allowed on every output element.
    pub fn precision(&self) -> f64 {
        self.precision
    }

    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    pub fn node(&self, id: ValueId) -> &Node {
        &self.nodes[id.index()]
    }

    /// Nodes paired with their ids, in definition order.
    pub fn iter(&self) -> impl Iterator<Item = (ValueId, &Node)> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (ValueId(i as u32), n))
    }

    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// Inputs as `(id, name, shape, range)`, in definition order.
    pub fn inputs(&self) -> impl Iterator<Item = (ValueId, &str, Shape, Range)> {
        self.iter().filter_map(|(id, n)| match &n.op {
            Op::Input { name, range } => Some((id, name.as_str(), n.ty.shape, *range)),
            _ => None,
        })
    }

    /// Whether each node contributes to some output.
    pub fn live(&self) -> Vec<bool> {
        let mut live = vec![false; self.nodes.len()];
        let mut stack: Vec<ValueId> = self.outputs.iter().map(|o| o.value).collect();
        while let Some(id) = stack.pop() {
            if !live[id.index()] {
                live[id.index()] = true;
                stack.extend(self.node(id).op.operands());
            }
        }
        live
    }
}

/// Builds a [`Program`], checking the type rules as each node is added.
#[derive(Debug)]
pub struct Builder {
    program: Program,
    input_names: HashSet<String>,
}

impl Builder {
    pub fn new(name: &str, precision: f64) -> Result<Self> {
        check_ident("program name", name)?;
        if !(precision.is_finite() && precision > 0.0) {
            return Err(type_error(format!(
                "precision must be a positive number, got {precision}"
            )));
        }
        Ok(Self {
            program: Program {
                name: name.to_owned(),
                precision,
                nodes: vec![],
                outputs: vec![],
            },
            input_names: HashSet::new(),
        })
    }

    /// Number of nodes added so far; the id the next node will get.
    pub fn len(&self) -> usize {
        self.program.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.program.nodes.is_empty()
    }

    pub fn ty(&self, id: ValueId) -> Result<Type> {
        self.program
            .nodes
            .get(id.index())
            .map(|n| n.ty)
            .ok_or_else(|| type_error(format!("{id} is not defined")))
    }

    pub fn input(&mut self, name: &str, shape: Shape, range: Range) -> Result<ValueId> {
        check_ident("input name", name)?;
        check_dims(shape)?;
        if !self.input_names.insert(name.to_owned()) {
            return Err(type_error(format!("duplicate input {name:?}")));
        }
        match shape {
            Shape::Scalar => {}
            Shape::Vector(n) if n > 0 => {}
            _ => {
                return Err(type_error(format!(
                    "input {name:?} must be a scalar or non-empty vector, got {shape}"
                )))
            }
        }
        if !range.is_valid() {
            return Err(Error::new(
                Code::MissingRange,
                format!(
                    "input {name:?} needs a finite range with lo < hi, got [{}, {}]",
                    range.lo, range.hi
                ),
            ));
        }
        let op = Op::Input {
            name: name.to_owned(),
            range,
        };
        Ok(self.push(op, Visibility::Secret, shape))
    }

    pub fn constant(&mut self, shape: Shape, data: Vec<f64>) -> Result<ValueId> {
        check_dims(shape)?;
        if shape.is_empty() {
            return Err(type_error(format!("constant of empty shape {shape}")));
        }
        if data.len() != shape.len() {
            return Err(type_error(format!(
                "constant of shape {shape} needs {} values, got {}",
                shape.len(),
                data.len()
            )));
        }
        if let Some(x) = data.iter().find(|x| !x.is_finite()) {
            return Err(type_error(format!(
                "constant contains non-finite value {x}"
            )));
        }
        Ok(self.push(Op::Const { data }, Visibility::Public, shape))
    }

    pub fn add(&mut self, a: ValueId, b: ValueId) -> Result<ValueId> {
        self.elementwise(Op::Add(a, b), a, b)
    }

    pub fn sub(&mut self, a: ValueId, b: ValueId) -> Result<ValueId> {
        self.elementwise(Op::Sub(a, b), a, b)
    }

    pub fn mul(&mut self, a: ValueId, b: ValueId) -> Result<ValueId> {
        self.elementwise(Op::Mul(a, b), a, b)
    }

    pub fn neg(&mut self, a: ValueId) -> Result<ValueId> {
        let t = self.secret_operand("neg", a)?;
        self.unary_shape("neg", t.shape)?;
        Ok(self.push(Op::Neg(a), Visibility::Secret, t.shape))
    }

    pub fn sum(&mut self, a: ValueId) -> Result<ValueId> {
        let t = self.secret_operand("sum", a)?;
        match t.shape {
            Shape::Vector(_) => Ok(self.push(Op::Sum(a), Visibility::Secret, Shape::Scalar)),
            s => Err(type_error(format!("sum needs a vector, got {s}"))),
        }
    }

    pub fn dot(&mut self, a: ValueId, b: ValueId) -> Result<ValueId> {
        let (ta, tb) = (self.ty(a)?, self.ty(b)?);
        self.any_secret("dot", ta, tb)?;
        match (ta.shape, tb.shape) {
            (Shape::Vector(n), Shape::Vector(m)) if n == m => {
                Ok(self.push(Op::Dot(a, b), Visibility::Secret, Shape::Scalar))
            }
            (sa, sb) => Err(type_error(format!(
                "dot needs two vectors of equal length, got {sa} and {sb}"
            ))),
        }
    }

    pub fn matvec(&mut self, m: ValueId, v: ValueId) -> Result<ValueId> {
        let (tm, tv) = (self.ty(m)?, self.ty(v)?);
        if tm.visibility != Visibility::Public {
            return Err(Error::new(
                Code::Unsupported,
                "matvec needs a public matrix in v0.1 (secret × secret matrix products are not supported)",
            ));
        }
        self.any_secret("matvec", tm, tv)?;
        match (tm.shape, tv.shape) {
            (Shape::Matrix(r, c), Shape::Vector(n)) if c == n => {
                Ok(self.push(Op::MatVec(m, v), Visibility::Secret, Shape::Vector(r)))
            }
            (sm, sv) => Err(type_error(format!(
                "matvec needs matrix<RxC> and vector<C>, got {sm} and {sv}"
            ))),
        }
    }

    pub fn poly(&mut self, x: ValueId, coeffs: Vec<f64>) -> Result<ValueId> {
        let t = self.secret_operand("poly", x)?;
        self.unary_shape("poly", t.shape)?;
        if coeffs.len() < 2 {
            return Err(type_error(
                "poly needs at least two coefficients (degree ≥ 1)",
            ));
        }
        if let Some(c) = coeffs.iter().find(|c| !c.is_finite()) {
            return Err(type_error(format!("poly coefficient {c} is not finite")));
        }
        Ok(self.push(Op::Poly { x, coeffs }, Visibility::Secret, t.shape))
    }

    pub fn sigmoid(&mut self, x: ValueId) -> Result<ValueId> {
        let t = self.secret_operand("sigmoid", x)?;
        self.unary_shape("sigmoid", t.shape)?;
        Ok(self.push(Op::Sigmoid(x), Visibility::Secret, t.shape))
    }

    pub fn output(&mut self, name: &str, value: ValueId) -> Result<()> {
        check_ident("output name", name)?;
        let t = self.ty(value)?;
        if self.program.outputs.iter().any(|o| o.name == name) {
            return Err(type_error(format!("duplicate output {name:?}")));
        }
        if t.visibility != Visibility::Secret {
            return Err(type_error(format!(
                "output {name:?} does not depend on any secret input; compute it outside Encompute"
            )));
        }
        self.program.outputs.push(Output {
            name: name.to_owned(),
            value,
        });
        Ok(())
    }

    pub fn finish(self) -> Result<Program> {
        if self.program.outputs.is_empty() {
            return Err(type_error("program has no outputs"));
        }
        Ok(self.program)
    }

    /// Rebuild `op` through the checked constructors, used by the parser.
    pub(crate) fn push_op(&mut self, op: Op, shape: Shape) -> Result<ValueId> {
        match op {
            Op::Input { name, range } => self.input(&name, shape, range),
            Op::Const { data } => self.constant(shape, data),
            Op::Add(a, b) => self.add(a, b),
            Op::Sub(a, b) => self.sub(a, b),
            Op::Mul(a, b) => self.mul(a, b),
            Op::Neg(a) => self.neg(a),
            Op::Sum(a) => self.sum(a),
            Op::Dot(a, b) => self.dot(a, b),
            Op::MatVec(m, v) => self.matvec(m, v),
            Op::Poly { x, coeffs } => self.poly(x, coeffs),
            Op::Sigmoid(x) => self.sigmoid(x),
        }
    }

    fn push(&mut self, op: Op, visibility: Visibility, shape: Shape) -> ValueId {
        let id = ValueId(self.program.nodes.len() as u32);
        self.program.nodes.push(Node {
            op,
            ty: Type { visibility, shape },
        });
        id
    }

    fn elementwise(&mut self, op: Op, a: ValueId, b: ValueId) -> Result<ValueId> {
        let (ta, tb) = (self.ty(a)?, self.ty(b)?);
        let name = op.mnemonic();
        self.any_secret(name, ta, tb)?;
        self.unary_shape(name, ta.shape)?;
        self.unary_shape(name, tb.shape)?;
        let shape = match (ta.shape, tb.shape) {
            (x, y) if x == y => x,
            (Shape::Scalar, y) => y,
            (x, Shape::Scalar) => x,
            (x, y) => {
                return Err(type_error(format!(
                    "{name} needs equal shapes or a scalar operand, got {x} and {y}"
                )))
            }
        };
        Ok(self.push(op, Visibility::Secret, shape))
    }

    fn secret_operand(&self, name: &str, a: ValueId) -> Result<Type> {
        let t = self.ty(a)?;
        if t.visibility != Visibility::Secret {
            return Err(public_only(name));
        }
        Ok(t)
    }

    fn any_secret(&self, name: &str, a: Type, b: Type) -> Result<()> {
        if a.visibility.join(b.visibility) != Visibility::Secret {
            return Err(public_only(name));
        }
        Ok(())
    }

    fn unary_shape(&self, name: &str, shape: Shape) -> Result<()> {
        match shape {
            Shape::Scalar | Shape::Vector(_) => Ok(()),
            s => Err(type_error(format!("{name} does not accept {s}"))),
        }
    }
}

/// Largest vector length or matrix dimension: the slot count of the largest
/// 128-bit ring (N = 2^16) supported without bootstrapping.
pub const MAX_DIM: usize = 32768;

fn check_dims(shape: Shape) -> Result<()> {
    let (a, b) = match shape {
        Shape::Scalar => (1, 1),
        Shape::Vector(n) => (n, 1),
        Shape::Matrix(r, c) => (r, c),
    };
    if a > MAX_DIM || b > MAX_DIM {
        return Err(Error::new(
            Code::Unsupported,
            format!("{shape} exceeds the maximum dimension {MAX_DIM}"),
        ));
    }
    Ok(())
}

fn public_only(name: &str) -> Error {
    type_error(format!(
        "{name} has only public operands; fold public computations before tracing"
    ))
}

pub(crate) fn check_ident(what: &str, s: &str) -> Result<()> {
    let mut chars = s.chars();
    let ok = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(type_error(format!(
            "{what} {s:?} must match [A-Za-z_][A-Za-z0-9_]*"
        )))
    }
}
