use std::collections::HashSet;

use crate::error::{type_error, Code, Error, Result};
use crate::types::{Elem, Range, Shape, Type, ValueId, Visibility};

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

    // --- exact scalar ops (0.3); lowered to TFHE, never to CKKS ---------------
    /// Comparison → bool. MLIR: `arith.cmpi`.
    Cmp(CmpOp, ValueId, ValueId),
    /// Boolean logic on bools, bitwise on integers. MLIR: `arith.andi/ori/xori`.
    Logic(LogicOp, ValueId, ValueId),
    /// Boolean or bitwise not. MLIR: `arith.xori` with all-ones.
    Not(ValueId),
    /// Shift by a public amount. MLIR: `arith.shli` / `arith.shrsi|shrui`.
    Shift { x: ValueId, left: bool, by: u32 },
    /// MLIR: `arith.minsi/minui`.
    Min(ValueId, ValueId),
    /// MLIR: `arith.maxsi/maxui`.
    Max(ValueId, ValueId),
    /// `cond ? a : b` with an encrypted condition. MLIR: `arith.select`.
    Select(ValueId, ValueId, ValueId),
    /// `table[x]` for x in `0..table.len()`. MLIR: `tensor.extract` from a
    /// constant (HEIR lowers to a programmable bootstrap).
    Lookup { x: ValueId, table: Vec<f64> },
    /// Integer width or signedness change (bool → int allowed); the value must
    /// fit the target. MLIR: `arith.extsi/extui/trunci`.
    Cast(ValueId),
    /// Truncating division by a public non-zero constant. MLIR: `arith.divsi/divui`.
    Div(ValueId, ValueId),
    /// Remainder by a public non-zero constant. MLIR: `arith.remsi/remui`.
    Rem(ValueId, ValueId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogicOp {
    And,
    Or,
    Xor,
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
            Op::Cmp(c, ..) => match c {
                CmpOp::Eq => "eq",
                CmpOp::Ne => "ne",
                CmpOp::Lt => "lt",
                CmpOp::Le => "le",
                CmpOp::Gt => "gt",
                CmpOp::Ge => "ge",
            },
            Op::Logic(l, ..) => match l {
                LogicOp::And => "and",
                LogicOp::Or => "or",
                LogicOp::Xor => "xor",
            },
            Op::Not(..) => "not",
            Op::Shift { left: true, .. } => "shl",
            Op::Shift { left: false, .. } => "shr",
            Op::Min(..) => "min",
            Op::Max(..) => "max",
            Op::Select(..) => "select",
            Op::Lookup { .. } => "lookup",
            Op::Cast(..) => "cast",
            Op::Div(..) => "div",
            Op::Rem(..) => "rem",
        }
    }

    pub fn operands(&self) -> Vec<ValueId> {
        match self {
            Op::Input { .. } | Op::Const { .. } => vec![],
            Op::Add(a, b) | Op::Sub(a, b) | Op::Mul(a, b) | Op::Dot(a, b) | Op::MatVec(a, b) => {
                vec![*a, *b]
            }
            Op::Neg(a) | Op::Sum(a) | Op::Sigmoid(a) | Op::Poly { x: a, .. } => vec![*a],
            Op::Cmp(_, a, b)
            | Op::Logic(_, a, b)
            | Op::Min(a, b)
            | Op::Max(a, b)
            | Op::Div(a, b)
            | Op::Rem(a, b) => vec![*a, *b],
            Op::Not(a) | Op::Cast(a) | Op::Shift { x: a, .. } | Op::Lookup { x: a, .. } => vec![*a],
            Op::Select(c, a, b) => vec![*c, *a, *b],
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

/// How strongly an execution must be verified (ADR-009). Part of the
/// program: it changes what the program compiles to, so it is part of the
/// program ID.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Verification {
    /// Signed execution receipts only (the default).
    #[default]
    Receipt,
    /// A cryptographic execution proof is required; compilation fails unless
    /// a proof backend covers the whole program, and clients never decrypt
    /// without a valid proof.
    Required,
}

impl Verification {
    pub fn name(self) -> &'static str {
        match self {
            Verification::Receipt => "receipt",
            Verification::Required => "required",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "receipt" => Some(Verification::Receipt),
            "required" => Some(Verification::Required),
            _ => None,
        }
    }
}

/// A verified Encompute program. Construct with [`Builder`] or [`crate::parse`].
#[derive(Clone, Debug, PartialEq)]
pub struct Program {
    name: String,
    precision: f64,
    verification: Verification,
    /// Confidentiality declarations (ADR-010); `None` for programs that
    /// declare no parties or assets.
    confidentiality: Option<crate::confidentiality::Confidentiality>,
    nodes: Vec<Node>,
    outputs: Vec<Output>,
}

impl Program {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The verification the program requires.
    pub fn verification(&self) -> Verification {
        self.verification
    }

    /// Confidentiality declarations, if any.
    pub fn confidentiality(&self) -> Option<&crate::confidentiality::Confidentiality> {
        self.confidentiality.as_ref()
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
                verification: Verification::Receipt,
                confidentiality: None,
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
        if t.elem.is_exact() {
            if !t.elem.is_int() {
                return Err(type_error("neg on bool; use not"));
            }
            if !t.elem.is_signed() {
                return Err(type_error(format!(
                    "neg on unsigned {}; subtract from a constant instead",
                    t.elem
                )));
            }
            return Ok(self.push_typed(Op::Neg(a), Visibility::Secret, Shape::Scalar, t.elem));
        }
        self.unary_shape("neg", t.shape)?;
        Ok(self.push(Op::Neg(a), Visibility::Secret, t.shape))
    }

    pub fn sum(&mut self, a: ValueId) -> Result<ValueId> {
        let t = self.secret_operand("sum", a)?;
        self.approx_only("sum", &[a])?;
        match t.shape {
            Shape::Vector(_) => Ok(self.push(Op::Sum(a), Visibility::Secret, Shape::Scalar)),
            s => Err(type_error(format!("sum needs a vector, got {s}"))),
        }
    }

    pub fn dot(&mut self, a: ValueId, b: ValueId) -> Result<ValueId> {
        let (ta, tb) = (self.ty(a)?, self.ty(b)?);
        self.any_secret("dot", ta, tb)?;
        self.approx_only("dot", &[a, b])?;
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
        self.approx_only("matvec", &[m, v])?;
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
        self.approx_only("poly", &[x])?;
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
        self.approx_only("sigmoid", &[x])?;
        self.unary_shape("sigmoid", t.shape)?;
        Ok(self.push(Op::Sigmoid(x), Visibility::Secret, t.shape))
    }

    /// Exact scalar input. Without a range, the type's full range; bools are
    /// always `[0, 1]`.
    pub fn input_exact(&mut self, name: &str, elem: Elem, range: Option<Range>) -> Result<ValueId> {
        check_ident("input name", name)?;
        if !elem.is_exact() {
            return Err(type_error("input_exact needs an exact type"));
        }
        let (min, max) = elem.bounds();
        let range = match (elem, range) {
            (Elem::Bool, _) => Range::new(0.0, 1.0),
            // Values cross the API as f64: ranges stop at ±2^53 (ADR-006).
            (_, None) => Range::new(min.max(-MAX_EXACT_IO) as f64, max.min(MAX_EXACT_IO) as f64),
            (_, Some(r)) => r,
        };
        let (min, max) = (min.max(-MAX_EXACT_IO), max.min(MAX_EXACT_IO));
        let integral = |x: f64| x.is_finite() && x.fract() == 0.0;
        if !(integral(range.lo) && integral(range.hi) && range.lo <= range.hi)
            || (range.lo as i128) < min
            || (range.hi as i128) > max
        {
            return Err(Error::new(
                Code::MissingRange,
                format!(
                    "input {name:?}: range [{}, {}] must be integers within [{min}, {max}] \
                     ({elem}, and at most 2^53 in magnitude)",
                    range.lo, range.hi
                ),
            ));
        }
        if !self.input_names.insert(name.to_owned()) {
            return Err(type_error(format!("duplicate input {name:?}")));
        }
        let op = Op::Input {
            name: name.to_owned(),
            range,
        };
        Ok(self.push_typed(op, Visibility::Secret, Shape::Scalar, elem))
    }

    /// Public exact scalar constant.
    pub fn constant_exact(&mut self, elem: Elem, value: f64) -> Result<ValueId> {
        let (min, max) = elem.bounds();
        let (min, max) = (min.max(-MAX_EXACT_IO), max.min(MAX_EXACT_IO));
        if !elem.is_exact()
            || !value.is_finite()
            || value.fract() != 0.0
            || (value as i128) < min
            || (value as i128) > max
        {
            return Err(type_error(format!(
                "constant {value} is not a valid {elem}"
            )));
        }
        Ok(self.push_typed(
            Op::Const { data: vec![value] },
            Visibility::Public,
            Shape::Scalar,
            elem,
        ))
    }

    pub fn cmp(&mut self, op: CmpOp, a: ValueId, b: ValueId) -> Result<ValueId> {
        let name = Op::Cmp(op, a, b).mnemonic();
        let elem = self.exact_pair(name, a, b)?;
        if elem == Elem::Bool && !matches!(op, CmpOp::Eq | CmpOp::Ne) {
            return Err(type_error(format!(
                "{name} on bool; only eq/ne compare bools"
            )));
        }
        Ok(self.push_typed(
            Op::Cmp(op, a, b),
            Visibility::Secret,
            Shape::Scalar,
            Elem::Bool,
        ))
    }

    pub fn logic(&mut self, op: LogicOp, a: ValueId, b: ValueId) -> Result<ValueId> {
        let elem = self.exact_pair(Op::Logic(op, a, b).mnemonic(), a, b)?;
        Ok(self.push_typed(Op::Logic(op, a, b), Visibility::Secret, Shape::Scalar, elem))
    }

    pub fn not(&mut self, a: ValueId) -> Result<ValueId> {
        self.secret_operand("not", a)?;
        let t = self.exact_operand("not", a)?;
        Ok(self.push_typed(Op::Not(a), Visibility::Secret, Shape::Scalar, t.elem))
    }

    pub fn shift(&mut self, x: ValueId, left: bool, by: u32) -> Result<ValueId> {
        self.secret_operand("shift", x)?;
        let t = self.exact_operand("shift", x)?;
        if !t.elem.is_int() || by >= t.elem.bits() {
            return Err(type_error(format!(
                "shift of {} by {by} is not valid",
                t.elem
            )));
        }
        Ok(self.push_typed(
            Op::Shift { x, left, by },
            Visibility::Secret,
            Shape::Scalar,
            t.elem,
        ))
    }

    pub fn min(&mut self, a: ValueId, b: ValueId) -> Result<ValueId> {
        self.min_max(Op::Min(a, b), a, b)
    }

    pub fn max(&mut self, a: ValueId, b: ValueId) -> Result<ValueId> {
        self.min_max(Op::Max(a, b), a, b)
    }

    fn min_max(&mut self, op: Op, a: ValueId, b: ValueId) -> Result<ValueId> {
        let elem = self.exact_pair(op.mnemonic(), a, b)?;
        if !elem.is_int() {
            return Err(type_error(format!("{} needs integers", op.mnemonic())));
        }
        Ok(self.push_typed(op, Visibility::Secret, Shape::Scalar, elem))
    }

    /// `cond ? a : b` without revealing `cond`.
    pub fn select(&mut self, cond: ValueId, a: ValueId, b: ValueId) -> Result<ValueId> {
        let tc = self.secret_operand("select condition", cond)?;
        if tc.elem != Elem::Bool {
            return Err(type_error(format!(
                "select needs a bool condition, got {}",
                tc.elem
            )));
        }
        let (ta, tb) = (
            self.exact_operand("select", a)?,
            self.exact_operand("select", b)?,
        );
        if ta.elem != tb.elem {
            return Err(type_error(format!(
                "select branches differ: {} and {}",
                ta.elem, tb.elem
            )));
        }
        Ok(self.push_typed(
            Op::Select(cond, a, b),
            Visibility::Secret,
            Shape::Scalar,
            ta.elem,
        ))
    }

    /// `table[x]`; every entry must be a valid value of `x`'s type.
    pub fn lookup(&mut self, x: ValueId, table: Vec<f64>) -> Result<ValueId> {
        self.secret_operand("lookup", x)?;
        let t = self.exact_operand("lookup", x)?;
        let (min, max) = t.elem.bounds();
        let (min, max) = (min.max(-MAX_EXACT_IO), max.min(MAX_EXACT_IO));
        if table.is_empty() || table.len() > 1 << 16 {
            return Err(type_error("lookup table needs 1 to 65536 entries"));
        }
        if let Some(v) = table.iter().find(|v| {
            !v.is_finite() || v.fract() != 0.0 || (**v as i128) < min || (**v as i128) > max
        }) {
            return Err(type_error(format!(
                "lookup entry {v} is not a valid {}",
                t.elem
            )));
        }
        Ok(self.push_typed(
            Op::Lookup { x, table },
            Visibility::Secret,
            Shape::Scalar,
            t.elem,
        ))
    }

    /// Convert to integer type `to`; the value must fit (checked by range analysis).
    pub fn cast(&mut self, x: ValueId, to: Elem) -> Result<ValueId> {
        self.secret_operand("cast", x)?;
        self.exact_operand("cast", x)?;
        if !to.is_int() {
            return Err(type_error(format!(
                "cast target must be an integer type, got {to}"
            )));
        }
        Ok(self.push_typed(Op::Cast(x), Visibility::Secret, Shape::Scalar, to))
    }

    pub fn div(&mut self, a: ValueId, b: ValueId) -> Result<ValueId> {
        self.div_rem(Op::Div(a, b), a, b)
    }

    pub fn rem(&mut self, a: ValueId, b: ValueId) -> Result<ValueId> {
        self.div_rem(Op::Rem(a, b), a, b)
    }

    fn div_rem(&mut self, op: Op, a: ValueId, b: ValueId) -> Result<ValueId> {
        let name = op.mnemonic();
        let ta = self.secret_operand(name, a)?;
        let tb = self.ty(b)?;
        let divisor = match &self.program.node(b).op {
            Op::Const { data } if tb.visibility == Visibility::Public => data[0],
            _ => {
                return Err(Error::new(
                    Code::SecretDivision,
                    format!("{name} needs a public constant divisor in 0.3"),
                ))
            }
        };
        if !ta.elem.is_int() || ta.elem != tb.elem {
            return Err(type_error(format!("{name} needs two integers of one type")));
        }
        if divisor == 0.0 {
            return Err(type_error(format!("{name} by zero")));
        }
        Ok(self.push_typed(op, Visibility::Secret, Shape::Scalar, ta.elem))
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

    /// Require verified execution (see [`Verification`]).
    pub fn verification(&mut self, v: Verification) {
        self.program.verification = v;
    }

    fn conf(&mut self) -> &mut crate::confidentiality::Confidentiality {
        self.program
            .confidentiality
            .get_or_insert_with(Default::default)
    }

    /// Declare the computation's purpose.
    pub fn purpose(&mut self, purpose: &str) -> Result<()> {
        crate::confidentiality::check_text("purpose", purpose)?;
        self.conf().purpose = Some(purpose.to_owned());
        Ok(())
    }

    pub fn party(&mut self, id: &str, name: &str) -> Result<()> {
        let id = crate::confidentiality::PartyId::new(id)?;
        crate::confidentiality::check_text("party name", name)?;
        self.conf().parties.push(crate::confidentiality::Party {
            id,
            name: name.to_owned(),
        });
        Ok(())
    }

    pub fn asset(&mut self, decl: crate::confidentiality::AssetDecl) -> Result<()> {
        crate::confidentiality::check_id("asset", &decl.id)?;
        self.conf().assets.push(decl);
        Ok(())
    }

    /// Secret input `input` is asset `asset`.
    pub fn bind_input(&mut self, input: &str, asset: &str) -> Result<()> {
        if !self.input_names.contains(input) {
            return Err(Error::new(
                Code::PolicyDeclaration,
                format!("no input named {input:?}"),
            ));
        }
        self.conf()
            .inputs
            .insert(input.to_owned(), asset.to_owned());
        Ok(())
    }

    /// `value` is an asset of `kind` released at most as `release`.
    pub fn derive(
        &mut self,
        value: ValueId,
        kind: crate::confidentiality::AssetKind,
        release: crate::confidentiality::Release,
    ) -> Result<()> {
        self.ty(value)?;
        if self
            .program
            .confidentiality
            .as_ref()
            .is_some_and(|c| c.derivations.iter().any(|d| d.value == value))
        {
            return Err(Error::new(
                Code::PolicyDeclaration,
                format!("{value} is derived twice"),
            ));
        }
        self.conf()
            .derivations
            .push(crate::confidentiality::Derivation {
                value,
                kind,
                release,
            });
        Ok(())
    }

    /// Where output `name` goes (default: sealed).
    /// Declares output `rule.output` an aggregation boundary.
    pub fn aggregate(&mut self, rule: crate::confidentiality::AggregationRule) -> Result<()> {
        if !self.program.outputs.iter().any(|o| o.name == rule.output) {
            return Err(Error::new(
                Code::AggregationPlan,
                format!("no output named {:?}", rule.output),
            ));
        }
        self.conf().aggregations.push(rule);
        Ok(())
    }

    pub fn output_release(
        &mut self,
        name: &str,
        release: crate::confidentiality::OutputRelease,
    ) -> Result<()> {
        if !self.program.outputs.iter().any(|o| o.name == name) {
            return Err(Error::new(
                Code::PolicyDeclaration,
                format!("no output named {name:?}"),
            ));
        }
        if release != crate::confidentiality::OutputRelease::Sealed {
            self.conf().outputs.insert(name.to_owned(), release);
        }
        Ok(())
    }

    pub fn finish(self) -> Result<Program> {
        if self.program.outputs.is_empty() {
            return Err(type_error("program has no outputs"));
        }
        if let Some(c) = &self.program.confidentiality {
            c.validate()?;
        }
        Ok(self.program)
    }

    /// Rebuild `op` through the checked constructors, used by the parser.
    pub(crate) fn push_op(&mut self, op: Op, ty: Type) -> Result<ValueId> {
        let (shape, elem) = (ty.shape, ty.elem);
        match op {
            Op::Input { name, range } if elem.is_exact() => {
                self.input_exact(&name, elem, Some(range))
            }
            Op::Input { name, range } => self.input(&name, shape, range),
            Op::Const { data } if elem.is_exact() => {
                if data.len() != 1 {
                    return Err(type_error("exact constants are scalars"));
                }
                self.constant_exact(elem, data[0])
            }
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
            Op::Cmp(c, a, b) => self.cmp(c, a, b),
            Op::Logic(l, a, b) => self.logic(l, a, b),
            Op::Not(a) => self.not(a),
            Op::Shift { x, left, by } => self.shift(x, left, by),
            Op::Min(a, b) => self.min(a, b),
            Op::Max(a, b) => self.max(a, b),
            Op::Select(c, a, b) => self.select(c, a, b),
            Op::Lookup { x, table } => self.lookup(x, table),
            Op::Cast(x) => self.cast(x, elem),
            Op::Div(a, b) => self.div(a, b),
            Op::Rem(a, b) => self.rem(a, b),
        }
    }

    fn push(&mut self, op: Op, visibility: Visibility, shape: Shape) -> ValueId {
        self.push_typed(op, visibility, shape, Elem::F64)
    }

    fn push_typed(&mut self, op: Op, visibility: Visibility, shape: Shape, elem: Elem) -> ValueId {
        let id = ValueId(self.program.nodes.len() as u32);
        self.program.nodes.push(Node {
            op,
            ty: Type {
                visibility,
                shape,
                elem,
            },
        });
        id
    }

    fn approx_only(&self, name: &str, ids: &[ValueId]) -> Result<()> {
        for &id in ids {
            if self.ty(id)?.elem.is_exact() {
                return Err(type_error(format!(
                    "{name} works on approximate (float) values, not {}",
                    self.ty(id)?.elem
                )));
            }
        }
        Ok(())
    }

    fn exact_operand(&self, name: &str, id: ValueId) -> Result<Type> {
        let t = self.ty(id)?;
        if !t.elem.is_exact() {
            return Err(type_error(format!(
                "{name} needs exact (integer or bool) operands; CKKS values have no exact \
                 comparison or logic semantics"
            )));
        }
        Ok(t)
    }

    /// Two exact operands of one element type, at least one secret.
    fn exact_pair(&self, name: &str, a: ValueId, b: ValueId) -> Result<Elem> {
        let (ta, tb) = (self.exact_operand(name, a)?, self.exact_operand(name, b)?);
        self.any_secret(name, ta, tb)?;
        if ta.elem != tb.elem {
            return Err(type_error(format!(
                "{name} needs operands of one type, got {} and {}; cast one explicitly",
                ta.elem, tb.elem
            )));
        }
        Ok(ta.elem)
    }

    fn elementwise(&mut self, op: Op, a: ValueId, b: ValueId) -> Result<ValueId> {
        let (ta, tb) = (self.ty(a)?, self.ty(b)?);
        let name = op.mnemonic();
        if ta.elem.is_exact() || tb.elem.is_exact() {
            let elem = self.exact_pair(name, a, b)?;
            if elem == Elem::Bool {
                return Err(type_error(format!(
                    "{name} on bool; use and/or/xor for Boolean logic"
                )));
            }
            return Ok(self.push_typed(op, Visibility::Secret, Shape::Scalar, elem));
        }
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
/// Largest magnitude of an exact value crossing the API (inputs, constants,
/// table entries, outputs): values travel as f64, exact up to 2^53 (ADR-006).
pub const MAX_EXACT_IO: i128 = 1 << 53;

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
