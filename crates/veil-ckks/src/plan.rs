use serde::{Deserialize, Serialize};
use veil_ir::{Program, Shape, ValueId};

use crate::approx::Chebyshev;

/// Register: the result of `instrs[i]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Reg(pub u32);

impl Reg {
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// A plaintext slot vector, materialized from the program's constants.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Plain {
    /// IR vector constant, zero-padded; negated if `negate`.
    Vector { value: ValueId, negate: bool },
    /// Hybrid diagonal `k` of IR matrix `matrix`, rotated left by `shift`:
    /// with `i = (j + shift) mod slots`,
    /// `out[j] = M[i mod period][(i + k) mod slots]`, zero outside the matrix.
    Diagonal {
        matrix: ValueId,
        k: usize,
        shift: usize,
        period: usize,
    },
    /// `value` in slots `0..len`, zero elsewhere.
    Fill { value: f64, len: usize },
}

impl Plain {
    pub fn materialize(&self, program: &Program, slots: usize) -> Vec<f64> {
        let mut out = vec![0.0; slots];
        match self {
            Plain::Vector { value, negate } => {
                let veil_ir::Op::Const { data } = &program.node(*value).op else {
                    panic!("{value} is not a constant");
                };
                let sign = if *negate { -1.0 } else { 1.0 };
                for (o, x) in out.iter_mut().zip(data) {
                    *o = sign * x;
                }
            }
            Plain::Diagonal {
                matrix,
                k,
                shift,
                period,
            } => {
                let node = program.node(*matrix);
                let (veil_ir::Op::Const { data }, Shape::Matrix(rows, cols)) =
                    (&node.op, node.ty.shape)
                else {
                    panic!("{matrix} is not a matrix constant");
                };
                for (j, o) in out.iter_mut().enumerate() {
                    let i = (j + shift) % slots;
                    let r = i % period;
                    let c = (i + k) % slots;
                    if r < rows && c < cols {
                        *o = data[r * cols + c];
                    }
                }
            }
            Plain::Fill { value, len } => out[..*len].fill(*value),
        }
        out
    }
}

/// One CKKS operation. Levels: multiplications (`Mul`, `MulPlain`,
/// `MulConst`) consume one; everything else keeps the deeper operand's level.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Instr {
    /// The `index`-th plan input, encrypted by the client.
    Input {
        index: usize,
    },
    Add(Reg, Reg),
    Sub(Reg, Reg),
    Neg(Reg),
    /// Ciphertext × ciphertext, relinearized.
    Mul(Reg, Reg),
    AddPlain(Reg, Plain),
    MulPlain(Reg, Plain),
    AddConst(Reg, f64),
    MulConst(Reg, f64),
    /// Cyclic left rotation over the slots: `out[i] = in[(i + k) mod slots]`.
    Rotate(Reg, u32),
}

impl Instr {
    pub fn mnemonic(&self) -> &'static str {
        match self {
            Instr::Input { .. } => "input",
            Instr::Add(..) => "add",
            Instr::Sub(..) => "sub",
            Instr::Neg(..) => "neg",
            Instr::Mul(..) => "mul",
            Instr::AddPlain(..) => "add_plain",
            Instr::MulPlain(..) => "mul_plain",
            Instr::AddConst(..) => "add_const",
            Instr::MulConst(..) => "mul_const",
            Instr::Rotate(..) => "rotate",
        }
    }

    pub fn operands(&self) -> Vec<Reg> {
        match self {
            Instr::Input { .. } => vec![],
            Instr::Add(a, b) | Instr::Sub(a, b) | Instr::Mul(a, b) => vec![*a, *b],
            Instr::Neg(a)
            | Instr::AddPlain(a, _)
            | Instr::MulPlain(a, _)
            | Instr::AddConst(a, _)
            | Instr::MulConst(a, _)
            | Instr::Rotate(a, _) => vec![*a],
        }
    }

    pub fn consumes_level(&self) -> bool {
        matches!(
            self,
            Instr::Mul(..) | Instr::MulPlain(..) | Instr::MulConst(..)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlanInput {
    pub name: String,
    /// Element count; a scalar (`len == 1`, `scalar`) is replicated in every slot.
    pub len: usize,
    pub scalar: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlanOutput {
    pub name: String,
    pub reg: Reg,
    /// Elements to read from slots `0..len`.
    pub len: usize,
}

/// A function replaced by a polynomial during lowering.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Approximation {
    pub value: ValueId,
    pub function: String,
    pub chebyshev: Chebyshev,
}

/// A straight-line CKKS program over registers.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CkksPlan {
    pub slots: usize,
    pub inputs: Vec<PlanInput>,
    pub instrs: Vec<Instr>,
    /// Level (multiplicative depth consumed) of each register.
    pub levels: Vec<u32>,
    /// Bound on |value| in every slot of each register, before CKKS noise.
    pub bounds: Vec<f64>,
    pub outputs: Vec<PlanOutput>,
    /// Distinct rotation amounts; one rotation key each.
    pub rotations: Vec<u32>,
    pub depth: u32,
    pub approximations: Vec<Approximation>,
}

impl CkksPlan {
    /// Instruction counts by mnemonic, sorted.
    pub fn op_counts(&self) -> Vec<(&'static str, usize)> {
        let mut counts = std::collections::BTreeMap::new();
        for i in &self.instrs {
            *counts.entry(i.mnemonic()).or_insert(0) += 1;
        }
        counts.into_iter().collect()
    }

    /// Encode input values into slots: scalars replicated, vectors zero-padded.
    pub fn encode_input(&self, index: usize, values: &[f64]) -> Vec<f64> {
        let input = &self.inputs[index];
        if input.scalar {
            vec![values[0]; self.slots]
        } else {
            let mut v = values.to_vec();
            v.resize(self.slots, 0.0);
            v
        }
    }
}
