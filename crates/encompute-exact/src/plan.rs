use serde::{Deserialize, Serialize};

use encompute_ir::{CmpOp, Elem, LogicOp};

/// Register: the result of `instrs[i]`.
pub type Reg = u32;

/// One exact operation. Scalar variants take a public constant.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactInstr {
    Input {
        index: usize,
    },
    /// Public constant as a (trivial) ciphertext.
    Trivial {
        value: i128,
    },
    Add(Reg, Reg),
    Sub(Reg, Reg),
    Mul(Reg, Reg),
    Neg(Reg),
    AddScalar(Reg, i128),
    SubScalar(Reg, i128),
    MulScalar(Reg, i128),
    /// `c - r`.
    ScalarSub(i128, Reg),
    DivScalar(Reg, i128),
    RemScalar(Reg, i128),
    Cmp(CmpOp, Reg, Reg),
    CmpScalar(CmpOp, Reg, i128),
    Logic(LogicOp, Reg, Reg),
    Not(Reg),
    Shift {
        x: Reg,
        left: bool,
        by: u32,
    },
    Min(Reg, Reg),
    Max(Reg, Reg),
    Select(Reg, Reg, Reg),
    Lookup {
        x: Reg,
        table: Vec<i128>,
    },
    Cast(Reg),
}

impl ExactInstr {
    pub fn operands(&self) -> Vec<Reg> {
        use ExactInstr::*;
        match self {
            Input { .. } | Trivial { .. } => vec![],
            Add(a, b)
            | Sub(a, b)
            | Mul(a, b)
            | Cmp(_, a, b)
            | Logic(_, a, b)
            | Min(a, b)
            | Max(a, b) => vec![*a, *b],
            Neg(a)
            | AddScalar(a, _)
            | SubScalar(a, _)
            | MulScalar(a, _)
            | ScalarSub(_, a)
            | DivScalar(a, _)
            | RemScalar(a, _)
            | CmpScalar(_, a, _)
            | Not(a)
            | Cast(a) => vec![*a],
            Shift { x, .. } | Lookup { x, .. } => vec![*x],
            Select(c, a, b) => vec![*c, *a, *b],
        }
    }

    /// Operation class, for statistics.
    pub fn class(&self) -> &'static str {
        use ExactInstr::*;
        match self {
            Input { .. } => "input",
            Trivial { .. } => "constant",
            Add(..) | Sub(..) | AddScalar(..) | SubScalar(..) | ScalarSub(..) | Neg(..) => {
                "add/sub"
            }
            Mul(..) => "multiply",
            MulScalar(..) => "multiply by constant",
            DivScalar(..) | RemScalar(..) => "divide by constant",
            Cmp(..) | CmpScalar(..) => "comparison",
            Logic(..) | Not(..) => "logic",
            Shift { .. } => "shift",
            Min(..) | Max(..) => "min/max",
            Select(..) => "select",
            Lookup { .. } => "lookup",
            Cast(..) => "cast",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExactInput {
    pub name: String,
    pub elem: Elem,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExactOutput {
    pub name: String,
    pub reg: Reg,
    pub elem: Elem,
}

/// A straight-line exact program over typed registers.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExactPlan {
    pub inputs: Vec<ExactInput>,
    pub instrs: Vec<ExactInstr>,
    /// Element type of each register.
    pub elems: Vec<Elem>,
    pub outputs: Vec<ExactOutput>,
}

impl ExactPlan {
    /// Operation counts by class, sorted.
    pub fn op_counts(&self) -> Vec<(&'static str, usize)> {
        let mut m = std::collections::BTreeMap::new();
        for i in &self.instrs {
            *m.entry(i.class()).or_insert(0) += 1;
        }
        m.into_iter().collect()
    }
}

/// The parameter profile a backend runs a plan with (vetted profiles only;
/// Encompute does not select TFHE parameters itself in 0.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExactProfile {
    pub backend: String,
    pub backend_version: String,
    pub profile: String,
    pub security: String,
    pub failure_probability: String,
    pub parameter_selector_version: String,
}

impl ExactProfile {
    /// Canonical JSON (pretty, trailing newline); its SHA-256 is the
    /// parameter-set ID.
    pub fn canonical_json(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).expect("serializable");
        s.push('\n');
        s
    }
}
