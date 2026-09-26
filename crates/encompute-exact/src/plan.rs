use serde::{Deserialize, Serialize};

use encompute_ir::{CmpOp, Code, Elem, Error, LogicOp, Result};

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

/// Largest lookup table a plan may carry (matches the IR builder).
pub const MAX_TABLE: usize = 1 << 16;

impl ExactPlan {
    /// Checks for a plan from outside this process: every register is
    /// defined before use, each input is read once, every instruction is
    /// well-typed (so each register's declared type is the type its
    /// ciphertext really has), constants fit their types, shifts fit, tables
    /// are non-empty and divisors non-zero. A plan that fails is rejected,
    /// never executed.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| {
            Err(Error::new(
                Code::Artifact,
                format!("invalid exact plan: {m}"),
            ))
        };
        if self.elems.len() != self.instrs.len() {
            return bad("one element type per instruction".into());
        }
        if let Some(e) = self.elems.iter().find(|e| !e.is_exact()) {
            return bad(format!("{e} is not an exact type"));
        }
        let fits = |e: Elem, v: i128| {
            let (min, max) = e.bounds();
            min <= v && v <= max
        };
        let mut read = vec![false; self.inputs.len()];
        for (i, instr) in self.instrs.iter().enumerate() {
            if let Some(r) = instr.operands().into_iter().find(|r| *r as usize >= i) {
                return bad(format!(
                    "instruction {i} uses register {r} before it is defined"
                ));
            }
            let t = |r: &Reg| self.elems[*r as usize];
            let out = self.elems[i];
            use ExactInstr::*;
            let ok = match instr {
                Input { index } => match read.get_mut(*index) {
                    Some(seen) if !*seen => {
                        *seen = true;
                        self.inputs[*index].elem == out
                    }
                    _ => return bad(format!("input {index} is missing or read twice")),
                },
                Trivial { value } => fits(out, *value),
                Add(a, b) | Sub(a, b) | Mul(a, b) | Logic(_, a, b) | Min(a, b) | Max(a, b) => {
                    t(a) == out && t(b) == out
                }
                Neg(a) | Not(a) => t(a) == out,
                AddScalar(a, c) | SubScalar(a, c) | MulScalar(a, c) | ScalarSub(c, a) => {
                    t(a) == out && fits(out, *c)
                }
                DivScalar(a, c) | RemScalar(a, c) => t(a) == out && *c != 0 && fits(out, *c),
                Cmp(_, a, b) => t(a) == t(b) && out == Elem::Bool,
                CmpScalar(_, a, c) => fits(t(a), *c) && out == Elem::Bool,
                Shift { x, by, .. } => t(x) == out && *by < out.bits(),
                Select(c, a, b) => t(c) == Elem::Bool && t(a) == out && t(b) == out,
                Lookup { table, .. } => {
                    !table.is_empty()
                        && table.len() <= MAX_TABLE
                        && table.iter().all(|v| fits(out, *v))
                }
                Cast(_) => true,
            };
            if !ok {
                return bad(format!("instruction {i} ({}) is ill-typed", instr.class()));
            }
        }
        if read.iter().any(|r| !r) {
            return bad("an input is never read".into());
        }
        for o in &self.outputs {
            match self.elems.get(o.reg as usize) {
                Some(e) if *e == o.elem => {}
                _ => return bad(format!("output {:?} has a bad register or type", o.name)),
            }
        }
        Ok(())
    }

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
/// Encompute does not select exact-backend parameters itself).
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
