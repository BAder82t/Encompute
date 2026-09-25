//! Plaintext replay of a semantic transcript, for testing the transcript
//! semantics against the exact plan. **Not a verifier and not secure**: it
//! needs the secret inputs in the clear and proves nothing.

use encompute_ir::{Code, Elem, Error, Result};

use crate::transcript::{ProofOp, PublicParam, SemanticTranscript};

/// Replays a transcript on plaintext inputs with the transcript's exact
/// semantics (checked arithmetic; every value must fit its type).
pub struct ReferenceTranscriptEvaluator;

fn err(msg: impl Into<String>) -> Error {
    Error::new(Code::Transcript, msg)
}

impl ReferenceTranscriptEvaluator {
    /// `inputs` in input-position order; returns the outputs in order.
    pub fn evaluate(t: &SemanticTranscript, inputs: &[i128]) -> Result<Vec<i128>> {
        t.validate()?;
        if inputs.len() != t.inputs.len() {
            return Err(err("wrong number of inputs"));
        }
        let mut regs: Vec<i128> = Vec::with_capacity(t.entries.len());
        for e in &t.entries {
            let ty = e.ty.0;
            let x = |k: usize| -> Result<i128> {
                e.operands
                    .get(k)
                    .map(|r| regs[*r as usize])
                    .ok_or_else(|| err(format!("entry {}: missing operand", e.index)))
            };
            let konst = || -> Result<i128> {
                match e.params.first() {
                    Some(PublicParam::Const { constant }) => constant.int(),
                    _ => Err(err(format!("entry {}: missing constant", e.index))),
                }
            };
            let c = |v: Option<i128>| v.ok_or_else(|| err(format!("entry {}: overflow", e.index)));
            let cmp = |op: ProofOp, a: i128, b: i128| {
                i128::from(match op {
                    ProofOp::Eq | ProofOp::EqConst => a == b,
                    ProofOp::Ne | ProofOp::NeConst => a != b,
                    ProofOp::Lt | ProofOp::LtConst => a < b,
                    ProofOp::Le | ProofOp::LeConst => a <= b,
                    ProofOp::Gt | ProofOp::GtConst => a > b,
                    _ => a >= b,
                })
            };
            use ProofOp::*;
            let v = match e.op {
                Input => match e.params.first() {
                    Some(PublicParam::InputIndex { index }) => inputs[*index as usize],
                    _ => return Err(err(format!("entry {}: input without index", e.index))),
                },
                Const => konst()?,
                Add => c(x(0)?.checked_add(x(1)?))?,
                Sub => c(x(0)?.checked_sub(x(1)?))?,
                Mul => c(x(0)?.checked_mul(x(1)?))?,
                Neg => c(x(0)?.checked_neg())?,
                AddConst => c(x(0)?.checked_add(konst()?))?,
                SubConst => c(x(0)?.checked_sub(konst()?))?,
                MulConst => c(x(0)?.checked_mul(konst()?))?,
                ConstSub => c(konst()?.checked_sub(x(0)?))?,
                DivConst | RemConst => {
                    let d = konst()?;
                    if d == 0 {
                        return Err(err(format!("entry {}: division by zero", e.index)));
                    }
                    if e.op == DivConst {
                        c(x(0)?.checked_div(d))?
                    } else {
                        c(x(0)?.checked_rem(d))?
                    }
                }
                Eq | Ne | Lt | Le | Gt | Ge => cmp(e.op, x(0)?, x(1)?),
                EqConst | NeConst | LtConst | LeConst | GtConst | GeConst => {
                    cmp(e.op, x(0)?, konst()?)
                }
                And => x(0)? & x(1)?,
                Or => x(0)? | x(1)?,
                Xor => x(0)? ^ x(1)?,
                Not if ty == Elem::Bool => 1 - x(0)?,
                // Two's complement for signed types; within the width for
                // unsigned ones.
                Not if ty.is_signed() => !x(0)?,
                Not => !x(0)? & ((1i128 << ty.bits()) - 1),
                Select => {
                    if x(0)? != 0 {
                        x(1)?
                    } else {
                        x(2)?
                    }
                }
                Shl | Shr => {
                    let by = match e.params.first() {
                        Some(PublicParam::ShiftAmount { bits }) if *bits < ty.bits() => *bits,
                        _ => return Err(err(format!("entry {}: bad shift", e.index))),
                    };
                    if e.op == Shl {
                        c(x(0)?.checked_mul(1i128 << by))?
                    } else {
                        x(0)? >> by
                    }
                }
                Min => x(0)?.min(x(1)?),
                Max => x(0)?.max(x(1)?),
                Lookup => {
                    let table = match e.params.first() {
                        Some(PublicParam::Table { entries }) => entries,
                        _ => return Err(err(format!("entry {}: lookup without table", e.index))),
                    };
                    let i = usize::try_from(x(0)?)
                        .ok()
                        .and_then(|i| table.get(i))
                        .ok_or_else(|| {
                            err(format!("entry {}: index outside the table", e.index))
                        })?;
                    i.int()?
                }
                Cast => x(0)?,
            };
            let (lo, hi) = ty.bounds();
            if v < lo || v > hi {
                return Err(err(format!("entry {}: {v} overflows {ty}", e.index)));
            }
            regs.push(v);
        }
        Ok(t.outputs
            .iter()
            .map(|o| regs[o.register as usize])
            .collect())
    }
}
