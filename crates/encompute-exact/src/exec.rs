use encompute_backend::ExactEvaluator;
use encompute_ir::Result;

use crate::plan::{ExactInstr, ExactPlan};

/// Run the plan on encrypted inputs (plan order); one ciphertext per output.
/// Needs no client key.
pub fn evaluate_exact<E: ExactEvaluator>(
    ev: &E,
    plan: &ExactPlan,
    inputs: Vec<E::Ciphertext>,
) -> Result<Vec<E::Ciphertext>>
where
    E::Ciphertext: Clone,
{
    let n = plan.instrs.len();
    let mut last_use = vec![0usize; n];
    for (i, instr) in plan.instrs.iter().enumerate() {
        for r in instr.operands() {
            last_use[r as usize] = i;
        }
    }
    for o in &plan.outputs {
        last_use[o.reg as usize] = usize::MAX;
    }
    let mut inputs: Vec<Option<E::Ciphertext>> = inputs.into_iter().map(Some).collect();
    let mut regs: Vec<Option<E::Ciphertext>> = Vec::with_capacity(n);
    for (i, instr) in plan.instrs.iter().enumerate() {
        let r = |x: u32| {
            regs[x as usize]
                .as_ref()
                .expect("register used after its last use")
        };
        let elem = plan.elems[i];
        use ExactInstr::*;
        let ct = match instr {
            Input { index } => inputs[*index].take().expect("each input is read once"),
            Trivial { value } => ev.trivial(elem, *value)?,
            Add(a, b) => ev.add(r(*a), r(*b))?,
            Sub(a, b) => ev.sub(r(*a), r(*b))?,
            Mul(a, b) => ev.mul(r(*a), r(*b))?,
            Neg(a) => ev.neg(r(*a))?,
            AddScalar(a, c) => ev.add_scalar(r(*a), *c)?,
            SubScalar(a, c) => ev.sub_scalar(r(*a), *c)?,
            MulScalar(a, c) => ev.mul_scalar(r(*a), *c)?,
            ScalarSub(c, a) => ev.scalar_sub(*c, r(*a))?,
            DivScalar(a, c) => ev.div_scalar(r(*a), *c)?,
            RemScalar(a, c) => ev.rem_scalar(r(*a), *c)?,
            Cmp(op, a, b) => ev.cmp(*op, r(*a), r(*b))?,
            CmpScalar(op, a, c) => ev.cmp_scalar(*op, r(*a), *c)?,
            Logic(op, a, b) => ev.logic(*op, r(*a), r(*b))?,
            Not(a) => ev.not(r(*a))?,
            Shift { x, left, by } => ev.shift(r(*x), *left, *by)?,
            Min(a, b) => ev.min(r(*a), r(*b))?,
            Max(a, b) => ev.max(r(*a), r(*b))?,
            Select(c, a, b) => ev.select(r(*c), r(*a), r(*b))?,
            Lookup { x, table } => ev.lookup(r(*x), table, elem)?,
            Cast(a) => ev.cast(r(*a), elem)?,
        };
        regs.push(Some(ct));
        for op in instr.operands() {
            if last_use[op as usize] == i {
                regs[op as usize] = None;
            }
        }
    }
    // Outputs may share a register; copy all but the last use.
    let mut out = Vec::with_capacity(plan.outputs.len());
    for (i, o) in plan.outputs.iter().enumerate() {
        let later = plan.outputs[i + 1..].iter().any(|p| p.reg == o.reg);
        let slot = &mut regs[o.reg as usize];
        out.push(if later { slot.clone() } else { slot.take() }.expect("output register"));
    }
    Ok(out)
}
