use encompute_backend::CkksEvaluator;
use encompute_ckks::{CkksPlan, Instr, Plain, Reg};
use encompute_ir::{Program, Result};

/// Run the plan on encrypted inputs (in plan input order). Returns one
/// ciphertext per plan output. Needs no secret key.
pub fn evaluate_encrypted<E: CkksEvaluator>(
    ev: &E,
    plan: &CkksPlan,
    program: &Program,
    inputs: Vec<E::Ciphertext>,
) -> Result<Vec<E::Ciphertext>> {
    let n = plan.instrs.len();
    // Free each register after its last use.
    let mut last_use = vec![0usize; n];
    for (i, instr) in plan.instrs.iter().enumerate() {
        for r in instr.operands() {
            last_use[r.index()] = i;
        }
    }
    for o in &plan.outputs {
        last_use[o.reg.index()] = usize::MAX;
    }

    let mut inputs: Vec<Option<E::Ciphertext>> = inputs.into_iter().map(Some).collect();
    let mut regs: Vec<Option<E::Ciphertext>> = Vec::with_capacity(n);
    for (i, instr) in plan.instrs.iter().enumerate() {
        let r = |reg: Reg| {
            regs[reg.index()]
                .as_ref()
                .expect("register used after its last use")
        };
        let plain = |p: &Plain| p.materialize(program, plan.slots);
        let ct = match instr {
            Instr::Input { index } => inputs[*index].take().expect("each input is read once"),
            Instr::Add(a, b) => ev.add(r(*a), r(*b))?,
            Instr::Sub(a, b) => ev.sub(r(*a), r(*b))?,
            Instr::Neg(a) => ev.neg(r(*a))?,
            Instr::Mul(a, b) => ev.mul(r(*a), r(*b))?,
            Instr::AddPlain(a, p) => ev.add_plain(r(*a), &plain(p))?,
            Instr::MulPlain(a, p) => ev.mul_plain(r(*a), &plain(p))?,
            Instr::AddConst(a, c) => ev.add_const(r(*a), *c)?,
            Instr::MulConst(a, c) => ev.mul_const(r(*a), *c)?,
            Instr::Rotate(a, k) => ev.rotate(r(*a), *k)?,
        };
        regs.push(Some(ct));
        for op in instr.operands() {
            if last_use[op.index()] == i {
                regs[op.index()] = None;
            }
        }
    }
    // The lowering gives every output its own register.
    Ok(plan
        .outputs
        .iter()
        .map(|o| {
            regs[o.reg.index()]
                .take()
                .expect("output registers are distinct")
        })
        .collect())
}
