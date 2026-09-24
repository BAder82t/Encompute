use encompute_backend::CkksBackend;
use encompute_ckks::{CkksPlan, Instr};
use encompute_ir::{check_inputs, Inputs, Outputs, Program, Result};

/// Client side: encode and encrypt inputs in plan order.
pub fn encrypt_inputs<B: CkksBackend>(
    backend: &B,
    plan: &CkksPlan,
    program: &Program,
    inputs: &Inputs,
) -> Result<Vec<B::Ciphertext>> {
    check_inputs(program, inputs)?;
    plan.inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| backend.encrypt(&plan.encode_input(i, &inputs[&inp.name])))
        .collect()
}

/// Evaluator side: run the plan on encrypted inputs. Needs no secret key.
/// Returns one ciphertext per plan output.
pub fn evaluate_encrypted<B: CkksBackend>(
    backend: &B,
    plan: &CkksPlan,
    program: &Program,
    inputs: Vec<B::Ciphertext>,
) -> Result<Vec<B::Ciphertext>> {
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

    let mut inputs: Vec<Option<B::Ciphertext>> = inputs.into_iter().map(Some).collect();
    let mut regs: Vec<Option<B::Ciphertext>> = Vec::with_capacity(n);
    for (i, instr) in plan.instrs.iter().enumerate() {
        let r = |reg: encompute_ckks::Reg| {
            regs[reg.index()]
                .as_ref()
                .expect("register used after its last use")
        };
        let plain = |p: &encompute_ckks::Plain| p.materialize(program, plan.slots);
        let ct = match instr {
            Instr::Input { index } => inputs[*index].take().expect("each input is read once"),
            Instr::Add(a, b) => backend.add(r(*a), r(*b))?,
            Instr::Sub(a, b) => backend.sub(r(*a), r(*b))?,
            Instr::Neg(a) => backend.neg(r(*a))?,
            Instr::Mul(a, b) => backend.mul(r(*a), r(*b))?,
            Instr::AddPlain(a, p) => backend.add_plain(r(*a), &plain(p))?,
            Instr::MulPlain(a, p) => backend.mul_plain(r(*a), &plain(p))?,
            Instr::AddConst(a, c) => backend.add_const(r(*a), *c)?,
            Instr::MulConst(a, c) => backend.mul_const(r(*a), *c)?,
            Instr::Rotate(a, k) => backend.rotate(r(*a), *k)?,
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

/// Client side: decrypt outputs and read their elements.
pub fn decrypt_outputs<B: CkksBackend>(
    backend: &B,
    sk: &B::SecretKey,
    plan: &CkksPlan,
    outputs: &[B::Ciphertext],
) -> Result<Outputs> {
    plan.outputs
        .iter()
        .zip(outputs)
        .map(|(o, ct)| {
            let mut v = backend.decrypt(sk, ct)?;
            v.truncate(o.len);
            Ok((o.name.clone(), v))
        })
        .collect()
}

/// Encrypt, evaluate and decrypt in one process.
pub fn run<B: CkksBackend>(
    backend: &B,
    sk: &B::SecretKey,
    plan: &CkksPlan,
    program: &Program,
    inputs: &Inputs,
) -> Result<Outputs> {
    let cts = encrypt_inputs(backend, plan, program, inputs)?;
    let outs = evaluate_encrypted(backend, plan, program, cts)?;
    decrypt_outputs(backend, sk, plan, &outs)
}
