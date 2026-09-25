use encompute_backend::ExactEvaluator;
use encompute_ir::{Code, Error, Result};

use crate::plan::{ExactInstr, ExactPlan, Reg};

/// Context of one execution, given to observers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionContext {
    /// Hex `ExecutionSpecId` of what is being executed.
    pub spec_id: String,
}

/// One executed instruction, as observers see it: the plan's structure
/// only (index, the instruction with its public constants, the result
/// register), never ciphertexts or plaintext values.
#[derive(Clone, Copy, Debug)]
pub struct InstructionEvent<'a> {
    pub index: usize,
    pub instr: &'a ExactInstr,
    pub result: Reg,
}

/// Watches an exact execution step by step: the hook for transcripts,
/// proof witnesses and profiling. An error aborts the execution.
pub trait ExecutionObserver {
    fn begin(&mut self, _plan: &ExactPlan, _ctx: &ExecutionContext) -> Result<()> {
        Ok(())
    }
    fn instruction(&mut self, _event: &InstructionEvent<'_>) -> Result<()> {
        Ok(())
    }
    /// Execution finished; `outputs` are the output registers in order.
    fn finish(&mut self, _outputs: &[Reg]) -> Result<()> {
        Ok(())
    }
}

/// Observes nothing; execution is unchanged.
pub struct NoopObserver;

impl ExecutionObserver for NoopObserver {}

/// Run the plan on encrypted inputs (plan order); one ciphertext per output.
/// Needs no client key. The plan is validated first.
pub fn evaluate_exact<E: ExactEvaluator>(
    ev: &E,
    plan: &ExactPlan,
    inputs: Vec<E::Ciphertext>,
) -> Result<Vec<E::Ciphertext>>
where
    E::Ciphertext: Clone,
{
    evaluate_exact_observed(
        ev,
        plan,
        inputs,
        &ExecutionContext::default(),
        &mut NoopObserver,
    )
}

/// [`evaluate_exact`] reporting each step to `observer`.
pub fn evaluate_exact_observed<E: ExactEvaluator>(
    ev: &E,
    plan: &ExactPlan,
    inputs: Vec<E::Ciphertext>,
    ctx: &ExecutionContext,
    observer: &mut dyn ExecutionObserver,
) -> Result<Vec<E::Ciphertext>>
where
    E::Ciphertext: Clone,
{
    plan.validate()?;
    if inputs.len() != plan.inputs.len() {
        return Err(Error::new(
            Code::BadInput,
            format!(
                "expected {} inputs, got {}",
                plan.inputs.len(),
                inputs.len()
            ),
        ));
    }
    if let Some((i, _)) = plan
        .inputs
        .iter()
        .zip(&inputs)
        .enumerate()
        .find(|(_, (d, ct))| ev.elem_of(ct) != d.elem)
    {
        return Err(Error::new(
            Code::BadInput,
            format!(
                "input {:?} is not a {}",
                plan.inputs[i].name, plan.inputs[i].elem
            ),
        ));
    }
    observer.begin(plan, ctx)?;
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
        observer.instruction(&InstructionEvent {
            index: i,
            instr,
            result: i as Reg,
        })?;
        for op in instr.operands() {
            if last_use[op as usize] == i {
                regs[op as usize] = None;
            }
        }
    }
    observer.finish(&plan.outputs.iter().map(|o| o.reg).collect::<Vec<_>>())?;
    // Outputs may share a register; copy all but the last use.
    let mut out = Vec::with_capacity(plan.outputs.len());
    for (i, o) in plan.outputs.iter().enumerate() {
        let later = plan.outputs[i + 1..].iter().any(|p| p.reg == o.reg);
        let slot = &mut regs[o.reg as usize];
        out.push(if later { slot.clone() } else { slot.take() }.expect("output register"));
    }
    Ok(out)
}
