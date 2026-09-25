//! Exact plan → semantic transcript (ADR-008). Derived from the plan alone,
//! so it is identical on every evaluator, thread schedule and backend
//! implementation.

use encompute_ir::{CmpOp, Elem, LogicOp, Result};
use encompute_verification::transcript::{
    Constant, InputDecl, OutputDecl, ProofOp, PublicParam, SemanticTranscript, TranscriptEntry,
    TRANSCRIPT_FORMAT,
};
use encompute_verification::TRANSCRIPT_VERSION;

use crate::exec::{ExecutionContext, ExecutionObserver, InstructionEvent};
use crate::plan::{ExactInstr, ExactPlan};
use crate::EXACT_PLAN_VERSION;

fn cmp_op(op: CmpOp, scalar: bool) -> ProofOp {
    use ProofOp::*;
    match (op, scalar) {
        (CmpOp::Eq, false) => Eq,
        (CmpOp::Ne, false) => Ne,
        (CmpOp::Lt, false) => Lt,
        (CmpOp::Le, false) => Le,
        (CmpOp::Gt, false) => Gt,
        (CmpOp::Ge, false) => Ge,
        (CmpOp::Eq, true) => EqConst,
        (CmpOp::Ne, true) => NeConst,
        (CmpOp::Lt, true) => LtConst,
        (CmpOp::Le, true) => LeConst,
        (CmpOp::Gt, true) => GtConst,
        (CmpOp::Ge, true) => GeConst,
    }
}

/// The transcript entry of instruction `index` of `plan`.
pub fn transcript_entry(plan: &ExactPlan, index: usize) -> TranscriptEntry {
    let instr = &plan.instrs[index];
    let ty = plan.elems[index];
    let of = |r: u32| plan.elems[r as usize];
    let konst = |t: Elem, v: i128| {
        vec![PublicParam::Const {
            constant: Constant::new(t, v),
        }]
    };
    use ExactInstr::*;
    let (op, operands, params) = match instr {
        Input { index } => (
            ProofOp::Input,
            vec![],
            vec![PublicParam::InputIndex {
                index: *index as u32,
            }],
        ),
        Trivial { value } => (ProofOp::Const, vec![], konst(ty, *value)),
        Add(a, b) => (ProofOp::Add, vec![*a, *b], vec![]),
        Sub(a, b) => (ProofOp::Sub, vec![*a, *b], vec![]),
        Mul(a, b) => (ProofOp::Mul, vec![*a, *b], vec![]),
        Neg(a) => (ProofOp::Neg, vec![*a], vec![]),
        AddScalar(a, c) => (ProofOp::AddConst, vec![*a], konst(of(*a), *c)),
        SubScalar(a, c) => (ProofOp::SubConst, vec![*a], konst(of(*a), *c)),
        MulScalar(a, c) => (ProofOp::MulConst, vec![*a], konst(of(*a), *c)),
        ScalarSub(c, a) => (ProofOp::ConstSub, vec![*a], konst(of(*a), *c)),
        DivScalar(a, c) => (ProofOp::DivConst, vec![*a], konst(of(*a), *c)),
        RemScalar(a, c) => (ProofOp::RemConst, vec![*a], konst(of(*a), *c)),
        Cmp(op, a, b) => (cmp_op(*op, false), vec![*a, *b], vec![]),
        CmpScalar(op, a, c) => (cmp_op(*op, true), vec![*a], konst(of(*a), *c)),
        Logic(op, a, b) => (
            match op {
                LogicOp::And => ProofOp::And,
                LogicOp::Or => ProofOp::Or,
                LogicOp::Xor => ProofOp::Xor,
            },
            vec![*a, *b],
            vec![],
        ),
        Not(a) => (ProofOp::Not, vec![*a], vec![]),
        Shift { x, left, by } => (
            if *left { ProofOp::Shl } else { ProofOp::Shr },
            vec![*x],
            vec![PublicParam::ShiftAmount { bits: *by }],
        ),
        Min(a, b) => (ProofOp::Min, vec![*a, *b], vec![]),
        Max(a, b) => (ProofOp::Max, vec![*a, *b], vec![]),
        Select(c, a, b) => (ProofOp::Select, vec![*c, *a, *b], vec![]),
        Lookup { x, table } => (
            ProofOp::Lookup,
            vec![*x],
            vec![PublicParam::Table {
                entries: table.iter().map(|v| Constant::new(ty, *v)).collect(),
            }],
        ),
        Cast(a) => (ProofOp::Cast, vec![*a], vec![]),
    };
    TranscriptEntry {
        index: index as u64,
        op,
        operands,
        result: index as u32,
        ty: encompute_verification::transcript::ExactType(ty),
        params,
    }
}

fn header(plan: &ExactPlan, spec_id: &str) -> SemanticTranscript {
    use encompute_verification::transcript::ExactType;
    SemanticTranscript {
        format: TRANSCRIPT_FORMAT.into(),
        transcript_version: TRANSCRIPT_VERSION,
        spec_id: spec_id.into(),
        plan_kind: "exact".into(),
        plan_version: EXACT_PLAN_VERSION,
        inputs: plan
            .inputs
            .iter()
            .enumerate()
            .map(|(i, x)| InputDecl {
                position: i as u32,
                name: x.name.clone(),
                ty: ExactType(x.elem),
                visibility: "secret".into(),
            })
            .collect(),
        outputs: plan
            .outputs
            .iter()
            .map(|o| OutputDecl {
                name: o.name.clone(),
                register: o.reg,
                ty: ExactType(o.elem),
            })
            .collect(),
        entries: vec![],
    }
}

/// The semantic transcript of `plan` under execution spec `spec_id` (hex).
/// Same plan and spec, same transcript and hash.
pub fn semantic_transcript(plan: &ExactPlan, spec_id: &str) -> SemanticTranscript {
    let mut t = header(plan, spec_id);
    t.entries = (0..plan.instrs.len())
        .map(|i| transcript_entry(plan, i))
        .collect();
    t
}

/// Records the transcript of an execution as it runs. Produces the same
/// transcript as [`semantic_transcript`] (tested): a check that execution
/// followed the plan step by step.
#[derive(Default)]
pub struct TranscriptObserver {
    transcript: Option<SemanticTranscript>,
    plan: Option<ExactPlan>,
}

impl TranscriptObserver {
    /// The recorded transcript, after a finished execution.
    pub fn into_transcript(self) -> Option<SemanticTranscript> {
        self.transcript
    }
}

impl ExecutionObserver for TranscriptObserver {
    fn begin(&mut self, plan: &ExactPlan, ctx: &ExecutionContext) -> Result<()> {
        self.transcript = Some(header(plan, &ctx.spec_id));
        self.plan = Some(plan.clone());
        Ok(())
    }

    fn instruction(&mut self, event: &InstructionEvent<'_>) -> Result<()> {
        if let (Some(t), Some(p)) = (&mut self.transcript, &self.plan) {
            t.entries.push(transcript_entry(p, event.index));
        }
        Ok(())
    }
}
