//! Exact encrypted computation, independent of any FHE library: lowers exact
//! IR (integers, bools, comparisons, logic, selection) to an [`ExactPlan`]
//! and runs it on any [`encompute_backend::ExactEvaluator`]. TFHE-rs is one
//! implementation (`encompute-tfhe`); others can follow (0.3, D1).

mod exec;
mod lower;
mod plan;
mod transcript;

pub use exec::{
    evaluate_exact, evaluate_exact_observed, ExecutionContext, ExecutionObserver, InstructionEvent,
    NoopObserver,
};
pub use transcript::{semantic_transcript, transcript_entry, TranscriptObserver};

/// Version of the exact plan format (`plan.json`), independent of CKKS.
pub const EXACT_PLAN_VERSION: u32 = 1;
pub use lower::{compile, CompiledExact};
pub use plan::{ExactInput, ExactInstr, ExactOutput, ExactPlan, ExactProfile, Reg, MAX_TABLE};
