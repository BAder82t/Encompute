//! Exact encrypted computation, independent of any FHE library: lowers exact
//! IR (integers, bools, comparisons, logic, selection) to an [`ExactPlan`]
//! and runs it on any [`encompute_backend::ExactEvaluator`]. TFHE-rs is one
//! implementation (`encompute-tfhe`); others can follow (0.3, D1).

mod exec;
mod lower;
mod plan;

pub use exec::{evaluate_exact, evaluate_exact_observed, ExecutionObserver, NoopObserver};
pub use lower::{compile, CompiledExact};
pub use plan::{ExactInput, ExactInstr, ExactOutput, ExactPlan, ExactProfile, Reg, MAX_TABLE};
