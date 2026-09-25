//! The evaluator role: runs a compiled plan (CKKS or exact) on encrypted
//! inputs using only evaluation keys. Has no access to key generation,
//! encryption or decryption (0.2 plan, D2).
//!
//! [`EvaluatorSession`] is the protocol-facing object: it accepts evaluation
//! keys and input envelopes, checks every binding (parameter set, program,
//! key, backend version), executes, and returns an output envelope.

mod compiled;
pub mod engine;
mod exec;
pub mod pool;
pub mod server;
mod session;

pub use compiled::{compile_program, CompiledProgram, ExactProgram, Semantics, EXACT_PLAN_VERSION};
pub use exec::evaluate_encrypted;
pub use session::{
    execution_spec, issue_receipt, program_id, BackendKind, Backends, EvaluatorSession, ExecTimes,
    Ids,
};
