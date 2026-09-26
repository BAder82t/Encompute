//! The evaluator role: runs a compiled plan (CKKS or exact) on encrypted
//! inputs using only evaluation keys. Has no access to key generation,
//! encryption or decryption.
//!
//! [`EvaluatorSession`] is the protocol-facing object: it accepts evaluation
//! keys and input envelopes, checks every binding (parameter set, program,
//! key, backend version), executes, and returns an output envelope.

mod compiled;
pub mod control;
pub mod engine;
mod exec;
pub mod pool;
pub mod server;
mod session;

pub use compiled::{
    compile_program, proof_coverable, refuse_aggregation, CompiledProgram, ExactProgram, Semantics,
    EXACT_PLAN_VERSION,
};
pub use exec::evaluate_encrypted;
pub use session::{
    execution_proof, execution_spec, issue_receipt, program_id, transcript_for, BackendKind,
    Backends, EvaluatorSession, ExecTimes, Ids,
};

/// The parameter profile name evaluators register for CKKS programs: any
/// parameters the compiler selects from the HE Standard 128-bit table.
pub const CKKS_PROFILE: &str = "OPENFHE_CKKS_HE_STD128_V1";
