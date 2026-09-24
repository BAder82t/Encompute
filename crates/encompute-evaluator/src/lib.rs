//! The evaluator role: runs a compiled plan on encrypted inputs using only
//! evaluation keys. Has no access to key generation, encryption or
//! decryption (0.2 plan, D2).
//!
//! [`EvaluatorSession`] is the protocol-facing object: it accepts evaluation
//! keys and input envelopes, checks every binding (parameter set, program,
//! key, backend version), executes, and returns an output envelope.

mod exec;
mod session;

pub use exec::evaluate_encrypted;
pub use session::{program_id, BackendKind, EvaluatorSession, ExecTimes, Ids};
