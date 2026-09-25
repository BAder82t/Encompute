//! Encompute IR: scheme-independent SSA graph with visibility and range metadata.
//!
//! Knows nothing about CKKS, OpenFHE or hardware. A [`Program`] is built with
//! a [`Builder`] (which enforces the type rules) or parsed from the textual
//! `.eir` form, and [`evaluate`] gives its plaintext reference semantics.
//!
//! Every op documents its MLIR lowering (ADR-004): upstream `arith`, `tensor`
//! and `linalg` ops inside HEIR's `secret.generic`.

mod error;
mod eval;
mod program;
mod text;
mod types;

pub use error::{Code, Error, Result};

/// Version of the IR and its `.eir` text form (the header line is
/// `encompute <IR_VERSION>`).
pub const IR_VERSION: &str = "0.1";
pub use eval::{check_inputs, evaluate, horner, sigmoid, Inputs, Outputs};
pub use program::{
    Builder, CmpOp, LogicOp, Node, Op, Output, Program, Verification, MAX_DIM, MAX_EXACT_IO,
};
pub use text::parse;
pub use types::{Elem, Range, Shape, Type, ValueId, Visibility};
