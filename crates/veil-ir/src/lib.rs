//! Veil IR: scheme-independent SSA graph with visibility and range metadata.
//!
//! Knows nothing about CKKS, OpenFHE or hardware. A [`Program`] is built with
//! a [`Builder`] (which enforces the type rules) or parsed from the textual
//! `.vlir` form, and [`evaluate`] gives its plaintext reference semantics.
//!
//! Every op documents its MLIR lowering (ADR-004): upstream `arith`, `tensor`
//! and `linalg` ops inside HEIR's `secret.generic`.

mod error;
mod eval;
mod program;
mod text;
mod types;

pub use error::{Code, Error, Result};
pub use eval::{check_inputs, evaluate, horner, sigmoid, Inputs, Outputs};
pub use program::{Builder, Node, Op, Output, Program};
pub use text::parse;
pub use types::{Range, Shape, Type, ValueId, Visibility};
