//! Semantic transcripts (0.4 V2, ADR-008): the canonical, deterministic
//! statement of which Encompute operations connect an execution's inputs
//! to its outputs. A transcript describes compiled exact-plan semantics,
//! not how a backend implements them (one `select` stays one `select`
//! however many bootstraps TFHE-rs spends on it), and never contains
//! runtime values, ciphertexts or keys.
//!
//! It is public metadata: it reveals the plan's structure, operation
//! counts, public constants and lookup tables, exactly as `plan.json` does.
//! A transcript hash proves nothing about an execution; it fixes the
//! statement a future proof must satisfy.

use std::fmt;

use encompute_ir::{Code, Elem, Error, Result};
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json;
use crate::hash::{hex, tagged, TRANSCRIPT};

pub const TRANSCRIPT_VERSION: u32 = 1;
/// Format name in every transcript header.
pub const TRANSCRIPT_FORMAT: &str = "EncomputeProofTranscriptV1";

/// Largest transcript accepted on parse.
pub const MAX_TRANSCRIPT_BYTES: usize = 64 << 20;

/// Largest lookup table (as exact plans).
pub const MAX_TABLE: usize = 1 << 16;

/// Verification opcodes with stable numeric codes (transcript version 1).
/// Codes and meanings never change within a transcript version; see
/// ADR-008 for the semantics of each. Not Rust discriminants: the code is
/// assigned explicitly below.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProofOp {
    Input,
    Const,
    Add,
    Sub,
    Mul,
    Neg,
    AddConst,
    SubConst,
    MulConst,
    ConstSub,
    DivConst,
    RemConst,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    EqConst,
    NeConst,
    LtConst,
    LeConst,
    GtConst,
    GeConst,
    And,
    Or,
    Xor,
    Not,
    Select,
    Shl,
    Shr,
    Min,
    Max,
    Lookup,
    Cast,
}

const OPS: [(ProofOp, u16, &str); 35] = [
    (ProofOp::Input, 0x0001, "INPUT"),
    (ProofOp::Const, 0x0002, "CONST"),
    (ProofOp::Add, 0x0010, "ADD"),
    (ProofOp::Sub, 0x0011, "SUB"),
    (ProofOp::Mul, 0x0012, "MUL"),
    (ProofOp::Neg, 0x0013, "NEG"),
    (ProofOp::AddConst, 0x0014, "ADD_CONST"),
    (ProofOp::SubConst, 0x0015, "SUB_CONST"),
    (ProofOp::MulConst, 0x0016, "MUL_CONST"),
    (ProofOp::ConstSub, 0x0017, "CONST_SUB"),
    (ProofOp::DivConst, 0x0018, "DIV_CONST"),
    (ProofOp::RemConst, 0x0019, "REM_CONST"),
    (ProofOp::Eq, 0x0020, "EQ"),
    (ProofOp::Ne, 0x0021, "NE"),
    (ProofOp::Lt, 0x0022, "LT"),
    (ProofOp::Le, 0x0023, "LE"),
    (ProofOp::Gt, 0x0024, "GT"),
    (ProofOp::Ge, 0x0025, "GE"),
    (ProofOp::EqConst, 0x0028, "EQ_CONST"),
    (ProofOp::NeConst, 0x0029, "NE_CONST"),
    (ProofOp::LtConst, 0x002a, "LT_CONST"),
    (ProofOp::LeConst, 0x002b, "LE_CONST"),
    (ProofOp::GtConst, 0x002c, "GT_CONST"),
    (ProofOp::GeConst, 0x002d, "GE_CONST"),
    (ProofOp::And, 0x0030, "AND"),
    (ProofOp::Or, 0x0031, "OR"),
    (ProofOp::Xor, 0x0032, "XOR"),
    (ProofOp::Not, 0x0033, "NOT"),
    (ProofOp::Select, 0x0040, "SELECT"),
    (ProofOp::Shl, 0x0050, "SHL"),
    (ProofOp::Shr, 0x0051, "SHR"),
    (ProofOp::Min, 0x0060, "MIN"),
    (ProofOp::Max, 0x0061, "MAX"),
    (ProofOp::Lookup, 0x0070, "LOOKUP"),
    (ProofOp::Cast, 0x0080, "CAST"),
];

impl ProofOp {
    pub const ALL: [ProofOp; 35] = {
        let mut a = [ProofOp::Input; 35];
        let mut i = 0;
        while i < 35 {
            a[i] = OPS[i].0;
            i += 1;
        }
        a
    };

    /// Stable numeric code (the canonical encoding).
    pub fn code(self) -> u16 {
        OPS.iter()
            .find(|o| o.0 == self)
            .expect("every op has a code")
            .1
    }

    pub fn from_code(code: u16) -> Option<Self> {
        OPS.iter().find(|o| o.1 == code).map(|o| o.0)
    }

    /// Display name, e.g. `MUL_CONST`.
    pub fn name(self) -> &'static str {
        OPS.iter()
            .find(|o| o.0 == self)
            .expect("every op has a name")
            .2
    }
}

impl fmt::Display for ProofOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl Serialize for ProofOp {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_u16(self.code())
    }
}

impl<'de> Deserialize<'de> for ProofOp {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let code = u16::deserialize(d)?;
        ProofOp::from_code(code)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown opcode {code:#06x}")))
    }
}

/// An exact value's type, bound by name (`u8` ... `i64`, `bool`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExactType(pub Elem);

impl Serialize for ExactType {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.0.name())
    }
}

impl<'de> Deserialize<'de> for ExactType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        match Elem::parse(&s) {
            Some(e) if e.is_exact() => Ok(ExactType(e)),
            _ => Err(serde::de::Error::custom(format!(
                "not an exact type: {s:?}"
            ))),
        }
    }
}

impl fmt::Display for ExactType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.name())
    }
}

/// A typed public constant: exact integer as a decimal string, never
/// through floating point (`u32:35` has exactly one encoding).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constant {
    #[serde(rename = "type")]
    pub ty: ExactType,
    pub value: String,
}

impl Constant {
    pub fn new(ty: Elem, value: i128) -> Self {
        Self {
            ty: ExactType(ty),
            value: value.to_string(),
        }
    }

    /// The value, checked against its type.
    pub fn int(&self) -> Result<i128> {
        let v: i128 = self
            .value
            .parse()
            .map_err(|_| bad(format!("constant {:?} is not an integer", self.value)))?;
        if v.to_string() != self.value {
            return Err(bad(format!("constant {:?} is not canonical", self.value)));
        }
        let (lo, hi) = self.ty.0.bounds();
        if v < lo || v > hi {
            return Err(bad(format!("constant {v} does not fit {}", self.ty)));
        }
        Ok(v)
    }
}

impl fmt::Display for Constant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ty, self.value)
    }
}

/// Public parameters of an instruction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicParam {
    /// Position of an encrypted input in the request.
    InputIndex {
        index: u32,
    },
    Const {
        constant: Constant,
    },
    ShiftAmount {
        bits: u32,
    },
    Table {
        entries: Vec<Constant>,
    },
}

/// Plan-local SSA value: `r{n}` is the result of instruction `n`.
pub type ValueId = u32;

/// One semantic operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptEntry {
    pub index: u64,
    pub op: ProofOp,
    pub operands: Vec<ValueId>,
    pub result: ValueId,
    /// Result type; operand types are the result types of their entries.
    #[serde(rename = "type")]
    pub ty: ExactType,
    pub params: Vec<PublicParam>,
}

/// A secret input: position, name and type. Its range is public too and
/// bound through the spec's program ID (`program.eir`); its value never
/// appears.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputDecl {
    pub position: u32,
    pub name: String,
    #[serde(rename = "type")]
    pub ty: ExactType,
    pub visibility: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputDecl {
    pub name: String,
    pub register: ValueId,
    #[serde(rename = "type")]
    pub ty: ExactType,
}

/// The canonical statement structure of one compiled exact plan under one
/// execution spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticTranscript {
    pub format: String,
    pub transcript_version: u32,
    /// Hex `ExecutionSpecId` this transcript belongs to.
    pub spec_id: String,
    pub plan_kind: String,
    pub plan_version: u32,
    pub inputs: Vec<InputDecl>,
    pub outputs: Vec<OutputDecl>,
    pub entries: Vec<TranscriptEntry>,
}

/// `SHA256("encompute.execution-transcript.v1" || 0x00 || canonical transcript)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TranscriptId(pub [u8; 32]);

impl TranscriptId {
    pub fn hex(&self) -> String {
        hex(&self.0)
    }
}

impl fmt::Display for TranscriptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "enctrace1:{}", self.hex())
    }
}

fn bad(msg: impl Into<String>) -> Error {
    Error::new(Code::Transcript, msg)
}

impl SemanticTranscript {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }

    pub fn id(&self) -> TranscriptId {
        TranscriptId(tagged(
            TRANSCRIPT,
            &self.canonical_bytes().expect("strings and integers only"),
        ))
    }

    /// Parse strictly and check structure (see [`SemanticTranscript::validate`]).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_TRANSCRIPT_BYTES {
            return Err(bad("transcript is too large"));
        }
        let t: Self =
            serde_json::from_slice(bytes).map_err(|e| bad(format!("malformed transcript: {e}")))?;
        t.validate()?;
        Ok(t)
    }

    /// Structural checks: known version and format; entries numbered in
    /// order with `result == index`; operands defined before use; for each
    /// opcode, exactly its operand count, its one parameter kind, and its
    /// type rule; constants canonical and within their types; each input
    /// read once by an `INPUT` entry; outputs defined with their types.
    pub fn validate(&self) -> Result<()> {
        if self.format != TRANSCRIPT_FORMAT || self.transcript_version != TRANSCRIPT_VERSION {
            return Err(bad(format!(
                "transcript {} v{} (this Encompute reads {TRANSCRIPT_FORMAT} v{TRANSCRIPT_VERSION})",
                self.format, self.transcript_version
            )));
        }
        let mut read = vec![false; self.inputs.len()];
        let mut types: Vec<Elem> = Vec::with_capacity(self.entries.len());
        for (i, e) in self.entries.iter().enumerate() {
            let ill = |why: &str| bad(format!("entry {i} ({}): {why}", e.op));
            if e.index != i as u64 || e.result as usize != i {
                return Err(bad(format!("entry {i} is out of order")));
            }
            if let Some(r) = e.operands.iter().find(|r| **r as usize >= i) {
                return Err(bad(format!("entry {i} uses r{r} before it is defined")));
            }
            let t: Vec<Elem> = e.operands.iter().map(|r| types[*r as usize]).collect();
            let ty = e.ty.0;
            use ProofOp::*;
            let arity = match e.op {
                Input | Const => 0,
                Add | Sub | Mul | Min | Max | And | Or | Xor | Eq | Ne | Lt | Le | Gt | Ge => 2,
                Select => 3,
                _ => 1,
            };
            if t.len() != arity {
                return Err(ill(&format!("{} operands, expected {arity}", t.len())));
            }
            // The one parameter each opcode takes (none for the rest).
            let param = match (e.op, e.params.as_slice()) {
                (Input, [PublicParam::InputIndex { index }]) => {
                    match read.get_mut(*index as usize) {
                        Some(seen) if !*seen => *seen = true,
                        _ => return Err(ill(&format!("input {index} is missing or read twice"))),
                    }
                    if self.inputs[*index as usize].ty != e.ty {
                        return Err(ill("input type differs from its declaration"));
                    }
                    None
                }
                (
                    Const | AddConst | SubConst | MulConst | ConstSub | DivConst | RemConst
                    | EqConst | NeConst | LtConst | LeConst | GtConst | GeConst,
                    [PublicParam::Const { constant }],
                ) => Some((constant.ty.0, constant.int()?)),
                (Shl | Shr, [PublicParam::ShiftAmount { bits }]) => {
                    if *bits >= ty.bits() {
                        return Err(ill("shift amount not below the width"));
                    }
                    None
                }
                (Lookup, [PublicParam::Table { entries }]) => {
                    if entries.is_empty() || entries.len() > MAX_TABLE {
                        return Err(ill("table needs 1 to 65536 entries"));
                    }
                    for c in entries {
                        if c.ty != e.ty {
                            return Err(ill("table entry of another type"));
                        }
                        c.int()?;
                    }
                    None
                }
                (
                    Add | Sub | Mul | Neg | Min | Max | And | Or | Xor | Not | Eq | Ne | Lt | Le
                    | Gt | Ge | Select | Cast,
                    [],
                ) => None,
                _ => return Err(ill("unexpected parameters")),
            };
            // Type rules (as the exact plan's validation).
            let ok = match e.op {
                Input | Lookup | Cast => true,
                Const => param.map(|p| p.0) == Some(ty),
                Add | Sub | Mul | Min | Max | And | Or | Xor => t[0] == ty && t[1] == ty,
                Neg | Not | Shl | Shr => t[0] == ty,
                AddConst | SubConst | MulConst | ConstSub => {
                    t[0] == ty && param.map(|p| p.0) == Some(ty)
                }
                DivConst | RemConst => {
                    t[0] == ty && param.map(|p| p.0) == Some(ty) && param.map(|p| p.1) != Some(0)
                }
                Eq | Ne | Lt | Le | Gt | Ge => t[0] == t[1] && ty == Elem::Bool,
                EqConst | NeConst | LtConst | LeConst | GtConst | GeConst => {
                    param.map(|p| p.0) == Some(t[0]) && ty == Elem::Bool
                }
                Select => t[0] == Elem::Bool && t[1] == ty && t[2] == ty,
            };
            if !ok {
                return Err(ill("ill-typed"));
            }
            types.push(ty);
        }
        if read.iter().any(|r| !r) {
            return Err(bad("an input is never read"));
        }
        for o in &self.outputs {
            match types.get(o.register as usize) {
                Some(t) if *t == o.ty.0 => {}
                _ => {
                    return Err(bad(format!(
                        "output {:?} has a bad register or type",
                        o.name
                    )))
                }
            }
        }
        Ok(())
    }

    /// Human-readable listing; never contains runtime values.
    pub fn listing(&self) -> String {
        let mut s = String::new();
        for e in &self.entries {
            let mut args: Vec<String> = e.operands.iter().map(|r| format!("r{r}")).collect();
            for p in &e.params {
                args.push(match p {
                    PublicParam::InputIndex { index } => format!("#{index}"),
                    PublicParam::Const { constant } => constant.value.clone(),
                    PublicParam::ShiftAmount { bits } => bits.to_string(),
                    PublicParam::Table { entries } => format!("[{} entries]", entries.len()),
                });
            }
            let lhs = format!("{:04} {:<10} {}", e.index, e.op.name(), args.join(" "));
            s.push_str(&format!("{lhs:<34} -> r{} : {}\n", e.result, e.ty));
        }
        s
    }
}
