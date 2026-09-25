//! Exact (TFHE-family) backend traits and a mock. Backend-neutral: TFHE-rs
//! and OpenFHE BinFHE can both implement them.
//!
//! Every ciphertext carries its element type; operations take operands of
//! one type (the plan guarantees it). Range analysis has proven that no
//! operation overflows, so backends may use wrapping arithmetic.

use std::cell::Cell;

use encompute_ir::{CmpOp, Code, Elem, Error, LogicOp, Result};

/// Client side: key owner. Values are exact integers (bools are 0/1).
pub trait ExactClient {
    fn name(&self) -> &'static str;
    fn encrypt(&self, elem: Elem, value: i128) -> Result<Vec<u8>>;
    fn decrypt(&self, elem: Elem, ciphertext: &[u8]) -> Result<i128>;
    /// Serialized server (evaluation) key for the evaluator.
    fn evaluation_keys(&self) -> Result<Vec<u8>>;
}

/// Evaluator side: computes on ciphertexts; cannot decrypt.
pub trait ExactEvaluator {
    type Ciphertext;

    fn name(&self) -> &'static str;
    fn load(&self, elem: Elem, bytes: &[u8]) -> Result<Self::Ciphertext>;
    fn store(&self, ct: &Self::Ciphertext) -> Result<Vec<u8>>;
    /// Element type a ciphertext actually holds.
    fn elem_of(&self, ct: &Self::Ciphertext) -> Elem;
    /// A public value as a (trivially encrypted) ciphertext.
    fn trivial(&self, elem: Elem, value: i128) -> Result<Self::Ciphertext>;

    fn add(&self, a: &Self::Ciphertext, b: &Self::Ciphertext) -> Result<Self::Ciphertext>;
    fn sub(&self, a: &Self::Ciphertext, b: &Self::Ciphertext) -> Result<Self::Ciphertext>;
    fn mul(&self, a: &Self::Ciphertext, b: &Self::Ciphertext) -> Result<Self::Ciphertext>;
    fn neg(&self, a: &Self::Ciphertext) -> Result<Self::Ciphertext>;
    fn add_scalar(&self, a: &Self::Ciphertext, c: i128) -> Result<Self::Ciphertext>;
    fn sub_scalar(&self, a: &Self::Ciphertext, c: i128) -> Result<Self::Ciphertext>;
    fn mul_scalar(&self, a: &Self::Ciphertext, c: i128) -> Result<Self::Ciphertext>;
    /// `c - a`.
    fn scalar_sub(&self, c: i128, a: &Self::Ciphertext) -> Result<Self::Ciphertext>;
    fn div_scalar(&self, a: &Self::Ciphertext, c: i128) -> Result<Self::Ciphertext>;
    fn rem_scalar(&self, a: &Self::Ciphertext, c: i128) -> Result<Self::Ciphertext>;
    fn cmp(
        &self,
        op: CmpOp,
        a: &Self::Ciphertext,
        b: &Self::Ciphertext,
    ) -> Result<Self::Ciphertext>;
    fn cmp_scalar(&self, op: CmpOp, a: &Self::Ciphertext, c: i128) -> Result<Self::Ciphertext>;
    fn logic(
        &self,
        op: LogicOp,
        a: &Self::Ciphertext,
        b: &Self::Ciphertext,
    ) -> Result<Self::Ciphertext>;
    fn not(&self, a: &Self::Ciphertext) -> Result<Self::Ciphertext>;
    fn shift(&self, a: &Self::Ciphertext, left: bool, by: u32) -> Result<Self::Ciphertext>;
    fn min(&self, a: &Self::Ciphertext, b: &Self::Ciphertext) -> Result<Self::Ciphertext>;
    fn max(&self, a: &Self::Ciphertext, b: &Self::Ciphertext) -> Result<Self::Ciphertext>;
    fn select(
        &self,
        c: &Self::Ciphertext,
        a: &Self::Ciphertext,
        b: &Self::Ciphertext,
    ) -> Result<Self::Ciphertext>;
    /// `table[a]`, result of type `elem`; the index is in range (proven).
    fn lookup(&self, a: &Self::Ciphertext, table: &[i128], elem: Elem) -> Result<Self::Ciphertext>;
    fn cast(&self, a: &Self::Ciphertext, to: Elem) -> Result<Self::Ciphertext>;
}

// --- mock ---------------------------------------------------------------------

const CT_MAGIC: &[u8; 8] = b"MOCKTF01";
const EK_MAGIC: &[u8; 8] = b"MOCKTK01";

fn err(msg: impl Into<String>) -> Error {
    Error::new(Code::Backend, format!("mock-tfhe: {}", msg.into()))
}

fn elem_code(e: Elem) -> u8 {
    Elem::EXACT.iter().position(|x| *x == e).unwrap() as u8
}

/// Exact plaintext stand-in that enforces key ownership and types.
pub struct PlainExactClient {
    key_id: u64,
}

impl PlainExactClient {
    pub fn new(seed: u64) -> Self {
        Self {
            key_id: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
        }
    }

    pub fn secret_key(&self) -> Vec<u8> {
        self.key_id.to_le_bytes().to_vec()
    }

    pub fn restore(secret: &[u8]) -> Result<Self> {
        let b: [u8; 8] = secret.try_into().map_err(|_| err("bad secret key"))?;
        Ok(Self {
            key_id: u64::from_le_bytes(b),
        })
    }
}

#[derive(Clone, Debug)]
pub struct PlainExactCiphertext {
    pub elem: Elem,
    value: i128,
}

fn store(key_id: u64, elem: Elem, v: i128) -> Vec<u8> {
    let mut b = CT_MAGIC.to_vec();
    b.extend_from_slice(&key_id.to_le_bytes());
    b.push(elem_code(elem));
    b.extend_from_slice(&v.to_le_bytes());
    b
}

fn load(key_id: u64, elem: Elem, bytes: &[u8]) -> Result<i128> {
    if bytes.len() != 8 + 8 + 1 + 16 || &bytes[..8] != CT_MAGIC {
        return Err(err("not a mock TFHE ciphertext"));
    }
    if u64::from_le_bytes(bytes[8..16].try_into().unwrap()) != key_id {
        return Err(Error::new(
            Code::WrongKey,
            "mock-tfhe: ciphertext under another key",
        ));
    }
    if bytes[16] != elem_code(elem) {
        return Err(err(format!("ciphertext is not a {elem}")));
    }
    let v = i128::from_le_bytes(bytes[17..].try_into().unwrap());
    let (min, max) = elem.bounds();
    if v < min || v > max {
        return Err(err(format!("ciphertext value is not a {elem}")));
    }
    Ok(v)
}

impl ExactClient for PlainExactClient {
    fn name(&self) -> &'static str {
        "mock"
    }
    fn encrypt(&self, elem: Elem, value: i128) -> Result<Vec<u8>> {
        Ok(store(self.key_id, elem, value))
    }
    fn decrypt(&self, elem: Elem, ciphertext: &[u8]) -> Result<i128> {
        load(self.key_id, elem, ciphertext)
    }
    fn evaluation_keys(&self) -> Result<Vec<u8>> {
        let mut b = EK_MAGIC.to_vec();
        b.extend_from_slice(&self.key_id.to_le_bytes());
        Ok(b)
    }
}

/// Evaluates in plaintext with the exact semantics; counts operations.
pub struct PlainExactEvaluator {
    key_id: u64,
    ops: Cell<u64>,
}

impl PlainExactEvaluator {
    pub fn new(evaluation_keys: &[u8]) -> Result<Self> {
        if evaluation_keys.len() != 16 || &evaluation_keys[..8] != EK_MAGIC {
            return Err(err("not mock TFHE evaluation keys"));
        }
        Ok(Self {
            key_id: u64::from_le_bytes(evaluation_keys[8..].try_into().unwrap()),
            ops: Cell::new(0),
        })
    }

    /// Operations executed so far.
    pub fn ops(&self) -> u64 {
        self.ops.get()
    }

    fn out(&self, elem: Elem, value: i128) -> Result<PlainExactCiphertext> {
        self.ops.set(self.ops.get() + 1);
        if !elem.is_exact() {
            return Err(err(format!("{elem} is not an exact type")));
        }
        let (min, max) = elem.bounds();
        if value < min || value > max {
            return Err(err(format!(
                "{value} overflows {elem}; range analysis should have prevented this"
            )));
        }
        Ok(PlainExactCiphertext { elem, value })
    }

    fn same(a: &PlainExactCiphertext, b: &PlainExactCiphertext) -> Result<Elem> {
        if a.elem != b.elem {
            return Err(err(format!("type mismatch {} vs {}", a.elem, b.elem)));
        }
        Ok(a.elem)
    }
}

fn cmp(op: CmpOp, a: i128, b: i128) -> i128 {
    i128::from(match op {
        CmpOp::Eq => a == b,
        CmpOp::Ne => a != b,
        CmpOp::Lt => a < b,
        CmpOp::Le => a <= b,
        CmpOp::Gt => a > b,
        CmpOp::Ge => a >= b,
    })
}

type M = PlainExactCiphertext;

impl ExactEvaluator for PlainExactEvaluator {
    type Ciphertext = PlainExactCiphertext;

    fn name(&self) -> &'static str {
        "mock"
    }
    fn load(&self, elem: Elem, bytes: &[u8]) -> Result<M> {
        Ok(M {
            elem,
            value: load(self.key_id, elem, bytes)?,
        })
    }
    fn elem_of(&self, ct: &M) -> Elem {
        ct.elem
    }
    fn store(&self, ct: &M) -> Result<Vec<u8>> {
        Ok(store(self.key_id, ct.elem, ct.value))
    }
    fn trivial(&self, elem: Elem, value: i128) -> Result<M> {
        self.out(elem, value)
    }
    fn add(&self, a: &M, b: &M) -> Result<M> {
        self.out(Self::same(a, b)?, a.value + b.value)
    }
    fn sub(&self, a: &M, b: &M) -> Result<M> {
        self.out(Self::same(a, b)?, a.value - b.value)
    }
    fn mul(&self, a: &M, b: &M) -> Result<M> {
        self.out(Self::same(a, b)?, a.value * b.value)
    }
    fn neg(&self, a: &M) -> Result<M> {
        self.out(a.elem, -a.value)
    }
    fn add_scalar(&self, a: &M, c: i128) -> Result<M> {
        self.out(a.elem, a.value + c)
    }
    fn sub_scalar(&self, a: &M, c: i128) -> Result<M> {
        self.out(a.elem, a.value - c)
    }
    fn mul_scalar(&self, a: &M, c: i128) -> Result<M> {
        self.out(a.elem, a.value * c)
    }
    fn scalar_sub(&self, c: i128, a: &M) -> Result<M> {
        self.out(a.elem, c - a.value)
    }
    fn div_scalar(&self, a: &M, c: i128) -> Result<M> {
        self.out(a.elem, a.value / c)
    }
    fn rem_scalar(&self, a: &M, c: i128) -> Result<M> {
        self.out(a.elem, a.value % c)
    }
    fn cmp(&self, op: CmpOp, a: &M, b: &M) -> Result<M> {
        Self::same(a, b)?;
        self.out(Elem::Bool, cmp(op, a.value, b.value))
    }
    fn cmp_scalar(&self, op: CmpOp, a: &M, c: i128) -> Result<M> {
        self.out(Elem::Bool, cmp(op, a.value, c))
    }
    fn logic(&self, op: LogicOp, a: &M, b: &M) -> Result<M> {
        let e = Self::same(a, b)?;
        self.out(
            e,
            match op {
                LogicOp::And => a.value & b.value,
                LogicOp::Or => a.value | b.value,
                LogicOp::Xor => a.value ^ b.value,
            },
        )
    }
    fn not(&self, a: &M) -> Result<M> {
        let v = match a.elem {
            Elem::Bool => 1 - a.value,
            e if e.is_signed() => !a.value,
            e => !a.value & ((1i128 << e.bits()) - 1),
        };
        self.out(a.elem, v)
    }
    fn shift(&self, a: &M, left: bool, by: u32) -> Result<M> {
        if by >= a.elem.bits() {
            return Err(err(format!("shift by {by} on {}", a.elem)));
        }
        let v = if left {
            a.value.checked_mul(1 << by)
        } else {
            Some(a.value >> by)
        };
        self.out(a.elem, v.ok_or_else(|| err("shift overflows"))?)
    }
    fn min(&self, a: &M, b: &M) -> Result<M> {
        self.out(Self::same(a, b)?, a.value.min(b.value))
    }
    fn max(&self, a: &M, b: &M) -> Result<M> {
        self.out(Self::same(a, b)?, a.value.max(b.value))
    }
    fn select(&self, c: &M, a: &M, b: &M) -> Result<M> {
        let e = Self::same(a, b)?;
        self.out(e, if c.value != 0 { a.value } else { b.value })
    }
    fn lookup(&self, a: &M, table: &[i128], elem: Elem) -> Result<M> {
        let v = usize::try_from(a.value)
            .ok()
            .and_then(|i| table.get(i))
            .ok_or_else(|| err("lookup index out of range"))?;
        self.out(elem, *v)
    }
    fn cast(&self, a: &M, to: Elem) -> Result<M> {
        self.out(to, a.value)
    }
}
