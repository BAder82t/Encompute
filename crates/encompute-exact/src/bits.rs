//! Exact programs as Boolean circuits: every exact type is a vector of
//! encrypted bits, and every exact operation is a circuit of two-input
//! gates, for any [`Gates`] implementation (OpenFHE BinFHE in production,
//! plaintext bits for exhaustive testing).
//!
//! **Representation** (version 1): a value of an exact type of width `w`
//! (`bool` 1, `u8`/`i8` 8, ... `u64`/`i64` 64) is `w` bits, least
//! significant first, two's complement for signed types.
//!
//! **Semantics** are [`ExactEvaluator`]'s, as the mock defines them:
//! fixed-width arithmetic whose results the compiler's range analysis has
//! proven representable (so wrapping never shows), truncating division and
//! remainder by public constants, arithmetic right shifts for signed
//! types, value-preserving casts.
//!
//! Public constants never cost a gate: a known bit folds away (`x AND 1 =
//! x`, `x XOR 1 = NOT x`, and NOT needs no bootstrapping).

use std::cell::Cell;

use encompute_backend::ExactEvaluator;
use encompute_ir::{CmpOp, Code, Elem, Error, LogicOp, Result};

use crate::plan::{ExactInstr, ExactPlan};

/// Representation version: bits, least significant first, two's complement.
pub const REPRESENTATION_VERSION: u32 = 1;

/// The largest lookup table a bit-level backend evaluates (a multiplexer
/// tree over the index's bits): 2^8 entries.
pub const MAX_LOOKUP_BITS: u32 = 8;

/// A gate library: two-input gates on encrypted bits.
pub trait Gates {
    type Bit: Clone;
    fn name(&self) -> &'static str;
    fn and(&self, a: &Self::Bit, b: &Self::Bit) -> Result<Self::Bit>;
    fn or(&self, a: &Self::Bit, b: &Self::Bit) -> Result<Self::Bit>;
    fn xor(&self, a: &Self::Bit, b: &Self::Bit) -> Result<Self::Bit>;
    /// NOT (free: no bootstrapping).
    fn not(&self, a: &Self::Bit) -> Result<Self::Bit>;
    /// A public bit as a (trivial) ciphertext.
    fn constant(&self, v: bool) -> Result<Self::Bit>;
    /// Loads a stored value of `elem` (its `elem.bits()` bits).
    fn load(&self, elem: Elem, bytes: &[u8]) -> Result<Vec<Self::Bit>>;
    fn store(&self, elem: Elem, bits: &[Self::Bit]) -> Result<Vec<u8>>;
}

/// A bit: a public constant, or encrypted.
#[derive(Clone, Debug)]
pub enum Sig<B> {
    Const(bool),
    Enc(B),
}

/// A quotient and a remainder.
type QuotRem<T> = (T, T);

/// An encrypted value: its type and its bits, least significant first.
#[derive(Clone, Debug)]
pub struct Word<B> {
    pub elem: Elem,
    pub bits: Vec<Sig<B>>,
}

/// Can a bit-level backend run `plan`? Refuses lookups over more than
/// 2^[`MAX_LOOKUP_BITS`] entries (the capability table's bound); every
/// other operation is supported for every exact type.
pub fn check_capabilities(plan: &ExactPlan) -> Result<()> {
    for (i, instr) in plan.instrs.iter().enumerate() {
        if let ExactInstr::Lookup { table, .. } = instr {
            if table.len() > 1 << MAX_LOOKUP_BITS {
                return Err(Error::new(
                    Code::Backend,
                    format!(
                        "instruction {i}: a lookup table of {} entries; the OpenFHE exact \
                         backend supports up to {} entries",
                        table.len(),
                        1 << MAX_LOOKUP_BITS
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// The capability table (machine-readable): `(operation, types, support)`.
pub const CAPABILITIES: &[(&str, &str, &str)] = &[
    ("and, or, xor, not", "bool and integer types", "yes"),
    (
        "add, sub, neg (and with constants)",
        "all integer types",
        "yes",
    ),
    ("multiply", "all integer types", "yes (quadratic in width)"),
    (
        "multiply by a constant",
        "all integer types",
        "yes (one adder per set bit)",
    ),
    ("compare (==, !=, <, <=, >, >=)", "all integer types", "yes"),
    ("select, min, max", "all exact types", "yes"),
    ("shift by a constant", "all integer types", "yes (no gates)"),
    (
        "divide, remainder by a constant",
        "all integer types",
        "yes (quadratic in width)",
    ),
    ("lookup", "any index type", "tables up to 256 entries"),
    ("cast", "all exact types", "yes (no gates)"),
];

/// Runs exact plans on a gate library, counting bootstrapped gates.
pub struct BitEvaluator<G: Gates> {
    pub gates: G,
    count: Cell<u64>,
}

impl<G: Gates> BitEvaluator<G> {
    pub fn new(gates: G) -> Self {
        Self {
            gates,
            count: Cell::new(0),
        }
    }

    /// Bootstrapped gates evaluated so far.
    pub fn gate_count(&self) -> u64 {
        self.count.get()
    }

    fn tick(&self) {
        self.count.set(self.count.get() + 1);
    }

    // --- bits, with constant folding ---------------------------------------

    fn and(&self, a: &Sig<G::Bit>, b: &Sig<G::Bit>) -> Result<Sig<G::Bit>> {
        Ok(match (a, b) {
            (Sig::Const(false), _) | (_, Sig::Const(false)) => Sig::Const(false),
            (Sig::Const(true), x) | (x, Sig::Const(true)) => x.clone(),
            (Sig::Enc(x), Sig::Enc(y)) => {
                self.tick();
                Sig::Enc(self.gates.and(x, y)?)
            }
        })
    }

    fn or(&self, a: &Sig<G::Bit>, b: &Sig<G::Bit>) -> Result<Sig<G::Bit>> {
        Ok(match (a, b) {
            (Sig::Const(true), _) | (_, Sig::Const(true)) => Sig::Const(true),
            (Sig::Const(false), x) | (x, Sig::Const(false)) => x.clone(),
            (Sig::Enc(x), Sig::Enc(y)) => {
                self.tick();
                Sig::Enc(self.gates.or(x, y)?)
            }
        })
    }

    fn xor(&self, a: &Sig<G::Bit>, b: &Sig<G::Bit>) -> Result<Sig<G::Bit>> {
        Ok(match (a, b) {
            (Sig::Const(x), Sig::Const(y)) => Sig::Const(x ^ y),
            (Sig::Const(false), x) | (x, Sig::Const(false)) => x.clone(),
            (Sig::Const(true), x) | (x, Sig::Const(true)) => self.not(x)?,
            (Sig::Enc(x), Sig::Enc(y)) => {
                self.tick();
                Sig::Enc(self.gates.xor(x, y)?)
            }
        })
    }

    fn not(&self, a: &Sig<G::Bit>) -> Result<Sig<G::Bit>> {
        Ok(match a {
            Sig::Const(v) => Sig::Const(!v),
            Sig::Enc(x) => Sig::Enc(self.gates.not(x)?),
        })
    }

    /// `c ? a : b`.
    fn mux(&self, c: &Sig<G::Bit>, a: &Sig<G::Bit>, b: &Sig<G::Bit>) -> Result<Sig<G::Bit>> {
        match (c, a, b) {
            (Sig::Const(true), a, _) => Ok(a.clone()),
            (Sig::Const(false), _, b) => Ok(b.clone()),
            (c, Sig::Const(true), Sig::Const(false)) => Ok(c.clone()),
            (c, Sig::Const(false), Sig::Const(true)) => self.not(c),
            (_, Sig::Const(x), Sig::Const(y)) if x == y => Ok(Sig::Const(*x)),
            _ => {
                // b XOR (c AND (a XOR b))
                let d = self.xor(a, b)?;
                let t = self.and(c, &d)?;
                self.xor(b, &t)
            }
        }
    }

    // --- words -------------------------------------------------------------

    fn constant(elem: Elem, v: i128) -> Word<G::Bit> {
        Word {
            elem,
            bits: (0..elem.bits())
                .map(|i| Sig::Const((v >> i) & 1 == 1))
                .collect(),
        }
    }

    fn msb(w: &Word<G::Bit>) -> &Sig<G::Bit> {
        w.bits.last().expect("a word has bits")
    }

    /// `a + b + carry`, `bits.len()` wide (wrapping; the range is proven).
    fn add_bits(
        &self,
        a: &[Sig<G::Bit>],
        b: &[Sig<G::Bit>],
        mut carry: Sig<G::Bit>,
    ) -> Result<Vec<Sig<G::Bit>>> {
        let n = a.len();
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let t = self.xor(&a[i], &b[i])?;
            out.push(self.xor(&t, &carry)?);
            if i + 1 < n {
                // carry = (a AND b) OR (carry AND (a XOR b))
                let g = self.and(&a[i], &b[i])?;
                let p = self.and(&carry, &t)?;
                carry = self.or(&g, &p)?;
            }
        }
        Ok(out)
    }

    /// Carry out of `a + b + carry` (no sum bits): `a + ~b + 1` carries
    /// out exactly when `a >= b` (unsigned).
    fn carry_out(
        &self,
        a: &[Sig<G::Bit>],
        b: &[Sig<G::Bit>],
        mut carry: Sig<G::Bit>,
    ) -> Result<Sig<G::Bit>> {
        for i in 0..a.len() {
            let t = self.xor(&a[i], &b[i])?;
            let g = self.and(&a[i], &b[i])?;
            let p = self.and(&carry, &t)?;
            carry = self.or(&g, &p)?;
        }
        Ok(carry)
    }

    fn not_bits(&self, a: &[Sig<G::Bit>]) -> Result<Vec<Sig<G::Bit>>> {
        a.iter().map(|x| self.not(x)).collect()
    }

    fn word(elem: Elem, bits: Vec<Sig<G::Bit>>) -> Word<G::Bit> {
        Word { elem, bits }
    }

    fn same(a: &Word<G::Bit>, b: &Word<G::Bit>) -> Result<Elem> {
        if a.elem != b.elem {
            return Err(Error::new(
                Code::Backend,
                format!("type mismatch {} vs {}", a.elem, b.elem),
            ));
        }
        Ok(a.elem)
    }

    fn sub_words(&self, a: &Word<G::Bit>, b: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        let nb = self.not_bits(&b.bits)?;
        Ok(Self::word(
            a.elem,
            self.add_bits(&a.bits, &nb, Sig::Const(true))?,
        ))
    }

    fn neg_word(&self, a: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        let zero = Self::constant(a.elem, 0);
        self.sub_words(&zero, a)
    }

    /// `a < b`, unsigned or signed (flipping the sign bits turns signed
    /// order into unsigned order).
    fn less(&self, a: &Word<G::Bit>, b: &Word<G::Bit>) -> Result<Sig<G::Bit>> {
        let (mut x, mut y) = (a.bits.clone(), b.bits.clone());
        if a.elem.is_signed() {
            let n = x.len() - 1;
            x[n] = self.not(&x[n])?;
            y[n] = self.not(&y[n])?;
        }
        let ny = self.not_bits(&y)?;
        let ge = self.carry_out(&x, &ny, Sig::Const(true))?;
        self.not(&ge)
    }

    fn equal(&self, a: &Word<G::Bit>, b: &Word<G::Bit>) -> Result<Sig<G::Bit>> {
        let mut eqs: Vec<Sig<G::Bit>> = a
            .bits
            .iter()
            .zip(&b.bits)
            .map(|(x, y)| self.xor(x, y).and_then(|d| self.not(&d)))
            .collect::<Result<_>>()?;
        // AND tree.
        while eqs.len() > 1 {
            let mut next = Vec::with_capacity(eqs.len().div_ceil(2));
            for pair in eqs.chunks(2) {
                next.push(if pair.len() == 2 {
                    self.and(&pair[0], &pair[1])?
                } else {
                    pair[0].clone()
                });
            }
            eqs = next;
        }
        Ok(eqs.pop().unwrap_or(Sig::Const(true)))
    }

    fn compare(&self, op: CmpOp, a: &Word<G::Bit>, b: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        let bit = match op {
            CmpOp::Eq => self.equal(a, b)?,
            CmpOp::Ne => self.not(&self.equal(a, b)?)?,
            CmpOp::Lt => self.less(a, b)?,
            CmpOp::Gt => self.less(b, a)?,
            CmpOp::Le => self.not(&self.less(b, a)?)?,
            CmpOp::Ge => self.not(&self.less(a, b)?)?,
        };
        Ok(Self::word(Elem::Bool, vec![bit]))
    }

    fn select_words(
        &self,
        c: &Sig<G::Bit>,
        a: &Word<G::Bit>,
        b: &Word<G::Bit>,
    ) -> Result<Word<G::Bit>> {
        Ok(Self::word(
            a.elem,
            a.bits
                .iter()
                .zip(&b.bits)
                .map(|(x, y)| self.mux(c, x, y))
                .collect::<Result<_>>()?,
        ))
    }

    /// `a * b`, truncated to the width (the range is proven): shift and
    /// add, skipping partial products that fold to zero.
    fn mul_bits(&self, a: &[Sig<G::Bit>], b: &[Sig<G::Bit>]) -> Result<Vec<Sig<G::Bit>>> {
        let n = a.len();
        let mut acc: Vec<Sig<G::Bit>> = vec![Sig::Const(false); n];
        for (i, bi) in b.iter().enumerate() {
            if matches!(bi, Sig::Const(false)) {
                continue;
            }
            let mut pp: Vec<Sig<G::Bit>> = vec![Sig::Const(false); n];
            for j in 0..n - i {
                pp[i + j] = self.and(&a[j], bi)?;
            }
            // The low i bits of pp are zero: add only the rest.
            let hi = self.add_bits(&acc[i..], &pp[i..], Sig::Const(false))?;
            acc.splice(i.., hi);
        }
        Ok(acc)
    }

    /// Unsigned division by a positive constant (restoring division): the
    /// quotient and remainder, each as wide as `a`.
    fn divmod_unsigned(&self, a: &[Sig<G::Bit>], c: u128) -> Result<QuotRem<Vec<Sig<G::Bit>>>> {
        let n = a.len();
        if c.is_power_of_two() {
            let k = c.trailing_zeros() as usize;
            let q: Vec<_> = (0..n)
                .map(|i| a.get(i + k).cloned().unwrap_or(Sig::Const(false)))
                .collect();
            let r: Vec<_> = (0..n)
                .map(|i| {
                    if i < k {
                        a[i].clone()
                    } else {
                        Sig::Const(false)
                    }
                })
                .collect();
            return Ok((q, r));
        }
        // The remainder is below c, so it fits in m bits; shifted in, m + 1.
        let m = (128 - c.leading_zeros()) as usize;
        let cbits: Vec<Sig<G::Bit>> = (0..=m).map(|i| Sig::Const((c >> i) & 1 == 1)).collect();
        let ncbits = self.not_bits(&cbits)?;
        let mut r: Vec<Sig<G::Bit>> = vec![Sig::Const(false); m + 1];
        let mut q: Vec<Sig<G::Bit>> = vec![Sig::Const(false); n];
        for i in (0..n).rev() {
            // r = (r << 1) | a_i
            r.pop();
            r.insert(0, a[i].clone());
            let ge = self.carry_out(&r, &ncbits, Sig::Const(true))?;
            let diff = self.add_bits(&r, &ncbits, Sig::Const(true))?;
            r = r
                .iter()
                .zip(&diff)
                .map(|(x, d)| self.mux(&ge, d, x))
                .collect::<Result<_>>()?;
            q[i] = ge;
        }
        let rem = (0..n)
            .map(|i| r.get(i).cloned().unwrap_or(Sig::Const(false)))
            .collect();
        Ok((q, rem))
    }

    /// Truncating division and remainder by a nonzero constant.
    fn divmod(&self, a: &Word<G::Bit>, c: i128) -> Result<QuotRem<Word<G::Bit>>> {
        let e = a.elem;
        if !e.is_signed() {
            let (q, r) = self.divmod_unsigned(&a.bits, c as u128)?;
            return Ok((Self::word(e, q), Self::word(e, r)));
        }
        let sign = Self::msb(a).clone();
        let na = self.neg_word(a)?;
        let abs = self.select_words(&sign, &na, a)?;
        let (q, r) = self.divmod_unsigned(&abs.bits, c.unsigned_abs())?;
        let (q, r) = (Self::word(e, q), Self::word(e, r));
        // The quotient is negative when exactly one operand is; the
        // remainder takes the dividend's sign.
        let qsign = if c < 0 {
            self.not(&sign)?
        } else {
            sign.clone()
        };
        let nq = self.neg_word(&q)?;
        let nr = self.neg_word(&r)?;
        Ok((
            self.select_words(&qsign, &nq, &q)?,
            self.select_words(&sign, &nr, &r)?,
        ))
    }

    fn lookup_word(&self, x: &Word<G::Bit>, table: &[i128], elem: Elem) -> Result<Word<G::Bit>> {
        let k = if table.len() <= 1 {
            0
        } else {
            (usize::BITS - (table.len() - 1).leading_zeros()) as usize
        };
        if k as u32 > MAX_LOOKUP_BITS {
            return Err(Error::new(
                Code::Backend,
                format!(
                    "lookup tables are limited to {} entries",
                    1 << MAX_LOOKUP_BITS
                ),
            ));
        }
        // Multiplexer tree over the index's low k bits (the index is proven
        // in range, so higher bits are zero); leaves are constants.
        let mut level: Vec<Word<G::Bit>> = (0..1usize << k)
            .map(|i| Self::constant(elem, table.get(i).copied().unwrap_or(0)))
            .collect();
        for j in 0..k {
            let c = &x.bits[j];
            level = level
                .chunks(2)
                .map(|p| self.select_words(c, &p[1], &p[0]))
                .collect::<Result<_>>()?;
        }
        Ok(level.pop().expect("one word"))
    }

    fn cast_word(&self, a: &Word<G::Bit>, to: Elem) -> Word<G::Bit> {
        let fill = if a.elem.is_signed() {
            Self::msb(a).clone()
        } else {
            Sig::Const(false)
        };
        let bits = (0..to.bits() as usize)
            .map(|i| a.bits.get(i).cloned().unwrap_or_else(|| fill.clone()))
            .collect();
        Self::word(to, bits)
    }

    fn materialize(&self, w: &Word<G::Bit>) -> Result<Vec<G::Bit>> {
        w.bits
            .iter()
            .map(|b| match b {
                Sig::Const(v) => self.gates.constant(*v),
                Sig::Enc(x) => Ok(x.clone()),
            })
            .collect()
    }
}

impl<G: Gates> ExactEvaluator for BitEvaluator<G> {
    type Ciphertext = Word<G::Bit>;

    fn name(&self) -> &'static str {
        self.gates.name()
    }
    fn load(&self, elem: Elem, bytes: &[u8]) -> Result<Word<G::Bit>> {
        let bits = self.gates.load(elem, bytes)?;
        if bits.len() != elem.bits() as usize {
            return Err(Error::new(
                Code::Envelope,
                format!("a {elem} ciphertext has {} bits", elem.bits()),
            ));
        }
        Ok(Self::word(elem, bits.into_iter().map(Sig::Enc).collect()))
    }
    fn store(&self, ct: &Word<G::Bit>) -> Result<Vec<u8>> {
        self.gates.store(ct.elem, &self.materialize(ct)?)
    }
    fn elem_of(&self, ct: &Word<G::Bit>) -> Elem {
        ct.elem
    }
    fn trivial(&self, elem: Elem, value: i128) -> Result<Word<G::Bit>> {
        Ok(Self::constant(elem, value))
    }
    fn add(&self, a: &Word<G::Bit>, b: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        let e = Self::same(a, b)?;
        Ok(Self::word(
            e,
            self.add_bits(&a.bits, &b.bits, Sig::Const(false))?,
        ))
    }
    fn sub(&self, a: &Word<G::Bit>, b: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        Self::same(a, b)?;
        self.sub_words(a, b)
    }
    fn mul(&self, a: &Word<G::Bit>, b: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        let e = Self::same(a, b)?;
        Ok(Self::word(e, self.mul_bits(&a.bits, &b.bits)?))
    }
    fn neg(&self, a: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        self.neg_word(a)
    }
    fn add_scalar(&self, a: &Word<G::Bit>, c: i128) -> Result<Word<G::Bit>> {
        self.add(a, &Self::constant(a.elem, c))
    }
    fn sub_scalar(&self, a: &Word<G::Bit>, c: i128) -> Result<Word<G::Bit>> {
        self.sub_words(a, &Self::constant(a.elem, c))
    }
    fn mul_scalar(&self, a: &Word<G::Bit>, c: i128) -> Result<Word<G::Bit>> {
        self.mul(a, &Self::constant(a.elem, c))
    }
    fn scalar_sub(&self, c: i128, a: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        self.sub_words(&Self::constant(a.elem, c), a)
    }
    fn div_scalar(&self, a: &Word<G::Bit>, c: i128) -> Result<Word<G::Bit>> {
        if c == 0 {
            return Err(Error::new(Code::Backend, "division by zero"));
        }
        Ok(self.divmod(a, c)?.0)
    }
    fn rem_scalar(&self, a: &Word<G::Bit>, c: i128) -> Result<Word<G::Bit>> {
        if c == 0 {
            return Err(Error::new(Code::Backend, "division by zero"));
        }
        Ok(self.divmod(a, c)?.1)
    }
    fn cmp(&self, op: CmpOp, a: &Word<G::Bit>, b: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        Self::same(a, b)?;
        self.compare(op, a, b)
    }
    fn cmp_scalar(&self, op: CmpOp, a: &Word<G::Bit>, c: i128) -> Result<Word<G::Bit>> {
        self.compare(op, a, &Self::constant(a.elem, c))
    }
    fn logic(&self, op: LogicOp, a: &Word<G::Bit>, b: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        let e = Self::same(a, b)?;
        let bits = a
            .bits
            .iter()
            .zip(&b.bits)
            .map(|(x, y)| match op {
                LogicOp::And => self.and(x, y),
                LogicOp::Or => self.or(x, y),
                LogicOp::Xor => self.xor(x, y),
            })
            .collect::<Result<_>>()?;
        Ok(Self::word(e, bits))
    }
    fn not(&self, a: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        Ok(Self::word(a.elem, self.not_bits(&a.bits)?))
    }
    fn shift(&self, a: &Word<G::Bit>, left: bool, by: u32) -> Result<Word<G::Bit>> {
        let n = a.bits.len();
        let by = by as usize;
        if by >= n {
            return Err(Error::new(
                Code::Backend,
                format!("shift by {by} on {}", a.elem),
            ));
        }
        let fill = if !left && a.elem.is_signed() {
            Self::msb(a).clone()
        } else {
            Sig::Const(false)
        };
        let bits = (0..n)
            .map(|i| {
                let src = if left {
                    i.checked_sub(by)
                } else {
                    Some(i + by)
                };
                src.and_then(|s| a.bits.get(s).cloned())
                    .unwrap_or_else(|| fill.clone())
            })
            .collect();
        Ok(Self::word(a.elem, bits))
    }
    fn min(&self, a: &Word<G::Bit>, b: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        Self::same(a, b)?;
        let lt = self.less(a, b)?;
        self.select_words(&lt, a, b)
    }
    fn max(&self, a: &Word<G::Bit>, b: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        Self::same(a, b)?;
        let lt = self.less(a, b)?;
        self.select_words(&lt, b, a)
    }
    fn select(&self, c: &Word<G::Bit>, a: &Word<G::Bit>, b: &Word<G::Bit>) -> Result<Word<G::Bit>> {
        Self::same(a, b)?;
        self.select_words(&c.bits[0], a, b)
    }
    fn lookup(&self, a: &Word<G::Bit>, table: &[i128], elem: Elem) -> Result<Word<G::Bit>> {
        self.lookup_word(a, table, elem)
    }
    fn cast(&self, a: &Word<G::Bit>, to: Elem) -> Result<Word<G::Bit>> {
        Ok(self.cast_word(a, to))
    }
}

// --- plaintext bits: the circuits' reference, for exhaustive testing ----------

/// Plaintext gates: the same circuits on clear bits. Not a backend (no
/// encryption); it checks the circuits exhaustively against the semantics.
pub struct PlainGates;

impl Gates for PlainGates {
    type Bit = bool;
    fn name(&self) -> &'static str {
        "plain-bits"
    }
    fn and(&self, a: &bool, b: &bool) -> Result<bool> {
        Ok(*a && *b)
    }
    fn or(&self, a: &bool, b: &bool) -> Result<bool> {
        Ok(*a || *b)
    }
    fn xor(&self, a: &bool, b: &bool) -> Result<bool> {
        Ok(a ^ b)
    }
    fn not(&self, a: &bool) -> Result<bool> {
        Ok(!a)
    }
    fn constant(&self, v: bool) -> Result<bool> {
        Ok(v)
    }
    fn load(&self, elem: Elem, bytes: &[u8]) -> Result<Vec<bool>> {
        if bytes.len() != elem.bits() as usize {
            return Err(Error::new(Code::Envelope, "wrong width"));
        }
        Ok(bytes.iter().map(|b| *b != 0).collect())
    }
    fn store(&self, _: Elem, bits: &[bool]) -> Result<Vec<u8>> {
        Ok(bits.iter().map(|b| u8::from(*b)).collect())
    }
}

/// Bootstrapped gates `plan` costs on a bit-level backend. Data-independent:
/// every input bit is treated as encrypted, and only the plan's constants
/// fold away, so the same count holds for every input.
pub fn gate_count(plan: &ExactPlan) -> Result<u64> {
    let ev = BitEvaluator::new(PlainGates);
    let inputs = plan.inputs.iter().map(|i| plain_word(i.elem, 0)).collect();
    crate::exec::evaluate_exact(&ev, plan, inputs)?;
    Ok(ev.gate_count())
}

/// The value of plaintext bits of `elem` (two's complement for signed).
pub fn plain_value(w: &Word<bool>) -> i128 {
    let mut v: i128 = 0;
    for (i, b) in w.bits.iter().enumerate() {
        let bit = match b {
            Sig::Const(x) | Sig::Enc(x) => *x,
        };
        if bit {
            v |= 1 << i;
        }
    }
    if w.elem.is_signed() && v >> (w.elem.bits() - 1) & 1 == 1 {
        v -= 1 << w.elem.bits();
    }
    v
}

/// Plaintext bits of a value (as if encrypted).
pub fn plain_word(elem: Elem, v: i128) -> Word<bool> {
    Word {
        elem,
        bits: (0..elem.bits())
            .map(|i| Sig::Enc((v >> i) & 1 == 1))
            .collect(),
    }
}

// --- the OpenFHE exact backend's identity (pure constants: artifacts can
// target it from builds without OpenFHE) ----------------------------------------

/// Backend name written into artifacts, envelopes and receipts. The
/// cryptographic family is BinFHE (FHEW/TFHE-style gate bootstrapping); the
/// software is OpenFHE.
pub const OPENFHE_EXACT_BACKEND: &str = "openfhe-exact";
/// The OpenFHE version it is built and tested with.
pub const OPENFHE_EXACT_VERSION: &str = "1.5.1";
/// The vetted parameter set: OpenFHE BinFHE STD128 with GINX bootstrapping
/// (128-bit classical security, gate failure probability 2^-135).
pub const OPENFHE_EXACT_PARAMSET: &str = "STD128";
/// The vetted profile's name (bound into its parameter-set ID).
pub const OPENFHE_EXACT_PROFILE: &str = "BINFHE_STD128_GINX_BITS_V1";

pub fn openfhe_exact_profile() -> crate::ExactProfile {
    crate::ExactProfile {
        backend: OPENFHE_EXACT_BACKEND.into(),
        backend_version: OPENFHE_EXACT_VERSION.into(),
        profile: OPENFHE_EXACT_PROFILE.into(),
        security: "128-bit".into(),
        failure_probability: "2^-135 per gate".into(),
        parameter_selector_version: "openfhe-exact-v1".into(),
    }
}
