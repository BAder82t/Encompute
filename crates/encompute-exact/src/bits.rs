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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sig<B> {
    Const(bool),
    Enc(B),
}

/// A quotient and a remainder.
type QuotRem<T> = (T, T);

/// A (generate, propagate) pair of a bit range.
type GenProp<B> = (Sig<B>, Sig<B>);

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

/// How integer circuits are built. Every strategy computes the same bits;
/// they trade gate count against depth (the critical path, which bounds
/// parallel execution).
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub struct Strategy {
    pub adder: Adder,
    pub comparator: Comparator,
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Adder {
    /// Ripple carry: fewest gates, depth linear in the width (reference).
    #[default]
    Ripple,
    /// Sklansky parallel prefix: more gates, depth logarithmic.
    Prefix,
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Comparator {
    /// The carry chain of `a + ~b + 1` (reference).
    #[default]
    Ripple,
    /// A balanced tree of (generate, propagate) pairs: logarithmic depth.
    Tree,
}

impl Strategy {
    /// The reference circuits (the original lowering).
    pub const REFERENCE: Strategy = Strategy {
        adder: Adder::Ripple,
        comparator: Comparator::Ripple,
    };
    /// Logarithmic-depth circuits, for parallel execution.
    pub const PARALLEL: Strategy = Strategy {
        adder: Adder::Prefix,
        comparator: Comparator::Tree,
    };
}

impl<G: Gates> Gates for std::sync::Arc<G> {
    type Bit = G::Bit;
    fn name(&self) -> &'static str {
        (**self).name()
    }
    fn and(&self, a: &G::Bit, b: &G::Bit) -> Result<G::Bit> {
        (**self).and(a, b)
    }
    fn or(&self, a: &G::Bit, b: &G::Bit) -> Result<G::Bit> {
        (**self).or(a, b)
    }
    fn xor(&self, a: &G::Bit, b: &G::Bit) -> Result<G::Bit> {
        (**self).xor(a, b)
    }
    fn not(&self, a: &G::Bit) -> Result<G::Bit> {
        (**self).not(a)
    }
    fn constant(&self, v: bool) -> Result<G::Bit> {
        (**self).constant(v)
    }
    fn load(&self, elem: Elem, bytes: &[u8]) -> Result<Vec<G::Bit>> {
        (**self).load(elem, bytes)
    }
    fn store(&self, elem: Elem, bits: &[G::Bit]) -> Result<Vec<u8>> {
        (**self).store(elem, bits)
    }
}

/// Runs exact plans on a gate library, counting bootstrapped gates.
pub struct BitEvaluator<G: Gates> {
    pub gates: G,
    pub strategy: Strategy,
    count: Cell<u64>,
}

impl<G: Gates> BitEvaluator<G> {
    pub fn new(gates: G) -> Self {
        Self::with_strategy(gates, Strategy::REFERENCE)
    }

    pub fn with_strategy(gates: G, strategy: Strategy) -> Self {
        Self {
            gates,
            strategy,
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

    /// `(G_hi, P_hi) ∘ (G_lo, P_lo)`: the generate/propagate pair of two
    /// adjacent bit ranges (associative).
    #[allow(clippy::type_complexity)]
    fn combine(
        &self,
        hi: &(Sig<G::Bit>, Sig<G::Bit>),
        lo: &(Sig<G::Bit>, Sig<G::Bit>),
    ) -> Result<(Sig<G::Bit>, Sig<G::Bit>)> {
        let t = self.and(&hi.1, &lo.0)?;
        Ok((self.or(&hi.0, &t)?, self.and(&hi.1, &lo.1)?))
    }

    /// Sklansky parallel-prefix addition: the same sum, logarithmic depth.
    fn prefix_add(
        &self,
        a: &[Sig<G::Bit>],
        b: &[Sig<G::Bit>],
        carry: Sig<G::Bit>,
    ) -> Result<Vec<Sig<G::Bit>>> {
        let n = a.len();
        let p: Vec<Sig<G::Bit>> = (0..n)
            .map(|i| self.xor(&a[i], &b[i]))
            .collect::<Result<_>>()?;
        // Element 0 is the carry-in; element i + 1 is bit i. Prefix k (the
        // combination of elements 0..=k) generates the carry into bit k.
        let mut e: Vec<GenProp<G::Bit>> = Vec::with_capacity(n);
        e.push((carry, Sig::Const(false)));
        for i in 0..n.saturating_sub(1) {
            e.push((self.and(&a[i], &b[i])?, p[i].clone()));
        }
        let len = e.len();
        let mut d = 0;
        while (1usize << d) < len {
            let prev = e.clone();
            for i in 0..len {
                if (i >> d) & 1 == 1 {
                    let j = ((i >> d) << d) - 1;
                    e[i] = self.combine(&prev[i], &prev[j])?;
                }
            }
            d += 1;
        }
        (0..n).map(|i| self.xor(&p[i], &e[i].0)).collect()
    }

    /// The carry out of `a + b + carry` by a balanced tree of
    /// (generate, propagate) pairs: logarithmic depth.
    fn tree_carry_out(
        &self,
        a: &[Sig<G::Bit>],
        b: &[Sig<G::Bit>],
        carry: Sig<G::Bit>,
    ) -> Result<Sig<G::Bit>> {
        let mut level: Vec<GenProp<G::Bit>> = Vec::with_capacity(a.len() + 1);
        level.push((carry, Sig::Const(false)));
        for i in 0..a.len() {
            level.push((self.and(&a[i], &b[i])?, self.xor(&a[i], &b[i])?));
        }
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                next.push(if pair.len() == 2 {
                    // pair[1] is the higher range.
                    self.combine(&pair[1], &pair[0])?
                } else {
                    pair[0].clone()
                });
            }
            level = next;
        }
        Ok(level.pop().expect("one pair").0)
    }

    /// `a + b + carry`, `bits.len()` wide (wrapping; the range is proven).
    fn add_bits(
        &self,
        a: &[Sig<G::Bit>],
        b: &[Sig<G::Bit>],
        mut carry: Sig<G::Bit>,
    ) -> Result<Vec<Sig<G::Bit>>> {
        let n = a.len();
        if self.strategy.adder == Adder::Prefix && n >= 4 {
            return self.prefix_add(a, b, carry);
        }
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
        if self.strategy.comparator == Comparator::Tree && a.len() >= 4 {
            return self.tree_carry_out(a, b, carry);
        }
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

// --- tests of the private bit-level transformations ------------------------------

#[cfg(test)]
mod tests {
    //! Constant folding on [`Sig`] bits, and the logarithmic-depth adder and
    //! comparator against the ripple ones at every width (the public API
    //! reaches only the widths of exact types and their slices). The
    //! differential tests on whole programs are in `tests/optimizer.rs`.

    use super::*;
    use proptest::prelude::{any, prop_assert, prop_assert_eq, TestCaseError};
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

    fn runner(default: u32) -> TestRunner {
        let cases = std::env::var("ENCOMPUTE_EXACT_PROGRAMS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default);
        TestRunner::new_with_rng(
            Config {
                cases,
                failure_persistence: None,
                ..Config::default()
            },
            TestRng::deterministic_rng(RngAlgorithm::ChaCha),
        )
    }

    fn ev(s: Strategy) -> BitEvaluator<PlainGates> {
        BitEvaluator::with_strategy(PlainGates, s)
    }

    fn val(s: &Sig<bool>) -> bool {
        match s {
            Sig::Const(v) | Sig::Enc(v) => *v,
        }
    }

    fn is_const(s: &Sig<bool>) -> bool {
        matches!(s, Sig::Const(_))
    }

    /// The four kinds of bit: public 0/1, encrypted 0/1.
    fn sigs() -> [Sig<bool>; 4] {
        [
            Sig::Const(false),
            Sig::Const(true),
            Sig::Enc(false),
            Sig::Enc(true),
        ]
    }

    /// `n` bits of `v`, those in `const_mask` public.
    fn word_bits(v: u128, n: usize, const_mask: u128) -> Vec<Sig<bool>> {
        (0..n)
            .map(|i| {
                let b = (v >> i) & 1 == 1;
                if (const_mask >> i) & 1 == 1 {
                    Sig::Const(b)
                } else {
                    Sig::Enc(b)
                }
            })
            .collect()
    }

    fn value(bits: &[Sig<bool>]) -> u128 {
        bits.iter()
            .enumerate()
            .fold(0, |acc, (i, b)| acc | (u128::from(val(b)) << i))
    }

    fn mask(n: usize) -> u128 {
        if n == 128 {
            u128::MAX
        } else {
            (1u128 << n) - 1
        }
    }

    // --- constant folding ------------------------------------------------------------

    #[test]
    fn bit_and_folds_constants() {
        for a in sigs() {
            for b in sigs() {
                let e = ev(Strategy::REFERENCE);
                let r = e.and(&a, &b).unwrap();
                assert_eq!(val(&r), val(&a) && val(&b), "{a:?} & {b:?}");
                let folded = is_const(&a) || is_const(&b);
                assert_eq!(e.gate_count(), u64::from(!folded), "{a:?} & {b:?}");
                if a == Sig::Const(false) || b == Sig::Const(false) {
                    assert_eq!(r, Sig::Const(false));
                } else if a == Sig::Const(true) {
                    assert_eq!(r, b, "1 & x = x");
                } else if b == Sig::Const(true) {
                    assert_eq!(r, a, "x & 1 = x");
                }
            }
        }
    }

    #[test]
    fn bit_or_folds_constants() {
        for a in sigs() {
            for b in sigs() {
                let e = ev(Strategy::REFERENCE);
                let r = e.or(&a, &b).unwrap();
                assert_eq!(val(&r), val(&a) || val(&b), "{a:?} | {b:?}");
                let folded = is_const(&a) || is_const(&b);
                assert_eq!(e.gate_count(), u64::from(!folded), "{a:?} | {b:?}");
                if a == Sig::Const(true) || b == Sig::Const(true) {
                    assert_eq!(r, Sig::Const(true));
                } else if a == Sig::Const(false) {
                    assert_eq!(r, b, "0 | x = x");
                } else if b == Sig::Const(false) {
                    assert_eq!(r, a, "x | 0 = x");
                }
            }
        }
    }

    #[test]
    fn bit_xor_folds_constants() {
        for a in sigs() {
            for b in sigs() {
                let e = ev(Strategy::REFERENCE);
                let r = e.xor(&a, &b).unwrap();
                assert_eq!(val(&r), val(&a) ^ val(&b), "{a:?} ^ {b:?}");
                let folded = is_const(&a) || is_const(&b);
                assert_eq!(e.gate_count(), u64::from(!folded), "{a:?} ^ {b:?}");
                // Public iff both operands are; x ^ 1 is a (free) NOT of x.
                assert_eq!(is_const(&r), is_const(&a) && is_const(&b));
            }
        }
    }

    #[test]
    fn bit_not_folds_constants() {
        for a in sigs() {
            let e = ev(Strategy::REFERENCE);
            let r = e.not(&a).unwrap();
            assert_eq!(val(&r), !val(&a));
            assert_eq!(is_const(&r), is_const(&a));
            assert_eq!(e.gate_count(), 0, "NOT is free");
        }
    }

    #[test]
    fn bit_mux_folds_constants() {
        for c in sigs() {
            for a in sigs() {
                for b in sigs() {
                    let e = ev(Strategy::REFERENCE);
                    let r = e.mux(&c, &a, &b).unwrap();
                    let want = if val(&c) { val(&a) } else { val(&b) };
                    assert_eq!(val(&r), want, "{c:?} ? {a:?} : {b:?}");
                    let n = e.gate_count();
                    match (&c, &a, &b) {
                        (Sig::Const(true), _, _) => assert_eq!((r, n), (a.clone(), 0)),
                        (Sig::Const(false), _, _) => assert_eq!((r, n), (b.clone(), 0)),
                        (_, Sig::Const(true), Sig::Const(false)) => {
                            assert_eq!((r, n), (c.clone(), 0), "c ? 1 : 0 = c")
                        }
                        (_, Sig::Const(false), Sig::Const(true)) => {
                            assert_eq!((r, n), (e.not(&c).unwrap(), 0), "c ? 0 : 1 = !c")
                        }
                        (_, Sig::Const(x), Sig::Const(y)) if x == y => {
                            assert_eq!((r, n), (Sig::Const(*x), 0))
                        }
                        // b ^ (c & (a ^ b)): an XOR with a public bit is free.
                        (_, Sig::Const(_), _) => assert_eq!(n, 2),
                        (_, _, Sig::Const(_)) => assert_eq!(n, 1),
                        _ => assert_eq!(n, 3),
                    }
                }
            }
        }
    }

    #[test]
    fn prop_bit_constant_folding() {
        // Random formulas over public and encrypted bits: the value is the
        // Boolean one, and an operation with a public operand costs no gate.
        runner(256)
            .run(
                &(
                    proptest::collection::vec(
                        (0u8..5, any::<u16>(), any::<u16>(), any::<u16>()),
                        1..40,
                    ),
                    any::<u8>(),
                ),
                |(steps, assign)| {
                    let e = ev(Strategy::REFERENCE);
                    let mut bits: Vec<Sig<bool>> = vec![Sig::Const(false), Sig::Const(true)];
                    bits.extend((0..4).map(|i| Sig::Enc((assign >> i) & 1 == 1)));
                    for (k, i, j, l) in steps {
                        let pick = |x: u16| bits[x as usize % bits.len()].clone();
                        let (a, b, c) = (pick(i), pick(j), pick(l));
                        let before = e.gate_count();
                        let (r, want, free) = match k {
                            0 => (
                                e.and(&a, &b),
                                val(&a) && val(&b),
                                is_const(&a) || is_const(&b),
                            ),
                            1 => (
                                e.or(&a, &b),
                                val(&a) || val(&b),
                                is_const(&a) || is_const(&b),
                            ),
                            2 => (
                                e.xor(&a, &b),
                                val(&a) ^ val(&b),
                                is_const(&a) || is_const(&b),
                            ),
                            3 => (e.not(&a), !val(&a), true),
                            _ => (
                                e.mux(&c, &a, &b),
                                if val(&c) { val(&a) } else { val(&b) },
                                is_const(&c) || (is_const(&a) && is_const(&b)),
                            ),
                        };
                        let r = r.unwrap();
                        prop_assert_eq!(val(&r), want);
                        let cost = e.gate_count() - before;
                        if free {
                            prop_assert_eq!(cost, 0);
                        } else {
                            prop_assert!(cost <= 3);
                        }
                        bits.push(r);
                    }
                    Ok(())
                },
            )
            .unwrap();
    }

    // --- the Sklansky prefix adder and the tree comparator -------------------------

    /// `prefix_add` and `tree_carry_out` against the ripple circuits and
    /// the integers, for one width, operands, carry and public-bit masks.
    fn check_adder_and_comparator(
        n: usize,
        a: u128,
        b: u128,
        c: bool,
        ma: u128,
        mb: u128,
    ) -> std::result::Result<(), TestCaseError> {
        let (a, b) = (a & mask(n), b & mask(n));
        let (x, y) = (word_bits(a, n, ma), word_bits(b, n, mb));
        let carry = if ma & 1 == 1 {
            Sig::Const(c)
        } else {
            Sig::Enc(c)
        };
        let (par, rip) = (ev(Strategy::PARALLEL), ev(Strategy::REFERENCE));
        let sum = a + b + u128::from(c);
        let prefix = par.prefix_add(&x, &y, carry.clone()).unwrap();
        let ripple = rip.add_bits(&x, &y, carry.clone()).unwrap();
        prop_assert_eq!(prefix.len(), n);
        prop_assert_eq!(
            value(&prefix),
            sum & mask(n),
            "prefix {} {}+{}+{}",
            n,
            a,
            b,
            c
        );
        prop_assert_eq!(
            value(&ripple),
            sum & mask(n),
            "ripple {} {}+{}+{}",
            n,
            a,
            b,
            c
        );
        let tree = par.tree_carry_out(&x, &y, carry.clone()).unwrap();
        let chain = rip.carry_out(&x, &y, carry).unwrap();
        prop_assert_eq!(val(&tree), sum >> n == 1, "tree {} {}+{}+{}", n, a, b, c);
        prop_assert_eq!(val(&chain), sum >> n == 1, "ripple carry {}", n);
        Ok(())
    }

    #[test]
    fn prefix_add_and_tree_carry_out_match_ripple_exhaustively_to_8_bits() {
        for n in 1..=8usize {
            for a in 0..1u128 << n {
                for b in 0..1u128 << n {
                    for c in [false, true] {
                        check_adder_and_comparator(n, a, b, c, 0, 0).unwrap();
                    }
                }
            }
        }
    }

    #[test]
    fn prefix_add_and_tree_carry_out_match_ripple_on_wide_samples() {
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for n in (9..=16).chain([17, 23, 31, 32, 33, 47, 48, 63, 64]) {
            let m = mask(n);
            let edges = [
                0,
                1,
                m,
                m - 1,
                m >> 1,
                (m >> 1) + 1,
                0x5555_5555_5555_5555 & m,
            ];
            for &a in &edges {
                for &b in &edges {
                    for c in [false, true] {
                        check_adder_and_comparator(n, a, b, c, 0, 0).unwrap();
                    }
                }
            }
            for _ in 0..64 {
                let (a, b, c) = (next() as u128, next() as u128, next() & 1 == 1);
                check_adder_and_comparator(n, a, b, c, 0, 0).unwrap();
                // Some bits public: folding inside the prefix network.
                let (ma, mb) = (next() as u128, next() as u128);
                check_adder_and_comparator(n, a, b, c, ma, mb).unwrap();
            }
        }
    }

    #[test]
    fn prop_prefix_add_and_tree_carry_out_match_ripple() {
        runner(512)
            .run(
                &(
                    1usize..=64,
                    any::<u64>(),
                    any::<u64>(),
                    any::<bool>(),
                    any::<u64>(),
                    any::<u64>(),
                ),
                |(n, a, b, c, ma, mb)| {
                    check_adder_and_comparator(n, a as u128, b as u128, c, ma as u128, mb as u128)
                },
            )
            .unwrap();
    }

    #[test]
    fn prefix_adder_and_tree_comparator_are_used_from_width_4() {
        // All bits encrypted: gate counts identify the circuit used.
        let count = |s: Strategy, f: &dyn Fn(&BitEvaluator<PlainGates>)| {
            let e = ev(s);
            f(&e);
            e.gate_count()
        };
        for n in 1..=64usize {
            let (x, y) = (word_bits(0, n, 0), word_bits(mask(n), n, 0));
            let c = || Sig::Enc(true);
            let add = |e: &BitEvaluator<PlainGates>| {
                e.add_bits(&x, &y, c()).unwrap();
            };
            let pre = |e: &BitEvaluator<PlainGates>| {
                e.prefix_add(&x, &y, c()).unwrap();
            };
            let cmp = |e: &BitEvaluator<PlainGates>| {
                e.carry_out(&x, &y, c()).unwrap();
            };
            let tree = |e: &BitEvaluator<PlainGates>| {
                e.tree_carry_out(&x, &y, c()).unwrap();
            };
            let (ripple_add, ripple_cmp) = (
                count(Strategy::REFERENCE, &add),
                count(Strategy::REFERENCE, &cmp),
            );
            let (par_add, par_cmp) = (
                count(Strategy::PARALLEL, &add),
                count(Strategy::PARALLEL, &cmp),
            );
            if n < 4 {
                assert_eq!(par_add, ripple_add, "width {n}: ripple adder");
                assert_eq!(par_cmp, ripple_cmp, "width {n}: ripple comparator");
            } else {
                assert_eq!(par_add, count(Strategy::PARALLEL, &pre), "width {n}");
                assert_eq!(par_cmp, count(Strategy::PARALLEL, &tree), "width {n}");
                assert_ne!(par_add, ripple_add, "width {n}: a different circuit");
            }
            // The reference strategy never uses them.
            assert_eq!(
                ripple_add,
                5 * n as u64 - 3,
                "width {n}: ripple adder gates"
            );
        }
    }

    /// Gates that compute depths: a bit is the length of its critical path.
    struct DepthGates;

    impl Gates for DepthGates {
        type Bit = u32;
        fn name(&self) -> &'static str {
            "depth"
        }
        fn and(&self, a: &u32, b: &u32) -> Result<u32> {
            Ok(1 + a.max(b))
        }
        fn or(&self, a: &u32, b: &u32) -> Result<u32> {
            Ok(1 + a.max(b))
        }
        fn xor(&self, a: &u32, b: &u32) -> Result<u32> {
            Ok(1 + a.max(b))
        }
        fn not(&self, a: &u32) -> Result<u32> {
            Ok(*a)
        }
        fn constant(&self, _: bool) -> Result<u32> {
            Ok(0)
        }
        fn load(&self, _: Elem, _: &[u8]) -> Result<Vec<u32>> {
            Err(Error::new(Code::Backend, "no ciphertexts"))
        }
        fn store(&self, _: Elem, _: &[u32]) -> Result<Vec<u8>> {
            Err(Error::new(Code::Backend, "no ciphertexts"))
        }
    }

    #[test]
    fn prefix_adder_and_tree_comparator_have_logarithmic_depth() {
        for n in [4usize, 8, 16, 32, 64] {
            let bits = vec![Sig::Enc(0u32); n];
            let depth = |v: &[Sig<u32>]| {
                v.iter()
                    .map(|b| match b {
                        Sig::Enc(d) => *d,
                        Sig::Const(_) => 0,
                    })
                    .max()
                    .unwrap()
            };
            let log = usize::BITS - n.leading_zeros(); // ceil(log2(n + 1))
            let par = BitEvaluator::with_strategy(DepthGates, Strategy::PARALLEL);
            let rip = BitEvaluator::with_strategy(DepthGates, Strategy::REFERENCE);
            let p = depth(&par.prefix_add(&bits, &bits, Sig::Enc(0)).unwrap());
            let r = depth(&rip.add_bits(&bits, &bits, Sig::Enc(0)).unwrap());
            assert!(p <= 2 * log + 2, "prefix adder depth {p} at width {n}");
            assert!(r >= 2 * n as u32 - 1, "ripple adder depth {r} at width {n}");
            let t = depth(&[par.tree_carry_out(&bits, &bits, Sig::Enc(0)).unwrap()]);
            let c = depth(&[rip.carry_out(&bits, &bits, Sig::Enc(0)).unwrap()]);
            assert!(t <= 2 * log + 1, "tree comparator depth {t} at width {n}");
            assert!(
                c >= 2 * n as u32,
                "ripple comparator depth {c} at width {n}"
            );
        }
    }
}
