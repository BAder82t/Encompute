//! OpenFHE CKKS evaluator for Encompute (ADR-001: Encompute-owned `cxx` shim
//! over OpenFHE v1.5.1). Nothing outside this crate sees OpenFHE types.
//!
//! This crate is the evaluator side only: it builds a crypto context from
//! parameters, loads evaluation keys exported by a client, and computes on
//! serialized ciphertexts. It has no key generation, encryption or
//! decryption; those live in `encompute-openfhe-client`, which the evaluator
//! binary does not link (0.2 plan, D2).

use encompute_backend::{CkksEvaluator, ExactEvaluator};
use encompute_ckks::CkksParams;
use encompute_ir::{CmpOp, Elem, LogicOp};
use encompute_ir::{Code, Error, Result};

/// OpenFHE release this crate is built and tested against.
pub const OPENFHE_VERSION: &str = "1.5.1";

#[allow(unsafe_code)]
#[cxx::bridge(namespace = "encompute_openfhe")]
mod ffi {
    unsafe extern "C++" {
        include!("shim.h");

        type Context;
        type Ciphertext;

        fn new_context(
            ring_dim: u32,
            mult_depth: u32,
            scale_bits: u32,
            first_mod_bits: u32,
            num_large_digits: u32,
            slots: u32,
        ) -> Result<UniquePtr<Context>>;
        fn new_bgv_context(mult_depth: u32) -> Result<UniquePtr<Context>>;
        fn ring_dimension(ctx: &Context) -> Result<u32>;
        fn log_qp(ctx: &Context) -> Result<u32>;
        fn load_evaluation_keys(ctx: Pin<&mut Context>, bytes: &[u8]) -> Result<String>;
        fn load_ciphertext(ctx: &Context, bytes: &[u8]) -> Result<UniquePtr<Ciphertext>>;
        fn store_ciphertext(ct: &Ciphertext) -> Result<Vec<u8>>;

        fn add(ctx: &Context, a: &Ciphertext, b: &Ciphertext) -> Result<UniquePtr<Ciphertext>>;
        fn sub(ctx: &Context, a: &Ciphertext, b: &Ciphertext) -> Result<UniquePtr<Ciphertext>>;
        fn neg(ctx: &Context, a: &Ciphertext) -> Result<UniquePtr<Ciphertext>>;
        fn mul(ctx: &Context, a: &Ciphertext, b: &Ciphertext) -> Result<UniquePtr<Ciphertext>>;
        fn add_plain(ctx: &Context, a: &Ciphertext, p: &[f64]) -> Result<UniquePtr<Ciphertext>>;
        fn mul_plain(ctx: &Context, a: &Ciphertext, p: &[f64]) -> Result<UniquePtr<Ciphertext>>;
        fn add_const(ctx: &Context, a: &Ciphertext, c: f64) -> Result<UniquePtr<Ciphertext>>;
        fn mul_const(ctx: &Context, a: &Ciphertext, c: f64) -> Result<UniquePtr<Ciphertext>>;
        fn rotate(ctx: &Context, a: &Ciphertext, k: i32) -> Result<UniquePtr<Ciphertext>>;
        fn level(ct: &Ciphertext) -> u32;
        fn clone_ciphertext(ct: &Ciphertext) -> Result<UniquePtr<Ciphertext>>;
        fn bgv_add_scalar(ctx: &Context, a: &Ciphertext, c: i64) -> Result<UniquePtr<Ciphertext>>;
        fn bgv_mul_scalar(ctx: &Context, a: &Ciphertext, c: i64) -> Result<UniquePtr<Ciphertext>>;
    }
}

// SAFETY (BgvCiphertext holds ffi::Ciphertext): see below.
// SAFETY: every shim function, including the wrappers' destructors, holds the
// process-wide OpenFHE mutex (ADR-001), so these objects may be used from and
// dropped on any thread.
#[allow(unsafe_code)]
unsafe impl Send for ffi::Context {}
#[allow(unsafe_code)]
unsafe impl Send for ffi::Ciphertext {}

fn backend_err(e: cxx::Exception) -> Error {
    let msg = e.what();
    let code = if msg.contains("another parameter set") {
        Code::WrongParameters
    } else if msg.contains("evaluation keys are not loaded") {
        Code::WrongKey
    } else {
        Code::Backend
    };
    Error::new(code, format!("OpenFHE: {msg}"))
}

/// Smallest ring dimension OpenFHE considers 128-bit secure for these
/// moduli (`ring_dim = 0`, full packing), and the resulting log2(Q·P).
/// Slot count is ignored: it can only force a larger ring.
pub fn openfhe_choice(p: &CkksParams) -> Result<(u32, u32)> {
    let ctx = ffi::new_context(
        0,
        p.mult_depth,
        p.scale_bits,
        p.first_mod_bits,
        p.num_large_digits,
        0,
    )
    .map_err(backend_err)?;
    Ok((
        ffi::ring_dimension(&ctx).map_err(backend_err)?,
        ffi::log_qp(&ctx).map_err(backend_err)?,
    ))
}

/// Create (without keys) the exact context Encompute would use, letting
/// OpenFHE apply its own security and batch-size checks. Returns log2(Q·P).
pub fn openfhe_validate(p: &CkksParams) -> Result<u32> {
    let ctx = new_checked_context(p)?;
    ffi::log_qp(&ctx).map_err(backend_err)
}

fn new_checked_context(p: &CkksParams) -> Result<cxx::UniquePtr<ffi::Context>> {
    let ctx = ffi::new_context(
        p.ring_dim,
        p.mult_depth,
        p.scale_bits,
        p.first_mod_bits,
        p.num_large_digits,
        p.slots,
    )
    .map_err(backend_err)?;
    let n = ffi::ring_dimension(&ctx).map_err(backend_err)?;
    let log_qp = ffi::log_qp(&ctx).map_err(backend_err)?;
    if n != p.ring_dim || log_qp > p.max_log_qp {
        return Err(Error::new(
            Code::Backend,
            format!(
                "OpenFHE parameters disagree with Encompute's: ring {n} (expected {}), \
                 log2 QP {log_qp} (limit {})",
                p.ring_dim, p.max_log_qp
            ),
        ));
    }
    Ok(ctx)
}

/// Evaluator over an OpenFHE CKKS context. Holds evaluation keys only.
pub struct OpenFheEvaluator {
    ctx: cxx::UniquePtr<ffi::Context>,
    slots: usize,
    key_tags: Vec<String>,
}

pub struct OpenFheCiphertext(cxx::UniquePtr<ffi::Ciphertext>);

impl OpenFheCiphertext {
    /// Number of rescalings applied so far.
    pub fn level(&self) -> u32 {
        ffi::level(&self.0)
    }
}

impl OpenFheEvaluator {
    /// Context for `params`, checked against the security table (plan D3).
    pub fn new(params: &CkksParams) -> Result<Self> {
        Ok(Self {
            ctx: new_checked_context(params)?,
            slots: params.slots as usize,
            key_tags: vec![],
        })
    }

    /// Load evaluation keys exported by `CkksClient::evaluation_keys`.
    pub fn load_keys(&mut self, bytes: &[u8]) -> Result<()> {
        let tag = ffi::load_evaluation_keys(self.ctx.pin_mut(), bytes).map_err(backend_err)?;
        self.key_tags.push(tag);
        Ok(())
    }

    fn check_len(&self, v: &[f64]) -> Result<()> {
        if v.len() != self.slots {
            return Err(Error::new(
                Code::Backend,
                format!("expected {} slots, got {}", self.slots, v.len()),
            ));
        }
        Ok(())
    }
}

type Ct = OpenFheCiphertext;

fn wrap(r: std::result::Result<cxx::UniquePtr<ffi::Ciphertext>, cxx::Exception>) -> Result<Ct> {
    r.map(OpenFheCiphertext).map_err(backend_err)
}

impl CkksEvaluator for OpenFheEvaluator {
    type Ciphertext = OpenFheCiphertext;

    fn name(&self) -> &'static str {
        "openfhe"
    }

    fn slots(&self) -> usize {
        self.slots
    }

    fn load_ciphertext(&self, bytes: &[u8]) -> Result<Ct> {
        if self.key_tags.is_empty() {
            return Err(Error::new(Code::WrongKey, "no evaluation keys are loaded"));
        }
        wrap(ffi::load_ciphertext(&self.ctx, bytes))
    }

    fn store_ciphertext(&self, ct: &Ct) -> Result<Vec<u8>> {
        ffi::store_ciphertext(&ct.0).map_err(backend_err)
    }

    fn add(&self, a: &Ct, b: &Ct) -> Result<Ct> {
        wrap(ffi::add(&self.ctx, &a.0, &b.0))
    }

    fn sub(&self, a: &Ct, b: &Ct) -> Result<Ct> {
        wrap(ffi::sub(&self.ctx, &a.0, &b.0))
    }

    fn neg(&self, a: &Ct) -> Result<Ct> {
        wrap(ffi::neg(&self.ctx, &a.0))
    }

    fn mul(&self, a: &Ct, b: &Ct) -> Result<Ct> {
        wrap(ffi::mul(&self.ctx, &a.0, &b.0))
    }

    fn add_plain(&self, a: &Ct, p: &[f64]) -> Result<Ct> {
        self.check_len(p)?;
        wrap(ffi::add_plain(&self.ctx, &a.0, p))
    }

    fn mul_plain(&self, a: &Ct, p: &[f64]) -> Result<Ct> {
        self.check_len(p)?;
        wrap(ffi::mul_plain(&self.ctx, &a.0, p))
    }

    fn add_const(&self, a: &Ct, c: f64) -> Result<Ct> {
        wrap(ffi::add_const(&self.ctx, &a.0, c))
    }

    fn mul_const(&self, a: &Ct, c: f64) -> Result<Ct> {
        wrap(ffi::mul_const(&self.ctx, &a.0, c))
    }

    fn rotate(&self, a: &Ct, k: u32) -> Result<Ct> {
        wrap(ffi::rotate(&self.ctx, &a.0, k as i32))
    }
}

/// Exact-program evaluator over OpenFHE BGV-RNS (0.4 V3, ADR-009): unsigned
/// 8/16-bit integers and Booleans in slot 0, plaintext modulus 65537. Range
/// analysis proves no value leaves its type, so arithmetic modulo 65537 is
/// exact. Evaluation is deterministic: the same inputs and keys give the
/// same output bytes, which is what re-execution verification checks.
/// Holds evaluation keys only.
pub struct BgvEvaluator {
    ctx: cxx::UniquePtr<ffi::Context>,
    loaded: bool,
}

/// A BGV ciphertext with the exact type it holds.
pub struct BgvCiphertext {
    ct: cxx::UniquePtr<ffi::Ciphertext>,
    elem: Elem,
}

impl Clone for BgvCiphertext {
    fn clone(&self) -> Self {
        // A deep copy: OpenFHE ciphertexts are shared handles.
        Self {
            ct: ffi::clone_ciphertext(&self.ct).expect("OpenFHE clone"),
            elem: self.elem,
        }
    }
}

fn unsupported(what: &str) -> Error {
    Error::new(
        Code::Unsupported,
        format!("the BGV backend does not support {what} (ADR-009 subset)"),
    )
}

fn subset(e: Elem) -> Result<()> {
    match e {
        Elem::U8 | Elem::U16 | Elem::Bool => Ok(()),
        other => Err(unsupported(&format!("type {other}"))),
    }
}

impl BgvEvaluator {
    /// Context for multiplicative depth `mult_depth` (from the plan).
    pub fn new(mult_depth: u32) -> Result<Self> {
        Ok(Self {
            ctx: ffi::new_bgv_context(mult_depth).map_err(backend_err)?,
            loaded: false,
        })
    }

    /// Load evaluation keys exported by the BGV client.
    pub fn load_keys(&mut self, bytes: &[u8]) -> Result<()> {
        ffi::load_evaluation_keys(self.ctx.pin_mut(), bytes).map_err(backend_err)?;
        self.loaded = true;
        Ok(())
    }

    fn wrap(
        &self,
        r: std::result::Result<cxx::UniquePtr<ffi::Ciphertext>, cxx::Exception>,
        elem: Elem,
    ) -> Result<BgvCiphertext> {
        Ok(BgvCiphertext {
            ct: r.map_err(backend_err)?,
            elem,
        })
    }

    fn same(a: &BgvCiphertext, b: &BgvCiphertext) -> Result<Elem> {
        if a.elem != b.elem {
            return Err(Error::new(Code::Backend, "operands of different types"));
        }
        Ok(a.elem)
    }

    fn scalar(c: i128) -> Result<i64> {
        i64::try_from(c)
            .ok()
            .filter(|c| (0..65537).contains(c))
            .ok_or_else(|| unsupported("constants outside [0, 65537)"))
    }

    fn mul_ct(&self, a: &BgvCiphertext, b: &BgvCiphertext, elem: Elem) -> Result<BgvCiphertext> {
        self.wrap(ffi::mul(&self.ctx, &a.ct, &b.ct), elem)
    }
}

impl ExactEvaluator for BgvEvaluator {
    type Ciphertext = BgvCiphertext;

    fn name(&self) -> &'static str {
        "openfhe-bgv"
    }

    fn load(&self, elem: Elem, bytes: &[u8]) -> Result<BgvCiphertext> {
        subset(elem)?;
        if !self.loaded {
            return Err(Error::new(Code::WrongKey, "no evaluation keys are loaded"));
        }
        self.wrap(ffi::load_ciphertext(&self.ctx, bytes), elem)
    }

    fn store(&self, ct: &BgvCiphertext) -> Result<Vec<u8>> {
        ffi::store_ciphertext(&ct.ct).map_err(backend_err)
    }

    fn elem_of(&self, ct: &BgvCiphertext) -> Elem {
        ct.elem
    }

    fn trivial(&self, _: Elem, _: i128) -> Result<BgvCiphertext> {
        Err(unsupported("public constants as ciphertexts"))
    }

    fn add(&self, a: &BgvCiphertext, b: &BgvCiphertext) -> Result<BgvCiphertext> {
        let e = Self::same(a, b)?;
        self.wrap(ffi::add(&self.ctx, &a.ct, &b.ct), e)
    }

    fn sub(&self, a: &BgvCiphertext, b: &BgvCiphertext) -> Result<BgvCiphertext> {
        let e = Self::same(a, b)?;
        self.wrap(ffi::sub(&self.ctx, &a.ct, &b.ct), e)
    }

    fn mul(&self, a: &BgvCiphertext, b: &BgvCiphertext) -> Result<BgvCiphertext> {
        let e = Self::same(a, b)?;
        self.mul_ct(a, b, e)
    }

    fn neg(&self, _: &BgvCiphertext) -> Result<BgvCiphertext> {
        Err(unsupported("negation"))
    }

    fn add_scalar(&self, a: &BgvCiphertext, c: i128) -> Result<BgvCiphertext> {
        self.wrap(
            ffi::bgv_add_scalar(&self.ctx, &a.ct, Self::scalar(c)?),
            a.elem,
        )
    }

    fn sub_scalar(&self, a: &BgvCiphertext, c: i128) -> Result<BgvCiphertext> {
        let c = Self::scalar(c)?;
        self.wrap(
            ffi::bgv_add_scalar(&self.ctx, &a.ct, (65537 - c) % 65537),
            a.elem,
        )
    }

    fn mul_scalar(&self, a: &BgvCiphertext, c: i128) -> Result<BgvCiphertext> {
        self.wrap(
            ffi::bgv_mul_scalar(&self.ctx, &a.ct, Self::scalar(c)?),
            a.elem,
        )
    }

    fn scalar_sub(&self, c: i128, a: &BgvCiphertext) -> Result<BgvCiphertext> {
        let neg = self.wrap(ffi::neg(&self.ctx, &a.ct), a.elem)?;
        self.wrap(
            ffi::bgv_add_scalar(&self.ctx, &neg.ct, Self::scalar(c)?),
            a.elem,
        )
    }

    fn div_scalar(&self, _: &BgvCiphertext, _: i128) -> Result<BgvCiphertext> {
        Err(unsupported("division"))
    }

    fn rem_scalar(&self, _: &BgvCiphertext, _: i128) -> Result<BgvCiphertext> {
        Err(unsupported("remainder"))
    }

    fn cmp(&self, _: CmpOp, _: &BgvCiphertext, _: &BgvCiphertext) -> Result<BgvCiphertext> {
        Err(unsupported("comparisons"))
    }

    fn cmp_scalar(&self, _: CmpOp, _: &BgvCiphertext, _: i128) -> Result<BgvCiphertext> {
        Err(unsupported("comparisons"))
    }

    /// Booleans only: and = ab, or = a + b − ab, xor = a + b − ab − ab
    /// (one multiplicative level each).
    fn logic(&self, op: LogicOp, a: &BgvCiphertext, b: &BgvCiphertext) -> Result<BgvCiphertext> {
        if Self::same(a, b)? != Elem::Bool {
            return Err(unsupported("bitwise logic on integers"));
        }
        let ab = self.mul_ct(a, b, Elem::Bool)?;
        if op == LogicOp::And {
            return Ok(ab);
        }
        // No product by a constant: that would need another level.
        let or = self.sub(&self.add(a, b)?, &ab)?;
        if op == LogicOp::Or {
            return Ok(or);
        }
        self.sub(&or, &ab)
    }

    /// Booleans only: not = 1 − a.
    fn not(&self, a: &BgvCiphertext) -> Result<BgvCiphertext> {
        if a.elem != Elem::Bool {
            return Err(unsupported("bitwise not on integers"));
        }
        self.scalar_sub(1, a)
    }

    fn shift(&self, _: &BgvCiphertext, _: bool, _: u32) -> Result<BgvCiphertext> {
        Err(unsupported("shifts"))
    }

    fn min(&self, _: &BgvCiphertext, _: &BgvCiphertext) -> Result<BgvCiphertext> {
        Err(unsupported("min"))
    }

    fn max(&self, _: &BgvCiphertext, _: &BgvCiphertext) -> Result<BgvCiphertext> {
        Err(unsupported("max"))
    }

    fn select(
        &self,
        _: &BgvCiphertext,
        _: &BgvCiphertext,
        _: &BgvCiphertext,
    ) -> Result<BgvCiphertext> {
        Err(unsupported("select"))
    }

    fn lookup(&self, _: &BgvCiphertext, _: &[i128], _: Elem) -> Result<BgvCiphertext> {
        Err(unsupported("lookup"))
    }

    fn cast(&self, _: &BgvCiphertext, _: Elem) -> Result<BgvCiphertext> {
        Err(unsupported("casts"))
    }
}
