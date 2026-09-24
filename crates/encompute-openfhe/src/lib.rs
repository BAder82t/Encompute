//! OpenFHE CKKS evaluator for Encompute (ADR-001: Encompute-owned `cxx` shim
//! over OpenFHE v1.5.1). Nothing outside this crate sees OpenFHE types.
//!
//! This crate is the evaluator side only: it builds a crypto context from
//! parameters, loads evaluation keys exported by a client, and computes on
//! serialized ciphertexts. It has no key generation, encryption or
//! decryption; those live in `encompute-openfhe-client`, which the evaluator
//! binary does not link (0.2 plan, D2).

use encompute_backend::CkksEvaluator;
use encompute_ckks::CkksParams;
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
    }
}

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
