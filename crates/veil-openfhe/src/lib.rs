//! OpenFHE CKKS backend for Veil (ADR-001: Veil-owned `cxx` shim over
//! OpenFHE v1.5.1). Nothing outside this crate sees OpenFHE types.
//!
//! [`OpenFheBackend`] is the evaluator: it holds the crypto context, public
//! key and evaluation keys. [`OpenFheSecretKey`] is the client's decryption
//! key, returned separately by [`OpenFheBackend::new`].

use veil_backend::CkksBackend;
use veil_ckks::CkksParams;
use veil_ir::{Code, Error, Result};

/// OpenFHE release this crate is built and tested against.
pub const OPENFHE_VERSION: &str = "1.5.1";

#[allow(unsafe_code)]
#[cxx::bridge(namespace = "veil_openfhe")]
mod ffi {
    unsafe extern "C++" {
        include!("shim.h");

        type Context;
        type SecretKey;
        type Ciphertext;

        fn new_context(
            ring_dim: u32,
            mult_depth: u32,
            scale_bits: u32,
            first_mod_bits: u32,
            num_large_digits: u32,
            slots: u32,
        ) -> Result<UniquePtr<Context>>;
        fn keygen(ctx: Pin<&mut Context>, rotations: &[i32]) -> Result<UniquePtr<SecretKey>>;
        fn ring_dimension(ctx: &Context) -> Result<u32>;
        fn log_qp(ctx: &Context) -> Result<u32>;

        fn encrypt(ctx: &Context, values: &[f64]) -> Result<UniquePtr<Ciphertext>>;
        fn decrypt(ctx: &Context, sk: &SecretKey, ct: &Ciphertext) -> Result<Vec<f64>>;
        fn add(ctx: &Context, a: &Ciphertext, b: &Ciphertext) -> Result<UniquePtr<Ciphertext>>;
        fn sub(ctx: &Context, a: &Ciphertext, b: &Ciphertext) -> Result<UniquePtr<Ciphertext>>;
        fn neg(ctx: &Context, a: &Ciphertext) -> Result<UniquePtr<Ciphertext>>;
        fn mul(ctx: &Context, a: &Ciphertext, b: &Ciphertext) -> Result<UniquePtr<Ciphertext>>;
        fn add_plain(ctx: &Context, a: &Ciphertext, p: &[f64]) -> Result<UniquePtr<Ciphertext>>;
        fn mul_plain(ctx: &Context, a: &Ciphertext, p: &[f64]) -> Result<UniquePtr<Ciphertext>>;
        fn add_const(ctx: &Context, a: &Ciphertext, c: f64) -> Result<UniquePtr<Ciphertext>>;
        fn mul_const(ctx: &Context, a: &Ciphertext, c: f64) -> Result<UniquePtr<Ciphertext>>;
        fn rotate(ctx: &Context, a: &Ciphertext, k: i32) -> Result<UniquePtr<Ciphertext>>;
        fn serialized_size(ct: &Ciphertext) -> Result<usize>;
        fn level(ct: &Ciphertext) -> u32;
    }
}

fn backend_err(e: cxx::Exception) -> Error {
    Error::new(Code::Backend, format!("OpenFHE: {}", e.what()))
}

/// Ring dimension and log2(Q·P) OpenFHE itself picks for the parameters, with
/// `ring_dim = 0` ("choose for 128-bit security"). Used to check Veil's own
/// selection against OpenFHE's.
pub fn openfhe_choice(p: &CkksParams) -> Result<(u32, u32)> {
    let ctx = ffi::new_context(
        0,
        p.mult_depth,
        p.scale_bits,
        p.first_mod_bits,
        p.num_large_digits,
        p.slots,
    )
    .map_err(backend_err)?;
    Ok((
        ffi::ring_dimension(&ctx).map_err(backend_err)?,
        ffi::log_qp(&ctx).map_err(backend_err)?,
    ))
}

/// Evaluator over an OpenFHE CKKS context.
pub struct OpenFheBackend {
    ctx: cxx::UniquePtr<ffi::Context>,
    slots: usize,
    ring_dim: u32,
    log_qp: u32,
}

/// The client's decryption key.
pub struct OpenFheSecretKey(cxx::UniquePtr<ffi::SecretKey>);

pub struct OpenFheCiphertext(cxx::UniquePtr<ffi::Ciphertext>);

impl OpenFheCiphertext {
    /// Number of rescalings applied so far.
    pub fn level(&self) -> u32 {
        ffi::level(&self.0)
    }
}

impl OpenFheBackend {
    /// Create the context for `params` and generate keys, including one
    /// rotation key per entry of `rotations`. Fails if OpenFHE's modulus
    /// exceeds the security table's limit for the ring dimension (plan D3).
    pub fn new(params: &CkksParams, rotations: &[u32]) -> Result<(Self, OpenFheSecretKey)> {
        let mut ctx = ffi::new_context(
            params.ring_dim,
            params.mult_depth,
            params.scale_bits,
            params.first_mod_bits,
            params.num_large_digits,
            params.slots,
        )
        .map_err(backend_err)?;
        let ring_dim = ffi::ring_dimension(&ctx).map_err(backend_err)?;
        let log_qp = ffi::log_qp(&ctx).map_err(backend_err)?;
        if ring_dim != params.ring_dim || log_qp > params.max_log_qp {
            return Err(Error::new(
                Code::Backend,
                format!(
                    "OpenFHE parameters disagree with Veil's: ring {ring_dim} (expected {}), \
                     log2 QP {log_qp} (limit {})",
                    params.ring_dim, params.max_log_qp
                ),
            ));
        }
        let rot: Vec<i32> = rotations.iter().map(|&k| k as i32).collect();
        let sk = ffi::keygen(ctx.pin_mut(), &rot).map_err(backend_err)?;
        Ok((
            Self {
                ctx,
                slots: params.slots as usize,
                ring_dim,
                log_qp,
            },
            OpenFheSecretKey(sk),
        ))
    }

    pub fn ring_dim(&self) -> u32 {
        self.ring_dim
    }

    /// log2(Q·P) of the generated context, as OpenFHE reports it.
    pub fn log_qp(&self) -> u32 {
        self.log_qp
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

impl CkksBackend for OpenFheBackend {
    type Ciphertext = OpenFheCiphertext;
    type SecretKey = OpenFheSecretKey;

    fn name(&self) -> &'static str {
        "openfhe"
    }

    fn slots(&self) -> usize {
        self.slots
    }

    fn encrypt(&self, values: &[f64]) -> Result<Ct> {
        self.check_len(values)?;
        wrap(ffi::encrypt(&self.ctx, values))
    }

    fn decrypt(&self, sk: &OpenFheSecretKey, ct: &Ct) -> Result<Vec<f64>> {
        ffi::decrypt(&self.ctx, &sk.0, &ct.0).map_err(backend_err)
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

    fn ciphertext_bytes(&self, ct: &Ct) -> Result<usize> {
        ffi::serialized_size(&ct.0).map_err(backend_err)
    }
}
