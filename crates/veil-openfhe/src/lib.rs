//! OpenFHE CKKS backend for Veil.
//!
//! M0 scope: a context, encrypt, add and decrypt, to prove the native build
//! and bridge. The context holds the secret key; key roles are split into
//! `Client` and `Evaluator` when the backend trait lands (M4–M5).

#[allow(unsafe_code)]
#[cxx::bridge(namespace = "veil_openfhe")]
mod ffi {
    unsafe extern "C++" {
        include!("shim.h");

        type CkksContext;
        type Ciphertext;

        fn new_ckks_context(
            mult_depth: u32,
            scale_mod_size: u32,
            batch_size: u32,
        ) -> Result<UniquePtr<CkksContext>>;
        fn ring_dimension(ctx: &CkksContext) -> u32;
        fn encrypt(ctx: &CkksContext, values: &[f64]) -> Result<UniquePtr<Ciphertext>>;
        fn add(ctx: &CkksContext, a: &Ciphertext, b: &Ciphertext) -> Result<UniquePtr<Ciphertext>>;
        fn decrypt(ctx: &CkksContext, ct: &Ciphertext, len: usize) -> Result<Vec<f64>>;
    }
}

/// Error raised by OpenFHE, carrying its exception message.
#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenFHE: {}", self.0)
    }
}

impl std::error::Error for Error {}

impl From<cxx::Exception> for Error {
    fn from(e: cxx::Exception) -> Self {
        Error(e.what().to_owned())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// A CKKS crypto context at 128-bit classical security, with a fresh key pair.
pub struct CkksContext {
    inner: cxx::UniquePtr<ffi::CkksContext>,
    batch_size: usize,
}

/// A CKKS ciphertext bound to the context that created it.
pub struct Ciphertext {
    inner: cxx::UniquePtr<ffi::Ciphertext>,
}

impl CkksContext {
    /// `scale_mod_size` is the bit size of each rescaling prime; the ring
    /// dimension is chosen by OpenFHE for 128-bit classical security.
    pub fn new(mult_depth: u32, scale_mod_size: u32, batch_size: u32) -> Result<Self> {
        let inner = ffi::new_ckks_context(mult_depth, scale_mod_size, batch_size)?;
        Ok(Self {
            inner,
            batch_size: batch_size as usize,
        })
    }

    pub fn ring_dimension(&self) -> u32 {
        ffi::ring_dimension(&self.inner)
    }

    pub fn encrypt(&self, values: &[f64]) -> Result<Ciphertext> {
        if values.len() > self.batch_size {
            return Err(Error(format!(
                "{} values exceed batch size {}",
                values.len(),
                self.batch_size
            )));
        }
        Ok(Ciphertext {
            inner: ffi::encrypt(&self.inner, values)?,
        })
    }

    pub fn add(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        Ok(Ciphertext {
            inner: ffi::add(&self.inner, &a.inner, &b.inner)?,
        })
    }

    pub fn decrypt(&self, ct: &Ciphertext, len: usize) -> Result<Vec<f64>> {
        Ok(ffi::decrypt(&self.inner, &ct.inner, len)?)
    }
}
