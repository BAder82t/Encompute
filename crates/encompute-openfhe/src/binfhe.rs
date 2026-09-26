//! OpenFHE BinFHE, evaluator side: Boolean gates on LWE ciphertexts with
//! the client's bootstrapping keys. Encompute's integer semantics are built
//! on these gates in `encompute-openfhe-exact`; nothing here knows about
//! integers. No key generation, encryption or decryption.

use encompute_ir::{Code, Error, Result};

#[allow(unsafe_code)]
#[cxx::bridge(namespace = "encompute_openfhe")]
mod ffi {
    unsafe extern "C++" {
        include!("binfhe.h");

        type BinContext;
        type BinCiphertext;

        fn bin_new_context(paramset: &str) -> Result<UniquePtr<BinContext>>;
        fn bin_lwe_n(ctx: &BinContext) -> Result<u64>;
        fn bin_lwe_q(ctx: &BinContext) -> Result<u64>;
        fn bin_load_keys(ctx: Pin<&mut BinContext>, refresh: &[u8], switching: &[u8])
            -> Result<()>;
        fn bin_load(ctx: &BinContext, bytes: &[u8]) -> Result<UniquePtr<BinCiphertext>>;
        fn bin_store(ct: &BinCiphertext) -> Result<Vec<u8>>;
        fn bin_gate(
            ctx: &BinContext,
            gate: u8,
            a: &BinCiphertext,
            b: &BinCiphertext,
        ) -> Result<UniquePtr<BinCiphertext>>;
        fn bin_not(ctx: &BinContext, a: &BinCiphertext) -> Result<UniquePtr<BinCiphertext>>;
        fn bin_constant(ctx: &BinContext, value: bool) -> Result<UniquePtr<BinCiphertext>>;
        fn bin_clone(ct: &BinCiphertext) -> Result<UniquePtr<BinCiphertext>>;
    }
}

fn err(e: cxx::Exception) -> Error {
    let m = e.what();
    let code = if m.contains("another parameter set") {
        Code::WrongParameters
    } else if m.contains("malformed") {
        Code::Envelope
    } else {
        Code::Backend
    };
    Error::new(code, format!("OpenFHE BinFHE: {m}"))
}

/// A two-input bootstrapped gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Or = 0,
    And = 1,
    Nor = 2,
    Nand = 3,
    Xor = 4,
    Xnor = 5,
}

/// A BinFHE context with (once loaded) the client's bootstrapping keys.
pub struct BinContext {
    inner: cxx::UniquePtr<ffi::BinContext>,
}

/// One encrypted bit.
pub struct BinCiphertext {
    inner: cxx::UniquePtr<ffi::BinCiphertext>,
}

// SAFETY: every shim function, including the wrappers' destructors, holds
// the global OpenFHE mutex (cpp/common.h), so the objects may move between
// threads and be shared by reference.
#[allow(unsafe_code)]
unsafe impl Send for BinContext {}
#[allow(unsafe_code)]
unsafe impl Sync for BinContext {}
#[allow(unsafe_code)]
unsafe impl Send for BinCiphertext {}
#[allow(unsafe_code)]
unsafe impl Sync for BinCiphertext {}

impl BinContext {
    /// A context for a vetted parameter set (`STD128` or `STD128Q`, GINX).
    pub fn new(paramset: &str) -> Result<Self> {
        Ok(Self {
            inner: ffi::bin_new_context(paramset).map_err(err)?,
        })
    }

    /// `(n, q)` of the LWE ciphertexts this context accepts.
    pub fn lwe(&self) -> Result<(u64, u64)> {
        Ok((
            ffi::bin_lwe_n(&self.inner).map_err(err)?,
            ffi::bin_lwe_q(&self.inner).map_err(err)?,
        ))
    }

    pub fn load_keys(&mut self, refresh: &[u8], switching: &[u8]) -> Result<()> {
        ffi::bin_load_keys(self.inner.pin_mut(), refresh, switching).map_err(err)
    }

    pub fn load(&self, bytes: &[u8]) -> Result<BinCiphertext> {
        Ok(BinCiphertext {
            inner: ffi::bin_load(&self.inner, bytes).map_err(err)?,
        })
    }

    pub fn gate(&self, g: Gate, a: &BinCiphertext, b: &BinCiphertext) -> Result<BinCiphertext> {
        Ok(BinCiphertext {
            inner: ffi::bin_gate(&self.inner, g as u8, &a.inner, &b.inner).map_err(err)?,
        })
    }

    pub fn not(&self, a: &BinCiphertext) -> Result<BinCiphertext> {
        Ok(BinCiphertext {
            inner: ffi::bin_not(&self.inner, &a.inner).map_err(err)?,
        })
    }

    pub fn constant(&self, value: bool) -> Result<BinCiphertext> {
        Ok(BinCiphertext {
            inner: ffi::bin_constant(&self.inner, value).map_err(err)?,
        })
    }
}

impl BinCiphertext {
    pub fn store(&self) -> Result<Vec<u8>> {
        ffi::bin_store(&self.inner).map_err(err)
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            inner: ffi::bin_clone(&self.inner).map_err(err)?,
        })
    }
}

impl Clone for BinCiphertext {
    fn clone(&self) -> Self {
        self.try_clone().expect("OpenFHE BinFHE clone")
    }
}
