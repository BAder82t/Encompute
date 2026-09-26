//! OpenFHE CKKS client for Encompute: key generation, encryption, decryption
//! and export of evaluation keys. The only crate that touches the secret key.
//! The evaluator binary does not depend on it.

pub mod exact;

pub use exact::OpenFheExactClient;

use encompute_backend::{CkksClient, ExactClient};
use encompute_ckks::CkksParams;
use encompute_ir::{Code, Elem, Error, Result};

#[allow(unsafe_code)]
#[cxx::bridge(namespace = "encompute_openfhe_client")]
mod ffi {
    unsafe extern "C++" {
        include!("client.h");

        type Client;

        #[allow(clippy::too_many_arguments)]
        fn generate(
            ring_dim: u32,
            mult_depth: u32,
            scale_bits: u32,
            first_mod_bits: u32,
            num_large_digits: u32,
            slots: u32,
            rotations: &[i32],
        ) -> Result<UniquePtr<Client>>;
        #[allow(clippy::too_many_arguments)]
        fn restore(
            ring_dim: u32,
            mult_depth: u32,
            scale_bits: u32,
            first_mod_bits: u32,
            num_large_digits: u32,
            slots: u32,
            secret: &[u8],
        ) -> Result<UniquePtr<Client>>;
        fn bgv_generate(mult_depth: u32) -> Result<UniquePtr<Client>>;
        fn bgv_restore(mult_depth: u32, secret: &[u8]) -> Result<UniquePtr<Client>>;
        fn bgv_encrypt(c: &Client, value: i64) -> Result<Vec<u8>>;
        fn bgv_decrypt(c: &Client, ciphertext: &[u8]) -> Result<i64>;
        fn export_evaluation_keys(c: &Client) -> Result<Vec<u8>>;
        fn export_secret_key(c: &Client) -> Result<Vec<u8>>;
        fn encrypt(c: &Client, values: &[f64]) -> Result<Vec<u8>>;
        fn decrypt(c: &Client, ciphertext: &[u8]) -> Result<Vec<f64>>;

        type BinClient;
        fn bin_generate(paramset: &str) -> Result<UniquePtr<BinClient>>;
        fn bin_restore(paramset: &str, secret: &[u8]) -> Result<UniquePtr<BinClient>>;
        fn bin_export_secret(c: &BinClient) -> Result<Vec<u8>>;
        fn bin_export_refresh_key(c: &BinClient) -> Result<Vec<u8>>;
        fn bin_export_switching_key(c: &BinClient) -> Result<Vec<u8>>;
        fn bin_encrypt(c: &BinClient, bit: bool) -> Result<Vec<u8>>;
        fn bin_decrypt(c: &BinClient, ciphertext: &[u8]) -> Result<bool>;
    }
}

/// OpenFHE BinFHE client: the LWE secret key, bit encryption and
/// decryption, and the bootstrapping keys for the evaluator. Integer
/// encoding lives in `encompute-openfhe-exact`.
pub struct BinClient {
    inner: cxx::UniquePtr<ffi::BinClient>,
}

// SAFETY: every shim function, including the destructor, holds the global
// OpenFHE mutex.
#[allow(unsafe_code)]
unsafe impl Send for BinClient {}
#[allow(unsafe_code)]
unsafe impl Sync for BinClient {}

impl BinClient {
    pub fn generate(paramset: &str) -> Result<Self> {
        Ok(Self {
            inner: ffi::bin_generate(paramset).map_err(backend_err)?,
        })
    }

    pub fn restore(paramset: &str, secret: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: ffi::bin_restore(paramset, secret).map_err(backend_err)?,
        })
    }

    pub fn secret_key(&self) -> Result<Vec<u8>> {
        ffi::bin_export_secret(&self.inner).map_err(backend_err)
    }

    /// `(refresh key, switching key)`.
    pub fn bootstrapping_keys(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        Ok((
            ffi::bin_export_refresh_key(&self.inner).map_err(backend_err)?,
            ffi::bin_export_switching_key(&self.inner).map_err(backend_err)?,
        ))
    }

    pub fn encrypt_bit(&self, bit: bool) -> Result<Vec<u8>> {
        ffi::bin_encrypt(&self.inner, bit).map_err(backend_err)
    }

    pub fn decrypt_bit(&self, ciphertext: &[u8]) -> Result<bool> {
        ffi::bin_decrypt(&self.inner, ciphertext).map_err(backend_err)
    }
}

fn backend_err(e: cxx::Exception) -> Error {
    let msg = e.what();
    let code = if msg.contains("another parameter set") {
        Code::WrongParameters
    } else if msg.contains("another key") {
        Code::WrongKey
    } else {
        Code::Backend
    };
    Error::new(code, format!("OpenFHE: {msg}"))
}

/// Holds the key pair. Keep it on the client machine.
pub struct OpenFheClient {
    inner: cxx::UniquePtr<ffi::Client>,
    slots: usize,
}

impl OpenFheClient {
    /// Generate a key pair, relinearization key and one rotation key per
    /// entry of `rotations`. Checks the parameters against OpenFHE first.
    pub fn generate(params: &CkksParams, rotations: &[u32]) -> Result<Self> {
        encompute_openfhe::openfhe_validate(params)?;
        let rot: Vec<i32> = rotations.iter().map(|&k| k as i32).collect();
        let inner = ffi::generate(
            params.ring_dim,
            params.mult_depth,
            params.scale_bits,
            params.first_mod_bits,
            params.num_large_digits,
            params.slots,
            &rot,
        )
        .map_err(backend_err)?;
        Ok(Self {
            inner,
            slots: params.slots as usize,
        })
    }

    /// Restore from [`OpenFheClient::secret_key`] bytes.
    pub fn restore(params: &CkksParams, secret: &[u8]) -> Result<Self> {
        encompute_openfhe::openfhe_validate(params)?;
        let inner = ffi::restore(
            params.ring_dim,
            params.mult_depth,
            params.scale_bits,
            params.first_mod_bits,
            params.num_large_digits,
            params.slots,
            secret,
        )
        .map_err(backend_err)?;
        Ok(Self {
            inner,
            slots: params.slots as usize,
        })
    }

    /// Serialized key pair (secret and public key). Store with owner-only permissions.
    pub fn secret_key(&self) -> Result<Vec<u8>> {
        ffi::export_secret_key(&self.inner).map_err(backend_err)
    }
}

impl CkksClient for OpenFheClient {
    fn name(&self) -> &'static str {
        "openfhe"
    }

    fn slots(&self) -> usize {
        self.slots
    }

    fn encrypt(&self, values: &[f64]) -> Result<Vec<u8>> {
        if values.len() != self.slots {
            return Err(Error::new(
                Code::Backend,
                format!("expected {} slots, got {}", self.slots, values.len()),
            ));
        }
        ffi::encrypt(&self.inner, values).map_err(backend_err)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<f64>> {
        ffi::decrypt(&self.inner, ciphertext).map_err(backend_err)
    }

    fn evaluation_keys(&self) -> Result<Vec<u8>> {
        ffi::export_evaluation_keys(&self.inner).map_err(backend_err)
    }
}

/// BGV client for exact programs (ADR-009): keys, encryption and
/// decryption of unsigned 8/16-bit integers and Booleans in slot 0.
pub struct BgvClient {
    inner: cxx::UniquePtr<ffi::Client>,
}

impl BgvClient {
    /// Fresh keys and relinearization key for multiplicative depth
    /// `mult_depth` (from the plan).
    pub fn generate(mult_depth: u32) -> Result<Self> {
        Ok(Self {
            inner: ffi::bgv_generate(mult_depth).map_err(backend_err)?,
        })
    }

    /// Restore from [`BgvClient::secret_key`] bytes.
    pub fn restore(mult_depth: u32, secret: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: ffi::bgv_restore(mult_depth, secret).map_err(backend_err)?,
        })
    }

    /// Serialized key pair. Store with owner-only permissions.
    pub fn secret_key(&self) -> Result<Vec<u8>> {
        ffi::export_secret_key(&self.inner).map_err(backend_err)
    }
}

fn check(elem: Elem, v: i128) -> Result<i64> {
    let (lo, hi) = elem.bounds();
    match elem {
        Elem::U8 | Elem::U16 | Elem::Bool if lo <= v && v <= hi => Ok(v as i64),
        Elem::U8 | Elem::U16 | Elem::Bool => {
            Err(Error::new(Code::BadInput, format!("{v} is not a {elem}")))
        }
        other => Err(Error::new(
            Code::Unsupported,
            format!("the BGV backend does not support type {other}"),
        )),
    }
}

impl ExactClient for BgvClient {
    fn name(&self) -> &'static str {
        "openfhe-bgv"
    }

    fn encrypt(&self, elem: Elem, value: i128) -> Result<Vec<u8>> {
        ffi::bgv_encrypt(&self.inner, check(elem, value)?).map_err(backend_err)
    }

    fn decrypt(&self, elem: Elem, ciphertext: &[u8]) -> Result<i128> {
        let v = ffi::bgv_decrypt(&self.inner, ciphertext).map_err(backend_err)? as i128;
        // Range analysis proves results fit their type; anything else means
        // a wrong or tampered result.
        check(elem, v).map(i128::from).map_err(|_| {
            Error::new(
                Code::Backend,
                format!("decrypted {v}, which is not a {elem}: the result is wrong"),
            )
        })
    }

    fn evaluation_keys(&self) -> Result<Vec<u8>> {
        ffi::export_evaluation_keys(&self.inner).map_err(backend_err)
    }
}
