//! OpenFHE CKKS client for Encompute: key generation, encryption, decryption
//! and export of evaluation keys. The only crate that touches the secret key.
//! The evaluator binary does not depend on it (0.2 plan, D2).

use encompute_backend::CkksClient;
use encompute_ckks::CkksParams;
use encompute_ir::{Code, Error, Result};

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
        fn export_evaluation_keys(c: &Client) -> Result<Vec<u8>>;
        fn export_secret_key(c: &Client) -> Result<Vec<u8>>;
        fn encrypt(c: &Client, values: &[f64]) -> Result<Vec<u8>>;
        fn decrypt(c: &Client, ciphertext: &[u8]) -> Result<Vec<f64>>;
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
