//! CKKS backend traits and a mock backend.
//!
//! The two roles are separate traits (0.2 plan, D2):
//!
//! - [`CkksClient`] holds the secret key: it encrypts, decrypts and exports
//!   evaluation keys.
//! - [`CkksEvaluator`] holds only evaluation keys: it computes on ciphertexts.
//!   It has no decryption method, and the evaluator binary does not link any
//!   client implementation.
//!
//! The roles exchange ciphertexts and evaluation keys as bytes, in-process
//! as well as over the network, so local execution takes the same path as
//! remote execution.
//!
//! The traits are CKKS-shaped on purpose; they become scheme-generic when a
//! second scheme exists.

mod mock;
pub mod rng;

use encompute_ir::Result;
pub use mock::{MockClient, MockConfig, MockEvaluator};

/// Client side: key owner.
pub trait CkksClient {
    /// Backend name, e.g. `"openfhe"`.
    fn name(&self) -> &'static str;
    fn slots(&self) -> usize;
    /// Public-key encryption of a full slot vector; returns a serialized ciphertext.
    fn encrypt(&self, values: &[f64]) -> Result<Vec<u8>>;
    /// Decrypt a serialized ciphertext into all slots.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<f64>>;
    /// Serialized evaluation keys (relinearization and rotations) for the evaluator.
    fn evaluation_keys(&self) -> Result<Vec<u8>>;
}

/// Evaluator side: computes on ciphertexts; cannot decrypt.
pub trait CkksEvaluator {
    type Ciphertext;

    fn name(&self) -> &'static str;
    fn slots(&self) -> usize;

    fn load_ciphertext(&self, bytes: &[u8]) -> Result<Self::Ciphertext>;
    fn store_ciphertext(&self, ct: &Self::Ciphertext) -> Result<Vec<u8>>;

    fn add(&self, a: &Self::Ciphertext, b: &Self::Ciphertext) -> Result<Self::Ciphertext>;
    fn sub(&self, a: &Self::Ciphertext, b: &Self::Ciphertext) -> Result<Self::Ciphertext>;
    fn neg(&self, a: &Self::Ciphertext) -> Result<Self::Ciphertext>;
    /// Ciphertext product, relinearized.
    fn mul(&self, a: &Self::Ciphertext, b: &Self::Ciphertext) -> Result<Self::Ciphertext>;
    fn add_plain(&self, a: &Self::Ciphertext, p: &[f64]) -> Result<Self::Ciphertext>;
    fn mul_plain(&self, a: &Self::Ciphertext, p: &[f64]) -> Result<Self::Ciphertext>;
    fn add_const(&self, a: &Self::Ciphertext, c: f64) -> Result<Self::Ciphertext>;
    fn mul_const(&self, a: &Self::Ciphertext, c: f64) -> Result<Self::Ciphertext>;
    /// Cyclic left rotation over the slots: `out[i] = in[(i + k) mod slots]`.
    /// Needs a rotation key for `k`.
    fn rotate(&self, a: &Self::Ciphertext, k: u32) -> Result<Self::Ciphertext>;
}
