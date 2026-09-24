//! The CKKS backend trait, and a mock backend that runs plans in plaintext.
//!
//! Key roles (plan D6): a backend value is the *evaluator*. It holds the
//! public and evaluation keys and can compute on ciphertexts. Decryption
//! needs the separate secret key, which only the client holds. v0.1 runs
//! both in one process; 0.2 puts a network between them.
//!
//! In v0.1 the trait is CKKS-shaped on purpose; it becomes scheme-generic
//! when a second scheme exists (plan, "Crates").

mod mock;
pub mod rng;

pub use mock::{MockBackend, MockCiphertext, MockConfig, MockSecretKey};
use veil_ir::Result;

/// Operations a CKKS evaluator provides. Every slot vector has exactly
/// `slots()` elements.
pub trait CkksBackend {
    type Ciphertext;
    type SecretKey;

    /// Human-readable backend name, e.g. `"openfhe"`.
    fn name(&self) -> &'static str;
    fn slots(&self) -> usize;

    /// Public-key encryption of a full slot vector.
    fn encrypt(&self, values: &[f64]) -> Result<Self::Ciphertext>;
    /// Decrypt all slots. Requires the client's secret key.
    fn decrypt(&self, sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Result<Vec<f64>>;

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

    /// Serialized size of a ciphertext in bytes.
    fn ciphertext_bytes(&self, ct: &Self::Ciphertext) -> Result<usize>;
}
