use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use encompute_ir::{Code, Error, Result};

use crate::hash::{hex, tagged, unhex, EVALUATOR};

/// An evaluator's public identity: an Ed25519 key and
/// `evaluator_id = SHA256("encompute.evaluator.v1" || 0x00 || public key)`.
/// Independent of the FHE backend and of every FHE key.
#[derive(Clone, PartialEq, Eq)]
pub struct EvaluatorIdentity {
    public_key: VerifyingKey,
}

impl EvaluatorIdentity {
    pub fn from_public_key(bytes: &[u8]) -> Result<Self> {
        let b: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::new(Code::Receipt, "evaluator public key must be 32 bytes"))?;
        let public_key = VerifyingKey::from_bytes(&b)
            .map_err(|e| Error::new(Code::Receipt, format!("evaluator public key: {e}")))?;
        Ok(Self { public_key })
    }

    pub fn from_public_key_hex(s: &str) -> Result<Self> {
        Self::from_public_key(
            &unhex(s)
                .ok_or_else(|| Error::new(Code::Receipt, "evaluator public key is not hex"))?,
        )
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    pub fn public_key_hex(&self) -> String {
        hex(&self.public_key())
    }

    /// Lowercase hex evaluator ID.
    pub fn evaluator_id(&self) -> String {
        hex(&tagged(EVALUATOR, &self.public_key()))
    }

    pub(crate) fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<()> {
        let sig = Signature::from_slice(signature)
            .map_err(|_| Error::new(Code::Receipt, "malformed receipt signature"))?;
        // Strict: rejects weak keys and non-canonical signatures.
        self.public_key
            .verify_strict(digest, &sig)
            .map_err(|_| Error::new(Code::Receipt, "receipt signature is invalid"))
    }
}

impl fmt::Debug for EvaluatorIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EvaluatorIdentity(enc-eval:{})", self.evaluator_id())
    }
}

/// The evaluator's receipt-signing key. Unrelated to any FHE key: the
/// evaluator still never holds a client's decryption key.
pub struct EvaluatorSigner {
    key: SigningKey,
}

impl EvaluatorSigner {
    /// A fresh identity from the operating system's randomness.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| Error::new(Code::Receipt, format!("no randomness: {e}")))?;
        Ok(Self::from_seed(&seed))
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte secret seed, for the evaluator's own disk.
    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn identity(&self) -> EvaluatorIdentity {
        EvaluatorIdentity {
            public_key: self.key.verifying_key(),
        }
    }

    pub(crate) fn sign(&self, digest: &[u8]) -> Vec<u8> {
        self.key.sign(digest).to_bytes().to_vec()
    }
}

impl fmt::Debug for EvaluatorSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EvaluatorSigner({:?})", self.identity())
    }
}
