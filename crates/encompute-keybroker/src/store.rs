//! Where a broker's asset keys live at rest.
//!
//! A [`SecretStore`] turns key material into a [`StoredKey`] for the state
//! file, and back only at release. The wrap is bound to the broker, asset and
//! version, so a stored key cannot be moved to another asset or version.
//!
//! - [`DevelopmentFileStore`]: plaintext, protected only by file
//!   permissions. Development only; production brokers refuse it.
//! - [`LocalKekStore`]: keys wrapped (ChaCha20-Poly1305) under a 32-byte
//!   key-encryption key held outside the state file. A KMS, HSM, KMIP or
//!   vault store implements the same trait: the broker never needs the
//!   KEK itself.

use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use encompute_ir::{Code, Error, Result};

use crate::KeyMaterial;
use encompute_verification::{hex, unhex};

fn err(msg: impl Into<String>) -> Error {
    Error::new(Code::KeyRelease, msg)
}

/// Whether a store may back a production broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreSecurity {
    DevelopmentOnly,
    Production,
}

/// A key as the state file holds it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "form", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoredKey {
    /// Development only.
    Plaintext { key: KeyMaterial },
    /// Revoked: the material is gone.
    Destroyed,
    Wrapped {
        /// The store that wrapped it (e.g. `local-kek`).
        store: String,
        /// Identifies the wrapping key (not secret).
        kek_id: String,
        nonce: String,
        ciphertext: String,
    },
}

/// What a wrap is bound to.
pub struct KeyContext<'a> {
    pub broker_id: &'a str,
    pub asset_id: &'a str,
    pub version: u64,
}

impl KeyContext<'_> {
    fn aad(&self) -> Vec<u8> {
        format!(
            "encompute.broker-key.v1\0{}\0{}\0{}",
            self.broker_id, self.asset_id, self.version
        )
        .into_bytes()
    }
}

/// Wraps asset keys at rest and unwraps them only for release.
pub trait SecretStore: Send {
    /// Stable name, recorded in the state file.
    fn name(&self) -> &'static str;
    fn security(&self) -> StoreSecurity;
    /// Identifies the wrapping key, if any (checked when a state file is
    /// opened with this store).
    fn key_id(&self) -> Option<String>;
    /// Stores a new key (put, and rotate's new version).
    fn wrap(&self, ctx: &KeyContext<'_>, key: &KeyMaterial) -> Result<StoredKey>;
    /// Recovers a key, only to seal it into a grant.
    fn unwrap_for_release(&self, ctx: &KeyContext<'_>, stored: &StoredKey) -> Result<KeyMaterial>;

    /// Revokes a stored key: its material is destroyed, not merely flagged.
    /// A KMS store would schedule the key version's destruction here.
    fn revoke(&self, _ctx: &KeyContext<'_>, _stored: &StoredKey) -> Result<StoredKey> {
        Ok(StoredKey::Destroyed)
    }

    /// Re-wraps a key stored by `from` under this store (KEK rotation, or a
    /// move to a KMS). Destroyed keys stay destroyed.
    fn rotate(
        &self,
        ctx: &KeyContext<'_>,
        stored: &StoredKey,
        from: &dyn SecretStore,
    ) -> Result<StoredKey> {
        match stored {
            StoredKey::Destroyed => Ok(StoredKey::Destroyed),
            s => self.wrap(ctx, &from.unwrap_for_release(ctx, s)?),
        }
    }
}

fn destroyed() -> Error {
    err("this key version was revoked and its material destroyed")
}

/// Plaintext keys in the owner-only state file. Development only.
pub struct DevelopmentFileStore;

impl SecretStore for DevelopmentFileStore {
    fn name(&self) -> &'static str {
        "development-file"
    }

    fn security(&self) -> StoreSecurity {
        StoreSecurity::DevelopmentOnly
    }

    fn key_id(&self) -> Option<String> {
        None
    }

    fn wrap(&self, _: &KeyContext<'_>, key: &KeyMaterial) -> Result<StoredKey> {
        Ok(StoredKey::Plaintext { key: key.clone() })
    }

    fn unwrap_for_release(&self, _: &KeyContext<'_>, stored: &StoredKey) -> Result<KeyMaterial> {
        match stored {
            StoredKey::Plaintext { key } => Ok(key.clone()),
            StoredKey::Destroyed => Err(destroyed()),
            StoredKey::Wrapped { store, .. } => Err(err(format!(
                "this key is wrapped by {store}; open the broker with that store"
            ))),
        }
    }
}

/// Keys wrapped under a 32-byte KEK from a separate file (mode 0600).
pub struct LocalKekStore {
    kek: Zeroizing<[u8; 32]>,
}

impl LocalKekStore {
    pub fn from_key(kek: [u8; 32]) -> Self {
        Self {
            kek: Zeroizing::new(kek),
        }
    }

    /// Reads the KEK file, creating it (mode 0600) if missing.
    pub fn open_or_create(path: &Path) -> Result<Self> {
        let io = |e: std::io::Error| err(format!("{}: {e}", path.display()));
        if path.exists() {
            let b = Zeroizing::new(std::fs::read(path).map_err(io)?);
            let k: [u8; 32] = b
                .as_slice()
                .try_into()
                .map_err(|_| err(format!("{}: a KEK file is 32 bytes", path.display())))?;
            return Ok(Self::from_key(k));
        }
        let mut k = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(k.as_mut()).map_err(|e| err(format!("no randomness: {e}")))?;
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(path)
            .and_then(|mut f| f.write_all(k.as_ref()))
            .map_err(io)?;
        Ok(Self::from_key(*k))
    }

    /// A fingerprint of the KEK (not secret).
    pub(crate) fn kek_id(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"encompute.kek-id.v1\0");
        h.update(self.kek.as_ref());
        hex(&h.finalize()[..16])
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&(*self.kek).into())
    }
}

impl SecretStore for LocalKekStore {
    fn name(&self) -> &'static str {
        "local-kek"
    }

    fn security(&self) -> StoreSecurity {
        StoreSecurity::Production
    }

    fn key_id(&self) -> Option<String> {
        Some(self.kek_id())
    }

    fn wrap(&self, ctx: &KeyContext<'_>, key: &KeyMaterial) -> Result<StoredKey> {
        self.wrap_as(self.name(), ctx, key)
    }

    fn unwrap_for_release(&self, ctx: &KeyContext<'_>, stored: &StoredKey) -> Result<KeyMaterial> {
        self.unwrap_as(self.name(), ctx, stored)
    }
}

impl LocalKekStore {
    /// Wraps under this KEK, recording `store` as the wrapping store (a
    /// store that obtains its KEK elsewhere, e.g. from a root key provider,
    /// reuses the cipher under its own name).
    pub(crate) fn wrap_as(
        &self,
        store: &str,
        ctx: &KeyContext<'_>,
        key: &KeyMaterial,
    ) -> Result<StoredKey> {
        let mut n = [0u8; 12];
        getrandom::getrandom(&mut n).map_err(|e| err(format!("no randomness: {e}")))?;
        let aad = ctx.aad();
        let ct = self
            .cipher()
            .encrypt(
                &Nonce::from(n),
                Payload {
                    msg: key.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| err("wrapping the key failed"))?;
        Ok(StoredKey::Wrapped {
            store: store.into(),
            kek_id: self.kek_id(),
            nonce: hex(&n),
            ciphertext: hex(&ct),
        })
    }

    pub(crate) fn unwrap_as(
        &self,
        expected: &str,
        ctx: &KeyContext<'_>,
        stored: &StoredKey,
    ) -> Result<KeyMaterial> {
        let (store, kek_id, nonce, ciphertext) = match stored {
            StoredKey::Wrapped {
                store,
                kek_id,
                nonce,
                ciphertext,
            } => (store, kek_id, nonce, ciphertext),
            StoredKey::Destroyed => return Err(destroyed()),
            StoredKey::Plaintext { .. } => return Err(err("a plaintext key in a wrapped store")),
        };
        if store != expected || *kek_id != self.kek_id() {
            return Err(err("the key was wrapped under another KEK"));
        }
        let n: [u8; 12] = unhex(nonce)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| err("malformed wrap nonce"))?;
        let ct = unhex(ciphertext).ok_or_else(|| err("malformed wrapped key"))?;
        let aad = ctx.aad();
        let pt = Zeroizing::new(
            self.cipher()
                .decrypt(
                    &Nonce::from(n),
                    Payload {
                        msg: &ct,
                        aad: &aad,
                    },
                )
                .map_err(|_| err("the wrapped key does not open (tampered, or moved to another asset or version)"))?,
        );
        KeyMaterial::from_bytes(&pt)
    }
}
