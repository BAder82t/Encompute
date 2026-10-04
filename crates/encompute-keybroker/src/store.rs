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

use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
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
    /// A KMS store would schedule the key version's destruction here. An
    /// older copy of the state file still holds the wrapped key, and the
    /// broker does not detect it being restored (a known limitation).
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

    /// Starts a rotation of this store's wrapping key (the crypto-shred of
    /// a revocation): a store with a fresh key, made durable under a
    /// pending name but not yet live, so a crash after the broker writes a
    /// state wrapped under it still finds it ([`adopt_pending`]). `None`
    /// when the store has no wrapping key it can replace (development
    /// plaintext, or a key held in memory only): nothing is shredded.
    ///
    /// [`adopt_pending`]: SecretStore::adopt_pending
    fn begin_rekey(&self) -> Result<Option<Box<dyn SecretStore>>> {
        Ok(None)
    }

    /// Makes this store, from [`begin_rekey`](SecretStore::begin_rekey), the
    /// live one, and destroys the wrapping key it replaced (and any other
    /// pending one). Called only after the state wrapped under it is saved
    /// and, with a generation mark, the mark advanced. Idempotent.
    fn commit_rekey(&self) -> Result<()> {
        Ok(())
    }

    /// Switches to the pending wrapping key `kek_id` that a rotation left
    /// behind (a state written under it was found), if there is one;
    /// whether it did. The key is promoted only by `commit_rekey`.
    fn adopt_pending(&mut self, _kek_id: &str) -> Result<bool> {
        Ok(false)
    }

    /// Authenticates the broker's state (release policies, mode,
    /// organization, key versions, revocations) under a key derived from
    /// this store's wrapping key: whoever can write the state file but does
    /// not hold the wrapping key cannot edit what is released to whom. It
    /// does not stop a rollback: an older authentic state file (one saved
    /// before a revocation) still verifies (a known limitation).
    /// `None` for a store without a wrapping key (development only; a
    /// production broker refuses a store that cannot authenticate state).
    fn state_mac(&self, _state: &[u8]) -> Result<Option<[u8; 32]>> {
        Ok(None)
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
    /// The KEK file, when the key came from one: a rotation writes its
    /// successor beside it.
    path: Option<PathBuf>,
}

impl LocalKekStore {
    pub fn from_key(kek: [u8; 32]) -> Self {
        Self {
            kek: Zeroizing::new(kek),
            path: None,
        }
    }

    /// Reads the KEK file, creating it (mode 0600) if missing.
    pub fn open_or_create(path: &Path) -> Result<Self> {
        let io = |e: std::io::Error| err(format!("{}: {e}", path.display()));
        if path.exists() {
            check_private(path)?;
            let b = Zeroizing::new(std::fs::read(path).map_err(io)?);
            let k: [u8; 32] = b
                .as_slice()
                .try_into()
                .map_err(|_| err(format!("{}: a KEK file is 32 bytes", path.display())))?;
            return Ok(Self::from_key(k).at(path));
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
        Ok(Self::from_key(*k).at(path))
    }

    fn at(mut self, path: &Path) -> Self {
        self.path = Some(path.to_owned());
        self
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

    /// HMAC-SHA256 of `state` under a key derived (HKDF) from the KEK for
    /// this one purpose: the KEK itself never keys anything but the wrap.
    pub(crate) fn mac_state(&self, state: &[u8]) -> [u8; 32] {
        let mut k = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, self.kek.as_ref())
            .expand(b"encompute.broker-state-mac.v1", k.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(k.as_ref()).expect("any key length");
        m.update(state);
        m.finalize().into_bytes().into()
    }
}

/// A file holding key material must be private to its owner: a KEK another
/// user can read (or replace) protects nothing.
pub(crate) fn check_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(path).map_err(|e| err(format!("{}: {e}", path.display())))?;
        let mode = m.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(err(format!(
                "{} is mode {mode:o}: a key file must not be accessible to others (chmod 600)",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The file a rotated wrapping key waits in, beside the live one, until
/// the state saved under it is recorded: `NAME.next.KEKID`. One file per
/// key ID, so a rotation never overwrites a pending key that a written
/// state may still need.
pub(crate) fn pending_path(live: &Path, kek_id: &str) -> PathBuf {
    let mut name = live.file_name().unwrap_or_default().to_owned();
    name.push(format!(".next.{kek_id}"));
    live.with_file_name(name)
}

/// Writes `bytes` to a new private file (mode 0600), durably.
pub(crate) fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let io = |e: std::io::Error| err(format!("{}: {e}", path.display()));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(io)?;
    f.write_all(bytes).and_then(|_| f.sync_all()).map_err(io)?;
    sync_dir(path);
    Ok(())
}

/// Flushes the directory entry of `path` (best effort: not every
/// filesystem supports it).
pub(crate) fn sync_dir(path: &Path) {
    if let Some(d) = path.parent() {
        let d = if d.as_os_str().is_empty() {
            Path::new(".")
        } else {
            d
        };
        if let Ok(f) = std::fs::File::open(d) {
            let _ = f.sync_all();
        }
    }
}

/// Whether a rotation left a pending key beside `live`.
pub(crate) fn has_pending(live: &Path) -> bool {
    let prefix = format!(
        "{}.next.",
        live.file_name().unwrap_or_default().to_string_lossy()
    );
    let dir = live.parent().filter(|d| !d.as_os_str().is_empty());
    std::fs::read_dir(dir.unwrap_or_else(|| Path::new(".")))
        .map(|rd| {
            rd.flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        })
        .unwrap_or(false)
}

/// Makes the pending key `kek_id` the live file `live` (an atomic rename,
/// which destroys the key it replaces) and removes every other pending
/// key. Returns whether a pending file was promoted; with none, the live
/// file is already it.
pub(crate) fn promote_pending(live: &Path, kek_id: &str) -> Result<bool> {
    let pending = pending_path(live, kek_id);
    let promoted = pending.exists();
    if promoted {
        std::fs::rename(&pending, live).map_err(|e| err(format!("{}: {e}", live.display())))?;
        sync_dir(live);
    }
    let prefix = format!(
        "{}.next.",
        live.file_name().unwrap_or_default().to_string_lossy()
    );
    let dir = live.parent().filter(|d| !d.as_os_str().is_empty());
    if let Ok(rd) = std::fs::read_dir(dir.unwrap_or_else(|| Path::new("."))) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    Ok(promoted)
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

    fn state_mac(&self, state: &[u8]) -> Result<Option<[u8; 32]>> {
        Ok(Some(self.mac_state(state)))
    }

    fn begin_rekey(&self) -> Result<Option<Box<dyn SecretStore>>> {
        let Some(live) = &self.path else {
            return Ok(None);
        };
        let mut k = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(k.as_mut()).map_err(|e| err(format!("no randomness: {e}")))?;
        let next = Self::from_key(*k).at(live);
        write_private_new(&pending_path(live, &next.kek_id()), k.as_ref())?;
        Ok(Some(Box::new(next)))
    }

    fn commit_rekey(&self) -> Result<()> {
        let Some(live) = &self.path else {
            return Ok(());
        };
        if !promote_pending(live, &self.kek_id())? {
            // Nothing pending: the live file must already be this key,
            // or the key that wrapped the state was never made durable.
            let b = Zeroizing::new(
                std::fs::read(live).map_err(|e| err(format!("{}: {e}", live.display())))?,
            );
            if b.as_slice() != self.kek.as_ref() {
                return Err(err(format!(
                    "{}: the rotated KEK is neither pending nor live",
                    live.display()
                )));
            }
        }
        Ok(())
    }

    fn adopt_pending(&mut self, kek_id: &str) -> Result<bool> {
        let Some(live) = &self.path else {
            return Ok(false);
        };
        let pending = pending_path(live, kek_id);
        if !pending.exists() {
            return Ok(false);
        }
        check_private(&pending)?;
        let b = Zeroizing::new(
            std::fs::read(&pending).map_err(|e| err(format!("{}: {e}", pending.display())))?,
        );
        let k: [u8; 32] = b
            .as_slice()
            .try_into()
            .map_err(|_| err(format!("{}: a KEK file is 32 bytes", pending.display())))?;
        let adopted = Self::from_key(k).at(live);
        if adopted.kek_id() != kek_id {
            return Err(err(format!(
                "{}: the pending KEK is not the one its name says",
                pending.display()
            )));
        }
        *self = adopted;
        Ok(true)
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
