//! Customer-managed root keys (BYOK).
//!
//! ```text
//! customer KMS / vault        root key: never leaves the provider
//!        │ wraps
//!        ▼
//! wrapped Encompute KEK       kek.wrapped.json (not secret)
//!        │ wraps
//!        ▼
//! wrapped asset keys          the broker's state file
//! ```
//!
//! A [`RootKeyProvider`] encrypts and decrypts the broker's 32-byte KEK
//! under an organization's root key. [`RootWrappedKekStore`] is the
//! [`SecretStore`] that unwraps the KEK through the provider when the broker
//! opens and wraps asset keys under it. Encompute stores only the key
//! reference, the provider, the root key version and the wrapped KEK.
//!
//! - Root rotation re-wraps only the KEK: asset keys stay as they are.
//! - A provider that is unreachable, disabled, or refuses the organization's
//!   context is an error: there is no fallback to local or plaintext keys.
//!
//! Providers: [`OpenBaoTransit`] (OpenBao or HashiCorp Vault Transit),
//! and [`DevelopmentRootKey`] (a local file; production brokers refuse it).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use encompute_ir::{Code, Error, Result};
use encompute_verification::{hex, unhex};

use crate::store::{KeyContext, LocalKekStore, SecretStore, StoreSecurity, StoredKey};
use crate::KeyMaterial;

fn err(msg: impl Into<String>) -> Error {
    Error::new(Code::KeyRelease, msg)
}

fn unavailable(provider: &str, e: impl std::fmt::Display) -> Error {
    err(format!(
        "root key provider {provider} unavailable: {e}; no key is released without it"
    ))
}

/// Encrypts small secrets (a KEK) under an organization's root key, held by
/// a KMS or vault that never exports it.
pub trait RootKeyProvider: Send + Sync {
    /// Stable provider name, recorded with the wrapped KEK.
    fn provider(&self) -> &'static str;
    /// Which root key (not secret), e.g. `https://bao:8200/transit/keys/org-a`.
    fn key_ref(&self) -> String;
    fn security(&self) -> StoreSecurity;
    /// Encrypts under the latest root key version: (ciphertext, version).
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<(String, u64)>;
    fn decrypt(&self, ciphertext: &str, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    /// Re-encrypts under the latest root key version.
    fn rewrap(&self, ciphertext: &str, aad: &[u8]) -> Result<(String, u64)>;
    /// Creates a new root key version; returns it.
    fn rotate(&self) -> Result<u64>;
}

/// The broker's KEK, wrapped under a root key. Not secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKek {
    pub format: u32,
    pub organization: String,
    pub provider: String,
    pub key_ref: String,
    pub key_version: u64,
    /// Fingerprint of the KEK, so a swapped file is detected.
    pub kek_id: String,
    pub ciphertext: String,
}

const WRAPPED_KEK_FORMAT: u32 = 1;

fn kek_aad(organization: &str) -> Vec<u8> {
    format!("encompute.root-wrapped-kek.v1\0{organization}").into_bytes()
}

/// A root key rotation, for the audit trail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRotation {
    pub organization: String,
    pub provider: String,
    pub key_ref: String,
    pub old_version: u64,
    pub new_version: u64,
}

/// Asset keys wrapped under a KEK that is itself wrapped under the
/// organization's root key.
pub struct RootWrappedKekStore {
    kek: LocalKekStore,
    wrapped: WrappedKek,
    provider: Box<dyn RootKeyProvider>,
    path: PathBuf,
}

impl RootWrappedKekStore {
    pub const NAME: &'static str = "root-wrapped-kek";

    /// Opens the wrapped KEK at `path` through `provider`, or creates one
    /// (random KEK, wrapped, written) if the file does not exist. The file
    /// must name this organization, provider and root key.
    pub fn open_or_create(
        path: &Path,
        provider: Box<dyn RootKeyProvider>,
        organization: &str,
    ) -> Result<Self> {
        if organization.is_empty() {
            return Err(err("a root-wrapped KEK needs an organization"));
        }
        let aad = kek_aad(organization);
        if !path.exists() {
            let mut k = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(k.as_mut()).map_err(|e| err(format!("no randomness: {e}")))?;
            let kek = LocalKekStore::from_key(*k);
            let (ciphertext, key_version) = provider.encrypt(k.as_ref(), &aad)?;
            let wrapped = WrappedKek {
                format: WRAPPED_KEK_FORMAT,
                organization: organization.into(),
                provider: provider.provider().into(),
                key_ref: provider.key_ref(),
                key_version,
                kek_id: kek.kek_id(),
                ciphertext,
            };
            write_new(path, &wrapped)?;
            return Ok(Self {
                kek,
                wrapped,
                provider,
                path: path.into(),
            });
        }
        let wrapped: WrappedKek = serde_json::from_slice(
            &std::fs::read(path).map_err(|e| err(format!("{}: {e}", path.display())))?,
        )
        .map_err(|e| err(format!("{}: {e}", path.display())))?;
        if wrapped.format != WRAPPED_KEK_FORMAT {
            return Err(err(format!("wrapped KEK format {}", wrapped.format)));
        }
        if wrapped.organization != organization {
            return Err(err(format!(
                "this KEK belongs to organization {:?}, not {organization:?}",
                wrapped.organization
            )));
        }
        if wrapped.provider != provider.provider() || wrapped.key_ref != provider.key_ref() {
            return Err(err(format!(
                "this KEK is wrapped by {} {}, not {} {}",
                wrapped.provider,
                wrapped.key_ref,
                provider.provider(),
                provider.key_ref()
            )));
        }
        let pt = provider.decrypt(&wrapped.ciphertext, &aad)?;
        let k: [u8; 32] = pt
            .as_slice()
            .try_into()
            .map_err(|_| err("the root key provider returned a KEK of the wrong length"))?;
        let kek = LocalKekStore::from_key(k);
        if kek.kek_id() != wrapped.kek_id {
            return Err(err("the unwrapped KEK does not match its fingerprint"));
        }
        Ok(Self {
            kek,
            wrapped,
            provider,
            path: path.into(),
        })
    }

    pub fn wrapped(&self) -> &WrappedKek {
        &self.wrapped
    }

    /// Rotates the organization's root key and re-wraps the KEK under the
    /// new version. Asset keys are untouched (the KEK is the same).
    pub fn rotate_root(&mut self) -> Result<RootRotation> {
        let old_version = self.wrapped.key_version;
        self.provider.rotate()?;
        let (ciphertext, new_version) = self.provider.rewrap(
            &self.wrapped.ciphertext,
            &kek_aad(&self.wrapped.organization),
        )?;
        let mut next = self.wrapped.clone();
        next.ciphertext = ciphertext;
        next.key_version = new_version;
        replace(&self.path, &next)?;
        self.wrapped = next;
        Ok(RootRotation {
            organization: self.wrapped.organization.clone(),
            provider: self.wrapped.provider.clone(),
            key_ref: self.wrapped.key_ref.clone(),
            old_version,
            new_version,
        })
    }
}

fn write_new(path: &Path, w: &WrappedKek) -> Result<()> {
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
    f.write_all(&serde_json::to_vec_pretty(w).expect("serializable"))
        .and_then(|_| f.sync_all())
        .map_err(io)
}

fn replace(path: &Path, w: &WrappedKek) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    write_new(&tmp, w)?;
    std::fs::rename(&tmp, path).map_err(|e| err(format!("{}: {e}", path.display())))
}

impl SecretStore for RootWrappedKekStore {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn security(&self) -> StoreSecurity {
        self.provider.security()
    }

    fn key_id(&self) -> Option<String> {
        Some(self.wrapped.kek_id.clone())
    }

    fn wrap(&self, ctx: &KeyContext<'_>, key: &KeyMaterial) -> Result<StoredKey> {
        self.kek.wrap_as(Self::NAME, ctx, key)
    }

    fn unwrap_for_release(&self, ctx: &KeyContext<'_>, stored: &StoredKey) -> Result<KeyMaterial> {
        self.kek.unwrap_as(Self::NAME, ctx, stored)
    }
}

// --- OpenBao / HashiCorp Vault Transit ----------------------------------------

/// A root key in OpenBao or HashiCorp Vault's Transit engine (same API).
/// The token comes from the environment or a mounted file, never from a
/// command line or config file.
pub struct OpenBaoTransit {
    addr: String,
    mount: String,
    key: String,
    token: Zeroizing<String>,
    agent: ureq::Agent,
}

impl OpenBaoTransit {
    /// `addr`: e.g. `https://bao.internal:8200`. Plain HTTP is accepted only
    /// for loopback addresses (local development containers).
    pub fn new(addr: &str, mount: &str, key: &str, token: Zeroizing<String>) -> Result<Self> {
        let addr = addr.trim_end_matches('/').to_owned();
        let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|p| addr.starts_with(p));
        if !addr.starts_with("https://") && !loopback {
            return Err(err(format!(
                "root key provider address {addr} must use https (plain http only on loopback)"
            )));
        }
        let ok = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        };
        if !ok(mount) || !ok(key) {
            return Err(err("malformed transit mount or key name"));
        }
        if token.is_empty() {
            return Err(err("no OpenBao/Vault token"));
        }
        Ok(Self {
            addr,
            mount: mount.into(),
            key: key.into(),
            token,
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(10))
                .build(),
        })
    }

    /// From `BAO_ADDR`/`VAULT_ADDR`, and the token from `BAO_TOKEN_FILE`
    /// (a mounted secret) or `BAO_TOKEN`/`VAULT_TOKEN`.
    pub fn from_env(mount: &str, key: &str) -> Result<Self> {
        let var = |names: &[&str]| names.iter().find_map(|n| std::env::var(n).ok());
        let addr = var(&["BAO_ADDR", "VAULT_ADDR"])
            .ok_or_else(|| err("set BAO_ADDR (or VAULT_ADDR) to the root key provider"))?;
        let token = match var(&["BAO_TOKEN_FILE", "VAULT_TOKEN_FILE"]) {
            Some(f) => Zeroizing::new(
                std::fs::read_to_string(&f)
                    .map_err(|e| err(format!("{f}: {e}")))?
                    .trim()
                    .to_owned(),
            ),
            None => Zeroizing::new(var(&["BAO_TOKEN", "VAULT_TOKEN"]).ok_or_else(|| {
                err("set BAO_TOKEN_FILE (or BAO_TOKEN) for the root key provider")
            })?),
        };
        Self::new(&addr, mount, key, token)
    }

    fn call(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}/v1/{}/{}", self.addr, self.mount, path);
        let r = self
            .agent
            .post(&url)
            .set("X-Vault-Token", &self.token)
            .send_json(body);
        match r {
            Ok(resp) => resp
                .into_json()
                .map_err(|e| unavailable(self.provider(), e)),
            Err(ureq::Error::Status(code, resp)) => {
                let detail = resp
                    .into_json::<serde_json::Value>()
                    .ok()
                    .and_then(|v| {
                        v["errors"].as_array().map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join("; ")
                        })
                    })
                    .unwrap_or_default();
                Err(err(format!(
                    "root key provider refused ({code}): {detail}; no key is released without it"
                )))
            }
            Err(e) => Err(unavailable(self.provider(), e)),
        }
    }

    fn ciphertext_version(c: &str) -> Result<u64> {
        c.strip_prefix("vault:v")
            .and_then(|r| r.split(':').next())
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| err("malformed transit ciphertext"))
    }

    fn cipher_of(v: &serde_json::Value) -> Result<(String, u64)> {
        let c = v["data"]["ciphertext"]
            .as_str()
            .ok_or_else(|| err("the root key provider returned no ciphertext"))?;
        Ok((c.to_owned(), Self::ciphertext_version(c)?))
    }
}

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

impl RootKeyProvider for OpenBaoTransit {
    fn provider(&self) -> &'static str {
        "openbao-transit"
    }

    fn key_ref(&self) -> String {
        format!("{}/{}/keys/{}", self.addr, self.mount, self.key)
    }

    fn security(&self) -> StoreSecurity {
        StoreSecurity::Production
    }

    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<(String, u64)> {
        let pt = Zeroizing::new(b64(plaintext));
        let v = self.call(
            &format!("encrypt/{}", self.key),
            serde_json::json!({"plaintext": pt.as_str(), "associated_data": b64(aad)}),
        )?;
        Self::cipher_of(&v)
    }

    fn decrypt(&self, ciphertext: &str, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Self::ciphertext_version(ciphertext)?;
        let v = self.call(
            &format!("decrypt/{}", self.key),
            serde_json::json!({"ciphertext": ciphertext, "associated_data": b64(aad)}),
        )?;
        let p = Zeroizing::new(
            v["data"]["plaintext"]
                .as_str()
                .ok_or_else(|| err("the root key provider returned no plaintext"))?
                .to_owned(),
        );
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(p.as_bytes())
            .map(Zeroizing::new)
            .map_err(|_| err("the root key provider returned malformed plaintext"))
    }

    fn rewrap(&self, ciphertext: &str, aad: &[u8]) -> Result<(String, u64)> {
        // Transit's rewrap endpoint ignores associated data, which binds the
        // KEK to its organization; the KEK is in the broker's memory anyway
        // while it is open, so decrypt and encrypt under the latest version.
        let pt = self.decrypt(ciphertext, aad)?;
        self.encrypt(&pt, aad)
    }

    fn rotate(&self) -> Result<u64> {
        self.call(&format!("keys/{}/rotate", self.key), serde_json::json!({}))?;
        let url = format!("{}/v1/{}/keys/{}", self.addr, self.mount, self.key);
        let v: serde_json::Value = self
            .agent
            .get(&url)
            .set("X-Vault-Token", &self.token)
            .call()
            .map_err(|e| unavailable(self.provider(), e))?
            .into_json()
            .map_err(|e| unavailable(self.provider(), e))?;
        v["data"]["latest_version"]
            .as_u64()
            .ok_or_else(|| err("the root key provider did not report a version"))
    }
}

// --- development --------------------------------------------------------------

/// Root keys in a local file (mode 0600). Development only: a production
/// broker refuses it, and it never stands in for an unavailable provider.
pub struct DevelopmentRootKey {
    path: PathBuf,
}

#[derive(Default, Serialize, Deserialize)]
struct DevRoots {
    /// Version → hex key.
    versions: BTreeMap<u64, String>,
}

impl DevelopmentRootKey {
    pub fn open(path: &Path) -> Result<Self> {
        let me = Self { path: path.into() };
        if !path.exists() {
            me.rotate()?;
        }
        Ok(me)
    }

    fn load(&self) -> Result<DevRoots> {
        if !self.path.exists() {
            return Ok(DevRoots::default());
        }
        serde_json::from_slice(
            &std::fs::read(&self.path).map_err(|e| err(format!("{}: {e}", self.path.display())))?,
        )
        .map_err(|e| err(format!("{}: {e}", self.path.display())))
    }

    fn cipher(roots: &DevRoots, version: u64) -> Result<ChaCha20Poly1305> {
        let k = roots
            .versions
            .get(&version)
            .and_then(|h| unhex(h))
            .ok_or_else(|| err(format!("no development root key version {version}")))?;
        let k: [u8; 32] = k
            .try_into()
            .map_err(|_| err("malformed development root key"))?;
        Ok(ChaCha20Poly1305::new(&k.into()))
    }
}

impl RootKeyProvider for DevelopmentRootKey {
    fn provider(&self) -> &'static str {
        "development-root"
    }

    fn key_ref(&self) -> String {
        format!("file:{}", self.path.display())
    }

    fn security(&self) -> StoreSecurity {
        StoreSecurity::DevelopmentOnly
    }

    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<(String, u64)> {
        let roots = self.load()?;
        let v = *roots
            .versions
            .keys()
            .last()
            .ok_or_else(|| err("no development root key"))?;
        let mut n = [0u8; 12];
        getrandom::getrandom(&mut n).map_err(|e| err(format!("no randomness: {e}")))?;
        let ct = Self::cipher(&roots, v)?
            .encrypt(
                &Nonce::from(n),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| err("encryption failed"))?;
        Ok((format!("dev:v{v}:{}{}", hex(&n), hex(&ct)), v))
    }

    fn decrypt(&self, ciphertext: &str, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let rest = ciphertext
            .strip_prefix("dev:v")
            .ok_or_else(|| err("not a development root ciphertext"))?;
        let (v, body) = rest
            .split_once(':')
            .ok_or_else(|| err("malformed ciphertext"))?;
        let v: u64 = v.parse().map_err(|_| err("malformed ciphertext"))?;
        let b = unhex(body).ok_or_else(|| err("malformed ciphertext"))?;
        if b.len() < 12 {
            return Err(err("malformed ciphertext"));
        }
        let (n, ct) = b.split_at(12);
        let n: [u8; 12] = n.try_into().expect("12 bytes");
        Self::cipher(&self.load()?, v)?
            .decrypt(&Nonce::from(n), Payload { msg: ct, aad })
            .map(Zeroizing::new)
            .map_err(|_| err("the wrapped KEK does not open under this root key and context"))
    }

    fn rewrap(&self, ciphertext: &str, aad: &[u8]) -> Result<(String, u64)> {
        let pt = self.decrypt(ciphertext, aad)?;
        self.encrypt(&pt, aad)
    }

    fn rotate(&self) -> Result<u64> {
        let mut roots = self.load()?;
        let next = roots.versions.keys().last().map_or(1, |v| v + 1);
        let mut k = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(k.as_mut()).map_err(|e| err(format!("no randomness: {e}")))?;
        roots.versions.insert(next, hex(k.as_ref()));
        let tmp = self.path.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp);
        {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o
                .open(&tmp)
                .map_err(|e| err(format!("{}: {e}", tmp.display())))?;
            f.write_all(&serde_json::to_vec(&roots).expect("serializable"))
                .map_err(|e| err(format!("{}: {e}", tmp.display())))?;
        }
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| err(format!("{}: {e}", self.path.display())))?;
        Ok(next)
    }
}
