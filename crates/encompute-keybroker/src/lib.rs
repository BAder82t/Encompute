//! The Encompute key broker (ADR-011): holds asset keys for their owner and
//! releases one only to a workload whose fresh attestation satisfies the
//! asset's [`AttestationPolicy`], sealed to that workload's attested
//! session key.
//!
//! The broker never sees asset data, and there is no path that returns a
//! key without attestation: the cloud operator can relay requests, but a
//! grant opens only inside the attested session.
//!
//! Flow: [`KeyBroker::challenge`] → the workload attests, binding the
//! challenge → [`KeyBroker::verify_attestation`] (consumes the challenge;
//! a replay finds none) → [`KeyBroker::release_key`] per asset.

mod client;
mod server;
pub mod store;
mod workload;

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use encompute_attestation::{
    check_freshness, seal_grant, unix_now, AttestationChallenge, AttestationEvidence,
    AttestationPolicy, EncryptedKeyGrant, GrantHeader, Security, VerifiedWorkload, Verifier,
    WorkloadSession, GRANT_VERSION,
};
use encompute_ir::{Code, Error, Result};

pub use client::BrokerClient;
pub use server::serve;
pub use store::{
    DevelopmentFileStore, KeyContext, LocalKekStore, SecretStore, StoreSecurity, StoredKey,
};
pub use workload::{acquire_keys, AcquiredKey};

/// Challenges live this long.
pub const CHALLENGE_TTL_SECS: u64 = 300;
/// An attested session may request keys for at most this long.
pub const SESSION_TTL_SECS: u64 = 600;
/// Open challenges (and sessions) kept at once.
const MAX_OPEN: usize = 4096;

fn err(code: Code, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

/// A production broker refuses development-only (mock) evidence whatever a
/// policy says; a development broker accepts it where policies allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerMode {
    Production,
    Development,
}

/// Key bytes; never printed, zeroed on drop, hex in the state file.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyMaterial(Zeroizing<Vec<u8>>);

impl KeyMaterial {
    pub fn generate() -> Result<Self> {
        let mut k = Zeroizing::new(vec![0u8; 32]);
        getrandom::getrandom(&mut k)
            .map_err(|e| err(Code::KeyRelease, format!("no randomness: {e}")))?;
        Ok(Self(k))
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.is_empty() || b.len() > 4096 {
            return Err(err(Code::KeyRelease, "keys are 1-4096 bytes"));
        }
        Ok(Self(Zeroizing::new(b.to_vec())))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyMaterial(<redacted>)")
    }
}

impl Serialize for KeyMaterial {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let h: Zeroizing<String> =
            Zeroizing::new(self.0.iter().map(|b| format!("{b:02x}")).collect());
        s.serialize_str(&h)
    }
}

impl<'de> Deserialize<'de> for KeyMaterial {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = Zeroizing::new(String::deserialize(d)?);
        let bad = || serde::de::Error::custom("key material is not hex");
        if !s.len().is_multiple_of(2) {
            return Err(bad());
        }
        let b: Option<Vec<u8>> = (0..s.len() / 2)
            .map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
            .collect();
        Ok(Self(Zeroizing::new(b.ok_or_else(bad)?)))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyVersion {
    pub key: StoredKey,
    pub revoked: bool,
}

/// An asset key under a release policy. Only the current version is
/// released.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedSecret {
    pub asset_id: String,
    pub key_version: u64,
    pub release_policy: AttestationPolicy,
    pub versions: BTreeMap<u64, KeyVersion>,
}

/// What a broker persists: its identity, mode, secrets and open
/// challenges.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerState {
    pub broker_id: String,
    pub mode: BrokerMode,
    /// The [`SecretStore`] holding the keys, and its wrapping key's ID.
    pub store: String,
    #[serde(default)]
    pub kek_id: Option<String>,
    pub secrets: BTreeMap<String, ProtectedSecret>,
    #[serde(default)]
    pub challenges: Vec<AttestationChallenge>,
}

/// An attested session as the broker recorded it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionInfo {
    /// Hex binding hash: the handle for [`KeyBroker::release_key`].
    pub session: String,
    pub workload_session_id: String,
    pub expires_at: u64,
    pub attestation_digest: String,
}

struct Session {
    info: SessionInfo,
    workload: VerifiedWorkload,
}

pub struct KeyBroker {
    state: BrokerState,
    verifier: Verifier,
    store: Box<dyn SecretStore>,
    sessions: BTreeMap<String, Session>,
    clock: Box<dyn Fn() -> u64 + Send>,
}

fn check_broker_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 512 || !id.bytes().all(|c| c.is_ascii_graphic()) {
        return Err(err(
            Code::KeyRelease,
            "broker ID must be 1-512 printable ASCII characters",
        ));
    }
    Ok(())
}

fn check_asset_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-_.".contains(&c));
    if !ok {
        return Err(err(
            Code::KeyRelease,
            format!("asset ID {id:?} must be 1-64 characters of a-z, 0-9, '-', '_', '.'"),
        ));
    }
    Ok(())
}

impl KeyBroker {
    /// A broker with no secrets, keeping keys in `store`. Its ID is the
    /// audience workloads attest to. A production broker needs a production
    /// store: plaintext keys on disk are for development only.
    pub fn new(
        broker_id: &str,
        mode: BrokerMode,
        verifier: Verifier,
        store: Box<dyn SecretStore>,
    ) -> Result<Self> {
        check_broker_id(broker_id)?;
        Self::from_state(
            BrokerState {
                broker_id: broker_id.to_owned(),
                mode,
                store: store.name().into(),
                kek_id: store.key_id(),
                secrets: BTreeMap::new(),
                challenges: Vec::new(),
            },
            verifier,
            store,
        )
    }

    /// Reopens a broker; `store` must be the one its keys were stored with.
    pub fn from_state(
        state: BrokerState,
        verifier: Verifier,
        store: Box<dyn SecretStore>,
    ) -> Result<Self> {
        if state.mode == BrokerMode::Production && store.security() != StoreSecurity::Production {
            return Err(err(
                Code::KeyRelease,
                format!(
                    "a production broker cannot keep keys in the {} store (development only)",
                    store.name()
                ),
            ));
        }
        if state.store != store.name() || state.kek_id != store.key_id() {
            return Err(err(
                Code::KeyRelease,
                format!(
                    "this broker's keys are in the {} store{}; open it with that store",
                    state.store,
                    state
                        .kek_id
                        .as_deref()
                        .map(|k| format!(" (KEK {k})"))
                        .unwrap_or_default()
                ),
            ));
        }
        Ok(Self {
            state,
            verifier,
            store,
            sessions: BTreeMap::new(),
            clock: Box::new(unix_now),
        })
    }

    fn wrap(&self, asset_id: &str, version: u64, key: &KeyMaterial) -> Result<StoredKey> {
        self.store.wrap(
            &KeyContext {
                broker_id: &self.state.broker_id,
                asset_id,
                version,
            },
            key,
        )
    }

    /// Replaces the clock (tests).
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    pub fn id(&self) -> &str {
        &self.state.broker_id
    }

    pub fn mode(&self) -> BrokerMode {
        self.state.mode
    }

    pub fn state(&self) -> &BrokerState {
        &self.state
    }

    pub fn secret(&self, asset_id: &str) -> Option<&ProtectedSecret> {
        self.state.secrets.get(asset_id)
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Protects `key` (or a fresh random key) for `asset_id` under `policy`.
    /// Returns the key version.
    pub fn add_secret(
        &mut self,
        asset_id: &str,
        key: Option<KeyMaterial>,
        policy: AttestationPolicy,
    ) -> Result<u64> {
        check_asset_id(asset_id)?;
        policy.validate()?;
        if self.state.mode == BrokerMode::Production && policy.allow_development {
            return Err(err(
                Code::WorkloadPolicy,
                "a production broker does not accept development policies",
            ));
        }
        if self.state.secrets.contains_key(asset_id) {
            return Err(err(
                Code::KeyRelease,
                format!("asset {asset_id} already has a key; rotate it instead"),
            ));
        }
        let key = match key {
            Some(k) => k,
            None => KeyMaterial::generate()?,
        };
        let key = self.wrap(asset_id, 1, &key)?;
        self.state.secrets.insert(
            asset_id.to_owned(),
            ProtectedSecret {
                asset_id: asset_id.to_owned(),
                key_version: 1,
                release_policy: policy,
                versions: [(
                    1,
                    KeyVersion {
                        key,
                        revoked: false,
                    },
                )]
                .into(),
            },
        );
        Ok(1)
    }

    fn secret_mut(&mut self, asset_id: &str) -> Result<&mut ProtectedSecret> {
        self.state
            .secrets
            .get_mut(asset_id)
            .ok_or_else(|| err(Code::KeyRelease, format!("no key for asset {asset_id}")))
    }

    /// A new current key version; older versions are no longer released.
    pub fn rotate_key(&mut self, asset_id: &str) -> Result<u64> {
        let v = self.secret_mut(asset_id)?.key_version + 1;
        let key = self.wrap(asset_id, v, &KeyMaterial::generate()?)?;
        let s = self.secret_mut(asset_id)?;
        s.key_version = v;
        s.versions.insert(
            v,
            KeyVersion {
                key,
                revoked: false,
            },
        );
        Ok(v)
    }

    /// Revokes a version (default: the current one). A revoked current key
    /// is never released; rotate to release again.
    pub fn revoke(&mut self, asset_id: &str, version: Option<u64>) -> Result<u64> {
        let broker_id = self.state.broker_id.clone();
        let s = self
            .state
            .secrets
            .get_mut(asset_id)
            .ok_or_else(|| err(Code::KeyRelease, format!("no key for asset {asset_id}")))?;
        let v = version.unwrap_or(s.key_version);
        let kv = s.versions.get_mut(&v).ok_or_else(|| {
            err(
                Code::KeyRelease,
                format!("{asset_id} has no key version {v}"),
            )
        })?;
        kv.key = self.store.revoke(
            &KeyContext {
                broker_id: &broker_id,
                asset_id,
                version: v,
            },
            &kv.key,
        )?;
        kv.revoked = true;
        Ok(v)
    }

    /// Re-wraps every key under `store` (KEK rotation, or a move to a KMS),
    /// which then replaces the current store. A production broker still
    /// needs a production store.
    pub fn rewrap(&mut self, store: Box<dyn SecretStore>) -> Result<()> {
        if self.state.mode == BrokerMode::Production
            && store.security() != StoreSecurity::Production
        {
            return Err(err(
                Code::KeyRelease,
                format!(
                    "a production broker cannot move keys to the {} store",
                    store.name()
                ),
            ));
        }
        let broker_id = self.state.broker_id.clone();
        let mut secrets = self.state.secrets.clone();
        for (asset_id, s) in secrets.iter_mut() {
            for (v, kv) in s.versions.iter_mut() {
                let ctx = KeyContext {
                    broker_id: &broker_id,
                    asset_id,
                    version: *v,
                };
                kv.key = store.rotate(&ctx, &kv.key, self.store.as_ref())?;
            }
        }
        self.state.secrets = secrets;
        self.state.store = store.name().into();
        self.state.kek_id = store.key_id();
        self.store = store;
        Ok(())
    }

    /// Replaces an asset's release policy.
    pub fn set_policy(&mut self, asset_id: &str, policy: AttestationPolicy) -> Result<()> {
        policy.validate()?;
        if self.state.mode == BrokerMode::Production && policy.allow_development {
            return Err(err(
                Code::WorkloadPolicy,
                "a production broker does not accept development policies",
            ));
        }
        self.secret_mut(asset_id)?.release_policy = policy;
        Ok(())
    }

    fn prune(&mut self, now: u64) {
        self.state.challenges.retain(|c| c.expires_at >= now);
        self.sessions.retain(|_, s| s.info.expires_at > now);
    }

    /// A fresh single-use challenge.
    pub fn challenge(&mut self) -> Result<AttestationChallenge> {
        let now = self.now();
        self.prune(now);
        if self.state.challenges.len() >= MAX_OPEN {
            return Err(err(Code::Freshness, "too many open challenges"));
        }
        let c = AttestationChallenge::new(&self.state.broker_id, now, CHALLENGE_TTL_SECS)?;
        self.state.challenges.push(c.clone());
        Ok(c)
    }

    /// Verifies evidence answering one of this broker's open challenges and
    /// opens an attested session. The challenge is consumed whatever the
    /// outcome, so evidence can be presented once.
    pub fn verify_attestation(&mut self, evidence: &AttestationEvidence) -> Result<SessionInfo> {
        let now = self.now();
        self.prune(now);
        let nonce = &evidence.binding.challenge_nonce;
        let i = self
            .state
            .challenges
            .iter()
            .position(|c| &c.nonce == nonce)
            .ok_or_else(|| {
                err(
                    Code::Freshness,
                    "the evidence answers no open challenge (unknown, expired or already used)",
                )
            })?;
        let challenge = self.state.challenges.swap_remove(i);
        if challenge.broker_id != self.state.broker_id {
            return Err(err(
                Code::Freshness,
                "the challenge was issued by another broker",
            ));
        }
        let w = self.verifier.verify_claims(evidence, Some(now))?;
        check_freshness(&w, &challenge, SESSION_TTL_SECS, now)?;
        if self.state.mode == BrokerMode::Production && w.security != Security::Production {
            return Err(err(
                Code::WorkloadPolicy,
                format!(
                    "{} evidence is development-only; this broker is in production mode",
                    w.provider
                ),
            ));
        }
        if self.sessions.len() >= MAX_OPEN {
            return Err(err(Code::Freshness, "too many open sessions"));
        }
        let info = SessionInfo {
            session: evidence.binding.nonce()?,
            workload_session_id: WorkloadSession::session_id_of(&evidence.binding)?,
            expires_at: w
                .expires_at
                .unwrap_or(u64::MAX)
                .min(now.saturating_add(SESSION_TTL_SECS)),
            attestation_digest: w.evidence_digest_hex(),
        };
        self.sessions.insert(
            info.session.clone(),
            Session {
                info: info.clone(),
                workload: w,
            },
        );
        Ok(info)
    }

    /// Releases the current key of `asset_id` to an attested session whose
    /// workload satisfies the asset's policy, sealed to its session key.
    pub fn release_key(&mut self, session: &str, asset_id: &str) -> Result<EncryptedKeyGrant> {
        let now = self.now();
        self.prune(now);
        let s = self.sessions.get(session).ok_or_else(|| {
            err(
                Code::KeyRelease,
                "no attested session (keys are released only after attestation)",
            )
        })?;
        let secret = self
            .state
            .secrets
            .get(asset_id)
            .ok_or_else(|| err(Code::KeyRelease, format!("no key for asset {asset_id}")))?;
        let policy = &secret.release_policy;
        policy.check(&s.workload)?;
        if s.workload
            .issued_at
            .is_none_or(|t| now > t.saturating_add(policy.max_evidence_age_secs))
        {
            return Err(err(
                Code::Freshness,
                "the attestation is stale for this asset",
            ));
        }
        let current = &secret.versions[&secret.key_version];
        if current.revoked {
            return Err(err(
                Code::KeyRelease,
                format!(
                    "key version {} of {asset_id} is revoked",
                    secret.key_version
                ),
            ));
        }
        let b = &s.workload.binding;
        let header = GrantHeader {
            version: GRANT_VERSION,
            broker_id: self.state.broker_id.clone(),
            asset_id: asset_id.to_owned(),
            key_version: secret.key_version,
            policy_id: b.policy_id.clone(),
            execution_spec_id: b.execution_spec_id.clone(),
            session_id: s.info.workload_session_id.clone(),
            binding_hash: s.info.session.clone(),
            attestation_digest: s.info.attestation_digest.clone(),
            expires_at: s.info.expires_at,
        };
        let key = self.store.unwrap_for_release(
            &KeyContext {
                broker_id: &self.state.broker_id,
                asset_id,
                version: secret.key_version,
            },
            &current.key,
        )?;
        seal_grant(header, b, key.as_bytes())
    }

    /// Verify and release in one step (debug CLI).
    pub fn release_with(
        &mut self,
        evidence: &AttestationEvidence,
        asset_id: &str,
    ) -> Result<(VerifiedWorkload, EncryptedKeyGrant)> {
        let info = self.verify_attestation(evidence)?;
        let grant = self.release_key(&info.session, asset_id)?;
        Ok((self.sessions[&info.session].workload.clone(), grant))
    }

    /// Writes the state (secrets included) to `path`, readable by the owner
    /// only.
    pub fn save(&self, path: &Path) -> Result<()> {
        let io = |e: std::io::Error| err(Code::KeyRelease, format!("{}: {e}", path.display()));
        let json = Zeroizing::new(
            serde_json::to_vec_pretty(&self.state)
                .map_err(|e| err(Code::KeyRelease, e.to_string()))?,
        );
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp).map_err(io)?;
            f.write_all(&json).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        std::fs::rename(&tmp, path).map_err(io)
    }

    pub fn load(path: &Path, verifier: Verifier, store: Box<dyn SecretStore>) -> Result<Self> {
        let bytes = Zeroizing::new(
            std::fs::read(path)
                .map_err(|e| err(Code::KeyRelease, format!("{}: {e}", path.display())))?,
        );
        let state: BrokerState = serde_json::from_slice(&bytes)
            .map_err(|e| err(Code::KeyRelease, format!("{}: {e}", path.display())))?;
        check_broker_id(&state.broker_id)?;
        Self::from_state(state, verifier, store)
    }
}
