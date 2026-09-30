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
//!
//! In a governed project the owner's broker is the final release
//! authority: a key bound to a source version is released only through
//! [`KeyBroker::prepare_governed_release`] and
//! [`KeyBroker::finish_release`], with the owner's signed authorization and
//! a control-plane release ticket (see the `governed` module).
//!
//! A broker may keep its state's generation high-water mark in the
//! organization's KMS ([`GenerationMark`], see the `generation` module), so
//! that restoring an older authentic state file is refused. A governed
//! production broker needs one.

mod client;
pub mod generation;
mod governed;
pub mod root;
mod server;
pub mod store;
mod workload;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use encompute_attestation::{
    check_freshness, seal_grant, unix_now, AttestationChallenge, AttestationEvidence,
    AttestationPolicy, EncryptedKeyGrant, GrantHeader, GrantSigner, Security, VerifiedWorkload,
    Verifier, WorkloadSession, GRANT_VERSION,
};
use encompute_ir::{Code, Error, Result};
use encompute_trust::authz::{GovernanceKey, SignedAuthorizationV2};
use encompute_verification::{hex, unhex};

pub use client::BrokerClient;
pub use generation::{
    DevelopmentFileMark, GenerationMark, Mark, MarkRead, OpenBaoKvMark, MARK_UNAVAILABLE,
};
pub use governed::{
    GovernanceConfig, GovernedGrant, GovernedReleaseRequest, PendingRelease,
    MAX_REVOKED_AUTHORIZATIONS,
};
pub use root::{
    DevelopmentRootKey, OpenBaoTransit, RootKeyProvider, RootRotation, RootWrappedKekStore,
    WrappedKek,
};
pub use server::{
    serve, serve_with_control, serve_with_limit, ControlChannel, REQUESTS_PER_MINUTE,
};
pub use store::{
    DevelopmentFileStore, KeyContext, LocalKekStore, SecretStore, StoreSecurity, StoredKey,
};
pub use workload::{acquire_keys, acquire_keys_governed, AcquiredKey, GovernedKeyRequest};

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
    /// The organization the key was protected for: a control plane's
    /// revocation for another organization never touches it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// Hex `AssetVersionId` of the source version this key protects (set
    /// once, never changed). A bound key is governed: it is released only
    /// with its owner's authorization and a release ticket, never on the
    /// plain release path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_version_id: Option<String>,
    /// The asset expired (its owner's retention ended): never released
    /// again.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expired: bool,
}

/// How often an owner authorization has been used at this broker.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthCounter {
    /// Keys released under it.
    pub releases: u64,
    /// Jobs it released keys to (kept only when it limits executions).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub jobs: BTreeSet<String>,
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
    /// The one organization this broker serves (set once).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// The key grants are signed with, wrapped like the asset keys
    /// (created when missing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_signing_key: Option<StoredKey>,
    /// The owner organization's governance key (pinned once by the owner).
    /// Once pinned, the broker is governed: only bound keys are released,
    /// and only through a governed release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_key: Option<GovernanceKey>,
    /// Installed owner authorizations, by ID, each verified under the
    /// pinned governance key when installed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub authorizations: BTreeMap<String, SignedAuthorizationV2>,
    /// Revoked authorizations: ID → the time the revocation takes effect.
    /// Kept after the authorization is gone, so it is never reinstalled.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub revoked_authorizations: BTreeMap<String, u64>,
    /// Use counters per authorization ID.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub counters: BTreeMap<String, AuthCounter>,
    /// Release tickets already used: ticket ID → until when it is kept
    /// (its end plus the clock skew), so each is accepted once.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub seen_tickets: BTreeMap<String, u64>,
    /// Incremented by every save: of two copies of a broker's state, the
    /// one with the lower generation is older. With a [`GenerationMark`]
    /// (the organization's KMS), every save also advances the mark, and a
    /// state older than the mark, or at its generation with another MAC,
    /// is refused: restoring an older authentic copy is detected. Without
    /// one it is informational only, and such a restore is not detected (a
    /// known limitation).
    #[serde(default)]
    pub generation: u64,
    /// Set by every save under a generation mark: the state is then opened
    /// only with its mark, so a mark cannot be dropped to hide a rollback.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub generation_marked: bool,
    /// Under a generation mark: the state MAC the mark recorded when this
    /// state was saved, so a state one save ahead of the mark is accepted
    /// only if it continues the state the mark holds (a hash chain), never
    /// a file from another history that happens to have the next number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_state_mac: Option<String>,
    /// Hex HMAC-SHA256 over every other field, under a key derived from
    /// the store's KEK ([`SecretStore::state_mac`]): an edited state file
    /// does not open, but an older authentic copy (one saved before a
    /// revocation, say) still does. Absent only for development plaintext
    /// storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

/// What the state MAC covers: this domain, then the state (without its
/// MAC) as the broker serializes it, so every field that gates release is
/// authenticated, and an unknown or reordered field changes nothing.
const STATE_MAC_DOMAIN: &[u8] = b"encompute.broker-state.v1\0";

fn state_bytes(state: &BrokerState) -> Result<Zeroizing<Vec<u8>>> {
    let mut s = state.clone();
    s.mac = None;
    let mut b = Zeroizing::new(STATE_MAC_DOMAIN.to_vec());
    serde_json::to_writer(&mut *b, &s).map_err(|e| err(Code::KeyRelease, e.to_string()))?;
    Ok(b)
}

/// Compares a stored state MAC with the expected one in constant time
/// (the `hmac` crate's [`CtOutput`](hmac::digest::CtOutput) equality); a
/// tag of the wrong length never matches.
fn same_mac(a: &[u8], b: &[u8; 32]) -> bool {
    use hmac::digest::{generic_array::GenericArray, CtOutput};
    type StateMac = hmac::Hmac<sha2::Sha256>;
    a.len() == b.len()
        && CtOutput::<StateMac>::new(GenericArray::clone_from_slice(a))
            == CtOutput::<StateMac>::new((*b).into())
}

/// How [`KeyBroker::open`] treats the state's MAC.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StateAuth {
    /// A new broker's state: nothing to check yet.
    New,
    /// The MAC must verify.
    Required,
    /// A state written before states were authenticated: accepted without
    /// a MAC, on its owner's word (`encompute keys upgrade-state`); one
    /// that has a MAC must still verify.
    Legacy,
}

fn authenticate(state: &BrokerState, store: &dyn SecretStore, auth: StateAuth) -> Result<()> {
    let expected = store.state_mac(&state_bytes(state)?)?;
    if expected.is_none() && store.security() == StoreSecurity::Production {
        return Err(err(
            Code::KeyRelease,
            format!(
                "the {} store cannot authenticate the broker state; a broker needs a store \
                 that can",
                store.name()
            ),
        ));
    }
    if auth == StateAuth::New {
        return Ok(());
    }
    match (expected, &state.mac) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(err(
            Code::KeyRelease,
            format!(
                "the {} store cannot authenticate the broker state; open it with the store \
                 that wrapped its keys",
                store.name()
            ),
        )),
        (Some(m), Some(h)) if unhex(h).is_some_and(|h| same_mac(&h, &m)) => Ok(()),
        (Some(_), Some(_)) => Err(err(
            Code::KeyRelease,
            "the broker state fails authentication under this broker's KEK: it was edited \
             outside Encompute (a release policy, the mode, the organization or a key \
             version changed); restore it from a trusted backup",
        )),
        (Some(_), None) if auth == StateAuth::Legacy => Ok(()),
        (Some(_), None) => Err(err(
            Code::KeyRelease,
            "the broker state is not authenticated (written by an earlier Encompute): check \
             its release policies, mode and organization, then run `encompute keys \
             upgrade-state`",
        )),
    }
}

/// The wrap context of the grant-signing key: not a valid asset ID, so it
/// never collides with an asset key's.
const GRANT_KEY_CONTEXT: &str = "#grant-signing-key";

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
    grant_signer: GrantSigner,
    /// The generation of the last state loaded or saved.
    generation: AtomicU64,
    /// The control plane whose release tickets are accepted (governed
    /// release); not part of the state.
    governance: Option<GovernanceConfig>,
    /// The state's generation high-water mark, if configured.
    mark: Option<AttachedMark>,
}

struct AttachedMark {
    mark: Box<dyn GenerationMark>,
    /// The mark's compare-and-set version as this broker last wrote or
    /// read it.
    cas: AtomicU64,
    /// The state MAC the mark holds (the head of the chain): the next save
    /// records it as its `previous_state_mac`.
    head: std::sync::Mutex<String>,
}

/// What the operator expects of the state file when a mark is first
/// created from it (the first start under a mark otherwise trusts the
/// file as found).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedState {
    pub generation: u64,
    /// The state's MAC in hex (for development plaintext storage,
    /// `sha256:` and the SHA-256 of the state), if checked.
    pub state_mac: Option<String>,
}

/// What a generation mark records of a state: its MAC, or (development
/// plaintext storage, which has none) the SHA-256 of what the MAC would
/// cover.
fn state_fingerprint(state: &BrokerState) -> Result<String> {
    match &state.mac {
        Some(m) => Ok(m.clone()),
        None => {
            use sha2::Digest;
            Ok(format!(
                "sha256:{}",
                hex(&sha2::Sha256::digest(state_bytes(state)?.as_slice()))
            ))
        }
    }
}

fn rollback(msg: impl Into<String>) -> Error {
    err(Code::GovernanceBrokerStateRollback, msg)
}

/// A state saved under a generation mark opens only with that mark.
fn refuse_marked(state: &BrokerState) -> Result<()> {
    if state.generation_marked {
        return Err(rollback(
            "this broker's state is guarded by a generation mark in the organization's KMS: \
             open it with its mark (--generation-mark)",
        ));
    }
    Ok(())
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
        Self::open(
            BrokerState {
                broker_id: broker_id.to_owned(),
                mode,
                store: store.name().into(),
                kek_id: store.key_id(),
                secrets: BTreeMap::new(),
                challenges: Vec::new(),
                organization: None,
                grant_signing_key: None,
                governance_key: None,
                authorizations: BTreeMap::new(),
                revoked_authorizations: BTreeMap::new(),
                counters: BTreeMap::new(),
                seen_tickets: BTreeMap::new(),
                generation: 0,
                generation_marked: false,
                previous_state_mac: None,
                mac: None,
            },
            verifier,
            store,
            StateAuth::New,
        )
    }

    /// Reopens a broker; `store` must be the one its keys were stored with,
    /// and the state must carry a valid MAC under its KEK (see
    /// [`BrokerState::mac`]). A state without a grant-signing key gets one
    /// (saved with the state).
    pub fn from_state(
        state: BrokerState,
        verifier: Verifier,
        store: Box<dyn SecretStore>,
    ) -> Result<Self> {
        refuse_marked(&state)?;
        Self::open(state, verifier, store, StateAuth::Required)
    }

    fn open(
        mut state: BrokerState,
        verifier: Verifier,
        store: Box<dyn SecretStore>,
        auth: StateAuth,
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
        authenticate(&state, store.as_ref(), auth)?;
        let broker_id = state.broker_id.clone();
        let ctx = KeyContext {
            broker_id: &broker_id,
            asset_id: GRANT_KEY_CONTEXT,
            version: 0,
        };
        let grant_signer = match &state.grant_signing_key {
            Some(k) => {
                let seed: [u8; 32] = store
                    .unwrap_for_release(&ctx, k)?
                    .as_bytes()
                    .try_into()
                    .map_err(|_| err(Code::KeyRelease, "the grant-signing key is 32 bytes"))?;
                GrantSigner::from_seed(&Zeroizing::new(seed))
            }
            None => {
                let g = GrantSigner::generate()?;
                state.grant_signing_key =
                    Some(store.wrap(&ctx, &KeyMaterial::from_bytes(g.seed().as_slice())?)?);
                g
            }
        };
        Ok(Self {
            generation: AtomicU64::new(state.generation),
            state,
            verifier,
            store,
            sessions: BTreeMap::new(),
            clock: Box::new(unix_now),
            grant_signer,
            governance: None,
            mark: None,
        })
    }

    /// Guards this broker's state with `mark` (see the `generation`
    /// module): the state must not be older than the mark, nor at its
    /// generation with another MAC (ENC2713); one save ahead (the broker
    /// stopped between writing the file and advancing the mark) is
    /// accepted and the mark advanced, but only if that state continues
    /// the one the mark records (its `previous_state_mac` is the mark's
    /// MAC). With no mark yet, the mark is
    /// created from this state: the first start under a mark trusts the
    /// state file. A production broker refuses a development mark, and an
    /// unreachable mark refuses to open (fails closed).
    pub fn with_generation_mark(self, mark: Box<dyn GenerationMark>) -> Result<Self> {
        self.with_generation_mark_expecting(mark, None)
    }

    /// [`with_generation_mark`](KeyBroker::with_generation_mark), and when
    /// no mark exists yet, the state must be what the operator `expected`
    /// (its generation, and its MAC if given), or nothing is written and
    /// the broker does not open (ENC2713). Without an expectation, the
    /// first marking prints the generation and MAC it trusted. Once a mark
    /// exists, the expectation is not used.
    pub fn with_generation_mark_expecting(
        mut self,
        mark: Box<dyn GenerationMark>,
        expected: Option<&ExpectedState>,
    ) -> Result<Self> {
        if self.state.mode == BrokerMode::Production && mark.security() != StoreSecurity::Production
        {
            return Err(err(
                Code::InsecureConfiguration,
                format!(
                    "a production broker cannot keep its generation mark in {} (development only)",
                    mark.describe()
                ),
            ));
        }
        let what = mark.describe();
        let generation = self.state.generation;
        let fingerprint = state_fingerprint(&self.state)?;
        let here = Mark {
            broker_id: self.state.broker_id.clone(),
            generation,
            state_mac: fingerprint.clone(),
        };
        let read = mark.read()?;
        let cas = match read.mark {
            None if self.state.generation_marked => {
                return Err(rollback(format!(
                    "this broker's state was saved under a generation mark, and there is none \
                     at {what}: the mark was deleted or another mark is configured; restore the \
                     mark (KV-v2 keeps its versions) or configure the broker's own"
                )))
            }
            None => {
                match expected {
                    Some(x)
                        if x.generation != generation
                            || x.state_mac.as_ref().is_some_and(|m| *m != fingerprint) =>
                    {
                        return Err(rollback(format!(
                            "the broker state is generation {generation} with MAC {fingerprint}, \
                             not the state expected (generation {}{}): no generation mark was \
                             created; restore the state file you expect",
                            x.generation,
                            x.state_mac
                                .as_deref()
                                .map(|m| format!(", MAC {m}"))
                                .unwrap_or_default()
                        )))
                    }
                    Some(_) => {}
                    None => eprintln!(
                        "generation mark created at {what} from the state file as found \
                         (generation {generation}, MAC {fingerprint}); check it against your \
                         records, and pass --expect-generation (and --expect-state-mac) to \
                         have the first marking check it"
                    ),
                }
                mark.advance(&here, read.cas)?
            }
            Some(m) if generation < m.generation => {
                return Err(rollback(format!(
                    "the broker state is generation {generation}, older than generation {} \
                     recorded at {what}: an older copy of the state file was restored \
                     (revocations, used tickets or counters since then would be lost); restore \
                     the latest state file",
                    m.generation
                )))
            }
            Some(m) if generation == m.generation => {
                if m.state_mac != fingerprint {
                    return Err(rollback(format!(
                        "the broker state is generation {generation}, as recorded at {what}, but \
                         another state was saved under that generation: the state forked; \
                         restore the state file that was saved last"
                    )));
                }
                read.cas
            }
            Some(m) if generation == m.generation + 1 => {
                // One save ahead: the broker stopped between writing the
                // file and advancing the mark. Only the state that
                // continues the mark's is that write.
                if self.state.previous_state_mac.as_deref() != Some(m.state_mac.as_str()) {
                    return Err(rollback(format!(
                        "the broker state is generation {generation}, one save ahead of {what}, \
                         but it is not chained to the state the mark records: it comes from \
                         another history; restore the state file that was saved last"
                    )));
                }
                mark.advance(&here, read.cas)?
            }
            Some(m) => {
                return Err(rollback(format!(
                    "the broker state is generation {generation}, more than one save ahead of \
                     generation {} recorded at {what}: it was saved without its mark",
                    m.generation
                )))
            }
        };
        self.mark = Some(AttachedMark {
            mark,
            cas: AtomicU64::new(cas),
            head: std::sync::Mutex::new(fingerprint),
        });
        Ok(self)
    }

    /// Whether a generation mark guards this broker's state.
    pub fn has_generation_mark(&self) -> bool {
        self.mark.is_some()
    }

    /// Whether this broker must have a generation mark: a governed broker
    /// (governance key pinned) in production mode.
    pub fn requires_generation_mark(&self) -> bool {
        self.state.governance_key.is_some() && self.state.mode == BrokerMode::Production
    }

    /// Refuses (ENC2605) a governed production broker without a generation
    /// mark: its counters, used tickets and revocations could otherwise be
    /// undone by restoring an older state file.
    pub fn check_generation_mark(&self) -> Result<()> {
        if self.requires_generation_mark() && self.mark.is_none() {
            return Err(err(
                Code::InsecureConfiguration,
                "a governed production broker needs a generation mark in the organization's KMS \
                 (--generation-mark openbao --kv-mount MOUNT), so that an older copy of its \
                 state is refused",
            ));
        }
        Ok(())
    }

    /// The hex Ed25519 key this broker signs grants with: workloads pin it.
    pub fn grant_public_key(&self) -> String {
        self.grant_signer.public_key_hex()
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

    /// The organization this broker serves, if set.
    pub fn organization(&self) -> Option<&str> {
        self.state.organization.as_deref()
    }

    /// Sets the one organization this broker serves. It is set once: a
    /// broker holding one organization's keys never switches to another.
    /// Keys protected before it was set are recorded for it (the operator
    /// asserts the broker serves this organization).
    pub fn set_organization(&mut self, organization: &str) -> Result<()> {
        check_broker_id(organization)?;
        match self.state.organization.as_deref() {
            Some(o) if o == organization => Ok(()),
            Some(o) => Err(err(
                Code::KeyRelease,
                format!("this broker serves organization {o:?}, not {organization:?}"),
            )),
            None => {
                self.state.organization = Some(organization.to_owned());
                for s in self.state.secrets.values_mut() {
                    s.organization
                        .get_or_insert_with(|| organization.to_owned());
                }
                Ok(())
            }
        }
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
                organization: self.state.organization.clone(),
                asset_version_id: None,
                expired: false,
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

    /// A control plane's revocation on behalf of `organization`: revokes
    /// every version of `asset_id` only if this broker serves that
    /// organization and recorded the key for it. Idempotent; returns the
    /// versions revoked now.
    pub fn revoke_for(&mut self, organization: &str, asset_id: &str) -> Result<Vec<u64>> {
        if self.state.organization.as_deref() != Some(organization) {
            return Err(err(
                Code::ServiceAuthentication,
                format!(
                    "this broker does not serve organization {organization:?}; no key was revoked"
                ),
            ));
        }
        match self.state.secrets.get(asset_id) {
            Some(s) if s.organization.as_deref() == Some(organization) => self.revoke_all(asset_id),
            _ => Err(err(
                Code::KeyRelease,
                format!("no key for asset {asset_id} of organization {organization}"),
            )),
        }
    }

    /// A control plane's notice, on behalf of `organization`, that
    /// `asset_id` expired (its retention ended): it is never released
    /// again. Only for the organization this broker serves; idempotent.
    pub fn expire_for(&mut self, organization: &str, asset_id: &str) -> Result<()> {
        if self.state.organization.as_deref() != Some(organization) {
            return Err(err(
                Code::ServiceAuthentication,
                format!("this broker does not serve organization {organization:?}"),
            ));
        }
        match self.state.secrets.get_mut(asset_id) {
            Some(s) if s.organization.as_deref() == Some(organization) => {
                s.expired = true;
                Ok(())
            }
            _ => Err(err(
                Code::KeyRelease,
                format!("no key for asset {asset_id} of organization {organization}"),
            )),
        }
    }

    /// Revokes every version of `asset_id`: idempotent, returns the
    /// versions revoked now.
    pub fn revoke_all(&mut self, asset_id: &str) -> Result<Vec<u64>> {
        let versions: Vec<u64> = self
            .state
            .secrets
            .get(asset_id)
            .ok_or_else(|| err(Code::KeyRelease, format!("no key for asset {asset_id}")))?
            .versions
            .iter()
            .filter(|(_, v)| !v.revoked)
            .map(|(k, _)| *k)
            .collect();
        for v in &versions {
            self.revoke(asset_id, Some(*v))?;
        }
        Ok(versions)
    }

    /// Revokes a version (default: the current one). A revoked current key
    /// is never released; rotate to release again. Restoring a state file
    /// saved before the revocation undoes it, undetected unless a
    /// generation mark guards the state (see
    /// [`load_with_mark`](KeyBroker::load_with_mark)).
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
        let grant_signing_key = match &self.state.grant_signing_key {
            Some(k) => Some(store.rotate(
                &KeyContext {
                    broker_id: &broker_id,
                    asset_id: GRANT_KEY_CONTEXT,
                    version: 0,
                },
                k,
                self.store.as_ref(),
            )?),
            None => None,
        };
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
        self.state.grant_signing_key = grant_signing_key;
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
        // A used ticket is kept until its window (and the skew) is over:
        // after that it is refused as expired anyway.
        self.state.seen_tickets.retain(|_, until| *until >= now);
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
        // A governed key, or any key of a governed broker, is released only
        // with its owner's authorization and a release ticket.
        if secret.asset_version_id.is_some() || self.state.governance_key.is_some() {
            return Err(err(
                Code::GovernanceAuthorizationMissing,
                format!(
                    "the key of {asset_id} is released only in a governed release, with its \
                     owner's authorization and a release ticket"
                ),
            ));
        }
        if secret.expired {
            return Err(err(Code::KeyRelease, format!("{asset_id} has expired")));
        }
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
            broker_public_key: self.grant_signer.public_key_hex(),
            governance: None,
        };
        let key = self.store.unwrap_for_release(
            &KeyContext {
                broker_id: &self.state.broker_id,
                asset_id,
                version: secret.key_version,
            },
            &current.key,
        )?;
        seal_grant(header, b, key.as_bytes(), &self.grant_signer)
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
    /// only, under the next generation and authenticated under the store's
    /// KEK. The MAC stops edits, not a later restore of this file over a
    /// newer one; a generation mark stops that (see
    /// [`with_generation_mark`](KeyBroker::with_generation_mark)).
    ///
    /// With a mark, the file is written first, then the mark advanced with
    /// compare-and-set, and only then does `save` succeed: a caller grants
    /// or acknowledges nothing before. If the mark cannot be advanced
    /// (unreachable, or advanced by someone else), `save` fails with
    /// ENC2713 and the broker's generation stays, so the next save rewrites
    /// the same generation; what was recorded in memory (a spent ticket, a
    /// counted release) stays recorded.
    pub fn save(&self, path: &Path) -> Result<()> {
        let io = |e: std::io::Error| err(Code::KeyRelease, format!("{}: {e}", path.display()));
        let mut state = self.state.clone();
        state.generation = match &self.mark {
            Some(_) => {
                state.generation_marked = true;
                state.previous_state_mac = self
                    .mark
                    .as_ref()
                    .map(|m| m.head.lock().unwrap_or_else(|p| p.into_inner()).clone());
                self.generation.load(Ordering::SeqCst) + 1
            }
            None => self.generation.fetch_add(1, Ordering::SeqCst) + 1,
        };
        state.mac = self
            .store
            .state_mac(&state_bytes(&state)?)?
            .map(|m| hex(&m));
        let json = Zeroizing::new(
            serde_json::to_vec_pretty(&state).map_err(|e| err(Code::KeyRelease, e.to_string()))?,
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
            // The mode above applies only to a new file: a leftover one
            // keeps its own, so set it before writing any key.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(io)?;
            }
            f.write_all(&json).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        std::fs::rename(&tmp, path).map_err(io)?;
        if let Some(m) = &self.mark {
            let next = Mark {
                broker_id: state.broker_id.clone(),
                generation: state.generation,
                state_mac: state_fingerprint(&state)?,
            };
            let cas = m.mark.advance(&next, m.cas.load(Ordering::SeqCst))?;
            m.cas.store(cas, Ordering::SeqCst);
            *m.head.lock().unwrap_or_else(|p| p.into_inner()) = next.state_mac;
            self.generation.store(state.generation, Ordering::SeqCst);
        }
        Ok(())
    }

    /// Opens the state at `path`: it must be authenticated under `store`'s
    /// KEK, so an edited file (a widened release policy, a flipped mode, a
    /// cleared revocation) is refused. A rollback is not: restoring an
    /// older authentic copy of the file (one saved before a revocation)
    /// is not detected here, and its revoked versions are released again.
    /// Open with [`load_with_mark`](KeyBroker::load_with_mark) to detect
    /// it; a state saved under a mark is refused here (ENC2713).
    pub fn load(path: &Path, verifier: Verifier, store: Box<dyn SecretStore>) -> Result<Self> {
        let state = Self::read(path)?;
        refuse_marked(&state)?;
        Self::open(state, verifier, store, StateAuth::Required)
    }

    /// Opens the state at `path` as [`load`](KeyBroker::load) does, then
    /// checks it against its generation mark: an older authentic copy, or a
    /// fork, is refused (ENC2713), and an unreachable mark refuses to open
    /// (see [`with_generation_mark`](KeyBroker::with_generation_mark)).
    pub fn load_with_mark(
        path: &Path,
        verifier: Verifier,
        store: Box<dyn SecretStore>,
        mark: Box<dyn GenerationMark>,
    ) -> Result<Self> {
        Self::load_with_mark_expecting(path, verifier, store, mark, None)
    }

    /// [`load_with_mark`](KeyBroker::load_with_mark), checking the state
    /// against what the operator `expected` when no mark exists yet (see
    /// [`with_generation_mark_expecting`](KeyBroker::with_generation_mark_expecting)).
    pub fn load_with_mark_expecting(
        path: &Path,
        verifier: Verifier,
        store: Box<dyn SecretStore>,
        mark: Box<dyn GenerationMark>,
        expected: Option<&ExpectedState>,
    ) -> Result<Self> {
        Self::open(Self::read(path)?, verifier, store, StateAuth::Required)?
            .with_generation_mark_expecting(mark, expected)
    }

    /// Opens a state file written before broker states were authenticated,
    /// on its owner's word that it has not been edited (after checking its
    /// release policies, mode and organization): the next [`save`] adds
    /// the MAC. A state that has a MAC must still verify.
    ///
    /// [`save`]: KeyBroker::save
    pub fn load_legacy(
        path: &Path,
        verifier: Verifier,
        store: Box<dyn SecretStore>,
    ) -> Result<Self> {
        let state = Self::read(path)?;
        refuse_marked(&state)?;
        Self::open(state, verifier, store, StateAuth::Legacy)
    }

    fn read(path: &Path) -> Result<BrokerState> {
        let bytes = Zeroizing::new(
            std::fs::read(path)
                .map_err(|e| err(Code::KeyRelease, format!("{}: {e}", path.display())))?,
        );
        let state: BrokerState = serde_json::from_slice(&bytes)
            .map_err(|e| err(Code::KeyRelease, format!("{}: {e}", path.display())))?;
        check_broker_id(&state.broker_id)?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::same_mac;

    #[test]
    fn a_state_mac_matches_only_itself() {
        let m = [7u8; 32];
        assert!(same_mac(&m, &m));
        let mut other = m;
        other[31] ^= 1;
        assert!(!same_mac(&other, &m));
        assert!(!same_mac(&m[..31], &m));
        assert!(!same_mac(&[7u8; 33], &m));
        assert!(!same_mac(&[], &m));
    }
}
