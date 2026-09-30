//! The state anchor: the latest privacy-ledger roots and audit root, signed
//! by the control plane and kept **outside** the database.
//!
//! Restoring an older database backup rewinds the database, not the
//! anchor. At startup the database must extend the anchor: every ledger
//! must contain the anchored entry, and the audit chain the anchored event.
//! If not, the control plane refuses to start (PRIVACY STATE ROLLBACK /
//! AUDIT STATE ROLLBACK) until an operator restores the missing entries
//! from a newer export; it never silently accepts forgotten spending.
//!
//! The anchor is updated after each privacy spend commits (synchronously,
//! before the spend is acknowledged) and at each audit checkpoint. A crash
//! between the two leaves the database *ahead* of the anchor, which is
//! allowed; only *behind* is a rollback. The anchor only ever moves
//! forward along the same chain: a ledger checkpoint or audit root that
//! does not extend the anchored one is refused, while the service runs as
//! well as at startup.
//!
//! Security-negative transitions are anchored too (revoked assets, frozen
//! ledgers, disabled service accounts and users, cancelled and failed
//! jobs, withdrawn asset approvals, removed project memberships, removed
//! organization roles, revoked owner authorizations, expired assets), so a
//! restored database cannot silently undo them.
//!
//! One control plane process per anchor: updates are compare-and-set on the
//! counter, and a process whose update lost the race reloads the stored
//! anchor and re-applies its change.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use encompute_ir::{Code, Error, Result};
use encompute_privacy::Checkpoint;
use encompute_verification::service::{verify_signed, ServiceSigner, STATE_ANCHOR};

use crate::config::AnchorConfig;

pub const ANCHOR_VERSION: u32 = 1;

/// Serialized anchor size above which every anchor write (and the start)
/// logs an `anchor_size_warning`. The anchor holds every ended job and
/// every disable, withdrawal and removal, and each write re-signs all of
/// it; an OpenBao KV entry is limited by the raft `max_entry_size` (1 MiB
/// by default), past which anchor writes fail and the control plane fails
/// closed. Half of that leaves time to act.
pub const ANCHOR_WARN_BYTES: u64 = 512 * 1024;

/// The anchor's size as written: its compact JSON serialization (what the
/// OpenBao KV store holds as one string; the directory store writes it
/// pretty-printed, somewhat larger).
pub fn serialized_len(a: &StateAnchor) -> u64 {
    serde_json::to_vec(a).map_or(0, |v| v.len() as u64)
}

/// Logs that the anchor outgrew [`ANCHOR_WARN_BYTES`] (nothing otherwise).
pub fn warn_if_large(service: &str, when: &str, bytes: u64) {
    if bytes > ANCHOR_WARN_BYTES {
        crate::log::LogLine::new(service, "anchor_size_warning")
            .field("when", when)
            .field("anchor_bytes", bytes)
            .field("threshold_bytes", ANCHOR_WARN_BYTES)
            .field(
                "action",
                "the state anchor is growing towards the anchor store's entry size limit (OpenBao raft max_entry_size, 1 MiB by default), past which anchor writes fail and the control plane refuses privacy spends and other anchored operations; raise max_entry_size, and plan for the governance event log that replaces the anchored sets (see docs/deployment.md)",
            )
            .emit();
    }
}

fn anchor_err(m: impl Into<String>) -> Error {
    Error::new(Code::PrivacyLedger, m)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateAnchor {
    pub version: u32,
    /// Increases with every update.
    pub counter: u64,
    pub audit_seq: i64,
    pub audit_root: String,
    /// Asset ID → the ledger's checkpoint (entry count and root).
    pub ledgers: BTreeMap<String, Checkpoint>,
    /// Ledgers frozen by an operator's recovery after a rollback (treated
    /// as exhausted, whatever the database says).
    #[serde(default)]
    pub frozen: BTreeSet<String>,
    /// Revoked assets: a restored database must still show them revoked.
    /// (This and the sets below are omitted while empty, so anchors written
    /// before them still verify.)
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub revoked: BTreeSet<String>,
    /// Disabled service accounts: a restored database must still show them
    /// disabled (or not hold them).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub disabled_services: BTreeSet<String>,
    /// Disabled users, likewise.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub disabled_users: BTreeSet<String>,
    /// Cancelled and failed jobs: never scheduled or started again.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub ended_jobs: BTreeSet<String>,
    /// Withdrawn asset approvals and ended grants (approval and grant IDs,
    /// never reused): a restored database must not hold them again.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub withdrawn_grants: BTreeSet<String>,
    /// Project memberships (and invitations) removed (membership IDs, never
    /// reused): a restored database must not list them again.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub removed_memberships: BTreeSet<String>,
    /// Organization roles removed from principals (role membership IDs,
    /// never reused): a restored database must not hold them again.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub removed_roles: BTreeSet<String>,
    /// Revoked owner authorizations of governed projects (row IDs, never
    /// reused): a restored database must still show them revoked. A key
    /// broker is told of a revocation only once it is here.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub revoked_authorizations: BTreeSet<String>,
    /// Expired assets (their owner's retention ended): a restored database
    /// must still show them expired, and a key broker is told only once
    /// they are here.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub expired_assets: BTreeSet<String>,
    /// Rows of the sets above that the database lost (deleted, or never
    /// restored), acknowledged by an operator's recovery, as `set:id`. A
    /// row missing without this is a rollback like one shown undone; with
    /// it, the ID stays blocked (IDs are never reused), and a row that
    /// comes back must still show the anchored state.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub lost: BTreeSet<String>,
    pub signer: String,
    pub signer_public_key: String,
    #[serde(default)]
    pub signature: String,
}

impl StateAnchor {
    pub fn empty(signer: &ServiceSigner) -> Self {
        Self {
            version: ANCHOR_VERSION,
            counter: 0,
            audit_seq: 0,
            audit_root: crate::audit::GENESIS.into(),
            ledgers: BTreeMap::new(),
            frozen: Default::default(),
            revoked: Default::default(),
            disabled_services: Default::default(),
            disabled_users: Default::default(),
            ended_jobs: Default::default(),
            withdrawn_grants: Default::default(),
            removed_memberships: Default::default(),
            removed_roles: Default::default(),
            revoked_authorizations: Default::default(),
            expired_assets: Default::default(),
            lost: Default::default(),
            signer: signer.id().into(),
            signer_public_key: signer.public_key_hex(),
            signature: String::new(),
        }
    }

    fn statement(&self) -> StateAnchor {
        StateAnchor {
            signature: String::new(),
            ..self.clone()
        }
    }

    fn sign(&mut self, signer: &ServiceSigner) -> Result<()> {
        self.signer = signer.id().into();
        self.signer_public_key = signer.public_key_hex();
        self.signature = signer.sign(STATE_ANCHOR, &self.statement())?;
        Ok(())
    }

    /// Checks the signature is by `public_key` (the control plane's key).
    pub fn verify(&self, public_key: &str) -> Result<()> {
        if self.version != ANCHOR_VERSION {
            return Err(anchor_err(format!("state anchor version {}", self.version)));
        }
        if self.signer_public_key != public_key {
            return Err(anchor_err(
                "the state anchor was signed by another key than this control plane's",
            ));
        }
        verify_signed(public_key, STATE_ANCHOR, &self.statement(), &self.signature)
            .map_err(|_| anchor_err("the state anchor's signature is invalid (tampered)"))
    }
}

/// Where the anchor is kept. Updates are compare-and-set on the counter.
pub trait AnchorStore: Send + Sync {
    fn describe(&self) -> String;
    fn load(&self) -> Result<Option<StateAnchor>>;
    /// Stores `next` if the stored anchor's counter is still `expected`.
    fn store(&self, next: &StateAnchor, expected: u64) -> Result<()>;
}

/// A file in a directory on a separate volume.
pub struct DirAnchor {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl DirAnchor {
    pub fn new(dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&dir).map_err(|e| anchor_err(format!("{}: {e}", dir.display())))?;
        Ok(Self {
            dir,
            lock: Mutex::new(()),
        })
    }

    fn path(&self) -> PathBuf {
        self.dir.join("state-anchor.json")
    }
}

impl AnchorStore for DirAnchor {
    fn describe(&self) -> String {
        format!("file {}", self.path().display())
    }

    fn load(&self) -> Result<Option<StateAnchor>> {
        let p = self.path();
        if !p.exists() {
            return Ok(None);
        }
        let b = std::fs::read(&p).map_err(|e| anchor_err(format!("{}: {e}", p.display())))?;
        serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| anchor_err(format!("{}: {e}", p.display())))
    }

    fn store(&self, next: &StateAnchor, expected: u64) -> Result<()> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let current = self.load()?.map_or(0, |a| a.counter);
        if current != expected {
            return Err(anchor_err(format!(
                "the state anchor changed concurrently (counter {current}, expected {expected})"
            )));
        }
        let p = self.path();
        let tmp = self.dir.join("state-anchor.json.tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| anchor_err(format!("{}: {e}", tmp.display())))?;
            f.write_all(&serde_json::to_vec_pretty(next).expect("serializable"))
                .and_then(|_| f.sync_all())
                .map_err(|e| anchor_err(format!("{}: {e}", tmp.display())))?;
        }
        std::fs::rename(&tmp, &p).map_err(|e| anchor_err(format!("{}: {e}", p.display())))
    }
}

/// OpenBao/Vault KV version 2, using its check-and-set versions.
pub struct OpenBaoKvAnchor {
    addr: String,
    mount: String,
    path: String,
    token: Zeroizing<String>,
    agent: ureq::Agent,
}

impl OpenBaoKvAnchor {
    pub fn new(addr: &str, mount: &str, path: &str, token: Zeroizing<String>) -> Self {
        Self {
            addr: addr.trim_end_matches('/').into(),
            mount: mount.into(),
            path: path.into(),
            token,
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(10))
                .build(),
        }
    }

    fn url(&self) -> String {
        format!("{}/v1/{}/data/{}", self.addr, self.mount, self.path)
    }

    /// (anchor, KV version)
    fn read(&self) -> Result<Option<(StateAnchor, u64)>> {
        match self
            .agent
            .get(&self.url())
            .set("X-Vault-Token", &self.token)
            .call()
        {
            Ok(r) => {
                let v: serde_json::Value = r
                    .into_json()
                    .map_err(|e| anchor_err(format!("anchor store: {e}")))?;
                let version = v["data"]["metadata"]["version"].as_u64().unwrap_or(0);
                let a = v["data"]["data"]["anchor"]
                    .as_str()
                    .ok_or_else(|| anchor_err("anchor store: malformed entry"))?;
                Ok(Some((
                    serde_json::from_str(a)
                        .map_err(|e| anchor_err(format!("anchor store: {e}")))?,
                    version,
                )))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(anchor_err(format!(
                "anchor store {} unavailable: {e}",
                self.addr
            ))),
        }
    }
}

impl AnchorStore for OpenBaoKvAnchor {
    fn describe(&self) -> String {
        format!("openbao-kv {}/{}/{}", self.addr, self.mount, self.path)
    }

    fn load(&self) -> Result<Option<StateAnchor>> {
        Ok(self.read()?.map(|(a, _)| a))
    }

    fn store(&self, next: &StateAnchor, expected: u64) -> Result<()> {
        let (current, kv_version) = match self.read()? {
            Some((a, v)) => (a.counter, v),
            None => (0, 0),
        };
        if current != expected {
            return Err(anchor_err(format!(
                "the state anchor changed concurrently (counter {current}, expected {expected})"
            )));
        }
        let body = serde_json::json!({
            "options": {"cas": kv_version},
            "data": {"anchor": serde_json::to_string(next).expect("serializable")},
        });
        self.agent
            .post(&self.url())
            .set("X-Vault-Token", &self.token)
            .send_json(body)
            .map(|_| ())
            .map_err(|e| anchor_err(format!("anchor store {}: {e}", self.addr)))
    }
}

pub fn open_store(c: &AnchorConfig) -> Result<Box<dyn AnchorStore>> {
    Ok(match c {
        AnchorConfig::Dir(d) => Box::new(DirAnchor::new(d.clone())?),
        AnchorConfig::OpenBaoKv {
            addr,
            mount,
            path,
            token,
        } => Box::new(OpenBaoKvAnchor::new(addr, mount, path, token.clone())),
    })
}

/// The anchor in memory, serialized updates, persisted before returning.
pub struct Anchor {
    store: Box<dyn AnchorStore>,
    state: Mutex<StateAnchor>,
    /// [`serialized_len`] of the anchor as last loaded or written.
    bytes: AtomicU64,
}

impl Anchor {
    /// Loads (and verifies) the stored anchor, or starts an empty one.
    pub fn open(store: Box<dyn AnchorStore>, signer: &ServiceSigner) -> Result<(Self, bool)> {
        let (state, existed) = match store.load()? {
            Some(a) => {
                a.verify(&signer.public_key_hex())?;
                (a, true)
            }
            None => (StateAnchor::empty(signer), false),
        };
        let bytes = AtomicU64::new(serialized_len(&state));
        Ok((
            Self {
                store,
                state: Mutex::new(state),
                bytes,
            },
            existed,
        ))
    }

    /// The anchor's serialized size as last loaded or written (the
    /// `encompute_anchor_bytes` gauge).
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> StateAnchor {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn describe(&self) -> String {
        self.store.describe()
    }

    /// Applies `f` and persists the result (counter + 1, re-signed).
    pub fn update(
        &self,
        signer: &ServiceSigner,
        f: impl Fn(&mut StateAnchor),
    ) -> Result<StateAnchor> {
        self.try_update(signer, |a| {
            f(a);
            Ok(true)
        })
    }

    /// Applies `f` under the anchor's lock; persists the result (counter +
    /// 1, re-signed) when `f` returns `Ok(true)`, keeps the anchor as it is
    /// on `Ok(false)` or an error. Checks that must see the anchor exactly
    /// as it will be updated (a rollback check, say) belong in `f`.
    ///
    /// If another process changed the stored anchor meanwhile (its counter
    /// moved), the stored anchor is reloaded (and verified) and `f` applied
    /// to it again, a few times at most.
    pub fn try_update(
        &self,
        signer: &ServiceSigner,
        mut f: impl FnMut(&mut StateAnchor) -> Result<bool>,
    ) -> Result<StateAnchor> {
        let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut attempt = 0;
        loop {
            let mut next = g.clone();
            if !f(&mut next)? {
                return Ok(g.clone());
            }
            next.counter = g.counter + 1;
            next.sign(signer)?;
            // Measured before the write, so a write the store refuses for
            // its size is still reported.
            let bytes = serialized_len(&next);
            warn_if_large(signer.id(), "write", bytes);
            match self.store.store(&next, g.counter) {
                Ok(()) => {
                    self.bytes.store(bytes, Ordering::Relaxed);
                    *g = next.clone();
                    return Ok(next);
                }
                Err(e) if attempt < 3 && e.message.contains("changed concurrently") => {
                    attempt += 1;
                    let stored = self
                        .store
                        .load()?
                        .ok_or_else(|| anchor_err("the state anchor disappeared"))?;
                    stored.verify(&signer.public_key_hex())?;
                    if stored.counter < g.counter {
                        return Err(anchor_err(format!(
                            "the stored state anchor went back from counter {} to {}",
                            g.counter, stored.counter
                        )));
                    }
                    *g = stored;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> ServiceSigner {
        ServiceSigner::from_seed("control-plane", &[7; 32]).unwrap()
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "encompute-anchor-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Review finding CP-S-4 (ENC-SF-2026-039): the anchored sets of disabled principals and
    /// ended jobs are optional, so an anchor written by 0.3.0-rc.3 (without
    /// them) still loads and verifies, and they are signed once present.
    #[test]
    fn anchors_without_the_new_sets_still_verify() {
        let s = signer();
        let mut a = StateAnchor::empty(&s);
        a.revoked.insert("ast_1".into());
        a.sign(&s).unwrap();
        let v = serde_json::to_value(&a).unwrap();
        for k in [
            "disabled_services",
            "disabled_users",
            "ended_jobs",
            "withdrawn_grants",
            "removed_memberships",
            "removed_roles",
            "revoked_authorizations",
            "expired_assets",
            "lost",
        ] {
            assert!(v.get(k).is_none(), "{k} serialized while empty");
        }
        let back: StateAnchor = serde_json::from_value(v).unwrap();
        back.verify(&s.public_key_hex()).unwrap();
        // Once present, they are covered by the signature.
        let mut a = back;
        a.ended_jobs.insert("job_1".into());
        a.sign(&s).unwrap();
        a.verify(&s.public_key_hex()).unwrap();
        let mut tampered = serde_json::to_value(&a).unwrap();
        tampered["ended_jobs"] = serde_json::json!([]);
        let t: StateAnchor = serde_json::from_value(tampered).unwrap();
        assert!(t.verify(&s.public_key_hex()).is_err());
    }

    /// Review finding CP-S-8 (ENC-SF-2026-083): an update that lost the compare-and-set race
    /// (another process moved the stored anchor) reloads the stored
    /// anchor, re-applies its change and keeps both; rc.3 failed every
    /// later update.
    #[test]
    fn a_lost_compare_and_set_reloads_and_reapplies() {
        let s = signer();
        let dir = tmp("cas");
        let (a1, _) = Anchor::open(Box::new(DirAnchor::new(dir.clone()).unwrap()), &s).unwrap();
        a1.update(&s, |_| {}).unwrap();
        let (a2, existed) =
            Anchor::open(Box::new(DirAnchor::new(dir.clone()).unwrap()), &s).unwrap();
        assert!(existed);
        a1.update(&s, |x| {
            x.revoked.insert("ast_a".into());
        })
        .unwrap();
        let after = a2
            .update(&s, |x| {
                x.disabled_users.insert("usr_b".into());
            })
            .unwrap();
        assert!(
            after.revoked.contains("ast_a"),
            "the other process's change is kept"
        );
        assert!(after.disabled_users.contains("usr_b"));
        let stored = DirAnchor::new(dir).unwrap().load().unwrap().unwrap();
        stored.verify(&s.public_key_hex()).unwrap();
        assert_eq!(stored, after);
        // A refused change stores nothing.
        let before = a2.snapshot();
        assert!(a2.try_update(&s, |_| Err(anchor_err("refused"))).is_err());
        assert_eq!(
            a2.try_update(&s, |_| Ok(false)).unwrap().counter,
            before.counter
        );
        assert_eq!(a2.snapshot(), before);
    }
}
