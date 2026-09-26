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
//! allowed; only *behind* is a rollback.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use encompute_ir::{Code, Error, Result};
use encompute_privacy::Checkpoint;
use encompute_verification::service::{verify_signed, ServiceSigner, STATE_ANCHOR};

use crate::config::AnchorConfig;

pub const ANCHOR_VERSION: u32 = 1;

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
    /// as exhausted).
    #[serde(default)]
    pub frozen: std::collections::BTreeSet<String>,
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
        Ok((
            Self {
                store,
                state: Mutex::new(state),
            },
            existed,
        ))
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
        f: impl FnOnce(&mut StateAnchor),
    ) -> Result<StateAnchor> {
        let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut next = g.clone();
        f(&mut next);
        next.counter = g.counter + 1;
        next.sign(signer)?;
        self.store.store(&next, g.counter)?;
        *g = next.clone();
        Ok(next)
    }

    /// Records a ledger checkpoint if it is newer than the anchored one.
    pub fn record_ledger(
        &self,
        signer: &ServiceSigner,
        asset: &str,
        cp: &Checkpoint,
    ) -> Result<()> {
        if self
            .snapshot()
            .ledgers
            .get(asset)
            .is_some_and(|a| a.seq >= cp.seq)
        {
            return Ok(());
        }
        self.update(signer, |a| {
            let newer = a.ledgers.get(asset).is_none_or(|x| x.seq < cp.seq);
            if newer {
                a.ledgers.insert(asset.into(), cp.clone());
            }
        })
        .map(|_| ())
    }
}
