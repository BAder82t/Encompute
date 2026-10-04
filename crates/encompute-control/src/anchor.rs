//! The state anchor: the audit root and the governance event log's head,
//! signed by the control plane and kept **outside** the database.
//!
//! Restoring an older database backup rewinds the database, not the
//! anchor. At startup the database must extend the anchor: the audit chain
//! must contain the anchored event and the governance event log the
//! anchored head at the anchored size; and because the log holds every
//! privacy ledger's latest checkpoint, each ledger must then contain the
//! entry its checkpoint names. If not, the control plane refuses to start
//! (PRIVACY, AUDIT or GOVERNANCE LOG STATE ROLLBACK) until an operator
//! restores the missing entries from a newer export; it never silently
//! accepts forgotten spending or a forgotten revocation.
//!
//! The anchor is updated after each privacy spend commits (synchronously,
//! before the spend is acknowledged: the spend's ledger checkpoint is a
//! log event, and the log is checkpointed), at each audit checkpoint and
//! after each security-negative transition. A crash between the two leaves
//! the database *ahead* of the anchor, which is allowed; only *behind* is a
//! rollback. The anchor only ever moves forward along the same chains: a
//! ledger that does not extend its latest checkpoint, an audit root or a
//! log head that does not extend the anchored one is refused, while the
//! service runs as well as at startup.
//!
//! Security-negative transitions (revoked or expired assets, frozen
//! ledgers, disabled service accounts and users, cancelled and failed
//! jobs, withdrawn asset approvals, removed project memberships and
//! organization roles, revoked owner authorizations, retired purposes,
//! revoked governance keys) are events of the governance log
//! (`crate::govlog`), and so are the privacy ledgers' checkpoints
//! (`privacy.ledger_checkpoint`); the anchor holds only the log's size and
//! head, so its size is constant: it does not grow with assets,
//! revocations or spends. (Version 1 held all of it as sets of IDs and one
//! checkpoint per ledger; [`StateAnchorV1`] is read only to migrate it,
//! once, see `Control::with_parts`.)
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
use encompute_verification::service::{
    sha256_hex, verify_signed, ServiceSigner, STATE_ANCHOR, STATE_ANCHOR_V2,
};

use crate::config::AnchorConfig;

/// The version this release writes while the governance log mirror has
/// never been compacted.
pub const ANCHOR_VERSION: u32 = 2;
/// The version of an anchor that holds a [`Seal`] (the mirror was
/// compacted): written by the first compaction and never before, so a
/// deployment that does not compact keeps an anchor the previous release
/// still reads, and a release that does not know seals refuses one that
/// holds a seal (it would otherwise treat the mirror's missing prefix as
/// truncation, or worse, not know which events the archive must hold).
pub const ANCHOR_SEALED_VERSION: u32 = 3;
/// The version read only to migrate it.
pub const ANCHOR_V1_VERSION: u32 = 1;

/// Serialized anchor size above which every anchor write (and the start)
/// logs an `anchor_size_warning`. The anchor is constant in size (its
/// fields are fixed: security-negative transitions and privacy ledger
/// checkpoints are governance log events), far below any anchor store's
/// entry limit (OpenBao's raft `max_entry_size`, 1 MiB by default); the
/// warning and the `encompute_anchor_bytes` gauge stay as a tripwire.
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
                "the state anchor is growing towards the anchor store's entry size limit (OpenBao raft max_entry_size, 1 MiB by default), past which anchor writes fail and the control plane refuses privacy spends and other anchored operations; its size should be constant: investigate (see docs/deployment.md)",
            )
            .emit();
    }
}

fn anchor_err(m: impl Into<String>) -> Error {
    Error::new(Code::PrivacyLedger, m)
}

/// The head of an empty governance log (no event yet).
pub fn empty_log_head() -> String {
    encompute_trust::govlog::hash_hex(&encompute_trust::govlog::CHAIN_GENESIS)
}

/// The anchor a version-1 anchor was migrated from: its counter and the
/// SHA-256 of its canonical JSON (signature included), which the log's
/// `anchor.genesis` event records too.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigratedFrom {
    pub counter: u64,
    pub digest: String,
}

/// What the anchor holds of a compacted mirror: the log's size and chain
/// head at the compaction (`size` events, the last one's hash `head`) and
/// the SHA-256 of the archive manifest (see [`crate::archive`]). The
/// events up to `size` are in the archive, not in the mirror; the
/// mirror's tail starts at event `size + 1` and chains from `head`.
/// Constant size, however many events are sealed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seal {
    pub size: i64,
    pub head: String,
    pub manifest: String,
}

/// The state anchor (version 2, or 3 once sealed): constant size.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateAnchor {
    pub version: u32,
    /// Increases with every update.
    pub counter: u64,
    pub audit_seq: i64,
    pub audit_root: String,
    /// The governance event log's anchored size (its last `gseq`) and the
    /// chain hash there: the database's log must contain exactly this
    /// event at this position.
    pub glog_size: i64,
    pub glog_head: String,
    /// Set once, when a version-1 anchor was migrated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migrated_from: Option<MigratedFrom>,
    /// Set by a compaction of the governance log mirror (version 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<Seal>,
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
            glog_size: 0,
            glog_head: empty_log_head(),
            migrated_from: None,
            seal: None,
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

    /// The version this anchor is written as: 3 with a seal, 2 without.
    fn version_for(&self) -> u32 {
        if self.seal.is_some() {
            ANCHOR_SEALED_VERSION
        } else {
            ANCHOR_VERSION
        }
    }

    fn sign(&mut self, signer: &ServiceSigner) -> Result<()> {
        self.version = self.version_for();
        self.signer = signer.id().into();
        self.signer_public_key = signer.public_key_hex();
        self.signature = signer.sign(STATE_ANCHOR_V2, &self.statement())?;
        Ok(())
    }

    /// Checks the signature is by `public_key` (the control plane's key).
    pub fn verify(&self, public_key: &str) -> Result<()> {
        if self.version != self.version_for() {
            return Err(anchor_err(format!("state anchor version {}", self.version)));
        }
        if let Some(seal) = &self.seal {
            if seal.size < 1 || seal.size > self.glog_size {
                return Err(anchor_err(format!(
                    "the state anchor's seal ({} events) is not within the anchored log ({} events)",
                    seal.size, self.glog_size
                )));
            }
        }
        if self.signer_public_key != public_key {
            return Err(anchor_err(
                "the state anchor was signed by another key than this control plane's",
            ));
        }
        verify_signed(
            public_key,
            STATE_ANCHOR_V2,
            &self.statement(),
            &self.signature,
        )
        .map_err(|_| anchor_err("the state anchor's signature is invalid (tampered)"))
    }
}

/// The state anchor of 0.3.0 and earlier (version 1): the sets of every
/// security-negative ID, growing with each. Read only to migrate it into
/// the governance log; never written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateAnchorV1 {
    pub version: u32,
    pub counter: u64,
    pub audit_seq: i64,
    pub audit_root: String,
    pub ledgers: BTreeMap<String, Checkpoint>,
    #[serde(default)]
    pub frozen: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub revoked: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub disabled_services: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub disabled_users: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub ended_jobs: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub withdrawn_grants: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub removed_memberships: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub removed_roles: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub revoked_authorizations: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub expired_assets: BTreeSet<String>,
    /// Rows of the sets above the database lost, acknowledged by recovery,
    /// as `set:id`.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub lost: BTreeSet<String>,
    pub signer: String,
    pub signer_public_key: String,
    #[serde(default)]
    pub signature: String,
}

impl StateAnchorV1 {
    /// An empty version-1 anchor (what 0.3.0 wrote on a fresh deployment;
    /// for tests and tooling).
    pub fn empty(signer: &ServiceSigner) -> Self {
        Self {
            version: ANCHOR_V1_VERSION,
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

    fn statement(&self) -> StateAnchorV1 {
        StateAnchorV1 {
            signature: String::new(),
            ..self.clone()
        }
    }

    /// Signs it as 0.3.0 did (for tests and tooling that build the
    /// anchors of earlier releases).
    pub fn sign(&mut self, signer: &ServiceSigner) -> Result<()> {
        self.signer = signer.id().into();
        self.signer_public_key = signer.public_key_hex();
        self.signature = signer.sign(STATE_ANCHOR, &self.statement())?;
        Ok(())
    }

    /// Checks the signature is by `public_key` (the control plane's key).
    pub fn verify(&self, public_key: &str) -> Result<()> {
        if self.version != ANCHOR_V1_VERSION {
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

    /// Its canonical JSON (signature included): what the migration keeps.
    pub fn canonical(&self) -> Result<String> {
        String::from_utf8(encompute_verification::canonical::canonical_json(self)?)
            .map_err(|e| anchor_err(format!("state anchor: {e}")))
    }

    /// SHA-256 of [`Self::canonical`].
    pub fn digest(&self) -> Result<String> {
        Ok(sha256_hex(self.canonical()?.as_bytes()))
    }
}

/// An anchor as stored: this release's, or one of 0.3.0 to migrate.
#[derive(Clone, Debug, PartialEq, Eq)]
// One value per load or store, never in bulk: the version-1 variant is the
// large one, and is read only to migrate it.
#[allow(clippy::large_enum_variant)]
pub enum StoredAnchor {
    V1(StateAnchorV1),
    V2(StateAnchor),
}

impl StoredAnchor {
    /// Reads an anchor by its `version`. A version this release does not
    /// know (a newer release wrote it) is refused: there is no downgrade.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let v: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| anchor_err(format!("state anchor: {e}")))?;
        let parsed = match v.get("version").and_then(|x| x.as_u64()) {
            Some(1) => serde_json::from_value(v).map(StoredAnchor::V1),
            Some(2) => serde_json::from_value(v).map(StoredAnchor::V2),
            // A sealed anchor: this release's format with a seal. Version 3
            // without one, or version 2 with one, is not an anchor any
            // release writes.
            Some(3) if v.get("seal").is_some() => {
                serde_json::from_value(v).map(StoredAnchor::V2)
            }
            Some(3) => {
                return Err(anchor_err(
                    "state anchor version 3 is not supported without a seal",
                ))
            }
            other => {
                return Err(anchor_err(format!(
                    "state anchor version {} is not supported by this release (written by a newer one? a control plane is never downgraded, see docs/deployment.md)",
                    other.map_or("(none)".to_owned(), |x| x.to_string())
                )))
            }
        };
        let parsed = parsed.map_err(|e| anchor_err(format!("state anchor: {e}")))?;
        if let StoredAnchor::V2(a) = &parsed {
            if a.version == ANCHOR_VERSION && a.seal.is_some() {
                return Err(anchor_err(
                    "a state anchor with a seal is version 3, not 2 (tampered?)",
                ));
            }
        }
        Ok(parsed)
    }

    pub fn counter(&self) -> u64 {
        match self {
            StoredAnchor::V1(a) => a.counter,
            StoredAnchor::V2(a) => a.counter,
        }
    }
}

/// Where the anchor is kept. Updates are compare-and-set on the counter.
pub trait AnchorStore: Send + Sync {
    fn describe(&self) -> String;
    fn load(&self) -> Result<Option<StoredAnchor>>;
    /// Stores `next` if the stored anchor's counter (of either version) is
    /// still `expected`.
    fn store(&self, next: &StateAnchor, expected: u64) -> Result<()>;
    /// The governance log mirror's segment numbers (`crate::mirror`), in
    /// any order. Names that are not segments are ignored.
    fn mirror_list(&self) -> Result<Vec<u64>>;
    /// A segment's lines. A segment larger than [`MIRROR_MAX_READ`] is
    /// refused (a planted or damaged one cannot exhaust memory).
    fn mirror_read(&self, n: u64) -> Result<String>;
    /// Writes segment `n` if no segment `n` exists: one atomic create of
    /// that single name (two writers: exactly one wins, the other gets an
    /// error containing "exists already (written concurrently)"), durable
    /// before returning.
    fn mirror_create(&self, n: u64, lines: &str) -> Result<()>;
    /// Replaces segment `n` (which exists) atomically and durably: a reader
    /// sees the old or the new segment whole. `allow` sees the current
    /// content and must accept the replacement (a replacement never
    /// shrinks what is anchored); in OpenBao KV the write is a
    /// compare-and-set on the version `allow` saw, so a segment changed
    /// meanwhile is not overwritten (the call fails and is retried).
    fn mirror_replace(&self, n: u64, lines: &str, allow: &Allow<'_>) -> Result<()>;
    /// Deletes segment `n` (succeeding when it is already gone), durably.
    /// `allow` sees the current content (`None` when it cannot be read)
    /// and must accept the deletion: only a compaction deletes, and only
    /// what its archive holds. A store that cannot delete refuses.
    fn mirror_delete(&self, _n: u64, _allow: &Allow<'_>) -> Result<()> {
        Err(anchor_err(
            "this anchor store cannot delete mirror segments",
        ))
    }
}

/// Decides whether a segment's current content (`None` when it cannot be
/// read) may be replaced.
pub type Allow<'a> = dyn Fn(Option<&str>) -> Result<()> + 'a;

/// The most bytes of one mirror segment a read accepts (a segment is
/// written under [`crate::mirror::SEGMENT_BYTES`] plus one event, far
/// below an OpenBao KV entry's 1 MiB).
pub const MIRROR_MAX_READ: u64 = 512 * 1024;

fn segment_file(n: u64) -> String {
    format!("{n:012}.jsonl")
}

fn tmp_name(base: &str) -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        ".{base}.{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
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

    /// The governance log mirror's directory, next to the anchor.
    pub fn mirror_dir(&self) -> PathBuf {
        self.dir.join("governance-log")
    }
}

fn fsync_dir(d: &std::path::Path) -> Result<()> {
    std::fs::File::open(d)
        .and_then(|f| f.sync_all())
        .map_err(|e| anchor_err(format!("{}: {e}", d.display())))
}

impl AnchorStore for DirAnchor {
    fn describe(&self) -> String {
        format!("file {}", self.path().display())
    }

    fn load(&self) -> Result<Option<StoredAnchor>> {
        let p = self.path();
        if !p.exists() {
            return Ok(None);
        }
        let b = std::fs::read(&p).map_err(|e| anchor_err(format!("{}: {e}", p.display())))?;
        StoredAnchor::parse(&b)
            .map(Some)
            .map_err(|e| anchor_err(format!("{}: {}", p.display(), e.message)))
    }

    fn store(&self, next: &StateAnchor, expected: u64) -> Result<()> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let current = self.load()?.map_or(0, |a| a.counter());
        if current != expected {
            return Err(anchor_err(format!(
                "the state anchor changed concurrently (counter {current}, expected {expected})"
            )));
        }
        // Atomic: the new anchor is written whole (unique temporary name,
        // fsync) and renamed over the old one, then the directory is
        // fsynced so the rename itself survives a crash. A crash leaves the
        // old anchor or the new one, never a torn one; a leftover
        // temporary file is ignored.
        let p = self.path();
        let tmp = self.dir.join(tmp_name("state-anchor.json"));
        let written = {
            use std::io::Write;
            std::fs::File::create(&tmp).and_then(|mut f| {
                f.write_all(&serde_json::to_vec_pretty(next).expect("serializable"))
                    .and_then(|_| f.sync_all())
            })
        };
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(anchor_err(format!("{}: {e}", tmp.display())));
        }
        if let Err(e) = std::fs::rename(&tmp, &p) {
            let _ = std::fs::remove_file(&tmp);
            return Err(anchor_err(format!("{}: {e}", p.display())));
        }
        fsync_dir(&self.dir)
    }

    fn mirror_list(&self) -> Result<Vec<u64>> {
        let d = self.mirror_dir();
        if !d.exists() {
            return Ok(vec![]);
        }
        let mut out = vec![];
        for e in std::fs::read_dir(&d).map_err(|e| anchor_err(format!("{}: {e}", d.display())))? {
            let e = e.map_err(|e| anchor_err(format!("{}: {e}", d.display())))?;
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(n) = name
                .strip_suffix(".jsonl")
                .and_then(|x| x.parse::<u64>().ok())
                .filter(|n| *n > 0 && segment_file(*n) == name)
            {
                out.push(n);
            }
        }
        Ok(out)
    }

    fn mirror_read(&self, n: u64) -> Result<String> {
        use std::io::Read;
        let p = self.mirror_dir().join(segment_file(n));
        let f = std::fs::File::open(&p).map_err(|e| anchor_err(format!("{}: {e}", p.display())))?;
        let mut s = String::new();
        f.take(MIRROR_MAX_READ + 1)
            .read_to_string(&mut s)
            .map_err(|e| anchor_err(format!("{}: {e}", p.display())))?;
        if s.len() as u64 > MIRROR_MAX_READ {
            return Err(anchor_err(format!(
                "{}: larger than a mirror segment may be",
                p.display()
            )));
        }
        Ok(s)
    }

    fn mirror_create(&self, n: u64, lines: &str) -> Result<()> {
        let d = self.mirror_dir();
        std::fs::create_dir_all(&d).map_err(|e| anchor_err(format!("{}: {e}", d.display())))?;
        let p = d.join(segment_file(n));
        let tmp = d.join(tmp_name(&segment_file(n)));
        let exists = || {
            anchor_err(format!(
                "governance log mirror segment {n} exists already (written concurrently)"
            ))
        };
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| anchor_err(format!("{}: {e}", tmp.display())))?;
            f.write_all(lines.as_bytes())
                .and_then(|_| f.sync_all())
                .map_err(|e| anchor_err(format!("{}: {e}", tmp.display())))?;
        }
        // Create-only: a hard link never replaces an existing name.
        match std::fs::hard_link(&tmp, &p) {
            Ok(()) => {
                let _ = std::fs::remove_file(&tmp);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(&tmp);
                return Err(exists());
            }
            Err(_) => {
                // No hard links on this file system: create the final name
                // exclusively and write into it. Still a single-name
                // create-only; a crash mid-write leaves a torn segment,
                // which readers treat as damaged and the next write
                // replaces.
                let _ = std::fs::remove_file(&tmp);
                use std::io::Write;
                let mut f = match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&p)
                {
                    Ok(f) => f,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(exists()),
                    Err(e) => return Err(anchor_err(format!("{}: {e}", p.display()))),
                };
                f.write_all(lines.as_bytes())
                    .and_then(|_| f.sync_all())
                    .map_err(|e| anchor_err(format!("{}: {e}", p.display())))?;
            }
        }
        fsync_dir(&d)
    }

    fn mirror_replace(&self, n: u64, lines: &str, allow: &Allow<'_>) -> Result<()> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let d = self.mirror_dir();
        let p = d.join(segment_file(n));
        if !p.exists() {
            return Err(anchor_err(format!(
                "governance log mirror segment {n} does not exist"
            )));
        }
        allow(self.mirror_read(n).ok().as_deref())?;
        let tmp = d.join(tmp_name(&segment_file(n)));
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| anchor_err(format!("{}: {e}", tmp.display())))?;
            f.write_all(lines.as_bytes())
                .and_then(|_| f.sync_all())
                .map_err(|e| anchor_err(format!("{}: {e}", tmp.display())))?;
        }
        if let Err(e) = std::fs::rename(&tmp, &p) {
            let _ = std::fs::remove_file(&tmp);
            return Err(anchor_err(format!("{}: {e}", p.display())));
        }
        fsync_dir(&d)
    }

    fn mirror_delete(&self, n: u64, allow: &Allow<'_>) -> Result<()> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let d = self.mirror_dir();
        let p = d.join(segment_file(n));
        if !p.exists() {
            return Ok(());
        }
        allow(self.mirror_read(n).ok().as_deref())?;
        std::fs::remove_file(&p).map_err(|e| anchor_err(format!("{}: {e}", p.display())))?;
        fsync_dir(&d)
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
    fn read(&self) -> Result<Option<(StoredAnchor, u64)>> {
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
                    StoredAnchor::parse(a.as_bytes())
                        .map_err(|e| anchor_err(format!("anchor store: {}", e.message)))?,
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

    fn load(&self) -> Result<Option<StoredAnchor>> {
        Ok(self.read()?.map(|(a, _)| a))
    }

    fn store(&self, next: &StateAnchor, expected: u64) -> Result<()> {
        let (current, kv_version) = match self.read()? {
            Some((a, v)) => (a.counter(), v),
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

    fn mirror_list(&self) -> Result<Vec<u64>> {
        let url = format!(
            "{}/v1/{}/metadata/{}-glog",
            self.addr, self.mount, self.path
        );
        match self
            .agent
            .request("LIST", &url)
            .set("X-Vault-Token", &self.token)
            .call()
        {
            Ok(r) => {
                let v: serde_json::Value = r
                    .into_json()
                    .map_err(|e| anchor_err(format!("anchor store: {e}")))?;
                Ok(v["data"]["keys"]
                    .as_array()
                    .map(|k| {
                        k.iter()
                            .filter_map(|x| x.as_str())
                            .filter_map(|x| {
                                x.parse::<u64>()
                                    .ok()
                                    .filter(|n| *n > 0 && format!("{n:012}") == x)
                            })
                            .collect()
                    })
                    .unwrap_or_default())
            }
            Err(ureq::Error::Status(404, _)) => Ok(vec![]),
            Err(e) => Err(anchor_err(format!(
                "anchor store {} unavailable: {e}",
                self.addr
            ))),
        }
    }

    fn mirror_read(&self, n: u64) -> Result<String> {
        Ok(self.mirror_entry(n)?.map(|(l, _)| l).unwrap_or_default())
    }

    fn mirror_create(&self, n: u64, lines: &str) -> Result<()> {
        // cas 0: created only if absent; one atomic single-name create.
        match self.mirror_put(n, lines, 0) {
            Err(e) => match self.mirror_entry(n) {
                Ok(Some(_)) => Err(anchor_err(format!(
                    "governance log mirror segment {n} exists already (written concurrently)"
                ))),
                _ => Err(e),
            },
            ok => ok,
        }
    }

    fn mirror_replace(&self, n: u64, lines: &str, allow: &Allow<'_>) -> Result<()> {
        let (current, version) = self.mirror_entry(n)?.ok_or_else(|| {
            anchor_err(format!("governance log mirror segment {n} does not exist"))
        })?;
        allow(Some(&current))?;
        // Compare-and-set on the version the guard saw.
        self.mirror_put(n, lines, version).map_err(|e| {
            anchor_err(format!(
                "governance log mirror segment {n} changed meanwhile (written concurrently): {}",
                e.message
            ))
        })
    }

    fn mirror_delete(&self, n: u64, allow: &Allow<'_>) -> Result<()> {
        let Some((current, _)) = self.mirror_entry(n)? else {
            return Ok(());
        };
        allow(Some(&current))?;
        // The metadata endpoint removes the entry and every version of it.
        // (No compare-and-set exists for a delete: only a compaction
        // deletes, below the seal, where no writer replaces.)
        let url = format!(
            "{}/v1/{}/metadata/{}-glog/{n:012}",
            self.addr, self.mount, self.path
        );
        match self
            .agent
            .delete(&url)
            .set("X-Vault-Token", &self.token)
            .call()
        {
            Ok(_) | Err(ureq::Error::Status(404, _)) => Ok(()),
            Err(e) => Err(anchor_err(format!("anchor store {}: {e}", self.addr))),
        }
    }
}

impl OpenBaoKvAnchor {
    fn mirror_url(&self, n: u64) -> String {
        format!(
            "{}/v1/{}/data/{}-glog/{n:012}",
            self.addr, self.mount, self.path
        )
    }

    /// (lines, KV version) of segment `n`.
    fn mirror_entry(&self, n: u64) -> Result<Option<(String, u64)>> {
        match self
            .agent
            .get(&self.mirror_url(n))
            .set("X-Vault-Token", &self.token)
            .call()
        {
            Ok(r) => {
                let v: serde_json::Value = r
                    .into_json()
                    .map_err(|e| anchor_err(format!("anchor store: {e}")))?;
                let lines = v["data"]["data"]["lines"]
                    .as_str()
                    .ok_or_else(|| anchor_err("anchor store: malformed mirror segment"))?
                    .to_owned();
                if lines.len() as u64 > MIRROR_MAX_READ {
                    return Err(anchor_err("anchor store: mirror segment too large"));
                }
                Ok(Some((
                    lines,
                    v["data"]["metadata"]["version"].as_u64().unwrap_or(0),
                )))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(anchor_err(format!(
                "anchor store {} unavailable: {e}",
                self.addr
            ))),
        }
    }

    fn mirror_put(&self, n: u64, lines: &str, cas: u64) -> Result<()> {
        let body = serde_json::json!({"options": {"cas": cas}, "data": {"lines": lines}});
        self.agent
            .post(&self.mirror_url(n))
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

/// What [`Anchor::open`] found.
#[derive(Debug)]
pub enum Opened {
    /// No anchor yet (a fresh deployment).
    Fresh,
    /// This release's anchor.
    Existing,
    /// A version-1 anchor (verified): the control plane migrates it before
    /// anything else; until then the anchor in memory carries its counter and
    /// audit root, and an empty log.
    V1(Box<StateAnchorV1>),
}

/// The anchor in memory, serialized updates, persisted before returning.
pub struct Anchor {
    store: Box<dyn AnchorStore>,
    state: Mutex<StateAnchor>,
    /// [`serialized_len`] of the anchor as last loaded or written.
    bytes: AtomicU64,
    /// The counter as last loaded or written, readable without the lock
    /// (a transaction that holds database locks must never wait on the
    /// anchor's lock, which a checkpoint holds while it takes the log's
    /// head: see [`Self::counter`]).
    counter: AtomicU64,
}

impl Anchor {
    /// Loads (and verifies) the stored anchor, or starts an empty one.
    pub fn open(store: Box<dyn AnchorStore>, signer: &ServiceSigner) -> Result<(Self, Opened)> {
        let (state, opened) = match store.load()? {
            Some(StoredAnchor::V2(a)) => {
                a.verify(&signer.public_key_hex())?;
                (a, Opened::Existing)
            }
            Some(StoredAnchor::V1(v1)) => {
                v1.verify(&signer.public_key_hex())?;
                let mut a = StateAnchor::empty(signer);
                a.counter = v1.counter;
                a.audit_seq = v1.audit_seq;
                a.audit_root = v1.audit_root.clone();
                (a, Opened::V1(Box::new(v1)))
            }
            None => (StateAnchor::empty(signer), Opened::Fresh),
        };
        let bytes = AtomicU64::new(serialized_len(&state));
        let counter = AtomicU64::new(state.counter);
        Ok((
            Self {
                store,
                state: Mutex::new(state),
                bytes,
                counter,
            },
            opened,
        ))
    }

    /// The store (its governance log mirror, `crate::mirror`).
    pub fn store(&self) -> &dyn AnchorStore {
        &*self.store
    }

    /// The anchor's serialized size as last loaded or written (the
    /// `encompute_anchor_bytes` gauge).
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// The anchor's counter as last loaded or written. Never takes the
    /// anchor's lock, so it is safe inside a database transaction. Lock
    /// order: the anchor's lock is outermost (a checkpoint holds it while it
    /// locks the governance log's head and the audit head), so code that
    /// holds a database lock must not call [`Self::snapshot`] or
    /// [`Self::update`]; read the snapshot before the transaction.
    pub fn counter(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
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
                    self.counter.store(next.counter, Ordering::Relaxed);
                    *g = next.clone();
                    return Ok(next);
                }
                Err(e) if attempt < 3 && e.message.contains("changed concurrently") => {
                    attempt += 1;
                    let stored = match self.store.load()? {
                        Some(StoredAnchor::V2(a)) => a,
                        Some(StoredAnchor::V1(_)) => {
                            return Err(anchor_err(
                                "the stored state anchor is version 1 again (replaced by an older copy?)",
                            ))
                        }
                        None => return Err(anchor_err("the state anchor disappeared")),
                    };
                    stored.verify(&signer.public_key_hex())?;
                    if stored.counter < g.counter {
                        return Err(anchor_err(format!(
                            "the stored state anchor went back from counter {} to {}",
                            g.counter, stored.counter
                        )));
                    }
                    self.counter.store(stored.counter, Ordering::Relaxed);
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
    /// (Version 1, read only to migrate it.)
    #[test]
    fn anchors_without_the_new_sets_still_verify() {
        let s = signer();
        let mut a = StateAnchorV1::empty(&s);
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
        let back = match StoredAnchor::parse(&serde_json::to_vec(&v).unwrap()).unwrap() {
            StoredAnchor::V1(a) => a,
            other => panic!("{other:?}"),
        };
        back.verify(&s.public_key_hex()).unwrap();
        // Once present, they are covered by the signature.
        let mut a = back;
        a.ended_jobs.insert("job_1".into());
        a.sign(&s).unwrap();
        a.verify(&s.public_key_hex()).unwrap();
        let mut tampered = serde_json::to_value(&a).unwrap();
        tampered["ended_jobs"] = serde_json::json!([]);
        let t: StateAnchorV1 = serde_json::from_value(tampered).unwrap();
        assert!(t.verify(&s.public_key_hex()).is_err());
    }

    /// INV-226: a version-2 anchor is refused by a release that reads only
    /// version 1 (0.3.0's struct refuses its fields: fail closed, no
    /// downgrade), a version-1 signature never verifies as version 2 (its
    /// own domain), and an unknown version is refused.
    #[test]
    fn versions_never_cross() {
        let s = signer();
        let mut a = StateAnchor::empty(&s);
        a.glog_size = 3;
        a.sign(&s).unwrap();
        a.verify(&s.public_key_hex()).unwrap();
        let v2 = serde_json::to_value(&a).unwrap();
        // What 0.3.0 does with it.
        let old: std::result::Result<StateAnchorV1, _> = serde_json::from_value(v2.clone());
        assert!(old.is_err(), "an older release read a version-2 anchor");
        // A version-2 body signed in version 1's domain does not verify.
        let mut forged = a.clone();
        forged.signature = s.sign(STATE_ANCHOR, &a.statement()).unwrap();
        assert!(forged.verify(&s.public_key_hex()).is_err());
        let mut v3 = v2;
        v3["version"] = 3.into();
        let e = StoredAnchor::parse(&serde_json::to_vec(&v3).unwrap()).unwrap_err();
        assert!(e.message.contains("not supported"), "{e}");
        // A version-1 anchor opens as one to migrate, carrying its counter.
        let dir = tmp("v1");
        let mut v1 = StateAnchorV1::empty(&s);
        v1.counter = 7;
        v1.ended_jobs.insert("job_1".into());
        v1.sign(&s).unwrap();
        std::fs::write(
            dir.join("state-anchor.json"),
            serde_json::to_vec(&v1).unwrap(),
        )
        .unwrap();
        let (an, opened) = Anchor::open(Box::new(DirAnchor::new(dir).unwrap()), &s).unwrap();
        assert!(matches!(opened, Opened::V1(ref x) if **x == v1));
        assert_eq!(an.snapshot().counter, 7);
        assert_eq!(an.snapshot().glog_size, 0);
    }

    /// INV-251: the anchor of a mirror that was compacted is version 3 and
    /// holds a seal; one that never was stays version 2, byte for byte what
    /// the previous release wrote and reads. The previous release refuses
    /// a sealed anchor twice over (its struct knows no seal, its version
    /// list ends at 2); a seal cannot be added to, removed from, or moved
    /// in a signed anchor, and neither version label fits the other form.
    #[test]
    fn a_sealed_anchor_is_version_3_and_refused_by_the_previous_release() {
        /// The previous release's anchor, field for field.
        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct PreviousAnchor {
            version: u32,
            counter: u64,
            audit_seq: i64,
            audit_root: String,
            glog_size: i64,
            glog_head: String,
            #[serde(default)]
            migrated_from: Option<MigratedFrom>,
            signer: String,
            signer_public_key: String,
            #[serde(default)]
            signature: String,
        }
        // What the previous release did with a version: 1 and 2 only.
        fn previous_release_accepts(bytes: &[u8]) -> bool {
            let v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            matches!(v.get("version").and_then(|x| x.as_u64()), Some(1 | 2))
                && serde_json::from_value::<PreviousAnchor>(v).is_ok()
        }
        let s = signer();
        let key = s.public_key_hex();
        // Never compacted: version 2, no seal field, read by the previous
        // release.
        let mut a = StateAnchor::empty(&s);
        a.glog_size = 3_000;
        a.glog_head = "ab".repeat(32);
        a.sign(&s).unwrap();
        assert_eq!(a.version, 2);
        let plain = serde_json::to_vec(&a).unwrap();
        assert!(!String::from_utf8_lossy(&plain).contains("seal"));
        assert!(previous_release_accepts(&plain));
        let StoredAnchor::V2(back) = StoredAnchor::parse(&plain).unwrap() else {
            panic!("not version 2");
        };
        back.verify(&key).unwrap();
        // Compacted: version 3 with the seal; the previous release refuses
        // it, this one verifies it.
        let seal = Seal {
            size: 2_500,
            head: "cd".repeat(32),
            manifest: "ef".repeat(32),
        };
        let mut sealed = a.clone();
        sealed.seal = Some(seal.clone());
        sealed.sign(&s).unwrap();
        assert_eq!(sealed.version, 3);
        let bytes = serde_json::to_vec(&sealed).unwrap();
        assert!(
            !previous_release_accepts(&bytes),
            "the previous release read a sealed anchor"
        );
        let e: std::result::Result<PreviousAnchor, _> = serde_json::from_slice(&bytes);
        assert!(e.is_err(), "its struct knows no seal");
        let StoredAnchor::V2(read) = StoredAnchor::parse(&bytes).unwrap() else {
            panic!("not parsed as this release's anchor");
        };
        assert_eq!(read.seal, Some(seal.clone()));
        read.verify(&key).unwrap();
        assert!(
            serialized_len(&sealed) < serialized_len(&a) + 256,
            "the seal is constant in size"
        );
        // The seal is signed: removed, edited or moved, it does not verify.
        for edit in [
            |v: &mut serde_json::Value| v["seal"]["size"] = 2_000.into(),
            |v: &mut serde_json::Value| v["seal"]["head"] = ("00".repeat(32)).into(),
            |v: &mut serde_json::Value| v["seal"]["manifest"] = ("11".repeat(32)).into(),
        ] {
            let mut v = serde_json::to_value(&sealed).unwrap();
            edit(&mut v);
            let t: StateAnchor = serde_json::from_value(v).unwrap();
            assert!(t.verify(&key).is_err(), "an edited seal verified");
        }
        // Version labels fit only their own form.
        let mut v = serde_json::to_value(&sealed).unwrap();
        v["version"] = 2.into();
        let e = StoredAnchor::parse(&serde_json::to_vec(&v).unwrap()).unwrap_err();
        assert!(e.message.contains("version 3"), "{e}");
        let mut v = serde_json::to_value(&a).unwrap();
        v["version"] = 3.into();
        let e = StoredAnchor::parse(&serde_json::to_vec(&v).unwrap()).unwrap_err();
        assert!(e.message.contains("not supported"), "{e}");
        // A seal past the anchored log is not an anchor.
        let mut past = sealed.clone();
        past.seal = Some(Seal {
            size: 3_001,
            ..seal
        });
        past.sign(&s).unwrap();
        assert!(past.verify(&key).is_err());
        // Signed as version 2 (the old label) with a seal, it does not
        // verify either: the label is part of what is signed.
        let mut relabelled = sealed.clone();
        relabelled.version = 2;
        assert!(relabelled.verify(&key).is_err());
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
        let (a2, opened) =
            Anchor::open(Box::new(DirAnchor::new(dir.clone()).unwrap()), &s).unwrap();
        assert!(matches!(opened, Opened::Existing));
        a1.update(&s, |x| x.audit_seq = 1).unwrap();
        let after = a2.update(&s, |x| x.glog_size = 2).unwrap();
        assert_eq!(after.audit_seq, 1, "the other process's change is kept");
        assert_eq!(after.glog_size, 2);
        let stored = match DirAnchor::new(dir).unwrap().load().unwrap().unwrap() {
            StoredAnchor::V2(a) => a,
            other => panic!("{other:?}"),
        };
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
