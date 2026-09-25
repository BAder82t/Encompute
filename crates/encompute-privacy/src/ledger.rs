//! The privacy ledger: one hash-chained, append-only file per budgeted
//! asset. Each release is reserved (charged) before any noisy output
//! exists and committed with the output's commitment after, all under an
//! exclusive file lock, so a crash never leaves an unaccounted release and
//! two processes cannot both spend the same remaining budget.
//!
//! Deleting, reordering or editing an entry changes every later hash, and
//! the genesis entry fixes the asset, budget and privacy policy, so one
//! asset's ledger cannot stand in for another's. A ledger *rollback* (or a
//! reset to an empty ledger) is detected by anyone holding a later root: data
//! owners keep the last root they saw and refuse a ledger that does not
//! extend it.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use encompute_ir::confidentiality::{DpMechanism, PrivacyBudget};
use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::hex;

use crate::accountant::{self, Cost};
use crate::tagged;

pub const LEDGER_VERSION: u32 = 1;
const ENTRY: &str = "encompute.privacy-ledger.v1";
/// Largest ledger accepted (entries are ~1 KiB).
const MAX_LEDGER_BYTES: u64 = 64 << 20;

fn ledger_err(m: impl Into<String>) -> Error {
    Error::new(Code::PrivacyLedger, m)
}

/// What a ledger accounts for: fixed at creation, hashed into every entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub version: u32,
    pub asset_id: String,
    pub budget: PrivacyBudget,
    pub privacy_policy_id: String,
}

/// A release's charge (reserve) or completion (commit).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivacyEvent {
    /// The release is charged. Written before any noisy output exists.
    Reserve {
        event_id: String,
        policy_id: Option<String>,
        execution_spec_id: Option<String>,
        round_id: Option<String>,
        output: String,
        mechanism: DpMechanism,
        /// L2 sensitivity in integer code units (an upper bound).
        sensitivity: u64,
        /// Noise variance parameter in code units squared.
        sigma2: u64,
        vector_len: usize,
        /// `csprng` (production) or an unmistakable testing marker.
        rng: String,
    },
    /// The release happened: its output is committed to.
    Commit {
        event_id: String,
        output_commitment: String,
    },
}

impl PrivacyEvent {
    pub fn event_id(&self) -> &str {
        match self {
            PrivacyEvent::Reserve { event_id, .. } | PrivacyEvent::Commit { event_id, .. } => {
                event_id
            }
        }
    }

    /// The zCDP cost of a reservation (commits cost nothing).
    pub fn rho(&self) -> Result<f64> {
        match self {
            PrivacyEvent::Reserve {
                sensitivity,
                sigma2,
                ..
            } => accountant::gaussian_rho(*sensitivity, *sigma2),
            PrivacyEvent::Commit { .. } => Ok(0.0),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub seq: u64,
    /// Hash of the previous entry (the genesis hash for seq 1).
    pub prev: String,
    pub event: PrivacyEvent,
    pub hash: String,
}

fn genesis_hash(g: &Genesis) -> Result<String> {
    Ok(hex(&tagged(ENTRY, &[b"genesis", &canonical_json(g)?])))
}

fn entry_hash(seq: u64, prev: &str, event: &PrivacyEvent) -> Result<String> {
    Ok(hex(&tagged(
        ENTRY,
        &[&seq.to_le_bytes(), prev.as_bytes(), &canonical_json(event)?],
    )))
}

/// A ledger's content: the genesis and its entries, verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerView {
    pub genesis: Genesis,
    pub entries: Vec<Entry>,
}

/// Where a reader last saw a ledger: it must only ever grow from here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub seq: u64,
    pub root: String,
}

impl LedgerView {
    /// Checks the chain from the genesis: hashes, sequence numbers, one
    /// reservation per event ID and per (round, output), commits only of
    /// open reservations.
    pub fn verify(&self) -> Result<()> {
        if self.genesis.version != LEDGER_VERSION {
            return Err(ledger_err(format!(
                "ledger version {}",
                self.genesis.version
            )));
        }
        self.genesis.budget.validate()?;
        let mut prev = genesis_hash(&self.genesis)?;
        let mut reserved = std::collections::BTreeSet::new();
        let mut rounds = std::collections::BTreeSet::new();
        let mut committed = std::collections::BTreeSet::new();
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as u64 + 1 || e.prev != prev {
                return Err(ledger_err(format!(
                    "ledger entry {} is out of order or unchained (deleted, reordered or \
                     inserted entries)",
                    i + 1
                )));
            }
            if entry_hash(e.seq, &e.prev, &e.event)? != e.hash {
                return Err(ledger_err(format!("ledger entry {} was modified", e.seq)));
            }
            match &e.event {
                PrivacyEvent::Reserve {
                    event_id,
                    round_id,
                    output,
                    ..
                } => {
                    if !reserved.insert(event_id.clone()) {
                        return Err(ledger_err(format!("event {event_id} reserved twice")));
                    }
                    if let Some(r) = round_id {
                        if !rounds.insert((r.clone(), output.clone())) {
                            return Err(ledger_err(format!("round {r} released {output} twice")));
                        }
                    }
                    e.event.rho()?;
                }
                PrivacyEvent::Commit { event_id, .. } => {
                    if !reserved.contains(event_id) || !committed.insert(event_id.clone()) {
                        return Err(ledger_err(format!(
                            "commit of event {event_id} without a single open reservation"
                        )));
                    }
                }
            }
            prev = e.hash.clone();
        }
        Ok(())
    }

    pub fn root(&self) -> Result<String> {
        match self.entries.last() {
            Some(e) => Ok(e.hash.clone()),
            None => genesis_hash(&self.genesis),
        }
    }

    pub fn checkpoint(&self) -> Result<Checkpoint> {
        Ok(Checkpoint {
            seq: self.entries.len() as u64,
            root: self.root()?,
        })
    }

    /// The ledger extends `seen`: nothing a reader already saw was removed
    /// or rewritten (rollback and reset detection).
    pub fn extends(&self, seen: &Checkpoint) -> Result<()> {
        let at = if seen.seq == 0 {
            genesis_hash(&self.genesis)?
        } else {
            match self.entries.get(seen.seq as usize - 1) {
                Some(e) => e.hash.clone(),
                None => {
                    return Err(ledger_err(format!(
                        "the ledger has {} entries but {} were already seen: it was rolled \
                         back or reset",
                        self.entries.len(),
                        seen.seq
                    )))
                }
            }
        };
        if at != seen.root {
            return Err(ledger_err(
                "the ledger does not extend the last one seen: it was rewritten, rolled back \
                 or reset",
            ));
        }
        Ok(())
    }

    /// The accumulated cost, in ledger order.
    pub fn cost(&self) -> Result<Cost> {
        let mut rho = 0.0;
        for e in &self.entries {
            rho += e.event.rho()?;
        }
        Cost::of(rho, &self.genesis.budget)
    }

    /// The cost after one more release costing `rho`.
    pub fn cost_after(&self, rho: f64) -> Result<Cost> {
        Cost::of(self.cost()?.rho + rho, &self.genesis.budget)
    }

    /// Refuses a release of `rho` that would exceed the budget.
    pub fn check(&self, rho: f64) -> Result<Cost> {
        let after = self.cost_after(rho)?;
        if after.epsilon > self.genesis.budget.epsilon {
            return Err(Error::new(
                Code::PrivacyBudgetExceeded,
                format!(
                    "RELEASE DENIED: asset {} has spent epsilon {:.4} of {}; this release \
                     would bring it to {:.4} (delta {:e})",
                    self.genesis.asset_id,
                    self.cost()?.epsilon,
                    self.genesis.budget.epsilon,
                    after.epsilon,
                    self.genesis.budget.delta
                ),
            ));
        }
        Ok(after)
    }
}

/// A ledger file under an exclusive lock for the duration of a
/// transaction.
pub struct Ledger {
    path: PathBuf,
    file: File,
    view: LedgerView,
}

impl Ledger {
    /// Opens (creating with `genesis` if missing) and locks the ledger at
    /// `path`, then verifies it and that its genesis is `genesis`.
    pub fn open(path: &Path, genesis: &Genesis) -> Result<Self> {
        let io = |e: std::io::Error| ledger_err(format!("{}: {e}", path.display()));
        let mut o = OpenOptions::new();
        o.read(true).append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let file = o.open(path).map_err(io)?;
        file.lock().map_err(io)?;
        let len = file.metadata().map_err(io)?.len();
        if len > MAX_LEDGER_BYTES {
            return Err(ledger_err(format!("{} is too large", path.display())));
        }
        let mut lines = BufReader::new(&file).lines();
        let view = match lines.next() {
            None => {
                let mut f = &file;
                writeln!(
                    f,
                    "{}",
                    String::from_utf8(canonical_json(genesis)?).expect("JSON")
                )
                .map_err(io)?;
                f.sync_all().map_err(io)?;
                LedgerView {
                    genesis: genesis.clone(),
                    entries: vec![],
                }
            }
            Some(first) => {
                let g: Genesis = serde_json::from_str(&first.map_err(io)?)
                    .map_err(|e| ledger_err(format!("{}: genesis: {e}", path.display())))?;
                let mut entries = vec![];
                for l in lines {
                    let l = l.map_err(io)?;
                    entries.push(
                        serde_json::from_str(&l)
                            .map_err(|e| ledger_err(format!("{}: entry: {e}", path.display())))?,
                    );
                }
                LedgerView {
                    genesis: g,
                    entries,
                }
            }
        };
        view.verify()?;
        if &view.genesis != genesis {
            return Err(ledger_err(format!(
                "{} accounts for another asset, budget or privacy policy",
                path.display()
            )));
        }
        Ok(Self {
            path: path.to_owned(),
            file,
            view,
        })
    }

    pub fn view(&self) -> &LedgerView {
        &self.view
    }

    /// Appends one event durably (fsync) and returns its entry.
    pub fn append(&mut self, event: PrivacyEvent) -> Result<Entry> {
        let seq = self.view.entries.len() as u64 + 1;
        let prev = self.view.root()?;
        let hash = entry_hash(seq, &prev, &event)?;
        let entry = Entry {
            seq,
            prev,
            event,
            hash,
        };
        let mut next = self.view.clone();
        next.entries.push(entry.clone());
        next.verify()?;
        let io = |e: std::io::Error| ledger_err(format!("{}: {e}", self.path.display()));
        let line = String::from_utf8(canonical_json(&entry)?).expect("JSON");
        writeln!(self.file, "{line}").map_err(io)?;
        self.file.sync_all().map_err(io)?;
        self.view = next;
        Ok(entry)
    }
}

/// Reads a ledger without locking (for display and for readers).
pub fn read(path: &Path) -> Result<LedgerView> {
    let io = |e: std::io::Error| ledger_err(format!("{}: {e}", path.display()));
    let f = File::open(path).map_err(io)?;
    let mut lines = BufReader::new(f).lines();
    let genesis: Genesis = serde_json::from_str(
        &lines
            .next()
            .ok_or_else(|| ledger_err(format!("{} is empty", path.display())))?
            .map_err(io)?,
    )
    .map_err(|e| ledger_err(format!("{}: genesis: {e}", path.display())))?;
    let mut entries = vec![];
    for l in lines {
        entries.push(
            serde_json::from_str(&l.map_err(io)?)
                .map_err(|e| ledger_err(format!("{}: entry: {e}", path.display())))?,
        );
    }
    let v = LedgerView { genesis, entries };
    v.verify()?;
    Ok(v)
}
