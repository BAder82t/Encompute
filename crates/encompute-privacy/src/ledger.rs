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
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use encompute_ir::confidentiality::{DpMechanism, PrivacyBudget};
use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::hex;

use crate::accountant::{self, Cost};
use crate::tagged;

pub const LEDGER_VERSION: u32 = 1;
/// Genesis version 2: a population or a scope (see [`Scoping`]). A version 1
/// genesis serializes exactly as it always did, so no existing ledger's
/// hashes change; a version 2 genesis always carries its scoping, and a
/// version 1 never does.
pub const LEDGER_VERSION_SCOPED: u32 = 2;
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
    /// What the ledger accounts for: an asset's ID (version 1), or the ID
    /// of the population or scope (version 2).
    pub asset_id: String,
    pub budget: PrivacyBudget,
    pub privacy_policy_id: String,
    /// Version 2 only: whether this is a population or one of its scopes,
    /// and what it is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoping: Option<Scoping>,
}

/// What a version 2 ledger is.
///
/// A **population** is the authoritative ledger of every release that
/// touches one organization's series of datasets (all versions of it), at
/// one privacy unit: its budget is a hard cap that no scope can raise and
/// no new version or project resets. A **scope** is a sub-ledger of one
/// population for one project, purpose and (optionally) program; its
/// budget is the share the owners allocated. A release charged to a scope
/// is charged to its population too, and must fit in both.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Scoping {
    Population {
        organization: String,
        series: String,
    },
    Scope {
        population_id: String,
        /// The population genesis's digest ([`Genesis::digest`]): the
        /// scope belongs to exactly this population, never a lookalike.
        population_digest: String,
        project: String,
        purpose: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        program: Option<String>,
    },
}

impl Genesis {
    /// The genesis's digest: what the first entry chains to, and what a
    /// scope names its population by.
    pub fn digest(&self) -> Result<String> {
        genesis_hash(self)
    }

    pub fn is_population(&self) -> bool {
        matches!(self.scoping, Some(Scoping::Population { .. }))
    }

    pub fn is_scope(&self) -> bool {
        matches!(self.scoping, Some(Scoping::Scope { .. }))
    }
}

/// What a scoped reservation says about itself, recorded in the entry (and
/// so in the hash chain of both the scope's and the population's ledger).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRef {
    pub scope_id: String,
    pub population_id: String,
    /// The governed job the release belongs to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// How many sources one privacy unit was assumed to span: the
    /// reservation's sensitivity already includes this factor.
    pub max_sources_per_unit: u32,
    /// The digest of the aggregate's stratum labels, if it declares them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout_id: Option<String>,
    /// The record linkage the aggregate performs: always `none` (an
    /// aggregate links no records, and says so).
    pub linkage: String,
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
        /// Set when the release is charged to a scope (and its
        /// population): the same entry is in both ledgers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<Box<ScopeRef>>,
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
        match (self.genesis.version, &self.genesis.scoping) {
            (LEDGER_VERSION, None) | (LEDGER_VERSION_SCOPED, Some(_)) => {}
            (v, _) => {
                return Err(ledger_err(format!(
                    "ledger version {v} (a version 1 genesis has no scoping, a version 2 one always has)"
                )))
            }
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
                    scope,
                    ..
                } => {
                    self.check_scope_ref(e.seq, scope.as_deref())?;
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

    /// A reservation's scope reference must fit the ledger it is in: none in
    /// a plain asset ledger, this scope's (and its population's) in a
    /// scope, and one of its own scopes in a population.
    fn check_scope_ref(&self, seq: u64, scope: Option<&ScopeRef>) -> Result<()> {
        let g = &self.genesis;
        let bad = |why: &str| ledger_err(format!("ledger entry {seq}: {why}"));
        match (&g.scoping, scope) {
            (None, None) => Ok(()),
            (None, Some(_)) => Err(bad("a scoped reservation is in a plain asset ledger")),
            (Some(_), None) => Err(bad(
                "a population or scope ledger holds scoped reservations only",
            )),
            (Some(Scoping::Population { .. }), Some(r)) => {
                if r.population_id != g.asset_id {
                    return Err(bad("the reservation is for another population"));
                }
                Ok(())
            }
            (Some(Scoping::Scope { population_id, .. }), Some(r)) => {
                if r.scope_id != g.asset_id || &r.population_id != population_id {
                    return Err(bad("the reservation is for another scope"));
                }
                Ok(())
            }
        }
    }

    /// The ledger with `event` appended: chained, verified (one reservation
    /// per event, commits of open reservations only). Storage-independent:
    /// the file ledger and database-backed ledgers both append through it.
    pub fn append_event(&self, event: PrivacyEvent) -> Result<(LedgerView, Entry)> {
        let seq = self.entries.len() as u64 + 1;
        let prev = self.root()?;
        let hash = entry_hash(seq, &prev, &event)?;
        let entry = Entry {
            seq,
            prev,
            event,
            hash,
        };
        let mut next = self.clone();
        next.entries.push(entry.clone());
        next.verify()?;
        Ok((next, entry))
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

    /// Every charged release: its zCDP cost and sampling rate.
    fn releases(&self) -> Result<Vec<(f64, Option<f64>)>> {
        let mut out = vec![];
        for e in &self.entries {
            if let PrivacyEvent::Reserve { mechanism, .. } = &e.event {
                out.push((e.event.rho()?, mechanism.sampling_rate));
            }
        }
        Ok(out)
    }

    /// The accumulated cost, in ledger order.
    pub fn cost(&self) -> Result<Cost> {
        cost_of(&self.releases()?, &self.genesis.budget)
    }

    /// The cost after one more release costing `rho`, sampled at
    /// `sampling_rate` (DP-SGD) or not.
    pub fn cost_after(&self, rho: f64, sampling_rate: Option<f64>) -> Result<Cost> {
        let mut r = self.releases()?;
        r.push((rho, sampling_rate));
        cost_of(&r, &self.genesis.budget)
    }

    /// Refuses a release that would exceed the budget.
    pub fn check(&self, rho: f64, sampling_rate: Option<f64>) -> Result<Cost> {
        let after = self.cost_after(rho, sampling_rate)?;
        if after.epsilon > self.genesis.budget.epsilon {
            let what = match &self.genesis.scoping {
                None => "asset",
                Some(Scoping::Population { .. }) => "population",
                Some(Scoping::Scope { .. }) => "scope",
            };
            return Err(Error::new(
                Code::PrivacyBudgetExceeded,
                format!(
                    "RELEASE DENIED: {what} {} has spent epsilon {:.4} of {}; this release \
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

/// The cost of `releases` (zCDP cost, sampling rate) against `budget`.
///
/// Without sampled releases, zCDP composition with the CKS conversion, as
/// always. With any sampled release, every release is accounted under Rényi
/// DP: Poisson-subsampled ones with the Zhu–Wang bound, the others with
/// their full curve.
pub fn cost_of(releases: &[(f64, Option<f64>)], budget: &PrivacyBudget) -> Result<Cost> {
    // Ledger entries and API events are untrusted: a sampling rate outside
    // (0, 1) or a cost that is not a finite non-negative number would
    // otherwise reach the accountant's assertions (a panic) or a NaN
    // comparison (a release allowed).
    for (r, q) in releases {
        if !(r.is_finite() && *r >= 0.0) {
            return Err(Error::new(
                Code::PrivacyMechanism,
                format!("release cost {r} is not a finite non-negative number"),
            ));
        }
        if q.is_some_and(|q| !(q.is_finite() && q > 0.0 && q < 1.0)) {
            return Err(Error::new(
                Code::PrivacyMechanism,
                format!(
                    "sampling_rate must be in (0, 1) (Poisson sampling), got {}",
                    q.unwrap_or_default()
                ),
            ));
        }
    }
    let rho = releases.iter().fold(0.0, |a, (r, _)| a + r);
    if releases.iter().all(|(_, q)| q.is_none()) {
        return Cost::of(rho, budget);
    }
    budget.validate()?;
    // Identical releases (the same mechanism, round after round) share one
    // curve, scaled by their count.
    let mut groups: Vec<((f64, Option<f64>), u64)> = vec![];
    for r in releases {
        match groups.iter_mut().find(|(k, _)| k == r) {
            Some((_, n)) => *n += 1,
            None => groups.push((*r, 1)),
        }
    }
    let curves: Vec<_> = groups
        .iter()
        .map(|((r, q), n)| crate::rdp::scaled(&crate::rdp::release_curve(*r, *q), *n))
        .collect();
    Ok(Cost {
        rho,
        epsilon: crate::rdp::epsilon(&crate::rdp::compose(&curves), budget.delta),
        delta: budget.delta,
    })
}

/// The most releases [`affordable`] reports: "at least this many".
pub const MAX_AFFORDABLE: u64 = 100_000;

/// How many identical releases (zCDP cost `rho`, sampling rate `q`) the
/// budget affords from empty, up to [`MAX_AFFORDABLE`].
pub fn affordable(rho: f64, q: Option<f64>, budget: &PrivacyBudget) -> Result<u64> {
    let fits = |n: u64| -> Result<bool> {
        Ok(cost_of(&vec![(rho, q); n as usize], budget)?.epsilon <= budget.epsilon)
    };
    if !fits(1)? {
        return Ok(0);
    }
    let (mut lo, mut hi) = (1u64, 2u64);
    loop {
        if hi >= MAX_AFFORDABLE {
            if fits(MAX_AFFORDABLE)? {
                return Ok(MAX_AFFORDABLE);
            }
            hi = MAX_AFFORDABLE;
            break;
        }
        if !fits(hi)? {
            break;
        }
        lo = hi;
        hi *= 2;
    }
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if fits(mid)? {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
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

    /// Opens and locks the ledger at `path` that must already exist with
    /// exactly `genesis`: never creates one. A population or scope is
    /// allocated by its owners; a release that finds none (an unrelated
    /// project's, a scope never allocated) is refused, not given a fresh
    /// budget (ENC2719).
    pub fn open_existing(path: &Path, genesis: &Genesis) -> Result<Self> {
        match std::fs::metadata(path) {
            Ok(m) if m.len() > 0 => {}
            _ => {
                return Err(Error::new(
                    Code::GovernancePrivacyScope,
                    format!(
                        "no privacy {} {} at {}: it is allocated by its owners, never created by a release",
                        if genesis.is_population() { "population" } else { "scope" },
                        genesis.asset_id,
                        path.display()
                    ),
                ))
            }
        }
        Self::open(path, genesis)
    }

    pub fn view(&self) -> &LedgerView {
        &self.view
    }

    /// Appends one event durably (fsync) and returns its entry.
    pub fn append(&mut self, event: PrivacyEvent) -> Result<Entry> {
        let (next, entry) = self.view.append_event(event)?;
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
    if f.metadata().map_err(io)?.len() > MAX_LEDGER_BYTES {
        return Err(ledger_err(format!("{} is too large", path.display())));
    }
    let mut lines = BufReader::new(f.take(MAX_LEDGER_BYTES + 1)).lines();
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
