//! Compaction of the governance log's mirror: the mirror in the anchor
//! store grows with the log (one segment per few hundred events); a
//! compaction moves its oldest segments to an archive the operator keeps
//! and prunes them from the anchor store.
//!
//! What it does and does not touch:
//!
//! - The **database's log is never compacted.** Every event stays in
//!   `governance_events` with its tree nodes, checkpoints and witnesses, so
//!   the startup check (the whole log verifies, contains the anchored head,
//!   and nothing a negative set records is undone), the negative sets
//!   (revocations, expiries, withdrawals, key revocations, retirements,
//!   frozen ledgers), inclusion and consistency proofs, evidence bundles
//!   and reports read exactly what they read before. Rollback and
//!   truncation detection do not change.
//! - Only the **mirror** is compacted: it is the copy recovery imports
//!   from after a restore of a backup older than the anchor.
//!
//! A compaction seals a prefix: events `1..=S`, where `S` is the last
//! event of a segment that is not the newest, at least `keep_events`
//! before the anchored size and at least `min_age_secs` old. Its commit
//! point is the anchor's compare-and-set, in the same style as a
//! checkpoint's:
//!
//! 1. the sealed segments are verified (they chain from the previous seal,
//!    or the empty log, to the database's own hash at `S`) and copied,
//!    byte for byte, to the archive, with a manifest listing each segment's
//!    SHA-256; the archive is read back and checked against the manifest;
//! 2. the anchor is replaced (version 3) with a seal: `S`, the chain head
//!    there, and the manifest's digest. **This is the commit point.**
//! 3. the sealed segments are deleted from the anchor store (each only if
//!    its bytes are the archived ones), oldest first.
//!
//! A crash before step 2 leaves archive files nothing refers to (the next
//! compaction writes the same bytes over them, or refuses different ones),
//! the anchor and the mirror as they were. A crash after it leaves the
//! seal and some sealed segments still in the mirror: reading takes events
//! up to the seal as the archive's and ignores them, and the next
//! compaction deletes them. At no point is an event neither in the mirror
//! nor in an archive the anchor commits to.
//!
//! Reading a compacted mirror (start, checkpoints, recovery) starts from
//! the sealed head. A database restored from a backup that ends inside the
//! sealed prefix is recovered with the archive (`recover --archive-dir`),
//! which is checked against the seal: the manifest's digest, every
//! segment's SHA-256, and the whole chain from the empty log to the
//! anchored head.

use std::path::PathBuf;

use encompute_ir::{Code, Error, Result};
use encompute_verification::service::sha256_hex;

use crate::anchor::{AnchorStore, Seal, StoredAnchor};
use crate::archive::{Archive, ArchivedSegment, Manifest, MANIFEST_VERSION};
use crate::control::Control;
use crate::govlog;
use crate::log::LogLine;
use crate::mirror::{scan, SegmentInfo, Segments};

/// Events at the end of the log a compaction leaves in the mirror (about
/// twenty segments).
pub const DEFAULT_KEEP_EVENTS: i64 = 10_000;
/// How old (seconds) the last event of a sealed segment must be.
pub const DEFAULT_MIN_AGE_SECS: u64 = 30 * 24 * 3600;

fn compact_err(m: impl Into<String>) -> Error {
    Error::new(Code::TrustEvidence, m)
}

/// What to compact, and the safety window.
#[derive(Clone, Debug)]
pub struct CompactOptions {
    /// The archive directory (created if missing; the same one every time).
    pub archive_dir: PathBuf,
    /// Never seal an event closer than this to the anchored size.
    pub keep_events: i64,
    /// Never seal a segment whose last event is younger than this.
    pub min_age_secs: u64,
    /// Report what would be done; write and delete nothing.
    pub dry_run: bool,
}

impl CompactOptions {
    pub fn new(archive_dir: impl Into<PathBuf>) -> Self {
        Self {
            archive_dir: archive_dir.into(),
            keep_events: DEFAULT_KEEP_EVENTS,
            min_age_secs: DEFAULT_MIN_AGE_SECS,
            dry_run: false,
        }
    }
}

/// What a compaction did (or, in a dry run, would do).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompactReport {
    pub dry_run: bool,
    /// The sealed size before and after (0: never compacted).
    pub sealed_before: i64,
    pub sealed_after: i64,
    pub archived_segments: usize,
    pub archived_events: i64,
    pub archived_bytes: u64,
    /// Segments deleted from the anchor store (new ones and leftovers of an
    /// earlier compaction).
    pub pruned_segments: usize,
    /// What the mirror holds after: the tail.
    pub mirror_segments: usize,
    pub mirror_events: i64,
    pub mirror_bytes: u64,
    /// Why there is nothing to do, or what was left in place.
    pub notes: Vec<String>,
}

impl CompactReport {
    /// One line per fact, for the command line.
    pub fn lines(&self) -> Vec<String> {
        let mut v = vec![format!(
            "{}governance log mirror: sealed through event {} (was {}): {} segments, {} events, {} bytes archived; {} segments pruned; the mirror now holds {} segments, {} events, {} bytes",
            if self.dry_run { "DRY RUN, nothing written: " } else { "" },
            self.sealed_after,
            self.sealed_before,
            self.archived_segments,
            self.archived_events,
            self.archived_bytes,
            self.pruned_segments,
            self.mirror_segments,
            self.mirror_events,
            self.mirror_bytes,
        )];
        v.extend(self.notes.iter().cloned());
        v
    }
}

/// An in-memory set of segments (the ones about to be archived), to
/// verify them as the mirror's reader would.
struct Mem(Vec<(u64, String)>);

impl Segments for Mem {
    fn list(&self) -> Result<Vec<u64>> {
        Ok(self.0.iter().map(|(n, _)| *n).collect())
    }

    fn read(&self, n: u64) -> Result<String> {
        self.0
            .iter()
            .find(|(m, _)| *m == n)
            .map(|(_, l)| l.clone())
            .ok_or_else(|| compact_err(format!("segment {n}")))
    }
}

impl Control {
    /// Compacts the governance log mirror (see the module documentation).
    /// The mirror must verify against the anchor first; a refusal changes
    /// nothing.
    pub fn compact_mirror(&self, o: &CompactOptions) -> Result<CompactReport> {
        if o.keep_events < 0 {
            return Err(Error::new(
                Code::BadInput,
                "--keep-events must not be negative",
            ));
        }
        let store = self.anchor.store();
        let a = self.anchor.snapshot();
        let seal0 = a.seal.clone();
        let s0 = seal0.as_ref().map_or(0, |s| s.size);
        // The mirror, verified against the anchor (as the start does).
        let scanned = scan(store, seal0.as_ref(), a.glog_size, &a.glog_head, None)?;
        let mut report = CompactReport {
            dry_run: o.dry_run,
            sealed_before: s0,
            sealed_after: s0,
            ..Default::default()
        };

        // The sealed prefix: whole segments of the run that reached the
        // anchored size, from the seal on, never the newest (the writer
        // extends it), inside the retention window.
        let run: Vec<&SegmentInfo> = scanned
            .run
            .iter()
            .filter_map(|n| scanned.segments.iter().find(|s| s.n == *n))
            .filter(|s| s.first > s0)
            .collect();
        let now = encompute_verification::service::now();
        let mut chosen: Vec<&SegmentInfo> = vec![];
        let mut expect = s0 + 1;
        let mut why = String::new();
        for (i, seg) in run.iter().enumerate() {
            if i + 1 == run.len() {
                why = "the newest segment stays (the writer extends it)".into();
                break;
            }
            if seg.first != expect {
                why = format!(
                    "segment {} starts at event {}, not at {expect}: not sealed",
                    seg.n, seg.first
                );
                break;
            }
            if seg.last > a.glog_size - o.keep_events {
                why = format!(
                    "segment {} ends at event {}, inside the last {} events that stay in the mirror",
                    seg.n, seg.last, o.keep_events
                );
                break;
            }
            if seg.last_at.saturating_add(o.min_age_secs) > now {
                why = format!(
                    "segment {} ends with an event younger than {} seconds",
                    seg.n, o.min_age_secs
                );
                break;
            }
            chosen.push(seg);
            expect = seg.last + 1;
        }
        // Segments a crash after an earlier commit left behind: wholly
        // inside the sealed prefix.
        let leftovers: Vec<&SegmentInfo> =
            scanned.segments.iter().filter(|s| s.last <= s0).collect();
        if chosen.is_empty() && leftovers.is_empty() {
            report.mirror_segments = run.len();
            report.mirror_events = a.glog_size - s0;
            report.mirror_bytes = run.iter().map(|s| s.bytes as u64).sum();
            report.notes.push(format!(
                "nothing to compact: {}",
                if why.is_empty() {
                    "the mirror holds no segment past the seal".into()
                } else {
                    why
                }
            ));
            return Ok(report);
        }

        // Read what is chosen, exactly as the store holds it.
        let mut texts: Vec<(u64, String)> = vec![];
        let mut sealed_head = a.glog_head.clone();
        let mut sealed_size = s0;
        if let Some(last) = chosen.last() {
            for seg in &chosen {
                let text = store.mirror_read(seg.n)?;
                if text.len() != seg.bytes {
                    return Err(compact_err(format!(
                        "governance log mirror segment {} changed while compacting",
                        seg.n
                    )));
                }
                texts.push((seg.n, text));
            }
            sealed_size = last.last;
            let (_, lines) = texts.last().expect("chosen is not empty");
            let tail = lines.lines().rev().find(|l| !l.trim().is_empty());
            sealed_head = tail
                .and_then(|l| serde_json::from_str::<govlog::Exported>(l).ok())
                .map(|x| x.hash)
                .ok_or_else(|| compact_err("the last sealed segment has no events"))?;
            // They chain from the previous seal (or the empty log) to the
            // head the database holds at that event.
            scan(
                &Mem(texts.clone()),
                seal0.as_ref(),
                sealed_size,
                &sealed_head,
                None,
            )?;
            let mut c = self.db.conn()?;
            if govlog::hash_at(&mut *c, sealed_size)?.as_deref() != Some(sealed_head.as_str()) {
                return Err(compact_err(format!(
                    "the database's governance log does not hold the mirror's event {sealed_size}: not compacting"
                )));
            }
        }
        report.sealed_after = sealed_size;
        report.archived_segments = chosen.len();
        report.archived_events = sealed_size - s0;
        report.archived_bytes = texts.iter().map(|(_, t)| t.len() as u64).sum();
        let pruned: Vec<u64> = leftovers
            .iter()
            .map(|s| s.n)
            .chain(chosen.iter().map(|s| s.n))
            .collect();
        report.pruned_segments = pruned.len();
        report.mirror_segments = run.len() - chosen.len();
        report.mirror_events = a.glog_size - sealed_size;
        report.mirror_bytes = run.iter().skip(chosen.len()).map(|s| s.bytes as u64).sum();
        if o.dry_run {
            return Ok(report);
        }

        // 1. The archive: the previous one (verified whole), then the new
        //    segments and the manifest, read back against it.
        let mut manifest_segments: Vec<ArchivedSegment> = vec![];
        let archive = Archive::open(&o.archive_dir, true)?;
        if let Some(prior) = &seal0 {
            let v = archive.load(prior, true).map_err(|e| {
                compact_err(format!(
                    "the archive does not hold the manifest of the previous seal ({}): {}",
                    prior.size, e.message
                ))
            })?;
            manifest_segments = v.manifest.segments;
        }
        let mut seal = seal0.clone();
        if !chosen.is_empty() {
            for ((n, text), seg) in texts.iter().zip(&chosen) {
                manifest_segments.push(archive.put_segment(*n, seg.first, seg.last, text)?);
            }
            let manifest = Manifest {
                v: MANIFEST_VERSION,
                size: sealed_size,
                head: sealed_head.clone(),
                segments: manifest_segments,
            };
            let new_seal = manifest.seal()?;
            archive.put_manifest(&manifest)?;
            archive.load(&new_seal, true)?;

            // 2. The commit point: the anchor with the seal.
            let committed = new_seal.clone();
            self.anchor.try_update(&self.signer, |cur| {
                let cur_size = cur.seal.as_ref().map_or(0, |x| x.size);
                if cur_size != s0 || cur.glog_size < sealed_size {
                    return Err(compact_err(
                        "the anchor changed while compacting (another compaction?): nothing was sealed; run it again",
                    ));
                }
                let mut c = self.db.conn()?;
                if govlog::hash_at(&mut *c, sealed_size)?.as_deref() != Some(committed.head.as_str())
                {
                    return Err(compact_err(
                        "the database's governance log does not hold the sealed head: nothing was sealed",
                    ));
                }
                cur.seal = Some(committed.clone());
                Ok(true)
            })?;
            seal = Some(new_seal);
        }

        // 3. Prune what the archive holds, oldest first.
        let Some(seal) = seal else {
            return Ok(report);
        };
        let manifest = archive.load(&seal, false)?.manifest;
        let mut pruned_ok = 0usize;
        let mut ordered = pruned;
        ordered.sort_unstable();
        for n in ordered {
            let Some(entry) = manifest.segments.iter().find(|s| s.n == n).cloned() else {
                report.notes.push(format!(
                    "segment {n} is inside the sealed prefix but not archived under that number: left in place"
                ));
                continue;
            };
            let r = store.mirror_delete(n, &move |cur: Option<&str>| match cur {
                Some(c)
                    if c.len() as u64 == entry.bytes
                        && sha256_hex(c.as_bytes()) == entry.sha256 =>
                {
                    Ok(())
                }
                _ => Err(compact_err(format!(
                    "mirror segment {n} is not the archived one: left in place"
                ))),
            });
            match r {
                Ok(()) => pruned_ok += 1,
                Err(e) if e.message.contains("left in place") => report.notes.push(e.message),
                Err(e) => {
                    return Err(compact_err(format!(
                        "sealed through event {sealed_size}, but pruning stopped at mirror segment {n}: {}; run the compaction again to finish",
                        e.message
                    )))
                }
            }
        }
        report.pruned_segments = pruned_ok;
        // The mirror as it is now still verifies against the anchor.
        let a2 = self.anchor.snapshot();
        let after = scan(store, a2.seal.as_ref(), a2.glog_size, &a2.glog_head, None)?;
        let tail: Vec<&SegmentInfo> = after
            .run
            .iter()
            .filter_map(|n| after.segments.iter().find(|s| s.n == *n))
            .collect();
        report.mirror_segments = tail.len();
        report.mirror_bytes = tail.iter().map(|s| s.bytes as u64).sum();
        report.mirror_events = a2.glog_size - sealed_size;
        LogLine::new(&self.service_id, "governance_mirror_compacted")
            .field("sealed_before", s0)
            .field("sealed_after", sealed_size)
            .field("archived_segments", report.archived_segments as i64)
            .field("pruned_segments", pruned_ok as i64)
            .field("mirror_segments", report.mirror_segments as i64)
            .emit();
        Ok(report)
    }
}

/// What [`verify_archive`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveReport {
    pub sealed: i64,
    pub segments: usize,
}

/// Checks an archive against the anchor in `store` (no database needed):
/// the anchor is this control plane's, carries a seal, the archive's
/// manifest is the sealed one, every segment is the listed bytes, and the
/// events chain from the empty log to the sealed head.
pub fn verify_archive(
    store: &dyn AnchorStore,
    control_key: &str,
    dir: &std::path::Path,
) -> Result<ArchiveReport> {
    let a = match store.load()? {
        Some(StoredAnchor::V2(a)) => a,
        Some(StoredAnchor::V1(_)) => {
            return Err(compact_err(
                "the state anchor is version 1: nothing is sealed",
            ))
        }
        None => return Err(compact_err("there is no state anchor")),
    };
    a.verify(control_key)?;
    let seal: Seal = a.seal.clone().ok_or_else(|| {
        compact_err("the state anchor holds no seal: the mirror was never compacted")
    })?;
    let v = Archive::open(dir, false)?.load(&seal, true)?;
    scan(&v, None, seal.size, &seal.head, None)?;
    Ok(ArchiveReport {
        sealed: seal.size,
        segments: v.manifest.segments.len(),
    })
}
