//! The governance log's mirror in the anchor store: every checkpoint
//! writes the events since the mirror's end **before** the anchor is
//! replaced (the anchor's compare-and-set stays the commit point), so the
//! anchor store holds every anchored event. After a database backup older
//! than the anchor is restored, recovery takes the missing events from the
//! mirror.
//!
//! Layout: segments numbered `1, 2, ...` (the segment's number is its only
//! name; the events it holds are in its lines). Each holds contiguous
//! events, at most [`SEGMENT_EVENTS`] and about [`SEGMENT_BYTES`] bytes. A
//! checkpoint **extends the last, not yet full, segment by replacing it**
//! with a longer one holding the same events and the new ones (atomically:
//! a reader sees the old or the new whole), and creates further segments
//! only when it fills, so the segment count grows with the log's size, not
//! with the number of checkpoints. A new segment is created with one
//! atomic create-only operation on its name: two writers racing for it,
//! exactly one wins and the other fails closed.
//!
//! The signed anchor is the only authority over the mirror:
//!
//! - Only the events up to the anchored size are ever used, and only when
//!   they chain to the anchored head (each leaf, partition position and
//!   chain hash recomputed). Events beyond it (a crash between the mirror's
//!   write and the anchor's update) are an orphan suffix: logged, never
//!   recovered from, and overwritten from the database's own events at the
//!   next checkpoint, whatever they say.
//! - Writing never trusts the mirror's own content: where the mirror ends
//!   comes from the database's event at the last position the newest valid
//!   segment holds. A torn, planted or garbage segment is ignored and
//!   overwritten; it cannot wedge checkpointing or a rebuild.
//! - Reading takes segments in number order. A segment that starts at event
//!   1 begins the mirror again (a rebuild: what recovery writes when it
//!   replaces a damaged mirror from a database that extends the anchor).
//!   Every start streams the mirror once, segment by segment, with a
//!   running hash, and refuses a mirror that is truncated, reordered,
//!   forked, edited, overlapping or damaged below the anchored size
//!   (GOVERNANCE LOG STATE ROLLBACK). A segment larger than the read bound
//!   is refused.
//!
//! One control plane per anchor store: the compare-and-set of the anchor
//! and of each new segment make a second writer fail closed rather than
//! corrupt the mirror, but only one is supported (a replaced segment is a
//! plain atomic replace).
//!
//! The mirror is never pruned below the anchored head except by a
//! compaction (`crate::compact`): the sealed prefix, events `1..=size`, is
//! copied to an archive and the anchor's seal commits to it; the mirror
//! then holds the tail, from event `size + 1`, which reading verifies from
//! the sealed head instead of from the empty log. Everything above holds
//! for the tail: the anchored head is the authority, a truncated, gapped,
//! forked or edited tail is refused, and a segment that covers the seal
//! (an old copy of a pruned one, say) only begins the tail again.

use std::collections::HashMap;
use std::sync::Mutex;

use encompute_ir::{Code, Error, Result};
use encompute_trust::govlog::{chain_hash, hash_hex, parse_hash, Hash, CHAIN_GENESIS};

use crate::anchor::{AnchorStore, Seal};
use crate::control::Control;
use crate::govlog::{self, Exported};
use crate::log::LogLine;

/// The most events one segment holds.
pub const SEGMENT_EVENTS: usize = 500;
/// The bytes after which a segment is full (an OpenBao KV entry is limited
/// to 1 MiB; a read refuses more than `anchor::MIRROR_MAX_READ`).
pub const SEGMENT_BYTES: usize = 256 * 1024;
/// How many of the newest segments the writer looks through for the last
/// valid one before it starts the mirror over.
const WALK: usize = 16;

fn mirror_err(m: impl Into<String>) -> Error {
    Error::new(Code::TrustEvidence, m)
}

fn is_concurrent(e: &Error) -> bool {
    e.message.contains("written concurrently")
}

/// A segment's events: contiguous, from its first position.
fn parse(n: u64, lines: &str) -> Result<Vec<Exported>> {
    let bad = |m: &str| mirror_err(format!("governance log mirror segment {n}: {m}"));
    let mut out: Vec<Exported> = vec![];
    for line in lines.lines().filter(|l| !l.trim().is_empty()) {
        let x: Exported = serde_json::from_str(line).map_err(|e| bad(&e.to_string()))?;
        if out.last().is_some_and(|p| x.gseq != p.gseq + 1) || x.gseq < 1 {
            return Err(bad("its events are not contiguous"));
        }
        out.push(x);
    }
    if out.is_empty() {
        return Err(bad("it holds no events"));
    }
    Ok(out)
}

/// The segments at or below `max_n` (the sealed range: the highest number
/// the archive holds) that the mirror's reader cannot parse, each named
/// with the store and its number (the KV key's last component). The reader
/// ignores such a segment below the seal, so nothing else would ever say it
/// is there; it is reported, never deleted (its bytes cannot be compared
/// with the archive's).
pub fn unparseable_sealed(store: &dyn AnchorStore, max_n: u64) -> Result<Vec<String>> {
    let mut nums = store.mirror_list()?;
    nums.sort_unstable();
    let mut out = vec![];
    for n in nums.into_iter().filter(|n| *n <= max_n) {
        let bad = match store.mirror_read(n) {
            Ok(text) => parse(n, &text).err().map(|e| e.message),
            Err(e) => Some(e.message),
        };
        if let Some(why) = bad {
            out.push(format!(
                "mirror segment {n:012} ({}) is in the sealed range but cannot be parsed ({why}): left in place, never deleted; check it against the archive and remove it by hand",
                store.describe()
            ));
        }
    }
    Ok(out)
}

/// The newest segment the writer extends: its number, its first and last
/// event positions, the last one's chain hash (`None` for a segment to
/// rewrite from its first position) and whether it is full.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Open {
    n: u64,
    from: i64,
    to: i64,
    hash: Option<String>,
    full: bool,
    /// Extend by replacing segment `n` (it exists and is the mirror's
    /// own), as opposed to creating it.
    replace: bool,
}

/// The mirror's open segment as written last (one control plane per
/// anchor store).
#[derive(Default)]
pub struct TailCache(Mutex<Option<Open>>);

impl TailCache {
    fn get(&self) -> Option<Open> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn set(&self, o: Option<Open>) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = o;
    }
}

/// What a scan calls with each verified event.
pub type Each<'a> = dyn FnMut(&Exported) -> Result<()> + 'a;

/// Where a scan reads segments from: the anchor store's mirror, or an
/// archive (checked as it is read), or both ([`Layered`]).
pub trait Segments {
    /// The segment numbers, in any order.
    fn list(&self) -> Result<Vec<u64>>;
    /// A segment's lines.
    fn read(&self, n: u64) -> Result<String>;
}

impl<T: AnchorStore + ?Sized> Segments for T {
    fn list(&self) -> Result<Vec<u64>> {
        self.mirror_list()
    }

    fn read(&self, n: u64) -> Result<String> {
        self.mirror_read(n)
    }
}

/// The archive's segments and, for the numbers it does not hold, the
/// mirror's: every event of the log from the first (recovery, when a
/// restored database ends inside the sealed prefix).
pub struct Layered<'a> {
    pub mirror: &'a dyn AnchorStore,
    pub archive: &'a crate::archive::Verified,
}

impl Segments for Layered<'_> {
    fn list(&self) -> Result<Vec<u64>> {
        let mut nums = self.mirror.mirror_list()?;
        nums.extend(Segments::list(self.archive)?);
        nums.sort_unstable();
        nums.dedup();
        Ok(nums)
    }

    fn read(&self, n: u64) -> Result<String> {
        if Segments::list(self.archive)?.contains(&n) {
            Segments::read(self.archive, n)
        } else {
            self.mirror.mirror_read(n)
        }
    }
}

/// A segment a scan parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentInfo {
    pub n: u64,
    pub first: i64,
    pub last: i64,
    pub bytes: usize,
    /// When the segment's last event happened (`at`, seconds).
    pub last_at: u64,
}

/// What a scan found.
#[derive(Debug)]
pub struct Scanned {
    /// The last event position seen, anchored or not.
    pub end: i64,
    /// Every segment that parsed, in number order.
    pub segments: Vec<SegmentInfo>,
    /// The numbers of the segments of the run that reached the anchored
    /// size (a run begins at a segment that covers the base: event 1, or
    /// the seal's).
    pub run: Vec<u64>,
}

/// Streams the mirror once, segment by segment: the first `size` events
/// must chain, recomputed, to `head`, from the empty log or, with `base`
/// (the anchor's seal), from the sealed head: the events up to it are the
/// archive's and are not read. `each` sees every verified event (in
/// order) as it is checked. Nothing is held beyond one segment.
pub fn scan<S: Segments + ?Sized>(
    store: &S,
    base: Option<&Seal>,
    size: i64,
    head: &str,
    mut each: Option<&mut Each<'_>>,
) -> Result<Scanned> {
    let mut nums = store.list()?;
    nums.sort_unstable();
    let genesis = hash_hex(&CHAIN_GENESIS);
    let (base_size, base_head) = match base {
        Some(b) => (b.size, b.head.clone()),
        None => (0, genesis.clone()),
    };
    let base_hash: Hash =
        parse_hash("sealed head", &base_head).map_err(|e| mirror_err(e.message))?;
    // A base that is not the anchored head at the anchored size cannot be
    // reached by any events.
    let base_mismatch = || -> Option<String> {
        (size == base_size && base_head != head).then(|| {
            if base.is_some() {
                "the anchor's seal holds a head that is not the anchored head".into()
            } else {
                "the anchored head of an empty log is not the empty head".into()
            }
        })
    };
    let mut prev: Hash = base_hash;
    let mut last = base_size;
    let mut pseqs: HashMap<String, u64> = HashMap::new();
    let mut pending: Option<String> = base_mismatch();
    let mut reached = size == base_size;
    let mut end = 0i64;
    let mut segments = vec![];
    let mut run: Vec<u64> = vec![];
    for n in nums {
        let bad = |m: String| format!("governance log mirror segment {n}: {m}");
        let text = store.read(n);
        let bytes = text.as_ref().map_or(0, |t| t.len());
        let events = match text.and_then(|l| parse(n, &l)) {
            Ok(e) => e,
            Err(e) => {
                // Damage past the anchored size is an orphan; below it,
                // an error unless a rebuild follows.
                if !reached {
                    pending.get_or_insert(e.message);
                }
                continue;
            }
        };
        let first = events[0].gseq;
        segments.push(SegmentInfo {
            n,
            first,
            last: events[events.len() - 1].gseq,
            bytes,
            last_at: events[events.len() - 1].event.at,
        });
        let starts_run = first <= base_size + 1;
        if starts_run {
            prev = base_hash;
            last = base_size;
            pseqs.clear();
            pending = base_mismatch();
            reached = size == base_size;
            run.clear();
        } else if reached && first > size {
            end = end.max(events[events.len() - 1].gseq);
            continue;
        } else if first != last + 1 {
            pending.get_or_insert(bad(format!(
                "it starts at event {first}, after event {last} (overlap or gap)"
            )));
            continue;
        }
        if first <= size {
            run.push(n);
        }
        for x in &events {
            if starts_run && x.gseq <= base_size {
                continue; // covered by the seal: the archive's, not read
            }
            if x.gseq > size {
                end = end.max(x.gseq);
                continue;
            }
            let b = |m: &str| mirror_err(format!("governance log mirror, event {}: {m}", x.gseq));
            // From a seal, a partition's position at the seal is not
            // known here (the database's own log checks it at import and
            // at every start): its first event in the tail sets it.
            let p = pseqs
                .entry(x.event.partition.clone())
                .or_insert(if base.is_some() {
                    x.event.pseq.saturating_sub(1)
                } else {
                    0
                });
            if x.event.pseq != *p + 1 {
                pending.get_or_insert(b("its partition's positions are not contiguous").message);
                break;
            }
            let h = chain_hash(&prev, x.gseq as u64, &x.event.leaf_hash()?);
            if hash_hex(&h) != x.hash {
                pending.get_or_insert(b("modified (its chain hash differs)").message);
                break;
            }
            *p = x.event.pseq;
            prev = h;
            last = x.gseq;
            end = end.max(last);
            if let Some(f) = each.as_mut() {
                f(x)?;
            }
            if last == size {
                if hash_hex(&prev) != head {
                    pending.get_or_insert(format!(
                        "the governance log mirror does not hold the anchored head at event {size} (another history)"
                    ));
                }
                reached = true;
            }
        }
    }
    if let Some(e) = pending {
        return Err(mirror_err(e));
    }
    if !reached {
        return Err(mirror_err(format!(
            "the governance log mirror ends at event {last}, before the anchored {size} (truncated)"
        )));
    }
    Ok(Scanned { end, segments, run })
}

impl Control {
    /// Where the writer extends the mirror: from the database's own
    /// events, never from what the mirror says it holds.
    fn find_open(&self, c: &mut postgres::Client, anchored: i64, base: i64) -> Result<Open> {
        let store = self.anchor.store();
        let mut nums = store.mirror_list()?;
        nums.sort_unstable_by(|a, b| b.cmp(a));
        for n in nums.iter().take(WALK) {
            let Ok(events) = store.mirror_read(*n).and_then(|l| parse(*n, &l)) else {
                continue; // torn, planted or garbage: ignored, overwritten
            };
            let (first, lastx) = (events[0].gseq, &events[events.len() - 1]);
            let bytes: usize = events.iter().map(|e| e.hash.len() + 256).sum();
            let full = events.len() >= SEGMENT_EVENTS || bytes + 8192 > SEGMENT_BYTES;
            if govlog::hash_at(c, lastx.gseq)?.as_deref() == Some(lastx.hash.as_str()) {
                return Ok(Open {
                    n: *n,
                    from: first,
                    to: lastx.gseq,
                    hash: Some(lastx.hash.clone()),
                    full,
                    replace: true,
                });
            }
            if lastx.gseq <= anchored {
                return Err(Error::new(
                    Code::PrivacyLedger,
                    format!(
                        "GOVERNANCE LOG STATE ROLLBACK: the governance log mirror differs from the database's anchored log at event {}. REFUSED: run `encompute-control recover` to rebuild it (see docs/deployment.md)",
                        lastx.gseq
                    ),
                ));
            }
            // An orphaned suffix (a crash between the mirror and the
            // anchor), or a planted segment: overwritten from the
            // database's own events.
            LogLine::new(&self.service_id, "governance_mirror_orphan")
                .field("segment", *n)
                .field("anchored", anchored)
                .field("action", "the mirror's events past the anchored head differ from the database's: rewritten from the database")
                .emit();
            if first <= anchored {
                // It holds anchored events too: rewrite it from its start.
                return Ok(Open {
                    n: *n,
                    from: first,
                    to: first - 1,
                    hash: None,
                    full: false,
                    replace: true,
                });
            }
            // Entirely past the anchored size (so there may be a gap
            // before it): never extend it from its own start; keep
            // looking for the last valid segment before it, or start over.
        }
        // Starting over: from the seal's tail when the mirror was
        // compacted (the sealed events are the archive's), else from the
        // first event.
        let next = nums.first().map_or(1, |m| m + 1);
        Ok(Open {
            n: next,
            from: base + 1,
            to: base,
            hash: None,
            full: false,
            replace: false,
        })
    }

    /// Writes segment `n`: replaces it when `replace` (the open segment),
    /// otherwise creates it, overwriting only a damaged one or an orphan
    /// that starts past the anchored size; another valid one means another
    /// writer won it (fail closed).
    fn write_segment(&self, n: u64, lines: &str, replace: bool, anchored: i64) -> Result<()> {
        let store = self.anchor.store();
        // What the store's own anchor says is anchored, if more than this
        // writer knows (another instance, or this one's stale view): a
        // replacement never shrinks or alters what it anchored.
        let anchored = anchored.max(self.stored_glog_size());
        let allow = move |cur: Option<&str>| -> Result<()> {
            let Some(old) = cur.and_then(|c| parse(n, c).ok()) else {
                return Ok(()); // damaged or unreadable: nothing to keep
            };
            let new = parse(n, lines)?;
            let keep = old[old.len() - 1].gseq.min(anchored);
            if old[0].gseq > keep {
                return Ok(()); // entirely past the anchored size: an orphan
            }
            let hash_at =
                |v: &[Exported]| v.iter().find(|x| x.gseq == keep).map(|x| x.hash.clone());
            if hash_at(&new).is_none() || hash_at(&new) != hash_at(&old) {
                return Err(mirror_err(format!(
                    "refusing to replace governance log mirror segment {n}: the replacement does not keep its anchored events through {keep} (a stale or forked writer)"
                )));
            }
            Ok(())
        };
        if replace {
            return store.mirror_replace(n, lines, &allow);
        }
        match store.mirror_create(n, lines) {
            Err(e) if is_concurrent(&e) => match store.mirror_read(n).and_then(|l| parse(n, &l)) {
                Err(_) => store.mirror_replace(n, lines, &allow),
                Ok(old) if old[0].gseq > anchored => store.mirror_replace(n, lines, &allow),
                Ok(_) => Err(e),
            },
            other => other,
        }
    }

    /// The anchored size the store's own anchor holds (0 if none, or not
    /// readable now).
    fn stored_glog_size(&self) -> i64 {
        match self.anchor.store().load() {
            Ok(Some(crate::anchor::StoredAnchor::V2(a))) => a.glog_size,
            _ => 0,
        }
    }

    /// Writes the database's events from `o` through `size` into segments,
    /// starting by extending `o`; leaves the open segment cached.
    fn write_from(
        &self,
        c: &mut postgres::Client,
        mut o: Open,
        anchored: i64,
        size: i64,
    ) -> Result<()> {
        let mut n = o.n;
        let mut from = if o.full { o.to + 1 } else { o.from };
        let mut replace = o.replace && !o.full;
        if o.full {
            n += 1;
            replace = false;
        }
        loop {
            let mut lines = String::new();
            let mut count = 0usize;
            let mut cursor = from - 1;
            let mut last: Option<Exported> = None;
            let mut full = false;
            'fill: while cursor < size && count < SEGMENT_EVENTS {
                let take = (SEGMENT_EVENTS - count) as i64;
                let batch = govlog::exported(c, cursor, size.min(cursor + take))?;
                if batch.is_empty() {
                    break;
                }
                for x in batch {
                    let l = govlog::to_lines(std::slice::from_ref(&x))?;
                    if count > 0 && lines.len() + l.len() > SEGMENT_BYTES {
                        full = true;
                        break 'fill;
                    }
                    lines.push_str(&l);
                    count += 1;
                    cursor = x.gseq;
                    last = Some(x);
                }
            }
            full = full || count >= SEGMENT_EVENTS || lines.len() >= SEGMENT_BYTES;
            let Some(l) = last else { break };
            let t0 = std::time::Instant::now();
            self.write_segment(n, &lines, replace, anchored)?;
            if replace {
                // The open segment's rewrite: its size and time.
                self.metrics
                    .set("encompute_mirror_rewrite_bytes", "all", lines.len() as i64);
                self.metrics.observe(
                    "encompute_mirror_write_seconds",
                    "open",
                    t0.elapsed().as_secs_f64(),
                );
            }
            o = Open {
                n,
                from,
                to: l.gseq,
                hash: Some(l.hash.clone()),
                full,
                replace: true,
            };
            self.mirror.set(Some(o.clone()));
            if l.gseq >= size {
                break;
            }
            n += 1;
            from = l.gseq + 1;
            replace = false;
        }
        // Planted or orphaned segments after the last one written that
        // start at or below `size` would overlap what was just written:
        // blanked (an unreadable segment past the anchored head is ignored).
        let store = self.anchor.store();
        let written = self.mirror.get().map_or(0, |o| o.n);
        let stored = anchored.max(self.stored_glog_size());
        for m in store.mirror_list()? {
            if m <= written {
                continue;
            }
            let Some(old) = store.mirror_read(m).ok().and_then(|l| parse(m, &l).ok()) else {
                continue;
            };
            if old[0].gseq <= size {
                store.mirror_replace(m, "", &move |cur: Option<&str>| {
                    match cur.and_then(|c| parse(m, c).ok()) {
                        Some(o) if o[0].gseq <= stored => Err(mirror_err(format!(
                            "governance log mirror segment {m} overlaps the mirror and holds anchored events"
                        ))),
                        _ => Ok(()),
                    }
                })?;
            }
        }
        // Whatever the mirror held, it must now reach `size` with the
        // database's own event there: the anchor never moves past a mirror
        // that does not hold every anchored event.
        match self.mirror.get() {
            Some(o) if o.to >= size && govlog::hash_at(c, size)? == o.hash => Ok(()),
            _ => Err(mirror_err(format!(
                "the governance log mirror does not reach event {size} after writing (planted or damaged segments?); the anchor is not moved"
            ))),
        }
    }

    /// Mirrors the database's events up to `size` before the anchor moves
    /// there from `anchored`.
    ///
    /// `base` is the size the anchor's seal holds (0 if the mirror was
    /// never compacted): a mirror that has to start over starts after it.
    pub(crate) fn mirror_through(&self, anchored: i64, size: i64, base: i64) -> Result<()> {
        let anchored = anchored.max(self.stored_glog_size());
        let mut c = self.db.conn()?;
        let cached = match self.mirror.get() {
            Some(o) if o.hash.is_some() && govlog::hash_at(&mut *c, o.to)? == o.hash => Some(o),
            _ => None,
        };
        let res = (|| {
            let o = match cached {
                Some(o) => o,
                None => self.find_open(&mut c, anchored, base)?,
            };
            if o.hash.is_some() && o.to >= size {
                return Ok(());
            }
            self.write_from(&mut c, o, anchored, size)
        })();
        if res.is_err() {
            self.mirror.set(None);
        }
        res
    }

    /// The startup check: the mirror chains to the anchored head. Logs an
    /// orphaned suffix.
    pub(crate) fn check_mirror(&self, size: i64, head: &str, seal: Option<&Seal>) -> Result<()> {
        let s = scan(self.anchor.store(), seal, size, head, None)?;
        if s.end > size {
            LogLine::new(&self.service_id, "governance_mirror_orphan")
                .field("mirror_end", s.end)
                .field("anchored", size)
                .field("action", "ignored: events past the anchored head are never recovered from; the next checkpoint mirrors the database's own")
                .emit();
        }
        Ok(())
    }

    /// Imports the anchored events the database lacks from the mirror,
    /// streaming, exactly up to the anchored head (never an orphaned
    /// suffix). Returns how many were added.
    ///
    /// After a compaction the mirror holds the tail only: a database that
    /// ends at or after the sealed size is completed from it. One that
    /// ends inside the sealed prefix needs `archive` (the directory the
    /// compaction wrote to), checked against the anchor's seal: then the
    /// whole log is read from its first event, archive and mirror together,
    /// and verified end to end.
    ///
    /// All of it is one transaction (see [`govlog::Importer`]): a failure
    /// or a crash anywhere leaves the database as it was.
    pub(crate) fn import_from_mirror(
        &self,
        a: &crate::anchor::StateAnchor,
        archive: Option<&std::path::Path>,
    ) -> Result<u64> {
        let (size, head) = (a.glog_size, a.glog_head.as_str());
        let store = self.anchor.store();
        let mut from_archive = None;
        if let Some(seal) = &a.seal {
            let have = {
                let mut c = self.db.conn()?;
                let (n, _) = c
                    .query_one("SELECT gseq, hash FROM governance_head WHERE id", &[])
                    .map(|r| (r.get::<_, i64>(0), r.get::<_, String>(1)))
                    .map_err(crate::db::db_err)?;
                n
            };
            if have < seal.size {
                let Some(dir) = archive else {
                    return Err(mirror_err(format!(
                        "the database's log ends at event {have}, inside the sealed prefix (events 1..={} were compacted out of the mirror into an archive): run recovery with the archive (`recover --archive-dir DIR`, see docs/deployment.md)",
                        seal.size
                    )));
                };
                from_archive = Some(crate::archive::Archive::open(dir, false)?.load(seal, false)?);
            }
        }
        let run = |t: &mut postgres::Transaction<'_>| -> Result<u64> {
            let mut imp = govlog::Importer::new(t)?;
            let each = &mut |x: &Exported| imp.push(t, x);
            match &from_archive {
                // The whole log, from its first event.
                Some(v) => scan(
                    &Layered {
                        mirror: store,
                        archive: v,
                    },
                    None,
                    size,
                    head,
                    Some(each),
                )?,
                None => scan(store, a.seal.as_ref(), size, head, Some(each))?,
            };
            imp.finish(t)
        };
        // First pass: the log chains to the anchored head, before
        // anything is written.
        match &from_archive {
            Some(v) => scan(
                &Layered {
                    mirror: store,
                    archive: v,
                },
                None,
                size,
                head,
                None,
            )?,
            None => scan(store, a.seal.as_ref(), size, head, None)?,
        };
        self.db.tx(run)
    }

    /// Rebuilds the whole mirror from the database's log up to `size`
    /// (recovery, after the database's log was checked against the
    /// anchor), as a new run starting at event 1 after every segment there
    /// is, damaged or not.
    pub(crate) fn rebuild_mirror(&self, size: i64, seal: Option<&Seal>) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        // After a compaction the rebuilt run is the tail: the sealed
        // events are the archive's and are not written back.
        let base = seal.map_or(0, |s| s.size);
        let next = self
            .anchor
            .store()
            .mirror_list()?
            .into_iter()
            .max()
            .map_or(1, |m| m + 1);
        let mut c = self.db.conn()?;
        let o = Open {
            n: next,
            from: base + 1,
            to: base,
            hash: None,
            full: false,
            replace: false,
        };
        let r = self.write_from(&mut c, o, size, size);
        if r.is_err() {
            self.mirror.set(None);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encompute_trust::govlog::{GovEvent, GOVLOG_VERSION};
    use std::collections::BTreeMap;

    /// Segments in memory: (number, lines).
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
                .ok_or_else(|| mirror_err("no such segment"))
        }
    }

    /// A well-formed chain of `n` events over three partitions.
    fn chain(n: usize) -> Vec<Exported> {
        let mut out = vec![];
        let mut prev = CHAIN_GENESIS;
        let mut pseqs: HashMap<String, u64> = HashMap::new();
        for g in 1..=n {
            let partition = ["platform", "o:org-a", "o:org-b"][g % 3].to_owned();
            let p = pseqs.entry(partition.clone()).or_insert(0);
            *p += 1;
            let event = GovEvent {
                v: GOVLOG_VERSION,
                partition,
                pseq: *p,
                kind: "role.removed".into(),
                subject: format!("rol_{g}"),
                org: None,
                at: 1_000 + g as u64,
                refs: BTreeMap::new(),
            };
            prev = chain_hash(&prev, g as u64, &event.leaf_hash().unwrap());
            out.push(Exported {
                gseq: g as i64,
                hash: hash_hex(&prev),
                event,
                anchor: None,
            });
        }
        out
    }

    /// Segments of `per` events each, numbered from `first_n`.
    fn segments(events: &[Exported], per: usize, first_n: u64) -> Vec<(u64, String)> {
        events
            .chunks(per)
            .enumerate()
            .map(|(i, c)| (first_n + i as u64, crate::govlog::to_lines(c).unwrap()))
            .collect()
    }

    fn seal_at(events: &[Exported], size: usize) -> Seal {
        Seal {
            size: size as i64,
            head: events[size - 1].hash.clone(),
            manifest: "0".repeat(64),
        }
    }

    fn scan_all(m: &Mem, seal: Option<&Seal>, events: &[Exported]) -> Result<Scanned> {
        scan(
            m,
            seal,
            events.len() as i64,
            &events.last().unwrap().hash,
            None,
        )
    }

    fn refused(r: Result<Scanned>, what: &str) {
        let e = r.expect_err(what);
        assert_eq!(e.code, Code::TrustEvidence, "{e}");
    }

    /// The whole mirror and the tail after a seal both reach the anchored
    /// head, and the sealed run reads only what follows the seal.
    #[test]
    fn a_tail_chains_from_the_seal() {
        let ev = chain(50);
        let all = Mem(segments(&ev, 10, 1));
        let s = scan_all(&all, None, &ev).unwrap();
        assert_eq!((s.end, s.run.len()), (50, 5));
        let seal = seal_at(&ev, 30);
        // After a compaction: segments 4 and 5 only.
        let tail = Mem(all.0[3..].to_vec());
        let mut seen = vec![];
        let s = scan(
            &tail,
            Some(&seal),
            50,
            &ev[49].hash,
            Some(&mut |x: &Exported| {
                seen.push(x.gseq);
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(seen, (31..=50).collect::<Vec<_>>());
        assert_eq!(s.run, vec![4, 5]);
        // The segments before the seal are ignored when they are still
        // there (a crash after the commit): the events up to it are not
        // read.
        let s = scan_all(&all, Some(&seal), &ev).unwrap();
        assert_eq!(s.end, 50);
        // Without the seal, the tail alone is a gap.
        refused(scan_all(&tail, None, &ev), "a tail with no seal");
        // The seal at the anchored size: nothing follows, the head is the
        // seal's.
        let seal50 = seal_at(&ev, 50);
        let none = Mem(vec![]);
        scan(&none, Some(&seal50), 50, &ev[49].hash, None).unwrap();
        refused(
            scan(&none, Some(&seal50), 50, &ev[48].hash, None),
            "a seal that is not the anchored head",
        );
    }

    /// Truncation, gaps, edits, forks and replays of a tail are refused.
    #[test]
    fn a_damaged_tail_is_refused() {
        let ev = chain(50);
        let seal = seal_at(&ev, 30);
        let all = segments(&ev, 10, 1);
        let tail = |v: Vec<(u64, String)>| Mem(v);
        // Truncated: the newest segment gone, or an event of it.
        refused(
            scan_all(&tail(all[3..4].to_vec()), Some(&seal), &ev),
            "newest gone",
        );
        let mut cut = all[4].1.lines().collect::<Vec<_>>();
        cut.pop();
        refused(
            scan_all(
                &tail(vec![all[3].clone(), (5, format!("{}\n", cut.join("\n")))]),
                Some(&seal),
                &ev,
            ),
            "last event dropped",
        );
        // A gap: the first tail segment gone.
        refused(
            scan_all(&tail(all[4..].to_vec()), Some(&seal), &ev),
            "first tail segment gone",
        );
        // An edited event.
        let edited = all[3].1.replacen("rol_35", "rol_99", 1);
        refused(
            scan_all(&tail(vec![(4, edited), all[4].clone()]), Some(&seal), &ev),
            "edited",
        );
        // A seal that is not this history's head: nothing chains from it.
        let mut forked = seal.clone();
        forked.head = ev[28].hash.clone();
        refused(
            scan_all(&tail(all[3..].to_vec()), Some(&forked), &ev),
            "another sealed head",
        );
        // A sealed segment replayed after the tail, or a tail segment
        // replayed: the run begins again and does not reach the head.
        let mut replay = all[3..].to_vec();
        replay.push((9, all[1].1.clone()));
        refused(
            scan_all(&tail(replay), Some(&seal), &ev),
            "an old segment replayed",
        );
        let mut replay = all[3..].to_vec();
        replay.push((9, all[3].1.clone()));
        refused(
            scan_all(&tail(replay), Some(&seal), &ev),
            "a tail segment replayed",
        );
        // A partition's positions out of order inside the tail.
        let mut swapped = ev.clone();
        swapped.swap(34, 37);
        for (i, x) in swapped.iter_mut().enumerate() {
            x.gseq = i as i64 + 1;
        }
        refused(
            scan(
                &tail(segments(&swapped[30..], 10, 4)),
                Some(&seal),
                50,
                &ev[49].hash,
                None,
            ),
            "reordered events",
        );
    }

    /// A segment that straddles the seal (an old copy kept under its
    /// number) begins the tail at the seal; segments of other runs are
    /// ignored; a rebuilt run after the seal supersedes a damaged one.
    #[test]
    fn leftovers_straddles_and_rebuilt_runs() {
        let ev = chain(50);
        let seal = seal_at(&ev, 25);
        // Segments of 10: 21..30 straddles the seal at 25.
        let all = segments(&ev, 10, 1);
        let s = scan_all(&Mem(all[2..].to_vec()), Some(&seal), &ev).unwrap();
        assert_eq!(s.run, vec![3, 4, 5]);
        // A damaged tail segment, then a rebuilt run from the seal on
        // under higher numbers: the later run is the mirror.
        let mut m = all[3..4].to_vec();
        m[0].1 = "garbage\n".into();
        m.extend(segments(&ev[25..], 10, 20));
        let s = scan_all(&Mem(m), Some(&seal), &ev).unwrap();
        assert_eq!(s.run, vec![20, 21, 22]);
        // Segments the mirror holds past the anchored size are an
        // orphan suffix: never part of the run.
        let orphans = chain(60);
        let m = Mem(segments(&orphans, 10, 1));
        let s = scan(
            &m,
            Some(&seal_at(&orphans, 25)),
            50,
            &orphans[49].hash,
            None,
        )
        .unwrap();
        assert_eq!(s.end, 60);
        assert_eq!(s.run, vec![3, 4, 5]);
    }
}
