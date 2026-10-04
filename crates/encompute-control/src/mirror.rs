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
//! plain atomic replace). The mirror is never pruned below the anchored
//! head; segments may be compacted (rewritten as a new run starting at
//! event 1) only when the result still chains to it.

use std::collections::HashMap;
use std::sync::Mutex;

use encompute_ir::{Code, Error, Result};
use encompute_trust::govlog::{chain_hash, hash_hex, Hash, CHAIN_GENESIS};

use crate::anchor::AnchorStore;
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

/// What a scan found.
#[derive(Debug)]
pub struct Scanned {
    /// The last event position seen, anchored or not.
    pub end: i64,
}

/// Streams the mirror once, segment by segment: the first `size` events
/// must chain, recomputed, to `head`. `each` sees every verified event (in
/// order) as it is checked. Nothing is held beyond one segment.
pub fn scan(
    store: &dyn AnchorStore,
    size: i64,
    head: &str,
    mut each: Option<&mut Each<'_>>,
) -> Result<Scanned> {
    let mut nums = store.mirror_list()?;
    nums.sort_unstable();
    let genesis = hash_hex(&CHAIN_GENESIS);
    let mut prev: Hash = CHAIN_GENESIS;
    let mut last = 0i64;
    let mut pseqs: HashMap<String, u64> = HashMap::new();
    let mut pending: Option<String> = None;
    let mut reached = size == 0;
    let mut end = 0i64;
    if size == 0 && head != genesis {
        pending = Some("the anchored head of an empty log is not the empty head".into());
    }
    for n in nums {
        let bad = |m: String| format!("governance log mirror segment {n}: {m}");
        let events = match store.mirror_read(n).and_then(|l| parse(n, &l)) {
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
        if first == 1 {
            prev = CHAIN_GENESIS;
            last = 0;
            pseqs.clear();
            pending = None;
            reached = size == 0;
        } else if reached && first > size {
            end = end.max(events[events.len() - 1].gseq);
            continue;
        } else if first != last + 1 {
            pending.get_or_insert(bad(format!(
                "it starts at event {first}, after event {last} (overlap or gap)"
            )));
            continue;
        }
        for x in &events {
            if x.gseq > size {
                end = end.max(x.gseq);
                continue;
            }
            let b = |m: &str| mirror_err(format!("governance log mirror, event {}: {m}", x.gseq));
            let p = pseqs.entry(x.event.partition.clone()).or_insert(0);
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
    Ok(Scanned { end })
}

impl Control {
    /// Where the writer extends the mirror: from the database's own
    /// events, never from what the mirror says it holds.
    fn find_open(&self, c: &mut postgres::Client, anchored: i64) -> Result<Open> {
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
        let next = nums.first().map_or(1, |m| m + 1);
        Ok(Open {
            n: next,
            from: 1,
            to: 0,
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
    pub(crate) fn mirror_through(&self, anchored: i64, size: i64) -> Result<()> {
        let anchored = anchored.max(self.stored_glog_size());
        let mut c = self.db.conn()?;
        let cached = match self.mirror.get() {
            Some(o) if o.hash.is_some() && govlog::hash_at(&mut *c, o.to)? == o.hash => Some(o),
            _ => None,
        };
        let res = (|| {
            let o = match cached {
                Some(o) => o,
                None => self.find_open(&mut c, anchored)?,
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
    pub(crate) fn check_mirror(&self, size: i64, head: &str) -> Result<()> {
        let s = scan(self.anchor.store(), size, head, None)?;
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
    pub(crate) fn import_from_mirror(&self, size: i64, head: &str) -> Result<u64> {
        // First pass: the mirror chains to the anchored head, before
        // anything is written.
        scan(self.anchor.store(), size, head, None)?;
        self.db.tx(|t| {
            let mut imp = govlog::Importer::new(t)?;
            scan(
                self.anchor.store(),
                size,
                head,
                Some(&mut |x: &Exported| imp.push(t, x)),
            )?;
            imp.finish(t)
        })
    }

    /// Rebuilds the whole mirror from the database's log up to `size`
    /// (recovery, after the database's log was checked against the
    /// anchor), as a new run starting at event 1 after every segment there
    /// is, damaged or not.
    pub(crate) fn rebuild_mirror(&self, size: i64) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
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
            from: 1,
            to: 0,
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
