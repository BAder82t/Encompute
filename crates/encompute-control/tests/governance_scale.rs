//! The governance event log at scale, and its truncation and replay
//! negatives.
//!
//! The load test appends governance events (removed roles, withdrawn
//! approvals, removed memberships, cancelled jobs, spread over many
//! partitions), checkpoints the log in batches, and shows that the state
//! anchor stays the same size however many there are, that the mirror in
//! the anchor store holds every anchored event, that a cold start verifies
//! the whole log, and that a database restored from an old backup recovers
//! from the mirror. It prints the anchor's size over time, the latency of
//! a checkpoint (percentiles) and the recovery times as `GOVERNANCE LOAD`
//! lines (nothing about latency is asserted: a loaded machine would make
//! that flaky; the sizes and the recovered state are).
//!
//! Two variants of one test body:
//!
//! - `load_10k_events` runs with the suite (`GOV_LOAD_EVENTS`, default
//!   10,000);
//! - `load_100k_events_heavy` is `#[ignore]`d (`GOV_LOAD_HEAVY_EVENTS`,
//!   default 120,000; minutes, not seconds):
//!   `cargo test --release -p encompute-control --test governance_scale
//!   -- --ignored --nocapture load_100k_events_heavy`.
//!
//! The negatives: the events after the last checkpoint are the one part of
//! the log that a truncation does not betray (the database is then behind
//! nothing the anchor holds), and are never resurrected from the mirror; an
//! event exactly at the anchored head cannot be dropped; a replayed,
//! forked, gapped or forged export is refused.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use std::time::Instant;

use common::*;
use encompute_control::govlog::{self, extra_kind, Draft};
use encompute_trust::govlog::Partition;

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[(((v.len() - 1) as f64) * p).round() as usize]
}

fn percentiles(what: &str, v: &mut [f64]) -> String {
    format!(
        "{what}: n={} p50={:.1}ms p95={:.1}ms p99={:.1}ms max={:.1}ms",
        v.len(),
        pct(v, 0.50),
        pct(v, 0.95),
        pct(v, 0.99),
        pct(v, 1.0)
    )
}

fn stop(t: T) -> Env0 {
    let env0 = t.env0;
    drop(t.control);
    env0
}

fn anchor_file_len(env0: &Env0) -> u64 {
    std::fs::metadata(env0.anchor_dir.join("state-anchor.json"))
        .unwrap()
        .len()
}

fn mirror_len(env0: &Env0) -> (usize, usize) {
    let dir = env0.anchor_dir.join("governance-log");
    let (mut files, mut events) = (0, 0);
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "jsonl") {
            files += 1;
            events += std::fs::read_to_string(p).unwrap().lines().count();
        }
    }
    (files, events)
}

/// One batch's events, numbered from `from`: the four sets that used to
/// grow the anchor (cancelled jobs with the recovery note that their rows
/// are gone, withdrawn approvals, removed memberships, removed roles),
/// over 40 organizations' partitions.
fn batch(from: usize, n: usize) -> Vec<Draft> {
    let mut out = vec![];
    for i in from..from + n {
        let part = Partition::Organization(format!("org-{}", i % 40));
        let d = match i % 4 {
            0 => Draft::new(
                part.clone(),
                govlog::kind::JOB_CANCELLED,
                &format!("job_{i:08}"),
            ),
            1 => Draft::new(
                part.clone(),
                govlog::kind::GRANT_WITHDRAWN,
                &format!("grant_{i:08}"),
            ),
            2 => Draft::new(
                part.clone(),
                govlog::kind::MEMBERSHIP_REMOVED,
                &format!("mem_{i:08}"),
            ),
            _ => Draft::new(
                part.clone(),
                govlog::kind::ROLE_REMOVED,
                &format!("rol_{i:08}"),
            ),
        };
        out.push(d.org(&format!("org-{}", i % 40)));
        if i % 4 == 0 {
            // A cancelled job whose row the database does not hold must be
            // acknowledged as lost, as recovery does, or the start refuses.
            out.push(
                Draft::new(part, extra_kind::ROW_LOST, &format!("job_{i:08}"))
                    .r#ref("state", "job"),
            );
        }
    }
    out
}

fn append_all(t: &T, drafts: Vec<Draft>) {
    t.control
        .db
        .tx(|tx| {
            for d in &drafts {
                govlog::append(tx, d.clone())?;
            }
            Ok(())
        })
        .unwrap();
}

/// The load run: `target` events at least, in batches of `per_batch`
/// before each checkpoint.
fn load(target: usize, per_batch: usize, label: &str) {
    let Some(mut t) = setup() else { return };
    let backup = format!("{}_ldbk", db_name(&t.env0.url));
    let start_bytes = t.control.anchor.bytes();
    let start_file = anchor_file_len(&t.env0);
    let mut sizes: Vec<(i64, u64)> = vec![(t.control.anchor.snapshot().glog_size, start_bytes)];
    let mut ck = vec![];
    let mut appended_ms = vec![];
    let mut next = 0usize;
    let mut backed_up_at = 0i64;
    let t0 = Instant::now();
    let tenth = (target / 10).max(1);
    let mut mark = tenth;
    while (t.control.anchor.snapshot().glog_size as usize) < target {
        let drafts = batch(next, per_batch);
        next += per_batch;
        let a = Instant::now();
        append_all(&t, drafts);
        appended_ms.push(a.elapsed().as_secs_f64() * 1000.0);
        let c = Instant::now();
        t.control.checkpoint_log().unwrap();
        ck.push(c.elapsed().as_secs_f64() * 1000.0);
        let size = t.control.anchor.snapshot().glog_size;
        if size as usize >= mark {
            sizes.push((size, t.control.anchor.bytes()));
            mark += tenth;
            if backed_up_at == 0 && size as usize >= target / 10 {
                // An older backup, to restore at the end: no connection to
                // the source database may be open.
                let env0 = stop(t);
                backup_database(&env0.url, &backup);
                backed_up_at = size;
                t = env0.started();
            }
        }
    }
    let total = t.control.anchor.snapshot().glog_size;
    let fill_secs = t0.elapsed().as_secs_f64();
    // The latency of the checkpoint a deny call waits for, with the log
    // this large: one event, then its forced checkpoint.
    let mut single = vec![];
    for i in 0..100 {
        append_all(&t, batch(next + i * 4 + 3, 1));
        let c = Instant::now();
        t.control.checkpoint_log().unwrap();
        single.push(c.elapsed().as_secs_f64() * 1000.0);
    }
    let total = total.max(t.control.anchor.snapshot().glog_size);
    let end_bytes = t.control.anchor.bytes();
    let end_file = anchor_file_len(&t.env0);
    let env0 = stop(t);
    let (files, mirrored) = mirror_len(&env0);
    eprintln!(
        "GOVERNANCE LOAD {label}: {total} events in {fill_secs:.1}s (batches of ~{per_batch})"
    );
    for (s, b) in &sizes {
        eprintln!("GOVERNANCE LOAD {label}: anchor at event {s}: {b} bytes");
    }
    eprintln!(
        "GOVERNANCE LOAD {label}: anchor file {start_file} -> {end_file} bytes; mirror {files} segments, {mirrored} events"
    );
    eprintln!(
        "GOVERNANCE LOAD {label}: {}",
        percentiles("append (one batch)", &mut appended_ms)
    );
    eprintln!(
        "GOVERNANCE LOAD {label}: {}",
        percentiles("checkpoint of a batch", &mut ck)
    );
    eprintln!(
        "GOVERNANCE LOAD {label}: {}",
        percentiles("checkpoint of one event at the full size", &mut single)
    );
    // The anchor does not grow with the log: only its digits do.
    assert!(
        end_bytes <= start_bytes + 64 && end_file <= start_file + 64,
        "the anchor grew from {start_bytes} to {end_bytes} bytes ({start_file} -> {end_file} on disk)"
    );
    assert!(end_bytes < 1024, "the anchor is {end_bytes} bytes");
    // Every anchored event is in the mirror, in segments of bounded size.
    assert!(
        mirrored as i64 >= total,
        "{mirrored} mirrored, {total} anchored"
    );
    assert!(
        files <= mirrored / 400 + 2,
        "{files} segments for {mirrored} events"
    );
    // A cold start verifies the whole log, the mirror and the checkpoints.
    let c = Instant::now();
    let t = env0.started();
    let cold = c.elapsed().as_secs_f64();
    assert_eq!(t.control.anchor.snapshot().glog_size, total);
    eprintln!("GOVERNANCE LOAD {label}: cold start over {total} events: {cold:.1}s");
    let env0 = stop(t);
    // The backup from about a tenth of the events is refused, and recovery
    // brings the rest back from the mirror.
    restore_database(&backup, &env0.url);
    let e = env0
        .start()
        .err()
        .unwrap_or_else(|| panic!("an old backup started"));
    assert!(e.message.contains("GOVERNANCE LOG STATE ROLLBACK"), "{e}");
    let c = Instant::now();
    let notes = run_recovery(&env0);
    let recovery = c.elapsed().as_secs_f64();
    assert!(
        notes.iter().any(|n| n.contains("from the mirror")),
        "{notes:?}"
    );
    eprintln!(
        "GOVERNANCE LOAD {label}: recovery of {} events from the mirror (backup held {backed_up_at}): {recovery:.1}s",
        total - backed_up_at
    );
    let c = Instant::now();
    let t = env0.started();
    eprintln!(
        "GOVERNANCE LOAD {label}: start after recovery: {:.1}s",
        c.elapsed().as_secs_f64()
    );
    assert!(t.control.anchor.snapshot().glog_size >= total);
    compaction_at_scale(t, &backup, total, backed_up_at, label);
}

/// The database's governance tables, in bytes.
fn db_bytes(t: &T) -> i64 {
    t.control
        .db
        .conn()
        .unwrap()
        .query_one(
            "SELECT (pg_total_relation_size('governance_events')
                   + pg_total_relation_size('governance_tree_nodes'))::bigint",
            &[],
        )
        .unwrap()
        .get(0)
}

fn mirror_bytes(env0: &Env0) -> u64 {
    std::fs::read_dir(env0.anchor_dir.join("governance-log"))
        .unwrap()
        .map(|e| e.unwrap().metadata().unwrap().len())
        .sum()
}

/// How long the start check of the mirror alone takes.
fn mirror_scan_secs(env0: &Env0) -> f64 {
    let store = encompute_control::anchor::DirAnchor::new(env0.anchor_dir.clone()).unwrap();
    let a = match encompute_control::anchor::StoredAnchor::parse(
        &std::fs::read(env0.anchor_dir.join("state-anchor.json")).unwrap(),
    )
    .unwrap()
    {
        encompute_control::anchor::StoredAnchor::V2(a) => a,
        other => panic!("{other:?}"),
    };
    let c = Instant::now();
    encompute_control::mirror::scan(&store, a.seal.as_ref(), a.glog_size, &a.glog_head, None)
        .unwrap();
    c.elapsed().as_secs_f64()
}

/// The same log, compacted: the anchor stays the same size (a seal adds a
/// few hundred bytes, however many events it covers), the mirror shrinks
/// to the tail, the database's log is untouched (so is its size), a cold
/// start still verifies everything, and the backup taken at the start
/// recovers with the archive. Prints before and after as
/// `GOVERNANCE LOAD` lines.
fn compaction_at_scale(t: T, backup: &str, total: i64, backed_up_at: i64, label: &str) {
    let events_before = t.control.anchor.snapshot().glog_size;
    let (db_before, anchor_before) = (db_bytes(&t), t.control.anchor.bytes());
    let env0 = stop(t);
    let (files_before, _) = mirror_len(&env0);
    let (mirror_before, scan_before) = (mirror_bytes(&env0), mirror_scan_secs(&env0));
    let c = Instant::now();
    let t = env0.started();
    let start_before = c.elapsed().as_secs_f64();
    let archive = tmp_dir("archive");
    let mut o = encompute_control::compact::CompactOptions::new(&archive);
    o.keep_events = (events_before / 10).max(1_000);
    o.min_age_secs = 0;
    let c = Instant::now();
    let r = t.control.compact_mirror(&o).unwrap();
    let compact_secs = c.elapsed().as_secs_f64();
    assert!(r.sealed_after > events_before / 2, "{r:?}");
    let (db_after, anchor_after) = (db_bytes(&t), t.control.anchor.bytes());
    let anchor_file_after = anchor_file_len(&t.env0);
    let env0 = stop(t);
    let (files_after, _) = mirror_len(&env0);
    let (mirror_after, scan_after) = (mirror_bytes(&env0), mirror_scan_secs(&env0));
    let c = Instant::now();
    let t = env0.started();
    let start_after = c.elapsed().as_secs_f64();
    assert_eq!(t.control.anchor.snapshot().glog_size, events_before);
    eprintln!(
        "GOVERNANCE LOAD {label}: compaction sealed {} of {events_before} events in {compact_secs:.1}s: {} segments, {} bytes archived",
        r.sealed_after, r.archived_segments, r.archived_bytes
    );
    eprintln!(
        "GOVERNANCE LOAD {label}: anchor {anchor_before} -> {anchor_after} bytes ({anchor_file_after} on disk); mirror {files_before} -> {files_after} segments, {mirror_before} -> {mirror_after} bytes; database log tables {db_before} -> {db_after} bytes"
    );
    eprintln!(
        "GOVERNANCE LOAD {label}: mirror check {scan_before:.2}s -> {scan_after:.2}s; start {start_before:.1}s -> {start_after:.1}s"
    );
    assert!(
        anchor_after <= anchor_before + 256 && anchor_after < 1024,
        "the anchor went from {anchor_before} to {anchor_after} bytes"
    );
    assert!(
        mirror_after < mirror_before / 2,
        "{mirror_before} -> {mirror_after}"
    );
    assert!(db_after * 10 >= db_before * 9, "{db_before} -> {db_after}");
    let env0 = stop(t);
    // The backup from the start of the run recovers with the archive.
    restore_database(backup, &env0.url);
    let e = env0
        .start()
        .err()
        .unwrap_or_else(|| panic!("an old backup started"));
    assert!(e.message.contains("GOVERNANCE LOG STATE ROLLBACK"), "{e}");
    let db = encompute_control::db::Db::connect(&env0.url).unwrap();
    let signer =
        encompute_verification::ServiceSigner::from_seed("control-plane", &env0.seed).unwrap();
    let store =
        Box::new(encompute_control::anchor::DirAnchor::new(env0.anchor_dir.clone()).unwrap());
    let rc = encompute_control::Control::for_recovery(&recovery_config(&env0), db, signer, store)
        .unwrap();
    let c = Instant::now();
    let notes = rc.recover_with("operator-1", None, Some(&archive)).unwrap();
    let recovery = c.elapsed().as_secs_f64();
    assert!(
        notes.iter().any(|n| n.contains("from the mirror")),
        "{notes:?}"
    );
    eprintln!(
        "GOVERNANCE LOAD {label}: recovery of {} events from the archive and the tail (backup held {backed_up_at}): {recovery:.1}s",
        total - backed_up_at
    );
    drop(rc);
    let t = env0.started();
    assert!(t.control.anchor.snapshot().glog_size >= total);
}

#[test]
fn load_10k_events() {
    let n = std::env::var("GOV_LOAD_EVENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    load(n, 250, "fast");
}

#[test]
#[ignore = "heavy: more than 100,000 events, minutes (see the module documentation)"]
fn load_100k_events_heavy() {
    let n = std::env::var("GOV_LOAD_HEAVY_EVENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120_000);
    load(n, 500, "heavy");
}

// --- truncation and replay ---------------------------------------------------------

fn append_role_removal(t: &T, id: &str) {
    append_all(
        t,
        vec![Draft::new(
            Partition::Platform,
            govlog::kind::ROLE_REMOVED,
            id,
        )],
    );
}

fn head(url: &str) -> (i64, String) {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    let r = c
        .query_one("SELECT gseq, hash FROM governance_head WHERE id", &[])
        .unwrap();
    (r.get(0), r.get(1))
}

const LOG_TABLES: &[&str] = &[
    "governance_events",
    "governance_head",
    "governance_tree_nodes",
    "governance_checkpoints",
];

/// Drops the events after `keep` (the head moved back with them), as a
/// database attacker with the tables' owner rights can.
fn truncate_log(url: &str, keep: i64) {
    attacker(
        url,
        LOG_TABLES,
        &format!(
            "DELETE FROM governance_tree_nodes n
              WHERE (n.idx + 1) * (1::bigint << n.level) >
                    (SELECT COALESCE(max(e.pseq), 0) FROM governance_events e
                      WHERE e.partition = n.partition AND e.gseq <= {keep});
             DELETE FROM governance_events WHERE gseq > {keep};
             UPDATE governance_head SET gseq = {keep}, hash = (SELECT hash FROM governance_events WHERE gseq = {keep});"
        ),
    );
}

/// The events after the last checkpoint are not yet anything the anchor
/// holds: truncating exactly them is accepted (the database is not behind
/// the anchor), they are never resurrected from the mirror (a mirror
/// suffix beyond the anchor is an orphan), and the next checkpoint
/// mirrors what the database holds then. Dropping one more event, the
/// anchored head itself, is refused.
#[test]
fn the_tail_after_the_last_checkpoint_is_not_resurrected_and_the_anchored_head_cannot_go() {
    let Some(t) = setup() else { return };
    for i in 0..5 {
        append_role_removal(&t, &format!("rol_anchored_{i}"));
    }
    t.control.checkpoint_log().unwrap();
    let anchored = t.control.anchor.snapshot().glog_size;
    let mut c = t.control.db.conn().unwrap();
    let anchored_hash = govlog::hash_at(&mut *c, anchored).unwrap().unwrap();
    drop(c);
    // Three more events, never checkpointed (a crash before the pass).
    for i in 0..3 {
        append_role_removal(&t, &format!("rol_tail_{i}"));
    }
    let env0 = stop(t);
    let url = env0.url.clone();
    assert!(head(&url).0 > anchored);
    truncate_log(&url, anchored);
    // Accepted: the anchor holds nothing of the tail.
    let t = env0.started();
    let a = t.control.anchor.snapshot();
    assert_eq!(
        (a.glog_size, a.glog_head.as_str()),
        (anchored, anchored_hash.as_str())
    );
    // The tail is gone for good: the log continues from the anchored head
    // with new events, and the mirror carries those, not the old tail.
    append_role_removal(&t, "rol_new");
    t.control.checkpoint_log().unwrap();
    let mut c = t.control.db.conn().unwrap();
    let all = govlog::exported(&mut *c, 0, i64::MAX).unwrap();
    drop(c);
    assert!(all
        .iter()
        .all(|x| !x.event.subject.starts_with("rol_tail_")));
    assert_eq!(all.last().unwrap().event.subject, "rol_new");
    let env0 = stop(t);
    let (_, mirrored) = mirror_len(&env0);
    assert_eq!(mirrored, all.len());
    // One more dropped, the anchored head itself: refused.
    truncate_log(&url, all.len() as i64 - 1);
    let e = env0
        .start()
        .err()
        .unwrap_or_else(|| panic!("the anchored head was dropped"));
    assert!(e.message.contains("GOVERNANCE LOG STATE ROLLBACK"), "{e}");
}

/// A mirror trimmed to the anchored size (its orphan suffix dropped) is
/// accepted; trimmed below it, refused.
#[test]
fn trimming_the_mirror_to_the_anchored_size_is_accepted_and_below_it_refused() {
    let Some(t) = setup() else { return };
    let (t, fail) = {
        let env0 = stop(t);
        env0.start_flaky()
    };
    append_role_removal(&t, "rol_a");
    t.control.checkpoint_log().unwrap();
    let anchored = t.control.anchor.snapshot().glog_size;
    // An orphan: mirrored, never anchored.
    append_role_removal(&t, "rol_orphan");
    fail.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(t.control.checkpoint_log().is_err());
    let env0 = stop(t);
    let seg = env0
        .anchor_dir
        .join("governance-log")
        .join(format!("{:012}.jsonl", 1));
    let text = std::fs::read_to_string(&seg).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len() as i64, anchored + 1);
    lines.truncate(anchored as usize);
    std::fs::write(&seg, lines.join("\n") + "\n").unwrap();
    let t = env0.started();
    assert_eq!(t.control.anchor.snapshot().glog_size, anchored);
    let env0 = stop(t);
    lines.truncate(anchored as usize - 1);
    std::fs::write(&seg, lines.join("\n") + "\n").unwrap();
    let e = env0
        .start()
        .err()
        .unwrap_or_else(|| panic!("a mirror below the anchor started"));
    assert!(e.message.contains("GOVERNANCE LOG STATE ROLLBACK"), "{e}");
}

/// A replayed, forked, gapped, reordered or forged export never changes
/// the database's log: an export no newer than the log adds nothing, and
/// every other defect is refused whole.
#[test]
fn a_replayed_or_forged_export_is_refused() {
    let Some(t) = setup() else { return };
    for i in 0..6 {
        append_role_removal(&t, &format!("rol_{i}"));
    }
    t.control.checkpoint_log().unwrap();
    let url = t.env0.url.clone();
    let export = export_log(&url);
    let lines: Vec<&str> = export.lines().collect();
    assert!(lines.len() >= 6);
    let import = |text: &str| t.control.db.tx(|tx| govlog::import(tx, text));
    let before = head(&url);
    // Replaying the whole export, or an older part of it, adds nothing.
    assert_eq!(import(&export).unwrap(), 0);
    assert_eq!(import(&(lines[..3].join("\n") + "\n")).unwrap(), 0);
    assert_eq!(head(&url), before);
    // Newer events are needed to test the rest: the export of a log that
    // moved on, from a copy of this one.
    let last: govlog::Exported = serde_json::from_str(lines.last().unwrap()).unwrap();
    let mut forged = last.clone();
    forged.gseq += 1;
    forged.event.pseq += 1;
    forged.event.subject = "rol_next".into();
    // Its hash is not the chain's hash of its contents: refused.
    forged.hash = "00".repeat(32);
    let e = import(&govlog::to_lines(&[last.clone(), forged.clone()]).unwrap())
        .expect_err("a forged hash was imported");
    assert!(e.message.contains("hash does not match"), "{e}");
    // A gap: the export starts after the log's end.
    let mut gap = forged.clone();
    gap.gseq += 1;
    let e = import(&govlog::to_lines(&[gap]).unwrap()).expect_err("a gapped export was imported");
    assert!(e.message.contains("events are missing"), "{e}");
    // Another history: the event at the log's head differs.
    let mut other = last.clone();
    other.hash = "11".repeat(32);
    let e = import(&govlog::to_lines(&[other]).unwrap()).expect_err("another history was imported");
    assert!(e.message.contains("another history"), "{e}");
    // Reordered: the newer event before the one it follows.
    let e = import(&format!(
        "{}\n{}\n",
        serde_json::to_string(&forged).unwrap(),
        serde_json::to_string(&last).unwrap()
    ))
    .expect_err("a reordered export was imported");
    assert!(!e.message.is_empty());
    // Garbage.
    assert!(import("not json\n").is_err());
    // Nothing above changed the log.
    assert_eq!(head(&url), before);
    drop(t);
}
