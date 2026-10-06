//! INV-226, compaction: the governance log's mirror in the anchor store is
//! compacted into an archive the state anchor's seal commits to, and
//! nothing the anchor and the database guard changes.
//!
//! - A compaction seals a prefix (anchor version 3), archives the sealed
//!   segments with their SHA-256, prunes them from the anchor store, and
//!   the service restarts, checkpoints and restarts again over the tail.
//! - The database's log is untouched: deny state stays denied, evidence
//!   (inclusion proofs against signed checkpoints) verifies across the
//!   boundary, a backup taken after the compaction restores as is.
//! - A backup taken before it is refused as behind the anchor, as ever;
//!   recovery brings it back from the tail alone when it reaches the seal,
//!   and needs the archive (checked against the seal) when it does not.
//! - A truncated, gapped or replayed tail is refused; a tampered, missing,
//!   swapped or substituted archive is refused.
//! - A crash before the commit point changes nothing (the same compaction
//!   runs again); a crash after it, before or in the middle of the pruning,
//!   leaves a mirror that still verifies, which the next run finishes.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::json;

use common::gov::*;
use common::*;
use encompute_control::anchor::{Allow, AnchorStore, DirAnchor, StateAnchor, StoredAnchor};
use encompute_control::compact::{verify_archive, CompactOptions, CompactReport};
use encompute_control::db::Db;
use encompute_control::govlog::{self, Draft};
use encompute_control::Control;
use encompute_trust::govlog::Partition;
use encompute_verification::ServiceSigner;

fn stop(t: T) -> Env0 {
    let env0 = t.env0;
    drop(t.control);
    env0
}

fn anchor_file(env0: &Env0) -> PathBuf {
    env0.anchor_dir.join("state-anchor.json")
}

fn anchor_of(env0: &Env0) -> StateAnchor {
    match StoredAnchor::parse(&std::fs::read(anchor_file(env0)).unwrap()).unwrap() {
        StoredAnchor::V2(a) => a,
        StoredAnchor::V1(_) => panic!("version 1"),
    }
}

fn mirror_dir(env0: &Env0) -> PathBuf {
    env0.anchor_dir.join("governance-log")
}

/// The mirror's segment numbers, in order.
fn nums(env0: &Env0) -> Vec<u64> {
    let mut v = DirAnchor::new(env0.anchor_dir.clone())
        .unwrap()
        .mirror_list()
        .unwrap();
    v.sort_unstable();
    v
}

fn segment(env0: &Env0, n: u64) -> PathBuf {
    mirror_dir(env0).join(format!("{n:012}.jsonl"))
}

fn mirror_bytes(env0: &Env0) -> u64 {
    nums(env0)
        .iter()
        .map(|n| std::fs::metadata(segment(env0, *n)).unwrap().len())
        .sum()
}

fn copy_dir(from: &Path, to: &Path) {
    let _ = std::fs::remove_dir_all(to);
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

fn refused_start(env0: &Env0, what: &str) -> String {
    let e = env0
        .start()
        .err()
        .unwrap_or_else(|| panic!("started although {what} was expected"));
    assert!(e.message.contains(what), "{e}");
    e.message
}

fn opts(archive: &Path) -> CompactOptions {
    let mut o = CompactOptions::new(archive);
    o.keep_events = 100;
    o.min_age_secs = 0;
    o
}

fn public_key(env0: &Env0) -> String {
    ServiceSigner::from_seed("control-plane", &env0.seed)
        .unwrap()
        .public_key_hex()
}

fn verify_the_archive(env0: &Env0, archive: &Path) -> encompute_ir::Result<usize> {
    let store = DirAnchor::new(env0.anchor_dir.clone()).unwrap();
    verify_archive(&store, &public_key(env0), archive).map(|r| r.segments)
}

fn drafts(from: usize, n: usize) -> Vec<Draft> {
    (from..from + n)
        .map(|i| {
            let part = if i % 8 == 7 {
                Partition::Platform
            } else {
                Partition::Organization(format!("org-{}", i % 7))
            };
            let kind = match i % 3 {
                0 => govlog::kind::ROLE_REMOVED,
                1 => govlog::kind::GRANT_WITHDRAWN,
                _ => govlog::kind::MEMBERSHIP_REMOVED,
            };
            Draft::new(part, kind, &format!("subject_{i:06}")).r#ref("n", i.to_string())
        })
        .collect()
}

/// `n` events from `from`, in groups, each checkpointed (as the service
/// does).
fn append_and_checkpoint(t: &T, from: usize, n: usize) {
    let mut i = from;
    while i < from + n {
        let k = 400.min(from + n - i);
        let ds = drafts(i, k);
        t.control
            .db
            .tx(|tx| {
                for d in &ds {
                    govlog::append(tx, d.clone())?;
                }
                Ok(())
            })
            .unwrap();
        t.control.checkpoint_log().unwrap();
        i += k;
    }
}

fn hash_at(url: &str, gseq: i64) -> String {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    govlog::hash_at(&mut c, gseq).unwrap().unwrap()
}

fn head_of(url: &str) -> i64 {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    c.query_one("SELECT gseq FROM governance_head WHERE id", &[])
        .unwrap()
        .get(0)
}

/// Recovery over `env0`'s anchor and database, with the archive.
fn recover_with_archive(env0: &Env0, archive: Option<&Path>) -> encompute_ir::Result<Vec<String>> {
    let db = Db::connect(&env0.url).unwrap();
    let signer = ServiceSigner::from_seed("control-plane", &env0.seed).unwrap();
    let store = Box::new(DirAnchor::new(env0.anchor_dir.clone()).unwrap());
    let rc = Control::for_recovery(&recovery_config(env0), db, signer, store).unwrap();
    rc.recover_with("operator-1", None, archive)
}

/// A log of `total` events with backups taken at `at` (ascending), the
/// control plane stopped: (environment, the backups' names).
fn log_with_backups(at: &[usize], total: usize) -> Option<(Env0, Vec<String>)> {
    let t = setup()?;
    let mut names = vec![];
    let mut env0 = stop(t);
    let mut done = 0usize;
    for (i, upto) in at.iter().chain(std::iter::once(&total)).enumerate() {
        let t = env0.started();
        append_and_checkpoint(&t, done, upto - done);
        done = *upto;
        env0 = stop(t);
        if i < at.len() {
            let name = format!("{}_cpbk{i}", db_name(&env0.url));
            backup_database(&env0.url, &name);
            names.push(name);
        }
    }
    Some((env0, names))
}

/// Compacts `env0` with `archive`, stops again.
fn compacted(env0: Env0, archive: &Path) -> (Env0, CompactReport) {
    let t = env0.started();
    let r = t.control.compact_mirror(&opts(archive)).unwrap();
    (stop(t), r)
}

// --- the compaction ------------------------------------------------------------------

/// A compaction seals a prefix, archives it with its hashes, prunes the
/// mirror to the tail, writes a version-3 anchor of the same bounded size,
/// and the service restarts, checkpoints and restarts over the tail. The
/// anchor of a deployment that never compacted is version 2 and stays so.
#[test]
fn compaction_seals_archives_prunes_and_the_service_restarts() {
    let Some((env0, _)) = log_with_backups(&[], 3_000) else {
        return;
    };
    let before = anchor_of(&env0);
    assert_eq!(before.version, 2, "a deployment that never compacted");
    assert!(before.seal.is_none());
    let anchor_before = std::fs::metadata(anchor_file(&env0)).unwrap().len();
    let segments_before = nums(&env0);
    let mirror_before = mirror_bytes(&env0);
    assert_eq!(segments_before.len(), 6, "{segments_before:?}");
    let archive = tmp_dir("archive");
    let (env0, r) = compacted(env0, &archive);
    let a = anchor_of(&env0);
    let seal = a.seal.clone().expect("sealed");
    assert_eq!(a.version, 3);
    assert_eq!(seal.size, 2_500, "{r:?}");
    assert_eq!(seal.head, hash_at(&env0.url, 2_500));
    assert_eq!(
        a.glog_size, before.glog_size,
        "the anchored log is the same"
    );
    assert_eq!((r.archived_segments, r.pruned_segments), (5, 5), "{r:?}");
    assert_eq!(r.archived_events, 2_500);
    assert_eq!((r.sealed_before, r.sealed_after), (0, 2_500));
    // The mirror holds the tail; the anchor is still constant in size.
    assert_eq!(nums(&env0), vec![6]);
    assert!(mirror_bytes(&env0) < mirror_before / 4, "{r:?}");
    let anchor_after = std::fs::metadata(anchor_file(&env0)).unwrap().len();
    assert!(
        anchor_after <= anchor_before + 256 && anchor_after < 1024,
        "{anchor_before} -> {anchor_after}"
    );
    // The archive: the segments as the mirror held them, and a manifest.
    assert_eq!(verify_the_archive(&env0, &archive).unwrap(), 5);
    assert!(archive
        .join(format!("manifest-{:012}.json", seal.size))
        .exists());
    // Starts, checkpoints (the open segment extends, a new one is added),
    // and starts again.
    let t = env0.started();
    append_and_checkpoint(&t, 3_000, 700);
    let env0 = stop(t);
    assert_eq!(nums(&env0), vec![6, 7, 8]);
    assert_eq!(anchor_of(&env0).seal, Some(seal.clone()));
    env0.started();
}

/// A dry run writes and deletes nothing (not even the archive directory);
/// the safety window keeps what is too young or too close to the end; the
/// newest segment always stays.
#[test]
fn a_dry_run_and_the_window_change_nothing() {
    let Some((env0, _)) = log_with_backups(&[], 3_000) else {
        return;
    };
    let archive = tmp_dir("archive-dry").join("not-yet");
    let anchor = std::fs::read(anchor_file(&env0)).unwrap();
    let before = nums(&env0);
    let t = env0.started();
    let mut o = opts(&archive);
    o.dry_run = true;
    let r = t.control.compact_mirror(&o).unwrap();
    assert!(r.dry_run);
    assert_eq!((r.sealed_after, r.archived_segments), (2_500, 5), "{r:?}");
    assert!(!archive.exists(), "a dry run made the archive directory");
    // Too close to the end: nothing is sealed.
    let mut o = opts(&archive);
    o.keep_events = 2_900;
    let r = t.control.compact_mirror(&o).unwrap();
    assert_eq!((r.archived_segments, r.sealed_after), (0, 0), "{r:?}");
    assert!(
        r.notes.iter().any(|n| n.contains("nothing to compact")),
        "{r:?}"
    );
    // Too young: every event is seconds old.
    let mut o = opts(&archive);
    o.min_age_secs = 30 * 24 * 3600;
    let r = t.control.compact_mirror(&o).unwrap();
    assert_eq!(r.archived_segments, 0, "{r:?}");
    assert!(r.notes.iter().any(|n| n.contains("younger")), "{r:?}");
    assert!(!archive.exists());
    let env0 = stop(t);
    assert_eq!(nums(&env0), before);
    assert_eq!(std::fs::read(anchor_file(&env0)).unwrap(), anchor);
}

/// A second compaction extends the archive and the seal; leftovers of the
/// first are not archived again.
#[test]
fn a_second_compaction_extends_the_archive() {
    let Some((env0, _)) = log_with_backups(&[], 3_000) else {
        return;
    };
    let archive = tmp_dir("archive");
    let (env0, r1) = compacted(env0, &archive);
    assert_eq!(r1.sealed_after, 2_500);
    let t = env0.started();
    append_and_checkpoint(&t, 3_000, 1_500);
    let r2 = t.control.compact_mirror(&opts(&archive)).unwrap();
    assert_eq!(
        (r2.sealed_before, r2.sealed_after),
        (2_500, 4_000),
        "{r2:?}"
    );
    assert_eq!(r2.archived_segments, 3, "{r2:?}");
    let env0 = stop(t);
    assert_eq!(verify_the_archive(&env0, &archive).unwrap(), 8);
    assert_eq!(anchor_of(&env0).seal.unwrap().size, 4_000);
    // A compaction against another archive than the sealed one is refused.
    let t = env0.started();
    append_and_checkpoint(&t, 4_500, 1_000);
    let other = tmp_dir("archive-other");
    let e = t
        .control
        .compact_mirror(&opts(&other))
        .expect_err("extended an archive that is not the sealed one");
    assert!(e.message.contains("previous seal"), "{e}");
    let env0 = stop(t);
    assert_eq!(
        anchor_of(&env0).seal.unwrap().size,
        4_000,
        "nothing was sealed"
    );
    env0.started();
}

// --- backups -------------------------------------------------------------------------

/// A backup taken after the compaction restores as it is (the database's
/// log was never compacted); one taken before is refused as behind the
/// anchor. Recovery completes it from the tail when it reaches the seal,
/// and needs the archive, checked against the seal, when it ends inside
/// the sealed prefix: the result is the database appending made.
#[test]
fn old_and_new_backups_after_a_compaction() {
    let Some((env0, backups)) = log_with_backups(&[1_000, 4_200], 4_500) else {
        return;
    };
    let (old, mid) = (&backups[0], &backups[1]);
    let source = dump_log(&env0.url);
    let archive = tmp_dir("archive");
    let (env0, r) = compacted(env0, &archive);
    assert_eq!(r.sealed_after, 4_000, "{r:?}");
    let url = env0.url.clone();
    // After the compaction: the database as it is, restored from itself.
    let post = format!("{}_cppost", db_name(&url));
    backup_database(&url, &post);
    restore_database(&post, &url);
    env0.started();
    assert_same_rows(
        "a backup taken after the compaction",
        &source,
        &dump_log(&url),
    );

    // Before the compaction, past the seal: refused, then recovered from
    // the tail alone (no archive given, none needed).
    restore_database(mid, &url);
    refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    let notes = recover_with_archive(&env0, None).unwrap();
    assert!(
        notes.iter().any(|n| n.contains("from the mirror")),
        "{notes:?}"
    );
    assert_same_rows("recovered from the tail", &source, &dump_log(&url));
    env0.started();

    // Before the compaction, inside the sealed prefix: refused; recovery
    // without the archive says what is missing and changes nothing;
    // with it, the log is whole again.
    restore_database(old, &url);
    refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    let behind = dump_log(&url);
    let e = recover_with_archive(&env0, None).expect_err("recovered without the archive");
    assert!(e.message.contains("--archive-dir"), "{e}");
    assert!(e.message.contains("sealed prefix"), "{e}");
    assert_same_rows("a refused recovery", &behind, &dump_log(&url));
    let e = recover_with_archive(&env0, Some(&tmp_dir("elsewhere"))).expect_err("an empty archive");
    assert!(e.message.contains("manifest"), "{e}");
    let notes = recover_with_archive(&env0, Some(&archive)).unwrap();
    assert!(
        notes.iter().any(|n| n.contains("from the mirror")),
        "{notes:?}"
    );
    assert_same_rows("recovered with the archive", &source, &dump_log(&url));
    env0.started();
}

// --- the recorded retention policy -----------------------------------------------------

/// The manifest files of an archive directory.
fn manifests(archive: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(archive)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("manifest-"))
        })
        .collect();
    v.sort();
    v
}

/// Rewrites the `policy` of a manifest file (or removes it: the format
/// from before it was recorded).
fn set_policy(manifest: &Path, policy: Option<serde_json::Value>) {
    let mut m: serde_json::Value =
        serde_json::from_slice(&std::fs::read(manifest).unwrap()).unwrap();
    match policy {
        Some(p) => m["policy"] = p,
        None => {
            m.as_object_mut().unwrap().remove("policy");
        }
    }
    std::fs::write(manifest, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
}

/// A compaction records the retention it ran with and when, in the
/// manifest, and that record is informational: verifying the archive and
/// recovery give the same result whatever it says (or when it is absent, as
/// in a manifest written before it was recorded), and a later compaction
/// with another retention leaves what an earlier one sealed as it was.
#[test]
fn the_recorded_retention_is_audit_information_and_never_read() {
    let Some((env0, backups)) = log_with_backups(&[1_000], 4_500) else {
        return;
    };
    let old = &backups[0];
    let source = dump_log(&env0.url);
    let archive = tmp_dir("archive");
    let before = encompute_verification::service::now();
    let (env0, r) = compacted(env0, &archive);
    let after = encompute_verification::service::now();
    assert_eq!(r.sealed_after, 4_000, "{r:?}");

    // Recorded: the effective keep_events and min_age_secs, and the time.
    let files = manifests(&archive);
    assert_eq!(files.len(), 1, "{files:?}");
    let m: serde_json::Value = serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
    assert_eq!(m["policy"]["keep_events"], 100, "{m}");
    assert_eq!(m["policy"]["min_age_secs"], 0, "{m}");
    let at = m["policy"]["compacted_at"].as_u64().unwrap();
    assert!(
        (before..=after).contains(&at),
        "{at} not in {before}..={after}"
    );

    // Verification and recovery do not depend on it: the same outcome with
    // the recorded values, with others, with absurd ones and with none.
    let url = env0.url.clone();
    let mut recovered = vec![];
    let policies = [
        Some(m["policy"].clone()),
        Some(json!({"keep_events": 0, "min_age_secs": 0, "compacted_at": 0})),
        Some(
            json!({"keep_events": 999_999_999, "min_age_secs": 31_536_000_000u64,
                    "compacted_at": u64::MAX / 2}),
        ),
        None,
    ];
    for p in policies {
        set_policy(&files[0], p.clone());
        assert_eq!(
            verify_the_archive(&env0, &archive).unwrap(),
            r.archived_segments,
            "{p:?}"
        );
        restore_database(old, &url);
        refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
        let notes = recover_with_archive(&env0, Some(&archive)).unwrap();
        assert!(
            notes.iter().any(|n| n.contains("from the mirror")),
            "{notes:?}"
        );
        recovered.push(dump_log(&url));
        env0.started();
    }
    for (i, rows) in recovered.iter().enumerate() {
        assert_same_rows("a recovery whatever the recorded policy", &source, rows);
        assert_same_rows("the same rows each time", &recovered[0], &recovered[i]);
    }
    // What the seal does commit to is still checked, policy or not.
    let sealed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
    let mut forged = sealed.clone();
    forged["segments"][0]["sha256"] = json!("00".repeat(32));
    std::fs::write(&files[0], serde_json::to_vec_pretty(&forged).unwrap()).unwrap();
    assert!(verify_the_archive(&env0, &archive).is_err());
    std::fs::write(&files[0], serde_json::to_vec_pretty(&sealed).unwrap()).unwrap();
    verify_the_archive(&env0, &archive).unwrap();

    // A later compaction under another retention extends the archive: the
    // earlier manifest stays byte for byte, and records its own policy.
    let first = std::fs::read(&files[0]).unwrap();
    let t = env0.started();
    append_and_checkpoint(&t, 4_500, 2_000);
    let mut o = opts(&archive);
    o.keep_events = 50;
    o.min_age_secs = 7;
    let r2 = t.control.compact_mirror(&o).unwrap();
    assert!(r2.sealed_after > r.sealed_after, "{r2:?}");
    let env0 = stop(t);
    let files2 = manifests(&archive);
    assert_eq!(files2.len(), 2, "{files2:?}");
    assert_eq!(std::fs::read(&files[0]).unwrap(), first);
    let m2: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&files2[1]).unwrap()).unwrap();
    assert_eq!(m2["policy"]["keep_events"], 50, "{m2}");
    assert_eq!(m2["policy"]["min_age_secs"], 7, "{m2}");
    verify_the_archive(&env0, &archive).unwrap();
    env0.started();
}

// --- truncation and replay -----------------------------------------------------------

/// What an attacker with the anchor store's files can do to a compacted
/// mirror is refused, and `recover` rebuilds it (the tail only).
#[test]
fn a_truncated_or_replayed_tail_is_refused() {
    let Some((env0, _)) = log_with_backups(&[], 3_000) else {
        return;
    };
    let archive = tmp_dir("archive");
    let pre_anchor = std::fs::read(anchor_file(&env0)).unwrap();
    let (env0, _) = compacted(env0, &archive);
    let keep = tmp_dir("mirror-keep");
    let restore = |env0: &Env0| {
        copy_dir(&keep, &mirror_dir(env0));
        env0.started();
    };
    let t = env0.started();
    append_and_checkpoint(&t, 3_000, 700);
    let env0 = stop(t);
    copy_dir(&mirror_dir(&env0), &keep);
    assert_eq!(nums(&env0), vec![6, 7, 8]);
    let seal = anchor_of(&env0).seal.unwrap();

    // The newest segment gone: truncated.
    std::fs::remove_file(segment(&env0, 8)).unwrap();
    let m = refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    assert!(m.contains("truncated"), "{m}");
    restore(&env0);
    // Its last event dropped.
    let text = std::fs::read_to_string(segment(&env0, 8)).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    lines.pop();
    std::fs::write(segment(&env0, 8), format!("{}\n", lines.join("\n"))).unwrap();
    let m = refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    assert!(m.contains("truncated"), "{m}");
    restore(&env0);
    // The tail's first segment gone (the next one then starts past the
    // seal with a gap before it).
    std::fs::remove_file(segment(&env0, 6)).unwrap();
    let m = refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    assert!(m.contains("gap") || m.contains("truncated"), "{m}");
    restore(&env0);
    // An event of the tail edited (its chain hash then differs).
    let text = std::fs::read_to_string(segment(&env0, 6)).unwrap();
    std::fs::write(
        segment(&env0, 6),
        text.replacen("subject_002600", "subject_002699", 1),
    )
    .unwrap();
    let m = refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    assert!(m.contains("modified"), "{m}");
    restore(&env0);

    // The anchor before the compaction put back: the mirror's tail starts
    // past event 1 with nothing before it.
    let sealed_anchor = std::fs::read(anchor_file(&env0)).unwrap();
    std::fs::write(anchor_file(&env0), &pre_anchor).unwrap();
    refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    std::fs::write(anchor_file(&env0), &sealed_anchor).unwrap();
    env0.started();

    // A sealed segment replayed after the tail (an old copy of a pruned
    // one, under a new number): refused.
    let old = std::fs::read(archive.join("segments").join(format!("{:012}.jsonl", 2))).unwrap();
    std::fs::write(segment(&env0, 9), &old).unwrap();
    refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    std::fs::remove_file(segment(&env0, 9)).unwrap();
    // A tail segment replayed after the tail: overlap, refused.
    std::fs::copy(segment(&env0, 6), segment(&env0, 9)).unwrap();
    let m = refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    assert!(m.contains("overlap") || m.contains("truncated"), "{m}");
    // Recovery rebuilds the mirror from the database: only the tail, from
    // the seal on, and the service starts.
    let notes = run_recovery(&env0);
    assert!(
        notes
            .iter()
            .any(|n| n.contains("rebuilt from the database")),
        "{notes:?}"
    );
    let t = env0.started();
    let env0 = stop(t);
    let a = anchor_of(&env0);
    // The rebuilt run starts at the seal's tail, not at event 1.
    let first_of = |n: u64| -> i64 {
        let text = std::fs::read_to_string(segment(&env0, n)).unwrap();
        let x: govlog::Exported = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        x.gseq
    };
    let rebuilt: Vec<i64> = nums(&env0)
        .into_iter()
        .filter(|n| *n > 9)
        .map(first_of)
        .collect();
    assert_eq!(rebuilt.first(), Some(&(seal.size + 1)), "{rebuilt:?}");
    assert_eq!(a.seal, Some(seal));
}

/// A mirror that was wiped (or lost its tail) and is then written by a
/// checkpoint starts over after the seal: it does not write the sealed
/// events back.
#[test]
fn the_writer_starts_over_after_the_seal() {
    let Some((env0, _)) = log_with_backups(&[], 3_000) else {
        return;
    };
    let archive = tmp_dir("archive");
    let (env0, _) = compacted(env0, &archive);
    let seal = anchor_of(&env0).seal.unwrap();
    for n in nums(&env0) {
        std::fs::remove_file(segment(&env0, n)).unwrap();
    }
    // The service started refuses the mirror; a fresh process that writes a
    // checkpoint before anything reads it (a crash and a restart in the
    // window) rebuilds the tail from the database.
    refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    let db = Db::connect(&env0.url).unwrap();
    let signer = ServiceSigner::from_seed("control-plane", &env0.seed).unwrap();
    let store = Box::new(DirAnchor::new(env0.anchor_dir.clone()).unwrap());
    let rc = Control::for_recovery(&recovery_config(&env0), db, signer, store).unwrap();
    rc.db
        .tx(|tx| {
            govlog::append(
                tx,
                Draft::new(
                    Partition::Platform,
                    govlog::kind::ROLE_REMOVED,
                    "rol_after_wipe",
                ),
            )
            .map(|_| ())
        })
        .unwrap();
    rc.checkpoint_log().unwrap();
    drop(rc);
    let mut firsts = vec![];
    for n in nums(&env0) {
        let text = std::fs::read_to_string(segment(&env0, n)).unwrap();
        let x: govlog::Exported = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        firsts.push(x.gseq);
    }
    assert_eq!(firsts.first(), Some(&(seal.size + 1)), "{firsts:?}");
    env0.started();
}

// --- the archive ---------------------------------------------------------------------

/// A tampered, missing, swapped or substituted archive is refused, by the
/// verification command and by recovery (which then changes nothing); the
/// untouched archive recovers.
#[test]
fn a_tampered_archive_is_refused() {
    let Some((env0, backups)) = log_with_backups(&[1_000], 4_500) else {
        return;
    };
    let source = dump_log(&env0.url);
    let archive = tmp_dir("archive");
    let (env0, _) = compacted(env0, &archive);
    let url = env0.url.clone();
    restore_database(&backups[0], &url);
    let behind = dump_log(&url);
    let seg = |n: u64| archive.join("segments").join(format!("{n:012}.jsonl"));
    let manifest = archive.join(format!(
        "manifest-{:012}.json",
        anchor_of(&env0).seal.unwrap().size
    ));
    let original: Vec<(u64, Vec<u8>)> = (1..=8)
        .map(|n| (n, std::fs::read(seg(n)).unwrap()))
        .collect();
    let manifest_original = std::fs::read(&manifest).unwrap();
    let reset = || {
        for (n, b) in &original {
            std::fs::write(seg(*n), b).unwrap();
        }
        std::fs::write(&manifest, &manifest_original).unwrap();
    };
    let refused = |what: &str| {
        let e = verify_the_archive(&env0, &archive).expect_err(what);
        let r = recover_with_archive(&env0, Some(&archive)).expect_err(what);
        assert_same_rows(what, &behind, &dump_log(&url));
        (e.message, r.message)
    };
    // A byte of an archived segment changed.
    let mut b = original[1].1.clone();
    let at = b.len() / 2;
    b[at] ^= 1;
    std::fs::write(seg(2), &b).unwrap();
    let (m, r) = refused("a changed segment");
    assert!(m.contains("SHA-256") && r.contains("SHA-256"), "{m} / {r}");
    reset();
    // A segment gone.
    std::fs::remove_file(seg(3)).unwrap();
    refused("a missing segment");
    reset();
    // Two segments swapped (replayed out of order).
    std::fs::write(seg(2), &original[2].1).unwrap();
    std::fs::write(seg(3), &original[1].1).unwrap();
    refused("swapped segments");
    reset();
    // A manifest rewritten to match the changed segment: not the one the
    // anchor sealed.
    let mut b = original[1].1.clone();
    b[at] ^= 1;
    std::fs::write(seg(2), &b).unwrap();
    let mut m: serde_json::Value = serde_json::from_slice(&manifest_original).unwrap();
    m["segments"][1]["sha256"] = json!(encompute_verification::service::sha256_hex(&b));
    std::fs::write(&manifest, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    let (m, r) = refused("a substituted manifest");
    assert!(
        m.contains("not the manifest the state anchor sealed"),
        "{m}"
    );
    assert!(
        r.contains("not the manifest the state anchor sealed"),
        "{r}"
    );
    reset();
    // A manifest that drops its last segment and names an earlier head.
    let mut m: serde_json::Value = serde_json::from_slice(&manifest_original).unwrap();
    m["segments"].as_array_mut().unwrap().pop();
    std::fs::write(&manifest, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    refused("a truncated manifest");
    reset();
    // Untouched, it recovers the database appending made.
    verify_the_archive(&env0, &archive).unwrap();
    recover_with_archive(&env0, Some(&archive)).unwrap();
    assert_same_rows("recovered", &source, &dump_log(&url));
    env0.started();
}

// --- crash windows -------------------------------------------------------------------

/// An anchor store that dies (as a crash would) at a chosen point of a
/// compaction: `commit` just before the anchor's compare-and-set, `delete:K`
/// just before the K-th pruned segment is deleted (after the commit).
struct Crash {
    inner: DirAnchor,
    mode: String,
    armed: Arc<AtomicBool>,
    deletes: AtomicUsize,
}

impl AnchorStore for Crash {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn load(&self) -> encompute_ir::Result<Option<StoredAnchor>> {
        self.inner.load()
    }
    fn store(&self, next: &StateAnchor, expected: u64) -> encompute_ir::Result<()> {
        if self.armed.load(Ordering::SeqCst) && self.mode == "commit" {
            std::process::exit(137);
        }
        self.inner.store(next, expected)
    }
    fn mirror_list(&self) -> encompute_ir::Result<Vec<u64>> {
        self.inner.mirror_list()
    }
    fn mirror_read(&self, n: u64) -> encompute_ir::Result<String> {
        self.inner.mirror_read(n)
    }
    fn mirror_create(&self, n: u64, lines: &str) -> encompute_ir::Result<()> {
        self.inner.mirror_create(n, lines)
    }
    fn mirror_replace(&self, n: u64, lines: &str, allow: &Allow<'_>) -> encompute_ir::Result<()> {
        self.inner.mirror_replace(n, lines, allow)
    }
    fn mirror_delete(&self, n: u64, allow: &Allow<'_>) -> encompute_ir::Result<()> {
        let k = self.deletes.fetch_add(1, Ordering::SeqCst) + 1;
        if self.armed.load(Ordering::SeqCst) && self.mode == format!("delete:{k}") {
            std::process::exit(137);
        }
        self.inner.mirror_delete(n, allow)
    }
}

/// The child of the crash tests: compacts and dies where told.
#[test]
fn compact_kill_child() {
    let (Ok(url), Ok(dir), Ok(archive), Ok(mode)) = (
        std::env::var("ENCOMPUTE_COMPACT_KILL_URL"),
        std::env::var("ENCOMPUTE_COMPACT_KILL_DIR"),
        std::env::var("ENCOMPUTE_COMPACT_KILL_ARCHIVE"),
        std::env::var("ENCOMPUTE_COMPACT_KILL_MODE"),
    ) else {
        return;
    };
    let env0 = Env0 {
        url,
        anchor_dir: dir.into(),
        seed: [42; 32],
        oidc: vec![],
        env: encompute_control::config::Env::Development,
    };
    let armed = Arc::new(AtomicBool::new(false));
    let t = env0
        .start_with(Box::new(Crash {
            inner: DirAnchor::new(env0.anchor_dir.clone()).unwrap(),
            mode,
            armed: armed.clone(),
            deletes: AtomicUsize::new(0),
        }))
        .unwrap();
    armed.store(true, Ordering::SeqCst);
    let _ = t.control.compact_mirror(&opts(Path::new(&archive)));
    std::process::exit(0);
}

fn kill_compaction(env0: &Env0, archive: &Path, mode: &str) {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "compact_kill_child", "--test-threads=1"])
        .env("ENCOMPUTE_COMPACT_KILL_URL", &env0.url)
        .env("ENCOMPUTE_COMPACT_KILL_DIR", &env0.anchor_dir)
        .env("ENCOMPUTE_COMPACT_KILL_ARCHIVE", archive)
        .env("ENCOMPUTE_COMPACT_KILL_MODE", mode)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(137), "{mode}: {status:?}");
}

/// A crash before the commit point: the anchor and the mirror are as they
/// were (the archive holds files nothing refers to), the service starts,
/// and the same compaction runs again over the same files.
#[test]
fn a_crash_before_the_commit_point_changes_nothing() {
    if std::env::var("ENCOMPUTE_COMPACT_KILL_URL").is_ok() {
        return;
    }
    let Some((env0, _)) = log_with_backups(&[], 3_000) else {
        return;
    };
    let archive = tmp_dir("archive");
    let anchor = std::fs::read(anchor_file(&env0)).unwrap();
    let before = nums(&env0);
    kill_compaction(&env0, &archive, "commit");
    assert_eq!(std::fs::read(anchor_file(&env0)).unwrap(), anchor);
    assert_eq!(nums(&env0), before, "nothing was pruned");
    assert!(archive
        .join("segments")
        .join(format!("{:012}.jsonl", 1))
        .exists());
    assert!(
        verify_the_archive(&env0, &archive).is_err(),
        "nothing is sealed: there is nothing to verify against"
    );
    let t = env0.started();
    let r = t.control.compact_mirror(&opts(&archive)).unwrap();
    assert_eq!((r.sealed_after, r.pruned_segments), (2_500, 5), "{r:?}");
    let env0 = stop(t);
    assert_eq!(verify_the_archive(&env0, &archive).unwrap(), 5);
    env0.started();
}

/// A crash after the commit point, before the first deletion or in the
/// middle of the pruning: the seal is anchored, the mirror still verifies
/// (the sealed events it still holds are the archive's, ignored), a
/// database restored from an old backup recovers with the archive, and the
/// next compaction finishes the pruning.
#[test]
fn a_crash_after_the_commit_point_is_finished_by_the_next_run() {
    if std::env::var("ENCOMPUTE_COMPACT_KILL_URL").is_ok() {
        return;
    }
    for (mode, left) in [("delete:1", 6usize), ("delete:3", 4usize)] {
        let Some((env0, backups)) = log_with_backups(&[1_000], 3_000) else {
            return;
        };
        let source = dump_log(&env0.url);
        let archive = tmp_dir("archive");
        kill_compaction(&env0, &archive, mode);
        let a = anchor_of(&env0);
        assert_eq!(a.seal.as_ref().map(|s| s.size), Some(2_500), "{mode}");
        assert_eq!(nums(&env0).len(), left, "{mode}: {:?}", nums(&env0));
        env0.started();
        // An old backup recovers (with the archive) over the part-pruned
        // mirror.
        restore_database(&backups[0], &env0.url);
        recover_with_archive(&env0, Some(&archive)).unwrap();
        assert_same_rows(mode, &source, &dump_log(&env0.url));
        let t = env0.started();
        let r = t.control.compact_mirror(&opts(&archive)).unwrap();
        assert_eq!(r.archived_segments, 0, "{mode}: {r:?}");
        assert_eq!(r.pruned_segments, left - 1, "{mode}: {r:?}");
        let env0 = stop(t);
        assert_eq!(nums(&env0), vec![6], "{mode}");
        assert_eq!(verify_the_archive(&env0, &archive).unwrap(), 5);
        env0.started();
    }
}

// --- deny state and evidence ---------------------------------------------------------

fn governed() -> Option<(G, String, String, String, String)> {
    let g = gov_world()?;
    let k = key(1);
    let (purpose, version) = g.ready(&k);
    let (row, _) = g.activated(&purpose, &version, &k);
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    let key_row = keys[0]["id"].as_str().unwrap().to_owned();
    let asset = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": TAX, "kind": "dataset", "name": "wages@2026-q1",
                    "series": "wages", "version": "2026-q1", "digest": "e".repeat(64),
                    "ir_policy": registered(TAX)["ir_policy"], "release_class": "boolean-only"}),
        ),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    Some((g, key_row, purpose, row, asset))
}

/// What a restore must not undo: the four governed transitions.
fn negative_transitions(g: &G, key_row: &str, purpose: &str, row: &str, asset: &str) {
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{row}/revoke"),
        Some(json!({"reason": "withdrawn"})),
    );
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{purpose}/retire"),
        None,
    );
    g.t.ok(
        &g.tax_sec2,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{key_row}/revoke"),
        None,
    );
    assert!(g.t.control.expire_asset("retention", asset).unwrap());
}

/// Deny state is not compacted away: a revoked authorization, a retired
/// purpose, a revoked key and an expired asset stay in the negative sets
/// after a compaction that seals their events, a restore of a backup from
/// before them is recovered from the archive (not resurrected), and an
/// attacker undoing one of them with the log intact is still refused.
#[test]
fn deny_state_survives_compaction_and_recovery() {
    let Some((g, key_row, purpose, row, asset)) = governed() else {
        return;
    };
    let env0 = stop(g.t);
    let url = env0.url.clone();
    let backup = format!("{}_cpgov", db_name(&url));
    backup_database(&url, &backup);
    let t = env0.started();
    let g = G { t, ..g };
    negative_transitions(&g, &key_row, &purpose, &row, &asset);
    append_and_checkpoint(&g.t, 0, 2_600);
    let sets = [
        (NegSet::RevokedAuthorizations, row.clone()),
        (NegSet::RetiredPurposes, purpose.clone()),
        (NegSet::RevokedKeys, key_row.clone()),
        (NegSet::ExpiredAssets, asset.clone()),
    ];
    let archive = tmp_dir("archive");
    let r = g.t.control.compact_mirror(&opts(&archive)).unwrap();
    // Their events are inside the sealed prefix.
    for (set, id) in &sets {
        let at = {
            let mut c = g.t.control.db.conn().unwrap();
            govlog::first_gseq(&mut *c, *set, id).unwrap().unwrap()
        };
        assert!(
            at <= r.sealed_after,
            "{set:?} {id} at {at}, sealed {}",
            r.sealed_after
        );
    }
    let env0 = stop(g.t);
    let t = env0.started();
    for (set, id) in &sets {
        assert!(log_set(&t, *set).contains(id), "{set:?} {id}");
        assert!(anchored(&t, *set, id), "{set:?} {id}");
    }
    let env0 = stop(t);
    // The backup from before them: refused, recovered with the archive.
    restore_database(&backup, &url);
    refused_start(&env0, "GOVERNANCE LOG STATE ROLLBACK");
    let e = recover_with_archive(&env0, None).expect_err("recovered without the archive");
    assert!(e.message.contains("--archive-dir"), "{e}");
    let notes = recover_with_archive(&env0, Some(&archive)).unwrap();
    for (id, what) in [
        (row.as_str(), "revocation re-applied"),
        (purpose.as_str(), "retirement re-applied"),
        (key_row.as_str(), "revocation re-applied"),
        (asset.as_str(), "expiry re-applied"),
    ] {
        assert!(
            notes.iter().any(|n| n.contains(id) && n.contains(what)),
            "{id}: {notes:?}"
        );
    }
    let t = env0.started();
    for (set, id) in &sets {
        assert!(log_set(&t, *set).contains(id), "{set:?} {id}");
        assert!(anchored(&t, *set, id), "{set:?} {id}");
    }
    // Undone alone, with the compacted mirror and the whole log intact:
    // still refused.
    let env0 = stop(t);
    attacker(
        &url,
        &["authorizations"],
        &format!("UPDATE authorizations SET status = 'active', revoked_at = NULL, revoked_by = NULL WHERE id = '{row}'"),
    );
    let m = refused_start(&env0, "AUTHORIZATION STATE ROLLBACK");
    assert!(m.contains(row.as_str()), "{m}");
}

/// Evidence across the boundary: an inclusion proof of an event inside the
/// sealed prefix verifies against the signed checkpoint, before the
/// compaction, after it, and after a restore of an old backup recovered
/// with the archive. (The database keeps every event and tree node.)
#[test]
fn evidence_verifies_across_a_compaction() {
    let Some((env0, backups)) = log_with_backups(&[1_000], 3_000) else {
        return;
    };
    let key = public_key(&env0);
    // Every signed checkpoint the database holds, verified, with inclusion
    // proofs of events across its tree.
    let check = |url: &str| -> std::collections::BTreeSet<String> {
        let db = Db::connect(url).unwrap();
        let mut c = db.conn().unwrap();
        let mut seen = std::collections::BTreeSet::new();
        let rows = c
            .query(
                "SELECT partition, size, signed FROM governance_checkpoints ORDER BY partition, size",
                &[],
            )
            .unwrap();
        for r in rows {
            let (partition, size): (String, i64) = (r.get(0), r.get(1));
            let cp: encompute_trust::govlog::SignedProjectCheckpoint =
                serde_json::from_value(r.get(2)).unwrap();
            cp.verify(&key).unwrap();
            let size = size as u64;
            let all = govlog::events(&mut *c, &partition, 0, size as i64).unwrap();
            assert_eq!(all.len() as u64, size);
            for pseq in [1u64, 2, size / 2, size] {
                if pseq == 0 {
                    continue;
                }
                let proof = govlog::prove(&mut *c, &partition, pseq, size).unwrap();
                cp.includes(&all[pseq as usize - 1], &proof).unwrap();
            }
            seen.insert(format!("{partition} {size} {}", cp.body.root));
        }
        seen
    };
    let before = check(&env0.url);
    let source = dump_log(&env0.url);
    let archive = tmp_dir("archive");
    let (env0, r) = compacted(env0, &archive);
    assert_eq!(r.sealed_after, 2_500);
    assert!(before.len() > 3, "{before:?}");
    assert_eq!(check(&env0.url), before);
    restore_database(&backups[0], &env0.url);
    recover_with_archive(&env0, Some(&archive)).unwrap();
    assert_same_rows("recovered", &source, &dump_log(&env0.url));
    // The backup's own checkpoints (older sizes) still verify against the
    // recovered log, and are among the ones signed before.
    let recovered = check(&env0.url);
    assert!(
        !recovered.is_empty() && recovered.is_subset(&before),
        "{recovered:?}"
    );
    assert_eq!(head_of(&env0.url), 3_000);
}

// --- the command line ----------------------------------------------------------------

/// Runs `bin` with `args` against `env0`'s database and anchor (the
/// development signing key the harness uses, written next to the anchor).
fn cli(bin: &str, env0: &Env0, args: &[&str]) -> (i32, String, String) {
    let key = env0.anchor_dir.join("development-signing.key");
    if !key.exists() {
        std::fs::write(&key, encompute_verification::hex(&env0.seed)).unwrap();
    }
    let o = std::process::Command::new(bin)
        .args(args)
        .env("ENCOMPUTE_ENV", "development")
        .env("ENCOMPUTE_DATABASE_URL", &env0.url)
        .env("ENCOMPUTE_ANCHOR_DIR", &env0.anchor_dir)
        .env("ENCOMPUTE_SIGNING_KEY_FILE", &key)
        .output()
        .unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// The commands an operator runs: a dry run, the compaction, the archive's
/// verification, and a recovery of an old backup with the archive.
#[test]
fn the_command_line_compacts_verifies_and_recovers() {
    let Some((env0, backups)) = log_with_backups(&[1_000], 3_000) else {
        return;
    };
    let bin = env!("CARGO_BIN_EXE_encompute-control");
    let archive = tmp_dir("archive");
    let dir = archive.to_str().unwrap();
    let source = dump_log(&env0.url);
    let common = [
        "--archive-dir",
        dir,
        "--keep-events",
        "100",
        "--min-age-days",
        "0",
    ];
    let mut dry = vec!["compact-governance-mirror", "--dry-run"];
    dry.extend(common);
    let (code, out, err) = cli(bin, &env0, &dry);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("DRY RUN") && out.contains("sealed through event 2500"),
        "{out}"
    );
    assert!(anchor_of(&env0).seal.is_none());
    // The default window (30 days) seals nothing of events seconds old.
    let (code, out, err) = cli(
        bin,
        &env0,
        &["compact-governance-mirror", "--archive-dir", dir],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("nothing to compact"), "{out}");
    let mut real = vec!["compact-governance-mirror"];
    real.extend(common);
    let (code, out, err) = cli(bin, &env0, &real);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("sealed through event 2500 (was 0)"), "{out}");
    let (code, out, err) = cli(
        bin,
        &env0,
        &["verify-governance-archive", "--archive-dir", dir],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("ARCHIVE VERIFIED: 5 segments"), "{out}");
    // A damaged archive is reported with a failing status.
    let seg = archive.join("segments/000000000003.jsonl");
    let good = std::fs::read(&seg).unwrap();
    std::fs::write(&seg, b"x").unwrap();
    let (code, _, err) = cli(
        bin,
        &env0,
        &["verify-governance-archive", "--archive-dir", dir],
    );
    assert_ne!(code, 0);
    assert!(err.contains("SHA-256"), "{err}");
    std::fs::write(&seg, good).unwrap();
    // Recovery of an old backup: refused without the archive, done with it.
    restore_database(&backups[0], &env0.url);
    let (code, _, err) = cli(bin, &env0, &["recover", "--operator", "op-1"]);
    assert_ne!(code, 0);
    assert!(err.contains("--archive-dir"), "{err}");
    let (code, out, err) = cli(
        bin,
        &env0,
        &["recover", "--operator", "op-1", "--archive-dir", dir],
    );
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("RECOVERED"), "{out}");
    assert_same_rows("recovered by the command", &source, &dump_log(&env0.url));
}

/// By hand, with the previous release's binary
/// (`ENCOMPUTE_OLD_CONTROL_BIN=/path/to/encompute-control`, built from the
/// sources before the seal existed): a compacted deployment's anchor is
/// refused by it, naming the version, and an uncompacted one still starts.
#[test]
#[ignore = "needs the previous release's binary: ENCOMPUTE_OLD_CONTROL_BIN"]
fn the_previous_release_refuses_a_sealed_anchor() {
    let Ok(old) = std::env::var("ENCOMPUTE_OLD_CONTROL_BIN") else {
        panic!("set ENCOMPUTE_OLD_CONTROL_BIN");
    };
    let Some((env0, _)) = log_with_backups(&[], 3_000) else {
        return;
    };
    let (code, out, err) = cli(&old, &env0, &["verify-state"]);
    assert_eq!(code, 0, "an uncompacted deployment: {out} {err}");
    assert!(out.contains("STATE VERIFIED"), "{out}");
    let archive = tmp_dir("archive");
    let (env0, _) = compacted(env0, &archive);
    assert_eq!(anchor_of(&env0).version, 3);
    let (code, _, err) = cli(&old, &env0, &["verify-state"]);
    assert_ne!(code, 0, "the previous release started over a sealed anchor");
    assert!(
        err.contains("version 3 is not supported by this release"),
        "{err}"
    );
    eprintln!("OLD BINARY REFUSED: {}", err.trim());
    // This release reads it.
    env0.started();
}
