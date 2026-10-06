//! Recovery from the mirror is batched, and what it verifies and writes is
//! unchanged: the importer checks every event in memory (leaf, partition
//! position, chain hash, continuation of the database's own log) and
//! writes a thousand per statement, in the caller's single transaction.
//!
//! - The database the batched importer produces equals, row for row, the
//!   one the reference importer (one event, three round trips: the code
//!   before batching) produces from the same mirror, and the one the
//!   appending path made: events, tree nodes, head, partition roots. From
//!   an empty log and from a backup that holds part of it.
//! - A refusal after some batches were written (the mirror changes
//!   between the verifying pass and the importing one) leaves the
//!   database as it was.
//! - A process killed in the middle of an import leaves the database as it
//!   was (the transaction never committed); running recovery again
//!   imports everything and reaches the same database.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};

use common::*;
use encompute_control::anchor::{Allow, AnchorStore, DirAnchor, StateAnchor, StoredAnchor};
use encompute_control::db::Db;
use encompute_control::govlog::{self, Draft, Importer, ReferenceImporter};
use encompute_control::mirror;
use encompute_control::Control;
use encompute_trust::govlog::Partition;
use encompute_verification::ServiceSigner;

fn stop(t: T) -> Env0 {
    let env0 = t.env0;
    drop(t.control);
    env0
}

fn anchor_of(env0: &Env0) -> StateAnchor {
    let b = std::fs::read(env0.anchor_dir.join("state-anchor.json")).unwrap();
    match StoredAnchor::parse(&b).unwrap() {
        StoredAnchor::V2(a) => a,
        StoredAnchor::V1(_) => panic!("version 1"),
    }
}

/// `n` events from `from`, over a platform partition and seven
/// organizations' (different kinds and references, so the leaves differ).
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

fn append_and_checkpoint(t: &T, from: usize, n: usize) {
    // In groups, each checkpointed (as the service does).
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

/// Imports the mirror (anchored `a`) into `url` with the reference
/// importer.
fn import_reference(env0: &Env0, a: &StateAnchor, url: &str) -> u64 {
    let db = Db::connect(url).unwrap();
    // A cold database is not migrated yet (a template clone is).
    db.migrate().unwrap();
    let store = DirAnchor::new(env0.anchor_dir.clone()).unwrap();
    db.tx(|t| {
        let mut imp = ReferenceImporter::new(t)?;
        mirror::scan(
            &store,
            a.seal.as_ref(),
            a.glog_size,
            &a.glog_head,
            Some(&mut |x: &govlog::Exported| imp.push(t, x)),
        )?;
        Ok(imp.added)
    })
    .unwrap()
}

/// The same with the batched importer.
fn import_batched(env0: &Env0, a: &StateAnchor, url: &str) -> u64 {
    let db = Db::connect(url).unwrap();
    // A cold database is not migrated yet (a template clone is).
    db.migrate().unwrap();
    let store = DirAnchor::new(env0.anchor_dir.clone()).unwrap();
    db.tx(|t| {
        let mut imp = Importer::new(t)?;
        mirror::scan(
            &store,
            a.seal.as_ref(),
            a.glog_size,
            &a.glog_head,
            Some(&mut |x: &govlog::Exported| imp.push(t, x)),
        )?;
        imp.finish(t)
    })
    .unwrap()
}

/// The batched importer writes what the reference importer writes, and
/// what appending wrote: from an empty log, and resuming a backup that
/// holds part of it (not at a batch boundary).
#[test]
fn batched_import_equals_the_reference_import_and_the_appended_log() {
    let Some(t) = setup() else { return };
    let url = t.env0.url.clone();
    let backup = format!("{}_impbk", db_name(&url));
    // 2,650 events in the backup would not cross a batch twice: take 1,350
    // (one batch and a half) then 2,100 more (past three batches).
    append_and_checkpoint(&t, 0, 1_350);
    let env0 = stop(t);
    backup_database(&env0.url, &backup);
    let t = env0.started();
    append_and_checkpoint(&t, 1_350, 2_100);
    let env0 = stop(t);
    let a = anchor_of(&env0);
    assert!(a.glog_size >= 3_450, "{a:?}");
    let source = dump_log(&env0.url);

    // From an empty log: both ways.
    let (e1, e2) = (fresh_database().unwrap(), fresh_database().unwrap());
    let n1 = import_reference(&env0, &a, &e1);
    let n2 = import_batched(&env0, &a, &e2);
    assert_eq!(n1, a.glog_size as u64);
    assert_eq!(n1, n2);
    assert_same_rows("reference import of an empty log", &source, &dump_log(&e1));
    assert_same_rows("batched import of an empty log", &source, &dump_log(&e2));

    // Resuming the backup, both ways (the live database is replaced by it
    // each time).
    for (label, batched) in [("reference", false), ("batched", true)] {
        restore_database(&backup, &env0.url);
        let before = dump_log(&env0.url);
        assert!(before.len() < source.len());
        let n = if batched {
            import_batched(&env0, &a, &env0.url)
        } else {
            import_reference(&env0, &a, &env0.url)
        };
        assert_eq!(n, (a.glog_size - 1_350) as u64, "{label}");
        assert_same_rows(
            &format!("{label} import resuming a backup"),
            &source,
            &dump_log(&env0.url),
        );
    }
    // The database a restored backup and a recovery produce starts.
    env0.started();
}

/// A store that runs `on_read(count, segment, lines)` on every read of a
/// mirror segment (to change what the second pass sees, or to die).
struct Hook {
    inner: DirAnchor,
    reads: AtomicUsize,
    on_read: Box<dyn Fn(usize, u64, String) -> String + Send + Sync>,
}

impl AnchorStore for Hook {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn load(&self) -> encompute_ir::Result<Option<StoredAnchor>> {
        self.inner.load()
    }
    fn store(&self, next: &StateAnchor, expected: u64) -> encompute_ir::Result<()> {
        self.inner.store(next, expected)
    }
    fn mirror_list(&self) -> encompute_ir::Result<Vec<u64>> {
        self.inner.mirror_list()
    }
    fn mirror_read(&self, n: u64) -> encompute_ir::Result<String> {
        let lines = self.inner.mirror_read(n)?;
        let count = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        Ok((self.on_read)(count, n, lines))
    }
    fn mirror_create(&self, n: u64, lines: &str) -> encompute_ir::Result<()> {
        self.inner.mirror_create(n, lines)
    }
    fn mirror_replace(&self, n: u64, lines: &str, allow: &Allow<'_>) -> encompute_ir::Result<()> {
        self.inner.mirror_replace(n, lines, allow)
    }
    fn mirror_delete(&self, n: u64, allow: &Allow<'_>) -> encompute_ir::Result<()> {
        self.inner.mirror_delete(n, allow)
    }
}

fn recovery_control(env0: &Env0, store: Box<dyn AnchorStore>) -> Control {
    let db = Db::connect(&env0.url).unwrap();
    let signer = ServiceSigner::from_seed("control-plane", &env0.seed).unwrap();
    Control::for_recovery(&recovery_config(env0), db, signer, store).unwrap()
}

fn head_of(url: &str) -> (i64, String) {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    let r = c
        .query_one("SELECT gseq, hash FROM governance_head WHERE id", &[])
        .unwrap();
    (r.get(0), r.get(1))
}

/// A database with a backup (`backup`, holding the first `kept` events)
/// restored behind a mirror of `total`; the original's dump.
fn behind_a_mirror(kept: usize, total: usize) -> Option<(Env0, Vec<String>)> {
    let t = setup()?;
    let backup = format!("{}_impbk", db_name(&t.env0.url));
    append_and_checkpoint(&t, 0, kept);
    let env0 = stop(t);
    backup_database(&env0.url, &backup);
    let t = env0.started();
    append_and_checkpoint(&t, kept, total - kept);
    let env0 = stop(t);
    let source = dump_log(&env0.url);
    restore_database(&backup, &env0.url);
    Some((env0, source))
}

/// The mirror changes between the verifying pass and the importing one
/// (a second writer, a replaced segment): the importing pass refuses it
/// after some batches were written, and the database is as it was.
#[test]
fn a_refusal_after_some_batches_leaves_the_database_as_it_was() {
    let Some((env0, source)) = behind_a_mirror(600, 3_300) else {
        return;
    };
    let before = dump_log(&env0.url);
    let segments = DirAnchor::new(env0.anchor_dir.clone())
        .unwrap()
        .mirror_list()
        .unwrap()
        .len();
    assert!(segments >= 6, "{segments} segments");
    // Reads 1..=segments are the verifying pass; the fifth segment of the
    // importing pass differs (an event's hash flipped): 2,000 events were
    // written by then.
    let target = segments + 5;
    let store = Hook {
        inner: DirAnchor::new(env0.anchor_dir.clone()).unwrap(),
        reads: AtomicUsize::new(0),
        on_read: Box::new(move |count, _n, lines| {
            if count == target {
                let mut l: Vec<String> = lines.lines().map(str::to_owned).collect();
                let last = l.len() - 1;
                l[last] = l[last].replacen("\"hash\":\"", "\"hash\":\"0", 1);
                format!("{}\n", l.join("\n"))
            } else {
                lines
            }
        }),
    };
    let rc = recovery_control(&env0, Box::new(store));
    let e = rc
        .recover("operator-1")
        .expect_err("imported a changed mirror");
    assert!(e.message.contains("mirror"), "{e}");
    assert_same_rows("after the refused import", &before, &dump_log(&env0.url));
    // With the mirror as it is, the same recovery succeeds and reaches the
    // database appending made.
    drop(rc);
    run_recovery(&env0);
    let after = dump_log(&env0.url);
    let events = |d: &[String]| d.iter().filter(|x| x.starts_with("event ")).count();
    assert!(events(&after) >= events(&source));
    env0.started();
}

/// The child of [`a_process_killed_mid_import_leaves_the_database_as_it_was`].
#[test]
fn import_kill_child() {
    let (Ok(url), Ok(dir), Ok(at)) = (
        std::env::var("ENCOMPUTE_IMPORT_KILL_URL"),
        std::env::var("ENCOMPUTE_IMPORT_KILL_DIR"),
        std::env::var("ENCOMPUTE_IMPORT_KILL_AT"),
    ) else {
        return;
    };
    let at: usize = at.parse().unwrap();
    let env0 = Env0 {
        url,
        anchor_dir: dir.into(),
        seed: [42; 32],
        oidc: vec![],
        env: encompute_control::config::Env::Development,
    };
    let store = Hook {
        inner: DirAnchor::new(env0.anchor_dir.clone()).unwrap(),
        reads: AtomicUsize::new(0),
        on_read: Box::new(move |count, _n, lines| {
            if count == at {
                // Dead in the middle of the importing pass.
                std::process::exit(137);
            }
            lines
        }),
    };
    let rc = recovery_control(&env0, Box::new(store));
    let _ = rc.recover("operator-1");
    std::process::exit(0);
}

/// A real kill in the middle of an import (after batches were sent, before
/// the commit): the database is as it was, with no event of the import,
/// and running recovery again imports everything.
#[test]
fn a_process_killed_mid_import_leaves_the_database_as_it_was() {
    if std::env::var("ENCOMPUTE_IMPORT_KILL_URL").is_ok() {
        return;
    }
    let Some((env0, source)) = behind_a_mirror(600, 3_300) else {
        return;
    };
    let before = dump_log(&env0.url);
    let head_before = head_of(&env0.url);
    let segments = DirAnchor::new(env0.anchor_dir.clone())
        .unwrap()
        .mirror_list()
        .unwrap()
        .len();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "import_kill_child", "--test-threads=1"])
        .env("ENCOMPUTE_IMPORT_KILL_URL", &env0.url)
        .env("ENCOMPUTE_IMPORT_KILL_DIR", &env0.anchor_dir)
        // The verifying pass reads every segment once; the kill is at the
        // fifth segment of the importing pass (2,000 events written).
        .env("ENCOMPUTE_IMPORT_KILL_AT", (segments + 5).to_string())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(137), "{status:?}");
    // Nothing of the import is visible: not a batch, not the head.
    assert_eq!(head_of(&env0.url), head_before);
    assert_same_rows("after the killed import", &before, &dump_log(&env0.url));
    // Recovery starts over and finishes.
    let notes = run_recovery(&env0);
    assert!(
        notes.iter().any(|n| n.contains("from the mirror")),
        "{notes:?}"
    );
    let after = dump_log(&env0.url);
    // Recovery may append its own events after the imported ones: the
    // imported prefix is the appended log's, row for row.
    let prefix: Vec<&String> = source.iter().filter(|x| x.starts_with("event ")).collect();
    let got: Vec<&String> = after.iter().filter(|x| x.starts_with("event ")).collect();
    assert_eq!(&got[..prefix.len()], &prefix[..]);
    env0.started();
}
