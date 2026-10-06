//! INV-251, against a real OpenBao: a compaction deletes the sealed
//! segments of the governance log's mirror from a KV version 2 mount.
//!
//! - The whole path with the OpenBao store: a mirror in OpenBao, compact to
//!   a directory archive, verify the archive, delete the sealed segments
//!   through OpenBao's own delete, restart the control plane, recover an
//!   old backup from the archive, and the log verifies end to end.
//! - What a deleted segment is to a reader: gone from the live path, from
//!   every version and from the listing (a destroy of the key's metadata,
//!   not a soft delete, which leaves the key listed). Deleting again is
//!   harmless, a segment that is not the archived one is not deleted, and a
//!   soft-deleted one is cleaned up by the next delete.
//! - A failure of OpenBao in the middle of the pruning (a token that may
//!   delete every segment but one: the real 403) leaves a mirror that still
//!   verifies and a rerun finishes.
//!
//! OpenBao here is the development server (in-memory storage); production
//! keeps the same KV API on raft storage, whose durability this does not
//! exercise. Needs `ENCOMPUTE_TEST_BAO_ADDR` and `ENCOMPUTE_TEST_BAO_TOKEN`
//! (a root token, to create a policy and a token) and PostgreSQL
//! (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without them unless
//! `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use std::path::Path;

use serde_json::{json, Value};

use common::*;
use encompute_control::anchor::{AnchorStore, OpenBaoKvAnchor};
use encompute_control::compact::{verify_archive, CompactOptions};
use encompute_control::db::Db;
use encompute_control::govlog::{self, Draft};
use encompute_control::Control;
use encompute_trust::govlog::Partition;
use encompute_verification::ServiceSigner;

/// (address, root token), or `None` when skipped.
fn bao() -> Option<(String, String)> {
    match (
        std::env::var("ENCOMPUTE_TEST_BAO_ADDR"),
        std::env::var("ENCOMPUTE_TEST_BAO_TOKEN"),
    ) {
        (Ok(a), Ok(t)) => Some((a, t)),
        _ if std::env::var("ENCOMPUTE_REQUIRE_SERVICES").is_ok() => {
            panic!("ENCOMPUTE_REQUIRE_SERVICES is set but ENCOMPUTE_TEST_BAO_ADDR is not")
        }
        _ => {
            eprintln!("SKIPPED: set ENCOMPUTE_TEST_BAO_ADDR and ENCOMPUTE_TEST_BAO_TOKEN");
            None
        }
    }
}

/// A KV path nothing else uses.
fn unique_path(tag: &str) -> String {
    format!(
        "encompute-test/compact-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn store_at(addr: &str, token: &str, path: &str) -> OpenBaoKvAnchor {
    OpenBaoKvAnchor::new(addr, "secret", path, zeroize::Zeroizing::new(token.into()))
}

fn boxed(addr: &str, token: &str, path: &str) -> Box<dyn AnchorStore> {
    Box::new(store_at(addr, token, path))
}

/// A raw call to OpenBao: (status, body).
fn raw(addr: &str, token: &str, method: &str, url: &str, body: Option<Value>) -> (u16, Value) {
    let r = ureq::request(method, &format!("{addr}/v1/{url}")).set("X-Vault-Token", token);
    let res = match body {
        Some(b) => r.send_json(b),
        None => r.call(),
    };
    match res {
        Ok(r) => {
            let s = r.status();
            (s, r.into_json().unwrap_or(Value::Null))
        }
        Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap_or(Value::Null)),
        Err(e) => panic!("OpenBao unreachable: {e}"),
    }
}

fn seg(n: u64) -> String {
    format!("{n:012}")
}

/// What a reader of the live path sees of segment `n`: (the data read, the
/// metadata read, a read of version 1, whether the listing names it).
fn live(addr: &str, token: &str, path: &str, n: u64) -> (u16, u16, u16, bool) {
    let key = format!("{path}-glog/{}", seg(n));
    let data = raw(addr, token, "GET", &format!("secret/data/{key}"), None).0;
    let meta = raw(addr, token, "GET", &format!("secret/metadata/{key}"), None).0;
    let v1 = raw(
        addr,
        token,
        "GET",
        &format!("secret/data/{key}?version=1"),
        None,
    )
    .0;
    let (_, l) = raw(
        addr,
        token,
        "LIST",
        &format!("secret/metadata/{path}-glog"),
        None,
    );
    let listed = l["data"]["keys"]
        .as_array()
        .is_some_and(|k| k.iter().any(|x| x == &json!(seg(n))));
    (data, meta, v1, listed)
}

fn nums(s: &dyn AnchorStore) -> Vec<u64> {
    let mut v = s.mirror_list().unwrap();
    v.sort_unstable();
    v
}

fn opts(archive: &Path) -> CompactOptions {
    let mut o = CompactOptions::new(archive);
    o.keep_events = 100;
    o.min_age_secs = 0;
    o
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

/// `n` events from `from`, in groups of 400, each checkpointed (as the
/// service does): a segment per group in the mirror.
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

fn fresh_env() -> Option<Env0> {
    Some(Env0 {
        url: fresh_database()?,
        anchor_dir: tmp_dir("unused-anchor"),
        seed: [42; 32],
        oidc: vec![],
        env: encompute_control::config::Env::Development,
    })
}

fn start(env0: &Env0, addr: &str, token: &str, path: &str) -> T {
    env0.start_with(boxed(addr, token, path))
        .unwrap_or_else(|e| panic!("the control plane failed to start over OpenBao: {e}"))
}

fn public_key(env0: &Env0) -> String {
    ServiceSigner::from_seed("control-plane", &env0.seed)
        .unwrap()
        .public_key_hex()
}

/// Recovery over `env0`'s database and the OpenBao anchor, with the
/// archive; then the verification `recover` ends with.
fn recover(
    env0: &Env0,
    store: Box<dyn AnchorStore>,
    archive: Option<&Path>,
) -> encompute_ir::Result<Vec<String>> {
    let db = Db::connect(&env0.url).unwrap();
    let signer = ServiceSigner::from_seed("control-plane", &env0.seed).unwrap();
    let rc = Control::for_recovery(&recovery_config(env0), db, signer, store)?;
    let notes = rc.recover_with("operator-1", None, archive)?;
    rc.verify_state(true)?;
    Ok(notes)
}

/// A log of 4,500 events (11 checkpointed groups) in an OpenBao mirror,
/// with a database backup taken after 1,000 (inside what gets sealed):
/// (environment, backup name, the log's rows, path).
fn log_in_openbao(addr: &str, token: &str) -> Option<(Env0, String, Vec<String>, String)> {
    let env0 = fresh_env()?;
    let path = unique_path("flow");
    let t = start(&env0, addr, token, &path);
    append_and_checkpoint(&t, 0, 1_000);
    drop(t.control);
    let backup = format!("{}_baobk", db_name(&env0.url));
    backup_database(&env0.url, &backup);
    let t = start(&env0, addr, token, &path);
    append_and_checkpoint(&t, 1_000, 3_500);
    drop(t.control);
    let rows = dump_log(&env0.url);
    Some((env0, backup, rows, path))
}

// --- the whole path -------------------------------------------------------------------

/// Real OpenBao mirror, compact to a directory archive, verify it, delete
/// the sealed segments through OpenBao, restart, recover an old backup from
/// the archive, and the log verifies end to end.
#[test]
fn compaction_over_openbao_then_restart_and_recovery() {
    let Some((addr, token)) = bao() else { return };
    let Some((env0, backup, source, path)) = log_in_openbao(&addr, &token) else {
        return;
    };
    let store = store_at(&addr, &token, &path);
    let before = nums(&store);
    assert!(before.len() >= 8, "{before:?}");
    let archive = tmp_dir("bao-archive");

    // Compact: the sealed segments are archived and deleted from OpenBao.
    let t = start(&env0, &addr, &token, &path);
    let r = t.control.compact_mirror(&opts(&archive)).unwrap();
    drop(t.control);
    assert_eq!(r.sealed_after, 4_000, "{r:?}");
    assert!(r.archived_segments >= 7, "{r:?}");
    assert_eq!(r.pruned_segments, r.archived_segments, "{r:?}");
    assert!(r.notes.is_empty(), "{r:?}");

    // The archive verifies against the anchor in OpenBao.
    let sealed = verify_archive(&store, &public_key(&env0), &archive).unwrap();
    assert_eq!(sealed.sealed, 4_000);
    assert_eq!(sealed.segments, r.archived_segments);

    // The sealed segments are gone from every path a reader has; the tail
    // is still there.
    let after = nums(&store);
    assert_eq!(after.len(), before.len() - r.archived_segments);
    for n in &before {
        let gone = !after.contains(n);
        let (data, meta, v1, listed) = live(&addr, &token, &path, *n);
        if gone {
            assert_eq!(
                (data, meta, v1, listed),
                (404, 404, 404, false),
                "segment {n}"
            );
        } else {
            assert_eq!(
                (data, meta, v1, listed),
                (200, 200, 200, true),
                "segment {n}"
            );
        }
    }

    // Restart: the control plane starts over the pruned mirror (the start
    // verifies the database's log and the mirror against the anchor).
    let t = start(&env0, &addr, &token, &path);
    t.control.verify_state(true).unwrap();
    drop(t.control);

    // An old backup, inside the sealed prefix: refused, then recovered
    // from the archive, and every check passes.
    restore_database(&backup, &env0.url);
    let e = env0
        .start_with(boxed(&addr, &token, &path))
        .err()
        .expect("started on a database behind the anchor");
    assert!(e.message.contains("GOVERNANCE LOG STATE ROLLBACK"), "{e}");
    let e = recover(&env0, boxed(&addr, &token, &path), None).unwrap_err();
    assert!(e.message.contains("--archive-dir"), "{e}");
    let notes = recover(&env0, boxed(&addr, &token, &path), Some(&archive)).unwrap();
    assert!(
        notes.iter().any(|n| n.contains("from the mirror")),
        "{notes:?}"
    );
    assert_same_rows("recovered through OpenBao", &source, &dump_log(&env0.url));
    let t = start(&env0, &addr, &token, &path);
    t.control.verify_state(true).unwrap();
    // And it keeps working: a new event is checkpointed over the tail.
    append_and_checkpoint(&t, 4_500, 400);
    drop(t.control);
    start(&env0, &addr, &token, &path);
}

// --- what a delete is -----------------------------------------------------------------

/// Deleting is a destroy of the key and its metadata, idempotent, guarded
/// by the byte check, and finishes a soft delete.
#[test]
fn a_delete_removes_the_key_for_every_reader_and_is_guarded() {
    let Some((addr, token)) = bao() else { return };
    let path = unique_path("delete");
    let s = store_at(&addr, &token, &path);
    for n in 1..=5u64 {
        s.mirror_create(n, &format!("segment {n}\n")).unwrap();
    }
    // A second version of segment 2 (an open segment replaced): a delete
    // must take every version, not just the latest.
    s.mirror_replace(2, "segment 2 again\n", &|_| Ok(()))
        .unwrap();
    assert_eq!(live(&addr, &token, &path, 2), (200, 200, 200, true));

    // Deleted: gone from the data path, the metadata, every version and the
    // listing; the neighbours are untouched.
    s.mirror_delete(2, &|c| {
        assert_eq!(c, Some("segment 2 again\n"));
        Ok(())
    })
    .unwrap();
    assert_eq!(live(&addr, &token, &path, 2), (404, 404, 404, false));
    assert_eq!(s.mirror_read(2).unwrap(), "", "a reader sees nothing");
    assert_eq!(nums(&s), vec![1, 3, 4, 5]);
    assert_eq!(s.mirror_read(3).unwrap(), "segment 3\n");
    // Version 2 is gone as well (not only the latest).
    let key = format!("{path}-glog/{}", seg(2));
    assert_eq!(
        raw(
            &addr,
            &token,
            "GET",
            &format!("secret/data/{key}?version=2"),
            None
        )
        .0,
        404
    );

    // Idempotent: deleting again, and deleting what never existed, succeeds
    // and does not ask the guard anything.
    s.mirror_delete(2, &|_| panic!("nothing to judge")).unwrap();
    s.mirror_delete(99, &|_| panic!("nothing to judge"))
        .unwrap();
    assert_eq!(nums(&s), vec![1, 3, 4, 5]);

    // A segment whose bytes are not the archived ones is not deleted: the
    // guard's refusal comes back and the entry, its versions and its
    // listing are as they were.
    let e = s
        .mirror_delete(3, &|c| match c {
            Some("archived bytes\n") => Ok(()),
            _ => Err(encompute_ir::Error::new(
                encompute_ir::Code::TrustEvidence,
                "mirror segment 3 is not the archived one: left in place",
            )),
        })
        .unwrap_err();
    assert!(e.message.contains("left in place"), "{e}");
    assert_eq!(live(&addr, &token, &path, 3), (200, 200, 200, true));
    assert_eq!(s.mirror_read(3).unwrap(), "segment 3\n");

    // A soft delete (the data path's DELETE) hides the content but leaves
    // the key listed with its metadata: the listing still names it, which
    // is why the store deletes the metadata and not the data.
    let key4 = format!("{path}-glog/{}", seg(4));
    assert_eq!(
        raw(
            &addr,
            &token,
            "DELETE",
            &format!("secret/data/{key4}"),
            None
        )
        .0,
        204
    );
    let (data, meta, _, listed) = live(&addr, &token, &path, 4);
    assert_eq!((data, meta, listed), (404, 200, true), "soft delete");
    assert!(nums(&s).contains(&4), "a soft-deleted segment stays listed");
    // The store's delete finishes it, without asking the guard (it cannot
    // read content), and the segment is then really gone.
    s.mirror_delete(4, &|_| panic!("nothing to judge")).unwrap();
    assert_eq!(live(&addr, &token, &path, 4), (404, 404, 404, false));
    // The same for a segment whose versions were destroyed but whose key
    // is still there.
    let key5 = format!("{path}-glog/{}", seg(5));
    assert_eq!(
        raw(
            &addr,
            &token,
            "PUT",
            &format!("secret/destroy/{key5}"),
            Some(json!({"versions": [1]}))
        )
        .0,
        204
    );
    assert!(nums(&s).contains(&5));
    s.mirror_delete(5, &|_| panic!("nothing to judge")).unwrap();
    assert_eq!(live(&addr, &token, &path, 5), (404, 404, 404, false));
    assert_eq!(nums(&s), vec![1, 3]);
}

// --- a failure in the middle of the pruning -------------------------------------------

/// A token that may do everything the control plane does and delete every
/// mirror segment but `keep`: OpenBao's own 403 in the middle of a prune.
fn limited_token(addr: &str, root: &str, path: &str, keep: u64) -> String {
    let policy = format!(
        r#"
path "secret/data/{path}" {{ capabilities = ["create", "read", "update"] }}
path "secret/data/{path}-glog/*" {{ capabilities = ["create", "read", "update"] }}
path "secret/metadata/{path}-glog" {{ capabilities = ["list", "read"] }}
path "secret/metadata/{path}-glog/*" {{ capabilities = ["read", "list", "delete"] }}
path "secret/metadata/{path}-glog/{keep}" {{ capabilities = ["read", "list"] }}
"#,
        keep = seg(keep)
    );
    let name = format!("compact-{}", std::process::id());
    let (s, v) = raw(
        addr,
        root,
        "PUT",
        &format!("sys/policies/acl/{name}"),
        Some(json!({ "policy": policy })),
    );
    assert!(s == 204 || s == 200, "{s} {v}");
    let (s, v) = raw(
        addr,
        root,
        "POST",
        "auth/token/create",
        Some(json!({"policies": [name], "no_default_policy": true, "ttl": "1h"})),
    );
    assert_eq!(s, 200, "{v}");
    v["auth"]["client_token"].as_str().unwrap().to_owned()
}

/// OpenBao refuses a delete in the middle of the pruning: the compaction
/// says where it stopped, the seal holds, the mirror still verifies and the
/// control plane starts; a rerun finishes the pruning, leaving alone (and
/// saying so) a segment whose bytes are no longer the archived ones.
#[test]
fn an_openbao_error_in_the_middle_of_a_prune_is_finished_by_a_rerun() {
    let Some((addr, token)) = bao() else { return };
    let Some((env0, _backup, _source, path)) = log_in_openbao(&addr, &token) else {
        return;
    };
    let store = store_at(&addr, &token, &path);
    let before = nums(&store);
    let third = before[2];
    let limited = limited_token(&addr, &token, &path, third);
    let archive = tmp_dir("bao-archive-partial");

    // The compaction (with the limited token) seals, archives and prunes
    // until the third segment, which OpenBao refuses to delete.
    let t = env0
        .start_with(boxed(&addr, &limited, &path))
        .unwrap_or_else(|e| panic!("the limited token cannot run the control plane: {e}"));
    let e = t.control.compact_mirror(&opts(&archive)).unwrap_err();
    drop(t.control);
    assert!(
        e.message
            .contains(&format!("pruning stopped at mirror segment {third}")),
        "{e}"
    );
    assert!(e.message.contains("run the compaction again"), "{e}");
    assert!(e.message.contains("403"), "OpenBao's own refusal: {e}");

    // State: sealed, two segments deleted, the rest still in the mirror.
    let mid = nums(&store);
    assert_eq!(mid, before[2..].to_vec(), "{mid:?}");
    assert_eq!(
        live(&addr, &token, &path, before[0]),
        (404, 404, 404, false)
    );
    // The mirror and the database still verify, and the archive does.
    let t = start(&env0, &addr, &token, &path);
    t.control.verify_state(true).unwrap();
    drop(t.control);
    let archived = verify_archive(&store, &public_key(&env0), &archive).unwrap();
    assert_eq!(archived.sealed, 4_000);

    // Two of the segments still to be pruned are damaged. One holds another
    // sealed segment's events (a well-formed segment that is not the
    // archived one): the rerun does not delete it and says so. The other is
    // not even a segment (the reader ignores such a file below the seal, so
    // the compaction cannot prune it): it stays too, and is reported.
    let (swapped, garbage) = (before[3], before[4]);
    let other = store.mirror_read(before[5]).unwrap();
    store.mirror_replace(swapped, &other, &|_| Ok(())).unwrap();
    store
        .mirror_replace(garbage, "not a segment\n", &|_| Ok(()))
        .unwrap();
    let t = start(&env0, &addr, &token, &path);
    let r = t.control.compact_mirror(&opts(&archive)).unwrap();
    drop(t.control);
    assert_eq!(r.sealed_before, 4_000, "{r:?}");
    assert_eq!(r.sealed_after, 4_000, "{r:?}");
    // Every archived segment but the two the first run deleted and the two
    // damaged ones (the garbage one is not counted: it is not listed).
    assert_eq!(r.pruned_segments, archived.segments - 4, "{r:?}");
    assert!(
        r.notes
            .iter()
            .any(|n| n.contains(&format!("mirror segment {swapped} is not the archived one"))),
        "{:?}",
        r.notes
    );
    // The one that is not a segment is reported, naming its key, by the
    // compaction; verify-governance-archive fails on it (a non-zero exit
    // for the command), never deleting it.
    let key = seg(garbage);
    assert!(
        r.notes
            .iter()
            .any(|n| n.contains(&key) && n.contains("cannot be parsed") && n.contains(&path)),
        "{:?}",
        r.notes
    );
    let e = verify_archive(&store, &public_key(&env0), &archive).unwrap_err();
    assert!(
        e.message.contains(&key) && e.message.contains("cannot be parsed"),
        "{e}"
    );
    // Both are still in OpenBao with the bytes they had; the other sealed
    // segments are gone.
    let left = nums(&store);
    assert!(
        left.contains(&swapped) && left.contains(&garbage),
        "{left:?}"
    );
    assert_eq!(store.mirror_read(swapped).unwrap(), other);
    assert_eq!(store.mirror_read(garbage).unwrap(), "not a segment\n");
    assert!(!left.contains(&third));
    // Starting still works: events up to the seal are the archive's.
    let t = start(&env0, &addr, &token, &path);
    t.control.verify_state(true).unwrap();
    drop(t.control);
}
