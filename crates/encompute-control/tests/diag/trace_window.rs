//! TEST-ONLY diagnostic. A passively instrumented copy of the `in_window`
//! helper of `anchor_window_adversarial.rs` / `anchor_negatives.rs`.
//!
//! The synchronisation logic is the original's, statement for statement: the
//! same trigger that sleeps one second in the audit insert, the same 5 ms
//! poll of `pg_locks` for a granted `RowExclusiveLock` by another backend on
//! `tables[0]`, the same `LOCK TABLE .. ACCESS EXCLUSIVE`, the same 500 ms
//! pause, the same `SET LOCAL session_replication_role = replica` and attack
//! SQL, the same commit. What is added is only observation:
//!
//! * the poll also returns the matched backends' pids (`array_agg(l.pid)`);
//! * the attack is sent with `simple_query` (the same wire message
//!   `batch_execute` sends) followed by `SELECT pg_current_xact_id()`, so the
//!   rows changed and the attacker's xid come back with no extra round trip;
//! * a SEPARATE monitor connection samples `pg_stat_activity` and `pg_locks`
//!   every 2 ms (it takes no table lock, so it cannot delay or be delayed by
//!   the attacker's ACCESS EXCLUSIVE lock);
//! * everything else (audit rows of the call, xids, commit order) is read
//!   AFTER the call, on the helper's own connection.
//!
//! Direct statement-level chronology (added): when the PostgreSQL service logs every statement
//! and every lock wait (scripts/release/diag-tests.sh, phase B), the helper additionally
//! * tags its own sessions (`application_name` diag-helper / diag-attacker / diag-monitor) so
//!   the server log names them, and silences the monitor's and the attacker's poll statements
//!   (session-level `log_statement=none`), which would only flood the log;
//! * runs a `clock_timestamp()` handshake (marked `diag:hs:..`) and a marker statement
//!   `diag:call_start` before the call and `diag:response` the instant `acting()` returns, on
//!   the helper's own idle connection, so the server log carries the response time on the
//!   server clock;
//! * emits a `server_ids` event: database name/oid, the oids of the tables, the pids.
//! The verdict from this server log is computed by scripts/release/diag-classify-window.py.
//! None of this adds a lock or a sleep inside the call.
//!
//! No sleep and no lock is added. Events are kept in memory and written, in
//! one append, after the call; set `ENCOMPUTE_TEST_TRACE=<file>`.
//!
//! HARD RULE: unless the verdict is `window_ok` the helper prints
//! `INCONCLUSIVE: attack did not reach the intended window` and panics, so a
//! missed attack is never a silent pass.

use std::collections::BTreeSet;
use std::fmt::Debug;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

static CALLS: AtomicU64 = AtomicU64::new(0);

fn wall_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

/// Replaces anything that could be a token, key or digest (a long run of
/// token characters) and truncates.
fn scrub(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= 32 {
            out.push_str("<redacted>");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' || ch == '=' {
            run.push(ch);
        } else {
            flush(&mut run, &mut out);
            out.push(ch);
        }
    }
    flush(&mut run, &mut out);
    if out.len() > max {
        let mut cut = max;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str("...");
    }
    out
}

#[derive(Clone, Debug, PartialEq)]
struct BackendRow {
    pid: i32,
    app: String,
    state: String,
    xid: String,
    xact_start: String,
    query_start: String,
    wait: String,
    query: String,
    locks: String,
}

impl BackendRow {
    fn json(&self) -> Value {
        json!({"pid": self.pid, "application_name": self.app, "state": self.state,
               "backend_xid": self.xid, "xact_start": self.xact_start,
               "query_start": self.query_start, "wait_event": self.wait,
               "query": self.query, "locks": self.locks})
    }
    fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.pid, self.state, self.xid, self.wait, self.query, self.locks
        )
    }
    fn holds(&self, table: &str) -> bool {
        self.locks
            .split(',')
            .any(|l| l == format!("{table}:RowExclusiveLock:g"))
    }
    fn queued_ae(&self, table: &str) -> bool {
        self.locks
            .split(',')
            .any(|l| l == format!("{table}:AccessExclusiveLock:w"))
    }
}

#[derive(Clone)]
struct Sample {
    t_ms: f64,
    wall_us: i64,
    rows: Vec<BackendRow>,
}

const SAMPLE_SQL: &str = "
SELECT a.pid, coalesce(a.application_name,''), coalesce(a.state,''), coalesce(a.backend_xid::text,''),
       coalesce(to_char(a.xact_start,'HH24:MI:SS.US'),''), coalesce(to_char(a.query_start,'HH24:MI:SS.US'),''),
       coalesce(a.wait_event_type||'/'||a.wait_event,''), left(coalesce(a.query,''),120),
       coalesce((SELECT string_agg(c.relname||':'||l.mode||':'||CASE WHEN l.granted THEN 'g' ELSE 'w' END, ',' ORDER BY c.relname, l.mode)
                   FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
                  WHERE l.pid=a.pid AND c.relname = ANY($1)),'')
  FROM pg_stat_activity a
 WHERE a.datname = current_database() AND a.pid <> pg_backend_pid() AND a.backend_type='client backend'
 ORDER BY a.pid";

fn sample_once(m: &mut postgres::Client, rel: &Vec<String>, t0: Instant) -> Option<Sample> {
    let t_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let w = wall_us();
    let rows = m.query(SAMPLE_SQL, &[rel]).ok()?;
    Some(Sample {
        t_ms,
        wall_us: w,
        rows: rows
            .iter()
            .map(|r| BackendRow {
                pid: r.get(0),
                app: r.get(1),
                state: r.get(2),
                xid: r.get(3),
                xact_start: r.get(4),
                query_start: r.get(5),
                wait: r.get(6),
                query: r.get(7),
                locks: r.get(8),
            })
            .collect(),
    })
}

struct Sink {
    path: Option<String>,
    lines: Vec<String>,
    flushed: bool,
}
impl Sink {
    fn ev(&mut self, v: Value) {
        self.lines.push(v.to_string());
    }
    fn flush(&mut self) {
        if self.flushed {
            return;
        }
        self.flushed = true;
        let mut text = self.lines.join("\n");
        text.push('\n');
        match &self.path {
            Some(p) => {
                // One append of the whole call: lines of concurrent tests never interleave
                // (O_APPEND, a single write of at most a few hundred KiB).
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                    let _ = f.write_all(text.as_bytes());
                }
            }
            None => eprint!("{text}"),
        }
    }
}
struct SinkGuard(Arc<Mutex<Sink>>);
impl Drop for SinkGuard {
    fn drop(&mut self) {
        if let Ok(mut s) = self.0.lock() {
            s.flush();
        }
    }
}

#[derive(Default, Clone)]
struct Attacker {
    pid: i32,
    poll_n: u64,
    match_t_ms: Option<f64>,
    match_wall_us: i64,
    match_pids: Vec<i32>,
    lock_request_ms: Option<f64>,
    lock_granted_ms: Option<f64>,
    attack_start_ms: Option<f64>,
    attack_done_ms: Option<f64>,
    attack_rows: Vec<u64>,
    attacker_xid: Option<i64>,
    commit_start_ms: Option<f64>,
    commit_done_ms: Option<f64>,
    commit_wall_us: i64,
}

pub fn in_window_traced<R: Send + Debug>(
    url: &str,
    tables: &[&str],
    attack_sql: &str,
    acting: impl FnOnce() -> R + Send,
) -> R {
    let test = std::thread::current()
        .name()
        .unwrap_or("unnamed")
        .to_owned();
    let call_id = format!(
        "{}-{}-{}",
        std::process::id(),
        CALLS.fetch_add(1, Ordering::SeqCst),
        wall_us()
    );
    let sink = Arc::new(Mutex::new(Sink {
        path: std::env::var("ENCOMPUTE_TEST_TRACE").ok().filter(|p| !p.is_empty()),
        lines: vec![],
        flushed: false,
    }));
    let _guard = SinkGuard(sink.clone());

    let table = tables[0];
    // ---- identical to the original: the attacker slows the call's audit insert ----
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    c.batch_execute(
        "CREATE OR REPLACE FUNCTION atk_sleep() RETURNS trigger AS $$ BEGIN PERFORM pg_sleep(1.0); RETURN NULL; END $$ LANGUAGE plpgsql;
         DROP TRIGGER IF EXISTS atk_slow ON audit_events;
         CREATE TRIGGER atk_slow AFTER INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION atk_sleep();",
    ).unwrap();
    // ---- observation set-up (before the call starts; no effect on the call) ----
    let baseline: i64 = c
        .query_one("SELECT coalesce(max(seq),0)::bigint FROM audit_events", &[])
        .map(|r| r.get(0))
        .unwrap_or(0);
    let mut mon = postgres::Client::connect(url, postgres::NoTls).unwrap();
    let mut rel: Vec<String> = tables.iter().map(|s| s.to_string()).collect();
    rel.push("audit_events".into());
    let mon_pid: i32 = mon
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    let helper_pid: i32 = c.query_one("SELECT pg_backend_pid()", &[]).unwrap().get(0);

    // ---- direct chronology set-up (before the call starts) ----
    c.batch_execute(&format!("SET application_name = 'diag-helper-{call_id}'"))
        .unwrap();
    mon.batch_execute("SET application_name = 'diag-monitor'; SET log_statement = 'none'; SET log_min_duration_statement = -1")
        .unwrap();
    // Clock handshake: server clock minus client wall clock, from the round trip of least
    // delay. Server log lines (%m) are on the server clock; the in-test times are on this one.
    let mut hs_best: Option<(i64, i64, i64)> = None; // (rtt_us, offset_us, server_us)
    for i in 0..7 {
        let b = wall_us();
        let srv: i64 = c
            .query_one(
                &format!("SELECT (extract(epoch from clock_timestamp())*1000000)::bigint /* diag:hs:{call_id}:{i} */"),
                &[],
            )
            .map(|r| r.get(0))
            .unwrap_or(0);
        let a = wall_us();
        let rtt = a - b;
        let off = srv - (a + b) / 2;
        if hs_best.is_none_or(|h| rtt < h.0) {
            hs_best = Some((rtt, off, srv));
        }
    }
    let (hs_rtt_us, hs_offset_us, _) = hs_best.unwrap_or((0, 0, 0));
    let db_name: String = c.query_one("SELECT current_database()::text", &[]).unwrap().get(0);
    let db_oid: i64 = c
        .query_one("SELECT oid::bigint FROM pg_database WHERE datname = current_database()", &[])
        .unwrap()
        .get(0);
    let rel_oids: Vec<(String, i64)> = c
        .query(
            "SELECT relname::text, oid::bigint FROM pg_class WHERE relname = ANY($1) AND relnamespace = 'public'::regnamespace ORDER BY relname",
            &[&rel],
        )
        .map(|rs| rs.iter().map(|r| (r.get(0), r.get(1))).collect())
        .unwrap_or_default();
    c.batch_execute(&format!("SELECT 'diag:call_start:{call_id}'"))
        .unwrap();

    let t0 = Instant::now();
    let w0 = wall_us();
    sink.lock().unwrap().ev(json!({
        "ev": "server_ids", "call_id": call_id, "test": test, "database": db_name, "database_oid": db_oid,
        "relation_oids": rel_oids.iter().map(|(n, o)| (n.clone(), json!(o))).collect::<serde_json::Map<String, Value>>(),
        "helper_pid": helper_pid, "monitor_pid": mon_pid,
        "clock_offset_us": hs_offset_us, "clock_rtt_us": hs_rtt_us,
        "clock_note": "server_time_us = client_wall_us + clock_offset_us",
    }));
    sink.lock().unwrap().ev(json!({
        "ev": "call_start", "call_id": call_id, "test": test, "t_ms": 0.0, "wall_us": w0,
        "tables": tables, "attack_sql": scrub(attack_sql, 300), "audit_baseline_seq": baseline,
        "monitor_pid": mon_pid, "helper_pid": helper_pid, "database": url.rsplit('/').next().unwrap_or(""),
    }));

    let done = AtomicBool::new(false);
    let stop = AtomicBool::new(false);
    let att = Arc::new(Mutex::new(Attacker::default()));
    let samples: Arc<Mutex<Vec<Sample>>> = Arc::new(Mutex::new(vec![]));
    let mut call_end_ms = 0.0;
    let mut call_end_wall = 0i64;

    let r = std::thread::scope(|s| {
        let mon_h = s.spawn(|| {
            // Passive monitor: records a sample whenever the picture changes.
            let mut last = String::new();
            while !stop.load(Ordering::SeqCst) {
                if let Some(smp) = sample_once(&mut mon, &rel, t0) {
                    let fp: String = smp
                        .rows
                        .iter()
                        .map(|r| r.fingerprint())
                        .collect::<Vec<_>>()
                        .join(";");
                    if fp != last {
                        last = fp;
                        samples.lock().unwrap().push(smp);
                    }
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            if let Some(smp) = sample_once(&mut mon, &rel, t0) {
                samples.lock().unwrap().push(smp);
            }
        });
        let h = s.spawn(|| {
            let mut a = postgres::Client::connect(url, postgres::NoTls).unwrap();
            let me: i32 = a.query_one("SELECT pg_backend_pid()", &[]).unwrap().get(0);
            att.lock().unwrap().pid = me;
            // the poll (every 5 ms) is not logged by the server; the attacker's own statements
            // from the LOCK onwards are
            a.batch_execute(&format!(
                "SET application_name = 'diag-attacker-{call_id}'; SET log_statement = 'none'; SET log_min_duration_statement = -1"
            ))
            .unwrap();
            // wait until another backend holds RowExclusiveLock on the table (original predicate)
            let mut polls = 0u64;
            let pids: Vec<i32> = loop {
                let row = a.query_one(
                    "SELECT count(*), coalesce(array_agg(l.pid), '{}'::int4[]) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
                     WHERE c.relname=$1 AND l.mode='RowExclusiveLock' AND l.granted AND l.pid<>$2",
                    &[&table, &me]).unwrap();
                polls += 1;
                let n: i64 = row.get(0);
                if n > 0 {
                    break row.get(1);
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            {
                let mut g = att.lock().unwrap();
                g.poll_n = polls;
                g.match_t_ms = Some(t0.elapsed().as_secs_f64() * 1000.0);
                g.match_wall_us = wall_us();
                g.match_pids = pids;
                g.lock_request_ms = g.match_t_ms;
            }
            a.batch_execute("SET log_statement = 'all'; SET log_min_duration_statement = 0").unwrap();
            let mut tx = a.transaction().unwrap();
            // blocks until the service's transaction has committed
            // SELF-TEST of the classifier only (never set in CI): take the first table, wait,
            // then the rest, which widens the gap `LOCK TABLE a, b` already has.
            let force_gap: Option<u64> = std::env::var("ENCOMPUTE_TEST_TRACE_FORCE_GAP_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|_| tables.len() > 1);
            if let Some(ms) = force_gap {
                tx.batch_execute(&format!("LOCK TABLE {} IN ACCESS EXCLUSIVE MODE", tables[0]))
                    .unwrap();
                std::thread::sleep(Duration::from_millis(ms));
                tx.batch_execute(&format!(
                    "LOCK TABLE {} IN ACCESS EXCLUSIVE MODE",
                    tables[1..].join(", ")
                ))
                .unwrap();
            } else {
                tx.batch_execute(&format!(
                    "LOCK TABLE {} IN ACCESS EXCLUSIVE MODE",
                    tables.join(", ")
                ))
                .unwrap();
            }
            att.lock().unwrap().lock_granted_ms = Some(t0.elapsed().as_secs_f64() * 1000.0);
            // the service's post-commit read is now queued behind us
            std::thread::sleep(Duration::from_millis(500));
            att.lock().unwrap().attack_start_ms = Some(t0.elapsed().as_secs_f64() * 1000.0);
            let msgs = tx
                .simple_query(&format!(
                    "SET LOCAL session_replication_role = replica; {attack_sql}; SELECT pg_current_xact_id()::text::bigint"
                ))
                .unwrap();
            {
                let mut g = att.lock().unwrap();
                g.attack_done_ms = Some(t0.elapsed().as_secs_f64() * 1000.0);
                for m in msgs {
                    match m {
                        postgres::SimpleQueryMessage::CommandComplete(n) => g.attack_rows.push(n),
                        postgres::SimpleQueryMessage::Row(r) => {
                            g.attacker_xid = r.get(0).and_then(|x| x.parse().ok())
                        }
                        _ => {}
                    }
                }
                g.commit_start_ms = Some(t0.elapsed().as_secs_f64() * 1000.0);
            }
            tx.commit().unwrap();
            {
                let mut g = att.lock().unwrap();
                g.commit_done_ms = Some(t0.elapsed().as_secs_f64() * 1000.0);
                g.commit_wall_us = wall_us();
            }
            done.store(true, Ordering::SeqCst);
        });
        let r = acting();
        call_end_ms = t0.elapsed().as_secs_f64() * 1000.0;
        call_end_wall = wall_us();
        // the response, on the server clock: a marker statement on the helper's idle connection
        // (the service and the attacker are not touched)
        let _ = c.batch_execute(&format!("SELECT 'diag:response:{call_id}'"));
        let hr = h.join();
        stop.store(true, Ordering::SeqCst);
        let _ = mon_h.join();
        if let Err(e) = hr {
            std::panic::resume_unwind(e);
        }
        r
    });
    assert!(done.load(Ordering::SeqCst));
    c.batch_execute("DROP TRIGGER IF EXISTS atk_slow ON audit_events")
        .unwrap();

    // ---- after the call: what did it commit? ----
    let described = scrub(&format!("{r:?}"), 600);
    let att = att.lock().unwrap().clone();
    let samples = samples.lock().unwrap().clone();

    let audit_rows: Vec<(i64, String, String, String)> = c
        .query(
            "SELECT seq, xmin::text, action, result FROM audit_events WHERE seq > $1 ORDER BY seq",
            &[&baseline],
        )
        .map(|rs| {
            rs.iter()
                .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
                .collect()
        })
        .unwrap_or_default();
    // The target transaction: the xid of the first audit row the call wrote (read after the
    // call); when the attack erased it (the audit-trace tests), the xid of the backend seen
    // executing `INSERT INTO audit_events` (it sleeps 1 s there) before the attacker's lock.
    let audit_row_xid: Option<i64> = audit_rows.first().and_then(|r| r.1.parse().ok());
    let monitor_audit_xids: BTreeSet<i64> = samples
        .iter()
        .filter(|smp| att.lock_granted_ms.is_none_or(|g| smp.t_ms < g))
        .flat_map(|smp| smp.rows.iter())
        .filter(|r| r.query.starts_with("INSERT INTO audit_events") && r.wait == "Timeout/PgSleep")
        .filter_map(|r| r.xid.parse().ok())
        .collect();
    let (target_xid, target_xid_source): (Option<i64>, &str) = match audit_row_xid {
        Some(x) if monitor_audit_xids.is_empty() || monitor_audit_xids.contains(&x) => {
            (Some(x), "audit_row_xmin")
        }
        Some(_) => (None, "conflict_audit_row_vs_monitor"),
        None if monitor_audit_xids.len() == 1 => {
            (monitor_audit_xids.iter().next().copied(), "monitor_audit_insert_backend")
        }
        None => (None, "none"),
    };
    let status = |c: &mut postgres::Client, x: Option<i64>| -> String {
        x.and_then(|x| {
            c.query_one("SELECT txid_status($1::bigint)", &[&x])
                .ok()
                .and_then(|r| r.get::<_, Option<String>>(0))
        })
        .unwrap_or_else(|| "unknown".into())
    };
    let commit_us = |c: &mut postgres::Client, x: Option<i64>| -> Option<i64> {
        let x = x?;
        c.query_one(
            "SELECT (extract(epoch from pg_xact_commit_timestamp(($1::bigint)::text::xid))*1000000)::bigint",
            &[&x],
        )
        .ok()
        .and_then(|r| r.get::<_, Option<i64>>(0))
    };
    let target_status = status(&mut c, target_xid);
    let attacker_status = status(&mut c, att.attacker_xid);
    let target_commit_us = commit_us(&mut c, target_xid);
    let attacker_commit_us = commit_us(&mut c, att.attacker_xid);

    // Who held the lock the attacker's poll matched, and was it the target transaction?
    let mut holders = vec![];
    for pid in &att.match_pids {
        let mut xids = BTreeSet::new();
        let mut first_t = None;
        let mut query = String::new();
        let mut app = String::new();
        let mut seen = false;
        for smp in &samples {
            if let Some(row) = smp.rows.iter().find(|r| r.pid == *pid && r.holds(table)) {
                seen = true;
                first_t.get_or_insert(smp.t_ms);
                if !row.xid.is_empty() {
                    xids.insert(row.xid.clone());
                }
                if query.is_empty() {
                    query = row.query.clone();
                    app = row.app.clone();
                }
            }
        }
        holders.push(json!({"pid": pid, "seen_in_this_database_holding_lock": seen,
            "backend_xids": xids, "first_sample_ms": first_t, "query": query, "application_name": app}));
    }
    let target_s = target_xid.map(|x| x.to_string());
    let holder_is_target = target_s.as_ref().is_some_and(|t| {
        holders.iter().any(|h| {
            h["backend_xids"]
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x == t))
        })
    });
    let holders_known = holders
        .iter()
        .all(|h| h["seen_in_this_database_holding_lock"] == true && h["backend_xids"].as_array().is_some_and(|a| !a.is_empty()));
    let service_pids: Vec<i32> = target_s
        .as_ref()
        .map(|t| {
            let mut v: BTreeSet<i32> = BTreeSet::new();
            for smp in &samples {
                for r in &smp.rows {
                    if &r.xid == t {
                        v.insert(r.pid);
                    }
                }
            }
            v.into_iter().collect()
        })
        .unwrap_or_default();
    // Was the attacker's LOCK queued while a holder still held a granted RowExclusiveLock?
    let queued_before_commit: Option<bool> = att.lock_granted_ms.map(|g| {
        samples.iter().any(|smp| {
            smp.t_ms < g
                && smp.rows.iter().any(|r| r.pid == att.pid && r.queued_ae(table))
                && smp.rows.iter().any(|r| r.pid != att.pid && r.holds(table))
        })
    });

    // CommandComplete counts: the SET LOCAL, the attack statements, then the trailing
    // `SELECT pg_current_xact_id()` (one row), which is not the attack's.
    // The first sample after the attacker's poll matched in which a backend that held the
    // target xid (the service's connection for this call) WAITS for a lock, and on which
    // table. `LOCK TABLE a, b` takes its tables one after the other: `a` is granted at the
    // target's commit, `b` only when the attacker's backend next runs. A service read of `b`
    // in that gap is not blocked (and sees the state before the attack). If the service's
    // first blocked statement is on `a` (not on the last table of the list), a read of the
    // later tables may have slipped through before they were locked.
    let first_block: Option<(f64, i32, String, String)> = att.match_t_ms.and_then(|m| {
        samples.iter().filter(|smp| smp.t_ms >= m).find_map(|smp| {
            smp.rows
                .iter()
                .find(|r| service_pids.contains(&r.pid) && r.locks.contains(":w"))
                .map(|r| {
                    let rel = r
                        .locks
                        .split(',')
                        .find(|l| l.ends_with(":w"))
                        .and_then(|l| l.split(':').next())
                        .unwrap_or("")
                        .to_owned();
                    (smp.t_ms, r.pid, rel, r.query.clone())
                })
        })
    });
    let last_table = tables.last().copied().unwrap_or("");
    // Evaluated for a list of exactly two tables (the two tests under diagnosis): a single
    // statement reading three tables blocks on the first of them whichever way it went, so
    // a longer list cannot be judged from the blocked table alone (lock_gap_evaluated=false; the
    // verdict is then not affected).
    let lock_gap_suspected: Option<bool> = match tables.len() {
        1 => Some(false),
        2 => first_block.as_ref().map(|b| b.2 != last_table),
        _ => Some(false),
    };
    let attack_rows_total: u64 = att.attack_rows.iter().take(att.attack_rows.len().saturating_sub(1)).sum();
    let (attack_after_target_commit, ordering_method) = match (target_commit_us, attacker_commit_us) {
        (Some(t), Some(a)) => (Some(a > t), "commit_timestamp"),
        _ => (
            // The attacker held ACCESS EXCLUSIVE on a table the target had written, so the
            // holder had ended; with the holder == the target and the target committed,
            // the attacker's commit follows the target's.
            if holder_is_target && target_status == "committed" && att.lock_granted_ms.is_some() {
                Some(true)
            } else {
                None
            },
            "lock_grant_implies",
        ),
    };
    // Client clocks only: the database may run in a VM whose clock differs from the host's
    // (Docker Desktop); on a GitHub-hosted runner the two coincide. The attacker sent COMMIT
    // before the call returned: a necessary condition for landing before the response.
    let before_response = att.commit_start_ms.map(|cs| cs < call_end_ms);

    let (verdict, reason) = if att.commit_done_ms.is_none() || target_xid.is_none() {
        ("unknown", format!("attacker did not finish or the target transaction is unidentified ({target_xid_source})"))
    } else if !holders_known {
        ("unknown", "the matched lock holder was not seen in this database".to_string())
    } else if !holder_is_target {
        (
            "attack_before_target",
            "the poll matched a RowExclusiveLock held by a transaction other than the call's target transaction".to_string(),
        )
    } else if attack_after_target_commit == Some(false) {
        ("attack_before_target", "the attacker committed before the target".to_string())
    } else if attack_after_target_commit.is_none() {
        ("unknown", "commit order not established".to_string())
    } else if attack_rows_total == 0 {
        ("attack_missed", "the attack SQL changed no rows".to_string())
    } else if queued_before_commit == Some(false) {
        ("attack_missed", "the attacker's LOCK was not queued before the target committed (late)".to_string())
    } else if queued_before_commit.is_none() {
        ("unknown", "queue state unknown".to_string())
    } else if before_response == Some(false) {
        (
            "attack_missed",
            if first_block.is_none() {
                "the service answered without ever waiting for the attacker's lock (its post-commit reads ran before the attacker held the tables); the attacker committed after the response".to_string()
            } else {
                "the attacker committed after the service had already answered".to_string()
            },
        )
    } else if lock_gap_suspected.is_none() {
        ("unknown", "the service was never seen waiting for the attacker's lock".to_string())
    } else if lock_gap_suspected == Some(true) {
        (
            "attack_missed",
            format!(
                "LOCK TABLE takes its tables one after the other: the service's first blocked statement was on {} (not the last locked table {last_table}), so its earlier post-commit read of a later table ran before the attacker held it",
                first_block.as_ref().map(|b| b.2.as_str()).unwrap_or("?")
            ),
        )
    } else if before_response.is_none() {
        ("unknown", "response order unknown".to_string())
    } else {
        ("window_ok", "target committed, then the attack changed rows and committed before the response".to_string())
    };

    {
        let mut s = sink.lock().unwrap();
        for smp in &samples {
            s.ev(json!({"ev": "monitor", "call_id": call_id, "test": test, "t_ms": round3(smp.t_ms), "wall_us": smp.wall_us,
                        "backends": smp.rows.iter().map(|r| r.json()).collect::<Vec<_>>()}));
        }
        s.ev(json!({"ev": "attacker", "call_id": call_id, "test": test, "pid": att.pid, "polls": att.poll_n,
            "poll_match_ms": att.match_t_ms.map(round3), "poll_match_wall_us": att.match_wall_us, "matched_pids": att.match_pids,
            "matched_holders": holders, "lock_requested_ms": att.lock_request_ms.map(round3),
            "lock_granted_ms": att.lock_granted_ms.map(round3), "attack_start_ms": att.attack_start_ms.map(round3),
            "attack_done_ms": att.attack_done_ms.map(round3), "attack_rows": att.attack_rows, "attack_rows_total": attack_rows_total,
            "attacker_xid": att.attacker_xid, "commit_start_ms": att.commit_start_ms.map(round3),
            "commit_done_ms": att.commit_done_ms.map(round3), "commit_wall_us": att.commit_wall_us}));
        s.ev(json!({"ev": "call_end", "call_id": call_id, "test": test, "t_ms": round3(call_end_ms), "wall_us": call_end_wall,
            "result": described}));
        s.ev(json!({"ev": "target", "call_id": call_id, "test": test,
            "audit_rows_of_the_call": audit_rows.iter().map(|r| json!({"seq": r.0, "xmin": r.1, "action": r.2, "result": r.3})).collect::<Vec<_>>(),
            "target_xid": target_xid, "target_xid_source": target_xid_source, "monitor_audit_insert_xids": monitor_audit_xids, "target_status": target_status, "attacker_status": attacker_status,
            "target_commit_us": target_commit_us, "attacker_commit_us": attacker_commit_us,
            "service_pids_with_target_xid": service_pids,
            "service_first_block": first_block.as_ref().map(|b| json!({"t_ms": round3(b.0), "pid": b.1, "waiting_on": b.2, "query": b.3})),
            "lock_gap_evaluated": tables.len() == 2, "lock_gap_suspected": lock_gap_suspected}));
        s.ev(json!({"ev": "verdict", "call_id": call_id, "test": test, "verdict": verdict, "reason": reason,
            "holder_is_target_txn": holder_is_target, "attack_after_target_commit": attack_after_target_commit,
            "ordering_method": ordering_method, "queued_before_target_commit": queued_before_commit,
            "attack_committed_before_response": before_response,
            "attack_rows_total": attack_rows_total, "call_end_ms": round3(call_end_ms), "result": described}));
        s.flush();
    }
    if verdict != "window_ok" {
        eprintln!("INCONCLUSIVE: attack did not reach the intended window");
        eprintln!("  verdict={verdict}: {reason}  (test {test}, call {call_id}; result {described})");
        panic!("INCONCLUSIVE: attack did not reach the intended window ({verdict}: {reason})");
    }
    r
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}
