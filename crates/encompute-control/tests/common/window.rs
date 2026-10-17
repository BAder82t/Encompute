//! The adversarial window of the rollback regression tests: one shared
//! implementation (it replaces the copies that lived in `anchor_window`,
//! `anchor_window_adversarial`, `anchor_negatives`, `anchor_genesis` and
//! `anchor_failclosed`).
//!
//! # What is being tested
//!
//! An acknowledged transition must be backed by a state the service verified
//! AFTER its own commit. A database owner who undoes the transition between
//! the commit and that verification must therefore get no acknowledgement. An
//! undo that lands after the verification, even before the HTTP response, is
//! detected by the NEXT request or tick, not prevented (the documented
//! check-to-use limitation). The tests are only meaningful when the undo lands
//! BEFORE the service's post-commit reads, so the helper has to prove that.
//!
//! # Why the old helper was wrong
//!
//! It ran `LOCK TABLE a, b IN ACCESS EXCLUSIVE MODE`. PostgreSQL locks the
//! listed tables one after the other: `a` is granted at the target's commit
//! (the request was queued behind it), but `b` is only requested when the
//! attacker's backend next runs. On a loaded machine the service's post-commit
//! read of `b` could run in that gap, unblocked; the attack then landed after
//! the read (a torn observation) or after the response. The service was right
//! (it acknowledged a state it had verified), the TEST was wrong.
//!
//! # The barrier
//!
//! * A deferred constraint trigger on `audit_events` makes every transaction
//!   that writes an audit event wait, at COMMIT (after all its other
//!   statements, with all its locks held), for a session-level advisory lock
//!   that the helper holds. This is the gate; the pid waiting on it is the
//!   TARGET transaction. (The old trigger slept a fixed second after the
//!   insert: under load the attacker could simply be late.)
//! * One helper session per table, each in its own transaction, issues
//!   `LOCK TABLE <t> IN ACCESS EXCLUSIVE MODE` once the target holds a lock on
//!   `<t>` (it would be granted at once otherwise and stall the target).
//!   The request queues behind the target.
//! * The controller opens the gate only when `pg_blocking_pids(helper)`
//!   contains the target for EVERY helper, i.e. every request is queued.
//! * PostgreSQL grants queued waiters in the lock-release path of the
//!   committing backend (`ProcLockWakeup`), in queue order, and a later
//!   request that conflicts with a queued ACCESS EXCLUSIVE (any AccessShare
//!   read) must queue behind it. So at the target's commit every table is
//!   held by the attacker side before ANY new service statement can obtain
//!   it: no gap in which a post-commit read of any of them can run.
//! * After the grant the controller checks that the target really committed
//!   (`pg_xact_status`), and waits (500 ms at least) until a service backend
//!   is seen waiting on one of the locked tables, then the helpers run the
//!   attack (each part in the session that holds the table it modifies),
//!   every part is executed before any part commits, and then all commit; the
//!   service's blocked statements resume only after the whole attack is
//!   visible.
//! * Anything else (a request not queued in time, the target never reaching
//!   the gate, a service call that returns before the attack committed or is
//!   never seen waiting) panics with `INCONCLUSIVE: attack did not reach the
//!   intended window`. Never a silent pass.
//!
//! Tables the service reads after its commit but the target holds no lock on
//! cannot be queued on. They are covered by ORDER: the service reads
//! sequentially, so once its first post-commit read is blocked every later
//! read happens after the attack. Each call site therefore locks (at least)
//! the table of the service's first post-commit read; the per-test analysis is
//! in the report that came with this file.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use postgres::{Client, NoTls};

/// Advisory-lock key of the gate (two-int form; distinct from the service's
/// own advisory locks).
const GATE_CLASS: i32 = 0x4154_4b31;
const GATE_OBJ: i32 = 0x0057_494e;

const POLL: Duration = Duration::from_millis(2);

pub const INCONCLUSIVE: &str = "INCONCLUSIVE: attack did not reach the intended window";

/// One table the attacker holds, and what runs in the session holding it (empty
/// = lock only; the session still holds the table until the attack is done).
#[derive(Clone, Copy)]
pub struct Part<'a> {
    pub table: &'a str,
    pub sql: &'a str,
}

/// Deliberate faults, for the negative control only.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    None,
    /// The old `LOCK TABLE a, b` behaviour: part `i` requests its lock only
    /// after part `i-1` was granted, i.e. after the target's commit.
    SequentialLocks,
}

#[derive(Clone, Copy)]
pub struct Opts {
    /// Longest wait for every request to be queued behind the target.
    pub barrier_timeout: Duration,
    /// Longest wait for a service statement to be seen waiting on a locked table.
    pub observe_timeout: Duration,
    /// Minimum time the attacker holds the tables before it acts.
    pub hold: Duration,
    /// Run the attack with `session_replication_role = replica` (triggers and
    /// constraints off, as the database owner can).
    pub replica: bool,
    pub fault: Fault,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            barrier_timeout: Duration::from_secs(30),
            observe_timeout: Duration::from_secs(30),
            hold: Duration::from_millis(500),
            replica: true,
            fault: Fault::None,
        }
    }
}

type Res<T> = Result<T, String>;

fn connect(url: &str) -> Client {
    Client::connect(url, NoTls).unwrap()
}

/// State shared by the helper sessions, the controller and the caller.
struct Shared {
    n: usize,
    tables: Vec<String>,
    /// First reason the window was not reached (prefixed INCONCLUSIVE), or
    /// the attack statement's own error.
    failure: Mutex<Option<String>>,
    abort: AtomicBool,
    /// Gate pid each helper queued behind.
    targets: Mutex<Vec<Option<i32>>>,
    granted: Vec<AtomicBool>,
    n_granted: AtomicUsize,
    go: AtomicBool,
    n_executed: AtomicUsize,
    n_committed: AtomicUsize,
    acting_done: AtomicBool,
    acting_returned: Mutex<Option<Instant>>,
    attack_committed: Mutex<Option<Instant>>, // when the first part started to commit,
    /// Tables on which the service was seen waiting: their holders commit
    /// last, so the first blocked read is released only by the final commit.
    last: Mutex<Vec<String>>,
    n_last: AtomicUsize,
    xids: Mutex<Vec<Option<String>>>,
    /// (table, started, finished) of every part's COMMIT.
    commits: Mutex<Vec<(String, Instant, Instant)>>,
    /// Evidence lines, printed when the window is proven.
    proof: Mutex<Vec<String>>,
}

impl Shared {
    fn new(n: usize, tables: Vec<String>) -> Shared {
        Shared {
            n,
            tables,
            failure: Mutex::new(None),
            abort: AtomicBool::new(false),
            targets: Mutex::new(vec![None; n]),
            granted: (0..n).map(|_| AtomicBool::new(false)).collect(),
            n_granted: AtomicUsize::new(0),
            go: AtomicBool::new(false),
            n_executed: AtomicUsize::new(0),
            n_committed: AtomicUsize::new(0),
            acting_done: AtomicBool::new(false),
            acting_returned: Mutex::new(None),
            attack_committed: Mutex::new(None),
            last: Mutex::new(Vec::new()),
            n_last: AtomicUsize::new(0),
            xids: Mutex::new(vec![None; n]),
            commits: Mutex::new(Vec::new()),
            proof: Mutex::new(Vec::new()),
        }
    }
    fn fail(&self, why: String) {
        let mut f = self.failure.lock().unwrap();
        if f.is_none() {
            *f = Some(why);
        }
        self.abort.store(true, Ordering::SeqCst);
    }
    fn inconclusive(&self, why: String) {
        self.fail(format!("{INCONCLUSIVE}: {why}"));
    }
    fn aborted(&self) -> bool {
        self.abort.load(Ordering::SeqCst)
    }
}

fn gate_setup(c: &mut Client) {
    c.batch_execute(&format!(
        "CREATE OR REPLACE FUNCTION atk_gate() RETURNS trigger AS $$
         BEGIN PERFORM pg_advisory_xact_lock_shared({GATE_CLASS}, {GATE_OBJ}); RETURN NULL; END $$ LANGUAGE plpgsql;
         DROP TRIGGER IF EXISTS atk_slow ON audit_events;
         CREATE CONSTRAINT TRIGGER atk_slow AFTER INSERT ON audit_events
           DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION atk_gate();
         SELECT pg_advisory_lock({GATE_CLASS}, {GATE_OBJ});"
    ))
    .unwrap();
}

fn gate_open(c: &mut Client) -> Res<()> {
    c.batch_execute(&format!(
        "SELECT pg_advisory_unlock({GATE_CLASS}, {GATE_OBJ})"
    ))
    .map_err(|e| format!("gate release failed: {e}"))
}

/// Pid of a backend that waits on the gate and holds a lock on `table`.
fn target_holding(c: &mut Client, table: &str) -> Res<Option<i32>> {
    let rows = c
        .query(
            &format!(
                "SELECT g.pid FROM pg_locks g
                   JOIN pg_locks r ON r.pid = g.pid AND r.locktype = 'relation' AND r.granted
                   JOIN pg_class k ON k.oid = r.relation
                  WHERE g.locktype = 'advisory' AND g.classid = {GATE_CLASS}::oid
                    AND g.objid = {GATE_OBJ}::oid AND g.objsubid = 2 AND NOT g.granted
                    AND k.relname = $1
                  LIMIT 1"
            ),
            &[&table],
        )
        .map_err(|e| format!("target lookup failed: {e}"))?;
    Ok(rows.first().map(|r| r.get::<_, i32>(0)))
}

fn helper(
    idx: usize,
    part: Part<'_>,
    mut a: Client,
    sh: &Shared,
    opts: &Opts,
    deadline: Instant,
) -> Res<()> {
    // 1. wait until the target (a backend parked at the commit gate) holds a
    //    lock on the table, then queue behind it
    let target = loop {
        if sh.aborted() {
            return Ok(());
        }
        if let Some(p) = target_holding(&mut a, part.table)? {
            break p;
        }
        if sh.acting_done.load(Ordering::SeqCst) {
            sh.inconclusive(format!(
                "the call returned without parking at its commit holding a lock on {}",
                part.table
            ));
            return Ok(());
        }
        if Instant::now() > deadline {
            sh.inconclusive(format!(
                "no transaction parked at its commit holding a lock on {} within {:?}",
                part.table, opts.barrier_timeout
            ));
            return Ok(());
        }
        std::thread::sleep(POLL);
    };
    sh.targets.lock().unwrap()[idx] = Some(target);
    if opts.fault == Fault::SequentialLocks && idx > 0 {
        // the old LOCK a, b: b is requested only after a was granted
        while !sh.granted[idx - 1].load(Ordering::SeqCst) {
            if sh.aborted() {
                return Ok(());
            }
            std::thread::sleep(POLL);
        }
    }
    let mut tx = a.transaction().map_err(|e| e.to_string())?;
    // blocks until the target has committed (the request queues behind it)
    tx.batch_execute(&format!(
        "LOCK TABLE {} IN ACCESS EXCLUSIVE MODE",
        part.table
    ))
    .map_err(|e| format!("LOCK {} failed: {e}", part.table))?;
    let xid: String = tx
        .query_one("SELECT pg_current_xact_id()::text", &[])
        .map_err(|e| e.to_string())?
        .get(0);
    sh.xids.lock().unwrap()[idx] = Some(xid);
    sh.granted[idx].store(true, Ordering::SeqCst);
    sh.n_granted.fetch_add(1, Ordering::SeqCst);
    // 2. every table must be held before anyone acts
    while sh.n_granted.load(Ordering::SeqCst) < sh.n || !sh.go.load(Ordering::SeqCst) {
        if sh.aborted() {
            let _ = tx.rollback();
            return Ok(());
        }
        std::thread::sleep(POLL);
    }
    // 3. the attack part, in the session that holds the table
    if !part.sql.is_empty() {
        let role = if opts.replica {
            "SET LOCAL session_replication_role = replica; "
        } else {
            ""
        };
        if let Err(e) = tx.batch_execute(&format!(
            "SET LOCAL lock_timeout = '20s'; {role}{}",
            part.sql
        )) {
            sh.fail(format!(
                "the attack statement on {} failed: {e}",
                part.table
            ));
            let _ = tx.rollback();
            return Ok(());
        }
    }
    sh.n_executed.fetch_add(1, Ordering::SeqCst);
    // 4. no part commits before every part ran
    while sh.n_executed.load(Ordering::SeqCst) < sh.n {
        if sh.aborted() {
            let _ = tx.rollback();
            return Ok(());
        }
        std::thread::sleep(POLL);
    }
    // The parts whose table the service was seen waiting on commit LAST,
    // after every other part has committed (verified from pg_xact_status), so
    // the blocked read is released only when the complete mutation is
    // committed.
    let is_last = sh.last.lock().unwrap().iter().any(|t| t == part.table);
    if is_last {
        let others = sh.n - sh.n_last.load(Ordering::SeqCst);
        while sh.n_committed.load(Ordering::SeqCst) < others {
            if sh.aborted() {
                let _ = tx.rollback();
                return Ok(());
            }
            std::thread::sleep(POLL);
        }
        let xids: Vec<Option<String>> = sh.xids.lock().unwrap().clone();
        for (i, x) in xids.iter().enumerate() {
            let other_last = sh.last.lock().unwrap().iter().any(|t| t == &sh.tables[i]);
            if i == idx || other_last {
                continue;
            }
            let st: Option<String> = tx
                .query_one("SELECT pg_xact_status($1::text::xid8)", &[x])
                .map_err(|e| e.to_string())?
                .get(0);
            if st.as_deref() != Some("committed") {
                sh.fail(format!(
                    "{INCONCLUSIVE}: part {} is {st:?}, not committed, when the last parts commit",
                    sh.tables[i]
                ));
                let _ = tx.rollback();
                return Ok(());
            }
        }
    }
    // the first commit starts here: before it no blocked read of a locked
    // table can resume
    let started = Instant::now();
    sh.attack_committed.lock().unwrap().get_or_insert(started);
    tx.commit().map_err(|e| e.to_string())?;
    sh.commits
        .lock()
        .unwrap()
        .push((part.table.to_owned(), started, Instant::now()));
    sh.n_committed.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

/// Waits for the barrier, opens the gate, checks the target committed, holds,
/// waits for a service statement to be blocked, and lets the helpers act.
fn controller(
    c: &mut Client,
    parts: &[Part<'_>],
    helper_pids: &[i32],
    sh: &Shared,
    opts: &Opts,
    hook: Option<&(dyn Fn() + Sync)>,
) -> Res<()> {
    let me: i32 = c
        .query_one("SELECT pg_backend_pid()", &[])
        .map_err(|e| e.to_string())?
        .get(0);
    let deadline = Instant::now() + opts.barrier_timeout;
    // every request queued behind its target
    let targets: Vec<i32>;
    let mut not_queued: Vec<&str> = parts.iter().map(|p| p.table).collect();
    loop {
        if sh.aborted() {
            return Ok(());
        }
        let t = sh.targets.lock().unwrap().clone();
        if t.iter().all(|x| x.is_some()) {
            let rows = c
                .query(
                    "SELECT pid, pg_blocking_pids(pid) FROM pg_stat_activity WHERE pid = ANY($1)",
                    &[&helper_pids.to_vec()],
                )
                .map_err(|e| e.to_string())?;
            let is_queued = |i: usize| {
                let want = t[i].unwrap();
                rows.iter().any(|r| {
                    r.get::<_, i32>(0) == helper_pids[i] && r.get::<_, Vec<i32>>(1).contains(&want)
                })
            };
            not_queued = (0..parts.len())
                .filter(|i| !is_queued(*i))
                .map(|i| parts[i].table)
                .collect();
            if not_queued.is_empty() {
                // (a) the lock manager itself shows each request waiting
                let rows = c
                    .query(
                        "SELECT l.pid, k.relname FROM pg_locks l JOIN pg_class k ON k.oid = l.relation
                          WHERE l.locktype = 'relation' AND l.mode = 'AccessExclusiveLock'
                            AND NOT l.granted AND l.pid = ANY($1)",
                        &[&helper_pids.to_vec()],
                    )
                    .map_err(|e| e.to_string())?;
                let all_waiting = (0..parts.len()).all(|i| {
                    rows.iter().any(|r| {
                        r.get::<_, i32>(0) == helper_pids[i]
                            && r.get::<_, String>(1) == parts[i].table
                    })
                });
                if all_waiting {
                    targets = t.into_iter().flatten().collect();
                    break;
                }
            }
        }
        if Instant::now() > deadline {
            sh.inconclusive(format!(
                "not every lock request was queued behind the target before it committed \
                 (still unqueued: {not_queued:?}) after {:?}",
                opts.barrier_timeout
            ));
            return Ok(());
        }
        std::thread::sleep(POLL);
    }
    let mut xids: Vec<(i32, String)> = Vec::new();
    for p in &targets {
        if let Some(r) = c
            .query_opt(
                "SELECT backend_xid::text FROM pg_stat_activity WHERE pid = $1",
                &[p],
            )
            .map_err(|e| e.to_string())?
        {
            if let Some(x) = r.get::<_, Option<String>>(0) {
                xids.push((*p, x));
            }
        }
    }
    // the gate opens: the target commits, its locks pass to the queued requests
    gate_open(c)?;
    let deadline = Instant::now() + opts.barrier_timeout;
    while sh.n_granted.load(Ordering::SeqCst) < sh.n {
        if sh.aborted() {
            return Ok(());
        }
        if Instant::now() > deadline {
            sh.inconclusive(
                "the attacker's locks were not all granted after the gate opened".into(),
            );
            return Ok(());
        }
        std::thread::sleep(POLL);
    }
    let granted_at = Instant::now();
    // (b1) every attacker lock is granted, in the lock manager's own view
    let rows = c
        .query(
            "SELECT l.pid, k.relname FROM pg_locks l JOIN pg_class k ON k.oid = l.relation
              WHERE l.locktype = 'relation' AND l.mode = 'AccessExclusiveLock'
                AND l.granted AND l.pid = ANY($1)",
            &[&helper_pids.to_vec()],
        )
        .map_err(|e| e.to_string())?;
    for (i, p) in parts.iter().enumerate() {
        if !rows
            .iter()
            .any(|r| r.get::<_, i32>(0) == helper_pids[i] && r.get::<_, String>(1) == p.table)
        {
            sh.inconclusive(format!(
                "the attacker does not hold {} (pg_locks) after the target committed",
                p.table
            ));
            return Ok(());
        }
    }
    for (pid, x) in &xids {
        let st: Option<String> = c
            .query_one("SELECT pg_xact_status($1::text::xid8)", &[x])
            .map_err(|e| e.to_string())?
            .get(0);
        if st.as_deref() != Some("committed") {
            sh.inconclusive(format!(
                "the target (pid {pid}, xid {x}) is {st:?}, not committed, when the locks were granted"
            ));
            return Ok(());
        }
    }
    // hold, and wait until a service statement is seen waiting on a locked table
    let tables: Vec<String> = parts.iter().map(|p| p.table.to_owned()).collect();
    let mut excluded: Vec<i32> = helper_pids.to_vec();
    excluded.push(me);
    let observe_deadline = Instant::now() + opts.observe_timeout;
    loop {
        if sh.aborted() {
            return Ok(());
        }
        let held = granted_at.elapsed() >= opts.hold;
        // (b2) a service backend is waiting (wait_event_type = 'Lock') on a
        // table the attacker holds
        let waiting = c
            .query(
                "SELECT l.pid, k.relname, left(a.query, 70) FROM pg_locks l
                   JOIN pg_class k ON k.oid = l.relation
                   JOIN pg_stat_activity a ON a.pid = l.pid
                  WHERE l.locktype = 'relation' AND NOT l.granted AND a.wait_event_type = 'Lock'
                    AND k.relname = ANY($1) AND l.pid <> ALL($2)",
                &[&tables, &excluded],
            )
            .map_err(|e| e.to_string())?;
        if held && !waiting.is_empty() {
            let mut rels: Vec<String> = waiting.iter().map(|r| r.get::<_, String>(1)).collect();
            rels.sort();
            rels.dedup();
            sh.n_last.store(
                parts
                    .iter()
                    .filter(|p| rels.iter().any(|r| r == p.table))
                    .count(),
                Ordering::SeqCst,
            );
            *sh.last.lock().unwrap() = rels;
            sh.proof.lock().unwrap().push(format!(
                "queued={:?} behind target pids {:?}; granted all; service waiting: {:?}",
                tables,
                targets,
                waiting
                    .iter()
                    .map(|r| format!(
                        "pid {} on {} ({})",
                        r.get::<_, i32>(0),
                        r.get::<_, String>(1),
                        r.get::<_, String>(2)
                    ))
                    .collect::<Vec<_>>()
            ));
            break;
        }
        if sh.acting_done.load(Ordering::SeqCst) {
            sh.inconclusive(
                "the service call returned before any of its statements was seen waiting behind the \
                 attacker's locks (its post-commit reads are not behind them)"
                    .into(),
            );
            return Ok(());
        }
        if Instant::now() > observe_deadline {
            sh.inconclusive(format!(
                "no service statement was seen waiting on {tables:?} within {:?}",
                opts.observe_timeout
            ));
            return Ok(());
        }
        std::thread::sleep(POLL);
    }
    if let Some(h) = hook {
        h();
    }
    sh.go.store(true, Ordering::SeqCst);
    Ok(())
}

/// Runs `acting` (the service call) inside the window described in the module
/// docs: `parts[i].table` is locked ACCESS EXCLUSIVE by its own session, queued
/// behind the call's transaction before the call commits, and
/// `parts[i].sql` is executed by that session before any part commits.
/// Panics with `INCONCLUSIVE: attack did not reach the intended window ...`
/// when that cannot be shown.
pub fn in_window_with<R: Send>(
    url: &str,
    parts: &[Part<'_>],
    opts: &Opts,
    acting: impl FnOnce() -> R + Send,
) -> R {
    in_window_hooked(url, parts, opts, None, acting)
}

/// [`in_window_with`] that calls `hook` once the window is proven (the attacker
/// holds every table and the service is seen waiting) and just before the
/// attack is applied: for tests that need something concurrent to start only
/// then (it cannot be taken for the call's own statements).
pub fn in_window_hooked<R: Send>(
    url: &str,
    parts: &[Part<'_>],
    opts: &Opts,
    hook: Option<&(dyn Fn() + Sync)>,
    acting: impl FnOnce() -> R + Send,
) -> R {
    assert!(!parts.is_empty());
    let mut c = connect(url);
    gate_setup(&mut c);
    let mut helpers: Vec<(Client, i32)> = parts
        .iter()
        .map(|_| {
            let mut h = connect(url);
            let pid: i32 = h.query_one("SELECT pg_backend_pid()", &[]).unwrap().get(0);
            (h, pid)
        })
        .collect();
    let helper_pids: Vec<i32> = helpers.iter().map(|h| h.1).collect();
    let sh = Shared::new(
        parts.len(),
        parts.iter().map(|p| p.table.to_owned()).collect(),
    );
    let shr = &sh;
    let deadline = Instant::now() + opts.barrier_timeout;
    let r = std::thread::scope(|s| {
        let mut hs = Vec::new();
        for (i, (part, (client, _))) in parts.iter().zip(helpers.drain(..)).enumerate() {
            let part = *part;
            hs.push(s.spawn(move || {
                if let Err(e) = helper(i, part, client, shr, opts, deadline) {
                    shr.fail(format!("helper for {} failed: {e}", part.table));
                }
            }));
        }
        let hp = &helper_pids;
        let ctl = s.spawn(move || {
            let res = controller(&mut c, parts, hp, shr, opts, hook);
            if let Err(e) = res {
                shr.fail(format!("controller failed: {e}"));
            }
            // always open the gate, so a parked target can finish
            let _ = gate_open(&mut c);
            c
        });
        let r = acting();
        *sh.acting_returned.lock().unwrap() = Some(Instant::now());
        sh.acting_done.store(true, Ordering::SeqCst);
        for h in hs {
            h.join().unwrap();
        }
        let mut c = ctl.join().unwrap();
        c.batch_execute("DROP TRIGGER IF EXISTS atk_slow ON audit_events")
            .unwrap();
        r
    });
    if let Some(f) = sh.failure.lock().unwrap().take() {
        panic!("{f}");
    }
    let committed = *sh.attack_committed.lock().unwrap();
    let returned = sh.acting_returned.lock().unwrap().unwrap();
    match committed {
        Some(t) if t <= returned => {}
        Some(_) => panic!(
            "{INCONCLUSIVE}: the service answered before the attack started to commit (its post-commit reads were not behind the attacker's locks)"
        ),
        None => panic!("{INCONCLUSIVE}: the attack never committed"),
    }
    // (c) the last commit (the part(s) the service waited on) is not before any other
    let commits = sh.commits.lock().unwrap().clone();
    let last = sh.last.lock().unwrap().clone();
    for (t, started, _) in commits.iter().filter(|(t, _, _)| last.contains(t)) {
        for (o, _, finished) in commits.iter().filter(|(o, _, _)| !last.contains(o)) {
            assert!(
                finished <= started,
                "{INCONCLUSIVE}: part {o} committed after {t}, which the service waited on"
            );
        }
    }
    eprintln!(
        "WINDOW-PROOF {} commit order {:?}",
        sh.proof.lock().unwrap().join(" | "),
        {
            let mut c = commits.clone();
            c.sort_by_key(|x| x.1);
            c.into_iter().map(|x| x.0).collect::<Vec<_>>()
        }
    );
    r
}

/// The common case: `tables[0]` is attacked (`attack_sql` runs in the session
/// that holds it, with triggers and constraints off); the other tables are
/// only held, because the service reads them after its commit. `attack_sql`
/// must not touch the other listed tables.
pub fn in_window<R: Send>(
    url: &str,
    tables: &[&str],
    attack_sql: &str,
    acting: impl FnOnce() -> R + Send,
) -> R {
    in_window_as(url, tables, attack_sql, true, acting)
}

/// [`in_window`] with the attack run as the ordinary role (`replica == false`).
pub fn in_window_as<R: Send>(
    url: &str,
    tables: &[&str],
    attack_sql: &str,
    replica: bool,
    acting: impl FnOnce() -> R + Send,
) -> R {
    let parts: Vec<Part> = tables
        .iter()
        .enumerate()
        .map(|(i, t)| Part {
            table: t,
            sql: if i == 0 { attack_sql } else { "" },
        })
        .collect();
    let opts = Opts {
        replica,
        ..Opts::default()
    };
    in_window_with(url, &parts, &opts, acting)
}

/// A multi-table attack, split by the table each statement modifies.
pub fn in_window_parts<R: Send>(
    url: &str,
    parts: &[(&str, &str)],
    acting: impl FnOnce() -> R + Send,
) -> R {
    let parts: Vec<Part> = parts
        .iter()
        .map(|(t, q)| Part { table: t, sql: q })
        .collect();
    in_window_with(url, &parts, &Opts::default(), acting)
}

fn wait_blocked_on(c: &mut Client, table: &str, sh: &Shared) -> bool {
    for _ in 0..4000 {
        if sh.aborted() {
            return false;
        }
        let n: i64 = c
            .query_one(
                "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
                 WHERE c.relname=$1 AND NOT l.granted AND l.pid<>pg_backend_pid()",
                &[&table],
            )
            .unwrap()
            .get(0);
        if n > 0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    sh.inconclusive(format!("the window did not open on {table}"));
    false
}

/// Like [`in_window`] for a call that writes nothing (the duplicate answer),
/// so no insert of its own opens the window. One session holds
/// `privacy_entries`, so the call stalls inside its transaction after it
/// locked the ledger row; a second queues ACCESS EXCLUSIVE on
/// `privacy_ledgers` behind that row lock (the table of the service's first
/// post-commit read), runs `attack_sql` once the call has committed, and only
/// then lets the call's post-commit read proceed. The hold is committed only
/// when the attacker's request is queued; otherwise INCONCLUSIVE.
pub fn in_window_readonly<R: Send>(
    url: &str,
    attack_sql: &str,
    replica: bool,
    acting: impl FnOnce() -> R + Send,
) -> R {
    let mut hold = connect(url);
    hold.batch_execute("BEGIN; LOCK TABLE privacy_entries IN ACCESS EXCLUSIVE MODE")
        .unwrap();
    let sh = Shared::new(1, vec!["privacy_ledgers".into()]);
    let shr = &sh;
    let r = std::thread::scope(|s| {
        let attacker = s.spawn(move || {
            let mut a = connect(url);
            if !wait_blocked_on(&mut a, "privacy_entries", shr) {
                return;
            }
            let mut tx = a.transaction().unwrap();
            // granted once the call has committed
            if let Err(e) = tx.batch_execute("LOCK TABLE privacy_ledgers IN ACCESS EXCLUSIVE MODE")
            {
                shr.fail(format!("LOCK privacy_ledgers failed: {e}"));
                return;
            }
            // hold, until the service's post-commit read is seen waiting on the ledgers
            let t0 = Instant::now();
            loop {
                let n: i64 = tx
                    .query_one(
                        "SELECT count(*) FROM pg_locks l JOIN pg_class k ON k.oid = l.relation
                           JOIN pg_stat_activity x ON x.pid = l.pid
                          WHERE k.relname = 'privacy_ledgers' AND NOT l.granted
                            AND x.wait_event_type = 'Lock' AND l.pid <> pg_backend_pid()",
                        &[],
                    )
                    .unwrap()
                    .get(0);
                if n > 0 && t0.elapsed() >= Duration::from_millis(500) {
                    break;
                }
                if shr.acting_done.load(Ordering::SeqCst) || t0.elapsed() > Duration::from_secs(30)
                {
                    shr.inconclusive(
                        "the service's post-commit read was not seen waiting behind the attacker"
                            .into(),
                    );
                    return;
                }
                std::thread::sleep(POLL);
            }
            let role = if replica {
                "SET LOCAL session_replication_role = replica; "
            } else {
                ""
            };
            if let Err(e) = tx.batch_execute(&format!("{role}{attack_sql}")) {
                shr.fail(format!("the attack statement failed: {e}"));
                return;
            }
            shr.attack_committed
                .lock()
                .unwrap()
                .get_or_insert(Instant::now());
            tx.commit().unwrap();
        });
        let releaser = s.spawn(move || {
            let mut w = connect(url);
            // the call is inside its transaction, and the attacker is queued behind it
            if wait_blocked_on(&mut w, "privacy_entries", shr)
                && wait_blocked_on(&mut w, "privacy_ledgers", shr)
            {
                hold.batch_execute("COMMIT").unwrap();
            }
            // otherwise the hold is dropped with its connection
        });
        let r = acting();
        *sh.acting_returned.lock().unwrap() = Some(Instant::now());
        sh.acting_done.store(true, Ordering::SeqCst);
        attacker.join().unwrap();
        releaser.join().unwrap();
        r
    });
    if let Some(f) = sh.failure.lock().unwrap().take() {
        panic!("{f}");
    }
    let committed = *sh.attack_committed.lock().unwrap();
    let returned = sh.acting_returned.lock().unwrap().unwrap();
    match committed {
        Some(t) if t <= returned => {}
        Some(_) => {
            panic!("{INCONCLUSIVE}: the service answered before the attack started to commit")
        }
        None => panic!("{INCONCLUSIVE}: the attack never committed"),
    }
    r
}
