//! Restarts and crashes: the control plane dropped and reopened at random
//! points of a job's lifecycle, its PostgreSQL connections terminated
//! mid-transaction (`pg_terminate_backend`) under concurrent privacy
//! spending and job submission, the real `encompute-control` process
//! SIGKILLed repeatedly under load, and an evaluator that restarts while
//! running a job.
//!
//! After each: recovery is safe (the control plane starts; no false
//! rollback), no privacy event is spent twice, no job is created or
//! executed twice, nothing acknowledged is lost, and no job is left stuck.
//!
//! Bounded by default (well under a minute); a soak raises the iteration
//! counts with `ENCOMPUTE_RESTART_ITERATIONS` (a multiplier, e.g. 20), and
//! `ENCOMPUTE_RESTART_SEED` replays a run (the seed is printed).

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use serde_json::{json, Value};

use encompute_control::transport::{seal, Scope};
use encompute_evaluator::{compile_program, execution_spec, transcript_for, Ids};
use encompute_privacy::PrivacyEvent;
use encompute_verification::http::Limits;
use encompute_verification::{output_commitment, request_commitment, ExecutionReceipt};

const KEY_ID: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

/// The soak multiplier (1 by default).
fn scale() -> usize {
    std::env::var("ENCOMPUTE_RESTART_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1)
}

/// A small deterministic PRNG (xorshift), seeded per test and printed.
struct Rng(u64);

impl Rng {
    fn new(test: &str) -> Self {
        let seed = std::env::var("ENCOMPUTE_RESTART_SEED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64
            })
            | 1;
        eprintln!("{test}: ENCOMPUTE_RESTART_SEED={seed}");
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Reopens the control plane of `w` (same database, anchor and key).
fn restart_world(w: World) -> World {
    let World {
        t,
        platform,
        a_admin,
        a_owner,
        a_dev,
        a_auditor,
        b_admin,
        b_owner,
        b_dev,
        b_auditor,
        c_admin,
        c_dev,
        b_sec,
        b_sec2,
        project,
        dataset_a,
        model_b,
        evaluator,
    } = w;
    World {
        t: t.restart().expect("the control plane restarts"),
        platform,
        a_admin,
        a_owner,
        a_dev,
        a_auditor,
        b_admin,
        b_owner,
        b_dev,
        b_auditor,
        c_admin,
        c_dev,
        b_sec,
        b_sec2,
        project,
        dataset_a,
        model_b,
        evaluator,
    }
}

fn db_name(url: &str) -> String {
    url.rsplit('/').next().unwrap().to_owned()
}

/// Terminates every connection to `url`'s database (the admin's own
/// excepted): each open transaction is aborted mid-flight.
fn terminate_backends(url: &str) -> u64 {
    let admin = std::env::var("ENCOMPUTE_TEST_DATABASE_URL").unwrap();
    let mut c = postgres::Client::connect(&admin, postgres::NoTls).unwrap();
    c.query(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
          WHERE datname = $1 AND pid <> pg_backend_pid()",
        &[&db_name(url)],
    )
    .unwrap()
    .len() as u64
}

fn receipt(e: &Evaluator, request: &[u8], response: &[u8]) -> Value {
    let p = encompute_ir::parse(EXACT).unwrap();
    let c = compile_program(&p).unwrap();
    let spec = execution_spec(&Ids::of(&p, &c), &c, c.target_backend());
    let th = transcript_for(&c, &spec).map(|t| t.id().hex());
    let r = ExecutionReceipt::new(
        &spec,
        th.as_deref(),
        KEY_ID,
        request,
        response,
        &e.receipt.identity(),
    )
    .unwrap()
    .sign(&e.receipt)
    .unwrap();
    serde_json::to_value(r).unwrap()
}

fn count(w: &World, sql: &str, arg: &str) -> i64 {
    w.t.control
        .db
        .conn()
        .unwrap()
        .query_one(sql, &[&arg])
        .unwrap()
        .get(0)
}

/// Every job ends in a terminal state or in the one it legitimately waits
/// in, and its recorded transitions are a legal path without repeats.
fn assert_transitions_legal(w: &World, job: &str) {
    let mut c = w.t.control.db.conn().unwrap();
    let rows = c
        .query(
            "SELECT from_state, to_state FROM job_transitions WHERE job_id = $1 ORDER BY seq",
            &[&job],
        )
        .unwrap();
    let mut seen = BTreeSet::new();
    let mut state = "created".to_owned();
    for r in rows {
        let (from, to): (String, String) = (r.get(0), r.get(1));
        assert_eq!(from, state, "{job}: transitions out of order");
        assert!(seen.insert(to.clone()), "{job}: entered {to} twice");
        state = to;
    }
}

/// Crashes the control plane (drop and reopen; sometimes also killing its
/// database connections first) after a random step of a job's lifecycle,
/// then redoes every step as a client and an evaluator would (their
/// retries): each ends exactly once.
#[test]
fn crashes_at_every_job_step_recover_without_duplicates() {
    let Some(mut w) = world() else { return };
    let mut rng = Rng::new("crashes_at_every_job_step");
    let plan = w.plan(EXACT);
    let (req, resp) = (b"request bytes".to_vec(), b"response bytes".to_vec());
    let iterations = 5 * scale();
    for i in 0..iterations {
        let key = format!("crash-{i}");
        let crash_after = rng.below(5); // 0: before submitting, …, 4: after completing
        let r = receipt(&w.evaluator, &req, &resp);
        let mut job = None::<String>;
        // The messages an evaluator would retry are built once.
        let mut msg = None::<Value>;
        let steps = |w: &World, job: &mut Option<String>, msg: &mut Option<Value>, upto: u64| {
            for step in 0..upto {
                match step {
                    0 => {
                        let (s, v) = w.job(&plan, &[], &key);
                        assert!(s == 200 || s == 201, "submit: {s} {v}");
                        let id = v["id"].as_str().unwrap().to_owned();
                        if let Some(prev) = job.as_ref() {
                            assert_eq!(prev, &id, "a retried submission made a second job");
                        }
                        *job = Some(id);
                    }
                    1 => {
                        let id = job.as_ref().unwrap();
                        let (s, v) = w.t.call(
                            &w.evaluator.service,
                            "POST",
                            &format!("/v1/jobs/{id}/start"),
                            None,
                        );
                        // Started now, or (retried) already started: 409.
                        assert!(s == 200 || s == 409, "start: {s} {v}");
                    }
                    2 => {
                        let id = job.as_ref().unwrap();
                        let m = msg.get_or_insert_with(|| {
                            serde_json::to_value(
                                seal(
                                    &w.evaluator.signer,
                                    "job.completed",
                                    "control-plane",
                                    Scope {
                                        job: Some(id.clone()),
                                        ..Scope::default()
                                    },
                                    &json!({"receipt": r, "evaluation_ms": 10}),
                                    300,
                                )
                                .unwrap(),
                            )
                            .unwrap()
                        });
                        w.t.ok(
                            &w.evaluator.service,
                            "POST",
                            "/v1/messages",
                            Some(m.clone()),
                        );
                    }
                    _ => {
                        let id = job.as_ref().unwrap();
                        let v = w.t.ok(
                            &w.b_dev,
                            "POST",
                            &format!("/v1/jobs/{id}/complete"),
                            Some(json!({"receipt": r,
                                "request_commitment": request_commitment(&req),
                                "output_commitment": output_commitment(&resp), "key_id": KEY_ID})),
                        );
                        assert_eq!(v["state"], "succeeded", "{v}");
                    }
                }
            }
        };
        steps(&w, &mut job, &mut msg, crash_after);
        if rng.below(2) == 0 {
            terminate_backends(&w.t.env0.url);
        }
        w = restart_world(w);
        steps(&w, &mut job, &mut msg, 4);
        let id = job.unwrap();
        let v = w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{id}"), None);
        assert_eq!(
            v["state"], "succeeded",
            "crash after step {crash_after}: {v}"
        );
        assert_eq!(
            count(
                &w,
                "SELECT count(*) FROM jobs WHERE idempotency_key = $1",
                &key
            ),
            1
        );
        for action in [
            "job.created",
            "job.started",
            "job.executed",
            "job.succeeded",
        ] {
            let n: i64 =
                w.t.control
                    .db
                    .conn()
                    .unwrap()
                    .query_one(
                        "SELECT count(*) FROM audit_events WHERE resource_id = $1 AND action = $2",
                        &[&id, &action],
                    )
                    .unwrap()
                    .get(0);
            assert_eq!(
                n, 1,
                "{action} of {id} recorded {n} times (crash after {crash_after})"
            );
        }
        assert_transitions_legal(&w, &id);
    }
    let mut c = w.t.control.db.conn().unwrap();
    encompute_control::audit::verify_chain(&mut *c).unwrap();
}

/// What the spenders saw acknowledged.
#[derive(Default)]
struct Acked {
    reserves: BTreeSet<String>,
    commits: BTreeSet<String>,
    jobs: BTreeMap<String, String>,
}

fn commit(event: &str) -> Value {
    serde_json::to_value(PrivacyEvent::Commit {
        event_id: event.into(),
        output_commitment: "c".repeat(64),
    })
    .unwrap()
}

/// Retries `f` until it returns a 2xx (a transport error or a 5xx is
/// retried: the request may or may not have been applied). Returns the
/// final body.
fn until_ok(what: &str, mut f: impl FnMut() -> Result<(u16, Value), String>) -> Value {
    let started = Instant::now();
    loop {
        match f() {
            Ok((s, v)) if (200..300).contains(&s) => return v,
            Ok((s, v)) if s < 500 && s != 408 && s != 429 => panic!("{what}: {s} {v}"),
            _ => {}
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "{what}: never succeeded"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Checks the ledger and jobs against what was acknowledged.
fn verify_no_loss_no_duplicates(w: &World, acked: &Acked, plan_jobs: usize) {
    let d = &w.dataset_a;
    let mut c = w.t.control.db.conn().unwrap();
    let view = encompute_control::control::load_ledger(&mut *c, d)
        .unwrap()
        .expect("ledger");
    view.verify().expect("the ledger verifies");
    let mut reserves = BTreeSet::new();
    let mut commits = BTreeSet::new();
    for e in &view.entries {
        let fresh = match &e.event {
            PrivacyEvent::Reserve { event_id, .. } => reserves.insert(event_id.clone()),
            PrivacyEvent::Commit { event_id, .. } => commits.insert(event_id.clone()),
        };
        assert!(fresh, "event {} recorded twice", e.event.event_id());
    }
    // Nothing acknowledged is missing (and nothing else was spent: every
    // spender retried until acknowledged).
    assert_eq!(reserves, acked.reserves, "reservations");
    assert_eq!(commits, acked.commits, "commits");
    // Each spend audited exactly once.
    for (action, n) in [
        ("privacy.spent", acked.reserves.len()),
        ("privacy.committed", acked.commits.len()),
    ] {
        let got: i64 = c
            .query_one(
                "SELECT count(*) FROM audit_events WHERE resource_id = $1 AND action = $2",
                &[d, &action],
            )
            .unwrap()
            .get(0);
        assert_eq!(got as usize, n, "{action}");
    }
    // One job per idempotency key, the one acknowledged.
    assert_eq!(acked.jobs.len(), plan_jobs);
    for (key, id) in &acked.jobs {
        let rows = c
            .query("SELECT id FROM jobs WHERE idempotency_key = $1", &[key])
            .unwrap();
        assert_eq!(rows.len(), 1, "{key}");
        assert_eq!(&rows[0].get::<_, String>(0), id);
    }
    encompute_control::audit::verify_chain(&mut *c).unwrap();
}

/// Four spenders reserve and commit privacy budget, and submit jobs, while
/// a fifth thread terminates the control plane's database connections at
/// random moments (so transactions die mid-flight, commits included).
#[test]
fn connection_loss_mid_transaction_neither_loses_nor_duplicates() {
    let Some(w) = world() else { return };
    let mut rng = Rng::new("connection_loss");
    let plan = w.plan(EXACT);
    let w = Arc::new(w);
    let acked = Arc::new(Mutex::new(Acked::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let url = w.t.env0.url.clone();
    let killer = {
        let (stop, mut rng) = (stop.clone(), Rng(rng.next() | 1));
        std::thread::spawn(move || {
            let mut killed = 0;
            while !stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20 + rng.below(200)));
                killed += terminate_backends(&url);
            }
            killed
        })
    };
    let per = 12 * scale();
    let workers: Vec<_> = (0..4)
        .map(|n| {
            let (w, acked, plan) = (w.clone(), acked.clone(), plan.clone());
            std::thread::spawn(move || {
                for j in 0..per {
                    let e = format!("e-{n}-{j}");
                    let url = format!("/v1/privacy/{}/events", w.dataset_a);
                    until_ok(&e, || {
                        Ok(w.t.call(&w.a_owner, "POST", &url, Some(reserve(&e, 1_000_000))))
                    });
                    acked.lock().unwrap().reserves.insert(e.clone());
                    until_ok(&e, || {
                        Ok(w.t.call(&w.a_owner, "POST", &url, Some(commit(&e))))
                    });
                    acked.lock().unwrap().commits.insert(e.clone());
                    if j % 4 == 0 {
                        let key = format!("job-{n}-{j}");
                        let v = until_ok(&key, || Ok(w.job(&plan, &[], &key)));
                        acked
                            .lock()
                            .unwrap()
                            .jobs
                            .insert(key, v["id"].as_str().unwrap().to_owned());
                    }
                }
            })
        })
        .collect();
    for h in workers {
        h.join().unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    let killed = killer.join().unwrap();
    assert!(killed > 0, "no connection was terminated");
    let w = Arc::try_unwrap(w).ok().expect("workers are done");
    let acked = Arc::try_unwrap(acked).ok().unwrap().into_inner().unwrap();
    verify_no_loss_no_duplicates(&w, &acked, 4 * per.div_ceil(4));
    // The control plane restarts: the database still extends the anchor.
    let w = restart_world(w);
    assert_eq!(
        w.t.control.ledger_floor(&w.dataset_a).unwrap().unwrap().seq as usize,
        2 * acked.reserves.len(),
        "every acknowledged spend was anchored"
    );
    verify_no_loss_no_duplicates(&w, &acked, 4 * per.div_ceil(4));
}

// --- the real process, SIGKILLed ---------------------------------------------------

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Proc {
    child: Child,
    addr: std::net::SocketAddr,
    log: std::path::PathBuf,
}

/// Starts `encompute-control serve` on `w`'s database and anchor, with the
/// same signing key; waits until it is ready.
fn spawn_control(env0: &Env0, key_file: &std::path::Path, port: u16, n: usize) -> Proc {
    let log = env0.anchor_dir.with_extension(format!("serve-{n}.log"));
    let child = Command::new(env!("CARGO_BIN_EXE_encompute-control"))
        .arg("serve")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("ENCOMPUTE_ENV", "development")
        .env("ENCOMPUTE_DATABASE_URL", &env0.url)
        .env("ENCOMPUTE_ANCHOR_DIR", &env0.anchor_dir)
        .env("ENCOMPUTE_SIGNING_KEY_FILE", key_file)
        .env("ENCOMPUTE_DEV_TOKEN_SECRET", SECRET)
        .env("ENCOMPUTE_LISTEN", format!("127.0.0.1:{port}"))
        .env("ENCOMPUTE_AUDIT_CHECKPOINT_EVERY", "7")
        .env("ENCOMPUTE_WORKERS", "4")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut p = Proc { child, addr, log };
    let started = Instant::now();
    loop {
        if let Ok(Some(status)) = p.child.try_wait() {
            panic!(
                "encompute-control exited at startup ({status}): {}",
                std::fs::read_to_string(&p.log).unwrap_or_default()
            );
        }
        if ureq::get(&format!("http://{addr}/ready"))
            .timeout(Duration::from_secs(2))
            .call()
            .is_ok()
        {
            return p;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "encompute-control never became ready"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    #[allow(unreachable_code)]
    {
        p.child.kill().ok();
        p
    }
}

/// Spenders and submitters work against the real `encompute-control`
/// process while it is SIGKILLed at random moments and restarted. Each
/// restart must succeed (the anchor is never ahead of the database); in the
/// end nothing acknowledged is lost and nothing is duplicated.
#[test]
fn killed_control_plane_process_recovers_every_time() {
    let Some(w) = world() else { return };
    let mut rng = Rng::new("killed_control_plane");
    let plan = w.plan(EXACT);
    let World {
        t,
        a_owner,
        b_dev,
        project,
        dataset_a,
        ..
    } = w;
    let env0 = Env0 {
        url: t.env0.url.clone(),
        anchor_dir: t.env0.anchor_dir.clone(),
        seed: t.env0.seed,
        oidc: vec![],
        env: t.env0.env,
    };
    drop(t);
    let key_file = env0.anchor_dir.with_extension("signing.key");
    std::fs::write(&key_file, encompute_verification::hex(&env0.seed)).unwrap();
    let port = free_port();
    let mut proc = spawn_control(&env0, &key_file, port, 0);
    let client = Arc::new(Client::new(proc.addr));
    let acked = Arc::new(Mutex::new(Acked::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let workers: Vec<_> = (0..3)
        .map(|n| {
            let (c, acked, stop) = (client.clone(), acked.clone(), stop.clone());
            let (owner, dev) = (a_owner.clone(), b_dev.clone());
            let (asset, plan, project) = (dataset_a.clone(), plan.clone(), project.clone());
            std::thread::spawn(move || {
                let url = format!("/v1/privacy/{asset}/events");
                let send = |who: &As, url: &str, body: Value, extra: &[(&str, &str)]| {
                    let bytes = serde_json::to_vec(&body).unwrap();
                    let mut h = auth_headers(who, "POST", url, &bytes);
                    h.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
                    c.try_raw("POST", url, &h, &bytes)
                };
                let mut j = 0;
                while !stop.load(Ordering::SeqCst) {
                    let e = format!("p-{n}-{j}");
                    until_ok(&e, || send(&owner, &url, reserve(&e, 1_000_000), &[]));
                    acked.lock().unwrap().reserves.insert(e.clone());
                    until_ok(&e, || send(&owner, &url, commit(&e), &[]));
                    acked.lock().unwrap().commits.insert(e.clone());
                    if j % 3 == 0 {
                        let key = format!("pk-{n}-{j}");
                        let body = json!({"project": project, "plan": plan, "purpose": "medical-training",
                                          "source_assets": [], "requested_output": "out"});
                        let v = until_ok(&key, || {
                            send(&dev, "/v1/jobs", body.clone(), &[("Idempotency-Key", &key)])
                        });
                        acked
                            .lock()
                            .unwrap()
                            .jobs
                            .insert(key, v["id"].as_str().unwrap().to_owned());
                    }
                    j += 1;
                }
            })
        })
        .collect();
    let kills = 4 * scale();
    for n in 1..=kills {
        std::thread::sleep(Duration::from_millis(150 + rng.below(900)));
        proc.child.kill().unwrap(); // SIGKILL: no shutdown path runs
        proc.child.wait().unwrap();
        proc = spawn_control(&env0, &key_file, port, n);
    }
    std::thread::sleep(Duration::from_millis(300));
    stop.store(true, Ordering::SeqCst);
    for h in workers {
        h.join().unwrap();
    }
    proc.child.kill().unwrap();
    proc.child.wait().unwrap();
    let acked = Arc::try_unwrap(acked).ok().unwrap().into_inner().unwrap();
    assert!(!acked.reserves.is_empty());
    // Reopen in-process and check everything against the acknowledgements.
    let t = env0.start().expect("the database extends the anchor");
    let d = dataset_a.clone();
    let mut c = t.control.db.conn().unwrap();
    let view = encompute_control::control::load_ledger(&mut *c, &d)
        .unwrap()
        .unwrap();
    view.verify().unwrap();
    let mut seen = BTreeSet::new();
    for e in &view.entries {
        let kind = matches!(e.event, PrivacyEvent::Reserve { .. });
        assert!(
            seen.insert((kind, e.event.event_id().to_owned())),
            "event {} recorded twice",
            e.event.event_id()
        );
    }
    let reserves: BTreeSet<String> = view
        .entries
        .iter()
        .filter(|e| matches!(e.event, PrivacyEvent::Reserve { .. }))
        .map(|e| e.event.event_id().to_owned())
        .collect();
    assert_eq!(reserves, acked.reserves, "acknowledged reservations");
    for (key, id) in &acked.jobs {
        let rows = c
            .query("SELECT id FROM jobs WHERE idempotency_key = $1", &[key])
            .unwrap();
        assert_eq!(rows.len(), 1, "{key}");
        assert_eq!(&rows[0].get::<_, String>(0), id);
    }
    encompute_control::audit::verify_chain(&mut *c).unwrap();
    // Every committed job is placed or waiting, never lost between states.
    let stuck: i64 = c
        .query_one(
            "SELECT count(*) FROM jobs WHERE state IN ('created', 'planning', 'planned')",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(stuck, 0, "jobs stuck before authorization");
    let _ = std::fs::remove_file(&key_file);
}

fn register_again(w: &World) {
    w.t.ok(
        &w.evaluator.service,
        "POST",
        "/v1/evaluators",
        Some(
            json!({"id": "evaluator-1", "url": "http://evaluator-1.internal:8750",
                "receipt_key": w.evaluator.receipt.identity().public_key_hex(),
                "backends": ["openfhe", "openfhe-exact"],
                "profiles": ["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
                "openfhe_version": "1.5.1", "capacity": 4}),
        ),
    );
}

/// The evaluator restarts at a random point of each job (before starting
/// it, while running it, after reporting its receipt). Every job ends:
/// started later and succeeded, failed without replay, or completed by its
/// client. None runs twice or stays running.
#[test]
fn evaluator_restarts_at_random_points_leave_no_job_behind() {
    let Some(w) = world() else { return };
    let mut rng = Rng::new("evaluator_restarts");
    let t = &w.t;
    let plan = w.plan(EXACT);
    let (req, resp) = (b"request".to_vec(), b"response".to_vec());
    let r = receipt(&w.evaluator, &req, &resp);
    for i in 0..6 * scale() {
        let id = w.job(&plan, &[], &format!("ev-{i}")).1["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let at = rng.below(3);
        let start = || {
            t.call(
                &w.evaluator.service,
                "POST",
                &format!("/v1/jobs/{id}/start"),
                None,
            )
        };
        let report = || {
            t.ok(
                &w.evaluator.service,
                "POST",
                &format!("/v1/jobs/{id}/receipt"),
                Some(json!({"receipt": r})),
            )
        };
        let complete = || {
            t.ok(
                &w.b_dev,
                "POST",
                &format!("/v1/jobs/{id}/complete"),
                Some(
                    json!({"receipt": r, "request_commitment": request_commitment(&req),
                        "output_commitment": output_commitment(&resp), "key_id": KEY_ID}),
                ),
            )["state"]
                .clone()
        };
        if at >= 1 {
            assert_eq!(start().0, 200);
        }
        if at >= 2 {
            report();
        }
        register_again(&w); // the evaluator process restarted here
        let want = match at {
            0 => {
                // Never started: the new process starts it (once) and runs it.
                assert_eq!(start().0, 200);
                assert_eq!(start().0, 409);
                report();
                complete()
            }
            // Lost with the old process: failed, and never started again.
            1 => {
                assert_eq!(start().0, 409);
                json!("failed")
            }
            // Already reported: the client completes it.
            _ => complete(),
        };
        let v = t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{id}"), None);
        assert_eq!(v["state"], want, "restart at point {at}: {v}");
        assert!(
            v["state"] == "succeeded" || v["state"] == "failed",
            "stuck: {v}"
        );
        assert_transitions_legal(&w, &id);
        let started: i64 = t
            .control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT count(*) FROM job_transitions WHERE job_id = $1 AND to_state = 'running'",
                &[&id],
            )
            .unwrap()
            .get(0);
        assert_eq!(started, 1, "started {started} times");
    }
}

/// An evaluator that restarts while running a job (its process, and the
/// job with it, is gone) registers again: the job fails, never replayed,
/// instead of staying "running" forever behind the new process's
/// heartbeats. Jobs it already reported, or never started, are untouched.
#[test]
fn evaluator_restart_fails_its_running_jobs() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let plan = w.plan(EXACT);
    let submit = |key: &str| w.job(&plan, &[], key).1["id"].as_str().unwrap().to_owned();
    let start = |id: &str| {
        t.ok(
            &w.evaluator.service,
            "POST",
            &format!("/v1/jobs/{id}/start"),
            None,
        );
    };
    let (running, reported, queued) = (submit("er-1"), submit("er-2"), submit("er-3"));
    start(&running);
    start(&reported);
    let r = receipt(&w.evaluator, b"q", b"a");
    t.ok(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{reported}/receipt"),
        Some(json!({"receipt": r})),
    );
    let state = |id: &str| {
        t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{id}"), None)["state"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    // Heartbeats alone never resolve a running job.
    t.ok(
        &w.evaluator.service,
        "POST",
        "/v1/evaluators/evaluator-1/status",
        Some(json!({"status": "ready"})),
    );
    t.control.expire_evaluators().unwrap();
    assert_eq!(state(&running), "running");
    // The evaluator process restarts and registers again.
    t.ok(
        &w.evaluator.service,
        "POST",
        "/v1/evaluators",
        Some(
            json!({"id": "evaluator-1", "url": "http://evaluator-1.internal:8750",
                "receipt_key": w.evaluator.receipt.identity().public_key_hex(),
                "backends": ["openfhe", "openfhe-exact"],
                "profiles": ["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
                "openfhe_version": "1.5.1", "capacity": 4}),
        ),
    );
    assert_eq!(state(&running), "failed");
    let v = t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{running}"), None);
    assert!(v["error"].as_str().unwrap().contains("not replayed"), "{v}");
    assert_eq!(state(&reported), "verifying");
    assert_eq!(state(&queued), "queued");
    start(&queued);
    assert_eq!(state(&queued), "running");
    // A failed job is not started again.
    let (s, _) = t.call(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{running}/start"),
        None,
    );
    assert_eq!(s, 409);
    assert_eq!(
        count(
            &w,
            "SELECT count(*) FROM audit_events WHERE resource_id = $1 AND action = 'job.failed'",
            &running
        ),
        1
    );
    let mut c = t.control.db.conn().unwrap();
    encompute_control::audit::verify_chain(&mut *c).unwrap();
}

/// The live HTTP server keeps serving through database connection loss:
/// requests in flight fail cleanly (5xx) and later ones succeed.
#[test]
fn http_server_survives_database_connection_loss() {
    let Some(w) = world() else { return };
    let c = Client::new(live(&w.t.control, Limits::default()));
    for _ in 0..5 {
        terminate_backends(&w.t.env0.url);
        let v = until_ok("whoami", || {
            c.try_raw(
                "GET",
                "/v1/whoami",
                &auth_headers(&w.a_dev, "GET", "/v1/whoami", b""),
                b"",
            )
        });
        assert_eq!(v["organization"], "hospital-a");
    }
    let (s, _) = c.raw("GET", "/ready", &[], b"");
    assert_eq!(s, 200);
}
