//! Shared test harness: a fresh PostgreSQL database per test (from
//! `ENCOMPUTE_TEST_DATABASE_URL`, an account allowed to create databases),
//! a temporary anchor directory, development tokens, and an in-memory
//! transport. Without the variable the tests are skipped, unless
//! `ENCOMPUTE_REQUIRE_SERVICES=1` (CI), where that is a failure.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};

pub mod gov;

use encompute_control::anchor::DirAnchor;
use encompute_control::api::{handle, Request};
use encompute_control::authn::{dev_token, Authenticator, DEV_ISSUER};
use encompute_control::config::{Env, OidcIssuer};
use encompute_control::db::Db;
pub use encompute_control::govlog::NegSet;
use encompute_control::transport::InMemoryTransport;
use encompute_control::Control;
use encompute_verification::ServiceSigner;

pub const SECRET: &str = "test-development-secret";

static N: AtomicU64 = AtomicU64::new(0);

/// The databases the running test created (fresh ones and backups). Each
/// test runs on its own thread, so this thread-local is dropped when the
/// test ends, passing or panicking (unwinding drops the test's control
/// planes first); dropping it drops the databases. Tests move the parts of
/// their worlds around freely (`let env0 = t.env0`), so the cleanup cannot
/// hang off one struct.
struct TestDatabases {
    admin: String,
    names: Vec<String>,
}

impl Drop for TestDatabases {
    fn drop(&mut self) {
        if self.names.is_empty() {
            return;
        }
        // Never panic here: a panicking thread-local destructor aborts.
        let mut c = match postgres::Client::connect(&self.admin, postgres::NoTls) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("test databases {:?} not dropped: {e}", self.names);
                return;
            }
        };
        for name in self.names.iter().rev() {
            // End the sessions first (a pool, a spawned server or a leaked
            // client may still hold one); FORCE ends any that reconnect.
            let _ = c.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                  WHERE datname = $1 AND pid <> pg_backend_pid()",
                &[name],
            );
            if let Err(e) = c.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            {
                eprintln!("test database {name} not dropped: {e}");
            }
        }
    }
}

thread_local! {
    static CREATED: std::cell::RefCell<Option<TestDatabases>> = const { std::cell::RefCell::new(None) };
}

/// Drops database `name` when the current test ends.
fn drop_at_test_end(admin: &str, name: &str) {
    CREATED.with(|c| {
        c.borrow_mut()
            .get_or_insert_with(|| TestDatabases {
                admin: admin.to_owned(),
                names: vec![],
            })
            .names
            .push(name.to_owned())
    });
}

/// A database for one test, or `None` (skipped). It is dropped when the
/// test ends.
pub fn fresh_database() -> Option<String> {
    let admin = match std::env::var("ENCOMPUTE_TEST_DATABASE_URL") {
        Ok(u) => u,
        Err(_) if std::env::var("ENCOMPUTE_REQUIRE_SERVICES").is_ok() => {
            panic!("ENCOMPUTE_REQUIRE_SERVICES is set but ENCOMPUTE_TEST_DATABASE_URL is not")
        }
        Err(_) => {
            eprintln!("SKIPPED: set ENCOMPUTE_TEST_DATABASE_URL (a PostgreSQL account that may create databases)");
            return None;
        }
    };
    let name = format!(
        "enc_test_{}_{}_{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros()
            % 1_000_000
    );
    let mut c = postgres::Client::connect(&admin, postgres::NoTls).expect("test database");
    c.batch_execute(&format!("CREATE DATABASE {name}")).unwrap();
    drop_at_test_end(&admin, &name);
    // Replace the database name in the URL.
    let url = match admin.rsplit_once('/') {
        Some((base, _)) if admin.starts_with("postgres") => format!("{base}/{name}"),
        _ => format!("{admin} dbname={name}"),
    };
    Some(url)
}

fn admin_url() -> String {
    std::env::var("ENCOMPUTE_TEST_DATABASE_URL").unwrap()
}

pub fn db_name(url: &str) -> String {
    url.rsplit('/').next().unwrap().to_owned()
}

/// "Backs up" `url` into database `backup` (a template copy; no connection
/// to the source may be open). The backup is dropped when the test ends.
pub fn backup_database(url: &str, backup: &str) {
    drop_at_test_end(&admin_url(), backup);
    let mut c = postgres::Client::connect(&admin_url(), postgres::NoTls).unwrap();
    drop_at_test_end(&admin_url(), backup);
    let live = db_name(url);
    // A dropped pool closes its connections asynchronously: end them first.
    for _ in 0..50 {
        c.batch_execute(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{live}'"
        ))
        .unwrap();
        match c.batch_execute(&format!("CREATE DATABASE {backup} TEMPLATE {live}")) {
            Ok(()) => return,
            Err(e) if e.code() == Some(&postgres::error::SqlState::OBJECT_IN_USE) => {
                std::thread::sleep(std::time::Duration::from_millis(100))
            }
            Err(e) => panic!("{e}"),
        }
    }
    panic!("the source database stayed in use");
}

/// Restores `backup` over `url`'s database (drops it first).
pub fn restore_database(backup: &str, url: &str) {
    let mut c = postgres::Client::connect(&admin_url(), postgres::NoTls).unwrap();
    let live = db_name(url);
    // FORCE terminates the remaining sessions atomically (a pool connection
    // can reconnect between a separate terminate and the drop).
    c.batch_execute(&format!("DROP DATABASE IF EXISTS {live} WITH (FORCE)"))
        .unwrap();
    // The template must have no sessions either; retry as for backups.
    for _ in 0..50 {
        c.batch_execute(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{backup}'"
        ))
        .unwrap();
        match c.batch_execute(&format!("CREATE DATABASE {live} TEMPLATE {backup}")) {
            Ok(()) => return,
            Err(e) if e.code() == Some(&postgres::error::SqlState::OBJECT_IN_USE) => {
                std::thread::sleep(std::time::Duration::from_millis(100))
            }
            Err(e) => panic!("restoring {backup}: {e}"),
        }
    }
    panic!("the backup database stayed in use");
}

/// Runs `sql` on `url` with the user triggers of `tables` disabled: what an
/// attacker with the database's credentials can do.
pub fn attacker(url: &str, tables: &[&str], sql: &str) {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    for t in tables {
        c.batch_execute(&format!("ALTER TABLE {t} DISABLE TRIGGER USER"))
            .unwrap();
    }
    c.batch_execute(sql).unwrap();
    for t in tables {
        c.batch_execute(&format!("ALTER TABLE {t} ENABLE TRIGGER USER"))
            .unwrap();
    }
}

/// The configuration `encompute-control recover` would run with on
/// `env0`'s database and anchor.
pub fn recovery_config(env0: &Env0) -> encompute_control::config::Config {
    encompute_control::config::Config {
        env: env0.env,
        listen: "127.0.0.1:0".into(),
        service_id: "control-plane".into(),
        database_url: zeroize::Zeroizing::new(env0.url.clone()),
        signing_key_file: None,
        oidc: vec![],
        dev_token_secret: None,
        anchor: encompute_control::config::AnchorConfig::Dir(env0.anchor_dir.clone()),
        audit_checkpoint_every: 5,
        max_token_lifetime_secs: encompute_control::authn::DEFAULT_MAX_TOKEN_LIFETIME_SECS,
        metrics: encompute_control::config::MetricsAccess::Closed,
    }
}

/// Runs `encompute-control recover` on `env0`'s database and anchor: its
/// notes.
pub fn run_recovery(env0: &Env0) -> Vec<String> {
    let db = Db::connect(&env0.url).unwrap();
    let signer = ServiceSigner::from_seed("control-plane", &env0.seed).unwrap();
    let store = Box::new(DirAnchor::new(env0.anchor_dir.clone()).unwrap());
    let rc = Control::for_recovery(&recovery_config(env0), db, signer, store)
        .unwrap_or_else(|e| panic!("the control plane failed to open for recovery: {e}"));
    rc.recover("operator-1").unwrap()
}

/// Runs `encompute-control recover --governance-log FILE` with `export`
/// (an `export-governance-log` taken before the restore): its notes.
pub fn run_recovery_importing(env0: &Env0, export: &str) -> Vec<String> {
    let db = Db::connect(&env0.url).unwrap();
    let signer = ServiceSigner::from_seed("control-plane", &env0.seed).unwrap();
    let store = Box::new(DirAnchor::new(env0.anchor_dir.clone()).unwrap());
    let rc = Control::for_recovery(&recovery_config(env0), db, signer, store)
        .unwrap_or_else(|e| panic!("the control plane failed to open for recovery: {e}"));
    rc.recover_importing("operator-1", Some(export)).unwrap()
}

/// Puts the events of `export` that `url`'s governance log lacks back
/// (what `recover --governance-log` does first).
pub fn import_log(url: &str, export: &str) -> u64 {
    let db = Db::connect(url).unwrap();
    db.tx(|t| encompute_control::govlog::import(t, export))
        .unwrap()
}

/// Restores `backup` over `env0`'s database after the governance log moved
/// on: the start is refused (GOVERNANCE LOG STATE ROLLBACK), and so is a
/// recovery without the missing events. Returns an export of the log taken
/// before the restore (what an operator keeps with `encompute-control
/// export-governance-log`).
pub fn restore_behind_the_log(env0: &Env0, backup: &str) -> String {
    let export = export_log(&env0.url);
    restore_database(backup, &env0.url);
    let e = env0
        .start()
        .err()
        .expect("a database behind the anchored governance log started");
    assert!(e.message.contains("GOVERNANCE LOG STATE ROLLBACK"), "{e}");
    export
}

/// [`restore_behind_the_log`], then the operator puts the governance log's
/// missing events back (from a newer copy of its tables, or an export):
/// the database's other tables stay as restored.
pub fn restore_keeping_log(env0: &Env0, backup: &str) {
    let export = restore_behind_the_log(env0, backup);
    assert!(import_log(&env0.url, &export) > 0);
}

/// `encompute-control export-governance-log` of `url`'s database.
pub fn export_log(url: &str) -> String {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    encompute_control::govlog::export(&mut c, 0).unwrap()
}

/// Whether the transition putting `id` in `set` is anchored (its
/// governance log event lies within the anchored size).
pub fn anchored(t: &T, set: NegSet, id: &str) -> bool {
    t.control.anchored(set, id).unwrap()
}

/// The IDs of a negative set, as the governance log records them.
pub fn log_set(t: &T, set: NegSet) -> Vec<String> {
    let mut c = t.control.db.conn().unwrap();
    encompute_control::govlog::negative_set(&mut *c, set).unwrap()
}

/// Whether recovery recorded the row of `id` as lost.
pub fn is_lost(t: &T, id: &str) -> bool {
    let mut c = t.control.db.conn().unwrap();
    c.query_opt(
        "SELECT 1 FROM governance_events WHERE kind = 'row.lost' AND subject_id = $1",
        &[&id],
    )
    .unwrap()
    .is_some()
}

/// A directory anchor store whose anchor writes fail while `fail` is set
/// (a crash between the governance log mirror's write and the anchor's).
pub struct FlakyAnchor {
    pub inner: DirAnchor,
    pub fail: Arc<std::sync::atomic::AtomicBool>,
}

impl encompute_control::anchor::AnchorStore for FlakyAnchor {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn load(&self) -> encompute_ir::Result<Option<encompute_control::anchor::StoredAnchor>> {
        self.inner.load()
    }
    fn store(
        &self,
        next: &encompute_control::anchor::StateAnchor,
        expected: u64,
    ) -> encompute_ir::Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(encompute_ir::Error::new(
                encompute_ir::Code::PrivacyLedger,
                "anchor store unavailable (injected)",
            ));
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
    fn mirror_replace(
        &self,
        n: u64,
        lines: &str,
        allow: &encompute_control::anchor::Allow<'_>,
    ) -> encompute_ir::Result<()> {
        self.inner.mirror_replace(n, lines, allow)
    }
}

/// A directory anchor store that kills the process (as a crash would)
/// when the anchor is written while `armed` is set: after the governance
/// log mirror's write, before the anchor's compare-and-set.
pub struct KillAnchor {
    pub inner: DirAnchor,
    pub armed: Arc<std::sync::atomic::AtomicBool>,
}

impl encompute_control::anchor::AnchorStore for KillAnchor {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn load(&self) -> encompute_ir::Result<Option<encompute_control::anchor::StoredAnchor>> {
        self.inner.load()
    }
    fn store(
        &self,
        next: &encompute_control::anchor::StateAnchor,
        expected: u64,
    ) -> encompute_ir::Result<()> {
        if self.armed.load(Ordering::SeqCst) {
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
    fn mirror_replace(
        &self,
        n: u64,
        lines: &str,
        allow: &encompute_control::anchor::Allow<'_>,
    ) -> encompute_ir::Result<()> {
        self.inner.mirror_replace(n, lines, allow)
    }
}

impl Env0 {
    /// Starts over a [`KillAnchor`]: the control plane and its trigger.
    pub fn start_killable(&self) -> (T, Arc<std::sync::atomic::AtomicBool>) {
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let t = self
            .start_with(Box::new(KillAnchor {
                inner: DirAnchor::new(self.anchor_dir.clone()).unwrap(),
                armed: armed.clone(),
            }))
            .unwrap_or_else(|e| panic!("the control plane failed to start: {e}"));
        (t, armed)
    }

    /// Starts over a [`FlakyAnchor`]: the control plane and its switch.
    pub fn start_flaky(&self) -> (T, Arc<std::sync::atomic::AtomicBool>) {
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let t = self
            .start_with(Box::new(FlakyAnchor {
                inner: DirAnchor::new(self.anchor_dir.clone()).unwrap(),
                fail: fail.clone(),
            }))
            .unwrap_or_else(|e| panic!("the control plane failed to start: {e}"));
        (t, fail)
    }
}

/// Removes the scratch directories of the test that made them when it
/// ends (a directory left behind, and found again under a reused process
/// ID, would hand a later test somebody else's anchor).
struct ScratchDirs(Vec<PathBuf>);

impl Drop for ScratchDirs {
    fn drop(&mut self) {
        for d in &self.0 {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

thread_local! {
    static SCRATCH: std::cell::RefCell<ScratchDirs> = const { std::cell::RefCell::new(ScratchDirs(vec![])) };
}

/// A new, empty directory: its name carries the process ID, a counter and
/// the time, it is created exclusively (one that exists is never reused:
/// process IDs wrap around, and earlier runs left directories behind), and
/// it is removed when the test ends.
pub fn tmp_dir(tag: &str) -> PathBuf {
    loop {
        let d = std::env::temp_dir().join(format!(
            "encompute-control-{tag}-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        match std::fs::create_dir(&d) {
            Ok(()) => {
                SCRATCH.with(|s| s.borrow_mut().0.push(d.clone()));
                return d;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("{}: {e}", d.display()),
        }
    }
}

pub struct Env0 {
    pub url: String,
    pub anchor_dir: PathBuf,
    pub seed: [u8; 32],
    pub oidc: Vec<OidcIssuer>,
    pub env: Env,
}

pub struct T {
    pub control: Arc<Control>,
    pub transport: Arc<InMemoryTransport>,
    pub env0: Env0,
}

struct SharedTransport(Arc<InMemoryTransport>);

impl encompute_control::transport::MessageTransport for SharedTransport {
    fn send(
        &self,
        url: &str,
        m: &encompute_control::model::MessageEnvelope,
    ) -> encompute_ir::Result<()> {
        self.0.send(url, m)
    }
}

impl Env0 {
    /// [`Self::start`], panicking with the reason when the control plane
    /// refuses to start.
    pub fn started(&self) -> T {
        self.start()
            .unwrap_or_else(|e| panic!("the control plane failed to start: {e}"))
    }

    pub fn start(&self) -> encompute_ir::Result<T> {
        self.start_with(Box::new(DirAnchor::new(self.anchor_dir.clone())?))
    }

    /// [`Self::start`] with another anchor store (over the same directory,
    /// say, failing on demand).
    pub fn start_with(
        &self,
        store: Box<dyn encompute_control::anchor::AnchorStore>,
    ) -> encompute_ir::Result<T> {
        let db = Db::connect(&self.url)?;
        db.migrate()?;
        let signer = ServiceSigner::from_seed("control-plane", &self.seed)?;
        let transport = Arc::new(InMemoryTransport::default());
        let control = Control::with_parts(
            self.env,
            "control-plane",
            db,
            Authenticator::new(
                self.env,
                "control-plane",
                self.oidc.clone(),
                Some(zeroize::Zeroizing::new(SECRET.into())),
            ),
            signer,
            store,
            Some(Box::new(SharedTransport(transport.clone()))),
            5,
        )?;
        Ok(T {
            control: Arc::new(control),
            transport,
            env0: Env0 {
                url: self.url.clone(),
                anchor_dir: self.anchor_dir.clone(),
                seed: self.seed,
                oidc: self.oidc.clone(),
                env: self.env,
            },
        })
    }
}

/// A fresh control plane (development mode), or `None` when skipped.
pub fn setup() -> Option<T> {
    let url = fresh_database()?;
    let env0 = Env0 {
        url,
        anchor_dir: tmp_dir("anchor"),
        seed: [42; 32],
        oidc: vec![],
        env: Env::Development,
    };
    Some(env0.started())
}

/// Who calls.
#[derive(Clone)]
pub enum As {
    Nobody,
    User(String),
    Service(Arc<ServiceSigner>),
    Raw(String),
}

pub fn token(subject: &str) -> String {
    dev_token(SECRET, subject, 3600).unwrap()
}

impl T {
    /// [`Self::restart`], panicking with the reason when the control plane
    /// refuses to start again.
    pub fn restarted(self) -> T {
        self.restart()
            .unwrap_or_else(|e| panic!("the control plane failed to restart: {e}"))
    }

    pub fn restart(self) -> encompute_ir::Result<T> {
        let env0 = self.env0;
        drop(self.control);
        env0.start()
    }

    pub fn call(&self, who: &As, method: &str, url: &str, body: Option<Value>) -> (u16, Value) {
        self.call_with(who, method, url, body, &[])
    }

    pub fn call_with(
        &self,
        who: &As,
        method: &str,
        url: &str,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> (u16, Value) {
        let body = body
            .map(|b| serde_json::to_vec(&b).unwrap())
            .unwrap_or_default();
        let mut headers: Vec<(String, String)> = extra
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        match who {
            As::Nobody => {}
            As::User(sub) => {
                headers.push(("Authorization".into(), format!("Bearer {}", token(sub))))
            }
            As::Raw(t) => headers.push(("Authorization".into(), format!("Bearer {t}"))),
            As::Service(s) => {
                // The whole target: the query is signed.
                let h = s
                    .sign_request(method, url, "control-plane", &Default::default(), &body)
                    .unwrap();
                for (k, v) in h.to_pairs() {
                    headers.push((k.into(), v));
                }
            }
        }
        let r = handle(
            &self.control,
            &Request {
                method: method.into(),
                url: url.into(),
                headers,
                body,
            },
        );
        let v = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        (r.status, v)
    }

    /// Calls and asserts a 2xx status.
    pub fn ok(&self, who: &As, method: &str, url: &str, body: Option<Value>) -> Value {
        let (s, v) = self.call(who, method, url, body);
        assert!((200..300).contains(&s), "{method} {url}: {s} {v}");
        v
    }
}

/// A world with the platform, two organizations (A: hospital-a, B: modelco),
/// their people, and a shared project.
pub struct World {
    pub t: T,
    pub platform: As,
    pub a_admin: As,
    pub a_owner: As,
    pub a_dev: As,
    pub a_auditor: As,
    pub b_admin: As,
    pub b_owner: As,
    pub b_dev: As,
    pub b_auditor: As,
    pub c_admin: As,
    pub c_dev: As,
    pub b_sec: As,
    pub b_sec2: As,
    pub project: String,
    pub dataset_a: String,
    pub model_b: String,
    pub evaluator: Evaluator,
}

pub fn user(t: &T, admin: &As, org: &str, subject: &str, roles: &[&str]) -> As {
    t.ok(
        admin,
        "POST",
        &format!("/v1/organizations/{org}/users"),
        Some(json!({"issuer": DEV_ISSUER, "subject": subject, "roles": roles})),
    );
    As::User(subject.into())
}

/// Gives `subject`'s user `role` in `org` directly in the database: a role
/// combination from before auditor separation (D9), which the API now
/// refuses to grant in organizations taking part in governed projects.
pub fn legacy_role(t: &T, subject: &str, org: &str, role: &str) {
    let n = t
        .control
        .db
        .conn()
        .unwrap()
        .execute(
            "INSERT INTO memberships (principal_id, organization_id, role)
             SELECT id, $2, $3 FROM users WHERE subject = $1",
            &[&subject, &org, &role],
        )
        .unwrap();
    assert_eq!(n, 1, "no user {subject}");
}

pub fn world() -> Option<World> {
    let t = setup()?;
    t.control
        .bootstrap(DEV_ISSUER, "platform-admin", None)
        .unwrap();
    let platform = As::User("platform-admin".into());
    for (org, admin) in [
        ("hospital-a", "a-admin"),
        ("modelco", "b-admin"),
        ("other-co", "c-admin"),
    ] {
        t.ok(
            &platform,
            "POST",
            "/v1/organizations",
            Some(json!({"id": org, "display_name": org, "admin": {"issuer": DEV_ISSUER, "subject": admin}})),
        );
    }
    let a_admin = As::User("a-admin".into());
    let b_admin = As::User("b-admin".into());
    let a_owner = user(&t, &a_admin, "hospital-a", "a-owner", &["data_owner"]);
    let a_dev = user(&t, &a_admin, "hospital-a", "a-dev", &["ml_developer"]);
    let a_auditor = user(&t, &a_admin, "hospital-a", "a-auditor", &["auditor"]);
    let b_owner = user(&t, &b_admin, "modelco", "b-owner", &["model_owner"]);
    let b_dev = user(&t, &b_admin, "modelco", "b-dev", &["ml_developer"]);
    let b_auditor = user(&t, &b_admin, "modelco", "b-auditor", &["auditor"]);
    let b_sec = user(&t, &b_admin, "modelco", "b-sec", &["security_admin"]);
    let b_sec2 = user(&t, &b_admin, "modelco", "b-sec2", &["security_admin"]);
    let c_admin = As::User("c-admin".into());
    let c_dev = user(&t, &c_admin, "other-co", "c-dev", &["ml_developer"]);
    let evaluator = evaluator(
        &t,
        &platform,
        "evaluator-1",
        &["openfhe", "openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
        4,
    );
    let p = t.ok(
        &b_dev,
        "POST",
        "/v1/projects",
        Some(json!({"organization": "modelco", "name": "medical-training"})),
    );
    let project = p["id"].as_str().unwrap().to_owned();
    // modelco invites hospital-a; hospital-a's admin accepts.
    t.ok(
        &b_admin,
        "POST",
        &format!("/v1/projects/{project}/members"),
        Some(json!({"organization": "hospital-a"})),
    );
    t.ok(
        &a_admin,
        "POST",
        &format!("/v1/projects/{project}/members"),
        Some(json!({"organization": "hospital-a"})),
    );
    let d = t.ok(
        &a_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": "hospital-a", "kind": "dataset", "name": "patients-2026",
                    "digest": "a".repeat(64),
                    "privacy_budget": budget(3.0)}),
        ),
    );
    let m = t.ok(
        &b_owner,
        "POST",
        "/v1/assets",
        Some(json!({"organization": "modelco", "kind": "model", "name": "model-7", "digest": "b".repeat(64),
                    "key_ref": {"broker": "keybroker-modelco", "provider": "openbao-transit",
                                "key_ref": "model-7", "key_version": 1}})),
    );
    Some(World {
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
        dataset_a: d["id"].as_str().unwrap().into(),
        model_b: m["id"].as_str().unwrap().into(),
        evaluator,
    })
}

pub fn budget(epsilon: f64) -> Value {
    serde_json::to_value(encompute_ir::confidentiality::PrivacyBudget {
        unit: encompute_ir::confidentiality::PrivacyUnit::Patient,
        epsilon,
        delta: 1e-6,
    })
    .unwrap()
}

/// A reservation costing what sensitivity 1 at noise variance `sigma2`
/// would (declared as sensitivity 2 at `4 * sigma2`, the least a release
/// can have: one clipped code unit plus one coordinate's rounding). Its
/// mechanism is consistent with that charge (a large noise multiplier), so
/// the control plane's check of the declared sensitivity accepts it.
pub fn reserve(event: &str, sigma2: u64) -> Value {
    serde_json::to_value(encompute_privacy::PrivacyEvent::Reserve {
        event_id: event.into(),
        policy_id: None,
        execution_spec_id: None,
        round_id: None,
        output: "update".into(),
        mechanism: encompute_ir::confidentiality::DpMechanism {
            kind: encompute_ir::confidentiality::DpKind::DiscreteGaussian,
            clip_norm: 1.0,
            noise_multiplier: 10_000_000.0,
            sampling_rate: None,
            preset: None,
        },
        sensitivity: 2,
        sigma2: 4 * sigma2,
        vector_len: 1,
        rng: encompute_privacy::CSPRNG.into(),
        scope: None,
    })
    .unwrap()
}

/// An exact program (u8 comparison), and an approximate one.
pub const EXACT: &str = "encompute 0.1
program adult precision 0.001
%0 = input \"age\" [0.0, 120.0] : secret u8
%1 = const [18.0] : public u8
%2 = ge %0, %1 : secret bool
output \"out\" = %2
";

pub const APPROX: &str = "encompute 0.1
program score precision 0.001
%0 = input \"x\" [-1.0, 1.0] : secret vector<4>
%1 = mul %0, %0 : secret vector<4>
output \"y\" = %1
";

/// [`EXACT`] over another organization's registered asset: the program
/// declares its purpose and binds its input to the asset by ID, as a job
/// using an asset another organization approved must.
pub fn exact_over(asset: &str, owner: &str, kind: &str, purpose: &str) -> String {
    format!(
        "encompute 0.1
program adult precision 0.001 purpose \"{purpose}\"
party \"{owner}\" \"{owner}\"
party \"modelco\" \"ModelCo\"
asset \"{asset}\" {kind} owners [\"{owner}\"] readers [\"modelco\"] purposes [\"{purpose}\"] release allowed_parties
%0 = input \"age\" [0.0, 120.0] asset \"{asset}\" : secret u8
%1 = const [18.0] : public u8
%2 = ge %0, %1 : secret bool
output \"out\" = %2 to \"modelco\"
"
    )
}

/// [`EXACT`] over modelco's own registered asset `asset` (its model, say):
/// the program binds its input to the asset by ID, so the asset is the
/// job's source. A job lists exactly the assets its program binds, even
/// over the submitter's own data; [`EXACT`] binds none and lists none.
pub fn exact_own(asset: &str) -> String {
    format!(
        "encompute 0.1
program adult precision 0.001 purpose \"medical-training\"
party \"modelco\" \"ModelCo\"
asset \"{asset}\" model owners [\"modelco\"] readers [\"modelco\"] purposes [\"medical-training\"] release allowed_parties
%0 = input \"age\" [0.0, 120.0] asset \"{asset}\" : secret u8
%1 = const [18.0] : public u8
%2 = ge %0, %1 : secret bool
output \"out\" = %2 to \"modelco\"
"
    )
}

impl World {
    /// A plan of `program` in the shared project, by modelco's developer.
    pub fn plan(&self, program: &str) -> String {
        let p = self.t.ok(
            &self.b_dev,
            "POST",
            "/v1/plans",
            Some(json!({"project": self.project, "program": program})),
        );
        p["id"].as_str().unwrap().into()
    }

    /// A job by modelco's developer (idempotency key `key`).
    pub fn job(&self, plan: &str, sources: &[&str], key: &str) -> (u16, Value) {
        self.t.call_with(
            &self.b_dev,
            "POST",
            "/v1/jobs",
            Some(
                json!({"project": self.project, "plan": plan, "purpose": "medical-training",
                        "source_assets": sources, "requested_output": "out"}),
            ),
            &[("Idempotency-Key", key)],
        )
    }
}

/// A registered evaluator service (identity + receipt key).
pub struct Evaluator {
    pub id: String,
    pub service: As,
    pub signer: Arc<ServiceSigner>,
    pub receipt: encompute_verification::EvaluatorSigner,
}

pub fn evaluator(
    t: &T,
    platform: &As,
    id: &str,
    backends: &[&str],
    profiles: &[&str],
    capacity: i32,
) -> Evaluator {
    evaluator_with(t, platform, id, backends, profiles, capacity, json!({}))
}

/// Like [`evaluator`], registering the machine-profile fields in `machine`
/// (e.g. `{"logical_cores": 16, "max_parallel_gates": 8}`).
pub fn evaluator_with(
    t: &T,
    platform: &As,
    id: &str,
    backends: &[&str],
    profiles: &[&str],
    capacity: i32,
    machine: Value,
) -> Evaluator {
    let seed = {
        let mut s = [0u8; 32];
        for (i, b) in id.bytes().enumerate() {
            s[i % 32] ^= b;
        }
        s[31] ^= 0x5a;
        s
    };
    let signer = Arc::new(ServiceSigner::from_seed(id, &seed).unwrap());
    t.ok(
        platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(
            json!({"id": id, "kind": "evaluator", "public_key": signer.public_key_hex(),
                    "url": format!("http://{id}.internal:8750")}),
        ),
    );
    let receipt = encompute_verification::EvaluatorSigner::from_seed(&seed.map(|b| b ^ 0x33));
    let service = As::Service(signer.clone());
    let mut body = json!({"id": id, "url": format!("http://{id}.internal:8750"),
                "receipt_key": receipt.identity().public_key_hex(),
                "backends": backends, "profiles": profiles, "openfhe_version": "1.5.1", "capacity": capacity});
    if let (Value::Object(b), Value::Object(m)) = (&mut body, machine) {
        b.extend(m);
    }
    t.ok(&service, "POST", "/v1/evaluators", Some(body));
    Evaluator {
        id: id.into(),
        service,
        signer,
        receipt,
    }
}

// --- over real HTTP ------------------------------------------------------------

/// Serves `control` over real HTTP on a fresh loopback port, with `limits`.
pub fn live(
    control: &Arc<Control>,
    limits: encompute_verification::http::Limits,
) -> std::net::SocketAddr {
    let server = encompute_verification::http::Server::http("127.0.0.1:0")
        .unwrap()
        .with_limits(limits);
    let addr = server.server_addr();
    let c = control.clone();
    std::thread::spawn(move || encompute_control::api::serve_on(c, server));
    addr
}

/// Headers `who` sends for `method url` with `body`.
pub fn auth_headers(who: &As, method: &str, url: &str, body: &[u8]) -> Vec<(String, String)> {
    match who {
        As::Nobody => vec![],
        As::User(sub) => vec![("Authorization".into(), format!("Bearer {}", token(sub)))],
        As::Raw(t) => vec![("Authorization".into(), format!("Bearer {t}"))],
        As::Service(s) => {
            let path = url.split('?').next().unwrap();
            s.sign_request(method, path, "control-plane", &Default::default(), body)
                .unwrap()
                .to_pairs()
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect()
        }
    }
}

/// An HTTP client of a live control plane.
pub struct Client {
    pub base: String,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(addr: std::net::SocketAddr) -> Self {
        Self {
            base: format!("http://{addr}"),
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(30))
                .build(),
        }
    }

    /// Sends raw headers and body: (status, JSON body or null).
    pub fn raw(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> (u16, Value) {
        match self.try_raw(method, url, headers, body) {
            Ok(r) => r,
            Err(e) => panic!("{method} {url}: {e}"),
        }
    }

    /// Like [`Client::raw`]; `Err` when the transport failed.
    pub fn try_raw(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Value), String> {
        let mut r = self
            .agent
            .request(method, &format!("{}{url}", self.base))
            .set("Content-Type", "application/json");
        for (k, v) in headers {
            r = r.set(k, v);
        }
        let out = if body.is_empty() {
            r.call()
        } else {
            r.send_bytes(body)
        };
        match out {
            Ok(resp) => Ok((resp.status(), resp.into_json().unwrap_or(Value::Null))),
            Err(ureq::Error::Status(s, resp)) => Ok((s, resp.into_json().unwrap_or(Value::Null))),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn call_with(
        &self,
        who: &As,
        method: &str,
        url: &str,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> (u16, Value) {
        let body = body
            .map(|b| serde_json::to_vec(&b).unwrap())
            .unwrap_or_default();
        let mut h = auth_headers(who, method, url, &body);
        h.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        self.raw(method, url, &h, &body)
    }

    pub fn call(&self, who: &As, method: &str, url: &str, body: Option<Value>) -> (u16, Value) {
        self.call_with(who, method, url, body, &[])
    }

    /// Calls and asserts a 2xx status.
    pub fn ok(&self, who: &As, method: &str, url: &str, body: Option<Value>) -> Value {
        let (s, v) = self.call(who, method, url, body);
        assert!((200..300).contains(&s), "{method} {url}: {s} {v}");
        v
    }
}

/// Writes `bytes` on a fresh connection and reads the whole reply.
pub fn raw_exchange(addr: std::net::SocketAddr, bytes: &[u8]) -> String {
    use std::io::{Read, Write};
    let mut c = std::net::TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let _ = c.write_all(bytes);
    let mut out = vec![];
    let _ = c.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// The status code of a raw HTTP reply (0 if none).
pub fn status_of(reply: &str) -> u16 {
    reply.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// The JSON body of a raw HTTP reply.
pub fn body_of(reply: &str) -> Value {
    reply
        .split_once("\r\n\r\n")
        .and_then(|(_, b)| serde_json::from_str(b).ok())
        .unwrap_or(Value::Null)
}

/// The registered policy (and release class) a governed dataset version of
/// `org` carries: readers benefits and tax, for benefits eligibility,
/// boolean-only. Governed sources need one.
#[allow(dead_code)]
pub fn registered(org: &str) -> serde_json::Value {
    serde_json::json!({
        "ir_policy": {"owners": [org], "readers": ["benefits-agency", "tax-agency"],
                      "purposes": ["benefits-eligibility"], "release": "allowed_parties",
                      "derive": {}},
        "release_class": "boolean-only"
    })
}

/// Probing limits a boolean-only authorization carries.
#[allow(dead_code)]
pub fn probing_limits() -> encompute_trust::authz::AuthorizationLimits {
    encompute_trust::authz::AuthorizationLimits {
        max_executions: Some(1000),
        max_releases: Some(1000),
        ..Default::default()
    }
}
