//! Test databases and directories, shared by every DB-backed test crate
//! (`#[path]`-included by the control-plane harness and by the CLI tests).
//!
//! Two modes, chosen by `ENCOMPUTE_TEST_DB_MODE`:
//!
//! * `template` (the default; fast development): the migrations run once per
//!   schema revision into an immutable template database, and every test
//!   gets its own clone (`CREATE DATABASE ... TEMPLATE`).
//! * `cold` (full validation; what every release gate sets): every test
//!   creates an empty database and the control plane migrates it itself, so
//!   a clone can never hide a broken migration or bootstrap.
//!
//! The template is keyed by a hash of the whole migration set (so a new or
//! edited migration is a new template), built under a PostgreSQL advisory
//! lock (parallel test binaries and CI jobs sharing a server do not race),
//! built under a scratch name and renamed last (a half-built template never
//! has the real name), and then marked `IS_TEMPLATE` with connections
//! forbidden: nothing can run against it, only clone it. Old templates are
//! left for the next cleanup of the test server. Every clone has a unique
//! name and is dropped (forced, with retries) when its test ends.
//!
//! Without `ENCOMPUTE_TEST_DATABASE_URL` the DB-backed tests are skipped,
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1` (CI, `scripts/test-full.sh`), where
//! that is a failure. When `ENCOMPUTE_TEST_EXEC_LOG` names a file, every
//! database a test takes appends one line to it: the runner counts them, so
//! a run whose tests quietly returned early cannot look like a run that
//! exercised the database.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use encompute_control::db::{Db, MIGRATIONS};

static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// Bump when this harness changes what a template contains.
const TEMPLATE_REVISION: &str = "1";
/// The advisory lock that serializes template creation.
const TEMPLATE_LOCK: i64 = 0x656e_6374_706c;
const TEMPLATE_PREFIX: &str = "encompute_test_template_";

/// How databases for tests are made.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DbMode {
    Template,
    Cold,
}

pub fn mode() -> DbMode {
    match std::env::var("ENCOMPUTE_TEST_DB_MODE").as_deref() {
        Err(_) | Ok("") | Ok("template") => DbMode::Template,
        Ok("cold") => DbMode::Cold,
        Ok(other) => panic!("ENCOMPUTE_TEST_DB_MODE must be `template` or `cold`, not `{other}`"),
    }
}

/// The admin URL, or `None` (skipped). A missing URL is a failure when
/// `ENCOMPUTE_REQUIRE_SERVICES` is set.
pub fn test_admin_url() -> Option<String> {
    match std::env::var("ENCOMPUTE_TEST_DATABASE_URL") {
        Ok(u) => Some(u),
        Err(_) if std::env::var("ENCOMPUTE_REQUIRE_SERVICES").is_ok() => {
            panic!("ENCOMPUTE_REQUIRE_SERVICES is set but ENCOMPUTE_TEST_DATABASE_URL is not")
        }
        Err(_) => {
            eprintln!("SKIPPED: set ENCOMPUTE_TEST_DATABASE_URL (a PostgreSQL account that may create databases)");
            None
        }
    }
}

/// `admin` with its database replaced by `name`.
pub fn url_for(admin: &str, name: &str) -> String {
    match admin.rsplit_once('/') {
        Some((base, _)) if admin.starts_with("postgres") => format!("{base}/{name}"),
        _ => format!("{admin} dbname={name}"),
    }
}

pub fn db_name(url: &str) -> String {
    url.rsplit('/').next().unwrap().to_owned()
}

fn connect(url: &str) -> postgres::Client {
    postgres::Client::connect(url, postgres::NoTls).expect("test database server")
}

fn is_in_use(e: &postgres::Error) -> bool {
    e.code() == Some(&postgres::error::SqlState::OBJECT_IN_USE)
}

/// Ends every session on `name` (the caller's own excepted). A dropped pool
/// closes its connections asynchronously, so this is retried around it.
fn terminate_sessions(c: &mut postgres::Client, name: &str) {
    let _ = c.execute(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
          WHERE datname = $1 AND pid <> pg_backend_pid()",
        &[&name],
    );
}

/// A name no other test, process or earlier run has. The process ID is
/// reused over time; the time and the counter are not.
pub fn unique_name(prefix: &str) -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    format!(
        "{prefix}_{}_{}_{}",
        std::process::id(),
        UNIQUE.fetch_add(1, Ordering::SeqCst),
        t.as_nanos() % 1_000_000_000_000
    )
}

// --- Teardown ------------------------------------------------------------------

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

/// Drops `name`, ending whatever sessions remain; retried, as a pool or a
/// spawned server can reconnect between the termination and the drop.
fn drop_database_hardened(admin: &str, name: &str) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 0..30u64 {
        let r = postgres::Client::connect(admin, postgres::NoTls)
            .map_err(|e| e.to_string())
            .and_then(|mut c| {
                terminate_sessions(&mut c, name);
                c.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                    .map_err(|e| e.to_string())
            });
        match r {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_millis(100 + 50 * attempt));
    }
    Err(last)
}

impl Drop for TestDatabases {
    fn drop(&mut self) {
        // Never panic here: a panicking thread-local destructor aborts.
        for name in self.names.iter().rev() {
            if let Err(e) = drop_database_hardened(&self.admin, name) {
                eprintln!("test database {name} not dropped: {e}");
            }
        }
    }
}

thread_local! {
    static CREATED: std::cell::RefCell<Option<TestDatabases>> = const { std::cell::RefCell::new(None) };
}

/// Drops database `name` when the current test ends.
pub fn drop_at_test_end(admin: &str, name: &str) {
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

// --- The template --------------------------------------------------------------

/// The name of the template for this migration set.
fn template_name(c: &mut postgres::Client) -> String {
    let mut set = format!("harness {TEMPLATE_REVISION}\n").into_bytes();
    for (v, name, sql) in MIGRATIONS {
        set.extend(format!("{v} {name} {} ", sql.len()).bytes());
        set.extend(sql.bytes());
        set.push(0);
    }
    let hash: String = c
        .query_one("SELECT left(encode(sha256($1), 'hex'), 16)", &[&set])
        .unwrap()
        .get(0);
    format!("{TEMPLATE_PREFIX}{hash}")
}

/// Builds the template when this server does not have it yet: migrated in a
/// scratch database, sealed (a template that accepts no connections), and
/// only then given its real name.
fn build_template(admin: &str) -> String {
    let mut c = connect(admin);
    let name = template_name(&mut c);
    c.execute("SELECT pg_advisory_lock($1)", &[&TEMPLATE_LOCK])
        .unwrap();
    let sealed: i64 = c
        .query_one(
            "SELECT count(*) FROM pg_database WHERE datname = $1 AND datistemplate AND NOT datallowconn",
            &[&name],
        )
        .unwrap()
        .get(0);
    if sealed == 0 {
        // The lock is held, so any scratch database is a build that died.
        let stale = c
            .query(
                "SELECT datname FROM pg_database WHERE datname LIKE 'encompute\\_test\\_build\\_%'",
                &[],
            )
            .unwrap();
        for row in stale {
            let old: String = row.get(0);
            c.batch_execute(&format!("DROP DATABASE IF EXISTS {old} WITH (FORCE)"))
                .unwrap();
        }
        let scratch = format!("encompute_test_build_{}", std::process::id());
        c.batch_execute(&format!("CREATE DATABASE {scratch}"))
            .unwrap();
        let db = Db::connect(&url_for(admin, &scratch)).expect("template database");
        let last = MIGRATIONS.last().unwrap().0;
        assert_eq!(db.migrate().unwrap(), last);
        assert_eq!(db.schema_version().unwrap(), last);
        drop(db);
        c.batch_execute(&format!(
            "ALTER DATABASE {scratch} WITH IS_TEMPLATE true ALLOW_CONNECTIONS false"
        ))
        .unwrap();
        let mut renamed = false;
        for _ in 0..100 {
            terminate_sessions(&mut c, &scratch);
            match c.batch_execute(&format!("ALTER DATABASE {scratch} RENAME TO {name}")) {
                Ok(()) => {
                    renamed = true;
                    break;
                }
                Err(e) if is_in_use(&e) => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => panic!("sealing the template: {e}"),
            }
        }
        assert!(renamed, "the template build database stayed in use");
    }
    let _ = c.execute("SELECT pg_advisory_unlock($1)", &[&TEMPLATE_LOCK]);
    name
}

/// The template's name (built once per process, once per server).
fn template(admin: &str) -> &'static str {
    static T: OnceLock<String> = OnceLock::new();
    T.get_or_init(|| build_template(admin))
}

/// Clones the template as `name`. Concurrent clones are fine; one that
/// meets a session on the template (none can connect) is retried.
fn clone_template(c: &mut postgres::Client, admin: &str, name: &str) {
    let tpl = template(admin);
    for _ in 0..100 {
        match c.batch_execute(&format!("CREATE DATABASE {name} TEMPLATE {tpl}")) {
            Ok(()) => return,
            Err(e) if is_in_use(&e) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("cloning the template: {e}"),
        }
    }
    panic!("the template stayed in use");
}

fn note_db_backed(name: &str) {
    use std::io::Write;
    if let Ok(path) = std::env::var("ENCOMPUTE_TEST_EXEC_LOG") {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(
                f,
                "{name} {}",
                std::thread::current().name().unwrap_or("unnamed")
            );
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    /// A clone in `template` mode, an empty database in `cold` mode.
    Mode,
    /// Always a clone of the template.
    Template,
    /// Always an empty database.
    Empty,
}

fn new_database(source: Source) -> Option<String> {
    let admin = test_admin_url()?;
    let name = unique_name("enc_test");
    assert!(!name.starts_with(TEMPLATE_PREFIX));
    // Connect first: the client's runtime must register its thread-local
    // before the cleanup does, or the cleanup would outlive it and could not
    // connect when the test ends (thread-locals are dropped in reverse).
    let mut c = connect(&admin);
    // Registered before creating: a failure half way still drops what was made.
    drop_at_test_end(&admin, &name);
    if source == Source::Template || (source == Source::Mode && mode() == DbMode::Template) {
        clone_template(&mut c, &admin, &name);
    } else {
        c.batch_execute(&format!("CREATE DATABASE {name}")).unwrap();
    }
    note_db_backed(&name);
    Some(url_for(&admin, &name))
}

/// A database for one test, or `None` (skipped): the current schema (a
/// template clone, or empty for the control plane to migrate in `cold`
/// mode). It is dropped when the test ends.
pub fn fresh_database() -> Option<String> {
    new_database(Source::Mode)
}

/// A clone of the template in either mode (tests of the template itself).
pub fn template_clone() -> Option<String> {
    new_database(Source::Template)
}

/// The template's name on `admin`'s server (built when missing).
pub fn template_database_name(admin: &str) -> &'static str {
    template(admin)
}

/// An empty database in either mode, for tests that exercise migrations:
/// they start from an older schema and must never get the current one.
pub fn unmigrated_database() -> Option<String> {
    new_database(Source::Empty)
}

// --- Directories ----------------------------------------------------------------

/// A new, empty directory for one test. Never a reused one: the process ID
/// repeats across runs, and a stale anchor left under a reused name made a
/// later test see another run's history. `create_dir` fails on an existing
/// directory, so the name is retried until it is new.
pub fn tmp_dir(tag: &str) -> PathBuf {
    for _ in 0..100 {
        let d = std::env::temp_dir().join(unique_name(&format!("encompute-control-{tag}")));
        match std::fs::create_dir(&d) {
            Ok(()) => return d,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("{}: {e}", d.display()),
        }
    }
    panic!("no unused temporary directory name");
}
