//! PostgreSQL: the control plane's only store. Versioned migrations are
//! embedded in the binary and applied in order under an advisory lock; an
//! applied migration whose text changed is refused rather than re-run.

use postgres::{NoTls, Transaction};
use r2d2_postgres::PostgresConnectionManager;
use sha2::{Digest, Sha256};

use encompute_ir::{Code, Error, Result};
use encompute_verification::hex;

pub type Pool = r2d2::Pool<PostgresConnectionManager<NoTls>>;
pub type Conn = r2d2::PooledConnection<PostgresConnectionManager<NoTls>>;

/// Every migration, in order. Never edit one that has shipped: add another.
pub const MIGRATIONS: &[(i32, &str, &str)] =
    &[(1, "initial", include_str!("../migrations/0001_initial.sql"))];

/// Serializes migrations across control-plane replicas.
const MIGRATION_LOCK: i64 = 0x656e_636f_6d70_7574; // "encomput"

/// A database error, with PostgreSQL's message and SQLSTATE when there is one.
pub fn db_err<E: std::fmt::Display + 'static>(e: E) -> Error {
    let any: &dyn std::any::Any = &e;
    if let Some(pe) = any.downcast_ref::<postgres::Error>() {
        if let Some(d) = pe.as_db_error() {
            return Error::new(
                Code::Remote,
                format!("database: {} (SQLSTATE {})", d.message(), d.code().code()),
            );
        }
    }
    Error::new(Code::Remote, format!("database: {e}"))
}

/// Deadlocks and serialization failures: the transaction rolled back and
/// may simply run again.
fn retryable(e: &Error) -> bool {
    e.code == Code::Remote
        && (e.message.contains("SQLSTATE 40P01") || e.message.contains("SQLSTATE 40001"))
}

#[derive(Clone)]
pub struct Db {
    pool: Pool,
}

impl Db {
    pub fn connect(url: &str) -> Result<Self> {
        let config: postgres::Config = url.parse().map_err(db_err)?;
        let manager = PostgresConnectionManager::new(config, NoTls);
        let pool = r2d2::Pool::builder()
            .max_size(16)
            // Open connections on demand (r2d2 otherwise opens all of them).
            .min_idle(Some(1))
            .connection_timeout(std::time::Duration::from_secs(10))
            .build(manager)
            .map_err(db_err)?;
        Ok(Self { pool })
    }

    pub fn conn(&self) -> Result<Conn> {
        self.pool.get().map_err(db_err)
    }

    /// Runs `f` in a transaction, committing on `Ok`; retried (at most
    /// three times) when PostgreSQL aborts it for a deadlock or a
    /// serialization failure.
    pub fn tx<T>(&self, mut f: impl FnMut(&mut Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut attempt = 0;
        loop {
            let mut c = self.conn()?;
            let mut t = c.transaction().map_err(db_err)?;
            let r = f(&mut t).and_then(|out| t.commit().map_err(db_err).map(|_| out));
            match r {
                Err(e) if retryable(&e) && attempt < 3 => {
                    attempt += 1;
                    std::thread::sleep(std::time::Duration::from_millis(10 * attempt));
                }
                other => return other,
            }
        }
    }

    /// Applies pending migrations; returns the schema version.
    pub fn migrate(&self) -> Result<i32> {
        let mut c = self.conn()?;
        c.execute("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK])
            .map_err(db_err)?;
        let r = migrate_locked(&mut c);
        let _ = c.execute("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK]);
        r
    }

    /// The applied schema version; an error if the database is newer than
    /// this binary or any applied migration differs from ours.
    pub fn schema_version(&self) -> Result<i32> {
        let mut c = self.conn()?;
        check_applied(&mut c)
    }

    /// Whether the database answers (readiness).
    pub fn ping(&self) -> bool {
        self.conn()
            .and_then(|mut c| c.simple_query("SELECT 1").map_err(db_err))
            .is_ok()
    }
}

fn checksum(sql: &str) -> String {
    hex(&Sha256::digest(sql.as_bytes()))
}

fn check_applied(c: &mut Conn) -> Result<i32> {
    c.batch_execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version    INTEGER PRIMARY KEY,
             name       TEXT NOT NULL,
             checksum   TEXT NOT NULL,
             applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
    )
    .map_err(db_err)?;
    let rows = c
        .query(
            "SELECT version, checksum FROM schema_migrations ORDER BY version",
            &[],
        )
        .map_err(db_err)?;
    let mut version = 0;
    for r in rows {
        let v: i32 = r.get(0);
        let sum: String = r.get(1);
        let Some((_, name, sql)) = MIGRATIONS.iter().find(|m| m.0 == v) else {
            return Err(Error::new(
                Code::Incompatible,
                format!("the database schema (version {v}) is newer than this control plane"),
            ));
        };
        if checksum(sql) != sum {
            return Err(Error::new(
                Code::Incompatible,
                format!("applied migration {v} ({name}) differs from this release's"),
            ));
        }
        version = v;
    }
    Ok(version)
}

fn migrate_locked(c: &mut Conn) -> Result<i32> {
    let mut version = check_applied(c)?;
    for (v, name, sql) in MIGRATIONS {
        if *v <= version {
            continue;
        }
        let mut t = c.transaction().map_err(db_err)?;
        t.batch_execute(sql)
            .map_err(|e| db_err(format!("migration {v} ({name}): {e}")))?;
        t.execute(
            "INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
            &[v, name, &checksum(sql)],
        )
        .map_err(db_err)?;
        t.commit().map_err(db_err)?;
        version = *v;
    }
    Ok(version)
}
