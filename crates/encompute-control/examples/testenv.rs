//! Readiness probes for the test runner (`scripts/test-full.sh`): never
//! shipped, never a test.
//!
//!     testenv postgres      the test database server answers, and the
//!                           account may create databases
//!     testenv migrations    the cold path: an empty database, created now,
//!                           is migrated to the latest schema by the control
//!                           plane's own migrations and dropped again
//!
//! Both read `ENCOMPUTE_TEST_DATABASE_URL`, print one line, and exit 0 on
//! success and 1 otherwise.

use std::process::ExitCode;
use std::time::Duration;

use encompute_control::db::{Db, MIGRATIONS};

fn admin() -> Result<postgres::Client, String> {
    let url = std::env::var("ENCOMPUTE_TEST_DATABASE_URL")
        .map_err(|_| "ENCOMPUTE_TEST_DATABASE_URL is not set".to_owned())?;
    let mut cfg: postgres::Config = url.parse().map_err(|e| format!("bad URL: {e}"))?;
    cfg.connect_timeout(Duration::from_secs(5));
    cfg.connect(postgres::NoTls)
        .map_err(|e| format!("cannot connect: {e}"))
}

fn postgres_ready() -> Result<String, String> {
    let mut c = admin()?;
    let v: String = c
        .query_one("SHOW server_version", &[])
        .map_err(|e| e.to_string())?
        .get(0);
    let can: bool = c
        .query_one(
            "SELECT rolcreatedb OR rolsuper FROM pg_roles WHERE rolname = current_user",
            &[],
        )
        .map_err(|e| e.to_string())?
        .get(0);
    if !can {
        return Err("the account may not create databases".into());
    }
    Ok(format!("PostgreSQL {v} answers"))
}

fn migrations_apply() -> Result<String, String> {
    let mut c = admin()?;
    let url = std::env::var("ENCOMPUTE_TEST_DATABASE_URL").unwrap();
    let name = format!(
        "enc_preflight_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % 1_000_000_000_000
    );
    c.batch_execute(&format!("CREATE DATABASE {name}"))
        .map_err(|e| e.to_string())?;
    let applied = (|| -> Result<i32, String> {
        let target = match url.rsplit_once('/') {
            Some((base, _)) => format!("{base}/{name}"),
            None => return Err("not a postgres:// URL".into()),
        };
        let db = Db::connect(&target).map_err(|e| e.to_string())?;
        let v = db.migrate().map_err(|e| e.to_string())?;
        let seen = db.schema_version().map_err(|e| e.to_string())?;
        if v != seen {
            return Err(format!("migrated to {v} but the schema says {seen}"));
        }
        Ok(v)
    })();
    let mut dropped = Err(String::new());
    for _ in 0..20 {
        dropped = c
            .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            .map_err(|e| e.to_string());
        if dropped.is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let v = applied?;
    dropped.map_err(|e| format!("cannot drop {name}: {e}"))?;
    let last = MIGRATIONS.last().unwrap().0;
    if v != last {
        return Err(format!("schema version {v}, expected {last}"));
    }
    Ok(format!(
        "{} migrations applied to an empty database (schema version {v})",
        MIGRATIONS.len()
    ))
}

fn main() -> ExitCode {
    let r = match std::env::args().nth(1).as_deref() {
        Some("postgres") => postgres_ready(),
        Some("migrations") => migrations_apply(),
        _ => Err("usage: testenv postgres|migrations".into()),
    };
    match r {
        Ok(m) => {
            println!("{m}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("{e}");
            ExitCode::FAILURE
        }
    }
}
