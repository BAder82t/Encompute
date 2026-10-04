//! The control plane against a real TLS-enabled PostgreSQL that requires a
//! client certificate (`scripts/tls-test-db.sh up`), and the production-mode
//! refusal of a plaintext database connection, through the real binary.
//!
//! Skipped without the TLS server (`ENCOMPUTE_TEST_TLS_DATABASE`,
//! `ENCOMPUTE_TEST_TLS_DATABASE_PASSWORD`, `ENCOMPUTE_TEST_TLS_PKI`; print
//! them with `scripts/tls-test-db.sh env`) or the ordinary test database,
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`, where a skip is a failure. The
//! server's certificate is for the name `postgres` only: the tests reach it
//! as `host=postgres hostaddr=127.0.0.1` (the right name) and as `127.0.0.1`
//! (the wrong one). `database_tls_handshake.rs` covers the rest without a
//! server.

#![allow(clippy::unwrap_used)]

use std::process::Command;

use encompute_control::db::Db;

struct TlsPg {
    port: String,
    password: String,
    pki: String,
}

fn require() -> bool {
    std::env::var("ENCOMPUTE_REQUIRE_SERVICES").is_ok()
}

fn tls_pg() -> Option<TlsPg> {
    let get = |n: &str| std::env::var(n).ok();
    match (
        get("ENCOMPUTE_TEST_TLS_DATABASE"),
        get("ENCOMPUTE_TEST_TLS_DATABASE_PASSWORD"),
        get("ENCOMPUTE_TEST_TLS_PKI"),
    ) {
        (Some(addr), Some(password), Some(pki)) => Some(TlsPg {
            port: addr.rsplit(':').next().unwrap().to_owned(),
            password,
            pki,
        }),
        _ if require() => panic!(
            "ENCOMPUTE_REQUIRE_SERVICES is set but the TLS PostgreSQL is not configured \
             (scripts/tls-test-db.sh up; eval \"$(scripts/tls-test-db.sh env)\")"
        ),
        _ => {
            eprintln!("SKIPPED: no TLS PostgreSQL (scripts/tls-test-db.sh up)");
            None
        }
    }
}

impl TlsPg {
    fn conn(&self, host: &str, params: &str) -> String {
        format!(
            "host={host} hostaddr=127.0.0.1 port={} user=encompute password={} dbname=encompute {params}",
            self.port, self.password
        )
    }

    fn file(&self, name: &str) -> String {
        format!("{}/{name}", self.pki)
    }

    /// A verify-full connection string with the right CA and client
    /// certificate, to which `extra` is appended.
    fn good(&self, extra: &str) -> String {
        self.conn(
            "postgres",
            &format!(
                "sslmode=verify-full sslrootcert={} sslcert={} sslkey={} {extra}",
                self.file("internal-ca.crt"),
                self.file("pg-client.crt"),
                self.file("pg-client.key")
            ),
        )
    }
}

/// (ssl in use, the client certificate's subject) of a pooled connection.
fn ssl_state(db: &Db) -> (bool, Option<String>) {
    let mut c = db.conn().unwrap();
    let r = c
        .query_one(
            "SELECT ssl, client_dn FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
            &[],
        )
        .unwrap();
    (r.get(0), r.get(1))
}

fn err(conn: &str) -> String {
    match Db::connect(conn) {
        Ok(_) => panic!("{conn}: connected"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn verify_full_with_the_right_ca_and_client_certificate_connects() {
    let Some(pg) = tls_pg() else { return };
    let db = Db::connect(&pg.good("")).unwrap();
    let (ssl, dn) = ssl_state(&db);
    assert!(ssl, "the connection is not encrypted");
    assert!(
        dn.unwrap().contains("CN=encompute"),
        "no client certificate"
    );
    // The URL form works the same way.
    let url = format!(
        "postgres://encompute:{}@/encompute?host=postgres&hostaddr=127.0.0.1&port={}&sslmode=verify-full&sslrootcert={}&sslcert={}&sslkey={}",
        pg.password,
        pg.port,
        pg.file("internal-ca.crt"),
        pg.file("pg-client.crt"),
        pg.file("pg-client.key")
    );
    assert!(ssl_state(&Db::connect(&url).unwrap()).0);
}

#[test]
fn another_ca_or_the_wrong_host_name_is_refused() {
    let Some(pg) = tls_pg() else { return };
    let cert = pg.file("pg-client.crt");
    let key = pg.file("pg-client.key");
    // A CA that did not sign the server's certificate.
    let e = err(&pg.conn(
        "postgres",
        &format!(
            "sslmode=verify-full sslrootcert={} sslcert={cert} sslkey={key}",
            pg.file("edge-ca.crt")
        ),
    ));
    assert!(e.contains("UnknownIssuer"), "{e}");
    // The right CA, a name the certificate does not carry.
    let root = pg.file("internal-ca.crt");
    let e = err(&pg.conn(
        "127.0.0.1",
        &format!("sslmode=verify-full sslrootcert={root} sslcert={cert} sslkey={key}"),
    ));
    assert!(e.contains("not valid for name"), "{e}");
    // verify-ca does not check the name.
    let db = Db::connect(&pg.conn(
        "127.0.0.1",
        &format!("sslmode=verify-ca sslrootcert={root} sslcert={cert} sslkey={key}"),
    ))
    .unwrap();
    assert!(ssl_state(&db).0);
}

#[test]
fn the_server_requires_a_client_certificate_from_the_right_ca() {
    let Some(pg) = tls_pg() else { return };
    let root = pg.file("internal-ca.crt");
    // None presented.
    let e = err(&pg.conn(
        "postgres",
        &format!("sslmode=verify-full sslrootcert={root}"),
    ));
    assert!(e.contains("requires a valid client certificate"), "{e}");
    // One from a CA the server does not trust.
    let e = err(&pg.conn(
        "postgres",
        &format!(
            "sslmode=verify-full sslrootcert={root} sslcert={} sslkey={}",
            pg.file("ops-client.crt"),
            pg.file("ops-client.key")
        ),
    ));
    assert!(e.contains("UnknownCA"), "{e}");
}

#[test]
fn require_encrypts_and_a_ca_makes_it_verify() {
    let Some(pg) = tls_pg() else { return };
    let cc = format!(
        "sslcert={} sslkey={}",
        pg.file("pg-client.crt"),
        pg.file("pg-client.key")
    );
    let db = Db::connect(&pg.conn("postgres", &format!("sslmode=require {cc}"))).unwrap();
    assert!(ssl_state(&db).0);
    // With sslrootcert, as libpq: the chain is verified.
    let e = err(&pg.conn(
        "postgres",
        &format!(
            "sslmode=require sslrootcert={} {cc}",
            pg.file("edge-ca.crt")
        ),
    ));
    assert!(e.contains("UnknownIssuer"), "{e}");
}

#[test]
fn a_server_that_offers_no_tls_fails_when_tls_is_required() {
    let Some(admin) = test_admin_url() else {
        return;
    };
    // The ordinary test database is plaintext. `?sslmode=` goes on its URL.
    let sep = if admin.contains('?') { '&' } else { '?' };
    for mode in ["require", "verify-full&sslrootcert=system"] {
        let e = err(&format!("{admin}{sep}sslmode={mode}"));
        assert!(e.contains("does not support TLS"), "{mode}: {e}");
    }
    // Without sslmode it connects, in plaintext, as it always has.
    assert!(!ssl_state(&Db::connect(&admin).unwrap()).0);
}

fn test_admin_url() -> Option<String> {
    match std::env::var("ENCOMPUTE_TEST_DATABASE_URL") {
        Ok(u) => Some(u),
        Err(_) if require() => {
            panic!("ENCOMPUTE_REQUIRE_SERVICES is set but ENCOMPUTE_TEST_DATABASE_URL is not")
        }
        Err(_) => {
            eprintln!("SKIPPED: set ENCOMPUTE_TEST_DATABASE_URL");
            None
        }
    }
}

/// `encompute-control migrate` in production mode with `url` as the
/// connection string: (success, stdout, stderr).
fn migrate(url: &str, allow_plaintext: bool) -> (bool, String, String) {
    let dir = std::env::temp_dir().join(format!(
        "enc-prod-{}-{}",
        std::process::id(),
        url.len() + usize::from(allow_plaintext)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let url_file = dir.join("db-url");
    std::fs::write(&url_file, url).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_encompute-control"));
    c.env_clear()
        .env("ENCOMPUTE_ENV", "production")
        .env("ENCOMPUTE_DATABASE_URL_FILE", &url_file)
        .env("ENCOMPUTE_OIDC_ISSUER", "https://idp.example")
        .env("ENCOMPUTE_OIDC_AUDIENCE", "encompute")
        .env("ENCOMPUTE_SIGNING_KEY_FILE", dir.join("unused-key"))
        .env("ENCOMPUTE_ANCHOR_DIR", &dir)
        .arg("migrate");
    if allow_plaintext {
        c.env("ENCOMPUTE_ALLOW_PLAINTEXT_DATABASE", "true");
    }
    let o = c.output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn production_mode_refuses_a_plaintext_database_unless_opted_out() {
    let Some(admin) = test_admin_url() else {
        return;
    };
    // A database and a role with a strong password (production refuses the
    // test server's default credentials).
    let mut c = postgres::Client::connect(&admin, postgres::NoTls).unwrap();
    let suffix = format!(
        "{}_{}",
        std::process::id(),
        std::time::UNIX_EPOCH.elapsed().unwrap().as_nanos()
    );
    let (role, name, pw) = (
        format!("tls_role_{suffix}"),
        format!("tls_prod_{suffix}"),
        format!("Xk3-{suffix}-long-random"),
    );
    c.batch_execute(&format!("CREATE ROLE {role} LOGIN PASSWORD '{pw}'"))
        .unwrap();
    c.batch_execute(&format!("CREATE DATABASE {name} OWNER {role}"))
        .unwrap();
    let cfg: postgres::Config = admin.parse().unwrap();
    let host = match &cfg.get_hosts()[0] {
        postgres::config::Host::Tcp(h) => h.clone(),
        _ => panic!("the test database must be reached over TCP"),
    };
    let port = cfg.get_ports()[0];
    let plain = format!("postgres://{role}:{pw}@{host}:{port}/{name}");

    let (ok, _, stderr) = migrate(&plain, false);
    assert!(!ok && stderr.contains("plaintext database"), "{stderr}");
    for q in ["?sslmode=disable", "?sslmode=prefer"] {
        let (ok, _, stderr) = migrate(&format!("{plain}{q}"), false);
        assert!(
            !ok && stderr.contains("plaintext database"),
            "{q}: {stderr}"
        );
    }
    // The explicit opt-out: it starts, and says so loudly.
    let (ok, stdout, stderr) = migrate(&plain, true);
    assert!(ok && stdout.contains("schema version"), "{stdout} {stderr}");
    assert!(stderr.contains("database_plaintext_allowed"), "{stderr}");
    // TLS enforced, but this server has none: refused by the client, with
    // no opt-out needed to get that far.
    let (ok, _, stderr) = migrate(&format!("{plain}?sslmode=require"), false);
    assert!(!ok && stderr.contains("does not support TLS"), "{stderr}");

    let _ = c.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"));
    let _ = c.batch_execute(&format!("DROP ROLE IF EXISTS {role}"));
}

#[test]
fn production_mode_runs_over_verify_full_with_a_client_certificate() {
    let Some(pg) = tls_pg() else { return };
    let (ok, stdout, stderr) = migrate(&pg.good(""), false);
    assert!(ok && stdout.contains("schema version"), "{stdout} {stderr}");
    assert!(!stderr.contains("database_plaintext_allowed"), "{stderr}");
}
