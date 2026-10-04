//! The control plane's PostgreSQL client against a stand-in server that
//! speaks just enough of the protocol (the SSL request and the TLS
//! handshake) to show what the client accepts, refuses and presents. It
//! needs no database and always runs; `database_tls.rs` repeats the
//! essential cases against a real TLS-enabled PostgreSQL.
//!
//! Every failure case asserts the TLS reason in the error (an unknown
//! issuer, an expired certificate, a name mismatch, a server without TLS),
//! not merely that the connection failed.

#[path = "common/tlspki.rs"]
mod tlspki;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use encompute_control::db::Db;
use rustls::pki_types::CertificateDer;
use rustls::{ServerConfig, ServerConnection};
use tlspki::{Ca, TempDir, Use};

#[derive(Debug, Clone, PartialEq)]
enum Seen {
    /// The client began TLS and the handshake completed; the client's
    /// certificate chain, if it sent one.
    Tls(Option<Vec<Vec<u8>>>),
    /// The client began TLS and the server refused the handshake.
    TlsFailed(String),
    /// The client sent a startup message without TLS.
    Plaintext,
}

struct FakePg {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl FakePg {
    /// `tls: None` is a server without TLS (it answers the SSL request `N`).
    fn start(tls: Option<Arc<ServerConfig>>) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(vec![]));
        let log = seen.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(s) = s else { continue };
                let (tls, log) = (tls.clone(), log.clone());
                std::thread::spawn(move || serve(s, tls, &log));
            }
        });
        Self { port, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn serve(mut s: TcpStream, tls: Option<Arc<ServerConfig>>, log: &Mutex<Vec<Seen>>) {
    let mut head = [0u8; 8];
    if s.read_exact(&mut head).is_err() {
        return;
    }
    // SSLRequest: length 8, code 80877103.
    if head != [0, 0, 0, 8, 4, 210, 22, 47] {
        log.lock().unwrap().push(Seen::Plaintext);
        return;
    }
    let Some(cfg) = tls else {
        let _ = s.write_all(b"N");
        // A client that falls back sends its startup message next.
        let mut next = [0u8; 4];
        if s.read_exact(&mut next).is_ok() {
            log.lock().unwrap().push(Seen::Plaintext);
        }
        return;
    };
    let _ = s.write_all(b"S");
    let mut conn = ServerConnection::new(cfg).unwrap();
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(&mut s) {
            log.lock().unwrap().push(Seen::TlsFailed(e.to_string()));
            return;
        }
    }
    let certs = conn
        .peer_certificates()
        .map(|c| c.iter().map(|d: &CertificateDer<'_>| d.to_vec()).collect());
    log.lock().unwrap().push(Seen::Tls(certs));
    // The startup message follows; then hang up.
    let mut stream = rustls::Stream::new(&mut conn, &mut s);
    let mut buf = [0u8; 64];
    let _ = stream.read(&mut buf);
}

/// Connects (and fails: nothing here is a database) and returns the error.
fn connect_err(conn: &str) -> String {
    match Db::connect(conn) {
        Ok(_) => panic!("{conn}: connected to a stand-in server"),
        Err(e) => e.to_string(),
    }
}

struct Fixture {
    dir: TempDir,
    ca: Ca,
}

impl Fixture {
    fn new() -> Self {
        let ca = tlspki::ca("db-ca");
        let dir = TempDir::new("pg");
        dir.put("ca.pem", &ca.pem);
        Self { dir, ca }
    }

    /// A key=value connection string for `host` (the name that is verified)
    /// on the stand-in's port, always dialling 127.0.0.1.
    fn conn(&self, port: u16, host: &str, params: &str) -> String {
        format!(
            "host={host} hostaddr=127.0.0.1 port={port} user=encompute password=Xk3long dbname=encompute {params}"
        )
    }

    fn ca_path(&self) -> String {
        self.dir.path("ca.pem")
    }
}

#[test]
fn verify_full_checks_chain_and_host_name_and_expiry() {
    let f = Fixture::new();
    let good = tlspki::leaf(&f.ca, &["db.internal"], "db", Use::Server, false);
    let srv = FakePg::start(Some(tlspki::server_config(&good, None)));
    let root = f.ca_path();

    // The right CA and the right name: the TLS handshake completes (the
    // stand-in then hangs up, so the connection as a whole still fails, but
    // not for a certificate reason).
    let e = connect_err(&f.conn(
        srv.port,
        "db.internal",
        &format!("sslmode=verify-full sslrootcert={root}"),
    ));
    assert!(!e.contains("invalid peer certificate"), "{e}");
    assert!(
        srv.seen().iter().any(|s| matches!(s, Seen::Tls(_))),
        "{:?}",
        srv.seen()
    );

    // The wrong host name: refused by verify-full...
    let before = srv.seen().len();
    let e = connect_err(&f.conn(
        srv.port,
        "other.internal",
        &format!("sslmode=verify-full sslrootcert={root}"),
    ));
    assert!(e.contains("not valid for name"), "{e}");
    // ...but accepted by verify-ca, which checks the chain only.
    let _ = connect_err(&f.conn(
        srv.port,
        "other.internal",
        &format!("sslmode=verify-ca sslrootcert={root}"),
    ));
    assert!(srv.seen()[before..]
        .iter()
        .any(|s| matches!(s, Seen::Tls(_))));
}

#[test]
fn a_certificate_from_another_ca_is_refused() {
    let f = Fixture::new();
    let theirs = tlspki::ca("someone else");
    let leaf = tlspki::leaf(&theirs, &["db.internal"], "db", Use::Server, false);
    let srv = FakePg::start(Some(tlspki::server_config(&leaf, None)));
    let root = f.ca_path();
    for mode in ["verify-full", "verify-ca"] {
        let e = connect_err(&f.conn(
            srv.port,
            "db.internal",
            &format!("sslmode={mode} sslrootcert={root}"),
        ));
        assert!(e.contains("UnknownIssuer"), "{mode}: {e}");
    }
    // `require` with a CA verifies the chain too (as libpq does).
    let e = connect_err(&f.conn(
        srv.port,
        "db.internal",
        &format!("sslmode=require sslrootcert={root}"),
    ));
    assert!(e.contains("UnknownIssuer"), "{e}");
}

#[test]
fn an_expired_certificate_is_refused() {
    let f = Fixture::new();
    let leaf = tlspki::leaf(&f.ca, &["db.internal"], "db", Use::Server, true);
    let srv = FakePg::start(Some(tlspki::server_config(&leaf, None)));
    let root = f.ca_path();
    for mode in ["verify-full", "verify-ca"] {
        let e = connect_err(&f.conn(
            srv.port,
            "db.internal",
            &format!("sslmode={mode} sslrootcert={root}"),
        ));
        assert!(e.contains("certificate expired"), "{mode}: {e}");
    }
}

#[test]
fn require_without_a_ca_encrypts_but_does_not_verify() {
    let f = Fixture::new();
    // A certificate nobody here trusts, expired, for another name: `require`
    // still talks TLS to it. That is the documented weakness of `require`.
    let theirs = tlspki::ca("unknown");
    let leaf = tlspki::leaf(&theirs, &["elsewhere"], "x", Use::Server, true);
    let srv = FakePg::start(Some(tlspki::server_config(&leaf, None)));
    let _ = connect_err(&f.conn(srv.port, "db.internal", "sslmode=require"));
    assert!(srv.seen().iter().any(|s| matches!(s, Seen::Tls(_))));
    assert!(!srv.seen().contains(&Seen::Plaintext));
}

#[test]
fn a_server_without_tls_fails_when_tls_is_required() {
    let f = Fixture::new();
    let srv = FakePg::start(None);
    let root = f.ca_path();
    for params in [
        format!("sslmode=verify-full sslrootcert={root}"),
        format!("sslmode=verify-ca sslrootcert={root}"),
        "sslmode=require".to_owned(),
    ] {
        let e = connect_err(&f.conn(srv.port, "db.internal", &params));
        assert!(e.contains("does not support TLS"), "{params}: {e}");
    }
    // Nothing was ever sent in plaintext: the startup message (with the
    // user name) is withheld when TLS is required.
    assert!(!srv.seen().contains(&Seen::Plaintext), "{:?}", srv.seen());
}

#[test]
fn without_sslmode_the_connection_is_plaintext_as_before() {
    let f = Fixture::new();
    let srv = FakePg::start(None);
    let _ = connect_err(&f.conn(srv.port, "db.internal", ""));
    let _ = connect_err(&f.conn(srv.port, "db.internal", "sslmode=disable"));
    let seen = srv.seen();
    assert!(
        !seen.is_empty() && seen.iter().all(|s| *s == Seen::Plaintext),
        "{seen:?}"
    );
    // `prefer` asks for TLS, is told no, and falls back (the documented
    // weakness of `prefer`).
    let srv = FakePg::start(None);
    let _ = connect_err(&f.conn(srv.port, "db.internal", "sslmode=prefer"));
    assert!(srv.seen().contains(&Seen::Plaintext), "{:?}", srv.seen());
}

#[test]
fn a_client_certificate_is_presented_and_can_be_required() {
    let f = Fixture::new();
    let clients = tlspki::ca("client-ca");
    let server = tlspki::leaf(&f.ca, &["db.internal"], "db", Use::Server, false);
    let srv = FakePg::start(Some(tlspki::server_config(&server, Some(&clients))));
    let root = f.ca_path();
    let base = format!("sslmode=verify-full sslrootcert={root}");

    // No client certificate: the server refuses the handshake.
    let before = srv.seen().len();
    let _ = connect_err(&f.conn(srv.port, "db.internal", &base));
    let after = srv.seen();
    assert!(
        after[before..]
            .iter()
            .all(|s| matches!(s, Seen::TlsFailed(_))),
        "{after:?}"
    );
    assert!(after[before..]
        .iter()
        .any(|s| matches!(s, Seen::TlsFailed(_))));

    // A certificate from the right CA: presented, and the handshake completes.
    let mine = tlspki::leaf(&clients, &[], "encompute", Use::Client, false);
    let cert = f.dir.put("client.crt", &mine.cert_pem);
    let key = f.dir.put("client.key", &mine.key_pem);
    let before = srv.seen().len();
    let _ = connect_err(&f.conn(
        srv.port,
        "db.internal",
        &format!("{base} sslcert={cert} sslkey={key}"),
    ));
    let seen = srv.seen();
    let presented: Vec<_> = seen[before..]
        .iter()
        .filter_map(|s| match s {
            Seen::Tls(Some(c)) => Some(c.clone()),
            _ => None,
        })
        .collect();
    assert!(!presented.is_empty(), "{seen:?}");
    assert_eq!(presented[0][0], mine.chain[0].to_vec());

    // A certificate from another CA: the server refuses it.
    let others = tlspki::ca("other-client-ca");
    let bad = tlspki::leaf(&others, &[], "encompute", Use::Client, false);
    let cert = f.dir.put("bad.crt", &bad.cert_pem);
    let key = f.dir.put("bad.key", &bad.key_pem);
    let before = srv.seen().len();
    let _ = connect_err(&f.conn(
        srv.port,
        "db.internal",
        &format!("{base} sslcert={cert} sslkey={key}"),
    ));
    assert!(srv.seen()[before..]
        .iter()
        .all(|s| matches!(s, Seen::TlsFailed(_))));
}

#[test]
fn an_unusable_trust_bundle_fails_loudly_and_never_falls_back() {
    let f = Fixture::new();
    let srv = FakePg::start(None);
    let empty = f.dir.put("empty.pem", "");
    let junk = f.dir.put("junk.pem", "not a certificate\n");
    let missing = f.dir.path("missing.pem");
    for root in [&empty, &junk, &missing] {
        for mode in ["verify-full", "verify-ca", "require"] {
            let e = connect_err(&f.conn(
                srv.port,
                "db.internal",
                &format!("sslmode={mode} sslrootcert={root}"),
            ));
            assert!(e.contains(root.as_str()), "{mode} {root}: {e}");
        }
    }
    // The verifying modes have nothing to trust without sslrootcert.
    let e = connect_err(&f.conn(srv.port, "db.internal", "sslmode=verify-full"));
    assert!(e.contains("sslrootcert"), "{e}");
    // Nothing reached the server: the client never dialled.
    assert!(srv.seen().is_empty(), "{:?}", srv.seen());
}
