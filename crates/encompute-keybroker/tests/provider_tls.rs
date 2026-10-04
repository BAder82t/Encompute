//! The root-key provider client (OpenBao or Vault Transit) and its TLS
//! settings: a private CA (`BAO_CACERT`), a client certificate
//! (`BAO_CLIENT_CERT`, `BAO_CLIENT_KEY`), and the unchanged default.
//!
//! The provider is a stand-in HTTPS server in this process (it answers every
//! Transit call with a fixed ciphertext), so the test needs no services and
//! always runs. The settings are process environment variables, so one test
//! runs every case in order.

#[path = "../../encompute-control/tests/common/tlspki.rs"]
mod tlspki;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use encompute_keybroker::{OpenBaoTransit, RootKeyProvider};
use tlspki::{Ca, TempDir, Use};
use zeroize::Zeroizing;

/// An HTTPS server; `served` counts the requests it answered.
fn serve(config: Arc<rustls::ServerConfig>) -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let served = Arc::new(AtomicUsize::new(0));
    let count = served.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let (config, count) = (config.clone(), count.clone());
            std::thread::spawn(move || {
                let mut conn = rustls::ServerConnection::new(config).unwrap();
                let mut t = rustls::Stream::new(&mut conn, &mut s);
                // Read the request head, then its body.
                let mut buf = vec![];
                let mut chunk = [0u8; 1024];
                loop {
                    match t.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                    if let Some(h) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..h]).to_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if buf.len() >= h + 4 + len {
                            break;
                        }
                    }
                }
                let body = r#"{"data":{"ciphertext":"vault:v1:c3R1Yg=="}}"#;
                let _ = write!(
                    t,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = t.flush();
                count.fetch_add(1, Ordering::SeqCst);
                conn.send_close_notify();
                let _ = conn.complete_io(&mut s);
            });
        }
    });
    (port, served)
}

const NAMES: [&str; 6] = [
    "BAO_CACERT",
    "VAULT_CACERT",
    "BAO_CLIENT_CERT",
    "BAO_CLIENT_KEY",
    "VAULT_CLIENT_CERT",
    "VAULT_CLIENT_KEY",
];

fn clear() {
    for n in NAMES {
        std::env::remove_var(n);
    }
}

/// `encrypt` through a client built from the environment: the call's result,
/// or the error (from `from_env` or from the call), as text.
fn encrypt(port: u16, host: &str) -> Result<(String, u64), String> {
    std::env::set_var("BAO_ADDR", format!("https://{host}:{port}"));
    std::env::set_var("BAO_TOKEN", "t");
    let p = OpenBaoTransit::from_env("transit", "k").map_err(|e| e.to_string())?;
    p.encrypt(b"x", b"aad").map_err(|e| e.to_string())
}

#[test]
fn private_ca_and_client_certificate() {
    let ca: Ca = tlspki::ca("provider-ca");
    let other = tlspki::ca("other-ca");
    let clients = tlspki::ca("client-ca");
    let dir = TempDir::new("bao");
    let ca_file = dir.put("ca.pem", &ca.pem);
    let other_file = dir.put("other.pem", &other.pem);
    let empty_file = dir.put("empty.pem", "");
    let missing_file = dir.path("missing.pem");
    let bundle_file = dir.put("bundle.pem", &format!("{}{}", other.pem, ca.pem));

    let server_leaf = tlspki::leaf(&ca, &["localhost"], "openbao", Use::Server, false);
    let (port, served) = serve(tlspki::server_config(&server_leaf, None));
    let (mtls_port, mtls_served) = serve(tlspki::server_config(&server_leaf, Some(&clients)));
    let mine = tlspki::leaf(&clients, &[], "keybroker", Use::Client, false);
    let cert_file = dir.put("client.crt", &mine.cert_pem);
    let key_file = dir.put("client.key", &mine.key_pem);
    let theirs = tlspki::leaf(&other, &[], "keybroker", Use::Client, false);
    let bad_cert = dir.put("bad.crt", &theirs.cert_pem);
    let bad_key = dir.put("bad.key", &theirs.key_pem);

    // Nothing configured: the built-in public roots, as before; a private
    // CA's certificate is not trusted.
    clear();
    let e = encrypt(port, "localhost").unwrap_err();
    assert!(e.contains("UnknownIssuer"), "{e}");
    assert_eq!(served.load(Ordering::SeqCst), 0);

    // The private CA, by either name: the provider is reached.
    std::env::set_var("BAO_CACERT", &ca_file);
    assert_eq!(encrypt(port, "localhost").unwrap().1, 1);
    clear();
    std::env::set_var("VAULT_CACERT", &ca_file);
    assert_eq!(encrypt(port, "localhost").unwrap().1, 1);
    // A bundle of several CAs.
    clear();
    std::env::set_var("BAO_CACERT", &bundle_file);
    assert_eq!(encrypt(port, "localhost").unwrap().1, 1);

    // Another CA, or the right CA and the wrong host name: refused.
    clear();
    std::env::set_var("BAO_CACERT", &other_file);
    let e = encrypt(port, "localhost").unwrap_err();
    assert!(e.contains("UnknownIssuer"), "{e}");
    std::env::set_var("BAO_CACERT", &ca_file);
    let e = encrypt(port, "127.0.0.1").unwrap_err();
    assert!(e.contains("not valid for name"), "{e}");

    // The configured bundle REPLACES the public roots, and an unusable one
    // is an error: it is never ignored (that would be the system roots) or
    // treated as empty trust that "works".
    for f in [&empty_file, &missing_file] {
        clear();
        std::env::set_var("BAO_CACERT", f);
        let e = encrypt(port, "localhost").unwrap_err();
        assert!(e.contains(f.as_str()), "{f}: {e}");
    }

    // Mutual TLS: the server requires a client certificate.
    clear();
    std::env::set_var("BAO_CACERT", &ca_file);
    let before = mtls_served.load(Ordering::SeqCst);
    assert!(encrypt(mtls_port, "localhost").is_err());
    assert_eq!(mtls_served.load(Ordering::SeqCst), before);
    std::env::set_var("BAO_CLIENT_CERT", &cert_file);
    std::env::set_var("BAO_CLIENT_KEY", &key_file);
    assert_eq!(encrypt(mtls_port, "localhost").unwrap().1, 1);
    assert!(mtls_served.load(Ordering::SeqCst) > before);
    // A certificate from another CA is refused by the server.
    let before = mtls_served.load(Ordering::SeqCst);
    std::env::set_var("BAO_CLIENT_CERT", &bad_cert);
    std::env::set_var("BAO_CLIENT_KEY", &bad_key);
    assert!(encrypt(mtls_port, "localhost").is_err());
    assert_eq!(mtls_served.load(Ordering::SeqCst), before);
    // The certificate and its key come as a pair.
    std::env::remove_var("BAO_CLIENT_KEY");
    let e = encrypt(mtls_port, "localhost").unwrap_err();
    assert!(e.contains("BAO_CLIENT_KEY"), "{e}");
    // A client certificate alone (public roots) still does not trust the
    // private CA.
    clear();
    std::env::set_var("BAO_CLIENT_CERT", &cert_file);
    std::env::set_var("BAO_CLIENT_KEY", &key_file);
    let e = encrypt(port, "localhost").unwrap_err();
    assert!(e.contains("UnknownIssuer"), "{e}");

    // Constructed directly (tests, embedding): the settings are not read.
    clear();
    std::env::set_var("BAO_CACERT", &missing_file);
    assert!(OpenBaoTransit::new(
        "https://bao.internal:8200",
        "transit",
        "k",
        Zeroizing::new("t".into())
    )
    .is_ok());
    clear();
}
