//! TLS for the PostgreSQL client, from the connection string.
//!
//! The control plane honours the libpq parameters `sslmode`, `sslrootcert`,
//! `sslcert` and `sslkey` in `ENCOMPUTE_DATABASE_URL` (a URL or a
//! `key=value` string; the file values are paths, so the whole string can
//! stay in a mounted `*_FILE` secret):
//!
//! | `sslmode` | meaning |
//! |---|---|
//! | absent, `disable` | plaintext (what the control plane always did) |
//! | `prefer` | TLS if the server offers it, else plaintext; the server is not verified |
//! | `require` | TLS or fail; the server is not verified, unless `sslrootcert` is set, which makes it `verify-ca` (as in libpq) |
//! | `verify-ca` | TLS or fail; the certificate chain must lead to `sslrootcert` |
//! | `verify-full` | as `verify-ca`, and the certificate must be valid for the host name |
//!
//! `sslrootcert` is a PEM bundle that replaces the public roots, or the word
//! `system` for the built-in public web roots. `sslcert` and `sslkey` (both
//! or neither) are the client certificate chain and key for a server that
//! asks for one. rustls (the `ring` provider) does the TLS; no OpenSSL.

use std::path::{Path, PathBuf};

use encompute_ir::{Code, Error, Result};
use encompute_verification::tls::{client_config, Roots, Verify};

fn bad(msg: impl Into<String>) -> Error {
    Error::new(Code::InsecureConfiguration, msg)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SslMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

#[derive(Clone, Debug)]
pub struct PgTls {
    pub mode: SslMode,
    root: Option<String>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
}

impl PgTls {
    /// Whether the connection is certain to be encrypted (`prefer` can
    /// silently fall back to plaintext).
    pub fn enforces_tls(&self) -> bool {
        matches!(
            self.mode,
            SslMode::Require | SslMode::VerifyCa | SslMode::VerifyFull
        )
    }

    /// Whether the server's identity is checked.
    pub fn verifies_server(&self) -> bool {
        matches!(self.mode, SslMode::VerifyCa | SslMode::VerifyFull)
    }

    /// The rustls client for this setting. For plaintext it is never used
    /// (the driver does not ask for TLS); it still must be valid.
    pub fn connector(&self) -> Result<tokio_postgres_rustls::MakeRustlsConnect> {
        let (verify, roots_arg) = match self.mode {
            SslMode::Disable => (Verify::Full, None),
            SslMode::Prefer => (Verify::None, None),
            SslMode::Require => match &self.root {
                None => (Verify::None, None),
                Some(r) => (Verify::Chain, Some(r)),
            },
            SslMode::VerifyCa => (Verify::Chain, self.root.as_ref()),
            SslMode::VerifyFull => (Verify::Full, self.root.as_ref()),
        };
        let roots = match roots_arg {
            None => Roots::Public,
            Some(r) if r == "system" => Roots::Public,
            Some(r) => Roots::Bundle(Path::new(r)),
        };
        let client = match (&self.cert, &self.key) {
            (Some(c), Some(k)) => Some((c.as_path(), k.as_path())),
            _ => None,
        };
        let cfg = client_config(&roots, verify, client)?;
        Ok(tokio_postgres_rustls::MakeRustlsConnect::new(
            (*cfg).clone(),
        ))
    }

    /// The `postgres` driver's own mode: it must refuse plaintext whenever
    /// ours does.
    pub fn driver_mode(&self) -> postgres::config::SslMode {
        match self.mode {
            SslMode::Disable => postgres::config::SslMode::Disable,
            SslMode::Prefer => postgres::config::SslMode::Prefer,
            _ => postgres::config::SslMode::Require,
        }
    }
}

const KEYS: [&str; 4] = ["sslmode", "sslrootcert", "sslcert", "sslkey"];

/// Splits the TLS parameters off a connection string. The rest goes to the
/// driver's own parser, which rejects the `verify-*` modes and the file
/// parameters. A string this cannot read is returned unchanged with
/// plaintext settings: the driver's parser then reports the real error.
pub fn split(url: &str) -> Result<(String, PgTls)> {
    let pairs = if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        scan_url(url)
    } else {
        scan_kv(url)
    };
    let Some((rest, found)) = pairs else {
        return Ok((url.to_owned(), plain()));
    };
    let get = |k: &str| found.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let mode = match get("sslmode").as_deref() {
        None | Some("disable") => SslMode::Disable,
        Some("prefer") => SslMode::Prefer,
        Some("require") => SslMode::Require,
        Some("verify-ca") => SslMode::VerifyCa,
        Some("verify-full") => SslMode::VerifyFull,
        Some(other) => {
            return Err(bad(format!(
                "sslmode={other}: use disable, prefer, require, verify-ca or verify-full"
            )))
        }
    };
    let t = PgTls {
        mode,
        root: get("sslrootcert").filter(|v| !v.is_empty()),
        cert: get("sslcert").filter(|v| !v.is_empty()).map(Into::into),
        key: get("sslkey").filter(|v| !v.is_empty()).map(Into::into),
    };
    if t.cert.is_some() != t.key.is_some() && mode != SslMode::Disable {
        return Err(bad("set both sslcert and sslkey (or neither)"));
    }
    if t.verifies_server() && t.root.is_none() {
        return Err(bad(
            "sslmode=verify-ca/verify-full needs sslrootcert (a PEM file, or `system` for the public roots)",
        ));
    }
    Ok((rest, t))
}

fn plain() -> PgTls {
    PgTls {
        mode: SslMode::Disable,
        root: None,
        cert: None,
        key: None,
    }
}

fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = s.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

type Scanned = (String, Vec<(String, String)>);

fn scan_url(url: &str) -> Option<Scanned> {
    let Some((base, query)) = url.split_once('?') else {
        return Some((url.to_owned(), vec![]));
    };
    let (query, fragment) = match query.split_once('#') {
        Some((q, f)) => (q, Some(f)),
        None => (query, None),
    };
    let mut kept = vec![];
    let mut found = vec![];
    for part in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = part.split_once('=')?;
        if KEYS.contains(&k) {
            found.push((k.to_owned(), pct_decode(v)?));
        } else {
            kept.push(part);
        }
    }
    let mut rest = base.to_owned();
    if !kept.is_empty() {
        rest.push('?');
        rest.push_str(&kept.join("&"));
    }
    if let Some(f) = fragment {
        rest.push('#');
        rest.push_str(f);
    }
    Some((rest, found))
}

fn scan_kv(s: &str) -> Option<Scanned> {
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut kept = String::new();
    let mut found = vec![];
    loop {
        while i < c.len() && c[i].is_whitespace() {
            i += 1;
        }
        if i >= c.len() {
            break;
        }
        let start = i;
        while i < c.len() && c[i] != '=' && !c[i].is_whitespace() {
            i += 1;
        }
        let key: String = c[start..i].iter().collect();
        while i < c.len() && c[i].is_whitespace() {
            i += 1;
        }
        if i >= c.len() || c[i] != '=' {
            return None;
        }
        i += 1;
        while i < c.len() && c[i].is_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < c.len() && c[i] == '\'' {
            i += 1;
            loop {
                match c.get(i)? {
                    '\\' => {
                        value.push(*c.get(i + 1)?);
                        i += 2;
                    }
                    '\'' => {
                        i += 1;
                        break;
                    }
                    ch => {
                        value.push(*ch);
                        i += 1;
                    }
                }
            }
        } else {
            while i < c.len() && !c[i].is_whitespace() {
                if c[i] == '\\' {
                    value.push(*c.get(i + 1)?);
                    i += 2;
                } else {
                    value.push(c[i]);
                    i += 1;
                }
            }
        }
        if KEYS.contains(&key.as_str()) {
            found.push((key, value));
        } else {
            if !kept.is_empty() {
                kept.push(' ');
            }
            kept.extend(c[start..i].iter());
        }
    }
    Some((kept, found))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parameters_are_split_off() {
        let (rest, t) = split(
            "postgres://u:p@db.internal:5432/enc?connect_timeout=5&sslmode=verify-full&sslrootcert=/ca%20x.pem&sslcert=/c.pem&sslkey=/k.pem",
        )
        .unwrap();
        assert_eq!(
            rest,
            "postgres://u:p@db.internal:5432/enc?connect_timeout=5"
        );
        assert_eq!(t.mode, SslMode::VerifyFull);
        assert_eq!(t.root.as_deref(), Some("/ca x.pem"));
        assert!(rest.parse::<postgres::Config>().is_ok());
        let (rest, t) = split("postgres://u:p@db/enc?sslmode=require").unwrap();
        assert_eq!(rest, "postgres://u:p@db/enc");
        assert_eq!(t.mode, SslMode::Require);
        assert!(t.enforces_tls() && !t.verifies_server());
    }

    #[test]
    fn key_value_parameters_are_split_off() {
        let (rest, t) = split(
            "host=db user=u password='a b' sslmode = verify-ca  sslrootcert='/x y/ca.pem' dbname=enc",
        )
        .unwrap();
        assert_eq!(rest, "host=db user=u password='a b' dbname=enc");
        assert_eq!(t.mode, SslMode::VerifyCa);
        assert_eq!(t.root.as_deref(), Some("/x y/ca.pem"));
        assert!(rest.parse::<postgres::Config>().is_ok());
    }

    #[test]
    fn absent_means_plaintext_as_before() {
        for u in ["postgres://u:p@db/enc", "host=db user=u"] {
            let (rest, t) = split(u).unwrap();
            assert_eq!(rest, u);
            assert_eq!(t.mode, SslMode::Disable);
            assert!(!t.enforces_tls());
        }
    }

    #[test]
    fn incomplete_or_unknown_settings_are_refused() {
        for u in [
            "postgres://u:p@db/enc?sslmode=verify-full",
            "postgres://u:p@db/enc?sslmode=verify-ca",
            "postgres://u:p@db/enc?sslmode=allow",
            "postgres://u:p@db/enc?sslmode=require&sslcert=/c.pem",
            "host=db sslmode=verify-full",
        ] {
            assert!(split(u).is_err(), "{u}");
        }
    }

    #[test]
    fn unreadable_or_empty_trust_bundle_is_an_error() {
        let d = std::env::temp_dir().join(format!("pgtls-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let empty = d.join("empty.pem");
        std::fs::write(&empty, "").unwrap();
        for root in [
            empty.display().to_string(),
            d.join("missing.pem").display().to_string(),
        ] {
            let (_, t) = split(&format!(
                "postgres://u:p@db/enc?sslmode=verify-full&sslrootcert={root}"
            ))
            .unwrap();
            assert!(t.connector().is_err(), "{root}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
