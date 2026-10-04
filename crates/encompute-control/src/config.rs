//! Configuration, from the environment only.
//!
//! Secrets are injected as environment variables or, preferably, mounted
//! files (`*_FILE`); never command-line arguments (visible in process
//! lists) and never config files in a repository.
//!
//! `ENCOMPUTE_ENV` must say `production` or `development`: an unset or
//! misspelt value refuses to start rather than meaning development.
//! `ENCOMPUTE_ENV=production` fails closed: it refuses development tokens,
//! a development state anchor, missing signing keys, default database
//! credentials, a plaintext database connection (see below), and plain-HTTP
//! identity providers, and serves `/metrics` only to a scraper presenting
//! the metrics token (unless told otherwise).
//!
//! The database connection is encrypted by the connection string itself
//! (`sslmode`, `sslrootcert`, `sslcert`, `sslkey`: see `pgtls`). Production
//! mode requires `sslmode=verify-full` (chain and host name). Weaker settings
//! are downgrades with their own, independent opt-outs, each logging a
//! warning at every start: `ENCOMPUTE_ALLOW_UNVERIFIED_DATABASE_TLS=true`
//! admits `verify-ca` and `require`; `ENCOMPUTE_ALLOW_PLAINTEXT_DATABASE=true`
//! admits `disable`, `prefer` and an absent `sslmode` (insecure; for
//! migration or emergencies). A unix-socket host is exempt.

use std::path::PathBuf;

use zeroize::Zeroizing;

use encompute_ir::{Code, Error, Result};

use crate::log::LogLine;

fn insecure(msg: impl Into<String>) -> Error {
    Error::new(Code::InsecureConfiguration, msg)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Env {
    Production,
    Development,
}

impl Env {
    pub fn is_production(self) -> bool {
        self == Env::Production
    }
}

/// An OpenID Connect issuer whose ID tokens the control plane accepts.
#[derive(Clone, Debug)]
pub struct OidcIssuer {
    pub issuer: String,
    pub audience: String,
    /// Where to fetch the JSON Web Key Set (usually `{issuer}/.well-known/jwks.json`
    /// via discovery); or a local JWKS file.
    pub jwks: JwksSource,
}

#[derive(Clone, Debug)]
pub enum JwksSource {
    Url(String),
    File(PathBuf),
    Inline(String),
}

/// Where the state anchor (signed privacy and audit roots) lives: outside
/// the database, so restoring an old database backup cannot roll it back.
#[derive(Clone, Debug)]
pub enum AnchorConfig {
    /// A directory on a separate volume.
    Dir(PathBuf),
    /// OpenBao/Vault KV v2 with check-and-set versions.
    OpenBaoKv {
        addr: String,
        mount: String,
        path: String,
        token: Zeroizing<String>,
    },
}

/// Who may read `GET /metrics`.
#[derive(Clone)]
pub enum MetricsAccess {
    /// Anyone who reaches the port (expose it on an internal network only).
    Public,
    /// Scrapers presenting `Authorization: Bearer <token>`.
    Token(Zeroizing<String>),
    /// Nobody (production without a metrics token or an explicit opt-in).
    Closed,
}

impl std::fmt::Debug for MetricsAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MetricsAccess::Public => "Public",
            MetricsAccess::Token(_) => "Token",
            MetricsAccess::Closed => "Closed",
        })
    }
}

impl MetricsAccess {
    /// The default: public in development, closed in production.
    pub fn default_for(env: Env) -> Self {
        if env.is_production() {
            MetricsAccess::Closed
        } else {
            MetricsAccess::Public
        }
    }
}

pub struct Config {
    pub env: Env,
    pub listen: String,
    /// This service's ID (the recipient name in signed requests).
    pub service_id: String,
    pub database_url: Zeroizing<String>,
    /// `ENCOMPUTE_ALLOW_PLAINTEXT_DATABASE=true`: production mode may use a
    /// database connection that is not TLS-enforced.
    pub allow_plaintext_database: bool,
    /// `ENCOMPUTE_ALLOW_UNVERIFIED_DATABASE_TLS=true`: production mode may
    /// use `sslmode=verify-ca` or `require` (TLS without host-name or server
    /// verification). Independent of the plaintext opt-out.
    pub allow_unverified_database_tls: bool,
    /// The control plane's signing key seed (job grants, audit
    /// checkpoints, anchors, messages).
    pub signing_key_file: Option<PathBuf>,
    pub oidc: Vec<OidcIssuer>,
    /// Development tokens (HS256 from this secret). Refused in production.
    pub dev_token_secret: Option<Zeroizing<String>>,
    pub anchor: AnchorConfig,
    /// Audit checkpoint every this many events.
    pub audit_checkpoint_every: u64,
    /// The longest identity token lifetime (`exp - iat`) accepted.
    pub max_token_lifetime_secs: u64,
    /// Who may read `/metrics`.
    pub metrics: MetricsAccess,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("env", &self.env)
            .field("listen", &self.listen)
            .field("service_id", &self.service_id)
            .field("oidc", &self.oidc)
            .finish_non_exhaustive()
    }
}

/// A secret from `NAME_FILE` (preferred) or `NAME`.
pub fn secret(name: &str) -> Result<Option<Zeroizing<String>>> {
    if let Ok(f) = std::env::var(format!("{name}_FILE")) {
        let s =
            std::fs::read_to_string(&f).map_err(|e| insecure(format!("{name}_FILE={f}: {e}")))?;
        return Ok(Some(Zeroizing::new(s.trim().to_owned())));
    }
    Ok(std::env::var(name).ok().map(Zeroizing::new))
}

const DEFAULT_PASSWORDS: [&str; 8] = [
    "postgres",
    "password",
    "encompute",
    "changeme",
    "admin",
    "secret",
    "test",
    "encompute-test",
];

/// The password of a connection string, as the database driver itself
/// reads it (`postgres://user:password@host/db`, a `?password=` query
/// parameter, percent-encoding, or `key=value` with quoting).
fn db_password(url: &str) -> Result<Option<String>> {
    let (rest, _) = crate::pgtls::split(url)?;
    let c: postgres::Config = rest
        .parse()
        .map_err(|_| insecure("ENCOMPUTE_DATABASE_URL is not a valid connection string"))?;
    Ok(c.get_password()
        .map(|p| String::from_utf8_lossy(p).into_owned()))
}

impl Config {
    pub fn from_env() -> Result<Self> {
        // Explicit only: an unset variable must not silently mean the
        // mode without production's checks.
        let env = match std::env::var("ENCOMPUTE_ENV").as_deref() {
            Ok("production") => Env::Production,
            Ok("development") => Env::Development,
            Ok(other) => {
                return Err(insecure(format!(
                    "ENCOMPUTE_ENV={other}: use production or development"
                )))
            }
            Err(_) => {
                return Err(insecure(
                    "set ENCOMPUTE_ENV to production (or development, for local trials only)",
                ))
            }
        };
        let database_url = secret("ENCOMPUTE_DATABASE_URL")?.ok_or_else(|| {
            insecure("set ENCOMPUTE_DATABASE_URL_FILE (or ENCOMPUTE_DATABASE_URL)")
        })?;
        let mut oidc = vec![];
        if let Ok(issuer) = std::env::var("ENCOMPUTE_OIDC_ISSUER") {
            let audience = std::env::var("ENCOMPUTE_OIDC_AUDIENCE")
                .map_err(|_| insecure("ENCOMPUTE_OIDC_AUDIENCE is required with an issuer"))?;
            let jwks = if let Ok(f) = std::env::var("ENCOMPUTE_OIDC_JWKS_FILE") {
                JwksSource::File(f.into())
            } else {
                JwksSource::Url(
                    std::env::var("ENCOMPUTE_OIDC_JWKS_URL").unwrap_or_else(|_| {
                        format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/'))
                    }),
                )
            };
            oidc.push(OidcIssuer {
                issuer,
                audience,
                jwks,
            });
        }
        let anchor = if let Ok(addr) = std::env::var("ENCOMPUTE_ANCHOR_BAO_ADDR") {
            AnchorConfig::OpenBaoKv {
                addr,
                mount: std::env::var("ENCOMPUTE_ANCHOR_BAO_MOUNT")
                    .unwrap_or_else(|_| "secret".into()),
                path: std::env::var("ENCOMPUTE_ANCHOR_BAO_PATH")
                    .unwrap_or_else(|_| "encompute/control-anchor".into()),
                token: secret("ENCOMPUTE_ANCHOR_BAO_TOKEN")?
                    .ok_or_else(|| insecure("set ENCOMPUTE_ANCHOR_BAO_TOKEN_FILE"))?,
            }
        } else {
            AnchorConfig::Dir(
                std::env::var("ENCOMPUTE_ANCHOR_DIR")
                    .map_err(|_| insecure("set ENCOMPUTE_ANCHOR_DIR or ENCOMPUTE_ANCHOR_BAO_ADDR"))?
                    .into(),
            )
        };
        let c = Config {
            env,
            listen: std::env::var("ENCOMPUTE_LISTEN").unwrap_or_else(|_| "127.0.0.1:8770".into()),
            service_id: std::env::var("ENCOMPUTE_SERVICE_ID")
                .unwrap_or_else(|_| "control-plane".into()),
            database_url,
            allow_plaintext_database: match std::env::var("ENCOMPUTE_ALLOW_PLAINTEXT_DATABASE")
                .as_deref()
            {
                Ok("true") => true,
                Ok("false") | Err(_) => false,
                Ok(other) => {
                    return Err(insecure(format!(
                        "ENCOMPUTE_ALLOW_PLAINTEXT_DATABASE={other}: use true or false"
                    )))
                }
            },
            allow_unverified_database_tls: match std::env::var(
                "ENCOMPUTE_ALLOW_UNVERIFIED_DATABASE_TLS",
            )
            .as_deref()
            {
                Ok("true") => true,
                Ok("false") | Err(_) => false,
                Ok(other) => {
                    return Err(insecure(format!(
                        "ENCOMPUTE_ALLOW_UNVERIFIED_DATABASE_TLS={other}: use true or false"
                    )))
                }
            },
            signing_key_file: std::env::var("ENCOMPUTE_SIGNING_KEY_FILE")
                .ok()
                .map(Into::into),
            oidc,
            dev_token_secret: secret("ENCOMPUTE_DEV_TOKEN_SECRET")?,
            anchor,
            audit_checkpoint_every: std::env::var("ENCOMPUTE_AUDIT_CHECKPOINT_EVERY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            max_token_lifetime_secs: match std::env::var("ENCOMPUTE_MAX_TOKEN_LIFETIME_SECS") {
                Ok(v) => v.parse().ok().filter(|n| *n > 0).ok_or_else(|| {
                    insecure(
                        "ENCOMPUTE_MAX_TOKEN_LIFETIME_SECS must be a positive number of seconds",
                    )
                })?,
                Err(_) => crate::authn::DEFAULT_MAX_TOKEN_LIFETIME_SECS,
            },
            metrics: match (
                secret("ENCOMPUTE_METRICS_TOKEN")?,
                std::env::var("ENCOMPUTE_METRICS_PUBLIC").as_deref(),
            ) {
                (Some(t), _) if !t.is_empty() => MetricsAccess::Token(t),
                (_, Ok("true")) => MetricsAccess::Public,
                (_, Ok("false")) | (_, Err(_)) => MetricsAccess::default_for(env),
                (_, Ok(other)) => {
                    return Err(insecure(format!(
                        "ENCOMPUTE_METRICS_PUBLIC={other}: use true or false"
                    )))
                }
            },
        };
        c.validate()?;
        Ok(c)
    }

    /// Production mode refuses every insecure fallback.
    pub fn validate(&self) -> Result<()> {
        encompute_verification::service::check_service_id(&self.service_id)
            .map_err(|e| insecure(e.message))?;
        if !self.env.is_production() {
            return Ok(());
        }
        if self.dev_token_secret.is_some() {
            return Err(insecure(
                "production mode refuses development tokens: unset ENCOMPUTE_DEV_TOKEN_SECRET",
            ));
        }
        if self.oidc.is_empty() {
            return Err(insecure(
                "production mode needs an OIDC issuer (ENCOMPUTE_OIDC_ISSUER, ENCOMPUTE_OIDC_AUDIENCE)",
            ));
        }
        for o in &self.oidc {
            if !o.issuer.starts_with("https://") {
                return Err(insecure(format!("OIDC issuer {} must use https", o.issuer)));
            }
            if let JwksSource::Url(u) = &o.jwks {
                if !u.starts_with("https://") {
                    return Err(insecure(format!("JWKS URL {u} must use https")));
                }
            }
        }
        if self.signing_key_file.is_none() {
            return Err(insecure(
                "production mode needs a persistent signing key (ENCOMPUTE_SIGNING_KEY_FILE, a mounted secret)",
            ));
        }
        match db_password(&self.database_url)? {
            None => {}
            Some(p) if p.is_empty() || DEFAULT_PASSWORDS.contains(&p.as_str()) => {
                return Err(insecure(
                    "production mode refuses default or empty database credentials",
                ))
            }
            Some(_) => {}
        }
        if let AnchorConfig::OpenBaoKv { addr, .. } = &self.anchor {
            if !addr.starts_with("https://") {
                return Err(insecure(format!("anchor store {addr} must use https")));
            }
        }
        self.check_database_transport()
    }

    /// Production: the database connection must be `sslmode=verify-full`.
    /// Anything weaker is a downgrade the operator acknowledges by name, and
    /// is told about at every start. The two opt-outs are independent:
    ///
    /// | `sslmode` | accepted |
    /// |---|---|
    /// | `verify-full` | always |
    /// | `verify-ca`, `require` | with `ENCOMPUTE_ALLOW_UNVERIFIED_DATABASE_TLS=true` |
    /// | `prefer`, `disable`, none | with `ENCOMPUTE_ALLOW_PLAINTEXT_DATABASE=true` (they can send plaintext) |
    ///
    /// Neither opt-out admits the other's modes. A unix-socket host never
    /// leaves the machine and is exempt.
    fn check_database_transport(&self) -> Result<()> {
        use crate::pgtls::SslMode;
        let (rest, tls) = crate::pgtls::split(&self.database_url)?;
        let cfg: postgres::Config = rest
            .parse()
            .map_err(|_| insecure("ENCOMPUTE_DATABASE_URL is not a valid connection string"))?;
        let local = !cfg.get_hosts().is_empty()
            && cfg
                .get_hosts()
                .iter()
                .all(|h| matches!(h, postgres::config::Host::Unix(_)));
        if local || tls.mode == SslMode::VerifyFull {
            return Ok(());
        }
        let fix = "set sslmode=verify-full with sslrootcert (and sslcert/sslkey if the server \
                   wants a client certificate) in ENCOMPUTE_DATABASE_URL";
        match tls.mode {
            SslMode::VerifyCa | SslMode::Require => {
                let (name, lacks) = if tls.mode == SslMode::VerifyCa {
                    (
                        "verify-ca",
                        "does not bind the connection to the database host name: a server \
                         with any certificate from the same CA is accepted",
                    )
                } else {
                    (
                        "require",
                        "encrypts but does not check the server's identity: an attacker \
                         on the path can impersonate the database",
                    )
                };
                if self.allow_unverified_database_tls {
                    LogLine::new(&self.service_id, "database_tls_unverified_allowed")
                        .field(
                            "warning",
                            format!(
                                "ENCOMPUTE_ALLOW_UNVERIFIED_DATABASE_TLS=true: sslmode={name} \
                                 {lacks}; this is a downgrade from sslmode=verify-full"
                            ),
                        )
                        .emit();
                    return Ok(());
                }
                Err(insecure(format!(
                    "production mode refuses sslmode={name} (it {lacks}): {fix}, or acknowledge \
                     the downgrade with ENCOMPUTE_ALLOW_UNVERIFIED_DATABASE_TLS=true"
                )))
            }
            _ => {
                if self.allow_plaintext_database {
                    LogLine::new(&self.service_id, "database_plaintext_allowed")
                        .field(
                            "warning",
                            "ENCOMPUTE_ALLOW_PLAINTEXT_DATABASE=true: the database connection \
                             is not TLS-enforced; credentials and data can cross the network \
                             unencrypted unless another channel protects them. This is INSECURE: \
                             a migration or emergency setting, not a configuration to keep",
                        )
                        .emit();
                    return Ok(());
                }
                Err(insecure(format!(
                    "production mode refuses a plaintext database connection (sslmode is \
                     absent, disable or prefer): {fix}, or, as an insecure emergency or \
                     migration measure, ENCOMPUTE_ALLOW_PLAINTEXT_DATABASE=true"
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prod() -> Config {
        Config {
            env: Env::Production,
            listen: "0.0.0.0:8770".into(),
            service_id: "control-plane".into(),
            database_url: Zeroizing::new(
                "postgres://encompute:Xk3!long-random@db/encompute?sslmode=verify-full&sslrootcert=/ca.pem".into(),
            ),
            allow_plaintext_database: false,
            allow_unverified_database_tls: false,
            signing_key_file: Some("/run/secrets/control-key".into()),
            oidc: vec![OidcIssuer {
                issuer: "https://login.example".into(),
                audience: "encompute".into(),
                jwks: JwksSource::Url("https://login.example/jwks".into()),
            }],
            dev_token_secret: None,
            anchor: AnchorConfig::Dir("/var/lib/encompute/anchor".into()),
            audit_checkpoint_every: 100,
            max_token_lifetime_secs: 3600,
            metrics: MetricsAccess::Closed,
        }
    }

    #[test]
    fn production_requires_verify_full_and_the_opt_outs_are_independent() {
        let with = |q: &str, plain: bool, unverified: bool| {
            let mut c = prod();
            c.database_url = Zeroizing::new(format!(
                "postgres://encompute:Xk3!long-random@db/encompute{q}"
            ));
            c.allow_plaintext_database = plain;
            c.allow_unverified_database_tls = unverified;
            c.validate()
        };
        let full = "?sslmode=verify-full&sslrootcert=/ca.pem";
        let ca = "?sslmode=verify-ca&sslrootcert=/ca.pem";
        let req = "?sslmode=require";
        let plain_modes = ["", "?sslmode=disable", "?sslmode=prefer"];
        // verify-full needs no opt-out (and `system` roots are fine).
        assert!(with(full, false, false).is_ok());
        assert!(with("?sslmode=verify-full&sslrootcert=system", false, false).is_ok());
        // Everything else is refused by default, with the exact variable named.
        for q in [ca, req] {
            let e = with(q, false, false).unwrap_err();
            assert_eq!(e.code, Code::InsecureConfiguration);
            assert!(
                e.message
                    .contains("ENCOMPUTE_ALLOW_UNVERIFIED_DATABASE_TLS=true"),
                "{e}"
            );
            assert!(e.message.contains("sslmode=verify-full"), "{e}");
        }
        assert!(with(ca, false, false)
            .unwrap_err()
            .message
            .contains("host name"));
        for q in plain_modes {
            let e = with(q, false, false).unwrap_err();
            assert!(
                e.message
                    .contains("ENCOMPUTE_ALLOW_PLAINTEXT_DATABASE=true"),
                "{q}: {e}"
            );
            assert!(e.message.contains("sslmode=verify-full"), "{q}: {e}");
        }
        assert!(with("?sslmode=bogus", true, true).is_err());
        // The unverified opt-out admits verify-ca and require only.
        assert!(with(ca, false, true).is_ok());
        assert!(with(req, false, true).is_ok());
        for q in plain_modes {
            assert!(with(q, false, true).is_err(), "{q}");
        }
        // The plaintext opt-out admits disable, prefer and none only.
        for q in plain_modes {
            assert!(with(q, true, false).is_ok(), "{q}");
        }
        assert!(with(ca, true, false).is_err());
        assert!(with(req, true, false).is_err());
        // A unix socket never leaves the host.
        let mut c = prod();
        c.database_url =
            Zeroizing::new("host=/var/run/postgresql user=e password=Xk3!long-random".into());
        assert!(c.validate().is_ok());
        // Development is never refused for it.
        let mut c = prod();
        c.env = Env::Development;
        c.database_url = Zeroizing::new("postgres://encompute:Xk3!long-random@db/encompute".into());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn production_refuses_insecure_fallbacks() {
        prod().validate().unwrap();
        let refused = |f: fn(&mut Config)| {
            let mut c = prod();
            // These cases are about something other than the transport: the
            // opt-out keeps their (plaintext) connection strings from being
            // refused for that reason instead.
            c.allow_plaintext_database = true;
            c.allow_unverified_database_tls = true;
            f(&mut c);
            assert_eq!(c.validate().unwrap_err().code, Code::InsecureConfiguration);
        };
        refused(|c| c.dev_token_secret = Some(Zeroizing::new("dev".into())));
        refused(|c| c.oidc.clear());
        refused(|c| c.oidc[0].issuer = "http://login.example".into());
        refused(|c| c.oidc[0].jwks = JwksSource::Url("http://login.example/jwks".into()));
        refused(|c| c.signing_key_file = None);
        refused(|c| c.database_url = Zeroizing::new("postgres://encompute:postgres@db/x".into()));
        refused(|c| c.database_url = Zeroizing::new("host=db user=e password=changeme".into()));
        // Review finding CP-A-8(d) (ENC-SF-2026-060): the driver also reads the password from
        // the query string, percent-encoded, or quoted.
        refused(|c| {
            c.database_url =
                Zeroizing::new("postgres://encompute@db/encompute?password=changeme".into())
        });
        refused(|c| {
            c.database_url = Zeroizing::new("postgres://encompute:chang%65me@db/encompute".into())
        });
        refused(|c| c.database_url = Zeroizing::new("host=db user=e password='postgres'".into()));
        refused(|c| c.database_url = Zeroizing::new("postgres://encompute:@db/encompute".into()));
        refused(|c| c.database_url = Zeroizing::new("not a :// connection string ' ".into()));
        refused(|c| {
            c.anchor = AnchorConfig::OpenBaoKv {
                addr: "http://bao:8200".into(),
                mount: "secret".into(),
                path: "a".into(),
                token: Zeroizing::new("t".into()),
            }
        });
        // Development mode accepts all of it.
        let mut c = prod();
        c.env = Env::Development;
        c.dev_token_secret = Some(Zeroizing::new("dev".into()));
        c.oidc.clear();
        c.signing_key_file = None;
        c.validate().unwrap();
    }
}

#[cfg(test)]
mod env_tests {
    use super::*;

    /// Review finding CP-A-8(e) (ENC-SF-2026-060): an unset ENCOMPUTE_ENV refuses to start
    /// instead of silently meaning development. (One test touches the
    /// process environment, so nothing races it.)
    #[test]
    fn unset_or_misspelt_environment_refuses_to_start() {
        std::env::set_var(
            "ENCOMPUTE_DATABASE_URL",
            "postgres://u:Xk3!long-random@db/x",
        );
        std::env::set_var("ENCOMPUTE_ANCHOR_DIR", "/tmp/encompute-env-test-anchor");
        std::env::remove_var("ENCOMPUTE_ENV");
        let e = Config::from_env().unwrap_err();
        assert_eq!(e.code, Code::InsecureConfiguration);
        assert!(e.message.contains("ENCOMPUTE_ENV"), "{e}");
        std::env::set_var("ENCOMPUTE_ENV", "prod");
        assert_eq!(
            Config::from_env().unwrap_err().code,
            Code::InsecureConfiguration
        );
        std::env::set_var("ENCOMPUTE_ENV", "development");
        let c = Config::from_env().unwrap();
        assert_eq!(c.env, Env::Development);
        assert!(matches!(c.metrics, MetricsAccess::Public));
        assert_eq!(
            c.max_token_lifetime_secs,
            crate::authn::DEFAULT_MAX_TOKEN_LIFETIME_SECS
        );
        std::env::set_var("ENCOMPUTE_METRICS_TOKEN", "scrape-secret");
        assert!(matches!(
            Config::from_env().unwrap().metrics,
            MetricsAccess::Token(_)
        ));
        std::env::remove_var("ENCOMPUTE_METRICS_TOKEN");
        std::env::set_var("ENCOMPUTE_MAX_TOKEN_LIFETIME_SECS", "0");
        assert!(Config::from_env().is_err());
        for v in [
            "ENCOMPUTE_ENV",
            "ENCOMPUTE_DATABASE_URL",
            "ENCOMPUTE_ANCHOR_DIR",
            "ENCOMPUTE_MAX_TOKEN_LIFETIME_SECS",
        ] {
            std::env::remove_var(v);
        }
    }
}
