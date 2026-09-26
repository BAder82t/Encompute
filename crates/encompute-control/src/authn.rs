//! Authentication: who is calling.
//!
//! - **Users**: OpenID Connect ID/access tokens (RS256, ES256, PS256) from a
//!   configured issuer, checked against its JWKS: signature, issuer,
//!   audience, expiry. The (issuer, subject) pair must be a registered,
//!   active user.
//! - **Development**: HS256 tokens from `ENCOMPUTE_DEV_TOKEN_SECRET`, issuer
//!   `encompute-development`. Production mode refuses them outright.
//! - **Services**: Ed25519-signed requests (see
//!   `encompute_verification::service`): a registered, active service
//!   account, addressed to this control plane, fresh, and a nonce never seen
//!   before. Source addresses and hostnames are never identity.
//!
//! A user identity (alice@hospital-a) is not a cryptographic party
//! (`hospital-a` in a program's policy): the two are never merged.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use postgres::GenericClient;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use encompute_ir::{Code, Error, Result};
use encompute_verification::service::{ServiceHeaders, MAX_CLOCK_SKEW_SECS};

use crate::config::{Env, JwksSource, OidcIssuer};
use crate::db::db_err;
use crate::model::{Role, ServiceKind};

pub const DEV_ISSUER: &str = "encompute-development";
pub const DEV_AUDIENCE: &str = "encompute";
/// Tokens larger than this are refused before parsing.
const MAX_TOKEN: usize = 16 * 1024;

fn unauth(msg: impl Into<String>) -> Error {
    Error::new(Code::Unauthenticated, msg)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PrincipalKind {
    User { issuer: String, subject: String },
    Service { service_kind: ServiceKind },
}

/// An authenticated caller and its roles.
#[derive(Clone, Debug, Serialize)]
pub struct Principal {
    pub id: String,
    pub kind: PrincipalKind,
    /// The organization the user or service account belongs to (`None`
    /// for platform services).
    pub organization: Option<String>,
    pub roles: BTreeSet<(String, Role)>,
}

impl Principal {
    pub fn has_role(&self, org: &str, role: Role) -> bool {
        self.roles.contains(&(org.to_owned(), role))
    }

    pub fn any_role(&self, org: &str, roles: &[Role]) -> bool {
        roles.iter().any(|r| self.has_role(org, *r))
    }

    pub fn member_of(&self, org: &str) -> bool {
        self.organization.as_deref() == Some(org) || self.roles.iter().any(|(o, _)| o == org)
    }

    pub fn service_kind(&self) -> Option<ServiceKind> {
        match &self.kind {
            PrincipalKind::Service { service_kind } => Some(*service_kind),
            PrincipalKind::User { .. } => None,
        }
    }

    /// Organizations this principal belongs to.
    pub fn organizations(&self) -> BTreeSet<String> {
        let mut s: BTreeSet<String> = self.roles.iter().map(|(o, _)| o.clone()).collect();
        if let Some(o) = &self.organization {
            s.insert(o.clone());
        }
        s
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    exp: u64,
}

struct IssuerKeys {
    cfg: OidcIssuer,
    keys: Mutex<(Option<JwkSet>, Option<Instant>)>,
}

impl IssuerKeys {
    fn fetch(&self) -> Result<JwkSet> {
        let text = match &self.cfg.jwks {
            JwksSource::Inline(s) => s.clone(),
            JwksSource::File(p) => std::fs::read_to_string(p)
                .map_err(|e| unauth(format!("JWKS {}: {e}", p.display())))?,
            JwksSource::Url(u) => ureq::get(u)
                .timeout(Duration::from_secs(10))
                .call()
                .map_err(|e| unauth(format!("JWKS {u}: {e}")))?
                .into_string()
                .map_err(|e| unauth(format!("JWKS {u}: {e}")))?,
        };
        serde_json::from_str(&text).map_err(|e| unauth(format!("malformed JWKS: {e}")))
    }

    /// The key for `kid`, refetching the set (at most once a minute) when
    /// the key is unknown: providers rotate keys.
    fn key(&self, kid: &str) -> Result<DecodingKey> {
        let mut g = self.keys.lock().unwrap_or_else(|p| p.into_inner());
        let found = |s: &Option<JwkSet>| {
            s.as_ref()
                .and_then(|s| s.find(kid))
                .map(DecodingKey::from_jwk)
        };
        if let Some(k) = found(&g.0) {
            return k.map_err(|e| unauth(format!("signing key: {e}")));
        }
        if g.1.is_none_or(|t| t.elapsed() > Duration::from_secs(60)) {
            g.1 = Some(Instant::now());
            g.0 = Some(self.fetch()?);
        }
        match found(&g.0) {
            Some(k) => k.map_err(|e| unauth(format!("signing key: {e}"))),
            None => Err(unauth(format!("unknown token signing key {kid:?}"))),
        }
    }
}

pub struct Authenticator {
    env: Env,
    service_id: String,
    issuers: Vec<IssuerKeys>,
    dev_secret: Option<Zeroizing<String>>,
}

/// What a request presents.
pub struct Credentials<'a> {
    pub authorization: Option<&'a str>,
    pub service: Option<ServiceHeaders>,
    pub method: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The unverified `iss` claim, only to pick which issuer verifies it.
fn peek_issuer(token: &str) -> Result<String> {
    use base64::Engine;
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| unauth("malformed token"))?;
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| unauth("malformed token"))?;
    let v: serde_json::Value = serde_json::from_slice(&b).map_err(|_| unauth("malformed token"))?;
    v["iss"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| unauth("the token names no issuer"))
}

/// A development token for `subject` (tests, local development).
pub fn dev_token(secret: &str, subject: &str, ttl_secs: u64) -> Result<String> {
    let c = Claims {
        iss: DEV_ISSUER.into(),
        sub: subject.into(),
        exp: unix_now() + ttl_secs,
    };
    #[derive(Serialize)]
    struct WithAud<'a> {
        #[serde(flatten)]
        c: &'a Claims,
        aud: &'a str,
    }
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &WithAud {
            c: &c,
            aud: DEV_AUDIENCE,
        },
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| unauth(format!("token: {e}")))
}

impl Authenticator {
    pub fn new(
        env: Env,
        service_id: &str,
        issuers: Vec<OidcIssuer>,
        dev_secret: Option<Zeroizing<String>>,
    ) -> Self {
        Self {
            env,
            service_id: service_id.into(),
            issuers: issuers
                .into_iter()
                .map(|cfg| IssuerKeys {
                    cfg,
                    keys: Mutex::new((None, None)),
                })
                .collect(),
            // Production never holds a development secret (config refuses
            // it; this is a second line).
            dev_secret: if env.is_production() {
                None
            } else {
                dev_secret
            },
        }
    }

    /// Verifies a bearer token: (issuer, subject).
    pub fn verify_token(&self, token: &str) -> Result<(String, String)> {
        if token.len() > MAX_TOKEN {
            return Err(unauth("token too large"));
        }
        let iss = peek_issuer(token)?;
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| unauth(format!("malformed token: {e}")))?;
        let (key, mut v) = if iss == DEV_ISSUER {
            if self.env.is_production() {
                return Err(unauth("development tokens are refused in production mode"));
            }
            let secret = self
                .dev_secret
                .as_ref()
                .ok_or_else(|| unauth("development tokens are not enabled"))?;
            if header.alg != Algorithm::HS256 {
                return Err(unauth("development tokens are HS256"));
            }
            let mut v = Validation::new(Algorithm::HS256);
            v.set_audience(&[DEV_AUDIENCE]);
            (DecodingKey::from_secret(secret.as_bytes()), v)
        } else {
            let issuer = self
                .issuers
                .iter()
                .find(|i| i.cfg.issuer == iss)
                .ok_or_else(|| unauth(format!("untrusted token issuer {iss:?}")))?;
            if !matches!(
                header.alg,
                Algorithm::RS256
                    | Algorithm::RS384
                    | Algorithm::RS512
                    | Algorithm::ES256
                    | Algorithm::ES384
                    | Algorithm::PS256
                    | Algorithm::PS384
                    | Algorithm::PS512
            ) {
                return Err(unauth(format!(
                    "token algorithm {:?} is not accepted from an identity provider",
                    header.alg
                )));
            }
            let kid = header
                .kid
                .as_deref()
                .ok_or_else(|| unauth("the token names no signing key"))?;
            let mut v = Validation::new(header.alg);
            v.set_audience(&[&issuer.cfg.audience]);
            (issuer.key(kid)?, v)
        };
        v.set_issuer(&[&iss]);
        v.leeway = 60;
        v.required_spec_claims = ["exp", "iss", "aud", "sub"].map(String::from).into();
        let c = jsonwebtoken::decode::<Claims>(token, &key, &v)
            .map_err(|e| unauth(format!("token rejected: {e}")))?
            .claims;
        Ok((c.iss, c.sub))
    }

    /// The caller of a request, or ENC2601/ENC2607.
    pub fn authenticate(
        &self,
        c: &mut impl GenericClient,
        cred: &Credentials<'_>,
    ) -> Result<Principal> {
        if let Some(h) = &cred.service {
            return self.authenticate_service(c, h, cred);
        }
        let token = cred
            .authorization
            .and_then(|a| a.strip_prefix("Bearer "))
            .ok_or_else(|| {
                unauth("authentication required: a bearer token or a service signature")
            })?;
        let (issuer, subject) = self.verify_token(token.trim())?;
        let row = c
            .query_opt(
                "SELECT id, organization_id, status FROM users WHERE issuer = $1 AND subject = $2",
                &[&issuer, &subject],
            )
            .map_err(db_err)?
            .ok_or_else(|| unauth("this identity is not registered with any organization"))?;
        let status: String = row.get(2);
        if status != "active" {
            return Err(unauth("this user is disabled"));
        }
        let id: String = row.get(0);
        Ok(Principal {
            roles: roles_of(c, &id)?,
            id,
            kind: PrincipalKind::User { issuer, subject },
            organization: Some(row.get(1)),
        })
    }

    fn authenticate_service(
        &self,
        c: &mut impl GenericClient,
        h: &ServiceHeaders,
        cred: &Credentials<'_>,
    ) -> Result<Principal> {
        let sa_err = |m: &str| Error::new(Code::ServiceAuthentication, m.to_owned());
        let row = c
            .query_opt(
                "SELECT organization_id, kind, public_key, status FROM service_accounts WHERE id = $1",
                &[&h.sender],
            )
            .map_err(db_err)?
            .ok_or_else(|| sa_err("unknown service"))?;
        let status: String = row.get(3);
        if status != "active" {
            return Err(sa_err("this service account is disabled"));
        }
        let pk: String = row.get(2);
        let now = unix_now();
        h.verify(
            &pk,
            cred.method,
            cred.path,
            cred.body,
            &self.service_id,
            now,
        )?;
        // The nonce is spent now; a replay within the window finds it.
        let inserted = c
            .execute(
                "INSERT INTO request_nonces (sender, nonce, expires_at) VALUES ($1, $2, $3)
                 ON CONFLICT DO NOTHING",
                &[
                    &h.sender,
                    &h.nonce,
                    &(SystemTime::now() + Duration::from_secs(2 * MAX_CLOCK_SKEW_SECS)),
                ],
            )
            .map_err(db_err)?;
        if inserted == 0 {
            return Err(sa_err("replayed request (nonce already used)"));
        }
        let kind: String = row.get(1);
        Ok(Principal {
            id: h.sender.clone(),
            kind: PrincipalKind::Service {
                service_kind: ServiceKind::parse(&kind)?,
            },
            organization: row.get(0),
            roles: roles_of(c, &h.sender)?,
        })
    }
}

pub fn roles_of(c: &mut impl GenericClient, principal: &str) -> Result<BTreeSet<(String, Role)>> {
    c.query(
        "SELECT organization_id, role FROM memberships WHERE principal_id = $1",
        &[&principal],
    )
    .map_err(db_err)?
    .iter()
    .map(|r| Ok((r.get::<_, String>(0), Role::parse(r.get(1))?)))
    .collect()
}

/// Removes expired nonces (called periodically).
pub fn prune_nonces(c: &mut impl GenericClient) -> Result<u64> {
    c.execute("DELETE FROM request_nonces WHERE expires_at < now()", &[])
        .map_err(db_err)
}
