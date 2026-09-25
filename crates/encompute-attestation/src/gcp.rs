//! Google Cloud Confidential Space.
//!
//! The workload asks the Confidential Space launcher for a custom OIDC
//! token (`POST /v1/token` on the launcher's Unix socket) whose nonce is
//! the [`WorkloadBinding`] hash. Google's attestation service signs it
//! (RS256) after checking the VM's hardware attestation and measured boot.
//! The verifier checks the signature against Google's published keys, the
//! issuer, audience and expiry, that the token commits to the binding, and
//! normalizes the hardware, image, debug and support claims.

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use encompute_ir::{Code, Result};

use crate::binding::{AttestationChallenge, WorkloadBinding};
use crate::policy::{Security, TcbStatus, TeeKind, VerifiedGpu, VerifiedWorkload};
use crate::provider::{
    AttestationEvidence, AttestationProvider, Attester, CLOCK_SKEW_SECS, EVIDENCE_VERSION,
};
use crate::util::{err, tagged, EVIDENCE, MEASUREMENT};

pub const PROVIDER: &str = "gcp-confidential-space";
pub const ISSUER: &str = "https://confidentialcomputing.googleapis.com";
/// Google's token-signing keys (they rotate; select by `kid`).
pub const JWKS_URL: &str = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";
/// The launcher's socket, inside the workload container.
pub const TEE_SERVER_SOCKET: &str = "/run/container_launcher/teeserver.sock";

const MAX_TOKEN_BYTES: usize = 32 << 10;

#[derive(Deserialize)]
struct Claims {
    iat: u64,
    exp: u64,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    eat_nonce: Option<Nonces>,
    #[serde(default)]
    hwmodel: String,
    #[serde(default)]
    swname: String,
    #[serde(default)]
    dbgstat: String,
    #[serde(default)]
    secboot: bool,
    #[serde(default)]
    submods: Submods,
}

/// `eat_nonce`: one nonce as a string, several as an array.
#[derive(Deserialize)]
#[serde(untagged)]
enum Nonces {
    One(String),
    Many(Vec<String>),
}

#[derive(Default, Deserialize)]
struct Submods {
    #[serde(default)]
    container: Container,
    #[serde(default)]
    confidential_space: SpaceClaims,
    #[serde(default)]
    nvidia_gpu: Option<GpuClaims>,
}

#[derive(Default, Deserialize)]
struct Container {
    #[serde(default)]
    image_digest: String,
}

#[derive(Default, Deserialize)]
struct SpaceClaims {
    #[serde(default)]
    support_attributes: Vec<String>,
}

#[derive(Deserialize)]
struct GpuClaims {
    #[serde(default)]
    cc_mode: String,
    #[serde(default)]
    gpus: Vec<GpuDevice>,
}

#[derive(Deserialize)]
struct GpuDevice {
    #[serde(default)]
    hwmodel: String,
}

/// Verifies Confidential Space tokens against a JWKS (Google's published
/// keys, fetched by the caller from [`JWKS_URL`]). The audience is the
/// broker's ID.
pub struct ConfidentialSpaceProvider {
    keys: JwkSet,
    audience: String,
}

impl ConfidentialSpaceProvider {
    /// `jwks`: the JSON key set; `audience`: the audience the workload
    /// requested (the broker's URL or ID).
    pub fn new(jwks: &str, audience: &str) -> Result<Self> {
        let keys: JwkSet = serde_json::from_str(jwks)
            .map_err(|e| err(Code::Attestation, format!("malformed JWKS: {e}")))?;
        if audience.is_empty() || audience.len() > 512 {
            return Err(err(Code::Attestation, "audience must be 1-512 bytes"));
        }
        Ok(Self {
            keys,
            audience: audience.to_owned(),
        })
    }
}

pub struct ConfidentialSpaceEvidence {
    binding: WorkloadBinding,
    token: String,
}

fn tee_kind(hwmodel: &str) -> TeeKind {
    match hwmodel {
        "GCP_INTEL_TDX" => TeeKind::IntelTdx,
        "GCP_AMD_SEV" => TeeKind::AmdSev,
        "GCP_AMD_SEV_SNP" => TeeKind::AmdSevSnp,
        other => TeeKind::Other(other.to_owned()),
    }
}

fn tcb_status(support: &[String]) -> TcbStatus {
    let has = |a: &str| support.iter().any(|s| s == a);
    if has("STABLE") && has("LATEST") {
        TcbStatus::Current
    } else if has("STABLE") {
        TcbStatus::Supported
    } else if has("USABLE") {
        TcbStatus::OutOfDate
    } else {
        TcbStatus::Unknown
    }
}

impl AttestationProvider for ConfidentialSpaceProvider {
    type Evidence = ConfidentialSpaceEvidence;

    fn name(&self) -> &'static str {
        PROVIDER
    }

    fn parse(&self, raw: &AttestationEvidence) -> Result<ConfidentialSpaceEvidence> {
        if raw.evidence.len() > MAX_TOKEN_BYTES {
            return Err(err(Code::Attestation, "attestation token is too large"));
        }
        Ok(ConfidentialSpaceEvidence {
            binding: raw.binding.clone(),
            token: raw.evidence.clone(),
        })
    }

    fn verify_claims(
        &self,
        e: &ConfidentialSpaceEvidence,
        now: Option<u64>,
    ) -> Result<VerifiedWorkload> {
        let bad = |m: String| err(Code::Attestation, m);
        let header = jsonwebtoken::decode_header(&e.token)
            .map_err(|x| bad(format!("malformed attestation token: {x}")))?;
        if header.alg != Algorithm::RS256 {
            return Err(bad(format!(
                "attestation token algorithm {:?} (RS256 required)",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| bad("attestation token names no signing key".into()))?;
        let jwk = self
            .keys
            .find(&kid)
            .ok_or_else(|| bad(format!("unknown token signing key {kid:?}")))?;
        let key = DecodingKey::from_jwk(jwk).map_err(|x| bad(format!("signing key: {x}")))?;
        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&[ISSUER]);
        v.set_audience(&[&self.audience]);
        // Times are checked below against the caller's clock.
        v.validate_exp = false;
        v.validate_nbf = false;
        v.required_spec_claims = ["exp", "iss", "aud"].map(String::from).into();
        let c = jsonwebtoken::decode::<Claims>(&e.token, &key, &v)
            .map_err(|x| bad(format!("attestation token rejected: {x}")))?
            .claims;
        if c.swname != "CONFIDENTIAL_SPACE" {
            return Err(bad(format!(
                "not a Confidential Space workload (swname {:?})",
                c.swname
            )));
        }
        if !c.secboot {
            return Err(bad("the VM did not boot with Secure Boot".into()));
        }
        let want = e.binding.nonce()?;
        let committed = match &c.eat_nonce {
            Some(Nonces::One(s)) => *s == want,
            Some(Nonces::Many(a)) => a.contains(&want),
            None => false,
        };
        if !committed {
            return Err(bad(
                "the attestation token does not commit to this workload binding".into(),
            ));
        }
        if let Some(now) = now {
            if now >= c.exp {
                return Err(err(Code::Freshness, "the attestation token has expired"));
            }
            if c.nbf.unwrap_or(c.iat) > now.saturating_add(CLOCK_SKEW_SECS) {
                return Err(err(
                    Code::Freshness,
                    "the attestation token is not yet valid",
                ));
            }
        }
        let image = c.submods.container.image_digest;
        if image.is_empty() {
            return Err(bad(
                "the attestation token measures no container image".into()
            ));
        }
        let mut m = format!("{PROVIDER}\0").into_bytes();
        m.extend_from_slice(image.as_bytes());
        let gpu = c.submods.nvidia_gpu.map(|g| VerifiedGpu {
            confidential_mode: g.cc_mode == "ON",
            models: g.gpus.into_iter().map(|d| d.hwmodel).collect(),
        });
        Ok(VerifiedWorkload {
            provider: PROVIDER.into(),
            security: Security::Production,
            tee_kind: tee_kind(&c.hwmodel),
            workload_measurement: tagged(MEASUREMENT, &m),
            image_digest: Some(image),
            debug_enabled: c.dbgstat != "disabled-since-boot",
            tcb_status: tcb_status(&c.submods.confidential_space.support_attributes),
            evidence_digest: tagged(EVIDENCE, e.token.as_bytes()),
            binding: e.binding.clone(),
            issued_at: Some(c.iat),
            expires_at: Some(c.exp),
            gpu,
        })
    }
}

/// Requests tokens from the Confidential Space launcher, addressed to the
/// challenging broker (its ID is the token audience). Only works inside a
/// Confidential Space workload.
pub struct ConfidentialSpaceAttester {
    socket: std::path::PathBuf,
}

impl Default for ConfidentialSpaceAttester {
    fn default() -> Self {
        Self::with_socket(TEE_SERVER_SOCKET)
    }
}

impl ConfidentialSpaceAttester {
    pub fn with_socket(socket: impl Into<std::path::PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }
}

impl Attester for ConfidentialSpaceAttester {
    fn provider(&self) -> &'static str {
        PROVIDER
    }

    fn attest(
        &self,
        challenge: &AttestationChallenge,
        binding: &WorkloadBinding,
    ) -> Result<AttestationEvidence> {
        let body = serde_json::json!({
            "audience": challenge.broker_id,
            "nonces": [binding.nonce()?],
            "token_type": "OIDC",
        })
        .to_string();
        let (status, reply) = unix_http_post(&self.socket, "/v1/token", &body)?;
        let token = String::from_utf8(reply)
            .map_err(|_| err(Code::Attestation, "the launcher returned a non-UTF-8 token"))?;
        if status != 200 {
            let snippet: String = token.chars().take(200).collect();
            return Err(err(
                Code::Attestation,
                format!("the launcher refused the token request ({status}): {snippet}"),
            ));
        }
        Ok(AttestationEvidence {
            version: EVIDENCE_VERSION,
            provider: PROVIDER.into(),
            binding: binding.clone(),
            evidence: token.trim().to_owned(),
        })
    }
}

#[cfg(unix)]
fn unix_http_post(socket: &std::path::Path, path: &str, body: &str) -> Result<(u16, Vec<u8>)> {
    use std::io::{Read, Write};
    let io = |x: std::io::Error| err(Code::Attestation, format!("{}: {x}", socket.display()));
    let mut s = std::os::unix::net::UnixStream::connect(socket).map_err(io)?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(io)?;
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(io)?;
    let mut raw = Vec::new();
    s.take(MAX_TOKEN_BYTES as u64 + 4096)
        .read_to_end(&mut raw)
        .map_err(io)?;
    parse_http_response(&raw)
}

#[cfg(not(unix))]
fn unix_http_post(_: &std::path::Path, _: &str, _: &str) -> Result<(u16, Vec<u8>)> {
    Err(err(
        Code::Attestation,
        "Confidential Space attestation needs a Unix socket",
    ))
}

/// Status and body of an HTTP/1.1 response (plain or chunked).
fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>)> {
    let bad = || {
        err(
            Code::Attestation,
            "malformed HTTP response from the launcher",
        )
    };
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(bad)?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| bad())?;
    let body = &raw[split + 4..];
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(bad)?;
    let chunked = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    if !chunked {
        return Ok((status, body.to_vec()));
    }
    let (mut out, mut rest) = (Vec::new(), body);
    loop {
        let eol = rest.windows(2).position(|w| w == b"\r\n").ok_or_else(bad)?;
        let size_text = std::str::from_utf8(&rest[..eol]).map_err(|_| bad())?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| bad())?;
        rest = &rest[eol + 2..];
        if size == 0 {
            return Ok((status, out));
        }
        if rest.len() < size + 2 {
            return Err(bad());
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_responses() {
        let (s, b) =
            parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc").unwrap();
        assert_eq!((s, b.as_slice()), (200, &b"abc"[..]));
        let (s, b) = parse_http_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!((s, b.as_slice()), (200, &b"abcde"[..]));
        assert!(parse_http_response(b"garbage").is_err());
    }

    #[test]
    fn claim_normalization() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            tcb_status(&s(&["LATEST", "STABLE", "USABLE"])),
            TcbStatus::Current
        );
        assert_eq!(tcb_status(&s(&["STABLE", "USABLE"])), TcbStatus::Supported);
        assert_eq!(tcb_status(&s(&["USABLE"])), TcbStatus::OutOfDate);
        assert_eq!(tcb_status(&s(&["EXPERIMENTAL"])), TcbStatus::Unknown);
        assert_eq!(tee_kind("GCP_INTEL_TDX"), TeeKind::IntelTdx);
        assert_eq!(
            tee_kind("GCP_SHIELDED_VM"),
            TeeKind::Other("GCP_SHIELDED_VM".into())
        );
    }
}
