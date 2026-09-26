//! DEVELOPMENT ONLY: a stand-in for the Confidential Space launcher's
//! token endpoint (`POST /v1/token` on a Unix socket), so the real
//! Confidential Space attester, and a production broker verifying real
//! token claims, can be exercised without Google Cloud.
//!
//! It signs OIDC tokens with a key the operator supplies. A broker trusts
//! them only if the operator gives it the matching JWKS instead of
//! Google's, so it can never forge a token a real deployment accepts. It
//! proves nothing about hardware.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;

use encompute_ir::{Code, Error, Result};

pub struct LauncherSim {
    pub key: jsonwebtoken::EncodingKey,
    pub kid: String,
    pub image_digest: String,
    pub debug: bool,
    pub hwmodel: String,
    pub lifetime: u64,
}

fn err(m: impl Into<String>) -> Error {
    Error::new(Code::Attestation, m)
}

impl LauncherSim {
    /// A token for `audience` committing to `nonces`, with the claims a
    /// production Confidential Space VM reports (or a debug one).
    pub fn token(&self, audience: &str, nonces: &[String]) -> Result<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| err("clock"))?
            .as_secs();
        let claims = serde_json::json!({
            "iss": encompute_runtime::attestation::gcp::ISSUER,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + self.lifetime,
            "eat_nonce": nonces,
            "hwmodel": self.hwmodel,
            "swname": "CONFIDENTIAL_SPACE",
            "swversion": ["250800"],
            "dbgstat": if self.debug { "enabled" } else { "disabled-since-boot" },
            "secboot": true,
            "oemid": 11129,
            "submods": {
                "container": {
                    "image_digest": self.image_digest,
                    "image_reference": format!("simulated/encompute-training@{}", self.image_digest)
                },
                "confidential_space": {"support_attributes": ["LATEST", "STABLE", "USABLE"]},
                "gce": {"project_id": "simulated", "zone": "simulated"}
            }
        });
        let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        h.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&h, &claims, &self.key).map_err(|e| err(format!("sign: {e}")))
    }

    /// Serves tokens on `socket` until killed.
    pub fn serve(&self, socket: &Path) -> Result<()> {
        let _ = std::fs::remove_file(socket);
        let listener =
            UnixListener::bind(socket).map_err(|e| err(format!("{}: {e}", socket.display())))?;
        eprintln!(
            "SIMULATED CONFIDENTIAL SPACE LAUNCHER on {} (image {}, debug {}): DEVELOPMENT ONLY, NO HARDWARE",
            socket.display(),
            self.image_digest,
            self.debug
        );
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { continue };
            let reply = match self.handle(&mut s) {
                Ok(t) => format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{t}", t.len()),
                Err(e) => {
                    let m = e.message;
                    format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{m}",
                        m.len()
                    )
                }
            };
            let _ = s.write_all(reply.as_bytes());
        }
        Ok(())
    }

    fn handle(&self, s: &mut std::os::unix::net::UnixStream) -> Result<String> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let (head_end, len) = loop {
            let n = s.read(&mut chunk).map_err(|e| err(e.to_string()))?;
            if n == 0 {
                return Err(err("connection closed"));
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..p]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                break (p + 4, len);
            }
            if buf.len() > 1 << 16 {
                return Err(err("request too large"));
            }
        };
        while buf.len() < head_end + len {
            let n = s.read(&mut chunk).map_err(|e| err(e.to_string()))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let body: serde_json::Value =
            serde_json::from_slice(&buf[head_end..]).map_err(|e| err(format!("request: {e}")))?;
        let audience = body["audience"]
            .as_str()
            .ok_or_else(|| err("no audience"))?;
        let nonces: Vec<String> = body["nonces"]
            .as_array()
            .ok_or_else(|| err("no nonces"))?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        self.token(audience, &nonces)
    }
}
