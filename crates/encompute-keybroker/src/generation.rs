//! The broker state's generation high-water mark, kept outside the state
//! file: in the organization's KMS (OpenBao or Vault KV-v2, written with
//! compare-and-set), or, for development only, in a separate local file.
//!
//! The state MAC stops an edited state file, but an older authentic copy
//! (one saved before a revocation, with a counter below its limit, or
//! without a used ticket) still verifies. The mark closes that gap: every
//! save writes the state file, then advances the mark to the new generation
//! and state MAC with compare-and-set, and only then does the broker grant
//! a key or acknowledge a change. Opening the state compares it with the
//! mark:
//!
//! - older than the mark: a rollback, refused (ENC2713);
//! - the mark's generation with another MAC: a fork, refused (ENC2713);
//! - one save ahead of the mark: the broker stopped between writing the
//!   file and advancing the mark; accepted, and the mark advanced, only if
//!   the state names the mark's MAC as its previous one (every marked save
//!   records it), so a file from another history with the same number is
//!   refused;
//! - further ahead: refused (every save advances the mark, so a state
//!   further ahead was saved without it);
//! - no mark yet: the first start under a mark trusts the state file and
//!   records it, unless the operator states what it expects (its
//!   generation and MAC), which is then checked first.
//!
//! A mark that cannot be read or advanced fails closed: the broker does not
//! start, or grants nothing (ENC2713; the broker answers 503).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use encompute_ir::{Code, Error, Result};

use crate::root::{bao_errors, bao_name_ok, BaoHttp};
use crate::store::StoreSecurity;

/// Every "the mark cannot be read or advanced" error starts with this: the
/// broker answers such a refusal with 503, not 403.
pub const MARK_UNAVAILABLE: &str = "generation mark unavailable";

/// The mark could not be reached (network, permissions, a malformed
/// answer): no grant, and the broker answers 503.
pub fn mark_unavailable(what: &str, e: impl std::fmt::Display) -> Error {
    Error::new(
        Code::GovernanceBrokerStateRollback,
        format!("{MARK_UNAVAILABLE} ({what}): {e}; no key is released without it"),
    )
}

/// Someone else advanced the mark since this broker last did: another
/// process is writing this broker's state (a fork), so nothing is granted.
pub fn mark_conflict(what: &str) -> Error {
    Error::new(
        Code::GovernanceBrokerStateRollback,
        format!(
            "the generation mark ({what}) was advanced by someone else: another copy of this \
             broker's state is in use; no key is released"
        ),
    )
}

/// What the mark records: the last saved generation and that state's MAC
/// (or, for development plaintext storage, its SHA-256).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mark {
    pub broker_id: String,
    pub generation: u64,
    pub state_mac: String,
}

/// A mark as read, with the compare-and-set version to advance it from
/// (0: no mark exists).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkRead {
    pub mark: Option<Mark>,
    pub cas: u64,
}

/// Where a broker keeps its generation high-water mark.
pub trait GenerationMark: Send + Sync {
    /// Where the mark lives (not secret), for messages.
    fn describe(&self) -> String;
    fn security(&self) -> StoreSecurity;
    /// The current mark, if any, and its compare-and-set version.
    fn read(&self) -> Result<MarkRead>;
    /// Writes `mark` only if the mark is still at `expected_cas` (0: only
    /// if none exists); returns the new compare-and-set version. A mark
    /// advanced by someone else is [`mark_conflict`].
    fn advance(&self, mark: &Mark, expected_cas: u64) -> Result<u64>;
}

/// The path segment for a broker's mark: its ID when that is a plain name,
/// otherwise the SHA-256 of the ID (broker IDs may hold `/`, `?` or `#`).
fn broker_segment(broker_id: &str) -> String {
    if bao_name_ok(broker_id) && broker_id.len() <= 128 && broker_id != "." && broker_id != ".." {
        broker_id.to_owned()
    } else {
        use sha2::Digest;
        format!(
            "sha256-{}",
            encompute_verification::hex(&sha2::Sha256::digest(broker_id.as_bytes()))
        )
    }
}

fn check_mark(broker_id: &str, m: Mark, what: &str) -> Result<Mark> {
    if m.broker_id != broker_id {
        return Err(Error::new(
            Code::GovernanceBrokerStateRollback,
            format!(
                "the generation mark at {what} belongs to broker {:?}, not {broker_id:?}",
                m.broker_id
            ),
        ));
    }
    Ok(m)
}

// --- OpenBao / Vault KV-v2 ----------------------------------------------------

/// The mark in an OpenBao or HashiCorp Vault KV-v2 engine, at
/// `{mount}/data/encompute/brokers/{broker}/generation`, advanced with
/// `options.cas`. The token needs read and write on that one path (and the
/// Transit key, when the same token wraps the KEK).
pub struct OpenBaoKvMark {
    http: BaoHttp,
    mount: String,
    broker_id: String,
    segment: String,
}

impl OpenBaoKvMark {
    /// `addr` follows the Transit provider's rules: https, or plain http on
    /// loopback only.
    pub fn new(addr: &str, mount: &str, broker_id: &str, token: Zeroizing<String>) -> Result<Self> {
        Self::with_http(BaoHttp::new(addr, token)?, mount, broker_id)
    }

    /// Trusts the CA bundle and presents the client certificate that
    /// `BAO_CACERT`, `BAO_CLIENT_CERT` and `BAO_CLIENT_KEY` (or the `VAULT_`
    /// names) point at: the same settings as the Transit root key. With none
    /// of them set the client is unchanged. `from_env` already applies it.
    pub fn with_tls_from_env(mut self) -> Result<Self> {
        self.http = self.http.with_tls_from_env()?;
        Ok(self)
    }

    /// From `BAO_ADDR`/`VAULT_ADDR`, and the token from `BAO_TOKEN_FILE` or
    /// `BAO_TOKEN`/`VAULT_TOKEN`; TLS from `BAO_CACERT` and `BAO_CLIENT_*`:
    /// the same settings as the Transit root key.
    pub fn from_env(mount: &str, broker_id: &str) -> Result<Self> {
        Self::with_http(BaoHttp::from_env()?, mount, broker_id)
    }

    fn with_http(http: BaoHttp, mount: &str, broker_id: &str) -> Result<Self> {
        if !bao_name_ok(mount) {
            return Err(Error::new(
                Code::KeyRelease,
                "malformed KV mount name (letters, digits, '-', '_', '.')",
            ));
        }
        Ok(Self {
            http,
            mount: mount.into(),
            broker_id: broker_id.into(),
            segment: broker_segment(broker_id),
        })
    }

    fn path(&self) -> String {
        format!(
            "{}/data/encompute/brokers/{}/generation",
            self.mount, self.segment
        )
    }

    fn body(resp: ureq::Response, what: &str) -> Result<serde_json::Value> {
        let status = resp.status();
        if !(200..300).contains(&status) {
            return Err(mark_unavailable(
                what,
                format!("answered {status} (redirects are not followed)"),
            ));
        }
        resp.into_json().map_err(|e| mark_unavailable(what, e))
    }
}

impl GenerationMark for OpenBaoKvMark {
    fn describe(&self) -> String {
        format!("{}/v1/{}", self.http.addr, self.path())
    }

    fn security(&self) -> StoreSecurity {
        StoreSecurity::Production
    }

    fn read(&self) -> Result<MarkRead> {
        let what = self.describe();
        let v = match self.http.get(&self.path()).map_err(|e| *e) {
            Ok(r) => Self::body(r, &what)?,
            // Never written. (A deleted mark also answers 404; its next
            // write, from version 0, then conflicts: it fails closed.)
            Err(ureq::Error::Status(404, _)) => return Ok(MarkRead { mark: None, cas: 0 }),
            Err(ureq::Error::Status(code, r)) => {
                return Err(mark_unavailable(
                    &what,
                    format!("refused ({code}): {}", bao_errors(r)),
                ))
            }
            Err(e) => return Err(mark_unavailable(&what, e)),
        };
        let cas = v["data"]["metadata"]["version"]
            .as_u64()
            .ok_or_else(|| mark_unavailable(&what, "no version in the answer"))?;
        let mark: Mark = serde_json::from_value(v["data"]["data"].clone())
            .map_err(|e| mark_unavailable(&what, format!("malformed mark: {e}")))?;
        Ok(MarkRead {
            mark: Some(check_mark(&self.broker_id, mark, &what)?),
            cas,
        })
    }

    fn advance(&self, mark: &Mark, expected_cas: u64) -> Result<u64> {
        let what = self.describe();
        let body = serde_json::json!({"options": {"cas": expected_cas}, "data": mark});
        match self.http.post(&self.path(), body).map_err(|e| *e) {
            Ok(r) => Self::body(r, &what)?["data"]["version"]
                .as_u64()
                .ok_or_else(|| mark_unavailable(&what, "no version in the answer")),
            Err(ureq::Error::Status(400, r)) => {
                let e = bao_errors(r);
                if e.contains("check-and-set") {
                    Err(mark_conflict(&what))
                } else {
                    Err(mark_unavailable(&what, format!("refused (400): {e}")))
                }
            }
            Err(ureq::Error::Status(code, r)) => Err(mark_unavailable(
                &what,
                format!("refused ({code}): {}", bao_errors(r)),
            )),
            Err(e) => Err(mark_unavailable(&what, e)),
        }
    }
}

// --- development --------------------------------------------------------------

/// The mark in a separate local file (mode 0600). Development only: a
/// production broker refuses it. Whoever can restore the state file can
/// usually restore this one too, so it demonstrates the checks and protects
/// little.
pub struct DevelopmentFileMark {
    path: PathBuf,
    broker_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileMark {
    cas: u64,
    mark: Mark,
}

impl DevelopmentFileMark {
    pub fn new(path: &Path, broker_id: &str) -> Self {
        Self {
            path: path.into(),
            broker_id: broker_id.into(),
        }
    }

    fn load(&self) -> Result<Option<FileMark>> {
        let what = self.describe();
        match std::fs::read(&self.path) {
            Ok(b) => serde_json::from_slice(&b)
                .map(Some)
                .map_err(|e| mark_unavailable(&what, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(mark_unavailable(&what, e)),
        }
    }
}

impl GenerationMark for DevelopmentFileMark {
    fn describe(&self) -> String {
        format!("file:{}", self.path.display())
    }

    fn security(&self) -> StoreSecurity {
        StoreSecurity::DevelopmentOnly
    }

    fn read(&self) -> Result<MarkRead> {
        Ok(match self.load()? {
            Some(f) => MarkRead {
                mark: Some(check_mark(&self.broker_id, f.mark, &self.describe())?),
                cas: f.cas,
            },
            None => MarkRead { mark: None, cas: 0 },
        })
    }

    fn advance(&self, mark: &Mark, expected_cas: u64) -> Result<u64> {
        let what = self.describe();
        let current = self.load()?.map_or(0, |f| f.cas);
        if current != expected_cas {
            return Err(mark_conflict(&what));
        }
        let next = FileMark {
            cas: current + 1,
            mark: mark.clone(),
        };
        let io = |e: std::io::Error| mark_unavailable(&what, e);
        let tmp = self.path.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp);
        {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp).map_err(io)?;
            f.write_all(&serde_json::to_vec_pretty(&next).expect("serializable"))
                .and_then(|_| f.sync_all())
                .map_err(io)?;
        }
        std::fs::rename(&tmp, &self.path).map_err(io)?;
        Ok(next.cas)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_ids_that_are_not_plain_names_are_hashed() {
        assert_eq!(broker_segment("keybroker-tax"), "keybroker-tax");
        for id in ["https://kb.example/x", "..", "a/b", "a?b", "a#b", "a b"] {
            let s = broker_segment(id);
            assert!(s.starts_with("sha256-") && s.len() == 71, "{id} -> {s}");
        }
    }

    #[test]
    fn the_file_mark_compares_and_sets() {
        let dir = std::env::temp_dir().join(format!("encompute-mark-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let m = DevelopmentFileMark::new(&dir.join("mark.json"), "b");
        assert_eq!(m.read().unwrap(), MarkRead { mark: None, cas: 0 });
        let mark = Mark {
            broker_id: "b".into(),
            generation: 3,
            state_mac: "ab".into(),
        };
        assert_eq!(m.advance(&mark, 0).unwrap(), 1);
        let e = m.advance(&mark, 0).unwrap_err();
        assert_eq!(e.code, Code::GovernanceBrokerStateRollback);
        assert!(!e.message.starts_with(MARK_UNAVAILABLE), "{e}");
        assert_eq!(m.read().unwrap().mark, Some(mark));
        let other = DevelopmentFileMark::new(&dir.join("mark.json"), "c");
        assert!(other.read().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
