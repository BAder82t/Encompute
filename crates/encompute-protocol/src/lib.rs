//! Encompute envelopes. Every object exchanged between client
//! and evaluator or written to disk is wrapped, never raw backend bytes:
//!
//! ```text
//! "ENCM" | format u16 LE | header_len u32 LE | header (JSON) | payload | SHA-256 of everything before
//! ```
//!
//! The header binds the payload to a scheme, backend version, parameter set,
//! program and key. Readers state what they expect with [`Expect`], and any
//! mismatch is an error with a specific code.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use encompute_ir::{Code, Error, Result};

pub const MAGIC: &[u8; 4] = b"ENCM";
pub const FORMAT_VERSION: u16 = 1;
/// Upper bound on the JSON header, to refuse absurd inputs early.
const MAX_HEADER: usize = 1 << 20;

/// Lowercase hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Relinearization and rotation keys, client → evaluator.
    EvaluationKeys,
    /// Encrypted program inputs, client → evaluator.
    Inputs,
    /// Encrypted program outputs, evaluator → client.
    Outputs,
    /// The client's secret key, on the client's disk only.
    SecretKey,
}

/// One named payload segment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    pub name: String,
    pub len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub kind: Kind,
    pub scheme: String,
    pub backend: String,
    pub backend_version: String,
    /// SHA-256 of the artifact's `parameters.json`.
    pub parameter_set_id: String,
    /// SHA-256 of the artifact's `program.eir` (inputs and outputs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_id: Option<String>,
    /// SHA-256 of the evaluation-key payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub items: Vec<Item>,
}

/// What a reader requires of an envelope.
#[derive(Clone, Debug)]
pub struct Expect<'a> {
    pub kind: Kind,
    /// "CKKS" or "TFHE"; never inferred from the backend.
    pub scheme: &'a str,
    pub backend: &'a str,
    pub backend_version: &'a str,
    pub parameter_set_id: &'a str,
    pub program_id: Option<&'a str>,
    pub key_id: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Envelope {
    pub header: Header,
    /// Concatenated item payloads, in `header.items` order.
    pub payload: Vec<u8>,
}

fn bad(msg: impl Into<String>) -> Error {
    Error::new(Code::Envelope, msg)
}

impl Envelope {
    /// Build an envelope from named payloads.
    pub fn new(mut header: Header, items: Vec<(String, Vec<u8>)>) -> Self {
        header.items = items
            .iter()
            .map(|(n, b)| Item {
                name: n.clone(),
                len: b.len() as u64,
            })
            .collect();
        let payload = items.into_iter().flat_map(|(_, b)| b).collect();
        Self { header, payload }
    }

    pub fn encode(&self) -> Vec<u8> {
        let header = serde_json::to_vec(&self.header).expect("serializable");
        let mut out = Vec::with_capacity(4 + 2 + 4 + header.len() + self.payload.len() + 32);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&(header.len() as u32).to_le_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.payload);
        let digest = Sha256::digest(&out);
        out.extend_from_slice(&digest);
        out
    }

    /// Parse and verify structure and checksum. Does not check bindings;
    /// use [`Envelope::check`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 + 2 + 4 + 32 {
            return Err(bad("envelope is truncated"));
        }
        if &bytes[..4] != MAGIC {
            return Err(bad("not an Encompute envelope"));
        }
        let (body, digest) = bytes.split_at(bytes.len() - 32);
        if Sha256::digest(body).as_slice() != digest {
            return Err(bad(
                "envelope checksum mismatch: the data was corrupted or modified",
            ));
        }
        let version = u16::from_le_bytes([body[4], body[5]]);
        if version != FORMAT_VERSION {
            return Err(Error::new(
                Code::Incompatible,
                format!("envelope format {version}, this Encompute reads {FORMAT_VERSION}"),
            ));
        }
        let hlen = u32::from_le_bytes(body[6..10].try_into().unwrap()) as usize;
        if hlen > MAX_HEADER || 10 + hlen > body.len() {
            return Err(bad("envelope header length is invalid"));
        }
        let header: Header = serde_json::from_slice(&body[10..10 + hlen])
            .map_err(|e| bad(format!("envelope header: {e}")))?;
        let payload = body[10 + hlen..].to_vec();
        let total = header
            .items
            .iter()
            .try_fold(0u64, |acc, i| acc.checked_add(i.len))
            .ok_or_else(|| bad("item lengths overflow"))?;
        if total != payload.len() as u64 {
            return Err(bad("item lengths do not match the payload"));
        }
        Ok(Self { header, payload })
    }

    /// Named payload segments.
    pub fn items(&self) -> Vec<(&str, &[u8])> {
        let mut at = 0usize;
        self.header
            .items
            .iter()
            .map(|i| {
                let s = &self.payload[at..at + i.len as usize];
                at += i.len as usize;
                (i.name.as_str(), s)
            })
            .collect()
    }

    /// Enforce every binding in `e`.
    pub fn check(&self, e: &Expect<'_>) -> Result<()> {
        let h = &self.header;
        if h.kind != e.kind {
            return Err(Error::new(
                Code::Incompatible,
                format!("expected {:?}, got {:?}", e.kind, h.kind),
            ));
        }
        if h.scheme != e.scheme || h.backend != e.backend || h.backend_version != e.backend_version
        {
            return Err(Error::new(
                Code::Incompatible,
                format!(
                    "made for {} on {} {}, this side runs {} on {} {}",
                    h.scheme, h.backend, h.backend_version, e.scheme, e.backend, e.backend_version
                ),
            ));
        }
        if h.parameter_set_id != e.parameter_set_id {
            return Err(Error::new(
                Code::WrongParameters,
                "made for a different parameter set; recompile or regenerate keys",
            ));
        }
        if let Some(p) = e.program_id {
            if h.program_id.as_deref() != Some(p) {
                return Err(Error::new(
                    Code::WrongProgram,
                    "made for a different program",
                ));
            }
        }
        if let Some(k) = e.key_id {
            if h.key_id.as_deref() != Some(k) {
                return Err(Error::new(Code::WrongKey, "made under a different key"));
            }
        }
        Ok(())
    }
}

/// Decode and check in one step.
pub fn open(bytes: &[u8], expect: &Expect<'_>) -> Result<Envelope> {
    let env = Envelope::decode(bytes)?;
    env.check(expect)?;
    Ok(env)
}
