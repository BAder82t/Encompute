//! Sealed artifacts: a model, dataset, checkpoint or adapter encrypted
//! (ChaCha20-Poly1305) under a key only an attested workload receives. The
//! header (what it is, whose, bound to what) is readable without the key
//! but authenticated by it: changing any of it makes opening fail.
//!
//! `ENCSEAL1 || u32le header length || canonical header || nonce(12) ||
//! ciphertext`, with the magic, length and header as associated data.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::hex;

const MAGIC: &[u8; 8] = b"ENCSEAL1";
const MAX_HEADER: usize = 1 << 20;

fn err(m: impl Into<String>) -> Error {
    Error::new(Code::Checkpoint, m)
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn cipher(key: &[u8]) -> Result<ChaCha20Poly1305> {
    let k: [u8; 32] = key
        .try_into()
        .map_err(|_| err("a sealing key is 32 bytes"))?;
    Ok(ChaCha20Poly1305::new(&Key::from(k)))
}

/// Encrypts `plaintext` under `key`, authenticating `header`.
pub fn seal<H: Serialize>(key: &[u8], header: &H, plaintext: &[u8]) -> Result<Vec<u8>> {
    let h = canonical_json(header)?;
    let mut aad = MAGIC.to_vec();
    aad.extend_from_slice(&(h.len() as u32).to_le_bytes());
    aad.extend_from_slice(&h);
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| err(format!("no randomness: {e}")))?;
    let ct = cipher(key)?
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| err("encryption failed"))?;
    let mut out = aad;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// A sealed artifact's parts: associated data (magic, length, header), the
/// header, the nonce and the ciphertext.
type Parts<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8]);

fn split(bytes: &[u8]) -> Result<Parts<'_>> {
    if bytes.len() < 12 || &bytes[..8] != MAGIC {
        return Err(err("not a sealed Encompute artifact"));
    }
    let n = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")) as usize;
    if n > MAX_HEADER || bytes.len() < 12 + n + 12 + 16 {
        return Err(err("truncated sealed artifact"));
    }
    Ok((
        &bytes[..12 + n],
        &bytes[12..12 + n],
        &bytes[12 + n..24 + n],
        &bytes[24 + n..],
    ))
}

/// The header, unauthenticated (for routing: which key to ask for).
pub fn peek<H: DeserializeOwned>(bytes: &[u8]) -> Result<H> {
    let (_, h, _, _) = split(bytes)?;
    serde_json::from_slice(h).map_err(|e| err(format!("malformed sealed header: {e}")))
}

/// Decrypts and authenticates; the header is returned only if it is the
/// one sealed.
pub fn open<H: DeserializeOwned>(key: &[u8], bytes: &[u8]) -> Result<(H, Zeroizing<Vec<u8>>)> {
    let (aad, h, nonce, ct) = split(bytes)?;
    let n: [u8; 12] = nonce.try_into().expect("12 bytes");
    let pt = cipher(key)?
        .decrypt(&Nonce::from(n), Payload { msg: ct, aad })
        .map_err(|_| err("the sealed artifact was modified, or this is the wrong key"))?;
    let header =
        serde_json::from_slice(h).map_err(|e| err(format!("malformed sealed header: {e}")))?;
    Ok((header, Zeroizing::new(pt)))
}

pub const ASSET_VERSION: u32 = 1;

/// What a sealed model or dataset is.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetHeader {
    pub version: u32,
    /// `model`, `dataset` or `adapter`.
    pub kind: String,
    pub project: String,
    pub asset_id: String,
    /// SHA-256 of the plaintext (hex): the commitment the spec binds.
    pub digest: String,
}

/// Seals an asset, committing to its plaintext digest.
pub fn seal_asset(
    key: &[u8],
    kind: &str,
    project: &str,
    asset_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    seal(
        key,
        &AssetHeader {
            version: ASSET_VERSION,
            kind: kind.into(),
            project: project.into(),
            asset_id: asset_id.into(),
            digest: sha256_hex(plaintext),
        },
        plaintext,
    )
}

/// Opens an asset, checking it is `asset_id` of `project` with the
/// committed `digest`.
pub fn open_asset(
    key: &[u8],
    bytes: &[u8],
    project: &str,
    asset_id: &str,
    digest: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let (h, pt): (AssetHeader, _) = open(key, bytes)?;
    if h.version != ASSET_VERSION {
        return Err(Error::new(
            Code::Checkpoint,
            format!("sealed asset version {} is not supported", h.version),
        ));
    }
    if h.project != project || h.asset_id != asset_id {
        return Err(Error::new(
            Code::TrainingSpec,
            format!(
                "this is {} of {}, not {asset_id} of {project}",
                h.asset_id, h.project
            ),
        ));
    }
    if h.digest != digest || sha256_hex(&pt) != digest {
        return Err(Error::new(
            Code::TrainingSpec,
            format!("{asset_id} is not the version the training spec commits to"),
        ));
    }
    Ok(pt)
}
