//! The canonical formats the training runtime exchanges with PyTorch, owned
//! here so every party computes the same digests:
//! - the **adapter layout**: which LoRA parameter occupies which offsets
//!   of the aggregated vector (its digest is bound into the training spec,
//!   so no participant can reinterpret the vector);
//! - the **canonical tensor file** (`ENCTENS1`): a JSON header and raw
//!   little-endian bytes. Model weights and datasets travel only in this
//!   format; anything else, a pickle in particular, is refused before any
//!   loading.

use serde::{Deserialize, Serialize};

use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;

use crate::tagged_hex;

pub const LAYOUT_VERSION: u32 = 1;
const LAYOUT: &str = "encompute.adapter-layout.v1";
const TENSORS_MAGIC: &[u8; 8] = b"ENCTENS1";
const DTYPES: &[(&str, usize)] = &[("float32", 4), ("float64", 8), ("int64", 8)];

fn bad(m: impl Into<String>) -> Error {
    Error::new(Code::TrainingSpec, m)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutEntry {
    pub module: String,
    pub parameter: String,
    pub shape: Vec<u64>,
    pub offset: u64,
    pub length: u64,
    pub dtype: String,
}

/// The adapter's parameters in aggregation order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterLayout {
    pub version: u32,
    pub entries: Vec<LayoutEntry>,
}

impl AdapterLayout {
    /// Sorted by (module, parameter), contiguous from 0, each length the
    /// product of its shape, a known dtype.
    pub fn validate(&self) -> Result<()> {
        if self.version != LAYOUT_VERSION {
            return Err(bad(format!("adapter layout version {}", self.version)));
        }
        if self.entries.is_empty() {
            return Err(bad("an adapter layout has at least one parameter"));
        }
        let mut offset = 0u64;
        for (i, e) in self.entries.iter().enumerate() {
            if i > 0 {
                let p = &self.entries[i - 1];
                if (p.module.as_str(), p.parameter.as_str())
                    >= (e.module.as_str(), e.parameter.as_str())
                {
                    return Err(bad(
                        "layout entries must be sorted by module and parameter, distinct",
                    ));
                }
            }
            let n: u64 = e
                .shape
                .iter()
                .try_fold(1u64, |a, &d| a.checked_mul(d))
                .ok_or_else(|| bad("layout shape overflows"))?;
            if e.offset != offset || e.length != n || n == 0 {
                return Err(bad(format!(
                    "{}.{}: offset {} length {} does not follow shape {:?} at {offset}",
                    e.module, e.parameter, e.offset, e.length, e.shape
                )));
            }
            if !DTYPES.iter().any(|(d, _)| *d == e.dtype) {
                return Err(bad(format!(
                    "{}.{}: unsupported dtype {}",
                    e.module, e.parameter, e.dtype
                )));
            }
            offset += n;
        }
        Ok(())
    }

    pub fn parameters(&self) -> u64 {
        self.entries.last().map_or(0, |e| e.offset + e.length)
    }

    /// `SHA256("encompute.adapter-layout.v1" || canonical layout)`.
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(tagged_hex(LAYOUT, &[&canonical_json(self)?]))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TensorEntry {
    pub name: String,
    pub dtype: String,
    pub shape: Vec<u64>,
    pub offset: u64,
    pub length: u64,
}

/// Checks a canonical tensor file and returns its entries. Refuses
/// anything that is not one (a pickle, a truncated or padded file,
/// overlapping or unsorted tensors, lengths that disagree with shapes).
pub fn tensor_manifest(bytes: &[u8]) -> Result<Vec<TensorEntry>> {
    if bytes.len() < 12 || &bytes[..8] != TENSORS_MAGIC {
        return Err(bad(
            "not a canonical tensor file (ENCTENS1): models and datasets are never loaded from \
             pickles or other formats",
        ));
    }
    let n = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")) as usize;
    let header = bytes
        .get(12..12 + n)
        .ok_or_else(|| bad("truncated tensor header"))?;
    let entries: Vec<TensorEntry> =
        serde_json::from_slice(header).map_err(|e| bad(format!("tensor header: {e}")))?;
    let body = (bytes.len() - 12 - n) as u64;
    let mut offset = 0u64;
    for (i, e) in entries.iter().enumerate() {
        if i > 0 && entries[i - 1].name >= e.name {
            return Err(bad("tensors must be sorted by name, distinct"));
        }
        let size = DTYPES
            .iter()
            .find(|(d, _)| *d == e.dtype)
            .map(|(_, s)| *s as u64)
            .ok_or_else(|| bad(format!("{}: unsupported dtype {}", e.name, e.dtype)))?;
        let count: u64 = e
            .shape
            .iter()
            .try_fold(1u64, |a, &d| a.checked_mul(d))
            .ok_or_else(|| bad("tensor shape overflows"))?;
        if e.offset != offset || count.checked_mul(size) != Some(e.length) {
            return Err(bad(format!(
                "{}: offset or length does not match its shape",
                e.name
            )));
        }
        offset += e.length;
    }
    if offset != body {
        return Err(bad("the tensor file's body is truncated or padded"));
    }
    Ok(entries)
}
