//! Exact encrypted execution on OpenFHE: the evaluator side.
//!
//! Every exact value is a vector of OpenFHE BinFHE ciphertexts, one per bit
//! (`encompute_exact::bits`, representation v1), and every exact operation
//! is a gate circuit evaluated with the client's bootstrapping keys. The
//! integer semantics are Encompute's (in Rust); the C++ boundary exposes
//! only gates, NOT, constants and serialization.
//!
//! Objects travel in Encompute envelopes, not bare OpenFHE serialization:
//! magic, format version, backend, parameter-set ID, key ID, object kind,
//! type, length-prefixed payloads and a SHA-256 checksum. A ciphertext from
//! another key, parameter set or backend is refused before evaluation.
//!
//! No key generation, encryption or decryption here: the client
//! (`encompute-openfhe-client`) holds the secret key, and the evaluator
//! binary never links it.

use sha2::{Digest, Sha256};

use encompute_exact::bits::{
    BitEvaluator, Gates, OPENFHE_EXACT_BACKEND, OPENFHE_EXACT_PARAMSET, OPENFHE_EXACT_VERSION,
};
use encompute_exact::ExactProfile;
use encompute_ir::{Code, Elem, Error, Result};
use encompute_openfhe::binfhe::{BinCiphertext, BinContext, Gate};

pub use encompute_exact::bits::{check_capabilities, CAPABILITIES};

pub const ENVELOPE_VERSION: u32 = 1;
const MAGIC: &[u8; 8] = b"ENCBINF1";
/// Object kinds.
pub const KIND_CIPHERTEXT: u8 = 1;
pub const KIND_EVALUATION_KEYS: u8 = 2;
pub const KIND_SECRET_KEY: u8 = 3;
/// Largest payload accepted (the switching key is about 450 MB).
pub const MAX_PAYLOAD: usize = 1 << 30;

fn bad(m: impl Into<String>) -> Error {
    Error::new(Code::Envelope, format!("OpenFHE exact: {}", m.into()))
}

/// The parameter-set ID: SHA-256 of the profile's canonical JSON.
pub fn parameter_id(profile: &ExactProfile) -> [u8; 32] {
    Sha256::digest(profile.canonical_json().as_bytes()).into()
}

pub fn default_profile() -> ExactProfile {
    encompute_exact::bits::openfhe_exact_profile()
}

fn elem_code(e: Elem) -> u8 {
    Elem::EXACT
        .iter()
        .position(|x| *x == e)
        .map_or(255, |i| i as u8)
}

/// An envelope's header: what it holds and for whom.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    pub parameter_id: [u8; 32],
    pub key_id: [u8; 16],
    pub elem: u8,
}

/// Wraps payloads: `MAGIC | version | backend | parameter ID | key ID |
/// kind | elem | count | (len, payload)* | SHA-256 of all before`.
pub fn seal(h: &Header, payloads: &[&[u8]]) -> Vec<u8> {
    let mut b = MAGIC.to_vec();
    b.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    b.extend_from_slice(&(OPENFHE_EXACT_BACKEND.len() as u32).to_le_bytes());
    b.extend_from_slice(OPENFHE_EXACT_BACKEND.as_bytes());
    b.extend_from_slice(&h.parameter_id);
    b.extend_from_slice(&h.key_id);
    b.push(h.kind);
    b.push(h.elem);
    b.extend_from_slice(&(payloads.len() as u32).to_le_bytes());
    for p in payloads {
        b.extend_from_slice(&(p.len() as u64).to_le_bytes());
        b.extend_from_slice(p);
    }
    let sum = Sha256::digest(&b);
    b.extend_from_slice(&sum);
    b
}

/// Opens an envelope, checking its checksum, version and backend; the
/// caller checks the kind, parameter set and key.
pub fn open(bytes: &[u8]) -> Result<(Header, Vec<&[u8]>)> {
    if bytes.len() < 8 + 32 || &bytes[..8] != MAGIC {
        return Err(bad("not an OpenFHE exact envelope"));
    }
    let (body, sum) = bytes.split_at(bytes.len() - 32);
    if Sha256::digest(body).as_slice() != sum {
        return Err(bad("the envelope's checksum does not match (corrupted)"));
    }
    let mut at = 8usize;
    let take = |at: &mut usize, n: usize| -> Result<&[u8]> {
        let s = body
            .get(*at..*at + n)
            .ok_or_else(|| bad("truncated envelope"))?;
        *at += n;
        Ok(s)
    };
    let u32_ = |s: &[u8]| u32::from_le_bytes(s.try_into().expect("4 bytes"));
    if u32_(take(&mut at, 4)?) != ENVELOPE_VERSION {
        return Err(bad("unsupported envelope version"));
    }
    let n = u32_(take(&mut at, 4)?) as usize;
    if n > 64 {
        return Err(bad("backend name too long"));
    }
    let backend = take(&mut at, n)?;
    if backend != OPENFHE_EXACT_BACKEND.as_bytes() {
        return Err(Error::new(
            Code::WrongParameters,
            format!(
                "an object for backend {:?}, not {OPENFHE_EXACT_BACKEND}",
                String::from_utf8_lossy(backend)
            ),
        ));
    }
    let parameter_id: [u8; 32] = take(&mut at, 32)?.try_into().expect("32");
    let key_id: [u8; 16] = take(&mut at, 16)?.try_into().expect("16");
    let kind = take(&mut at, 1)?[0];
    let elem = take(&mut at, 1)?[0];
    let count = u32_(take(&mut at, 4)?) as usize;
    if count > 64 * 1024 {
        return Err(bad("too many payloads"));
    }
    let mut payloads = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u64::from_le_bytes(take(&mut at, 8)?.try_into().expect("8")) as usize;
        if len > MAX_PAYLOAD {
            return Err(bad("payload too large"));
        }
        payloads.push(take(&mut at, len)?);
    }
    if at != body.len() {
        return Err(bad("trailing bytes in the envelope"));
    }
    Ok((
        Header {
            kind,
            parameter_id,
            key_id,
            elem,
        },
        payloads,
    ))
}

/// OpenFHE BinFHE as a [`Gates`] library, with the client's bootstrapping
/// keys loaded, bound to one parameter set and key.
pub struct OpenFheGates {
    ctx: BinContext,
    parameter_id: [u8; 32],
    key_id: [u8; 16],
}

impl OpenFheGates {
    /// Loads the client's evaluation keys (an envelope of kind
    /// [`KIND_EVALUATION_KEYS`]: refresh key, switching key) for `profile`.
    pub fn new(profile: &ExactProfile, evaluation_keys: &[u8]) -> Result<Self> {
        if profile.backend != OPENFHE_EXACT_BACKEND
            || profile.backend_version != OPENFHE_EXACT_VERSION
            || *profile != default_profile()
        {
            return Err(Error::new(
                Code::WrongParameters,
                format!(
                    "the OpenFHE exact backend runs only its vetted profile, not {} {} {}",
                    profile.backend, profile.backend_version, profile.profile
                ),
            ));
        }
        let (h, p) = open(evaluation_keys)?;
        let pid = parameter_id(profile);
        if h.kind != KIND_EVALUATION_KEYS || p.len() != 2 {
            return Err(bad("not OpenFHE exact evaluation keys"));
        }
        if h.parameter_id != pid {
            return Err(Error::new(
                Code::WrongParameters,
                "evaluation keys for another parameter set",
            ));
        }
        let mut ctx = BinContext::new(OPENFHE_EXACT_PARAMSET)?;
        ctx.load_keys(p[0], p[1])?;
        Ok(Self {
            ctx,
            parameter_id: pid,
            key_id: h.key_id,
        })
    }

    pub fn key_id(&self) -> [u8; 16] {
        self.key_id
    }
}

impl Gates for OpenFheGates {
    type Bit = BinCiphertext;

    fn name(&self) -> &'static str {
        OPENFHE_EXACT_BACKEND
    }
    fn and(&self, a: &BinCiphertext, b: &BinCiphertext) -> Result<BinCiphertext> {
        self.ctx.gate(Gate::And, a, b)
    }
    fn or(&self, a: &BinCiphertext, b: &BinCiphertext) -> Result<BinCiphertext> {
        self.ctx.gate(Gate::Or, a, b)
    }
    fn xor(&self, a: &BinCiphertext, b: &BinCiphertext) -> Result<BinCiphertext> {
        self.ctx.gate(Gate::Xor, a, b)
    }
    fn not(&self, a: &BinCiphertext) -> Result<BinCiphertext> {
        self.ctx.not(a)
    }
    fn constant(&self, v: bool) -> Result<BinCiphertext> {
        self.ctx.constant(v)
    }
    fn load(&self, elem: Elem, bytes: &[u8]) -> Result<Vec<BinCiphertext>> {
        let (h, p) = open(bytes)?;
        if h.kind != KIND_CIPHERTEXT {
            return Err(bad("not a ciphertext"));
        }
        if h.parameter_id != self.parameter_id {
            return Err(Error::new(
                Code::WrongParameters,
                "a ciphertext for another parameter set",
            ));
        }
        if h.key_id != self.key_id {
            return Err(Error::new(Code::WrongKey, "a ciphertext under another key"));
        }
        if h.elem != elem_code(elem) || p.len() != elem.bits() as usize {
            return Err(bad(format!("the ciphertext is not a {elem}")));
        }
        p.iter().map(|b| self.ctx.load(b)).collect()
    }
    fn store(&self, elem: Elem, bits: &[BinCiphertext]) -> Result<Vec<u8>> {
        let payloads: Vec<Vec<u8>> = bits.iter().map(|b| b.store()).collect::<Result<_>>()?;
        let refs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
        Ok(seal(
            &Header {
                kind: KIND_CIPHERTEXT,
                parameter_id: self.parameter_id,
                key_id: self.key_id,
                elem: elem_code(elem),
            },
            &refs,
        ))
    }
}

/// The OpenFHE exact evaluator: exact plans as BinFHE gate circuits.
pub type OpenFheExactEvaluator = BitEvaluator<OpenFheGates>;

/// An evaluator for `profile` with the client's evaluation keys.
pub fn evaluator(profile: &ExactProfile, evaluation_keys: &[u8]) -> Result<OpenFheExactEvaluator> {
    Ok(BitEvaluator::new(OpenFheGates::new(
        profile,
        evaluation_keys,
    )?))
}

/// The element code written into envelopes.
pub fn envelope_elem(e: Elem) -> u8 {
    elem_code(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vetted profile is 128-bit STD128, and every field of it is bound
    /// into the parameter-set ID that keys and ciphertexts carry.
    #[test]
    fn the_profile_is_vetted_and_bound_into_the_parameter_id() {
        let p = default_profile();
        assert_eq!(p.backend, OPENFHE_EXACT_BACKEND);
        assert_eq!(p.security, "128-bit");
        assert_eq!(p.failure_probability, "2^-135 per gate");
        assert_eq!(p.profile, "BINFHE_STD128_GINX_BITS_V1");
        let id = parameter_id(&p);
        let edits: [fn(&mut ExactProfile); 6] = [
            |p| p.backend = "tfhe-rs".into(),
            |p| p.backend_version = "1.5.0".into(),
            |p| p.profile = "BINFHE_TOY".into(),
            |p| p.security = "80-bit".into(),
            |p| p.failure_probability = "2^-40 per gate".into(),
            |p| p.parameter_selector_version = "openfhe-exact-v0".into(),
        ];
        for edit in edits {
            let mut q = p.clone();
            edit(&mut q);
            assert_ne!(parameter_id(&q), id, "{q:?}");
        }
        // A sealed object carries the ID; opening it returns the same ID.
        let h = Header {
            parameter_id: id,
            key_id: [7; 16],
            kind: KIND_CIPHERTEXT,
            elem: 0,
        };
        let sealed = seal(&h, &[b"bit"]);
        let (got, payloads) = open(&sealed).unwrap();
        assert_eq!(got.parameter_id, id);
        assert_eq!(payloads, vec![&b"bit"[..]]);
    }
}
