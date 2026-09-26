//! The OpenFHE exact client: the only code that holds the BinFHE secret
//! key. Encrypts exact values bit by bit (two's complement, least
//! significant bit first), decrypts results, and exports the bootstrapping
//! keys the evaluator needs, all in Encompute envelopes bound to this key
//! and parameter set.

use encompute_backend::ExactClient;
use encompute_exact::bits::{OPENFHE_EXACT_BACKEND, OPENFHE_EXACT_PARAMSET};
use encompute_ir::{Code, Elem, Error, Result};
use encompute_openfhe_exact::{
    default_profile, envelope_elem, open, parameter_id, seal, Header, KIND_CIPHERTEXT,
    KIND_EVALUATION_KEYS, KIND_SECRET_KEY,
};

use crate::BinClient;

pub struct OpenFheExactClient {
    bin: BinClient,
    key_id: [u8; 16],
    parameter_id: [u8; 32],
    /// Only a freshly generated client holds the bootstrapping keys.
    fresh: bool,
}

impl OpenFheExactClient {
    /// A fresh secret key and bootstrapping keys (128-bit, STD128/GINX).
    pub fn generate() -> Result<Self> {
        let mut key_id = [0u8; 16];
        getrandom::getrandom(&mut key_id)
            .map_err(|e| Error::new(Code::Backend, format!("no randomness: {e}")))?;
        Ok(Self {
            bin: BinClient::generate(OPENFHE_EXACT_PARAMSET)?,
            key_id,
            parameter_id: parameter_id(&default_profile()),
            fresh: true,
        })
    }

    /// The secret key, in an envelope (keep it on the client machine).
    pub fn secret_key(&self) -> Result<Vec<u8>> {
        let sk = self.bin.secret_key()?;
        Ok(seal(&self.header(KIND_SECRET_KEY, 0), &[&sk]))
    }

    pub fn restore(secret: &[u8]) -> Result<Self> {
        let (h, p) = open(secret)?;
        let pid = parameter_id(&default_profile());
        if h.kind != KIND_SECRET_KEY || p.len() != 1 {
            return Err(Error::new(
                Code::WrongKey,
                "not an OpenFHE exact secret key",
            ));
        }
        if h.parameter_id != pid {
            return Err(Error::new(
                Code::WrongParameters,
                "a secret key for another parameter set",
            ));
        }
        Ok(Self {
            bin: BinClient::restore(OPENFHE_EXACT_PARAMSET, p[0])?,
            key_id: h.key_id,
            parameter_id: pid,
            fresh: false,
        })
    }

    pub fn key_id(&self) -> [u8; 16] {
        self.key_id
    }

    fn header(&self, kind: u8, elem: u8) -> Header {
        Header {
            kind,
            parameter_id: self.parameter_id,
            key_id: self.key_id,
            elem,
        }
    }
}

impl ExactClient for OpenFheExactClient {
    fn name(&self) -> &'static str {
        OPENFHE_EXACT_BACKEND
    }

    fn encrypt(&self, elem: Elem, v: i128) -> Result<Vec<u8>> {
        if !elem.is_exact() {
            return Err(Error::new(Code::Backend, "f64 is not an exact type"));
        }
        let (lo, hi) = elem.bounds();
        if v < lo || v > hi {
            return Err(Error::new(Code::BadInput, format!("{v} is not a {elem}")));
        }
        let bits: Vec<Vec<u8>> = (0..elem.bits())
            .map(|i| self.bin.encrypt_bit((v >> i) & 1 == 1))
            .collect::<Result<_>>()?;
        let refs: Vec<&[u8]> = bits.iter().map(|b| b.as_slice()).collect();
        Ok(seal(
            &self.header(KIND_CIPHERTEXT, envelope_elem(elem)),
            &refs,
        ))
    }

    fn decrypt(&self, elem: Elem, ciphertext: &[u8]) -> Result<i128> {
        let (h, p) = open(ciphertext)?;
        if h.kind != KIND_CIPHERTEXT {
            return Err(Error::new(Code::Envelope, "not a ciphertext"));
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
        if h.elem != envelope_elem(elem) || p.len() != elem.bits() as usize {
            return Err(Error::new(
                Code::Envelope,
                format!("the ciphertext is not a {elem}"),
            ));
        }
        let mut v: i128 = 0;
        for (i, b) in p.iter().enumerate() {
            if self.bin.decrypt_bit(b)? {
                v |= 1 << i;
            }
        }
        if elem.is_signed() && (v >> (elem.bits() - 1)) & 1 == 1 {
            v -= 1 << elem.bits();
        }
        Ok(v)
    }

    fn evaluation_keys(&self) -> Result<Vec<u8>> {
        if !self.fresh {
            return Err(Error::new(
                Code::Backend,
                "a restored OpenFHE exact client has no bootstrapping keys; export them when \
                 the keys are generated",
            ));
        }
        let (refresh, switching) = self.bin.bootstrapping_keys()?;
        Ok(seal(
            &self.header(KIND_EVALUATION_KEYS, 0),
            &[&refresh, &switching],
        ))
    }
}
