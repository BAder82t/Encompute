use encompute_backend::ExactClient;
use encompute_ir::{Code, Elem, Error, Result};
use encompute_tfhe::tfhe_rs::{config, MAX_CT_BYTES, MAX_KEY_BYTES};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_serialize, DeserializationConfig};
use tfhe::{
    ClientKey, CompressedServerKey, FheBool, FheInt16, FheInt32, FheInt64, FheInt8, FheUint16,
    FheUint32, FheUint64, FheUint8,
};

fn backend(e: impl std::fmt::Display) -> Error {
    Error::new(Code::Backend, format!("TFHE-rs: {e}"))
}

/// Holds the TFHE-rs client key. Keep it on the client machine.
pub struct TfheRsClient {
    key: ClientKey,
    /// Compressed server key, when this client generated it.
    server_key: Option<Vec<u8>>,
}

impl TfheRsClient {
    /// Generate a client key and a compressed server key.
    pub fn generate() -> Result<Self> {
        let key = ClientKey::generate(config());
        let compressed = CompressedServerKey::new(&key);
        let mut server_key = vec![];
        safe_serialize(&compressed, &mut server_key, MAX_KEY_BYTES).map_err(backend)?;
        Ok(Self {
            key,
            server_key: Some(server_key),
        })
    }

    /// The client key, for the client's disk only.
    pub fn secret_key(&self) -> Result<Vec<u8>> {
        let mut out = vec![];
        safe_serialize(&self.key, &mut out, MAX_KEY_BYTES).map_err(backend)?;
        Ok(out)
    }

    /// Restore from [`TfheRsClient::secret_key`] bytes. A restored client
    /// does not re-export the server key (use the saved `eval.keys`).
    pub fn restore(secret: &[u8]) -> Result<Self> {
        let key: ClientKey = DeserializationConfig::new(MAX_KEY_BYTES)
            .disable_conformance()
            .deserialize_from(secret)
            .map_err(|e| Error::new(Code::WrongKey, format!("TFHE-rs client key rejected: {e}")))?;
        Ok(Self {
            key,
            server_key: None,
        })
    }
}

macro_rules! enc {
    ($T:ty, $v:expr, $key:expr) => {{
        let ct = <$T>::encrypt($v, $key);
        let mut out = vec![];
        safe_serialize(&ct, &mut out, MAX_CT_BYTES).map_err(backend)?;
        out
    }};
}

/// Evaluator output is loaded with the size limit and versioned type check,
/// but not TFHE-rs's fresh-ciphertext conformance profile, which rejects
/// valid results of some operations (e.g. multiplication). Strict
/// conformance applies on the evaluator, where untrusted input arrives; a
/// malformed result here becomes an error, never a panic.
macro_rules! dec {
    ($T:ty, $clear:ty, $bytes:expr, $key:expr) => {{
        let ct: $T = DeserializationConfig::new(MAX_CT_BYTES)
            .disable_conformance()
            .deserialize_from($bytes)
            .map_err(|e| Error::new(Code::Envelope, format!("TFHE-rs ciphertext rejected: {e}")))?;
        let key = $key;
        let v: $clear = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ct.decrypt(key)))
            .map_err(|_| Error::new(Code::Envelope, "malformed TFHE-rs ciphertext"))?;
        v
    }};
}

impl ExactClient for TfheRsClient {
    fn name(&self) -> &'static str {
        "tfhe-rs"
    }

    fn encrypt(&self, elem: Elem, v: i128) -> Result<Vec<u8>> {
        let k = &self.key;
        Ok(match elem {
            Elem::Bool => enc!(FheBool, v != 0, k),
            Elem::U8 => enc!(FheUint8, v as u8, k),
            Elem::U16 => enc!(FheUint16, v as u16, k),
            Elem::U32 => enc!(FheUint32, v as u32, k),
            Elem::U64 => enc!(FheUint64, v as u64, k),
            Elem::I8 => enc!(FheInt8, v as i8, k),
            Elem::I16 => enc!(FheInt16, v as i16, k),
            Elem::I32 => enc!(FheInt32, v as i32, k),
            Elem::I64 => enc!(FheInt64, v as i64, k),
            Elem::F64 => return Err(backend("f64 is not an exact type")),
        })
    }

    fn decrypt(&self, elem: Elem, b: &[u8]) -> Result<i128> {
        Ok(match elem {
            Elem::Bool => i128::from(dec!(FheBool, bool, b, &self.key)),
            Elem::U8 => dec!(FheUint8, u8, b, &self.key) as i128,
            Elem::U16 => dec!(FheUint16, u16, b, &self.key) as i128,
            Elem::U32 => dec!(FheUint32, u32, b, &self.key) as i128,
            Elem::U64 => dec!(FheUint64, u64, b, &self.key) as i128,
            Elem::I8 => dec!(FheInt8, i8, b, &self.key) as i128,
            Elem::I16 => dec!(FheInt16, i16, b, &self.key) as i128,
            Elem::I32 => dec!(FheInt32, i32, b, &self.key) as i128,
            Elem::I64 => dec!(FheInt64, i64, b, &self.key) as i128,
            Elem::F64 => return Err(backend("f64 is not an exact type")),
        })
    }

    fn evaluation_keys(&self) -> Result<Vec<u8>> {
        self.server_key.clone().ok_or_else(|| {
            Error::new(
                Code::WrongKey,
                "a restored client has no server key; use the saved eval.keys",
            )
        })
    }
}
