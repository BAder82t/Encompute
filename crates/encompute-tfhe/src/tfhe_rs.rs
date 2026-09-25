//! TFHE-rs 1.8.1 evaluator (feature `tfhe-rs`). TFHE-rs source is
//! BSD-3-Clause-Clear; Zama states that commercial use of its technology
//! requires a separate patent license.
//!
//! Holds the server (evaluation) key only. Ciphertexts and keys are loaded
//! with TFHE-rs conformance checks against the expected parameters.

use encompute_backend::ExactEvaluator;
use encompute_ir::{CmpOp, Code, Elem, Error, LogicOp, Result};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_serialize, DeserializationConfig};
use tfhe::{
    CompressedServerKey, ConfigBuilder, FheBool, FheBoolConformanceParams, FheInt16,
    FheInt16ConformanceParams, FheInt32, FheInt32ConformanceParams, FheInt64,
    FheInt64ConformanceParams, FheInt8, FheInt8ConformanceParams, FheUint16,
    FheUint16ConformanceParams, FheUint32, FheUint32ConformanceParams, FheUint64,
    FheUint64ConformanceParams, FheUint8, FheUint8ConformanceParams, MatchValues, ServerKey,
};

/// Largest accepted server key and ciphertext, in bytes.
pub const MAX_KEY_BYTES: u64 = 1 << 32;
pub const MAX_CT_BYTES: u64 = 1 << 28;

fn backend(e: impl std::fmt::Display) -> Error {
    Error::new(Code::Backend, format!("TFHE-rs: {e}"))
}

/// The TFHE-rs configuration Encompute uses (see `default_profile`).
pub fn config() -> tfhe::Config {
    ConfigBuilder::default().build()
}

#[derive(Clone)]
pub enum Ct {
    B(FheBool),
    U8(FheUint8),
    U16(FheUint16),
    U32(FheUint32),
    U64(FheUint64),
    I8(FheInt8),
    I16(FheInt16),
    I32(FheInt32),
    I64(FheInt64),
}

impl Ct {
    pub fn elem(&self) -> Elem {
        match self {
            Ct::B(_) => Elem::Bool,
            Ct::U8(_) => Elem::U8,
            Ct::U16(_) => Elem::U16,
            Ct::U32(_) => Elem::U32,
            Ct::U64(_) => Elem::U64,
            Ct::I8(_) => Elem::I8,
            Ct::I16(_) => Elem::I16,
            Ct::I32(_) => Elem::I32,
            Ct::I64(_) => Elem::I64,
        }
    }
}

/// Apply `$f` to an integer ciphertext and rewrap it as the same type;
/// `$clear` is the variant's clear type for scalar operands.
macro_rules! int_unary {
    ($a:expr, |$x:ident, $clear:ident| $body:expr) => {
        match $a {
            Ct::U8($x) => {
                #[allow(dead_code)]
                type $clear = u8;
                Ok(Ct::U8($body))
            }
            Ct::U16($x) => {
                #[allow(dead_code)]
                type $clear = u16;
                Ok(Ct::U16($body))
            }
            Ct::U32($x) => {
                #[allow(dead_code)]
                type $clear = u32;
                Ok(Ct::U32($body))
            }
            Ct::U64($x) => {
                #[allow(dead_code)]
                type $clear = u64;
                Ok(Ct::U64($body))
            }
            Ct::I8($x) => {
                #[allow(dead_code)]
                type $clear = i8;
                Ok(Ct::I8($body))
            }
            Ct::I16($x) => {
                #[allow(dead_code)]
                type $clear = i16;
                Ok(Ct::I16($body))
            }
            Ct::I32($x) => {
                #[allow(dead_code)]
                type $clear = i32;
                Ok(Ct::I32($body))
            }
            Ct::I64($x) => {
                #[allow(dead_code)]
                type $clear = i64;
                Ok(Ct::I64($body))
            }
            Ct::B(_) => Err(backend("integer operation on bool")),
        }
    };
}

/// Same as `int_unary` but for operations returning a bool.
macro_rules! int_to_bool {
    ($a:expr, |$x:ident, $clear:ident| $body:expr) => {
        match $a {
            Ct::U8($x) => {
                #[allow(dead_code)]
                type $clear = u8;
                Ok(Ct::B($body))
            }
            Ct::U16($x) => {
                #[allow(dead_code)]
                type $clear = u16;
                Ok(Ct::B($body))
            }
            Ct::U32($x) => {
                #[allow(dead_code)]
                type $clear = u32;
                Ok(Ct::B($body))
            }
            Ct::U64($x) => {
                #[allow(dead_code)]
                type $clear = u64;
                Ok(Ct::B($body))
            }
            Ct::I8($x) => {
                #[allow(dead_code)]
                type $clear = i8;
                Ok(Ct::B($body))
            }
            Ct::I16($x) => {
                #[allow(dead_code)]
                type $clear = i16;
                Ok(Ct::B($body))
            }
            Ct::I32($x) => {
                #[allow(dead_code)]
                type $clear = i32;
                Ok(Ct::B($body))
            }
            Ct::I64($x) => {
                #[allow(dead_code)]
                type $clear = i64;
                Ok(Ct::B($body))
            }
            Ct::B(_) => Err(backend("integer operation on bool")),
        }
    };
}

/// Binary operation on two integer ciphertexts of one type.
macro_rules! int_binary {
    ($a:expr, $b:expr, |$x:ident, $y:ident| $body:expr) => {
        match ($a, $b) {
            (Ct::U8($x), Ct::U8($y)) => Ok(Ct::U8($body)),
            (Ct::U16($x), Ct::U16($y)) => Ok(Ct::U16($body)),
            (Ct::U32($x), Ct::U32($y)) => Ok(Ct::U32($body)),
            (Ct::U64($x), Ct::U64($y)) => Ok(Ct::U64($body)),
            (Ct::I8($x), Ct::I8($y)) => Ok(Ct::I8($body)),
            (Ct::I16($x), Ct::I16($y)) => Ok(Ct::I16($body)),
            (Ct::I32($x), Ct::I32($y)) => Ok(Ct::I32($body)),
            (Ct::I64($x), Ct::I64($y)) => Ok(Ct::I64($body)),
            (a, b) => Err(backend(format!(
                "type mismatch {} vs {}",
                a.elem(),
                b.elem()
            ))),
        }
    };
}

macro_rules! int_binary_bool {
    ($a:expr, $b:expr, |$x:ident, $y:ident| $body:expr) => {
        match ($a, $b) {
            (Ct::U8($x), Ct::U8($y)) => Ok(Ct::B($body)),
            (Ct::U16($x), Ct::U16($y)) => Ok(Ct::B($body)),
            (Ct::U32($x), Ct::U32($y)) => Ok(Ct::B($body)),
            (Ct::U64($x), Ct::U64($y)) => Ok(Ct::B($body)),
            (Ct::I8($x), Ct::I8($y)) => Ok(Ct::B($body)),
            (Ct::I16($x), Ct::I16($y)) => Ok(Ct::B($body)),
            (Ct::I32($x), Ct::I32($y)) => Ok(Ct::B($body)),
            (Ct::I64($x), Ct::I64($y)) => Ok(Ct::B($body)),
            (Ct::B($x), Ct::B($y)) => Ok(Ct::B($body)),
            (a, b) => Err(backend(format!(
                "type mismatch {} vs {}",
                a.elem(),
                b.elem()
            ))),
        }
    };
}

/// Cast any ciphertext to integer type `to` (bool → 0/1).
fn cast_to(a: &Ct, to: Elem) -> Result<Ct> {
    macro_rules! from {
        ($T:ty) => {
            match a.clone() {
                Ct::B(x) => <$T>::cast_from(x),
                Ct::U8(x) => <$T>::cast_from(x),
                Ct::U16(x) => <$T>::cast_from(x),
                Ct::U32(x) => <$T>::cast_from(x),
                Ct::U64(x) => <$T>::cast_from(x),
                Ct::I8(x) => <$T>::cast_from(x),
                Ct::I16(x) => <$T>::cast_from(x),
                Ct::I32(x) => <$T>::cast_from(x),
                Ct::I64(x) => <$T>::cast_from(x),
            }
        };
    }
    Ok(match to {
        Elem::U8 => Ct::U8(from!(FheUint8)),
        Elem::U16 => Ct::U16(from!(FheUint16)),
        Elem::U32 => Ct::U32(from!(FheUint32)),
        Elem::U64 => Ct::U64(from!(FheUint64)),
        Elem::I8 => Ct::I8(from!(FheInt8)),
        Elem::I16 => Ct::I16(from!(FheInt16)),
        Elem::I32 => Ct::I32(from!(FheInt32)),
        Elem::I64 => Ct::I64(from!(FheInt64)),
        e => return Err(backend(format!("cannot cast to {e}"))),
    })
}

/// Evaluator: server key only.
pub struct TfheRsEvaluator {
    key: ServerKey,
}

impl TfheRsEvaluator {
    /// Load a serialized compressed server key, checking it conforms to
    /// Encompute's profile, and decompress it.
    pub fn new(server_key: &[u8]) -> Result<Self> {
        let key: CompressedServerKey = DeserializationConfig::new(MAX_KEY_BYTES)
            .deserialize_from(server_key, &config().into())
            .map_err(|e| {
                Error::new(
                    Code::WrongParameters,
                    format!("TFHE-rs server key rejected: {e}"),
                )
            })?;
        Ok(Self {
            key: key.decompress(),
        })
    }

    fn on(&self) {
        tfhe::set_server_key(self.key.clone());
    }
}

macro_rules! load_as {
    ($T:ty, $P:ty, $key:expr, $bytes:expr) => {
        DeserializationConfig::new(MAX_CT_BYTES)
            .deserialize_from::<$T>($bytes, &<$P>::from($key))
            .map_err(|e| {
                Error::new(
                    Code::WrongParameters,
                    format!("TFHE-rs ciphertext rejected: {e}"),
                )
            })?
    };
}

fn store_one(ct: &Ct) -> Result<Vec<u8>> {
    let mut out = vec![];
    match ct {
        Ct::B(x) => safe_serialize(x, &mut out, MAX_CT_BYTES),
        Ct::U8(x) => safe_serialize(x, &mut out, MAX_CT_BYTES),
        Ct::U16(x) => safe_serialize(x, &mut out, MAX_CT_BYTES),
        Ct::U32(x) => safe_serialize(x, &mut out, MAX_CT_BYTES),
        Ct::U64(x) => safe_serialize(x, &mut out, MAX_CT_BYTES),
        Ct::I8(x) => safe_serialize(x, &mut out, MAX_CT_BYTES),
        Ct::I16(x) => safe_serialize(x, &mut out, MAX_CT_BYTES),
        Ct::I32(x) => safe_serialize(x, &mut out, MAX_CT_BYTES),
        Ct::I64(x) => safe_serialize(x, &mut out, MAX_CT_BYTES),
    }
    .map_err(backend)?;
    Ok(out)
}

/// Trivial (public) ciphertext of `elem`.
fn trivial(elem: Elem, v: i128) -> Result<Ct> {
    Ok(match elem {
        Elem::Bool => Ct::B(FheBool::encrypt_trivial(v != 0)),
        Elem::U8 => Ct::U8(FheUint8::encrypt_trivial(v as u8)),
        Elem::U16 => Ct::U16(FheUint16::encrypt_trivial(v as u16)),
        Elem::U32 => Ct::U32(FheUint32::encrypt_trivial(v as u32)),
        Elem::U64 => Ct::U64(FheUint64::encrypt_trivial(v as u64)),
        Elem::I8 => Ct::I8(FheInt8::encrypt_trivial(v as i8)),
        Elem::I16 => Ct::I16(FheInt16::encrypt_trivial(v as i16)),
        Elem::I32 => Ct::I32(FheInt32::encrypt_trivial(v as i32)),
        Elem::I64 => Ct::I64(FheInt64::encrypt_trivial(v as i64)),
        Elem::F64 => return Err(backend("f64 is not an exact type")),
    })
}

fn unsigned_of(bits: u32) -> Elem {
    match bits {
        8 => Elem::U8,
        16 => Elem::U16,
        32 => Elem::U32,
        _ => Elem::U64,
    }
}

impl ExactEvaluator for TfheRsEvaluator {
    type Ciphertext = Ct;

    fn name(&self) -> &'static str {
        "tfhe-rs"
    }

    fn load(&self, elem: Elem, bytes: &[u8]) -> Result<Ct> {
        let k = &self.key;
        Ok(match elem {
            Elem::Bool => Ct::B(load_as!(FheBool, FheBoolConformanceParams, k, bytes)),
            Elem::U8 => Ct::U8(load_as!(FheUint8, FheUint8ConformanceParams, k, bytes)),
            Elem::U16 => Ct::U16(load_as!(FheUint16, FheUint16ConformanceParams, k, bytes)),
            Elem::U32 => Ct::U32(load_as!(FheUint32, FheUint32ConformanceParams, k, bytes)),
            Elem::U64 => Ct::U64(load_as!(FheUint64, FheUint64ConformanceParams, k, bytes)),
            Elem::I8 => Ct::I8(load_as!(FheInt8, FheInt8ConformanceParams, k, bytes)),
            Elem::I16 => Ct::I16(load_as!(FheInt16, FheInt16ConformanceParams, k, bytes)),
            Elem::I32 => Ct::I32(load_as!(FheInt32, FheInt32ConformanceParams, k, bytes)),
            Elem::I64 => Ct::I64(load_as!(FheInt64, FheInt64ConformanceParams, k, bytes)),
            Elem::F64 => return Err(backend("f64 is not an exact type")),
        })
    }

    fn store(&self, ct: &Ct) -> Result<Vec<u8>> {
        store_one(ct)
    }

    fn trivial(&self, elem: Elem, value: i128) -> Result<Ct> {
        self.on();
        trivial(elem, value)
    }

    fn add(&self, a: &Ct, b: &Ct) -> Result<Ct> {
        self.on();
        int_binary!(a, b, |x, y| x + y)
    }
    fn sub(&self, a: &Ct, b: &Ct) -> Result<Ct> {
        self.on();
        int_binary!(a, b, |x, y| x - y)
    }
    fn mul(&self, a: &Ct, b: &Ct) -> Result<Ct> {
        self.on();
        int_binary!(a, b, |x, y| x * y)
    }
    fn neg(&self, a: &Ct) -> Result<Ct> {
        self.on();
        int_unary!(a, |x, C| -x)
    }
    fn add_scalar(&self, a: &Ct, c: i128) -> Result<Ct> {
        self.on();
        int_unary!(a, |x, C| x + (c as C))
    }
    fn sub_scalar(&self, a: &Ct, c: i128) -> Result<Ct> {
        self.on();
        int_unary!(a, |x, C| x - (c as C))
    }
    fn mul_scalar(&self, a: &Ct, c: i128) -> Result<Ct> {
        self.on();
        int_unary!(a, |x, C| x * (c as C))
    }
    fn scalar_sub(&self, c: i128, a: &Ct) -> Result<Ct> {
        self.on();
        int_unary!(a, |x, C| (c as C) - x)
    }
    fn div_scalar(&self, a: &Ct, c: i128) -> Result<Ct> {
        self.on();
        int_unary!(a, |x, C| x / (c as C))
    }
    fn rem_scalar(&self, a: &Ct, c: i128) -> Result<Ct> {
        self.on();
        int_unary!(a, |x, C| x % (c as C))
    }
    fn cmp(&self, op: CmpOp, a: &Ct, b: &Ct) -> Result<Ct> {
        self.on();
        match op {
            CmpOp::Eq => int_binary_bool!(a, b, |x, y| x.eq(y)),
            CmpOp::Ne => int_binary_bool!(a, b, |x, y| x.ne(y)),
            _ => cmp_ord(op, a, b),
        }
    }
    fn cmp_scalar(&self, op: CmpOp, a: &Ct, c: i128) -> Result<Ct> {
        self.on();
        match op {
            CmpOp::Eq => int_to_bool!(a, |x, C| x.eq(c as C)),
            CmpOp::Ne => int_to_bool!(a, |x, C| x.ne(c as C)),
            CmpOp::Lt => int_to_bool!(a, |x, C| x.lt(c as C)),
            CmpOp::Le => int_to_bool!(a, |x, C| x.le(c as C)),
            CmpOp::Gt => int_to_bool!(a, |x, C| x.gt(c as C)),
            CmpOp::Ge => int_to_bool!(a, |x, C| x.ge(c as C)),
        }
    }
    fn logic(&self, op: LogicOp, a: &Ct, b: &Ct) -> Result<Ct> {
        self.on();
        if let (Ct::B(x), Ct::B(y)) = (a, b) {
            return Ok(Ct::B(match op {
                LogicOp::And => x & y,
                LogicOp::Or => x | y,
                LogicOp::Xor => x ^ y,
            }));
        }
        match op {
            LogicOp::And => int_binary!(a, b, |x, y| x & y),
            LogicOp::Or => int_binary!(a, b, |x, y| x | y),
            LogicOp::Xor => int_binary!(a, b, |x, y| x ^ y),
        }
    }
    fn not(&self, a: &Ct) -> Result<Ct> {
        self.on();
        if let Ct::B(x) = a {
            return Ok(Ct::B(!x));
        }
        int_unary!(a, |x, C| !x)
    }
    fn shift(&self, a: &Ct, left: bool, by: u32) -> Result<Ct> {
        self.on();
        if left {
            int_unary!(a, |x, C| x << (by as u8))
        } else {
            int_unary!(a, |x, C| x >> (by as u8))
        }
    }
    fn min(&self, a: &Ct, b: &Ct) -> Result<Ct> {
        self.on();
        int_binary!(a, b, |x, y| x.min(y))
    }
    fn max(&self, a: &Ct, b: &Ct) -> Result<Ct> {
        self.on();
        int_binary!(a, b, |x, y| x.max(y))
    }
    fn select(&self, c: &Ct, a: &Ct, b: &Ct) -> Result<Ct> {
        self.on();
        let Ct::B(c) = c else {
            return Err(backend("select condition must be bool"));
        };
        if let (Ct::B(x), Ct::B(y)) = (a, b) {
            return Ok(Ct::B(c.select(x, y)));
        }
        int_binary!(a, b, |x, y| c.select(x, y))
    }
    fn lookup(&self, a: &Ct, table: &[i128], elem: Elem) -> Result<Ct> {
        self.on();
        // Index as unsigned of the same width (non-negative, proven), table
        // shifted to non-negative values, then cast back and re-offset;
        // two's-complement wrap makes the result exact for signed types.
        let width = a.elem().bits();
        let idx = cast_to(a, unsigned_of(width))?;
        let min = *table.iter().min().expect("non-empty table");
        let pairs: Vec<(u64, u64)> = table
            .iter()
            .enumerate()
            .map(|(i, v)| (i as u64, (v - min) as u64))
            .collect();
        let mv = MatchValues::new(pairs).map_err(backend)?;
        let out_bits = elem.bits().max(8);
        macro_rules! run {
            ($x:expr, $Out:ty) => {{
                let (r, _matched): ($Out, FheBool) = $x.match_value(&mv).map_err(backend)?;
                r
            }};
        }
        macro_rules! by_index {
            ($Out:ty, $wrap:ident) => {
                match &idx {
                    Ct::U8(x) => Ct::$wrap(run!(x, $Out)),
                    Ct::U16(x) => Ct::$wrap(run!(x, $Out)),
                    Ct::U32(x) => Ct::$wrap(run!(x, $Out)),
                    Ct::U64(x) => Ct::$wrap(run!(x, $Out)),
                    _ => unreachable!("index cast to unsigned"),
                }
            };
        }
        let shifted = match unsigned_of(out_bits) {
            Elem::U8 => by_index!(FheUint8, U8),
            Elem::U16 => by_index!(FheUint16, U16),
            Elem::U32 => by_index!(FheUint32, U32),
            _ => by_index!(FheUint64, U64),
        };
        let r = if shifted.elem() == elem {
            shifted
        } else {
            cast_to(&shifted, elem)?
        };
        if min == 0 {
            Ok(r)
        } else {
            self.add_scalar(&r, min)
        }
    }
    fn cast(&self, a: &Ct, to: Elem) -> Result<Ct> {
        self.on();
        cast_to(a, to)
    }
}

/// Ordering comparisons (integers only).
macro_rules! int_ord {
    ($a:expr, $b:expr, |$x:ident, $y:ident| $body:expr) => {
        match ($a, $b) {
            (Ct::U8($x), Ct::U8($y)) => Ok(Ct::B($body)),
            (Ct::U16($x), Ct::U16($y)) => Ok(Ct::B($body)),
            (Ct::U32($x), Ct::U32($y)) => Ok(Ct::B($body)),
            (Ct::U64($x), Ct::U64($y)) => Ok(Ct::B($body)),
            (Ct::I8($x), Ct::I8($y)) => Ok(Ct::B($body)),
            (Ct::I16($x), Ct::I16($y)) => Ok(Ct::B($body)),
            (Ct::I32($x), Ct::I32($y)) => Ok(Ct::B($body)),
            (Ct::I64($x), Ct::I64($y)) => Ok(Ct::B($body)),
            (a, b) => Err(backend(format!(
                "cannot order {} and {}",
                a.elem(),
                b.elem()
            ))),
        }
    };
}

fn cmp_ord(op: CmpOp, a: &Ct, b: &Ct) -> Result<Ct> {
    match op {
        CmpOp::Lt => int_ord!(a, b, |x, y| x.lt(y)),
        CmpOp::Le => int_ord!(a, b, |x, y| x.le(y)),
        CmpOp::Gt => int_ord!(a, b, |x, y| x.gt(y)),
        CmpOp::Ge => int_ord!(a, b, |x, y| x.ge(y)),
        _ => unreachable!(),
    }
}

/// Serialize a ciphertext (shared with the client crate).
pub fn store(ct: &Ct) -> Result<Vec<u8>> {
    store_one(ct)
}
