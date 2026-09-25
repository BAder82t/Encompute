//! Canonical JSON for everything that is hashed or signed (ADR-007):
//! object keys sorted by their UTF-8 bytes, no whitespace, strings escaped
//! as serde_json does (RFC 8259, `\uXXXX` only for control characters),
//! integers only. Floating-point numbers, NaN and infinities are refused.
//! For objects of strings, integers, booleans, null and arrays this is the
//! same output as RFC 8785 (JCS).
//!
//! Key order is imposed here, not taken from `serde_json::Map`, so a
//! dependency enabling serde_json's `preserve_order` cannot change it.

use encompute_ir::{Code, Error, Result};
use serde::Serialize;
use serde_json::Value;

fn bad(msg: impl Into<String>) -> Error {
    Error::new(Code::Receipt, msg)
}

/// Canonical bytes of `value`.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let v = serde_json::to_value(value).map_err(|e| bad(format!("not serializable: {e}")))?;
    let mut out = Vec::new();
    write(&v, &mut out)?;
    Ok(out)
}

fn write(v: &Value, out: &mut Vec<u8>) -> Result<()> {
    match v {
        Value::Null | Value::Bool(_) | Value::String(_) => {
            out.extend(serde_json::to_vec(v).expect("scalar"));
        }
        Value::Number(n) => {
            if !(n.is_i64() || n.is_u64()) {
                return Err(bad(format!("{n}: canonical JSON carries integers only")));
            }
            out.extend(n.to_string().as_bytes());
        }
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(x, out)?;
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_vec(k).expect("string"));
                out.push(b':');
                write(&m[k], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}
