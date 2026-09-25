//! Mutation of every field: take a serialized object, change each leaf in
//! turn (and drop each optional field), and hand every variant to a
//! verifier that must reject it.

use serde_json::Value;

/// One mutated copy and where it was changed.
pub struct Mutant {
    pub path: String,
    pub value: Value,
}

fn tweak(v: &Value) -> Vec<Value> {
    match v {
        Value::String(s) => {
            let mut out = vec![];
            if let Some(c) = s.chars().next() {
                // Flip the first character within its class (hex stays hex).
                let flipped = match c {
                    '0'..='8' | 'a'..='e' | 'A'..='E' => ((c as u8) + 1) as char,
                    '9' => '0',
                    'f' => 'e',
                    'F' => 'E',
                    _ => 'x',
                };
                let mut t = s.clone();
                t.replace_range(0..c.len_utf8(), &flipped.to_string());
                out.push(Value::String(t));
            } else {
                out.push(Value::String("x".into()));
            }
            out
        }
        Value::Number(n) => {
            let mut out = vec![];
            if let Some(u) = n.as_u64() {
                out.push(Value::from(u.wrapping_add(1)));
            } else if let Some(i) = n.as_i64() {
                out.push(Value::from(i.wrapping_add(1)));
            } else if let Some(f) = n.as_f64() {
                out.push(Value::from(f + 1.0));
            }
            out
        }
        Value::Bool(b) => vec![Value::Bool(!b)],
        Value::Null => vec![Value::String("x".into())],
        _ => vec![],
    }
}

fn walk(v: &Value, path: String, root: &Value, out: &mut Vec<Mutant>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                let p = format!("{path}/{k}");
                walk(child, p.clone(), root, out);
                // Dropping the field (a null field dropped is the same
                // value: serde reads a missing optional field as null).
                if child.is_null() {
                    continue;
                }
                let mut r = root.clone();
                if let Some(Value::Object(parent)) = r.pointer_mut(&path) {
                    parent.remove(k);
                    out.push(Mutant {
                        path: format!("{p} (removed)"),
                        value: r,
                    });
                }
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                walk(child, format!("{path}/{i}"), root, out);
            }
            if !a.is_empty() {
                let mut r = root.clone();
                if let Some(Value::Array(arr)) = r.pointer_mut(&path) {
                    arr.pop();
                    out.push(Mutant {
                        path: format!("{path} (shortened)"),
                        value: r,
                    });
                }
            }
        }
        leaf => {
            for t in tweak(leaf) {
                let mut r = root.clone();
                *r.pointer_mut(&path).expect("path exists") = t;
                out.push(Mutant {
                    path: path.clone(),
                    value: r,
                });
            }
        }
    }
}

/// Every single-field mutation of `v` (leaves changed, fields dropped,
/// arrays shortened).
pub fn mutants(v: &Value) -> Vec<Mutant> {
    let mut out = vec![];
    walk(v, String::new(), v, &mut out);
    out
}

/// Runs `accepts` on every mutant; returns the paths it wrongly accepted
/// (skipping paths matched by `unbound`, fields documented as not
/// security-relevant).
pub fn accepted<F>(v: &Value, unbound: &[&str], accepts: F) -> (usize, Vec<String>)
where
    F: Fn(&Value) -> bool,
{
    let ms = mutants(v);
    let n = ms.len();
    let bad = ms
        .into_iter()
        .filter(|m| !unbound.iter().any(|u| m.path.starts_with(u)))
        .filter(|m| accepts(&m.value))
        .map(|m| m.path)
        .collect();
    (n, bad)
}
