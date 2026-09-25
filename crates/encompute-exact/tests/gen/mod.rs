//! Random exact programs for differential tests, shared by the mock tests
//! here and the TFHE-rs tests (`encompute-tfhe-client`), so both backends
//! run the same programs.

#![allow(dead_code)]

use encompute_ir::{Builder, CmpOp, Elem, Inputs, LogicOp, Program, Range, ValueId};
use proptest::prelude::*;

/// Every integer width.
pub const WIDTHS: [Elem; 8] = [
    Elem::U8,
    Elem::U16,
    Elem::U32,
    Elem::U64,
    Elem::I8,
    Elem::I16,
    Elem::I32,
    Elem::I64,
];

/// A program over one integer type (three inputs) plus a bool input, and
/// the declared input ranges `(name, lo, hi)`.
pub type Generated = (Program, Vec<(String, i64, i64)>);

fn wider(e: Elem) -> Elem {
    match e {
        Elem::U8 => Elem::U16,
        Elem::U16 => Elem::U32,
        Elem::U32 | Elem::U64 => Elem::U64,
        Elem::I8 => Elem::I16,
        Elem::I16 => Elem::I32,
        _ => Elem::I64,
    }
}

pub fn arb_program() -> impl Strategy<Value = Generated> {
    (
        0usize..WIDTHS.len(),
        prop::collection::vec((0u8..19, any::<u32>(), any::<u32>(), any::<i16>()), 1..12),
        prop::collection::vec((any::<i32>(), 0u32..300), 3),
    )
        .prop_map(|(w, steps, ranges)| {
            let elem = WIDTHS[w];
            let (min, max) = elem.bounds();
            // 64-bit programs get wider inputs; products still fit.
            let limit: i128 = if elem.bits() == 64 { 1 << 31 } else { 30000 };
            let clamp = |v: i128| v.clamp(min.max(-limit), max.min(limit));
            let mut b = Builder::new("p", 1e-3).unwrap();
            let mut decl = vec![];
            let mut ints: Vec<ValueId> = vec![];
            for (i, (lo, span)) in ranges.iter().enumerate() {
                let lo = clamp(*lo as i128);
                let hi = clamp(lo + *span as i128);
                let name = format!("x{i}");
                ints.push(
                    b.input_exact(&name, elem, Some(Range::new(lo as f64, hi as f64)))
                        .unwrap(),
                );
                decl.push((name, lo as i64, hi as i64));
            }
            let flag = b.input_exact("flag", Elem::Bool, None).unwrap();
            decl.push(("flag".into(), 0, 1));
            let mut bools: Vec<ValueId> = vec![flag];
            for (kind, i, j, c) in steps {
                let a = ints[i as usize % ints.len()];
                let o = ints[j as usize % ints.len()];
                let k = b
                    .constant_exact(elem, clamp(c as i128 % 9 + 1) as f64)
                    .unwrap();
                let r = match kind {
                    0 => b.add(a, o),
                    1 => b.sub(a, k),
                    2 => b.sub(k, a),
                    3 => b.mul(a, k),
                    4 => b.min(a, o),
                    5 => b.max(k, a),
                    6 => b.logic(LogicOp::And, a, o),
                    7 => b.logic(LogicOp::Xor, a, k),
                    8 => b.not(a),
                    9 => b.shift(a, c % 2 == 0, (c.unsigned_abs() as u32) % 3),
                    10 => {
                        if c % 2 == 0 {
                            b.div(a, k)
                        } else {
                            b.rem(a, k)
                        }
                    }
                    11 => b.mul(a, o),
                    12 | 13 => {
                        let op = [
                            CmpOp::Lt,
                            CmpOp::Ge,
                            CmpOp::Eq,
                            CmpOp::Ne,
                            CmpOp::Le,
                            CmpOp::Gt,
                        ][(c.unsigned_abs() as usize) % 6];
                        let r = if kind == 12 {
                            b.cmp(op, a, o)
                        } else {
                            b.cmp(op, k, a)
                        };
                        if let Ok(t) = r {
                            bools.push(t);
                        }
                        r
                    }
                    14 => b.select(bools[i as usize % bools.len()], a, k),
                    15 => {
                        let op = [LogicOp::And, LogicOp::Or, LogicOp::Xor]
                            [(c.unsigned_abs() as usize) % 3];
                        let t = b.logic(
                            op,
                            bools[i as usize % bools.len()],
                            bools[j as usize % bools.len()],
                        );
                        if let Ok(t) = t {
                            bools.push(t);
                        }
                        t
                    }
                    16 => {
                        let lo = ranges[0].0.max(0) as usize % 4;
                        let t: Vec<f64> = (0..64)
                            .map(|v| clamp(((v * 7 + lo) % 50) as i128) as f64)
                            .collect();
                        let m = b.constant_exact(elem, 64.0).ok().unwrap_or(k);
                        match b.rem(a, m).ok() {
                            Some(ix) => b.lookup(ix, t),
                            None => b.neg(a),
                        }
                    }
                    17 => {
                        // Widen and narrow back: value-preserving casts.
                        match b.cast(a, wider(elem)) {
                            Ok(w) => b.cast(w, elem),
                            e => e,
                        }
                    }
                    18 => {
                        let t = b.not(bools[i as usize % bools.len()]);
                        if let Ok(t) = t {
                            bools.push(t);
                        }
                        t
                    }
                    _ => b.neg(a),
                };
                if let Ok(id) = r {
                    if b.ty(id).unwrap().elem == elem {
                        ints.push(id);
                    }
                }
            }
            for (k, id) in ints.iter().enumerate().skip(3) {
                b.output(&format!("v{k}"), *id).unwrap();
            }
            for (k, id) in bools.iter().enumerate().skip(1) {
                b.output(&format!("b{k}"), *id).unwrap();
            }
            b.output("x0", ints[0]).unwrap();
            (b.finish().unwrap(), decl)
        })
}

/// Deterministic inputs for case `case`: all low ends, all high ends, then
/// pseudo-random values (a quarter of them at a range end).
pub fn inputs_for(decl: &[(String, i64, i64)], case: usize, seed: u64) -> Inputs {
    let mut s = seed ^ (case as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    decl.iter()
        .map(|(n, lo, hi)| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let r = s >> 11;
            let v = match case {
                0 => *lo,
                1 => *hi,
                _ if r.is_multiple_of(4) => {
                    if r.is_multiple_of(8) {
                        *lo
                    } else {
                        *hi
                    }
                }
                _ => lo + (r % ((hi - lo) as u64 + 1)) as i64,
            };
            (n.clone(), vec![v as f64])
        })
        .collect()
}

/// Number of random programs: `ENCOMPUTE_EXACT_PROGRAMS`, else `default`.
pub fn programs(default: u32) -> u32 {
    std::env::var("ENCOMPUTE_EXACT_PROGRAMS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
