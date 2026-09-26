//! The bit-level circuits against the reference semantics (the mock):
//! exhaustive over 8-bit types, sampled over wider ones. A circuit must
//! agree wherever the mock's result is defined (the compiler's range
//! analysis rules out the rest).

use encompute_backend::ExactClient;
use encompute_backend::{ExactEvaluator, PlainExactClient, PlainExactEvaluator};
use encompute_exact::bits::{plain_value, plain_word, BitEvaluator, PlainGates, Word};
use encompute_ir::{CmpOp, Elem, LogicOp};

struct Ref {
    ev: PlainExactEvaluator,
    client: PlainExactClient,
}

impl Ref {
    fn new() -> Self {
        let client = PlainExactClient::new(7);
        Self {
            ev: PlainExactEvaluator::new(&client.evaluation_keys().unwrap()).unwrap(),
            client,
        }
    }
    fn ct(&self, e: Elem, v: i128) -> <PlainExactEvaluator as ExactEvaluator>::Ciphertext {
        self.ev
            .load(e, &self.client.encrypt(e, v).unwrap())
            .unwrap()
    }
    fn val(&self, e: Elem, ct: &<PlainExactEvaluator as ExactEvaluator>::Ciphertext) -> i128 {
        self.client.decrypt(e, &self.ev.store(ct).unwrap()).unwrap()
    }
}

type W = Word<bool>;

fn bits() -> BitEvaluator<PlainGates> {
    BitEvaluator::new(PlainGates)
}

/// Compares a binary operation on every pair of `e` (or a sample).
fn binary(
    e: Elem,
    values: &[i128],
    name: &str,
    r: impl Fn(&Ref, i128, i128) -> Option<(Elem, i128)>,
    b: impl Fn(&BitEvaluator<PlainGates>, &W, &W) -> W,
) {
    let rf = Ref::new();
    let ev = bits();
    let mut n = 0;
    for &x in values {
        for &y in values {
            let Some((re, want)) = r(&rf, x, y) else {
                continue;
            };
            let got = b(&ev, &plain_word(e, x), &plain_word(e, y));
            assert_eq!(got.elem, re, "{name} {e}");
            assert_eq!(plain_value(&got), want, "{name} {e} {x} {y}");
            n += 1;
        }
    }
    assert!(n > 0, "{name} {e}: no defined cases");
}

fn all(e: Elem) -> Vec<i128> {
    let (lo, hi) = e.bounds();
    (lo..=hi).collect()
}

fn sample(e: Elem) -> Vec<i128> {
    let (lo, hi) = e.bounds();
    let mut v = vec![lo, lo + 1, -1, 0, 1, 2, 3, 7, 100, 255, 256, hi - 1, hi];
    let mut s: u64 = 0x9e3779b97f4a7c15;
    for _ in 0..40 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let span = (hi - lo) as u128 + 1;
        v.push(lo + (s as u128 % span) as i128);
    }
    v.retain(|x| (lo..=hi).contains(x));
    v.sort();
    v.dedup();
    v
}

macro_rules! op {
    ($rf:ident, $e:ident, $x:ident, $y:ident, $f:expr) => {{
        let a = $rf.ct($e, $x);
        let b = $rf.ct($e, $y);
        match $f(&$rf.ev, &a, &b) {
            Ok(c) => Some(($rf.ev.elem_of(&c), $rf.val($rf.ev.elem_of(&c), &c))),
            Err(_) => None,
        }
    }};
}

fn check_binary_ops(e: Elem, values: &[i128]) {
    binary(
        e,
        values,
        "add",
        |rf, x, y| op!(rf, e, x, y, |ev: &PlainExactEvaluator, a, b| ev.add(a, b)),
        |ev, a, b| ev.add(a, b).unwrap(),
    );
    binary(
        e,
        values,
        "sub",
        |rf, x, y| op!(rf, e, x, y, |ev: &PlainExactEvaluator, a, b| ev.sub(a, b)),
        |ev, a, b| ev.sub(a, b).unwrap(),
    );
    // (Products beyond i128 are outside every exact type: the reference
    // mock cannot form them, and range analysis never lets them through.)
    binary(
        e,
        values,
        "mul",
        |rf, x, y| {
            x.checked_mul(y)?;
            op!(rf, e, x, y, |ev: &PlainExactEvaluator, a, b| ev.mul(a, b))
        },
        |ev, a, b| ev.mul(a, b).unwrap(),
    );
    binary(
        e,
        values,
        "min",
        |rf, x, y| op!(rf, e, x, y, |ev: &PlainExactEvaluator, a, b| ev.min(a, b)),
        |ev, a, b| ev.min(a, b).unwrap(),
    );
    binary(
        e,
        values,
        "max",
        |rf, x, y| op!(rf, e, x, y, |ev: &PlainExactEvaluator, a, b| ev.max(a, b)),
        |ev, a, b| ev.max(a, b).unwrap(),
    );
    for op in [
        CmpOp::Eq,
        CmpOp::Ne,
        CmpOp::Lt,
        CmpOp::Le,
        CmpOp::Gt,
        CmpOp::Ge,
    ] {
        binary(
            e,
            values,
            "cmp",
            |rf, x, y| {
                op!(rf, e, x, y, |ev: &PlainExactEvaluator, a, b| ev
                    .cmp(op, a, b))
            },
            |ev, a, b| ev.cmp(op, a, b).unwrap(),
        );
    }
    for op in [LogicOp::And, LogicOp::Or, LogicOp::Xor] {
        binary(
            e,
            values,
            "logic",
            |rf, x, y| {
                op!(rf, e, x, y, |ev: &PlainExactEvaluator, a, b| ev
                    .logic(op, a, b))
            },
            |ev, a, b| ev.logic(op, a, b).unwrap(),
        );
    }
    // Constants on the right: x op c, for every c in the sample.
    binary(
        e,
        values,
        "add_scalar",
        |rf, x, c| {
            op!(rf, e, x, c, |ev: &PlainExactEvaluator, a, _b| ev
                .add_scalar(a, c))
        },
        |ev, a, b| ev.add_scalar(a, plain_value(b)).unwrap(),
    );
    binary(
        e,
        values,
        "sub_scalar",
        |rf, x, c| {
            op!(rf, e, x, c, |ev: &PlainExactEvaluator, a, _b| ev
                .sub_scalar(a, c))
        },
        |ev, a, b| ev.sub_scalar(a, plain_value(b)).unwrap(),
    );
    binary(
        e,
        values,
        "mul_scalar",
        |rf, x, c| {
            x.checked_mul(c)?;
            op!(rf, e, x, c, |ev: &PlainExactEvaluator, a, _b| ev
                .mul_scalar(a, c))
        },
        |ev, a, b| ev.mul_scalar(a, plain_value(b)).unwrap(),
    );
    binary(
        e,
        values,
        "scalar_sub",
        |rf, x, c| {
            op!(rf, e, x, c, |ev: &PlainExactEvaluator, a, _b| ev
                .scalar_sub(c, a))
        },
        |ev, a, b| ev.scalar_sub(plain_value(b), a).unwrap(),
    );
    for op in [CmpOp::Eq, CmpOp::Lt, CmpOp::Ge] {
        binary(
            e,
            values,
            "cmp_scalar",
            |rf, x, c| {
                op!(rf, e, x, c, |ev: &PlainExactEvaluator, a, _b| ev
                    .cmp_scalar(op, a, c))
            },
            |ev, a, b| ev.cmp_scalar(op, a, plain_value(b)).unwrap(),
        );
    }
    let nonzero: Vec<i128> = values.iter().copied().filter(|v| *v != 0).collect();
    binary(
        e,
        &nonzero,
        "div_scalar",
        |rf, x, c| {
            op!(rf, e, x, c, |ev: &PlainExactEvaluator, a, _b| ev
                .div_scalar(a, c))
        },
        |ev, a, b| ev.div_scalar(a, plain_value(b)).unwrap(),
    );
    binary(
        e,
        &nonzero,
        "rem_scalar",
        |rf, x, c| {
            op!(rf, e, x, c, |ev: &PlainExactEvaluator, a, _b| ev
                .rem_scalar(a, c))
        },
        |ev, a, b| ev.rem_scalar(a, plain_value(b)).unwrap(),
    );
}

#[test]
fn eight_bit_operations_are_exhaustively_exact() {
    for e in [Elem::U8, Elem::I8] {
        check_binary_ops(e, &all(e));
    }
}

#[test]
fn wider_operations_agree_on_samples() {
    for e in [
        Elem::U16,
        Elem::I16,
        Elem::U32,
        Elem::I32,
        Elem::U64,
        Elem::I64,
    ] {
        check_binary_ops(e, &sample(e));
    }
}

#[test]
fn unary_operations_shifts_casts_select_and_lookup() {
    let rf = Ref::new();
    let ev = bits();
    for e in Elem::EXACT {
        let values = if e.bits() <= 8 { all(e) } else { sample(e) };
        for &x in &values {
            let a = rf.ct(e, x);
            let w = plain_word(e, x);
            let check = |name: &str,
                         r: Result<<PlainExactEvaluator as ExactEvaluator>::Ciphertext, _>,
                         got: W| {
                if let Ok(c) = r {
                    let re = rf.ev.elem_of(&c);
                    assert_eq!(plain_value(&got), rf.val(re, &c), "{name} {e} {x}");
                }
            };
            check("not", rf.ev.not(&a), ev.not(&w).unwrap());
            if e != Elem::Bool {
                check("neg", rf.ev.neg(&a), ev.neg(&w).unwrap());
                for by in [0, 1, 3, e.bits() - 1] {
                    check(
                        "shl",
                        rf.ev.shift(&a, true, by),
                        ev.shift(&w, true, by).unwrap(),
                    );
                    check(
                        "shr",
                        rf.ev.shift(&a, false, by),
                        ev.shift(&w, false, by).unwrap(),
                    );
                }
            }
            for to in Elem::EXACT {
                check("cast", rf.ev.cast(&a, to), ev.cast(&w, to).unwrap());
            }
            for c in [true, false] {
                let cb = plain_word(Elem::Bool, c as i128);
                let y = values[values.len() / 2];
                check(
                    "select",
                    rf.ev
                        .select(&rf.ct(Elem::Bool, c as i128), &a, &rf.ct(e, y)),
                    ev.select(&cb, &w, &plain_word(e, y)).unwrap(),
                );
            }
        }
    }
    // Lookup: every index of tables of several sizes and output types.
    for (len, out) in [
        (1usize, Elem::U8),
        (5, Elem::I16),
        (200, Elem::U32),
        (256, Elem::I8),
    ] {
        let table: Vec<i128> = (0..len as i128).map(|i| (i * 37 % 97) - 40).collect();
        let table: Vec<i128> = table
            .into_iter()
            .map(|v| {
                let (lo, hi) = out.bounds();
                v.clamp(lo, hi)
            })
            .collect();
        for i in 0..len as i128 {
            let got = ev.lookup(&plain_word(Elem::U16, i), &table, out).unwrap();
            assert_eq!(plain_value(&got), table[i as usize], "lookup {len} {i}");
        }
    }
    assert!(ev.gate_count() > 0);
}

#[test]
fn bool_logic_truth_tables() {
    let ev = bits();
    for a in [0, 1] {
        for b in [0, 1] {
            let (x, y) = (plain_word(Elem::Bool, a), plain_word(Elem::Bool, b));
            assert_eq!(plain_value(&ev.logic(LogicOp::And, &x, &y).unwrap()), a & b);
            assert_eq!(plain_value(&ev.logic(LogicOp::Or, &x, &y).unwrap()), a | b);
            assert_eq!(plain_value(&ev.logic(LogicOp::Xor, &x, &y).unwrap()), a ^ b);
        }
        assert_eq!(
            plain_value(&ev.not(&plain_word(Elem::Bool, a)).unwrap()),
            1 - a
        );
    }
}
