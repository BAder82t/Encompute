//! Integer range analysis is security-critical: a bounded-category release
//! form (governed projects) is admitted only when `int_ranges` proves an
//! output lies in `[0, max]`. These adversarial tests evaluate programs
//! over every input in small domains (negative, mixed-sign, shifts,
//! negative divisors and remainders, comparisons feeding arithmetic,
//! casts, lookups) and check that every value lies in its analyzed range,
//! so the analysis never under-approximates, and that a bounded category
//! is claimed only for values that are.

use encompute_analysis::confidentiality::provable_forms;
use encompute_analysis::int_ranges;
use encompute_ir::confidentiality::{AssetKind, ReleaseForm};
use encompute_ir::{
    evaluate, Builder, CmpOp, Code, Elem, Inputs, LogicOp, Program, Range, Shape, ValueId,
};
use proptest::prelude::*;

/// Every input combination over `decl` (name, lo, hi).
fn grid(decl: &[(String, i64, i64)]) -> Vec<Inputs> {
    let mut all: Vec<Inputs> = vec![Inputs::new()];
    for (n, lo, hi) in decl {
        all = all
            .into_iter()
            .flat_map(|i| {
                (*lo..=*hi).map(move |v| {
                    let mut i = i.clone();
                    i.insert(n.clone(), vec![v as f64]);
                    i
                })
            })
            .collect();
    }
    all
}

/// Checks every output of `p` over every input: within its range, and a
/// bounded category only if every value is in `[0, max]`.
/// Returns how many inputs were evaluated (0 when the analysis refuses the
/// program as a possible overflow).
fn sound(p: &Program, decl: &[(String, i64, i64)]) -> std::result::Result<usize, String> {
    let ranges = match int_ranges(p) {
        Ok(r) => r,
        Err(e) if e.code == Code::Overflow => return Ok(0),
        Err(e) => return Err(format!("{e:?}")),
    };
    let mut evaluated = 0;
    for inputs in grid(decl) {
        // An accepted program evaluates on every declared input.
        let out = evaluate(p, &inputs).map_err(|e| format!("{e:?} for {inputs:?}\n{p}"))?;
        evaluated += 1;
        for o in p.outputs() {
            let v = out[&o.name][0] as i128;
            let (lo, hi) = ranges[o.value.index()].unwrap();
            if v < lo || v > hi {
                return Err(format!(
                    "{} = {v} outside [{lo}, {hi}] for {inputs:?}\n{p}",
                    o.name
                ));
            }
            let ty = p.node(o.value).ty;
            for f in provable_forms(
                ty.elem,
                Shape::Scalar,
                Some((lo, hi)),
                false,
                false,
                AssetKind::Generic,
            ) {
                if let ReleaseForm::BoundedCategory { max } = f {
                    if v < 0 || v > max as i128 {
                        return Err(format!("{} = {v} claimed within [0, {max}]\n{p}", o.name));
                    }
                }
            }
        }
    }
    Ok(evaluated)
}

/// Hand-written adversarial cases over signed, mixed-sign inputs.
#[test]
fn ranges_hold_on_every_input_of_adversarial_programs() {
    for elem in [Elem::I8, Elem::I16, Elem::U8] {
        let signed = elem.is_signed();
        let (xl, xh, yl, yh) = if signed {
            (-6, 5, -3, 4)
        } else {
            (0, 11, 0, 7)
        };
        let mut b = Builder::new("adv", 1e-3).unwrap();
        let x = b
            .input_exact("x", elem, Some(Range::new(xl as f64, xh as f64)))
            .unwrap();
        let y = b
            .input_exact("y", elem, Some(Range::new(yl as f64, yh as f64)))
            .unwrap();
        let mut outs: Vec<(String, ValueId)> = vec![];
        let mut push = |name: &str, v: encompute_ir::Result<ValueId>| {
            if let Ok(v) = v {
                outs.push((name.to_owned(), v));
            }
        };
        if signed {
            push("sub", b.sub(x, y));
        }
        push("mul", b.mul(x, y));
        push("neg", b.neg(x));
        push("not", b.not(x));
        push("and", b.logic(LogicOp::And, x, y));
        push("or", b.logic(LogicOp::Or, x, y));
        push("xor", b.logic(LogicOp::Xor, x, y));
        push("shl", b.shift(x, true, 2));
        push("shr", b.shift(x, false, 1));
        push("min", b.min(x, y));
        push("max", b.max(x, y));
        for k in [3.0, -3.0, 1.0, -1.0, 7.0] {
            if !signed && k < 0.0 {
                continue;
            }
            let c = b.constant_exact(elem, k).unwrap();
            push(&format!("div{}", k as i64 + 10), b.div(x, c));
            push(&format!("rem{}", k as i64 + 10), b.rem(x, c));
        }
        // Comparisons feeding arithmetic.
        let lt = b.cmp(CmpOp::Lt, x, y).unwrap();
        push("sel", b.select(lt, x, y));
        if let Ok(bit) = b.cast(lt, elem) {
            push("bit", Ok(bit));
            push("bitsum", b.add(bit, x));
            push("bitmul", b.mul(bit, y));
        }
        push("lt", Ok(lt));
        let d = if signed { b.sub(x, y) } else { b.max(x, y) };
        if let Ok(d) = d {
            push("dd", b.mul(d, d));
            push("dshr", b.shift(d, false, 2));
        }
        if !signed {
            push(
                "lookup",
                b.lookup(y, vec![5.0, 0.0, 9.0, 1.0, 2.0, 200.0, 3.0, 4.0]),
            );
        }
        let wide = if signed { Elem::I16 } else { Elem::U16 };
        push("cast", b.cast(x, wide));
        let names: Vec<(String, ValueId)> = outs;
        for (n, v) in &names {
            b.output(n, *v).unwrap();
        }
        let p = b.finish().unwrap();
        let decl = vec![("x".to_owned(), xl, xh), ("y".to_owned(), yl, yh)];
        let n = sound(&p, &decl).unwrap();
        assert_eq!(n, ((xh - xl + 1) * (yh - yl + 1)) as usize, "{elem}: {p}");
        assert!(p.outputs().len() >= 20, "{elem}: {}", p.outputs().len());
    }
}

/// Random signed programs over small domains, every node an output,
/// every input combination checked; divisors of both signs.
fn arb_program() -> impl Strategy<Value = (Program, Vec<(String, i64, i64)>)> {
    (
        prop::collection::vec((0u8..14, any::<u16>(), any::<u16>(), any::<i8>()), 1..10),
        (-8i64..8, 0i64..9, -8i64..8, 0i64..9),
    )
        .prop_map(|(steps, (a, sa, c, sc))| {
            let elem = Elem::I32;
            let decl = vec![("x".to_owned(), a, a + sa), ("y".to_owned(), c, c + sc)];
            let mut b = Builder::new("p", 1e-3).unwrap();
            let mut ints: Vec<ValueId> = decl
                .iter()
                .map(|(n, lo, hi)| {
                    b.input_exact(n, elem, Some(Range::new(*lo as f64, *hi as f64)))
                        .unwrap()
                })
                .collect();
            let mut outs = vec![];
            for (kind, i, j, k) in steps {
                let x = ints[i as usize % ints.len()];
                let y = ints[j as usize % ints.len()];
                let k = if k == 0 { 1 } else { (k % 9) as i64 };
                let r = match kind {
                    0 => b.add(x, y),
                    1 => b.sub(x, y),
                    2 => b.mul(x, y),
                    3 => b.neg(x),
                    4 => b.not(x),
                    5 => b.logic(
                        [LogicOp::And, LogicOp::Or, LogicOp::Xor][j as usize % 3],
                        x,
                        y,
                    ),
                    6 => b.shift(x, i % 2 == 0, (j % 4) as u32),
                    7 => b.min(x, y),
                    8 => b.max(x, y),
                    9 | 10 => {
                        let c = b
                            .constant_exact(elem, if k == 0 { 1.0 } else { k as f64 })
                            .unwrap();
                        if kind == 9 {
                            b.div(x, c)
                        } else {
                            b.rem(x, c)
                        }
                    }
                    _ => {
                        let op = [CmpOp::Lt, CmpOp::Ge, CmpOp::Eq, CmpOp::Ne][i as usize % 4];
                        b.cmp(op, x, y).and_then(|t| {
                            if kind == 11 {
                                b.select(t, x, y)
                            } else {
                                let bit = b.cast(t, elem)?;
                                if kind == 12 {
                                    b.mul(bit, y)
                                } else {
                                    b.add(bit, x)
                                }
                            }
                        })
                    }
                };
                if let Ok(r) = r {
                    ints.push(r);
                    outs.push(r);
                }
            }
            for (n, v) in outs.iter().enumerate() {
                b.output(&format!("o{n}"), *v).unwrap();
            }
            (b.finish().unwrap(), decl)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn ranges_never_under_approximate((p, decl) in arb_program()) {
        prop_assert!(sound(&p, &decl).is_ok(), "{}", sound(&p, &decl).unwrap_err());
    }
}
