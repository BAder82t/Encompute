use encompute_analysis::{int_ranges, semantics, Semantics};
use encompute_ir::{
    evaluate, parse, Builder, CmpOp, Code, Elem, Inputs, LogicOp, Program, Range, Shape, ValueId,
};
use proptest::prelude::*;

/// The 0.3 flagship: private eligibility.
fn approve() -> Program {
    let mut b = Builder::new("approve", 1e-3).unwrap();
    let age = b
        .input_exact("age", Elem::U8, Some(Range::new(0.0, 120.0)))
        .unwrap();
    let income = b
        .input_exact("income", Elem::U32, Some(Range::new(0.0, 1e6)))
        .unwrap();
    let debt = b
        .input_exact("debt", Elem::U32, Some(Range::new(0.0, 1e6)))
        .unwrap();
    let risk = b
        .input_exact("risk", Elem::U16, Some(Range::new(0.0, 1000.0)))
        .unwrap();
    let c18 = b.constant_exact(Elem::U8, 18.0).unwrap();
    let c100 = b.constant_exact(Elem::U32, 100.0).unwrap();
    let c35 = b.constant_exact(Elem::U32, 35.0).unwrap();
    let c650 = b.constant_exact(Elem::U16, 650.0).unwrap();
    let adult = b.cmp(CmpOp::Ge, age, c18).unwrap();
    let d = b.mul(debt, c100).unwrap();
    let i = b.mul(income, c35).unwrap();
    let ok_debt = b.cmp(CmpOp::Lt, d, i).unwrap();
    let ok_risk = b.cmp(CmpOp::Lt, risk, c650).unwrap();
    let x = b.logic(LogicOp::And, adult, ok_debt).unwrap();
    let x = b.logic(LogicOp::And, x, ok_risk).unwrap();
    b.output("approved", x).unwrap();
    b.finish().unwrap()
}

fn run(p: &Program, vals: &[(&str, f64)]) -> f64 {
    let inputs: Inputs = vals
        .iter()
        .map(|(k, v)| (k.to_string(), vec![*v]))
        .collect();
    evaluate(p, &inputs).unwrap().values().next().unwrap()[0]
}

#[test]
fn flagship_semantics_text_and_ranges() {
    let p = approve();
    assert_eq!(semantics(&p).unwrap(), Semantics::Exact);
    int_ranges(&p).unwrap();
    let text = p.to_string();
    assert!(
        text.contains(": secret u32")
            && text.contains(": secret bool")
            && text.contains(": public u16"),
        "{text}"
    );
    assert_eq!(parse(&text).unwrap(), p);
    let yes = [
        ("age", 35.0),
        ("income", 100_000.0),
        ("debt", 20_000.0),
        ("risk", 420.0),
    ];
    assert_eq!(run(&p, &yes), 1.0);
    let minor = [
        ("age", 17.0),
        ("income", 100_000.0),
        ("debt", 20_000.0),
        ("risk", 420.0),
    ];
    assert_eq!(run(&p, &minor), 0.0);
    let debt = [
        ("age", 35.0),
        ("income", 100_000.0),
        ("debt", 35_000.0),
        ("risk", 420.0),
    ];
    assert_eq!(run(&p, &debt), 0.0, "debt*100 == income*35 is not <");
    let e = evaluate(
        &p,
        &[
            ("age", vec![35.5]),
            ("income", vec![0.0]),
            ("debt", vec![0.0]),
            ("risk", vec![0.0]),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
    )
    .unwrap_err();
    assert_eq!(e.code, Code::BadInput, "fractional exact input");
}

#[test]
fn overflow_is_a_compile_error() {
    let mut b = Builder::new("p", 1e-3).unwrap();
    let debt = b
        .input_exact("debt", Elem::U16, Some(Range::new(0.0, 1000.0)))
        .unwrap();
    let c = b.constant_exact(Elem::U16, 100.0).unwrap();
    let m = b.mul(debt, c).unwrap();
    b.output("m", m).unwrap();
    let e = int_ranges(&b.finish().unwrap()).unwrap_err();
    assert_eq!(e.code, Code::Overflow);
    assert!(
        e.message.contains("[0, 100000]") && e.message.contains("u16"),
        "{}",
        e.message
    );

    // Unsigned subtraction that can go negative.
    let mut b = Builder::new("p", 1e-3).unwrap();
    let a = b.input_exact("a", Elem::U8, None).unwrap();
    let c = b.input_exact("c", Elem::U8, None).unwrap();
    let d = b.sub(a, c).unwrap();
    b.output("d", d).unwrap();
    assert_eq!(
        int_ranges(&b.finish().unwrap()).unwrap_err().code,
        Code::Overflow
    );

    // Lookup index beyond the table.
    let mut b = Builder::new("p", 1e-3).unwrap();
    let x = b
        .input_exact("x", Elem::U8, Some(Range::new(0.0, 10.0)))
        .unwrap();
    let l = b.lookup(x, vec![1.0, 2.0, 3.0]).unwrap();
    b.output("l", l).unwrap();
    assert_eq!(
        int_ranges(&b.finish().unwrap()).unwrap_err().code,
        Code::Overflow
    );

    // Output beyond ±2^53.
    let mut b = Builder::new("p", 1e-3).unwrap();
    let x = b
        .input_exact("x", Elem::I64, Some(Range::new(0.0, (1u64 << 40) as f64)))
        .unwrap();
    let c = b.constant_exact(Elem::I64, (1u64 << 20) as f64).unwrap();
    let y = b.mul(x, c).unwrap();
    b.output("y", y).unwrap();
    assert_eq!(
        int_ranges(&b.finish().unwrap()).unwrap_err().code,
        Code::Overflow
    );
}

#[test]
fn type_rules_and_scheme_classification() {
    let mut b = Builder::new("p", 1e-3).unwrap();
    let x = b.input_exact("x", Elem::U8, None).unwrap();
    let y = b.input_exact("y", Elem::U16, None).unwrap();
    let f = b.input("f", Shape::Scalar, Range::new(0.0, 1.0)).unwrap();
    assert_eq!(
        b.add(x, y).unwrap_err().code,
        Code::Type,
        "mixed widths need a cast"
    );
    assert_eq!(
        b.cmp(CmpOp::Lt, f, f).unwrap_err().code,
        Code::Type,
        "no exact compare on floats"
    );
    assert_eq!(b.add(x, f).unwrap_err().code, Code::Type);
    assert_eq!(b.sigmoid(x).unwrap_err().code, Code::Type);
    let t = b.cmp(CmpOp::Gt, x, x).unwrap();
    assert_eq!(
        b.add(t, t).unwrap_err().code,
        Code::Type,
        "arithmetic on bool"
    );
    assert_eq!(
        b.select(x, x, x).unwrap_err().code,
        Code::Type,
        "non-bool condition"
    );
    assert_eq!(b.div(x, y).unwrap_err().code, Code::SecretDivision);
    let z = b.constant_exact(Elem::U8, 0.0).unwrap();
    assert_eq!(
        b.div(x, z).unwrap_err().code,
        Code::Type,
        "division by zero"
    );
    assert!(b.constant_exact(Elem::U8, 300.0).is_err());
    assert!(b.constant_exact(Elem::I8, 1.5).is_err());
    assert_eq!(
        b.input_exact("w", Elem::U8, Some(Range::new(-1.0, 10.0)))
            .unwrap_err()
            .code,
        Code::MissingRange
    );
    let wide = b.cast(x, Elem::U16).unwrap();
    let s = b.add(wide, y).unwrap();
    b.output("s", s).unwrap();
    b.output("f", f).unwrap();
    let p = b.finish().unwrap();
    assert_eq!(
        semantics(&p).unwrap_err().code,
        Code::Unsupported,
        "mixed programs are 0.4"
    );
}

const WIDTHS: [Elem; 6] = [
    Elem::U8,
    Elem::U16,
    Elem::U32,
    Elem::I8,
    Elem::I16,
    Elem::I32,
];

/// Random exact programs over one integer type.
fn arb_program() -> impl Strategy<Value = (Program, Vec<(String, i64, i64)>)> {
    (
        0usize..WIDTHS.len(),
        prop::collection::vec((0u8..16, any::<u32>(), any::<u32>(), any::<i16>()), 1..12),
        prop::collection::vec((any::<i16>(), 0u16..400), 3),
    )
        .prop_map(|(w, steps, ranges)| {
            let elem = WIDTHS[w];
            let (min, max) = elem.bounds();
            let clamp = |v: i128| v.clamp(min.max(-30000), max.min(30000));
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
            let mut bools: Vec<ValueId> = vec![];
            for (kind, i, j, c) in steps {
                let a = ints[i as usize % ints.len()];
                let o = ints[j as usize % ints.len()];
                let r = match kind {
                    0 => b.add(a, o),
                    1 => b.sub(a, o),
                    2 => b.mul(a, o),
                    3 => b.min(a, o),
                    4 => b.max(a, o),
                    5 => b.logic(LogicOp::And, a, o),
                    6 => b.logic(LogicOp::Or, a, o),
                    7 => b.logic(LogicOp::Xor, a, o),
                    8 => b.not(a),
                    9 => b.shift(a, c % 2 == 0, (c.unsigned_abs() as u32) % 3),
                    10 => {
                        let k = b
                            .constant_exact(elem, clamp(c as i128 % 7 + 1) as f64)
                            .unwrap();
                        if c % 2 == 0 {
                            b.div(a, k)
                        } else {
                            b.rem(a, k)
                        }
                    }
                    11 => {
                        let k = b
                            .constant_exact(elem, clamp(c as i128 % 50) as f64)
                            .unwrap();
                        b.mul(a, k)
                    }
                    12 | 13 => {
                        let op = [CmpOp::Lt, CmpOp::Ge, CmpOp::Eq, CmpOp::Ne][(c as usize) % 4];
                        match b.cmp(op, a, o) {
                            Ok(t) => {
                                bools.push(t);
                                Ok(t)
                            }
                            e => e,
                        }
                    }
                    14 if !bools.is_empty() => b.select(bools[i as usize % bools.len()], a, o),
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
            for (k, id) in bools.iter().enumerate() {
                b.output(&format!("b{k}"), *id).unwrap();
            }
            if ints.len() == 3 && bools.is_empty() {
                let n = b.neg(ints[0]).or_else(|_| b.not(ints[0])).unwrap();
                b.output("n", n).unwrap();
            }
            (b.finish().unwrap(), decl)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Soundness: accepted programs never leave their analyzed ranges or
    /// their types; the text form round-trips.
    #[test]
    fn exact_analysis_is_sound((p, decl) in arb_program(), seed in any::<u64>()) {
        prop_assert_eq!(parse(&p.to_string()).unwrap(), p.clone());
        let ranges = match int_ranges(&p) {
            Ok(r) => r,
            Err(e) => {
                prop_assert_eq!(e.code, Code::Overflow);
                return Ok(());
            }
        };
        let mut s = seed;
        for case in 0..8 {
            let inputs: Inputs = decl.iter().map(|(n, lo, hi)| {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let v = match case { 0 => *lo, 1 => *hi, _ => lo + (s >> 33) as i64 % (hi - lo + 1) };
                (n.clone(), vec![v as f64])
            }).collect();
            let out = evaluate(&p, &inputs).unwrap();
            for o in p.outputs() {
                let v = out[&o.name][0] as i128;
                let (lo, hi) = ranges[o.value.index()].unwrap();
                let (tmin, tmax) = p.node(o.value).ty.elem.bounds();
                prop_assert!(lo <= v && v <= hi, "{} = {} outside [{}, {}]\n{}", o.name, v, lo, hi, p);
                prop_assert!(tmin <= v && v <= tmax);
            }
        }
    }
}

/// A u64 value near 2^64 squared (or shifted by 63) exceeds i128: refused,
/// never a panic or a wrap.
#[test]
fn wide_ranges_fail_closed() {
    let top = 9007199254740992.0; // 2^53, the largest exact input
    for op in ["mul", "shl"] {
        let mut b = Builder::new("w", 1e-3).unwrap();
        let x = b
            .input_exact("x", Elem::U64, Some(Range::new(0.0, top)))
            .unwrap();
        let k = b.constant_exact(Elem::U64, 2047.0).unwrap();
        let big = b.mul(x, k).unwrap(); // up to ~2^64, still a u64
        let r = if op == "mul" {
            b.mul(big, big).unwrap()
        } else {
            b.shift(big, true, 63).unwrap()
        };
        b.output("r", r).unwrap();
        let p = b.finish().unwrap();
        assert_eq!(int_ranges(&p).unwrap_err().code, Code::Overflow, "{op}");
        // The clear interpreter is checked on its own, too.
        let inputs: Inputs = [("x".into(), vec![top])].into();
        assert_eq!(
            evaluate(&p, &inputs).unwrap_err().code,
            Code::Overflow,
            "{op}"
        );
    }
}

#[test]
fn exact_io_stops_at_2_pow_53() {
    let mut b = Builder::new("w", 1e-3).unwrap();
    let too_big = Range::new(0.0, 2f64.powi(60));
    assert_eq!(
        b.input_exact("x", Elem::U64, Some(too_big))
            .unwrap_err()
            .code,
        Code::MissingRange
    );
    assert_eq!(
        b.constant_exact(Elem::I64, -(2f64.powi(54)))
            .unwrap_err()
            .code,
        Code::Type
    );
}

#[test]
fn unsigned_neg_is_a_type_error() {
    let mut b = Builder::new("n", 1e-3).unwrap();
    let x = b.input_exact("x", Elem::U8, None).unwrap();
    assert_eq!(b.neg(x).unwrap_err().code, Code::Type);
}
