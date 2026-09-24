use proptest::prelude::*;
use veil_ir::{evaluate, parse, Builder, Code, Inputs, Program, Range, Shape, ValueId};

fn logistic() -> Program {
    let mut b = Builder::new("score", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(3), Range::new(-1.0, 1.0))
        .unwrap();
    let w = b.constant(Shape::Vector(3), vec![0.5, -0.25, 2.0]).unwrap();
    let bias = b.constant(Shape::Scalar, vec![0.1]).unwrap();
    let z = b.dot(w, x).unwrap();
    let z = b.add(z, bias).unwrap();
    let y = b.sigmoid(z).unwrap();
    b.output("score", y).unwrap();
    b.finish().unwrap()
}

#[test]
fn prints_the_documented_form() {
    let text = logistic().to_string();
    assert_eq!(
        text,
        "veil 0.1\n\
         program score precision 0.001\n\
         %0 = input \"x\" [-1.0, 1.0] : secret vector<3>\n\
         %1 = const [0.5, -0.25, 2.0] : public vector<3>\n\
         %2 = const [0.1] : public scalar\n\
         %3 = dot %1, %0 : secret scalar\n\
         %4 = add %3, %2 : secret scalar\n\
         %5 = sigmoid %4 : secret scalar\n\
         output \"score\" = %5\n"
    );
    assert_eq!(parse(&text).unwrap(), logistic());
}

#[test]
fn evaluates_reference_semantics() {
    let mut inputs = Inputs::new();
    inputs.insert("x".into(), vec![1.0, 0.0, -0.5]);
    let out = evaluate(&logistic(), &inputs).unwrap();
    let z: f64 = 0.5 - 1.0 + 0.1;
    assert!((out["score"][0] - 1.0 / (1.0 + (-z).exp())).abs() < 1e-15);
}

#[test]
fn matvec_and_broadcast() {
    let mut b = Builder::new("m", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(3), Range::new(-2.0, 2.0))
        .unwrap();
    let s = b.input("s", Shape::Scalar, Range::new(0.0, 1.0)).unwrap();
    let m = b
        .constant(Shape::Matrix(2, 3), vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0])
        .unwrap();
    let y = b.matvec(m, x).unwrap();
    let y = b.mul(y, s).unwrap();
    let p = b.poly(y, vec![1.0, 0.0, 2.0]).unwrap();
    b.output("y", p).unwrap();
    let prog = b.finish().unwrap();
    let mut inputs = Inputs::new();
    inputs.insert("x".into(), vec![1.0, -1.0, 2.0]);
    inputs.insert("s".into(), vec![0.5]);
    let out = evaluate(&prog, &inputs).unwrap();
    // m·x = [5, 11], ·0.5 = [2.5, 5.5], 1 + 2y² = [13.5, 61.5]
    assert_eq!(out["y"], vec![13.5, 61.5]);
    assert_eq!(parse(&prog.to_string()).unwrap(), prog);
}

#[test]
fn rejects_out_of_range_and_missing_inputs() {
    let p = logistic();
    let mut inputs = Inputs::new();
    inputs.insert("x".into(), vec![1.0, 0.0, -1.5]);
    assert_eq!(evaluate(&p, &inputs).unwrap_err().code, Code::BadInput);
    assert_eq!(
        evaluate(&p, &Inputs::new()).unwrap_err().code,
        Code::BadInput
    );
    inputs.insert("x".into(), vec![0.0, 0.0, 0.0]);
    inputs.insert("y".into(), vec![0.0]);
    assert_eq!(evaluate(&p, &inputs).unwrap_err().code, Code::BadInput);
}

#[test]
fn type_rules() {
    let mut b = Builder::new("t", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(3), Range::new(-1.0, 1.0))
        .unwrap();
    let y = b
        .input("y", Shape::Vector(4), Range::new(-1.0, 1.0))
        .unwrap();
    let c = b.constant(Shape::Scalar, vec![1.0]).unwrap();
    let m = b.constant(Shape::Matrix(2, 4), vec![0.0; 8]).unwrap();
    assert_eq!(b.add(x, y).unwrap_err().code, Code::Type);
    assert_eq!(b.dot(x, y).unwrap_err().code, Code::Type);
    assert_eq!(b.add(c, c).unwrap_err().code, Code::Type, "public-only op");
    assert_eq!(b.matvec(m, x).unwrap_err().code, Code::Type);
    assert_eq!(b.add(m, x).unwrap_err().code, Code::Type);
    assert_eq!(b.matvec(x, y).unwrap_err().code, Code::Unsupported);
    assert_eq!(b.poly(x, vec![1.0]).unwrap_err().code, Code::Type);
    assert_eq!(b.ty(ValueId(99)).unwrap_err().code, Code::Type);
    assert_eq!(
        b.input("z", Shape::Scalar, Range::new(1.0, 1.0))
            .unwrap_err()
            .code,
        Code::MissingRange
    );
    assert_eq!(
        b.input("x", Shape::Scalar, Range::new(0.0, 1.0))
            .unwrap_err()
            .code,
        Code::Type,
        "duplicate"
    );
    assert_eq!(
        b.output("out", c).unwrap_err().code,
        Code::Type,
        "public output"
    );
    assert!(Builder::new("bad name", 1e-3).is_err());
    assert!(Builder::new("p", 0.0).is_err());
    assert_eq!(b.finish().unwrap_err().code, Code::Type, "no outputs");
}

#[test]
fn parse_errors_carry_line_numbers() {
    let bad = "veil 0.1\nprogram p precision 0.1\n%0 = input \"x\" [0.0, 1.0] : secret vector<2>\n%1 = neg %0 : secret scalar\noutput \"y\" = %1\n";
    let e = parse(bad).unwrap_err();
    assert_eq!(e.code, Code::Parse);
    assert!(e.message.starts_with("line 4:"), "{}", e.message);

    let bad = "veil 0.1\nprogram p precision 0.1\n%1 = input \"x\" [0.0, 1.0] : secret scalar\n";
    assert!(parse(bad).unwrap_err().message.contains("expected %0"));
    assert_eq!(parse("veil 0.2\n").unwrap_err().code, Code::Parse);
    let bad = "veil 0.1\nprogram p precision 0.1\n%0 = input \"x\" [0.0, 1.0] : secret scalar\n%1 = frob %0 : secret scalar\n";
    assert!(parse(bad).unwrap_err().message.contains("unknown op"));
    let bad = "veil 0.1\nprogram p precision 0.1\n%0 = input \"x\" [0.0, inf] : secret scalar\n";
    assert_eq!(parse(bad).unwrap_err().code, Code::Parse);
}

#[test]
fn comments_and_blank_lines_are_ignored() {
    let src = format!("# model\n\n{}\n# end\n", logistic());
    assert_eq!(parse(&src).unwrap(), logistic());
}

/// Random well-typed programs built through the checked builder.
fn arb_program() -> impl Strategy<Value = Program> {
    let finite = -1e6f64..1e6;
    (
        1usize..6,
        prop::collection::vec((0u8..9, any::<u32>(), any::<u32>(), finite.clone()), 1..25),
        prop::collection::vec(finite, 8),
    )
        .prop_map(|(n, steps, pool)| {
            let mut b = Builder::new("p", 1e-4).unwrap();
            let v = b
                .input("v", Shape::Vector(n), Range::new(-3.0, 3.5))
                .unwrap();
            let s = b.input("s", Shape::Scalar, Range::new(-0.5, 1e-3)).unwrap();
            let mut secrets = vec![v, s];
            for (kind, i, j, x) in steps {
                let a = secrets[i as usize % secrets.len()];
                let other = secrets[j as usize % secrets.len()];
                let r = match kind {
                    0 => b.add(a, other),
                    1 => b.sub(a, other),
                    2 => b.mul(a, other),
                    3 => b.neg(a),
                    4 => b.sum(a),
                    5 => b.sigmoid(a),
                    6 => b.poly(a, vec![x, pool[0], pool[1]]),
                    7 => {
                        let c = b
                            .constant(
                                Shape::Vector(n),
                                pool.iter().cycle().take(n).copied().collect(),
                            )
                            .unwrap();
                        b.dot(c, a)
                    }
                    _ => {
                        let c = b
                            .constant(
                                Shape::Matrix(2, n),
                                pool.iter().cycle().take(2 * n).copied().collect(),
                            )
                            .unwrap();
                        b.matvec(c, a)
                    }
                };
                if let Ok(id) = r {
                    secrets.push(id);
                }
            }
            let last = *secrets.last().unwrap();
            b.output("out", last).unwrap();
            b.output("v_copy", v).unwrap();
            b.finish().unwrap()
        })
}

proptest! {
    #[test]
    fn print_parse_round_trip(p in arb_program()) {
        let text = p.to_string();
        let back = parse(&text).unwrap();
        prop_assert_eq!(&back, &p);
        prop_assert_eq!(back.to_string(), text);
    }
}
