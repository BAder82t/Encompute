use encompute_analysis::{privacy, ranges, Interval};
use encompute_ir::{evaluate, Builder, Inputs, Range, Shape};
use proptest::prelude::*;

#[test]
fn logistic_ranges_are_tight() {
    let mut b = Builder::new("p", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(3), Range::new(-1.0, 1.0))
        .unwrap();
    let w = b.constant(Shape::Vector(3), vec![0.5, -0.25, 2.0]).unwrap();
    let z = b.dot(w, x).unwrap();
    let sq = b.mul(z, z).unwrap();
    let s = b.sigmoid(z).unwrap();
    b.output("s", s).unwrap();
    b.output("sq", sq).unwrap();
    let p = b.finish().unwrap();
    let r = ranges(&p).unwrap();
    assert_eq!(r.hull(z), Interval::new(-2.75, 2.75));
    assert_eq!(r.hull(sq), Interval::new(0.0, 2.75 * 2.75));
    assert!((r.hull(s).lo - 1.0 / (1.0 + 2.75f64.exp())).abs() < 1e-15);
}

#[test]
fn privacy_tracks_dependencies() {
    let mut b = Builder::new("p", 1e-3).unwrap();
    let x = b.input("x", Shape::Scalar, Range::new(0.0, 1.0)).unwrap();
    let y = b.input("y", Shape::Scalar, Range::new(0.0, 1.0)).unwrap();
    let _unused = b.input("z", Shape::Scalar, Range::new(0.0, 1.0)).unwrap();
    let xy = b.mul(x, y).unwrap();
    b.output("xy", xy).unwrap();
    b.output("x", x).unwrap();
    let rep = privacy(&b.finish().unwrap());
    assert_eq!(rep.outputs[0].depends_on, vec!["x", "y"]);
    assert_eq!(rep.outputs[1].depends_on, vec!["x"]);
    assert_eq!(rep.unused_inputs, vec!["z"]);
}

proptest! {
    /// Soundness: evaluating at random in-range inputs stays inside the bounds.
    #[test]
    fn ranges_contain_evaluations(
        xs in prop::collection::vec(-2.0f64..3.0, 4),
        s in -1.0f64..0.5,
        coeffs in prop::collection::vec(-3.0f64..3.0, 2..6),
        w in prop::collection::vec(-5.0f64..5.0, 8),
    ) {
        let mut b = Builder::new("p", 1e-3).unwrap();
        let x = b.input("x", Shape::Vector(4), Range::new(-2.0, 3.0)).unwrap();
        let si = b.input("s", Shape::Scalar, Range::new(-1.0, 0.5)).unwrap();
        let m = b.constant(Shape::Matrix(2, 4), w).unwrap();
        let y = b.matvec(m, x).unwrap();
        let y = b.sub(y, si).unwrap();
        let p = b.poly(y, coeffs).unwrap();
        let q = b.mul(p, si).unwrap();
        let t = b.sum(q).unwrap();
        let u = b.sigmoid(t).unwrap();
        let v = b.neg(x).unwrap();
        let v = b.add(v, u).unwrap();
        let v = b.mul(v, v).unwrap();
        b.output("t", t).unwrap();
        b.output("v", v).unwrap();
        let prog = b.finish().unwrap();
        let r = ranges(&prog).unwrap();
        let mut inputs = Inputs::new();
        inputs.insert("x".into(), xs);
        inputs.insert("s".into(), vec![s]);
        let out = evaluate(&prog, &inputs).unwrap();
        for o in prog.outputs() {
            for (val, iv) in out[&o.name].iter().zip(r.elements(o.value)) {
                let slack = 1e-9 * (1.0 + iv.max_abs());
                prop_assert!(iv.lo - slack <= *val && *val <= iv.hi + slack, "{} = {} not in {:?}", o.name, val, iv);
            }
        }
    }
}
