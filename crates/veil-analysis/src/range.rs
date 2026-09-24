use veil_ir::{sigmoid, Code, Error, Op, Program, Result, Shape, ValueId};

/// Closed interval. Always finite; analysis fails rather than produce ∞.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Interval {
    pub lo: f64,
    pub hi: f64,
}

impl Interval {
    pub fn point(x: f64) -> Self {
        Self { lo: x, hi: x }
    }

    pub fn new(lo: f64, hi: f64) -> Self {
        debug_assert!(lo <= hi);
        Self { lo, hi }
    }

    pub fn contains(self, x: f64) -> bool {
        self.lo <= x && x <= self.hi
    }

    pub fn max_abs(self) -> f64 {
        self.lo.abs().max(self.hi.abs())
    }

    pub fn union(self, o: Self) -> Self {
        Self::new(self.lo.min(o.lo), self.hi.max(o.hi))
    }

    pub fn intersect(self, o: Self) -> Self {
        Self::new(self.lo.max(o.lo), self.hi.min(o.hi))
    }

    fn add(self, o: Self) -> Self {
        Self::new(self.lo + o.lo, self.hi + o.hi)
    }

    fn neg(self) -> Self {
        Self::new(-self.hi, -self.lo)
    }

    fn mul(self, o: Self) -> Self {
        let p = [
            self.lo * o.lo,
            self.lo * o.hi,
            self.hi * o.lo,
            self.hi * o.hi,
        ];
        Self::new(
            p.iter().copied().fold(f64::INFINITY, f64::min),
            p.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        )
    }

    /// `x^k`, exact for a single interval (tighter than repeated `mul`).
    fn powi(self, k: u32) -> Self {
        if k == 0 {
            return Self::point(1.0);
        }
        let (a, b) = (self.lo.powi(k as i32), self.hi.powi(k as i32));
        if k % 2 == 1 {
            Self::new(a, b)
        } else if self.contains(0.0) {
            Self::new(0.0, a.max(b))
        } else {
            Self::new(a.min(b), a.max(b))
        }
    }

    fn scale(self, c: f64) -> Self {
        Self::point(c).mul(self)
    }
}

/// Per-element intervals for every node (a scalar has one element).
#[derive(Clone, Debug)]
pub struct RangeMap {
    values: Vec<Vec<Interval>>,
}

impl RangeMap {
    pub fn elements(&self, id: ValueId) -> &[Interval] {
        &self.values[id.index()]
    }

    /// Hull of all elements of `id`.
    pub fn hull(&self, id: ValueId) -> Interval {
        self.values[id.index()]
            .iter()
            .copied()
            .reduce(Interval::union)
            .expect("values are non-empty")
    }

    /// Largest magnitude of any element of any value.
    pub fn max_abs(&self) -> f64 {
        self.values
            .iter()
            .flatten()
            .map(|i| i.max_abs())
            .fold(0.0, f64::max)
    }
}

/// Sound interval bounds for every value, given the declared input ranges.
pub fn ranges(program: &Program) -> Result<RangeMap> {
    let mut values: Vec<Vec<Interval>> = Vec::with_capacity(program.nodes().len());
    for (id, node) in program.iter() {
        let get = |v: ValueId| &values[v.index()];
        let r: Vec<Interval> = match &node.op {
            Op::Input { range, .. } => {
                vec![Interval::new(range.lo, range.hi); node.ty.shape.len()]
            }
            Op::Const { data } => data.iter().map(|&x| Interval::point(x)).collect(),
            Op::Add(a, b) => zip(get(*a), get(*b), Interval::add),
            Op::Sub(a, b) => zip(get(*a), get(*b), |x, y| x.add(y.neg())),
            Op::Mul(a, b) if a == b => get(*a).iter().map(|x| x.powi(2)).collect(),
            Op::Mul(a, b) => zip(get(*a), get(*b), Interval::mul),
            Op::Neg(a) => get(*a).iter().map(|x| x.neg()).collect(),
            Op::Sum(a) => vec![sum(get(*a).iter().copied())],
            Op::Dot(a, b) => vec![sum(get(*a).iter().zip(get(*b)).map(|(x, y)| x.mul(*y)))],
            Op::MatVec(m, v) => {
                let Shape::Matrix(rows, cols) = program.node(*m).ty.shape else {
                    unreachable!("verified by the builder")
                };
                let (m, v) = (get(*m), get(*v));
                (0..rows)
                    .map(|r| sum((0..cols).map(|c| m[r * cols + c].mul(v[c]))))
                    .collect()
            }
            Op::Poly { x, coeffs } => get(*x).iter().map(|&x| poly(coeffs, x)).collect(),
            Op::Sigmoid(x) => get(*x)
                .iter()
                .map(|x| Interval::new(sigmoid(x.lo), sigmoid(x.hi)))
                .collect(),
        };
        if let Some(bad) = r.iter().find(|i| !(i.lo.is_finite() && i.hi.is_finite())) {
            return Err(Error::new(
                Code::PrecisionUnreachable,
                format!(
                    "{id} ({}) has an unbounded range [{}, {}]; narrow the input ranges",
                    node.op.mnemonic(),
                    bad.lo,
                    bad.hi
                ),
            ));
        }
        values.push(r);
    }
    Ok(RangeMap { values })
}

fn zip(
    a: &[Interval],
    b: &[Interval],
    f: impl Fn(Interval, Interval) -> Interval,
) -> Vec<Interval> {
    match (a.len(), b.len()) {
        (1, _) => b.iter().map(|&y| f(a[0], y)).collect(),
        (_, 1) => a.iter().map(|&x| f(x, b[0])).collect(),
        _ => a.iter().zip(b).map(|(&x, &y)| f(x, y)).collect(),
    }
}

fn sum(it: impl Iterator<Item = Interval>) -> Interval {
    it.fold(Interval::point(0.0), Interval::add)
}

/// Intersection of two sound enclosures: interval Horner, and the sum of
/// exact monomial ranges.
fn poly(coeffs: &[f64], x: Interval) -> Interval {
    let horner = coeffs.iter().rev().fold(Interval::point(0.0), |acc, &c| {
        acc.mul(x).add(Interval::point(c))
    });
    let monomials = sum(coeffs
        .iter()
        .enumerate()
        .map(|(k, &c)| x.powi(k as u32).scale(c)));
    horner.intersect(monomials)
}
