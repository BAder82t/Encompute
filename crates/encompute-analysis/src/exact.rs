//! Integer range analysis for exact programs: proves that no operation can
//! overflow its type for any input in the declared ranges (0.3, checked
//! arithmetic), and that lookup indices stay in their tables.

use encompute_ir::{Code, Elem, Error, LogicOp, Op, Program, Result, ValueId};

/// Largest magnitude that crosses the API boundary exactly (f64).
pub const MAX_IO: i128 = encompute_ir::MAX_EXACT_IO;

/// Inclusive interval over 128-bit integers.
pub type IntRange = (i128, i128);

fn overflow(id: ValueId, op: &str, r: IntRange, elem: Elem) -> Error {
    let (min, max) = elem.bounds();
    Error::new(
        Code::Overflow,
        format!(
            "possible integer overflow: {id} ({op}) may be in [{}, {}], but {elem} holds [{min}, {max}]; \
             use a wider type or narrower input ranges",
            r.0, r.1
        ),
    )
}

fn span_pow2(hi: i128) -> i128 {
    // Smallest 2^k - 1 ≥ hi, for hi ≥ 0.
    let mut m: i128 = 0;
    while m < hi {
        m = (m << 1) | 1;
    }
    m
}

/// Ranges of every exact node (`None` for approximate nodes).
pub fn int_ranges(program: &Program) -> Result<Vec<Option<IntRange>>> {
    let mut out: Vec<Option<IntRange>> = Vec::with_capacity(program.nodes().len());
    for (id, node) in program.iter() {
        let elem = node.ty.elem;
        if !elem.is_exact() {
            out.push(None);
            continue;
        }
        let g = |v: ValueId| out[v.index()].expect("exact operands have ranges");
        // Operands fit 64 bits, but u64 × u64 (or u64 << 63) can exceed
        // i128: fail closed instead of wrapping.
        let c = |v: Option<i128>| {
            v.ok_or_else(|| {
                Error::new(
                    Code::Overflow,
                    format!(
                        "possible integer overflow: {id} ({}) may exceed 128 bits; \
                         use narrower input ranges",
                        node.op.mnemonic()
                    ),
                )
            })
        };
        let (tmin, tmax) = elem.bounds();
        let r: IntRange = match &node.op {
            Op::Input { range, .. } => (range.lo as i128, range.hi as i128),
            Op::Const { data } => (data[0] as i128, data[0] as i128),
            Op::Add(a, b) => (
                c(g(*a).0.checked_add(g(*b).0))?,
                c(g(*a).1.checked_add(g(*b).1))?,
            ),
            Op::Sub(a, b) => (
                c(g(*a).0.checked_sub(g(*b).1))?,
                c(g(*a).1.checked_sub(g(*b).0))?,
            ),
            Op::Mul(a, b) => {
                let (a, b) = (g(*a), g(*b));
                let p = [
                    c(a.0.checked_mul(b.0))?,
                    c(a.0.checked_mul(b.1))?,
                    c(a.1.checked_mul(b.0))?,
                    c(a.1.checked_mul(b.1))?,
                ];
                (*p.iter().min().unwrap(), *p.iter().max().unwrap())
            }
            Op::Neg(a) => (-g(*a).1, -g(*a).0),
            Op::Cmp(..) => (0, 1),
            Op::Logic(l, a, b) => {
                let (a, b) = (g(*a), g(*b));
                if elem == Elem::Bool {
                    (0, 1)
                } else if a.0 >= 0 && b.0 >= 0 {
                    match l {
                        LogicOp::And => (0, a.1.min(b.1)),
                        LogicOp::Or | LogicOp::Xor => (0, span_pow2(a.1.max(b.1))),
                    }
                } else {
                    (tmin, tmax)
                }
            }
            Op::Not(_) if elem == Elem::Bool => (0, 1),
            Op::Not(a) if elem.is_signed() => (-g(*a).1 - 1, -g(*a).0 - 1),
            Op::Not(a) => (tmax - g(*a).1, tmax - g(*a).0),
            Op::Shift { x, left: true, by } => (
                c(g(*x).0.checked_mul(1 << by))?,
                c(g(*x).1.checked_mul(1 << by))?,
            ),
            Op::Shift { x, left: false, by } => (g(*x).0 >> by, g(*x).1 >> by),
            Op::Min(a, b) => (g(*a).0.min(g(*b).0), g(*a).1.min(g(*b).1)),
            Op::Max(a, b) => (g(*a).0.max(g(*b).0), g(*a).1.max(g(*b).1)),
            Op::Select(_, a, b) => (g(*a).0.min(g(*b).0), g(*a).1.max(g(*b).1)),
            Op::Lookup { x, table } => {
                let (lo, hi) = g(*x);
                if lo < 0 || hi >= table.len() as i128 {
                    return Err(Error::new(
                        Code::Overflow,
                        format!(
                            "{id} (lookup): index may be in [{lo}, {hi}], but the table has {} entries",
                            table.len()
                        ),
                    ));
                }
                let vals = table[lo as usize..=hi as usize].iter().map(|v| *v as i128);
                (vals.clone().min().unwrap(), vals.max().unwrap())
            }
            Op::Cast(a) => g(*a),
            Op::Div(a, b) => {
                let (a, c) = (g(*a), g(*b).0);
                if c > 0 {
                    (a.0 / c, a.1 / c)
                } else {
                    (a.1 / c, a.0 / c)
                }
            }
            Op::Rem(a, b) => {
                let (a, m) = (g(*a), g(*b).0.abs() - 1);
                if a.0 >= 0 {
                    (0, a.1.min(m))
                } else {
                    (-m, m)
                }
            }
            op => unreachable!("{} has an approximate result", op.mnemonic()),
        };
        if r.0 < tmin || r.1 > tmax {
            return Err(overflow(id, node.op.mnemonic(), r, elem));
        }
        out.push(Some(r));
    }
    for o in program.outputs() {
        if let Some((lo, hi)) = out[o.value.index()] {
            if lo < -MAX_IO || hi > MAX_IO {
                return Err(Error::new(
                    Code::Overflow,
                    format!(
                        "output {:?} may be in [{lo}, {hi}], beyond ±2^53, which numbers at the API \
                         boundary cannot represent exactly",
                        o.name
                    ),
                ));
            }
        }
    }
    Ok(out)
}

/// Which kind of program this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Semantics {
    /// Only approximate (f64) values: CKKS.
    Approximate,
    /// Only exact (integer/bool) values: TFHE.
    Exact,
}

/// Classify a program; mixing approximate and exact values is 0.4 work.
pub fn semantics(program: &Program) -> Result<Semantics> {
    let exact = program.nodes().iter().any(|n| n.ty.elem.is_exact());
    let approx = program.nodes().iter().any(|n| !n.ty.elem.is_exact());
    match (exact, approx) {
        (true, true) => Err(Error::new(
            Code::Unsupported,
            "this program mixes approximate (float) and exact (integer/bool) encrypted values; \
             Encompute 0.3 runs one encrypted scheme per program: split the computation, or \
             wait for hybrid execution (0.4)",
        )),
        (true, false) => Ok(Semantics::Exact),
        _ => Ok(Semantics::Approximate),
    }
}
