use std::collections::BTreeSet;

use encompute_analysis::{privacy, ranges, PrivacyReport, RangeMap};
use encompute_ir::{sigmoid, Code, Error, Op, Program, Result, Shape, ValueId};
use serde::{Deserialize, Serialize};

use crate::approx::chebyshev_fit;
use crate::params::{select_params, CkksParams};
use crate::plan::{Approximation, CkksPlan, Instr, Plain, PlanInput, PlanOutput, Reg};

/// Highest Chebyshev degree tried for an approximation (depth 7 + 2).
const MAX_APPROX_DEGREE: usize = 127;
/// Share of the precision budget given to function approximation; the rest
/// is left for CKKS noise.
const APPROX_SHARE: f64 = 0.5;

/// Output of [`compile`].
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Compiled {
    pub plan: CkksPlan,
    pub params: CkksParams,
    pub estimate: PrecisionEstimate,
    pub privacy: PrivacyReport,
}

/// Advisory error estimate; `encompute test` measures the real error.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrecisionEstimate {
    pub target: f64,
    /// Sum of the approximation errors of every approximated function.
    pub approximation: f64,
    /// Heuristic CKKS noise bound from the scale and value magnitudes.
    pub ckks_noise: f64,
    pub total: f64,
}

/// Lower `program` to a CKKS plan and choose its parameters.
pub fn compile(program: &Program) -> Result<Compiled> {
    if encompute_analysis::semantics(program)? == encompute_analysis::Semantics::Exact {
        return Err(Error::new(
            Code::Type,
            "program requires exact integer/bool semantics (comparisons, logic, selection); CKKS \
             does not provide exact semantics. Use scheme \"auto\" or \"tfhe\"",
        ));
    }
    let ranges = ranges(program)?;
    let slots = required_slots(program);
    let mut e = Emitter::new(program, &ranges, slots);
    let live = program.live();
    let mut vals: Vec<Option<Val>> = vec![None; program.nodes().len()];

    for (id, node) in program.iter() {
        let is_input = matches!(node.op, Op::Input { .. });
        if !live[id.index()] && !is_input {
            continue;
        }
        let get = |v: ValueId| vals[v.index()].expect("operands precede their users");
        let v = match &node.op {
            Op::Input { name, .. } => {
                let index = e.inputs.len();
                e.inputs.push(PlanInput {
                    name: name.clone(),
                    len: node.ty.shape.len(),
                    scalar: node.ty.shape == Shape::Scalar,
                });
                let bound = ranges.hull(id).max_abs();
                let reg = e.push(Instr::Input { index }, bound);
                Val::Secret(reg, layout_of(node.ty.shape))
            }
            Op::Const { .. } => Val::Public(id),
            Op::Add(a, b) => e.add(get(*a), get(*b), false)?,
            Op::Sub(a, b) => e.add(get(*a), get(*b), true)?,
            Op::Mul(a, b) => e.mul(get(*a), get(*b))?,
            Op::Neg(a) => {
                let (r, l) = secret(get(*a));
                Val::Secret(e.neg(r), l)
            }
            Op::Sum(a) => e.sum(get(*a)),
            Op::Dot(a, b) => {
                let prod = e.mul(get(*a), get(*b))?;
                e.sum(prod)
            }
            Op::MatVec(m, v) => e.matvec(*m, get(*v)),
            Op::Poly { x, coeffs } => e.poly(get(*x), coeffs),
            Op::Sigmoid(x) => e.sigmoid(id, *x, get(*x))?,
            op => unreachable!("{} is exact; rejected above", op.mnemonic()),
        };
        // IR ranges bound the real elements; padding is covered only when clean.
        if let Val::Secret(reg, layout) = v {
            if layout.padding_is_zero() {
                let ir = ranges.hull(id).max_abs() + e.approx_error;
                e.tighten(reg, ir * (1.0 + 1e-9));
            }
        }
        vals[id.index()] = Some(v);
    }

    // Each output gets its own register so the evaluator can hand them out
    // by value; a repeated one is copied with a level-free `+ 0`.
    let mut seen = BTreeSet::new();
    let outputs = program
        .outputs()
        .iter()
        .map(|o| {
            let (mut reg, _) = secret(vals[o.value.index()].unwrap());
            if !seen.insert(reg) {
                let b = e.bound(reg);
                reg = e.push(Instr::AddConst(reg, 0.0), b);
            }
            PlanOutput {
                name: o.name.clone(),
                reg,
                len: program.node(o.value).ty.shape.len(),
            }
        })
        .collect();

    let depth = e.levels.iter().copied().max().unwrap_or(0);
    let max_abs = e.bounds.iter().copied().fold(0.0, f64::max);
    let params = select_params(depth, max_abs, program.precision(), slots)?;

    let approximation = e
        .approximations
        .iter()
        .map(|a| a.chebyshev.max_error)
        .fold(0.0, |s, x| s + x);
    let ckks_noise = (1.0 + max_abs) * 2f64.powi(-(params.scale_bits as i32 - 20));
    let estimate = PrecisionEstimate {
        target: program.precision(),
        approximation,
        ckks_noise,
        total: approximation + ckks_noise,
    };

    let plan = CkksPlan {
        slots: params.slots as usize,
        inputs: e.inputs,
        instrs: e.instrs,
        levels: e.levels,
        bounds: e.bounds,
        outputs,
        rotations: e.rotations.into_iter().collect(),
        depth,
        approximations: e.approximations,
    };
    Ok(Compiled {
        plan,
        params,
        estimate,
        privacy: privacy(program),
    })
}

/// Slots needed: the next power of two covering every vector and matrix dimension.
fn required_slots(program: &Program) -> usize {
    program
        .nodes()
        .iter()
        .map(|n| match n.ty.shape {
            Shape::Scalar => 1,
            Shape::Vector(k) => k,
            Shape::Matrix(r, c) => r.max(c),
        })
        .max()
        .unwrap_or(1)
        .next_power_of_two()
        .max(2)
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Layout {
    /// Scalar value in every slot.
    Replicated,
    /// Elements in slots `0..len`; `clean` if all other slots are zero.
    Vector { len: usize, clean: bool },
}

impl Layout {
    fn padding_is_zero(self) -> bool {
        matches!(
            self,
            Layout::Replicated | Layout::Vector { clean: true, .. }
        )
    }
}

fn layout_of(shape: Shape) -> Layout {
    match shape {
        Shape::Vector(len) => Layout::Vector { len, clean: true },
        _ => Layout::Replicated,
    }
}

#[derive(Clone, Copy, Debug)]
enum Val {
    Secret(Reg, Layout),
    Public(ValueId),
}

fn secret(v: Val) -> (Reg, Layout) {
    match v {
        Val::Secret(r, l) => (r, l),
        Val::Public(id) => unreachable!("{id} is public; the builder rejects public-only ops"),
    }
}

struct Emitter<'a> {
    program: &'a Program,
    ranges: &'a RangeMap,
    slots: usize,
    inputs: Vec<PlanInput>,
    instrs: Vec<Instr>,
    levels: Vec<u32>,
    bounds: Vec<f64>,
    rotations: BTreeSet<u32>,
    approximations: Vec<Approximation>,
    /// Accumulated approximation error, added to IR bounds downstream.
    approx_error: f64,
}

impl<'a> Emitter<'a> {
    fn new(program: &'a Program, ranges: &'a RangeMap, slots: usize) -> Self {
        Self {
            program,
            ranges,
            slots,
            inputs: vec![],
            instrs: vec![],
            levels: vec![],
            bounds: vec![],
            rotations: BTreeSet::new(),
            approximations: vec![],
            approx_error: 0.0,
        }
    }

    fn push(&mut self, instr: Instr, bound: f64) -> Reg {
        let level = instr
            .operands()
            .iter()
            .map(|r| self.levels[r.index()])
            .max()
            .unwrap_or(0)
            + u32::from(instr.consumes_level());
        if let Instr::Rotate(_, k) = instr {
            self.rotations.insert(k);
        }
        self.instrs.push(instr);
        self.levels.push(level);
        self.bounds.push(bound);
        Reg(self.instrs.len() as u32 - 1)
    }

    fn bound(&self, r: Reg) -> f64 {
        self.bounds[r.index()]
    }

    fn tighten(&mut self, r: Reg, b: f64) {
        let cur = &mut self.bounds[r.index()];
        *cur = cur.min(b);
    }

    fn plain_max(&self, p: &Plain) -> f64 {
        p.materialize(self.program, self.slots)
            .iter()
            .fold(0.0, |m, x| m.max(x.abs()))
    }

    fn const_data(&self, id: ValueId) -> &'a [f64] {
        match &self.program.node(id).op {
            Op::Const { data } => data,
            _ => unreachable!("{id} is not a constant"),
        }
    }

    // --- primitive emitters -------------------------------------------------

    fn add_regs(&mut self, a: Reg, b: Reg, sub: bool) -> Reg {
        let bound = self.bound(a) + self.bound(b);
        let i = if sub {
            Instr::Sub(a, b)
        } else {
            Instr::Add(a, b)
        };
        self.push(i, bound)
    }

    fn neg(&mut self, a: Reg) -> Reg {
        self.push(Instr::Neg(a), self.bound(a))
    }

    fn mul_regs(&mut self, a: Reg, b: Reg) -> Reg {
        let bound = self.bound(a) * self.bound(b);
        self.push(Instr::Mul(a, b), bound)
    }

    fn add_plain(&mut self, a: Reg, p: Plain) -> Reg {
        let bound = self.bound(a) + self.plain_max(&p);
        self.push(Instr::AddPlain(a, p), bound)
    }

    fn mul_plain(&mut self, a: Reg, p: Plain) -> Reg {
        let bound = self.bound(a) * self.plain_max(&p);
        self.push(Instr::MulPlain(a, p), bound)
    }

    fn rotate(&mut self, a: Reg, k: usize) -> Reg {
        let k = k % self.slots;
        if k == 0 {
            return a;
        }
        self.push(Instr::Rotate(a, k as u32), self.bound(a))
    }

    /// `a · c`, without spending a level on ±1.
    fn scale(&mut self, a: Reg, c: f64) -> Reg {
        if c == 1.0 {
            a
        } else if c == -1.0 {
            self.neg(a)
        } else {
            let bound = self.bound(a) * c.abs();
            self.push(Instr::MulConst(a, c), bound)
        }
    }

    /// `a + c` on the value's elements, keeping vector padding untouched.
    fn add_scalar(&mut self, a: Reg, layout: Layout, c: f64) -> Reg {
        if c == 0.0 {
            return a;
        }
        match layout {
            Layout::Replicated => {
                let bound = self.bound(a) + c.abs();
                self.push(Instr::AddConst(a, c), bound)
            }
            Layout::Vector { len, .. } => self.add_plain(a, Plain::Fill { value: c, len }),
        }
    }

    /// Zero the padding of a dirty vector (one level).
    fn clean(&mut self, v: Val) -> (Reg, Layout) {
        let (r, l) = secret(v);
        match l {
            Layout::Vector { len, clean: false } => {
                let r = self.mul_plain(r, Plain::Fill { value: 1.0, len });
                (r, Layout::Vector { len, clean: true })
            }
            _ => (r, l),
        }
    }

    // --- IR ops ---------------------------------------------------------------

    fn add(&mut self, a: Val, b: Val, sub: bool) -> Result<Val> {
        Ok(match (a, b) {
            (Val::Secret(ra, la), Val::Secret(rb, lb)) => {
                let r = self.add_regs(ra, rb, sub);
                let l = match (la, lb) {
                    (Layout::Replicated, Layout::Replicated) => Layout::Replicated,
                    (Layout::Vector { len, clean: ca }, Layout::Vector { clean: cb, .. }) => {
                        Layout::Vector {
                            len,
                            clean: ca && cb,
                        }
                    }
                    // A replicated scalar lands in the padding too.
                    (Layout::Vector { len, .. }, _) | (_, Layout::Vector { len, .. }) => {
                        Layout::Vector { len, clean: false }
                    }
                };
                Val::Secret(r, l)
            }
            (Val::Secret(r, l), Val::Public(c)) => self.add_public(r, l, c, sub),
            (Val::Public(c), Val::Secret(r, l)) => {
                let r = if sub { self.neg(r) } else { r };
                self.add_public(r, l, c, false)
            }
            (Val::Public(_), Val::Public(_)) => unreachable!("rejected by the builder"),
        })
    }

    fn add_public(&mut self, r: Reg, l: Layout, c: ValueId, negate: bool) -> Val {
        let data = self.const_data(c);
        let sign = if negate { -1.0 } else { 1.0 };
        match self.program.node(c).ty.shape {
            Shape::Scalar => Val::Secret(self.add_scalar(r, l, sign * data[0]), l),
            Shape::Vector(len) => {
                let r = self.add_plain(r, Plain::Vector { value: c, negate });
                let clean = matches!(l, Layout::Vector { clean: true, .. });
                Val::Secret(r, Layout::Vector { len, clean })
            }
            Shape::Matrix(..) => unreachable!("rejected by the builder"),
        }
    }

    fn mul(&mut self, a: Val, b: Val) -> Result<Val> {
        Ok(match (a, b) {
            (Val::Secret(ra, la), Val::Secret(rb, lb)) => {
                let r = if ra == rb {
                    let bound = self.bound(ra).powi(2);
                    self.push(Instr::Mul(ra, ra), bound)
                } else {
                    self.mul_regs(ra, rb)
                };
                let l = match (la, lb) {
                    (Layout::Replicated, Layout::Replicated) => Layout::Replicated,
                    (Layout::Vector { len, clean: ca }, Layout::Vector { clean: cb, .. }) => {
                        Layout::Vector {
                            len,
                            clean: ca || cb,
                        }
                    }
                    (v @ Layout::Vector { .. }, _) | (_, v @ Layout::Vector { .. }) => v,
                };
                Val::Secret(r, l)
            }
            (Val::Secret(r, l), Val::Public(c)) | (Val::Public(c), Val::Secret(r, l)) => {
                let data = self.const_data(c);
                match self.program.node(c).ty.shape {
                    Shape::Scalar => Val::Secret(self.scale(r, data[0]), l),
                    Shape::Vector(len) => {
                        let r = self.mul_plain(
                            r,
                            Plain::Vector {
                                value: c,
                                negate: false,
                            },
                        );
                        Val::Secret(r, Layout::Vector { len, clean: true })
                    }
                    Shape::Matrix(..) => unreachable!("rejected by the builder"),
                }
            }
            (Val::Public(_), Val::Public(_)) => unreachable!("rejected by the builder"),
        })
    }

    /// Rotate-and-sum: the total lands replicated in every slot.
    fn sum(&mut self, v: Val) -> Val {
        let (mut r, l) = self.clean(v);
        let Layout::Vector { len, .. } = l else {
            unreachable!("sum takes a vector")
        };
        let elem = self.bound(r);
        let mut k = 1;
        while k < self.slots {
            let rot = self.rotate(r, k);
            let bound = (2.0 * self.bound(r)).min(elem * len as f64);
            r = self.push(Instr::Add(r, rot), bound);
            k *= 2;
        }
        Val::Secret(r, Layout::Replicated)
    }

    /// Public `rows × cols` matrix times a vector, by the hybrid diagonal
    /// method with baby-step/giant-step rotations: `period` = next power of
    /// two ≥ rows diagonals of length `slots`, then a fold over
    /// `slots / period` blocks.
    fn matvec(&mut self, m: ValueId, v: Val) -> Val {
        let (x, _) = self.clean(v);
        let Shape::Matrix(rows, cols) = self.program.node(m).ty.shape else {
            unreachable!("verified by the builder")
        };
        let data = self.const_data(m);
        let row_l1 = (0..rows)
            .map(|r| {
                data[r * cols..(r + 1) * cols]
                    .iter()
                    .map(|w| w.abs())
                    .sum::<f64>()
            })
            .fold(0.0, f64::max);
        let bound = row_l1 * self.bound(x);

        let period = rows.next_power_of_two();
        let baby = (period as f64).sqrt().ceil() as usize;
        let baby = baby.next_power_of_two().min(period);
        let giants = period / baby;

        let rotated: Vec<Reg> = (0..baby).map(|b| self.rotate(x, b)).collect();
        let mut acc: Option<Reg> = None;
        for g in 0..giants {
            let mut inner: Option<Reg> = None;
            for (b, &xr) in rotated.iter().enumerate() {
                let k = g * baby + b;
                let shift = (self.slots - g * baby) % self.slots;
                let plain = Plain::Diagonal {
                    matrix: m,
                    k,
                    shift,
                    period,
                };
                if self.plain_max(&plain) == 0.0 {
                    continue;
                }
                let t = self.mul_plain(xr, plain);
                self.tighten(t, bound);
                inner = Some(match inner {
                    None => t,
                    Some(s) => {
                        let s = self.add_regs(s, t, false);
                        self.tighten(s, bound);
                        s
                    }
                });
            }
            let Some(inner) = inner else { continue };
            let giant = self.rotate(inner, g * baby);
            acc = Some(match acc {
                None => giant,
                Some(a) => {
                    let s = self.add_regs(a, giant, false);
                    self.tighten(s, bound);
                    s
                }
            });
        }
        let mut y = match acc {
            Some(y) => y,
            // All-zero matrix: 0 · x keeps the value secret and zero.
            None => self.mul_plain(x, Plain::Fill { value: 0.0, len: 1 }),
        };
        let mut s = period;
        while s < self.slots {
            let rot = self.rotate(y, s);
            y = self.add_regs(y, rot, false);
            self.tighten(y, bound);
            s *= 2;
        }
        Val::Secret(
            y,
            Layout::Vector {
                len: rows,
                clean: period == self.slots,
            },
        )
    }

    /// Power-basis polynomial; powers by repeated squaring (depth ⌈log₂ d⌉ + 1).
    fn poly(&mut self, x: Val, coeffs: &[f64]) -> Val {
        let (r, l) = secret(x);
        let d = coeffs.len() - 1;
        let a = self.bound(r);
        let mut pow: Vec<Option<Reg>> = vec![None; d + 1];
        pow[1] = Some(r);
        for k in 2..=d {
            let hi = 1 << (usize::BITS - 1 - (k - 1).leading_zeros()); // largest 2^j < k
            let (p, q) = (pow[hi].unwrap(), pow[k - hi].unwrap());
            let reg = self.mul_regs(p, q);
            self.tighten(reg, a.powi(k as i32));
            pow[k] = Some(reg);
        }
        let mut acc: Option<Reg> = None;
        for (k, &c) in coeffs.iter().enumerate().skip(1) {
            if c == 0.0 {
                continue;
            }
            let t = self.scale(pow[k].unwrap(), c);
            acc = Some(match acc {
                None => t,
                Some(s) => self.add_regs(s, t, false),
            });
        }
        let acc = match acc {
            Some(a) => a,
            None => self.scale(r, 0.0),
        };
        Val::Secret(self.add_scalar(acc, l, coeffs[0]), l)
    }

    /// Chebyshev approximation of the sigmoid over the input's analyzed range.
    fn sigmoid(&mut self, id: ValueId, x_id: ValueId, x: Val) -> Result<Val> {
        let (r, l) = secret(x);
        let hull = self.ranges.hull(x_id);
        let (mut lo, mut hi) = (hull.lo - self.approx_error, hull.hi + self.approx_error);
        if hi - lo < 1e-9 {
            lo -= 1e-6;
            hi += 1e-6;
        }
        let tolerance = APPROX_SHARE * self.program.precision();
        let cheb =
            chebyshev_fit(sigmoid, lo, hi, tolerance, MAX_APPROX_DEGREE).ok_or_else(|| {
                Error::new(
                    Code::PrecisionUnreachable,
                    format!(
                        "sigmoid over [{lo:.3}, {hi:.3}] needs a polynomial above degree \
                     {MAX_APPROX_DEGREE} to reach error {tolerance:e}; narrow the input \
                     ranges or relax the precision"
                    ),
                )
            })?;

        // y = αx + β maps [lo, hi] onto [-1, 1].
        let alpha = 2.0 / (hi - lo);
        let beta = -(hi + lo) / (hi - lo);
        let y = self.scale(r, alpha);
        let y = self.add_scalar(y, l, beta);
        self.tighten(y, 1.0 + 1e-6);

        // T_k with depth ⌈log₂ k⌉ from T_{m+n} = 2·T_m·T_n − T_{m−n}; the
        // doubling is an addition so it costs no level.
        let d = cheb.degree();
        let mut t: Vec<Option<Reg>> = vec![None; d + 1];
        t[1] = Some(y);
        for k in 2..=d {
            let m = 1 << (usize::BITS - 1 - (k - 1).leading_zeros());
            let n = k - m;
            let tm = t[m].unwrap();
            let two_tm = self.add_regs(tm, tm, false);
            let prod = self.mul_regs(two_tm, t[n].unwrap());
            self.tighten(prod, 2.0 + 1e-5);
            let tk = if m == n {
                self.add_scalar(prod, l, -1.0)
            } else {
                self.add_regs(prod, t[m - n].unwrap(), true)
            };
            self.tighten(tk, 1.0 + 1e-5);
            t[k] = Some(tk);
        }

        let mut acc: Option<Reg> = None;
        for (k, &c) in cheb.coeffs.iter().enumerate().skip(1) {
            let term = self.scale(t[k].unwrap(), c);
            acc = Some(match acc {
                None => term,
                Some(s) => self.add_regs(s, term, false),
            });
        }
        let out = self.add_scalar(acc.expect("degree ≥ 1"), l, cheb.coeffs[0]);

        self.approx_error += cheb.max_error;
        self.approximations.push(Approximation {
            value: id,
            function: "sigmoid".into(),
            chebyshev: cheb,
        });
        Ok(Val::Secret(out, l))
    }
}
