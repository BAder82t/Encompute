//! The optimized execution of exact plans on bit-level backends.
//!
//! An [`ExactPlan`] is semantic: it never changes. For a bit-level backend
//! (OpenFHE exact), the plan is lowered once per program into a gate DAG,
//! the **execution plan**:
//!
//! 1. **Range-aware widths.** Interval analysis over the plan, starting from
//!    the declared input ranges, proves bits constant: the high bits of a
//!    `u16` in `[0, 100]` are zero, those of a negative value are one, and a
//!    mixed-sign value's high bits copy its sign. They become constants (or
//!    copies), so the gates that depended on them fold away. External types
//!    are unchanged; inputs outside their declared ranges are refused by
//!    the client before encryption, as for every exact program.
//! 2. **Constant folding and Boolean simplification** (`x & x = x`,
//!    `x ^ x = 0`, `!!x = x`, ...), and **common subexpressions**: gates
//!    are hash-consed, so an identical gate on identical operands is
//!    evaluated once and its ciphertext reused.
//! 3. **Circuit strategy**: ripple or logarithmic-depth adders and
//!    comparators, whichever the cost model estimates faster for the
//!    available workers.
//! 4. **Dead gate elimination**: only gates the outputs depend on remain.
//!
//! [`execute`] runs the DAG level by level; the gates of a level are
//! independent and run on a bounded pool of workers. Every gate is a pure
//! function of its operands, so the result does not depend on scheduling.
//!
//! The reference lowering ([`crate::bits::BitEvaluator`] with
//! [`Strategy::REFERENCE`], instruction by instruction) stays available as
//! the correctness oracle: every optimized circuit is differential-tested
//! against it.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use encompute_backend::ExactEvaluator;
use encompute_ir::{Code, Elem, Error, LogicOp, Result};

use crate::bits::{BitEvaluator, Gates, Sig, Strategy, Word};
use crate::plan::{ExactInstr, ExactPlan};

/// Changes whenever the optimizer's output for some plan could change.
/// Recorded in execution provenance, never in semantic identities.
pub const OPTIMIZER_VERSION: u32 = 1;

pub type NodeId = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateOp {
    And,
    Or,
    Xor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum Node {
    Input { input: u32, bit: u32 },
    Const { v: bool },
    Not { a: NodeId },
    Gate { op: GateOp, a: NodeId, b: NodeId },
}

/// An output bit: a constant, or a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum OutBit {
    Const { v: bool },
    Node { id: NodeId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutWord {
    pub elem: Elem,
    pub bits: Vec<OutBit>,
}

/// What the optimizer did, for `explain` and the benchmarks.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitStats {
    /// Bootstrapped gates (AND, OR, XOR).
    pub gates: u64,
    /// NOTs (free on BinFHE: no bootstrapping).
    pub nots: u64,
    /// Critical path, in bootstrapped gates.
    pub depth: u32,
    /// The largest number of gates in one level (independent gates).
    pub width: u32,
    /// Input bits the circuit reads (the others are proven constant).
    pub input_bits_used: u32,
    pub input_bits_total: u32,
    /// Bits proven constant (or a copy of another bit) by range analysis.
    pub range_bits_folded: u64,
    /// Gates found already computed (common subexpressions).
    pub cse_hits: u64,
    /// Gates removed by Boolean simplification.
    pub simplifications: u64,
    /// Gates removed because no output depends on them.
    pub dead_gates: u64,
}

/// A lowered, optimized program for a bit-level backend.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Circuit {
    pub optimizer_version: u32,
    pub strategy: Strategy,
    pub input_elems: Vec<Elem>,
    /// Topologically ordered: operands precede their users.
    pub nodes: Vec<Node>,
    pub outputs: Vec<OutWord>,
    pub stats: CircuitStats,
    /// Level (critical-path position) of each node.
    #[serde(skip)]
    levels: Vec<u32>,
}

// --- interval analysis -----------------------------------------------------------

/// A closed interval of integers.
pub type Interval = (i128, i128);

fn clamp_to(e: Elem, iv: Option<Interval>) -> Interval {
    let (lo, hi) = e.bounds();
    match iv {
        Some((a, b)) if a >= lo && b <= hi && a <= b => (a, b),
        _ => (lo, hi),
    }
}

fn span(xs: &[Option<i128>]) -> Option<Interval> {
    let mut lo = i128::MAX;
    let mut hi = i128::MIN;
    for x in xs {
        let x = (*x)?;
        lo = lo.min(x);
        hi = hi.max(x);
    }
    Some((lo, hi))
}

fn bitlen(v: i128) -> u32 {
    if v <= 0 {
        0
    } else {
        128 - v.leading_zeros()
    }
}

/// Sound intervals for every register, from the inputs' declared ranges
/// (`None`: the type's full range). Exceeding a type's range (which the
/// compiler's overflow analysis rules out) falls back to the full range.
pub fn ranges(plan: &ExactPlan, inputs: &[Option<Interval>]) -> Vec<Interval> {
    let mut r: Vec<Interval> = Vec::with_capacity(plan.instrs.len());
    for (i, instr) in plan.instrs.iter().enumerate() {
        let e = plan.elems[i];
        let g = |x: u32| r[x as usize];
        use ExactInstr::*;
        let iv: Option<Interval> = match instr {
            Input { index } => inputs.get(*index).copied().flatten(),
            Trivial { value } => Some((*value, *value)),
            Add(a, b) => {
                let (a, b) = (g(*a), g(*b));
                span(&[a.0.checked_add(b.0), a.1.checked_add(b.1)])
            }
            Sub(a, b) => {
                let (a, b) = (g(*a), g(*b));
                span(&[a.0.checked_sub(b.1), a.1.checked_sub(b.0)])
            }
            Mul(a, b) => {
                let (a, b) = (g(*a), g(*b));
                span(&[
                    a.0.checked_mul(b.0),
                    a.0.checked_mul(b.1),
                    a.1.checked_mul(b.0),
                    a.1.checked_mul(b.1),
                ])
            }
            Neg(a) => {
                let a = g(*a);
                span(&[a.1.checked_neg(), a.0.checked_neg()])
            }
            AddScalar(a, c) => {
                let a = g(*a);
                span(&[a.0.checked_add(*c), a.1.checked_add(*c)])
            }
            SubScalar(a, c) => {
                let a = g(*a);
                span(&[a.0.checked_sub(*c), a.1.checked_sub(*c)])
            }
            MulScalar(a, c) => {
                let a = g(*a);
                span(&[a.0.checked_mul(*c), a.1.checked_mul(*c)])
            }
            ScalarSub(c, a) => {
                let a = g(*a);
                span(&[c.checked_sub(a.1), c.checked_sub(a.0)])
            }
            // Truncating division is monotonic in the dividend.
            DivScalar(a, c) => {
                let a = g(*a);
                span(&[a.0.checked_div(*c), a.1.checked_div(*c)])
            }
            RemScalar(a, c) => {
                let a = g(*a);
                let m = c.checked_abs().map(|m| m - 1);
                match m {
                    None => None,
                    Some(m) if a.0 >= 0 => Some((0, a.1.min(m))),
                    Some(m) if a.1 <= 0 => Some((a.0.max(-m), 0)),
                    Some(m) => Some((-m, m)),
                }
            }
            Cmp(..) | CmpScalar(..) => Some((0, 1)),
            Logic(op, a, b) => {
                if e == Elem::Bool {
                    Some((0, 1))
                } else {
                    let (a, b) = (g(*a), g(*b));
                    if a.0 >= 0 && b.0 >= 0 {
                        match op {
                            LogicOp::And => Some((0, a.1.min(b.1))),
                            _ => {
                                let k = bitlen(a.1.max(b.1));
                                Some((0, (1i128 << k) - 1))
                            }
                        }
                    } else {
                        None
                    }
                }
            }
            Not(a) => {
                if e == Elem::Bool {
                    Some((0, 1))
                } else {
                    let a = g(*a);
                    if e.is_signed() {
                        // ~x = -x - 1
                        span(&[
                            a.1.checked_neg().map(|v| v - 1),
                            a.0.checked_neg().map(|v| v - 1),
                        ])
                    } else {
                        let max = e.bounds().1;
                        Some((max - a.1, max - a.0))
                    }
                }
            }
            Shift { x, left, by } => {
                let a = g(*x);
                if *left {
                    let f = |v: i128| {
                        if *by >= 127 {
                            None
                        } else {
                            v.checked_mul(1i128 << by)
                        }
                    };
                    span(&[f(a.0), f(a.1)])
                } else if a.0 >= 0 || e.is_signed() {
                    // Arithmetic (signed) or logical (non-negative) right shift.
                    Some((a.0 >> by.min(&127), a.1 >> by.min(&127)))
                } else {
                    None
                }
            }
            Min(a, b) => {
                let (a, b) = (g(*a), g(*b));
                Some((a.0.min(b.0), a.1.min(b.1)))
            }
            Max(a, b) => {
                let (a, b) = (g(*a), g(*b));
                Some((a.0.max(b.0), a.1.max(b.1)))
            }
            Select(_, a, b) => {
                let (a, b) = (g(*a), g(*b));
                Some((a.0.min(b.0), a.1.max(b.1)))
            }
            Lookup { table, .. } => span(&table.iter().map(|v| Some(*v)).collect::<Vec<_>>()),
            // Value-preserving when the source range fits the target.
            Cast(a) => Some(g(*a)),
        };
        r.push(clamp_to(e, iv));
    }
    r
}

/// The bits of a `width`-bit word whose value lies in `iv`: `Some(Some(b))`
/// a known constant, `Some(None)` a copy of the bit below (sign
/// extension), `None` unknown.
fn known_bits(width: u32, iv: Interval) -> Vec<Option<Option<bool>>> {
    let (lo, hi) = iv;
    let w = width as usize;
    let mut out = vec![None; w];
    if lo == hi {
        for (i, o) in out.iter_mut().enumerate() {
            *o = Some(Some((lo >> i) & 1 == 1));
        }
        return out;
    }
    if lo >= 0 {
        for o in out.iter_mut().skip(bitlen(hi) as usize) {
            *o = Some(Some(false));
        }
    } else if hi < 0 {
        for o in out.iter_mut().skip(bitlen(-lo - 1) as usize) {
            *o = Some(Some(true));
        }
    } else {
        // The sign bit is at position k - 1; above it, copies of it.
        let k = bitlen(hi).max(bitlen(-lo - 1)) as usize + 1;
        for o in out.iter_mut().skip(k) {
            *o = Some(None);
        }
    }
    out
}

// --- recording the DAG ----------------------------------------------------------

#[derive(Default)]
struct Recorder {
    nodes: std::cell::RefCell<Vec<Node>>,
    index: std::cell::RefCell<HashMap<Node, NodeId>>,
    cse_hits: std::cell::Cell<u64>,
    simplified: std::cell::Cell<u64>,
}

impl Recorder {
    fn node(&self, n: Node) -> NodeId {
        if let Some(id) = self.index.borrow().get(&n) {
            if matches!(n, Node::Gate { .. }) {
                self.cse_hits.set(self.cse_hits.get() + 1);
            }
            return *id;
        }
        let mut nodes = self.nodes.borrow_mut();
        let id = nodes.len() as NodeId;
        nodes.push(n);
        self.index.borrow_mut().insert(n, id);
        id
    }

    fn get(&self, id: NodeId) -> Node {
        self.nodes.borrow()[id as usize]
    }

    fn is_not_of(&self, a: NodeId, b: NodeId) -> bool {
        self.get(a) == (Node::Not { a: b }) || self.get(b) == (Node::Not { a })
    }

    fn konst(&self, v: bool) -> NodeId {
        self.node(Node::Const { v })
    }

    fn simplified(&self, id: NodeId) -> Result<NodeId> {
        self.simplified.set(self.simplified.get() + 1);
        Ok(id)
    }

    fn gate(&self, op: GateOp, a: NodeId, b: NodeId) -> Result<NodeId> {
        let (na, nb) = (self.get(a), self.get(b));
        match (op, na, nb) {
            (GateOp::And, Node::Const { v: false }, _)
            | (GateOp::And, _, Node::Const { v: false }) => {
                return self.simplified(self.konst(false))
            }
            (GateOp::And, Node::Const { v: true }, _) => return self.simplified(b),
            (GateOp::And, _, Node::Const { v: true }) => return self.simplified(a),
            (GateOp::Or, Node::Const { v: true }, _) | (GateOp::Or, _, Node::Const { v: true }) => {
                return self.simplified(self.konst(true))
            }
            (GateOp::Or, Node::Const { v: false }, _) => return self.simplified(b),
            (GateOp::Or, _, Node::Const { v: false }) => return self.simplified(a),
            (GateOp::Xor, Node::Const { v }, _) => {
                return self.simplified(if v { self.not(&b)? } else { b })
            }
            (GateOp::Xor, _, Node::Const { v }) => {
                return self.simplified(if v { self.not(&a)? } else { a })
            }
            _ => {}
        }
        if a == b {
            return self.simplified(match op {
                GateOp::And | GateOp::Or => a,
                GateOp::Xor => self.konst(false),
            });
        }
        if self.is_not_of(a, b) {
            return self.simplified(match op {
                GateOp::And => self.konst(false),
                GateOp::Or | GateOp::Xor => self.konst(true),
            });
        }
        if op == GateOp::Xor {
            // NOTs move out of XORs, so equal gates meet in the table.
            if let Node::Not { a: x } = na {
                let inner = self.gate(GateOp::Xor, x, b)?;
                return self.not(&inner);
            }
            if let Node::Not { a: y } = nb {
                let inner = self.gate(GateOp::Xor, a, y)?;
                return self.not(&inner);
            }
        }
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        Ok(self.node(Node::Gate { op, a, b }))
    }
}

impl Gates for Recorder {
    type Bit = NodeId;

    fn name(&self) -> &'static str {
        "circuit-recorder"
    }
    fn and(&self, a: &NodeId, b: &NodeId) -> Result<NodeId> {
        self.gate(GateOp::And, *a, *b)
    }
    fn or(&self, a: &NodeId, b: &NodeId) -> Result<NodeId> {
        self.gate(GateOp::Or, *a, *b)
    }
    fn xor(&self, a: &NodeId, b: &NodeId) -> Result<NodeId> {
        self.gate(GateOp::Xor, *a, *b)
    }
    fn not(&self, a: &NodeId) -> Result<NodeId> {
        Ok(match self.get(*a) {
            Node::Const { v } => self.konst(!v),
            Node::Not { a } => a,
            _ => self.node(Node::Not { a: *a }),
        })
    }
    fn constant(&self, v: bool) -> Result<NodeId> {
        Ok(self.konst(v))
    }
    fn load(&self, _: Elem, _: &[u8]) -> Result<Vec<NodeId>> {
        Err(Error::new(
            Code::Backend,
            "the circuit recorder loads no ciphertexts",
        ))
    }
    fn store(&self, _: Elem, _: &[NodeId]) -> Result<Vec<u8>> {
        Err(Error::new(
            Code::Backend,
            "the circuit recorder stores no ciphertexts",
        ))
    }
}

/// Lowers `plan` to a circuit with `strategy`, using the inputs' declared
/// ranges (`None`: the type's range).
pub fn build(
    plan: &ExactPlan,
    input_ranges: &[Option<Interval>],
    strategy: Strategy,
) -> Result<Circuit> {
    plan.validate()?;
    let ev = BitEvaluator::with_strategy(Recorder::default(), strategy);
    let ivs = ranges(plan, input_ranges);
    let mut folded = 0u64;
    let mut regs: Vec<Word<NodeId>> = Vec::with_capacity(plan.instrs.len());
    let mut input_bits_total = 0u32;
    for (i, instr) in plan.instrs.iter().enumerate() {
        let elem = plan.elems[i];
        let r = |x: u32| &regs[x as usize];
        use ExactInstr::*;
        let mut w: Word<NodeId> = match instr {
            Input { index } => {
                input_bits_total += elem.bits();
                Word {
                    elem,
                    bits: (0..elem.bits())
                        .map(|b| {
                            Sig::Enc(ev.gates.node(Node::Input {
                                input: *index as u32,
                                bit: b,
                            }))
                        })
                        .collect(),
                }
            }
            Trivial { value } => ev.trivial(elem, *value)?,
            Add(a, b) => ev.add(r(*a), r(*b))?,
            Sub(a, b) => ev.sub(r(*a), r(*b))?,
            Mul(a, b) => ev.mul(r(*a), r(*b))?,
            Neg(a) => ev.neg(r(*a))?,
            AddScalar(a, c) => ev.add_scalar(r(*a), *c)?,
            SubScalar(a, c) => ev.sub_scalar(r(*a), *c)?,
            MulScalar(a, c) => ev.mul_scalar(r(*a), *c)?,
            ScalarSub(c, a) => ev.scalar_sub(*c, r(*a))?,
            DivScalar(a, c) => ev.div_scalar(r(*a), *c)?,
            RemScalar(a, c) => ev.rem_scalar(r(*a), *c)?,
            Cmp(op, a, b) => ev.cmp(*op, r(*a), r(*b))?,
            CmpScalar(op, a, c) => ev.cmp_scalar(*op, r(*a), *c)?,
            Logic(op, a, b) => ev.logic(*op, r(*a), r(*b))?,
            Not(a) => ev.not(r(*a))?,
            Shift { x, left, by } => ev.shift(r(*x), *left, *by)?,
            Min(a, b) => ev.min(r(*a), r(*b))?,
            Max(a, b) => ev.max(r(*a), r(*b))?,
            Select(c, a, b) => ev.select(r(*c), r(*a), r(*b))?,
            Lookup { x, table } => ev.lookup(r(*x), table, elem)?,
            Cast(a) => ev.cast(r(*a), elem)?,
        };
        // Bits the range proves constant, or copies of the sign bit.
        for (b, k) in known_bits(elem.bits(), ivs[i]).into_iter().enumerate() {
            match k {
                Some(Some(v)) => {
                    if w.bits[b] != Sig::Const(v) {
                        folded += 1;
                        w.bits[b] = Sig::Const(v);
                    }
                }
                Some(None) => {
                    let below = w.bits[b - 1].clone();
                    if w.bits[b] != below {
                        folded += 1;
                        w.bits[b] = below;
                    }
                }
                None => {}
            }
        }
        regs.push(w);
    }
    let rec = ev.gates;
    let nodes = rec.nodes.into_inner();
    let outputs_sig: Vec<(Elem, Vec<Sig<NodeId>>)> = plan
        .outputs
        .iter()
        .map(|o| (o.elem, regs[o.reg as usize].bits.clone()))
        .collect();
    // Reachable nodes, renumbered in order (operands precede users).
    let mut live = vec![false; nodes.len()];
    let mut stack: Vec<NodeId> = outputs_sig
        .iter()
        .flat_map(|(_, bs)| bs.iter())
        .filter_map(|b| match b {
            Sig::Enc(id) => Some(*id),
            Sig::Const(_) => None,
        })
        .collect();
    while let Some(id) = stack.pop() {
        if std::mem::replace(&mut live[id as usize], true) {
            continue;
        }
        match nodes[id as usize] {
            Node::Not { a } => stack.push(a),
            Node::Gate { a, b, .. } => {
                stack.push(a);
                stack.push(b);
            }
            _ => {}
        }
    }
    let total_gates = nodes
        .iter()
        .filter(|n| matches!(n, Node::Gate { .. }))
        .count() as u64;
    let mut remap = vec![u32::MAX; nodes.len()];
    let mut out_nodes = Vec::new();
    for (i, n) in nodes.iter().enumerate() {
        if !live[i] {
            continue;
        }
        let m = |x: NodeId| remap[x as usize];
        let n2 = match *n {
            Node::Not { a } => Node::Not { a: m(a) },
            Node::Gate { op, a, b } => Node::Gate {
                op,
                a: m(a),
                b: m(b),
            },
            other => other,
        };
        remap[i] = out_nodes.len() as NodeId;
        out_nodes.push(n2);
    }
    let outputs = outputs_sig
        .into_iter()
        .map(|(elem, bs)| OutWord {
            elem,
            bits: bs
                .into_iter()
                .map(|b| match b {
                    Sig::Const(v) => OutBit::Const { v },
                    Sig::Enc(id) => OutBit::Node {
                        id: remap[id as usize],
                    },
                })
                .collect(),
        })
        .collect();
    let mut c = Circuit {
        optimizer_version: OPTIMIZER_VERSION,
        strategy,
        input_elems: plan.inputs.iter().map(|i| i.elem).collect(),
        nodes: out_nodes,
        outputs,
        stats: CircuitStats {
            input_bits_total,
            range_bits_folded: folded,
            cse_hits: rec.cse_hits.get(),
            simplifications: rec.simplified.get(),
            ..CircuitStats::default()
        },
        levels: vec![],
    };
    c.analyze();
    c.stats.dead_gates = total_gates - c.stats.gates;
    Ok(c)
}

impl Circuit {
    fn analyze(&mut self) {
        let mut levels = vec![0u32; self.nodes.len()];
        let mut per_level: HashMap<u32, u32> = HashMap::new();
        let (mut gates, mut nots, mut inputs) = (0u64, 0u64, 0u32);
        for (i, n) in self.nodes.iter().enumerate() {
            levels[i] = match *n {
                Node::Input { .. } => {
                    inputs += 1;
                    0
                }
                Node::Const { .. } => 0,
                Node::Not { a } => {
                    nots += 1;
                    levels[a as usize]
                }
                Node::Gate { a, b, .. } => {
                    gates += 1;
                    let l = 1 + levels[a as usize].max(levels[b as usize]);
                    *per_level.entry(l).or_default() += 1;
                    l
                }
            };
        }
        self.stats.gates = gates;
        self.stats.nots = nots;
        self.stats.input_bits_used = inputs;
        self.stats.depth = levels.iter().copied().max().unwrap_or(0);
        self.stats.width = per_level.values().copied().max().unwrap_or(0);
        self.levels = levels;
    }

    /// Gates per level, in level order.
    pub fn level_sizes(&self) -> Vec<u32> {
        let mut sizes = vec![0u32; self.stats.depth as usize + 1];
        for (i, n) in self.nodes.iter().enumerate() {
            if matches!(n, Node::Gate { .. }) {
                sizes[self.levels[i] as usize] += 1;
            }
        }
        sizes.into_iter().skip(1).collect()
    }

    /// Estimated rounds of gate evaluation with `workers` in parallel:
    /// each level takes ⌈gates / workers⌉ rounds.
    pub fn rounds(&self, workers: u32) -> u64 {
        let w = workers.max(1) as u64;
        self.level_sizes()
            .iter()
            .map(|g| (*g as u64).div_ceil(w))
            .sum()
    }
}

/// The cheapest circuit for `workers` among the strategies: fewest rounds,
/// then fewest gates (the reference on ties).
pub fn optimize(
    plan: &ExactPlan,
    input_ranges: &[Option<Interval>],
    workers: u32,
) -> Result<Circuit> {
    let mut best: Option<Circuit> = None;
    for s in [Strategy::REFERENCE, Strategy::PARALLEL] {
        let c = build(plan, input_ranges, s)?;
        let better = match &best {
            None => true,
            Some(b) => (c.rounds(workers), c.stats.gates) < (b.rounds(workers), b.stats.gates),
        };
        if better {
            best = Some(c);
        }
    }
    Ok(best.expect("a strategy"))
}

// --- execution ----------------------------------------------------------------

/// A gate library the parallel executor can drive from several threads.
pub trait CircuitGates: Sync {
    type Bit: Clone + Send + Sync;
    fn gate(&self, op: GateOp, a: &Self::Bit, b: &Self::Bit) -> Result<Self::Bit>;
    fn not(&self, a: &Self::Bit) -> Result<Self::Bit>;
    fn constant(&self, v: bool) -> Result<Self::Bit>;
    /// Called once on each worker thread before it evaluates gates.
    fn init_worker(&self) {}
}

/// Runs `c` on encrypted input bits (one vector per plan input, all of the
/// input's bits) with at most `workers` threads; returns the output words'
/// bits. Constant output bits are trivial encryptions.
pub fn execute<G: CircuitGates>(
    c: &Circuit,
    g: &G,
    inputs: &[Vec<G::Bit>],
    workers: usize,
) -> Result<Vec<Vec<G::Bit>>> {
    if inputs.len() != c.input_elems.len() {
        return Err(Error::new(Code::BadInput, "wrong number of circuit inputs"));
    }
    for (bits, e) in inputs.iter().zip(&c.input_elems) {
        if bits.len() != e.bits() as usize {
            return Err(Error::new(
                Code::BadInput,
                format!("a {e} input has {} bits", e.bits()),
            ));
        }
    }
    let n = c.nodes.len();
    let mut values: Vec<Option<G::Bit>> = vec![None; n];
    // Group node indices by level.
    let depth = c.stats.depth as usize;
    let mut by_level: Vec<(Vec<usize>, Vec<usize>)> = vec![(vec![], vec![]); depth + 1];
    for (i, node) in c.nodes.iter().enumerate() {
        let l = c.levels[i] as usize;
        match node {
            Node::Gate { .. } => by_level[l].0.push(i),
            _ => by_level[l].1.push(i),
        }
    }
    let workers = workers.max(1);
    for (gates, others) in by_level {
        if !gates.is_empty() {
            let computed: Vec<(usize, G::Bit)> =
                if workers == 1 || gates.len() == 1 {
                    gates
                        .iter()
                        .map(|&i| eval_gate(c, g, &values, i).map(|v| (i, v)))
                        .collect::<Result<_>>()?
                } else {
                    let chunk = gates.len().div_ceil(workers);
                    let vals = &values;
                    std::thread::scope(|s| {
                        let handles: Vec<_> = gates
                            .chunks(chunk)
                            .map(|part| {
                                s.spawn(move || {
                                    g.init_worker();
                                    part.iter()
                                        .map(|&i| eval_gate(c, g, vals, i).map(|v| (i, v)))
                                        .collect::<Result<Vec<_>>>()
                                })
                            })
                            .collect();
                        let mut all = Vec::with_capacity(gates.len());
                        for h in handles {
                            all.extend(h.join().map_err(|_| {
                                Error::new(Code::Backend, "a gate worker panicked")
                            })??);
                        }
                        Ok::<_, Error>(all)
                    })?
                };
            for (i, v) in computed {
                values[i] = Some(v);
            }
        }
        // Inputs, constants and NOTs (cheap) of this level, in order.
        for i in others {
            let v = match c.nodes[i] {
                Node::Input { input, bit } => inputs[input as usize][bit as usize].clone(),
                Node::Const { v } => g.constant(v)?,
                Node::Not { a } => g.not(values[a as usize].as_ref().expect("operand computed"))?,
                Node::Gate { .. } => unreachable!("gates are evaluated above"),
            };
            values[i] = Some(v);
        }
    }
    c.outputs
        .iter()
        .map(|w| {
            w.bits
                .iter()
                .map(|b| match b {
                    OutBit::Const { v } => g.constant(*v),
                    OutBit::Node { id } => {
                        Ok(values[*id as usize].clone().expect("output computed"))
                    }
                })
                .collect()
        })
        .collect()
}

fn eval_gate<G: CircuitGates>(
    c: &Circuit,
    g: &G,
    values: &[Option<G::Bit>],
    i: usize,
) -> Result<G::Bit> {
    let Node::Gate { op, a, b } = c.nodes[i] else {
        unreachable!("a gate")
    };
    let get = |x: NodeId| {
        values[x as usize]
            .as_ref()
            .expect("operand of an earlier level")
    };
    g.gate(op, get(a), get(b))
}

/// Plaintext bits, for differential tests of the optimizer.
pub struct PlainCircuitGates;

impl CircuitGates for PlainCircuitGates {
    type Bit = bool;
    fn gate(&self, op: GateOp, a: &bool, b: &bool) -> Result<bool> {
        Ok(match op {
            GateOp::And => *a && *b,
            GateOp::Or => *a || *b,
            GateOp::Xor => a ^ b,
        })
    }
    fn not(&self, a: &bool) -> Result<bool> {
        Ok(!a)
    }
    fn constant(&self, v: bool) -> Result<bool> {
        Ok(v)
    }
}

/// Plaintext inputs as bits (two's complement, least significant first).
pub fn plain_bits(e: Elem, v: i128) -> Vec<bool> {
    (0..e.bits()).map(|i| (v >> i) & 1 == 1).collect()
}

/// The value of plaintext output bits.
pub fn plain_value(e: Elem, bits: &[bool]) -> i128 {
    let mut v: i128 = 0;
    for (i, b) in bits.iter().enumerate() {
        if *b {
            v |= 1 << i;
        }
    }
    if e.is_signed() && v >> (e.bits() - 1) & 1 == 1 {
        v -= 1 << e.bits();
    }
    v
}
