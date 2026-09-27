//! Optimizer verification: every transformation of the execution plan
//! (`circuit.rs`, `bits.rs`) against the reference lowering
//! ([`BitEvaluator`] with [`Lowering::REFERENCE`], run instruction by
//! instruction by [`evaluate_exact`]) and the clear interpreter
//! ([`encompute_ir::evaluate`]), with unit, property and differential tests.
//! `tests/OPTIMIZER_TESTS.md` maps each transformation to its tests; the
//! last test here checks that every test the table names exists.
//!
//! Rule-level tests of the (private) recorder and of the private adder and
//! comparator circuits are in `src/circuit.rs` and `src/bits.rs`.

mod gen;

use std::cell::Cell;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

use encompute_backend::ExactEvaluator;
use encompute_exact::bits::{self, gate_count, BitEvaluator, PlainGates, Strategy as Lowering};
use encompute_exact::circuit::{
    self, build, execute, optimize, plain_bits, ranges, Circuit, CircuitGates, GateOp, Interval,
    Node, OutBit, PlainCircuitGates, OPTIMIZER_VERSION,
};
use encompute_exact::{compile, evaluate_exact, ExactInput, ExactInstr, ExactOutput, ExactPlan};
use encompute_ir::{
    evaluate, Builder, CmpOp, Code, Elem, Inputs, LogicOp, Program, Range, ValueId,
};

// --- harness -------------------------------------------------------------------

fn runner(cases: u32) -> TestRunner {
    TestRunner::new_with_rng(
        Config {
            cases,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    )
}

/// The inputs' declared ranges, as the evaluator session reads them.
fn input_ranges(p: &Program, plan: &ExactPlan) -> Vec<Option<Interval>> {
    plan.inputs
        .iter()
        .map(|i| {
            p.inputs()
                .find(|(_, n, _, _)| *n == i.name)
                .map(|(_, _, _, r)| (r.lo.ceil() as i128, r.hi.floor() as i128))
        })
        .collect()
}

/// The reference lowering: the original circuits (ripple adders and
/// comparators, constant folding only), instruction by instruction, on
/// plaintext bits.
fn reference(plan: &ExactPlan, vals: &[i128]) -> Vec<i128> {
    let ev = BitEvaluator::new(PlainGates);
    let words = plan
        .inputs
        .iter()
        .zip(vals)
        .map(|(i, v)| bits::plain_word(i.elem, *v))
        .collect();
    evaluate_exact(&ev, plan, words)
        .unwrap()
        .iter()
        .map(bits::plain_value)
        .collect()
}

/// Runs an optimized circuit on plaintext bits with `workers` threads.
fn run(c: &Circuit, plan: &ExactPlan, vals: &[i128], workers: usize) -> Vec<i128> {
    let bits: Vec<Vec<bool>> = plan
        .inputs
        .iter()
        .zip(vals)
        .map(|(i, v)| plain_bits(i.elem, *v))
        .collect();
    execute(c, &PlainCircuitGates, &bits, workers)
        .unwrap()
        .iter()
        .zip(&plan.outputs)
        .map(|(b, o)| circuit::plain_value(o.elem, b))
        .collect()
}

/// The clear interpreter's outputs, in plan order.
fn clear(p: &Program, plan: &ExactPlan, vals: &[i128]) -> Vec<f64> {
    let inputs: Inputs = plan
        .inputs
        .iter()
        .zip(vals)
        .map(|(i, v)| (i.name.clone(), vec![*v as f64]))
        .collect();
    let out = evaluate(p, &inputs).unwrap();
    plan.outputs.iter().map(|o| out[&o.name][0]).collect()
}

/// Every circuit the optimizer produces for `plan`: both strategies, and
/// the choices for one and for eight workers.
fn circuits(plan: &ExactPlan, ranges: &[Option<Interval>]) -> Vec<Circuit> {
    vec![
        build(plan, ranges, Lowering::REFERENCE).unwrap(),
        build(plan, ranges, Lowering::PARALLEL).unwrap(),
        optimize(plan, ranges, 1).unwrap(),
        optimize(plan, ranges, 8).unwrap(),
    ]
}

/// The differential check: each circuit (one worker; the last also three)
/// is bit-exact with the reference lowering, which matches the clear
/// interpreter (when there is a program).
fn differential(
    p: Option<&Program>,
    plan: &ExactPlan,
    cs: &[Circuit],
    vals: &[i128],
) -> Result<(), String> {
    let want = reference(plan, vals);
    if let Some(p) = p {
        let got: Vec<f64> = want.iter().map(|v| *v as f64).collect();
        let clear = clear(p, plan, vals);
        if got != clear {
            return Err(format!(
                "reference lowering {want:?} vs clear interpreter {clear:?} on {vals:?}"
            ));
        }
    }
    for (k, c) in cs.iter().enumerate() {
        let workers: &[usize] = if k + 1 == cs.len() { &[1, 3] } else { &[1] };
        for &w in workers {
            let got = run(c, plan, vals, w);
            if got != want {
                return Err(format!(
                    "circuit {k} ({:?}, {w} workers): {got:?}, reference lowering {want:?}, \
                     inputs {vals:?}",
                    c.strategy
                ));
            }
        }
    }
    Ok(())
}

/// Every combination of `values` (one list per plan input).
fn combinations(values: &[Vec<i128>]) -> Vec<Vec<i128>> {
    values.iter().fold(vec![vec![]], |acc, vs| {
        acc.iter()
            .flat_map(|prefix| {
                vs.iter().map(move |v| {
                    let mut p = prefix.clone();
                    p.push(*v);
                    p
                })
            })
            .collect()
    })
}

/// Compiles `p`, builds every circuit and checks them on every combination
/// of `values`; returns the plan and the circuits.
fn check_program(p: &Program, values: &[Vec<i128>]) -> (ExactPlan, Vec<Circuit>) {
    let plan = compile(p).unwrap().plan;
    let ranges = input_ranges(p, &plan);
    let cs = circuits(&plan, &ranges);
    for c in &cs {
        check_circuit(c).unwrap();
    }
    for vals in combinations(values) {
        differential(Some(p), &plan, &cs, &vals).unwrap();
    }
    (plan, cs)
}

/// A program over two full-range `u8` inputs `x` and `y`, with the
/// outputs `f` builds.
fn program(f: impl FnOnce(&mut Builder, ValueId, ValueId) -> Vec<ValueId>) -> Program {
    let mut b = Builder::new("p", 1e-3).unwrap();
    let x = b.input_exact("x", Elem::U8, None).unwrap();
    let y = b.input_exact("y", Elem::U8, None).unwrap();
    for (i, o) in f(&mut b, x, y).into_iter().enumerate() {
        b.output(&format!("o{i}"), o).unwrap();
    }
    b.finish().unwrap()
}

/// A program over two inputs of `e` in `[lo, hi]`.
fn program_in(
    e: Elem,
    (lo, hi): (f64, f64),
    f: impl FnOnce(&mut Builder, ValueId, ValueId) -> Vec<ValueId>,
) -> Program {
    let mut b = Builder::new("p", 1e-3).unwrap();
    let x = b.input_exact("x", e, Some(Range::new(lo, hi))).unwrap();
    let y = b.input_exact("y", e, Some(Range::new(lo, hi))).unwrap();
    for (i, o) in f(&mut b, x, y).into_iter().enumerate() {
        b.output(&format!("o{i}"), o).unwrap();
    }
    b.finish().unwrap()
}

fn all_u8() -> Vec<i128> {
    (0..=255).collect()
}

fn some_u8() -> Vec<i128> {
    vec![0, 1, 2, 85, 127, 128, 170, 254, 255]
}

/// Edge and pseudo-random values of `[lo, hi]`.
fn samples(lo: i128, hi: i128, n: usize) -> Vec<i128> {
    let mut v = vec![lo, lo + 1, hi - 1, hi, 0, 1, -1, (lo + hi) / 2];
    let mut s: u64 = 0x2545_F491_4F6C_DD1D;
    for _ in 0..n {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        v.push(lo + (s as u128 % ((hi - lo) as u128 + 1)) as i128);
    }
    v.retain(|x| (lo..=hi).contains(x));
    v.sort();
    v.dedup();
    v
}

/// The circuit's structural invariants and statistics, recomputed
/// independently from its nodes: operands precede users, nothing is
/// duplicated (CSE), no rule's pattern survives, every node is live (DCE),
/// and the level analysis matches.
fn check_circuit(c: &Circuit) -> Result<(), String> {
    let n = c.nodes.len();
    if c.optimizer_version != OPTIMIZER_VERSION {
        return Err("optimizer version".into());
    }
    let mut seen = HashSet::new();
    let (mut gates, mut nots, mut inputs) = (0u64, 0u64, 0u32);
    let mut level = vec![0u32; n];
    for (i, node) in c.nodes.iter().enumerate() {
        if !seen.insert(*node) {
            return Err(format!("node {i} {node:?} is duplicated"));
        }
        let before = |x: u32| {
            if (x as usize) < i {
                Ok(c.nodes[x as usize])
            } else {
                Err(format!("node {i}: operand {x} does not precede it"))
            }
        };
        level[i] = match *node {
            Node::Input { input, bit } => {
                inputs += 1;
                match c.input_elems.get(input as usize) {
                    Some(e) if bit < e.bits() => {}
                    _ => return Err(format!("node {i}: no input bit {input}.{bit}")),
                }
                0
            }
            Node::Const { .. } => 0,
            Node::Not { a } => {
                nots += 1;
                match before(a)? {
                    Node::Const { .. } => return Err(format!("node {i}: NOT of a constant")),
                    Node::Not { .. } => return Err(format!("node {i}: double negation")),
                    _ => {}
                }
                level[a as usize]
            }
            Node::Gate { op, a, b } => {
                gates += 1;
                let (na, nb) = (before(a)?, before(b)?);
                if a >= b {
                    return Err(format!("node {i}: operands not canonical"));
                }
                if matches!(na, Node::Const { .. }) || matches!(nb, Node::Const { .. }) {
                    return Err(format!("node {i}: a gate with a constant operand"));
                }
                if na == (Node::Not { a: b }) || nb == (Node::Not { a }) {
                    return Err(format!("node {i}: a gate on x and NOT x"));
                }
                if op == GateOp::Xor
                    && (matches!(na, Node::Not { .. }) || matches!(nb, Node::Not { .. }))
                {
                    return Err(format!("node {i}: an XOR with a NOT operand"));
                }
                1 + level[a as usize].max(level[b as usize])
            }
        };
    }
    // Liveness: every node is reachable from an output.
    let mut live = vec![false; n];
    let mut stack = vec![];
    for w in &c.outputs {
        for b in &w.bits {
            if let OutBit::Node { id } = b {
                if *id as usize >= n {
                    return Err(format!("output node {id} out of range"));
                }
                stack.push(*id);
            }
        }
    }
    while let Some(id) = stack.pop() {
        if std::mem::replace(&mut live[id as usize], true) {
            continue;
        }
        match c.nodes[id as usize] {
            Node::Not { a } => stack.push(a),
            Node::Gate { a, b, .. } => stack.extend([a, b]),
            _ => {}
        }
    }
    if let Some(i) = live.iter().position(|l| !l) {
        return Err(format!("node {i} is dead"));
    }
    // Statistics and the level analysis.
    let s = &c.stats;
    let depth = level.iter().copied().max().unwrap_or(0);
    let mut sizes = vec![0u32; depth as usize];
    for (i, node) in c.nodes.iter().enumerate() {
        if matches!(node, Node::Gate { .. }) {
            sizes[level[i] as usize - 1] += 1;
        }
    }
    let width = sizes.iter().copied().max().unwrap_or(0);
    let total: u32 = c.input_elems.iter().map(|e| e.bits()).sum();
    let got = (
        s.gates,
        s.nots,
        s.input_bits_used,
        s.input_bits_total,
        s.depth,
        s.width,
    );
    let want = (gates, nots, inputs, total, depth, width);
    if got != want {
        return Err(format!("stats {got:?}, recount {want:?}"));
    }
    if c.level_sizes() != sizes {
        return Err(format!(
            "level sizes {:?}, recount {sizes:?}",
            c.level_sizes()
        ));
    }
    if sizes.contains(&0) {
        return Err("an empty level below the depth".into());
    }
    for w in [0u32, 1, 2, 3, 8, 1 << 20] {
        let r: u64 = sizes
            .iter()
            .map(|g| (*g as u64).div_ceil(w.max(1) as u64))
            .sum();
        if c.rounds(w) != r {
            return Err(format!("rounds({w}) = {}, recount {r}", c.rounds(w)));
        }
    }
    Ok(())
}

/// Runs `check` on random programs (each with four input cases).
fn random_programs(
    default: u32,
    check: impl Fn(&Program, &ExactPlan, &[Option<Interval>], &[Vec<i128>]) -> Result<(), TestCaseError>,
) {
    let n = gen::programs(default);
    let compiled = Cell::new(0u32);
    runner(n)
        .run(&(gen::arb_program(), any::<u64>()), |((p, decl), seed)| {
            let Ok(c) = compile(&p) else { return Ok(()) };
            compiled.set(compiled.get() + 1);
            let plan = c.plan;
            let ranges = input_ranges(&p, &plan);
            let cases: Vec<Vec<i128>> = (0..4)
                .map(|case| {
                    let inputs = gen::inputs_for(&decl, case, seed);
                    plan.inputs
                        .iter()
                        .map(|i| inputs[&i.name][0] as i128)
                        .collect()
                })
                .collect();
            check(&p, &plan, &ranges, &cases)
        })
        .unwrap();
    assert!(
        compiled.get() >= n / 3,
        "{} of {n} compiled",
        compiled.get()
    );
}

/// `plan` with other outputs.
fn with_outputs(plan: &ExactPlan, regs: impl IntoIterator<Item = u32>) -> ExactPlan {
    let mut p = plan.clone();
    p.outputs = regs
        .into_iter()
        .map(|r| ExactOutput {
            name: format!("r{r}"),
            reg: r,
            elem: plan.elems[r as usize],
        })
        .collect();
    p
}

fn remap(i: &ExactInstr, m: impl Fn(u32) -> u32) -> ExactInstr {
    use ExactInstr::*;
    match i.clone() {
        Input { index } => Input { index },
        Trivial { value } => Trivial { value },
        Add(a, b) => Add(m(a), m(b)),
        Sub(a, b) => Sub(m(a), m(b)),
        Mul(a, b) => Mul(m(a), m(b)),
        Neg(a) => Neg(m(a)),
        AddScalar(a, c) => AddScalar(m(a), c),
        SubScalar(a, c) => SubScalar(m(a), c),
        MulScalar(a, c) => MulScalar(m(a), c),
        ScalarSub(c, a) => ScalarSub(c, m(a)),
        DivScalar(a, c) => DivScalar(m(a), c),
        RemScalar(a, c) => RemScalar(m(a), c),
        Cmp(op, a, b) => Cmp(op, m(a), m(b)),
        CmpScalar(op, a, c) => CmpScalar(op, m(a), c),
        Logic(op, a, b) => Logic(op, m(a), m(b)),
        Not(a) => Not(m(a)),
        Shift { x, left, by } => Shift { x: m(x), left, by },
        Min(a, b) => Min(m(a), m(b)),
        Max(a, b) => Max(m(a), m(b)),
        Select(c, a, b) => Select(m(c), m(a), m(b)),
        Lookup { x, table } => Lookup { x: m(x), table },
        Cast(a) => Cast(m(a)),
    }
}

/// `plan` with every non-input instruction emitted twice (the copy reads
/// the copies) and every output twice.
fn duplicated(plan: &ExactPlan) -> ExactPlan {
    let mut p = plan.clone();
    let mut map: Vec<u32> = (0..plan.instrs.len() as u32).collect();
    for (i, instr) in plan.instrs.iter().enumerate() {
        if matches!(instr, ExactInstr::Input { .. }) {
            continue;
        }
        let copy = remap(instr, |r| map[r as usize]);
        map[i] = p.instrs.len() as u32;
        p.instrs.push(copy);
        p.elems.push(plan.elems[i]);
    }
    for o in &plan.outputs {
        p.outputs.push(ExactOutput {
            name: format!("{}'", o.name),
            reg: map[o.reg as usize],
            elem: o.elem,
        });
    }
    p
}

/// `plan` with every public constant register turned into an input (fed
/// the constant): nothing folds.
fn lift_constants(plan: &ExactPlan) -> (ExactPlan, Vec<i128>) {
    let mut p = plan.clone();
    let mut consts = vec![];
    for (i, instr) in p.instrs.iter_mut().enumerate() {
        if let ExactInstr::Trivial { value } = *instr {
            *instr = ExactInstr::Input {
                index: p.inputs.len(),
            };
            p.inputs.push(ExactInput {
                name: format!("const{i}"),
                elem: p.elems[i],
            });
            consts.push(value);
        }
    }
    (p, consts)
}

/// `e`'s range, within the 2^53 an IR input range may declare.
fn ir_bounds(e: Elem) -> (i128, i128) {
    let (lo, hi) = e.bounds();
    (lo.max(-(1 << 52)), hi.min(1 << 52))
}

/// Two's-complement wrapping to `e`'s width.
fn wrap(e: Elem, v: i128) -> i128 {
    let n = e.bits();
    let m = v & ((1i128 << n) - 1);
    if e.is_signed() && (m >> (n - 1)) & 1 == 1 {
        m - (1i128 << n)
    } else {
        m
    }
}

// --- Recorder rules: differential tests against the reference lowering ---------

/// Checks a rule's program (x exhaustive, y sampled) and returns the
/// plan and its reference-strategy circuit.
fn rule(f: impl FnOnce(&mut Builder, ValueId, ValueId) -> Vec<ValueId>) -> (ExactPlan, Circuit) {
    let p = program(f);
    let (plan, cs) = check_program(&p, &[all_u8(), some_u8()]);
    (plan, cs.into_iter().next().unwrap())
}

#[test]
fn diff_rule_and_self() {
    let (plan, c) = rule(|b, x, _| vec![b.logic(LogicOp::And, x, x).unwrap()]);
    assert_eq!(
        gate_count(&plan).unwrap(),
        8,
        "the reference evaluates x & x"
    );
    assert_eq!((c.stats.gates, c.stats.simplifications), (0, 8));
}

#[test]
fn diff_rule_or_self() {
    let (plan, c) = rule(|b, x, _| vec![b.logic(LogicOp::Or, x, x).unwrap()]);
    assert_eq!(gate_count(&plan).unwrap(), 8);
    assert_eq!((c.stats.gates, c.stats.simplifications), (0, 8));
}

#[test]
fn diff_rule_xor_self() {
    let (plan, c) = rule(|b, x, _| vec![b.logic(LogicOp::Xor, x, x).unwrap()]);
    assert_eq!(gate_count(&plan).unwrap(), 8);
    assert_eq!((c.stats.gates, c.stats.simplifications), (0, 8));
}

#[test]
fn diff_rule_and_not_self() {
    let (plan, c) = rule(|b, x, _| {
        let nx = b.not(x).unwrap();
        vec![
            b.logic(LogicOp::And, x, nx).unwrap(),
            b.logic(LogicOp::And, nx, x).unwrap(),
        ]
    });
    assert_eq!(gate_count(&plan).unwrap(), 16);
    assert_eq!((c.stats.gates, c.stats.simplifications), (0, 16));
}

#[test]
fn diff_rule_or_not_self() {
    let (plan, c) = rule(|b, x, _| {
        let nx = b.not(x).unwrap();
        vec![
            b.logic(LogicOp::Or, x, nx).unwrap(),
            b.logic(LogicOp::Or, nx, x).unwrap(),
        ]
    });
    assert_eq!(gate_count(&plan).unwrap(), 16);
    assert_eq!((c.stats.gates, c.stats.simplifications), (0, 16));
}

#[test]
fn diff_rule_xor_not_self() {
    let (plan, c) = rule(|b, x, _| {
        let nx = b.not(x).unwrap();
        vec![
            b.logic(LogicOp::Xor, x, nx).unwrap(),
            b.logic(LogicOp::Xor, nx, x).unwrap(),
        ]
    });
    assert_eq!(gate_count(&plan).unwrap(), 16);
    assert_eq!((c.stats.gates, c.stats.simplifications), (0, 16));
}

#[test]
fn diff_rule_xor_not_pull_out_left() {
    let (plan, c) = rule(|b, x, y| {
        let nx = b.not(x).unwrap();
        vec![
            b.logic(LogicOp::Xor, nx, y).unwrap(),
            b.logic(LogicOp::Xor, x, y).unwrap(),
        ]
    });
    assert_eq!(gate_count(&plan).unwrap(), 16);
    // !x ^ y = !(x ^ y): the eight XORs serve both outputs.
    assert_eq!((c.stats.gates, c.stats.nots, c.stats.cse_hits), (8, 8, 8));
}

#[test]
fn diff_rule_xor_not_pull_out_right() {
    let (plan, c) = rule(|b, x, y| {
        let ny = b.not(y).unwrap();
        vec![
            b.logic(LogicOp::Xor, x, ny).unwrap(),
            b.logic(LogicOp::Xor, y, x).unwrap(),
        ]
    });
    assert_eq!(gate_count(&plan).unwrap(), 16);
    assert_eq!((c.stats.gates, c.stats.nots, c.stats.cse_hits), (8, 8, 8));
}

#[test]
fn diff_rule_double_negation() {
    let (_, c) = rule(|b, x, _| {
        let nx = b.not(x).unwrap();
        vec![b.not(nx).unwrap()]
    });
    assert_eq!((c.stats.gates, c.stats.nots), (0, 0));
    for (i, bit) in c.outputs[0].bits.iter().enumerate() {
        let OutBit::Node { id } = bit else {
            panic!("bit {i} is constant")
        };
        assert_eq!(
            c.nodes[*id as usize],
            Node::Input {
                input: 0,
                bit: i as u32
            }
        );
    }
}

/// `y ^ y`: encrypted-side zero bits (constant nodes of the recorder, not
/// public constants of the lowering), and their NOT: all-one bits.
fn zeros_and_ones(b: &mut Builder, y: ValueId) -> (ValueId, ValueId) {
    let z = b.logic(LogicOp::Xor, y, y).unwrap();
    let t = b.not(z).unwrap();
    (z, t)
}

#[test]
fn diff_rule_not_of_constant() {
    let (_, c) = rule(|b, _, y| vec![zeros_and_ones(b, y).1]);
    assert_eq!((c.stats.gates, c.stats.nots), (0, 0));
    for bit in &c.outputs[0].bits {
        let v = match bit {
            OutBit::Const { v } => *v,
            OutBit::Node { id } => match c.nodes[*id as usize] {
                Node::Const { v } => v,
                n => panic!("{n:?}: NOT of a constant is a constant"),
            },
        };
        assert!(v);
    }
}

#[test]
fn diff_rule_and_with_constants() {
    let (_, c) = rule(|b, x, y| {
        let (z, t) = zeros_and_ones(b, y);
        vec![
            b.logic(LogicOp::And, x, z).unwrap(),
            b.logic(LogicOp::And, z, x).unwrap(),
            b.logic(LogicOp::And, x, t).unwrap(),
            b.logic(LogicOp::And, t, x).unwrap(),
        ]
    });
    assert_eq!(c.stats.gates, 0);
    assert_eq!(c.stats.simplifications, 8 + 4 * 8, "y ^ y, then 4 x 8 bits");
}

#[test]
fn diff_rule_or_with_constants() {
    let (_, c) = rule(|b, x, y| {
        let (z, t) = zeros_and_ones(b, y);
        vec![
            b.logic(LogicOp::Or, x, z).unwrap(),
            b.logic(LogicOp::Or, z, x).unwrap(),
            b.logic(LogicOp::Or, x, t).unwrap(),
            b.logic(LogicOp::Or, t, x).unwrap(),
        ]
    });
    assert_eq!(c.stats.gates, 0);
    assert_eq!(c.stats.simplifications, 8 + 4 * 8);
}

#[test]
fn diff_rule_xor_with_constants() {
    let (_, c) = rule(|b, x, y| {
        let (z, t) = zeros_and_ones(b, y);
        vec![
            b.logic(LogicOp::Xor, x, z).unwrap(),
            b.logic(LogicOp::Xor, z, x).unwrap(),
            b.logic(LogicOp::Xor, x, t).unwrap(),
            b.logic(LogicOp::Xor, t, x).unwrap(),
        ]
    });
    assert_eq!(c.stats.gates, 0);
    assert_eq!(c.stats.nots, 8, "x ^ 1 = !x");
    assert_eq!(c.stats.simplifications, 8 + 4 * 8);
}

/// The recorder's invariants on circuits of random programs: no pattern a
/// rule rewrites survives, operands are canonical, nodes are unique.
#[test]
fn prop_circuit_structure_and_stats() {
    random_programs(64, |p, plan, ranges, _| {
        for c in [
            build(plan, ranges, Lowering::REFERENCE).unwrap(),
            build(plan, ranges, Lowering::PARALLEL).unwrap(),
            build(plan, &[], Lowering::REFERENCE).unwrap(),
        ] {
            prop_assert_eq!(check_circuit(&c), Ok(()), "{}", p);
        }
        Ok(())
    });
}

// --- constant folding ------------------------------------------------------------

/// Public constants fold in the lowering itself: `x & 0`, `x | 1`,
/// `x ^ 1 = !x`, multiplexers with public branches.
#[test]
fn diff_bit_constant_folding() {
    let p = program(|b, x, y| {
        let k = |b: &mut Builder, v: f64| b.constant_exact(Elem::U8, v).unwrap();
        let (k0, k255, k5, k10) = (k(b, 0.0), k(b, 255.0), k(b, 5.0), k(b, 10.0));
        let c = b.cmp(CmpOp::Lt, x, y).unwrap();
        let (t, f) = (
            b.constant_exact(Elem::Bool, 1.0).unwrap(),
            b.constant_exact(Elem::Bool, 0.0).unwrap(),
        );
        vec![
            b.logic(LogicOp::And, x, k0).unwrap(),
            b.logic(LogicOp::And, k255, x).unwrap(),
            b.logic(LogicOp::Or, x, k0).unwrap(),
            b.logic(LogicOp::Or, k255, x).unwrap(),
            b.logic(LogicOp::Xor, x, k0).unwrap(),
            b.logic(LogicOp::Xor, k255, x).unwrap(),
            b.select(c, k5, k10).unwrap(),
            b.select(c, k5, k5).unwrap(),
            b.select(c, t, f).unwrap(),
            b.select(c, f, t).unwrap(),
        ]
    });
    let (plan, cs) = check_program(&p, &[all_u8(), some_u8()]);
    // Everything but the comparison is free, in the reference lowering too.
    let cmp_only = program(|b, x, y| vec![b.cmp(CmpOp::Lt, x, y).unwrap()]);
    let cmp_plan = compile(&cmp_only).unwrap().plan;
    assert_eq!(gate_count(&plan).unwrap(), gate_count(&cmp_plan).unwrap());
    let c = build(&cmp_plan, &[], Lowering::REFERENCE).unwrap();
    assert_eq!(cs[0].stats.gates, c.stats.gates);
}

/// Differential: a plan against itself with every public constant turned
/// into an input (nothing folds): the same values, never fewer gates.
#[test]
fn prop_constant_lifting_differential() {
    let lifted_any = Cell::new(0u32);
    random_programs(64, |p, plan, ranges, cases| {
        let (lifted, consts) = lift_constants(plan);
        if !consts.is_empty() {
            lifted_any.set(lifted_any.get() + 1);
        }
        let mut lranges = ranges.to_vec();
        lranges.extend(consts.iter().map(|v| Some((*v, *v))));
        let cs = circuits(plan, ranges);
        let lc = build(&lifted, &[], Lowering::REFERENCE).unwrap();
        prop_assert!(gate_count(plan).unwrap() <= gate_count(&lifted).unwrap());
        for vals in cases {
            let mut lvals = vals.clone();
            lvals.extend(&consts);
            let want = reference(&lifted, &lvals);
            prop_assert_eq!(&reference(plan, vals), &want, "{}", p);
            prop_assert_eq!(&run(&lc, &lifted, &lvals, 1), &want);
            prop_assert_eq!(differential(Some(p), plan, &cs, vals), Ok(()), "{}", p);
        }
        // The lifted constants' declared ranges fold them back.
        let back = build(&lifted, &lranges, Lowering::REFERENCE).unwrap();
        prop_assert_eq!(back.stats.gates, cs[0].stats.gates, "{}", p);
        Ok(())
    });
    assert!(lifted_any.get() > 0, "no program had a public constant");
}

// --- known-bit / range folding ---------------------------------------------------

#[test]
fn ranges_per_instruction() {
    use ExactInstr::*;
    let (i16_, u8_, bool_) = (Elem::I16, Elem::U8, Elem::Bool);
    let full16 = (-32768, 32767);
    let rows: Vec<(ExactInstr, Elem, Interval)> = vec![
        (Input { index: 0 }, i16_, (-10, 20)),       // 0 x
        (Input { index: 1 }, i16_, (3, 5)),          // 1 y
        (Input { index: 2 }, u8_, (0, 100)),         // 2 u
        (Input { index: 3 }, bool_, (0, 1)),         // 3 flag (undeclared)
        (Trivial { value: 7 }, i16_, (7, 7)),        // 4
        (Add(0, 1), i16_, (-7, 25)),                 // 5
        (Sub(0, 1), i16_, (-15, 17)),                // 6
        (Mul(0, 1), i16_, (-50, 100)),               // 7
        (Neg(0), i16_, (-20, 10)),                   // 8
        (AddScalar(0, 3), i16_, (-7, 23)),           // 9
        (SubScalar(0, 3), i16_, (-13, 17)),          // 10
        (MulScalar(0, -2), i16_, (-40, 20)),         // 11
        (ScalarSub(5, 0), i16_, (-15, 15)),          // 12
        (DivScalar(0, 3), i16_, (-3, 6)),            // 13
        (DivScalar(0, -3), i16_, (-6, 3)),           // 14
        (RemScalar(0, 3), i16_, (-2, 2)),            // 15 mixed sign
        (RemScalar(2, 7), u8_, (0, 6)),              // 16 non-negative
        (SubScalar(1, 10), i16_, (-7, -5)),          // 17
        (RemScalar(17, 4), i16_, (-3, 0)),           // 18 non-positive
        (Cmp(CmpOp::Lt, 0, 1), bool_, (0, 1)),       // 19
        (CmpScalar(CmpOp::Eq, 0, 3), bool_, (0, 1)), // 20
        (Logic(LogicOp::And, 2, 16), u8_, (0, 6)),   // 21
        (Logic(LogicOp::Or, 2, 16), u8_, (0, 127)),  // 22
        (Logic(LogicOp::Xor, 0, 1), i16_, full16),   // 23 a negative operand
        (Logic(LogicOp::And, 3, 19), bool_, (0, 1)), // 24
        (Not(2), u8_, (155, 255)),                   // 25
        (Not(0), i16_, (-21, 9)),                    // 26
        (Not(3), bool_, (0, 1)),                     // 27
        (
            Shift {
                x: 0,
                left: true,
                by: 2,
            },
            i16_,
            (-40, 80),
        ), // 28
        (
            Shift {
                x: 0,
                left: false,
                by: 1,
            },
            i16_,
            (-5, 10),
        ), // 29 arithmetic
        (
            Shift {
                x: 2,
                left: false,
                by: 3,
            },
            u8_,
            (0, 12),
        ), // 30
        (
            Shift {
                x: 2,
                left: true,
                by: 2,
            },
            u8_,
            (0, 255),
        ), // 31 exceeds: full
        (Min(0, 1), i16_, (-10, 5)),                 // 32
        (Max(0, 1), i16_, (3, 20)),                  // 33
        (Select(3, 0, 1), i16_, (-10, 20)),          // 34
        (
            Lookup {
                x: 2,
                table: vec![4, -2, 9],
            },
            i16_,
            (-2, 9),
        ), // 35
        (Cast(2), i16_, (0, 100)),                   // 36 widening
        (Cast(0), u8_, (0, 255)),                    // 37 does not fit: full
        (MulScalar(0, 30000), i16_, full16),         // 38 exceeds: full
        (Trivial { value: -1 }, i16_, (-1, -1)),     // 39
    ];
    let plan = ExactPlan {
        inputs: [i16_, i16_, u8_, bool_]
            .iter()
            .enumerate()
            .map(|(i, e)| ExactInput {
                name: format!("in{i}"),
                elem: *e,
            })
            .collect(),
        instrs: rows.iter().map(|r| r.0.clone()).collect(),
        elems: rows.iter().map(|r| r.1).collect(),
        outputs: vec![],
    };
    plan.validate().unwrap();
    let declared = [Some((-10, 20)), Some((3, 5)), Some((0, 100)), None];
    let got = ranges(&plan, &declared);
    for (i, (row, iv)) in rows.iter().zip(&got).enumerate() {
        assert_eq!(*iv, row.2, "register {i}: {:?}", row.0);
    }
    // Undeclared, inverted or out-of-type input ranges: the type's range.
    let got = ranges(&plan, &[None, Some((5, 1)), Some((-1, 300))]);
    assert_eq!(&got[..4], &[full16, full16, (0, 255), (0, 1)]);
}

/// The folding loop in `build`: bits a range proves constant become
/// constants, a mixed-sign value's high bits become copies of its sign.
#[test]
fn range_folding_in_build() {
    type Want = fn(&Circuit);
    type Case = (Elem, (f64, f64), u32, u64, Want);
    let cases: Vec<Case> = vec![
        (Elem::U16, (0.0, 100.0), 7, 9, |c| {
            assert!(c.outputs[0].bits[7..]
                .iter()
                .all(|b| *b == OutBit::Const { v: false }));
        }),
        (Elem::I16, (-300.0, -200.0), 9, 7, |c| {
            assert!(c.outputs[0].bits[9..]
                .iter()
                .all(|b| *b == OutBit::Const { v: true }));
        }),
        (Elem::I32, (-3.0, 5.0), 4, 28, |c| {
            // The sign-copy case: bits 4.. are bit 3's node.
            let sign = c.outputs[0].bits[3];
            assert!(matches!(sign, OutBit::Node { .. }));
            assert!(c.outputs[0].bits[4..].iter().all(|b| *b == sign));
        }),
        (Elem::U8, (42.0, 42.0), 0, 8, |c| {
            let bits: Vec<bool> = c.outputs[0]
                .bits
                .iter()
                .map(|b| matches!(b, OutBit::Const { v: true }))
                .collect();
            assert_eq!(bits, plain_bits(Elem::U8, 42));
        }),
    ];
    for (e, (lo, hi), used, folded, want) in cases {
        let mut b = Builder::new("p", 1e-3).unwrap();
        let x = b.input_exact("x", e, Some(Range::new(lo, hi))).unwrap();
        b.output("x", x).unwrap();
        let p = b.finish().unwrap();
        let values: Vec<i128> = (lo as i128..=hi as i128).collect();
        let (_, cs) = check_program(&p, &[values]);
        for c in &cs {
            assert_eq!(c.stats.input_bits_used, used, "{e} [{lo}, {hi}]");
            assert_eq!(c.stats.range_bits_folded, folded, "{e} [{lo}, {hi}]");
            assert_eq!(c.stats.gates, 0);
            want(c);
        }
    }
    // A computed value's high bits fold too: the circuit computes the high
    // bits of x - y = x + !y + 1 with gates; the range proves them zero.
    let (p, values) = difference();
    let (_, cs) = check_program(&p, &values);
    for c in &cs {
        assert!(c.outputs[0].bits[8..]
            .iter()
            .all(|b| *b == OutBit::Const { v: false }));
        // x: 8 bits folded, y: 10, the difference: 8.
        assert_eq!(c.stats.range_bits_folded, 8 + 10 + 8);
    }
}

/// `x - y` for `u16` `x` in `[100, 200]` and `y` in `[0, 50]`, with sample
/// values: a result in `[50, 200]` whose high bits the circuit computes.
fn difference() -> (Program, Vec<Vec<i128>>) {
    let mut b = Builder::new("d", 1e-3).unwrap();
    let x = b
        .input_exact("x", Elem::U16, Some(Range::new(100.0, 200.0)))
        .unwrap();
    let y = b
        .input_exact("y", Elem::U16, Some(Range::new(0.0, 50.0)))
        .unwrap();
    let d = b.sub(x, y).unwrap();
    b.output("d", d).unwrap();
    (
        b.finish().unwrap(),
        vec![samples(100, 200, 10), samples(0, 50, 10)],
    )
}

/// Soundness of the interval analysis: on random programs and inputs in
/// the declared ranges, every register's value lies in its interval.
#[test]
fn prop_ranges_are_sound() {
    random_programs(96, |p, plan, declared, cases| {
        let all = with_outputs(plan, 0..plan.instrs.len() as u32);
        let ivs = ranges(plan, declared);
        for vals in cases {
            for (i, v) in reference(&all, vals).into_iter().enumerate() {
                let (lo, hi) = ivs[i];
                prop_assert!(
                    lo <= v && v <= hi,
                    "register {} ({:?}) = {} outside [{}, {}] in {}",
                    i,
                    plan.instrs[i],
                    v,
                    lo,
                    hi,
                    p
                );
            }
        }
        Ok(())
    });
}

/// Differential: circuits folded with the declared ranges against the same
/// circuits without range information, both against the reference.
#[test]
fn diff_range_folding_matches_unfolded() {
    random_programs(64, |p, plan, ranges, cases| {
        let folded = circuits(plan, ranges);
        let unfolded = circuits(plan, &[]);
        for vals in cases {
            prop_assert_eq!(differential(Some(p), plan, &folded, vals), Ok(()), "{}", p);
            prop_assert_eq!(differential(None, plan, &unfolded, vals), Ok(()), "{}", p);
        }
        Ok(())
    });
}

// --- common subexpressions -------------------------------------------------------

#[test]
fn cse_reuses_repeated_and_commuted_instructions() {
    let r = (0.0, 100.0);
    let one = program_in(Elem::U8, r, |b, x, y| vec![b.add(x, y).unwrap()]);
    let three = program_in(Elem::U8, r, |b, x, y| {
        vec![
            b.add(x, y).unwrap(),
            b.add(y, x).unwrap(),
            b.add(x, y).unwrap(),
        ]
    });
    let vals = [samples(0, 100, 10), samples(0, 100, 10)];
    let (_, c1) = check_program(&one, &vals);
    let (plan3, c3) = check_program(&three, &vals);
    for (a, b) in c1.iter().zip(&c3) {
        let s = &a.stats;
        assert_eq!(b.stats.gates, s.gates, "each sum is evaluated once");
        assert_eq!(b.stats.dead_gates, s.dead_gates);
        // Every gate of the second and third sum is a hit.
        let calls = s.gates + s.dead_gates + s.cse_hits;
        assert_eq!(b.stats.cse_hits, s.cse_hits + 2 * calls);
        assert_eq!(b.stats.simplifications, 3 * s.simplifications);
    }
    assert!(gate_count(&plan3).unwrap() > c3[0].stats.gates);
}

/// A plan with its instructions emitted twice costs what it costs once;
/// every gate of the copy is counted as a hit.
#[test]
fn prop_cse_duplicated_plan_is_free() {
    random_programs(64, |p, plan, ranges, cases| {
        let twice = duplicated(plan);
        for s in [Lowering::REFERENCE, Lowering::PARALLEL] {
            let (a, b) = (
                build(plan, ranges, s).unwrap(),
                build(&twice, ranges, s).unwrap(),
            );
            let st = &a.stats;
            prop_assert_eq!(b.stats.gates, st.gates, "{}", p);
            prop_assert_eq!(b.stats.dead_gates, st.dead_gates, "{}", p);
            prop_assert_eq!(
                b.stats.cse_hits,
                2 * st.cse_hits + st.gates + st.dead_gates,
                "{}",
                p
            );
            prop_assert_eq!(b.stats.simplifications, 2 * st.simplifications);
            prop_assert_eq!(check_circuit(&b), Ok(()));
            for vals in cases {
                prop_assert_eq!(
                    differential(None, &twice, std::slice::from_ref(&b), vals),
                    Ok(())
                );
            }
        }
        Ok(())
    });
}

/// Differential: programs full of repeated work, against the reference.
#[test]
fn diff_cse_matches_reference() {
    let p = program_in(Elem::I16, (-100.0, 100.0), |b, x, y| {
        let m1 = b.mul(x, y).unwrap();
        let m2 = b.mul(y, x).unwrap();
        let s = b.add(m1, m2).unwrap();
        let k = b.constant_exact(Elem::I16, 650.0).unwrap();
        let c1 = b.cmp(CmpOp::Le, x, k).unwrap();
        let c2 = b.cmp(CmpOp::Le, x, k).unwrap();
        let c3 = b.cmp(CmpOp::Ge, k, x).unwrap();
        let a = b.logic(LogicOp::And, c1, c2).unwrap();
        let a = b.logic(LogicOp::And, a, c3).unwrap();
        vec![s, a, m1, m2]
    });
    let v = samples(-100, 100, 14);
    let (plan, cs) = check_program(&p, &[v.clone(), v]);
    for c in &cs {
        assert!(c.stats.cse_hits > 0);
        assert!(gate_count(&plan).unwrap() > c.stats.gates);
    }
}

// --- dead-code elimination ------------------------------------------------------

#[test]
fn dce_removes_unreachable_and_folded_gates() {
    use ExactInstr::*;
    // Unused instructions: none of their gates remain, nor y's input bits.
    let plan = ExactPlan {
        inputs: ["x", "y"]
            .iter()
            .map(|n| ExactInput {
                name: (*n).into(),
                elem: Elem::U8,
            })
            .collect(),
        instrs: vec![Input { index: 0 }, Input { index: 1 }, Add(0, 1), Mul(0, 1)],
        elems: vec![Elem::U8; 4],
        outputs: vec![],
    };
    let only_x = with_outputs(&plan, [0]);
    let live = with_outputs(&plan, [2, 3]);
    for s in [Lowering::REFERENCE, Lowering::PARALLEL] {
        let (a, b) = (
            build(&only_x, &[], s).unwrap(),
            build(&live, &[], s).unwrap(),
        );
        check_circuit(&a).unwrap();
        assert_eq!(a.stats.gates, 0);
        assert_eq!(a.stats.dead_gates, b.stats.gates + b.stats.dead_gates);
        assert_eq!(a.nodes.len(), 8, "x's eight input bits only");
        assert_eq!(a.stats.input_bits_used, 8);
        let none = build(&plan, &[], s).unwrap();
        assert!(none.nodes.is_empty());
        assert_eq!(none.stats.dead_gates, a.stats.dead_gates);
        for x in [0, 1, 77, 255] {
            assert_eq!(run(&a, &only_x, &[x, 3], 2), vec![x]);
        }
    }
    // Gates whose bits the range folds become dead: the high bits of a
    // difference in [50, 200].
    let (p, values) = difference();
    let (plan, cs) = check_program(&p, &values);
    let unfolded = build(&plan, &[], Lowering::REFERENCE).unwrap();
    for c in &cs {
        assert!(c.stats.dead_gates > 0, "{:?}", c.stats);
        assert!(c.stats.gates < unfolded.stats.gates);
    }
}

/// The recorded DAG does not depend on the outputs: the live and dead gates
/// always add up to every gate recorded, and every remaining node is live.
#[test]
fn prop_dce_counts_every_recorded_gate() {
    random_programs(64, |p, plan, ranges, _| {
        let n = plan.instrs.len() as u32;
        for s in [Lowering::REFERENCE, Lowering::PARALLEL] {
            let total = build(&with_outputs(plan, []), ranges, s)
                .unwrap()
                .stats
                .dead_gates;
            for q in [
                plan.clone(),
                with_outputs(plan, 0..n),
                with_outputs(plan, [n - 1]),
                with_outputs(plan, plan.outputs.first().map(|o| o.reg)),
            ] {
                let c = build(&q, ranges, s).unwrap();
                prop_assert_eq!(c.stats.gates + c.stats.dead_gates, total, "{}", p);
                prop_assert_eq!(check_circuit(&c), Ok(()), "{}", p);
            }
        }
        Ok(())
    });
}

/// Differential: a circuit for some outputs against one for every
/// register: the shared outputs agree, and with the reference.
#[test]
fn diff_dce_matches_reference() {
    random_programs(48, |p, plan, ranges, cases| {
        let n = plan.instrs.len() as u32;
        let all = with_outputs(plan, (0..n).chain(plan.outputs.iter().map(|o| o.reg)));
        let (c, ca) = (
            optimize(plan, ranges, 8).unwrap(),
            optimize(&all, ranges, 8).unwrap(),
        );
        prop_assert!(c.stats.gates <= ca.stats.gates);
        for vals in cases {
            let got = run(&c, plan, vals, 2);
            let every = run(&ca, &all, vals, 2);
            prop_assert_eq!(&got[..], &every[n as usize..], "{}", p);
            prop_assert_eq!(&every, &reference(&all, vals), "{}", p);
            prop_assert_eq!(
                differential(Some(p), plan, std::slice::from_ref(&c), vals),
                Ok(())
            );
        }
        Ok(())
    });
}

// --- prefix adder and tree comparator -------------------------------------------

/// The parallel strategy's adders against the ripple ones (and the
/// integers) through the lowering's public operations: every exact width,
/// exhaustively for 8 bits; the odd widths of multiplication's partial
/// sums and of division's restoring steps.
#[test]
fn diff_prefix_adder_every_width() {
    let par = BitEvaluator::with_strategy(PlainGates, Lowering::PARALLEL);
    let rip = BitEvaluator::new(PlainGates);
    let v = |w: &bits::Word<bool>| bits::plain_value(w);
    let w = bits::plain_word;
    for e in [Elem::U8, Elem::I8] {
        let (lo, hi) = e.bounds();
        for x in lo..=hi {
            for y in lo..=hi {
                let (a, b) = (w(e, x), w(e, y));
                let s = v(&par.add(&a, &b).unwrap());
                assert_eq!(s, v(&rip.add(&a, &b).unwrap()), "{e} {x}+{y}");
                assert_eq!(s, wrap(e, x + y), "{e} {x}+{y}");
            }
            let a = w(e, x);
            assert_eq!(v(&par.neg(&a).unwrap()), wrap(e, -x));
            for c in [3, 5, 7, 10, 100, -7] {
                if e == Elem::U8 && c < 0 {
                    continue;
                }
                let q = v(&par.div_scalar(&a, c).unwrap());
                let r = v(&par.rem_scalar(&a, c).unwrap());
                assert_eq!((q, r), (x / c, x % c), "{e} {x} / {c}");
                assert_eq!(q, v(&rip.div_scalar(&a, c).unwrap()));
                assert_eq!(r, v(&rip.rem_scalar(&a, c).unwrap()));
                let m = v(&par.mul_scalar(&a, c).unwrap());
                assert_eq!(m, wrap(e, x * c));
                assert_eq!(m, v(&rip.mul_scalar(&a, c).unwrap()));
            }
            for y in samples(lo, hi, 8) {
                let (a, b) = (w(e, x), w(e, y));
                let s = v(&par.sub(&a, &b).unwrap());
                assert_eq!(s, v(&rip.sub(&a, &b).unwrap()));
                assert_eq!(s, wrap(e, x - y));
                let m = v(&par.mul(&a, &b).unwrap());
                assert_eq!(m, v(&rip.mul(&a, &b).unwrap()));
                assert_eq!(m, wrap(e, x * y));
            }
        }
    }
    for e in [
        Elem::U16,
        Elem::I16,
        Elem::U32,
        Elem::I32,
        Elem::U64,
        Elem::I64,
    ] {
        let (lo, hi) = e.bounds();
        let xs = samples(lo, hi, 24);
        for &x in &xs {
            for &y in &xs {
                let (a, b) = (w(e, x), w(e, y));
                for (got, want) in [
                    (par.add(&a, &b), rip.add(&a, &b)),
                    (par.sub(&a, &b), rip.sub(&a, &b)),
                ] {
                    assert_eq!(v(&got.unwrap()), v(&want.unwrap()), "{e} {x} {y}");
                }
                assert_eq!(v(&par.add(&a, &b).unwrap()), wrap(e, x + y));
            }
            let a = w(e, x);
            for c in [7, 1000, 12345] {
                let q = v(&par.div_scalar(&a, c).unwrap());
                assert_eq!(q, x / c, "{e} {x} / {c}");
                assert_eq!(v(&par.rem_scalar(&a, c).unwrap()), x % c);
            }
        }
    }
    // As circuits: the parallel strategy's adder is shallower from 16 bits.
    for e in gen::WIDTHS {
        let (lo, hi) = ir_bounds(e);
        let (lo, hi) = (lo / 2, hi / 2);
        let p = program_in(e, (lo as f64, hi as f64), |b, x, y| {
            vec![b.add(x, y).unwrap()]
        });
        let (plan, cs) = check_program(&p, &[samples(lo, hi, 6), samples(lo, hi, 6)]);
        assert_eq!(cs[1].strategy, Lowering::PARALLEL);
        if e.bits() >= 16 {
            assert!(cs[1].stats.depth < cs[0].stats.depth, "{e}");
        }
        assert!(cs[0].stats.gates <= gate_count(&plan).unwrap());
    }
}

/// The tree comparator against the ripple carry chain (and the integers):
/// every comparison, exhaustively for 8 bits, sampled wider.
#[test]
fn diff_tree_comparator_every_width() {
    let par = BitEvaluator::with_strategy(PlainGates, Lowering::PARALLEL);
    let rip = BitEvaluator::new(PlainGates);
    let v = |w: &bits::Word<bool>| bits::plain_value(w);
    let ops = [
        (CmpOp::Lt, (|a, b| a < b) as fn(i128, i128) -> bool),
        (CmpOp::Le, |a, b| a <= b),
        (CmpOp::Gt, |a, b| a > b),
        (CmpOp::Ge, |a, b| a >= b),
        (CmpOp::Eq, |a, b| a == b),
        (CmpOp::Ne, |a, b| a != b),
    ];
    let check = |e: Elem, x: i128, y: i128, all_ops: bool| {
        let (a, b) = (bits::plain_word(e, x), bits::plain_word(e, y));
        for (op, f) in &ops[..if all_ops { 6 } else { 2 }] {
            let got = v(&par.cmp(*op, &a, &b).unwrap());
            assert_eq!(got, v(&rip.cmp(*op, &a, &b).unwrap()), "{e} {x} {op:?} {y}");
            assert_eq!(got == 1, f(x, y), "{e} {x} {op:?} {y}");
        }
        assert_eq!(v(&par.min(&a, &b).unwrap()), x.min(y));
        assert_eq!(v(&par.max(&a, &b).unwrap()), x.max(y));
    };
    for e in [Elem::U8, Elem::I8] {
        let (lo, hi) = e.bounds();
        for x in lo..=hi {
            for y in lo..=hi {
                check(e, x, y, false);
            }
            for y in samples(lo, hi, 6) {
                check(e, x, y, true);
            }
        }
    }
    for e in [
        Elem::U16,
        Elem::I16,
        Elem::U32,
        Elem::I32,
        Elem::U64,
        Elem::I64,
    ] {
        let (lo, hi) = e.bounds();
        let xs = samples(lo, hi, 24);
        for &x in &xs {
            for &y in &xs {
                check(e, x, y, true);
            }
            for c in [0, 1, -1, 100] {
                if !(lo..=hi).contains(&c) {
                    continue;
                }
                let a = bits::plain_word(e, x);
                let got = v(&par.cmp_scalar(CmpOp::Lt, &a, c).unwrap());
                assert_eq!(got == 1, x < c);
                assert_eq!(got, v(&rip.cmp_scalar(CmpOp::Lt, &a, c).unwrap()));
            }
        }
    }
    // As circuits: the tree comparator is shallower from 16 bits.
    for e in gen::WIDTHS {
        let (lo, hi) = ir_bounds(e);
        let p = program_in(e, (lo as f64, hi as f64), |b, x, y| {
            vec![b.cmp(CmpOp::Lt, x, y).unwrap()]
        });
        let (_, cs) = check_program(&p, &[samples(lo, hi, 6), samples(lo, hi, 6)]);
        if e.bits() >= 16 {
            assert!(cs[1].stats.depth < cs[0].stats.depth, "{e}");
        }
    }
}

// --- strategy selection ----------------------------------------------------------

/// A `u32` sum (the prefix adder's case) and its declared ranges.
fn wide_add() -> (Program, ExactPlan, Vec<Option<Interval>>) {
    let p = program_in(Elem::U32, (0.0, (1u64 << 30) as f64), |b, x, y| {
        vec![b.add(x, y).unwrap()]
    });
    let plan = compile(&p).unwrap().plan;
    let ranges = input_ranges(&p, &plan);
    (p, plan, ranges)
}

#[test]
fn optimize_prefers_fewest_rounds_then_gates_and_the_reference_on_ties() {
    // Logic only: both strategies build the same circuit; the reference
    // strategy wins the tie.
    let p = program(|b, x, y| vec![b.logic(LogicOp::And, x, y).unwrap()]);
    let plan = compile(&p).unwrap().plan;
    let par = build(&plan, &[], Lowering::PARALLEL).unwrap();
    for w in [1, 8, 64] {
        let c = optimize(&plan, &[], w).unwrap();
        assert_eq!(c.strategy, Lowering::REFERENCE);
        assert_eq!(c.nodes, par.nodes, "a tie");
    }
    // A wide sum: one worker runs one gate per round, so the fewest gates
    // (ripple) win; eight workers finish the prefix adder in fewer rounds.
    let (_, plan, ranges) = wide_add();
    let (r, q) = (
        build(&plan, &ranges, Lowering::REFERENCE).unwrap(),
        build(&plan, &ranges, Lowering::PARALLEL).unwrap(),
    );
    assert!(q.stats.gates > r.stats.gates);
    assert_eq!(r.rounds(1), r.stats.gates);
    assert_eq!(optimize(&plan, &ranges, 1).unwrap(), r);
    assert!(q.rounds(8) < r.rounds(8));
    assert_eq!(optimize(&plan, &ranges, 8).unwrap(), q);
}

#[test]
fn rounds_and_level_sizes_follow_levels() {
    let (_, plan, ranges) = wide_add();
    for s in [Lowering::REFERENCE, Lowering::PARALLEL] {
        let c = build(&plan, &ranges, s).unwrap();
        check_circuit(&c).unwrap();
        let sizes = c.level_sizes();
        assert_eq!(sizes.len(), c.stats.depth as usize);
        assert_eq!(sizes.iter().map(|g| *g as u64).sum::<u64>(), c.stats.gates);
        assert_eq!(*sizes.iter().max().unwrap(), c.stats.width);
        assert_eq!(c.rounds(0), c.rounds(1), "no workers means one");
        assert_eq!(c.rounds(1), c.stats.gates);
        assert_eq!(c.rounds(u32::MAX), c.stats.depth as u64);
        let w = c.stats.width;
        assert_eq!(c.rounds(w), c.stats.depth as u64);
        for k in 1..w {
            assert!(c.rounds(k + 1) <= c.rounds(k));
        }
    }
    // No gates: no levels, no rounds.
    let p = program(|b, x, _| vec![b.not(x).unwrap()]);
    let plan = compile(&p).unwrap().plan;
    let c = build(&plan, &[], Lowering::REFERENCE).unwrap();
    assert!(c.level_sizes().is_empty());
    assert_eq!((c.rounds(1), c.stats.depth, c.stats.width), (0, 0, 0));
}

#[test]
fn prop_optimize_selects_fewest_rounds_then_gates() {
    random_programs(48, |p, plan, ranges, _| {
        let r = build(plan, ranges, Lowering::REFERENCE).unwrap();
        let q = build(plan, ranges, Lowering::PARALLEL).unwrap();
        for w in [0u32, 1, 2, 3, 8, 64] {
            let key = |c: &Circuit| (c.rounds(w), c.stats.gates);
            let want = if key(&q) < key(&r) { &q } else { &r };
            let got = optimize(plan, ranges, w).unwrap();
            prop_assert_eq!(&got, want, "{} workers {}", w, p);
            prop_assert!(got.rounds(w) <= r.rounds(w));
        }
        Ok(())
    });
}

#[test]
fn diff_optimize_matches_reference_lowering() {
    random_programs(64, |p, plan, ranges, cases| {
        let cs: Vec<Circuit> = [1, 2, 4, 8, 64]
            .iter()
            .map(|w| optimize(plan, ranges, *w).unwrap())
            .collect();
        for c in &cs {
            prop_assert!(
                c.stats.gates <= gate_count(plan).unwrap() || c.strategy != Lowering::REFERENCE
            );
        }
        for vals in cases {
            prop_assert_eq!(differential(Some(p), plan, &cs, vals), Ok(()), "{}", p);
        }
        Ok(())
    });
}

// --- levelized parallel execution -----------------------------------------------

fn mixed() -> (Program, ExactPlan, Vec<Option<Interval>>) {
    let p = program_in(Elem::I16, (-150.0, 150.0), |b, x, y| {
        let s = b.add(x, y).unwrap();
        let m = b.mul(x, y).unwrap();
        let lt = b.cmp(CmpOp::Lt, s, m).unwrap();
        let k = b.constant_exact(Elem::I16, 3.0).unwrap();
        let q = b.div(m, k).unwrap();
        vec![s, m, lt, q]
    });
    let plan = compile(&p).unwrap().plan;
    let ranges = input_ranges(&p, &plan);
    (p, plan, ranges)
}

#[test]
fn execute_rejects_bad_inputs() {
    let (_, plan, ranges) = mixed();
    let c = optimize(&plan, &ranges, 4).unwrap();
    let (x, y) = (plain_bits(Elem::I16, -7), plain_bits(Elem::I16, 9));
    let g = PlainCircuitGates;
    for workers in [1, 4] {
        let few = execute(&c, &g, std::slice::from_ref(&x), workers).unwrap_err();
        assert_eq!(few.code, Code::BadInput);
        let many = execute(&c, &g, &[x.clone(), y.clone(), y.clone()], workers).unwrap_err();
        assert_eq!(many.code, Code::BadInput);
        let short = execute(&c, &g, &[x.clone(), y[..15].to_vec()], workers).unwrap_err();
        assert_eq!(short.code, Code::BadInput);
        assert!(short.message.contains("16 bits"), "{}", short.message);
        let long = execute(&c, &g, &[plain_bits(Elem::I32, 1), y.clone()], workers).unwrap_err();
        assert_eq!(long.code, Code::BadInput);
    }
    // Zero workers run as one.
    assert_eq!(
        execute(&c, &g, &[x.clone(), y.clone()], 0).unwrap(),
        execute(&c, &g, &[x, y], 1).unwrap()
    );
}

/// Malformed inputs (an input missing or extra, a bit missing or extra)
/// are refused, whatever the worker count, before any gate runs.
#[test]
fn prop_execute_rejects_malformed_inputs() {
    random_programs(48, |p, plan, ranges, cases| {
        let c = optimize(plan, ranges, 8).unwrap();
        let good: Vec<Vec<bool>> = plan
            .inputs
            .iter()
            .zip(&cases[0])
            .map(|(i, v)| plain_bits(i.elem, *v))
            .collect();
        let k = cases[1][0].unsigned_abs() as usize % good.len();
        let mut bad = vec![good[..good.len() - 1].to_vec(), {
            let mut g = good.clone();
            g.push(good[k].clone());
            g
        }];
        let mut short = good.clone();
        short[k].pop();
        bad.push(short);
        let mut long = good.clone();
        long[k].push(true);
        bad.push(long);
        for inputs in &bad {
            for workers in [1usize, 3] {
                let g = Counting::default();
                let e = execute(&c, &g, inputs, workers).unwrap_err();
                prop_assert_eq!(e.code, Code::BadInput, "{}", p);
                prop_assert_eq!(g.gates.into_inner(), 0);
            }
        }
        prop_assert!(execute(&c, &PlainCircuitGates, &good, 3).is_ok());
        Ok(())
    });
}

/// Differential: a wrong number of inputs is refused by the executor and by
/// the reference lowering alike.
#[test]
fn diff_execute_rejects_what_the_reference_rejects() {
    let (_, plan, ranges) = mixed();
    let c = optimize(&plan, &ranges, 8).unwrap();
    let ev = BitEvaluator::new(PlainGates);
    for n in [0usize, 1, 3] {
        let words: Vec<_> = (0..n).map(|_| bits::plain_word(Elem::I16, 1)).collect();
        let bits: Vec<_> = (0..n).map(|_| plain_bits(Elem::I16, 1)).collect();
        let r = evaluate_exact(&ev, &plan, words).unwrap_err();
        let e = execute(&c, &PlainCircuitGates, &bits, 2).unwrap_err();
        assert_eq!(
            (r.code, e.code),
            (Code::BadInput, Code::BadInput),
            "{n} inputs"
        );
    }
    let vals = [12, -34];
    assert_eq!(run(&c, &plan, &vals, 2), reference(&plan, &vals));
}

/// Counts calls; can fail the `fail_at`-th gate.
#[derive(Default)]
struct Counting {
    gates: AtomicU64,
    nots: AtomicU64,
    consts: AtomicU64,
    inits: AtomicU64,
    fail_at: Option<u64>,
}

impl CircuitGates for Counting {
    type Bit = bool;
    fn gate(&self, op: GateOp, a: &bool, b: &bool) -> encompute_ir::Result<bool> {
        let n = self.gates.fetch_add(1, Ordering::SeqCst);
        if self.fail_at == Some(n) {
            return Err(encompute_ir::Error::new(
                Code::Backend,
                "injected gate failure",
            ));
        }
        PlainCircuitGates.gate(op, a, b)
    }
    fn not(&self, a: &bool) -> encompute_ir::Result<bool> {
        self.nots.fetch_add(1, Ordering::SeqCst);
        Ok(!a)
    }
    fn constant(&self, v: bool) -> encompute_ir::Result<bool> {
        self.consts.fetch_add(1, Ordering::SeqCst);
        Ok(v)
    }
    fn init_worker(&self) {
        self.inits.fetch_add(1, Ordering::SeqCst);
    }
}

/// Bits are levels: a gate is one deeper than its deeper operand.
struct Levels;

impl CircuitGates for Levels {
    type Bit = u32;
    fn gate(&self, _: GateOp, a: &u32, b: &u32) -> encompute_ir::Result<u32> {
        Ok(1 + a.max(b))
    }
    fn not(&self, a: &u32) -> encompute_ir::Result<u32> {
        Ok(*a)
    }
    fn constant(&self, _: bool) -> encompute_ir::Result<u32> {
        Ok(0)
    }
}

#[test]
fn execute_evaluates_each_gate_once_level_by_level() {
    let (_, plan, ranges) = mixed();
    for s in [Lowering::REFERENCE, Lowering::PARALLEL] {
        let c = build(&plan, &ranges, s).unwrap();
        check_circuit(&c).unwrap();
        let bits = vec![plain_bits(Elem::I16, -77), plain_bits(Elem::I16, 131)];
        let want = execute(&c, &PlainCircuitGates, &bits, 1).unwrap();
        for workers in [1usize, 2, 4, 16] {
            let g = Counting::default();
            assert_eq!(execute(&c, &g, &bits, workers).unwrap(), want);
            let consts = c
                .nodes
                .iter()
                .filter(|n| matches!(n, Node::Const { .. }))
                .count()
                + c.outputs
                    .iter()
                    .flat_map(|w| &w.bits)
                    .filter(|b| matches!(b, OutBit::Const { .. }))
                    .count();
            assert_eq!(g.gates.into_inner(), c.stats.gates, "each gate once");
            assert_eq!(g.nots.into_inner(), c.stats.nots);
            assert_eq!(g.consts.into_inner(), consts as u64);
            let inits = g.inits.into_inner();
            if workers == 1 {
                assert_eq!(inits, 0, "no worker threads");
            } else {
                assert!(inits > 0 && c.stats.width > 1);
            }
        }
        // Critical paths: the deepest output bit is at the circuit's depth.
        let zero = vec![vec![0u32; 16], vec![0u32; 16]];
        let out = execute(&c, &Levels, &zero, 4).unwrap();
        let deepest = out.iter().flatten().copied().max().unwrap();
        assert_eq!(deepest, c.stats.depth);
    }
}

#[test]
fn execute_propagates_gate_errors() {
    let (_, plan, ranges) = mixed();
    let c = optimize(&plan, &ranges, 8).unwrap();
    let bits = vec![plain_bits(Elem::I16, 5), plain_bits(Elem::I16, -6)];
    for fail_at in [0, c.stats.gates / 2, c.stats.gates - 1] {
        for workers in [1, 4] {
            let g = Counting {
                fail_at: Some(fail_at),
                ..Counting::default()
            };
            let e = execute(&c, &g, &bits, workers).unwrap_err();
            assert_eq!(e.code, Code::Backend, "gate {fail_at}, {workers} workers");
        }
    }
}

#[test]
fn prop_execute_is_worker_count_independent() {
    random_programs(48, |p, plan, ranges, cases| {
        let c = optimize(plan, ranges, 8).unwrap();
        for (k, vals) in cases.iter().enumerate() {
            let one = run(&c, plan, vals, 1);
            for workers in [2usize, 3, 5, 9 + k] {
                prop_assert_eq!(
                    &run(&c, plan, vals, workers),
                    &one,
                    "{} workers {}",
                    workers,
                    p
                );
            }
            prop_assert_eq!(&one, &reference(plan, vals), "{}", p);
        }
        Ok(())
    });
}

#[test]
fn diff_execute_workers_match_reference() {
    let (p, plan, ranges) = mixed();
    let cs = circuits(&plan, &ranges);
    let v = vec![-150, -1, 0, 77, 150];
    for vals in combinations(&[v.clone(), v]) {
        let want = reference(&plan, &vals);
        let clear: Vec<i128> = clear(&p, &plan, &vals).iter().map(|v| *v as i128).collect();
        assert_eq!(want, clear);
        for c in &cs {
            for workers in [1usize, 2, 3, 4, 7, 8, 16] {
                assert_eq!(
                    run(c, &plan, &vals, workers),
                    want,
                    "{workers} workers {vals:?}"
                );
            }
        }
    }
}

// --- the transformation -> tests table -------------------------------------------

/// `tests/OPTIMIZER_TESTS.md` names, per transformation, a unit, a property
/// and a differential test as `path::function`; each must be a `#[test]`
/// function in that file.
#[test]
fn optimizer_tests_table_names_existing_tests() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let table = std::fs::read_to_string(root.join("tests/OPTIMIZER_TESTS.md")).unwrap();
    let mut rows = 0;
    let mut named = 0;
    for line in table.lines().filter(|l| l.starts_with('|')) {
        // `\|` is a pipe inside a cell.
        let line = line.replace("\\|", "/");
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() < 5 || cells[0] == "Transformation" || cells[0].starts_with("---") {
            continue;
        }
        rows += 1;
        for (col, cell) in cells[cells.len() - 3..].iter().enumerate() {
            let refs: Vec<&str> = cell
                .split('`')
                .skip(1)
                .step_by(2)
                .filter(|r| r.contains("::"))
                .collect();
            assert!(
                !refs.is_empty(),
                "row {:?}: column {} names no test",
                cells[0],
                col
            );
            for r in refs {
                let (file, name) = r.rsplit_once("::").unwrap();
                let src = std::fs::read_to_string(root.join(file))
                    .unwrap_or_else(|e| panic!("{r}: {file}: {e}"));
                let at = src
                    .find(&format!("fn {name}("))
                    .unwrap_or_else(|| panic!("{r}: no function {name} in {file}"));
                assert!(
                    src[..at].trim_end().ends_with("#[test]"),
                    "{r}: {name} is not a #[test]"
                );
                named += 1;
            }
        }
    }
    assert!(rows >= 25, "{rows} rows");
    eprintln!("OPTIMIZER_TESTS.md: {rows} transformations, {named} test references");
}
