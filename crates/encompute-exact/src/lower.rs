use std::collections::HashMap;

use encompute_analysis::{int_ranges, privacy, semantics, PrivacyReport, Semantics};
use encompute_ir::{CmpOp, Code, Elem, Error, Op, Program, Result, ValueId};
use serde::Serialize;

use crate::plan::{ExactInput, ExactInstr, ExactOutput, ExactPlan, Reg};

/// Output of [`compile`].
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CompiledExact {
    pub plan: ExactPlan,
    pub privacy: PrivacyReport,
}

#[derive(Clone, Copy)]
enum Val {
    Secret(Reg),
    Public(i128),
}

struct Emitter {
    instrs: Vec<ExactInstr>,
    elems: Vec<Elem>,
    trivial: HashMap<(Elem, i128), Reg>,
}

impl Emitter {
    fn push(&mut self, i: ExactInstr, elem: Elem) -> Reg {
        self.instrs.push(i);
        self.elems.push(elem);
        (self.instrs.len() - 1) as Reg
    }

    /// A public value as a register (deduplicated).
    fn reg(&mut self, v: Val, elem: Elem) -> Reg {
        match v {
            Val::Secret(r) => r,
            Val::Public(c) => {
                if let Some(&r) = self.trivial.get(&(elem, c)) {
                    return r;
                }
                let r = self.push(ExactInstr::Trivial { value: c }, elem);
                self.trivial.insert((elem, c), r);
                r
            }
        }
    }
}

fn flip(op: CmpOp) -> CmpOp {
    match op {
        CmpOp::Lt => CmpOp::Gt,
        CmpOp::Le => CmpOp::Ge,
        CmpOp::Gt => CmpOp::Lt,
        CmpOp::Ge => CmpOp::Le,
        o => o,
    }
}

/// Lower an exact program to an exact plan. Fails with ENC1303 if any
/// operation may overflow (checked arithmetic).
pub fn compile(program: &Program) -> Result<CompiledExact> {
    if semantics(program)? != Semantics::Exact {
        return Err(Error::new(
            Code::Type,
            "program uses approximate (float) values; TFHE handles exact integer/bool programs. \
             Use scheme \"auto\" or \"approx\"",
        ));
    }
    int_ranges(program)?;
    let live = program.live();
    let mut e = Emitter {
        instrs: vec![],
        elems: vec![],
        trivial: HashMap::new(),
    };
    let mut inputs = vec![];
    let mut vals: Vec<Option<Val>> = vec![None; program.nodes().len()];
    for (id, node) in program.iter() {
        let is_input = matches!(node.op, Op::Input { .. });
        if !live[id.index()] && !is_input {
            continue;
        }
        let elem = node.ty.elem;
        let get = |v: ValueId| vals[v.index()].expect("operands precede users");
        let sec = |v: Val| match v {
            Val::Secret(r) => r,
            Val::Public(_) => unreachable!("builder rejects public-only ops"),
        };
        let v = match &node.op {
            Op::Input { name, .. } => {
                inputs.push(ExactInput {
                    name: name.clone(),
                    elem,
                });
                Val::Secret(e.push(
                    ExactInstr::Input {
                        index: inputs.len() - 1,
                    },
                    elem,
                ))
            }
            Op::Const { data } => Val::Public(data[0] as i128),
            Op::Add(a, b) | Op::Mul(a, b) => {
                let mul = matches!(node.op, Op::Mul(..));
                Val::Secret(match (get(*a), get(*b)) {
                    (Val::Secret(x), Val::Secret(y)) => e.push(
                        if mul {
                            ExactInstr::Mul(x, y)
                        } else {
                            ExactInstr::Add(x, y)
                        },
                        elem,
                    ),
                    (Val::Secret(x), Val::Public(c)) | (Val::Public(c), Val::Secret(x)) => e.push(
                        if mul {
                            ExactInstr::MulScalar(x, c)
                        } else {
                            ExactInstr::AddScalar(x, c)
                        },
                        elem,
                    ),
                    _ => unreachable!(),
                })
            }
            Op::Sub(a, b) => Val::Secret(match (get(*a), get(*b)) {
                (Val::Secret(x), Val::Secret(y)) => e.push(ExactInstr::Sub(x, y), elem),
                (Val::Secret(x), Val::Public(c)) => e.push(ExactInstr::SubScalar(x, c), elem),
                (Val::Public(c), Val::Secret(y)) => e.push(ExactInstr::ScalarSub(c, y), elem),
                _ => unreachable!(),
            }),
            Op::Neg(a) => Val::Secret(e.push(ExactInstr::Neg(sec(get(*a))), elem)),
            Op::Cmp(op, a, b) => Val::Secret(match (get(*a), get(*b)) {
                (Val::Secret(x), Val::Secret(y)) => e.push(ExactInstr::Cmp(*op, x, y), elem),
                (Val::Secret(x), Val::Public(c)) => e.push(ExactInstr::CmpScalar(*op, x, c), elem),
                (Val::Public(c), Val::Secret(y)) => {
                    e.push(ExactInstr::CmpScalar(flip(*op), y, c), elem)
                }
                _ => unreachable!(),
            }),
            Op::Logic(op, a, b) => {
                let (x, y) = (e.reg(get(*a), elem), e.reg(get(*b), elem));
                Val::Secret(e.push(ExactInstr::Logic(*op, x, y), elem))
            }
            Op::Not(a) => Val::Secret(e.push(ExactInstr::Not(sec(get(*a))), elem)),
            Op::Shift { x, left, by } => Val::Secret(e.push(
                ExactInstr::Shift {
                    x: sec(get(*x)),
                    left: *left,
                    by: *by,
                },
                elem,
            )),
            Op::Min(a, b) | Op::Max(a, b) => {
                let (x, y) = (e.reg(get(*a), elem), e.reg(get(*b), elem));
                let i = if matches!(node.op, Op::Min(..)) {
                    ExactInstr::Min(x, y)
                } else {
                    ExactInstr::Max(x, y)
                };
                Val::Secret(e.push(i, elem))
            }
            Op::Select(c, a, b) => {
                let c = sec(get(*c));
                let (x, y) = (e.reg(get(*a), elem), e.reg(get(*b), elem));
                Val::Secret(e.push(ExactInstr::Select(c, x, y), elem))
            }
            Op::Lookup { x, table } => Val::Secret(e.push(
                ExactInstr::Lookup {
                    x: sec(get(*x)),
                    table: table.iter().map(|v| *v as i128).collect(),
                },
                elem,
            )),
            Op::Cast(a) => Val::Secret(e.push(ExactInstr::Cast(sec(get(*a))), elem)),
            Op::Div(a, b) | Op::Rem(a, b) => {
                let (x, c) = match (get(*a), get(*b)) {
                    (Val::Secret(x), Val::Public(c)) => (x, c),
                    _ => unreachable!("builder requires a public divisor"),
                };
                let i = if matches!(node.op, Op::Div(..)) {
                    ExactInstr::DivScalar(x, c)
                } else {
                    ExactInstr::RemScalar(x, c)
                };
                Val::Secret(e.push(i, elem))
            }
            op => unreachable!("{} is approximate; rejected above", op.mnemonic()),
        };
        vals[id.index()] = Some(v);
    }
    let outputs = program
        .outputs()
        .iter()
        .map(|o| ExactOutput {
            name: o.name.clone(),
            reg: match vals[o.value.index()].unwrap() {
                Val::Secret(r) => r,
                Val::Public(_) => unreachable!("outputs are secret"),
            },
            elem: program.node(o.value).ty.elem,
        })
        .collect();
    Ok(CompiledExact {
        plan: ExactPlan {
            inputs,
            instrs: e.instrs,
            elems: e.elems,
            outputs,
        },
        privacy: privacy(program),
    })
}
