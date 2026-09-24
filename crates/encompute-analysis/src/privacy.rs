use std::collections::BTreeSet;

use encompute_ir::{Op, Program};
use serde::Serialize;

/// What each output depends on and what an evaluator can observe.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PrivacyReport {
    /// For each output, the secret inputs it depends on.
    pub outputs: Vec<OutputDeps>,
    /// Secret inputs that no output uses.
    pub unused_inputs: Vec<String>,
    /// Visible to the evaluator: program structure, public constants,
    /// input and output shapes. Never input or output values.
    pub evaluator_observes: Vec<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OutputDeps {
    pub name: String,
    pub depends_on: Vec<String>,
}

pub fn privacy(program: &Program) -> PrivacyReport {
    let mut deps: Vec<BTreeSet<String>> = Vec::with_capacity(program.nodes().len());
    for (_, node) in program.iter() {
        let mut d = BTreeSet::new();
        if let Op::Input { name, .. } = &node.op {
            d.insert(name.clone());
        }
        for o in node.op.operands() {
            d.extend(deps[o.index()].iter().cloned());
        }
        deps.push(d);
    }
    let outputs: Vec<OutputDeps> = program
        .outputs()
        .iter()
        .map(|o| OutputDeps {
            name: o.name.clone(),
            depends_on: deps[o.value.index()].iter().cloned().collect(),
        })
        .collect();
    let used: BTreeSet<&String> = outputs.iter().flat_map(|o| &o.depends_on).collect();
    let unused_inputs = program
        .inputs()
        .map(|(_, n, _, _)| n.to_owned())
        .filter(|n| !used.contains(n))
        .collect();
    PrivacyReport {
        outputs,
        unused_inputs,
        evaluator_observes: vec![
            "program structure (operations and their order)",
            "public constants (weights, coefficients)",
            "input and output shapes",
            "declared input ranges",
        ],
    }
}
