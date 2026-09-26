//! An adapter's lineage in words: its base model, training data, training
//! configuration, aggregation, privacy spend, history and the evidence
//! verdicts, all read from the signed evidence in the bundle.

use std::collections::BTreeMap;
use std::fmt::Write;

use encompute_ir::{parse, Code, Error, Result};
use encompute_training::TrainingSpec;

use crate::graph::{node_id, Evidence, NodeKind, TrustGraph};
use crate::report::TrustReport;

const RULE: &str = "────────────────────────";

fn spec_of<'a>(g: &'a TrustGraph, id: &str) -> Option<&'a TrainingSpec> {
    match g
        .node(&node_id(NodeKind::Training, id))?
        .evidence
        .as_ref()?
    {
        Evidence::TrainingSpec(s) => Some(s),
        _ => None,
    }
}

/// The training spec and program an adapter was produced under.
pub fn adapter_context(g: &TrustGraph, adapter: &str) -> Result<(TrainingSpec, String)> {
    let r = match g
        .node(&node_id(NodeKind::Adapter, adapter))
        .and_then(|n| n.evidence.as_ref())
    {
        Some(Evidence::Adapter(r)) => r,
        _ => {
            return Err(Error::new(
                Code::TrustGraph,
                format!("no adapter {adapter} in the bundle"),
            ))
        }
    };
    let spec = spec_of(g, &r.record.training_spec_id)
        .ok_or_else(|| Error::new(Code::TrustGraph, "the adapter's training spec is missing"))?
        .clone();
    let program = match g
        .node(&node_id(NodeKind::Program, &spec.program_id))
        .and_then(|n| n.evidence.as_ref())
    {
        Some(Evidence::Program(t)) => t.clone(),
        _ => {
            return Err(Error::new(
                Code::TrustGraph,
                "the training program is missing",
            ))
        }
    };
    Ok((spec, program))
}

pub fn adapter_lineage(g: &TrustGraph, adapter: &str, report: &TrustReport) -> Result<String> {
    let (spec, program) = adapter_context(g, adapter)?;
    let p = parse(&program)?;
    let c = p.confidentiality();
    let mut s = String::new();
    let _ = writeln!(s, "ADAPTER {adapter}\n");
    let _ = writeln!(
        s,
        "Base model\n{RULE}\n{} ({})\n",
        spec.base_model.asset_id, spec.base_model.owner
    );
    let _ = writeln!(s, "Training data\n{RULE}");
    for d in &spec.datasets {
        let _ = writeln!(s, "{} ({})", d.asset_id, d.owner);
    }
    // The adapter's history, from its signed records.
    let mut history = BTreeMap::new();
    for (_, n) in g.of(NodeKind::Adapter) {
        if let Some(Evidence::Adapter(r)) = &n.evidence {
            if r.record.training_spec_id == spec.id()? {
                history.insert(r.record.round, r.record.adapter_id.clone());
            }
        }
    }
    let _ = writeln!(s, "\nTraining\n{RULE}");
    let method = if spec.config.method == "lora" {
        "LoRA"
    } else {
        spec.config.method.as_str()
    };
    let _ = writeln!(s, "{:<17}{method}", "Method");
    let _ = writeln!(s, "{:<17}{}", "LoRA rank", spec.config.rank);
    let _ = writeln!(
        s,
        "{:<17}{}",
        "Target modules",
        spec.config.target_modules.join(", ")
    );
    let _ = writeln!(
        s,
        "{:<17}{} of {}",
        "Rounds",
        history.len(),
        spec.config.rounds
    );
    let _ = writeln!(s, "{:<17}enctrain1:{}", "Training spec", &spec.id()?[..16]);
    if let Some(agg) = g.spec(&spec.aggregation_spec_id) {
        let _ = writeln!(s, "\nAggregation\n{RULE}\nsecure aggregation");
        let _ = writeln!(s, "{:<17}{}", "minimum parties", agg.plan.minimum);
        let _ = writeln!(s, "{:<17}{}", "threshold", agg.threshold);
    }
    // Privacy: the latest cumulative spend per budgeted asset.
    let mut spent: BTreeMap<String, (u64, String)> = BTreeMap::new();
    for (_, n) in g.of(NodeKind::PrivacyRelease) {
        if let Some(Evidence::PrivacyReceipt(r)) = &n.evidence {
            let e = spent
                .entry(r.asset_id.clone())
                .or_insert((0, String::new()));
            if r.ledger_seq >= e.0 {
                *e = (r.ledger_seq, r.cumulative_epsilon.clone());
            }
        }
    }
    if !spent.is_empty() {
        let _ = writeln!(s, "\nPrivacy\n{RULE}");
        match &spec.config.dp_sgd {
            Some(d) => {
                let _ = writeln!(
                    s,
                    "{:<24}{} (DP-SGD: per-{} clip {}, Poisson sampling {}, noise {}, {})",
                    "privacy unit",
                    d.privacy_unit,
                    d.privacy_unit,
                    d.per_example_clip,
                    d.sampling_rate,
                    d.noise_multiplier,
                    d.accountant
                );
            }
            None => {
                let _ = writeln!(
                    s,
                    "{:<24}organization (each participant's whole update clipped)",
                    "privacy unit"
                );
            }
        }
        for (asset, (_, eps)) in &spent {
            let a = c.and_then(|c| c.asset(asset));
            let (unit, budget) = a
                .and_then(|a| a.policy.privacy.as_ref())
                .map(|b| (b.unit.to_string(), format!("{:.2}", b.epsilon)))
                .unwrap_or_default();
            let used: f64 = eps.parse().unwrap_or(f64::NAN);
            let _ = writeln!(s, "{asset:<24}{unit}-level DP, ε used {used:.2} / {budget}");
        }
    }
    let _ = writeln!(s, "\nAdapter history\n{RULE}");
    for (round, id) in &history {
        let _ = writeln!(s, "{id} ← round {round}");
    }
    let row = |name: &str| {
        report
            .rows
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.status.to_string())
            .unwrap_or_default()
    };
    let _ = writeln!(s, "\nEvidence\n{RULE}");
    for (label, name) in [
        ("attestation", "Workload"),
        ("aggregation", "Private aggregation"),
        ("privacy", "Privacy budget"),
        ("training", "Training"),
        ("lineage", "Lineage"),
    ] {
        let _ = writeln!(s, "{label:<17}{}", row(name));
    }
    Ok(s)
}
