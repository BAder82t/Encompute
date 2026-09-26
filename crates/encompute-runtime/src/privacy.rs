//! `encompute privacy`: the confidentiality graph of a program (ADR-010),
//! as text or Graphviz DOT, and stable asset IDs.

use std::fmt::Write as _;

use encompute_analysis::confidentiality::{analyze, AssetNode, Policy};
use encompute_ir::confidentiality::OutputRelease;
use encompute_ir::Result;
use sha2::{Digest, Sha256};

use crate::model::Model;

/// Stable asset-definition ID: SHA-256 over a domain tag, the program ID,
/// the node label and its canonical policy. Declared assets and derived
/// values of the same program always get the same IDs; runtime instances
/// (checkpoints, per-run updates) will need their own instance IDs.
pub fn asset_id(program_id: &str, node: &AssetNode) -> String {
    let policy = serde_json::to_string(&node.policy).expect("serializable");
    let mut h = Sha256::new();
    h.update(b"encompute.asset-definition.v1\0");
    h.update(program_id.as_bytes());
    h.update([0]);
    h.update(node.label.as_bytes());
    h.update([0]);
    h.update(policy.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn parties(p: &Policy) -> String {
    match &p.audience {
        None => "anyone".into(),
        Some(a) if a.is_empty() => "nobody".into(),
        Some(a) => a
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn label(n: &AssetNode) -> String {
    match n.label.split_once(':') {
        Some(("derived", v)) => format!("{} {v}", n.policy.kind),
        Some(("output", o)) => format!("output {o}"),
        Some(("aggregate", o)) => format!("aggregate {o} ({})", n.policy.kind),
        _ => n.label.clone(),
    }
}

/// What `rounds` releases would cost one budgeted asset.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct PrivacyPreview {
    pub output: String,
    pub asset: String,
    pub unit: String,
    /// `organization` (each party's whole contribution clipped) or
    /// `example` (DP-SGD: each privacy unit clipped and Poisson-sampled).
    pub level: String,
    pub sampling_rate: Option<f64>,
    pub accountant: String,
    pub rounds: u64,
    /// Epsilon after `rounds` releases, at the budget's delta.
    pub epsilon: f64,
    pub budget_epsilon: f64,
    pub delta: f64,
    /// How many releases the whole budget affords.
    pub affordable: u64,
    pub allowed: bool,
}

/// Renders previews as `encompute privacy explain --rounds` prints them.
pub fn render_preview(rows: &[PrivacyPreview]) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "PRIVACY PREVIEW");
    let _ = writeln!(s, "{}", "─".repeat(48));
    for r in rows {
        let _ = writeln!(s, "{:<24}{} ({})", "Asset", r.asset, r.output);
        let _ = writeln!(s, "{:<24}{}", "Privacy unit", r.unit);
        let _ = writeln!(
            s,
            "{:<24}{}",
            "Level",
            match r.sampling_rate {
                Some(q) => format!("example (DP-SGD, Poisson sampling {q})"),
                None => r.level.clone(),
            }
        );
        let _ = writeln!(s, "{:<24}{}", "Accountant", r.accountant);
        let _ = writeln!(s, "{:<24}{}", "Rounds", r.rounds);
        let _ = writeln!(
            s,
            "{:<24}epsilon {:.3} of {} (delta {:e})",
            "Projected", r.epsilon, r.budget_epsilon, r.delta
        );
        let _ = writeln!(s, "{:<24}{} rounds", "Budget affords", r.affordable);
        let _ = writeln!(
            s,
            "{:<24}{}\n",
            "RESULT",
            if r.allowed {
                "WITHIN BUDGET"
            } else {
                "DENIED BEFORE TRAINING (over budget)"
            }
        );
    }
    s
}

impl Model {
    /// What `rounds` releases of every privacy-budgeted output would cost
    /// each charged asset, before anything runs. Empty without budgets.
    pub fn privacy_projection(&self, rounds: u64) -> Result<Vec<PrivacyPreview>> {
        let p = self.program();
        let Some(r) = analyze(p)? else {
            return Ok(vec![]);
        };
        let mut out = vec![];
        for rel in &r.privacy_releases {
            let m = &rel.mechanism;
            let Some(bd) = r.aggregations.iter().find(|b| b.output == rel.output) else {
                continue;
            };
            for (asset, b) in &rel.charged {
                let spec = encompute_privacy::ReleaseSpec {
                    round_id: String::new(),
                    output: rel.output.clone(),
                    policy_id: None,
                    privacy_policy_id: String::new(),
                    execution_spec_id: None,
                    mechanism: m.clone(),
                    codec: bd.codec,
                    vector_len: bd.vector_len,
                    charged: vec![],
                };
                let c = encompute_privacy::Charged {
                    asset_id: asset.clone(),
                    budget: b.clone(),
                };
                let rho = spec.rho(&c)?;
                let q = m.sampling_rate;
                let epsilon = match (rounds, q) {
                    (0, _) => 0.0,
                    (n, Some(_)) => encompute_privacy::rdp::epsilon(
                        &encompute_privacy::rdp::scaled(
                            &encompute_privacy::rdp::release_curve(rho, q),
                            n,
                        ),
                        b.delta,
                    ),
                    (n, None) => encompute_privacy::Cost::of(rho * n as f64, b)?.epsilon,
                };
                let affordable = encompute_privacy::ledger::affordable(rho, q, b)?;
                out.push(PrivacyPreview {
                    output: rel.output.clone(),
                    asset: asset.clone(),
                    unit: b.unit.to_string(),
                    level: match (q, &b.unit) {
                        (Some(_), _) => "example",
                        (None, encompute_ir::confidentiality::PrivacyUnit::Organization) => {
                            "organization"
                        }
                        (None, _) => "contribution (each party's whole contribution clipped)",
                    }
                    .into(),
                    sampling_rate: q,
                    accountant: if q.is_some() {
                        encompute_ir::confidentiality::SAMPLED_PRIVACY_ACCOUNTANT
                    } else {
                        encompute_ir::confidentiality::PRIVACY_ACCOUNTANT
                    }
                    .into(),
                    rounds,
                    epsilon,
                    budget_epsilon: b.epsilon,
                    delta: b.delta,
                    affordable,
                    allowed: rounds <= affordable,
                });
            }
        }
        Ok(out)
    }

    /// `encompute privacy explain`: parties, assets with their (derived)
    /// policies, flows and warnings. `None` without declarations.
    pub fn privacy_explain(&self) -> Result<Option<String>> {
        let p = self.program();
        let (Some(c), Some(r)) = (p.confidentiality(), analyze(p)?) else {
            return Ok(None);
        };
        let ids = self.ids();
        let mut s = String::new();
        let section = |s: &mut String, t: &str| {
            let _ = write!(s, "\n{t}\n{}\n", "─".repeat(48));
        };
        let _ = writeln!(s, "CONFIDENTIALITY GRAPH  {}", p.name());
        let _ = writeln!(
            s,
            "policy {}",
            format_args!(
                "encpolicy1:{}",
                ids.policy_id.as_deref().unwrap_or_default()
            )
        );
        if let Some(purpose) = &c.purpose {
            let _ = writeln!(s, "purpose {purpose}");
        }
        section(&mut s, "Parties");
        for party in &c.parties {
            let _ = writeln!(s, "  {:<22}{}", party.id, party.name);
        }
        section(&mut s, "Assets");
        for n in &r.nodes {
            let pol = &n.policy;
            let _ = writeln!(s, "  {}", label(n));
            let _ = writeln!(s, "    {:<14}{}", "kind", pol.kind);
            if n.label.contains(':') {
                let src: Vec<&str> = pol.sources.iter().map(String::as_str).collect();
                let _ = writeln!(s, "    {:<14}{}", "derived from", src.join(" + "));
            }
            let owners: Vec<String> = pol.owners.iter().map(ToString::to_string).collect();
            let _ = writeln!(s, "    {:<14}{}", "owners", owners.join(", "));
            let _ = writeln!(s, "    {:<14}{}", "may learn it", parties(pol));
            if let Some(purposes) = &pol.purposes {
                let v: Vec<&str> = purposes.iter().map(String::as_str).collect();
                let _ = writeln!(s, "    {:<14}{}", "purposes", v.join(", "));
            }
            let _ = writeln!(s, "    {:<14}{}", "release", pol.release);
            if let Some(b) = c.asset(&n.label).and_then(|a| a.policy.privacy.as_ref()) {
                let _ = writeln!(
                    s,
                    "    {:<14}{} (epsilon {} delta {:e})",
                    "privacy unit", b.unit, b.epsilon, b.delta
                );
            }
            match &n.destination {
                Some(OutputRelease::Sealed) => {
                    let _ = writeln!(s, "    {:<14}sealed (stays encrypted)", "goes to");
                }
                Some(OutputRelease::Party(to)) => {
                    let _ = writeln!(s, "    {:<14}{to}", "goes to");
                }
                Some(OutputRelease::Public) => {
                    let _ = writeln!(s, "    {:<14}public", "goes to");
                }
                None => {}
            }
        }
        section(&mut s, "Flows");
        // One entry per target: its sources and the operations between.
        let name = |l: &str| {
            r.nodes
                .iter()
                .find(|n| n.label == l)
                .map_or(l.to_owned(), label)
        };
        let mut targets: Vec<&str> = vec![];
        for f in &r.flows {
            if !targets.contains(&f.to.as_str()) {
                targets.push(&f.to);
            }
        }
        for t in targets {
            let flows: Vec<_> = r.flows.iter().filter(|f| f.to == t).collect();
            let from: Vec<String> = flows.iter().map(|f| name(&f.from)).collect();
            let mut ops: Vec<&str> = flows.iter().flat_map(|f| f.ops.iter().copied()).collect();
            ops.sort_unstable();
            ops.dedup();
            let via = if ops.is_empty() {
                "(as is)".to_owned()
            } else {
                ops.join(", ")
            };
            let _ = writeln!(s, "  {}\n     ↓ {via}\n  {}\n", from.join(" + "), name(t));
        }
        for b in &r.aggregations {
            section(&mut s, &format!("Aggregation boundary  {}", b.output));
            let k = &b.codec;
            let parties: Vec<&str> = b.contributions.iter().map(|c| c.party.as_str()).collect();
            let row = |s: &mut String, k: &str, v: String| {
                let _ = writeln!(s, "  {k:<14}{v}");
            };
            row(
                &mut s,
                "POLICY",
                format!(
                    "{} contributions are {}",
                    b.contribution_policy.kind, b.contribution_policy.release
                ),
            );
            row(
                &mut s,
                "MECHANISM",
                format!(
                    "secure aggregation ({} v{})",
                    encompute_secagg::PROTOCOL,
                    encompute_secagg::PROTOCOL_VERSION
                ),
            );
            row(
                &mut s,
                "participants",
                format!("{} ({})", parties.join(", "), parties.len()),
            );
            row(&mut s, "minimum", b.minimum.to_string());
            row(
                &mut s,
                "collusion",
                format!(
                    "private against the coordinator plus {} colluding part{} (threshold {}, \
                     tolerates {} dropout{})",
                    b.colluding,
                    if b.colluding == 1 { "y" } else { "ies" },
                    b.threshold,
                    parties.len() - b.threshold,
                    if parties.len() - b.threshold == 1 {
                        ""
                    } else {
                        "s"
                    }
                ),
            );
            row(&mut s, "function", b.function.name().to_string());
            row(&mut s, "vector", format!("{} values", b.vector_len));
            row(
                &mut s,
                "encoding",
                format!(
                    "fixed point: clip [{}, {}], scale {}, modulus 2^{}",
                    k.clip_min, k.clip_max, k.scale, k.modulus_bits
                ),
            );
            row(
                &mut s,
                "overflow",
                format!(
                    "max aggregate {} < 2^{} (checked)",
                    k.max_aggregate(parties.len()),
                    k.modulus_bits
                ),
            );
            row(
                &mut s,
                "rounding",
                format!(
                    "±{:e} per value; values outside the clip range are clipped",
                    k.resolution()
                ),
            );
            let to = match &b.recipient {
                OutputRelease::Sealed => "sealed".to_owned(),
                OutputRelease::Party(p) => p.to_string(),
                OutputRelease::Public => "public".to_owned(),
            };
            row(&mut s, "aggregate to", to);
            let _ = writeln!(
                s,
                "  ✓ individual {}s never released",
                b.contribution_policy.kind
            );
            let _ = writeln!(
                s,
                "  ✓ output satisfies the {} requirement",
                b.contribution_policy.release
            );
            let _ = writeln!(s, "  {:<21}PROHIBITED", "individual release");
            let _ = writeln!(
                s,
                "  {:<21}PERMITTED (≥ {} contributions)",
                "aggregate release", b.minimum
            );
            let _ = writeln!(
                s,
                "  {:<21}ACTIVE (secure aggregation only; evaluators refuse this program)",
                "runtime enforcement"
            );
            row(&mut s, "STATUS", "SATISFIED".into());
        }
        for rel in &r.privacy_releases {
            section(&mut s, &format!("Differential privacy  {}", rel.output));
            let m = &rel.mechanism;
            let _ = writeln!(
                s,
                "  {:<21}{} (clip_norm {}, noise_multiplier {})",
                "mechanism",
                m.kind.name(),
                m.clip_norm,
                m.noise_multiplier
            );
            let boundary = r.aggregations.iter().find(|b| b.output == rel.output);
            for (asset, b) in &rel.charged {
                let per = boundary.map(|bd| {
                    let spec = encompute_privacy::ReleaseSpec {
                        round_id: String::new(),
                        output: rel.output.clone(),
                        policy_id: None,
                        privacy_policy_id: String::new(),
                        execution_spec_id: None,
                        mechanism: m.clone(),
                        codec: bd.codec,
                        vector_len: bd.vector_len,
                        charged: vec![],
                    };
                    let c = encompute_privacy::Charged {
                        asset_id: asset.clone(),
                        budget: b.clone(),
                    };
                    spec.rho(&c).and_then(|rho| {
                        let one = encompute_privacy::ledger::cost_of(&[(rho, m.sampling_rate)], b)?;
                        let n = encompute_privacy::ledger::affordable(rho, m.sampling_rate, b)?;
                        Ok((one.epsilon, n))
                    })
                });
                let _ = writeln!(
                    s,
                    "  {:<21}{asset}: privacy unit {}, epsilon {} delta {:e}{}",
                    "budget",
                    b.unit,
                    b.epsilon,
                    b.delta,
                    match per {
                        Some(Ok((e, n))) => {
                            format!(
                                ", one release costs epsilon {e:.3}; the budget affords {n} release{}",
                                if n == 1 { "" } else { "s" }
                            )
                        }
                        _ => String::new(),
                    }
                );
            }
            let _ = writeln!(
                s,
                "  {:<21}{}",
                "accounting",
                match m.sampling_rate {
                    Some(q) => format!(
                        "Rényi DP: Poisson subsampling at rate {q} (Zhu and Wang 2019), composed \
                         across releases; privacy unit clipped per example before summation"
                    ),
                    None => "zCDP, composed across releases (CKS 2020)".to_owned(),
                }
            );
            let _ = writeln!(
                s,
                "  {:<21}ACTIVE (a hash-chained ledger per asset; the coordinator and each owner refuse releases over budget)",
                "runtime enforcement"
            );
            let _ = writeln!(s, "  {:<21}SATISFIED", "STATUS");
        }
        section(&mut s, "Warnings");
        if r.warnings.is_empty() {
            let _ = writeln!(s, "  none");
        }
        for w in &r.warnings {
            let _ = writeln!(s, "  {w}");
        }
        let _ = writeln!(
            s,
            "\nThis is the policy the program declares and Encompute checked at compile time. \
             At run time, attested key release and secure aggregation \
             enforce it."
        );
        Ok(Some(s))
    }

    /// `encompute privacy graph --format dot`.
    pub fn privacy_dot(&self) -> Result<Option<String>> {
        let Some(r) = analyze(self.program())? else {
            return Ok(None);
        };
        let q = |s: &str| format!("\"{}\"", s.replace('"', "\\\""));
        let mut s = String::from("digraph confidentiality {\n  rankdir=TB;\n  node [shape=box];\n");
        for n in &r.nodes {
            let _ = writeln!(
                s,
                "  {} [label={}];",
                q(&n.label),
                q(&format!(
                    "{}\\nrelease {}\\nmay learn: {}",
                    label(n),
                    n.policy.release,
                    parties(&n.policy)
                ))
            );
        }
        for f in &r.flows {
            let _ = writeln!(
                s,
                "  {} -> {} [label={}];",
                q(&f.from),
                q(&f.to),
                q(&f.ops.join(", "))
            );
        }
        s.push_str("}\n");
        Ok(Some(s))
    }
}

impl Model {
    /// `explain --ledger`: what the next release of each DP aggregation
    /// would cost each budgeted asset, given the ledgers in `dir`.
    pub fn privacy_preview(&self, dir: &std::path::Path) -> Result<String> {
        let mut s = String::from("PROPOSED PRIVACY RELEASE\n");
        let Some(r) = analyze(self.program())? else {
            return Ok(s + "  (no privacy budgets)\n");
        };
        for b in &r.aggregations {
            let plan = self.aggregation_plan(Some(&b.output))?;
            let all: Vec<_> = plan.participants.iter().map(|p| p.party.clone()).collect();
            let Some(spec) = plan.release_spec("", None, &all)? else {
                continue;
            };
            let m = &spec.mechanism;
            let _ = writeln!(s, "\n{}", b.output);
            let _ = writeln!(
                s,
                "  {:<18}{} clip_norm {} noise_multiplier {}",
                "mechanism",
                m.kind.name(),
                m.clip_norm,
                m.noise_multiplier
            );
            for c in &spec.charged {
                let p = plan
                    .participants
                    .iter()
                    .find(|p| p.asset == c.asset_id)
                    .expect("plan");
                let view = plan.ledger_view(dir, p)?.expect("budgeted");
                let now = view.cost()?;
                let after = view.cost_after(spec.rho(c)?, spec.mechanism.sampling_rate)?;
                let ok = after.epsilon <= c.budget.epsilon;
                let _ = writeln!(
                    s,
                    "  {:<18}epsilon {:.3} now, {:.3} after, budget {} (delta {:e})  {}",
                    c.asset_id,
                    now.epsilon,
                    after.epsilon,
                    c.budget.epsilon,
                    c.budget.delta,
                    if ok {
                        "PERMITTED"
                    } else {
                        "DENIED: privacy budget exceeded"
                    }
                );
            }
        }
        Ok(s)
    }
}

/// `encompute privacy budget`: every ledger in `dir` (or one asset's).
pub fn privacy_budget_report(dir: &std::path::Path, asset: Option<&str>) -> Result<String> {
    let io = |e: std::io::Error| {
        encompute_ir::Error::new(
            encompute_ir::Code::PrivacyLedger,
            format!("{}: {e}", dir.display()),
        )
    };
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .map_err(io)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "ledger"))
        .collect();
    files.sort();
    let mut s = String::from("PRIVACY BUDGET\n");
    for f in files {
        let v = encompute_privacy::ledger::read(&f)?;
        let g = &v.genesis;
        if asset.is_some_and(|a| a != g.asset_id) {
            continue;
        }
        let cost = v.cost()?;
        let section = |s: &mut String, t: &str| {
            let _ = write!(s, "\n{t}\n{}\n", "─".repeat(40));
        };
        section(&mut s, &format!("Asset {}", g.asset_id));
        let _ = writeln!(s, "  {:<14}{}", "unit", g.budget.unit);
        let _ = writeln!(
            s,
            "  {:<14}encprivacy1:{}",
            "policy",
            &g.privacy_policy_id[..16]
        );
        let _ = writeln!(
            s,
            "  {:<14}epsilon {}  delta {:e}",
            "Budget", g.budget.epsilon, g.budget.delta
        );
        let _ = writeln!(
            s,
            "  {:<14}epsilon {:.3}  (rho {:.5})",
            "Consumed", cost.epsilon, cost.rho
        );
        let _ = writeln!(
            s,
            "  {:<14}epsilon {:.3}",
            "Remaining",
            (g.budget.epsilon - cost.epsilon).max(0.0)
        );
        let _ = writeln!(
            s,
            "  {:<14}{} (root {})",
            "Ledger",
            v.entries.len(),
            &v.root()?[..16]
        );
        let mut so_far = vec![];
        for e in &v.entries {
            if let encompute_privacy::PrivacyEvent::Reserve {
                round_id,
                mechanism,
                ..
            } = &e.event
            {
                let before = encompute_privacy::ledger::cost_of(&so_far, &g.budget)?.epsilon;
                so_far.push((e.event.rho()?, mechanism.sampling_rate));
                let after = encompute_privacy::ledger::cost_of(&so_far, &g.budget)?.epsilon;
                let committed = v.entries.iter().any(|c| matches!(&c.event,
                    encompute_privacy::PrivacyEvent::Commit { event_id, .. } if event_id == e.event.event_id()));
                let _ = writeln!(
                    s,
                    "  round {:<10}+{:.3}{}",
                    round_id.as_deref().map(|r| &r[..8]).unwrap_or("-"),
                    after - before,
                    if committed {
                        ""
                    } else {
                        "  (reserved; released output not recorded)"
                    }
                );
            }
        }
    }
    Ok(s)
}

impl Model {
    /// `privacy explain --ledger`: for each budgeted asset, the budget,
    /// what is spent and remains, and whether the next release is
    /// permitted.
    pub fn privacy_status(&self, dir: &std::path::Path) -> Result<String> {
        let mut s = String::from("PRIVACY BUDGETS\n");
        let Some(r) = analyze(self.program())? else {
            return Ok(s + "  (none)\n");
        };
        for b in &r.aggregations {
            let plan = self.aggregation_plan(Some(&b.output))?;
            let all: Vec<_> = plan.participants.iter().map(|p| p.party.clone()).collect();
            let Some(spec) = plan.release_spec("", None, &all)? else {
                continue;
            };
            for c in &spec.charged {
                let p = plan
                    .participants
                    .iter()
                    .find(|p| p.asset == c.asset_id)
                    .expect("plan");
                let view = plan.ledger_view(dir, p)?.expect("budgeted");
                let now = view.cost()?;
                let next = spec.rho(c)?;
                let after = view.cost_after(next, spec.mechanism.sampling_rate)?;
                let ok = after.epsilon <= c.budget.epsilon;
                let _ = write!(s, "\n{}\n{}\n", c.asset_id, "─".repeat(40));
                let row = |s: &mut String, k: &str, v: String| {
                    let _ = writeln!(s, "  {k:<22}{v}");
                };
                row(&mut s, "owner", p.party.to_string());
                row(&mut s, "unit", c.budget.unit.to_string());
                row(&mut s, "secure aggregation", "ACTIVE".into());
                row(&mut s, "differential privacy", "ACTIVE".into());
                row(
                    &mut s,
                    "budget",
                    format!(
                        "epsilon {:.3}  delta {:e}",
                        c.budget.epsilon, c.budget.delta
                    ),
                );
                row(&mut s, "consumed", format!("epsilon {:.3}", now.epsilon));
                row(
                    &mut s,
                    "remaining",
                    format!("epsilon {:.3}", (c.budget.epsilon - now.epsilon).max(0.0)),
                );
                row(
                    &mut s,
                    "next release",
                    format!(
                        "epsilon {:.3} (after: {:.3})",
                        after.epsilon - now.epsilon,
                        after.epsilon
                    ),
                );
                row(
                    &mut s,
                    "status",
                    if ok {
                        "PERMITTED".into()
                    } else {
                        "DENIED: privacy budget exceeded".into()
                    },
                );
            }
        }
        Ok(s)
    }
}
