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

impl Model {
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
             At run time, attested key release (ADR-011) and secure aggregation (ADR-012) \
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
