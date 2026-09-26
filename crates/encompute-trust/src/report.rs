//! The trust report: one answer to "can I trust what happened?", from every
//! piece of evidence in the graph.
//!
//! The report trusts nothing the bundle says about itself. It rebuilds the
//! graph from the evidence alone (a bundle's edges and attributes are only
//! a cache, and any difference fails the report), and it checks every
//! signature against keys its *caller* supplies ([`Anchors`]): the
//! consortium's party keys, and the coordinators and evaluators the caller
//! trusts, obtained out of band. Evidence it cannot check against an anchor
//! is reported as present but unchecked, and then the requirements are not
//! satisfied.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use encompute_attestation::{AttestationPolicy, Verifier};
use encompute_ir::{parse, Result};
use encompute_secagg::verify_aggregation_receipt;
use encompute_verification::{PolicyId, PrivacyPolicyId};

use encompute_planner::{verify_plan, Mechanism, Placement, Scheme, StepKind};
use encompute_verification::VerificationEvidence;

use crate::graph::{node_id, EdgeKind, Evidence, NodeKind, TrustGraph};
use crate::ingest::program_id;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Verified,
    Satisfied,
    Authorized,
    Attested,
    Complete,
    /// Present, but not checked against a trust anchor.
    Unchecked,
    NotPresent,
    Failed,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Status::Verified => "VERIFIED",
            Status::Satisfied => "SATISFIED",
            Status::Authorized => "AUTHORIZED",
            Status::Attested => "ATTESTED",
            Status::Complete => "COMPLETE",
            Status::Unchecked => "PRESENT (not checked)",
            Status::NotPresent => "NOT PRESENT",
            Status::Failed => "FAILED",
        })
    }
}

/// The report's rows, in order.
pub const ROWS: [&str; 10] = [
    "Evidence",
    "Program",
    "Policy",
    "Plan",
    "Owner authorization",
    "Workload",
    "Private aggregation",
    "Privacy budget",
    "Execution",
    "Lineage",
];

#[derive(Clone, Debug, Serialize)]
pub struct Row {
    pub name: &'static str,
    pub status: Status,
    pub details: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TrustReport {
    pub root: String,
    pub rows: Vec<Row>,
    /// Assets revoked, and what was derived from them (to retrain or
    /// unlearn).
    pub revoked: BTreeMap<String, BTreeSet<String>>,
    /// Why the requirements are not satisfied, if they are not.
    pub unmet: Vec<String>,
    pub satisfied: bool,
}

/// Keys the caller trusts, obtained out of band (never from the bundle).
#[derive(Clone, Debug, Default)]
pub struct Anchors {
    /// Party ID → Ed25519 public key (hex): the consortium's `parties.json`.
    pub parties: BTreeMap<String, String>,
    /// Aggregation coordinators' receipt-signing keys (hex).
    pub coordinators: BTreeSet<String>,
    /// Evaluators' receipt-signing keys (hex). An evaluator bound by an
    /// attestation that verifies needs no anchor.
    pub evaluators: BTreeSet<String>,
}

/// What the report may use to check the evidence.
#[derive(Default)]
pub struct ReportOptions<'a> {
    pub anchors: Anchors,
    pub verifier: Option<&'a Verifier>,
    /// A policy for execution workloads (aggregation specs carry their
    /// own).
    pub execution_policy: Option<&'a AttestationPolicy>,
    /// Rows (see [`ROWS`]) that must be present; "Program" always must.
    pub require: Vec<String>,
    /// Time for authorization expiry (default: now).
    pub now: Option<u64>,
}

/// Collects a row's problems and the evidence it could not anchor.
#[derive(Default)]
struct Tally {
    problems: Vec<String>,
    unchecked: Vec<String>,
    present: bool,
}

impl Tally {
    fn fail(&mut self, m: String) {
        self.problems.push(m);
    }

    fn unanchored(&mut self, m: String) {
        self.unchecked.push(m);
    }

    fn row(self, name: &'static str, ok: Status) -> Row {
        let (status, details) = if !self.problems.is_empty() {
            (Status::Failed, self.problems)
        } else if !self.unchecked.is_empty() {
            (Status::Unchecked, self.unchecked)
        } else if !self.present {
            (Status::NotPresent, vec![])
        } else {
            (ok, vec![])
        };
        Row {
            name,
            status,
            details,
        }
    }
}

/// A receipt's number: finite, or a problem.
fn finite(s: &str) -> Option<f64> {
    s.parse::<f64>().ok().filter(|x| x.is_finite())
}

impl TrustGraph {
    pub fn report(&self, opts: &ReportOptions<'_>) -> Result<TrustReport> {
        let now = opts.now.unwrap_or_else(encompute_attestation::unix_now);
        let a = &opts.anchors;
        let mut rows = vec![];

        // Evidence: the graph is exactly what its evidence implies.
        let (g, link_problems) = self.rebuild();
        let mut t = Tally {
            present: !self.nodes.is_empty(),
            ..Tally::default()
        };
        for p in link_problems {
            t.fail(p);
        }
        if let Err(e) = self.check_edges() {
            t.fail(e.message);
        }
        if let Err(e) = g.check_edges() {
            t.fail(format!(
                "the evidence refers to missing nodes: {}",
                e.message
            ));
        }
        for e in self.edges.difference(&g.edges) {
            t.fail(format!(
                "edge {} -{:?}-> {} is not backed by any evidence",
                e.from, e.kind, e.to
            ));
        }
        for e in g.edges.difference(&self.edges) {
            t.fail(format!(
                "edge {} -{:?}-> {} implied by the evidence is missing",
                e.from, e.kind, e.to
            ));
        }
        let (have, want): (BTreeSet<&String>, BTreeSet<&String>) =
            (self.nodes.keys().collect(), g.nodes.keys().collect());
        for n in have.difference(&want) {
            t.fail(format!("{n} is not backed by any evidence"));
        }
        for n in want.difference(&have) {
            t.fail(format!("{n}, implied by the evidence, is missing"));
        }
        for id in have.intersection(&want) {
            // Party keys are the one thing a bundle may carry beyond its
            // evidence (informational: the report never reads them).
            let mut mine = self.nodes[*id].clone();
            if mine.kind == NodeKind::Party {
                mine.attrs.remove("public_key");
            }
            if mine != g.nodes[*id] {
                t.fail(format!(
                    "{id}: its label or attributes contradict its evidence"
                ));
            }
        }
        rows.push(t.row("Evidence", Status::Verified));
        // From here on only the rebuilt graph is read.

        // Program and policies: the stored text reproduces every ID.
        let mut prog = Tally::default();
        let mut policy = Tally::default();
        // The bundle's own program nodes: each ID is its text's hash.
        for (id, n) in self.of(NodeKind::Program) {
            if let Some(Evidence::Program(text)) = &n.evidence {
                if node_id(NodeKind::Program, &program_id(text)) != *id {
                    prog.present = true;
                    prog.fail(format!("{id}: its text does not hash to its ID"));
                }
            }
        }
        let programs: Vec<_> = g.of(NodeKind::Program).collect();
        for (id, n) in &programs {
            prog.present = true;
            policy.present = true;
            let Some(Evidence::Program(text)) = &n.evidence else {
                prog.fail(format!("{id} has no program text"));
                continue;
            };
            if node_id(NodeKind::Program, &program_id(text)) != **id {
                prog.fail(format!("{id}: its text does not hash to its ID"));
                continue;
            }
            let p = match parse(text) {
                Ok(p) => p,
                Err(e) => {
                    prog.fail(format!("{id}: {e}"));
                    continue;
                }
            };
            if p.to_string() != *text {
                prog.fail(format!("{id}: its text is not canonical"));
            }
            if let Some(c) = p.confidentiality() {
                let want = node_id(NodeKind::Policy, &PolicyId::of(c).hex());
                if !g.out(id, EdgeKind::GovernedBy).any(|x| x == want) {
                    policy.fail(format!("{id} is not governed by its own policy"));
                }
                if let Some(pp) = PrivacyPolicyId::of(c) {
                    let want = node_id(NodeKind::PrivacyPolicy, &pp.hex());
                    if !g.out(id, EdgeKind::GovernedBy).any(|x| x == want) {
                        policy.fail(format!("{id} is not governed by its own privacy policy"));
                    }
                }
            }
        }
        rows.push(prog.row("Program", Status::Verified));
        rows.push(policy.row("Policy", Status::Verified));
        rows.push(plan_row(&g));

        // Revocations: asset → revoked at. An unanchored revocation is
        // still honoured (it can only withhold trust), but is unchecked.
        let mut auth = Tally::default();
        let mut revoked_at: BTreeMap<String, u64> = BTreeMap::new();
        let mut revoked_auth: BTreeSet<String> = BTreeSet::new();
        for (id, n) in g.of(NodeKind::Revocation) {
            let Some(Evidence::Revocation(r)) = &n.evidence else {
                continue;
            };
            match a.parties.get(&r.body.party) {
                Some(k) if r.verify(k).is_err() => {
                    auth.fail(format!("{id}: invalid revocation signature"));
                    continue;
                }
                Some(_) => {}
                None => auth.unanchored(format!(
                    "{id}: no trusted key for {} to check the revocation",
                    r.body.party
                )),
            }
            match &r.body.authorization {
                Some(x) => {
                    revoked_auth.insert(node_id(NodeKind::Authorization, x));
                }
                None => {
                    let at = revoked_at
                        .entry(node_id(NodeKind::Asset, &r.body.asset))
                        .or_insert(u64::MAX);
                    *at = (*at).min(r.body.issued_at);
                }
            }
        }

        // Authorizations: every asset a program uses has at least one
        // owner, and each owner approved this program, under its policies
        // and purpose, unexpired and unrevoked, with its trusted key.
        for (pid, pn) in &programs {
            let purpose = pn.attrs.get("purpose");
            let key = pid.trim_start_matches("program:");
            let policies: Vec<&str> = g.out(pid, EdgeKind::GovernedBy).collect();
            for asset in g.out(pid, EdgeKind::Uses) {
                auth.present = true;
                let owners: Vec<&str> = g.into_(asset, EdgeKind::Owns).collect();
                if owners.is_empty() {
                    auth.fail(format!("{asset} is used but has no owner"));
                }
                for owner in owners {
                    let party = owner.trim_start_matches("party:");
                    let Some(owner_key) = a.parties.get(party) else {
                        auth.unanchored(format!("no trusted key for {party}"));
                        continue;
                    };
                    let ok = g.into_(asset, EdgeKind::Covers).any(|x| {
                        let Some(Evidence::Authorization(s)) =
                            g.node(x).and_then(|n| n.evidence.as_ref())
                        else {
                            return false;
                        };
                        let b = &s.body;
                        s.verify(owner_key).is_ok()
                            && b.party == party
                            && b.program_id == key
                            && b.policy_id.as_ref().is_none_or(|p| {
                                policies.contains(&node_id(NodeKind::Policy, p).as_str())
                            })
                            && b.privacy_policy_id.as_ref().is_none_or(|p| {
                                policies.contains(&node_id(NodeKind::PrivacyPolicy, p).as_str())
                            })
                            && (b.purpose.is_none() || b.purpose.as_ref() == purpose)
                            && b.expires_at.is_none_or(|t| now < t)
                            && !revoked_auth.contains(x)
                            && revoked_at.get(asset).is_none_or(|t| b.issued_at > *t)
                    });
                    if !ok {
                        auth.fail(format!(
                            "{}: no valid authorization from {party} for {pid}",
                            asset.trim_start_matches("asset:"),
                        ));
                    }
                }
            }
        }
        rows.push(auth.row("Owner authorization", Status::Authorized));

        // Attestations: checked against the spec's policy (rounds) or the
        // execution policy. Keys they bind count as trusted evaluators.
        let mut att = Tally::default();
        let mut attested_keys: BTreeSet<String> = BTreeSet::new();
        for (id, n) in g.of(NodeKind::Attestation) {
            att.present = true;
            let Some(Evidence::Attestation(rec)) = &n.evidence else {
                att.fail(format!("{id}: record not in the bundle"));
                continue;
            };
            let spec_policy = g.into_(id, EdgeKind::AttestedBy).find_map(|r| {
                let spec = g.out(r, EdgeKind::GovernedBy).next()?;
                match g.node(spec)?.evidence.as_ref()? {
                    Evidence::AggregationSpec(s) => s.attestation.clone(),
                    _ => None,
                }
            });
            match (
                opts.verifier,
                spec_policy.as_ref().or(opts.execution_policy),
            ) {
                (Some(v), Some(p)) => match rec.verify(v, p) {
                    Ok(_) => {
                        attested_keys.insert(rec.evidence.binding.evaluator_public_key.clone());
                    }
                    Err(e) => att.fail(format!("{id}: {e}")),
                },
                _ => att.unanchored(format!("{id}: no verifier or policy to check it")),
            }
        }
        rows.push(att.row("Workload", Status::Attested));

        // Aggregation rounds: the receipt verifies against its spec, from a
        // trusted coordinator, and the spec's party keys are the trusted
        // ones.
        let mut agg = Tally::default();
        let rounds: Vec<_> = g.of(NodeKind::AggregationRound).collect();
        for (id, n) in &rounds {
            agg.present = true;
            let Some(Evidence::AggregationReceipt(r)) = &n.evidence else {
                agg.fail(format!("{id}: no receipt"));
                continue;
            };
            let Some(spec) = g.spec(&r.manifest.spec_id) else {
                agg.fail(format!("{id}: its spec is not in the bundle"));
                continue;
            };
            if let Err(e) = verify_aggregation_receipt(r, spec, None, None) {
                agg.fail(format!("{id}: {e}"));
            }
            if !a.coordinators.contains(&r.coordinator_key) {
                let m = format!("{id}: coordinator {} is not trusted", r.coordinator_key);
                if a.coordinators.is_empty() {
                    agg.unanchored(m);
                } else {
                    agg.fail(m);
                }
            }
            for p in &spec.parties {
                match a.parties.get(p.party.as_str()) {
                    Some(k) if *k != p.public_key => agg.fail(format!(
                        "{id}: its spec gives {} a key that is not the party's",
                        p.party
                    )),
                    Some(_) => {}
                    None => agg.unanchored(format!("no trusted key for {}", p.party)),
                }
            }
        }
        rows.push(agg.row("Private aggregation", Status::Verified));

        // Privacy: every receipt is signed by a trusted coordinator (the
        // round's own, for a round's releases) and, per asset, the spend
        // stays within the budget the program *declares* and only grows.
        let mut dp = Tally::default();
        let mut per_asset: BTreeMap<String, Vec<(u64, f64)>> = BTreeMap::new();
        for (id, n) in g.of(NodeKind::PrivacyRelease) {
            dp.present = true;
            let Some(Evidence::PrivacyReceipt(r)) = &n.evidence else {
                dp.fail(format!("{id}: no receipt"));
                continue;
            };
            let round_key = g
                .into_(id, EdgeKind::ReleasedBy)
                .find_map(|x| g.into_(x, EdgeKind::Produced).next())
                .and_then(|round| match g.node(round)?.evidence.as_ref()? {
                    Evidence::AggregationReceipt(rr) => Some(rr.coordinator_key.clone()),
                    _ => None,
                });
            if round_key.as_ref().is_some_and(|k| *k != r.signer_key) {
                dp.fail(format!("{id}: not signed by its round's coordinator"));
            }
            if !a.coordinators.contains(&r.signer_key) {
                let m = format!("{id}: signer {} is not a trusted coordinator", r.signer_key);
                if a.coordinators.is_empty() {
                    dp.unanchored(m);
                } else {
                    dp.fail(m);
                }
            }
            if let Err(e) =
                encompute_privacy::verify_privacy_receipt(r, Some(&r.signer_key), None, None)
            {
                dp.fail(format!("{id}: {e}"));
            }
            let asset = node_id(NodeKind::Asset, &r.asset_id);
            let declared = g.node(&asset).and_then(|n| {
                Some((
                    finite(n.attrs.get("epsilon")?)?,
                    finite(n.attrs.get("delta")?)?,
                ))
            });
            let Some((budget, delta)) = declared else {
                dp.fail(format!(
                    "{id}: spends {} whose budget no program declares",
                    r.asset_id
                ));
                continue;
            };
            let (Some(eps), Some(claimed), Some(d)) = (
                finite(&r.cumulative_epsilon),
                finite(&r.budget_epsilon),
                finite(&r.delta),
            ) else {
                dp.fail(format!("{id}: a non-finite or malformed epsilon or delta"));
                continue;
            };
            if claimed != budget || d != delta {
                dp.fail(format!(
                    "{id}: accounts against budget ({claimed}, {d}), but {} declares ({budget}, \
                     {delta})",
                    r.asset_id
                ));
            }
            if eps > budget {
                dp.fail(format!(
                    "{}: epsilon {eps} exceeds its declared budget {budget}",
                    r.asset_id
                ));
            }
            per_asset
                .entry(r.asset_id.clone())
                .or_default()
                .push((r.ledger_seq, eps));
        }
        for (asset, mut rs) in per_asset {
            rs.sort_by_key(|x| x.0);
            for w in rs.windows(2) {
                if w[0].0 == w[1].0 {
                    dp.fail(format!("{asset}: two releases at one ledger position"));
                } else if w[1].1 <= w[0].1 {
                    dp.fail(format!(
                        "{asset}: the spent budget did not grow (ledger rolled back)"
                    ));
                }
            }
        }
        rows.push(dp.row("Privacy budget", Status::Satisfied));

        // Executions: signed by a trusted or attested evaluator, and
        // consistent with the attestation they name.
        let mut ex = Tally::default();
        for (id, n) in g.of(NodeKind::Execution) {
            ex.present = true;
            let Some(Evidence::ExecutionReceipt(r)) = &n.evidence else {
                ex.fail(format!("{id}: no receipt"));
                continue;
            };
            let own = encompute_verification::EvaluatorIdentity::from_public_key_hex(
                &r.evaluator_public_key,
            );
            if own.and_then(|k| r.verify_signature(&k)).is_err() {
                ex.fail(format!("{id}: invalid receipt signature"));
            }
            for x in g.out(id, EdgeKind::AttestedBy) {
                if let Some(Evidence::Attestation(rec)) =
                    g.node(x).and_then(|n| n.evidence.as_ref())
                {
                    if rec.evidence.binding.evaluator_public_key != r.evaluator_public_key {
                        ex.fail(format!("{id}: its attestation binds another evaluator key"));
                    }
                    if rec.evidence.binding.execution_spec_id != r.receipt.spec_id {
                        ex.fail(format!(
                            "{id}: its attestation binds another execution spec"
                        ));
                    }
                }
            }
            if !a.evaluators.contains(&r.evaluator_public_key)
                && !attested_keys.contains(&r.evaluator_public_key)
            {
                ex.unanchored(format!(
                    "{id}: evaluator {} is neither trusted nor attested",
                    r.evaluator_public_key
                ));
            }
        }
        rows.push(ex.row("Execution", Status::Verified));

        // Lineage: aggregates derive from owned assets that their
        // contributors own; nothing revoked was used in a round opened (per
        // its signed receipt) after the revocation.
        let mut lin = Tally::default();
        for (id, _) in g.of(NodeKind::Aggregate) {
            lin.present = true;
            let round = g.into_(id, EdgeKind::Produced).next();
            let opened_at = round.and_then(|r| match g.node(r)?.evidence.as_ref()? {
                Evidence::AggregationReceipt(rr) => Some(rr.manifest.round.opened_at),
                _ => None,
            });
            let contributors: BTreeSet<&str> = round
                .map(|r| g.into_(r, EdgeKind::Contributed).collect())
                .unwrap_or_default();
            for parent in g.out(id, EdgeKind::DerivedFrom) {
                let owners: BTreeSet<&str> = g.into_(parent, EdgeKind::Owns).collect();
                if owners.is_empty() {
                    lin.fail(format!("{id}: parent {parent} has no owner"));
                } else if owners.is_disjoint(&contributors) {
                    lin.fail(format!("{id}: no contributor owns {parent}"));
                }
                match (revoked_at.get(parent), opened_at) {
                    (Some(at), Some(o)) if o >= *at => {
                        lin.fail(format!("{id}: used {parent} after it was revoked"))
                    }
                    (Some(_), None) => {
                        lin.fail(format!("{id}: no signed round time to order its use"))
                    }
                    _ => {}
                }
            }
        }
        rows.push(lin.row("Lineage", Status::Complete));

        // The result: nothing failed, nothing unchecked, and the required
        // rows present.
        let mut unmet = vec![];
        for r in &rows {
            match r.status {
                Status::Failed => unmet.push(format!("{} failed", r.name)),
                Status::Unchecked => unmet.push(format!(
                    "{} is not checked against trusted keys or policies",
                    r.name
                )),
                _ => {}
            }
        }
        let required = std::iter::once("Program").chain(opts.require.iter().map(String::as_str));
        for name in required {
            match rows.iter().find(|r| r.name == name) {
                None => unmet.push(format!("unknown required row {name}")),
                Some(r) if r.status == Status::NotPresent => {
                    unmet.push(format!("{name} is required but not present"))
                }
                _ => {}
            }
        }
        unmet.dedup();
        let revoked = revoked_at
            .keys()
            .map(|x| (x.clone(), g.downstream(x)))
            .collect();
        Ok(TrustReport {
            root: self.root()?,
            satisfied: unmet.is_empty(),
            rows,
            revoked,
            unmet,
        })
    }
}

/// The approved plans, and whether what was observed matches them: every
/// aggregation round under the plan's ID with its mechanisms, every
/// execution of the planned program with the planned scheme (and proof),
/// and evidence for every step. A round or execution of the planned
/// program outside the plan fails; a step without evidence yet is
/// unchecked.
fn plan_row(g: &TrustGraph) -> Row {
    let mut t = Tally::default();
    let plans: Vec<_> = g
        .of(NodeKind::Plan)
        .filter_map(|(id, n)| match &n.evidence {
            Some(Evidence::Plan(p)) => Some((id.clone(), p.as_ref())),
            _ => None,
        })
        .collect();
    for (id, plan) in &plans {
        t.present = true;
        let hex = id.trim_start_matches("plan:");
        let program = match g
            .node(&node_id(NodeKind::Program, &plan.program_id))
            .and_then(|n| n.evidence.as_ref())
        {
            Some(Evidence::Program(text)) => parse(text).ok(),
            _ => None,
        };
        match program {
            None => t.fail(format!("{id}: its program is not in the bundle")),
            Some(p) => {
                if let Err(e) = verify_plan(&p, plan) {
                    t.fail(format!("{id}: {}", e.message));
                    continue;
                }
            }
        }
        for step in &plan.steps {
            match &step.kind {
                StepKind::Aggregate { output } => {
                    let rounds: Vec<_> = g
                        .of(NodeKind::AggregationRound)
                        .filter_map(|(rid, n)| match &n.evidence {
                            Some(Evidence::AggregationReceipt(r)) => {
                                let spec = g.spec(&r.manifest.spec_id)?;
                                (spec.plan.program_id == plan.program_id
                                    && &spec.plan.output == output)
                                    .then_some((rid, spec))
                            }
                            _ => None,
                        })
                        .collect();
                    if rounds.is_empty() {
                        t.unanchored(format!("{}: no aggregation observed yet", step.id));
                    }
                    for (rid, spec) in rounds {
                        if spec.plan.execution_plan_id.as_deref() != Some(hex) {
                            t.fail(format!("{rid} did not run under the approved plan"));
                            continue;
                        }
                        for m in &step.mechanisms {
                            let ok = match m {
                                Mechanism::SecureAggregation {
                                    threshold,
                                    colluding,
                                } => {
                                    spec.threshold >= *threshold
                                        && spec.plan.colluding == *colluding
                                }
                                Mechanism::DifferentialPrivacy {
                                    noise_multiplier,
                                    clip_norm,
                                } => spec.plan.dp.as_ref().is_some_and(|d| {
                                    format!("{:?}", d.noise_multiplier) == *noise_multiplier
                                        && format!("{:?}", d.clip_norm) == *clip_norm
                                }),
                                Mechanism::Attestation { .. } => {
                                    spec.coordinator_attestation.is_some()
                                }
                                _ => true,
                            };
                            if !ok {
                                t.fail(format!(
                                    "{rid}: the round's spec does not provide {}",
                                    m.name()
                                ));
                            }
                        }
                    }
                }
                StepKind::Evaluate => {
                    let execs: Vec<_> = g
                        .of(NodeKind::Execution)
                        .filter_map(|(eid, n)| match &n.evidence {
                            Some(Evidence::ExecutionReceipt(r))
                                if r.receipt.program_id == plan.program_id =>
                            {
                                Some((eid, r))
                            }
                            _ => None,
                        })
                        .collect();
                    if execs.is_empty() {
                        t.unanchored(format!("{}: no execution observed yet", step.id));
                    }
                    for (eid, r) in execs {
                        let e = &r.receipt;
                        for m in &step.mechanisms {
                            let ok = match m {
                                Mechanism::Fhe { scheme, backend } => {
                                    e.backend == *backend
                                        && e.scheme
                                            == match scheme {
                                                Scheme::Ckks => "CKKS",
                                                Scheme::Tfhe => "TFHE",
                                                Scheme::Bgv => "BGV",
                                            }
                                }
                                Mechanism::VerifiedExecution => {
                                    matches!(e.evidence, VerificationEvidence::Vfhe { .. })
                                }
                                Mechanism::Attestation { .. }
                                | Mechanism::ConfidentialCompute { .. } => e.attestation.is_some(),
                                _ => true,
                            };
                            if !ok {
                                t.fail(format!("{eid} did not use {}", m.name()));
                            }
                        }
                        if step.mechanisms.is_empty() && step.placement != Placement::UntrustedHost
                        {
                            t.fail(format!("{eid} ran outside the planned placement"));
                        }
                    }
                }
                StepKind::Train { .. } => {
                    if matches!(step.placement, Placement::Tee(_))
                        && g.of(NodeKind::Attestation)
                            .all(|(_, n)| n.evidence.is_none())
                    {
                        t.unanchored(format!(
                            "{}: no attestation of the training workload observed yet",
                            step.id
                        ));
                    }
                }
            }
        }
    }
    // Rounds bound to a plan the bundle does not hold.
    for (rid, n) in g.of(NodeKind::AggregationRound) {
        if let Some(Evidence::AggregationReceipt(r)) = &n.evidence {
            if let Some(p) = g
                .spec(&r.manifest.spec_id)
                .and_then(|s| s.plan.execution_plan_id.as_ref())
            {
                if !plans
                    .iter()
                    .any(|(id, _)| id.trim_start_matches("plan:") == p)
                {
                    t.present = true;
                    t.fail(format!("{rid} claims plan {p}, which is not in the bundle"));
                }
            }
        }
    }
    t.row("Plan", Status::Satisfied)
}

impl fmt::Display for TrustReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "TRUST REPORT")?;
        writeln!(f, "bundle {}\n", &self.root[..16])?;
        for r in &self.rows {
            writeln!(f, "{:<24}{}", r.name, r.status)?;
            for d in &r.details {
                writeln!(f, "  - {d}")?;
            }
        }
        if !self.revoked.is_empty() {
            writeln!(f, "\nRevoked")?;
            for (a, down) in &self.revoked {
                let d: Vec<&str> = down.iter().map(String::as_str).collect();
                writeln!(
                    f,
                    "  {}: {}",
                    a.trim_start_matches("asset:"),
                    if d.is_empty() {
                        "nothing derived from it".to_owned()
                    } else {
                        format!("derived {} (retrain or unlearn)", d.join(", "))
                    }
                )?;
            }
        }
        if self.satisfied {
            writeln!(f, "\nRESULT\nTRUST REQUIREMENTS SATISFIED")?;
            if self
                .rows
                .iter()
                .any(|r| r.name == "Plan" && r.status == Status::Satisfied)
            {
                writeln!(f, "PLAN SATISFIED BY OBSERVED EXECUTION")?;
            }
            Ok(())
        } else {
            writeln!(f, "\nRESULT\nTRUST REQUIREMENTS NOT SATISFIED")?;
            for u in &self.unmet {
                writeln!(f, "  - {u}")?;
            }
            Ok(())
        }
    }
}
