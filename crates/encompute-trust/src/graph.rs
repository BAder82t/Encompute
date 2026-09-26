//! The trust graph: one content-addressed graph of everything a
//! collaboration's trust rests on. Nodes are parties, assets, programs,
//! policies, owner authorizations and revocations, aggregation specs and
//! rounds, released aggregates, privacy releases, attestations and
//! executions; edges say who owns what, what governs what, what was derived
//! from what, and what evidence backs it. Evidence (signed receipts and
//! records) travels inside the nodes, so a bundle can be checked offline.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use encompute_attestation::AttestationRecord;
use encompute_ir::{Code, Error, Result};
use encompute_planner::ConfidentialExecutionPlan;
use encompute_privacy::PrivacyReceipt;
use encompute_secagg::{AggregationReceipt, AggregationSpec};
use encompute_verification::canonical::canonical_json;
use encompute_verification::SignedExecutionReceipt;

use crate::authz::{SignedAuthorization, SignedRevocation};
use crate::tagged_hex;

pub const GRAPH_VERSION: u32 = 1;
const BUNDLE: &str = "encompute.trust-bundle.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Party,
    Asset,
    Program,
    Policy,
    PrivacyPolicy,
    Authorization,
    Revocation,
    AggregationSpec,
    AggregationRound,
    Aggregate,
    PrivacyRelease,
    Attestation,
    Execution,
    /// An approved confidential execution plan (ADR-015).
    Plan,
}

impl NodeKind {
    pub fn prefix(self) -> &'static str {
        match self {
            NodeKind::Party => "party",
            NodeKind::Asset => "asset",
            NodeKind::Program => "program",
            NodeKind::Policy => "policy",
            NodeKind::PrivacyPolicy => "privacy-policy",
            NodeKind::Authorization => "authorization",
            NodeKind::Revocation => "revocation",
            NodeKind::AggregationSpec => "spec",
            NodeKind::AggregationRound => "round",
            NodeKind::Aggregate => "aggregate",
            NodeKind::PrivacyRelease => "privacy",
            NodeKind::Attestation => "attestation",
            NodeKind::Execution => "execution",
            NodeKind::Plan => "plan",
        }
    }
}

/// `kind:key`, e.g. `asset:gradient-a`, `round:<hex>`.
pub fn node_id(kind: NodeKind, key: &str) -> String {
    format!("{}:{key}", kind.prefix())
}

/// The signed or content-addressed object behind a node.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Evidence {
    /// Canonical `.eir` text (its SHA-256 is the program ID).
    Program(String),
    Authorization(SignedAuthorization),
    Revocation(SignedRevocation),
    AggregationSpec(Box<AggregationSpec>),
    AggregationReceipt(Box<AggregationReceipt>),
    PrivacyReceipt(Box<PrivacyReceipt>),
    Attestation(Box<AttestationRecord>),
    ExecutionReceipt(Box<SignedExecutionReceipt>),
    Plan(Box<ConfidentialExecutionPlan>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub kind: NodeKind,
    pub label: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attrs: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// party → asset
    Owns,
    /// program/asset → policy, round → spec
    GovernedBy,
    /// program → asset (an input it reads)
    Uses,
    /// aggregate → asset it was derived from
    DerivedFrom,
    /// party → round it contributed to
    Contributed,
    /// round → aggregate it released
    Produced,
    /// privacy release → asset whose budget it spent
    ChargedTo,
    /// round/aggregate → privacy release that paid for it
    ReleasedBy,
    /// round/execution → attestation of the workload
    AttestedBy,
    /// party → authorization it signed; authorization → program/asset
    Signed,
    Authorizes,
    Covers,
    /// revocation → asset/authorization it revokes
    Revokes,
    /// spec/execution/plan → program it runs
    Runs,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub kind: EdgeKind,
    pub to: String,
}

/// Nodes and edges, content-addressed as a whole by [`TrustGraph::root`].
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustGraph {
    pub version: u32,
    pub nodes: BTreeMap<String, Node>,
    pub edges: BTreeSet<Edge>,
}

impl TrustGraph {
    pub fn new() -> Self {
        Self {
            version: GRAPH_VERSION,
            ..Self::default()
        }
    }

    /// `SHA256("encompute.trust-bundle.v1", canonical graph)`: changes with
    /// any node, edge or evidence.
    pub fn root(&self) -> Result<String> {
        Ok(tagged_hex(BUNDLE, &canonical_json(self)?))
    }

    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.get(id)
    }

    /// Nodes of one kind.
    pub fn of(&self, kind: NodeKind) -> impl Iterator<Item = (&String, &Node)> {
        self.nodes.iter().filter(move |(_, n)| n.kind == kind)
    }

    pub fn out<'a>(&'a self, from: &'a str, kind: EdgeKind) -> impl Iterator<Item = &'a str> + 'a {
        self.edges
            .iter()
            .filter(move |e| e.from == from && e.kind == kind)
            .map(|e| e.to.as_str())
    }

    pub fn into_<'a>(&'a self, to: &'a str, kind: EdgeKind) -> impl Iterator<Item = &'a str> + 'a {
        self.edges
            .iter()
            .filter(move |e| e.to == to && e.kind == kind)
            .map(|e| e.from.as_str())
    }

    /// Inserts a node; an existing node keeps its evidence and gains new
    /// attributes, but must not contradict them.
    pub(crate) fn upsert(&mut self, id: String, node: Node) -> Result<()> {
        match self.nodes.get_mut(&id) {
            None => {
                self.nodes.insert(id, node);
            }
            Some(n) => {
                if n.kind != node.kind {
                    return Err(Error::new(
                        Code::TrustGraph,
                        format!("{id} already exists as another kind"),
                    ));
                }
                for (k, v) in node.attrs {
                    match n.attrs.get(&k) {
                        Some(old) if old != &v => {
                            return Err(Error::new(
                                Code::TrustGraph,
                                format!("{id}: {k} is {old}, not {v}"),
                            ))
                        }
                        _ => {
                            n.attrs.insert(k, v);
                        }
                    }
                }
                if n.evidence.is_none() {
                    n.evidence = node.evidence;
                } else if node.evidence.is_some() && node.evidence != n.evidence {
                    return Err(Error::new(
                        Code::TrustGraph,
                        format!("{id} already has different evidence"),
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn edge(&mut self, from: &str, kind: EdgeKind, to: &str) {
        self.edges.insert(Edge {
            from: from.to_owned(),
            kind,
            to: to.to_owned(),
        });
    }

    /// Every edge joins two nodes that exist.
    pub fn check_edges(&self) -> Result<()> {
        for e in &self.edges {
            for end in [&e.from, &e.to] {
                if !self.nodes.contains_key(end) {
                    return Err(Error::new(
                        Code::TrustGraph,
                        format!("edge {:?} names a missing node {end}", e.kind),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let g: Self = serde_json::from_slice(b)
            .map_err(|e| Error::new(Code::TrustGraph, format!("malformed trust bundle: {e}")))?;
        if g.version != GRAPH_VERSION {
            return Err(Error::new(
                Code::TrustGraph,
                format!("trust bundle version {}", g.version),
            ));
        }
        Ok(g)
    }

    /// Transitively, the nodes `id` was derived from or uses (its inputs).
    pub fn upstream(&self, id: &str) -> BTreeSet<String> {
        self.walk(id, |g, n| {
            g.out(n, EdgeKind::DerivedFrom)
                .chain(g.out(n, EdgeKind::Uses))
                .map(str::to_owned)
                .collect()
        })
    }

    /// Transitively, the nodes derived from `id`.
    pub fn downstream(&self, id: &str) -> BTreeSet<String> {
        self.walk(id, |g, n| {
            g.into_(n, EdgeKind::DerivedFrom)
                .map(str::to_owned)
                .collect()
        })
    }

    fn walk(&self, id: &str, next: impl Fn(&Self, &str) -> Vec<String>) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![id.to_owned()];
        while let Some(n) = stack.pop() {
            for m in next(self, &n) {
                if seen.insert(m.clone()) {
                    stack.push(m);
                }
            }
        }
        seen
    }
}
