//! Adding evidence to the graph. Each `add_*` checks the evidence on the
//! way in (as far as it can without trust anchors) and then *links* it:
//! nodes, attributes and edges computed from the evidence alone. The
//! report re-links every piece of evidence into a fresh graph
//! ([`TrustGraph::rebuild`]), so a bundle's own edges and attributes are
//! never trusted: they are a cache the report checks.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use encompute_attestation::AttestationRecord;
use encompute_ir::{parse, Code, Error, Result};
use encompute_planner::{verify_plan, ConfidentialExecutionPlan};
use encompute_privacy::PrivacyReceipt;
use encompute_secagg::{
    aggregate_asset_id, verify_aggregation_receipt, AggregationReceipt, AggregationSpec,
    PartyIdentity,
};
use encompute_training::{SignedAdapterRecord, SignedWorkerEvidence, TrainingSpec};
use encompute_verification::{PolicyId, PrivacyPolicyId, SignedExecutionReceipt};

use crate::authz::{SignedAuthorization, SignedRevocation};
use crate::graph::{node_id, EdgeKind, Evidence, Node, NodeKind, TrustGraph};

fn graph_err(m: impl Into<String>) -> Error {
    Error::new(Code::TrustGraph, m)
}

fn node(kind: NodeKind, label: &str) -> Node {
    Node {
        kind,
        label: label.to_owned(),
        attrs: BTreeMap::new(),
        evidence: None,
    }
}

fn with(mut n: Node, attrs: &[(&str, String)]) -> Node {
    for (k, v) in attrs {
        n.attrs.insert((*k).to_owned(), v.clone());
    }
    n
}

/// The program ID of canonical `.eir` text.
pub fn program_id(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl TrustGraph {
    /// A program, its policies, parties and declared assets. Returns the
    /// program's node ID.
    pub fn add_program(&mut self, eir: &str) -> Result<String> {
        let text = parse(eir)?.to_string();
        self.link_program(&text)
    }

    fn link_program(&mut self, text: &str) -> Result<String> {
        let program = parse(text)?;
        let pid = program_id(text);
        let prog = node_id(NodeKind::Program, &pid);
        let mut pn = with(
            node(NodeKind::Program, program.name()),
            &[("program_id", pid.clone())],
        );
        pn.evidence = Some(Evidence::Program(text.to_owned()));
        let Some(c) = program.confidentiality() else {
            self.upsert(prog.clone(), pn)?;
            return Ok(prog);
        };
        if let Some(p) = &c.purpose {
            pn.attrs.insert("purpose".into(), p.clone());
        }
        self.upsert(prog.clone(), pn)?;
        let policy = PolicyId::of(c).hex();
        let pol = node_id(NodeKind::Policy, &policy);
        self.upsert(
            pol.clone(),
            node(NodeKind::Policy, &format!("encpolicy1:{}", &policy[..16])),
        )?;
        self.edge(&prog, EdgeKind::GovernedBy, &pol);
        if let Some(pp) = PrivacyPolicyId::of(c).map(|p| p.hex()) {
            let n = node_id(NodeKind::PrivacyPolicy, &pp);
            self.upsert(
                n.clone(),
                node(
                    NodeKind::PrivacyPolicy,
                    &format!("encprivacy1:{}", &pp[..16]),
                ),
            )?;
            self.edge(&prog, EdgeKind::GovernedBy, &n);
        }
        for p in &c.parties {
            self.upsert(
                node_id(NodeKind::Party, p.id.as_str()),
                node(NodeKind::Party, &p.name),
            )?;
        }
        for a in &c.assets {
            let id = node_id(NodeKind::Asset, &a.id);
            let mut attrs = vec![
                ("kind", a.kind.to_string()),
                ("release", a.policy.release.to_string()),
            ];
            if let Some(b) = &a.policy.privacy {
                attrs.push(("privacy_unit", b.unit.to_string()));
                attrs.push(("epsilon", format!("{:?}", b.epsilon)));
                attrs.push(("delta", format!("{:?}", b.delta)));
            }
            self.upsert(id.clone(), with(node(NodeKind::Asset, &a.id), &attrs))?;
            for o in &a.policy.owners {
                self.edge(&node_id(NodeKind::Party, o.as_str()), EdgeKind::Owns, &id);
            }
            self.edge(&id, EdgeKind::GovernedBy, &pol);
            if c.inputs.values().any(|x| x == &a.id) {
                self.edge(&prog, EdgeKind::Uses, &id);
            }
        }
        Ok(prog)
    }

    /// The parties' signing keys, for checks while building a bundle (the
    /// consortium's `parties.json`). The report never reads these: it
    /// checks signatures only against the keys its caller supplies.
    pub fn add_party_keys(&mut self, ids: &[PartyIdentity]) -> Result<()> {
        for p in ids {
            let id = node_id(NodeKind::Party, p.party.as_str());
            if !self.nodes.contains_key(&id) {
                return Err(graph_err(format!("party {} is not in the graph", p.party)));
            }
            self.upsert(
                id.clone(),
                with(
                    node(NodeKind::Party, ""),
                    &[("public_key", p.public_key.clone())],
                ),
            )
            .map_err(|_| graph_err(format!("party {} already has another key", p.party)))?;
        }
        Ok(())
    }

    fn party_key(&self, party: &str) -> Result<String> {
        self.node(&node_id(NodeKind::Party, party))
            .and_then(|n| n.attrs.get("public_key").cloned())
            .ok_or_else(|| {
                Error::new(
                    Code::TrustAuthorization,
                    format!("party {party} has no key in the graph"),
                )
            })
    }

    fn check_owner(&self, party: &str, asset: &str) -> Result<()> {
        if !self
            .into_(&node_id(NodeKind::Asset, asset), EdgeKind::Owns)
            .any(|p| p == node_id(NodeKind::Party, party))
        {
            return Err(Error::new(
                Code::TrustAuthorization,
                format!("{party} does not own {asset}"),
            ));
        }
        Ok(())
    }

    /// An owner's signed approval of a program for one of its assets.
    pub fn add_authorization(&mut self, a: SignedAuthorization) -> Result<String> {
        let b = &a.body;
        a.verify(&self.party_key(&b.party)?)?;
        self.check_owner(&b.party, &b.asset)?;
        if !self
            .nodes
            .contains_key(&node_id(NodeKind::Program, &b.program_id))
        {
            return Err(graph_err(
                "the authorization names a program not in the graph",
            ));
        }
        self.link_authorization(&a)
    }

    fn link_authorization(&mut self, a: &SignedAuthorization) -> Result<String> {
        let b = &a.body;
        let id = node_id(NodeKind::Authorization, &a.id()?);
        let mut n = node(
            NodeKind::Authorization,
            &format!("{} approves {}", b.party, b.asset),
        );
        n.evidence = Some(Evidence::Authorization(a.clone()));
        self.upsert(id.clone(), n)?;
        self.edge(&node_id(NodeKind::Party, &b.party), EdgeKind::Signed, &id);
        self.edge(
            &id,
            EdgeKind::Authorizes,
            &node_id(NodeKind::Program, &b.program_id),
        );
        self.edge(&id, EdgeKind::Covers, &node_id(NodeKind::Asset, &b.asset));
        Ok(id)
    }

    /// An owner's revocation of an asset (or of one authorization).
    pub fn add_revocation(&mut self, r: SignedRevocation) -> Result<String> {
        r.verify(&self.party_key(&r.body.party)?)?;
        self.check_owner(&r.body.party, &r.body.asset)?;
        self.link_revocation(&r)
    }

    fn link_revocation(&mut self, r: &SignedRevocation) -> Result<String> {
        let b = &r.body;
        let id = node_id(NodeKind::Revocation, &r.id()?);
        let mut n = node(
            NodeKind::Revocation,
            &format!("{} revokes {}", b.party, b.asset),
        );
        n.evidence = Some(Evidence::Revocation(r.clone()));
        self.upsert(id.clone(), n)?;
        self.edge(&node_id(NodeKind::Party, &b.party), EdgeKind::Signed, &id);
        self.edge(&id, EdgeKind::Revokes, &node_id(NodeKind::Asset, &b.asset));
        if let Some(a) = &b.authorization {
            // Authorizations link before revocations (see `rebuild`).
            let an = node_id(NodeKind::Authorization, a);
            if self.nodes.contains_key(&an) {
                self.edge(&id, EdgeKind::Revokes, &an);
            }
        }
        Ok(id)
    }

    /// An approved confidential execution plan, checked by the independent
    /// validator against the program already in the graph.
    pub fn add_plan(&mut self, plan: ConfidentialExecutionPlan) -> Result<String> {
        let program = match self
            .node(&node_id(NodeKind::Program, &plan.program_id))
            .and_then(|n| n.evidence.as_ref())
        {
            Some(Evidence::Program(t)) => parse(t)?,
            _ => return Err(graph_err("the plan is for a program not in the graph")),
        };
        verify_plan(&program, &plan)?;
        self.link_plan(&plan)
    }

    fn link_plan(&mut self, plan: &ConfidentialExecutionPlan) -> Result<String> {
        let id = node_id(NodeKind::Plan, &plan.id()?.hex());
        let mut n = with(
            node(
                NodeKind::Plan,
                &format!("plan ({} profile)", plan.context.profile.name()),
            ),
            &[("profile", plan.context.profile.name().to_owned())],
        );
        n.evidence = Some(Evidence::Plan(Box::new(plan.clone())));
        self.upsert(id.clone(), n)?;
        self.edge(
            &id,
            EdgeKind::Runs,
            &node_id(NodeKind::Program, &plan.program_id),
        );
        Ok(id)
    }

    /// A training specification (validated; the report checks it against
    /// the plan and the rounds).
    pub fn add_training_spec(&mut self, spec: TrainingSpec) -> Result<String> {
        spec.validate()?;
        if !self
            .nodes
            .contains_key(&node_id(NodeKind::Program, &spec.program_id))
        {
            return Err(graph_err("the training spec's program is not in the graph"));
        }
        self.link_training_spec(&spec)
    }

    fn link_training_spec(&mut self, spec: &TrainingSpec) -> Result<String> {
        let id = node_id(NodeKind::Training, &spec.id()?);
        let mut n = with(
            node(
                NodeKind::Training,
                &format!(
                    "{} fine-tuning of {}",
                    spec.config.method, spec.base_model.asset_id
                ),
            ),
            &[("project", spec.project.clone())],
        );
        n.evidence = Some(Evidence::TrainingSpec(Box::new(spec.clone())));
        self.upsert(id.clone(), n)?;
        self.edge(
            &id,
            EdgeKind::Runs,
            &node_id(NodeKind::Program, &spec.program_id),
        );
        self.edge(
            &id,
            EdgeKind::GovernedBy,
            &node_id(NodeKind::Plan, &spec.plan_id),
        );
        self.edge(
            &id,
            EdgeKind::Uses,
            &node_id(NodeKind::Asset, &spec.base_model.asset_id),
        );
        for d in &spec.datasets {
            self.edge(&id, EdgeKind::Uses, &node_id(NodeKind::Asset, &d.asset_id));
        }
        Ok(id)
    }

    /// An adapter produced by a training round, signed by the coordinator
    /// (the report requires a trusted coordinator key).
    /// A confidential training worker's evidence: it trained under a
    /// training spec, in an attested workload, on a model and a dataset,
    /// and produced a sealed output. The report checks it against the spec
    /// and the attestation.
    pub fn add_worker_evidence(&mut self, r: SignedWorkerEvidence) -> Result<String> {
        self.link_worker(&r)
    }

    fn link_worker(&mut self, r: &SignedWorkerEvidence) -> Result<String> {
        let e = &r.evidence;
        let id = node_id(NodeKind::Worker, &r.id()?);
        let mut n = with(
            node(
                NodeKind::Worker,
                &format!("{} training worker (round {})", e.participant, e.round),
            ),
            &[
                ("output_asset", e.output_asset.clone()),
                ("output_commitment", e.output_commitment.clone()),
                ("image_digest", e.image_digest.clone()),
            ],
        );
        n.evidence = Some(Evidence::TrainingWorker(Box::new(r.clone())));
        self.upsert(id.clone(), n)?;
        self.edge(
            &id,
            EdgeKind::GovernedBy,
            &node_id(NodeKind::Training, &e.training_spec_id),
        );
        self.edge(
            &id,
            EdgeKind::AttestedBy,
            &node_id(NodeKind::Attestation, &e.attestation_record_id),
        );
        self.edge(
            &id,
            EdgeKind::Uses,
            &node_id(NodeKind::Asset, &e.model_asset),
        );
        self.edge(
            &id,
            EdgeKind::Uses,
            &node_id(NodeKind::Asset, &e.dataset_asset),
        );
        Ok(id)
    }

    pub fn add_adapter(&mut self, r: SignedAdapterRecord) -> Result<String> {
        r.verify(None)?;
        self.link_adapter(&r)
    }

    fn link_adapter(&mut self, r: &SignedAdapterRecord) -> Result<String> {
        let a = &r.record;
        let id = node_id(NodeKind::Adapter, &a.adapter_id);
        let mut n = with(
            node(
                NodeKind::Adapter,
                &format!("{} (round {})", a.adapter_id, a.round),
            ),
            &[("adapter_digest", a.adapter_digest.clone())],
        );
        n.evidence = Some(Evidence::Adapter(Box::new(r.clone())));
        self.upsert(id.clone(), n)?;
        self.edge(
            &id,
            EdgeKind::GovernedBy,
            &node_id(NodeKind::Training, &a.training_spec_id),
        );
        self.edge(
            &id,
            EdgeKind::DerivedFrom,
            &node_id(
                NodeKind::Aggregate,
                &aggregate_asset_id(&a.aggregation_receipt_id, &a.aggregation_output),
            ),
        );
        self.edge(
            &id,
            EdgeKind::DerivedFrom,
            &node_id(NodeKind::Asset, &a.base_model),
        );
        for d in &a.datasets {
            self.edge(&id, EdgeKind::DerivedFrom, &node_id(NodeKind::Asset, d));
        }
        if let Some(p) = &a.previous {
            self.edge(&id, EdgeKind::DerivedFrom, &node_id(NodeKind::Adapter, p));
        }
        Ok(id)
    }

    /// An aggregation spec: the plan (program, policies, codec, mechanism)
    /// and the parties' keys.
    pub fn add_aggregation_spec(&mut self, spec: AggregationSpec) -> Result<String> {
        spec.validate()?;
        if !self
            .nodes
            .contains_key(&node_id(NodeKind::Program, &spec.plan.program_id))
        {
            return Err(graph_err(
                "the aggregation spec runs a program not in the graph",
            ));
        }
        self.add_party_keys(&spec.parties)?;
        self.link_aggregation_spec(&spec)
    }

    fn link_aggregation_spec(&mut self, spec: &AggregationSpec) -> Result<String> {
        let id = node_id(NodeKind::AggregationSpec, &spec.id()?);
        let mut n = with(
            node(
                NodeKind::AggregationSpec,
                &format!("aggregate {}", spec.plan.output),
            ),
            &[
                ("minimum", spec.plan.minimum.to_string()),
                ("threshold", spec.threshold.to_string()),
            ],
        );
        n.evidence = Some(Evidence::AggregationSpec(Box::new(spec.clone())));
        self.upsert(id.clone(), n)?;
        self.edge(
            &id,
            EdgeKind::Runs,
            &node_id(NodeKind::Program, &spec.plan.program_id),
        );
        if let Some(p) = &spec.plan.execution_plan_id {
            self.edge(&id, EdgeKind::GovernedBy, &node_id(NodeKind::Plan, p));
        }
        Ok(id)
    }

    pub(crate) fn spec(&self, spec_id: &str) -> Option<&AggregationSpec> {
        match self
            .node(&node_id(NodeKind::AggregationSpec, spec_id))?
            .evidence
            .as_ref()?
        {
            Evidence::AggregationSpec(s) => Some(s),
            _ => None,
        }
    }

    /// A finished aggregation round: verified against its spec, then
    /// added with the aggregate it released, its lineage and its privacy
    /// releases.
    pub fn add_aggregation(&mut self, receipt: AggregationReceipt) -> Result<String> {
        let m = &receipt.manifest;
        let spec = self
            .spec(&m.spec_id)
            .ok_or_else(|| {
                graph_err(format!(
                    "aggregation spec {} is not in the graph",
                    m.spec_id
                ))
            })?
            .clone();
        verify_aggregation_receipt(&receipt, &spec, None, None)?;
        for pr in &m.privacy {
            encompute_privacy::verify_privacy_receipt(
                pr,
                Some(&receipt.coordinator_key),
                None,
                None,
            )?;
        }
        self.link_aggregation(&receipt)
    }

    fn link_aggregation(&mut self, receipt: &AggregationReceipt) -> Result<String> {
        let m = &receipt.manifest;
        let round = node_id(NodeKind::AggregationRound, &m.round_id);
        let receipt_id = receipt.id()?;
        let agg = node_id(
            NodeKind::Aggregate,
            &aggregate_asset_id(&receipt_id, &m.output),
        );
        let mut rn = with(
            node(
                NodeKind::AggregationRound,
                &format!("round {}", m.round.sequence),
            ),
            &[
                ("sequence", m.round.sequence.to_string()),
                ("opened_at", m.round.opened_at.to_string()),
                ("coordinator_key", receipt.coordinator_key.clone()),
                ("contributors", m.contributors.len().to_string()),
            ],
        );
        rn.evidence = Some(Evidence::AggregationReceipt(Box::new(receipt.clone())));
        self.upsert(round.clone(), rn)?;
        self.edge(
            &round,
            EdgeKind::GovernedBy,
            &node_id(NodeKind::AggregationSpec, &m.spec_id),
        );
        self.upsert(
            agg.clone(),
            with(
                node(
                    NodeKind::Aggregate,
                    &format!("{} (round {})", m.output, m.round.sequence),
                ),
                &[("output", m.output.clone()), ("receipt_id", receipt_id)],
            ),
        )?;
        self.edge(&round, EdgeKind::Produced, &agg);
        for p in &m.contributors {
            self.edge(
                &node_id(NodeKind::Party, p.as_str()),
                EdgeKind::Contributed,
                &round,
            );
        }
        for parent in &m.parents {
            self.edge(
                &agg,
                EdgeKind::DerivedFrom,
                &node_id(NodeKind::Asset, parent),
            );
        }
        for aid in m.attestations.values() {
            let a = node_id(NodeKind::Attestation, aid);
            self.placeholder_attestation(&a)?;
            self.edge(&round, EdgeKind::AttestedBy, &a);
        }
        for pr in &m.privacy {
            let id = self.link_privacy_receipt(pr)?;
            self.edge(&agg, EdgeKind::ReleasedBy, &id);
        }
        Ok(round)
    }

    /// A privacy release on its own (not inside an aggregation receipt).
    /// Only its self-consistency is checked here; the report requires its
    /// signer to be a coordinator the caller trusts.
    pub fn add_privacy_receipt(&mut self, r: PrivacyReceipt) -> Result<String> {
        encompute_privacy::verify_privacy_receipt(&r, None, None, None)?;
        self.link_privacy_receipt(&r)
    }

    fn link_privacy_receipt(&mut self, r: &PrivacyReceipt) -> Result<String> {
        let id = node_id(NodeKind::PrivacyRelease, &r.event_id);
        let mut n = with(
            node(
                NodeKind::PrivacyRelease,
                &format!("{} spends {}", r.output, r.asset_id),
            ),
            &[
                ("epsilon_cost", r.epsilon_cost.clone()),
                ("cumulative_epsilon", r.cumulative_epsilon.clone()),
                ("ledger_seq", r.ledger_seq.to_string()),
            ],
        );
        n.evidence = Some(Evidence::PrivacyReceipt(Box::new(r.clone())));
        self.upsert(id.clone(), n)?;
        self.edge(
            &id,
            EdgeKind::ChargedTo,
            &node_id(NodeKind::Asset, &r.asset_id),
        );
        Ok(id)
    }

    fn placeholder_attestation(&mut self, id: &str) -> Result<()> {
        if !self.nodes.contains_key(id) {
            self.upsert(
                id.to_owned(),
                node(NodeKind::Attestation, "attestation (record not added)"),
            )?;
        }
        Ok(())
    }

    /// An attestation record (checked by the report against a policy).
    pub fn add_attestation(&mut self, record: AttestationRecord) -> Result<String> {
        self.link_attestation(&record)
    }

    fn link_attestation(&mut self, record: &AttestationRecord) -> Result<String> {
        let id = node_id(NodeKind::Attestation, &record.id()?);
        let b = &record.evidence.binding;
        let mut n = with(
            node(
                NodeKind::Attestation,
                &format!("{} workload", record.evidence.provider),
            ),
            &[
                ("provider", record.evidence.provider.clone()),
                ("evaluator_key", b.evaluator_public_key.clone()),
            ],
        );
        n.evidence = Some(Evidence::Attestation(Box::new(record.clone())));
        // A placeholder from a receipt gains its record.
        if let Some(existing) = self.nodes.get_mut(&id) {
            if existing.evidence.is_none() {
                *existing = n;
                return Ok(id);
            }
        }
        self.upsert(id.clone(), n)?;
        Ok(id)
    }

    /// An execution receipt (its signature checked against its own key; the
    /// report requires that key to be trusted or attested).
    pub fn add_execution_receipt(&mut self, r: SignedExecutionReceipt) -> Result<String> {
        let own = encompute_verification::EvaluatorIdentity::from_public_key_hex(
            &r.evaluator_public_key,
        )?;
        r.verify_signature(&own)?;
        self.link_execution_receipt(&r)
    }

    fn link_execution_receipt(&mut self, r: &SignedExecutionReceipt) -> Result<String> {
        let e = &r.receipt;
        let id = node_id(NodeKind::Execution, &e.execution_id);
        let mut n = with(
            node(
                NodeKind::Execution,
                &format!(
                    "execution {}",
                    e.execution_id.get(..8).unwrap_or(&e.execution_id)
                ),
            ),
            &[
                ("spec_id", e.spec_id.clone()),
                ("evaluator_key", r.evaluator_public_key.clone()),
            ],
        );
        n.evidence = Some(Evidence::ExecutionReceipt(Box::new(r.clone())));
        self.upsert(id.clone(), n)?;
        self.edge(
            &id,
            EdgeKind::Runs,
            &node_id(NodeKind::Program, &e.program_id),
        );
        if let Some(a) = &e.attestation {
            let a = node_id(NodeKind::Attestation, &a.attestation_id);
            self.placeholder_attestation(&a)?;
            self.edge(&id, EdgeKind::AttestedBy, &a);
        }
        Ok(id)
    }

    /// The graph as its evidence alone implies it: every piece of evidence
    /// re-linked into a fresh graph, in dependency order. Edges, nodes and
    /// attributes the bundle carries but the evidence does not imply are
    /// absent here. Returns the graph and the evidence that failed to link.
    pub fn rebuild(&self) -> (TrustGraph, Vec<String>) {
        let mut g = TrustGraph::new();
        let mut problems = vec![];
        let order = |e: &Evidence| match e {
            Evidence::Program(_) => 0,
            Evidence::Plan(_) => 0,
            Evidence::TrainingSpec(_) => 1,
            Evidence::Adapter(_) => 8,
            Evidence::TrainingWorker(_) => 8,
            Evidence::AggregationSpec(_) => 1,
            Evidence::Attestation(_) => 2,
            Evidence::Authorization(_) => 3,
            Evidence::Revocation(_) => 4,
            Evidence::AggregationReceipt(_) => 5,
            Evidence::PrivacyReceipt(_) => 6,
            Evidence::ExecutionReceipt(_) => 7,
        };
        let mut items: Vec<(&String, &Evidence)> = self
            .nodes
            .iter()
            .filter_map(|(id, n)| n.evidence.as_ref().map(|e| (id, e)))
            .collect();
        items.sort_by_key(|(id, e)| (order(e), (*id).clone()));
        for (id, e) in items {
            let linked = match e {
                Evidence::Program(t) => g.link_program(t),
                Evidence::Plan(p) => g.link_plan(p),
                Evidence::TrainingSpec(s) => g.link_training_spec(s),
                Evidence::Adapter(r) => g.link_adapter(r),
                Evidence::TrainingWorker(r) => g.link_worker(r),
                Evidence::AggregationSpec(s) => g.link_aggregation_spec(s),
                Evidence::Attestation(a) => g.link_attestation(a),
                Evidence::Authorization(a) => g.link_authorization(a),
                Evidence::Revocation(r) => g.link_revocation(r),
                Evidence::AggregationReceipt(r) => g.link_aggregation(r),
                Evidence::PrivacyReceipt(r) => g.link_privacy_receipt(r),
                Evidence::ExecutionReceipt(r) => g.link_execution_receipt(r),
            };
            match linked {
                Ok(at) if at != *id => {
                    problems.push(format!("{id}: its evidence identifies it as {at}"))
                }
                Ok(_) => {}
                Err(e) => problems.push(format!("{id}: {}", e.message)),
            }
        }
        (g, problems)
    }
}
