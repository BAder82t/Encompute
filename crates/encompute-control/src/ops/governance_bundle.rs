//! `GET /v1/jobs/{id}/governance-bundle?view=shared|org`: a governed job's
//! evidence bundle (ADR-027), assembled from what the control plane holds.
//!
//! The control plane only collects. Every part is signed by someone else
//! (the owners, the custodians, the evaluator, the control plane's own
//! grant and checkpoints) or is proven against a signed checkpoint, and the
//! reader verifies all of it locally against its own pins
//! (`encompute governance verify`): the answer of this route is never
//! shown as a verdict.
//!
//! - **Shared view** (`view=shared`, any member or auditor organization):
//!   the same bytes for each of them. Another organization's signed
//!   authorization names its approvers, so it appears as a card, with the
//!   approvers as per-project pseudonyms. No `key_ref`, storage location,
//!   broker key reference or raw principal ID is read here at all.
//! - **Organization view** (`view=org&organization=<id>`, a member of that
//!   organization): the shared view plus that organization's own signed
//!   authorizations. Never another organization's.
//!
//! `exported_at` is the time of the log state the bundle reflects (its
//! latest checkpoint, or the grant), not the time of the request, so two
//! members asking for the same state get the same BundleId.
//!
//! The reads happen in one read-only, repeatable-read snapshot and release
//! it before the bundle is assembled and checked, so a slow caller holds no
//! lock. The log is capped at [`MAX_BUNDLE_EVENTS`] events (ENC2730): a
//! partial log is never exported. A caller is rate limited.

use std::collections::BTreeMap;

use postgres::IsolationLevel;
use serde_json::Value;

use encompute_ir::{Code, Error, Result};
use encompute_trust::authz::{SignedAuthorizationV2, SignedPurposeAcceptance, SignedReleaseRecord};
use encompute_trust::govlog::{
    Partition, SignedCheckpointWitness, SignedProjectCheckpoint, SignedRevocationHead,
};
use encompute_trust::{
    AuditEntry, AuditEvidence, AuthorizationCard, AuthorizationEntry, GovernanceBundle,
    GovernanceEvidence, Provenance, SharedApproval, TrustGraph, GOVERNANCE_EVIDENCE_VERSION,
};
use encompute_verification::governance::Purpose;
use encompute_verification::SignedExecutionReceipt;

use super::*;
use crate::db::db_err;
use crate::govlog;
use crate::ops::tenancy::project_reader;

/// The most events of one project's log a bundle carries.
pub const MAX_BUNDLE_EVENTS: u64 = 5_000;

/// Requests per caller per minute for bundles (the dearest read there is:
/// the whole log with its proofs).
pub const BUNDLE_RATE: u32 = 12;

/// One of the few concurrent bundle builds the control plane allows.
struct BundleSlot<'a>(&'a std::sync::atomic::AtomicUsize);

/// How many bundles may be built at once.
pub const BUNDLE_SLOTS: usize = 4;

impl<'a> BundleSlot<'a> {
    fn take(n: &'a std::sync::atomic::AtomicUsize) -> Result<Self> {
        use std::sync::atomic::Ordering::SeqCst;
        if n.fetch_add(1, SeqCst) >= BUNDLE_SLOTS {
            n.fetch_sub(1, SeqCst);
            return Err(Error::new(
                Code::Scheduling,
                "too many governance bundles are being built: retry shortly",
            ));
        }
        Ok(Self(n))
    }
}

impl Drop for BundleSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

enum View {
    Shared,
    Organization(String),
}

impl View {
    fn name(&self) -> String {
        match self {
            View::Shared => "shared".into(),
            View::Organization(o) => format!("organization:{o}"),
        }
    }
}

/// Everything read in the snapshot.
struct Parts {
    job: JobRow,
    governance: JobGovernance,
    program_text: String,
    plan: encompute_planner::ConfidentialExecutionPlan,
    spec: encompute_verification::ExecutionSpec,
    receipt: Option<SignedExecutionReceipt>,
    purpose: Purpose,
    acceptances: Vec<SignedPurposeAcceptance>,
    /// (document, approvers' pseudonyms with role and time).
    authorizations: Vec<(SignedAuthorizationV2, Vec<SharedApproval>)>,
    release_records: Vec<SignedReleaseRecord>,
    submitter: String,
    checkpoint: Option<SignedProjectCheckpoint>,
    members: Vec<String>,
    witnesses: Vec<SignedCheckpointWitness>,
    events: Vec<AuditEntry>,
    heads: Vec<SignedRevocationHead>,
    head_leaves: std::collections::BTreeMap<String, Vec<String>>,
}

fn limit(m: impl Into<String>) -> Error {
    Error::new(Code::GovernanceBundleLimit, m)
}

impl Control {
    /// The governance bundle of governed job `id` as the caller may see it.
    pub fn governance_bundle(
        &self,
        ctx: &Ctx,
        id: &str,
        view: Option<&str>,
        organization: Option<&str>,
    ) -> Result<Value> {
        self.bundle_limit.hit(&ctx.principal.id)?;
        // At most a few bundles are built at once, whoever asks.
        let _slot = BundleSlot::take(&self.bundle_slots)?;
        let view = match (view.unwrap_or("shared"), organization) {
            ("shared", None) => View::Shared,
            ("shared", Some(_)) => return Err(bad("the shared view is for no organization")),
            ("org", Some(o)) => View::Organization(o.to_owned()),
            ("org", None) => return Err(bad("name your organization: view=org&organization=<id>")),
            _ => return Err(bad("view is `shared` or `org`")),
        };
        // 1. Read, in one snapshot, then let go of the connection.
        let parts = {
            let mut c = self.db.conn()?;
            let mut t = c
                .build_transaction()
                .isolation_level(IsolationLevel::RepeatableRead)
                .read_only(true)
                .start()
                .map_err(db_err)?;
            let p = self.read_bundle_parts(&mut t, ctx, id, &view)?;
            t.commit().map_err(db_err)?;
            p
        };
        // 2. Assemble and check, holding nothing.
        let bundle = self.assemble_bundle(parts, &view)?;
        serde_json::to_value(&bundle).map_err(|e| db_err(format!("bundle: {e}")))
    }

    fn read_bundle_parts(
        &self,
        t: &mut postgres::Transaction<'_>,
        ctx: &Ctx,
        id: &str,
        view: &View,
    ) -> Result<Parts> {
        let j = job_row(t, id, false)?.ok_or_else(|| not_found("job", id))?;
        job_visible(t, ctx, &j)?;
        // An evaluator sees its grant and nothing else of a governed job.
        if ctx.principal.service_kind() == Some(ServiceKind::Evaluator) {
            return Err(not_found("job", id));
        }
        let Some(g) = j.governance.clone() else {
            return Err(bad(
                "only a governed job has a governance bundle: this job runs in a standard project",
            ));
        };
        // The same readers as the project's audit: members and auditors.
        let project = project_reader(t, &ctx.principal, &j.project)?;
        if let View::Organization(o) = view {
            if !ctx.principal.member_of(o) {
                return Err(not_found("organization", o));
            }
            if !project
                .members
                .iter()
                .chain(&project.auditors)
                .any(|m| m == o)
            {
                return Err(not_found("organization", o));
            }
        }
        let grant = j.grant.clone().ok_or_else(|| {
            conflict(
                "the job has no grant yet (it was never scheduled): there is nothing to export",
            )
        })?;
        let _ = grant;
        let (program, _compiled, spec, doc) = self.load_plan(t, &j.plan)?;
        let spec = spec.governed(&g.binding);
        if spec.id().hex() != j.spec_id {
            return Err(conflict(
                "the job's spec ID does not match its plan's program",
            ));
        }
        let receipt: Option<SignedExecutionReceipt> = j
            .receipt
            .clone()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| db_err(format!("stored receipt: {e}")))?;
        let purpose_id = g.binding.purpose_id.clone();
        let purpose: Purpose = serde_json::from_value(
            t.query_opt(
                "SELECT document FROM purposes WHERE id = $1",
                &[&purpose_id],
            )
            .map_err(db_err)?
            .ok_or_else(|| not_found("purpose", &purpose_id))?
            .get(0),
        )
        .map_err(|e| db_err(format!("stored purpose: {e}")))?;
        let acceptances = t
            .query(
                "SELECT acceptance FROM purpose_acceptances WHERE purpose_id = $1 ORDER BY organization_id",
                &[&purpose_id],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| serde_json::from_value(r.get(0)).map_err(|e| db_err(format!("stored acceptance: {e}"))))
            .collect::<Result<Vec<SignedPurposeAcceptance>>>()?;
        // The authorizations the job runs under, in the grant's set (sorted
        // by ID, so every viewer gets one order).
        let mut authorizations = vec![];
        for (row, aid) in &g.authorizations {
            let r = t
                .query_one("SELECT signed FROM authorizations WHERE id = $1", &[row])
                .map_err(db_err)?;
            let signed: SignedAuthorizationV2 =
                serde_json::from_value(r.get::<_, Option<Value>>(0).ok_or_else(|| {
                    db_err(format!("authorization {row} has no signed document"))
                })?)
                .map_err(|e| db_err(format!("stored authorization: {e}")))?;
            if signed.id() != *aid {
                return Err(db_err(format!(
                    "authorization {row} is not the one the job was bound to"
                )));
            }
            let mut approvals = vec![];
            for a in t
                .query(
                    "SELECT approver_id, evidence FROM authorization_approvals
                      WHERE authorization_row = $1 ORDER BY approved_at, approver_id",
                    &[row],
                )
                .map_err(db_err)?
            {
                let e: encompute_trust::authz::ApprovalEvidence = serde_json::from_value(a.get(1))
                    .map_err(|e| db_err(format!("stored approval: {e}")))?;
                approvals.push(SharedApproval {
                    organization: e.organization,
                    role: e.role,
                    at: e.at,
                    approver: self.pseudonyms.pseudonym(&j.project, a.get(0)),
                });
            }
            authorizations.push((signed, approvals));
        }
        authorizations.sort_by_key(|(s, _)| s.id());
        let release_records = t
            .query(
                "SELECT release_record FROM assets WHERE derived_from_job = $1 AND release_record IS NOT NULL
                  ORDER BY derived_output, id",
                &[&j.id],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| serde_json::from_value(r.get(0)).map_err(|e| db_err(format!("stored release record: {e}"))))
            .collect::<Result<Vec<SignedReleaseRecord>>>()?;
        // The log, to one checkpoint, whole.
        let g_authorizations = g.authorizations.clone();
        let g_owners: std::collections::BTreeSet<String> = g
            .binding
            .inputs
            .values()
            .map(|i| i.organization.clone())
            .collect();
        let partition = Partition::Project(j.project.clone()).to_string();
        let checkpoint = govlog::latest_checkpoint(t, &partition)?;
        let (mut events, mut witnesses, mut members) = (vec![], vec![], vec![]);
        let mut head_leaves = std::collections::BTreeMap::new();
        if let Some(cp) = &checkpoint {
            // The contiguous run of the project's events from where this job's
            // authorizations and its owners' heads need it to the checkpoint:
            // nothing selective, so what an export leaves out is detected.
            let auth_ids: Vec<String> = g_authorizations.values().cloned().collect();
            let owners: Vec<String> = g_owners.iter().cloned().collect();
            let max = self
                .bundle_max_events
                .load(std::sync::atomic::Ordering::Relaxed)
                .min(MAX_BUNDLE_EVENTS);
            if max == 0 {
                return Err(limit("this control plane exports no governance events"));
            }
            let start = govlog::run_start(t, &partition, cp.body.size, &auth_ids, &owners, max)?;
            let mut after = start - 1;
            while after < cp.body.size {
                let page = govlog::leaves(
                    t,
                    &self.node_cache,
                    &partition,
                    after,
                    cp.body.size,
                    crate::ops::PROJECT_LOG_MAX_PAGE,
                )?;
                let Some(last) = page.last().map(|(e, _, _)| e.pseq) else {
                    return Err(db_err("the log's events stop before its checkpoint"));
                };
                events.extend(
                    page.into_iter()
                        .map(|(event, _, proof)| AuditEntry { event, proof }),
                );
                after = last;
            }
            // A run that does not begin at the log's first event cannot show
            // what the owners' heads cover before it: the leaves, to be checked
            // against each head's signed root.
            if start > 1 {
                for o in &owners {
                    if let Some(l) = govlog::head_leaves(t, &partition, o, cp.body.size)? {
                        head_leaves.insert(o.clone(), l);
                    }
                }
            }
            witnesses = govlog::witnesses_at(t, &partition, cp.body.size)?;
            members = govlog::members_at(t, &j.project, cp.body.size)?;
        }
        // Only heads the checkpoint's log records: one state, one set of
        // bytes for every member.
        let heads = crate::ops::revocation_heads::latest_heads(t, &j.project)?
            .into_iter()
            .map(|v| serde_json::from_value(v).map_err(|e| db_err(format!("stored head: {e}"))))
            .collect::<Result<Vec<SignedRevocationHead>>>()?
            .into_iter()
            .filter(|h| {
                events.iter().any(|e| {
                    e.event.kind == encompute_trust::govlog::kind::REVOCATION_HEAD_SIGNED
                        && e.event.org.as_deref() == Some(h.body.organization.as_str())
                        && e.event.refs.get("seq") == Some(&h.body.seq.to_string())
                        && e.event.refs.get("root") == Some(&h.body.root)
                })
            })
            .collect();
        Ok(Parts {
            submitter: self.pseudonyms.pseudonym(&j.project, &j.initiated_by),
            program_text: program.to_string(),
            plan: doc.doc.plan,
            spec,
            receipt,
            purpose,
            acceptances,
            authorizations,
            release_records,
            checkpoint,
            members,
            witnesses,
            events,
            heads,
            head_leaves,
            governance: g,
            job: j,
        })
    }

    fn assemble_bundle(&self, p: Parts, view: &View) -> Result<GovernanceBundle> {
        let grant = p.job.grant.clone().expect("checked when read");
        let mut graph = TrustGraph::new();
        graph.add_program(&p.program_text)?;
        graph.add_plan(p.plan)?;
        if let Some(r) = p.receipt {
            graph.add_execution_receipt(r)?;
        }
        let authorizations = p
            .authorizations
            .into_iter()
            .map(|(doc, approvals)| {
                let mine = match view {
                    View::Organization(o) => doc.body.party == *o,
                    View::Shared => false,
                };
                if mine {
                    AuthorizationEntry::Signed {
                        document: Box::new(doc),
                    }
                } else {
                    let mut body = doc.body.clone();
                    body.approvals.clear();
                    AuthorizationEntry::Card {
                        card: Box::new(AuthorizationCard {
                            id: doc.id(),
                            governance_key_id: encompute_trust::authz::governance_key_id(
                                &doc.public_key,
                            ),
                            body,
                            approvals,
                        }),
                    }
                }
            })
            .collect();
        let exported_at = p
            .checkpoint
            .as_ref()
            .map_or(grant.issued_at, |c| c.body.at.max(grant.issued_at));
        let evidence = GovernanceEvidence {
            version: GOVERNANCE_EVIDENCE_VERSION,
            project: p.job.project.clone(),
            job_id: p.job.id.clone(),
            purpose: p.purpose,
            purpose_acceptances: p.acceptances,
            spec: p.spec,
            grant,
            authorizations,
            authorization_revocations: vec![],
            release_records: p.release_records,
            submitter: Some(p.submitter),
        };
        let audit = AuditEvidence {
            version: GOVERNANCE_EVIDENCE_VERSION,
            project: p.job.project.clone(),
            checkpoint: p.checkpoint,
            members: p.members,
            witnesses: p.witnesses,
            events: p.events,
            revocation_heads: p.heads,
            head_leaves: p.head_leaves,
        };
        let _: &BTreeMap<String, String> = &p.governance.authorizations;
        // The exporter's own check: what cannot be verified (digests, the
        // view's rules, the plaintext guard) is not served.
        GovernanceBundle::build(
            &view.name(),
            exported_at,
            self.signer.id(),
            graph,
            evidence,
            audit,
            Provenance::default(),
        )
    }
}
