//! Key custody in governed projects: each organization's own key brokers,
//! release tickets, and the deny-only messages a broker receives
//! (`authorization.revoked`, `asset.expired`).
//!
//! An owner's key broker is the final release authority. It releases a
//! source's key only with the owner's signed authorization and a release
//! ticket: a short-lived, single-use request the control plane signs for
//! the scheduled evaluator of one job. A ticket alone releases nothing (the
//! control plane cannot sign an authorization).
//!
//! In sovereign custody, which every governed project is in, every source's
//! key is held by a broker its own organization registered here, never a
//! platform broker (ENC2715).
//!
//! A broker learns of a revocation or an expiry only once the state anchor
//! holds its governance log event (see `deliver_outbox`): a restored
//! database cannot then undo a revocation a broker already applied without
//! it being noticed.

use std::collections::{BTreeMap, BTreeSet};

use postgres::GenericClient;
use serde_json::{json, Value};

use encompute_ir::{Code, Error, Result};
use encompute_trust::authz::AuthorizationSetId;
use encompute_verification::governance::is_hex32;
use encompute_verification::service::{now, verify_signed, JOB_GRANT};
use encompute_verification::ticket::{
    ReleaseTicket, TicketKind, MAX_TICKET_TTL_SECS, TICKET_SKEW_SECS, TICKET_VERSION,
};

use super::derived::JOBS_UNDER;
use crate::audit::{self, AuditDraft, Outcome};
use crate::authz::{
    auditor_organization, conflict, deny_auditor, deny_auditor_in, forbidden, not_found,
    org_roles_lock, project_row, require, require_human, AssetRow,
};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::model::{
    bad, check_name, JobGrant, KeyRef, RegisterKeyBroker, RequestReleaseTicket, Role, ServiceKind,
    PLATFORM_ORG,
};
use crate::transport::{seal, Scope};

/// Plans whose compiled spec is kept for ticket requests.
pub const PLAN_SPEC_CACHE: usize = 256;

/// How long a revocation or expiry message stays deliverable.
const MESSAGE_TTL_SECS: u64 = 7 * 24 * 3600;

fn custody(msg: impl Into<String>) -> Error {
    Error::new(Code::GovernanceCustody, msg)
}

/// In sovereign custody, `broker` must be a key broker `org` registered
/// itself, active, on an active service account: never a platform broker,
/// another organization's, or one nobody registered (ENC2715; the same
/// answer for each, so it reveals nothing of other organizations).
pub(crate) fn require_own_broker(
    t: &mut impl GenericClient,
    org: &str,
    broker: Option<&str>,
) -> Result<()> {
    let Some(b) = broker else {
        return Err(custody(format!(
            "in sovereign custody an asset's key is held by a key broker {org} registered: name it in key_ref"
        )));
    };
    let own = t
        .query_opt(
            "SELECT 1 FROM key_brokers k JOIN service_accounts s ON s.id = k.id
              WHERE k.id = $1 AND k.organization_id = $2 AND k.status = 'active'
                AND s.status = 'active' AND s.kind = 'keybroker' AND s.organization_id = $2",
            &[&b, &org],
        )
        .map_err(db_err)?;
    if own.is_none() {
        return Err(custody(format!(
            "{b} is not an active key broker registered by {org}: sovereign custody refuses platform brokers and other organizations' brokers (register it with POST /v1/organizations/{org}/key-brokers)"
        )));
    }
    Ok(())
}

/// A location's self-declared fields: at most 16 short printable strings.
fn check_location(l: &serde_json::Map<String, Value>) -> Result<()> {
    if l.len() > 16 {
        return Err(bad("a broker location has at most 16 fields"));
    }
    for (k, v) in l {
        check_name("location field", k)?;
        match v.as_str() {
            Some(s) => check_name("location value", s)?,
            None => return Err(bad("a broker location's values are strings")),
        }
    }
    Ok(())
}

/// The key brokers that serve `org` and are told of its revocations: those
/// it registered, and the broker its asset `asset` names when that is the
/// platform's or its own. (broker ID, URL), each once.
fn brokers_of(
    t: &mut impl GenericClient,
    org: &str,
    asset: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let mut out: BTreeMap<String, String> = t
        .query(
            "SELECT k.id, s.url FROM key_brokers k JOIN service_accounts s ON s.id = k.id
              WHERE k.organization_id = $1 AND k.status = 'active' AND s.status = 'active'
                AND s.url IS NOT NULL ORDER BY k.id",
            &[&org],
        )
        .map_err(db_err)?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    if let Some(a) = asset {
        let named: Option<Option<Value>> = t
            .query_opt("SELECT key_ref FROM assets WHERE id = $1", &[&a])
            .map_err(db_err)?
            .map(|r| r.get(0));
        if let Some(k) = named
            .flatten()
            .and_then(|k| serde_json::from_value::<KeyRef>(k).ok())
        {
            if let Some(url) = broker_url(t, org, &k.broker)? {
                out.insert(k.broker, url);
            }
        }
    }
    Ok(out)
}

/// The URL of `broker` when it is an active key broker of the platform or
/// of `org` (the brokers an asset of `org` may name).
fn broker_url(t: &mut impl GenericClient, org: &str, broker: &str) -> Result<Option<String>> {
    Ok(t
        .query_opt(
            "SELECT url FROM service_accounts WHERE id = $1 AND kind = 'keybroker' AND status = 'active'
                AND (organization_id IS NULL OR organization_id = $2)",
            &[&broker, &org],
        )
        .map_err(db_err)?
        .and_then(|r| r.get::<_, Option<String>>(0)))
}

impl Control {
    // --- an organization's key brokers ----------------------------------------------

    /// A person who is a security admin of `org` registers one of `org`'s
    /// own key-broker service accounts as its key broker (never a platform
    /// broker, ENC2715). Audited.
    pub fn register_key_broker(&self, ctx: &Ctx, org: &str, r: RegisterKeyBroker) -> Result<Value> {
        if org == PLATFORM_ORG {
            return Err(custody(
                "platform key brokers serve every organization: an organization registers its own",
            ));
        }
        require_human(
            &ctx.principal,
            org,
            &[Role::SecurityAdmin],
            "registering a key broker",
        )?;
        check_name("key broker", &r.id)?;
        check_name("provider_kind", &r.provider_kind)?;
        check_name("key_ref_namespace", &r.key_ref_namespace)?;
        check_location(&r.location)?;
        encompute_verification::EvaluatorIdentity::from_public_key_hex(&r.grant_public_key)
            .map_err(|_| bad("grant_public_key must be a 32-byte Ed25519 key in hex"))?;
        self.tx_anchored(|t| {
            deny_auditor_in(t, &ctx.principal, org)?;
            // An auditor organization holds no keys for a governed project
            // (D9, ENC2716): serialized with its joining one.
            org_roles_lock(t, org)?;
            if auditor_organization(t, org)? {
                return Err(Error::new(
                    Code::GovernanceAuditorSeparation,
                    format!("{org} is an auditor organization: it holds no keys, so it registers no key broker"),
                ));
            }
            // The broker ID's lock, as service-account and asset
            // registrations naming it take it.
            crate::ops::keybroker_lock(t, &r.id)?;
            let sa = t
                .query_opt(
                    "SELECT kind, organization_id, status FROM service_accounts WHERE id = $1 FOR SHARE",
                    &[&r.id],
                )
                .map_err(db_err)?
                .map(|x| (x.get::<_, String>(0), x.get::<_, Option<String>>(1), x.get::<_, String>(2)));
            match sa {
                None => return Err(not_found("service account", &r.id)),
                Some((_, None, _)) => {
                    return Err(custody(format!(
                        "{} is a platform service: an organization registers its own key broker",
                        r.id
                    )))
                }
                // Another organization's account: not found (no oracle).
                Some((_, Some(o), _)) if o != org => return Err(not_found("service account", &r.id)),
                Some((k, _, _)) if k != "keybroker" => {
                    return Err(conflict(format!("{} is not a key-broker service account", r.id)))
                }
                Some((_, _, s)) if s != "active" => {
                    return Err(conflict(format!("service account {} is {s}", r.id)))
                }
                Some(_) => {}
            }
            t.execute(
                "INSERT INTO key_brokers (id, organization_id, grant_public_key, provider_kind,
                     key_ref_namespace, location, status, created_by)
                 VALUES ($1, $2, $3, $4, $5, $6, 'active', $7)",
                &[
                    &r.id,
                    &org,
                    &r.grant_public_key,
                    &r.provider_kind,
                    &r.key_ref_namespace,
                    &Value::Object(r.location.clone()),
                    &ctx.actor(),
                ],
            )
            .map_err(|e| {
                if e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                    conflict("this key broker or grant key is already registered")
                } else {
                    db_err(e)
                }
            })?;
            audit::append(
                t,
                ctx.draft("key_broker.registered", "key_broker", &r.id, Outcome::Succeeded)
                    .org(org)
                    .r#ref("provider_kind", r.provider_kind.clone())
                    .r#ref("grant_public_key", r.grant_public_key.clone()),
            )?;
            Ok(json!({"id": r.id, "organization": org, "grant_public_key": r.grant_public_key,
                      "provider_kind": r.provider_kind, "key_ref_namespace": r.key_ref_namespace,
                      "location": r.location, "status": "active"}))
        })
    }

    /// `org`'s registered key brokers, to its security admins, admins,
    /// auditors and data owners (who name them in their assets' keys).
    pub fn list_key_brokers(&self, ctx: &Ctx, org: &str) -> Result<Value> {
        // People only, like every other governance route: no service needs
        // the list (a broker pins the control plane's key, a workload the
        // broker keys its governed spec names).
        if !matches!(ctx.principal.kind, crate::authn::PrincipalKind::User { .. }) {
            return Err(forbidden(
                "listing key brokers is for people of the organization",
            ));
        }
        require(
            &ctx.principal,
            org,
            &[
                Role::SecurityAdmin,
                Role::OrganizationAdmin,
                Role::Auditor,
                Role::DataOwner,
            ],
            "listing key brokers",
        )?;
        let mut c = self.db.conn()?;
        let rows = c
            .query(
                "SELECT id, grant_public_key, provider_kind, key_ref_namespace, location, status
                   FROM key_brokers WHERE organization_id = $1 ORDER BY id",
                &[&org],
            )
            .map_err(db_err)?;
        Ok(Value::Array(
            rows.iter()
                .map(|r| {
                    json!({"id": r.get::<_, String>(0), "organization": org,
                           "grant_public_key": r.get::<_, String>(1),
                           "provider_kind": r.get::<_, String>(2),
                           "key_ref_namespace": r.get::<_, String>(3),
                           "location": r.get::<_, Value>(4), "status": r.get::<_, String>(5)})
                })
                .collect(),
        ))
    }

    // --- release tickets ----------------------------------------------------------------

    /// The execution spec of plan row `plan`, compiled once and kept (a
    /// plan's program never changes; at most [`PLAN_SPEC_CACHE`] plans, the
    /// cache emptied when full), so repeated ticket requests do not
    /// recompile it.
    fn cached_plan_spec(&self, plan: &str) -> Result<encompute_verification::ExecutionSpec> {
        let mut c = self.db.conn()?;
        self.cached_plan_spec_in(&mut *c, plan)
    }

    /// [`Self::cached_plan_spec`], compiling on connection `c` (a caller's
    /// transaction) when the plan is not cached.
    pub(crate) fn cached_plan_spec_in(
        &self,
        c: &mut impl GenericClient,
        plan: &str,
    ) -> Result<encompute_verification::ExecutionSpec> {
        if let Some(s) = self
            .plan_specs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(plan)
        {
            return Ok(s.clone());
        }
        let spec = self.plan_spec(c, plan)?;
        let mut m = self.plan_specs.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() >= PLAN_SPEC_CACHE {
            m.clear();
        }
        m.insert(plan.to_owned(), spec.clone());
        Ok(spec)
    }

    /// The scheduled evaluator of a governed job asks for a release ticket
    /// for one of its sources (by dataset version): signed with the
    /// control plane's key, stored and audited. The job must be queued or
    /// running on it with a governed grant the control plane signed; the
    /// source must be a live source of the job, its key held by a broker
    /// custody allows, and at least one owner authorization for it usable
    /// now. `not_after = min(now + 300 s, the grant's governed not_after,
    /// the grant's expiry, the authorizations' valid_until)`.
    pub fn issue_release_ticket(
        &self,
        ctx: &Ctx,
        id: &str,
        r: RequestReleaseTicket,
    ) -> Result<Value> {
        if ctx.principal.service_kind() != Some(ServiceKind::Evaluator) {
            return Err(forbidden(
                "only the job's scheduled evaluator asks for a release ticket",
            ));
        }
        if !is_hex32(&r.asset_version_id) {
            return Err(bad("asset_version_id must be 32 bytes of lowercase hex"));
        }
        // The plan's spec, compiled before the transaction takes any lock.
        let plan: String = {
            let mut c = self.db.conn()?;
            c.query_opt(
                "SELECT plan_id FROM jobs WHERE id = $1 AND evaluator_id = $2",
                &[&id, &ctx.actor()],
            )
            .map_err(db_err)?
            .ok_or_else(|| not_found("job", id))?
            .get(0)
        };
        let base_spec = self.cached_plan_spec(&plan)?;
        let version_mismatch = |m: String| Error::new(Code::GovernanceAssetVersionMismatch, m);
        let ticket = self.tx_anchored(|t| {
            // The source first, then the job (the order revocation takes).
            let a = t
                .query_opt(
                    "SELECT id, organization_id, key_ref, status, expired_at IS NOT NULL
                       FROM assets WHERE version_id = $1 FOR SHARE",
                    &[&r.asset_version_id],
                )
                .map_err(db_err)?
                .ok_or_else(|| version_mismatch("no such dataset version".into()))?;
            let (asset, owner): (String, String) = (a.get(0), a.get(1));
            let key_ref: Option<Value> = a.get(2);
            let (status, expired): (String, bool) = (a.get(3), a.get(4));
            let j = t
                .query_opt(
                    "SELECT organization_id, project_id, spec_id, state, evaluator_id, job_grant, source_assets
                       FROM jobs WHERE id = $1 FOR SHARE",
                    &[&id],
                )
                .map_err(db_err)?
                .ok_or_else(|| not_found("job", id))?;
            let (job_org, project, spec_id, state): (String, String, String, String) =
                (j.get(0), j.get(1), j.get(2), j.get(3));
            if j.get::<_, Option<String>>(4).as_deref() != Some(ctx.actor()) {
                return Err(not_found("job", id));
            }
            if !matches!(state.as_str(), "queued" | "running") {
                return Err(conflict(format!(
                    "job {id} is {state}: release tickets are for queued or running jobs"
                )));
            }
            let p = project_row(t, &project)?.ok_or_else(|| not_found("project", &project))?;
            deny_auditor(&ctx.principal, &p)?;
            // An auditor organization never holds a source's key.
            if p.auditors.contains(&owner) || p.invited_auditors.contains(&owner) {
                return Err(Error::new(
                    Code::GovernanceAuditorSeparation,
                    format!("{owner} audits this project: no release ticket is issued for its keys"),
                ));
            }
            if !p.governed() {
                return Err(conflict(
                    "release tickets belong to governed projects",
                ));
            }
            let grant: JobGrant = j
                .get::<_, Option<Value>>(5)
                .and_then(|v| serde_json::from_value(v).ok())
                .ok_or_else(|| conflict("the job has no grant"))?;
            // Only a grant this control plane signed, for this job and
            // evaluator: a row written to the database some other way
            // gets no ticket.
            let pk = self.signer.public_key_hex();
            if grant.issuer_public_key != pk
                || verify_signed(&pk, JOB_GRANT, &grant.unsigned(), &grant.signature).is_err()
                || grant.job_id != id
                || grant.evaluator != ctx.actor()
                || grant.project != project
            {
                return Err(conflict("the job's grant is not one this control plane issued for it"));
            }
            let g = grant.governance.clone().ok_or_else(|| {
                Error::new(
                    Code::GovernanceReleaseTicket,
                    "the job's grant carries no governance binding",
                )
            })?;
            g.check(&project)?;
            // No key is released to an evaluator the job's placement does
            // not admit now, or that is no longer the machine the grant
            // recorded (ENC2710, ENC2725).
            self.check_job_placement(t, id, &g.binding, Some(ctx.actor()), g.placement.as_ref())?;
            let at = now();
            if at >= grant.expires_at {
                return Err(conflict("the job's grant expired"));
            }
            if at >= g.not_after {
                return Err(Error::new(
                    Code::GovernanceAuthorizationExpired,
                    "the job's governed window has ended",
                ));
            }
            let spec = base_spec.clone().governed(&g.binding);
            if spec.id().hex() != spec_id {
                return Err(conflict(
                    "the job's execution spec is not its plan's under its governance binding",
                ));
            }
            // The source: one the job reads, bound as this owner's input.
            let sources: Vec<String> = serde_json::from_value(j.get(6)).unwrap_or_default();
            if !sources.contains(&asset)
                || !g.binding.inputs.values().any(|i| {
                    i.asset_version_id == r.asset_version_id && i.organization == owner
                })
            {
                return Err(version_mismatch(format!(
                    "dataset version {} is not a source of job {id}",
                    r.asset_version_id
                )));
            }
            // A revoked source is withdrawn (ENC2706); an expired one is
            // past its owner's retention, an expiry (ENC2705).
            if status == "revoked" {
                return Err(Error::new(
                    Code::GovernanceAuthorizationRevoked,
                    "the source is revoked",
                ));
            }
            if expired {
                return Err(Error::new(
                    Code::GovernanceAuthorizationExpired,
                    "the source is expired",
                ));
            }
            // A derived source's ancestors: none revoked or expired, and
            // every owner of them authorized the job.
            self.check_lineage(t, std::slice::from_ref(&asset), at)?;
            crate::ops::derived::require_lineage_consent(t, id, std::slice::from_ref(&asset))?;
            let broker = key_ref
                .and_then(|k| serde_json::from_value::<KeyRef>(k).ok())
                .map(|k| k.broker);
            // A governed project is always in sovereign custody.
            if !p.sovereign() {
                return Err(custody("a governed project is always in sovereign custody"));
            }
            require_own_broker(t, &owner, broker.as_deref())?;
            let broker = broker.expect("checked");
            // The job's own authorization for this source (recorded at
            // submission), checked exactly as scheduling and start check
            // it: never another authorization of the owner, however broad.
            let bound: BTreeMap<String, String> = t
                .query(
                    "SELECT authorization_row, authorization_id FROM job_authorizations
                      WHERE job_id = $1 ORDER BY authorization_row",
                    &[&id],
                )
                .map_err(db_err)?
                .iter()
                .map(|x| (x.get(0), x.get(1)))
                .collect();
            if bound.is_empty()
                || AuthorizationSetId::of(bound.values().cloned())?.hex() != g.authorization_set_id
            {
                return Err(Error::new(
                    Code::GovernanceProgramNotAuthorized,
                    "the job's authorizations are not the set its grant names",
                ));
            }
            let mine: Vec<(String, String)> = t
                .query(
                    "SELECT authorization_row, authorization_id FROM job_authorizations
                      WHERE job_id = $1 AND asset_id = $2 ORDER BY authorization_row",
                    &[&id, &asset],
                )
                .map_err(db_err)?
                .iter()
                .map(|x| (x.get(0), x.get(1)))
                .collect();
            if mine.is_empty() {
                return Err(Error::new(
                    Code::GovernanceAuthorizationMissing,
                    format!("job {id} runs under no authorization of {owner} for this source"),
                ));
            }
            let versions = BTreeMap::from([(asset.clone(), r.asset_version_id.clone())]);
            let spec_hex = spec.id().hex();
            let mut authorization_ids = BTreeSet::new();
            let mut until = u64::MAX;
            for (row, aid) in &mine {
                let valid_until = self.check_bound_authorization(
                    t,
                    crate::ops::jobs::BoundAuthorization {
                        row,
                        authorization_id: aid,
                        binding: &g.binding,
                        base_spec: &base_spec,
                        spec_id: &spec_hex,
                        versions: &versions,
                    },
                    at,
                )?;
                authorization_ids.insert(aid.clone());
                until = until.min(valid_until);
            }
            let not_after = (at + MAX_TICKET_TTL_SECS)
                .min(g.not_after)
                .min(grant.expires_at)
                .min(until);
            if not_after <= at + TICKET_SKEW_SECS {
                return Err(Error::new(
                    Code::GovernanceReleaseTicket,
                    "the job's window closes too soon for a release ticket to be accepted",
                ));
            }
            let receipt_key: String = t
                .query_opt("SELECT receipt_key FROM evaluators WHERE id = $1", &[&ctx.actor()])
                .map_err(db_err)?
                .ok_or_else(|| not_found("evaluator", ctx.actor()))?
                .get(0);
            let ticket = ReleaseTicket {
                version: TICKET_VERSION,
                ticket_id: ReleaseTicket::new_ticket_id()?,
                kind: TicketKind::KeyRelease,
                organization: owner.clone(),
                broker: broker.clone(),
                asset_version_id: r.asset_version_id.clone(),
                authorization_ids,
                job_id: id.to_owned(),
                project: project.clone(),
                purpose_id: g.binding.purpose_id.clone(),
                governance_id: g.governance_id.clone(),
                plan_id: g.plan_hash.clone(),
                execution_spec_id: spec.id().hex(),
                policy_id: spec.policy_id.clone(),
                workload_or_recipient: receipt_key,
                recipient: None,
                placement_digest: g.binding.placement_digest.clone(),
                execution_spec: spec,
                binding: g.binding.clone(),
                not_before: at,
                not_after,
                anchor_counter: self.anchor.counter(),
                issuer: String::new(),
                issuer_public_key: String::new(),
                signature: String::new(),
            };
            // The owner's trail, and the submitter's when it is another.
            let mut orgs = vec![owner.as_str()];
            if job_org != owner {
                orgs.push(job_org.as_str());
            }
            self.issue_ticket(
                t,
                ctx,
                ticket,
                ctx.actor(),
                ("job", id),
                &project,
                &orgs,
                &[("owner", owner.clone())],
            )
        })?;
        Ok(json!({"ticket": ticket}))
    }

    /// Signs `ticket` (built unsigned by the caller) as the control plane,
    /// checks it is consistent, stores it and audits it for each of `orgs`
    /// (on `resource`, with `refs`): the one way the control plane issues a
    /// ticket of any kind, a key release to a scheduled evaluator or an
    /// export to a recipient. Stored append-only, one row per ticket; the
    /// broker that redeems it accepts it once.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue_ticket(
        &self,
        t: &mut postgres::Transaction<'_>,
        ctx: &Ctx,
        ticket: ReleaseTicket,
        issued_to: &str,
        resource: (&'static str, &str),
        project: &str,
        orgs: &[&str],
        refs: &[(&'static str, String)],
    ) -> Result<ReleaseTicket> {
        let ticket = ticket.sign(&self.signer)?;
        ticket.check_consistent()?;
        let kind = match ticket.kind {
            TicketKind::KeyRelease => "key_release",
            TicketKind::Export => "export",
            TicketKind::Decrypt => {
                return Err(Error::new(
                    Code::GovernanceReleaseTicket,
                    "decryption tickets are not issued",
                ))
            }
        };
        t.execute(
            "INSERT INTO release_tickets (ticket_id, job_id, organization_id, broker_id,
                 asset_version_id, issued_to, not_after, body, kind)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &ticket.ticket_id,
                &ticket.job_id,
                &ticket.organization,
                &ticket.broker,
                &ticket.asset_version_id,
                &issued_to,
                &i64::try_from(ticket.not_after).unwrap_or(i64::MAX),
                &serde_json::to_value(&ticket).expect("serializable"),
                &kind,
            ],
        )
        .map_err(|e| {
            if e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                Error::new(
                    Code::GovernanceReleaseTicket,
                    "this ticket was issued already",
                )
            } else {
                db_err(e)
            }
        })?;
        for org in orgs {
            let mut d = ctx
                .draft(
                    "release_ticket.issued",
                    resource.0,
                    resource.1,
                    Outcome::Succeeded,
                )
                .org(org)
                .project(project)
                .r#ref("ticket", ticket.ticket_id.clone())
                .r#ref("broker", ticket.broker.clone())
                .r#ref("asset_version", ticket.asset_version_id.clone())
                .r#ref("not_after", ticket.not_after.to_string());
            if ticket.kind != TicketKind::KeyRelease {
                d = d.r#ref("kind", kind);
            }
            for (k, v) in refs {
                d = d.r#ref(k, v.clone());
            }
            audit::append(t, d)?;
        }
        Ok(ticket)
    }

    // --- deny-only messages to key brokers ----------------------------------------------

    /// Queues `authorization.revoked` for authorization row `row` (revoked
    /// in the caller's transaction) to its owner's brokers and to the key
    /// broker of every custodian holding a result derived (every hop) from
    /// a job that ran under it (where the owner's authorization is
    /// installed as a lineage owner's), in the caller's transaction;
    /// delivered only once the revocation is anchored (`deliver_outbox`).
    /// Each message names the broker's own organization: it only denies.
    /// An authorization that was never signed was never installed at a
    /// broker: nothing is sent. Returns how many messages were queued.
    pub fn queue_authorization_revoked(
        &self,
        t: &mut postgres::Transaction<'_>,
        actor: &str,
        request_id: &str,
        row: &str,
    ) -> Result<usize> {
        let r = t
            .query_one(
                "SELECT organization_id, project_id, asset_id, authorization_id,
                        floor(extract(epoch FROM revoked_at))::bigint
                   FROM authorizations WHERE id = $1",
                &[&row],
            )
            .map_err(db_err)?;
        let (org, project, asset): (String, String, String) = (r.get(0), r.get(1), r.get(2));
        let (Some(authorization_id), Some(revoked_at)) =
            (r.get::<_, Option<String>>(3), r.get::<_, Option<i64>>(4))
        else {
            return Ok(0);
        };
        // (broker, its organization) → URL: the owner's brokers, then every
        // custodian broker downstream.
        let mut brokers: BTreeMap<(String, String), String> = brokers_of(t, &org, Some(&asset))?
            .into_iter()
            .map(|(b, u)| ((b, org.clone()), u))
            .collect();
        let custodians: Vec<(String, String)> = t
            .query(
                &format!(
                    "{JOBS_UNDER}
                     SELECT DISTINCT d.organization_id, d.key_ref->>'broker' FROM assets d
                      WHERE d.derived_from_job IN (SELECT id FROM under)
                        AND d.key_ref->>'broker' IS NOT NULL
                      ORDER BY 1, 2"
                ),
                &[&row],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        for (custodian, broker) in custodians {
            if brokers.keys().any(|(b, _)| *b == broker) {
                continue;
            }
            if let Some(url) = broker_url(t, &custodian, &broker)? {
                brokers.insert((broker, custodian), url);
            }
        }
        for ((broker, holder), url) in &brokers {
            let m = seal(
                &self.signer,
                "authorization.revoked",
                broker,
                Scope {
                    organization: Some(holder.clone()),
                    ..Scope::default()
                },
                &json!({"authorization": row, "authorization_id": authorization_id,
                        "revoked_at": revoked_at.max(0)}),
                MESSAGE_TTL_SECS,
            )?;
            t.execute(
                "INSERT INTO outbox (message_id, recipient, url, envelope) VALUES ($1, $2, $3, $4)",
                &[
                    &m.message_id,
                    broker,
                    url,
                    &serde_json::to_value(&m).expect("serializable"),
                ],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                AuditDraft::new(
                    actor,
                    request_id,
                    "authorization.revocation.sent",
                    "authorization",
                    row,
                    Outcome::Succeeded,
                )
                .org(&org)
                .project(&project)
                .r#ref("broker", broker.clone())
                .r#ref("message", m.message_id.clone()),
            )?;
            if *holder != org {
                // The custodian's trail too: its broker was told.
                audit::append(
                    t,
                    AuditDraft::new(
                        actor,
                        request_id,
                        "authorization.revocation.sent",
                        "authorization",
                        row,
                        Outcome::Succeeded,
                    )
                    .org(holder)
                    .project(&project)
                    .r#ref("broker", broker.clone())
                    .r#ref("message", m.message_id.clone())
                    .r#ref("reason", "lineage"),
                )?;
            }
        }
        Ok(brokers.len())
    }

    /// Marks `a` expired in the caller's transaction (from now on its key
    /// is never released again), audits it and queues its broker's
    /// `asset.expired`, delivered once the expiry is anchored. `reason`
    /// annotates the audit event (retention, recovery). Returns whether it
    /// was newly expired. Retention ([`Control::retire_in`]) also marks and
    /// fails what depends on it.
    pub(crate) fn expire_in(
        &self,
        t: &mut postgres::Transaction<'_>,
        actor: &str,
        request_id: &str,
        a: &AssetRow,
        reason: Option<&str>,
    ) -> Result<bool> {
        let n = t
            .execute(
                "UPDATE assets SET expired_at = now() WHERE id = $1 AND expired_at IS NULL",
                &[&a.id],
            )
            .map_err(db_err)?;
        if n == 0 {
            return Ok(false);
        }
        crate::govlog::append_asset_event(
            t,
            crate::govlog::kind::ASSET_EXPIRED,
            &a.id,
            &a.organization,
        )?;
        let draft = |action| {
            AuditDraft::new(
                actor,
                request_id,
                action,
                "asset",
                &a.id,
                Outcome::Succeeded,
            )
            .org(&a.organization)
        };
        let broker = a
            .key_ref
            .clone()
            .and_then(|k| serde_json::from_value::<KeyRef>(k).ok())
            .map(|k| broker_url(t, &a.organization, &k.broker).map(|u| (k, u)))
            .transpose()?;
        let mut d = draft("asset.expired");
        if let Some(r) = reason {
            d = d.r#ref("reason", r.to_owned());
        }
        audit::append(t, d)?;
        if let Some((k, Some(url))) = broker {
            let m = seal(
                &self.signer,
                "asset.expired",
                &k.broker,
                Scope {
                    organization: Some(a.organization.clone()),
                    ..Scope::default()
                },
                &json!({"asset": a.id, "key_ref": k.key_ref, "key_version": k.key_version}),
                MESSAGE_TTL_SECS,
            )?;
            t.execute(
                "INSERT INTO outbox (message_id, recipient, url, envelope) VALUES ($1, $2, $3, $4)",
                &[
                    &m.message_id,
                    &k.broker,
                    &url,
                    &serde_json::to_value(&m).expect("serializable"),
                ],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                draft("key.expiry.sent")
                    .r#ref("broker", k.broker.clone())
                    .r#ref("message", m.message_id.clone()),
            )?;
        }
        Ok(true)
    }
}
