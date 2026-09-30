//! Governed projects: governance keys, purposes and owner authorizations
//! (public-sector confidential data collaboration, phase 1).
//!
//! The control plane coordinates and enforces; it is not the authority.
//! Each organization's consent is a signature by its own governance key,
//! which stays in the organization's KMS or HSM (signing happens outside
//! the control plane, e.g. `encompute governance sign`); only the public
//! key, its fingerprint and its state are held here.
//!
//! Every step is taken by people of the organization concerned, never by a
//! service account, an auditor, or someone homed in another organization
//! ([`require_human`]); approvals take a different person than the one who
//! proposed (four eyes, ENC2707).
//!
//! Once approved (its quorum met) an authorization is immutable evidence:
//! no approval is added or removed, and any change of meaning is a new
//! authorization. Revocations, of an authorization or of the governance key
//! that signed it, and purpose retirements take effect at the time the
//! control plane records (its own clock, never changed afterwards): from
//! then on nothing new uses the authorization, while uses before it stay
//! valid history ([`Control::authorization_usable_at`]).
//!
//! A revoked authorization is anchored before the revocation is
//! acknowledged, and only then are the owner's key brokers told
//! (`authorization.revoked`, see `ops/custody.rs`); release tickets are
//! issued there too.
//!
//! Jobs run under these authorizations (`ops/jobs.rs`): checked at
//! submission, scheduling, start and ticket issue with [`usable_at`], and a
//! revocation fails the jobs under it that have not started.
//!
//! Not yet (later phases): anchoring of purpose retirements and
//! governance-key revocations against database rollback.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use encompute_ir::{Code, Error, Result};
use encompute_trust::authz::{
    governance_key_id, ApprovalEvidence, AuthorizationV2, GovernanceKey, GovernanceKeyStatus,
    Signed, SignedAuthorizationV2,
};
use encompute_verification::governance::{Purpose, PURPOSE_VERSION};
use encompute_verification::service::now;

use crate::audit::{self, Outcome};
use crate::authn::PrincipalKind;
use crate::authz::{
    conflict, deny_auditor, forbidden, not_found, project_row, project_visible, require_human,
    require_other_person, ProjectRow,
};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::model::{
    bad, check_name, new_id, AcceptPurpose, ApproveAuthorization, AuthorizationSignature,
    ProposeAuthorization, ProposeGovernanceKey, ProposePurpose, RevokeAuthorization, Role,
};

fn gov(code: Code, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

fn unique_violation(e: &postgres::Error) -> bool {
    e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION)
}

/// A governed project the principal's organization collaborates in.
fn governed_project(t: &mut postgres::Transaction<'_>, ctx: &Ctx, id: &str) -> Result<ProjectRow> {
    let p = project_visible(t, &ctx.principal, id)?;
    if !p.governed() {
        return Err(conflict(format!(
            "project {id} is a standard project: purposes and authorizations belong to governed projects"
        )));
    }
    Ok(p)
}

/// The organization's active governance key: (public key, key ID).
fn active_key(t: &mut postgres::Transaction<'_>, org: &str) -> Result<(String, String)> {
    t.query_opt(
        "SELECT public_key, key_id FROM governance_keys WHERE organization_id = $1 AND status = 'active'",
        &[&org],
    )
    .map_err(db_err)?
    .map(|r| (r.get(0), r.get(1)))
    .ok_or_else(|| {
        gov(
            Code::GovernanceKeyRevoked,
            format!("{org} has no active governance key"),
        )
    })
}

/// Verifies `check` (a signature check under `org`'s active key), naming
/// a refusal by a revoked or unapproved key of `org` ENC2708, and any other
/// ENC2701.
fn under_active_key(
    t: &mut postgres::Transaction<'_>,
    org: &str,
    presented: &str,
    check: impl FnOnce(&str) -> Result<()>,
) -> Result<String> {
    let (active, key_id) = active_key(t, org)?;
    if presented != active {
        let state: Option<String> = t
            .query_opt(
                "SELECT status FROM governance_keys WHERE organization_id = $1 AND public_key = $2",
                &[&org, &presented],
            )
            .map_err(db_err)?
            .map(|r| r.get(0));
        return Err(match state {
            Some(s) => gov(
                Code::GovernanceKeyRevoked,
                format!("signed by a governance key of {org} that is {s}, not active"),
            ),
            None => gov(
                Code::GovernanceAuthorizationMissing,
                format!("signed by a key that is not {org}'s governance key"),
            ),
        });
    }
    check(&active).map_err(|e| {
        gov(
            Code::GovernanceAuthorizationMissing,
            format!(
                "the signature does not verify under {org}'s governance key: {}",
                e.message
            ),
        )
    })?;
    Ok(key_id)
}

/// Window bounds are stored as signed 64-bit seconds.
fn check_window(from: u64, until: u64) -> Result<()> {
    if from > i64::MAX as u64 || until > i64::MAX as u64 {
        return Err(bad("validity times are Unix seconds below 2^63"));
    }
    Ok(())
}

fn approver(ctx: &Ctx) -> Result<(String, String)> {
    match &ctx.principal.kind {
        PrincipalKind::User { issuer, subject } => Ok((issuer.clone(), subject.clone())),
        PrincipalKind::Service { .. } => Err(gov(
            Code::GovernanceFourEyesIncomplete,
            "approvals are given by people, not services",
        )),
    }
}

impl Control {
    // --- governance keys ---------------------------------------------------------

    /// Registers `org`'s governance public key, for a different security
    /// admin to approve. Only public keys: signing stays with the
    /// organization.
    pub fn propose_governance_key(
        &self,
        ctx: &Ctx,
        org: &str,
        r: ProposeGovernanceKey,
    ) -> Result<Value> {
        require_human(
            &ctx.principal,
            org,
            &[Role::OrganizationAdmin, Role::SecurityAdmin],
            "registering a governance key",
        )?;
        encompute_verification::EvaluatorIdentity::from_public_key_hex(&r.public_key)
            .map_err(|_| bad("public_key must be a 32-byte Ed25519 key in lowercase hex"))?;
        if let Some(k) = &r.kms_key_ref {
            check_name("kms_key_ref", k)?;
        }
        let key_id = governance_key_id(&r.public_key);
        let id = new_id("gky");
        self.db.tx(|t| {
            t.execute(
                "INSERT INTO governance_keys (id, organization_id, key_id, public_key, kms_key_ref, status, proposed_by)
                 VALUES ($1, $2, $3, $4, $5, 'proposed', $6)",
                &[&id, &org, &key_id, &r.public_key, &r.kms_key_ref, &ctx.actor()],
            )
            .map_err(|e| {
                if unique_violation(&e) {
                    conflict("this governance key is registered already")
                } else {
                    db_err(e)
                }
            })?;
            audit::append(
                t,
                ctx.draft("governance_key.proposed", "governance_key", &id, Outcome::Succeeded)
                    .org(org)
                    .r#ref("key_id", key_id.clone()),
            )?;
            Ok(json!({"id": id, "organization": org, "key_id": key_id, "status": "proposed"}))
        })
    }

    /// A different person, a security admin of `org`, approves the key: it
    /// becomes the organization's one active governance key.
    pub fn approve_governance_key(&self, ctx: &Ctx, org: &str, id: &str) -> Result<Value> {
        require_human(
            &ctx.principal,
            org,
            &[Role::SecurityAdmin],
            "approving a governance key",
        )?;
        self.db.tx(|t| {
            let r = t
                .query_opt(
                    "SELECT status, proposed_by, key_id FROM governance_keys
                      WHERE id = $1 AND organization_id = $2 FOR UPDATE",
                    &[&id, &org],
                )
                .map_err(db_err)?
                .ok_or_else(|| not_found("governance key", id))?;
            let (status, proposer, key_id): (String, String, String) = (r.get(0), r.get(1), r.get(2));
            require_other_person(ctx.actor(), &[proposer.as_str()], "approving a governance key")?;
            if status != "proposed" {
                return Err(conflict(format!("governance key {id} is {status}")));
            }
            let active = t
                .query_opt(
                    "SELECT id FROM governance_keys WHERE organization_id = $1 AND status = 'active' FOR UPDATE",
                    &[&org],
                )
                .map_err(db_err)?;
            if active.is_some() {
                return Err(conflict(format!(
                    "{org} has an active governance key: revoke it before approving another"
                )));
            }
            t.execute(
                "UPDATE governance_keys SET status = 'active', approved_by = $2, approved_at = now() WHERE id = $1",
                &[&id, &ctx.actor()],
            )
            .map_err(|e| {
                if unique_violation(&e) {
                    conflict(format!("{org} has an active governance key"))
                } else {
                    db_err(e)
                }
            })?;
            audit::append(
                t,
                ctx.draft("governance_key.approved", "governance_key", id, Outcome::Succeeded)
                    .org(org)
                    .r#ref("key_id", key_id.clone()),
            )?;
            Ok(json!({"id": id, "organization": org, "key_id": key_id, "status": "active"}))
        })
    }

    /// Revokes a governance key (proposed or active); never undone. From
    /// its revocation time (recorded once, never changed) signatures by it
    /// activate nothing, and nothing it signed is used: every authorization
    /// it signed is unusable from then on, though uses before it stay valid
    /// history ([`Self::authorization_usable_at`]).
    pub fn revoke_governance_key(&self, ctx: &Ctx, org: &str, id: &str) -> Result<Value> {
        require_human(
            &ctx.principal,
            org,
            &[Role::SecurityAdmin, Role::OrganizationAdmin],
            "revoking a governance key",
        )?;
        self.db.tx(|t| {
            let r = t
                .query_opt(
                    "SELECT status, key_id FROM governance_keys WHERE id = $1 AND organization_id = $2 FOR UPDATE",
                    &[&id, &org],
                )
                .map_err(db_err)?
                .ok_or_else(|| not_found("governance key", id))?;
            let (status, key_id): (String, String) = (r.get(0), r.get(1));
            if status != "revoked" {
                t.execute(
                    "UPDATE governance_keys SET status = 'revoked', revoked_by = $2,
                            revoked_at = to_timestamp($3::bigint) WHERE id = $1",
                    &[&id, &ctx.actor(), &secs(now())],
                )
                .map_err(db_err)?;
                audit::append(
                    t,
                    ctx.draft("governance_key.revoked", "governance_key", id, Outcome::Succeeded)
                        .org(org)
                        .r#ref("key_id", key_id.clone()),
                )?;
            }
            let revoked_at: Option<i64> = t
                .query_one(
                    &format!("SELECT {} FROM governance_keys WHERE id = $1", epoch("revoked_at")),
                    &[&id],
                )
                .map_err(db_err)?
                .get(0);
            Ok(json!({"id": id, "organization": org, "key_id": key_id, "status": "revoked",
                      "revoked_at": revoked_at}))
        })
    }

    /// `org`'s governance keys, to its members.
    pub fn list_governance_keys(&self, ctx: &Ctx, org: &str) -> Result<Value> {
        if !ctx.principal.member_of(org) {
            return Err(not_found("organization", org));
        }
        let mut c = self.db.conn()?;
        let rows = c
            .query(
                &format!(
                    "SELECT id, key_id, public_key, kms_key_ref, status, {} FROM governance_keys
                      WHERE organization_id = $1 ORDER BY created_at, id",
                    epoch("revoked_at")
                ),
                &[&org],
            )
            .map_err(db_err)?;
        Ok(Value::Array(
            rows.iter()
                .map(|r| {
                    json!({"id": r.get::<_, String>(0), "organization": org,
                           "key_id": r.get::<_, String>(1), "public_key": r.get::<_, String>(2),
                           "kms_key_ref": r.get::<_, Option<String>>(3), "status": r.get::<_, String>(4),
                           "revoked_at": r.get::<_, Option<i64>>(5)})
                })
                .collect(),
        ))
    }

    // --- purposes ----------------------------------------------------------------

    /// A security admin of a member organization proposes a purpose; its ID
    /// is the PurposeId of the document (project included).
    pub fn propose_purpose(&self, ctx: &Ctx, project: &str, r: ProposePurpose) -> Result<Value> {
        let purpose = Purpose {
            version: PURPOSE_VERSION,
            project_id: project.to_owned(),
            name: r.name.clone(),
            revision: r.revision,
            description: r.description.clone(),
            legal_basis_ref: r.legal_basis_ref.clone(),
            modes: r.modes.clone(),
            allowed_release_classes: r.allowed_release_classes.clone(),
            recipients: r.recipients.clone(),
            linkage_policy_id: r.linkage_policy_id.clone(),
            min_aggregate_parties: r.min_aggregate_parties,
            valid_from: r.valid_from,
            valid_until: r.valid_until,
            created_by_org: r.organization.clone(),
        };
        check_window(purpose.valid_from, purpose.valid_until)?;
        let id = purpose.id().hex();
        let document = serde_json::to_value(&purpose).expect("serializable");
        self.db.tx(|t| {
            let p = governed_project(t, ctx, project)?;
            deny_auditor(&ctx.principal, &p)?;
            require_human(
                &ctx.principal,
                &r.organization,
                &[Role::SecurityAdmin],
                "proposing a purpose",
            )?;
            if !p.members.contains(&r.organization) {
                return Err(forbidden(format!(
                    "{} is not a member of the project",
                    r.organization
                )));
            }
            purpose.check()?;
            for o in &purpose.recipients {
                if !p.members.contains(o) && !p.invited.contains(o) {
                    return Err(bad(format!("recipient {o} is not in the project")));
                }
            }
            if now() >= purpose.valid_until {
                return Err(gov(
                    Code::GovernanceAuthorizationExpired,
                    "the purpose's window is over",
                ));
            }
            t.execute(
                "INSERT INTO purposes (id, project_id, organization_id, name, revision, document,
                                       valid_from, valid_until, status, proposed_by)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'proposed', $9)",
                &[
                    &id,
                    &project,
                    &r.organization,
                    &purpose.name,
                    &(purpose.revision as i32),
                    &document,
                    &(purpose.valid_from as i64),
                    &(purpose.valid_until as i64),
                    &ctx.actor(),
                ],
            )
            .map_err(|e| {
                if unique_violation(&e) {
                    conflict(format!(
                        "purpose {} revision {} exists in this project: propose a new revision",
                        purpose.name, purpose.revision
                    ))
                } else {
                    db_err(e)
                }
            })?;
            audit::append(
                t,
                ctx.draft("purpose.proposed", "purpose", &id, Outcome::Succeeded)
                    .org(&r.organization)
                    .project(project)
                    .r#ref("name", purpose.name.clone()),
            )?;
            Ok(json!({"id": id, "project": project, "status": "proposed", "purpose": document}))
        })
    }

    /// A different security admin of the proposing organization approves:
    /// the purpose becomes active (and can then be accepted).
    pub fn approve_purpose(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        self.db.tx(|t| {
            let (project, org, status, proposer, valid_until) = purpose_row(t, id, true)?;
            let p = project_visible(t, &ctx.principal, &project).map_err(|_| not_found("purpose", id))?;
            deny_auditor(&ctx.principal, &p)?;
            if !ctx.principal.member_of(&org) {
                return Err(forbidden(format!(
                    "a purpose is approved by a security admin of its proposer, {org}"
                )));
            }
            require_human(&ctx.principal, &org, &[Role::SecurityAdmin], "approving a purpose")?;
            require_other_person(ctx.actor(), &[proposer.as_str()], "approving a purpose")?;
            if status != "proposed" {
                return Err(conflict(format!("purpose {id} is {status}")));
            }
            if now() >= valid_until {
                return Err(gov(Code::GovernanceAuthorizationExpired, "the purpose's window is over"));
            }
            t.execute(
                "UPDATE purposes SET status = 'active', approved_by = $2, approved_at = now() WHERE id = $1",
                &[&id, &ctx.actor()],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                ctx.draft("purpose.approved", "purpose", id, Outcome::Succeeded)
                    .org(&org)
                    .project(&project),
            )?;
            Ok(json!({"id": id, "project": project, "status": "active"}))
        })
    }

    /// A member organization accepts an active purpose with its governance
    /// key (the signed acceptance is kept as evidence).
    pub fn accept_purpose(&self, ctx: &Ctx, id: &str, r: AcceptPurpose) -> Result<Value> {
        let a = r.acceptance.body.clone();
        self.db.tx(|t| {
            let (project, _, status, _, _) = purpose_row(t, id, true)?;
            let p = project_visible(t, &ctx.principal, &project).map_err(|_| not_found("purpose", id))?;
            deny_auditor(&ctx.principal, &p)?;
            require_human(
                &ctx.principal,
                &a.organization,
                &[Role::SecurityAdmin, Role::OrganizationAdmin],
                "accepting a purpose",
            )?;
            if !p.members.contains(&a.organization) {
                return Err(forbidden(format!("{} is not a member of the project", a.organization)));
            }
            if a.purpose_id != id || a.project != project {
                return Err(gov(
                    Code::GovernancePurposeMismatch,
                    "the acceptance is for another purpose or project",
                ));
            }
            match status.as_str() {
                "active" => {}
                "retired" => {
                    return Err(gov(Code::GovernanceAuthorizationRevoked, format!("purpose {id} is retired")))
                }
                s => {
                    return Err(gov(
                        Code::GovernancePurposeMismatch,
                        format!("purpose {id} is {s}: it is accepted once approved"),
                    ))
                }
            }
            let key_id = under_active_key(t, &a.organization, &r.acceptance.public_key, |k| {
                r.acceptance.verify(k)
            })?;
            t.execute(
                "INSERT INTO purpose_acceptances (purpose_id, organization_id, governance_key_id, acceptance, accepted_by)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (purpose_id, organization_id) DO NOTHING",
                &[
                    &id,
                    &a.organization,
                    &key_id,
                    &serde_json::to_value(&r.acceptance).expect("serializable"),
                    &ctx.actor(),
                ],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                ctx.draft("purpose.accepted", "purpose", id, Outcome::Succeeded)
                    .org(&a.organization)
                    .project(&project)
                    .r#ref("governance_key", key_id.clone()),
            )?;
            Ok(json!({"id": id, "organization": a.organization, "accepted": true}))
        })
    }

    /// A security admin of the proposing organization retires the purpose;
    /// it takes no new authorization, and is never active again.
    pub fn retire_purpose(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        self.db.tx(|t| {
            let (project, org, status, _, _) = purpose_row(t, id, true)?;
            let p = project_visible(t, &ctx.principal, &project)
                .map_err(|_| not_found("purpose", id))?;
            deny_auditor(&ctx.principal, &p)?;
            if !ctx.principal.member_of(&org) {
                return Err(forbidden(format!(
                    "a purpose is retired by a security admin of its proposer, {org}"
                )));
            }
            require_human(
                &ctx.principal,
                &org,
                &[Role::SecurityAdmin],
                "retiring a purpose",
            )?;
            if status != "retired" {
                t.execute(
                    "UPDATE purposes SET status = 'retired', retired_by = $2,
                            retired_at = to_timestamp($3::bigint) WHERE id = $1",
                    &[&id, &ctx.actor(), &secs(now())],
                )
                .map_err(db_err)?;
                audit::append(
                    t,
                    ctx.draft("purpose.retired", "purpose", id, Outcome::Succeeded)
                        .org(&org)
                        .project(&project),
                )?;
            }
            Ok(json!({"id": id, "project": project, "status": "retired"}))
        })
    }

    pub fn get_purpose(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        self.db.tx(|t| {
            let r = t
                .query_opt(
                    "SELECT project_id, organization_id, status, document FROM purposes WHERE id = $1",
                    &[&id],
                )
                .map_err(db_err)?
                .ok_or_else(|| not_found("purpose", id))?;
            let (project, org, status, document): (String, String, String, Value) =
                (r.get(0), r.get(1), r.get(2), r.get(3));
            project_visible(t, &ctx.principal, &project).map_err(|_| not_found("purpose", id))?;
            let accepted: Vec<String> = t
                .query(
                    "SELECT organization_id FROM purpose_acceptances WHERE purpose_id = $1 ORDER BY 1",
                    &[&id],
                )
                .map_err(db_err)?
                .iter()
                .map(|r| r.get(0))
                .collect();
            Ok(json!({"id": id, "project": project, "organization": org, "status": status,
                      "purpose": document, "accepted_by": accepted}))
        })
    }

    pub fn list_purposes(&self, ctx: &Ctx, project: &str) -> Result<Value> {
        self.db.tx(|t| {
            governed_project(t, ctx, project)?;
            let rows = t
                .query(
                    "SELECT id, name, revision, organization_id, status FROM purposes
                      WHERE project_id = $1 ORDER BY name, revision, id",
                    &[&project],
                )
                .map_err(db_err)?;
            Ok(Value::Array(
                rows.iter()
                    .map(|r| {
                        json!({"id": r.get::<_, String>(0), "name": r.get::<_, String>(1),
                               "revision": r.get::<_, i32>(2), "organization": r.get::<_, String>(3),
                               "status": r.get::<_, String>(4)})
                    })
                    .collect(),
            ))
        })
    }

    // --- owner authorizations ------------------------------------------------------

    /// A person of the owning organization proposes an authorization
    /// (without approvals). It must fit an active purpose the organization
    /// accepted, name a version the organization registered, and lie
    /// within the purpose's window.
    pub fn propose_authorization(&self, ctx: &Ctx, r: ProposeAuthorization) -> Result<Value> {
        let b = r.body;
        if !b.approvals.is_empty() {
            return Err(bad(
                "propose an authorization without approvals: people approve it through /approve",
            ));
        }
        b.check()?;
        check_window(b.valid_from, b.valid_until)?;
        let id = new_id("atz");
        self.db.tx(|t| {
            let p = governed_project(t, ctx, &b.project)?;
            deny_auditor(&ctx.principal, &p)?;
            require_human(
                &ctx.principal,
                &b.party,
                &[Role::DataOwner, Role::SecurityAdmin],
                "proposing an authorization",
            )?;
            if !p.members.contains(&b.party) {
                return Err(forbidden(format!("{} is not a member of the project", b.party)));
            }
            let purpose = usable_purpose(t, &b.project, &b.purpose_id)?;
            let accepted = t
                .query_opt(
                    "SELECT 1 FROM purpose_acceptances WHERE purpose_id = $1 AND organization_id = $2",
                    &[&b.purpose_id, &b.party],
                )
                .map_err(db_err)?;
            if accepted.is_none() {
                return Err(gov(
                    Code::GovernancePurposeMismatch,
                    format!("{} has not accepted this purpose", b.party),
                ));
            }
            if b.linkage_policy_id != purpose.linkage_policy_id {
                return Err(gov(
                    Code::GovernanceLinkageMismatch,
                    "the authorization's linkage policy is not the purpose's",
                ));
            }
            if !purpose.allowed_release_classes.contains(&b.release_class) {
                return Err(gov(
                    Code::GovernanceReleaseClass,
                    format!("the purpose does not allow release class {}", b.release_class.as_str()),
                ));
            }
            if let Some(o) = b.recipients.iter().find(|o| !purpose.recipients.contains(*o)) {
                return Err(gov(
                    Code::GovernanceReleaseClass,
                    format!("{o} is not a recipient the purpose allows"),
                ));
            }
            let asset = t
                .query_opt(
                    "SELECT id, status FROM assets WHERE version_id = $1 AND organization_id = $2",
                    &[&b.asset_version_id, &b.party],
                )
                .map_err(db_err)?
                .ok_or_else(|| {
                    gov(
                        Code::GovernanceAssetVersionMismatch,
                        format!("{} registered no such dataset version", b.party),
                    )
                })?;
            let (asset_id, asset_status): (String, String) = (asset.get(0), asset.get(1));
            if asset_status != "active" {
                return Err(gov(
                    Code::GovernanceAuthorizationRevoked,
                    format!("dataset version {asset_id} is {asset_status}"),
                ));
            }
            if now() >= b.valid_until {
                return Err(gov(Code::GovernanceAuthorizationExpired, "the authorization's window is over"));
            }
            if b.valid_from < purpose.valid_from || b.valid_until > purpose.valid_until {
                return Err(gov(
                    Code::GovernanceAuthorizationExpired,
                    "the authorization's window reaches outside the purpose's",
                ));
            }
            t.execute(
                "INSERT INTO authorizations (id, organization_id, project_id, purpose_id, asset_id, asset_version_id,
                                             body, valid_from, valid_until, status, proposed_by)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'proposed', $10)",
                &[
                    &id,
                    &b.party,
                    &b.project,
                    &b.purpose_id,
                    &asset_id,
                    &b.asset_version_id,
                    &serde_json::to_value(&b).expect("serializable"),
                    &(b.valid_from as i64),
                    &(b.valid_until as i64),
                    &ctx.actor(),
                ],
            )
            .map_err(db_err)?;
            for o in &b.recipients {
                t.execute(
                    "INSERT INTO authorization_recipients (authorization_row, organization_id) VALUES ($1, $2)",
                    &[&id, o],
                )
                .map_err(db_err)?;
            }
            audit::append(
                t,
                ctx.draft("authorization.proposed", "authorization", &id, Outcome::Succeeded)
                    .org(&b.party)
                    .project(&b.project)
                    .r#ref("purpose", b.purpose_id.clone())
                    .r#ref("asset", asset_id.clone()),
            )?;
            Ok(json!({"id": id, "organization": b.party, "project": b.project, "status": "proposed"}))
        })
    }

    /// A person of the owning organization approves, in a role it holds
    /// there. Each person approves once; once the organization's rule is
    /// met (by default two people: a data owner and a security admin) the
    /// authorization is approved, ready for the owner's signature, and its
    /// approvals are closed (ENC2604): an approved authorization is
    /// immutable evidence, and a change is a new authorization.
    pub fn approve_authorization(
        &self,
        ctx: &Ctx,
        id: &str,
        r: ApproveAuthorization,
    ) -> Result<Value> {
        self.db.tx(|t| {
            let row = owned_authorization(t, ctx, id)?;
            require_human(
                &ctx.principal,
                &row.org,
                &[r.role],
                &format!("approving an authorization as {}", r.role.as_str()),
            )?;
            if row.status != "proposed" {
                return Err(conflict(format!(
                    "authorization {id} is {}: its approvals are closed (an approved authorization is \
                     immutable evidence; propose a new authorization to change it)",
                    row.status
                )));
            }
            let (issuer, subject) = approver(ctx)?;
            let again = t
                .query_opt(
                    "SELECT 1 FROM authorization_approvals WHERE authorization_row = $1
                        AND (approver_id = $2 OR (idp_issuer = $3 AND approver_subject = $4))",
                    &[&id, &ctx.actor(), &issuer, &subject],
                )
                .map_err(db_err)?;
            if again.is_some() {
                return Err(gov(
                    Code::GovernanceFourEyesIncomplete,
                    "this person has approved already: four eyes are two different people",
                ));
            }
            let evidence = ApprovalEvidence {
                statement_digest: row.body.approval_statement(&issuer, &subject, r.role.as_str()),
                approver_subject: subject.clone(),
                idp_issuer: issuer.clone(),
                auth_time: None,
                acr: None,
                amr: None,
                role: r.role.as_str().to_owned(),
                organization: row.org.clone(),
                at: now(),
            };
            t.execute(
                "INSERT INTO authorization_approvals (authorization_row, approver_id, idp_issuer, approver_subject,
                                                      role, statement_digest, evidence)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &id,
                    &ctx.actor(),
                    &issuer,
                    &subject,
                    &r.role.as_str(),
                    &evidence.statement_digest,
                    &serde_json::to_value(&evidence).expect("serializable"),
                ],
            )
            .map_err(db_err)?;
            let doc = with_approvals(t, id, &row.body)?;
            let (min, roles) = approval_rule(t, &row.project, &row.org)?;
            let status = if doc.check_quorum(min, &roles).is_ok() {
                "approved"
            } else {
                "proposed"
            };
            t.execute(
                "UPDATE authorizations SET status = $2 WHERE id = $1",
                &[&id, &status],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                ctx.draft("authorization.approved", "authorization", id, Outcome::Succeeded)
                    .org(&row.org)
                    .project(&row.project)
                    .r#ref("role", r.role.as_str()),
            )?;
            Ok(json!({"id": id, "status": status, "approvals": doc.approvals.len()}))
        })
    }

    /// The authorization as its owner's members see it: `body` is the
    /// document to sign (approvals included). Everyone else taking part in
    /// the project (members, auditor organizations) gets the shared view:
    /// the same document with each approval as (organization, role, time)
    /// and a pseudonym of the approver, and without the signed copy (whose
    /// approvals name the approvers); the same bytes for each of them.
    pub fn get_authorization(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        self.db.tx(|t| {
            let (row, _) = authorization_row(t, ctx, id)?;
            let owner = ctx.principal.member_of(&row.org);
            let body = if owner {
                serde_json::to_value(with_approvals(t, id, &row.body)?).expect("serializable")
            } else {
                let approvals = t
                    .query(
                        "SELECT approver_id, evidence FROM authorization_approvals WHERE authorization_row = $1
                          ORDER BY approved_at, approver_id",
                        &[&id],
                    )
                    .map_err(db_err)?
                    .iter()
                    .map(|r| {
                        let e: ApprovalEvidence = serde_json::from_value(r.get(1))
                            .map_err(|e| db_err(format!("stored approval: {e}")))?;
                        Ok(crate::views::shared_approval(
                            &self.pseudonyms,
                            &row.project,
                            r.get(0),
                            &e.organization,
                            &e.role,
                            e.at,
                        ))
                    })
                    .collect::<Result<Vec<Value>>>()?;
                let mut b = serde_json::to_value(&row.body).expect("serializable");
                b["approvals"] = json!(approvals);
                b
            };
            let r = t
                .query_one(
                    &format!(
                        "SELECT a.authorization_id, a.signed, a.governance_key_id, {}, {}, {}
                           FROM authorizations a
                           LEFT JOIN governance_keys k
                             ON k.key_id = a.governance_key_id AND k.organization_id = a.organization_id
                          WHERE a.id = $1",
                        epoch("a.activated_at"),
                        epoch("a.revoked_at"),
                        epoch("k.revoked_at")
                    ),
                    &[&id],
                )
                .map_err(db_err)?;
            let mut v = json!({"id": id, "organization": row.org, "project": row.project,
                               "purpose_id": row.body.purpose_id, "asset_version_id": row.body.asset_version_id,
                               "status": row.status, "body": body,
                               "revoked_at": r.get::<_, Option<i64>>(4)});
            if let Some(a) = r.get::<_, Option<String>>(0) {
                v["authorization_id"] = json!(a);
                if owner {
                    v["signed"] = r.get::<_, Option<Value>>(1).unwrap_or(Value::Null);
                }
                v["governance_key_id"] = json!(r.get::<_, Option<String>>(2));
                v["activated_at"] = json!(r.get::<_, Option<i64>>(3));
                v["governance_key_revoked_at"] = json!(r.get::<_, Option<i64>>(5));
            }
            // Whether anything new may use it now, and if not, why.
            match usable_at(t, id, now()) {
                Ok(()) => v["usable"] = json!(true),
                Err(e) => {
                    v["usable"] = json!(false);
                    v["unusable"] = json!({"code": e.code.as_str(), "message": e.message});
                }
            }
            Ok(v)
        })
    }

    /// The owner's governance-key signature over the approved document:
    /// verified against the organization's active governance key, it makes
    /// the authorization active.
    pub fn sign_authorization(
        &self,
        ctx: &Ctx,
        id: &str,
        r: AuthorizationSignature,
    ) -> Result<Value> {
        self.db.tx(|t| {
            let row = owned_authorization(t, ctx, id)?;
            require_human(
                &ctx.principal,
                &row.org,
                &[Role::SecurityAdmin, Role::DataOwner],
                "activating an authorization",
            )?;
            match row.status.as_str() {
                "revoked" => {
                    return Err(gov(
                        Code::GovernanceAuthorizationRevoked,
                        format!("authorization {id} is revoked"),
                    ))
                }
                "active" => return Err(conflict(format!("authorization {id} is active already"))),
                _ => {}
            }
            let doc = with_approvals(t, id, &row.body)?;
            let (min, roles) = approval_rule(t, &row.project, &row.org)?;
            doc.check_quorum(min, &roles)?;
            usable_purpose(t, &row.project, &doc.purpose_id)?;
            let asset_status: String = t
                .query_one(
                    "SELECT status FROM assets WHERE version_id = $1",
                    &[&doc.asset_version_id],
                )
                .map_err(db_err)?
                .get(0);
            if asset_status != "active" {
                return Err(gov(
                    Code::GovernanceAuthorizationRevoked,
                    "the dataset version is revoked",
                ));
            }
            if now() >= doc.valid_until {
                return Err(gov(
                    Code::GovernanceAuthorizationExpired,
                    "the authorization's window is over",
                ));
            }
            let signed = Signed {
                body: doc.clone(),
                public_key: r.public_key.clone(),
                signature: r.signature.clone(),
            };
            let key_id = under_active_key(t, &row.org, &r.public_key, |k| signed.verify(k))?;
            let authorization_id = doc.id();
            t.execute(
                "UPDATE authorizations SET status = 'active', authorization_id = $2, signed = $3,
                        governance_key_id = $4, activated_at = to_timestamp($5::bigint) WHERE id = $1",
                &[
                    &id,
                    &authorization_id,
                    &serde_json::to_value(&signed).expect("serializable"),
                    &key_id,
                    &secs(now()),
                ],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                ctx.draft(
                    "authorization.activated",
                    "authorization",
                    id,
                    Outcome::Succeeded,
                )
                .org(&row.org)
                .project(&row.project)
                .r#ref("authorization_id", authorization_id.clone())
                .r#ref("governance_key", key_id.clone()),
            )?;
            Ok(json!({"id": id, "status": "active", "authorization_id": authorization_id}))
        })
    }

    /// Whether anything new may use `authorization` (its row ID or its
    /// AuthorizationId) at `at` (Unix seconds): a plan, submission,
    /// schedule, start, key release or export at `at`, or, as history, an
    /// execution that ran then. See [`usable_at`]; the enforcement phases
    /// call it inside their own transactions.
    pub fn authorization_usable_at(&self, authorization: &str, at: u64) -> Result<()> {
        self.db.tx(|t| usable_at(t, authorization, at))
    }

    /// A person of the owning organization revokes the authorization (with
    /// the owner's signed revocation, when it has one). Final, and a state
    /// transition of its own, never an edit: from its recorded time (never
    /// changed) it blocks new use; it is not retroactive.
    pub fn revoke_authorization(
        &self,
        ctx: &Ctx,
        id: &str,
        r: RevokeAuthorization,
    ) -> Result<Value> {
        check_name("reason", &r.reason)?;
        let out = self.db.tx(|t| {
            // One lock order everywhere: jobs (by ID) before the
            // authorizations they run under, as scheduling, start and
            // release tickets take them. The unstarted jobs under this
            // authorization are locked first, then the authorization.
            t.execute(
                "SELECT j.id FROM jobs j JOIN job_authorizations ja ON ja.job_id = j.id
                  WHERE ja.authorization_row = $1
                    AND j.state IN ('created', 'planning', 'planned', 'waiting_for_approval', 'authorized', 'queued')
                  ORDER BY j.id FOR UPDATE OF j",
                &[&id],
            )
            .map_err(db_err)?;
            let row = owned_authorization(t, ctx, id)?;
            require_human(
                &ctx.principal,
                &row.org,
                &[Role::SecurityAdmin, Role::DataOwner],
                "revoking an authorization",
            )?;
            if row.status == "revoked" {
                return Ok(json!({"id": id, "status": "revoked"}));
            }
            let authorization_id: Option<String> = t
                .query_one(
                    "SELECT authorization_id FROM authorizations WHERE id = $1",
                    &[&id],
                )
                .map_err(db_err)?
                .get(0);
            if let Some(rev) = &r.revocation {
                if rev.body.party != row.org
                    || authorization_id.as_deref() != Some(rev.body.authorization.as_str())
                {
                    return Err(bad("the signed revocation is for another authorization"));
                }
                under_active_key(t, &row.org, &rev.public_key, |k| rev.verify(k))?;
            }
            t.execute(
                "UPDATE authorizations SET status = 'revoked', revoked_by = $2,
                        revoked_at = to_timestamp($4::bigint), revocation = $3 WHERE id = $1",
                &[
                    &id,
                    &ctx.actor(),
                    &r.revocation
                        .as_ref()
                        .map(|x| serde_json::to_value(x).expect("serializable")),
                    &secs(now()),
                ],
            )
            .map_err(db_err)?;
            // Jobs that run under it and have not started cannot start now
            // (rows locked before the audit chain, which every transaction
            // takes last). One that runs already may finish: revocation
            // blocks new use, it is not retroactive.
            let failed = self.fail_unstarted_jobs(
                t,
                ctx,
                "SELECT j.id, j.organization_id FROM jobs j
                   JOIN job_authorizations ja ON ja.job_id = j.id
                  WHERE ja.authorization_row = $1
                    AND j.state IN ('created', 'planning', 'planned', 'waiting_for_approval', 'authorized', 'queued')
                  ORDER BY j.id FOR UPDATE OF j",
                &[&id],
                "an owner authorization the job runs under was revoked",
                ("revoked_authorization", id),
            )?;
            let mut d = ctx
                .draft(
                    "authorization.revoked",
                    "authorization",
                    id,
                    Outcome::Succeeded,
                )
                .org(&row.org)
                .project(&row.project)
                .r#ref("reason", r.reason.clone());
            if let Some(a) = &authorization_id {
                d = d.r#ref("authorization_id", a.clone());
            }
            audit::append(t, d)?;
            // The owner's brokers stop using it too: queued now, sent once
            // the revocation is anchored.
            self.queue_authorization_revoked(t, ctx.actor(), &ctx.request_id, id)?;
            Ok(json!({"id": id, "status": "revoked", "failed_jobs": failed}))
        })?;
        // Anchored before acknowledging (a retry of a revoked one
        // re-anchors); the brokers' messages go out only after that.
        self.sync_anchor()?;
        let _ = self.deliver_outbox();
        Ok(out)
    }
}

/// (project, organization, status, proposer, valid_until) of a purpose.
fn purpose_row(
    t: &mut postgres::Transaction<'_>,
    id: &str,
    lock: bool,
) -> Result<(String, String, String, String, u64)> {
    let sql = if lock {
        "SELECT project_id, organization_id, status, proposed_by, valid_until FROM purposes WHERE id = $1 FOR UPDATE"
    } else {
        "SELECT project_id, organization_id, status, proposed_by, valid_until FROM purposes WHERE id = $1"
    };
    let r = t
        .query_opt(sql, &[&id])
        .map_err(db_err)?
        .ok_or_else(|| not_found("purpose", id))?;
    Ok((
        r.get(0),
        r.get(1),
        r.get(2),
        r.get(3),
        r.get::<_, i64>(4) as u64,
    ))
}

/// An active purpose of `project` (ENC2702 if there is none, ENC2706 if it
/// is retired), locked against a concurrent retirement.
pub(crate) fn usable_purpose(
    t: &mut postgres::Transaction<'_>,
    project: &str,
    id: &str,
) -> Result<Purpose> {
    let r = t
        .query_opt(
            "SELECT status, document FROM purposes WHERE id = $1 AND project_id = $2 FOR SHARE",
            &[&id, &project],
        )
        .map_err(db_err)?
        .ok_or_else(|| {
            gov(
                Code::GovernancePurposeMismatch,
                "no such purpose in this project",
            )
        })?;
    let status: String = r.get(0);
    match status.as_str() {
        "active" => {}
        "retired" => {
            return Err(gov(
                Code::GovernanceAuthorizationRevoked,
                "the purpose is retired",
            ))
        }
        s => {
            return Err(gov(
                Code::GovernancePurposeMismatch,
                format!("the purpose is {s}, not active"),
            ))
        }
    }
    serde_json::from_value(r.get(1)).map_err(|e| db_err(format!("stored purpose: {e}")))
}

struct AuthorizationRow {
    org: String,
    project: String,
    status: String,
    body: AuthorizationV2,
}

/// An authorization, locked, with its project: visible to its owner's
/// members and to everyone taking part in the project (members and auditor
/// organizations, who get the shared view); anyone else gets "not found".
fn authorization_row(
    t: &mut postgres::Transaction<'_>,
    ctx: &Ctx,
    id: &str,
) -> Result<(AuthorizationRow, ProjectRow)> {
    let r = t
        .query_opt(
            "SELECT organization_id, project_id, status, body FROM authorizations WHERE id = $1 FOR UPDATE",
            &[&id],
        )
        .map_err(db_err)?
        .ok_or_else(|| not_found("authorization", id))?;
    let row = AuthorizationRow {
        org: r.get(0),
        project: r.get(1),
        status: r.get(2),
        body: serde_json::from_value(r.get(3))
            .map_err(|e| db_err(format!("stored authorization: {e}")))?,
    };
    let p = project_row(t, &row.project)?.ok_or_else(|| not_found("authorization", id))?;
    let participant = p
        .members
        .iter()
        .chain(&p.auditors)
        .any(|o| ctx.principal.member_of(o));
    if !ctx.principal.member_of(&row.org) && !participant {
        return Err(not_found("authorization", id));
    }
    Ok((row, p))
}

/// An authorization its owner's people act on (approve, sign, revoke):
/// never an auditor ([`deny_auditor`]); others get "not found".
fn owned_authorization(
    t: &mut postgres::Transaction<'_>,
    ctx: &Ctx,
    id: &str,
) -> Result<AuthorizationRow> {
    let (row, p) = authorization_row(t, ctx, id)?;
    deny_auditor(&ctx.principal, &p)?;
    if !ctx.principal.member_of(&row.org) {
        return Err(not_found("authorization", id));
    }
    Ok(row)
}

/// The proposed body with its approvals, in a fixed order: the document
/// the owner signs.
fn with_approvals(
    t: &mut postgres::Transaction<'_>,
    id: &str,
    body: &AuthorizationV2,
) -> Result<AuthorizationV2> {
    let approvals = t
        .query(
            "SELECT evidence FROM authorization_approvals WHERE authorization_row = $1
              ORDER BY approved_at, approver_id",
            &[&id],
        )
        .map_err(db_err)?
        .iter()
        .map(|r| {
            serde_json::from_value(r.get(0)).map_err(|e| db_err(format!("stored approval: {e}")))
        })
        .collect::<Result<Vec<ApprovalEvidence>>>()?;
    Ok(AuthorizationV2 {
        approvals,
        ..body.clone()
    })
}

/// The organization's approval rule in the project: (minimum distinct
/// people, role → count). Default: two people, a data owner and a security
/// admin.
pub(crate) fn approval_rule(
    t: &mut postgres::Transaction<'_>,
    project: &str,
    org: &str,
) -> Result<(usize, BTreeMap<String, u32>)> {
    let r = t
        .query_opt(
            "SELECT min_distinct_humans, required_roles FROM approval_rules
              WHERE project_id = $1 AND organization_id = $2",
            &[&project, &org],
        )
        .map_err(db_err)?;
    Ok(match r {
        Some(r) => {
            let roles: BTreeMap<String, u32> = serde_json::from_value(r.get(1))
                .map_err(|e| db_err(format!("stored approval rule: {e}")))?;
            // Auditors never approve: such a rule could never be met (the
            // database refuses it too).
            if roles.contains_key(Role::Auditor.as_str()) {
                return Err(conflict(format!(
                    "{org}'s approval rule in project {project} requires auditor, which no approval can meet"
                )));
            }
            (r.get::<_, i32>(0).max(2) as usize, roles)
        }
        None => (
            2,
            BTreeMap::from([
                (Role::DataOwner.as_str().to_owned(), 1),
                (Role::SecurityAdmin.as_str().to_owned(), 1),
            ]),
        ),
    })
}

/// Seconds as stored (`to_timestamp($n::bigint)`): the control plane's
/// clock, so every governance time is on one clock.
fn secs(t: u64) -> i64 {
    i64::try_from(t).unwrap_or(i64::MAX)
}

/// A timestamp column as whole Unix seconds (NULL stays NULL).
fn epoch(column: &str) -> String {
    format!("floor(extract(epoch FROM {column}))::bigint")
}

fn at_or_before(t: Option<i64>, at: u64) -> Option<u64> {
    t.map(|t| t.max(0) as u64).filter(|t| *t <= at)
}

/// Whether `authorization` (row ID or AuthorizationId) may be used at `at`,
/// the rows it depends on share-locked against a concurrent revocation:
/// - it is signed, and was active by `at` (else ENC2701);
/// - it was not revoked by `at` (ENC2706);
/// - its signature verifies under the governance key that signed it, which
///   was not revoked by `at` and did not sign after its revocation
///   (ENC2708), and `at` lies in its window (ENC2705): the same check the
///   trust graph and the key brokers make
///   ([`SignedAuthorizationV2::usable_at`]);
/// - its purpose was not retired, nor its dataset version revoked, by `at`
///   (ENC2706).
///
/// A revocation (of the authorization, its key, purpose or version) blocks
/// use from its recorded time on, never before: an execution before it
/// stays valid history.
pub(crate) fn usable_at(
    t: &mut postgres::Transaction<'_>,
    authorization: &str,
    at: u64,
) -> Result<()> {
    let missing = |m: String| gov(Code::GovernanceAuthorizationMissing, m);
    let withdrawn = |m: String| gov(Code::GovernanceAuthorizationRevoked, m);
    let r = t
        .query_opt(
            &format!(
                "SELECT id, organization_id, status, signed, governance_key_id, purpose_id, asset_id, {}, {}
                   FROM authorizations WHERE id = $1 OR authorization_id = $1 FOR SHARE",
                epoch("activated_at"),
                epoch("revoked_at")
            ),
            &[&authorization],
        )
        .map_err(db_err)?
        .ok_or_else(|| missing(format!("no authorization {authorization}")))?;
    let (row, org, status): (String, String, String) = (r.get(0), r.get(1), r.get(2));
    let (signed, key_id): (Option<Value>, Option<String>) = (r.get(3), r.get(4));
    let (purpose, asset): (String, String) = (r.get(5), r.get(6));
    let (activated_at, revoked_at): (Option<i64>, Option<i64>) = (r.get(7), r.get(8));
    let (Some(signed), Some(key_id)) = (signed, key_id) else {
        return Err(missing(format!(
            "authorization {row} is {status}: only one its owner signed is used"
        )));
    };
    let signed: SignedAuthorizationV2 =
        serde_json::from_value(signed).map_err(|e| db_err(format!("stored authorization: {e}")))?;
    match activated_at {
        Some(a) if a.max(0) as u64 <= at => {}
        _ => {
            return Err(missing(format!(
                "authorization {row} was not active yet at {at}"
            )))
        }
    }
    if let Some(r) = at_or_before(revoked_at, at) {
        return Err(withdrawn(format!("authorization {row} was revoked at {r}")));
    }
    let k = t
        .query_opt(
            &format!(
                "SELECT public_key, {} FROM governance_keys
                  WHERE organization_id = $1 AND key_id = $2 FOR SHARE",
                epoch("revoked_at")
            ),
            &[&org, &key_id],
        )
        .map_err(db_err)?
        .ok_or_else(|| {
            gov(
                Code::GovernanceKeyRevoked,
                format!("the governance key that signed authorization {row} is not on record"),
            )
        })?;
    let key_revoked_at: Option<i64> = k.get(1);
    let key = GovernanceKey {
        organization: org,
        public_key: k.get(0),
        status: if key_revoked_at.is_some() {
            GovernanceKeyStatus::Revoked
        } else {
            GovernanceKeyStatus::Active
        },
        revoked_at: key_revoked_at.map(|t| t.max(0) as u64),
    };
    signed.usable_at(&key, None, at).map_err(|e| {
        if e.code == Code::TrustAuthorization {
            missing(format!(
                "authorization {row} does not verify under its governance key: {}",
                e.message
            ))
        } else {
            e
        }
    })?;
    let retired: Option<i64> = t
        .query_one(
            &format!(
                "SELECT {} FROM purposes WHERE id = $1 FOR SHARE",
                epoch("retired_at")
            ),
            &[&purpose],
        )
        .map_err(db_err)?
        .get(0);
    if let Some(r) = at_or_before(retired, at) {
        return Err(withdrawn(format!("its purpose was retired at {r}")));
    }
    let v = t
        .query_one(
            &format!(
                "SELECT status, {} FROM assets WHERE id = $1 FOR SHARE",
                epoch("revoked_at")
            ),
            &[&asset],
        )
        .map_err(db_err)?;
    let (asset_status, asset_revoked): (String, Option<i64>) = (v.get(0), v.get(1));
    if asset_status == "revoked" && asset_revoked.is_none_or(|r| r.max(0) as u64 <= at) {
        return Err(withdrawn("its dataset version was revoked".to_owned()));
    }
    Ok(())
}
