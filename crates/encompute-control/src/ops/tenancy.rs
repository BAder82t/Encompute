//! Organizations, users, service accounts and projects.

use serde_json::{json, Value};

use encompute_ir::Result;
use encompute_verification::service::check_service_id;

use crate::audit::{self, Outcome};
use crate::authz::{
    conflict, forbidden, not_found, project_row, project_visible, require, require_human,
};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::model::{
    bad, check_name, check_slug, new_id, AddProjectMember, CreateOrganization, CreateProject,
    CreateServiceAccount, CreateUser, GovernanceMode, RemoveMembership, Role, ServiceKind,
    PLATFORM_ORG,
};

fn unique_violation(e: &postgres::Error) -> bool {
    e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION)
}

/// The release that refuses legacy security_admin service accounts.
pub const LEGACY_SERVICE_ADMINS_REFUSED_FROM: &str = "0.4.0";

/// Service accounts holding security_admin (legacy: no path grants it any
/// more), in `orgs` or everywhere, by organization then ID: each with its
/// kind, status, creation time, last audited action (UTC, RFC 3339) and
/// the call that removes the role.
pub fn legacy_service_admins(
    c: &mut impl postgres::GenericClient,
    orgs: Option<&[String]>,
) -> Result<Vec<Value>> {
    const TS: &str = "'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'";
    let sql = format!(
        "SELECT m.organization_id, s.id, s.kind, s.status,
                to_char(s.created_at AT TIME ZONE 'UTC', {TS}),
                (SELECT to_char(max(e.at) AT TIME ZONE 'UTC', {TS})
                   FROM audit_events e WHERE e.actor = s.id)
           FROM memberships m JOIN service_accounts s ON s.id = m.principal_id
          WHERE m.role = 'security_admin'
            AND ($1::text[] IS NULL OR m.organization_id = ANY($1))
          ORDER BY 1, 2"
    );
    let orgs: Option<Vec<String>> = orgs.map(<[String]>::to_vec);
    Ok(c.query(sql.as_str(), &[&orgs])
        .map_err(db_err)?
        .iter()
        .map(|r| {
            let (org, id): (String, String) = (r.get(0), r.get(1));
            json!({
                "organization": org,
                "id": id,
                "kind": r.get::<_, String>(2),
                "status": r.get::<_, String>(3),
                "created_at": r.get::<_, String>(4),
                "last_activity": r.get::<_, Option<String>>(5),
                "remove": {
                    "method": "POST",
                    "path": format!("/v1/organizations/{org}/memberships/remove"),
                    "body": {"principal": id, "role": "security_admin"},
                },
            })
        })
        .collect())
}

impl Control {
    /// First start: the platform organization and its first admin (an OIDC
    /// identity). Refused once any organization exists.
    pub fn bootstrap(&self, issuer: &str, subject: &str, email: Option<&str>) -> Result<String> {
        self.db.tx(|t| {
            let n: i64 = t
                .query_one("SELECT count(*) FROM organizations", &[])
                .map_err(db_err)?
                .get(0);
            if n > 0 {
                return Err(conflict("already bootstrapped: organizations exist"));
            }
            t.execute(
                "INSERT INTO organizations (id, display_name, status, policy_namespace)
                 VALUES ($1, 'Platform operators', 'active', $1)",
                &[&PLATFORM_ORG],
            )
            .map_err(db_err)?;
            let id = new_id("usr");
            t.execute(
                "INSERT INTO users (id, organization_id, issuer, subject, email, status)
                 VALUES ($1, $2, $3, $4, $5, 'active')",
                &[&id, &PLATFORM_ORG, &issuer, &subject, &email],
            )
            .map_err(db_err)?;
            for role in [Role::OrganizationAdmin, Role::Operator, Role::Auditor] {
                t.execute(
                    "INSERT INTO memberships (principal_id, organization_id, role, membership_id) VALUES ($1, $2, $3, $4)",
                    &[&id, &PLATFORM_ORG, &role.as_str(), &new_id("rol")],
                )
                .map_err(db_err)?;
            }
            audit::append(
                t,
                audit::AuditDraft::new("bootstrap", "bootstrap", "platform.bootstrapped", "user", &id, Outcome::Succeeded)
                    .org(PLATFORM_ORG),
            )?;
            Ok(id)
        })
    }

    pub fn create_organization(&self, ctx: &Ctx, r: CreateOrganization) -> Result<Value> {
        require(
            &ctx.principal,
            PLATFORM_ORG,
            &[Role::OrganizationAdmin],
            "creating an organization",
        )?;
        check_slug("organization ID", &r.id)?;
        check_name("display name", &r.display_name)?;
        if r.id == PLATFORM_ORG {
            return Err(conflict("the platform organization is reserved"));
        }
        self.db.tx(|t| {
            t.execute(
                "INSERT INTO organizations (id, display_name, status, policy_namespace)
                 VALUES ($1, $2, 'active', $1)",
                &[&r.id, &r.display_name],
            )
            .map_err(|e| {
                if unique_violation(&e) {
                    conflict(format!("organization {} exists", r.id))
                } else {
                    db_err(e)
                }
            })?;
            audit::append(
                t,
                ctx.draft("organization.created", "organization", &r.id, Outcome::Succeeded)
                    .org(&r.id),
            )?;
            let mut admin_id = None;
            if let Some(a) = &r.admin {
                check_name("issuer", &a.issuer)?;
                check_name("subject", &a.subject)?;
                let id = new_id("usr");
                t.execute(
                    "INSERT INTO users (id, organization_id, issuer, subject, email, status)
                     VALUES ($1, $2, $3, $4, $5, 'active')",
                    &[&id, &r.id, &a.issuer, &a.subject, &a.email],
                )
                .map_err(|e| {
                    if unique_violation(&e) {
                        conflict("this identity is already registered")
                    } else {
                        db_err(e)
                    }
                })?;
                t.execute(
                    "INSERT INTO memberships (principal_id, organization_id, role, membership_id)
                     VALUES ($1, $2, 'organization_admin', $3)",
                    &[&id, &r.id, &new_id("rol")],
                )
                .map_err(db_err)?;
                audit::append(
                    t,
                    ctx.draft("user.created", "user", &id, Outcome::Succeeded)
                        .org(&r.id)
                        .r#ref("roles", "organization_admin"),
                )?;
                admin_id = Some(id);
            }
            Ok(json!({"id": r.id, "display_name": r.display_name, "status": "active", "policy_namespace": r.id, "admin": admin_id}))
        })
    }

    pub fn get_organization(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        if !ctx.principal.member_of(id) {
            return Err(not_found("organization", id));
        }
        let mut c = self.db.conn()?;
        let r = c
            .query_opt(
                "SELECT id, display_name, status, policy_namespace FROM organizations WHERE id = $1",
                &[&id],
            )
            .map_err(db_err)?
            .ok_or_else(|| not_found("organization", id))?;
        Ok(json!({
            "id": r.get::<_, String>(0),
            "display_name": r.get::<_, String>(1),
            "status": r.get::<_, String>(2),
            "policy_namespace": r.get::<_, String>(3),
        }))
    }

    pub fn create_user(&self, ctx: &Ctx, org: &str, r: CreateUser) -> Result<Value> {
        require(
            &ctx.principal,
            org,
            &[Role::OrganizationAdmin],
            "adding a user",
        )?;
        check_name("issuer", &r.issuer)?;
        check_name("subject", &r.subject)?;
        if r.roles.is_empty() {
            return Err(bad("a user needs at least one role"));
        }
        let id = new_id("usr");
        self.db.tx(|t| {
            t.execute(
                "INSERT INTO users (id, organization_id, issuer, subject, email, status)
                 VALUES ($1, $2, $3, $4, $5, 'active')",
                &[&id, &org, &r.issuer, &r.subject, &r.email],
            )
            .map_err(|e| {
                if unique_violation(&e) {
                    conflict("this identity is already registered")
                } else {
                    db_err(e)
                }
            })?;
            for role in &r.roles {
                t.execute(
                    "INSERT INTO memberships (principal_id, organization_id, role, membership_id) VALUES ($1, $2, $3, $4)",
                    &[&id, &org, &role.as_str(), &new_id("rol")],
                )
                .map_err(db_err)?;
            }
            audit::append(
                t,
                ctx.draft("user.created", "user", &id, Outcome::Succeeded)
                    .org(org)
                    .r#ref(
                        "roles",
                        r.roles.iter().map(|x| x.as_str()).collect::<Vec<_>>().join("+"),
                    ),
            )?;
            Ok(json!({"id": id, "organization": org, "roles": r.roles}))
        })
    }

    /// A service account. Evaluators, SecAgg coordinators and key brokers
    /// run for the platform (`org` = `platform`, registered by its admins);
    /// organizations register automation accounts for themselves.
    pub fn create_service_account(
        &self,
        ctx: &Ctx,
        org: &str,
        r: CreateServiceAccount,
        url: Option<String>,
    ) -> Result<Value> {
        require(
            &ctx.principal,
            org,
            &[Role::OrganizationAdmin],
            "registering a service account",
        )?;
        check_service_id(&r.id).map_err(|e| bad(e.message))?;
        let platform = org == PLATFORM_ORG;
        match (r.kind, platform) {
            (ServiceKind::Control, _) => return Err(bad("the control plane registers itself")),
            (ServiceKind::Evaluator | ServiceKind::Secagg, false) => {
                return Err(bad(
                    "evaluators and SecAgg coordinators are platform services",
                ))
            }
            _ => {}
        }
        if !r.roles.is_empty() && platform && r.kind != ServiceKind::Automation {
            return Err(bad("platform services hold no organization roles"));
        }
        // Security administration (policy four eyes, revocation) is for
        // people: an admin could otherwise create the second pair of eyes
        // itself, as a key it holds.
        if r.roles.contains(&Role::SecurityAdmin) {
            return Err(bad(
                "service accounts do not hold security_admin: give it to people",
            ));
        }
        encompute_verification::EvaluatorIdentity::from_public_key_hex(&r.public_key)
            .map_err(|_| bad("public_key must be a 32-byte Ed25519 key in hex"))?;
        let owner: Option<&str> = if platform && r.kind != ServiceKind::Automation {
            None
        } else {
            Some(org)
        };
        self.db.tx(|t| {
            // An organization's key broker cannot take the name another
            // organization's assets give their broker (it would receive
            // their revocations). The platform's brokers serve every
            // organization. (Same answer as a taken ID: no oracle.) The
            // broker ID's lock, taken by asset registrations naming it
            // too, serializes the two checks; it is taken for every kind,
            // since an asset naming a service that is not a key broker is
            // refused as well.
            crate::ops::keybroker_lock(t, &r.id)?;
            if r.kind == ServiceKind::Keybroker {
                if let Some(o) = owner {
                    let named = t
                        .query_opt(
                            "SELECT 1 FROM assets WHERE key_ref->>'broker' = $1 AND organization_id <> $2 LIMIT 1",
                            &[&r.id, &o],
                        )
                        .map_err(db_err)?;
                    if named.is_some() {
                        return Err(conflict("this service ID or key is already registered"));
                    }
                }
            }
            t.execute(
                "INSERT INTO service_accounts (id, organization_id, kind, public_key, url, status)
                 VALUES ($1, $2, $3, $4, $5, 'active')",
                &[&r.id, &owner, &r.kind.as_str(), &r.public_key, &url],
            )
            .map_err(|e| {
                if unique_violation(&e) {
                    conflict("this service ID or key is already registered")
                } else {
                    db_err(e)
                }
            })?;
            for role in &r.roles {
                t.execute(
                    "INSERT INTO memberships (principal_id, organization_id, role, membership_id) VALUES ($1, $2, $3, $4)",
                    &[&r.id, &org, &role.as_str(), &new_id("rol")],
                )
                .map_err(db_err)?;
            }
            audit::append(
                t,
                ctx.draft("service_account.created", "service_account", &r.id, Outcome::Succeeded)
                    .org(org)
                    .r#ref("kind", r.kind.as_str()),
            )?;
            Ok(json!({"id": r.id, "kind": r.kind, "organization": owner, "roles": r.roles}))
        })
    }

    pub fn disable_service_account(&self, ctx: &Ctx, org: &str, id: &str) -> Result<Value> {
        require(
            &ctx.principal,
            org,
            &[Role::OrganizationAdmin, Role::SecurityAdmin],
            "disabling a service account",
        )?;
        let out = self.db.tx(|t| {
            // Platform services are stored without an organization, the
            // platform's automation accounts with `platform`: both are the
            // platform's to disable.
            let n = t
                .execute(
                    "UPDATE service_accounts SET status = 'disabled'
                     WHERE id = $1 AND kind <> 'control'
                       AND (organization_id = $2 OR ($2 = $3 AND organization_id IS NULL))",
                    &[&id, &org, &PLATFORM_ORG],
                )
                .map_err(db_err)?;
            if n == 0 {
                return Err(not_found("service account", id));
            }
            audit::append(
                t,
                ctx.draft(
                    "service_account.disabled",
                    "service_account",
                    id,
                    Outcome::Succeeded,
                )
                .org(org),
            )?;
            Ok(json!({"id": id, "status": "disabled"}))
        })?;
        // Anchored before acknowledging: a restored database cannot bring
        // the account back.
        self.sync_anchor()?;
        Ok(out)
    }

    /// Disables a user of the organization: every request it makes is
    /// refused from the next one on (ENC2601). Anchored, like a service
    /// account's disable.
    pub fn disable_user(&self, ctx: &Ctx, org: &str, id: &str) -> Result<Value> {
        require(
            &ctx.principal,
            org,
            &[Role::OrganizationAdmin, Role::SecurityAdmin],
            "disabling a user",
        )?;
        let out = self.db.tx(|t| {
            let n = t
                .execute(
                    "UPDATE users SET status = 'disabled' WHERE id = $1 AND organization_id = $2",
                    &[&id, &org],
                )
                .map_err(db_err)?;
            if n == 0 {
                return Err(not_found("user", id));
            }
            audit::append(
                t,
                ctx.draft("user.disabled", "user", id, Outcome::Succeeded)
                    .org(org),
            )?;
            Ok(json!({"id": id, "status": "disabled"}))
        })?;
        self.sync_anchor()?;
        Ok(out)
    }

    /// Removes a principal's role (or all its roles) in the organization,
    /// effective from its next request. Each role removed is recorded (by
    /// its membership ID, never reused) and anchored before the removal is
    /// acknowledged: a restored database that holds it again is refused at
    /// startup (ROLE STATE ROLLBACK). A role granted again later is a new
    /// membership.
    pub fn remove_membership(&self, ctx: &Ctx, org: &str, r: RemoveMembership) -> Result<Value> {
        require(
            &ctx.principal,
            org,
            &[Role::OrganizationAdmin],
            "removing a role",
        )?;
        check_name("principal", &r.principal)?;
        let out = self.db.tx(|t| {
            let mut removed: Vec<(String, String)> = t
                .query(
                    "DELETE FROM memberships WHERE principal_id = $1 AND organization_id = $2
                        AND ($3::text IS NULL OR role = $3) RETURNING role, membership_id",
                    &[&r.principal, &org, &r.role.map(|x| x.as_str())],
                )
                .map_err(db_err)?
                .iter()
                .map(|x| (x.get(0), x.get(1)))
                .collect();
            if removed.is_empty() {
                return Err(not_found("membership of", &r.principal));
            }
            removed.sort();
            for (role, id) in &removed {
                t.execute(
                    "INSERT INTO removed_roles (id, principal_id, organization_id, role, removed_by)
                     VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                    &[id, &r.principal, &org, role, &ctx.actor()],
                )
                .map_err(db_err)?;
            }
            let roles: Vec<String> = removed.iter().map(|(role, _)| role.clone()).collect();
            let ids: Vec<&str> = removed.iter().map(|(_, id)| id.as_str()).collect();
            audit::append(
                t,
                ctx.draft(
                    "membership.removed",
                    "principal",
                    &r.principal,
                    Outcome::Succeeded,
                )
                .org(org)
                .r#ref("roles", roles.join("+"))
                .r#ref("memberships", ids.join("+")),
            )?;
            Ok(json!({"principal": r.principal, "organization": org, "removed": roles}))
        })?;
        // Anchored before acknowledging: a restored database cannot give
        // the role back.
        self.sync_anchor()?;
        Ok(out)
    }

    /// Service accounts that still hold security_admin: granted before
    /// 0.3.0 refused the role to services, and kept (never stripped
    /// silently) until an organization admin removes it. Platform operators,
    /// admins, security admins and auditors see every organization's; an
    /// organization's admins, security admins and auditors see their own.
    pub fn list_legacy_service_admins(&self, ctx: &Ctx) -> Result<Value> {
        let readers = [Role::OrganizationAdmin, Role::SecurityAdmin, Role::Auditor];
        let scope: Option<Vec<String>> = if ctx.principal.any_role(
            PLATFORM_ORG,
            &[
                Role::Operator,
                Role::OrganizationAdmin,
                Role::SecurityAdmin,
                Role::Auditor,
            ],
        ) {
            None
        } else {
            let orgs: Vec<String> = ctx
                .principal
                .organizations()
                .into_iter()
                .filter(|o| ctx.principal.any_role(o, &readers))
                .collect();
            if orgs.is_empty() {
                return Err(forbidden(
                    "listing legacy service admins needs organization_admin, security_admin or auditor",
                ));
            }
            Some(orgs)
        };
        let mut c = self.db.conn()?;
        let accounts = legacy_service_admins(&mut *c, scope.as_deref())?;
        Ok(json!({
            "count": accounts.len(),
            "service_accounts": accounts,
            "refused_from": LEGACY_SERVICE_ADMINS_REFUSED_FROM,
        }))
    }

    /// Records a root key rotation (done in the organization's KMS by its
    /// key broker) in the audit trail: old and new version, actor, time.
    pub fn record_key_rotation(&self, ctx: &Ctx, org: &str, r: Value) -> Result<Value> {
        require(
            &ctx.principal,
            org,
            &[Role::SecurityAdmin, Role::OrganizationAdmin],
            "recording a key rotation",
        )?;
        let s = |k: &str| {
            r[k].as_str()
                .map(str::to_owned)
                .ok_or_else(|| bad(format!("missing {k}")))
        };
        let n = |k: &str| r[k].as_u64().ok_or_else(|| bad(format!("missing {k}")));
        let (provider, key_ref, old, new) = (
            s("provider")?,
            s("key_ref")?,
            n("old_version")?,
            n("new_version")?,
        );
        if new <= old {
            return Err(bad("the new key version must be newer"));
        }
        self.db.tx(|t| {
            audit::append(
                t,
                ctx.draft("key.rotated", "organization", org, Outcome::Succeeded)
                    .org(org)
                    .r#ref("provider", provider.clone())
                    .r#ref("key_ref", key_ref.clone())
                    .r#ref("old_version", old.to_string())
                    .r#ref("new_version", new.to_string()),
            )?;
            Ok(json!({"organization": org, "provider": provider, "key_ref": key_ref, "old_version": old, "new_version": new}))
        })
    }

    /// Creates a project, `standard` unless `governance` says `governed`
    /// (immutable either way). `organizations` are invited: each one's
    /// admin accepts. A governed project, or one that invites, is created
    /// by a person who administers the owning organization.
    pub fn create_project(&self, ctx: &Ctx, r: CreateProject) -> Result<Value> {
        let mode = r.governance.unwrap_or_default();
        if mode == GovernanceMode::Governed || !r.organizations.is_empty() {
            require_human(
                &ctx.principal,
                &r.organization,
                &[Role::OrganizationAdmin],
                "creating a governed project, or inviting at creation,",
            )?;
        } else {
            require(
                &ctx.principal,
                &r.organization,
                &[Role::OrganizationAdmin, Role::MlDeveloper],
                "creating a project",
            )?;
        }
        check_name("project name", &r.name)?;
        let invited: std::collections::BTreeSet<String> = r.organizations.iter().cloned().collect();
        for o in &invited {
            check_slug("organization", o)?;
            if o == &r.organization || o == PLATFORM_ORG {
                return Err(bad(format!("{o} cannot be invited to its own project")));
            }
        }
        let id = new_id("prj");
        self.db.tx(|t| {
            t.execute(
                "INSERT INTO projects (id, organization_id, name, status, governance) VALUES ($1, $2, $3, 'active', $4)",
                &[&id, &r.organization, &r.name, &mode.as_str()],
            )
            .map_err(|e| {
                if unique_violation(&e) {
                    conflict(format!("project {} exists in {}", r.name, r.organization))
                } else {
                    db_err(e)
                }
            })?;
            t.execute(
                "INSERT INTO project_members (project_id, organization_id, added_by, membership_id) VALUES ($1, $2, $3, $4)",
                &[&id, &r.organization, &ctx.actor(), &new_id("pmb")],
            )
            .map_err(db_err)?;
            // (Standard projects' audit events are unchanged.)
            let mut created = ctx
                .draft("project.created", "project", &id, Outcome::Succeeded)
                .org(&r.organization)
                .project(&id);
            if mode == GovernanceMode::Governed {
                created = created.r#ref("governance", mode.as_str());
            }
            audit::append(t, created)?;
            // Invitations, as `add_project_member` makes them: an unknown
            // organization gets the same answer (nothing is recorded).
            for o in &invited {
                let exists = t
                    .query_opt("SELECT 1 FROM organizations WHERE id = $1", &[o])
                    .map_err(db_err)?
                    .is_some();
                if !exists {
                    continue;
                }
                t.execute(
                    "INSERT INTO project_members (project_id, organization_id, added_by, status, membership_id)
                     VALUES ($1, $2, $3, 'invited', $4)",
                    &[&id, o, &ctx.actor(), &new_id("pmb")],
                )
                .map_err(db_err)?;
                audit::append(
                    t,
                    ctx.draft("project.member_invited", "project", &id, Outcome::Succeeded)
                        .org(&r.organization)
                        .project(&id)
                        .r#ref("member", o.clone()),
                )?;
                audit::append(
                    t,
                    ctx.draft("project.invited", "project", &id, Outcome::Succeeded)
                        .org(o)
                        .project(&id)
                        .r#ref("owner", r.organization.clone()),
                )?;
            }
            let mut out = json!({"id": id, "organization": r.organization, "name": r.name,
                                 "members": [r.organization], "governance": mode.as_str()});
            if !invited.is_empty() {
                out["invited"] = json!(invited);
            }
            Ok(out)
        })
    }

    pub fn list_projects(&self, ctx: &Ctx) -> Result<Value> {
        let orgs: Vec<String> = ctx.principal.organizations().into_iter().collect();
        let mut c = self.db.conn()?;
        let rows = c
            .query(
                "SELECT DISTINCT p.id, p.organization_id, p.name, p.status, p.governance FROM projects p
                   JOIN project_members m ON m.project_id = p.id AND m.status = 'active'
                  WHERE m.organization_id = ANY($1) ORDER BY p.id",
                &[&orgs],
            )
            .map_err(db_err)?;
        Ok(Value::Array(
            rows.iter()
                .map(|r| {
                    json!({"id": r.get::<_, String>(0), "organization": r.get::<_, String>(1),
                           "name": r.get::<_, String>(2), "status": r.get::<_, String>(3),
                           "governance": r.get::<_, String>(4)})
                })
                .collect(),
        ))
    }

    pub fn get_project(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let p = project_visible(&mut *c, &ctx.principal, id)?;
        // The approvals that cover the caller's organizations (or are of
        // their own assets): a later member does not learn of earlier ones.
        let orgs: Vec<String> = ctx.principal.organizations().into_iter().collect();
        let assets = c
            .query(
                "SELECT DISTINCT ap.asset_id, ap.purpose FROM asset_approvals ap
                   JOIN assets a ON a.id = ap.asset_id
                  WHERE ap.project_id = $1
                    AND (a.organization_id = ANY($2)
                         OR EXISTS (SELECT 1 FROM asset_approval_members am
                                     WHERE am.asset_id = ap.asset_id AND am.project_id = ap.project_id
                                       AND am.purpose = ap.purpose AND am.organization_id = ANY($2)))
                  ORDER BY 1, 2",
                &[&id, &orgs],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| json!({"asset": r.get::<_, String>(0), "purpose": r.get::<_, String>(1)}))
            .collect::<Vec<_>>();
        Ok(json!({
            "id": p.id, "organization": p.organization, "name": p.name, "status": p.status,
            "members": p.members, "invited": p.invited, "approved_assets": assets,
            "governance": p.governance,
        }))
    }

    /// Invites a collaborating organization, or accepts an invitation.
    ///
    /// The project owner's admins invite; the invited organization's admins
    /// accept (the same call, naming their own organization), and only then
    /// is it a member: it sees the project, and nothing of the others'
    /// assets until their owners approve them for it. The answer to an
    /// invitation is the same whether or not the organization exists.
    pub fn add_project_member(
        &self,
        ctx: &Ctx,
        project: &str,
        r: AddProjectMember,
    ) -> Result<Value> {
        check_name("organization", &r.organization)?;
        let consents = ctx
            .principal
            .has_role(&r.organization, Role::OrganizationAdmin)
            && r.organization != PLATFORM_ORG;
        let answer =
            |status: &str| json!({"project": project, "member": r.organization, "status": status});
        self.db.tx(|t| {
            let p = project_row(t, project)?.ok_or_else(|| not_found("project", project))?;
            let current: Option<String> = t
                .query_opt(
                    "SELECT status FROM project_members WHERE project_id = $1 AND organization_id = $2 FOR UPDATE",
                    &[&project, &r.organization],
                )
                .map_err(db_err)?
                .map(|x| x.get(0));
            // The invited organization's admin accepts.
            if consents && current.as_deref() == Some("invited") {
                t.execute(
                    "UPDATE project_members SET status = 'active' WHERE project_id = $1 AND organization_id = $2",
                    &[&project, &r.organization],
                )
                .map_err(db_err)?;
                self.audit_joined(t, ctx, &p.organization, project, &r.organization)?;
                return Ok(answer("active"));
            }
            if !p.members.iter().any(|o| ctx.principal.member_of(o)) {
                return Err(not_found("project", project));
            }
            require(&ctx.principal, &p.organization, &[Role::OrganizationAdmin], "adding a project member")?;
            if let Some(s) = current {
                return Ok(answer(&s));
            }
            let exists = r.organization != PLATFORM_ORG
                && t
                    .query_opt("SELECT 1 FROM organizations WHERE id = $1", &[&r.organization])
                    .map_err(db_err)?
                    .is_some();
            if !exists {
                return Ok(answer("invited"));
            }
            // An admin of both organizations consents for the invited one.
            // (A membership's ID is never reused: an organization that left
            // and is invited again is a new member.)
            let status = if consents { "active" } else { "invited" };
            t.execute(
                "INSERT INTO project_members (project_id, organization_id, added_by, status, membership_id)
                 VALUES ($1, $2, $3, $4, $5)",
                &[&project, &r.organization, &ctx.actor(), &status, &new_id("pmb")],
            )
            .map_err(db_err)?;
            if consents {
                self.audit_joined(t, ctx, &p.organization, project, &r.organization)?;
            } else {
                audit::append(
                    t,
                    ctx.draft("project.member_invited", "project", project, Outcome::Succeeded)
                        .org(&p.organization)
                        .project(project)
                        .r#ref("member", r.organization.clone()),
                )?;
                // The invited organization learns of it from its own trail.
                audit::append(
                    t,
                    ctx.draft("project.invited", "project", project, Outcome::Succeeded)
                        .org(&r.organization)
                        .project(project)
                        .r#ref("owner", p.organization.clone()),
                )?;
            }
            Ok(answer(status))
        })
    }

    fn audit_joined(
        &self,
        t: &mut postgres::Transaction<'_>,
        ctx: &Ctx,
        owner: &str,
        project: &str,
        member: &str,
    ) -> Result<()> {
        audit::append(
            t,
            ctx.draft(
                "project.member_added",
                "project",
                project,
                Outcome::Succeeded,
            )
            .org(owner)
            .project(project)
            .r#ref("member", member.to_owned()),
        )?;
        // The added organization's own trail records it too.
        audit::append(
            t,
            ctx.draft("project.joined", "project", project, Outcome::Succeeded)
                .org(member)
                .project(project),
        )?;
        Ok(())
    }

    /// Removes a member organization (or declines or withdraws an
    /// invitation): the project owner's admins remove any other member, a
    /// member's admins remove their own organization. Its approvals in the
    /// project go (both ways: others' assets approved to it, and its own
    /// assets approved to the project), and the project's jobs that have
    /// not started and that it submitted or that use its assets fail. The
    /// removal is anchored before it is acknowledged, like the grants it
    /// ended: a restored database that lists the organization again is
    /// refused at startup (MEMBERSHIP STATE ROLLBACK).
    pub fn remove_project_member(
        &self,
        ctx: &Ctx,
        project: &str,
        r: AddProjectMember,
    ) -> Result<Value> {
        check_name("organization", &r.organization)?;
        let out = self.db.tx(|t| {
            let p = project_row(t, project)?.ok_or_else(|| not_found("project", project))?;
            let own = ctx.principal.has_role(&r.organization, Role::OrganizationAdmin);
            let invited_here = p.invited.contains(&r.organization);
            if !own || !(p.members.contains(&r.organization) || invited_here) {
                if !p.members.iter().any(|o| ctx.principal.member_of(o)) {
                    return Err(not_found("project", project));
                }
                if !ctx.principal.has_role(&p.organization, Role::OrganizationAdmin) {
                    return Err(forbidden(
                        "removing a project member needs organization_admin in the project's owner or in that member",
                    ));
                }
            }
            if r.organization == p.organization {
                return Err(forbidden("the project's owner cannot leave it"));
            }
            // The membership (or invitation) is recorded as removed, and
            // anchored: a restored database that lists it again is refused.
            let removed = t
                .query_opt(
                    "DELETE FROM project_members WHERE project_id = $1 AND organization_id = $2
                     RETURNING membership_id",
                    &[&project, &r.organization],
                )
                .map_err(db_err)?
                .ok_or_else(|| not_found("project member", &r.organization))?
                .get::<_, String>(0);
            t.execute(
                "INSERT INTO removed_memberships (id, project_id, organization_id, removed_by)
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                &[&removed, &project, &r.organization, &ctx.actor()],
            )
            .map_err(db_err)?;
            // Its grants in the project end, and so do the approvals of its
            // own assets there: recorded as withdrawn (and anchored), so a
            // restored database cannot share them again.
            crate::ops::withdraw_grants(
                t,
                ctx.actor(),
                "project_id = $1 AND asset_id IN (SELECT id FROM assets WHERE organization_id = $2)",
                "project_id = $1 AND organization_id = $2",
                &[&project, &r.organization],
            )?;
            let failed = self.fail_unstarted_jobs(
                t,
                ctx,
                "SELECT j.id, j.organization_id FROM jobs j
                  WHERE j.project_id = $1
                    AND j.state IN ('created', 'planning', 'planned', 'waiting_for_approval', 'authorized', 'queued')
                    AND (j.organization_id = $2
                         OR EXISTS (SELECT 1 FROM assets x WHERE x.organization_id = $2 AND j.source_assets ? x.id))
                  ORDER BY j.id FOR UPDATE",
                &[&project, &r.organization],
                "an organization left the project",
                ("removed_member", &r.organization),
            )?;
            audit::append(
                t,
                ctx.draft("project.member_removed", "project", project, Outcome::Succeeded)
                    .org(&p.organization)
                    .project(project)
                    .r#ref("member", r.organization.clone())
                    .r#ref("membership", removed.clone()),
            )?;
            audit::append(
                t,
                ctx.draft("project.left", "project", project, Outcome::Succeeded)
                    .org(&r.organization)
                    .project(project),
            )?;
            Ok(json!({"project": project, "member": r.organization, "removed": true, "failed_jobs": failed}))
        })?;
        self.sync_anchor()?;
        Ok(out)
    }
}
