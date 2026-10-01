//! Organizations, users, service accounts and projects.

use serde_json::{json, Value};

use encompute_ir::Result;
use encompute_verification::service::check_service_id;

use crate::audit::{self, Outcome};
use crate::authz::{
    auditor_combinations, auditor_organization, conflict, deny_auditor_role, forbidden,
    in_governed_project, not_found, org_roles_lock, project_row, project_visible, require,
    require_auditor_separation, require_human,
};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::govlog;
use crate::model::{
    bad, check_name, check_slug, new_id, AddProjectMember, CreateOrganization, CreateProject,
    CreateServiceAccount, CreateUser, Custody, GovernanceMode, Participation, RemoveMembership,
    Role, ServiceKind, PLATFORM_ORG,
};

fn unique_violation(e: &postgres::Error) -> bool {
    e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION)
}

/// An auditor organization takes part in no governed project as a member
/// (D9, ENC2716).
fn separation(org: &str) -> encompute_ir::Error {
    encompute_ir::Error::new(
        encompute_ir::Code::GovernanceAuditorSeparation,
        format!("{org} is an auditor organization: it takes part in governed projects only as an auditor"),
    )
}

/// Joining governed project `p` as `participation` (D9): `org` has no
/// principal holding auditor with another role, and takes part in every
/// governed project the same way (an auditor organization is never a
/// member of one, and a member never an auditor organization).
fn check_governed_join(
    t: &mut postgres::Transaction<'_>,
    org: &str,
    participation: Participation,
) -> Result<()> {
    org_roles_lock(t, org)?;
    require_auditor_separation(t, org)?;
    let other = match participation {
        Participation::Member => "auditor",
        Participation::Auditor => "member",
    };
    let clash = t
        .query_opt(
            "SELECT 1 FROM project_members m JOIN projects p ON p.id = m.project_id
              WHERE m.organization_id = $1 AND p.governance = 'governed' AND m.participation = $2
             LIMIT 1",
            &[&org, &other],
        )
        .map_err(db_err)?;
    if clash.is_some() {
        return Err(match participation {
            Participation::Member => separation(org),
            Participation::Auditor => encompute_ir::Error::new(
                encompute_ir::Code::GovernanceAuditorSeparation,
                format!("{org} is a member of a governed project: an auditor organization is independent of the projects it audits"),
            ),
        });
    }
    Ok(())
}

/// Auditor separation (D9, ENC2716) when granting `roles` in `org`: an
/// auditor holds no other role in an organization taking part in a
/// governed project. Takes the organization's roles lock
/// ([`org_roles_lock`]) first, as joining a governed project does.
fn check_auditor_grant(t: &mut postgres::Transaction<'_>, org: &str, roles: &[Role]) -> Result<()> {
    if !roles.contains(&Role::Auditor) || roles.iter().all(|r| *r == Role::Auditor) {
        return Ok(());
    }
    org_roles_lock(t, org)?;
    if in_governed_project(t, org)? {
        return Err(encompute_ir::Error::new(
            encompute_ir::Code::GovernanceAuditorSeparation,
            format!(
                "{org} takes part in a governed project: an auditor there holds no other role (grant auditor alone)"
            ),
        ));
    }
    Ok(())
}

/// Principals holding `auditor` with another role, in `orgs` or
/// everywhere: each with its organization, kind, roles, whether the
/// organization takes part in a governed project (where joining is refused
/// while it lasts, ENC2716) and the call that removes the other roles.
/// Organizations outside governed projects keep such combinations for now
/// (bootstrap admins hold admin, operator and auditor); a later migration
/// removes them.
pub fn auditor_role_combinations(
    c: &mut impl postgres::GenericClient,
    orgs: Option<&[String]>,
) -> Result<Vec<Value>> {
    let mut out = vec![];
    for (org, id, kind, roles) in auditor_combinations(c, orgs)? {
        let governed = in_governed_project(c, &org)?;
        out.push(json!({
            "organization": org,
            "id": id,
            "kind": kind,
            "roles": roles,
            "governed": governed,
            "remove": {
                "method": "POST",
                "path": format!("/v1/organizations/{org}/memberships/remove"),
                "body": {"principal": id, "role": "auditor"},
            },
        }));
    }
    Ok(out)
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
        self.tx_anchored(|t| {
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
        self.tx_anchored(|t| {
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
        self.tx_anchored(|t| {
            check_auditor_grant(t, org, &r.roles)?;
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
        // A disabled service's ID is never registered again, even when its
        // row is gone: whatever trusts it by ID (an asset's broker, an
        // evaluator) would trust the new key.
        let disabled = {
            let mut c = self.db.conn()?;
            crate::govlog::contains(&mut *c, crate::govlog::NegSet::DisabledServices, &r.id)?
        };
        if disabled {
            return Err(conflict("this service ID or key is already registered"));
        }
        self.tx_anchored(|t| {
            check_auditor_grant(t, org, &r.roles)?;
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
        let out = self.tx_anchored(|t| {
            // Platform services are stored without an organization, the
            // platform's automation accounts with `platform`: both are the
            // platform's to disable.
            let row = t
                .query_opt(
                    "SELECT status, organization_id FROM service_accounts
                     WHERE id = $1 AND kind <> 'control'
                       AND (organization_id = $2 OR ($2 = $3 AND organization_id IS NULL))
                     FOR UPDATE",
                    &[&id, &org, &PLATFORM_ORG],
                )
                .map_err(db_err)?;
            let Some(row) = row else {
                return Err(not_found("service account", id));
            };
            t.execute(
                "UPDATE service_accounts SET status = 'disabled' WHERE id = $1",
                &[&id],
            )
            .map_err(db_err)?;
            let (was, owner): (String, Option<String>) = (row.get(0), row.get(1));
            if was != "disabled" {
                let mut d = govlog::Draft::new(
                    govlog::for_org(owner.as_deref()),
                    govlog::kind::SERVICE_ACCOUNT_DISABLED,
                    id,
                );
                if let Some(o) = &owner {
                    d = d.org(o);
                }
                govlog::append(t, d)?;
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
        self.checkpoint_log()?;
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
        let out = self.tx_anchored(|t| {
            let row = t
                .query_opt(
                    "SELECT status FROM users WHERE id = $1 AND organization_id = $2 FOR UPDATE",
                    &[&id, &org],
                )
                .map_err(db_err)?;
            let Some(row) = row else {
                return Err(not_found("user", id));
            };
            t.execute("UPDATE users SET status = 'disabled' WHERE id = $1", &[&id])
                .map_err(db_err)?;
            if row.get::<_, String>(0) != "disabled" {
                govlog::append(
                    t,
                    govlog::Draft::new(govlog::for_org(Some(org)), govlog::kind::USER_DISABLED, id)
                        .org(org),
                )?;
            }
            audit::append(
                t,
                ctx.draft("user.disabled", "user", id, Outcome::Succeeded)
                    .org(org),
            )?;
            Ok(json!({"id": id, "status": "disabled"}))
        })?;
        self.checkpoint_log()?;
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
        let out = self.tx_anchored(|t| {
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
                let n = t
                    .execute(
                        "INSERT INTO removed_roles (id, principal_id, organization_id, role, removed_by)
                         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                        &[id, &r.principal, &org, role, &ctx.actor()],
                    )
                    .map_err(db_err)?;
                if n == 1 {
                    govlog::append(
                        t,
                        govlog::Draft::new(govlog::for_org(Some(org)), govlog::kind::ROLE_REMOVED, id)
                            .org(org)
                            .r#ref("role", role.clone()),
                    )?;
                }
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
        self.checkpoint_log()?;
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
        let combined = auditor_role_combinations(&mut *c, scope.as_deref())?;
        Ok(json!({
            "count": accounts.len(),
            "service_accounts": accounts,
            "refused_from": LEGACY_SERVICE_ADMINS_REFUSED_FROM,
            "auditor_combinations": combined,
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
        self.tx_anchored(|t| {
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
        // A governed project is always in sovereign custody; a standard
        // project keeps the platform's custody, as before.
        let custody = match (mode, r.custody) {
            (GovernanceMode::Governed, None | Some(Custody::Sovereign)) => Custody::Sovereign,
            (GovernanceMode::Governed, Some(Custody::Standard)) => {
                return Err(encompute_ir::Error::new(
                    encompute_ir::Code::GovernanceCustody,
                    "a governed project is always in sovereign custody: each source's key is held by a key broker its own organization registered",
                ))
            }
            (GovernanceMode::Standard, None | Some(Custody::Standard)) => Custody::Standard,
            (GovernanceMode::Standard, Some(Custody::Sovereign)) => {
                return Err(bad("sovereign key custody belongs to governed projects"))
            }
        };
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
        self.tx_anchored(|t| {
            // Auditor separation: the owner takes part from now on.
            if mode == GovernanceMode::Governed {
                org_roles_lock(t, &r.organization)?;
                require_auditor_separation(t, &r.organization)?;
                if auditor_organization(t, &r.organization)? {
                    return Err(separation(&r.organization));
                }
            }
            t.execute(
                "INSERT INTO projects (id, organization_id, name, status, governance, custody)
                 VALUES ($1, $2, $3, 'active', $4, $5)",
                &[&id, &r.organization, &r.name, &mode.as_str(), &custody.as_str()],
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
                created = created
                    .r#ref("governance", mode.as_str())
                    .r#ref("custody", custody.as_str());
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
            if mode == GovernanceMode::Governed {
                out["custody"] = json!(custody.as_str());
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
        if p.governed() {
            // The shared view: the same bytes for everyone taking part
            // (consent there is by owner authorizations, never approvals).
            return Ok(json!({
                "id": p.id, "organization": p.organization, "name": p.name, "status": p.status,
                "members": p.members, "invited": p.invited, "approved_assets": [],
                "governance": p.governance, "custody": p.custody,
                "auditors": p.auditors, "invited_auditors": p.invited_auditors,
            }));
        }
        Ok(json!({
            "id": p.id, "organization": p.organization, "name": p.name, "status": p.status,
            "members": p.members, "invited": p.invited, "approved_assets": assets,
            "governance": p.governance,
        }))
    }

    /// A governed project's audit events (those recorded for the project),
    /// as everyone taking part sees them: to readers of the trail
    /// (auditors, admins, security admins) of a member or auditor
    /// organization, the same bytes for each, actors labelled and only the
    /// project's shared references ([`crate::views`]). An organization's
    /// own trail stays `GET /v1/audit?organization=`.
    pub fn project_audit(&self, ctx: &Ctx, id: &str, after: i64, limit: i64) -> Result<Value> {
        let mut c = self.db.conn()?;
        let p = project_visible(&mut *c, &ctx.principal, id)?;
        if !p.governed() {
            return Err(bad(
                "a project's shared audit view belongs to governed projects: read your organization's trail",
            ));
        }
        let readers = [Role::Auditor, Role::OrganizationAdmin, Role::SecurityAdmin];
        if !p
            .members
            .iter()
            .chain(&p.auditors)
            .any(|o| ctx.principal.any_role(o, &readers))
        {
            return Err(forbidden(
                "reading a project's audit events needs auditor, organization_admin or security_admin in an organization taking part",
            ));
        }
        let mut labels = crate::views::Labels::default();
        let mut out = vec![];
        for e in audit::list_project(&mut *c, id, after, limit)? {
            out.push(crate::views::shared_audit_event(&mut *c, &mut labels, &e)?);
        }
        Ok(Value::Array(out))
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
        let answer = |status: &str, participation: Participation| {
            let mut v = json!({"project": project, "member": r.organization, "status": status});
            if participation == Participation::Auditor {
                v["participation"] = json!(participation.as_str());
            }
            v
        };
        self.tx_anchored(|t| {
            let p = project_row(t, project)?.ok_or_else(|| not_found("project", project))?;
            let current: Option<(String, Participation)> = t
                .query_opt(
                    "SELECT status, participation FROM project_members
                      WHERE project_id = $1 AND organization_id = $2 FOR UPDATE",
                    &[&project, &r.organization],
                )
                .map_err(db_err)?
                .map(|x| Ok::<_, encompute_ir::Error>((x.get(0), Participation::parse(x.get(1))?)))
                .transpose()?;
            // The invited organization's admin accepts, as invited.
            if let (true, Some(("invited", invited_as))) =
                (consents, current.as_ref().map(|(s, a)| (s.as_str(), *a)))
            {
                deny_auditor_role(&ctx.principal, &p)?;
                if r.participation.is_some_and(|x| x != invited_as) {
                    return Err(conflict(format!(
                        "{} is invited as {}",
                        r.organization,
                        invited_as.as_str()
                    )));
                }
                if p.governed() {
                    check_governed_join(t, &r.organization, invited_as)?;
                }
                t.execute(
                    "UPDATE project_members SET status = 'active' WHERE project_id = $1 AND organization_id = $2",
                    &[&project, &r.organization],
                )
                .map_err(db_err)?;
                self.audit_joined(t, ctx, &p.organization, project, &r.organization, invited_as)?;
                return Ok(answer("active", invited_as));
            }
            if !p.members.iter().any(|o| ctx.principal.member_of(o)) {
                return Err(not_found("project", project));
            }
            deny_auditor_role(&ctx.principal, &p)?;
            require(&ctx.principal, &p.organization, &[Role::OrganizationAdmin], "adding a project member")?;
            let participation = r.participation.unwrap_or_default();
            if participation == Participation::Auditor {
                if !p.governed() {
                    return Err(bad("auditor organizations take part in governed projects only"));
                }
                if r.organization == p.organization {
                    return Err(bad("the project's owner cannot audit it"));
                }
            }
            if let Some((s, was)) = current {
                if was != participation {
                    return Err(conflict(format!(
                        "{} takes part as {}: a different participation is a new membership",
                        r.organization,
                        was.as_str()
                    )));
                }
                return Ok(answer(&s, was));
            }
            let exists = r.organization != PLATFORM_ORG
                && t
                    .query_opt("SELECT 1 FROM organizations WHERE id = $1", &[&r.organization])
                    .map_err(db_err)?
                    .is_some();
            if !exists {
                return Ok(answer("invited", participation));
            }
            // An admin of both organizations consents for the invited one.
            // (A membership's ID is never reused: an organization that left
            // and is invited again is a new member.)
            let status = if consents { "active" } else { "invited" };
            if consents && p.governed() {
                check_governed_join(t, &r.organization, participation)?;
            }
            t.execute(
                "INSERT INTO project_members (project_id, organization_id, added_by, status, membership_id, participation)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[&project, &r.organization, &ctx.actor(), &status, &new_id("pmb"), &participation.as_str()],
            )
            .map_err(db_err)?;
            if consents {
                self.audit_joined(t, ctx, &p.organization, project, &r.organization, participation)?;
            } else {
                let mut invited = ctx
                    .draft("project.member_invited", "project", project, Outcome::Succeeded)
                    .org(&p.organization)
                    .project(project)
                    .r#ref("member", r.organization.clone());
                if participation == Participation::Auditor {
                    invited = invited.r#ref("participation", participation.as_str());
                }
                audit::append(t, invited)?;
                // The invited organization learns of it from its own trail.
                let mut told = ctx
                    .draft("project.invited", "project", project, Outcome::Succeeded)
                    .org(&r.organization)
                    .project(project)
                    .r#ref("owner", p.organization.clone());
                if participation == Participation::Auditor {
                    told = told.r#ref("participation", participation.as_str());
                }
                audit::append(t, told)?;
            }
            Ok(answer(status, participation))
        })
    }

    fn audit_joined(
        &self,
        t: &mut postgres::Transaction<'_>,
        ctx: &Ctx,
        owner: &str,
        project: &str,
        member: &str,
        participation: Participation,
    ) -> Result<()> {
        let mut added = ctx
            .draft(
                "project.member_added",
                "project",
                project,
                Outcome::Succeeded,
            )
            .org(owner)
            .project(project)
            .r#ref("member", member.to_owned());
        let mut joined = ctx
            .draft("project.joined", "project", project, Outcome::Succeeded)
            .org(member)
            .project(project);
        if participation == Participation::Auditor {
            added = added.r#ref("participation", participation.as_str());
            joined = joined.r#ref("participation", participation.as_str());
        }
        audit::append(t, added)?;
        // The added organization's own trail records it too.
        audit::append(t, joined)?;
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
        let out = self.tx_anchored(|t| {
            let p = project_row(t, project)?.ok_or_else(|| not_found("project", project))?;
            deny_auditor_role(&ctx.principal, &p)?;
            let own = ctx.principal.has_role(&r.organization, Role::OrganizationAdmin);
            let invited_here =
                p.invited.contains(&r.organization) || p.invited_auditors.contains(&r.organization);
            let taking_part = p.members.contains(&r.organization) || p.auditors.contains(&r.organization);
            if !own || !(taking_part || invited_here) {
                if !p.members.iter().chain(&p.auditors).any(|o| ctx.principal.member_of(o)) {
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
            let n = t
                .execute(
                    "INSERT INTO removed_memberships (id, project_id, organization_id, removed_by)
                     VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                    &[&removed, &project, &r.organization, &ctx.actor()],
                )
                .map_err(db_err)?;
            if n == 1 {
                let partition = govlog::for_project(t, project, Some(&p.organization))?;
                govlog::append(
                    t,
                    govlog::Draft::new(partition, govlog::kind::MEMBERSHIP_REMOVED, &removed)
                        .org(&r.organization)
                        .r#ref("project", project),
                )?;
            }
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
        self.checkpoint_log()?;
        Ok(out)
    }
}
