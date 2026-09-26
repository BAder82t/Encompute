//! Organizations, users, service accounts and projects.

use serde_json::{json, Value};

use encompute_ir::Result;
use encompute_verification::service::check_service_id;

use crate::audit::{self, Outcome};
use crate::authz::{conflict, not_found, project_visible, require};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::model::{
    bad, check_name, check_slug, new_id, AddProjectMember, CreateOrganization, CreateProject,
    CreateServiceAccount, CreateUser, Role, ServiceKind, PLATFORM_ORG,
};

fn unique_violation(e: &postgres::Error) -> bool {
    e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION)
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
                    "INSERT INTO memberships (principal_id, organization_id, role) VALUES ($1, $2, $3)",
                    &[&id, &PLATFORM_ORG, &role.as_str()],
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
                    "INSERT INTO memberships (principal_id, organization_id, role) VALUES ($1, $2, 'organization_admin')",
                    &[&id, &r.id],
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
                    "INSERT INTO memberships (principal_id, organization_id, role) VALUES ($1, $2, $3)",
                    &[&id, &org, &role.as_str()],
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
        encompute_verification::EvaluatorIdentity::from_public_key_hex(&r.public_key)
            .map_err(|_| bad("public_key must be a 32-byte Ed25519 key in hex"))?;
        let owner: Option<&str> = if platform && r.kind != ServiceKind::Automation {
            None
        } else {
            Some(org)
        };
        self.db.tx(|t| {
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
                    "INSERT INTO memberships (principal_id, organization_id, role) VALUES ($1, $2, $3)",
                    &[&r.id, &org, &role.as_str()],
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
        let owner: Option<&str> = if org == PLATFORM_ORG { None } else { Some(org) };
        self.db.tx(|t| {
            let n = t
                .execute(
                    "UPDATE service_accounts SET status = 'disabled'
                     WHERE id = $1 AND organization_id IS NOT DISTINCT FROM $2 AND kind <> 'control'",
                    &[&id, &owner],
                )
                .map_err(db_err)?;
            if n == 0 {
                return Err(not_found("service account", id));
            }
            audit::append(t, ctx.draft("service_account.disabled", "service_account", id, Outcome::Succeeded).org(org))?;
            Ok(json!({"id": id, "status": "disabled"}))
        })
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

    pub fn create_project(&self, ctx: &Ctx, r: CreateProject) -> Result<Value> {
        require(
            &ctx.principal,
            &r.organization,
            &[Role::OrganizationAdmin, Role::MlDeveloper],
            "creating a project",
        )?;
        check_name("project name", &r.name)?;
        let id = new_id("prj");
        self.db.tx(|t| {
            t.execute(
                "INSERT INTO projects (id, organization_id, name, status) VALUES ($1, $2, $3, 'active')",
                &[&id, &r.organization, &r.name],
            )
            .map_err(|e| {
                if unique_violation(&e) {
                    conflict(format!("project {} exists in {}", r.name, r.organization))
                } else {
                    db_err(e)
                }
            })?;
            t.execute(
                "INSERT INTO project_members (project_id, organization_id, added_by) VALUES ($1, $2, $3)",
                &[&id, &r.organization, &ctx.actor()],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                ctx.draft("project.created", "project", &id, Outcome::Succeeded)
                    .org(&r.organization)
                    .project(&id),
            )?;
            Ok(json!({"id": id, "organization": r.organization, "name": r.name, "members": [r.organization]}))
        })
    }

    pub fn list_projects(&self, ctx: &Ctx) -> Result<Value> {
        let orgs: Vec<String> = ctx.principal.organizations().into_iter().collect();
        let mut c = self.db.conn()?;
        let rows = c
            .query(
                "SELECT DISTINCT p.id, p.organization_id, p.name, p.status FROM projects p
                   JOIN project_members m ON m.project_id = p.id
                  WHERE m.organization_id = ANY($1) ORDER BY p.id",
                &[&orgs],
            )
            .map_err(db_err)?;
        Ok(Value::Array(
            rows.iter()
                .map(|r| {
                    json!({"id": r.get::<_, String>(0), "organization": r.get::<_, String>(1),
                           "name": r.get::<_, String>(2), "status": r.get::<_, String>(3)})
                })
                .collect(),
        ))
    }

    pub fn get_project(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let p = project_visible(&mut *c, &ctx.principal, id)?;
        let assets = c
            .query(
                "SELECT asset_id, purpose FROM asset_approvals WHERE project_id = $1 ORDER BY 1, 2",
                &[&id],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| json!({"asset": r.get::<_, String>(0), "purpose": r.get::<_, String>(1)}))
            .collect::<Vec<_>>();
        Ok(json!({
            "id": p.id, "organization": p.organization, "name": p.name, "status": p.status,
            "members": p.members, "approved_assets": assets,
        }))
    }

    /// Adds a collaborating organization. Only the project owner's admins
    /// may; the new member sees the project, and nothing of the others'
    /// assets until their owners approve them for it.
    pub fn add_project_member(
        &self,
        ctx: &Ctx,
        project: &str,
        r: AddProjectMember,
    ) -> Result<Value> {
        self.db.tx(|t| {
            let p = project_visible(t, &ctx.principal, project)?;
            require(&ctx.principal, &p.organization, &[Role::OrganizationAdmin], "adding a project member")?;
            let exists = t
                .query_opt("SELECT 1 FROM organizations WHERE id = $1 AND id <> $2", &[&r.organization, &PLATFORM_ORG])
                .map_err(db_err)?;
            if exists.is_none() {
                return Err(not_found("organization", &r.organization));
            }
            let n = t
                .execute(
                    "INSERT INTO project_members (project_id, organization_id, added_by) VALUES ($1, $2, $3)
                     ON CONFLICT DO NOTHING",
                    &[&project, &r.organization, &ctx.actor()],
                )
                .map_err(db_err)?;
            if n > 0 {
                audit::append(
                    t,
                    ctx.draft("project.member_added", "project", project, Outcome::Succeeded)
                        .org(&p.organization)
                        .project(project)
                        .r#ref("member", r.organization.clone()),
                )?;
                // The added organization's own trail records it too.
                audit::append(
                    t,
                    ctx.draft("project.joined", "project", project, Outcome::Succeeded)
                        .org(&r.organization)
                        .project(project),
                )?;
            }
            Ok(json!({"project": project, "member": r.organization}))
        })
    }
}
