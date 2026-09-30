//! Project policies: proposed by one security admin, approved by another
//! of the project owner's organization (four eyes: two different people,
//! never service accounts). Jobs may reference an approved policy.

use serde_json::{json, Value};

use encompute_ir::Result;
use encompute_verification::canonical::canonical_json;
use encompute_verification::service::sha256_hex;

use crate::audit::{self, Outcome};
use crate::authn::PrincipalKind;
use crate::authz::{
    conflict, deny_auditor, forbidden, not_found, project_role_orgs, project_row, project_visible,
};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::model::{bad, new_id, Role};

impl Control {
    pub fn propose_policy(&self, ctx: &Ctx, project: &str, document: Value) -> Result<Value> {
        if !document.is_object() {
            return Err(bad("a policy document is a JSON object"));
        }
        if !matches!(ctx.principal.kind, PrincipalKind::User { .. }) {
            return Err(forbidden(
                "policies are proposed by people (security admins), not services",
            ));
        }
        let digest = sha256_hex(&canonical_json(&document)?);
        self.db.tx(|t| {
            let p = project_visible(t, &ctx.principal, project)?;
            deny_auditor(&ctx.principal, &p)?;
            let orgs = project_role_orgs(&ctx.principal, &p, &[Role::SecurityAdmin]);
            let org = orgs.first().cloned().ok_or_else(|| forbidden("proposing a policy needs security_admin in a project member organization"))?;
            let id = new_id("pol");
            t.execute(
                "INSERT INTO policies (id, organization_id, project_id, digest, document, status, created_by)
                 VALUES ($1, $2, $3, $4, $5, 'proposed', $6)",
                &[&id, &org, &project, &digest, &document, &ctx.actor()],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                ctx.draft("policy.changed", "policy", &id, Outcome::Succeeded)
                    .org(&org)
                    .project(project)
                    .r#ref("digest", digest.clone()),
            )?;
            Ok(json!({"id": id, "project": project, "digest": digest, "status": "proposed"}))
        })
    }

    pub fn approve_policy(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        self.db.tx(|t| {
            let r = t
                .query_opt(
                    "SELECT organization_id, project_id, status, created_by, digest FROM policies WHERE id = $1 FOR UPDATE",
                    &[&id],
                )
                .map_err(db_err)?
                .ok_or_else(|| not_found("policy", id))?;
            let (org, project, status, creator, digest): (String, String, String, String, String) =
                (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4));
            // The project's owner decides what policy governs its project:
            // a collaborator proposes, the owner's security admins approve.
            let p = project_row(t, &project)?.ok_or_else(|| not_found("policy", id))?;
            if !ctx.principal.member_of(&org) && !p.members.iter().any(|o| ctx.principal.member_of(o)) {
                return Err(not_found("policy", id));
            }
            deny_auditor(&ctx.principal, &p)?;
            if !ctx.principal.has_role(&p.organization, Role::SecurityAdmin) {
                return Err(forbidden(format!(
                    "approving a policy needs security_admin in the project's owner, {}",
                    p.organization
                )));
            }
            // Four eyes are two different people: a service account (an
            // admin's second key) is neither the approver nor the author.
            if !matches!(ctx.principal.kind, PrincipalKind::User { .. }) {
                return Err(forbidden("policies are approved by people (security admins), not services"));
            }
            if creator == ctx.actor() {
                return Err(forbidden("a policy is approved by a different security admin than its author"));
            }
            let author_is_person = t
                .query_opt("SELECT 1 FROM users WHERE id = $1", &[&creator])
                .map_err(db_err)?
                .is_some();
            if !author_is_person {
                return Err(forbidden("the policy's author is not a person: propose it again as a security admin"));
            }
            if status != "proposed" {
                return Err(conflict(format!("policy {id} is {status}")));
            }
            t.execute(
                "UPDATE policies SET status = 'approved', approved_by = $2 WHERE id = $1",
                &[&id, &ctx.actor()],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                ctx.draft("policy.approved", "policy", id, Outcome::Succeeded)
                    .org(&org)
                    .project(&project)
                    .r#ref("digest", digest.clone()),
            )?;
            Ok(json!({"id": id, "status": "approved", "digest": digest}))
        })
    }
}
