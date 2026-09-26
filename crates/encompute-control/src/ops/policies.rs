//! Project policies: proposed by one security admin, approved by another
//! (four eyes). Jobs may reference an approved policy.

use serde_json::{json, Value};

use encompute_ir::Result;
use encompute_verification::canonical::canonical_json;
use encompute_verification::service::sha256_hex;

use crate::audit::{self, Outcome};
use crate::authz::{conflict, forbidden, not_found, project_role_orgs, project_visible, require};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::model::{bad, new_id, Role};

impl Control {
    pub fn propose_policy(&self, ctx: &Ctx, project: &str, document: Value) -> Result<Value> {
        if !document.is_object() {
            return Err(bad("a policy document is a JSON object"));
        }
        let digest = sha256_hex(&canonical_json(&document)?);
        self.db.tx(|t| {
            let p = project_visible(t, &ctx.principal, project)?;
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
            if !ctx.principal.member_of(&org) {
                return Err(not_found("policy", id));
            }
            require(&ctx.principal, &org, &[Role::SecurityAdmin], "approving a policy")?;
            if creator == ctx.actor() {
                return Err(forbidden("a policy is approved by a different security admin than its author"));
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
