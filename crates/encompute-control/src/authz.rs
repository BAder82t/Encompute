//! Authorization: roles within an organization, and tenant isolation.
//!
//! Isolation is the default: an identity sees only its own organizations'
//! resources, plus what an explicit collaboration grants (project
//! membership its organization accepted, and assets their owners approved
//! for a project and purpose while it was a member). A resource outside that is reported as not found (ENC2603),
//! so other tenants' IDs do not even confirm existence. Inside its own
//! organization, a missing role is ENC2602.
//!
//! Platform admins (organization `platform`) create organizations and
//! register platform services; they get no access to tenant data.

use postgres::GenericClient;

use encompute_ir::{Code, Error, Result};

use crate::authn::{Principal, PrincipalKind};
use crate::db::db_err;
use crate::model::Role;

pub fn forbidden(msg: impl Into<String>) -> Error {
    Error::new(Code::Forbidden, msg)
}

pub fn not_found(what: &str, id: &str) -> Error {
    Error::new(Code::NotFound, format!("no {what} {id:?}"))
}

pub fn conflict(msg: impl Into<String>) -> Error {
    Error::new(Code::Conflict, msg)
}

/// A person acting for `org` in a governed project: never a service
/// account (an automation key an admin holds is not a second pair of eyes,
/// ENC2707), homed in `org` (a role held there by someone of another
/// organization does not count), never an auditor (read-only, whatever
/// else it holds), and holding one of `roles` there. Non-members get "not
/// found" for the organization itself.
pub fn require_human(p: &Principal, org: &str, roles: &[Role], action: &str) -> Result<()> {
    if !p.member_of(org) {
        return Err(not_found("organization", org));
    }
    if !matches!(p.kind, PrincipalKind::User { .. }) {
        return Err(Error::new(
            Code::GovernanceFourEyesIncomplete,
            format!("{action} needs a person, not a service account"),
        ));
    }
    if p.organization.as_deref() != Some(org) {
        return Err(forbidden(format!(
            "{action} needs a person of {org}: roles held from another organization do not count"
        )));
    }
    if p.has_role(org, Role::Auditor) {
        return Err(forbidden(format!(
            "auditors are read-only: {action} needs someone who is not an auditor"
        )));
    }
    require(p, org, roles, action)
}

/// Four eyes: `actor` is none of the people who already acted (`earlier`).
pub fn require_other_person(actor: &str, earlier: &[&str], action: &str) -> Result<()> {
    if earlier.contains(&actor) {
        return Err(Error::new(
            Code::GovernanceFourEyesIncomplete,
            format!("{action} needs a different person"),
        ));
    }
    Ok(())
}

/// The principal must hold one of `roles` in `org`. Non-members get
/// "not found" for the organization itself.
pub fn require(p: &Principal, org: &str, roles: &[Role], action: &str) -> Result<()> {
    if !p.member_of(org) {
        return Err(not_found("organization", org));
    }
    if !p.any_role(org, roles) {
        return Err(forbidden(format!(
            "{action} needs one of {} in {org}",
            roles
                .iter()
                .map(|r| r.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ProjectRow {
    pub id: String,
    pub organization: String,
    pub name: String,
    pub status: String,
    /// Organizations whose membership is effective (accepted).
    pub members: Vec<String>,
    /// Organizations invited that have not accepted yet: they see and do
    /// nothing in the project.
    pub invited: Vec<String>,
    /// `standard` or `governed` (immutable).
    pub governance: String,
    /// `standard` or `sovereign` (governed projects only; immutable).
    pub custody: String,
}

impl ProjectRow {
    pub fn governed(&self) -> bool {
        self.governance == "governed"
    }

    /// Every source's key is held by a broker its own organization
    /// registered.
    pub fn sovereign(&self) -> bool {
        self.custody == "sovereign"
    }
}

pub fn project_row(c: &mut impl GenericClient, id: &str) -> Result<Option<ProjectRow>> {
    let Some(r) = c
        .query_opt(
            "SELECT id, organization_id, name, status, governance, custody FROM projects WHERE id = $1",
            &[&id],
        )
        .map_err(db_err)?
    else {
        return Ok(None);
    };
    let (mut members, mut invited) = (vec![], vec![]);
    for m in c
        .query(
            "SELECT organization_id, status FROM project_members WHERE project_id = $1 ORDER BY 1",
            &[&id],
        )
        .map_err(db_err)?
    {
        if m.get::<_, String>(1) == "active" {
            members.push(m.get(0));
        } else {
            invited.push(m.get(0));
        }
    }
    Ok(Some(ProjectRow {
        id: r.get(0),
        organization: r.get(1),
        name: r.get(2),
        status: r.get(3),
        members,
        invited,
        governance: r.get(4),
        custody: r.get(5),
    }))
}

/// A project the principal's organization collaborates in.
pub fn project_visible(c: &mut impl GenericClient, p: &Principal, id: &str) -> Result<ProjectRow> {
    let row = project_row(c, id)?.ok_or_else(|| not_found("project", id))?;
    if !row.members.iter().any(|o| p.member_of(o)) {
        return Err(not_found("project", id));
    }
    Ok(row)
}

/// The organizations through which `p` takes part in `project` with one of
/// `roles`.
pub fn project_role_orgs(p: &Principal, project: &ProjectRow, roles: &[Role]) -> Vec<String> {
    project
        .members
        .iter()
        .filter(|o| p.any_role(o, roles))
        .cloned()
        .collect()
}

#[derive(Clone, Debug)]
pub struct AssetRow {
    pub id: String,
    pub organization: String,
    pub kind: String,
    pub name: String,
    pub digest: String,
    pub status: String,
    pub lineage_root: String,
    pub parents: Vec<String>,
    pub key_ref: Option<serde_json::Value>,
    pub policy: serde_json::Value,
    pub size_bytes: Option<i64>,
    pub media_type: Option<String>,
    pub storage_uri: Option<String>,
}

pub fn asset_row(c: &mut impl GenericClient, id: &str) -> Result<Option<AssetRow>> {
    Ok(c.query_opt(
        "SELECT id, organization_id, kind, name, digest, status, lineage_root, parents, key_ref,
                    policy, size_bytes, media_type, storage_uri
             FROM assets WHERE id = $1",
        &[&id],
    )
    .map_err(db_err)?
    .map(|r| AssetRow {
        id: r.get(0),
        organization: r.get(1),
        kind: r.get(2),
        name: r.get(3),
        digest: r.get(4),
        status: r.get(5),
        lineage_root: r.get(6),
        parents: serde_json::from_value(r.get(7)).unwrap_or_default(),
        key_ref: r.get(8),
        policy: r.get(9),
        size_bytes: r.get(10),
        media_type: r.get(11),
        storage_uri: r.get(12),
    }))
}

/// An asset its owner's members see, or that its owner approved for a
/// project the principal's organization collaborates in, while that
/// organization was a member (a later member needs a new approval). In a
/// governed project, where consent is an owner-signed authorization and
/// not an approval, a source is visible beyond its owner only to an
/// organization an active authorization of it names as a recipient (while
/// a member of that project), and to the submitting organization of a job
/// that runs under an authorization of it. Anyone else gets "not found".
/// Other organizations get the row without where it is stored, which key
/// protects it or its size.
pub fn asset_visible(c: &mut impl GenericClient, p: &Principal, id: &str) -> Result<AssetRow> {
    let a = asset_row(c, id)?.ok_or_else(|| not_found("asset", id))?;
    if p.member_of(&a.organization) {
        return Ok(a);
    }
    let orgs: Vec<String> = p.organizations().into_iter().collect();
    let shared = c
        .query_opt(
            "SELECT 1 FROM asset_approval_members am
               JOIN project_members pm ON pm.project_id = am.project_id
                AND pm.organization_id = am.organization_id AND pm.status = 'active'
              WHERE am.asset_id = $1 AND am.organization_id = ANY($2)
             UNION ALL
             SELECT 1 FROM authorizations z
               JOIN authorization_recipients ar ON ar.authorization_row = z.id
               JOIN project_members pm ON pm.project_id = z.project_id
                AND pm.organization_id = ar.organization_id AND pm.status = 'active'
              WHERE z.asset_id = $1 AND z.status = 'active' AND ar.organization_id = ANY($2)
             UNION ALL
             SELECT 1 FROM job_authorizations ja JOIN jobs j ON j.id = ja.job_id
              WHERE ja.asset_id = $1 AND j.organization_id = ANY($2)
             LIMIT 1",
            &[&id, &orgs],
        )
        .map_err(db_err)?;
    if shared.is_some() {
        Ok(AssetRow {
            key_ref: None,
            storage_uri: None,
            size_bytes: None,
            media_type: None,
            ..a
        })
    } else {
        Err(not_found("asset", id))
    }
}
