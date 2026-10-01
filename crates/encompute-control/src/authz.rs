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
//!
//! Auditors are read-only (D9). In a governed project every mutating call
//! refuses them ([`deny_auditor`]), and in an organization taking part in
//! one an auditor holds no other role ([`require_auditor_separation`],
//! ENC2716). An auditor organization takes part in a governed project only
//! to read its shared records (`crate::views`).

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

/// [`require_human`], and not the job's `submitter`: whoever submitted a
/// job never counts toward its own approval, whatever roles they hold
/// (four eyes, ENC2707).
pub fn require_human_not_submitter(
    p: &Principal,
    org: &str,
    roles: &[Role],
    action: &str,
    submitter: &str,
) -> Result<()> {
    require_human(p, org, roles, action)?;
    if p.id == submitter {
        return Err(Error::new(
            Code::GovernanceFourEyesIncomplete,
            format!("{action} needs someone other than the job's submitter"),
        ));
    }
    Ok(())
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
    /// Auditor organizations that accepted (governed projects only): they
    /// see the project's shared records and change nothing. Never in
    /// `members`.
    pub auditors: Vec<String>,
    /// Auditor organizations invited that have not accepted yet.
    pub invited_auditors: Vec<String>,
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

    /// Every organization taking part, invited or not, member or auditor.
    pub fn participants(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.organization)
            .chain(&self.members)
            .chain(&self.invited)
            .chain(&self.auditors)
            .chain(&self.invited_auditors)
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
    let (mut auditors, mut invited_auditors) = (vec![], vec![]);
    for m in c
        .query(
            "SELECT organization_id, status, participation FROM project_members
              WHERE project_id = $1 ORDER BY 1",
            &[&id],
        )
        .map_err(db_err)?
    {
        let active = m.get::<_, String>(1) == "active";
        match (m.get::<_, String>(2) == "auditor", active) {
            (false, true) => members.push(m.get(0)),
            (false, false) => invited.push(m.get(0)),
            (true, true) => auditors.push(m.get(0)),
            (true, false) => invited_auditors.push(m.get(0)),
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
        auditors,
        invited_auditors,
    }))
}

/// A project the principal's organization collaborates in, as a member or
/// (governed projects) as an auditor organization that accepted.
pub fn project_visible(c: &mut impl GenericClient, p: &Principal, id: &str) -> Result<ProjectRow> {
    let row = project_row(c, id)?.ok_or_else(|| not_found("project", id))?;
    if !row
        .members
        .iter()
        .chain(&row.auditors)
        .any(|o| p.member_of(o))
    {
        return Err(not_found("project", id));
    }
    Ok(row)
}

fn read_only(msg: String) -> Error {
    forbidden(format!("auditors are read-only: {msg}"))
}

/// Auditors change nothing in a governed project (D9): refused when the
/// principal holds `auditor` in any organization taking part in it (the
/// owner, a member, an auditor organization, invited or not), whatever
/// else it holds. Standard projects are unchanged. The membership calls
/// use only this part: an auditor organization's admin accepts and leaves
/// its own participation.
pub fn deny_auditor_role(p: &Principal, project: &ProjectRow) -> Result<()> {
    if !project.governed() {
        return Ok(());
    }
    if let Some(o) = project
        .participants()
        .find(|o| p.has_role(o, Role::Auditor))
    {
        return Err(read_only(format!(
            "auditor in {o}, which takes part in governed project {}",
            project.id
        )));
    }
    Ok(())
}

/// Every mutating call that touches governed project `project` (its
/// members, policies, purposes, authorizations, plans, jobs, approvals,
/// tickets, sources) refuses an auditor (D9, ENC2602): someone holding
/// `auditor` in an organization taking part in it ([`deny_auditor_role`]),
/// and anyone acting for one of its auditor organizations, which never
/// own, submit, receive, approve or hold keys there.
pub fn deny_auditor(p: &Principal, project: &ProjectRow) -> Result<()> {
    deny_auditor_role(p, project)?;
    if !project.governed() {
        return Ok(());
    }
    if let Some(o) = project
        .auditors
        .iter()
        .chain(&project.invited_auditors)
        .find(|o| p.member_of(o))
    {
        return Err(read_only(format!(
            "{o} audits governed project {} and changes nothing there",
            project.id
        )));
    }
    Ok(())
}

/// Whether `org` takes part in a governed project (as owner, member or
/// auditor organization, invited or not).
pub fn in_governed_project(c: &mut impl GenericClient, org: &str) -> Result<bool> {
    Ok(c.query_opt(
        "SELECT 1 FROM project_members m JOIN projects p ON p.id = m.project_id
              WHERE m.organization_id = $1 AND p.governance = 'governed' LIMIT 1",
        &[&org],
    )
    .map_err(db_err)?
    .is_some())
}

/// Whether `org` is an auditor organization: it takes part in a governed
/// project as an auditor (invited or not). Such an organization takes part
/// in no governed project as a member, and holds no keys for one.
pub fn auditor_organization(c: &mut impl GenericClient, org: &str) -> Result<bool> {
    Ok(c
        .query_opt(
            "SELECT 1 FROM project_members WHERE organization_id = $1 AND participation = 'auditor' LIMIT 1",
            &[&org],
        )
        .map_err(db_err)?
        .is_some())
}

/// Mutations of `org`'s own governance state (its assets, governance
/// keys, key brokers, privacy ledgers) refuse someone holding `auditor`
/// there once `org` takes part in a governed project (D9, ENC2602). In
/// organizations outside governed projects roles combine as before.
pub fn deny_auditor_in(c: &mut impl GenericClient, p: &Principal, org: &str) -> Result<()> {
    if p.has_role(org, Role::Auditor) && in_governed_project(c, org)? {
        return Err(read_only(format!(
            "auditor in {org}, which takes part in a governed project"
        )));
    }
    Ok(())
}

/// Serializes changes of `org`'s roles with its joining governed projects:
/// both take this transaction-scoped lock before reading what the other
/// writes, so a role combination and a governed participation are never
/// both accepted.
pub fn org_roles_lock(c: &mut impl GenericClient, org: &str) -> Result<()> {
    c.execute(
        "SELECT pg_advisory_xact_lock(hashtext('org-roles'), hashtext($1))",
        &[&org],
    )
    .map(|_| ())
    .map_err(db_err)
}

/// A principal holding `auditor` with another role: (organization,
/// principal, kind `user` or `service`, every role it holds there).
pub type AuditorCombination = (String, String, String, Vec<String>);

/// Principals of `org` (or of every organization) holding `auditor`
/// together with another role there, by organization then principal.
pub fn auditor_combinations(
    c: &mut impl GenericClient,
    orgs: Option<&[String]>,
) -> Result<Vec<AuditorCombination>> {
    let orgs: Option<Vec<String>> = orgs.map(<[String]>::to_vec);
    Ok(c.query(
        "SELECT m.organization_id, m.principal_id,
                    CASE WHEN EXISTS (SELECT 1 FROM users u WHERE u.id = m.principal_id)
                         THEN 'user' ELSE 'service' END,
                    array_agg(m.role ORDER BY m.role)
               FROM memberships m
              WHERE ($1::text[] IS NULL OR m.organization_id = ANY($1))
              GROUP BY m.organization_id, m.principal_id
             HAVING bool_or(m.role = 'auditor') AND bool_or(m.role <> 'auditor')
              ORDER BY 1, 2",
        &[&orgs],
    )
    .map_err(db_err)?
    .iter()
    .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
    .collect())
}

/// Auditor separation (D9, ENC2716): `org` may take part in a governed
/// project only while none of its principals holds `auditor` together
/// with another role there.
pub fn require_auditor_separation(c: &mut impl GenericClient, org: &str) -> Result<()> {
    let combined = auditor_combinations(c, Some(&[org.to_owned()]))?;
    if let Some((_, principal, _, roles)) = combined.first() {
        return Err(Error::new(
            Code::GovernanceAuditorSeparation,
            format!(
                "{org} cannot take part in a governed project while {principal} holds auditor with {} \
                 ({} principal(s) in all; see GET /v1/security/legacy-service-admins): an auditor holds no other role",
                roles.iter().filter(|r| *r != "auditor").cloned().collect::<Vec<_>>().join(", "),
                combined.len()
            ),
        ));
    }
    Ok(())
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
    /// A derived result (governed projects): the job that released it.
    pub derived_from_job: Option<String>,
    /// When a source of it was revoked (Unix seconds): never erased,
    /// never used again.
    pub source_revoked_at: Option<i64>,
}

pub fn asset_row(c: &mut impl GenericClient, id: &str) -> Result<Option<AssetRow>> {
    Ok(c.query_opt(
        "SELECT id, organization_id, kind, name, digest, status, lineage_root, parents, key_ref,
                    policy, size_bytes, media_type, storage_uri, derived_from_job,
                    floor(extract(epoch FROM source_revoked_at))::bigint
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
        derived_from_job: r.get(13),
        source_revoked_at: r.get(14),
    }))
}

/// An asset its owner's members see, or that its owner approved for a
/// project the principal's organization collaborates in, while that
/// organization was a member (a later member needs a new approval). In a
/// governed project, where consent is an owner-signed authorization and
/// not an approval, a source is visible beyond its owner only to an
/// organization an active authorization of it names as a recipient (while
/// a member of that project), to the submitting organization of a job
/// that runs under an authorization of it, and to the project's auditor
/// organizations (the version an authorization names). A derived result
/// is visible beyond its custodian only to the recipients its signed
/// release record names, the owners of the data it is derived from (every
/// hop up its lineage) and the auditor organizations of the project of
/// the job that released it. Anyone else gets "not found".
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
             UNION ALL
             SELECT 1 FROM authorizations z
               JOIN project_members pm ON pm.project_id = z.project_id AND pm.participation = 'auditor'
                AND pm.status = 'active'
              WHERE z.asset_id = $1 AND pm.organization_id = ANY($2)
             UNION ALL
             SELECT 1 FROM assets d JOIN jobs j ON j.id = d.derived_from_job
               JOIN project_members pm ON pm.project_id = j.project_id AND pm.status = 'active'
                AND pm.participation = 'auditor'
              WHERE d.id = $1 AND pm.organization_id = ANY($2)
             UNION ALL
             SELECT 1 FROM assets d
              WHERE d.id = $1 AND d.derived_from_job IS NOT NULL
                AND d.release_record->'body'->'recipients' ?| $2
             UNION ALL
             SELECT 1 FROM (
                 WITH RECURSIVE anc(id) AS (
                     SELECT jsonb_array_elements_text(parents) FROM assets
                      WHERE id = $1 AND derived_from_job IS NOT NULL
                     UNION
                     SELECT jsonb_array_elements_text(a.parents) FROM assets a JOIN anc ON a.id = anc.id
                 )
                 SELECT id FROM anc
             ) l JOIN assets a ON a.id = l.id
              WHERE a.organization_id = ANY($2)
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
