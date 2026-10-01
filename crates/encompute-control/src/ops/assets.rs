//! The asset registry (metadata only), sharing approvals, revocation,
//! lineage, and privacy ledgers.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use encompute_ir::{Code, Error, Result};
use encompute_privacy::{Genesis, PrivacyEvent};
use encompute_verification::canonical::canonical_json;
use encompute_verification::service::sha256_hex;

use crate::audit::{self, Outcome};
use crate::authz::{
    asset_row, asset_visible, conflict, deny_auditor, deny_auditor_in, forbidden, not_found,
    project_visible, require, AssetRow,
};
use crate::control::{load_ledger, runtime_rollback, Control, Ctx};
use crate::db::db_err;
use crate::model::{
    bad, check_digest, check_name, check_storage_uri, new_id, ApproveAsset, AssetKind, KeyRef,
    RegisterAsset, Role, ServiceKind,
};
use crate::transport::{seal, Scope};

/// One asset in a lineage view: a derived result also shows its job and,
/// once a source of it was revoked, when (a later revocation is shown; it
/// erased nothing).
fn lineage_entry(x: &AssetRow) -> Value {
    let mut v =
        json!({"id": x.id, "kind": x.kind, "status": x.status, "organization": x.organization});
    if let Some(j) = &x.derived_from_job {
        v["derived_from_job"] = json!(j);
    }
    if let Some(t) = x.source_revoked_at {
        v["source_revoked_at"] = json!(t);
    }
    if let Some(t) = x.expired_at {
        v["expired_at"] = json!(t);
    }
    if let Some(t) = x.source_expired_at {
        v["source_expired_at"] = json!(t);
    }
    v
}

/// What a revocation did: the jobs it failed and the derived results
/// downstream it marked (none of them erased).
pub(crate) struct Revoked {
    pub failed_jobs: Vec<String>,
    pub downstream: Vec<String>,
}

/// What happened to the source of the derived results downstream.
#[derive(Clone, Copy)]
pub(crate) enum Downstream {
    /// `source_revoked_at`.
    Revoked,
    /// `source_expired_at`.
    Expired,
}

/// Marks every derived result downstream of asset `id` (governed only: a
/// standard asset's children are unchanged, and every hop down) with the
/// time its source was revoked or expired, each once, in the caller's
/// transaction, after `id` itself was updated; returns them. A derivation
/// racing this one holds its parents shared, so it either finished (and is
/// found here) or sees the change. Until none is new: marking one waits for
/// a derivation holding it, whose result the next round finds.
pub(crate) fn mark_downstream(
    t: &mut postgres::Transaction<'_>,
    id: &str,
    what: Downstream,
) -> Result<Vec<String>> {
    let mark = match what {
        Downstream::Revoked => {
            "UPDATE assets SET source_revoked_at = now()
              WHERE id = ANY($1) AND source_revoked_at IS NULL"
        }
        Downstream::Expired => {
            "UPDATE assets SET source_expired_at = now()
              WHERE id = ANY($1) AND source_expired_at IS NULL"
        }
    };
    let mut downstream: Vec<String> = vec![];
    loop {
        let found: Vec<String> = t
            .query(
                "WITH RECURSIVE d(id) AS (
                     SELECT x.id FROM assets x WHERE x.parents ? $1 AND x.derived_from_job IS NOT NULL
                     UNION
                     SELECT x.id FROM assets x JOIN d ON x.parents ? d.id
                      WHERE x.derived_from_job IS NOT NULL
                 )
                 SELECT id FROM d ORDER BY id",
                &[&id],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        if found.len() == downstream.len() {
            break;
        }
        t.execute(mark, &[&found]).map_err(db_err)?;
        downstream = found;
    }
    Ok(downstream)
}

fn owner_roles(kind: &str) -> &'static [Role] {
    match kind {
        "dataset" => &[Role::DataOwner, Role::OrganizationAdmin],
        "model" | "adapter" | "checkpoint" => &[Role::ModelOwner, Role::OrganizationAdmin],
        _ => &[
            Role::DataOwner,
            Role::ModelOwner,
            Role::MlDeveloper,
            Role::OrganizationAdmin,
        ],
    }
}

/// Deletes the approvals `approvals` selects and the grants (covered
/// organizations) `grants` selects, both over `params`, and records each
/// one's ID as withdrawn: the state anchor keeps them withdrawn, so a
/// restored database that still holds one is refused. Returns how many
/// approvals were deleted.
pub(crate) fn withdraw_grants(
    t: &mut postgres::Transaction<'_>,
    actor: &str,
    approvals: &str,
    grants: &str,
    params: &[&(dyn postgres::types::ToSql + Sync)],
) -> Result<u64> {
    // The grants first: those of the deleted approvals would otherwise go
    // by the cascade, unrecorded.
    let g = t
        .query(
            &format!(
                "WITH d AS (DELETE FROM asset_approval_members
                             WHERE {grants}
                                OR (asset_id, project_id, purpose) IN
                                   (SELECT asset_id, project_id, purpose FROM asset_approvals WHERE {approvals})
                            RETURNING grant_id, asset_id, project_id, purpose, organization_id)
                 SELECT grant_id, asset_id, project_id, purpose, organization_id FROM d"
            ),
            params,
        )
        .map_err(db_err)?;
    let a = t
        .query(
            &format!(
                "DELETE FROM asset_approvals WHERE {approvals}
                 RETURNING approval_id, asset_id, project_id, purpose"
            ),
            params,
        )
        .map_err(db_err)?;
    for r in &g {
        let n = t
            .execute(
                "INSERT INTO withdrawn_grants (id, kind, asset_id, project_id, purpose, organization_id, withdrawn_by)
                 VALUES ($1, 'grant', $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
                &[
                    &r.get::<_, String>(0),
                    &r.get::<_, String>(1),
                    &r.get::<_, String>(2),
                    &r.get::<_, String>(3),
                    &r.get::<_, String>(4),
                    &actor,
                ],
            )
            .map_err(db_err)?;
        if n == 1 {
            log_withdrawal(
                t,
                &r.get::<_, String>(0),
                "grant",
                &r.get::<_, String>(1),
                &r.get::<_, String>(2),
                Some(&r.get::<_, String>(4)),
            )?;
        }
    }
    for r in &a {
        let n = t
            .execute(
                "INSERT INTO withdrawn_grants (id, kind, asset_id, project_id, purpose, withdrawn_by)
                 VALUES ($1, 'approval', $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                &[
                    &r.get::<_, String>(0),
                    &r.get::<_, String>(1),
                    &r.get::<_, String>(2),
                    &r.get::<_, String>(3),
                    &actor,
                ],
            )
            .map_err(db_err)?;
        if n == 1 {
            log_withdrawal(
                t,
                &r.get::<_, String>(0),
                "approval",
                &r.get::<_, String>(1),
                &r.get::<_, String>(2),
                None,
            )?;
        }
    }
    Ok(a.len() as u64)
}

/// Records a withdrawn approval or ended grant in the governance log: in
/// the project's partition when it is governed, the asset owner's
/// otherwise.
fn log_withdrawal(
    t: &mut postgres::Transaction<'_>,
    id: &str,
    what: &str,
    asset: &str,
    project: &str,
    covered: Option<&str>,
) -> Result<()> {
    let owner: Option<String> = t
        .query_opt(
            "SELECT organization_id FROM assets WHERE id = $1",
            &[&asset],
        )
        .map_err(db_err)?
        .map(|r| r.get(0));
    let partition = crate::govlog::for_project(t, project, owner.as_deref())?;
    let mut d = crate::govlog::Draft::new(partition, crate::govlog::kind::GRANT_WITHDRAWN, id)
        .r#ref("withdrawn", what)
        .r#ref("asset", asset)
        .r#ref("project", project);
    if let Some(o) = &owner {
        d = d.org(o);
    }
    if let Some(c) = covered {
        d = d.r#ref("covered_organization", c);
    }
    crate::govlog::append(t, d)?;
    Ok(())
}

/// An asset as its owner's members see it.
pub fn asset_json(a: &AssetRow) -> Value {
    let mut v = json!({
        "id": a.id, "organization": a.organization, "kind": a.kind, "name": a.name,
        "digest": a.digest, "status": a.status, "lineage_root": a.lineage_root,
        "parents": a.parents, "key_ref": a.key_ref, "policy": a.policy,
        "size_bytes": a.size_bytes, "media_type": a.media_type, "storage_uri": a.storage_uri,
    });
    derived_fields(a, &mut v);
    // The owner's retention of a version.
    for (k, t) in [
        ("delete_after", a.delete_after),
        ("retention_until", a.retention_until),
        ("evidence_retention_until", a.evidence_retention_until),
    ] {
        if let Some(t) = t {
            v[k] = json!(t);
        }
    }
    v
}

/// A derived result's job and custodian, and when a source of it was
/// revoked or expired, or it expired itself: only on assets that have
/// them, so other views are unchanged.
fn derived_fields(a: &AssetRow, v: &mut Value) {
    if let Some(j) = &a.derived_from_job {
        v["derived_from_job"] = json!(j);
        v["custodian"] = json!(a.organization);
    }
    for (k, t) in [
        ("source_revoked_at", a.source_revoked_at),
        ("expired_at", a.expired_at),
        ("source_expired_at", a.source_expired_at),
    ] {
        if let Some(t) = t {
            v[k] = json!(t);
        }
    }
}

/// An asset as another organization it is shared with sees it: what
/// identifies it and whether it can be used, never where it is stored,
/// which key protects it, its size or its owner's full policy. Of the
/// policy only `require_job_approval` is shown (a submitter needs to know
/// the owner approves each job).
pub fn shared_asset_json(a: &AssetRow) -> Value {
    let mut policy = serde_json::Map::new();
    if let Some(v) = a.policy.get("require_job_approval") {
        policy.insert("require_job_approval".into(), v.clone());
    }
    let mut v = json!({
        "id": a.id, "organization": a.organization, "kind": a.kind, "name": a.name,
        "digest": a.digest, "status": a.status, "lineage_root": a.lineage_root,
        "parents": a.parents, "policy": policy,
    });
    derived_fields(a, &mut v);
    v
}

/// The view of `a` for `p`: in full to its owner's members, redacted to
/// everyone else.
pub fn asset_view(p: &crate::authn::Principal, a: &AssetRow) -> Value {
    if p.member_of(&a.organization) {
        asset_json(a)
    } else {
        shared_asset_json(a)
    }
}

/// A registered policy as its owner sends it: the IR asset policy in its
/// canonical JSON form (no unknown or redundant field), well formed, and
/// owned by `organization` alone. Returns the value to store.
fn registered_policy(v: &Value, organization: &str) -> Result<Value> {
    use encompute_ir::confidentiality::{check_text, AssetPolicy, PartyId};
    let p: AssetPolicy = serde_json::from_value(v.clone())
        .map_err(|e| bad(format!("ir_policy is not an asset policy: {e}")))?;
    let canonical = serde_json::to_value(&p).expect("serializable");
    if &canonical != v {
        return Err(bad(
            "ir_policy has unknown, missing or non-canonical fields (absent optional fields are left out)",
        ));
    }
    let party = |x: &PartyId| PartyId::new(x.as_str()).map(|_| ());
    for x in p
        .owners
        .iter()
        .chain(&p.readers)
        .chain(p.derive.values().flat_map(|d| &d.to))
    {
        party(x)?;
    }
    let owner = PartyId::new(organization)
        .map_err(|_| bad("the organization's ID is not a party ID: it cannot register a policy"))?;
    if p.owners != [owner].into() {
        return Err(bad(format!(
            "a registered policy's owners are exactly its organization, {organization}"
        )));
    }
    for x in &p.purposes {
        check_text("purpose", x)?;
    }
    if let Some(b) = &p.privacy {
        b.validate()?;
    }
    p.check_forms()?;
    Ok(canonical)
}

impl Control {
    pub fn register_asset(&self, ctx: &Ctx, r: RegisterAsset) -> Result<Value> {
        deny_auditor_in(&mut *self.db.conn()?, &ctx.principal, &r.organization)?;
        require(
            &ctx.principal,
            &r.organization,
            owner_roles(r.kind.as_str()),
            &format!("registering a {}", r.kind.as_str()),
        )?;
        check_name("asset name", &r.name)?;
        check_digest("digest", &r.digest)?;
        if let Some(u) = &r.storage_uri {
            check_storage_uri(u)?;
        }
        if let Some(k) = &r.key_ref {
            check_name("key_ref.broker", &k.broker)?;
            check_name("key_ref.key_ref", &k.key_ref)?;
        }
        if r.privacy_budget.is_some() && r.kind != AssetKind::Dataset {
            return Err(bad("privacy budgets apply to datasets"));
        }
        // A dataset version: `series@version`, content-addressed.
        let version = match (&r.series, &r.version) {
            (None, None) => None,
            (Some(series), Some(label)) => {
                let v = encompute_verification::governance::AssetVersion {
                    version: encompute_verification::governance::ASSET_VERSION_VERSION,
                    organization: r.organization.clone(),
                    series: series.clone(),
                    label: label.clone(),
                    digest: r.digest.clone(),
                };
                v.check()?;
                if r.name != v.name() {
                    return Err(bad(format!("a version's name is {}", v.name())));
                }
                Some(v)
            }
            _ => {
                return Err(bad(
                    "a dataset version names both its series and its version",
                ))
            }
        };
        // A version's deletion date: in the future, and fixed for good.
        let delete_after = match r.delete_after {
            None => None,
            Some(_) if version.is_none() => {
                return Err(bad("only a dataset version has a deletion date"))
            }
            Some(d) if d > i64::MAX as u64 => {
                return Err(bad("delete_after is Unix seconds below 2^63"))
            }
            Some(d) if d <= encompute_verification::service::now() => {
                return Err(bad("delete_after is in the past"))
            }
            Some(d) => Some(d as i64),
        };
        // Its retention, and its evidence's: versions only.
        let secs = |what: &str, v: Option<u64>| -> Result<Option<i64>> {
            match v {
                None => Ok(None),
                Some(_) if version.is_none() => {
                    Err(bad(format!("only a dataset version has {what}")))
                }
                Some(t) if t > i64::MAX as u64 => {
                    Err(bad(format!("{what} is Unix seconds below 2^63")))
                }
                Some(t) => Ok(Some(t as i64)),
            }
        };
        let retention_until = secs("retention_until", r.retention_until)?;
        let evidence_retention_until =
            secs("evidence_retention_until", r.evidence_retention_until)?;
        if let (Some(k), Some(d)) = (retention_until, delete_after) {
            if k > d {
                return Err(bad(
                    "retention_until is after delete_after: the data cannot be both kept and deleted",
                ));
            }
        }
        // A version's registered policy: typed, canonical, owned by the
        // version's organization alone, fixed for good.
        if (r.ir_policy.is_some() || r.release_class.is_some()) && version.is_none() {
            return Err(bad(
                "only a dataset version has a registered policy and release class",
            ));
        }
        let ir_policy = r
            .ir_policy
            .as_ref()
            .map(|v| registered_policy(v, &r.organization))
            .transpose()?;
        let release_class = r.release_class.map(|c| c.as_str());
        let id = new_id("ast");
        let policy = if r.policy.is_null() {
            json!({})
        } else {
            r.policy.clone()
        };
        let out = self.tx_anchored(|t| {
            // Parents must be visible and not revoked.
            let mut roots = BTreeSet::new();
            for p in &r.parents {
                let a = asset_visible(t, &ctx.principal, p)?;
                if a.status == "revoked" {
                    return Err(conflict(format!("parent {p} is revoked")));
                }
                roots.insert(a.lineage_root);
            }
            let lineage_root = match roots.len() {
                1 => roots.into_iter().next().expect("one"),
                _ => id.clone(),
            };
            // A broker key belongs to one organization: another
            // organization's asset naming it could have it revoked. The
            // advisory lock is the broker ID's, the same one registering a
            // service account takes (`crate::ops::keybroker_lock`): it
            // serializes this check against a concurrent registration of
            // the broker, and against concurrent registrations naming the
            // same key (same key, same broker). It is the only advisory
            // lock either transaction takes, before the audit head.
            if let Some(k) = &r.key_ref {
                crate::ops::keybroker_lock(t, &k.broker)?;
                // The broker, once registered, is the platform's or this
                // organization's own: another tenant's service account of
                // that name never receives this asset's revocation.
                let broker = t
                    .query_opt(
                        "SELECT kind, organization_id FROM service_accounts WHERE id = $1",
                        &[&k.broker],
                    )
                    .map_err(db_err)?
                    .map(|r| (r.get::<_, String>(0), r.get::<_, Option<String>>(1)));
                if let Some((kind, owner)) = broker {
                    if kind != "keybroker" || owner.as_ref().is_some_and(|o| o != &r.organization) {
                        return Err(conflict(format!(
                            "{} is not a key broker of the platform or of {}",
                            k.broker, r.organization
                        )));
                    }
                }
                let taken = t
                    .query_opt(
                        "SELECT 1 FROM assets WHERE key_ref->>'broker' = $1 AND key_ref->>'key_ref' = $2
                            AND organization_id <> $3 LIMIT 1",
                        &[&k.broker, &k.key_ref, &r.organization],
                    )
                    .map_err(db_err)?;
                if taken.is_some() {
                    return Err(conflict(format!(
                        "key {} at broker {} belongs to another organization",
                        k.key_ref, k.broker
                    )));
                }
            }
            // Registered for a project: the owner must be a member, and in
            // sovereign custody the key must be held by a broker the
            // owner itself registered (never a platform broker).
            if let Some(project) = &r.project {
                let p = project_visible(t, &ctx.principal, project)?;
                deny_auditor(&ctx.principal, &p)?;
                if !p.members.contains(&r.organization) {
                    return Err(forbidden("the asset's owner must be a member of the project"));
                }
                if p.sovereign() {
                    crate::ops::require_own_broker(t, &r.organization, r.key_ref.as_ref().map(|k| k.broker.as_str()))?;
                }
            }
            if let Some(v) = &version {
                // One label is one digest, forever: the same series and
                // version with another digest is refused (and not only by
                // name).
                let taken = t
                    .query_opt(
                        "SELECT 1 FROM assets WHERE organization_id = $1 AND series = $2 AND version = $3",
                        &[&r.organization, &v.series, &v.label],
                    )
                    .map_err(db_err)?;
                if taken.is_some() {
                    return Err(Error::new(
                        Code::GovernanceAssetVersionMismatch,
                        format!("{} is registered already: versions are immutable, register a new one", v.name()),
                    ));
                }
            }
            t.execute(
                "INSERT INTO assets (id, organization_id, kind, name, digest, size_bytes, media_type,
                     storage_uri, policy, lineage_root, parents, key_ref, status, created_by,
                     series, version, version_id, delete_after, ir_policy, release_class,
                     retention_until, evidence_retention_until)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'active', $13, $14, $15, $16, $17,
                         $18, $19, $20, $21)",
                &[
                    &id,
                    &r.organization,
                    &r.kind.as_str(),
                    &r.name,
                    &r.digest,
                    &r.size_bytes,
                    &r.media_type,
                    &r.storage_uri,
                    &policy,
                    &lineage_root,
                    &json!(r.parents),
                    &r.key_ref.as_ref().map(|k| json!(k)),
                    &ctx.actor(),
                    &version.as_ref().map(|v| v.series.clone()),
                    &version.as_ref().map(|v| v.label.clone()),
                    &version.as_ref().map(|v| v.id().hex()),
                    &delete_after,
                    &ir_policy,
                    &release_class,
                    &retention_until,
                    &evidence_retention_until,
                ],
            )
            .map_err(|e| {
                if e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) && version.is_some() {
                    Error::new(
                        Code::GovernanceAssetVersionMismatch,
                        format!("asset {} exists in {}: versions are immutable", r.name, r.organization),
                    )
                } else if e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                    conflict(format!("asset {} exists in {}", r.name, r.organization))
                } else {
                    db_err(e)
                }
            })?;
            let mut d = ctx
                .draft("asset.registered", "asset", &id, Outcome::Succeeded)
                .org(&r.organization)
                .r#ref("kind", r.kind.as_str())
                .r#ref("digest", r.digest.clone());
            if let Some(k) = &r.key_ref {
                d = d.r#ref("key_provider", k.provider.clone()).r#ref("key_version", k.key_version.to_string());
            }
            if let Some(p) = &r.project {
                d = d.project(p);
            }
            audit::append(t, d)?;
            let mut ledger = None;
            if let Some(budget) = &r.privacy_budget {
                budget.validate()?;
                let genesis = Genesis {
                    version: encompute_privacy::ledger::LEDGER_VERSION,
                    asset_id: id.clone(),
                    budget: budget.clone(),
                    privacy_policy_id: sha256_hex(&canonical_json(&policy)?),
                    scoping: None,
                };
                t.execute(
                    "INSERT INTO privacy_ledgers (asset_id, organization_id, genesis) VALUES ($1, $2, $3)",
                    &[&id, &r.organization, &serde_json::to_value(&genesis).expect("serializable")],
                )
                .map_err(db_err)?;
                audit::append(
                    t,
                    ctx.draft("privacy.ledger.created", "asset", &id, Outcome::Succeeded)
                        .org(&r.organization),
                )?;
                ledger = Some(genesis);
            }
            let mut out = json!({"id": id, "organization": r.organization, "lineage_root": lineage_root});
            if let Some(v) = &version {
                out["series"] = json!(v.series);
                out["version"] = json!(v.label);
                out["version_id"] = json!(v.id().hex());
            }
            Ok((out, ledger))
        })?;
        if out.1.is_some() {
            self.anchor_ledger(&id)?;
        }
        Ok(out.0)
    }

    pub fn get_asset(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let a = asset_visible(&mut *c, &ctx.principal, id)?;
        let approvals = c
            .query(
                "SELECT project_id, purpose FROM asset_approvals WHERE asset_id = $1 ORDER BY 1, 2",
                &[&id],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| json!({"project": r.get::<_, String>(0), "purpose": r.get::<_, String>(1)}))
            .collect::<Vec<_>>();
        let mut v = asset_view(&ctx.principal, &a);
        // Only the owner sees where else its asset is approved.
        if ctx.principal.member_of(&a.organization) {
            v["approvals"] = json!(approvals);
        }
        Ok(v)
    }

    pub fn list_assets(&self, ctx: &Ctx) -> Result<Value> {
        let orgs: Vec<String> = ctx.principal.organizations().into_iter().collect();
        let mut c = self.db.conn()?;
        let ids: Vec<String> = c
            .query(
                "SELECT id FROM assets WHERE organization_id = ANY($1)
                 UNION
                 SELECT am.asset_id FROM asset_approval_members am
                   JOIN project_members pm ON pm.project_id = am.project_id
                    AND pm.organization_id = am.organization_id AND pm.status = 'active'
                  WHERE am.organization_id = ANY($1)
                 ORDER BY 1",
                &[&orgs],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        let mut out = vec![];
        for id in ids {
            if let Some(a) = asset_row(&mut *c, &id)? {
                out.push(asset_view(&ctx.principal, &a));
            }
        }
        Ok(Value::Array(out))
    }

    /// The owner approves its asset for a project and purpose. Ownership
    /// never moves; the approval is the only way another organization sees
    /// or uses it, and it covers the organizations that are project members
    /// now: one that joins later sees and uses nothing of it until the
    /// owner approves again.
    pub fn approve_asset(&self, ctx: &Ctx, id: &str, r: ApproveAsset) -> Result<Value> {
        check_name("purpose", &r.purpose)?;
        self.tx_anchored(|t| {
            let a = asset_row(t, id)?.ok_or_else(|| not_found("asset", id))?;
            if !ctx.principal.member_of(&a.organization) {
                return Err(not_found("asset", id));
            }
            deny_auditor_in(t, &ctx.principal, &a.organization)?;
            require(&ctx.principal, &a.organization, owner_roles(&a.kind), "approving an asset")?;
            if a.status == "revoked" {
                return Err(conflict(format!("asset {id} is revoked")));
            }
            let p = project_visible(t, &ctx.principal, &r.project)?;
            deny_auditor(&ctx.principal, &p)?;
            if !p.members.contains(&a.organization) {
                return Err(forbidden("the asset's owner must be a member of the project"));
            }
            // In a governed project an owner shares only through its signed
            // authorization (`/v1/authorizations`), never a v1 approval.
            if p.governed() {
                return Err(Error::new(
                    Code::GovernanceAuthorizationMissing,
                    "a governed project shares assets only under owner-signed authorizations (POST /v1/authorizations)",
                ));
            }
            // A new approval (and each organization it newly covers) gets a
            // new ID: one withdrawn before is never the same approval again.
            t.execute(
                "INSERT INTO asset_approvals (asset_id, project_id, purpose, approved_by, approval_id)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (asset_id, project_id, purpose) DO NOTHING",
                &[&id, &r.project, &r.purpose, &ctx.actor(), &new_id("apv")],
            )
            .map_err(db_err)?;
            let active: Vec<String> = t
                .query(
                    "SELECT organization_id FROM project_members
                      WHERE project_id = $1 AND status = 'active' ORDER BY 1",
                    &[&r.project],
                )
                .map_err(db_err)?
                .iter()
                .map(|r| r.get(0))
                .collect();
            for o in &active {
                t.execute(
                    "INSERT INTO asset_approval_members (asset_id, project_id, purpose, organization_id, grant_id)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (asset_id, project_id, purpose, organization_id) DO NOTHING",
                    &[&id, &r.project, &r.purpose, o, &new_id("apg")],
                )
                .map_err(db_err)?;
            }
            let members = p.members.join("+");
            audit::append(
                t,
                ctx.draft("asset.approved", "asset", id, Outcome::Succeeded)
                    .org(&a.organization)
                    .project(&r.project)
                    .r#ref("purpose", r.purpose.clone())
                    .r#ref("members", if members.len() <= 256 { members } else { p.members.len().to_string() }),
            )?;
            Ok(json!({"asset": id, "project": r.project, "purpose": r.purpose, "members": p.members}))
        })
    }

    /// The owner withdraws an approval: the project's other members no
    /// longer see or use the asset for that purpose, and their jobs using
    /// it there that have not started fail (running ones finish).
    pub fn withdraw_asset_approval(&self, ctx: &Ctx, id: &str, r: ApproveAsset) -> Result<Value> {
        check_name("purpose", &r.purpose)?;
        let out = self.tx_anchored(|t| {
            let a = asset_row(t, id)?.ok_or_else(|| not_found("asset", id))?;
            if !ctx.principal.member_of(&a.organization) {
                return Err(not_found("asset", id));
            }
            deny_auditor_in(t, &ctx.principal, &a.organization)?;
            require(&ctx.principal, &a.organization, owner_roles(&a.kind), "withdrawing an asset approval")?;
            // Serializes with submissions (they hold the asset row shared).
            t.execute("SELECT 1 FROM assets WHERE id = $1 FOR UPDATE", &[&id])
                .map_err(db_err)?;
            let n = withdraw_grants(
                t,
                ctx.actor(),
                "asset_id = $1 AND project_id = $2 AND purpose = $3",
                "asset_id = $1 AND project_id = $2 AND purpose = $3",
                &[&id, &r.project, &r.purpose],
            )?;
            if n == 0 {
                return Err(not_found("approval of asset", id));
            }
            let failed = self.fail_unstarted_jobs(
                t,
                ctx,
                "SELECT id, organization_id FROM jobs
                  WHERE source_assets ? $1 AND project_id = $2 AND purpose = $3 AND organization_id <> $4
                    AND state IN ('created', 'planning', 'planned', 'waiting_for_approval', 'authorized', 'queued')
                  ORDER BY id FOR UPDATE",
                &[&id, &r.project, &r.purpose, &a.organization],
                "the owner withdrew its approval of a source asset",
                ("withdrawn_asset", id),
            )?;
            audit::append(
                t,
                ctx.draft("asset.approval_withdrawn", "asset", id, Outcome::Succeeded)
                    .org(&a.organization)
                    .project(&r.project)
                    .r#ref("purpose", r.purpose.clone()),
            )?;
            Ok(json!({"asset": id, "project": r.project, "purpose": r.purpose, "withdrawn": true, "failed_jobs": failed}))
        })?;
        self.checkpoint_log()?;
        Ok(out)
    }

    /// Fails the jobs `sql` selects (and locks) with `params`: not yet
    /// running ones, in the caller's transaction, each audited with `r#ref`.
    pub(crate) fn fail_unstarted_jobs(
        &self,
        t: &mut postgres::Transaction<'_>,
        ctx: &Ctx,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
        reason: &str,
        r#ref: (&str, &str),
    ) -> Result<Vec<String>> {
        let jobs: Vec<(String, String)> = t
            .query(sql, params)
            .map_err(db_err)?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        for (job, org) in &jobs {
            self.transition_in(
                t,
                ctx.actor(),
                &ctx.request_id,
                job,
                crate::model::JobState::Failed,
                Some(reason),
            )?;
            audit::append(
                t,
                ctx.draft("job.failed", "job", job, Outcome::Failed)
                    .org(org)
                    .r#ref(r#ref.0, r#ref.1.to_owned()),
            )?;
        }
        Ok(jobs.into_iter().map(|j| j.0).collect())
    }

    /// Revokes an asset: no new job may use it, jobs not yet running that
    /// use it fail, and its key broker is told to destroy the key (no new
    /// key release). Derived assets are found through lineage. The
    /// revocation is anchored before it is acknowledged, so restoring an
    /// older database cannot silently make the asset usable again.
    pub fn revoke_asset(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let r = self.tx_anchored(|t| {
            let a = asset_row(t, id)?.ok_or_else(|| not_found("asset", id))?;
            if !ctx.principal.member_of(&a.organization) {
                return Err(not_found("asset", id));
            }
            deny_auditor_in(t, &ctx.principal, &a.organization)?;
            let mut roles = owner_roles(&a.kind).to_vec();
            roles.push(Role::SecurityAdmin);
            require(&ctx.principal, &a.organization, &roles, "revoking an asset")?;
            if a.status == "revoked" {
                return Ok(json!({"id": id, "status": "revoked", "already": true}));
            }
            let r = self.revoke_in(t, ctx.actor(), &ctx.request_id, &a, None)?;
            let mut out = json!({"id": id, "status": "revoked", "failed_jobs": r.failed_jobs});
            // The derived results downstream are listed; nothing already
            // released is erased, and the answer says so.
            if !r.downstream.is_empty() {
                out["downstream"] = json!(r.downstream);
                out["erased"] = json!(false);
            }
            Ok(out)
        })?;
        // Anchored before acknowledging (a retry, "already", re-anchors),
        // with the jobs it failed; the broker's revocation message is sent
        // only once the revocation is anchored (see `deliver_outbox`).
        self.checkpoint_log()?;
        self.metrics
            .inc("encompute_key_release_denied_total", "revoked");
        let _ = self.deliver_outbox();
        Ok(r)
    }

    /// Revokes `a` in the caller's transaction (authorization done): marks
    /// it revoked, marks the derived results downstream of it
    /// `source_revoked_at` (set once; nothing released is erased), fails
    /// the jobs not yet running that use it or one of them, and queues the
    /// key broker's revocation. Returns the failed jobs and the derived
    /// results downstream. `reason` annotates the audit event (recovery
    /// re-applying an anchored revocation).
    pub(crate) fn revoke_in(
        &self,
        t: &mut postgres::Transaction<'_>,
        actor: &str,
        request_id: &str,
        a: &crate::authz::AssetRow,
        reason: Option<&str>,
    ) -> Result<Revoked> {
        let id = a.id.as_str();
        // Only the transaction that revokes it records the transition (a
        // concurrent one waits for the row and changes nothing).
        let n = t
            .execute(
                "UPDATE assets SET status = 'revoked', revoked_at = now()
                  WHERE id = $1 AND status <> 'revoked'",
                &[&id],
            )
            .map_err(db_err)?;
        if n == 1 {
            crate::govlog::append_asset_event(
                t,
                crate::govlog::kind::ASSET_REVOKED,
                id,
                &a.organization,
            )?;
        }
        // The derived results downstream, each marked source-revoked once.
        let downstream = mark_downstream(t, id, Downstream::Revoked)?;
        // Jobs that have not started cannot start now. (Rows are locked
        // before the audit chain: every transaction takes the audit head
        // last, so no two wait on each other.)
        let mut used = downstream.clone();
        used.push(id.to_owned());
        let jobs: Vec<(String, String, String)> = t
            .query(
                "SELECT id, state, organization_id FROM jobs
                  WHERE source_assets ?| $1
                    AND state IN ('created', 'planning', 'planned', 'waiting_for_approval', 'authorized', 'queued')
                  ORDER BY id FOR UPDATE",
                &[&used],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect();
        let draft = |action, rtype, rid: &str, outcome| {
            audit::AuditDraft::new(actor, request_id, action, rtype, rid, outcome)
        };
        let mut d = draft("asset.revoked", "asset", id, Outcome::Succeeded).org(&a.organization);
        if let Some(r) = reason {
            d = d.r#ref("reason", r.to_owned());
        }
        if !downstream.is_empty() {
            d = d.r#ref("downstream", downstream.len().to_string());
        }
        audit::append(t, d)?;
        // Each derived result's custodian learns its source was revoked.
        for x in &downstream {
            let org: String = t
                .query_one("SELECT organization_id FROM assets WHERE id = $1", &[x])
                .map_err(db_err)?
                .get(0);
            audit::append(
                t,
                draft("asset.source_revoked", "asset", x, Outcome::Succeeded)
                    .org(&org)
                    .r#ref("revoked_source", id),
            )?;
        }
        for (job, _, org) in &jobs {
            self.transition_in(
                t,
                actor,
                request_id,
                job,
                crate::model::JobState::Failed,
                Some("a source asset was revoked"),
            )?;
            audit::append(
                t,
                draft("job.failed", "job", job, Outcome::Failed)
                    .org(org)
                    .r#ref("revoked_asset", id),
            )?;
        }
        // Tell the key broker (at least once, idempotent there).
        if let Some(k) = a
            .key_ref
            .clone()
            .and_then(|k| serde_json::from_value::<KeyRef>(k).ok())
        {
            let url: Option<Option<String>> = t
                .query_opt(
                    "SELECT url FROM service_accounts WHERE id = $1 AND kind = 'keybroker' AND status = 'active'
                        AND (organization_id IS NULL OR organization_id = $2)",
                    &[&k.broker, &a.organization],
                )
                .map_err(db_err)?
                .map(|r| r.get(0));
            if let Some(Some(url)) = url {
                let m = seal(
                    &self.signer,
                    "asset.revoked",
                    &k.broker,
                    Scope {
                        organization: Some(a.organization.clone()),
                        ..Scope::default()
                    },
                    &json!({"asset": id, "key_ref": k.key_ref, "key_version": k.key_version}),
                    7 * 24 * 3600,
                )?;
                t.execute(
                    "INSERT INTO outbox (message_id, recipient, url, envelope) VALUES ($1, $2, $3, $4)",
                    &[&m.message_id, &k.broker, &url, &serde_json::to_value(&m).expect("serializable")],
                )
                .map_err(db_err)?;
                audit::append(
                    t,
                    draft("key.revocation.sent", "asset", id, Outcome::Succeeded)
                        .org(&a.organization)
                        .r#ref("broker", k.broker.clone())
                        .r#ref("message", m.message_id.clone()),
                )?;
            }
        }
        Ok(Revoked {
            failed_jobs: jobs.into_iter().map(|j| j.0).collect(),
            downstream,
        })
    }

    /// Lineage: ancestors and descendants the caller may see; others are
    /// counted, not named.
    pub fn lineage(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let a = asset_visible(&mut *c, &ctx.principal, id)?;
        let mut ancestors = vec![];
        let mut hidden = 0usize;
        let mut todo: Vec<String> = a.parents.clone();
        let mut seen = BTreeSet::new();
        while let Some(p) = todo.pop() {
            if !seen.insert(p.clone()) || seen.len() > 10_000 {
                continue;
            }
            match asset_visible(&mut *c, &ctx.principal, &p) {
                Ok(x) => {
                    todo.extend(x.parents.clone());
                    ancestors.push(lineage_entry(&x));
                }
                Err(_) => hidden += 1,
            }
        }
        let mut descendants = vec![];
        let mut todo = vec![id.to_owned()];
        let mut seen = BTreeSet::new();
        while let Some(p) = todo.pop() {
            if !seen.insert(p.clone()) || seen.len() > 10_000 {
                continue;
            }
            let kids: Vec<String> = c
                .query("SELECT id FROM assets WHERE parents ? $1", &[&p])
                .map_err(db_err)?
                .iter()
                .map(|r| r.get(0))
                .collect();
            for k in kids {
                match asset_visible(&mut *c, &ctx.principal, &k) {
                    Ok(x) => {
                        descendants.push(lineage_entry(&x));
                        todo.push(k);
                    }
                    Err(_) => hidden += 1,
                }
            }
        }
        let mut out = json!({
            "asset": id, "lineage_root": a.lineage_root, "status": a.status,
            "ancestors": ancestors, "descendants": descendants, "not_visible": hidden,
        });
        if let Some(t) = a.source_revoked_at {
            out["source_revoked_at"] = json!(t);
        }
        Ok(out)
    }

    // --- privacy --------------------------------------------------------------

    pub fn privacy_view(&self, ctx: &Ctx, asset: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let a = asset_row(&mut *c, asset)?.ok_or_else(|| not_found("asset", asset))?;
        if !ctx.principal.member_of(&a.organization) {
            return Err(not_found("asset", asset));
        }
        require(
            &ctx.principal,
            &a.organization,
            &[
                Role::DataOwner,
                Role::Auditor,
                Role::OrganizationAdmin,
                Role::SecurityAdmin,
            ],
            "reading a privacy ledger",
        )?;
        let view = load_ledger(&mut *c, asset)?
            .ok_or_else(|| not_found("privacy ledger for asset", asset))?;
        view.verify()?;
        let frozen: Option<String> = c
            .query_one(
                "SELECT frozen_reason FROM privacy_ledgers WHERE asset_id = $1",
                &[&asset],
            )
            .map_err(db_err)?
            .get(0);
        // Frozen in the governance log holds even where the ledger's row
        // forgot it.
        let logged = crate::govlog::contains(&mut *c, crate::govlog::NegSet::FrozenLedgers, asset)?;
        let frozen = frozen.or_else(|| {
            logged.then(|| "frozen after a detected rollback (governance log)".to_owned())
        });
        let cost = view.cost()?;
        let cp = view.checkpoint()?;
        Ok(json!({
            "asset": asset,
            "budget": view.genesis.budget,
            "spent": {"epsilon": cost.epsilon, "delta": cost.delta},
            "entries": view.entries.len(),
            "root": cp.root,
            "frozen": frozen,
        }))
    }

    /// The whole ledger (entries), for audits and recovery exports.
    pub fn privacy_export(&self, ctx: &Ctx, asset: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let a = asset_row(&mut *c, asset)?.ok_or_else(|| not_found("asset", asset))?;
        if !ctx.principal.member_of(&a.organization) {
            return Err(not_found("asset", asset));
        }
        require(
            &ctx.principal,
            &a.organization,
            &[Role::Auditor, Role::DataOwner],
            "exporting a privacy ledger",
        )?;
        let view = load_ledger(&mut *c, asset)?
            .ok_or_else(|| not_found("privacy ledger for asset", asset))?;
        Ok(serde_json::to_value(&view).expect("serializable"))
    }

    /// The owner authorizes a SecAgg service to record privacy events for
    /// its asset (the only way a platform service may spend its budget).
    pub fn authorize_privacy_spender(
        &self,
        ctx: &Ctx,
        asset: &str,
        service: &str,
    ) -> Result<Value> {
        self.tx_anchored(|t| {
            let a = asset_row(t, asset)?.ok_or_else(|| not_found("asset", asset))?;
            if !ctx.principal.member_of(&a.organization) {
                return Err(not_found("asset", asset));
            }
            deny_auditor_in(t, &ctx.principal, &a.organization)?;
            require(
                &ctx.principal,
                &a.organization,
                &[Role::DataOwner, Role::OrganizationAdmin],
                "authorizing a privacy spender",
            )?;
            let kind: Option<String> = t
                .query_opt(
                    "SELECT kind FROM service_accounts WHERE id = $1 AND status = 'active'",
                    &[&service],
                )
                .map_err(db_err)?
                .map(|r| r.get(0));
            if kind.as_deref() != Some("secagg") {
                return Err(bad("privacy spenders are active SecAgg services"));
            }
            let n = t
                .execute(
                    "INSERT INTO privacy_spenders (asset_id, service_id, granted_by) VALUES ($1, $2, $3)
                     ON CONFLICT DO NOTHING",
                    &[&asset, &service, &ctx.actor()],
                )
                .map_err(|e| {
                    if e.code() == Some(&postgres::error::SqlState::FOREIGN_KEY_VIOLATION) {
                        not_found("privacy ledger for asset", asset)
                    } else {
                        db_err(e)
                    }
                })?;
            if n > 0 {
                audit::append(
                    t,
                    ctx.draft("privacy.spender.authorized", "asset", asset, Outcome::Succeeded)
                        .org(&a.organization)
                        .r#ref("service", service.to_owned()),
                )?;
            }
            Ok(json!({"asset": asset, "service": service}))
        })
    }

    /// Records a privacy event (a reservation before a noisy release, or
    /// its commit). Race-safe (the ledger row is locked), idempotent (the
    /// same event again returns the stored entry), and anchored before it
    /// returns: committed spending is never forgotten.
    pub fn privacy_spend(&self, ctx: &Ctx, asset: &str, event: PrivacyEvent) -> Result<Value> {
        // Every spend is an event of the log and its mirror: bounded per
        // actor and asset (a duplicate delivery counts too).
        self.spend_limit.hit(&format!("{}:{asset}", ctx.actor()))?;
        // What the anchor holds, read before the transaction takes the
        // ledger's lock (the anchor's lock is outermost; see
        // `Anchor::counter`). By the time the lock is held, the log holds
        // at least this.
        let anchored = self.anchor.snapshot();
        let res = self.tx_anchored(|t| {
            let row = t
                .query_opt(
                    "SELECT organization_id, frozen_reason FROM privacy_ledgers WHERE asset_id = $1 FOR UPDATE",
                    &[&asset],
                )
                .map_err(db_err)?
                .ok_or_else(|| not_found("privacy ledger for asset", asset))?;
            let org: String = row.get(0);
            let frozen: Option<String> = row.get(1);
            // A SecAgg service spends only on assets whose owner authorized
            // it; people and automation only within their own organization.
            let authorized_service =
                matches!(ctx.principal.service_kind(), Some(ServiceKind::Secagg))
                    && t.query_opt(
                        "SELECT 1 FROM privacy_spenders WHERE asset_id = $1 AND service_id = $2",
                        &[&asset, &ctx.actor()],
                    )
                    .map_err(db_err)?
                    .is_some();
            if !authorized_service {
                if !ctx.principal.member_of(&org) {
                    return Err(not_found("privacy ledger for asset", asset));
                }
                deny_auditor_in(t, &ctx.principal, &org)?;
                if !ctx.principal.any_role(&org, &[Role::DataOwner, Role::Operator]) {
                    return Err(forbidden(
                        "privacy spending is done by the owner's data owners, or SecAgg services the owner authorized",
                    ));
                }
            }
            let a = asset_row(t, asset)?.ok_or_else(|| not_found("asset", asset))?;
            if a.status == "revoked" {
                return Err(conflict(format!("asset {asset} is revoked")));
            }
            let view = load_ledger(t, asset)?.ok_or_else(|| not_found("privacy ledger for asset", asset))?;
            // The log must still hold the anchored head: a database rewound
            // together with its log (ledger entries and checkpoint events
            // alike) passes the ledger's floor below, and is refused here,
            // before anything is written. One probe of the log's key.
            if crate::govlog::hash_at(t, anchored.glog_size)?.as_deref()
                != Some(anchored.glog_head.as_str())
            {
                self.rollback_alarm("governance", "log");
                return Err(runtime_rollback(
                    "GOVERNANCE LOG",
                    format!(
                        "the log does not hold anchored governance event {}",
                        anchored.glog_size
                    ),
                ));
            }
            // The database must still extend the ledger's latest checkpoint
            // in the governance log: one rolled back, reset or rewritten
            // while the service runs is refused now, not only at the next
            // start. (Every checkpoint committed after the spend it covers,
            // which committed before this transaction took the ledger's
            // lock, so a ledger that was not rewound extends it. One indexed
            // read; the log's head is not locked.)
            if let Some(cp) = crate::govlog::latest_ledger_checkpoint(t, asset)? {
                view.extends(&cp).map_err(|e| {
                    self.rollback_alarm("privacy", asset);
                    runtime_rollback("PRIVACY", format!("the privacy ledger of {asset}: {}", e.message))
                })?;
            }
            // Duplicate delivery: the same event is already recorded.
            if let Some(e) = view.entries.iter().find(|e| {
                e.event.event_id() == event.event_id()
                    && std::mem::discriminant(&e.event) == std::mem::discriminant(&event)
            }) {
                if e.event == event {
                    return Ok((json!({"seq": e.seq, "hash": e.hash, "duplicate": true}), org, view.checkpoint()?));
                }
                return Err(conflict(format!("event {} was recorded with other contents", event.event_id())));
            }
            // Frozen in the ledger's row or in the governance log: the
            // log's freeze holds whatever the row says.
            if frozen.is_some()
                || crate::govlog::contains(t, crate::govlog::NegSet::FrozenLedgers, asset)?
            {
                return Err(Error::new(
                    Code::PrivacyBudgetExceeded,
                    "this privacy ledger is frozen after a detected rollback: treated as exhausted",
                ));
            }
            if let PrivacyEvent::Reserve { mechanism, .. } = &event {
                check_reservation(&view.genesis, &event, self.env.is_production())?;
                view.check(event.rho()?, mechanism.sampling_rate)?;
            }
            let (next, entry) = view.append_event(event.clone())?;
            t.execute(
                "INSERT INTO privacy_entries (asset_id, seq, entry) VALUES ($1, $2, $3)",
                &[&asset, &(entry.seq as i64), &serde_json::to_value(&entry).expect("serializable")],
            )
            .map_err(db_err)?;
            let action = match &event {
                PrivacyEvent::Reserve { .. } => "privacy.spent",
                PrivacyEvent::Commit { .. } => "privacy.committed",
            };
            audit::append(
                t,
                ctx.draft(action, "asset", asset, Outcome::Succeeded)
                    .org(&org)
                    .r#ref("event", event.event_id().to_owned())
                    .r#ref("seq", entry.seq.to_string()),
            )?;
            Ok((json!({"seq": entry.seq, "hash": entry.hash, "duplicate": false}), org, next.checkpoint()?))
        });
        match res {
            Ok((v, _org, _cp)) => {
                // Anchored before acknowledging (a retry re-anchors); the
                // anchor refuses a ledger that does not extend it.
                self.anchor_ledger(asset)?;
                Ok(v)
            }
            Err(e) => {
                if matches!(e.code, Code::PrivacyBudgetExceeded) {
                    self.metrics.inc("encompute_privacy_denied_total", "budget");
                    let org = self
                        .db
                        .conn()
                        .ok()
                        .and_then(|mut c| asset_row(&mut *c, asset).ok().flatten())
                        .map(|a| a.organization);
                    let mut d = ctx.draft("privacy.denied", "asset", asset, Outcome::Denied);
                    if let Some(o) = org {
                        d = d.org(&o);
                    }
                    self.audit_denied(d.r#ref("event", event.event_id().to_owned()));
                }
                Err(e)
            }
        }
    }
}

/// The least L2 sensitivity (code units) a reservation's own mechanism and
/// noise imply, for a ledger accounting privacy `unit`s.
///
/// The control plane does not hold the release's codec, so it cannot
/// recompute the charge; it bounds it instead, with the release's own
/// rule ([`encompute_privacy::release::sensitivity`]). A release's noise
/// variance is `sigma2 = ceil((noise_multiplier * clip_norm * scale)^2)`, so
/// `clip_norm * scale` exceeds `sqrt(sigma2 - 1) / noise_multiplier`; the
/// sensitivity of a release with that (or any larger) clipped scale is at
/// least the one computed here.
pub fn least_sensitivity(
    unit: &encompute_ir::confidentiality::PrivacyUnit,
    mechanism: &encompute_ir::confidentiality::DpMechanism,
    sigma2: u64,
    vector_len: usize,
) -> u64 {
    // A hair below the bound, so floating-point rounding never refuses an
    // honest release.
    let scaled_clip =
        (sigma2.saturating_sub(1) as f64).sqrt() / mechanism.noise_multiplier * (1.0 - 1e-12);
    let at_bound = encompute_ir::confidentiality::DpMechanism {
        clip_norm: scaled_clip,
        ..mechanism.clone()
    };
    let unit_scale = encompute_ir::confidentiality::FixedPointCodec {
        clip_min: -1.0,
        clip_max: 1.0,
        scale: 1,
        modulus_bits: 64,
    };
    encompute_privacy::release::sensitivity(unit, &at_bound, &unit_scale, vector_len)
}

/// A reservation must be internally consistent before it is charged: a
/// valid mechanism, a positive noise variance and vector length, production
/// randomness in production mode, and a declared sensitivity no smaller
/// than its own noise implies ([`least_sensitivity`]). A spender that
/// under-declares its sensitivity to be charged less is refused (ENC2204).
/// The least zCDP cost one reservation may have.
pub const MIN_RESERVATION_RHO: f64 = 1e-9;

pub fn check_reservation(
    genesis: &encompute_privacy::Genesis,
    event: &PrivacyEvent,
    production: bool,
) -> Result<()> {
    let PrivacyEvent::Reserve {
        mechanism,
        sensitivity,
        sigma2,
        vector_len,
        rng,
        ..
    } = event
    else {
        return Ok(());
    };
    let refused = |m: String| Err(Error::new(Code::PrivacyMechanism, m));
    mechanism.validate()?;
    if *sensitivity == 0 || *sigma2 == 0 || *vector_len == 0 {
        return refused(
            "a reservation needs a positive sensitivity, noise variance and vector length".into(),
        );
    }
    if production && rng != encompute_privacy::CSPRNG {
        return refused(format!(
            "production mode charges only releases drawn with {}",
            encompute_privacy::CSPRNG
        ));
    }
    // A reservation that costs next to nothing still costs the log an
    // event: each must charge at least a floor (no honest release is that
    // noisy: this is a noise multiplier of over 20,000 at sensitivity 1).
    if event.rho()? < MIN_RESERVATION_RHO {
        return refused(format!(
            "a reservation must charge at least rho {MIN_RESERVATION_RHO} (its noise variance {sigma2} at sensitivity {sensitivity} charges less)"
        ));
    }
    let least = least_sensitivity(&genesis.budget.unit, mechanism, *sigma2, *vector_len);
    if *sensitivity < least {
        return refused(format!(
            "the reservation declares sensitivity {sensitivity}, but its noise (sigma2 {sigma2}, noise multiplier {}) implies at least {least} for {:?}-level units: it would be charged too little",
            mechanism.noise_multiplier, genesis.budget.unit
        ));
    }
    Ok(())
}
