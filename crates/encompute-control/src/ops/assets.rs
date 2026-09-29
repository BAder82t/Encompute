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
    asset_row, asset_visible, conflict, forbidden, not_found, project_visible, require, AssetRow,
};
use crate::control::{load_ledger, runtime_rollback, Control, Ctx};
use crate::db::db_err;
use crate::model::{
    bad, check_digest, check_name, check_storage_uri, new_id, ApproveAsset, AssetKind, KeyRef,
    RegisterAsset, Role, ServiceKind,
};
use crate::transport::{seal, Scope};

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
        t.execute(
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
    }
    for r in &a {
        t.execute(
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
    }
    Ok(a.len() as u64)
}

/// An asset as its owner's members see it.
pub fn asset_json(a: &AssetRow) -> Value {
    json!({
        "id": a.id, "organization": a.organization, "kind": a.kind, "name": a.name,
        "digest": a.digest, "status": a.status, "lineage_root": a.lineage_root,
        "parents": a.parents, "key_ref": a.key_ref, "policy": a.policy,
        "size_bytes": a.size_bytes, "media_type": a.media_type, "storage_uri": a.storage_uri,
    })
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
    json!({
        "id": a.id, "organization": a.organization, "kind": a.kind, "name": a.name,
        "digest": a.digest, "status": a.status, "lineage_root": a.lineage_root,
        "parents": a.parents, "policy": policy,
    })
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

impl Control {
    pub fn register_asset(&self, ctx: &Ctx, r: RegisterAsset) -> Result<Value> {
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
        let id = new_id("ast");
        let policy = if r.policy.is_null() {
            json!({})
        } else {
            r.policy.clone()
        };
        let out = self.db.tx(|t| {
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
                     series, version, version_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'active', $13, $14, $15, $16)",
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
            audit::append(t, d)?;
            let mut ledger = None;
            if let Some(budget) = &r.privacy_budget {
                budget.validate()?;
                let genesis = Genesis {
                    version: encompute_privacy::ledger::LEDGER_VERSION,
                    asset_id: id.clone(),
                    budget: budget.clone(),
                    privacy_policy_id: sha256_hex(&canonical_json(&policy)?),
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
        self.db.tx(|t| {
            let a = asset_row(t, id)?.ok_or_else(|| not_found("asset", id))?;
            if !ctx.principal.member_of(&a.organization) {
                return Err(not_found("asset", id));
            }
            require(&ctx.principal, &a.organization, owner_roles(&a.kind), "approving an asset")?;
            if a.status == "revoked" {
                return Err(conflict(format!("asset {id} is revoked")));
            }
            let p = project_visible(t, &ctx.principal, &r.project)?;
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
        let out = self.db.tx(|t| {
            let a = asset_row(t, id)?.ok_or_else(|| not_found("asset", id))?;
            if !ctx.principal.member_of(&a.organization) {
                return Err(not_found("asset", id));
            }
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
        self.sync_anchor()?;
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
        let r = self.db.tx(|t| {
            let a = asset_row(t, id)?.ok_or_else(|| not_found("asset", id))?;
            if !ctx.principal.member_of(&a.organization) {
                return Err(not_found("asset", id));
            }
            let mut roles = owner_roles(&a.kind).to_vec();
            roles.push(Role::SecurityAdmin);
            require(&ctx.principal, &a.organization, &roles, "revoking an asset")?;
            if a.status == "revoked" {
                return Ok(json!({"id": id, "status": "revoked", "already": true}));
            }
            let failed = self.revoke_in(t, ctx.actor(), &ctx.request_id, &a, None)?;
            Ok(json!({"id": id, "status": "revoked", "failed_jobs": failed}))
        })?;
        // Anchored before acknowledging (a retry, "already", re-anchors),
        // with the jobs it failed; the broker's revocation message is sent
        // only once the revocation is anchored (see `deliver_outbox`).
        self.sync_anchor()?;
        self.metrics
            .inc("encompute_key_release_denied_total", "revoked");
        let _ = self.deliver_outbox();
        Ok(r)
    }

    /// Revokes `a` in the caller's transaction (authorization done): marks
    /// it revoked, fails the jobs not yet running that use it, and queues
    /// the key broker's revocation. Returns the failed jobs. `reason`
    /// annotates the audit event (recovery re-applying an anchored
    /// revocation).
    pub(crate) fn revoke_in(
        &self,
        t: &mut postgres::Transaction<'_>,
        actor: &str,
        request_id: &str,
        a: &crate::authz::AssetRow,
        reason: Option<&str>,
    ) -> Result<Vec<String>> {
        let id = a.id.as_str();
        t.execute(
            "UPDATE assets SET status = 'revoked', revoked_at = now() WHERE id = $1",
            &[&id],
        )
        .map_err(db_err)?;
        // Jobs that have not started cannot start now. (Rows are locked
        // before the audit chain: every transaction takes the audit head
        // last, so no two wait on each other.)
        let jobs: Vec<(String, String, String)> = t
            .query(
                "SELECT id, state, organization_id FROM jobs
                  WHERE source_assets ? $1
                    AND state IN ('created', 'planning', 'planned', 'waiting_for_approval', 'authorized', 'queued')
                  FOR UPDATE",
                &[&id],
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
        audit::append(t, d)?;
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
        Ok(jobs.into_iter().map(|j| j.0).collect())
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
                    ancestors.push(json!({"id": x.id, "kind": x.kind, "status": x.status, "organization": x.organization}));
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
                        descendants.push(json!({"id": x.id, "kind": x.kind, "status": x.status, "organization": x.organization}));
                        todo.push(k);
                    }
                    Err(_) => hidden += 1,
                }
            }
        }
        Ok(json!({
            "asset": id, "lineage_root": a.lineage_root, "status": a.status,
            "ancestors": ancestors, "descendants": descendants, "not_visible": hidden,
        }))
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
        // Frozen in the anchor holds even where the database forgot it.
        let frozen = frozen.or_else(|| {
            self.anchor
                .snapshot()
                .frozen
                .contains(asset)
                .then(|| "frozen in the state anchor after a detected rollback".to_owned())
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
        self.db.tx(|t| {
            let a = asset_row(t, asset)?.ok_or_else(|| not_found("asset", asset))?;
            if !ctx.principal.member_of(&a.organization) {
                return Err(not_found("asset", asset));
            }
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
        let res = self.db.tx(|t| {
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
            // The database must still extend the anchored ledger: one rolled
            // back, reset or rewritten while the service runs is refused now,
            // not only at the next start. (Everything anchored committed
            // before this transaction took the ledger's lock.)
            let anchored = self.anchor.snapshot();
            if let Some(cp) = anchored.ledgers.get(asset) {
                view.extends(cp).map_err(|e| {
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
            // Frozen in the database or in the anchor: the anchor's freeze
            // holds whatever the database says.
            if frozen.is_some() || anchored.frozen.contains(asset) {
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
    let least = least_sensitivity(&genesis.budget.unit, mechanism, *sigma2, *vector_len);
    if *sensitivity < least {
        return refused(format!(
            "the reservation declares sensitivity {sensitivity}, but its noise (sigma2 {sigma2}, noise multiplier {}) implies at least {least} for {:?}-level units: it would be charged too little",
            mechanism.noise_multiplier, genesis.budget.unit
        ));
    }
    Ok(())
}
