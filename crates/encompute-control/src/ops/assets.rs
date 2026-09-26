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
use crate::control::{load_ledger, Control, Ctx};
use crate::db::db_err;
use crate::model::{
    bad, check_digest, check_name, new_id, ApproveAsset, AssetKind, KeyRef, RegisterAsset, Role,
    ServiceKind,
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

pub fn asset_json(a: &AssetRow) -> Value {
    json!({
        "id": a.id, "organization": a.organization, "kind": a.kind, "name": a.name,
        "digest": a.digest, "status": a.status, "lineage_root": a.lineage_root,
        "parents": a.parents, "key_ref": a.key_ref, "policy": a.policy,
        "size_bytes": a.size_bytes, "media_type": a.media_type, "storage_uri": a.storage_uri,
    })
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
            check_name("storage_uri", u)?;
        }
        if let Some(k) = &r.key_ref {
            check_name("key_ref.broker", &k.broker)?;
            check_name("key_ref.key_ref", &k.key_ref)?;
        }
        if r.privacy_budget.is_some() && r.kind != AssetKind::Dataset {
            return Err(bad("privacy budgets apply to datasets"));
        }
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
            t.execute(
                "INSERT INTO assets (id, organization_id, kind, name, digest, size_bytes, media_type,
                     storage_uri, policy, lineage_root, parents, key_ref, status, created_by)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'active', $13)",
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
                ],
            )
            .map_err(|e| {
                if e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
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
            Ok((json!({"id": id, "organization": r.organization, "lineage_root": lineage_root}), ledger))
        })?;
        if let Some(g) = out.1 {
            let view = encompute_privacy::LedgerView {
                genesis: g,
                entries: vec![],
            };
            self.anchor
                .record_ledger(&self.signer, &id, &view.checkpoint()?)?;
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
        let mut v = asset_json(&a);
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
                 SELECT ap.asset_id FROM asset_approvals ap
                   JOIN project_members pm ON pm.project_id = ap.project_id
                  WHERE pm.organization_id = ANY($1)
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
                out.push(asset_json(&a));
            }
        }
        Ok(Value::Array(out))
    }

    /// The owner approves its asset for a project and purpose. Ownership
    /// never moves; the approval is the only way another organization sees
    /// or uses it.
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
            t.execute(
                "INSERT INTO asset_approvals (asset_id, project_id, purpose, approved_by) VALUES ($1, $2, $3, $4)
                 ON CONFLICT DO NOTHING",
                &[&id, &r.project, &r.purpose, &ctx.actor()],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                ctx.draft("asset.approved", "asset", id, Outcome::Succeeded)
                    .org(&a.organization)
                    .project(&r.project)
                    .r#ref("purpose", r.purpose.clone()),
            )?;
            Ok(json!({"asset": id, "project": r.project, "purpose": r.purpose}))
        })
    }

    /// Revokes an asset: no new job may use it, jobs not yet running that
    /// use it fail, and its key broker is told to destroy the key (no new
    /// key release). Derived assets are found through lineage.
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
            t.execute(
                "UPDATE assets SET status = 'revoked', revoked_at = now() WHERE id = $1",
                &[&id],
            )
            .map_err(db_err)?;
            // Jobs that have not started cannot start now. (Rows are locked
            // before the audit chain: every transaction takes the audit
            // head last, so no two wait on each other.)
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
            audit::append(
                t,
                ctx.draft("asset.revoked", "asset", id, Outcome::Succeeded).org(&a.organization),
            )?;
            for (job, _, org) in &jobs {
                self.transition_in(t, ctx.actor(), &ctx.request_id, job, crate::model::JobState::Failed, Some("a source asset was revoked"))?;
                audit::append(
                    t,
                    ctx.draft("job.failed", "job", job, Outcome::Failed)
                        .org(org)
                        .r#ref("revoked_asset", id),
                )?;
            }
            // Tell the key broker (at least once, idempotent there).
            if let Some(k) = a.key_ref.clone().and_then(|k| serde_json::from_value::<KeyRef>(k).ok()) {
                let url: Option<Option<String>> = t
                    .query_opt(
                        "SELECT url FROM service_accounts WHERE id = $1 AND kind = 'keybroker' AND status = 'active'",
                        &[&k.broker],
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
                        ctx.draft("key.revocation.sent", "asset", id, Outcome::Succeeded)
                            .org(&a.organization)
                            .r#ref("broker", k.broker.clone())
                            .r#ref("message", m.message_id.clone()),
                    )?;
                }
            }
            let failed: Vec<String> = jobs.into_iter().map(|j| j.0).collect();
            Ok(json!({"id": id, "status": "revoked", "failed_jobs": failed}))
        })?;
        self.metrics
            .inc("encompute_key_release_denied_total", "revoked");
        let _ = self.deliver_outbox();
        Ok(r)
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

    /// Records a privacy event (a reservation before a noisy release, or
    /// its commit). Race-safe (the ledger row is locked), idempotent (the
    /// same event again returns the stored entry), and anchored before it
    /// returns: committed spending is never forgotten.
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
            if frozen.is_some() {
                return Err(Error::new(
                    Code::PrivacyBudgetExceeded,
                    "this privacy ledger is frozen after a detected rollback: treated as exhausted",
                ));
            }
            if let PrivacyEvent::Reserve { mechanism, .. } = &event {
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
            Ok((v, _org, cp)) => {
                // Anchored before acknowledging (a retry re-anchors).
                self.anchor.record_ledger(&self.signer, asset, &cp)?;
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
