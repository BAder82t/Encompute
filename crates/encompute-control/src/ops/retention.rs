//! Retention of dataset versions.
//!
//! A dataset version carries its owner's retention: `delete_after` (from
//! then on it is not used), fixed at registration and only ever brought
//! forward by its owner; `retention_until` (until when the owner keeps the
//! data, fixed, never after `delete_after`); and `evidence_retention_until`
//! (until when the evidence about it is kept, only ever extended).
//!
//! Once `delete_after` passes, [`Control::expire_assets`] (run in the
//! background) expires the version: it is marked expired, every derived
//! result downstream is marked source-expired, their jobs that have not
//! started fail, the expiry is anchored, and only then is the version's key
//! broker told (`asset.expired`). A job that started before the deletion
//! date may finish, but nothing derived from an expired version is used,
//! derived from or exported again: every such check walks the ancestors
//! themselves, whose expiry the governance log records.
//!
//! Deleting the data itself is the job of the owner's storage. Encompute
//! blocks every further use and records the expiry; the evidence about the
//! version (receipts, audit events, anchors, release records) stays
//! verifiable after the data is gone.

use serde_json::{json, Value};

use encompute_ir::Result;
use encompute_verification::service::now;

use super::assets::{mark_downstream, Downstream};
use crate::audit::{self, AuditDraft, Outcome};
use crate::authz::{asset_row, conflict, deny_auditor_in, not_found, require_human, AssetRow};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::model::{bad, JobState, Role, UpdateRetention};

/// Versions expired in one background pass at most (the rest wait for the
/// next one).
const EXPIRE_BATCH: i64 = 1000;

/// What an expiry did: the jobs it failed and the derived results
/// downstream it marked.
pub(crate) struct Expired {
    pub failed_jobs: Vec<String>,
    pub downstream: Vec<String>,
}

impl Control {
    /// A person who is a security admin or data owner of a dataset
    /// version's organization changes its retention: brings its deletion
    /// date forward (never back, and never before `retention_until`), or
    /// extends its evidence retention (never shortens it). Audited. A
    /// deletion date brought to now or earlier expires the version at once.
    pub fn update_retention(&self, ctx: &Ctx, id: &str, r: UpdateRetention) -> Result<Value> {
        if r.delete_after.is_none() && r.evidence_retention_until.is_none() {
            return Err(bad("name a new delete_after or evidence_retention_until"));
        }
        for v in [r.delete_after, r.evidence_retention_until]
            .into_iter()
            .flatten()
        {
            if v > i64::MAX as u64 {
                return Err(bad("retention times are Unix seconds below 2^63"));
            }
        }
        let at = now();
        let out = self.tx_anchored(|t| {
            let a = asset_row(t, id)?.ok_or_else(|| not_found("asset", id))?;
            if !ctx.principal.member_of(&a.organization) {
                return Err(not_found("asset", id));
            }
            deny_auditor_in(t, &ctx.principal, &a.organization)?;
            require_human(
                &ctx.principal,
                &a.organization,
                &[Role::SecurityAdmin, Role::DataOwner],
                "changing a dataset version's retention",
            )?;
            let row = t
                .query_one(
                    "SELECT series IS NOT NULL, delete_after, retention_until, evidence_retention_until
                       FROM assets WHERE id = $1 FOR UPDATE",
                    &[&id],
                )
                .map_err(db_err)?;
            if !row.get::<_, bool>(0) {
                return Err(bad("only a dataset version has a retention"));
            }
            let (delete_after, retention_until, evidence): (Option<i64>, Option<i64>, Option<i64>) =
                (row.get(1), row.get(2), row.get(3));
            let mut d = ctx
                .draft("asset.retention_changed", "asset", id, Outcome::Succeeded)
                .org(&a.organization);
            let mut new_delete = delete_after;
            if let Some(n) = r.delete_after {
                let n = n as i64;
                if delete_after.is_some_and(|o| n > o) {
                    return Err(conflict(format!(
                        "{id}'s deletion date is {}: it is only brought forward, never pushed back",
                        delete_after.unwrap_or_default()
                    )));
                }
                if retention_until.is_some_and(|k| n < k) {
                    return Err(conflict(format!(
                        "{id} is kept until {}: its deletion date is not brought forward past it",
                        retention_until.unwrap_or_default()
                    )));
                }
                if delete_after != Some(n) {
                    t.execute(
                        "UPDATE assets SET delete_after = $2 WHERE id = $1",
                        &[&id, &n],
                    )
                    .map_err(db_err)?;
                    d = d
                        .r#ref(
                            "previous_delete_after",
                            delete_after.map_or("none".to_owned(), |o| o.to_string()),
                        )
                        .r#ref("delete_after", n.to_string());
                }
                new_delete = Some(n);
            }
            let mut new_evidence = evidence;
            if let Some(n) = r.evidence_retention_until {
                let n = n as i64;
                if evidence.is_some_and(|o| n < o) {
                    return Err(conflict(format!(
                        "{id}'s evidence is kept until {}: evidence retention is only extended, never shortened",
                        evidence.unwrap_or_default()
                    )));
                }
                if evidence != Some(n) {
                    t.execute(
                        "UPDATE assets SET evidence_retention_until = $2 WHERE id = $1",
                        &[&id, &n],
                    )
                    .map_err(db_err)?;
                    d = d
                        .r#ref(
                            "previous_evidence_retention_until",
                            evidence.map_or("none".to_owned(), |o| o.to_string()),
                        )
                        .r#ref("evidence_retention_until", n.to_string());
                }
                new_evidence = Some(n);
            }
            audit::append(t, d)?;
            let mut out = json!({"id": id, "delete_after": new_delete,
                                 "retention_until": retention_until,
                                 "evidence_retention_until": new_evidence});
            if new_delete.is_some_and(|n| n.max(0) as u64 <= at) {
                out["expires_now"] = json!(true);
            }
            Ok(out)
        })?;
        if out.get("expires_now").is_some() {
            self.expire_assets()?;
        }
        Ok(out)
    }

    /// Expires every dataset version whose deletion date has passed (at
    /// most a batch per call), anchors the expiries, then tells their key
    /// brokers. The background task calls it; returns the versions expired
    /// now.
    pub fn expire_assets(&self) -> Result<Vec<String>> {
        let expired = self.expire_due(now())?;
        if !expired.is_empty() {
            // Anchored before any broker hears of it (`deliver_outbox`
            // holds `asset.expired` until then).
            self.checkpoint_log()?;
            // (Its plain transactions left the thread's deny flag set; the
            // checkpoint just settled it.)
            crate::govlog::DENY_PENDING.with(|d| d.set(false));
            let _ = self.deliver_outbox();
        }
        Ok(expired)
    }

    /// Expires, in the database only (nothing is anchored or sent), every
    /// dataset version whose deletion date is at or before `at`: one
    /// transaction each. Returns the versions expired now.
    ///
    /// **Not for callers outside this crate's own tasks and tests**: an
    /// expiry that is not anchored is not yet protected against a restore.
    /// Use [`Self::expire_assets`], which anchors them before any broker
    /// is told.
    #[doc(hidden)]
    pub fn expire_due(&self, at: u64) -> Result<Vec<String>> {
        let due: Vec<String> = {
            let mut c = self.db.conn()?;
            c.query(
                "SELECT id FROM assets
                  WHERE expired_at IS NULL AND delete_after IS NOT NULL AND delete_after <= $1
                  ORDER BY delete_after, id LIMIT $2",
                &[&i64::try_from(at).unwrap_or(i64::MAX), &EXPIRE_BATCH],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect()
        };
        let mut out = vec![];
        for id in due {
            let newly = self.db.tx(|t| {
                let Some(a) = asset_row(t, &id)? else {
                    return Ok(false);
                };
                let Some(x) =
                    self.retire_in(t, &self.service_id, "retention", &a, Some("delete_after"))?
                else {
                    return Ok(false);
                };
                crate::log::LogLine::new(&self.service_id, "asset_expired")
                    .field("asset", id.clone())
                    .field("failed_jobs", x.failed_jobs.len().to_string())
                    .field("downstream", x.downstream.len().to_string())
                    .emit();
                Ok(true)
            })?;
            if newly {
                out.push(id);
            }
        }
        Ok(out)
    }

    /// Marks asset `id` expired (its owner's retention ended) at once, with
    /// everything an expiry does ([`Self::retire_in`]), anchors it and tells
    /// its key broker. Returns whether it was newly expired.
    pub fn expire_asset(&self, actor: &str, id: &str) -> Result<bool> {
        let newly = self.tx_anchored(|t| {
            let a = asset_row(t, id)?.ok_or_else(|| not_found("asset", id))?;
            Ok(self.retire_in(t, actor, "retention", &a, None)?.is_some())
        })?;
        self.checkpoint_log()?;
        let _ = self.deliver_outbox();
        Ok(newly)
    }

    /// Expires `a` in the caller's transaction: marks it expired, marks
    /// every derived result downstream source-expired (each once), fails
    /// the jobs that have not started reading it or one of them, and queues
    /// its key broker's `asset.expired` (delivered once anchored). A job
    /// already running may finish. `None` when it was expired already.
    pub(crate) fn retire_in(
        &self,
        t: &mut postgres::Transaction<'_>,
        actor: &str,
        request_id: &str,
        a: &AssetRow,
        reason: Option<&str>,
    ) -> Result<Option<Expired>> {
        // Rows first, the audit chain last (as every transaction takes it).
        let expired: bool = t
            .query_one(
                "SELECT expired_at IS NOT NULL FROM assets WHERE id = $1 FOR UPDATE",
                &[&a.id],
            )
            .map_err(db_err)?
            .get(0);
        if expired {
            return Ok(None);
        }
        let downstream = mark_downstream(t, &a.id, Downstream::Expired)?;
        let mut used = downstream.clone();
        used.push(a.id.clone());
        let jobs: Vec<(String, String)> = t
            .query(
                "SELECT id, organization_id FROM jobs
                  WHERE source_assets ?| $1
                    AND state IN ('created', 'planning', 'planned', 'waiting_for_approval', 'authorized', 'queued')
                  ORDER BY id FOR UPDATE",
                &[&used],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        if !self.expire_in(t, actor, request_id, a, reason)? {
            return Ok(None);
        }
        let draft = |action, rtype, rid: &str, outcome| {
            AuditDraft::new(actor, request_id, action, rtype, rid, outcome)
        };
        // Each derived result's custodian learns its source expired.
        for x in &downstream {
            let org: String = t
                .query_one("SELECT organization_id FROM assets WHERE id = $1", &[x])
                .map_err(db_err)?
                .get(0);
            audit::append(
                t,
                draft("asset.source_expired", "asset", x, Outcome::Succeeded)
                    .org(&org)
                    .r#ref("expired_source", a.id.clone()),
            )?;
        }
        for (job, org) in &jobs {
            self.transition_in(
                t,
                actor,
                request_id,
                job,
                JobState::Failed,
                Some("a source asset expired (its deletion date passed)"),
            )?;
            audit::append(
                t,
                draft("job.failed", "job", job, Outcome::Failed)
                    .org(org)
                    .r#ref("expired_asset", a.id.clone()),
            )?;
        }
        Ok(Some(Expired {
            failed_jobs: jobs.into_iter().map(|j| j.0).collect(),
            downstream,
        }))
    }
}
