//! The one-time migration of a version-1 state anchor (0.3.0: sets of
//! every security-negative ID, growing with each) into the governance
//! event log, leaving a constant-size version-2 anchor that holds the
//! log's head.
//!
//! 1. The version-1 anchor must pass every check 0.3.0 made at its start
//!    (the database extends it); otherwise nothing is migrated and the
//!    start is refused.
//!    Those checks, the gathering of the sets and step 2 run in one
//!    REPEATABLE READ transaction that holds the governance log's head
//!    from its first statement: every transition appends to the log, so
//!    none lands between them. A transition that commits after the
//!    snapshot began makes taking the head fail with a serialization error
//!    (it cannot be seen, and must not be missed): the transaction is
//!    retried a few times, and otherwise the start fails closed, to be
//!    started again. A transition still in flight waits for the head and
//!    lands after the migration's events.
//! 2. One transaction appends the genesis event (`anchor.genesis`: the
//!    version-1 anchor's digest; the signed anchor itself is kept beside
//!    it) and one event per ID of its sets, and of the database's own
//!    negative state the anchor had not caught up with yet:
//!    `migrated.<set>` (in the project's or organization's partition where
//!    the database knows it, the platform's otherwise), `ledger.frozen` for
//!    a frozen ledger, `row.lost` for a lost row, and
//!    `privacy.ledger_checkpoint` for each ledger's checkpoint (its floor).
//! 3. The log's mirror in the anchor store is written, then the anchor is
//!    replaced, compare-and-set on its counter, by version 2
//!    holding the log's size and head and the version-1 anchor's counter
//!    and digest (and nothing per ledger or per ID).
//!
//! A crash between 2 and 3 leaves the version-1 anchor and the migrated
//! log: the next start finds the genesis event with the stored anchor's
//! digest and only completes step 3 (refusing if anything but the
//! migration's events followed it, or if the digest is another anchor's).
//! There is no window in which the anchor could be rolled back: the
//! version-1 anchor stays authoritative until the version-2 anchor
//! replaces it. A version-2 anchor is refused by earlier releases: there
//! is no downgrade.

use std::collections::BTreeSet;

use encompute_ir::{Error, Result};

use crate::anchor::StateAnchorV1;
use crate::audit;
use crate::control::{load_ledger, revoked_status, rollback, Control};
use crate::db::db_err;
use crate::govlog::{self, NegSet};
use crate::log::LogLine;
use postgres::GenericClient;
use postgres::Transaction;

thread_local! {
    /// Runs inside the migration's transaction, after the checks and the
    /// gathering, before the events are written (tests: a concurrent
    /// writer must not escape the migration's snapshot).
    static MIGRATION_HOOK: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Sets (or clears) the migration hook of this thread (tests only).
#[doc(hidden)]
pub fn set_migration_test_hook(f: Option<Box<dyn Fn()>>) {
    MIGRATION_HOOK.with(|h| *h.borrow_mut() = f);
}

impl Control {
    /// Migrates `v1` (see the module documentation).
    pub(crate) fn migrate_v1_anchor(&self, v1: &StateAnchorV1) -> Result<()> {
        let digest = v1.digest()?;
        let canonical = v1.canonical()?;
        // One transaction, one snapshot: the governance log's head is
        // locked first (every transition appends to the log, so none can
        // land between the checks, the gathering of the sets and their
        // events), then 0.3.0's checks, the sets and the events, all read
        // at REPEATABLE READ.
        let migrated = self.db.tx(|t| {
            t.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .map_err(db_err)?;
            govlog::lock_head(t)?;
            self.verify_state_v1(t, v1).map_err(|e| {
                Error::new(
                    e.code,
                    format!("{} (the version-1 state anchor was not migrated)", e.message),
                )
            })?;
            let count: usize = match govlog::genesis(t)? {
                Some((g, d, _)) if d == digest => {
                    // Step 2 committed, step 3 did not: only the
                    // migration's events may follow the genesis.
                    let later: i64 = t
                        .query_one(
                            "SELECT count(*) FROM governance_events
                              WHERE gseq > $1 AND kind NOT LIKE 'migrated.%' AND kind NOT IN ($2, $3, $4)",
                            &[
                                &g,
                                &govlog::extra_kind::LEDGER_FROZEN,
                                &govlog::extra_kind::ROW_LOST,
                                &govlog::extra_kind::LEDGER_CHECKPOINT,
                            ],
                        )
                        .map_err(db_err)?
                        .get(0);
                    if later > 0 {
                        return Err(rollback(
                            "ANCHOR",
                            "the governance log moved on after migrating this version-1 state anchor, which is stored again (the anchor store was rolled back)",
                        ));
                    }
                    Ok(0)
                }
                Some((_, d, _)) => Err(rollback(
                    "ANCHOR",
                    format!(
                        "the governance log was migrated from another version-1 state anchor (digest {d}) than the stored one ({digest}): the anchor store was rolled back or replaced"
                    ),
                )),
                None => {
                    let sets = self.v1_sets(t, v1)?;
                    MIGRATION_HOOK.with(|h| {
                        if let Some(f) = h.borrow().as_ref() {
                            f()
                        }
                    });
                    govlog::append_genesis(t, v1.counter, &digest, &canonical)?;
                    for (set, ids) in &sets {
                        let kind = set.migrated_kind();
                        for id in ids {
                            govlog::append_routed(t, *set, &kind, id, &[])?;
                        }
                    }
                    // The version-1 anchor's ledger checkpoints: the floor
                    // each ledger must still extend.
                    for (asset, cp) in &v1.ledgers {
                        govlog::append_ledger_checkpoint(t, asset, cp)?;
                    }
                    for key in &v1.lost {
                        let (state, id) = key.split_once(':').ok_or_else(|| {
                            rollback("ANCHOR", format!("lost row {key:?} of the version-1 anchor"))
                        })?;
                        let set = NegSet::ALL
                            .into_iter()
                            .find(|s| s.lost_state() == state)
                            .ok_or_else(|| {
                                rollback("ANCHOR", format!("lost row {key:?} of the version-1 anchor"))
                            })?;
                        govlog::append_lost(t, set, id)?;
                    }
                    Ok(sets.iter().map(|(_, ids)| ids.len()).sum::<usize>()
                        + v1.ledgers.len()
                        + v1.lost.len())
                }
            }?;
            // The head this transaction leaves (it holds the head's lock):
            // a writer that appends right after must not be mistaken for
            // part of the migration.
            let (size, head) = govlog::lock_head(t)?;
            Ok((count, size, head))
        })?;
        let (migrated, size, head) = migrated;
        // The mirror first, then the anchor (the commit point).
        self.mirror_through(0, size)?;
        self.anchor.try_update(&self.signer, |a| {
            a.glog_size = size;
            a.glog_head = head.clone();
            a.migrated_from = Some(crate::anchor::MigratedFrom {
                counter: v1.counter,
                digest: digest.clone(),
            });
            Ok(true)
        })?;
        LogLine::new(&self.service_id, "state_anchor_migrated")
            .field("from_version", crate::anchor::ANCHOR_V1_VERSION)
            .field("to_version", crate::anchor::ANCHOR_VERSION)
            .field("v1_counter", v1.counter)
            .field("events", migrated)
            .field("glog_size", size)
            .emit();
        Ok(())
    }

    /// The version-1 anchor's sets, with the negative state the database
    /// holds that the anchor had not caught up with yet (what 0.3.0's
    /// background sync would have added).
    fn v1_sets(
        &self,
        c: &mut Transaction<'_>,
        v1: &StateAnchorV1,
    ) -> Result<Vec<(NegSet, BTreeSet<String>)>> {
        let ids = |c: &mut Transaction<'_>,
                   sql: &str,
                   base: &BTreeSet<String>|
         -> Result<BTreeSet<String>> {
            let mut out = base.clone();
            out.extend(
                c.query(sql, &[])
                    .map_err(db_err)?
                    .iter()
                    .map(|r| r.get::<_, String>(0)),
            );
            Ok(out)
        };
        Ok(vec![
            (
                NegSet::RevokedAssets,
                ids(
                    c,
                    "SELECT id FROM assets WHERE status = 'revoked'",
                    &v1.revoked,
                )?,
            ),
            (
                NegSet::DisabledServices,
                ids(
                    c,
                    "SELECT id FROM service_accounts WHERE status = 'disabled'",
                    &v1.disabled_services,
                )?,
            ),
            (
                NegSet::DisabledUsers,
                ids(
                    c,
                    "SELECT id FROM users WHERE status = 'disabled'",
                    &v1.disabled_users,
                )?,
            ),
            (
                NegSet::EndedJobs,
                ids(
                    c,
                    "SELECT id FROM jobs WHERE state IN ('failed', 'cancelled')",
                    &v1.ended_jobs,
                )?,
            ),
            (
                NegSet::WithdrawnGrants,
                ids(c, "SELECT id FROM withdrawn_grants", &v1.withdrawn_grants)?,
            ),
            (
                NegSet::RemovedMemberships,
                ids(
                    c,
                    "SELECT id FROM removed_memberships",
                    &v1.removed_memberships,
                )?,
            ),
            (
                NegSet::RemovedRoles,
                ids(c, "SELECT id FROM removed_roles", &v1.removed_roles)?,
            ),
            (
                NegSet::RevokedAuthorizations,
                ids(
                    c,
                    "SELECT id FROM authorizations WHERE status = 'revoked'
                     UNION SELECT authorization_id FROM authorizations
                      WHERE status = 'revoked' AND authorization_id IS NOT NULL",
                    &v1.revoked_authorizations,
                )?,
            ),
            (
                NegSet::ExpiredAssets,
                ids(
                    c,
                    "SELECT id FROM assets WHERE expired_at IS NOT NULL",
                    &v1.expired_assets,
                )?,
            ),
            (
                NegSet::RetiredPurposes,
                ids(
                    c,
                    "SELECT id FROM purposes WHERE status = 'retired'",
                    &BTreeSet::new(),
                )?,
            ),
            (
                NegSet::RevokedKeys,
                ids(
                    c,
                    "SELECT id FROM governance_keys WHERE status = 'revoked'",
                    &BTreeSet::new(),
                )?,
            ),
            (NegSet::FrozenLedgers, v1.frozen.clone()),
        ])
    }

    /// Every check 0.3.0 made of its (version-1) anchor at startup.
    fn verify_state_v1(&self, c: &mut Transaction<'_>, a: &StateAnchorV1) -> Result<()> {
        let (seq, _root) = audit::verify_chain(&mut *c)?;
        if a.audit_seq > seq
            || audit::hash_at(&mut *c, a.audit_seq)?.as_deref() != Some(a.audit_root.as_str())
        {
            return Err(rollback(
                "AUDIT",
                format!(
                    "the anchor recorded audit event {} but the database's chain ends at {seq} or differs",
                    a.audit_seq
                ),
            ));
        }
        for (asset, cp) in &a.ledgers {
            let Some(view) = load_ledger(&mut *c, asset)? else {
                // A frozen ledger whose asset the database does not hold
                // either cannot be spent (asset IDs are never reissued).
                if a.frozen.contains(asset) && revoked_status(&mut *c, asset)?.is_none() {
                    continue;
                }
                return Err(rollback(
                    "PRIVACY",
                    format!("the privacy ledger of {asset} is missing"),
                ));
            };
            view.verify()?;
            view.extends(cp).map_err(|e| {
                rollback(
                    "PRIVACY",
                    format!("the privacy ledger of {asset}: {}", e.message),
                )
            })?;
        }
        // A ledger the anchor froze stays frozen, whatever the database says.
        for asset in &a.frozen {
            let row = c
                .query_opt(
                    "SELECT frozen_reason FROM privacy_ledgers WHERE asset_id = $1",
                    &[asset],
                )
                .map_err(db_err)?;
            if let Some(r) = row {
                if r.get::<_, Option<String>>(0).is_none() {
                    return Err(rollback(
                        "FREEZE",
                        format!("the privacy ledger of {asset} was frozen, but the database shows it spendable"),
                    ));
                }
            }
        }
        // A row an anchored set names must still be there: deleting it
        // undoes the transition as surely as changing it back (a deleted
        // revoked authorization frees its signed document to come back
        // under another row; a deleted disabled service frees its ID).
        // Only recovery's acknowledgement in the anchor excuses a loss.
        if let Some((what, id)) = missing_rows_v1(&mut *c, a)?.into_iter().next() {
            return Err(rollback(
                what,
                format!("{id} is anchored, but the database no longer holds it"),
            ));
        }
        // A revoked asset must still be revoked.
        for asset in &a.revoked {
            if let Some(status) = revoked_status(&mut *c, asset)? {
                if status != "revoked" {
                    return Err(rollback(
                        "REVOCATION",
                        format!("asset {asset} was revoked, but the database shows it {status}"),
                    ));
                }
            }
        }
        // Disabled principals stay disabled; cancelled and failed jobs stay
        // ended.
        let undone = |c: &mut Transaction<'_>,
                      sql: &str,
                      ids: &std::collections::BTreeSet<String>|
         -> Result<Vec<(String, String)>> {
            if ids.is_empty() {
                return Ok(vec![]);
            }
            let ids: Vec<&String> = ids.iter().collect();
            Ok(c.query(sql, &[&ids])
                .map_err(db_err)?
                .iter()
                .map(|r| (r.get(0), r.get(1)))
                .collect())
        };
        for (what, sql, ids) in [
            (
                "SERVICE ACCOUNT",
                "SELECT id, status FROM service_accounts WHERE id = ANY($1) AND status <> 'disabled' ORDER BY id",
                &a.disabled_services,
            ),
            (
                "USER",
                "SELECT id, status FROM users WHERE id = ANY($1) AND status <> 'disabled' ORDER BY id",
                &a.disabled_users,
            ),
            (
                "JOB",
                "SELECT id, state FROM jobs WHERE id = ANY($1) AND state NOT IN ('failed', 'cancelled') ORDER BY id",
                &a.ended_jobs,
            ),
        ] {
            if let Some((id, status)) = undone(c, sql, ids)?.into_iter().next() {
                let was = if what == "JOB" { "cancelled or failed" } else { "disabled" };
                return Err(rollback(
                    what,
                    format!("{} {id} was {was}, but the database shows it {status}", what.to_lowercase()),
                ));
            }
        }
        // A withdrawn approval (or ended grant) stays withdrawn: its ID is
        // never reused, so a database holding it again was restored.
        if let Some((id, asset)) = undone(
            c,
            "SELECT approval_id, asset_id FROM asset_approvals WHERE approval_id = ANY($1)
             UNION ALL
             SELECT grant_id, asset_id FROM asset_approval_members WHERE grant_id = ANY($1)
             ORDER BY 1",
            &a.withdrawn_grants,
        )?
        .into_iter()
        .next()
        {
            return Err(rollback(
                "APPROVAL",
                format!("approval {id} of asset {asset} was withdrawn, but the database holds it"),
            ));
        }
        // A removed project membership stays removed, likewise: the
        // organization would see the project, submit jobs in it and be
        // covered by approvals given to its members again.
        if let Some((id, who)) = undone(
            c,
            "SELECT membership_id, organization_id || ' in project ' || project_id FROM project_members
              WHERE membership_id = ANY($1) ORDER BY 1",
            &a.removed_memberships,
        )?
        .into_iter()
        .next()
        {
            return Err(rollback(
                "MEMBERSHIP",
                format!("membership {id} ({who}) was removed, but the database holds it"),
            ));
        }
        // A removed organization role stays removed, likewise: the
        // principal would act with it again.
        if let Some((id, who)) = undone(
            c,
            "SELECT membership_id, role || ' of ' || principal_id || ' in ' || organization_id FROM memberships
              WHERE membership_id = ANY($1) ORDER BY 1",
            &a.removed_roles,
        )?
        .into_iter()
        .next()
        {
            return Err(rollback(
                "ROLE",
                format!("role {id} ({who}) was removed, but the database holds it"),
            ));
        }
        // A revoked owner authorization stays revoked (its key brokers were
        // told already), and an expired asset stays expired.
        if let Some((id, status)) = undone(
            c,
            "SELECT id, status FROM authorizations
              WHERE (id = ANY($1) OR authorization_id = ANY($1)) AND status <> 'revoked' ORDER BY id",
            &a.revoked_authorizations,
        )?
        .into_iter()
        .next()
        {
            return Err(rollback(
                "AUTHORIZATION",
                format!("authorization {id} was revoked, but the database shows it {status}"),
            ));
        }
        if let Some((id, status)) = undone(
            c,
            "SELECT id, status FROM assets WHERE id = ANY($1) AND expired_at IS NULL ORDER BY id",
            &a.expired_assets,
        )?
        .into_iter()
        .next()
        {
            return Err(rollback(
                "EXPIRY",
                format!("asset {id} expired, but the database shows it {status} and not expired"),
            ));
        }
        Ok(())
    }
}

/// The anchor's key of a lost row: `set:id`.
fn lost_key(what: &str, id: &str) -> String {
    format!("{}:{id}", what.to_lowercase().replace(' ', "_"))
}

/// The IDs anchored sets name that the database does not hold, and that
/// recovery has not acknowledged as lost: (state, ID). Withdrawn approvals
/// and removed memberships and roles are anchored as absent rows, so they
/// are not here.
fn missing_rows_v1(
    c: &mut impl GenericClient,
    a: &StateAnchorV1,
) -> Result<Vec<(&'static str, String)>> {
    let mut out = vec![];
    for (what, ids, table, matches) in [
        ("REVOCATION", &a.revoked, "assets", "t.id = x"),
        (
            "SERVICE ACCOUNT",
            &a.disabled_services,
            "service_accounts",
            "t.id = x",
        ),
        ("USER", &a.disabled_users, "users", "t.id = x"),
        ("JOB", &a.ended_jobs, "jobs", "t.id = x"),
        (
            "AUTHORIZATION",
            &a.revoked_authorizations,
            "authorizations",
            "t.id = x OR t.authorization_id = x",
        ),
        ("EXPIRY", &a.expired_assets, "assets", "t.id = x"),
    ] {
        let ids: Vec<&String> = ids
            .iter()
            .filter(|id| !a.lost.contains(&lost_key(what, id)))
            .collect();
        if ids.is_empty() {
            continue;
        }
        let rows = c
            .query(
                &format!(
                    "SELECT x FROM unnest($1::text[]) AS x
                      WHERE NOT EXISTS (SELECT 1 FROM {table} t WHERE {matches}) ORDER BY x"
                ),
                &[&ids],
            )
            .map_err(db_err)?;
        out.extend(rows.iter().map(|r| (what, r.get::<_, String>(0))));
    }
    Ok(out)
}
