//! Control-plane operations, grouped by resource. Each checks
//! authorization, runs in one transaction, and records its audit event in
//! that transaction.

mod assets;
mod jobs;
mod policies;
mod tenancy;

pub(crate) use assets::withdraw_grants;
pub use assets::{asset_json, check_reservation, least_sensitivity, shared_asset_json};
pub use jobs::{estimated_ms, job_profile, GATE_MS, HEARTBEAT_TIMEOUT_SECS};
pub use tenancy::{legacy_service_admins, LEGACY_SERVICE_ADMINS_REFUSED_FROM};

/// Takes the transaction-scoped advisory lock of service ID `broker` as a
/// key broker. Registering a service account under that ID and registering
/// an asset whose key names that broker both take it, before any row lock
/// and before the audit head, so each sees the other's committed write:
/// an organization's broker and another organization's asset naming it
/// cannot both be accepted (ENC-SF-2026-041).
pub fn keybroker_lock(
    t: &mut impl postgres::GenericClient,
    broker: &str,
) -> encompute_ir::Result<()> {
    t.execute(
        "SELECT pg_advisory_xact_lock(hashtext('keybroker'), hashtext($1))",
        &[&broker],
    )
    .map(|_| ())
    .map_err(crate::db::db_err)
}

/// How long [`revalidate`] waits for a row lock another transaction holds.
/// The wait fails the request (a database error, HTTP 500)
/// rather than let it go on with a decision made before the wait.
const REVALIDATE_LOCK_TIMEOUT: &str = "SET LOCAL lock_timeout = '5s'";

/// What [`revalidate`] locks and re-reads besides the caller's own standing
/// (account status and roles), which it always does.
#[derive(Default, Clone, Copy)]
pub(crate) struct Authority<'a> {
    /// A project whose membership rows are locked and re-read: the caller's
    /// organization must still be an active member.
    project: Option<&'a str>,
    /// Assets locked shared; the caller then reads their status.
    assets: Option<&'a [String]>,
    /// A job whose source assets are locked shared (the evaluator's start).
    job_sources: Option<&'a str>,
    /// `(project, purpose, organization)`: the asset approvals covering
    /// `assets` for that organization, locked shared.
    approvals: Option<(&'a str, &'a str, &'a str)>,
}

impl<'a> Authority<'a> {
    pub(crate) fn principal() -> Self {
        Self::default()
    }
    pub(crate) fn project(mut self, id: &'a str) -> Self {
        self.project = Some(id);
        self
    }
    pub(crate) fn assets(mut self, ids: &'a [String]) -> Self {
        self.assets = Some(ids);
        self
    }
    pub(crate) fn job_sources(mut self, job: &'a str) -> Self {
        self.job_sources = Some(job);
        self
    }
    pub(crate) fn approvals(mut self, project: &'a str, purpose: &'a str, org: &'a str) -> Self {
        self.approvals = Some((project, purpose, org));
        self
    }
}

/// Re-reads, inside the transaction `t` that is about to take effect and
/// after taking the row locks it needs, the security state the request's
/// earlier checks relied on: the caller's account is not disabled, every
/// role it was authenticated with is still held, its organization is still
/// an active member of the project, the assets and their approvals
/// are locked (see [`Authority`]); the caller's reads after the locks
/// (asset status, approval rows, job state) are the re-read of those. A decision made before a wait (the
/// request-level check, authentication, an earlier read) is therefore not
/// the decision the effect rests on. Fails closed: a missing or changed row
/// refuses the call, and a lock another transaction holds longer than the
/// timeout fails it (never passes).
///
/// Locks are shared (`FOR SHARE`): a concurrent revocation, disabling or
/// removal waits for this transaction to end, or has committed and is seen
/// here. They are taken in one
/// global order, which every transaction follows, so none waits in a cycle:
/// account row, role rows by (organization, role), project member rows by
/// organization, assets by ID, approvals by asset ID; the job rows an
/// operation updates come after (the callers lock them later). A call may
/// run this again with a wider scope: the later tables come later in the
/// order. The isolation is PostgreSQL's default, READ COMMITTED: each
/// statement sees what has committed when it starts, and a row locked here
/// cannot change until this transaction ends, so the reads that follow the
/// locks (here and in the caller) see the state the effect commits on.
pub(crate) fn revalidate(
    t: &mut impl postgres::GenericClient,
    p: &crate::authn::Principal,
    scope: &Authority<'_>,
) -> encompute_ir::Result<()> {
    use crate::authn::PrincipalKind;
    use crate::authz::{forbidden, not_found};
    use encompute_ir::{Code, Error};

    let db = |e: postgres::Error| lock_err(e);
    t.batch_execute(REVALIDATE_LOCK_TIMEOUT).map_err(db)?;

    // 1. The account.
    let (table, code, what) = match p.kind {
        PrincipalKind::User { .. } => ("users", Code::Unauthenticated, "user"),
        PrincipalKind::Service { .. } => (
            "service_accounts",
            Code::ServiceAuthentication,
            "service account",
        ),
    };
    let status: Option<String> = t
        .query_opt(
            &format!("SELECT status FROM {table} WHERE id = $1 FOR SHARE"),
            &[&p.id],
        )
        .map_err(db)?
        .map(|r| r.get(0));
    match status.as_deref() {
        Some("active") => {}
        Some(_) => return Err(Error::new(code, format!("this {what} is disabled"))),
        None => return Err(Error::new(code, format!("this {what} no longer exists"))),
    }

    // 2. The roles it was authenticated with.
    let held: std::collections::BTreeSet<(String, String)> = t
        .query(
            "SELECT organization_id, role FROM memberships WHERE principal_id = $1
              ORDER BY organization_id, role FOR SHARE",
            &[&p.id],
        )
        .map_err(db)?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    if let Some((org, role)) = p
        .roles
        .iter()
        .find(|(o, r)| !held.contains(&(o.clone(), r.as_str().to_owned())))
    {
        return Err(forbidden(format!(
            "the role {} in {org} is no longer held",
            role.as_str()
        )));
    }

    // 3. Project membership.
    if let Some(project) = scope.project {
        let members: Vec<String> = t
            .query(
                "SELECT organization_id FROM project_members WHERE project_id = $1 AND status = 'active'
                  ORDER BY organization_id FOR SHARE",
                &[&project],
            )
            .map_err(db)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        if !members.iter().any(|o| p.member_of(o)) {
            return Err(not_found("project", project));
        }
    }

    // 4. Assets and the approvals that cover them.
    let mut ids: Vec<String> = scope.assets.map(<[String]>::to_vec).unwrap_or_default();
    if let Some(job) = scope.job_sources {
        if let Some(r) = t
            .query_opt("SELECT source_assets FROM jobs WHERE id = $1", &[&job])
            .map_err(db)?
        {
            let v: serde_json::Value = r.get(0);
            ids.extend(serde_json::from_value::<Vec<String>>(v).unwrap_or_default());
        }
    }
    if !ids.is_empty() {
        ids.sort();
        ids.dedup();
        t.query(
            "SELECT id FROM assets WHERE id = ANY($1) ORDER BY id FOR SHARE",
            &[&ids],
        )
        .map_err(db)?;
        if let Some((project, purpose, org)) = scope.approvals {
            t.query(
                "SELECT asset_id FROM asset_approval_members
                  WHERE asset_id = ANY($1) AND project_id = $2 AND purpose = $3 AND organization_id = $4
                  ORDER BY asset_id FOR SHARE",
                &[&ids, &project, &purpose, &org],
            )
            .map_err(db)?;
        }
    }
    Ok(())
}

/// A database error from a revalidation statement; a lock wait that ran out
/// says so.
fn lock_err(e: postgres::Error) -> encompute_ir::Error {
    if e.code() == Some(&postgres::error::SqlState::LOCK_NOT_AVAILABLE) {
        return encompute_ir::Error::new(
            encompute_ir::Code::Remote,
            "database: the authority could not be revalidated: a row it needs is locked by another \
             transaction (lock timeout, SQLSTATE 55P03); the request is refused",
        );
    }
    crate::db::db_err(e)
}
