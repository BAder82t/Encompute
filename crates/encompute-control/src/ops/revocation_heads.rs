//! Owner revocation heads: an organization's signed statement, in a
//! governed project, of every revocation it made there, so an evidence
//! bundle cannot silently leave one out.
//!
//! The revocations an organization made in a project are in the project's
//! log: an authorization it revoked (and its signed revocation), an asset
//! of its own that was revoked or expired where the project used it, a
//! purpose it retired, a governance key it revoked. Their leaves, sorted,
//! fold into the root a head carries ([`encompute_trust::govlog`]). The
//! control plane states that root ([`Control::revocation_head_draft`]); the
//! organization recomputes it from the leaves before signing
//! (`encompute governance sign --kind revocation-head`) and the control
//! plane accepts the head only when its root is its own fold of the log
//! ([`accept_head`]).
//!
//! A governed revocation owes the next head, and nothing extra is recorded
//! for it: a head covers the revocations recorded before its own event, so
//! the revocations after the latest head's event are the ones owed
//! (`pending_since` is when the oldest was recorded). A revocation that
//! reaches the project may carry the next head (authorization revocation
//! and purpose retirement take one), and is then accepted or refused
//! together with it: the revocation is not recorded without it. Revocations
//! that reach several projects (an asset's, a governance key's) leave a head
//! owed in each. Nothing blocks while a head is owed (a revocation must take
//! effect now); a bundle checked against a head that is behind is UNCHECKED
//! until the next one, never a pass, and the draft reports `overdue` after
//! a day.

use serde_json::{json, Value};

use encompute_ir::{Code, Error, Result};
use encompute_trust::govlog::{
    hash_hex, kind, revocation_root, revocation_state, GovEvent, Partition, RevocationState,
    SignedRevocationHead,
};
use encompute_verification::service::now;

use crate::audit::{self, Outcome};
use crate::authz::{conflict, deny_auditor, forbidden, not_found, project_visible, require_human};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::govlog;
use crate::model::{bad, Role};

/// How far ahead of the control plane's clock a head may be dated.
const HEAD_SKEW_SECS: u64 = 60;
/// How long an owner may owe a head before the draft calls it overdue
/// (the bound on how long its bundles stay unchecked).
pub const HEAD_DUE_SECS: u64 = 86_400;

fn head_err(m: impl Into<String>) -> Error {
    Error::new(Code::GovernanceRevocationHead, m)
}

/// An organization's events about its revocations in `project`.
fn org_events(
    c: &mut impl postgres::GenericClient,
    project: &str,
    org: &str,
) -> Result<Vec<GovEvent>> {
    let mut kinds: Vec<&str> = kind::REVOCATIONS.to_vec();
    kinds.push(kind::REVOCATION_HEAD_SIGNED);
    let partition = Partition::Project(project.to_owned()).to_string();
    c.query(
        "SELECT body FROM governance_events
          WHERE partition = $1 AND org_id = $2 AND kind = ANY($3) ORDER BY pseq",
        &[&partition, &org, &kinds],
    )
    .map_err(db_err)?
    .iter()
    .map(|r| serde_json::from_value(r.get(0)).map_err(db_err))
    .collect()
}

/// The organization's revocation state in the project, from the log.
pub fn state(
    c: &mut impl postgres::GenericClient,
    project: &str,
    org: &str,
) -> Result<RevocationState> {
    Ok(revocation_state(&org_events(c, project, org)?, org))
}

/// The latest head stored: (number, date).
fn previous(
    c: &mut impl postgres::GenericClient,
    project: &str,
    org: &str,
) -> Result<Option<(u64, u64)>> {
    Ok(c.query_opt(
        "SELECT seq, at FROM revocation_heads
          WHERE organization_id = $1 AND project_id = $2 ORDER BY seq DESC LIMIT 1",
        &[&org, &project],
    )
    .map_err(db_err)?
    .map(|r| (r.get::<_, i64>(0) as u64, r.get::<_, i64>(1) as u64)))
}

/// Each organization's latest head in the project (signed), for the
/// readers of its log.
pub fn latest_heads(c: &mut impl postgres::GenericClient, project: &str) -> Result<Vec<Value>> {
    Ok(c.query(
        "SELECT DISTINCT ON (organization_id) signed FROM revocation_heads
          WHERE project_id = $1 ORDER BY organization_id, seq DESC",
        &[&project],
    )
    .map_err(db_err)?
    .iter()
    .map(|r| r.get(0))
    .collect())
}

/// Accepts `h` in the caller's transaction: the next head of its
/// organization in the project, signed by the organization's active
/// governance key, dated no later than the control plane's clock plus
/// five minutes and no earlier than the previous head, with the root the
/// control plane folds from the log (ENC2717 otherwise; a key that is
/// revoked or not the organization's keeps its own code). Stores it and
/// appends the `revocation_head.signed` event. `lock` takes the governance
/// log head first (a caller that appended a revocation holds it already);
/// the audit event is last.
pub(crate) fn accept_head(
    t: &mut postgres::Transaction<'_>,
    ctx: &Ctx,
    project: &crate::authz::ProjectRow,
    h: &SignedRevocationHead,
    lock: bool,
) -> Result<Value> {
    let (id, org) = (project.id.as_str(), h.body.organization.as_str());
    h.body.check().map_err(|e| head_err(e.message))?;
    if h.body.project != id {
        return Err(head_err(format!(
            "the head is for project {}, not {id}",
            h.body.project
        )));
    }
    if project.organization != org && !project.members.iter().any(|m| m == org) {
        return Err(forbidden(format!(
            "{org} does not take part in project {id} as an owner or member: it has no revocation head there"
        )));
    }
    if lock {
        govlog::lock_head(t)?;
    }
    super::governance::under_active_key(t, org, &h.public_key, |k| h.verify(k))?;
    if h.body.at > now() + HEAD_SKEW_SECS {
        return Err(head_err("a revocation head is not dated in the future"));
    }
    let prev = previous(t, id, org)?;
    let expected = prev.map_or(1, |p| p.0 + 1);
    if h.body.seq != expected {
        return Err(head_err(format!(
            "{org}'s next revocation head in {id} is number {expected}, not {}: a number is never skipped or repeated",
            h.body.seq
        )));
    }
    if prev.is_some_and(|p| h.body.at < p.1) {
        return Err(head_err(
            "a revocation head is not dated before the previous one",
        ));
    }
    let events = org_events(t, id, org)?;
    let leaves = revocation_state(&events, org).leaves;
    let newest = events
        .iter()
        .filter(|e| kind::REVOCATIONS.contains(&e.kind.as_str()))
        .map(|e| e.at)
        .max()
        .unwrap_or(0);
    if h.body.at < newest {
        return Err(head_err(format!(
            "a revocation head is dated no earlier than the newest revocation it covers ({newest}): date it at or after that"
        )));
    }
    let root = hash_hex(&revocation_root(&leaves)?);
    if h.body.root != root {
        return Err(head_err(format!(
            "the head's root is not the control plane's fold of {org}'s {} revocations in {id}: fetch the draft again and sign the root it states",
            leaves.len()
        )));
    }
    t.execute(
        "INSERT INTO revocation_heads (organization_id, project_id, seq, root, at, signed)
         VALUES ($1, $2, $3, $4, $5, $6)",
        &[
            &org,
            &id,
            &(h.body.seq as i64),
            &h.body.root,
            &(h.body.at as i64),
            &serde_json::to_value(h).map_err(db_err)?,
        ],
    )
    .map_err(db_err)?;
    govlog::append(
        t,
        govlog::Draft::new(
            Partition::Project(id.to_owned()),
            kind::REVOCATION_HEAD_SIGNED,
            org,
        )
        .org(org)
        .r#ref("seq", h.body.seq.to_string())
        .r#ref("root", h.body.root.clone()),
    )?;
    audit::append(
        t,
        ctx.draft("revocation_head.signed", "project", id, Outcome::Succeeded)
            .org(org)
            .project(id)
            .r#ref("seq", h.body.seq.to_string())
            .r#ref("root", h.body.root.clone()),
    )?;
    Ok(
        json!({"project": id, "organization": org, "seq": h.body.seq, "root": h.body.root,
              "at": h.body.at, "revocations": leaves.len()}),
    )
}

impl Control {
    /// What `org`'s next revocation head in the governed project must
    /// carry: its revocations there as sorted leaves, the root over them,
    /// the next number and whether a head is owed (and since when). Read
    /// by `org`'s security admins and by the project's auditors (read-only);
    /// anyone else gets 404 or 403. The organization recomputes the root
    /// from the leaves before it signs.
    pub fn revocation_head_draft(&self, ctx: &Ctx, id: &str, org: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let p = project_visible(&mut *c, &ctx.principal, id)?;
        if !p.governed() {
            return Err(bad(
                "revocation heads belong to governed projects: a standard project has none",
            ));
        }
        let own = ctx.principal.member_of(org) && ctx.principal.has_role(org, Role::SecurityAdmin);
        let auditor = p
            .members
            .iter()
            .chain(&p.auditors)
            .any(|o| ctx.principal.has_role(o, Role::Auditor));
        if !own && !auditor {
            return Err(forbidden(
                "a revocation head's draft is read by a security admin of the organization or an auditor of the project",
            ));
        }
        let relevant = p.organization == org || p.members.iter().any(|m| m == org);
        self.project_log_limit.hit(&ctx.principal.id)?;
        let st = state(&mut *c, id, org)?;
        // An organization that left has nothing to sign for, but what it
        // left owed is still shown (it is never an error to read).
        if !relevant && st.leaves.is_empty() && st.last_head.is_none() {
            return Err(not_found("organization", org));
        }
        let prev = previous(&mut *c, id, org)?;
        let now = now();
        let has_key: bool = c
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM governance_keys WHERE organization_id = $1 AND status = 'active')",
                &[&org],
            )
            .map_err(db_err)?
            .get(0);
        let cannot = if !relevant {
            Some(format!(
                "{org} no longer takes part in the project: a head owed stays owed and its bundles stay UNCHECKED"
            ))
        } else if !has_key {
            Some(format!(
                "{org} has no active governance key: register and approve one; until then a head owed stays owed and its bundles stay UNCHECKED"
            ))
        } else {
            None
        };
        let partition = Partition::Project(id.to_owned()).to_string();
        Ok(json!({
            "project": id,
            "organization": org,
            "seq": prev.map_or(1, |p| p.0 + 1),
            "leaves": st.leaves,
            "root": hash_hex(&revocation_root(&st.leaves)?),
            "at": now,
            "log_size": govlog::partition_size(&mut *c, &partition)?,
            "previous": prev.map(|p| json!({"seq": p.0, "at": p.1})),
            "pending_since": st.pending_since,
            "overdue": st.pending_since.is_some_and(|s| now > s + HEAD_DUE_SECS),
            "due_secs": HEAD_DUE_SECS,
            "cannot_sign_reason": cannot,
        }))
    }

    /// An organization's signed revocation head: by a person who is a
    /// security admin of the organization (never a service account or an
    /// auditor), accepted as [`accept_head`] says. 201 with the head's
    /// number and root.
    pub fn submit_revocation_head(
        &self,
        ctx: &Ctx,
        id: &str,
        h: SignedRevocationHead,
    ) -> Result<Value> {
        self.db.tx(|t| {
            let p = project_visible(t, &ctx.principal, id)?;
            if !p.governed() {
                return Err(conflict(format!(
                    "project {id} is a standard project: revocation heads belong to governed projects"
                )));
            }
            deny_auditor(&ctx.principal, &p)?;
            require_human(
                &ctx.principal,
                &h.body.organization,
                &[Role::SecurityAdmin],
                "signing a revocation head",
            )?;
            accept_head(t, ctx, &p, &h, true)
        })
    }
}
