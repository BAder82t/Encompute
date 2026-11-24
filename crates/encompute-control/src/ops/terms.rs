//! Job terms: which jobs a project runs at all.
//!
//! The member organizations of a project, standard or governed, can agree
//! on terms ([`JobTerms`]; they can come from an agreement between the
//! organizations): the execution specs, purposes, submitting organizations
//! and evaluator receipt keys its jobs may have, how many jobs in total,
//! and a time window. A person who is an organization admin of a member
//! organization, acting for their own organization, proposes them (which
//! is that organization's acceptance); they take effect when such a person
//! of every active member organization has accepted them. Service accounts
//! never propose or accept, and neither does someone acting through a role
//! held in another organization or an auditor.
//!
//! While terms are active the control plane admits a job of the project
//! only within them, on top of every check it already makes (refusals are
//! audited as `job.denied` with their reason): submitted by an organization
//! they name that accepted them, over sources whose owner organizations
//! each accepted them too (a member that joined after they took effect
//! accepts the active terms before its data is used under them; that
//! acceptance changes nothing else). It counts every job submitted under
//! them, schedules a job only on an evaluator whose registered receipt key
//! they name (on top of the scheduler's own candidates and a governed job's
//! placement), and gives its grant an expiry before their end; a job still
//! unscheduled at the end fails, anchored as ended like any failed job. New
//! terms replace active ones only when every member accepted them too, so
//! no organization loosens them alone; when terms become active, every
//! other set of the project's terms, active or still proposed, is
//! superseded and can never be accepted again (so an older proposal cannot
//! replace newer terms later). Each member organization has at most
//! [`MAX_OPEN_TERMS_PROPOSALS`] of its own proposals awaiting acceptance in
//! a project at once, so none keeps the others from proposing. When an
//! organization leaves, the newest proposal every remaining member accepted
//! takes effect ([`Control::settle_terms`]); should that fail, the control
//! plane's periodic pass settles it ([`Control::settle_pending_terms`]). A
//! project created with `terms_required` runs nothing until terms are
//! active, and activation makes a project require terms from then on.
//!
//! Both are security-negative transitions of the governance log
//! ([`govlog::NegSet::TermsRequired`], [`govlog::NegSet::SupersededTerms`]),
//! written in the same transaction and anchored before the call returns: a
//! restored database that shows a project no longer requiring terms, or
//! superseded terms proposed or active again, is refused at startup (TERMS
//! REQUIREMENT, JOB TERMS STATE ROLLBACK), and recovery applies them again.
//! So is each job admitted under terms (`terms.job_admitted`, with its
//! number under them, [`record_admission`]): a restored database whose
//! terms count fewer jobs than the log recorded admitting is refused at
//! startup (JOB TERMS COUNT STATE ROLLBACK), and recovery raises the count
//! again, so terms never admit more jobs than they allow.
//!
//! Fairness. Every change of terms takes the project's terms advisory
//! lock exclusively just before the project's row, and a submission takes
//! it shared just before the row (`terms_lock_shared`): a waiting change
//! of terms is queued ahead of later submissions, so a stream of
//! submissions cannot hold it off. The advisory lock sits at the project
//! row's place in the lock order below.
//!
//! Lock order. A project's row is the first lock of every change to who
//! takes part in it or what it allows: joining it and changing its
//! placement take it `FOR UPDATE` before they read the members, and so do
//! proposing and accepting terms and settling them (after checking the
//! caller without any lock, and again under it), which then lock terms
//! rows, with the governance and audit heads last ([`audit::append`]).
//! Every change of a project's terms goes through [`lock_project`] first;
//! none relies on the lock an `UPDATE` of the row takes. A submission
//! takes, after every lock it already holds (the source assets and, in a
//! governed project, the rows of the purpose and the authorizations), the
//! project row `FOR KEY SHARE` and then the active terms row `FOR UPDATE`,
//! immediately before it inserts the job ([`admit`]), and the governance
//! and audit heads last: concurrent submissions under one set of terms are
//! counted one at a time, and none is counted against terms that a
//! concurrent acceptance is replacing (`FOR KEY SHARE` conflicts with the
//! `FOR UPDATE` of a change of terms or a join, not with an ordinary update
//! of the project's row, which it does not hold up). No transaction that
//! holds a project row `FOR UPDATE` waits for an asset, authorization or
//! job row, so the two orders never meet. A removal takes no lock on the
//! project row (it fails the project's unstarted jobs, so it waits for job
//! rows): an acceptance that read the members before the removal committed
//! needs the leaving organization's acceptance too, which is stricter, and
//! the settle after the removal takes the lock in its own transaction.
//! Scheduling reads a job's terms without a lock: a terms document never
//! changes (the database refuses it, schema version 19).

use postgres::GenericClient;
use serde_json::{json, Value};

use encompute_ir::{Error, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::service::sha256_hex;
use encompute_verification::EvaluatorIdentity;

use crate::audit::{self, AuditDraft, Outcome};
use crate::authz::{
    conflict, deny_auditor, forbidden, not_found, project_row, project_visible, require_human,
    ProjectRow,
};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::govlog::{self, NegSet};
use crate::log::LogLine;
use crate::model::{
    bad, check_name, new_id, JobTerms, Role, MAX_OPEN_TERMS_PROPOSALS, MAX_TERMS_ENTRIES,
    MAX_TERMS_JOBS,
};

/// 32 bytes of lowercase hex: how spec IDs and receipt keys are written.
fn lower_hex32(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn check_list(what: &str, v: &[String]) -> Result<()> {
    if v.is_empty() || v.len() > MAX_TERMS_ENTRIES {
        return Err(bad(format!(
            "job terms: {what} must list 1-{MAX_TERMS_ENTRIES} entries"
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    if let Some(d) = v.iter().find(|x| !seen.insert(x.as_str())) {
        return Err(bad(format!("job terms: {what} lists {d:?} twice")));
    }
    Ok(())
}

/// A terms document is well formed (its members are checked against the
/// project in [`check_members`]).
fn check_form(d: &JobTerms) -> Result<()> {
    check_list("specs", &d.specs)?;
    check_list("purposes", &d.purposes)?;
    check_list("submitters", &d.submitters)?;
    check_list("evaluator_keys", &d.evaluator_keys)?;
    if d.specs.iter().any(|s| !lower_hex32(s)) {
        return Err(bad(
            "job terms: a spec must be an execution spec ID (32 bytes of lowercase hex)",
        ));
    }
    for p in &d.purposes {
        check_name("job terms: a purpose", p)?;
    }
    for k in &d.evaluator_keys {
        if !lower_hex32(k) || EvaluatorIdentity::from_public_key_hex(k).is_err() {
            return Err(bad(
                "job terms: an evaluator key must be an Ed25519 public key in lowercase hex",
            ));
        }
    }
    if d.max_jobs == 0 || d.max_jobs > MAX_TERMS_JOBS {
        return Err(bad(format!(
            "job terms: max_jobs must be 1-{MAX_TERMS_JOBS}"
        )));
    }
    if d.not_after <= d.not_before || d.not_after > i64::MAX as u64 {
        return Err(bad("job terms: not_after must be after not_before"));
    }
    // Audited as a reference: an identifier, never free text.
    if let Some(r) = &d.reference {
        if r.is_empty()
            || r.len() > 200
            || !r
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:/@+".contains(&b))
        {
            return Err(bad(
                "job terms: reference must be 1-200 characters of letters, digits and -_.:/@+",
            ));
        }
    }
    Ok(())
}

/// Every submitter is a member organization of the project.
fn check_members(d: &JobTerms, members: &[String]) -> Result<()> {
    if let Some(o) = d.submitters.iter().find(|o| !members.contains(o)) {
        return Err(bad(format!(
            "job terms: submitter {o} is not a member of the project"
        )));
    }
    Ok(())
}

/// The organization a person acts for here: their own, a member of the
/// project, where they are an organization admin. Consent to terms is a
/// person's in their own organization ([`require_human`]), never a service
/// account's, an auditor's, nor that of someone homed elsewhere who holds
/// a role there.
fn admin_org(ctx: &Ctx, project: &ProjectRow, action: &str) -> Result<String> {
    deny_auditor(&ctx.principal, project)?;
    let Some(org) = ctx
        .principal
        .organization
        .clone()
        .filter(|o| project.members.contains(o))
    else {
        return Err(forbidden(format!(
            "{action} needs a person who is an organization_admin of a member organization, acting for their own organization"
        )));
    };
    require_human(&ctx.principal, &org, &[Role::OrganizationAdmin], action)?;
    Ok(org)
}

/// Locks project `id`'s row for a change of its terms (the first lock: see
/// the lock order above).
fn lock_project(t: &mut impl GenericClient, id: &str) -> Result<()> {
    // The project's terms lock, exclusive, then its row: see
    // [`terms_lock_shared`].
    t.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, $2))",
        &[&id, &TERMS_LOCK_SALT],
    )
    .map_err(db_err)?;
    t.query_opt("SELECT 1 FROM projects WHERE id = $1 FOR UPDATE", &[&id])
        .map_err(db_err)?;
    Ok(())
}

/// Salt of the per-project advisory lock that orders submissions and
/// changes of terms (a constant: every control plane of a database uses
/// the same one).
const TERMS_LOCK_SALT: i64 = 0x7465_726d_735f_6c6b;

/// A submission's side of the project's terms lock, shared, taken just
/// before the project's row. Row locks alone let a stream of overlapping
/// submissions (each holding the row `FOR KEY SHARE`) keep a change of
/// terms waiting for its `FOR UPDATE` indefinitely: PostgreSQL grants a
/// row lock that does not conflict with its holders even when a conflicting
/// request waits. Its lock manager queues an advisory lock request behind a
/// waiting conflicting one, so once a change of terms waits for the
/// exclusive lock, later submissions wait behind it.
fn terms_lock_shared(t: &mut impl GenericClient, project: &str) -> Result<()> {
    t.execute(
        "SELECT pg_advisory_xact_lock_shared(hashtextextended($1, $2))",
        &[&project, &TERMS_LOCK_SALT],
    )
    .map_err(db_err)?;
    Ok(())
}

fn terms_json(c: &mut impl GenericClient, id: &str) -> Result<Value> {
    let r = c
        .query_one(
            "SELECT id, project_id, organization_id, digest, document, status, jobs_submitted FROM job_terms WHERE id = $1",
            &[&id],
        )
        .map_err(db_err)?;
    let accepted: Vec<String> = c
        .query(
            "SELECT organization_id FROM job_terms_acceptances WHERE terms_id = $1 ORDER BY 1",
            &[&id],
        )
        .map_err(db_err)?
        .iter()
        .map(|x| x.get(0))
        .collect();
    Ok(json!({
        "id": r.get::<_, String>(0), "project": r.get::<_, String>(1),
        "proposed_by": r.get::<_, String>(2), "digest": r.get::<_, String>(3),
        "terms": r.get::<_, Value>(4), "status": r.get::<_, String>(5),
        "accepted_by": accepted, "jobs": r.get::<_, i64>(6),
    }))
}

/// Who records a change of terms: (actor, request ID). A caller's, or the
/// control plane's own service identity for its periodic pass.
pub(crate) type By<'a> = (&'a str, &'a str);

fn caller(ctx: &Ctx) -> By<'_> {
    (ctx.actor(), &ctx.request_id)
}

fn draft(by: By<'_>, action: &'static str, id: &str) -> AuditDraft {
    AuditDraft::new(by.0, by.1, action, "terms", id, Outcome::Succeeded)
}

/// Why proposed terms took effect other than on their last acceptance.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Settled<'a> {
    /// An organization leaving the project made them complete.
    MemberLeft(&'a str),
    /// The control plane's periodic pass found them complete (a settle
    /// after a removal that failed, retried).
    Pass,
}

/// Activates `id` when every active member organization of `project` has
/// accepted it: every other set of the project's terms, active or still
/// proposed, is superseded, and the project requires terms from now on.
/// Both are recorded in the governance log (anchored before the call
/// returns). Every member sees the activation in its own trail, and the
/// proposer of a superseded proposal sees that; when they took effect
/// other than on their last acceptance (`settled`), the activation says
/// why. Expects the project row and `id` locked.
fn activate_if_complete(
    t: &mut impl GenericClient,
    by: By<'_>,
    project: &str,
    members: &[String],
    id: &str,
    settled: Option<Settled<'_>>,
) -> Result<bool> {
    let accepted: Vec<String> = t
        .query(
            "SELECT organization_id FROM job_terms_acceptances WHERE terms_id = $1",
            &[&id],
        )
        .map_err(db_err)?
        .iter()
        .map(|r| r.get(0))
        .collect();
    // A project with no active member has nobody to agree terms for it.
    if members.is_empty() || !members.iter().all(|m| accepted.contains(m)) {
        return Ok(false);
    }
    // (id, what it was, who proposed it), by ID.
    let superseded: Vec<(String, String, String)> = t
        .query(
            "WITH old AS (
                 SELECT id, status FROM job_terms
                  WHERE project_id = $1 AND id <> $2 AND status IN ('active', 'proposed')
                  ORDER BY id FOR UPDATE)
             UPDATE job_terms x SET status = 'superseded' FROM old WHERE x.id = old.id
             RETURNING x.id, old.status, x.organization_id",
            &[&project, &id],
        )
        .map_err(db_err)?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    t.execute(
        "UPDATE job_terms SET status = 'active', activated_at = now() WHERE id = $1",
        &[&id],
    )
    .map_err(db_err)?;
    let newly_required = t
        .execute(
            "UPDATE projects SET terms_required = true WHERE id = $1 AND NOT terms_required",
            &[&project],
        )
        .map_err(db_err)?
        == 1;
    let mut sorted = superseded.clone();
    sorted.sort();
    for (old, was, _) in &sorted {
        govlog::append_routed(
            t,
            NegSet::SupersededTerms,
            govlog::kind::TERMS_SUPERSEDED,
            old,
            &[("by", id), ("was", was.as_str())],
        )?;
    }
    if newly_required {
        govlog::append_routed(
            t,
            NegSet::TermsRequired,
            govlog::kind::PROJECT_TERMS_REQUIRED,
            project,
            &[("terms", id)],
        )?;
    }
    let previous = sorted.iter().find(|(_, was, _)| was == "active");
    for m in members {
        let mut d = draft(by, "terms.activated", id).org(m).project(project);
        if let Some((s, _, _)) = previous {
            d = d.r#ref("superseded", s.clone());
        }
        match settled {
            Some(Settled::MemberLeft(o)) => {
                d = d
                    .r#ref("reason", "member_left")
                    .r#ref("member", o.to_owned());
            }
            Some(Settled::Pass) => d = d.r#ref("reason", "settled"),
            None => {}
        }
        audit::append(t, d)?;
    }
    for (old, _, proposer) in sorted.iter().filter(|(_, was, _)| was == "proposed") {
        audit::append(
            t,
            draft(by, "terms.superseded", old)
                .org(proposer)
                .project(project)
                .r#ref("by", id.to_owned()),
        )?;
    }
    Ok(true)
}

/// Why the project's terms refuse a submission: (resource type, resource
/// ID, audit reason, error).
pub(crate) type Refusal = (&'static str, String, &'static str, Error);

/// The terms a job of `project` submitted by `org` for `purpose` at `at`
/// is admitted under: `Ok(None)` when the project has no active terms and
/// does not require them, `Ok(Some(id))` within the active terms, or the
/// refusal. `specs` are the job's spec IDs the terms may name (the plan's;
/// a governed job's under its binding too); `sources` are its source
/// assets, whose owner organizations must each have accepted the terms.
///
/// Called last before the job is inserted, in the submission's
/// transaction: it key-share-locks the project row and locks the active
/// terms row for update (the lock order above), so the jobs already
/// submitted under them are counted one submission at a time, and the
/// acceptances it reads cannot change until it commits.
pub(crate) fn admit(
    t: &mut impl GenericClient,
    project: &str,
    org: &str,
    specs: &[&str],
    purpose: &str,
    sources: &[String],
    at: u64,
) -> Result<std::result::Result<Option<String>, Refusal>> {
    // FOR KEY SHARE: it conflicts with the FOR UPDATE that every change of
    // the project's terms (and a join) takes first, so a submission and
    // such a change are ordered, but not with an ordinary update of the
    // row.
    terms_lock_shared(t, project)?;
    let required: bool = t
        .query_opt(
            "SELECT terms_required FROM projects WHERE id = $1 FOR KEY SHARE",
            &[&project],
        )
        .map_err(db_err)?
        .ok_or_else(|| not_found("project", project))?
        .get(0);
    let Some(r) = t
        .query_opt(
            "SELECT id, document, jobs_submitted FROM job_terms WHERE project_id = $1 AND status = 'active' FOR UPDATE",
            &[&project],
        )
        .map_err(db_err)?
    else {
        if required {
            return Ok(Err((
                "project",
                project.to_owned(),
                "terms_none_active",
                forbidden(format!(
                    "project {project} runs jobs only under job terms its members have accepted, and none are active"
                )),
            )));
        }
        return Ok(Ok(None));
    };
    let id: String = r.get(0);
    let d: JobTerms = serde_json::from_value(r.get(1))
        .map_err(|e| db_err(format!("job terms {id} cannot be read: {e}")))?;
    let n: i64 = r.get(2);
    let accepted: Vec<String> = t
        .query(
            "SELECT organization_id FROM job_terms_acceptances WHERE terms_id = $1",
            &[&id],
        )
        .map_err(db_err)?
        .iter()
        .map(|x| x.get(0))
        .collect();
    let refuse = |why: &'static str, m: String| {
        Ok(Err((
            "terms",
            id.clone(),
            why,
            forbidden(format!("outside the project's job terms ({id}): {m}")),
        )))
    };
    if !d.submitters.iter().any(|s| s == org) || !accepted.iter().any(|s| s == org) {
        return refuse(
            "terms_submitter",
            format!(
                "{org} is not a submitter that accepted them (terms that name it take effect when every member organization has accepted them)"
            ),
        );
    }
    // The owner of each source accepted them too: an organization that
    // joined after they took effect consents to them before its data is
    // used under them. (The control plane never changes an asset's owner,
    // and no acceptance of these terms commits while the project row is
    // key-share-locked here.)
    let owners: Vec<String> = t
        .query(
            "SELECT DISTINCT organization_id FROM assets WHERE id = ANY($1) ORDER BY 1",
            &[&sources],
        )
        .map_err(db_err)?
        .iter()
        .map(|x| x.get(0))
        .collect();
    if let Some(o) = owners.iter().find(|o| !accepted.contains(o)) {
        return refuse(
            "terms_owner",
            format!(
                "{o} owns a source of the job and has not accepted them: {o} must accept the terms before its data is used under them"
            ),
        );
    }
    if at < d.not_before || at >= d.not_after {
        return refuse(
            "terms_window",
            format!(
                "they admit jobs from {} until {} (unix seconds), not at {at}",
                d.not_before, d.not_after
            ),
        );
    }
    if !specs.iter().any(|s| d.specs.iter().any(|x| x == s)) {
        return refuse(
            "terms_spec",
            format!("execution spec {} is not one they name", specs.join(" or ")),
        );
    }
    if !d.purposes.iter().any(|p| p == purpose) {
        return refuse(
            "terms_purpose",
            format!("purpose {purpose:?} is not one they name"),
        );
    }
    // Counted by the database as each job is inserted (schema version 20),
    // under the row lock held here.
    if n.max(0) as u64 >= d.max_jobs {
        return refuse(
            "terms_limit",
            format!(
                "they allow {} job(s), and {n} have been submitted under them",
                d.max_jobs
            ),
        );
    }
    Ok(Ok(Some(id)))
}

/// Records in the governance log that job `job`, submitted by `org`, was
/// admitted under terms `terms` of `project`, with the number the database
/// gave it under them ([`govlog::append_terms_admission`]). In the
/// submission's transaction, after the job's row and last before its
/// audit event (the governance head immediately before the audit head),
/// while the terms row is still locked: the submission is then anchored
/// before it is acknowledged (`Control::tx_anchored`), so a restored
/// database cannot count fewer jobs under the terms than were admitted.
pub(crate) fn record_admission(
    t: &mut impl GenericClient,
    project: &str,
    org: &str,
    terms: &str,
    job: &str,
) -> Result<()> {
    let seq: i64 = t
        .query_one("SELECT terms_seq FROM jobs WHERE id = $1", &[&job])
        .map_err(db_err)?
        .get(0);
    govlog::append_terms_admission(t, project, org, terms, job, seq)?;
    Ok(())
}

/// Whether terms `d` name `key`, an evaluator's registered receipt key.
pub(crate) fn names_key(d: &JobTerms, key: &str) -> bool {
    d.evaluator_keys.contains(&key.to_ascii_lowercase())
}

/// Whether evaluator `evaluator`'s receipt key, as registered now, is one
/// terms `d` name (an evaluator may register again with another key after
/// a job under them was scheduled on it).
pub(crate) fn names_evaluator(
    c: &mut impl GenericClient,
    d: &JobTerms,
    evaluator: &str,
) -> Result<bool> {
    Ok(c.query_opt(
        "SELECT receipt_key FROM evaluators WHERE id = $1",
        &[&evaluator],
    )
    .map_err(db_err)?
    .is_some_and(|r| names_key(d, r.get(0))))
}

/// The document of terms `id` (a job's: never changed, read unlocked).
pub(crate) fn document(c: &mut impl GenericClient, id: &str) -> Result<JobTerms> {
    let r = c
        .query_opt("SELECT document FROM job_terms WHERE id = $1", &[&id])
        .map_err(db_err)?
        .ok_or_else(|| db_err(format!("job terms {id} are missing")))?;
    serde_json::from_value(r.get(0))
        .map_err(|e| db_err(format!("job terms {id} cannot be read: {e}")))
}

impl Control {
    /// `POST /v1/projects/{id}/terms`: an organization admin of a member
    /// organization proposes terms, accepting them for that organization.
    pub fn propose_terms(&self, ctx: &Ctx, project: &str, doc: JobTerms) -> Result<Value> {
        let document = serde_json::to_value(&doc).map_err(|e| bad(e.to_string()))?;
        let digest = sha256_hex(&canonical_json(&document)?);
        self.tx_anchored(|t| {
            // Who asks, before any lock (an outsider locks nothing; an
            // auditor is refused as such), then again under the project's
            // lock, then what they propose.
            let p = project_visible(t, &ctx.principal, project)?;
            admin_org(ctx, &p, "proposing job terms")?;
            lock_project(t, project)?;
            let p = project_visible(t, &ctx.principal, project)?;
            let org = admin_org(ctx, &p, "proposing job terms")?;
            check_form(&doc)?;
            check_members(&doc, &p.members)?;
            let open: i64 = t
                .query_one(
                    "SELECT count(*) FROM job_terms
                      WHERE project_id = $1 AND organization_id = $2 AND status = 'proposed'",
                    &[&project, &org],
                )
                .map_err(db_err)?
                .get(0);
            if open >= MAX_OPEN_TERMS_PROPOSALS {
                return Err(conflict(format!(
                    "{org} has {open} proposed job terms awaiting acceptance in project {project}, the most one organization may have at once: terms that become active supersede them"
                )));
            }
            let id = new_id("terms");
            t.execute(
                "INSERT INTO job_terms (id, project_id, organization_id, digest, document, status, created_by)
                 VALUES ($1, $2, $3, $4, $5, 'proposed', $6)",
                &[&id, &project, &org, &digest, &document, &ctx.actor()],
            )
            .map_err(db_err)?;
            t.execute(
                "INSERT INTO job_terms_acceptances (terms_id, organization_id, accepted_by) VALUES ($1, $2, $3)",
                &[&id, &org, &ctx.actor()],
            )
            .map_err(db_err)?;
            let mut d = ctx
                .draft("terms.proposed", "terms", &id, Outcome::Succeeded)
                .org(&org)
                .project(project)
                .r#ref("digest", digest.clone());
            if let Some(r) = &doc.reference {
                d = d.r#ref("reference", r.clone());
            }
            audit::append(t, d)?;
            activate_if_complete(t, caller(ctx), project, &p.members, &id, None)?;
            terms_json(t, &id)
        })
    }

    /// `POST /v1/terms/{id}/accept`: an organization admin of another
    /// member organization accepts proposed terms for it; the last
    /// acceptance activates them. A member organization that has not
    /// accepted the active terms (one that joined after they took effect)
    /// accepts them the same way: its acceptance is recorded and nothing
    /// else changes, and from then on jobs under them may use its assets.
    /// Accepting active terms again succeeds once the anchor holds what
    /// the first acceptance committed (it may have committed when
    /// anchoring failed); superseded terms are never accepted.
    pub fn accept_terms(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let again = std::cell::Cell::new(false);
        let out = self.tx_anchored(|t| {
            again.set(false);
            // Terms never move to another project (schema version 19).
            let project: String = t
                .query_opt("SELECT project_id FROM job_terms WHERE id = $1", &[&id])
                .map_err(db_err)?
                .ok_or_else(|| not_found("terms", id))?
                .get(0);
            // Who asks, before any lock, then again under the project's
            // lock (the lock order above).
            let p =
                project_visible(t, &ctx.principal, &project).map_err(|_| not_found("terms", id))?;
            admin_org(ctx, &p, "accepting job terms")?;
            lock_project(t, &project)?;
            let p =
                project_visible(t, &ctx.principal, &project).map_err(|_| not_found("terms", id))?;
            let org = admin_org(ctx, &p, "accepting job terms")?;
            let status: String = t
                .query_one(
                    "SELECT status FROM job_terms WHERE id = $1 FOR UPDATE",
                    &[&id],
                )
                .map_err(db_err)?
                .get(0);
            if status == "superseded" {
                return Err(conflict(format!("terms {id} are {status}")));
            }
            let n = t
                .execute(
                    "INSERT INTO job_terms_acceptances (terms_id, organization_id, accepted_by)
                     VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    &[&id, &org, &ctx.actor()],
                )
                .map_err(db_err)?;
            if status == "active" {
                // Accepted already: the acceptance that activated them (or
                // this organization's own) committed, perhaps without being
                // anchored; the anchor is caught up below.
                if n == 0 {
                    again.set(true);
                    return terms_json(t, id);
                }
                // A member that joined after they took effect consents to
                // them: nothing is activated or superseded.
                audit::append(
                    t,
                    ctx.draft("terms.accepted", "terms", id, Outcome::Succeeded)
                        .org(&org)
                        .project(&project),
                )?;
                return terms_json(t, id);
            }
            if n == 0 {
                // Accepted already. Every other member may have accepted
                // them meanwhile without their taking effect (the last one
                // to accept left the project before a recovery re-applied
                // its removal, say): then they take effect now.
                if activate_if_complete(t, caller(ctx), &project, &p.members, id, None)? {
                    return terms_json(t, id);
                }
                return Err(conflict(format!("{org} has accepted terms {id} already")));
            }
            audit::append(
                t,
                ctx.draft("terms.accepted", "terms", id, Outcome::Succeeded)
                    .org(&org)
                    .project(&project),
            )?;
            activate_if_complete(t, caller(ctx), &project, &p.members, id, None)?;
            terms_json(t, id)
        })?;
        if again.get() {
            // Whatever the first acceptance committed (the activation, the
            // superseded terms, the project's requirement) is anchored
            // before this answers.
            self.checkpoint_log()?;
        }
        Ok(out)
    }

    /// The newest of `project`'s proposed terms that every current member
    /// organization has accepted takes effect (superseding the others), as
    /// it would have on the last acceptance, and its activation records
    /// why (`settled`: an organization left, or the periodic pass found
    /// it). Returns its ID. The same locks as an acceptance, in the same
    /// order (its own transaction: after a removal's, or the pass's).
    pub(crate) fn settle_terms(
        &self,
        by: By<'_>,
        project: &str,
        settled: Settled<'_>,
    ) -> Result<Option<String>> {
        self.tx_anchored(|t| {
            lock_project(t, project)?;
            let Some(p) = project_row(t, project)? else {
                return Ok(None);
            };
            let ids: Vec<String> = t
                .query(
                    "SELECT id FROM job_terms WHERE project_id = $1 AND status = 'proposed'
                      ORDER BY created_at DESC, id DESC FOR UPDATE",
                    &[&project],
                )
                .map_err(db_err)?
                .iter()
                .map(|r| r.get(0))
                .collect();
            for id in ids {
                if activate_if_complete(t, by, project, &p.members, &id, Some(settled))? {
                    return Ok(Some(id));
                }
            }
            Ok(None)
        })
    }

    /// The periodic pass: proposed terms that every current member
    /// organization of their project has accepted take effect
    /// ([`Self::settle_terms`], recorded by the control plane's own
    /// service identity with `reason: settled`). Only a settle that failed
    /// after a removal leaves such terms (an acceptance that completes them
    /// activates them in its own transaction), so this retries it. A
    /// project that fails is logged; the others are still settled.
    pub fn settle_pending_terms(&self) -> Result<()> {
        let projects: Vec<String> = self
            .db
            .conn()?
            .query(
                "SELECT DISTINCT x.project_id FROM job_terms x
                  WHERE x.status = 'proposed'
                    AND EXISTS (
                        SELECT 1 FROM project_members m
                         WHERE m.project_id = x.project_id AND m.status = 'active'
                           AND m.participation = 'member')
                    AND NOT EXISTS (
                        SELECT 1 FROM project_members m
                         WHERE m.project_id = x.project_id AND m.status = 'active'
                           AND m.participation = 'member'
                           AND NOT EXISTS (SELECT 1 FROM job_terms_acceptances a
                                            WHERE a.terms_id = x.id AND a.organization_id = m.organization_id))
                  ORDER BY 1",
                &[],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        for project in projects {
            match self.settle_terms((&self.service_id, "scheduler"), &project, Settled::Pass) {
                Ok(Some(id)) => LogLine::new(&self.service_id, "terms_settled")
                    .field("project", &project)
                    .field("terms", &id)
                    .emit(),
                Ok(None) => {}
                Err(e) => LogLine::new(&self.service_id, "terms_settle_failed")
                    .field("project", &project)
                    .field("code", e.code)
                    .field("error", &e.message)
                    .emit(),
            }
        }
        Ok(())
    }

    /// `GET /v1/terms/{id}/jobs?after=&limit=`: the jobs submitted under
    /// terms `id`, by their number under them (`seq`, from 1), those after
    /// `after` and at most `limit` of them; for the organizations that
    /// accepted them while they are members of the project (each can hold
    /// the others to them): IDs, submitter, spec, program, purpose, state,
    /// evaluator, when it was submitted and whether its evaluator started
    /// it; never a grant or the evaluator's URL. An organization that left
    /// the project sees none of it.
    pub fn terms_jobs(&self, ctx: &Ctx, id: &str, after: i64, limit: i64) -> Result<Value> {
        let mut c = self.db.conn()?;
        let project: String = c
            .query_opt("SELECT project_id FROM job_terms WHERE id = $1", &[&id])
            .map_err(db_err)?
            .ok_or_else(|| not_found("terms", id))?
            .get(0);
        let members = project_row(&mut *c, &project)?
            .map(|p| p.members)
            .unwrap_or_default();
        let accepted: Vec<String> = c
            .query(
                "SELECT organization_id FROM job_terms_acceptances WHERE terms_id = $1",
                &[&id],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        if !accepted
            .iter()
            .any(|o| members.contains(o) && ctx.principal.member_of(o))
        {
            return Err(not_found("terms", id));
        }
        let rows = c
            .query(
                "SELECT j.id, j.organization_id, j.spec_id, j.program_id, j.purpose, j.state, j.evaluator_id,
                        floor(extract(epoch FROM j.created_at))::bigint,
                        EXISTS (SELECT 1 FROM job_transitions x WHERE x.job_id = j.id AND x.to_state = 'running'),
                        j.terms_seq
                   FROM jobs j WHERE j.terms_id = $1 AND j.terms_seq > $2
                  ORDER BY j.terms_seq LIMIT $3",
                &[&id, &after, &limit],
            )
            .map_err(db_err)?;
        Ok(Value::Array(
            rows.iter()
                .map(|r| {
                    json!({"id": r.get::<_, String>(0), "organization": r.get::<_, String>(1),
                           "spec_id": r.get::<_, String>(2), "program_id": r.get::<_, String>(3),
                           "purpose": r.get::<_, String>(4), "state": r.get::<_, String>(5),
                           "evaluator": r.get::<_, Option<String>>(6), "created_at": r.get::<_, i64>(7),
                           "started": r.get::<_, bool>(8), "seq": r.get::<_, i64>(9)})
                })
                .collect(),
        ))
    }

    /// `GET /v1/projects/{id}/terms`: every set of terms of a project
    /// (proposed, active and superseded), to its members and auditor
    /// organizations.
    pub fn list_terms(&self, ctx: &Ctx, project: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        project_visible(&mut *c, &ctx.principal, project)?;
        let ids: Vec<String> = c
            .query(
                "SELECT id FROM job_terms WHERE project_id = $1 ORDER BY created_at, id",
                &[&project],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(terms_json(&mut *c, &id)?);
        }
        Ok(Value::Array(out))
    }
}
