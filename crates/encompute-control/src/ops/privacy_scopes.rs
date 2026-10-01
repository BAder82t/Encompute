//! Privacy populations and scopes (governed projects, differential
//! privacy).
//!
//! - A **population** is one organization's series of datasets, all
//!   versions, at one privacy unit: the authoritative ledger whose cap no
//!   scope, project or new version resets or raises. It is created once by
//!   a person of the owning organization.
//! - A **scope** is a sub-ledger of one population for one project, purpose
//!   (by name) and, optionally, program. One person of the owning
//!   organization proposes it, a different one approves it (four eyes,
//!   ENC2707; auditors never, ENC2602), and its allocation is an event of
//!   the project's log, shared by its members and auditors.
//! - A release is charged to a scope **and** its population, and must fit
//!   in both ([`encompute_privacy::scoped`]). The population is
//!   authoritative: scopes may add up to more than it, and then it refuses
//!   first. A project with no scope cannot spend and inherits nothing
//!   (ENC2719).
//!
//! Both ledgers are `privacy_ledgers` rows under the keys
//! `population:<id>` and `scope:<id>`, so a ledger's checkpoints in the
//! governance log (platform partition, entry count and root only), the
//! rollback check on every spend and at start, the freeze after a detected
//! rollback and the recovery treat them exactly as an asset's ledger. A
//! restored older scope or population is refused at start, or on its next
//! spend, like a restored asset ledger.
//!
//! **Governed jobs** that release a differential-privacy aggregate reserve
//! their release in each source's scope (and population) when they start,
//! before any noise exists, and are checked again (read-only) when they are
//! scheduled: [`Control::check_job_privacy`] and
//! [`Control::reserve_job_privacy`]. The reservation is the job's, an entry
//! the control plane computes itself from the job's program (the
//! sensitivity, scaled by the sources a privacy unit may span, the noise,
//! the mechanism), so the coordinator's own report of the same release is
//! the same entry, and an under-declared one is refused (ENC2721).
//!
//! Lock order: the job, then scope rows (sorted), then population rows
//! (sorted), then the governance head and the audit head. A single spend
//! locks its scope, then its population.

use std::collections::{BTreeMap, BTreeSet};

use postgres::{GenericClient, Transaction};
use serde_json::{json, Value};

use encompute_ir::confidentiality::PrivacyBudget;
use encompute_ir::{Code, Error, Result};
use encompute_privacy::scoped::{
    append_scoped, check_scope_ref, population_genesis, scope_genesis,
};
use encompute_privacy::{Entry, Genesis, LedgerView, PrivacyEvent};
use encompute_secagg::{AggregationPlan, ScopedBudget};

use crate::audit::{self, Outcome};
use crate::authz::{
    asset_row, conflict, deny_auditor, deny_auditor_in, forbidden, not_found, project_row,
    project_visible, require, require_human, require_other_person, ProjectRow,
};
use crate::control::{load_ledger, runtime_rollback, Control, Ctx};
use crate::db::db_err;
use crate::govlog::{self, extra_kind, NegSet};
use crate::model::{bad, check_name, new_id, CreatePopulation, ProposeScope, Role, ServiceKind};

pub(crate) const POPULATION_KEY: &str = "population:";
pub(crate) const SCOPE_KEY: &str = "scope:";

fn new_scope_id() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("operating-system randomness");
    encompute_verification::hex(&b)
}

pub(crate) fn population_key(id: &str) -> String {
    format!("{POPULATION_KEY}{id}")
}

pub(crate) fn scope_key(id: &str) -> String {
    format!("{SCOPE_KEY}{id}")
}

fn allocation(m: impl Into<String>) -> Error {
    Error::new(Code::GovernancePrivacyAllocation, m)
}

fn scope_refused(m: impl Into<String>) -> Error {
    Error::new(Code::GovernancePrivacyScope, m)
}

fn unique_violation(e: &postgres::Error) -> bool {
    e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION)
}

/// The people who read a ledger of their own organization.
const LEDGER_READERS: &[Role] = &[
    Role::DataOwner,
    Role::Auditor,
    Role::OrganizationAdmin,
    Role::SecurityAdmin,
];

/// A scope row.
struct ScopeRow {
    id: String,
    population: String,
    organization: String,
    project: String,
    purpose: String,
    program: Option<String>,
    epsilon: f64,
    status: String,
    proposed_by: String,
    ledger_key: Option<String>,
}

fn scope_row(c: &mut impl GenericClient, id: &str, lock: bool) -> Result<Option<ScopeRow>> {
    let q = format!(
        "SELECT id, population_id, organization_id, project_id, purpose, program_id, epsilon, status,
                proposed_by, ledger_key
           FROM privacy_scopes WHERE id = $1 {}",
        if lock { "FOR UPDATE" } else { "" }
    );
    Ok(c.query_opt(&q, &[&id]).map_err(db_err)?.map(|r| ScopeRow {
        id: r.get(0),
        population: r.get(1),
        organization: r.get(2),
        project: r.get(3),
        purpose: r.get(4),
        program: r.get(5),
        epsilon: r.get(6),
        status: r.get(7),
        proposed_by: r.get(8),
        ledger_key: r.get(9),
    }))
}

/// Whether the ledger `key` is frozen: in its row, or in the governance
/// log (which holds whatever the row says).
fn frozen(c: &mut impl GenericClient, key: &str) -> Result<Option<String>> {
    let row: Option<String> = c
        .query_opt(
            "SELECT frozen_reason FROM privacy_ledgers WHERE asset_id = $1",
            &[&key],
        )
        .map_err(db_err)?
        .and_then(|r| r.get(0));
    if row.is_some() {
        return Ok(row);
    }
    Ok(govlog::contains(c, NegSet::FrozenLedgers, key)?
        .then(|| "frozen after a detected rollback (governance log)".to_owned()))
}

fn require_governed(t: &mut Transaction<'_>, ctx: &Ctx, project: &str) -> Result<ProjectRow> {
    let p = project_visible(t, &ctx.principal, project)?;
    if !p.governed() {
        return Err(conflict(format!(
            "project {project} is a standard project: privacy scopes belong to governed projects"
        )));
    }
    Ok(p)
}

/// A ledger's totals: what a project's members and auditors may see of a
/// scope (never an entry).
fn totals(view: &LedgerView) -> Result<Value> {
    let cost = view.cost()?;
    let cp = view.checkpoint()?;
    Ok(json!({
        "budget": view.genesis.budget,
        "spent": {"epsilon": cost.epsilon, "delta": cost.delta},
        "remaining_epsilon": (view.genesis.budget.epsilon - cost.epsilon).max(0.0),
        "entries": cp.seq,
        "root": cp.root,
    }))
}

impl Control {
    // --- populations ---------------------------------------------------------------

    /// A person of `organization` creates the privacy population of one of
    /// its dataset series: the cap on everything released from any version
    /// of it, in any project, at one privacy unit. Allocated once; it is
    /// never raised, and a new version or project never resets it.
    pub fn create_population(&self, ctx: &Ctx, r: CreatePopulation) -> Result<Value> {
        self.scope_limit
            .hit(&format!("population:{}", ctx.actor()))?;
        let id = new_id("pop");
        let key = population_key(&id);
        let genesis = population_genesis(&id, &r.organization, &r.series, r.budget.clone())?;
        self.tx_anchored(|t| {
            deny_auditor_in(t, &ctx.principal, &r.organization)?;
            require_human(
                &ctx.principal,
                &r.organization,
                &[Role::SecurityAdmin, Role::DataOwner],
                "creating a privacy population",
            )?;
            t.execute(
                "INSERT INTO privacy_ledgers (asset_id, organization_id, genesis) VALUES ($1, $2, $3)",
                &[
                    &key,
                    &r.organization,
                    &serde_json::to_value(&genesis).expect("serializable"),
                ],
            )
            .map_err(db_err)?;
            t.execute(
                "INSERT INTO privacy_populations (id, organization_id, series, ledger_key, created_by)
                 VALUES ($1, $2, $3, $4, $5)",
                &[&id, &r.organization, &r.series, &key, &ctx.actor()],
            )
            .map_err(|e| {
                if unique_violation(&e) {
                    allocation(format!(
                        "{} already has a privacy population for series {}: a cap is allocated once, and a new version never resets it",
                        r.organization, r.series
                    ))
                } else {
                    db_err(e)
                }
            })?;
            govlog::append(
                t,
                govlog::Draft::new(
                    govlog::for_org(Some(&r.organization)),
                    extra_kind::POPULATION_CREATED,
                    &id,
                )
                .org(&r.organization),
            )?;
            audit::append(
                t,
                ctx.draft("privacy.population.created", "population", &id, Outcome::Succeeded)
                    .org(&r.organization)
                    .r#ref("series", r.series.clone())
                    .r#ref("unit", r.budget.unit.to_string()),
            )?;
            Ok(())
        })?;
        // Its first checkpoint (entry count 0): from now on a database that
        // lost it is refused.
        self.anchor_ledger(&key)?;
        Ok(json!({
            "id": id,
            "organization": r.organization,
            "series": r.series,
            "budget": r.budget,
            "rho_cap": encompute_privacy::accountant::rho_cap(&r.budget)?,
        }))
    }

    /// A population, for its owner: its cap, what it has spent across every
    /// scope, its ledger's root and its scopes.
    pub fn get_population(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let row = c
            .query_opt(
                "SELECT organization_id, series, ledger_key FROM privacy_populations WHERE id = $1",
                &[&id],
            )
            .map_err(db_err)?
            .ok_or_else(|| not_found("privacy population", id))?;
        let (org, series, key): (String, String, String) = (row.get(0), row.get(1), row.get(2));
        if !ctx.principal.member_of(&org) {
            return Err(not_found("privacy population", id));
        }
        require(
            &ctx.principal,
            &org,
            LEDGER_READERS,
            "reading a privacy population",
        )?;
        let view = load_ledger(&mut *c, &key)?
            .ok_or_else(|| not_found("privacy population ledger", id))?;
        view.verify()?;
        let scopes: Vec<String> = c
            .query(
                "SELECT id FROM privacy_scopes WHERE population_id = $1 ORDER BY id",
                &[&id],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        let mut out = totals(&view)?;
        out["id"] = json!(id);
        out["organization"] = json!(org);
        out["series"] = json!(series);
        out["rho_cap"] = json!(encompute_privacy::accountant::rho_cap(
            &view.genesis.budget
        )?);
        out["frozen"] = json!(frozen(&mut *c, &key)?);
        out["scopes"] = json!(scopes);
        Ok(out)
    }

    // --- scopes --------------------------------------------------------------------

    /// A person of the population's organization proposes a scope of it for
    /// one project, purpose (by name) and, optionally, program, with a cap
    /// no larger than the population's: another person approves it.
    pub fn propose_scope(&self, ctx: &Ctx, r: ProposeScope) -> Result<Value> {
        self.scope_limit.hit(&format!("scope:{}", ctx.actor()))?;
        check_name("purpose", &r.purpose)?;
        if let Some(p) = &r.program_id {
            check_name("program_id", p)?;
        }
        if !(r.epsilon.is_finite() && r.epsilon > 0.0) {
            return Err(allocation("a scope's epsilon is a positive number"));
        }
        // A scope's ID is 32 random bytes (hex): an owner's authorization
        // may pin it (`privacy_scope_id`).
        let id = new_scope_id();
        self.tx_anchored(|t| {
            // The project first: an auditor is refused before anything else
            // is looked up.
            let project = require_governed(t, ctx, &r.project)?;
            deny_auditor(&ctx.principal, &project)?;
            let pop = t
                .query_opt(
                    "SELECT organization_id, ledger_key FROM privacy_populations WHERE id = $1",
                    &[&r.population],
                )
                .map_err(db_err)?
                .filter(|p| ctx.principal.member_of(&p.get::<_, String>(0)))
                .ok_or_else(|| not_found("privacy population", &r.population))?;
            let (org, pop_key): (String, String) = (pop.get(0), pop.get(1));
            deny_auditor_in(t, &ctx.principal, &org)?;
            require_human(
                &ctx.principal,
                &org,
                &[Role::SecurityAdmin],
                "proposing a privacy scope",
            )?;
            if !project.members.contains(&org) {
                return Err(allocation(format!(
                    "{org}, the population's owner, is not a member of project {}",
                    r.project
                )));
            }
            let active: Option<i64> = t
                .query_opt(
                    "SELECT 1::bigint FROM purposes WHERE project_id = $1 AND name = $2 AND status = 'active' LIMIT 1",
                    &[&r.project, &r.purpose],
                )
                .map_err(db_err)?
                .map(|x| x.get(0));
            if active.is_none() {
                return Err(allocation(format!(
                    "project {} has no active purpose {:?}",
                    r.project, r.purpose
                )));
            }
            // The cap, unit and delta, checked against the population now
            // (and again when approved).
            let pop_view = load_ledger(t, &pop_key)?
                .ok_or_else(|| not_found("privacy population ledger", &r.population))?;
            scope_genesis(
                &id,
                &pop_view.genesis,
                &r.project,
                &r.purpose,
                r.program_id.as_deref(),
                PrivacyBudget {
                    epsilon: r.epsilon,
                    ..pop_view.genesis.budget.clone()
                },
            )?;
            t.execute(
                "INSERT INTO privacy_scopes (id, population_id, organization_id, project_id, purpose, program_id,
                                             epsilon, status, proposed_by)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 'proposed', $8)",
                &[
                    &id,
                    &r.population,
                    &org,
                    &r.project,
                    &r.purpose,
                    &r.program_id,
                    &r.epsilon,
                    &ctx.actor(),
                ],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                ctx.draft("privacy.scope.proposed", "scope", &id, Outcome::Succeeded)
                    .org(&org)
                    .project(&r.project)
                    .r#ref("purpose", r.purpose.clone()),
            )?;
            Ok(json!({
                "id": id, "population": r.population, "project": r.project,
                "purpose": r.purpose, "program_id": r.program_id,
                "epsilon": r.epsilon, "status": "proposed",
            }))
        })
    }

    /// A different person of the population's organization approves the
    /// scope: its ledger is created, its allocation is recorded in the
    /// project's log and anchored before this returns.
    pub fn approve_scope(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        self.scope_limit.hit(&format!("scope:{}", ctx.actor()))?;
        let key = scope_key(id);
        let out = self.tx_anchored(|t| {
            let row = scope_row(t, id, true)?.ok_or_else(|| not_found("privacy scope", id))?;
            let project = project_visible(t, &ctx.principal, &row.project)
                .map_err(|_| not_found("privacy scope", id))?;
            deny_auditor(&ctx.principal, &project)?;
            deny_auditor_in(t, &ctx.principal, &row.organization)?;
            if !ctx.principal.member_of(&row.organization) {
                return Err(forbidden(format!(
                    "a privacy scope is approved by a security admin of the population's organization, {}",
                    row.organization
                )));
            }
            require_human(
                &ctx.principal,
                &row.organization,
                &[Role::SecurityAdmin],
                "approving a privacy scope",
            )?;
            require_other_person(
                ctx.actor(),
                &[row.proposed_by.as_str()],
                "approving a privacy scope",
            )?;
            if row.status != "proposed" {
                return Err(conflict(format!("privacy scope {id} is {}", row.status)));
            }
            let pop_key: String = t
                .query_one(
                    "SELECT ledger_key FROM privacy_populations WHERE id = $1",
                    &[&row.population],
                )
                .map_err(db_err)?
                .get(0);
            let pop = load_ledger(t, &pop_key)?
                .ok_or_else(|| not_found("privacy population ledger", &row.population))?;
            let genesis = scope_genesis(
                id,
                &pop.genesis,
                &row.project,
                &row.purpose,
                row.program.as_deref(),
                PrivacyBudget {
                    epsilon: row.epsilon,
                    ..pop.genesis.budget.clone()
                },
            )?;
            t.execute(
                "INSERT INTO privacy_ledgers (asset_id, organization_id, genesis) VALUES ($1, $2, $3)",
                &[
                    &key,
                    &row.organization,
                    &serde_json::to_value(&genesis).expect("serializable"),
                ],
            )
            .map_err(db_err)?;
            t.execute(
                "UPDATE privacy_scopes SET status = 'active', approved_by = $2, approved_at = now(), ledger_key = $3
                  WHERE id = $1",
                &[&id, &ctx.actor(), &key],
            )
            .map_err(|e| {
                if unique_violation(&e) {
                    allocation(format!(
                        "project {} already has an active scope of this population for purpose {:?}{}: a share is allocated once",
                        row.project,
                        row.purpose,
                        row.program
                            .as_ref()
                            .map(|p| format!(" and program {p}"))
                            .unwrap_or_default()
                    ))
                } else {
                    db_err(e)
                }
            })?;
            // The project's log: its members and auditors see that a share
            // was allocated (the cap, never a population's spending).
            let mut d = govlog::Draft::new(
                govlog::for_project(t, &row.project, Some(&row.organization))?,
                extra_kind::SCOPE_ALLOCATED,
                id,
            )
            .org(&row.organization)
            .r#ref("purpose", row.purpose.clone())
            .r#ref("unit", genesis.budget.unit.to_string())
            .r#ref("epsilon", format!("{:?}", genesis.budget.epsilon))
            .r#ref("delta", format!("{:?}", genesis.budget.delta));
            if let Some(p) = &row.program {
                d = d.r#ref("program", p.clone());
            }
            govlog::append(t, d)?;
            audit::append(
                t,
                ctx.draft("privacy.scope.approved", "scope", id, Outcome::Succeeded)
                    .org(&row.organization)
                    .project(&row.project),
            )?;
            Ok(json!({
                "id": id, "population": row.population, "project": row.project,
                "purpose": row.purpose, "program_id": row.program,
                "epsilon": row.epsilon, "status": "active",
            }))
        })?;
        // Its first checkpoint: a database that lost the scope is refused.
        self.anchor_ledger(&key)?;
        Ok(out)
    }

    /// What `ctx` sees of scope `id`: its owner (the population's
    /// organization) everything but the entries; the project's other
    /// members and its auditors its totals (cap, spent, remaining, entries,
    /// root); nobody else the scope exists.
    pub fn get_scope(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let row = scope_row(&mut *c, id, false)?.ok_or_else(|| not_found("privacy scope", id))?;
        let project =
            project_row(&mut *c, &row.project)?.ok_or_else(|| not_found("privacy scope", id))?;
        let owner = ctx.principal.member_of(&row.organization);
        let participant = owner
            || project
                .members
                .iter()
                .chain(&project.auditors)
                .any(|o| ctx.principal.member_of(o));
        if !participant {
            return Err(not_found("privacy scope", id));
        }
        // A proposal is the owner's business until it is approved.
        if row.status != "active" && !owner {
            return Err(not_found("privacy scope", id));
        }
        let full = owner && ctx.principal.any_role(&row.organization, LEDGER_READERS);
        let mut out = json!({
            "id": row.id, "project": row.project, "purpose": row.purpose,
            "program_id": row.program, "status": row.status,
        });
        if let Some(key) = &row.ledger_key {
            let view = load_ledger(&mut *c, key)?.ok_or_else(|| not_found("privacy scope", id))?;
            view.verify()?;
            let t = totals(&view)?;
            for (k, v) in t.as_object().expect("an object") {
                out[k] = v.clone();
            }
            out["frozen"] = json!(frozen(&mut *c, key)?);
        } else {
            out["budget"] = json!({"epsilon": row.epsilon});
        }
        if full {
            out["population"] = json!(row.population);
            out["organization"] = json!(row.organization);
        }
        Ok(out)
    }

    /// The scope's whole ledger (entries), for the owner's auditors and
    /// data owners and the project's auditor organizations.
    pub fn scope_ledger_export(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let row = scope_row(&mut *c, id, false)?.ok_or_else(|| not_found("privacy scope", id))?;
        let project =
            project_row(&mut *c, &row.project)?.ok_or_else(|| not_found("privacy scope", id))?;
        let owner = ctx.principal.member_of(&row.organization);
        let auditor_org = project.auditors.iter().any(|o| ctx.principal.member_of(o));
        if !owner && !auditor_org {
            return Err(not_found("privacy scope", id));
        }
        if owner {
            require(
                &ctx.principal,
                &row.organization,
                &[Role::Auditor, Role::DataOwner],
                "exporting a privacy scope",
            )?;
        }
        let key = row
            .ledger_key
            .ok_or_else(|| not_found("privacy scope", id))?;
        let view = load_ledger(&mut *c, &key)?.ok_or_else(|| not_found("privacy scope", id))?;
        Ok(serde_json::to_value(&view).expect("serializable"))
    }

    /// The scopes of a governed project its caller may see.
    pub fn list_project_scopes(&self, ctx: &Ctx, project: &str) -> Result<Value> {
        let ids: Vec<String> = {
            let mut c = self.db.conn()?;
            let p = project_visible(&mut *c, &ctx.principal, project)?;
            if !p.governed() {
                return Err(conflict(format!(
                    "project {project} is a standard project: privacy scopes belong to governed projects"
                )));
            }
            c.query(
                "SELECT id FROM privacy_scopes WHERE project_id = $1 ORDER BY id",
                &[&project],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect()
        };
        let mut out = vec![];
        for id in ids {
            // Proposals are the owner's: others do not see them.
            if let Ok(v) = self.get_scope(ctx, &id) {
                out.push(v);
            }
        }
        Ok(Value::Array(out))
    }

    /// The owner authorizes a SecAgg service to report privacy events of a
    /// scope (its coordinator's reservations and commits).
    pub fn authorize_scope_spender(&self, ctx: &Ctx, scope: &str, service: &str) -> Result<Value> {
        self.scope_limit.hit(&format!("scope:{}", ctx.actor()))?;
        self.tx_anchored(|t| {
            let row = scope_row(t, scope, false)?.ok_or_else(|| not_found("privacy scope", scope))?;
            let project = project_row(t, &row.project)?
                .ok_or_else(|| not_found("privacy scope", scope))?;
            deny_auditor(&ctx.principal, &project)?;
            if !ctx.principal.member_of(&row.organization) {
                return Err(not_found("privacy scope", scope));
            }
            deny_auditor_in(t, &ctx.principal, &row.organization)?;
            require(
                &ctx.principal,
                &row.organization,
                &[Role::DataOwner, Role::OrganizationAdmin, Role::SecurityAdmin],
                "authorizing a privacy spender",
            )?;
            let Some(key) = &row.ledger_key else {
                return Err(conflict(format!("privacy scope {scope} is not approved yet")));
            };
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
                    &[key, &service, &ctx.actor()],
                )
                .map_err(db_err)?;
            if n > 0 {
                audit::append(
                    t,
                    ctx.draft("privacy.spender.authorized", "scope", scope, Outcome::Succeeded)
                        .org(&row.organization)
                        .project(&row.project)
                        .r#ref("service", service.to_owned()),
                )?;
            }
            Ok(json!({"scope": scope, "service": service}))
        })
    }

    // --- spending ------------------------------------------------------------------

    /// Records a privacy event of scope `scope`: a governed job's
    /// reservation before its noisy release (it must be exactly the job's
    /// own release, computed from its program: [`Control::job_releases`]), or
    /// its commit. Appended to the scope's ledger and its population's in
    /// one transaction, scope locked before population, race-safe across
    /// scopes, idempotent (the same event again returns the stored entry)
    /// and anchored (both ledgers) before it returns.
    pub fn privacy_spend_scoped(
        &self,
        ctx: &Ctx,
        scope: &str,
        event: PrivacyEvent,
    ) -> Result<Value> {
        self.spend_limit.hit(&format!("{}:{scope}", ctx.actor()))?;
        // What the anchor holds, read before the transaction takes any
        // lock (the anchor's lock is outermost).
        let anchored = self.anchor.snapshot();
        let res = self.tx_anchored(|t| {
            let row = scope_row(t, scope, false)?.ok_or_else(|| not_found("privacy scope", scope))?;
            // An auditor of an organization taking part changes nothing.
            if let Some(project) = project_row(t, &row.project)? {
                deny_auditor(&ctx.principal, &project)?;
            }
            let Some(skey) = row.ledger_key.clone() else {
                return Err(scope_refused(format!("privacy scope {scope} is not approved yet")));
            };
            let pkey: String = t
                .query_one(
                    "SELECT ledger_key FROM privacy_populations WHERE id = $1",
                    &[&row.population],
                )
                .map_err(db_err)?
                .get(0);
            // Who may spend: a SecAgg service the owner authorized for
            // this scope; people and automation of the owning organization.
            let authorized_service =
                matches!(ctx.principal.service_kind(), Some(ServiceKind::Secagg))
                    && t.query_opt(
                        "SELECT 1 FROM privacy_spenders WHERE asset_id = $1 AND service_id = $2",
                        &[&skey, &ctx.actor()],
                    )
                    .map_err(db_err)?
                    .is_some();
            if !authorized_service {
                if !ctx.principal.member_of(&row.organization) {
                    return Err(not_found("privacy scope", scope));
                }
                deny_auditor_in(t, &ctx.principal, &row.organization)?;
                if !ctx
                    .principal
                    .any_role(&row.organization, &[Role::DataOwner, Role::Operator])
                {
                    return Err(forbidden(
                        "scoped privacy spending is done by the owner's data owners, or SecAgg services the owner authorized for the scope",
                    ));
                }
            }
            // The job a reservation is for (shared-locked: it is not
            // ended or changed under the spend).
            let job = match &event {
                PrivacyEvent::Reserve { scope: r, .. } => {
                    let r = r.as_ref().ok_or_else(|| {
                        scope_refused("a reservation against a scope names its scope, population and job")
                    })?;
                    if r.scope_id != scope {
                        return Err(scope_refused(format!(
                            "the reservation names scope {}, not {scope}",
                            r.scope_id
                        )));
                    }
                    Some(r.job_id.clone().ok_or_else(|| {
                        scope_refused("a scoped release belongs to a governed job: the reservation names none")
                    })?)
                }
                PrivacyEvent::Commit { .. } => None,
            };
            let job_info = match &job {
                Some(j) => Some(job_for_scope(t, j, &row)?),
                None => None,
            };
            // Lock order: scope, then population.
            for key in [&skey, &pkey] {
                t.query_one(
                    "SELECT 1 FROM privacy_ledgers WHERE asset_id = $1 FOR UPDATE",
                    &[key],
                )
                .map_err(db_err)?;
            }
            let (Some(sview), Some(pview)) = (load_ledger(t, &skey)?, load_ledger(t, &pkey)?) else {
                return Err(runtime_rollback(
                    "PRIVACY",
                    format!("the privacy ledger of scope {scope} or its population is missing"),
                ));
            };
            self.probe_log(t, &anchored)?;
            self.check_floor(t, &skey, &sview)?;
            self.check_floor(t, &pkey, &pview)?;
            // Duplicate delivery: the same event is already recorded.
            if let Some(e) = sview.entries.iter().find(|e| {
                e.event.event_id() == event.event_id()
                    && std::mem::discriminant(&e.event) == std::mem::discriminant(&event)
            }) {
                if e.event == event {
                    return Ok((json!({"seq": e.seq, "hash": e.hash, "duplicate": true}), [skey, pkey]));
                }
                return Err(conflict(format!(
                    "event {} was recorded with other contents",
                    event.event_id()
                )));
            }
            for key in [&skey, &pkey] {
                if frozen(t, key)?.is_some() {
                    return Err(Error::new(
                        Code::PrivacyBudgetExceeded,
                        "this privacy scope or its population is frozen after a detected rollback: treated as exhausted",
                    ));
                }
            }
            if let (PrivacyEvent::Reserve { .. }, Some((state, program_job))) = (&event, &job_info) {
                if state != "running" {
                    return Err(scope_refused(format!(
                        "the job is {state}: a release is reserved by a running job"
                    )));
                }
                // Exactly the job's own release: its sensitivity (scaled by
                // the sources a unit may span), noise and mechanism.
                let expected = self
                    .job_releases(t, program_job)?
                    .into_iter()
                    .find(|x| x.scope_id == scope && x.event.event_id() == event.event_id())
                    .ok_or_else(|| {
                        scope_refused(
                            "the reservation is not a release of this job's program under this scope",
                        )
                    })?;
                check_declared(&event, &expected.event)?;
            }
            if let PrivacyEvent::Reserve { scope: Some(r), .. } = &event {
                check_scope_ref(r, &pview.genesis, &sview.genesis)?;
            }
            let (pnext, snext, pe, se) = append_scoped(&pview, &sview, event.clone())?;
            for (key, entry) in [(&skey, &se), (&pkey, &pe)] {
                t.execute(
                    "INSERT INTO privacy_entries (asset_id, seq, entry) VALUES ($1, $2, $3)",
                    &[key, &(entry.seq as i64), &serde_json::to_value(entry).expect("serializable")],
                )
                .map_err(db_err)?;
            }
            let _ = (pnext, snext);
            let action = match &event {
                PrivacyEvent::Reserve { .. } => "privacy.spent",
                PrivacyEvent::Commit { .. } => "privacy.committed",
            };
            audit::append(
                t,
                ctx.draft(action, "scope", scope, Outcome::Succeeded)
                    .org(&row.organization)
                    .project(&row.project)
                    .r#ref("event", event.event_id().to_owned())
                    .r#ref("seq", se.seq.to_string()),
            )?;
            Ok((
                json!({"seq": se.seq, "hash": se.hash, "duplicate": false}),
                [skey, pkey],
            ))
        });
        match res {
            Ok((v, keys)) => {
                // Anchored before acknowledging (a retry re-anchors).
                for k in &keys {
                    self.anchor_ledger(k)?;
                }
                Ok(v)
            }
            Err(e) => {
                if matches!(e.code, Code::PrivacyBudgetExceeded) {
                    self.metrics.inc("encompute_privacy_denied_total", "budget");
                    let row = self
                        .db
                        .conn()
                        .ok()
                        .and_then(|mut c| scope_row(&mut *c, scope, false).ok().flatten());
                    let mut d = ctx.draft("privacy.denied", "scope", scope, Outcome::Denied);
                    if let Some(r) = row {
                        d = d.org(&r.organization).project(&r.project);
                    }
                    self.audit_denied(d.r#ref("event", event.event_id().to_owned()));
                }
                Err(e)
            }
        }
    }

    /// The log still holds the anchored head: a database rewound together
    /// with its log (ledger entries and checkpoint events alike) passes a
    /// ledger's floor, and is refused here, before anything is written. One
    /// probe of the log's key.
    pub(crate) fn probe_log(
        &self,
        t: &mut Transaction<'_>,
        anchored: &crate::anchor::StateAnchor,
    ) -> Result<()> {
        if govlog::hash_at(t, anchored.glog_size)?.as_deref() != Some(anchored.glog_head.as_str()) {
            self.rollback_alarm("governance", "log");
            return Err(runtime_rollback(
                "GOVERNANCE LOG",
                format!(
                    "the log does not hold anchored governance event {}",
                    anchored.glog_size
                ),
            ));
        }
        Ok(())
    }

    /// The ledger still extends its latest checkpoint in the governance
    /// log: one rolled back, reset or rewritten while the service runs is
    /// refused now, not only at the next start.
    pub(crate) fn check_floor(
        &self,
        t: &mut Transaction<'_>,
        key: &str,
        view: &LedgerView,
    ) -> Result<()> {
        if let Some(cp) = govlog::latest_ledger_checkpoint(t, key)? {
            view.extends(&cp).map_err(|e| {
                self.rollback_alarm("privacy", key);
                runtime_rollback(
                    "PRIVACY",
                    format!("the privacy ledger of {key}: {}", e.message),
                )
            })?;
        }
        Ok(())
    }
}

/// A reservation is the job's own, as the control plane computed it: the
/// sources per unit may not be lower (ENC2721), and every other field,
/// sensitivity and noise included, is the program's.
fn check_declared(got: &PrivacyEvent, want: &PrivacyEvent) -> Result<()> {
    if let (
        PrivacyEvent::Reserve { scope: Some(g), .. },
        PrivacyEvent::Reserve { scope: Some(w), .. },
    ) = (got, want)
    {
        if g.max_sources_per_unit < w.max_sources_per_unit {
            return Err(Error::new(
                Code::GovernanceAggregateDeclaration,
                format!(
                    "the reservation declares {} source{} per privacy unit, but the job's program declares {} (undeclared, a scoped release assumes every participant): a smaller number would charge too little",
                    g.max_sources_per_unit,
                    if g.max_sources_per_unit == 1 { "" } else { "s" },
                    w.max_sources_per_unit
                ),
            ));
        }
    }
    if got != want {
        return Err(Error::new(
            Code::GovernanceAggregateDeclaration,
            "the reservation is not the release of the job's program: its sensitivity, noise, mechanism, layout or linkage differ from what the job's program and scope imply",
        ));
    }
    Ok(())
}

/// A job a scoped reservation names: its state, and what it is (a
/// governed job of the scope's project and purpose, running one of the
/// scope's programs).
fn job_for_scope(
    t: &mut Transaction<'_>,
    job: &str,
    scope: &ScopeRow,
) -> Result<(String, JobFacts)> {
    let r = t
        .query_opt(
            "SELECT state, project_id, purpose, program_id, plan_id, governance IS NOT NULL
               FROM jobs WHERE id = $1 FOR SHARE",
            &[&job],
        )
        .map_err(db_err)?
        .ok_or_else(|| {
            scope_refused(format!(
                "no job {job}: a scoped release belongs to a governed job"
            ))
        })?;
    let (state, project, purpose, program, plan, governed): (
        String,
        String,
        String,
        String,
        String,
        bool,
    ) = (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5));
    if !governed || project != scope.project || purpose != scope.purpose {
        return Err(scope_refused(format!(
            "job {job} is not a governed job of project {} for purpose {:?}: another project's or purpose's job cannot spend this scope",
            scope.project, scope.purpose
        )));
    }
    if scope.program.as_ref().is_some_and(|p| *p != program) {
        return Err(scope_refused(format!(
            "this scope is for program {}, not the job's",
            scope.program.as_deref().unwrap_or_default()
        )));
    }
    Ok((
        state,
        JobFacts {
            job: job.to_owned(),
            project,
            purpose,
            program,
            plan,
        },
    ))
}

/// What the control plane needs of a governed job to compute its release.
#[derive(Clone, Debug)]
pub(crate) struct JobFacts {
    pub job: String,
    pub project: String,
    pub purpose: String,
    pub program: String,
    pub plan: String,
}

/// One release a governed job makes, charged to one source's scope: the
/// reservation the control plane computes from the job's program.
#[derive(Clone, Debug)]
pub(crate) struct JobRelease {
    pub asset: String,
    pub scope_id: String,
    pub scope_key: String,
    pub population_key: String,
    pub event: PrivacyEvent,
}

/// A job's reservations, prepared in memory: nothing is written until all
/// of them are known to fit.
pub(crate) struct Prepared {
    /// (ledger key, entry) in order.
    writes: Vec<(String, Entry)>,
    /// (scope, asset, event, scope seq) per reservation made now.
    reservations: Vec<(String, String, String, u64)>,
    keys: BTreeSet<String>,
}

impl Control {
    /// The releases a governed job's program makes, one per source and
    /// differential-privacy output, each as the reservation it must write
    /// in its source's scope; `None` when the program releases no
    /// differential-privacy aggregate. Refused (ENC2719) when a source's
    /// series has no population, or the population has no active scope for
    /// the job's project, purpose and program: a governed job with no scope
    /// cannot spend.
    pub(crate) fn job_releases(
        &self,
        t: &mut Transaction<'_>,
        facts: &JobFacts,
    ) -> Result<Vec<JobRelease>> {
        let program_text: String = t
            .query_one("SELECT program FROM plans WHERE id = $1", &[&facts.plan])
            .map_err(db_err)?
            .get(0);
        let program = encompute_ir::parse(&program_text)?;
        let Some(report) = encompute_analysis::confidentiality::analyze(&program)? else {
            return Ok(vec![]);
        };
        let conf = program.confidentiality().expect("analyzed");
        let policy_id = encompute_verification::PolicyId::of(conf).hex();
        let privacy_policy_id = encompute_verification::PrivacyPolicyId::of(conf).map(|p| p.hex());
        let mut out = vec![];
        for b in report.aggregations.iter().filter(|b| b.dp.is_some()) {
            let plan = AggregationPlan::from_boundary(
                &facts.program,
                Some(&policy_id),
                privacy_policy_id.as_deref(),
                b,
            );
            let mut scopes = BTreeMap::new();
            let mut served = BTreeMap::new();
            for p in &plan.participants {
                let (population, scope, ids) = self.resolve_scope(t, &p.asset, facts)?;
                scopes.insert(
                    p.asset.clone(),
                    ScopedBudget {
                        population: population.0,
                        scope: scope.0,
                    },
                );
                served.insert(p.asset.clone(), ids);
            }
            let plan = plan.with_scopes(scopes)?.with_job(&facts.job);
            let all: Vec<_> = plan.participants.iter().map(|p| p.party.clone()).collect();
            let release = plan
                .release_spec("", None, &all)?
                .expect("a differential-privacy plan");
            for p in &plan.participants {
                let sb = p.scoped.as_ref().expect("scoped above");
                let charged = release
                    .charged
                    .iter()
                    .find(|c| c.asset_id == sb.scope.asset_id)
                    .expect("the scope is charged");
                let (scope_key, population_key) = served.remove(&p.asset).expect("resolved");
                let event = release.reserve_event(charged, encompute_privacy::CSPRNG)?;
                // Consistent before it is charged: a valid mechanism, a
                // positive noise, and a cost of at least the floor (no
                // honest release is that noisy).
                super::check_reservation(&sb.scope, &event, self.env.is_production())?;
                out.push(JobRelease {
                    asset: p.asset.clone(),
                    scope_id: sb.scope.asset_id.clone(),
                    scope_key,
                    population_key,
                    event,
                });
            }
        }
        Ok(out)
    }

    /// The population and active scope serving source `asset` for the
    /// job's project, purpose and program: their genesis documents and
    /// ledger keys.
    #[allow(clippy::type_complexity)]
    fn resolve_scope(
        &self,
        t: &mut Transaction<'_>,
        asset: &str,
        facts: &JobFacts,
    ) -> Result<((Genesis, String), (Genesis, String), (String, String))> {
        let a = asset_row(t, asset)?.ok_or_else(|| {
            scope_refused(format!(
                "source {asset} is not on record: no scope can pay for it"
            ))
        })?;
        let series: Option<String> = t
            .query_one("SELECT series FROM assets WHERE id = $1", &[&asset])
            .map_err(db_err)?
            .get(0);
        let series = series.ok_or_else(|| {
            scope_refused(format!(
                "source {asset} is not a dataset version: a governed release is charged to the population of a series"
            ))
        })?;
        let pop = t
            .query_opt(
                "SELECT id, ledger_key FROM privacy_populations WHERE organization_id = $1 AND series = $2",
                &[&a.organization, &series],
            )
            .map_err(db_err)?
            .ok_or_else(|| {
                scope_refused(format!(
                    "{}'s series {series} has no privacy population: a differential-privacy release is charged to a scope of one, and without a scope it cannot spend",
                    a.organization
                ))
            })?;
        let (pop_id, pop_key): (String, String) = (pop.get(0), pop.get(1));
        // The scope the owner's authorization of this source pins, if it
        // names one: that scope or none. Otherwise a scope of the job's
        // program first, then one for any program.
        let pinned: Option<String> = t
            .query_opt(
                "SELECT a.signed #>> '{body,privacy_scope_id}'
                   FROM job_authorizations ja JOIN authorizations a ON a.id = ja.authorization_row
                  WHERE ja.job_id = $1 AND a.asset_id = $2",
                &[&facts.job, &asset],
            )
            .map_err(db_err)?
            .and_then(|r| r.get(0));
        let sc = match &pinned {
            Some(pin) => t
                .query_opt(
                    "SELECT id, ledger_key FROM privacy_scopes
                      WHERE id = $1 AND population_id = $2 AND project_id = $3 AND purpose = $4
                        AND status = 'active' AND (program_id IS NULL OR program_id = $5)",
                    &[pin, &pop_id, &facts.project, &facts.purpose, &facts.program],
                )
                .map_err(db_err)?
                .ok_or_else(|| {
                    scope_refused(format!(
                        "{}'s authorization of this source names scope {pin}, which is not an active scope of its series for this project, purpose and program",
                        a.organization
                    ))
                })?,
            None => t
                .query_opt(
                    "SELECT id, ledger_key FROM privacy_scopes
                      WHERE population_id = $1 AND project_id = $2 AND purpose = $3 AND status = 'active'
                        AND (program_id IS NULL OR program_id = $4)
                      ORDER BY (program_id IS NULL), id LIMIT 1",
                    &[&pop_id, &facts.project, &facts.purpose, &facts.program],
                )
                .map_err(db_err)?
                .ok_or_else(|| {
                    scope_refused(format!(
                        "no active privacy scope of {}'s series {series} for project {}, purpose {:?} and this program: an unrelated project or purpose has none, so it cannot spend and inherits nothing",
                        a.organization, facts.project, facts.purpose
                    ))
                })?,
        };
        let (_scope_id, scope_key): (String, String) = (sc.get(0), sc.get(1));
        let genesis = |t: &mut Transaction<'_>, key: &str| -> Result<Genesis> {
            serde_json::from_value(
                t.query_one(
                    "SELECT genesis FROM privacy_ledgers WHERE asset_id = $1",
                    &[&key],
                )
                .map_err(db_err)?
                .get(0),
            )
            .map_err(db_err)
        };
        Ok((
            (genesis(t, &pop_key)?, pop_key.clone()),
            (genesis(t, &scope_key)?, scope_key.clone()),
            (scope_key, pop_key),
        ))
    }

    /// Whether a governed job's differential-privacy releases can be paid
    /// for now, without changing anything: every source has a scope (and
    /// population) and both afford the release (ENC2719, ENC2201). A job
    /// that releases none, and a job that reserved already, pass. `lock`
    /// takes the ledger rows' locks (start) instead of leaving them
    /// unlocked (schedule): scopes first, then populations, each sorted.
    pub(crate) fn check_job_privacy(
        &self,
        t: &mut Transaction<'_>,
        facts: &JobFacts,
        anchored: Option<&crate::anchor::StateAnchor>,
        lock: bool,
    ) -> Result<Prepared> {
        let releases = self.job_releases(t, facts)?;
        if let (Some(a), false) = (anchored, releases.is_empty()) {
            self.probe_log(t, a)?;
        }
        let mut p = Prepared {
            writes: vec![],
            reservations: vec![],
            keys: BTreeSet::new(),
        };
        if releases.is_empty() {
            return Ok(p);
        }
        if lock {
            let mut scopes: Vec<&String> = releases.iter().map(|r| &r.scope_key).collect();
            scopes.sort();
            scopes.dedup();
            let mut pops: Vec<&String> = releases.iter().map(|r| &r.population_key).collect();
            pops.sort();
            pops.dedup();
            for k in scopes.into_iter().chain(pops) {
                t.query_one(
                    "SELECT 1 FROM privacy_ledgers WHERE asset_id = $1 FOR UPDATE",
                    &[k],
                )
                .map_err(db_err)?;
            }
        }
        // Each ledger once, evolving as the job's releases land in it.
        let mut views: BTreeMap<String, LedgerView> = BTreeMap::new();
        for r in &releases {
            for key in [&r.scope_key, &r.population_key] {
                if !views.contains_key(key) {
                    let v = load_ledger(t, key)?.ok_or_else(|| {
                        runtime_rollback(
                            "PRIVACY",
                            format!("the privacy ledger of {key} is missing"),
                        )
                    })?;
                    self.check_floor(t, key, &v)?;
                    if frozen(t, key)?.is_some() {
                        return Err(Error::new(
                            Code::PrivacyBudgetExceeded,
                            format!(
                                "RELEASE DENIED: {key} is frozen after a detected rollback: treated as exhausted"
                            ),
                        ));
                    }
                    views.insert(key.clone(), v);
                }
            }
        }
        for r in releases {
            let (sv, pv) = (
                views.get(&r.scope_key).expect("loaded").clone(),
                views.get(&r.population_key).expect("loaded").clone(),
            );
            // Reserved already (by this job's start, or by the coordinator's
            // report of the same release): nothing more to charge.
            if sv.entries.iter().any(|e| {
                matches!(&e.event, PrivacyEvent::Reserve { .. })
                    && e.event.event_id() == r.event.event_id()
            }) {
                continue;
            }
            let (pn, sn, pe, se) = append_scoped(&pv, &sv, r.event.clone())?;
            p.writes.push((r.scope_key.clone(), se.clone()));
            p.writes.push((r.population_key.clone(), pe));
            p.reservations.push((
                r.scope_id.clone(),
                r.asset.clone(),
                r.event.event_id().to_owned(),
                se.seq,
            ));
            p.keys.insert(r.scope_key.clone());
            p.keys.insert(r.population_key.clone());
            views.insert(r.scope_key, sn);
            views.insert(r.population_key, pn);
        }
        Ok(p)
    }

    /// Reserves a governed job's differential-privacy releases in their
    /// scopes and populations, when it starts and before any noise exists.
    /// `Ok(Err(e))` is a refusal that wrote nothing (the caller fails the
    /// job); `Ok(Ok(keys))` the ledgers to anchor after the transaction
    /// commits; `Err` an infrastructure failure (roll back). Idempotent:
    /// a job reserves once.
    pub(crate) fn reserve_job_privacy(
        &self,
        t: &mut Transaction<'_>,
        actor: &str,
        request_id: &str,
        facts: &JobFacts,
        organization: &str,
        anchored: &crate::anchor::StateAnchor,
    ) -> Result<std::result::Result<BTreeSet<String>, Error>> {
        let prepared = match self.check_job_privacy(t, facts, Some(anchored), true) {
            Ok(p) => p,
            Err(e) if e.code == Code::Remote => return Err(e),
            Err(e) => return Ok(Err(e)),
        };
        for (key, entry) in &prepared.writes {
            t.execute(
                "INSERT INTO privacy_entries (asset_id, seq, entry) VALUES ($1, $2, $3)",
                &[
                    key,
                    &(entry.seq as i64),
                    &serde_json::to_value(entry).expect("serializable"),
                ],
            )
            .map_err(db_err)?;
        }
        for (scope, asset, event, seq) in &prepared.reservations {
            t.execute(
                "INSERT INTO job_privacy_reservations (job_id, scope_id, asset_id, event_id, scope_seq)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                &[&facts.job, scope, asset, event, &(*seq as i64)],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                audit::AuditDraft::new(
                    actor,
                    request_id,
                    "privacy.spent",
                    "scope",
                    scope,
                    Outcome::Succeeded,
                )
                .org(organization)
                .project(&facts.project)
                .r#ref("job", facts.job.clone())
                .r#ref("event", event.clone())
                .r#ref("seq", seq.to_string()),
            )?;
        }
        Ok(Ok(prepared.keys))
    }

    /// Anchors the ledgers a job's start reserved in (after its
    /// transaction committed): the call that started the job returns only
    /// when they are.
    pub(crate) fn anchor_ledgers(&self, keys: &BTreeSet<String>) -> Result<()> {
        for k in keys {
            self.anchor_ledger(k)?;
        }
        Ok(())
    }
}
