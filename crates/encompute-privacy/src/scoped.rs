//! Privacy populations and scopes: how one organization's series of
//! datasets is accounted when several projects, purposes and programs
//! release from it.
//!
//! - A **population** is one ledger per organization and series (all
//!   versions of it, so a new version never resets the budget), at one
//!   privacy unit. Its budget is the hard cap, in epsilon at a delta and
//!   enforced as the zCDP rho it converts to ([`rho_cap`]): rho composes by
//!   addition across every release charged to it, from any scope.
//! - A **scope** is a sub-ledger of one population for one project, purpose
//!   and (optionally) program, with the share the owners allocated. It has
//!   the population's unit and delta, and a cap no larger than the
//!   population's.
//!
//! A release charged to a scope is charged to its population too, with the
//! same reservation, and must fit in **both**: the scope bounds what one
//! project's purpose may use, the population bounds what the series can
//! ever give up. The population is authoritative: scopes may add up to
//! more than the population (the owners over-allocate on purpose), and
//! then the population refuses first. A project with no scope, and a scope
//! of another project, purpose or program, cannot charge anything: there is
//! nothing to inherit.
//!
//! Both are version 2 ledgers ([`Scoping`]); a version 1 (per-asset) ledger
//! is byte-for-byte what it was.

use encompute_ir::confidentiality::{check_id, PrivacyBudget};
use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::hex;

use crate::accountant::{rho_cap, Cost};
use crate::ledger::{
    Entry, Genesis, LedgerView, PrivacyEvent, ScopeRef, Scoping, LEDGER_VERSION_SCOPED,
};
use crate::tagged;

pub use crate::accountant::rho_cap as population_rho_cap;

const POLICY: &str = "encompute.privacy-population.v1";
/// The only record linkage an aggregate performs.
pub const LINKAGE_NONE: &str = "none";

fn alloc_err(m: impl Into<String>) -> Error {
    Error::new(Code::GovernancePrivacyAllocation, m)
}

fn scope_err(m: impl Into<String>) -> Error {
    Error::new(Code::GovernancePrivacyScope, m)
}

/// The privacy policy ID of a population and of each of its scopes: the
/// accountant and the population's unit and cap. (The program's own privacy
/// policy varies from scope to scope, so it is not part of it.)
fn policy_id(budget: &PrivacyBudget) -> Result<String> {
    Ok(hex(&tagged(
        POLICY,
        &[
            encompute_ir::confidentiality::PRIVACY_ACCOUNTANT.as_bytes(),
            &canonical_json(budget)?,
        ],
    )))
}

/// The genesis of a population: `id` names it, `organization` owns it,
/// `series` is the dataset series it accounts for.
pub fn population_genesis(
    id: &str,
    organization: &str,
    series: &str,
    budget: PrivacyBudget,
) -> Result<Genesis> {
    for (what, v) in [
        ("population", id),
        ("organization", organization),
        ("series", series),
    ] {
        check_id(what, v).map_err(|e| alloc_err(e.message))?;
    }
    budget.validate().map_err(|e| alloc_err(e.message))?;
    rho_cap(&budget)?;
    Ok(Genesis {
        version: LEDGER_VERSION_SCOPED,
        asset_id: id.to_owned(),
        privacy_policy_id: policy_id(&budget)?,
        budget,
        scoping: Some(Scoping::Population {
            organization: organization.to_owned(),
            series: series.to_owned(),
        }),
    })
}

/// The genesis of scope `id` of `population`, for one project, purpose and
/// program, with `budget` as its share: the population's unit and delta
/// (epsilons at different deltas cannot be compared) and an epsilon no
/// larger than the population's.
pub fn scope_genesis(
    id: &str,
    population: &Genesis,
    project: &str,
    purpose: &str,
    program: Option<&str>,
    budget: PrivacyBudget,
) -> Result<Genesis> {
    check_id("scope", id).map_err(|e| alloc_err(e.message))?;
    if !population.is_population() || population.version != LEDGER_VERSION_SCOPED {
        return Err(alloc_err("a scope belongs to a population"));
    }
    for (what, v) in [("project", project), ("purpose", purpose)] {
        if v.is_empty() || v.len() > 128 || v.chars().any(char::is_control) {
            return Err(alloc_err(format!("a scope names its {what}")));
        }
    }
    if program.is_some_and(|p| p.is_empty() || p.len() > 128 || p.chars().any(char::is_control)) {
        return Err(alloc_err("a scope's program is a non-empty identifier"));
    }
    budget.validate().map_err(|e| alloc_err(e.message))?;
    let pop = &population.budget;
    if budget.unit != pop.unit {
        return Err(alloc_err(format!(
            "the scope's privacy unit {} is not the population's, {}: they compose at one unit",
            budget.unit, pop.unit
        )));
    }
    if budget.delta != pop.delta {
        return Err(alloc_err(format!(
            "the scope's delta {:e} is not the population's, {:e}: epsilons at different deltas do not compare",
            budget.delta, pop.delta
        )));
    }
    if budget.epsilon > pop.epsilon {
        return Err(alloc_err(format!(
            "the scope's epsilon {} is above its population's cap {}: the population is authoritative",
            budget.epsilon, pop.epsilon
        )));
    }
    Ok(Genesis {
        version: LEDGER_VERSION_SCOPED,
        asset_id: id.to_owned(),
        privacy_policy_id: population.privacy_policy_id.clone(),
        budget,
        scoping: Some(Scoping::Scope {
            population_id: population.asset_id.clone(),
            population_digest: population.digest()?,
            project: project.to_owned(),
            purpose: purpose.to_owned(),
            program: program.map(str::to_owned),
        }),
    })
}

/// `scope` is a scope of `population`, bound to this very population, at
/// its unit and delta, with no more than its cap.
pub fn check_genesis_pair(population: &Genesis, scope: &Genesis) -> Result<()> {
    let Some(Scoping::Scope {
        population_id,
        population_digest,
        ..
    }) = &scope.scoping
    else {
        return Err(scope_err("not a scope"));
    };
    if !population.is_population()
        || &population.asset_id != population_id
        || *population_digest != population.digest()?
    {
        return Err(scope_err(format!(
            "scope {} is not a scope of population {}",
            scope.asset_id, population.asset_id
        )));
    }
    if population.version != LEDGER_VERSION_SCOPED
        || scope.version != LEDGER_VERSION_SCOPED
        || scope.budget.unit != population.budget.unit
        || scope.budget.delta != population.budget.delta
        || scope.budget.epsilon > population.budget.epsilon
        || scope.privacy_policy_id != population.privacy_policy_id
    {
        return Err(scope_err(format!(
            "scope {} does not compose with population {}: another unit, delta or policy, or a cap above the population's",
            scope.asset_id, population.asset_id
        )));
    }
    Ok(())
}

/// What a scope names, to be matched against a job's own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeBinding<'a> {
    pub project: &'a str,
    pub purpose: &'a str,
    pub program: Option<&'a str>,
}

impl Genesis {
    /// Whether this scope is for exactly this project and purpose, and for
    /// this program (a scope without a program serves every program of the
    /// purpose; one with a program, only that one).
    pub fn serves(&self, want: &ScopeBinding<'_>) -> bool {
        match &self.scoping {
            Some(Scoping::Scope {
                project,
                purpose,
                program,
                ..
            }) => {
                project == want.project
                    && purpose == want.purpose
                    && match program {
                        None => true,
                        Some(p) => want.program == Some(p.as_str()),
                    }
            }
            _ => false,
        }
    }
}

/// What a scoped release would leave in each ledger.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScopedCost {
    pub population: Cost,
    pub scope: Cost,
}

/// The pair of ledgers, consistent and ready to spend: the scope belongs to
/// the population and both verify.
fn check_pair(population: &LedgerView, scope: &LedgerView) -> Result<()> {
    population.verify()?;
    scope.verify()?;
    check_genesis_pair(&population.genesis, &scope.genesis)
}

fn check_fits(
    population: &LedgerView,
    scope: &LedgerView,
    rho: f64,
    sampling_rate: Option<f64>,
) -> Result<ScopedCost> {
    let population = population.check(rho, sampling_rate)?;
    let scope = scope.check(rho, sampling_rate)?;
    Ok(ScopedCost { population, scope })
}

/// Refuses a release of cost `rho` (sampled at `sampling_rate` or not)
/// unless it fits in **both** the population and the scope: the
/// population is checked first, because it is authoritative.
pub fn check_spend(
    population: &LedgerView,
    scope: &LedgerView,
    rho: f64,
    sampling_rate: Option<f64>,
) -> Result<ScopedCost> {
    check_pair(population, scope)?;
    check_fits(population, scope, rho, sampling_rate)
}

/// The population and scope ledgers after `event` is appended to both: a
/// reservation naming this scope and population, charged against both
/// caps; a commit of an open reservation in both. All or nothing: nothing
/// is appended unless both accept.
pub fn append_scoped(
    population: &LedgerView,
    scope: &LedgerView,
    event: PrivacyEvent,
) -> Result<(LedgerView, LedgerView, Entry, Entry)> {
    check_pair(population, scope)?;
    if let PrivacyEvent::Reserve {
        scope: r,
        mechanism,
        ..
    } = &event
    {
        let r = r.as_ref().ok_or_else(|| {
            scope_err("a reservation against a scope names its scope (and population)")
        })?;
        check_scope_ref(r, &population.genesis, &scope.genesis)?;
        check_fits(population, scope, event.rho()?, mechanism.sampling_rate)?;
    }
    let (pop, pe) = population.append_event(event.clone())?;
    let (sc, se) = scope.append_event(event)?;
    Ok((pop, sc, pe, se))
}

/// A reservation's scope reference names this scope and population and
/// declares what an aggregate must: at least one source per unit, and no
/// record linkage.
pub fn check_scope_ref(r: &ScopeRef, population: &Genesis, scope: &Genesis) -> Result<()> {
    if r.scope_id != scope.asset_id || r.population_id != population.asset_id {
        return Err(scope_err(format!(
            "the reservation names scope {} of population {}, not {} of {}",
            r.scope_id, r.population_id, scope.asset_id, population.asset_id
        )));
    }
    if r.linkage != LINKAGE_NONE {
        return Err(Error::new(
            Code::GovernanceAggregateDeclaration,
            format!(
                "an aggregate performs no record linkage: its linkage is `{LINKAGE_NONE}`, not {:?}",
                r.linkage
            ),
        ));
    }
    if r.max_sources_per_unit == 0 {
        return Err(Error::new(
            Code::GovernanceAggregateDeclaration,
            "a reservation declares at least one source per privacy unit",
        ));
    }
    Ok(())
}
