//! Residency and operators in the control plane: where each evaluator is
//! and who operates it, how that is evidenced, and the offers the planner
//! and the scheduler judge.
//!
//! - An evaluator's **operator** is the organization of the service account
//!   that registered it; `platform` when it has none. Operator-owned
//!   evaluators are scheduled only for governed jobs that admit them.
//! - Its **location** carries an evidence level. The evaluator's own claim
//!   is `self_declared`. A person who is a security admin of the operator
//!   organization makes it `operator_declared` (never a service account,
//!   never another organization's people). Evidence past its validity is
//!   not evidence. An evaluator that re-registers with another location
//!   loses its evidence.
//! - Every change of an evaluator's location is audited and recorded in the
//!   governance log of its operator and of every governed project that
//!   plans on or runs on it.

use postgres::{GenericClient, Transaction};
use serde::Deserialize;
use serde_json::{json, Value};

use encompute_ir::{Code, Error, Result};
use encompute_planner::{EvaluatorOffer, Location, LocationEvidence};
use encompute_trust::govlog::Partition;
use encompute_verification::service::now;

use crate::audit::{self, Outcome};
use crate::authn::PrincipalKind;
use crate::authz::{not_found, require_human};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::govlog;
use crate::model::{bad, new_id, Role, PLATFORM_ORG};

/// How long a declaration holds when it names no period.
pub const DECLARATION_DEFAULT_DAYS: u32 = 90;
/// The longest a declaration holds.
pub const DECLARATION_MAX_DAYS: u32 = 366;

/// Governance-log kinds of this module.
pub mod kind {
    /// A person of the operator declared an evaluator's location.
    pub const EVALUATOR_LOCATION_DECLARED: &str = "evaluator.location_declared";
    /// An evaluator's location changed, or its evidence was lost.
    pub const EVALUATOR_LOCATION_CHANGED: &str = "evaluator.location_changed";
}

/// `provider/region[/zone]`: an audit reference (identifiers only).
pub fn location_ref(l: &Location) -> String {
    match &l.zone {
        Some(z) => format!("{}/{}/{z}", l.provider, l.region),
        None => format!("{}/{}", l.provider, l.region),
    }
}

fn evidence_err(m: impl Into<String>) -> Error {
    Error::new(Code::GovernanceLocationEvidence, m)
}

/// A location as a service reports it: the table fills in the
/// jurisdiction, so a service cannot claim one.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocationInput {
    pub provider: String,
    pub region: String,
    #[serde(default)]
    pub zone: Option<String>,
}

impl LocationInput {
    pub fn resolve(&self) -> Result<Location> {
        Location::resolve(&self.provider, &self.region, self.zone.as_deref())
            .map_err(|e| evidence_err(e.message))
    }
}

/// `POST /v1/evaluators/{id}/location-declarations`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclareLocation {
    pub provider: String,
    pub region: String,
    #[serde(default)]
    pub zone: Option<String>,
    /// How many days the declaration holds (default 90, at most 366).
    #[serde(default)]
    pub valid_for_days: Option<u32>,
}

/// The governed projects that plan on or run on `evaluator`: one with a
/// plan whose admissible set names it, or a job scheduled on it.
pub fn governed_projects_using_evaluator(
    c: &mut impl GenericClient,
    evaluator: &str,
) -> Result<Vec<String>> {
    Ok(c.query(
        "SELECT p.id FROM projects p
          WHERE p.governance = 'governed'
            AND (EXISTS (SELECT 1 FROM plans x
                          WHERE x.project_id = p.id
                            AND x.document #> '{plan,placement,admissible}' @> $2::jsonb)
                 OR EXISTS (SELECT 1 FROM jobs j
                             WHERE j.project_id = p.id AND j.evaluator_id = $1))
          ORDER BY p.id",
        &[&evaluator, &json!([{"id": evaluator}])],
    )
    .map_err(db_err)?
    .iter()
    .map(|r| r.get(0))
    .collect())
}

/// Records an evaluator event in its operator's partition and in each
/// governed project that uses it, so their members and auditors see it.
pub fn append_evaluator_event(
    t: &mut impl GenericClient,
    kind: &'static str,
    evaluator: &str,
    operator: &str,
    refs: &[(&str, String)],
) -> Result<()> {
    let mut partitions = vec![govlog::for_org(Some(operator))];
    for p in governed_projects_using_evaluator(t, evaluator)? {
        partitions.push(Partition::Project(p));
    }
    for p in partitions {
        let mut d = govlog::Draft::new(p, kind, evaluator).org(operator);
        for (k, v) in refs {
            d = d.r#ref(k, v.clone());
        }
        govlog::append(t, d)?;
    }
    Ok(())
}

/// The operator of `evaluator`: the organization of its service account,
/// `platform` when it has none.
pub fn operator_of(c: &mut impl GenericClient, evaluator: &str) -> Result<Option<String>> {
    Ok(c.query_opt(
        "SELECT s.organization_id FROM evaluators e
           JOIN service_accounts s ON s.id = e.service_account
          WHERE e.id = $1",
        &[&evaluator],
    )
    .map_err(db_err)?
    .map(|r| {
        r.get::<_, Option<String>>(0)
            .unwrap_or_else(|| PLATFORM_ORG.to_owned())
    }))
}

/// Every registered evaluator whose service account is active, as the
/// planner and the scheduler judge it. Evidence past its validity is
/// counted as self-declared: stale evidence is not evidence.
pub fn evaluator_offers(c: &mut impl GenericClient) -> Result<Vec<EvaluatorOffer>> {
    let mut out = vec![];
    for r in c
        .query(
            "SELECT e.id, s.organization_id, e.backends, e.profiles, e.location,
                    e.location_evidence, e.location_evidence_digest,
                    (e.location_valid_until IS NULL OR e.location_valid_until > now())
               FROM evaluators e JOIN service_accounts s ON s.id = e.service_account
              WHERE s.status = 'active'
              ORDER BY e.id",
            &[],
        )
        .map_err(db_err)?
    {
        let location: Option<Location> = r
            .get::<_, Option<Value>>(4)
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| db_err(format!("stored evaluator location: {e}")))?;
        let stored = LocationEvidence::parse(r.get::<_, &str>(5))
            .ok_or_else(|| db_err("stored location evidence"))?;
        let fresh: bool = r.get(7);
        let (evidence, digest) = if stored == LocationEvidence::SelfDeclared || fresh {
            (stored, r.get::<_, Option<String>>(6))
        } else {
            (LocationEvidence::SelfDeclared, None)
        };
        let list = |v: Value| -> Vec<String> { serde_json::from_value(v).unwrap_or_default() };
        out.push(EvaluatorOffer {
            id: r.get(0),
            operator: r
                .get::<_, Option<String>>(1)
                .unwrap_or_else(|| PLATFORM_ORG.to_owned()),
            backends: list(r.get(2)),
            profiles: list(r.get(3)),
            location,
            evidence,
            evidence_digest: digest,
        });
    }
    Ok(out)
}

impl Control {
    /// What an evaluator reports about its location when it registers, in
    /// the caller's transaction (the row exists already or is inserted by
    /// the caller after this returns the values to store). Returns the
    /// columns to write: `(location, evidence, digest, valid_until_secs)`;
    /// the change, if any, is recorded.
    ///
    /// - nothing reported: the stored location and evidence stand;
    /// - the stored location reported again: unchanged;
    /// - another location: it replaces the stored one as **self-declared**,
    ///   whatever evidence the old one had (a declaration never vouches
    ///   for a machine that moved), audited and logged.
    pub(crate) fn register_location(
        &self,
        t: &mut Transaction<'_>,
        ctx: &Ctx,
        evaluator: &str,
        operator: &str,
        reported: Option<&LocationInput>,
    ) -> Result<()> {
        let Some(input) = reported else { return Ok(()) };
        let new = input.resolve()?;
        let old: Option<(Option<Value>, String)> = t
            .query_opt(
                "SELECT location, location_evidence FROM evaluators WHERE id = $1 FOR UPDATE",
                &[&evaluator],
            )
            .map_err(db_err)?
            .map(|r| (r.get(0), r.get(1)));
        let unchanged = old.as_ref().is_some_and(|(l, _)| {
            l.as_ref()
                .and_then(|v| serde_json::from_value::<Location>(v.clone()).ok())
                .as_ref()
                == Some(&new)
        });
        if unchanged {
            return Ok(());
        }
        t.execute(
            "UPDATE evaluators SET location = $2, location_evidence = 'self_declared',
                    location_evidence_digest = NULL, location_valid_until = NULL,
                    location_updated_at = now()
              WHERE id = $1",
            &[
                &evaluator,
                &serde_json::to_value(&new).expect("serializable"),
            ],
        )
        .map_err(db_err)?;
        audit::append(
            t,
            ctx.draft(
                "evaluator.location_changed",
                "evaluator",
                evaluator,
                Outcome::Succeeded,
            )
            .org(operator)
            .r#ref("location", location_ref(&new))
            .r#ref("evidence", LocationEvidence::SelfDeclared.as_str()),
        )?;
        append_evaluator_event(
            t,
            kind::EVALUATOR_LOCATION_CHANGED,
            evaluator,
            operator,
            &[(
                "evidence",
                LocationEvidence::SelfDeclared.as_str().to_owned(),
            )],
        )
    }

    /// `POST /v1/evaluators/{id}/location-declarations`: a person who is a
    /// security admin of the evaluator's operator organization declares
    /// where it runs. Never a service account (not the evaluator itself,
    /// not an automation key of the operator), never a person of another
    /// organization, never an auditor. An attested location is not
    /// replaced by a declaration.
    pub fn declare_evaluator_location(
        &self,
        ctx: &Ctx,
        id: &str,
        r: DeclareLocation,
    ) -> Result<Value> {
        if !matches!(ctx.principal.kind, PrincipalKind::User { .. }) {
            self.audit_denied(
                ctx.draft(
                    "evaluator.location_declaration_denied",
                    "evaluator",
                    id,
                    Outcome::Denied,
                )
                .org(PLATFORM_ORG)
                .r#ref("reason", "not_a_person"),
            );
            return Err(evidence_err(
                "a location is declared by a person who is a security admin of the evaluator's \
                 operator, never by a service account",
            ));
        }
        let days = r.valid_for_days.unwrap_or(DECLARATION_DEFAULT_DAYS);
        if days == 0 || days > DECLARATION_MAX_DAYS {
            return Err(bad(format!("valid_for_days is 1-{DECLARATION_MAX_DAYS}")));
        }
        let location = LocationInput {
            provider: r.provider,
            region: r.region,
            zone: r.zone,
        }
        .resolve()?;
        let valid_until = now() + u64::from(days) * 86_400;
        let declaration = new_id("eld");
        let out = self.tx_anchored(|t| {
            let operator = operator_of(t, id)?.ok_or_else(|| not_found("evaluator", id))?;
            // The operator's own security admin, by name: anyone else is
            // refused as if the evaluator were not theirs to see.
            if !ctx.principal.member_of(&operator) {
                return Err(not_found("evaluator", id));
            }
            require_human(
                &ctx.principal,
                &operator,
                &[Role::SecurityAdmin],
                "declaring an evaluator's location",
            )
            .map_err(|e| match e.code {
                Code::Forbidden | Code::NotFound => e,
                _ => evidence_err(e.message),
            })?;
            let cur = t
                .query_one(
                    "SELECT location_evidence,
                            (location_valid_until IS NOT NULL AND location_valid_until > now())
                       FROM evaluators WHERE id = $1 FOR UPDATE",
                    &[&id],
                )
                .map_err(db_err)?;
            if cur.get::<_, &str>(0) == LocationEvidence::Attested.as_str() && cur.get::<_, bool>(1)
            {
                return Err(evidence_err(
                    "the evaluator's location is attested: a declaration does not replace \
                     attested evidence",
                ));
            }
            let digest = location.evidence_digest(LocationEvidence::OperatorDeclared, ctx.actor());
            let location_json = serde_json::to_value(&location).expect("serializable");
            t.execute(
                "INSERT INTO evaluator_location_declarations
                     (id, evaluator_id, operator, location, evidence_digest, declared_by, valid_until)
                 VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7::bigint))",
                &[
                    &declaration,
                    &id,
                    &operator,
                    &location_json,
                    &digest,
                    &ctx.actor(),
                    &(valid_until as i64),
                ],
            )
            .map_err(db_err)?;
            t.execute(
                "UPDATE evaluators SET location = $2, location_evidence = 'operator_declared',
                        location_evidence_digest = $3, location_valid_until = to_timestamp($4::bigint),
                        location_updated_at = now()
                  WHERE id = $1",
                &[&id, &location_json, &digest, &(valid_until as i64)],
            )
            .map_err(db_err)?;
            audit::append(
                t,
                ctx.draft(
                    "evaluator.location_declared",
                    "evaluator",
                    id,
                    Outcome::Succeeded,
                )
                .org(&operator)
                .r#ref("declaration", declaration.clone())
                .r#ref("location", location_ref(&location))
                .r#ref("evidence_digest", digest.clone())
                .r#ref("valid_until", valid_until.to_string()),
            )?;
            append_evaluator_event(
                t,
                kind::EVALUATOR_LOCATION_DECLARED,
                id,
                &operator,
                &[
                    ("evidence", LocationEvidence::OperatorDeclared.as_str().to_owned()),
                    ("evidence_digest", digest.clone()),
                ],
            )?;
            Ok(json!({
                "id": declaration, "evaluator": id, "operator": operator,
                "location": location, "evidence": LocationEvidence::OperatorDeclared.as_str(),
                "evidence_digest": digest, "valid_until": valid_until,
            }))
        })?;
        Ok(out)
    }
}
