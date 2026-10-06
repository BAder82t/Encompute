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

use std::collections::BTreeSet;

use postgres::{GenericClient, Transaction};
use serde::Deserialize;
use serde_json::{json, Value};

use encompute_ir::{Code, Error, Result};
use encompute_planner::placement::Admission;
use encompute_planner::{
    AdmittedEvaluator, EvaluatorOffer, Location, LocationEvidence, Origin, PlacementConstraints,
    PlacementSource, PlanningContext, Roles,
};
use encompute_trust::authz::SignedAuthorizationV2;
use encompute_trust::govlog::Partition;
use encompute_verification::governance::GovernanceBinding;
use encompute_verification::placement::GrantPlacement;
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
/// The most declarations per evaluator per hour.
pub const MAX_DECLARATIONS_PER_HOUR: i64 = 30;
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
                    (e.location_valid_until IS NULL OR e.location_valid_until > now()),
                    e.url, e.receipt_key
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
            endpoint_digest: Some(endpoint_digest(
                &r.get::<_, String>(8),
                &r.get::<_, String>(9),
            )),
        });
    }
    Ok(out)
}

/// Digest of where an evaluator is reached and the key it signs with: the
/// endpoint a location's evidence vouches for.
pub fn endpoint_digest(url: &str, receipt_key: &str) -> String {
    encompute_verification::service::sha256_hex(format!("{url}\0{receipt_key}").as_bytes())
}

/// The digest of evaluator `id`'s current endpoint (URL and receipt key).
pub fn endpoint_of(c: &mut impl GenericClient, id: &str) -> Result<Option<String>> {
    Ok(c.query_opt(
        "SELECT url, receipt_key FROM evaluators WHERE id = $1",
        &[&id],
    )
    .map_err(db_err)?
    .map(|r| endpoint_digest(&r.get::<_, String>(0), &r.get::<_, String>(1))))
}

impl Control {
    /// An evaluator registered again at another URL or with another receipt
    /// key (`before` is its endpoint digest from before): the evidence for
    /// its location vouched for the old endpoint, so it is lost (back to
    /// self-declared), audited and logged like a changed location.
    pub(crate) fn endpoint_changed(
        &self,
        t: &mut Transaction<'_>,
        ctx: &Ctx,
        evaluator: &str,
        operator: &str,
        before: Option<String>,
    ) -> Result<()> {
        let Some(before) = before else { return Ok(()) };
        if endpoint_of(t, evaluator)?.as_deref() == Some(before.as_str()) {
            return Ok(());
        }
        let n = t
            .execute(
                "UPDATE evaluators SET location_evidence = 'self_declared',
                        location_evidence_digest = NULL, location_valid_until = NULL,
                        location_updated_at = now()
                  WHERE id = $1 AND location_evidence <> 'self_declared'",
                &[&evaluator],
            )
            .map_err(db_err)?;
        if n > 0 {
            audit::append(
                t,
                ctx.draft(
                    "evaluator.location_changed",
                    "evaluator",
                    evaluator,
                    Outcome::Succeeded,
                )
                .org(operator)
                .r#ref("reason", "endpoint_changed")
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
            )?;
        }
        Ok(())
    }

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
            // Bounded: an evaluator's record is not a place to write history
            // without end (each declaration is a log event in every project
            // that uses it).
            let recent: i64 = t
                .query_one(
                    "SELECT count(*) FROM evaluator_location_declarations
                      WHERE evaluator_id = $1 AND declared_at > now() - interval '1 hour'",
                    &[&id],
                )
                .map_err(db_err)?
                .get(0);
            let renewal: bool = t
                .query_one(
                    "SELECT COALESCE((SELECT location = $2 AND location_evidence = 'operator_declared'
                                        FROM evaluators WHERE id = $1), false)",
                    &[&id, &serde_json::to_value(&location).expect("serializable")],
                )
                .map_err(db_err)?
                .get(0);
            if recent >= MAX_DECLARATIONS_PER_HOUR && !renewal {
                return Err(evidence_err(format!(
                    "at most {MAX_DECLARATIONS_PER_HOUR} location declarations an hour for one \
                     evaluator: declare again later"
                )));
            }
            let endpoint = endpoint_of(t, id)?.unwrap_or_default();
            let digest = location.evidence_digest(
                LocationEvidence::OperatorDeclared,
                &format!("{}\0{endpoint}", ctx.actor()),
            );
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

// --- rollback: what a restore must not undo ---------------------------------------------

/// The state a restore may have dropped or rewritten though the
/// governance log records it: a version of a project's placement
/// constraints (every tightening is an event naming its version and
/// digest) or an evaluator's location evidence (its declarations and
/// losses are events). Found at startup, like the negative sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlacementLoss {
    /// Version `version` of `project`'s constraints, with `digest`, as the
    /// log records it, is not what the database holds.
    Version {
        project: String,
        version: i32,
        digest: String,
        shows: &'static str,
    },
    /// The log's last word on `evaluator`'s location evidence is
    /// `logged`; the database shows operator-declared evidence that `shows`.
    Evidence {
        evaluator: String,
        logged: String,
        shows: &'static str,
    },
}

/// The `row.lost` state that acknowledges a lost version of a project's
/// constraints (subject `<project>@<version>`).
pub const LOST_PLACEMENT: &str = "project_placement";

impl PlacementLoss {
    /// The state a rollback refusal names.
    pub fn state(&self) -> &'static str {
        match self {
            PlacementLoss::Version { .. } => "PLACEMENT",
            PlacementLoss::Evidence { .. } => "LOCATION EVIDENCE",
        }
    }

    pub fn message(&self) -> String {
        match self {
            PlacementLoss::Version {
                project,
                version,
                digest,
                shows,
            } => format!(
                "version {version} of project {project}'s placement constraints (digest {digest}) is in the governance log, but the database {shows}"
            ),
            PlacementLoss::Evidence {
                evaluator,
                logged,
                shows,
            } => format!(
                "the governance log records {logged} for evaluator {evaluator}'s location, but the database shows operator-declared evidence that {shows}"
            ),
        }
    }
}

/// Every [`PlacementLoss`], in order. A lost version that recovery
/// acknowledged (`row.lost`) is not reported again.
pub fn placement_losses(c: &mut impl GenericClient) -> Result<Vec<PlacementLoss>> {
    let mut out = vec![];
    // Every placement version the log records: the database must hold it
    // with the logged digest, and its constraints must still hash to it.
    for r in c
        .query(
            "SELECT DISTINCT e.subject_id, (e.body #>> '{refs,version}')::int, e.body #>> '{refs,digest}'
               FROM governance_events e
              WHERE e.kind = $1
                AND NOT EXISTS (SELECT 1 FROM governance_events l
                                 WHERE l.kind = $2 AND l.subject_id = e.subject_id || '@' || (e.body #>> '{refs,version}')
                                   AND l.body #>> '{refs,state}' = $3)
              ORDER BY 1, 2",
            &[&PLACEMENT_CHANGED, &govlog::extra_kind::ROW_LOST, &LOST_PLACEMENT],
        )
        .map_err(db_err)?
    {
        let (project, version, digest): (String, i32, String) = (r.get(0), r.get(1), r.get(2));
        let held = c
            .query_opt(
                "SELECT digest, constraints FROM project_placements WHERE project_id = $1 AND version = $2",
                &[&project, &version],
            )
            .map_err(db_err)?;
        let shows = match held {
            None => Some("no longer holds that version"),
            Some(h) if h.get::<_, String>(0) != digest => Some("holds that version with another digest"),
            Some(h) => {
                let ok = serde_json::from_value::<PlacementConstraints>(h.get(1))
                    .is_ok_and(|x| x.digest() == digest);
                (!ok).then_some("holds constraints that no longer hash to that digest")
            }
        };
        if let Some(shows) = shows {
            out.push(PlacementLoss::Version {
                project,
                version,
                digest,
                shows,
            });
        }
    }
    // An evaluator's location evidence: its latest event says what the
    // database may still show. Evidence the log records lost, or another
    // declaration than the latest, or one whose record is gone, is not
    // evidence a restore may bring back.
    for r in c
        .query(
            "SELECT DISTINCT ON (e.subject_id) e.subject_id, e.kind, e.body #>> '{refs,evidence_digest}'
               FROM governance_events e
              WHERE e.kind = ANY($1)
              ORDER BY e.subject_id, e.gseq DESC",
            &[&vec![
                kind::EVALUATOR_LOCATION_DECLARED,
                kind::EVALUATOR_LOCATION_CHANGED,
            ]],
        )
        .map_err(db_err)?
    {
        let (evaluator, last, logged): (String, String, Option<String>) =
            (r.get(0), r.get(1), r.get(2));
        let Some(row) = c
            .query_opt(
                "SELECT location, location_evidence, location_evidence_digest FROM evaluators WHERE id = $1",
                &[&evaluator],
            )
            .map_err(db_err)?
        else {
            continue;
        };
        if row.get::<_, String>(1) != LocationEvidence::OperatorDeclared.as_str() {
            continue;
        }
        let (location, shown): (Option<Value>, Option<String>) = (row.get(0), row.get(2));
        let (logged, shows) = if last == kind::EVALUATOR_LOCATION_CHANGED {
            (
                "that its evidence was lost".to_owned(),
                Some("is still in force"),
            )
        } else if shown != logged {
            (
                "a declaration".to_owned(),
                Some("is not that declaration's"),
            )
        } else {
            let declared: Option<Option<Value>> = c
                .query_opt(
                    "SELECT location FROM evaluator_location_declarations
                      WHERE evaluator_id = $1 AND evidence_digest = $2",
                    &[&evaluator, &shown],
                )
                .map_err(db_err)?
                .map(|d| d.get(0));
            (
                "a declaration".to_owned(),
                match declared {
                    None => Some("has no declaration on record"),
                    Some(l) if l != location => Some("is for another location than declared"),
                    Some(_) => None,
                },
            )
        };
        if let Some(shows) = shows {
            out.push(PlacementLoss::Evidence {
                evaluator,
                logged,
                shows,
            });
        }
    }
    Ok(out)
}

impl Control {
    /// Recovery's answer to [`placement_losses`]: a lost or rewritten
    /// version of a project's constraints cannot be restored (the log holds
    /// only its digest), so recovery records it as lost, in the project's
    /// own log where every member sees it, and the project is held to the
    /// version the database has until a member's security admin tightens it
    /// again (at once); evidence a restore brought back is taken back to
    /// self-declared and logged. Returns what it did.
    pub(crate) fn recover_placement(&self, operator: &str) -> Result<Vec<String>> {
        let losses = {
            let mut c = self.db.conn()?;
            placement_losses(&mut *c)?
        };
        let mut notes = vec![];
        for loss in losses {
            match loss {
                PlacementLoss::Version {
                    project,
                    version,
                    digest,
                    ..
                } => {
                    self.db.tx(|t| {
                        govlog::append(
                            t,
                            govlog::Draft::new(
                                Partition::Project(project.clone()),
                                govlog::extra_kind::ROW_LOST,
                                &format!("{project}@{version}"),
                            )
                            .r#ref("state", LOST_PLACEMENT)
                            .r#ref("digest", digest.clone()),
                        )?;
                        audit::append(
                            t,
                            audit::AuditDraft::new(
                                operator,
                                "recovery",
                                "project.placement_lost",
                                "project",
                                &project,
                                Outcome::Succeeded,
                            )
                            .project(&project)
                            .r#ref("version", version.to_string())
                            .r#ref("digest", digest.clone()),
                        )?;
                        Ok(())
                    })?;
                    notes.push(format!(
                        "project {project}: placement version {version} (digest {digest}) is lost with the restored database and recorded as lost; the project is held to the constraints the database has until a member's security admin sets them again"
                    ));
                }
                PlacementLoss::Evidence { evaluator, .. } => {
                    self.db.tx(|t| {
                        let operator_org =
                            operator_of(t, &evaluator)?.unwrap_or_else(|| PLATFORM_ORG.to_owned());
                        t.execute(
                            "UPDATE evaluators SET location_evidence = 'self_declared',
                                    location_evidence_digest = NULL, location_valid_until = NULL,
                                    location_updated_at = now()
                              WHERE id = $1",
                            &[&evaluator],
                        )
                        .map_err(db_err)?;
                        audit::append(
                            t,
                            audit::AuditDraft::new(
                                operator,
                                "recovery",
                                "evaluator.location_changed",
                                "evaluator",
                                &evaluator,
                                Outcome::Succeeded,
                            )
                            .org(&operator_org)
                            .r#ref("reason", "restored_evidence_withdrawn")
                            .r#ref("evidence", LocationEvidence::SelfDeclared.as_str()),
                        )?;
                        append_evaluator_event(
                            t,
                            kind::EVALUATOR_LOCATION_CHANGED,
                            &evaluator,
                            &operator_org,
                            &[(
                                "evidence",
                                LocationEvidence::SelfDeclared.as_str().to_owned(),
                            )],
                        )
                    })?;
                    notes.push(format!(
                        "evaluator {evaluator}: location evidence the log records as lost or replaced was shown again; taken back to self-declared (declare it again)"
                    ));
                }
            }
        }
        Ok(notes)
    }
}

// --- project constraints -------------------------------------------------------------

/// The governance-log kind of a change to a project's placement.
pub const PLACEMENT_CHANGED: &str = "placement.changed";

fn change_err(m: impl Into<String>) -> Error {
    Error::new(Code::GovernancePlacementChange, m)
}

/// A project's placement constraints as of one version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectPlacement {
    pub version: i32,
    pub constraints: PlacementConstraints,
    pub digest: String,
}

/// `POST /v1/projects/{id}/placement`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetProjectPlacement {
    pub constraints: PlacementConstraints,
    /// The version the caller read (0 when the project has none): a change
    /// based on anything else is refused, so two members never overwrite
    /// each other unseen.
    pub base_version: i32,
}

/// The project's current constraints; `None` when it has never had any.
pub fn project_placement(
    c: &mut impl GenericClient,
    project: &str,
) -> Result<Option<ProjectPlacement>> {
    c.query_opt(
        "SELECT version, constraints, digest FROM project_placements
          WHERE project_id = $1 ORDER BY version DESC LIMIT 1",
        &[&project],
    )
    .map_err(db_err)?
    .map(|r| {
        Ok(ProjectPlacement {
            version: r.get(0),
            constraints: serde_json::from_value(r.get(1))
                .map_err(|e| db_err(format!("stored project placement: {e}")))?,
            digest: r.get(2),
        })
    })
    .transpose()
}

/// The version of the project's constraints with `digest`: what a job's
/// binding names. `None` when the project never had it.
pub fn project_placement_by_digest(
    c: &mut impl GenericClient,
    project: &str,
    digest: &str,
) -> Result<Option<PlacementConstraints>> {
    c.query_opt(
        "SELECT constraints FROM project_placements
          WHERE project_id = $1 AND digest = $2 ORDER BY version DESC LIMIT 1",
        &[&project, &digest],
    )
    .map_err(db_err)?
    .map(|r| {
        serde_json::from_value(r.get(0))
            .map_err(|e| db_err(format!("stored project placement: {e}")))
    })
    .transpose()
}

/// Whether `new` names (in `allowed_operators` or `allowed_evaluators`) an
/// operator that is neither the platform nor a member of the project, and
/// that `cur` did not already name.
fn names_outsider(
    t: &mut impl GenericClient,
    new: &PlacementConstraints,
    cur: &PlacementConstraints,
    members: &[String],
) -> Result<bool> {
    let known = |o: &str| o == PLATFORM_ORG || members.iter().any(|m| m == o);
    for o in new.allowed_operators.iter().flatten() {
        if !known(o)
            && !cur
                .allowed_operators
                .as_ref()
                .is_some_and(|c| c.contains(o))
        {
            return Ok(true);
        }
    }
    for e in new.allowed_evaluators.iter().flatten() {
        if cur
            .allowed_evaluators
            .as_ref()
            .is_some_and(|c| c.contains(e))
        {
            continue;
        }
        match operator_of(t, e)? {
            Some(o) if known(&o) => {}
            _ => return Ok(true),
        }
    }
    Ok(false)
}

impl Control {
    /// `GET /v1/projects/{id}/placement`: the project's constraints, shared
    /// by every member and auditor, with the change proposals waiting for
    /// the rest of the members.
    pub fn project_placement_view(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let p = super::tenancy::project_reader(&mut *c, &ctx.principal, id)?;
        let current = project_placement(&mut *c, id)?;
        let pending: Vec<Value> = c
            .query(
                "SELECT digest, constraints, array_agg(organization ORDER BY organization)
                   FROM project_placement_proposals
                  WHERE project_id = $1
                    AND based_on = $2
                  GROUP BY digest, constraints ORDER BY digest",
                &[&id, &current.as_ref().map_or(0, |c| c.version)],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| {
                let by: Vec<String> = r.get(2);
                let waiting: Vec<&String> = p.members.iter().filter(|m| !by.contains(m)).collect();
                json!({"digest": r.get::<_, String>(0), "constraints": r.get::<_, Value>(1),
                       "proposed_by": by, "waiting_for": waiting})
            })
            .collect();
        Ok(json!({
            "project": id,
            "version": current.as_ref().map_or(0, |c| c.version),
            "constraints": current.as_ref().map(|c| &c.constraints),
            "digest": current.as_ref().map(|c| &c.digest),
            "pending_loosening": pending,
            "locations_table": encompute_planner::locations::digest(),
        }))
    }

    /// `POST /v1/projects/{id}/placement`: a person who is a security admin
    /// of a member organization changes the project's constraints.
    ///
    /// - **Tightening** (the new constraints admit nothing the current ones
    ///   refuse) takes effect at once, for any member.
    /// - Anything else **loosens** (it admits something the current ones
    ///   refuse): it takes effect when every member organization has
    ///   proposed exactly the same constraints, from the same version.
    ///
    /// Either change is audited in every member's trail and recorded in the
    /// project's governance log. An existing job keeps being judged by the
    /// version it was bound under as well as the current one.
    pub fn set_project_placement(
        &self,
        ctx: &Ctx,
        id: &str,
        r: SetProjectPlacement,
    ) -> Result<Value> {
        self.tx_anchored(|t| {
            // Lock the project's row before reading its member list (the
            // join of a member takes the same lock first), so the members a
            // loosening needs are the members there are when it applies.
            t.query_opt("SELECT 1 FROM projects WHERE id = $1 FOR UPDATE", &[&id])
                .map_err(db_err)?;
            let p = crate::authz::project_visible(t, &ctx.principal, id)?;
            crate::authz::deny_auditor(&ctx.principal, &p)?;
            if !p.governed() {
                return Err(change_err(
                    "placement constraints belong to governed projects",
                ));
            }
            let orgs = crate::authz::project_role_orgs(&ctx.principal, &p, &[Role::SecurityAdmin]);
            let Some(org) = orgs.first().cloned() else {
                return Err(crate::authz::forbidden(
                    "changing a project's placement needs security_admin in a member organization",
                ));
            };
            require_human(
                &ctx.principal,
                &org,
                &[Role::SecurityAdmin],
                "changing a project's placement",
            )?;
            r.constraints
                .check()
                .map_err(|e| change_err(e.message))?;
            let current = project_placement(t, id)?;
            let n = current.as_ref().map_or(0, |c| c.version);
            let cur = current
                .as_ref()
                .map(|c| c.constraints.clone())
                .unwrap_or_default();
            if r.base_version != n {
                return Err(change_err(format!(
                    "the change is based on version {}, the project is at version {n}: read it again",
                    r.base_version
                )));
            }
            if r.constraints == cur {
                return Ok(json!({"status": "unchanged", "version": n}));
            }
            let digest = r.constraints.digest();
            // Naming an operator or an evaluator of an organization that is
            // not a member admits something no member's own rule did: it is
            // a loosening, whatever else the change narrows.
            let tightening = r.constraints.tightens(&cur)
                && !names_outsider(t, &r.constraints, &cur, &p.members)?;
            let proposal = |t: &mut Transaction<'_>| -> Result<Vec<String>> {
                t.execute(
                    "INSERT INTO project_placement_proposals
                         (project_id, based_on, digest, constraints, organization, proposed_by)
                     VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
                    &[
                        &id,
                        &n,
                        &digest,
                        &serde_json::to_value(&r.constraints).expect("serializable"),
                        &org,
                        &ctx.actor(),
                    ],
                )
                .map_err(db_err)?;
                Ok(t.query(
                    "SELECT organization FROM project_placement_proposals
                      WHERE project_id = $1 AND based_on = $2 AND digest = $3
                      ORDER BY organization",
                    &[&id, &n, &digest],
                )
                .map_err(db_err)?
                .iter()
                .map(|x| x.get(0))
                .filter(|o: &String| p.members.contains(o))
                .collect())
            };
            let kind = if tightening {
                "tighten"
            } else {
                // Loosening: this organization's proposal, and the change
                // once every member has made it.
                let by = proposal(t)?;
                let waiting: Vec<String> = p
                    .members
                    .iter()
                    .filter(|m| !by.contains(m))
                    .cloned()
                    .collect();
                audit::append(
                    t,
                    ctx.draft(
                        "project.placement_proposed",
                        "project",
                        id,
                        Outcome::Succeeded,
                    )
                    .org(&org)
                    .project(id)
                    .r#ref("digest", digest.clone())
                    .r#ref("based_on", n.to_string()),
                )?;
                if !waiting.is_empty() {
                    return Ok(json!({"status": "pending", "version": n, "digest": digest,
                                     "proposed_by": by, "waiting_for": waiting}));
                }
                "loosen"
            };
            let version = n + 1;
            t.execute(
                "INSERT INTO project_placements (project_id, version, constraints, digest, kind, set_by, set_by_org)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &id,
                    &version,
                    &serde_json::to_value(&r.constraints).expect("serializable"),
                    &digest,
                    &kind,
                    &ctx.actor(),
                    &org,
                ],
            )
            .map_err(db_err)?;
            t.execute(
                "DELETE FROM project_placement_proposals WHERE project_id = $1",
                &[&id],
            )
            .map_err(db_err)?;
            // Every member sees it, in its own trail and in the project's
            // log.
            for m in &p.members {
                audit::append(
                    t,
                    ctx.draft("project.placement_changed", "project", id, Outcome::Succeeded)
                        .org(m)
                        .project(id)
                        .r#ref("version", version.to_string())
                        .r#ref("digest", digest.clone())
                        .r#ref("change", kind),
                )?;
            }
            govlog::append(
                t,
                govlog::Draft::new(Partition::Project(id.to_owned()), PLACEMENT_CHANGED, id)
                    .org(&org)
                    .r#ref("version", version.to_string())
                    .r#ref("digest", digest.clone())
                    .r#ref("change", kind),
            )?;
            Ok(json!({"status": "applied", "version": version, "digest": digest, "change": kind}))
        })
    }
}

// --- governed jobs --------------------------------------------------------------------

/// A refusal that nothing can run the job where its constraints and the
/// separation of operators allow: operator separation when that is all
/// that refused, residency otherwise.
pub fn placement_refused(a: &Admission) -> Error {
    let code = if a.only_separation_refused() {
        Code::GovernanceOperatorSeparation
    } else {
        Code::GovernanceResidency
    };
    Error::new(code, format!("no admissible evaluator: {}", a.why_none()))
}

/// The owner constraints of `authorizations` (rows of the signed
/// authorizations a job runs under), each from its organization.
pub fn owner_sources(
    c: &mut impl GenericClient,
    rows: &[&str],
) -> Result<(Vec<PlacementSource>, BTreeSet<String>, Vec<String>)> {
    let mut out = vec![];
    let mut parties = BTreeSet::new();
    let mut pins = vec![];
    for r in c
        .query(
            "SELECT signed FROM authorizations WHERE id = ANY($1) ORDER BY id",
            &[&rows],
        )
        .map_err(db_err)?
    {
        let Some(v) = r.get::<_, Option<Value>>(0) else {
            continue;
        };
        let signed: SignedAuthorizationV2 =
            serde_json::from_value(v).map_err(|e| db_err(format!("stored authorization: {e}")))?;
        parties.insert(signed.body.party.clone());
        pins.extend(signed.body.limits.project_placement_digest.clone());
        if let Some(c) = signed.body.limits.placement.clone() {
            out.push(PlacementSource {
                origin: Origin::Organization(signed.body.party.clone()),
                constraints: c,
            });
        }
    }
    Ok((out, parties, pins))
}

/// What a governed job's placement is judged against.
pub struct JobPlacement<'a> {
    pub project: &'a str,
    pub plan: &'a str,
    /// The job's binding: its project-constraints digest, its inputs'
    /// owners and its outputs' recipients.
    pub binding: &'a GovernanceBinding,
    /// The encrypted backend the plan's ciphertext steps need.
    pub backend: &'a str,
    /// The owners' own constraints (from their authorizations).
    pub owners: Vec<PlacementSource>,
    /// Every organization whose authorization the job runs under, with
    /// or without constraints: they own sources (lineage owners of a
    /// derived source included), so none of them operates the evaluator.
    pub parties: BTreeSet<String>,
    /// The project-constraint digests the owners pinned in their
    /// authorizations: the binding must name exactly these.
    pub pins: Vec<String>,
}

impl Control {
    /// The evaluators the job's placement admits **now**, with every other
    /// evaluator's reason, from the database in the caller's transaction:
    /// the plan's own context (its project constraints and roles), the
    /// project's constraints as the binding names them and as they are now
    /// (a later loosening never widens a bound job), the owners' own
    /// constraints, the roles named by the binding, the evaluators and
    /// their evidence as registered now. A plan without a placement
    /// context, or a binding that names project constraints the project
    /// never had, admits nothing.
    pub fn job_admission(
        &self,
        t: &mut impl GenericClient,
        j: &JobPlacement<'_>,
    ) -> Result<Admission> {
        let doc: Value = t
            .query_opt("SELECT document FROM plans WHERE id = $1", &[&j.plan])
            .map_err(db_err)?
            .ok_or_else(|| not_found("plan", j.plan))?
            .get(0);
        let mut ctx: PlanningContext = serde_json::from_value(doc["plan"]["context"].clone())
            .map_err(|e| db_err(format!("stored plan context: {e}")))?;
        let Some(pc) = ctx.placement.as_mut() else {
            return Err(Error::new(
                Code::GovernanceResidency,
                "the job's plan was made without placement: a governed job's plan names where it \
                 may run",
            ));
        };
        // The project's constraints: the version the job was bound under
        // and the current one. Never fewer than either.
        pc.constraints.clear();
        let current = project_placement(t, j.project)?;
        let mut digests = BTreeSet::new();
        if let Some(d) = &j.binding.placement_digest {
            let Some(bound) = project_placement_by_digest(t, j.project, d)? else {
                return Err(Error::new(
                    Code::GovernanceResidency,
                    "the job's binding names project constraints the project never had",
                ));
            };
            digests.insert(d.clone());
            pc.constraints.push(PlacementSource {
                origin: Origin::Project(j.project.to_owned()),
                constraints: bound,
            });
        }
        if let Some(c) = current {
            if digests.insert(c.digest.clone()) {
                pc.constraints.push(PlacementSource {
                    origin: Origin::Project(j.project.to_owned()),
                    constraints: c.constraints,
                });
            }
        }
        if j.pins
            .iter()
            .any(|p| j.binding.placement_digest.as_deref() != Some(p.as_str()))
        {
            return Err(Error::new(
                Code::GovernanceResidency,
                "the project's placement constraints changed since the owner pinned them; the \
                 owner must re-authorize",
            ));
        }
        let participants: BTreeSet<String> = crate::authz::project_row(t, j.project)?
            .map(|p| p.members.into_iter().collect())
            .unwrap_or_default();
        pc.production = self.env.is_production();
        pc.locations_digest = encompute_planner::locations::digest();
        pc.roles = Roles {
            source_owners: j
                .binding
                .inputs
                .values()
                .map(|i| i.organization.clone())
                .chain(j.parties.iter().cloned())
                .collect(),
            decryptors: j
                .binding
                .outputs
                .values()
                .flat_map(|o| o.recipients.iter().cloned())
                .collect(),
            coordinator: None,
            participants,
        };
        ctx.infrastructure.evaluators = evaluator_offers(t)?;
        Ok(encompute_planner::placement::admission(
            &ctx,
            Some(j.backend),
            &j.owners,
            &BTreeSet::new(),
        ))
    }
}

/// How a grant records a placement: the admitted evaluator's operator,
/// location and evidence.
pub fn grant_placement(a: &AdmittedEvaluator) -> GrantPlacement {
    GrantPlacement {
        operator: a.operator.clone(),
        location: a.location.clone(),
        evidence: a.evidence,
        evidence_digest: a.evidence_digest.clone(),
        endpoint_digest: a.endpoint_digest.clone(),
    }
}

impl Control {
    /// The job's placement prerequisites and, with `evaluator`, whether
    /// that evaluator is admissible **now** and is still the machine the
    /// grant recorded (`recorded`: its operator, location and evidence at
    /// scheduling). The shared check behind `revalidate_governed` at
    /// scheduling and start, and behind release tickets:
    ///
    /// - the plan names where it may run, and the binding's project
    ///   constraints exist (ENC2710);
    /// - with an evaluator: it is admitted by every constraint as the
    ///   registry has it now (ENC2710, or ENC2725 when it is operator
    ///   separation), and when the grant recorded its placement, the
    ///   operator, location, evidence level and evidence digest are the
    ///   same (ENC2710): an evaluator that moved, lost its evidence, or
    ///   was re-registered after scheduling does not run the job.
    pub(crate) fn check_job_placement(
        &self,
        t: &mut Transaction<'_>,
        job: &str,
        binding: &GovernanceBinding,
        evaluator: Option<&str>,
        recorded: Option<&GrantPlacement>,
    ) -> Result<()> {
        let adm = self.admission_for_job(t, job, binding)?;
        let Some(ev) = evaluator else { return Ok(()) };
        let Some(now_admitted) = adm.admitted.iter().find(|a| a.id == ev) else {
            let why = if adm.hidden.contains(ev) {
                "its operator takes no part in the project".to_owned()
            } else {
                adm.excluded.iter().find(|(id, _)| id == ev).map_or(
                    "it is not a registered, active evaluator".to_owned(),
                    |(_, w)| w.clone(),
                )
            };
            let code = if adm.separation.contains(ev) {
                Code::GovernanceOperatorSeparation
            } else {
                Code::GovernanceResidency
            };
            return Err(Error::new(
                code,
                format!("evaluator {ev} is not admissible for this job now: {why}"),
            ));
        };
        if let Some(rec) = recorded {
            if *rec != grant_placement(now_admitted) {
                return Err(Error::new(
                    Code::GovernanceResidency,
                    format!(
                        "evaluator {ev} is not the machine the job was scheduled on: its \
                         operator, location or evidence changed since"
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Whether the only reason governed job `job` may not start on
    /// `evaluator` is that the evidence for its location was renewed after
    /// scheduling: the evaluator is still admitted and is the same machine
    /// (operator, location, evidence level, endpoint), and the grant's
    /// placement differs from what the registry holds now in the evidence's
    /// digest alone (another person of the operator declared the same
    /// location again). Such a job is scheduled again, with a grant that
    /// records the renewed evidence, instead of failing for good.
    pub(crate) fn placement_only_renewed(
        &self,
        t: &mut Transaction<'_>,
        job: &str,
        binding: &GovernanceBinding,
        evaluator: &str,
        recorded: &GrantPlacement,
    ) -> Result<bool> {
        let adm = self.admission_for_job(t, job, binding)?;
        let Some(now_admitted) = adm.admitted.iter().find(|a| a.id == evaluator) else {
            return Ok(false);
        };
        let current = grant_placement(now_admitted);
        Ok(current != *recorded
            && current
                == GrantPlacement {
                    evidence_digest: current.evidence_digest.clone(),
                    ..recorded.clone()
                })
    }

    /// The evaluators governed job `job` may run on **now**: every
    /// constraint, the owners' authorizations it runs under, and the
    /// registry as it is (see [`Control::job_admission`]).
    pub(crate) fn admission_for_job(
        &self,
        t: &mut impl GenericClient,
        job: &str,
        binding: &GovernanceBinding,
    ) -> Result<Admission> {
        let r = t
            .query_one(
                "SELECT project_id, plan_id, backend FROM jobs WHERE id = $1",
                &[&job],
            )
            .map_err(db_err)?;
        let (project, plan, backend): (String, String, String) = (r.get(0), r.get(1), r.get(2));
        let rows: Vec<String> = t
            .query(
                "SELECT authorization_row FROM job_authorizations WHERE job_id = $1 ORDER BY authorization_row",
                &[&job],
            )
            .map_err(db_err)?
            .iter()
            .map(|x| x.get(0))
            .collect();
        let rows: Vec<&str> = rows.iter().map(String::as_str).collect();
        let (owners, parties, pins) = owner_sources(t, &rows)?;
        self.job_admission(
            t,
            &JobPlacement {
                project: &project,
                plan: &plan,
                binding,
                backend: &backend,
                owners,
                parties,
                pins,
            },
        )
    }
}
