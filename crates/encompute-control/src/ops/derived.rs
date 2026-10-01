//! Derived results and their exports (governed projects).
//!
//! A result a governed job released becomes a first-class asset once its
//! job succeeded: a dataset version held by its custodian, the recipient
//! organization that decrypted it (never the control-plane operator),
//! whose parents are the job's exact source versions and whose policy and
//! release class are never wider than theirs. The custodian signs a
//! release record of it with its governance key, the control plane
//! co-signs that record once it has checked it against the result's real
//! ancestry (every lineage owner named, under its active governance key),
//! and its key is held at the custodian's own key broker, which binds it
//! only to a co-signed record.
//!
//! An export of a derived result is a single-use export ticket for one
//! recipient, redeemed at the custodian's broker. It is issued only while
//! every authorization in the result's lineage is usable (after its
//! `valid_until` a started job may finish, but nothing it released is
//! exported), no ancestor is revoked or expired, the recipient is named by
//! every one of those authorizations and by the custodian's record, the
//! export's class is within every ancestor's ceiling, and the owners'
//! release limits allow it.
//!
//! Revocation blocks new use; it is not retroactive. Revoking a source
//! marks its derived descendants (`source_revoked_at`), and every use,
//! derivation and export walks the ancestors themselves, whose revocation
//! the state anchor holds: a restored database that lost the mark changes
//! nothing. Nothing already released is erased, and nothing here claims it
//! is.

use std::collections::{BTreeMap, BTreeSet};

use postgres::{GenericClient, Transaction};
use serde_json::{json, Value};

use encompute_analysis::confidentiality::{join_registered, no_wider};
use encompute_ir::confidentiality::AssetPolicy;
use encompute_ir::{Code, Error, Result};
use encompute_trust::authz::{
    DerivedReleaseCosignature, SignedAuthorizationV2, SignedDerivedReleaseCosignature,
    SignedReleaseRecord, CONTROL_STATEMENT_VERSION,
};
use encompute_verification::canonical::canonical_json;
use encompute_verification::governance::{
    release_within, AssetVersion, ReleaseClass, ASSET_VERSION_VERSION,
};
use encompute_verification::service::{now, sha256_hex};
use encompute_verification::ticket::{
    ReleaseTicket, TicketKind, MAX_TICKET_TTL_SECS, TICKET_SKEW_SECS, TICKET_VERSION,
};

use super::governance::{under_active_key, usable_at, usable_purpose};
use super::jobs::{released_job, ReleasedJob};
use crate::audit::{self, Outcome};
use crate::authz::{asset_row, conflict, deny_auditor_in, forbidden, not_found, require_human};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::model::{
    bad, check_digest, check_name, new_id, KeyRef, RegisterDerivedAsset, RequestExport, Role,
};

/// Assets a lineage walk visits at most.
const MAX_LINEAGE: usize = 10_000;

/// Who records and exports a derived result for its custodian.
const CUSTODIAN_ROLES: &[Role] = &[
    Role::DataOwner,
    Role::ModelOwner,
    Role::MlDeveloper,
    Role::OrganizationAdmin,
    Role::SecurityAdmin,
];

fn gov(code: Code, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

fn release(msg: impl Into<String>) -> Error {
    gov(Code::GovernanceReleaseClass, msg)
}

/// The digest of an onward policy a release record names: SHA-256 (hex) of
/// the policy's canonical JSON.
pub fn onward_policy_id(policy: &Value) -> Result<String> {
    Ok(sha256_hex(&canonical_json(policy)?))
}

/// One asset of a lineage.
pub(crate) struct LineageNode {
    pub organization: String,
    /// The job that released it, for a derived result.
    pub derived_from_job: Option<String>,
}

fn class_of(v: Option<String>, id: &str) -> Result<ReleaseClass> {
    v.and_then(|c| serde_json::from_value(Value::String(c)).ok())
        .ok_or_else(|| {
            release(format!(
                "asset {id} has no registered release class: a governed result derives only from registered versions"
            ))
        })
}

/// The authorizations the jobs `jobs` ran under, share-locked (after the
/// jobs, as everywhere): (row, signed document), ordered by row.
pub(crate) fn lineage_authorizations(
    t: &mut Transaction<'_>,
    jobs: &[String],
) -> Result<Vec<(String, SignedAuthorizationV2)>> {
    let rows = t
        .query(
            "SELECT z.id, z.authorization_id, z.signed FROM authorizations z
              WHERE z.id IN (SELECT authorization_row FROM job_authorizations WHERE job_id = ANY($1))
              ORDER BY z.id FOR SHARE",
            &[&jobs],
        )
        .map_err(db_err)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let row: String = r.get(0);
        let signed: SignedAuthorizationV2 = r
            .get::<_, Option<Value>>(2)
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| db_err(format!("stored authorization: {e}")))?
            .ok_or_else(|| {
                gov(
                    Code::GovernanceAuthorizationMissing,
                    format!("authorization {row} is not signed"),
                )
            })?;
        if r.get::<_, Option<String>>(1).as_deref() != Some(signed.id().as_str()) {
            return Err(gov(
                Code::GovernanceProgramNotAuthorized,
                format!("authorization {row} is not the document on record"),
            ));
        }
        out.push((row, signed));
    }
    Ok(out)
}

/// The organizations owning an ancestor of derived result `asset`, every
/// hop up its lineage (read, not locked: a lineage never changes). Empty
/// for an asset that is not a derived result. Each of them authorizes a
/// governed job reading `asset`, as the owners of a source do: consent
/// carries through derivation.
pub(crate) fn lineage_owners(c: &mut impl GenericClient, asset: &str) -> Result<BTreeSet<String>> {
    Ok(c.query(
        "WITH RECURSIVE anc(id) AS (
                 SELECT jsonb_array_elements_text(parents) FROM assets
                  WHERE id = $1 AND derived_from_job IS NOT NULL
                 UNION
                 SELECT jsonb_array_elements_text(a.parents) FROM assets a JOIN anc ON a.id = anc.id
             )
             SELECT DISTINCT a.organization_id FROM anc JOIN assets a ON a.id = anc.id ORDER BY 1",
        &[&asset],
    )
    .map_err(db_err)?
    .iter()
    .map(|r| r.get(0))
    .collect())
}

/// Every owner in the lineage of each of `sources` authorized job `job`'s
/// use of it (bound at submission), not only the source's own owner
/// (ENC2701).
pub(crate) fn require_lineage_consent(
    t: &mut Transaction<'_>,
    job: &str,
    sources: &[String],
) -> Result<()> {
    for a in sources {
        let owners = lineage_owners(t, a)?;
        if owners.is_empty() {
            continue;
        }
        let bound: BTreeSet<String> = t
            .query(
                "SELECT z.organization_id FROM job_authorizations ja
                   JOIN authorizations z ON z.id = ja.authorization_row
                  WHERE ja.job_id = $1 AND ja.asset_id = $2",
                &[&job, a],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        if let Some(o) = owners.difference(&bound).next() {
            return Err(gov(
                Code::GovernanceAuthorizationMissing,
                format!(
                    "{o} owns data source {a} is derived from, and the job runs under no authorization of {o} for it"
                ),
            ));
        }
    }
    Ok(())
}

/// Jobs derived from the jobs bound to authorization row `$1`: those jobs,
/// and every job reading a derived result one of them released, every hop
/// down. (A CTE for the queries below.)
pub(crate) const JOBS_UNDER: &str = "WITH RECURSIVE under(id) AS (
         SELECT job_id FROM job_authorizations WHERE authorization_row = $1
         UNION
         SELECT x.id FROM under JOIN assets d ON d.derived_from_job = under.id
           JOIN jobs x ON x.source_assets ? d.id
     )";

/// Executions that count against authorization row `row`
/// ([`JOBS_UNDER`]: directly or through derived results, every hop), other
/// than `except`: every such job that started, or has not failed or been
/// cancelled.
pub(crate) fn executions_under(
    t: &mut Transaction<'_>,
    row: &str,
    except: Option<&str>,
) -> Result<u64> {
    let n: i64 = t
        .query_one(
            &format!(
                "{JOBS_UNDER}
                 SELECT count(*) FROM under JOIN jobs x ON x.id = under.id
                  WHERE (x.state NOT IN ('failed', 'cancelled') OR x.started_at IS NOT NULL)
                    AND x.id IS DISTINCT FROM $2"
            ),
            &[&row, &except],
        )
        .map_err(db_err)?
        .get(0);
    Ok(n.max(0) as u64)
}

/// Exports that count against authorization row `row`: every export of a
/// result released by a job under it ([`JOBS_UNDER`], every hop).
pub(crate) fn exports_under(t: &mut Transaction<'_>, row: &str) -> Result<u64> {
    let n: i64 = t
        .query_one(
            &format!(
                "{JOBS_UNDER}
                 SELECT count(*) FROM exports e JOIN assets d ON d.id = e.asset_id
                  WHERE d.derived_from_job IN (SELECT id FROM under)"
            ),
            &[&row],
        )
        .map_err(db_err)?
        .get(0);
    Ok(n.max(0) as u64)
}

/// The authorizations of the jobs that released `assets`' derived
/// ancestors (every hop up): a job reading one counts against each of
/// them too.
pub(crate) fn ancestor_authorizations(
    t: &mut Transaction<'_>,
    assets: &[String],
) -> Result<Vec<(String, SignedAuthorizationV2)>> {
    let jobs: Vec<String> = t
        .query(
            "WITH RECURSIVE anc(id) AS (
                 SELECT unnest($1::text[])
                 UNION
                 SELECT jsonb_array_elements_text(a.parents) FROM assets a JOIN anc ON a.id = anc.id
             )
             SELECT DISTINCT a.derived_from_job FROM anc JOIN assets a ON a.id = anc.id
              WHERE a.derived_from_job IS NOT NULL ORDER BY 1",
            &[&assets],
        )
        .map_err(db_err)?
        .iter()
        .map(|r| r.get(0))
        .collect();
    if jobs.is_empty() {
        return Ok(vec![]);
    }
    lineage_authorizations(t, &jobs)
}

/// Probing limits across derivation (ENC2714): one more execution under
/// each of `rows` (the job's own authorizations and those of its sources'
/// ancestors) stays within its `max_executions`, counting every job under
/// it through derived results, `except` the job itself.
pub(crate) fn check_executions(
    t: &mut Transaction<'_>,
    rows: &[(String, SignedAuthorizationV2)],
    except: Option<&str>,
) -> Result<()> {
    for (row, a) in rows {
        if let Some(max) = a.body.limits.max_executions {
            if executions_under(t, row, except)? >= max {
                return Err(gov(
                    Code::GovernanceAuthorizationLimit,
                    format!(
                        "authorization {row} allows {max} execution(s), counting every job that reads a result derived under it; all are used"
                    ),
                ));
            }
        }
    }
    Ok(())
}

impl Control {
    /// Walks `assets` and every ancestor, and refuses when one is revoked,
    /// in the database or in the state anchor (ENC2706), marked
    /// source-revoked (ENC2706), expired (in the database or in the state
    /// anchor), marked source-expired or past its deletion date at `at`
    /// (ENC2705), or not on record. The check a governed use, derivation,
    /// key-release ticket and export make: revocation blocks new use
    /// downstream without relying on the mark.
    ///
    /// `assets` are share-locked (ordered by ID), their ancestors only
    /// read: a revocation marks every derived descendant under its own row
    /// lock after the revoked asset, so a revocation racing this call
    /// either waits for it (the use came first) or is seen by it. Locking
    /// only downward keeps one lock order with revocation (ancestor, then
    /// descendants).
    pub(crate) fn check_lineage(
        &self,
        t: &mut Transaction<'_>,
        assets: &[String],
        at: u64,
    ) -> Result<Vec<LineageNode>> {
        let anchor = self.anchor.snapshot();
        let mut out = vec![];
        let mut seen = BTreeSet::new();
        let mut todo: Vec<String> = assets.to_vec();
        while !todo.is_empty() {
            let batch: Vec<String> = std::mem::take(&mut todo)
                .into_iter()
                .filter(|a| seen.insert(a.clone()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            if batch.is_empty() {
                break;
            }
            if seen.len() > MAX_LINEAGE {
                return Err(conflict(format!(
                    "a lineage of more than {MAX_LINEAGE} assets is not used"
                )));
            }
            let rows = t
                .query(
                    &format!(
                        "SELECT id, organization_id, status, expired_at IS NOT NULL, delete_after,
                                source_revoked_at IS NOT NULL, parents, derived_from_job,
                                source_expired_at IS NOT NULL
                           FROM assets WHERE id = ANY($1) ORDER BY id {}",
                        if out.is_empty() { "FOR SHARE" } else { "" }
                    ),
                    &[&batch],
                )
                .map_err(db_err)?;
            if rows.len() != batch.len() {
                return Err(gov(
                    Code::GovernanceAssetVersionMismatch,
                    "an asset of the lineage is not on record",
                ));
            }
            for r in rows {
                let id: String = r.get(0);
                let first = assets.contains(&id);
                let which = if first {
                    format!("asset {id}")
                } else {
                    format!("its ancestor {id}")
                };
                if r.get::<_, String>(2) == "revoked" || anchor.revoked.contains(&id) {
                    return Err(gov(
                        Code::GovernanceAuthorizationRevoked,
                        format!("{which} is revoked"),
                    ));
                }
                if r.get::<_, bool>(5) {
                    return Err(gov(
                        Code::GovernanceAuthorizationRevoked,
                        format!("a source of {which} was revoked: it is not used, derived from or exported again"),
                    ));
                }
                if r.get::<_, bool>(8) {
                    return Err(gov(
                        Code::GovernanceAuthorizationExpired,
                        format!("a source of {which} expired (its deletion date passed): it is not used, derived from or exported again"),
                    ));
                }
                if r.get::<_, bool>(3)
                    || anchor.expired_assets.contains(&id)
                    || r.get::<_, Option<i64>>(4)
                        .is_some_and(|d| d.max(0) as u64 <= at)
                {
                    return Err(gov(
                        Code::GovernanceAuthorizationExpired,
                        format!("{which} is expired or past its deletion date"),
                    ));
                }
                let parents: Vec<String> = serde_json::from_value(r.get(6)).unwrap_or_default();
                todo.extend(parents);
                out.push(LineageNode {
                    organization: r.get(1),
                    derived_from_job: r.get(7),
                });
            }
        }
        Ok(out)
    }

    /// A person of a recipient organization of `r.output` records the
    /// result of governed job `job` (succeeded) as a derived asset its
    /// organization holds as custodian: a dataset version whose parents are
    /// the job's sources, whose policy and class are never wider than its
    /// parents' (ENC2709), whose key is at the custodian's own broker
    /// (ENC2715), under the custodian's release record signed with its
    /// active governance key. Audited for the custodian and every owner in
    /// its lineage.
    pub fn register_derived_asset(
        &self,
        ctx: &Ctx,
        job: &str,
        r: RegisterDerivedAsset,
    ) -> Result<Value> {
        check_name("output", &r.output)?;
        check_digest("digest", &r.digest)?;
        check_name("key_ref.broker", &r.key_ref.broker)?;
        check_name("key_ref.key_ref", &r.key_ref.key_ref)?;
        let at = now();
        self.db.tx(|t| {
            // Visible, and never by an auditor (D9).
            let (j, p) = released_job(t, Some(ctx), job)?;
            if !j.succeeded {
                return Err(conflict(format!(
                    "job {job} has not succeeded: a result becomes a derived asset only after its job succeeded"
                )));
            }
            let o = j
                .binding
                .outputs
                .get(&r.output)
                .ok_or_else(|| not_found("output of the job", &r.output))?
                .clone();
            // The custodian: the recipient organization, by one of its
            // people.
            let custodian = ctx
                .principal
                .organization
                .clone()
                .ok_or_else(|| forbidden("a derived result is recorded by a person of its recipient"))?;
            require_human(&ctx.principal, &custodian, CUSTODIAN_ROLES, "recording a derived result")?;
            if !o.recipients.contains(&custodian) {
                return Err(forbidden(format!(
                    "{custodian} is not a recipient of output {:?}: only a recipient records it as a derived asset",
                    r.output
                )));
            }
            // The parents: exactly the job's sources, and with every
            // ancestor share-locked and usable (no further derivation of
            // anything revoked or expired). Then the job, then its
            // authorizations (assets → jobs → authorizations, the order
            // revocation and tickets take).
            let lineage = self.check_lineage(t, &j.sources, at)?;
            let mut jobs: BTreeSet<String> = lineage
                .iter()
                .filter_map(|n| n.derived_from_job.clone())
                .collect();
            jobs.insert(j.id.clone());
            let jobs: Vec<String> = jobs.into_iter().collect();
            t.execute(
                "SELECT 1 FROM jobs WHERE id = ANY($1) ORDER BY id FOR SHARE",
                &[&jobs],
            )
            .map_err(db_err)?;
            let rows = t
                .query(
                    "SELECT id, version_id, ir_policy, release_class, lineage_root
                       FROM assets WHERE id = ANY($1) ORDER BY id",
                    &[&j.sources],
                )
                .map_err(db_err)?;
            let mut parents = BTreeSet::new();
            let mut policies = vec![];
            let mut classes = vec![];
            let mut roots = BTreeSet::new();
            for row in rows {
                let id: String = row.get(0);
                let v: Option<String> = row.get(1);
                let v = v
                    .filter(|v| j.binding.inputs.values().any(|i| &i.asset_version_id == v))
                    .ok_or_else(|| {
                        gov(
                            Code::GovernanceAssetVersionMismatch,
                            format!("source {id} is not the version the job was bound to"),
                        )
                    })?;
                parents.insert(v);
                let policy: AssetPolicy = row
                    .get::<_, Option<Value>>(2)
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|e| db_err(format!("stored policy: {e}")))?
                    .ok_or_else(|| {
                        release(format!("source {id} has no registered policy"))
                    })?;
                policies.push(policy);
                classes.push((id.clone(), class_of(row.get(3), &id)?));
                roots.insert(row.get::<_, String>(4));
            }
            let authorizations = lineage_authorizations(t, &jobs)?;
            let own: BTreeSet<String> = j.authorizations.values().cloned().collect();
            // The class: within the output's, every parent's and every
            // authorization's in its lineage.
            let class = r.release_class;
            if !release_within(class, o.release_class) {
                return Err(release(format!(
                    "class {} is wider than output {:?}'s, {}",
                    class.as_str(),
                    r.output,
                    o.release_class.as_str()
                )));
            }
            for (id, c) in &classes {
                if !release_within(class, *c) {
                    return Err(release(format!(
                        "class {} is wider than parent {id}'s, {}",
                        class.as_str(),
                        c.as_str()
                    )));
                }
            }
            for (row, a) in &authorizations {
                if !release_within(class, a.body.release_class) {
                    return Err(release(format!(
                        "class {} is wider than authorization {row}'s ceiling, {}",
                        class.as_str(),
                        a.body.release_class.as_str()
                    )));
                }
            }
            // The onward policy: never wider than the parents' joined.
            let declared: AssetPolicy = serde_json::from_value(r.ir_policy.clone())
                .map_err(|e| bad(format!("ir_policy is not an asset policy: {e}")))?;
            let canonical = serde_json::to_value(&declared).expect("serializable");
            if canonical != r.ir_policy {
                return Err(bad(
                    "ir_policy has unknown, missing or non-canonical fields (absent optional fields are left out)",
                ));
            }
            declared.check_forms()?;
            let joined = join_registered(&policies).map_err(|e| release(e.message))?;
            no_wider(&declared, &joined).map_err(|e| release(e.message))?;
            // The version, the custodian's own.
            let version = AssetVersion {
                version: ASSET_VERSION_VERSION,
                organization: custodian.clone(),
                series: r.series.clone(),
                label: r.version.clone(),
                digest: r.digest.clone(),
            };
            version.check()?;
            let version_id = version.id().hex();
            let taken = t
                .query_opt(
                    "SELECT 1 FROM assets WHERE organization_id = $1 AND series = $2 AND version = $3",
                    &[&custodian, &version.series, &version.label],
                )
                .map_err(db_err)?;
            if taken.is_some() {
                return Err(gov(
                    Code::GovernanceAssetVersionMismatch,
                    format!("{} is registered already: versions are immutable", version.name()),
                ));
            }
            // Custody: the custodian's own broker, the key its own.
            crate::ops::keybroker_lock(t, &r.key_ref.broker)?;
            crate::ops::require_own_broker(t, &custodian, Some(&r.key_ref.broker))?;
            let foreign = t
                .query_opt(
                    "SELECT 1 FROM assets WHERE key_ref->>'broker' = $1 AND key_ref->>'key_ref' = $2
                        AND organization_id <> $3 LIMIT 1",
                    &[&r.key_ref.broker, &r.key_ref.key_ref, &custodian],
                )
                .map_err(db_err)?;
            if foreign.is_some() {
                return Err(conflict(format!(
                    "key {} at broker {} belongs to another organization",
                    r.key_ref.key_ref, r.key_ref.broker
                )));
            }
            // The custodian's release record: of exactly this result, never
            // naming a recipient any authorization of its lineage does not,
            // and signed with its active governance key.
            let rec = &r.release_record;
            let b = &rec.body;
            let mismatch = |what: &str| {
                gov(
                    Code::GovernanceAssetVersionMismatch,
                    format!("the release record is not this result's: its {what} differs"),
                )
            };
            let onward = onward_policy_id(&canonical)?;
            for (what, same) in [
                ("party", b.party == custodian),
                ("project", b.project == j.project),
                ("purpose", b.purpose_id == j.binding.purpose_id),
                ("job", b.job_id == j.id),
                ("governance ID", b.governance_id == j.governance_id),
                ("output", b.output == r.output),
                ("version", b.derived_version_id == version_id),
                ("class", b.release_class == class),
                ("parents", b.parents == parents),
                ("authorizations", b.authorization_ids == own),
                ("onward policy", b.onward_policy_id == onward),
            ] {
                if !same {
                    return Err(mismatch(what));
                }
            }
            // Every other organization owning data in the lineage, under its
            // active governance key: the custodian's broker requires an
            // authorization of each, verified under that key.
            let mut expected = BTreeMap::new();
            for o in lineage.iter().map(|n| &n.organization) {
                if *o == custodian || expected.contains_key(o) {
                    continue;
                }
                let k: String = t
                    .query_opt(
                        "SELECT key_id FROM governance_keys WHERE organization_id = $1 AND status = 'active'",
                        &[o],
                    )
                    .map_err(db_err)?
                    .ok_or_else(|| {
                        gov(Code::GovernanceKeyRevoked, format!("{o} has no active governance key"))
                    })?
                    .get(0);
                expected.insert(o.clone(), k);
            }
            if b.lineage_owners != expected {
                return Err(mismatch("lineage owners"));
            }
            for x in b.recipients.keys() {
                if p.auditors.contains(x) || p.invited_auditors.contains(x) {
                    return Err(gov(
                        Code::GovernanceAuditorSeparation,
                        format!("{x} audits this project and receives no export"),
                    ));
                }
                if let Some((row, _)) = authorizations
                    .iter()
                    .find(|(_, a)| !a.body.recipients.contains(x))
                {
                    return Err(release(format!(
                        "the release record names {x}, whom authorization {row} does not"
                    )));
                }
            }
            under_active_key(t, &custodian, &rec.public_key, |k| rec.verify(k))?;
            let id = new_id("ast");
            // The control plane's co-signature of the record it has just
            // validated against the result's real ancestry: the custodian's
            // broker binds the result's key only to it, so a custodian
            // cannot bind a record that leaves a lineage owner out.
            let cosignature = DerivedReleaseCosignature {
                version: CONTROL_STATEMENT_VERSION,
                organization: custodian.clone(),
                asset_id: id.clone(),
                broker: r.key_ref.broker.clone(),
                key_ref: r.key_ref.key_ref.clone(),
                derived_version_id: version_id.clone(),
                release_record_id: rec.id(),
                lineage_owners: b.lineage_owners.clone(),
                issued_at: at,
            }
            .sign(&self.signer)?;
            let cosignature = serde_json::to_value(&cosignature).expect("serializable");
            let lineage_root = match roots.len() {
                1 => roots.into_iter().next().expect("one"),
                _ => id.clone(),
            };
            t.execute(
                "INSERT INTO assets (id, organization_id, kind, name, digest, policy, lineage_root, parents,
                     key_ref, status, created_by, series, version, version_id, ir_policy, release_class,
                     derived_from_job, derived_output, custodian_org, release_record, release_cosignature)
                 VALUES ($1, $2, $3, $4, $5, '{}', $6, $7, $8, 'active', $9, $10, $11, $12, $13, $14,
                         $15, $16, $2, $17, $18)",
                &[
                    &id,
                    &custodian,
                    &r.kind.as_str(),
                    &version.name(),
                    &r.digest,
                    &lineage_root,
                    &json!(j.sources),
                    &json!(r.key_ref),
                    &ctx.actor(),
                    &version.series,
                    &version.label,
                    &version_id,
                    &canonical,
                    &class.as_str(),
                    &j.id,
                    &r.output,
                    &serde_json::to_value(rec).expect("serializable"),
                    &cosignature,
                ],
            )
            .map_err(|e| {
                if e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                    gov(
                        Code::GovernanceAssetVersionMismatch,
                        format!("output {:?} of job {job} is recorded already, or {} exists", r.output, version.name()),
                    )
                } else {
                    db_err(e)
                }
            })?;
            // The custodian's trail, and every owner's in its lineage.
            let mut orgs: BTreeSet<&str> = lineage.iter().map(|n| n.organization.as_str()).collect();
            orgs.insert(&custodian);
            for org in orgs {
                audit::append(
                    t,
                    ctx.draft("asset.derived", "asset", &id, Outcome::Succeeded)
                        .org(org)
                        .project(&j.project)
                        .r#ref("job", j.id.clone())
                        .r#ref("output", r.output.clone())
                        .r#ref("custodian", custodian.clone())
                        .r#ref("release_class", class.as_str())
                        .r#ref("release_record", rec.id()),
                )?;
            }
            Ok(json!({
                "id": id, "organization": custodian, "custodian": custodian,
                "derived_from_job": j.id, "output": r.output,
                "series": version.series, "version": version.label, "version_id": version_id,
                "parents": j.sources, "lineage_root": lineage_root,
                "release_class": class.as_str(), "release_record": rec.id(),
                "release_cosignature": cosignature,
            }))
        })
    }

    /// A person of a derived result's custodian asks for an export ticket
    /// of it to `r.recipient`: single-use, for the custodian's broker,
    /// stored with its export row (one per ticket) and audited. Refused
    /// when an authorization in its lineage is not usable now (after its
    /// `valid_until`, ENC2705; revoked, ENC2706; its key revoked, ENC2708),
    /// an ancestor is revoked, source-revoked or expired (ENC2706, ENC2705),
    /// the recipient is not named by every such authorization and by the
    /// custodian's record, or the class is not within the result's and
    /// every ceiling (ENC2709), or an owner's release limit is used up
    /// (ENC2714).
    pub fn export_asset(&self, ctx: &Ctx, id: &str, r: RequestExport) -> Result<Value> {
        check_name("recipient", &r.recipient)?;
        let at = now();
        self.db.tx(|t| {
            let a = asset_row(t, id)?.ok_or_else(|| not_found("asset", id))?;
            if !ctx.principal.member_of(&a.organization) {
                return Err(not_found("asset", id));
            }
            deny_auditor_in(t, &ctx.principal, &a.organization)?;
            let row = t
                .query_one(
                    "SELECT derived_from_job, release_record, release_class, version_id FROM assets WHERE id = $1",
                    &[&id],
                )
                .map_err(db_err)?;
            let Some(job) = row.get::<_, Option<String>>(0) else {
                return Err(conflict(format!(
                    "asset {id} is not a derived result: only a governed job's recorded result is exported"
                )));
            };
            let (j, p) = released_job(t, Some(ctx), &job)?;
            let custodian = a.organization.clone();
            require_human(&ctx.principal, &custodian, CUSTODIAN_ROLES, "exporting a derived result")?;
            if p.auditors.contains(&r.recipient) || p.invited_auditors.contains(&r.recipient) {
                return Err(gov(
                    Code::GovernanceAuditorSeparation,
                    format!("{} audits this project and receives no export", r.recipient),
                ));
            }
            let own_class = class_of(row.get(2), id)?;
            let version_id: String = row
                .get::<_, Option<String>>(3)
                .ok_or_else(|| db_err("a derived result is a version"))?;
            let rec: SignedReleaseRecord = serde_json::from_value(row.get(1))
                .map_err(|e| db_err(format!("stored release record: {e}")))?;
            // The result and every ancestor, share-locked and usable; then
            // the jobs of its lineage; then their authorizations.
            let lineage = self.check_lineage(t, &[id.to_owned()], at)?;
            let jobs: Vec<String> = lineage
                .iter()
                .filter_map(|n| n.derived_from_job.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            t.execute(
                "SELECT 1 FROM jobs WHERE id = ANY($1) ORDER BY id FOR SHARE",
                &[&jobs],
            )
            .map_err(db_err)?;
            let class = r.release_class.unwrap_or(own_class);
            if !release_within(class, own_class) {
                return Err(release(format!(
                    "an export in class {} is wider than the result's class, {}",
                    class.as_str(),
                    own_class.as_str()
                )));
            }
            let anchored = self.anchor.snapshot().revoked_authorizations;
            let mut until = at + MAX_TICKET_TTL_SECS;
            let mut limits: BTreeMap<String, u64> = BTreeMap::new();
            for (row, a) in lineage_authorizations(t, &jobs)? {
                if anchored.contains(&row) || anchored.contains(&a.id()) {
                    return Err(gov(
                        Code::GovernanceAuthorizationRevoked,
                        format!("authorization {row} was revoked"),
                    ));
                }
                // K-7: a job that started inside its window finished, but
                // nothing it released is exported after the window.
                usable_at(t, &row, at)?;
                if !a.body.recipients.contains(&r.recipient) {
                    return Err(release(format!(
                        "authorization {row} does not name {} as a recipient",
                        r.recipient
                    )));
                }
                if !release_within(class, a.body.release_class) {
                    return Err(release(format!(
                        "an export in class {} is wider than authorization {row}'s ceiling, {}",
                        class.as_str(),
                        a.body.release_class.as_str()
                    )));
                }
                if let Some(max) = a.body.limits.max_releases {
                    limits.insert(row.clone(), max);
                }
                until = until.min(a.body.valid_until);
            }
            // Probing: the owner's release limit counts every export of a
            // result released under its authorization, however many
            // derivations away.
            for (row, max) in &limits {
                if exports_under(t, row)? >= *max {
                    return Err(gov(
                        Code::GovernanceAuthorizationLimit,
                        format!("authorization {row} allows {max} release(s); all are used"),
                    ));
                }
            }
            // The purpose the result was released for.
            let purpose = usable_purpose(t, &j.project, &j.binding.purpose_id)?;
            if !purpose.is_valid_at(at) {
                return Err(gov(
                    Code::GovernanceAuthorizationExpired,
                    format!(
                        "the purpose is valid from {} until {}, not at {at}",
                        purpose.valid_from, purpose.valid_until
                    ),
                ));
            }
            until = until.min(purpose.valid_until);
            // The custodian's record, under its active governance key, names
            // the recipient and the key the export is sealed to.
            under_active_key(t, &custodian, &rec.public_key, |k| rec.verify(k))?;
            let export_key = rec.body.recipients.get(&r.recipient).cloned().ok_or_else(|| {
                release(format!(
                    "the custodian's release record does not name {} as a recipient",
                    r.recipient
                ))
            })?;
            let broker = a
                .key_ref
                .clone()
                .and_then(|k| serde_json::from_value::<KeyRef>(k).ok())
                .map(|k| k.broker);
            crate::ops::require_own_broker(t, &custodian, broker.as_deref())?;
            let broker = broker.expect("checked");
            let ticket = self.export_ticket(t, &j, &rec, version_id, broker, &r.recipient, export_key, at, until)?;
            // The trails of the custodian, the recipient and every owner in
            // the lineage.
            let mut orgs: BTreeSet<&str> = lineage.iter().map(|n| n.organization.as_str()).collect();
            orgs.insert(&custodian);
            orgs.insert(&r.recipient);
            let orgs: Vec<&str> = orgs.into_iter().collect();
            let ticket = self.issue_ticket(
                t,
                ctx,
                ticket,
                &r.recipient,
                ("asset", id),
                &j.project,
                &orgs,
                &[
                    ("recipient", r.recipient.clone()),
                    ("release_class", class.as_str().to_owned()),
                ],
            )?;
            let export = new_id("exp");
            t.execute(
                "INSERT INTO exports (id, asset_id, ticket_id, recipient, release_class, requested_by)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[&export, &id, &ticket.ticket_id, &r.recipient, &class.as_str(), &ctx.actor()],
            )
            .map_err(|e| {
                if e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                    gov(Code::GovernanceReleaseTicket, "this export ticket was used already")
                } else if e.code() == Some(&postgres::error::SqlState::FOREIGN_KEY_VIOLATION) {
                    not_found("organization", &r.recipient)
                } else {
                    db_err(e)
                }
            })?;
            Ok(json!({"id": export, "asset": id, "recipient": r.recipient,
                      "release_class": class.as_str(), "ticket": ticket}))
        })
    }

    /// The control plane's co-signature of derived result `id`'s release
    /// record in force (the latest re-issue, else the one made at
    /// registration), with the one made at registration: to the people of
    /// its custodian who operate its broker (security admins and data
    /// owners; its other members are refused, as for a re-issue), never
    /// anyone else (not found).
    pub fn release_cosignature(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let mut c = self.db.conn()?;
        let a = asset_row(&mut *c, id)?.ok_or_else(|| not_found("asset", id))?;
        if a.derived_from_job.is_none() || !ctx.principal.member_of(&a.organization) {
            return Err(not_found("asset", id));
        }
        require_human(
            &ctx.principal,
            &a.organization,
            &[Role::SecurityAdmin, Role::DataOwner],
            "reading a derived result's co-signature",
        )?;
        let registered: Value = c
            .query_one(
                "SELECT release_cosignature FROM assets WHERE id = $1",
                &[&id],
            )
            .map_err(db_err)?
            .get(0);
        let reissued = c
            .query(
                "SELECT cosignature FROM derived_cosignatures WHERE asset_id = $1 ORDER BY issued_at",
                &[&id],
            )
            .map_err(db_err)?;
        let current = reissued
            .last()
            .map(|r| r.get::<_, Value>(0))
            .unwrap_or_else(|| registered.clone());
        Ok(json!({"asset": id, "custodian": a.organization,
                  "release_cosignature": current, "registered_cosignature": registered,
                  "reissued": reissued.len()}))
    }

    /// A person who is a security admin of derived result `id`'s custodian
    /// has the control plane re-issue its co-signature of the custodian's
    /// release record after a lineage owner rotated its governance key: the
    /// same custodian, asset, broker, key, derived version and record, the
    /// same lineage owners, each under its active governance key now
    /// (ENC2708 when one has none), and a later issue time. The custodian's
    /// broker then re-binds the key ([`encompute_keybroker`]'s
    /// `rebind_derived_lineage`), so a result bound under a rotated key is
    /// not stranded. Recorded append-only and audited for the custodian and
    /// every lineage owner. Refused (409) when the co-signature in force
    /// already names every owner's active key.
    pub fn reissue_release_cosignature(&self, ctx: &Ctx, id: &str) -> Result<Value> {
        let at = now();
        self.db.tx(|t| {
            let a = asset_row(t, id)?.ok_or_else(|| not_found("asset", id))?;
            if !ctx.principal.member_of(&a.organization) {
                return Err(not_found("asset", id));
            }
            deny_auditor_in(t, &ctx.principal, &a.organization)?;
            if a.derived_from_job.is_none() {
                return Err(not_found("derived asset", id));
            }
            require_human(
                &ctx.principal,
                &a.organization,
                &[Role::SecurityAdmin],
                "re-issuing a derived result's co-signature",
            )?;
            // Nothing is re-bound to a result that is no longer used.
            if a.expired_at.is_some() || a.source_expired_at.is_some() {
                return Err(gov(
                    Code::GovernanceAuthorizationExpired,
                    format!(
                        "{id} {}: its co-signature is not re-issued",
                        if a.expired_at.is_some() {
                            "expired (its deletion date passed)"
                        } else {
                            "derives from a source that expired"
                        }
                    ),
                ));
            }
            // One re-issue at a time per result.
            let registered: Value = t
                .query_one(
                    "SELECT release_cosignature FROM assets WHERE id = $1 FOR UPDATE",
                    &[&id],
                )
                .map_err(db_err)?
                .get(0);
            let current: Value = t
                .query_opt(
                    "SELECT cosignature FROM derived_cosignatures WHERE asset_id = $1
                      ORDER BY issued_at DESC LIMIT 1",
                    &[&id],
                )
                .map_err(db_err)?
                .map(|r| r.get(0))
                .unwrap_or(registered);
            let current: SignedDerivedReleaseCosignature = serde_json::from_value(current)
                .map_err(|e| db_err(format!("stored co-signature: {e}")))?;
            let mut owners = BTreeMap::new();
            for o in current.body.lineage_owners.keys() {
                let k: String = t
                    .query_opt(
                        "SELECT key_id FROM governance_keys WHERE organization_id = $1 AND status = 'active'",
                        &[o],
                    )
                    .map_err(db_err)?
                    .ok_or_else(|| {
                        gov(
                            Code::GovernanceKeyRevoked,
                            format!(
                                "{o}, whose data this result derives from, has no active governance key: nothing is re-bound to it"
                            ),
                        )
                    })?
                    .get(0);
                owners.insert(o.clone(), k);
            }
            if owners == current.body.lineage_owners {
                return Err(conflict(
                    "the co-signature in force already names every lineage owner's active governance key",
                ));
            }
            let issued_at = at.max(current.body.issued_at + 1);
            let reissued = DerivedReleaseCosignature {
                lineage_owners: owners.clone(),
                issued_at,
                ..current.body.clone()
            }
            .sign(&self.signer)?;
            let reissued = serde_json::to_value(&reissued).expect("serializable");
            t.execute(
                "INSERT INTO derived_cosignatures (id, asset_id, cosignature, issued_at, issued_by)
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &new_id("dcs"),
                    &id,
                    &reissued,
                    &i64::try_from(issued_at).unwrap_or(i64::MAX),
                    &ctx.actor(),
                ],
            )
            .map_err(db_err)?;
            let mut orgs: BTreeSet<&str> = owners.keys().map(String::as_str).collect();
            orgs.insert(&a.organization);
            for org in orgs {
                let mut d = ctx
                    .draft("asset.release_cosignature_reissued", "asset", id, Outcome::Succeeded)
                    .org(org)
                    .r#ref("custodian", a.organization.clone())
                    .r#ref("issued_at", issued_at.to_string());
                for (o, k) in &owners {
                    if current.body.lineage_owners.get(o) != Some(k) {
                        d = d.r#ref(&format!("lineage_key:{o}"), k.clone());
                    }
                }
                audit::append(t, d)?;
            }
            Ok(json!({"asset": id, "custodian": a.organization,
                      "release_cosignature": reissued}))
        })
    }

    /// The unsigned export ticket of derived version `version_id` (held at
    /// `broker`) to `recipient`, sealed to `export_key`: for the job,
    /// binding and authorizations the custodian's record names, valid from
    /// `at` until `until` (never beyond 300 seconds, any authorization's or
    /// the purpose's end).
    #[allow(clippy::too_many_arguments)]
    fn export_ticket(
        &self,
        t: &mut Transaction<'_>,
        j: &ReleasedJob,
        rec: &SignedReleaseRecord,
        version_id: String,
        broker: String,
        recipient: &str,
        export_key: String,
        at: u64,
        until: u64,
    ) -> Result<ReleaseTicket> {
        let spec = self.cached_plan_spec_in(t, &j.plan)?.governed(&j.binding);
        if spec.id().hex() != j.spec_id {
            return Err(gov(
                Code::GovernanceProgramNotAuthorized,
                "the plan's spec under the job's binding no longer recomputes to the job's spec",
            ));
        }
        if until <= at + TICKET_SKEW_SECS {
            return Err(gov(
                Code::GovernanceReleaseTicket,
                "the lineage's window closes too soon for an export ticket to be accepted",
            ));
        }
        Ok(ReleaseTicket {
            version: TICKET_VERSION,
            ticket_id: ReleaseTicket::new_ticket_id()?,
            kind: TicketKind::Export,
            organization: rec.body.party.clone(),
            broker,
            asset_version_id: version_id,
            authorization_ids: rec.body.authorization_ids.clone(),
            job_id: j.id.clone(),
            project: j.project.clone(),
            purpose_id: j.binding.purpose_id.clone(),
            governance_id: j.governance_id.clone(),
            plan_id: j.plan_hash.clone(),
            execution_spec_id: spec.id().hex(),
            policy_id: spec.policy_id.clone(),
            workload_or_recipient: export_key,
            recipient: Some(recipient.to_owned()),
            placement_digest: j.binding.placement_digest.clone(),
            execution_spec: spec,
            binding: j.binding.clone(),
            not_before: at,
            not_after: until,
            anchor_counter: self.anchor.snapshot().counter,
            issuer: String::new(),
            issuer_public_key: String::new(),
            signature: String::new(),
        })
    }
}
