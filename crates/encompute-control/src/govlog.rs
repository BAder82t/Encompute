//! The governance event log: one append-only event per security-negative
//! governance transition, written in the same transaction as the change
//! (schema version 13). The formats, trees and proofs are
//! `encompute_trust::govlog`.
//!
//! Every event goes to one partition: `p:<project>` for a governed
//! project's transitions, `o:<organization>` for an organization's (and for
//! everything of a standard project, which stays as it was), `platform`
//! otherwise. A governance-key revocation goes to its organization and to
//! each governed project the organization takes part in.
//!
//! Lock order: `governance_head` is taken immediately before `audit_head`,
//! which stays last (`audit::append` takes the governance head first), so
//! an event and an audit event recorded in one transaction, in either
//! order, lock the heads in the same order. Rows the transition changes
//! are locked before both.
//!
//! The database refuses to update, delete or truncate the log (schema
//! version 13's triggers). That does not stop a database superuser or the
//! tables' owner, who can disable triggers, as with the audit chain: the
//! anchored head and the members' witnessed checkpoints are what detect
//! such edits.
//!
//! The log is recorded alongside the state anchor's sets for now: nothing
//! reads it to decide yet.

use std::collections::{BTreeMap, HashMap};

use postgres::GenericClient;

use encompute_ir::{Code, Error, Result};
use encompute_trust::govlog::{
    chain_hash, completed_nodes, hash_hex, parse_hash, root_with, ConsistencyProof, GovEvent, Hash,
    InclusionProof, Nodes, Partition, ProjectCheckpoint, SignedProjectCheckpoint, GOVLOG_VERSION,
};
use encompute_verification::service::ServiceSigner;

use crate::db::db_err;
use crate::model::PLATFORM_ORG;

pub use encompute_trust::govlog::kind;

fn log_err(m: impl Into<String>) -> Error {
    Error::new(Code::TrustEvidence, m)
}

/// An event to record.
#[derive(Clone, Debug)]
pub struct Draft {
    pub partition: Partition,
    pub kind: &'static str,
    pub subject: String,
    pub org: Option<String>,
    pub refs: BTreeMap<String, String>,
}

impl Draft {
    pub fn new(partition: Partition, kind: &'static str, subject: &str) -> Self {
        Self {
            partition,
            kind,
            subject: subject.to_owned(),
            org: None,
            refs: BTreeMap::new(),
        }
    }

    pub fn org(mut self, org: &str) -> Self {
        self.org = Some(org.to_owned());
        self
    }

    pub fn r#ref(mut self, k: &str, v: impl Into<String>) -> Self {
        self.refs.insert(k.to_owned(), v.into());
        self
    }
}

/// A recorded event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded {
    pub gseq: i64,
    pub event: GovEvent,
    pub leaf_hash: String,
    pub hash: String,
}

/// The partition of an organization's own transitions (the platform's for
/// none, or the platform organization).
pub fn for_org(org: Option<&str>) -> Partition {
    match org {
        Some(o) if o != PLATFORM_ORG => Partition::Organization(o.to_owned()),
        _ => Partition::Platform,
    }
}

/// The partition of a transition in `project`: the project's own when it
/// is governed, otherwise `org`'s (the project owner's when `None`).
pub fn for_project(
    c: &mut impl GenericClient,
    project: &str,
    org: Option<&str>,
) -> Result<Partition> {
    let r = c
        .query_opt(
            "SELECT governance, organization_id FROM projects WHERE id = $1",
            &[&project],
        )
        .map_err(db_err)?;
    Ok(match r {
        Some(r) if r.get::<_, String>(0) == "governed" => Partition::Project(project.to_owned()),
        Some(r) => for_org(Some(org.unwrap_or(&r.get::<_, String>(1)))),
        None => for_org(org),
    })
}

/// The governed projects `org` takes part in (as owner, member, invitee or
/// auditor), in order.
pub fn governed_projects_of(c: &mut impl GenericClient, org: &str) -> Result<Vec<String>> {
    Ok(c.query(
        "SELECT p.id FROM projects p
              WHERE p.governance = 'governed'
                AND (p.organization_id = $1
                     OR EXISTS (SELECT 1 FROM project_members m
                                 WHERE m.project_id = p.id AND m.organization_id = $1))
              ORDER BY p.id",
        &[&org],
    )
    .map_err(db_err)?
    .iter()
    .map(|r| r.get(0))
    .collect())
}

/// Complete subtrees of one partition, read from the database.
struct DbNodes<'a, C: GenericClient> {
    c: &'a mut C,
    partition: &'a str,
}

impl<C: GenericClient> Nodes for DbNodes<'_, C> {
    fn node(&mut self, level: u32, index: u64) -> Result<Hash> {
        let (level, idx) = (level as i32, index as i64);
        let h: String = self
            .c
            .query_opt(
                "SELECT hash FROM governance_tree_nodes WHERE partition = $1 AND level = $2 AND idx = $3",
                &[&self.partition, &level, &idx],
            )
            .map_err(db_err)?
            .ok_or_else(|| {
                log_err(format!(
                    "the governance log's tree node {level}/{idx} of {} is missing",
                    self.partition
                ))
            })?
            .get(0);
        parse_hash("tree node", &h)
    }
}

/// Locks the chain head (see the lock order above): its position and hash.
pub fn lock_head(t: &mut impl GenericClient) -> Result<(i64, String)> {
    let r = t
        .query_one(
            "SELECT gseq, hash FROM governance_head WHERE id FOR UPDATE",
            &[],
        )
        .map_err(db_err)?;
    Ok((r.get(0), r.get(1)))
}

fn now_secs() -> u64 {
    encompute_verification::service::now()
}

/// Appends one event inside the caller's transaction.
pub fn append(t: &mut impl GenericClient, d: Draft) -> Result<Recorded> {
    let (head, prev) = lock_head(t)?;
    let partition = d.partition.to_string();
    let pseq: i64 = t
        .query_one(
            "SELECT COALESCE(max(pseq), 0) + 1 FROM governance_events WHERE partition = $1",
            &[&partition],
        )
        .map_err(db_err)?
        .get(0);
    let event = GovEvent {
        v: GOVLOG_VERSION,
        partition: partition.clone(),
        pseq: pseq as u64,
        kind: d.kind.to_owned(),
        subject: d.subject,
        org: d.org,
        at: now_secs(),
        refs: d.refs,
    };
    let leaf = event.leaf_hash()?;
    let gseq = head + 1;
    let hash = chain_hash(
        &parse_hash("governance log head", &prev)?,
        gseq as u64,
        &leaf,
    );
    let (leaf_hex, hash_hex_) = (hash_hex(&leaf), hash_hex(&hash));
    t.execute(
        "INSERT INTO governance_events (gseq, partition, pseq, kind, subject_id, org_id, body,
             leaf_hash, prev_hash, hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        &[
            &gseq,
            &partition,
            &pseq,
            &event.kind,
            &event.subject,
            &event.org,
            &serde_json::to_value(&event).map_err(db_err)?,
            &leaf_hex,
            &prev,
            &hash_hex_,
        ],
    )
    .map_err(db_err)?;
    let nodes = completed_nodes(
        event.leaf_index(),
        leaf,
        &mut DbNodes {
            c: t,
            partition: &partition,
        },
    )?;
    for (level, idx, h) in nodes {
        t.execute(
            "INSERT INTO governance_tree_nodes (partition, level, idx, hash) VALUES ($1, $2, $3, $4)",
            &[&partition, &(level as i32), &(idx as i64), &hash_hex(&h)],
        )
        .map_err(db_err)?;
    }
    t.execute(
        "UPDATE governance_head SET gseq = $1, hash = $2 WHERE id",
        &[&gseq, &hash_hex_],
    )
    .map_err(db_err)?;
    Ok(Recorded {
        gseq,
        event,
        leaf_hash: leaf_hex,
        hash: hash_hex_,
    })
}

/// The governed projects that use `asset`: one where an authorization
/// names it or a result derived from it, or where a job read it or a
/// result derived from it (through any number of derivations), or where
/// such a result was derived. In order.
pub fn governed_projects_using_asset(
    c: &mut impl GenericClient,
    asset: &str,
) -> Result<Vec<String>> {
    Ok(c.query(
        "WITH RECURSIVE d(id) AS (
                 SELECT $1::text
                 UNION
                 SELECT x.id FROM assets x JOIN d ON x.parents ? d.id
                  WHERE x.derived_from_job IS NOT NULL
             )
             SELECT p.id FROM projects p
              WHERE p.governance = 'governed'
                AND (EXISTS (SELECT 1 FROM authorizations a JOIN d ON a.asset_id = d.id
                              WHERE a.project_id = p.id)
                     OR EXISTS (SELECT 1 FROM jobs j JOIN d ON j.source_assets ? d.id
                                 WHERE j.project_id = p.id)
                     OR EXISTS (SELECT 1 FROM assets x JOIN d ON x.id = d.id
                                  JOIN jobs j ON j.id = x.derived_from_job
                                 WHERE j.project_id = p.id))
              ORDER BY p.id",
        &[&asset],
    )
    .map_err(db_err)?
    .iter()
    .map(|r| r.get(0))
    .collect())
}

/// Appends an asset's revocation or expiry (`kind`): to its owner's
/// partition and to each governed project that uses it
/// ([`governed_projects_using_asset`]), so their members and auditors see
/// it in the project's log.
pub fn append_asset_event(
    t: &mut impl GenericClient,
    kind: &'static str,
    asset: &str,
    owner: &str,
) -> Result<Vec<Recorded>> {
    let mut partitions = vec![for_org(Some(owner))];
    for p in governed_projects_using_asset(t, asset)? {
        partitions.push(Partition::Project(p));
    }
    let mut out = vec![];
    for p in partitions {
        out.push(append(t, Draft::new(p, kind, asset).org(owner))?);
    }
    Ok(out)
}

/// Appends a governance-key revocation: to the organization's partition
/// and to each governed project it takes part in.
pub fn append_key_revocation(
    t: &mut impl GenericClient,
    org: &str,
    key_row: &str,
    key_id: &str,
) -> Result<Vec<Recorded>> {
    let mut out = vec![];
    let mut partitions = vec![for_org(Some(org))];
    for p in governed_projects_of(t, org)? {
        partitions.push(Partition::Project(p));
    }
    for p in partitions {
        out.push(append(
            t,
            Draft::new(p, kind::GOVERNANCE_KEY_REVOKED, key_row)
                .org(org)
                .r#ref("key_id", key_id),
        )?);
    }
    Ok(out)
}

/// Recomputes the whole log: every event's body against its columns, its
/// leaf hash and level-0 node, each partition's positions, the chain's
/// links and hashes, and the head. Returns (last gseq, head hash).
pub fn verify_chain(c: &mut impl GenericClient) -> Result<(i64, String)> {
    let mut prev = hash_hex(&encompute_trust::govlog::CHAIN_GENESIS);
    let mut gseq = 0i64;
    let mut pseqs: HashMap<String, i64> = HashMap::new();
    loop {
        let rows = c
            .query(
                "SELECT e.gseq, e.partition, e.pseq, e.kind, e.subject_id, e.org_id, e.body,
                        e.leaf_hash, e.prev_hash, e.hash, n.hash
                   FROM governance_events e
                   LEFT JOIN governance_tree_nodes n
                     ON n.partition = e.partition AND n.level = 0 AND n.idx = e.pseq - 1
                  WHERE e.gseq > $1 ORDER BY e.gseq LIMIT 1000",
                &[&gseq],
            )
            .map_err(db_err)?;
        if rows.is_empty() {
            break;
        }
        for r in &rows {
            let g: i64 = r.get(0);
            let bad = |what: &str| log_err(format!("governance event {g}: {what}"));
            if g != gseq + 1 {
                return Err(bad("out of order or missing events before it"));
            }
            let e: GovEvent =
                serde_json::from_value(r.get(6)).map_err(|e| bad(&format!("body: {e}")))?;
            let (partition, pseq): (String, i64) = (r.get(1), r.get(2));
            if e.partition != partition
                || e.pseq as i64 != pseq
                || e.kind != r.get::<_, String>(3)
                || e.subject != r.get::<_, String>(4)
                || e.org != r.get::<_, Option<String>>(5)
            {
                return Err(bad("its columns differ from its body"));
            }
            let last = pseqs.entry(partition).or_insert(0);
            if pseq != *last + 1 {
                return Err(bad("its partition's positions are not contiguous"));
            }
            *last = pseq;
            let leaf = e.leaf_hash()?;
            let leaf_hex = hash_hex(&leaf);
            if r.get::<_, String>(7) != leaf_hex
                || r.get::<_, Option<String>>(10).as_deref() != Some(leaf_hex.as_str())
            {
                return Err(bad("modified (its leaf hash differs)"));
            }
            if r.get::<_, String>(8) != prev {
                return Err(bad("not chained to the event before it"));
            }
            let h = hash_hex(&chain_hash(
                &parse_hash("previous hash", &prev)?,
                g as u64,
                &leaf,
            ));
            if r.get::<_, String>(9) != h {
                return Err(bad("modified (its chain hash differs)"));
            }
            prev = h;
            gseq = g;
        }
    }
    let head = c
        .query_one("SELECT gseq, hash FROM governance_head WHERE id", &[])
        .map_err(db_err)?;
    if head.get::<_, i64>(0) != gseq || head.get::<_, String>(1) != prev {
        return Err(log_err("the governance log head does not match the chain"));
    }
    Ok((gseq, prev))
}

/// The subjects of every event of `kind` (for example the revoked
/// authorizations), in order.
pub fn negative_ids(c: &mut impl GenericClient, kind: &str) -> Result<Vec<String>> {
    Ok(c.query(
        "SELECT DISTINCT subject_id FROM governance_events WHERE kind = $1 ORDER BY 1",
        &[&kind],
    )
    .map_err(db_err)?
    .iter()
    .map(|r| r.get(0))
    .collect())
}

/// The number of events in `partition`.
pub fn partition_size(c: &mut impl GenericClient, partition: &str) -> Result<u64> {
    let n: i64 = c
        .query_one(
            "SELECT COALESCE(max(pseq), 0) FROM governance_events WHERE partition = $1",
            &[&partition],
        )
        .map_err(db_err)?
        .get(0);
    Ok(n as u64)
}

/// The root of the first `size` events of `partition`.
pub fn partition_root(c: &mut impl GenericClient, partition: &str, size: u64) -> Result<Hash> {
    root_with(size, &mut DbNodes { c, partition })
}

/// Signs and stores a checkpoint of `partition` as it now stands (the one
/// already stored at that size, if any; a stored one with another root is
/// refused).
pub fn checkpoint_partition(
    t: &mut impl GenericClient,
    signer: &ServiceSigner,
    partition: &str,
) -> Result<SignedProjectCheckpoint> {
    Partition::parse(partition)?;
    lock_head(t)?;
    let size = partition_size(t, partition)?;
    let root = hash_hex(&partition_root(t, partition, size)?);
    if let Some(r) = t
        .query_opt(
            "SELECT root, signed FROM governance_checkpoints WHERE partition = $1 AND size = $2",
            &[&partition, &(size as i64)],
        )
        .map_err(db_err)?
    {
        if r.get::<_, String>(0) != root {
            return Err(log_err(format!(
                "the stored checkpoint of {partition} at size {size} has another root"
            )));
        }
        return serde_json::from_value(r.get(1)).map_err(db_err);
    }
    let gseq: i64 = t
        .query_one(
            "SELECT COALESCE(max(gseq), 0) FROM governance_events WHERE partition = $1",
            &[&partition],
        )
        .map_err(db_err)?
        .get(0);
    let cp = ProjectCheckpoint {
        version: GOVLOG_VERSION,
        partition: partition.to_owned(),
        size,
        root: root.clone(),
        gseq: gseq as u64,
        at: now_secs(),
    }
    .sign(signer)?;
    t.execute(
        "INSERT INTO governance_checkpoints (partition, size, root, gseq, signed)
         VALUES ($1, $2, $3, $4, $5)",
        &[
            &partition,
            &(size as i64),
            &root,
            &gseq,
            &serde_json::to_value(&cp).map_err(db_err)?,
        ],
    )
    .map_err(db_err)?;
    Ok(cp)
}

/// The inclusion proof of event `pseq` of `partition` in its first `size`
/// events.
pub fn prove(
    c: &mut impl GenericClient,
    partition: &str,
    pseq: u64,
    size: u64,
) -> Result<InclusionProof> {
    if pseq == 0 || size > partition_size(c, partition)? {
        return Err(log_err("no such event or tree size"));
    }
    InclusionProof::build(partition, pseq - 1, size, &mut DbNodes { c, partition })
}

/// The consistency proof between the first `first` and the first `second`
/// events of `partition`.
pub fn prove_consistency(
    c: &mut impl GenericClient,
    partition: &str,
    first: u64,
    second: u64,
) -> Result<ConsistencyProof> {
    if second > partition_size(c, partition)? {
        return Err(log_err("no such tree size"));
    }
    ConsistencyProof::build(partition, first, second, &mut DbNodes { c, partition })
}

/// The events of `partition` after position `after`, in order.
pub fn events(
    c: &mut impl GenericClient,
    partition: &str,
    after: u64,
    limit: i64,
) -> Result<Vec<GovEvent>> {
    c.query(
        "SELECT body FROM governance_events WHERE partition = $1 AND pseq > $2 ORDER BY pseq LIMIT $3",
        &[&partition, &(after as i64), &limit],
    )
    .map_err(db_err)?
    .iter()
    .map(|r| serde_json::from_value(r.get(0)).map_err(db_err))
    .collect()
}
