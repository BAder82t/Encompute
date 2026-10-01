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
//! The state anchor holds the log's size and head (`checkpoint_log`): at
//! every start the database's log must contain the anchored head at the
//! anchored size, and the security-negative state the log records (its
//! [`NegSet`]s) must still hold in the database. The anchor's size no
//! longer grows with them.

use std::collections::{BTreeMap, HashMap};

use postgres::types::Type;
use postgres::GenericClient;

use encompute_ir::{Code, Error, Result};
use encompute_trust::govlog::{
    chain_hash, completed_nodes, hash_hex, parse_hash, root_with, ConsistencyProof, GovEvent, Hash,
    InclusionProof, Nodes, Partition, ProjectCheckpoint, SignedCheckpointWitness,
    SignedProjectCheckpoint, GOVLOG_VERSION,
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
    pub kind: String,
    pub subject: String,
    pub org: Option<String>,
    pub refs: BTreeMap<String, String>,
}

impl Draft {
    pub fn new(partition: Partition, kind: &str, subject: &str) -> Self {
        Self {
            partition,
            kind: kind.to_owned(),
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

thread_local! {
    /// Set when a security deny event was appended (anything but an issued
    /// authorization or the migration's own events): the transaction that
    /// appended it is followed by a synchronous checkpoint
    /// ([`crate::Control::tx_anchored`]), so no deny transition is
    /// acknowledged before it is anchored, whichever path made it.
    ///
    /// Per thread: the transaction and its caller run on one thread.
    pub static DENY_PENDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A checkpoint that failed after a deny transition committed: the next
    /// `tx_anchored` call on this thread settles it (the background task
    /// anchors it otherwise).
    pub static RETRY_CHECKPOINT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn is_deny(kind: &str) -> bool {
    kind != kind::AUTHORIZATION_ISSUED
        && kind != kind::MEMBERSHIP_ADDED
        && kind != kind::REVOCATION_HEAD_SIGNED
        && kind != extra_kind::ANCHOR_GENESIS
        && !kind.starts_with(extra_kind::MIGRATED)
}

/// Appends one event inside the caller's transaction.
///
/// Two round trips, each a single typed statement (no separate prepare):
/// the head locked, with the partition's size and the complete subtrees
/// on its right edge (all the new leaf can need), then one statement
/// writing the event, the subtrees it completes and the head.
pub fn append(t: &mut impl GenericClient, d: Draft) -> Result<Recorded> {
    let partition = d.partition.to_string();
    let r = t
        .query_typed_one(
            "SELECT h.gseq, h.hash, s.n,
                    ARRAY(SELECT x.level::text || ':' || x.hash FROM governance_tree_nodes x
                           WHERE x.partition = $1
                             AND (x.level, x.idx) IN (SELECT l, (s.n >> l) - 1 FROM generate_series(0, 62) AS l
                                                       WHERE ((s.n >> l) & 1) = 1))
               FROM governance_head h
               CROSS JOIN LATERAL (SELECT COALESCE(max(e.pseq), 0) AS n FROM governance_events e
                                    WHERE e.partition = $1) s
              WHERE h.id FOR UPDATE OF h",
            &[(&partition, Type::TEXT)],
        )
        .map_err(db_err)?;
    let (head, prev, size, edge): (i64, String, i64, Vec<String>) =
        (r.get(0), r.get(1), r.get(2), r.get(3));
    let mut siblings = HashMap::new();
    for x in edge {
        let (l, h) = x
            .split_once(':')
            .ok_or_else(|| log_err("malformed tree node"))?;
        let l: u32 = l.parse().map_err(|_| log_err("malformed tree node"))?;
        siblings.insert((l, ((size as u64) >> l) - 1), parse_hash("tree node", h)?);
    }
    let event = GovEvent {
        v: GOVLOG_VERSION,
        partition,
        pseq: size as u64 + 1,
        kind: d.kind,
        subject: d.subject,
        org: d.org,
        at: now_secs(),
        refs: d.refs,
    };
    if is_deny(&event.kind) {
        DENY_PENDING.with(|d| d.set(true));
    }
    insert(t, head + 1, &prev, event, Some(siblings))
}

/// The complete subtrees a leaf at `index` needs to complete its
/// ancestors: the left sibling at each level where it is a right child.
struct Siblings(HashMap<(u32, u64), Hash>);

impl Nodes for Siblings {
    fn node(&mut self, level: u32, index: u64) -> Result<Hash> {
        self.0.get(&(level, index)).copied().ok_or_else(|| {
            log_err(format!(
                "the governance log's tree node {level}/{index} is missing"
            ))
        })
    }
}

/// Writes `event` as event `gseq` after the head `prev` (locked by the
/// caller): its row, its partition's completed subtrees, the head.
/// `siblings`: the partition's right-edge subtrees when the caller read
/// them already, otherwise they are read here.
fn insert(
    t: &mut impl GenericClient,
    gseq: i64,
    prev: &str,
    event: GovEvent,
    siblings: Option<HashMap<(u32, u64), Hash>>,
) -> Result<Recorded> {
    let partition = event.partition.clone();
    let leaf = event.leaf_hash()?;
    let hash = chain_hash(
        &parse_hash("governance log head", prev)?,
        gseq as u64,
        &leaf,
    );
    let (leaf_hex, hash_hex_) = (hash_hex(&leaf), hash_hex(&hash));
    // The left siblings the leaf completes, read in one statement.
    let (mut levels, mut idxs) = (vec![], vec![]);
    let mut i = event.leaf_index();
    let mut level = 0i32;
    while i % 2 == 1 {
        levels.push(level);
        idxs.push((i - 1) as i64);
        i /= 2;
        level += 1;
    }
    let known = siblings.is_some();
    let mut siblings = siblings.unwrap_or_default();
    if !levels.is_empty() && !known {
        for r in t
            .query_typed(
                "SELECT n.level, n.idx, n.hash FROM governance_tree_nodes n
                   JOIN unnest($2, $3) AS w(level, idx) ON w.level = n.level AND w.idx = n.idx
                  WHERE n.partition = $1",
                &[
                    (&partition, Type::TEXT),
                    (&levels, Type::INT4_ARRAY),
                    (&idxs, Type::INT8_ARRAY),
                ],
            )
            .map_err(db_err)?
        {
            let (l, x, h): (i32, i64, String) = (r.get(0), r.get(1), r.get(2));
            siblings.insert((l as u32, x as u64), parse_hash("tree node", &h)?);
        }
    }
    let nodes = completed_nodes(event.leaf_index(), leaf, &mut Siblings(siblings))?;
    let n_levels: Vec<i32> = nodes.iter().map(|(l, _, _)| *l as i32).collect();
    let n_idxs: Vec<i64> = nodes.iter().map(|(_, x, _)| *x as i64).collect();
    let n_hashes: Vec<String> = nodes.iter().map(|(_, _, h)| hash_hex(h)).collect();
    let body = serde_json::to_value(&event).map_err(db_err)?;
    let pseq = event.pseq as i64;
    t.query_typed(
        "WITH e AS (
             INSERT INTO governance_events (gseq, partition, pseq, kind, subject_id, org_id, body,
                 leaf_hash, prev_hash, hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)),
         n AS (
             INSERT INTO governance_tree_nodes (partition, level, idx, hash)
             SELECT $2, u.level, u.idx, u.hash FROM unnest($11, $12, $13) AS u(level, idx, hash))
         UPDATE governance_head SET gseq = $1, hash = $10 WHERE id",
        &[
            (&gseq, Type::INT8),
            (&partition, Type::TEXT),
            (&pseq, Type::INT8),
            (&event.kind, Type::TEXT),
            (&event.subject, Type::TEXT),
            (&event.org, Type::TEXT),
            (&body, Type::JSONB),
            (&leaf_hex, Type::TEXT),
            (&prev, Type::TEXT),
            (&hash_hex_, Type::TEXT),
            (&n_levels, Type::INT4_ARRAY),
            (&n_idxs, Type::INT8_ARRAY),
            (&n_hashes, Type::TEXT_ARRAY),
        ],
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
    verify_from(c, 0, &hash_hex(&encompute_trust::govlog::CHAIN_GENESIS))
}

/// The chain hash of event `gseq` (the empty log's head for 0), if the
/// database holds it.
pub fn hash_at(c: &mut impl GenericClient, gseq: i64) -> Result<Option<String>> {
    if gseq == 0 {
        return Ok(Some(hash_hex(&encompute_trust::govlog::CHAIN_GENESIS)));
    }
    Ok(c.query_opt(
        "SELECT hash FROM governance_events WHERE gseq = $1",
        &[&gseq],
    )
    .map_err(db_err)?
    .map(|r| r.get(0)))
}

/// Like [`verify_chain`] for the events after `from`, whose chain hash
/// must be `from_hash`: the log extends that head. Returns (last gseq,
/// head hash).
pub fn verify_from(
    c: &mut impl GenericClient,
    from: i64,
    from_hash: &str,
) -> Result<(i64, String)> {
    if from < 0 || hash_at(c, from)?.as_deref() != Some(from_hash) {
        return Err(log_err(format!(
            "the governance log does not hold the anchored head at event {from}"
        )));
    }
    let mut prev = from_hash.to_owned();
    let mut gseq = from;
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
            let last = match pseqs.get(&partition) {
                Some(p) => *p,
                None if from == 0 => 0,
                None => c
                    .query_one(
                        "SELECT COALESCE(max(pseq), 0) FROM governance_events
                          WHERE partition = $1 AND gseq <= $2",
                        &[&partition, &from],
                    )
                    .map_err(db_err)?
                    .get(0),
            };
            if pseq != last + 1 {
                return Err(bad("its partition's positions are not contiguous"));
            }
            pseqs.insert(partition, pseq);
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

/// Checkpoints the log as it extends the anchored head (`size`, `head`):
/// the events after it link and hash correctly, and each partition they
/// touched gets a signed checkpoint. Under the log's head lock (appends
/// wait). Returns the new (size, head); a log that does not extend the
/// anchored head is an error (`Code::TrustEvidence`), and nothing is
/// signed.
pub fn checkpoint_extending(
    t: &mut impl GenericClient,
    signer: &ServiceSigner,
    size: i64,
    head: &str,
) -> Result<(i64, String)> {
    lock_head(t)?;
    let (n, h) = verify_from(t, size, head)?;
    if n > size {
        let dirty: Vec<String> = t
            .query(
                "SELECT DISTINCT partition FROM governance_events WHERE gseq > $1 ORDER BY 1",
                &[&size],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        for p in dirty {
            checkpoint_partition(t, signer, &p)?;
        }
    }
    Ok((n, h))
}

/// The latest signed checkpoint of every partition: (partition, size,
/// root, signed).
pub fn latest_checkpoints(
    c: &mut impl GenericClient,
) -> Result<Vec<(String, i64, String, serde_json::Value)>> {
    Ok(c.query(
        "SELECT DISTINCT ON (partition) partition, size, root, signed
           FROM governance_checkpoints ORDER BY partition, size DESC",
        &[],
    )
    .map_err(db_err)?
    .iter()
    .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
    .collect())
}

// --- security-negative sets ------------------------------------------------------

/// Kinds written by recovery and by the migration of a version-1 anchor.
pub mod extra_kind {
    /// The migration's first event: the version-1 anchor's digest.
    pub const ANCHOR_GENESIS: &str = "anchor.genesis";
    /// A privacy ledger frozen after a detected rollback.
    pub const LEDGER_FROZEN: &str = "ledger.frozen";
    /// A row of a security-negative set the database lost, acknowledged by
    /// recovery (`refs.state` names the set).
    pub const ROW_LOST: &str = "row.lost";
    /// The suffix of a transition recovery applied again.
    pub const REAPPLIED: &str = ".reapplied";
    /// The prefix of an ID a version-1 anchor's set held.
    pub const MIGRATED: &str = "migrated.";
}

/// A security-negative set: the IDs whose transition the database must
/// never show undone. The log is its record: each set is the subjects of
/// its kinds (the transition, recovery's re-application, the migrated
/// version-1 set).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NegSet {
    RevokedAssets,
    DisabledServices,
    DisabledUsers,
    EndedJobs,
    WithdrawnGrants,
    RemovedMemberships,
    RemovedRoles,
    RevokedAuthorizations,
    ExpiredAssets,
    RetiredPurposes,
    RevokedKeys,
    FrozenLedgers,
}

impl NegSet {
    pub const ALL: [NegSet; 12] = [
        NegSet::RevokedAssets,
        NegSet::DisabledServices,
        NegSet::DisabledUsers,
        NegSet::EndedJobs,
        NegSet::WithdrawnGrants,
        NegSet::RemovedMemberships,
        NegSet::RemovedRoles,
        NegSet::RevokedAuthorizations,
        NegSet::ExpiredAssets,
        NegSet::RetiredPurposes,
        NegSet::RevokedKeys,
        NegSet::FrozenLedgers,
    ];

    /// Its name: the version-1 anchor's field (`migrated.<name>`).
    pub fn name(self) -> &'static str {
        match self {
            NegSet::RevokedAssets => "revoked",
            NegSet::DisabledServices => "disabled_services",
            NegSet::DisabledUsers => "disabled_users",
            NegSet::EndedJobs => "ended_jobs",
            NegSet::WithdrawnGrants => "withdrawn_grants",
            NegSet::RemovedMemberships => "removed_memberships",
            NegSet::RemovedRoles => "removed_roles",
            NegSet::RevokedAuthorizations => "revoked_authorizations",
            NegSet::ExpiredAssets => "expired_assets",
            NegSet::RetiredPurposes => "retired_purposes",
            NegSet::RevokedKeys => "revoked_governance_keys",
            NegSet::FrozenLedgers => "frozen",
        }
    }

    /// The state a rollback refusal names.
    pub fn state(self) -> &'static str {
        match self {
            NegSet::RevokedAssets => "REVOCATION",
            NegSet::DisabledServices => "SERVICE ACCOUNT",
            NegSet::DisabledUsers => "USER",
            NegSet::EndedJobs => "JOB",
            NegSet::WithdrawnGrants => "APPROVAL",
            NegSet::RemovedMemberships => "MEMBERSHIP",
            NegSet::RemovedRoles => "ROLE",
            NegSet::RevokedAuthorizations => "AUTHORIZATION",
            NegSet::ExpiredAssets => "EXPIRY",
            NegSet::RetiredPurposes => "PURPOSE",
            NegSet::RevokedKeys => "GOVERNANCE KEY",
            NegSet::FrozenLedgers => "FREEZE",
        }
    }

    /// The `refs.state` of its `row.lost` events (what version 1 wrote
    /// before the colon of a lost row).
    pub fn lost_state(self) -> String {
        self.state().to_lowercase().replace(' ', "_")
    }

    /// The transitions that put an ID in it.
    pub fn transition_kinds(self) -> &'static [&'static str] {
        match self {
            NegSet::RevokedAssets => &[kind::ASSET_REVOKED],
            NegSet::DisabledServices => &[kind::SERVICE_ACCOUNT_DISABLED],
            NegSet::DisabledUsers => &[kind::USER_DISABLED],
            NegSet::EndedJobs => &[kind::JOB_FAILED, kind::JOB_CANCELLED],
            NegSet::WithdrawnGrants => &[kind::GRANT_WITHDRAWN],
            NegSet::RemovedMemberships => &[kind::MEMBERSHIP_REMOVED],
            NegSet::RemovedRoles => &[kind::ROLE_REMOVED],
            NegSet::RevokedAuthorizations => &[kind::AUTHORIZATION_REVOKED],
            NegSet::ExpiredAssets => &[kind::ASSET_EXPIRED],
            NegSet::RetiredPurposes => &[kind::PURPOSE_RETIRED],
            NegSet::RevokedKeys => &[kind::GOVERNANCE_KEY_REVOKED],
            NegSet::FrozenLedgers => &[extra_kind::LEDGER_FROZEN],
        }
    }

    /// The kind recovery writes when it applies the transition again.
    pub fn reapplied_kind(self) -> String {
        format!("{}{}", self.transition_kinds()[0], extra_kind::REAPPLIED)
    }

    /// The kind of an ID migrated from a version-1 anchor's set (a frozen
    /// ledger migrates as `ledger.frozen`).
    pub fn migrated_kind(self) -> String {
        match self {
            NegSet::FrozenLedgers => extra_kind::LEDGER_FROZEN.to_owned(),
            s => format!("{}{}", extra_kind::MIGRATED, s.name()),
        }
    }

    /// Every kind whose subjects are in it.
    pub fn kinds(self) -> Vec<String> {
        let mut k: Vec<String> = self
            .transition_kinds()
            .iter()
            .map(|x| x.to_string())
            .collect();
        k.extend(
            self.transition_kinds()
                .iter()
                .map(|x| format!("{x}{}", extra_kind::REAPPLIED)),
        );
        k.push(self.migrated_kind());
        k.sort();
        k.dedup();
        k
    }

    /// A query of its IDs, with its kinds as `$1`: the subjects, and for a
    /// revoked authorization also the signed document's ID (a document
    /// stays revoked whatever row carries it).
    pub fn ids_sql(self) -> &'static str {
        match self {
            NegSet::RevokedAuthorizations => {
                "SELECT subject_id FROM governance_events WHERE kind = ANY($1)
                 UNION SELECT body #>> '{refs,authorization_id}' FROM governance_events
                  WHERE kind = ANY($1) AND body #>> '{refs,authorization_id}' IS NOT NULL"
            }
            _ => "SELECT subject_id FROM governance_events WHERE kind = ANY($1)",
        }
    }
}

/// The IDs of `set`, in order.
pub fn negative_set(c: &mut impl GenericClient, set: NegSet) -> Result<Vec<String>> {
    Ok(c.query(
        &format!(
            "SELECT DISTINCT x FROM ({}) AS s(x) ORDER BY 1",
            set.ids_sql()
        ),
        &[&set.kinds()],
    )
    .map_err(db_err)?
    .iter()
    .map(|r| r.get(0))
    .collect())
}

/// The condition that an event of `set` (kinds `$1`) names `x`: its
/// subject, or for a revoked authorization also its document's ID. Each
/// branch is an index lookup (kind and subject, or the document ID).
fn names(set: NegSet, x: &str) -> String {
    let doc = if set == NegSet::RevokedAuthorizations {
        format!(" OR e.body #>> '{{refs,authorization_id}}' = {x}")
    } else {
        String::new()
    };
    format!("e.kind = ANY($1) AND (e.subject_id = {x}{doc})")
}

/// The first of `ids` that is in `set`, if any (one query, an index lookup
/// per ID: run-time checks never scan the log).
pub fn first_in(c: &mut impl GenericClient, set: NegSet, ids: &[&str]) -> Result<Option<String>> {
    if ids.is_empty() {
        return Ok(None);
    }
    Ok(c.query_opt(
        &format!(
            "SELECT x FROM unnest($2::text[]) AS x
              WHERE EXISTS (SELECT 1 FROM governance_events e WHERE {})
              ORDER BY x LIMIT 1",
            names(set, "x")
        ),
        &[&set.kinds(), &ids],
    )
    .map_err(db_err)?
    .map(|r| r.get(0)))
}

/// Whether `id` is in `set`.
pub fn contains(c: &mut impl GenericClient, set: NegSet, id: &str) -> Result<bool> {
    Ok(first_in(c, set, &[id])?.is_some())
}

/// The first event that put `id` in `set` (its `gseq`), if any.
pub fn first_gseq(c: &mut impl GenericClient, set: NegSet, id: &str) -> Result<Option<i64>> {
    Ok(c.query_one(
        &format!(
            "SELECT min(e.gseq) FROM governance_events e WHERE {}",
            names(set, "$2")
        ),
        &[&set.kinds(), &id],
    )
    .map_err(db_err)?
    .get(0))
}

/// The partition (and organization) of an event about `id` in `set`,
/// from the rows the database holds: its project's when it has one (a
/// governed project's own, otherwise its organization's), its
/// organization's, or the platform's when neither is known.
pub fn route(
    t: &mut impl GenericClient,
    set: NegSet,
    id: &str,
) -> Result<(Partition, Option<String>)> {
    let one = |t: &mut _, sql: &str| -> Result<Option<(Option<String>, Option<String>)>> {
        Ok(GenericClient::query_opt(t, sql, &[&id])
            .map_err(db_err)?
            .map(|r| (r.get(0), r.get(1))))
    };
    let found = match set {
        NegSet::RevokedAssets | NegSet::ExpiredAssets | NegSet::FrozenLedgers => one(
            t,
            "SELECT NULL::text, organization_id FROM assets WHERE id = $1",
        )?,
        NegSet::DisabledServices => one(
            t,
            "SELECT NULL::text, organization_id FROM service_accounts WHERE id = $1",
        )?,
        NegSet::DisabledUsers => one(
            t,
            "SELECT NULL::text, organization_id FROM users WHERE id = $1",
        )?,
        NegSet::EndedJobs => one(
            t,
            "SELECT project_id, organization_id FROM jobs WHERE id = $1",
        )?,
        NegSet::WithdrawnGrants => one(
            t,
            "SELECT w.project_id, a.organization_id FROM withdrawn_grants w
               LEFT JOIN assets a ON a.id = w.asset_id WHERE w.id = $1",
        )?,
        NegSet::RemovedMemberships => one(
            t,
            "SELECT project_id, organization_id FROM removed_memberships WHERE id = $1",
        )?,
        NegSet::RemovedRoles => one(
            t,
            "SELECT NULL::text, organization_id FROM removed_roles WHERE id = $1",
        )?,
        NegSet::RevokedAuthorizations => one(
            t,
            "SELECT project_id, organization_id FROM authorizations
              WHERE id = $1 OR authorization_id = $1 ORDER BY id LIMIT 1",
        )?,
        NegSet::RetiredPurposes => one(
            t,
            "SELECT project_id, organization_id FROM purposes WHERE id = $1",
        )?,
        NegSet::RevokedKeys => one(
            t,
            "SELECT NULL::text, organization_id FROM governance_keys WHERE id = $1",
        )?,
    };
    Ok(match found {
        Some((Some(project), org)) => (for_project(t, &project, org.as_deref())?, org),
        Some((None, org)) => (for_org(org.as_deref()), org),
        None => (Partition::Platform, None),
    })
}

/// Every partition an event about `id` in `set` goes to: [`route`]'s,
/// and for an asset's revocation, expiry or frozen ledger also each
/// governed project that uses it ([`governed_projects_using_asset`]), as
/// [`append_asset_event`] does.
pub fn routes(
    t: &mut impl GenericClient,
    set: NegSet,
    id: &str,
) -> Result<Vec<(Partition, Option<String>)>> {
    let first = route(t, set, id)?;
    let mut out = vec![first.clone()];
    if matches!(
        set,
        NegSet::RevokedAssets | NegSet::ExpiredAssets | NegSet::FrozenLedgers
    ) {
        for p in governed_projects_using_asset(t, id)? {
            let p = Partition::Project(p);
            if p != first.0 {
                out.push((p, first.1.clone()));
            }
        }
    }
    Ok(out)
}

/// Appends `kind` about `id` of `set` to every partition [`routes`] names.
pub fn append_routed(
    t: &mut impl GenericClient,
    set: NegSet,
    kind: &str,
    id: &str,
    refs: &[(&str, &str)],
) -> Result<Vec<Recorded>> {
    let mut out = vec![];
    for (partition, org) in routes(t, set, id)? {
        let mut d = Draft::new(partition, kind, id);
        if let Some(o) = org {
            d = d.org(&o);
        }
        for (k, v) in refs {
            d = d.r#ref(k, *v);
        }
        out.push(append(t, d)?);
    }
    Ok(out)
}

/// Appends recovery's re-application of `set`'s transition of `id`
/// (to every partition [`routes`] names).
pub fn append_reapplied(
    t: &mut impl GenericClient,
    set: NegSet,
    id: &str,
    refs: &[(&str, &str)],
) -> Result<Vec<Recorded>> {
    append_routed(t, set, &set.reapplied_kind(), id, refs)
}

/// Appends that the database lost the row of `id` of `set`
/// (acknowledged by recovery; the ID stays blocked).
pub fn append_lost(t: &mut impl GenericClient, set: NegSet, id: &str) -> Result<Recorded> {
    append(
        t,
        Draft::new(Partition::Platform, extra_kind::ROW_LOST, id).r#ref("state", set.lost_state()),
    )
}

/// Whether recovery acknowledged that the database lost the row of `id`
/// of `set`.
pub fn is_lost(c: &mut impl GenericClient, set: NegSet, id: &str) -> Result<bool> {
    Ok(c.query_opt(
        "SELECT 1 FROM governance_events
          WHERE kind = $1 AND subject_id = $2 AND body #>> '{refs,state}' = $3 LIMIT 1",
        &[&extra_kind::ROW_LOST, &id, &set.lost_state()],
    )
    .map_err(db_err)?
    .is_some())
}

// --- migration from a version-1 anchor ------------------------------------------

/// The migration's genesis: (its gseq, the version-1 anchor's digest, its
/// canonical JSON), the latest if several.
pub fn genesis(c: &mut impl GenericClient) -> Result<Option<(i64, String, Option<String>)>> {
    Ok(c.query_opt(
        "SELECT e.gseq, e.body #>> '{refs,digest}', g.anchor FROM governance_events e
           LEFT JOIN governance_anchor_genesis g ON g.gseq = e.gseq
          WHERE e.kind = $1 ORDER BY e.gseq DESC LIMIT 1",
        &[&extra_kind::ANCHOR_GENESIS],
    )
    .map_err(db_err)?
    .map(|r| {
        (
            r.get(0),
            r.get::<_, Option<String>>(1).unwrap_or_default(),
            r.get(2),
        )
    }))
}

/// Appends the migration's genesis event (the version-1 anchor's digest
/// and counter; the anchor itself, signed, is kept beside it, outside the
/// shared leaf). Dropping or editing that copy is detected all the same:
/// every start requires the copy's SHA-256 to equal the digest the
/// genesis event (a leaf of the chain) and the signed version-2 anchor
/// both carry (`check_log_extends`).
pub fn append_genesis(
    t: &mut impl GenericClient,
    counter: u64,
    digest: &str,
    anchor: &str,
) -> Result<Recorded> {
    let r = append(
        t,
        Draft::new(
            Partition::Platform,
            extra_kind::ANCHOR_GENESIS,
            &format!("state-anchor-v1-{counter}"),
        )
        .r#ref("digest", digest)
        .r#ref("counter", counter.to_string()),
    )?;
    t.execute(
        "INSERT INTO governance_anchor_genesis (gseq, digest, anchor) VALUES ($1, $2, $3)",
        &[&r.gseq, &digest, &anchor],
    )
    .map_err(db_err)?;
    Ok(r)
}

// --- export and import ----------------------------------------------------------

/// One event of an export (`encompute-control export-governance-log`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exported {
    pub gseq: i64,
    pub hash: String,
    pub event: GovEvent,
    /// The version-1 anchor, for the migration's genesis event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
}

/// The events after `after`, as JSON lines.
pub fn export(c: &mut impl GenericClient, after: i64) -> Result<String> {
    to_lines(&exported(c, after, i64::MAX)?)
}

/// JSON lines of `events`.
pub fn to_lines(events: &[Exported]) -> Result<String> {
    let mut out = String::new();
    for x in events {
        out.push_str(&serde_json::to_string(x).map_err(db_err)?);
        out.push('\n');
    }
    Ok(out)
}

/// The events after `after`, up to `upto` (inclusive), in order.
pub fn exported(c: &mut impl GenericClient, after: i64, upto: i64) -> Result<Vec<Exported>> {
    let mut out = vec![];
    let mut from = after;
    loop {
        let rows = c
            .query(
                "SELECT e.gseq, e.hash, e.body, g.anchor FROM governance_events e
                   LEFT JOIN governance_anchor_genesis g ON g.gseq = e.gseq
                  WHERE e.gseq > $1 AND e.gseq <= $2 ORDER BY e.gseq LIMIT 1000",
                &[&from, &upto],
            )
            .map_err(db_err)?;
        if rows.is_empty() {
            return Ok(out);
        }
        for r in &rows {
            let x = Exported {
                gseq: r.get(0),
                hash: r.get(1),
                event: serde_json::from_value(r.get(2)).map_err(db_err)?,
                anchor: r.get(3),
            };
            from = x.gseq;
            out.push(x);
        }
    }
}

/// Appends the events of an export (JSON lines) that the database's log
/// lacks, in the caller's transaction. The database's own log must verify
/// and the export must continue it: its event at the database's head (if
/// it has one) must carry the same hash, and its events after it must
/// follow on without a gap, each recomputed (leaf, partition position,
/// chain hash) as it is written. Nothing in the export is trusted: the
/// caller checks that the result holds the anchored head. Returns how
/// many events were added.
pub fn import(t: &mut impl GenericClient, lines: &str) -> Result<u64> {
    let mut imp = Importer::new(t)?;
    for (n, line) in lines.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let x: Exported = serde_json::from_str(line)
            .map_err(|e| log_err(format!("governance log export, line {}: {e}", n + 1)))?;
        imp.push(t, &x)?;
    }
    Ok(imp.added)
}

/// Appends exported events one at a time (what [`import`] does per line),
/// so a caller can stream them from a store without holding them all.
pub struct Importer {
    head: i64,
    prev: String,
    first: bool,
    pub added: u64,
}

impl Importer {
    /// Verifies the database's own log and locks its head.
    pub fn new(t: &mut impl GenericClient) -> Result<Self> {
        let (head, prev) = verify_chain(t)?;
        lock_head(t)?;
        Ok(Self {
            head,
            prev,
            first: true,
            added: 0,
        })
    }

    /// Appends `x` if the database lacks it; every field is recomputed
    /// (leaf, partition position, chain hash). An event the database holds
    /// must be the same (checked at its head).
    pub fn push(&mut self, t: &mut impl GenericClient, x: &Exported) -> Result<()> {
        let bad = |m: &str| log_err(format!("governance log export, event {}: {m}", x.gseq));
        if self.first && x.gseq > self.head + 1 {
            return Err(bad(&format!(
                "the export starts after the database's last event ({}): events are missing",
                self.head
            )));
        }
        self.first = false;
        if x.gseq <= self.head {
            if x.gseq == self.head && x.hash != self.prev {
                return Err(bad(
                    "differs from the database's event there (another history)",
                ));
            }
            return Ok(());
        }
        if x.gseq != self.head + 1 {
            return Err(bad("out of order or missing events before it"));
        }
        let expected = partition_size(t, &x.event.partition)? + 1;
        if x.event.pseq != expected {
            return Err(bad("its partition's positions are not contiguous"));
        }
        let genesis = x.event.kind == extra_kind::ANCHOR_GENESIS;
        let r = insert(t, x.gseq, &self.prev, x.event.clone(), None)?;
        if r.hash != x.hash {
            return Err(bad("its hash does not match its contents and position"));
        }
        if let (true, Some(a)) = (genesis, &x.anchor) {
            let digest = x.event.refs.get("digest").cloned().unwrap_or_default();
            if encompute_verification::service::sha256_hex(a.as_bytes()) != digest {
                return Err(bad(
                    "the version-1 anchor does not match the genesis digest",
                ));
            }
            t.execute(
                "INSERT INTO governance_anchor_genesis (gseq, digest, anchor) VALUES ($1, $2, $3)",
                &[&r.gseq, &digest, a],
            )
            .map_err(db_err)?;
        }
        self.head = r.gseq;
        self.prev = r.hash;
        self.added += 1;
        Ok(())
    }
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

// --- a project's audit, checkpoints and witnesses ----------------------------------

/// The stored, signed checkpoint of `partition` at exactly `size`.
pub fn checkpoint_at(
    c: &mut impl GenericClient,
    partition: &str,
    size: u64,
) -> Result<Option<SignedProjectCheckpoint>> {
    c.query_opt(
        "SELECT signed FROM governance_checkpoints WHERE partition = $1 AND size = $2",
        &[&partition, &(size as i64)],
    )
    .map_err(db_err)?
    .map(|r| serde_json::from_value(r.get(0)).map_err(db_err))
    .transpose()
}

/// The latest stored, signed checkpoint of `partition`.
pub fn latest_checkpoint(
    c: &mut impl GenericClient,
    partition: &str,
) -> Result<Option<SignedProjectCheckpoint>> {
    c.query_opt(
        "SELECT signed FROM governance_checkpoints WHERE partition = $1 ORDER BY size DESC LIMIT 1",
        &[&partition],
    )
    .map_err(db_err)?
    .map(|r| serde_json::from_value(r.get(0)).map_err(db_err))
    .transpose()
}

/// The organizations that countersigned the checkpoint of `partition` at
/// `size`, in order.
pub fn witnesses_at(
    c: &mut impl GenericClient,
    partition: &str,
    size: u64,
) -> Result<Vec<SignedCheckpointWitness>> {
    c.query(
        "SELECT signed FROM checkpoint_witnesses WHERE partition = $1 AND size = $2
          ORDER BY organization_id",
        &[&partition, &(size as i64)],
    )
    .map_err(db_err)?
    .iter()
    .map(|r| serde_json::from_value(r.get(0)).map_err(db_err))
    .collect()
}

/// The member organizations of governed project `project` when its log had
/// `size` events, derived from the log (see
/// [`encompute_trust::govlog::members_at`]): the project's membership
/// events, read through an index on them, and the organizations that are
/// members now and have no event of their own (the owner, and members of a
/// project that predates the events).
pub fn members_at(c: &mut impl GenericClient, project: &str, size: u64) -> Result<Vec<String>> {
    let partition = Partition::Project(project.to_owned()).to_string();
    let events: Vec<GovEvent> = c
        .query(
            "SELECT body FROM governance_events
              WHERE partition = $1 AND kind IN ('membership.added', 'membership.removed')
              ORDER BY pseq",
            &[&partition],
        )
        .map_err(db_err)?
        .iter()
        .map(|r| serde_json::from_value(r.get(0)).map_err(db_err))
        .collect::<Result<_>>()?;
    let now: Vec<String> = c
        .query(
            "SELECT organization_id FROM project_members
              WHERE project_id = $1 AND status = 'active' AND participation = 'member'",
            &[&project],
        )
        .map_err(db_err)?
        .iter()
        .map(|r| r.get(0))
        .collect();
    Ok(encompute_trust::govlog::members_at(&events, size, &now))
}

/// Who witnessed a checkpoint, of those who had to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessState {
    /// The member organizations when the checkpoint was made.
    pub required: Vec<String>,
    /// Those that countersigned it.
    pub witnessed_by: Vec<String>,
    /// Those that have not.
    pub missing: Vec<String>,
}

impl WitnessState {
    /// Every member organization signed (and there is at least one).
    pub fn witnessed(&self) -> bool {
        !self.required.is_empty() && self.missing.is_empty()
    }

    /// `witnessed`, or `unwitnessed`: a label, never a gate.
    pub fn label(&self) -> &'static str {
        if self.witnessed() {
            "witnessed"
        } else {
            "unwitnessed"
        }
    }
}

/// The witness state of `cp` (a checkpoint of project `project`), with the
/// stored witnesses.
pub fn witness_state(
    c: &mut impl GenericClient,
    project: &str,
    cp: &ProjectCheckpoint,
) -> Result<(WitnessState, Vec<SignedCheckpointWitness>)> {
    let witnesses = witnesses_at(c, &cp.partition, cp.size)?;
    let required = members_at(c, project, cp.size)?;
    let signed: Vec<&str> = witnesses
        .iter()
        .map(|w| w.body.organization.as_str())
        .collect();
    let (witnessed_by, missing) = required
        .iter()
        .cloned()
        .partition(|o| signed.contains(&o.as_str()));
    Ok((
        WitnessState {
            required,
            witnessed_by,
            missing,
        },
        witnesses,
    ))
}

/// Complete subtrees read from the database before. They never change
/// once written, so entries are never stale; the cache is emptied when it
/// reaches [`NODE_CACHE_MAX`] entries.
#[derive(Default)]
pub struct NodeCache(std::sync::Mutex<HashMap<(String, u32, u64), Hash>>);

/// The most subtrees [`NodeCache`] holds.
pub const NODE_CACHE_MAX: usize = 50_000;

/// Statements that read tree nodes for inclusion proofs (a page of them is
/// one, however many events it holds).
pub static NODE_QUERIES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The events of `partition` in `(after, size]` (at most `limit`), each
/// with its leaf hash and its inclusion proof in the first `size` events.
/// Two statements at most for a page: the events, and every tree node
/// their proofs need that the cache does not hold, read in one range
/// fetch.
pub fn leaves(
    c: &mut impl GenericClient,
    cache: &NodeCache,
    partition: &str,
    after: u64,
    size: u64,
    limit: i64,
) -> Result<Vec<(GovEvent, String, InclusionProof)>> {
    let rows = c
        .query(
            "SELECT body FROM governance_events
              WHERE partition = $1 AND pseq > $2 AND pseq <= $3 ORDER BY pseq LIMIT $4",
            &[&partition, &(after as i64), &(size as i64), &limit],
        )
        .map_err(db_err)?;
    let events: Vec<GovEvent> = rows
        .iter()
        .map(|r| serde_json::from_value(r.get(0)).map_err(db_err))
        .collect::<Result<_>>()?;
    prove_events(c, cache, partition, size, events)
}

/// The revocation leaves `org`'s latest head in `partition` covers (the
/// revocations recorded before the head's event), sorted: what a bundle
/// whose run starts after them carries so a reader can recompute the head's
/// root. `None` when the organization has no head.
pub fn head_leaves(
    c: &mut impl GenericClient,
    partition: &str,
    org: &str,
    size: u64,
) -> Result<Option<Vec<String>>> {
    let head: Option<i64> = c
        .query_one(
            "SELECT max(pseq) FROM governance_events
              WHERE partition = $1 AND kind = 'revocation_head.signed' AND org_id = $2 AND pseq <= $3",
            &[&partition, &org, &(size as i64)],
        )
        .map_err(db_err)?
        .get(0);
    let Some(head) = head else { return Ok(None) };
    let kinds: Vec<String> = encompute_trust::govlog::kind::REVOCATIONS
        .iter()
        .map(|k| (*k).to_owned())
        .collect();
    let events: Vec<GovEvent> = c
        .query(
            "SELECT body FROM governance_events
              WHERE partition = $1 AND org_id = $2 AND kind = ANY($3) AND pseq < $4 ORDER BY pseq",
            &[&partition, &org, &kinds, &head],
        )
        .map_err(db_err)?
        .iter()
        .map(|r| serde_json::from_value(r.get(0)).map_err(db_err))
        .collect::<Result<_>>()?;
    Ok(Some(encompute_trust::govlog::revocation_leaves(
        &events, org,
    )))
}

/// Where a bundle's run of a project's events starts: the earliest of the
/// issuance of each of `authorizations` and each of `owners`' latest head
/// (the first event when any has none), so that nothing that can bear on
/// them is left before it. A run longer than `max` is cut to its last `max`
/// events: the verifier then finds it does not reach back far enough.
pub fn run_start(
    c: &mut impl GenericClient,
    partition: &str,
    size: u64,
    authorizations: &[String],
    owners: &[String],
    max: u64,
) -> Result<u64> {
    let mut start = size;
    let n = |r: Option<postgres::Row>| r.and_then(|r| r.get::<_, Option<i64>>(0));
    // One indexed (by kind) read for every authorization's issuance; one
    // missing from the log starts the run at the first event.
    let found: std::collections::BTreeMap<String, i64> = c
        .query(
            "SELECT body->'refs'->>'authorization_id', min(pseq) FROM governance_events
              WHERE partition = $1 AND kind = 'authorization.issued' AND pseq <= $2
                AND body->'refs'->>'authorization_id' = ANY($3)
              GROUP BY 1",
            &[&partition, &(size as i64), &authorizations],
        )
        .map_err(db_err)?
        .iter()
        .filter_map(|r| Some((r.get::<_, Option<String>>(0)?, r.get::<_, i64>(1))))
        .collect();
    for a in authorizations {
        start = start.min(found.get(a).map_or(1, |x| (*x).max(1) as u64));
    }
    for o in owners {
        let at = n(c
            .query_opt(
                "SELECT max(pseq) FROM governance_events
                  WHERE partition = $1 AND kind = 'revocation_head.signed' AND org_id = $2 AND pseq <= $3",
                &[&partition, o, &(size as i64)],
            )
            .map_err(db_err)?);
        start = start.min(at.map_or(1, |x| x.max(1) as u64));
    }
    Ok(start.max((size + 1).saturating_sub(max).max(1)))
}

fn prove_events(
    c: &mut impl GenericClient,
    cache: &NodeCache,
    partition: &str,
    size: u64,
    events: Vec<GovEvent>,
) -> Result<Vec<(GovEvent, String, InclusionProof)>> {
    // Which nodes the proofs read depends on the sizes only, so a dry run
    // with placeholder hashes names them.
    let mut needed = std::collections::BTreeSet::new();
    for e in &events {
        InclusionProof::build(partition, e.leaf_index(), size, &mut |l: u32, i: u64| {
            needed.insert((l, i));
            Ok([0u8; 32])
        })?;
    }
    let mut known: HashMap<(u32, u64), Hash> = HashMap::new();
    let mut missing = vec![];
    {
        let held = cache.0.lock().unwrap_or_else(|e| e.into_inner());
        for (l, i) in &needed {
            match held.get(&(partition.to_owned(), *l, *i)) {
                Some(h) => {
                    known.insert((*l, *i), *h);
                }
                None => missing.push((*l, *i)),
            }
        }
    }
    if !missing.is_empty() {
        NODE_QUERIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let levels: Vec<i32> = missing.iter().map(|(l, _)| *l as i32).collect();
        let idxs: Vec<i64> = missing.iter().map(|(_, i)| *i as i64).collect();
        for r in c
            .query(
                "SELECT n.level, n.idx, n.hash FROM governance_tree_nodes n
                   JOIN unnest($2::int4[], $3::int8[]) AS w(level, idx)
                     ON w.level = n.level AND w.idx = n.idx
                  WHERE n.partition = $1",
                &[&partition, &levels, &idxs],
            )
            .map_err(db_err)?
        {
            let (l, i, h): (i32, i64, String) = (r.get(0), r.get(1), r.get(2));
            known.insert((l as u32, i as u64), parse_hash("tree node", &h)?);
        }
        let mut held = cache.0.lock().unwrap_or_else(|e| e.into_inner());
        if held.len() + missing.len() > NODE_CACHE_MAX {
            held.clear();
        }
        for (l, i) in &missing {
            if let Some(h) = known.get(&(*l, *i)) {
                held.insert((partition.to_owned(), *l, *i), *h);
            }
        }
    }
    let mut out = Vec::with_capacity(events.len());
    for e in events {
        let leaf = hash_hex(&e.leaf_hash()?);
        let proof =
            InclusionProof::build(partition, e.leaf_index(), size, &mut |l: u32, i: u64| {
                known.get(&(l, i)).copied().ok_or_else(|| {
                    log_err(format!(
                        "the governance log's tree node {l}/{i} of {partition} is missing"
                    ))
                })
            })?;
        out.push((e, leaf, proof));
    }
    Ok(out)
}
