//! The governance event log's verifiable formats.
//!
//! The control plane records every security-negative governance transition
//! (a revoked authorization, a retired purpose, a revoked governance key, an
//! expired or revoked asset, an ended job, a withdrawn approval, a removed
//! membership or role, a disabled account) as one event in an append-only
//! log. Each event belongs to one partition: a governed project
//! (`p:<project>`), an organization (`o:<organization>`) or the platform.
//!
//! - Every partition is a Merkle tree over its events, built exactly as in
//!   RFC 6962 (leaf hash `SHA256(0x00 || leaf)`, interior node
//!   `SHA256(0x01 || left || right)`), so inclusion and consistency proofs
//!   are the standard ones. The leaf input is the event's canonical JSON
//!   under the domain [`LEAF_DOMAIN`], and names its partition: an event of
//!   one project never proves inclusion in another's tree.
//! - All events, of every partition, are also one hash chain in the order
//!   they were recorded ([`chain_hash`]); the control plane anchors its
//!   head.
//! - A [`ProjectCheckpoint`] is the control plane's signed statement of a
//!   partition's size and root. Each member organization countersigns it
//!   with its governance key ([`CheckpointWitness`]) after checking that it
//!   extends the checkpoint it witnessed before; two signed checkpoints
//!   that cannot both be true are an [`EquivocationProof`] anyone can
//!   check.
//! - A [`RevocationHead`] is an owner's signed statement of its revocations
//!   in a project, so an exported bundle cannot silently omit one.
//!
//! Events carry only what every member of the partition may see:
//! identifiers, the kind of transition and when. Never a storage location,
//! a key reference, a person's identifier from another organization or
//! private metadata.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::service::ServiceSigner;
use encompute_verification::{hex, unhex};

use crate::authz::{check_hex32, check_label, ControlSigned, Signed};

/// A SHA-256 digest.
pub type Hash = [u8; 32];

pub const GOVLOG_VERSION: u32 = 1;
/// Domain of an event's leaf input (inside the RFC 6962 leaf hash).
pub const LEAF_DOMAIN: &str = "encompute.govlog-leaf.v1";
/// Domain of the global hash chain over all events.
pub const CHAIN_DOMAIN: &str = "encompute.govlog-chain.v1";
/// Domain of the control plane's signed partition checkpoint.
pub const PROJECT_CHECKPOINT: &str = "encompute.project-checkpoint.v1";
/// Domain of the control plane's signed consistency proof.
pub const CONSISTENCY_PROOF: &str = "encompute.govlog-consistency.v1";
/// Domain of a member organization's witness signature on a checkpoint.
pub const CHECKPOINT_WITNESS: &str = "encompute.checkpoint-witness.v1";
/// Domain of an owner's signed revocation head.
pub const REVOCATION_HEAD: &str = "encompute.revocation-head.v1";

/// The platform partition (events of no project and no organization).
pub const PLATFORM: &str = "platform";

/// The most references an event carries.
pub const MAX_REFS: usize = 32;

/// The previous hash of the first event of the chain.
pub const CHAIN_GENESIS: Hash = [0u8; 32];

/// Event kinds recorded today. A verifier accepts any well-formed kind
/// (later versions add some); these are the ones the control plane writes.
pub mod kind {
    pub const ASSET_REVOKED: &str = "asset.revoked";
    pub const ASSET_EXPIRED: &str = "asset.expired";
    pub const SERVICE_ACCOUNT_DISABLED: &str = "service_account.disabled";
    pub const USER_DISABLED: &str = "user.disabled";
    pub const JOB_CANCELLED: &str = "job.cancelled";
    pub const JOB_FAILED: &str = "job.failed";
    pub const GRANT_WITHDRAWN: &str = "grant.withdrawn";
    pub const MEMBERSHIP_REMOVED: &str = "membership.removed";
    /// A member organization joined a governed project (not a deny event:
    /// it exists so the members at any size of a project's log can be
    /// derived from the log).
    pub const MEMBERSHIP_ADDED: &str = "membership.added";
    pub const ROLE_REMOVED: &str = "role.removed";
    pub const AUTHORIZATION_ISSUED: &str = "authorization.issued";
    pub const AUTHORIZATION_REVOKED: &str = "authorization.revoked";
    pub const PURPOSE_RETIRED: &str = "purpose.retired";
    pub const GOVERNANCE_KEY_REVOKED: &str = "governance_key.revoked";

    /// Every kind above.
    pub const ALL: &[&str] = &[
        ASSET_REVOKED,
        ASSET_EXPIRED,
        SERVICE_ACCOUNT_DISABLED,
        USER_DISABLED,
        JOB_CANCELLED,
        JOB_FAILED,
        GRANT_WITHDRAWN,
        MEMBERSHIP_REMOVED,
        MEMBERSHIP_ADDED,
        ROLE_REMOVED,
        AUTHORIZATION_ISSUED,
        AUTHORIZATION_REVOKED,
        PURPOSE_RETIRED,
        GOVERNANCE_KEY_REVOKED,
    ];
}

fn err(m: impl Into<String>) -> Error {
    Error::new(Code::TrustEvidence, m)
}

pub fn hash_hex(h: &Hash) -> String {
    hex(h)
}

/// A 32-byte hash from lowercase hex.
pub fn parse_hash(what: &str, s: &str) -> Result<Hash> {
    check_hex32(what, s)?;
    unhex(s)
        .and_then(|b| <Hash>::try_from(b).ok())
        .ok_or_else(|| err(format!("{what} must be 32 bytes of lowercase hex")))
}

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

// --- partitions and events ---------------------------------------------------

/// Where an event belongs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Partition {
    /// A governed project: its members (and appointed auditors) read it.
    Project(String),
    /// One organization: only it reads it.
    Organization(String),
    /// Neither (platform service accounts and users).
    Platform,
}

impl Partition {
    pub fn parse(s: &str) -> Result<Self> {
        let p = if s == PLATFORM {
            Partition::Platform
        } else if let Some(id) = s.strip_prefix("p:") {
            Partition::Project(id.to_owned())
        } else if let Some(id) = s.strip_prefix("o:") {
            Partition::Organization(id.to_owned())
        } else {
            return Err(err(format!("unknown governance log partition {s:?}")));
        };
        match &p {
            Partition::Project(id) | Partition::Organization(id) => check_id("partition", id)?,
            Partition::Platform => {}
        }
        Ok(p)
    }
}

impl std::fmt::Display for Partition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Partition::Project(id) => write!(f, "p:{id}"),
            Partition::Organization(id) => write!(f, "o:{id}"),
            Partition::Platform => f.write_str(PLATFORM),
        }
    }
}

/// An identifier or digest: never free text that could carry a payload.
fn check_id(what: &str, v: &str) -> Result<()> {
    let ok = !v.is_empty()
        && v.len() <= 256
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/@+".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(err(format!("{what} must be an identifier or digest")))
    }
}

fn check_kind(k: &str) -> Result<()> {
    let ok = !k.is_empty()
        && k.len() <= 64
        && k.contains('.')
        && k.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._".contains(&b))
        && !k.starts_with('.')
        && !k.ends_with('.');
    if ok {
        Ok(())
    } else {
        Err(err(format!("governance event kind {k:?} is malformed")))
    }
}

/// One event: the shared-safe body that is hashed into its partition's
/// tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovEvent {
    pub v: u32,
    /// `p:<project>`, `o:<organization>` or `platform`.
    pub partition: String,
    /// Position in the partition, from 1.
    pub pseq: u64,
    /// What happened (see [`kind`]).
    pub kind: String,
    /// The ID of what it happened to.
    pub subject: String,
    /// The organization the subject belongs to, when it belongs to one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// When (Unix seconds).
    pub at: u64,
    /// Related identifiers (other IDs and digests only).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub refs: BTreeMap<String, String>,
}

impl GovEvent {
    pub fn check(&self) -> Result<()> {
        if self.v != GOVLOG_VERSION {
            return Err(err(format!("governance event version {}", self.v)));
        }
        Partition::parse(&self.partition)?;
        if self.pseq == 0 {
            return Err(err("a governance event's position starts at 1"));
        }
        check_kind(&self.kind)?;
        check_id("subject", &self.subject)?;
        if let Some(o) = &self.org {
            check_id("organization", o)?;
        }
        if self.refs.len() > MAX_REFS {
            return Err(err(format!(
                "a governance event has at most {MAX_REFS} references"
            )));
        }
        for (k, v) in &self.refs {
            let key_ok = !k.is_empty()
                && k.len() <= 64
                && k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
            if !key_ok {
                return Err(err(format!("governance event reference name {k:?}")));
            }
            check_id(k, v)?;
        }
        Ok(())
    }

    /// The leaf's index in its partition's tree (from 0).
    pub fn leaf_index(&self) -> u64 {
        self.pseq.saturating_sub(1)
    }

    /// `SHA256(0x00 || LEAF_DOMAIN || 0x00 || canonical JSON)`: the RFC 6962
    /// leaf hash of the domain-tagged event.
    pub fn leaf_hash(&self) -> Result<Hash> {
        self.check()?;
        Ok(rfc6962_leaf(&leaf_input(&canonical_json(self)?)))
    }
}

fn leaf_input(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(LEAF_DOMAIN.len() + 1 + body.len());
    v.extend_from_slice(LEAF_DOMAIN.as_bytes());
    v.push(0);
    v.extend_from_slice(body);
    v
}

// --- RFC 6962 Merkle trees ---------------------------------------------------

/// The RFC 6962 hash of a leaf input: `SHA256(0x00 || data)`.
pub fn rfc6962_leaf(data: &[u8]) -> Hash {
    sha256(&[&[0u8], data])
}

/// The RFC 6962 hash of an interior node: `SHA256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256(&[&[1u8], left, right])
}

/// The root of the empty tree: `SHA256()`.
pub fn empty_root() -> Hash {
    sha256(&[])
}

/// The largest power of two smaller than `n` (`n >= 2`).
fn split(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1u64 << (63 - (n - 1).leading_zeros())
}

/// The root (RFC 6962 MTH) of `leaves` (leaf hashes).
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split(n as u64) as usize;
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// The complete subtrees a tree is stored as: `node(level, index)` is the
/// root of leaves `[index << level, (index + 1) << level)`, a perfect
/// subtree (level 0 is the leaves). Only complete subtrees exist, so a
/// stored node never changes as the tree grows.
pub trait Nodes {
    fn node(&mut self, level: u32, index: u64) -> Result<Hash>;
}

impl<F: FnMut(u32, u64) -> Result<Hash>> Nodes for F {
    fn node(&mut self, level: u32, index: u64) -> Result<Hash> {
        self(level, index)
    }
}

/// The root of leaves `[a, b)` from complete subtrees.
fn range_hash(nodes: &mut impl Nodes, a: u64, b: u64) -> Result<Hash> {
    let n = b - a;
    if n == 0 {
        return Ok(empty_root());
    }
    if n.is_power_of_two() && a.is_multiple_of(n) {
        let level = n.trailing_zeros();
        return nodes.node(level, a >> level);
    }
    let k = split(n);
    let l = range_hash(nodes, a, a + k)?;
    let r = range_hash(nodes, a + k, b)?;
    Ok(node_hash(&l, &r))
}

/// The root of the first `size` leaves, from complete subtrees (O(log
/// size) lookups).
pub fn root_with(size: u64, nodes: &mut impl Nodes) -> Result<Hash> {
    range_hash(nodes, 0, size)
}

/// The complete subtrees that appending the leaf at `index` (with hash
/// `leaf`) completes, the leaf itself first: what a store of complete
/// subtrees inserts. `nodes` must hold every complete subtree of the
/// first `index` leaves.
pub fn completed_nodes(
    index: u64,
    leaf: Hash,
    nodes: &mut impl Nodes,
) -> Result<Vec<(u32, u64, Hash)>> {
    let mut out = vec![(0, index, leaf)];
    let (mut level, mut idx, mut cur) = (0u32, index, leaf);
    while idx % 2 == 1 {
        let left = nodes.node(level, idx - 1)?;
        cur = node_hash(&left, &cur);
        level += 1;
        idx /= 2;
        out.push((level, idx, cur));
    }
    Ok(out)
}

fn path(nodes: &mut impl Nodes, m: u64, a: u64, b: u64, out: &mut Vec<Hash>) -> Result<()> {
    let n = b - a;
    if n <= 1 {
        return Ok(());
    }
    let k = split(n);
    if m < a + k {
        path(nodes, m, a, a + k, out)?;
        out.push(range_hash(nodes, a + k, b)?);
    } else {
        path(nodes, m, a + k, b, out)?;
        out.push(range_hash(nodes, a, a + k)?);
    }
    Ok(())
}

/// RFC 6962 SUBPROOF(m, D[a:b], b): `m` relative to `a`.
fn subproof(
    nodes: &mut impl Nodes,
    m: u64,
    a: u64,
    b: u64,
    complete: bool,
    out: &mut Vec<Hash>,
) -> Result<()> {
    let n = b - a;
    if m == n {
        if !complete {
            out.push(range_hash(nodes, a, b)?);
        }
        return Ok(());
    }
    let k = split(n);
    if m <= k {
        subproof(nodes, m, a, a + k, complete, out)?;
        out.push(range_hash(nodes, a + k, b)?);
    } else {
        subproof(nodes, m - k, a + k, b, false, out)?;
        out.push(range_hash(nodes, a, a + k)?);
    }
    Ok(())
}

fn hexes(v: &[Hash]) -> Vec<String> {
    v.iter().map(hash_hex).collect()
}

fn parse_path(path: &[String]) -> Result<Vec<Hash>> {
    if path.len() > 64 {
        return Err(err("a Merkle proof has at most 64 hashes"));
    }
    path.iter().map(|h| parse_hash("proof hash", h)).collect()
}

/// That leaf `leaf_index` is in the tree of `tree_size` leaves of
/// `partition` (RFC 6962 audit path, leaf to root).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProof {
    pub partition: String,
    pub leaf_index: u64,
    pub tree_size: u64,
    pub path: Vec<String>,
}

impl InclusionProof {
    /// The audit path of leaf `index` in the first `size` leaves.
    pub fn build(partition: &str, index: u64, size: u64, nodes: &mut impl Nodes) -> Result<Self> {
        if index >= size {
            return Err(err("the leaf is not in a tree of that size"));
        }
        let mut out = vec![];
        path(nodes, index, 0, size, &mut out)?;
        Ok(Self {
            partition: partition.to_owned(),
            leaf_index: index,
            tree_size: size,
            path: hexes(&out),
        })
    }

    /// The same, from all the tree's leaf hashes.
    pub fn from_leaves(partition: &str, leaves: &[Hash], index: u64) -> Result<Self> {
        Self::build(
            partition,
            index,
            leaves.len() as u64,
            &mut |level: u32, i: u64| {
                let a = (i << level) as usize;
                Ok(root(&leaves[a..a + (1usize << level)]))
            },
        )
    }

    /// Recomputes the root from `leaf` (RFC 9162 section 2.1.3.2) and
    /// checks it is `root`.
    pub fn verify(&self, leaf: &Hash, root: &Hash) -> Result<()> {
        if self.leaf_index >= self.tree_size {
            return Err(err("the inclusion proof's leaf is outside its tree"));
        }
        let path = parse_path(&self.path)?;
        let (mut f, mut s) = (self.leaf_index, self.tree_size - 1);
        let mut r = *leaf;
        for p in &path {
            if s == 0 {
                return Err(err("the inclusion proof is too long"));
            }
            if f % 2 == 1 || f == s {
                r = node_hash(p, &r);
                while f % 2 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            } else {
                r = node_hash(&r, p);
            }
            f >>= 1;
            s >>= 1;
        }
        if s != 0 || &r != root {
            return Err(err("the inclusion proof does not lead to the root"));
        }
        Ok(())
    }
}

/// That the tree of `first` leaves (root `first_root`) is a prefix of the
/// tree of `second` leaves (root `second_root`) of `partition`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistencyProof {
    pub partition: String,
    pub first: u64,
    pub second: u64,
    pub first_root: String,
    pub second_root: String,
    pub path: Vec<String>,
}

pub type SignedConsistencyProof = ControlSigned<ConsistencyProof>;

impl ConsistencyProof {
    /// The RFC 6962 consistency proof between the first `first` and the
    /// first `second` leaves.
    pub fn build(partition: &str, first: u64, second: u64, nodes: &mut impl Nodes) -> Result<Self> {
        if first > second {
            return Err(err(
                "a consistency proof goes from a smaller tree to a larger one",
            ));
        }
        let mut out = vec![];
        if first > 0 && first < second {
            subproof(nodes, first, 0, second, true, &mut out)?;
        }
        Ok(Self {
            partition: partition.to_owned(),
            first,
            second,
            first_root: hash_hex(&range_hash(nodes, 0, first)?),
            second_root: hash_hex(&range_hash(nodes, 0, second)?),
            path: hexes(&out),
        })
    }

    /// The same, from all the larger tree's leaf hashes.
    pub fn from_leaves(partition: &str, leaves: &[Hash], first: u64) -> Result<Self> {
        Self::build(
            partition,
            first,
            leaves.len() as u64,
            &mut |level: u32, i: u64| {
                let a = (i << level) as usize;
                Ok(root(&leaves[a..a + (1usize << level)]))
            },
        )
    }

    /// Checks the proof (RFC 9162 section 2.1.4.2): the first tree is a
    /// prefix of the second.
    pub fn verify(&self) -> Result<()> {
        let fail = || err("the trees are not consistent (the larger does not extend the smaller)");
        let r1 = parse_hash("first root", &self.first_root)?;
        let r2 = parse_hash("second root", &self.second_root)?;
        let path = parse_path(&self.path)?;
        let (m, n) = (self.first, self.second);
        if m > n {
            return Err(fail());
        }
        if m == n {
            return if path.is_empty() && r1 == r2 {
                Ok(())
            } else {
                Err(fail())
            };
        }
        if m == 0 {
            return if path.is_empty() && r1 == empty_root() {
                Ok(())
            } else {
                Err(fail())
            };
        }
        let mut path = path;
        if m.is_power_of_two() {
            path.insert(0, r1);
        }
        let Some((first, rest)) = path.split_first() else {
            return Err(fail());
        };
        let (mut f, mut s) = (m - 1, n - 1);
        while f % 2 == 1 {
            f >>= 1;
            s >>= 1;
        }
        let (mut fr, mut sr) = (*first, *first);
        for c in rest {
            if s == 0 {
                return Err(fail());
            }
            if f % 2 == 1 || f == s {
                fr = node_hash(c, &fr);
                sr = node_hash(c, &sr);
                while f % 2 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            } else {
                sr = node_hash(&sr, c);
            }
            f >>= 1;
            s >>= 1;
        }
        if s != 0 || fr != r1 || sr != r2 {
            return Err(fail());
        }
        Ok(())
    }

    /// Signed by the control plane: a proof it served that fails is
    /// evidence against it.
    pub fn sign(self, signer: &ServiceSigner) -> Result<SignedConsistencyProof> {
        Partition::parse(&self.partition)?;
        ControlSigned::sign_as(CONSISTENCY_PROOF, self, signer)
    }
}

impl SignedConsistencyProof {
    /// Signed by `control_key` (the proof itself is checked by
    /// [`ConsistencyProof::verify`]).
    pub fn verify_signature(&self, control_key: &str) -> Result<()> {
        self.verify_as(CONSISTENCY_PROOF, control_key)
    }
}

// --- the global chain --------------------------------------------------------

/// The chain hash of event `gseq` (from 1) with leaf hash `leaf` after
/// `prev` ([`CHAIN_GENESIS`] for the first): it binds the order of every
/// event of every partition.
pub fn chain_hash(prev: &Hash, gseq: u64, leaf: &Hash) -> Hash {
    sha256(&[
        CHAIN_DOMAIN.as_bytes(),
        &[0u8],
        prev,
        &gseq.to_be_bytes(),
        leaf,
    ])
}

// --- checkpoints, witnesses, revocation heads --------------------------------

/// The control plane's statement of one partition's tree: its size and
/// root, at global position `gseq` of the chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCheckpoint {
    pub version: u32,
    pub partition: String,
    pub size: u64,
    pub root: String,
    pub gseq: u64,
    pub at: u64,
}

pub type SignedProjectCheckpoint = ControlSigned<ProjectCheckpoint>;

impl ProjectCheckpoint {
    pub fn check(&self) -> Result<()> {
        if self.version != GOVLOG_VERSION {
            return Err(err(format!("project checkpoint version {}", self.version)));
        }
        Partition::parse(&self.partition)?;
        parse_hash("checkpoint root", &self.root)?;
        if self.size == 0 && self.root != hash_hex(&empty_root()) {
            return Err(err("an empty checkpoint has the empty root"));
        }
        Ok(())
    }

    pub fn sign(self, signer: &ServiceSigner) -> Result<SignedProjectCheckpoint> {
        self.check()?;
        ControlSigned::sign_as(PROJECT_CHECKPOINT, self, signer)
    }
}

impl SignedProjectCheckpoint {
    /// Well formed and signed by `control_key` (hex).
    pub fn verify(&self, control_key: &str) -> Result<()> {
        self.body.check()?;
        self.verify_as(PROJECT_CHECKPOINT, control_key)
    }

    /// That `event` is in this checkpoint's tree: same partition, inside
    /// its size, and `proof` leads from the event's leaf to its root. (The
    /// checkpoint's signature is checked separately, by [`Self::verify`].)
    pub fn includes(&self, event: &GovEvent, proof: &InclusionProof) -> Result<()> {
        let cp = &self.body;
        if event.partition != cp.partition || proof.partition != cp.partition {
            return Err(err("the event is not in this checkpoint's partition"));
        }
        if proof.tree_size != cp.size || proof.leaf_index != event.leaf_index() {
            return Err(err("the inclusion proof is for another tree or leaf"));
        }
        proof.verify(&event.leaf_hash()?, &parse_hash("root", &cp.root)?)
    }
}

/// A member organization's countersignature of a checkpoint, with its
/// governance key: it saw this size and root, consistent with every
/// checkpoint it witnessed before.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointWitness {
    pub version: u32,
    pub organization: String,
    pub partition: String,
    pub size: u64,
    pub root: String,
    pub at: u64,
}

pub type SignedCheckpointWitness = Signed<CheckpointWitness>;

impl CheckpointWitness {
    pub fn check(&self) -> Result<()> {
        if self.version != GOVLOG_VERSION {
            return Err(err(format!("checkpoint witness version {}", self.version)));
        }
        check_label("organization", &self.organization)?;
        Partition::parse(&self.partition)?;
        parse_hash("witnessed root", &self.root)?;
        Ok(())
    }

    /// Whether it witnesses `cp` (same partition, size and root).
    pub fn witnesses(&self, cp: &ProjectCheckpoint) -> bool {
        self.partition == cp.partition && self.size == cp.size && self.root == cp.root
    }

    pub fn sign(self, key: &SigningKey) -> Result<SignedCheckpointWitness> {
        self.check()?;
        crate::authz::sign(CHECKPOINT_WITNESS, self, key)
    }
}

impl SignedCheckpointWitness {
    /// Well formed and signed by `governance_key` (hex).
    pub fn verify(&self, governance_key: &str) -> Result<()> {
        self.body.check()?;
        crate::authz::verify(CHECKPOINT_WITNESS, self, governance_key)
    }
}

/// An owner's statement of its revocations in a project: the `seq`-th
/// head (from 1), whose `root` covers every revocation it made there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationHead {
    pub version: u32,
    pub organization: String,
    pub project: String,
    pub seq: u64,
    pub root: String,
    pub at: u64,
}

pub type SignedRevocationHead = Signed<RevocationHead>;

impl RevocationHead {
    pub fn check(&self) -> Result<()> {
        if self.version != GOVLOG_VERSION {
            return Err(err(format!("revocation head version {}", self.version)));
        }
        check_label("organization", &self.organization)?;
        check_label("project", &self.project)?;
        if self.seq == 0 {
            return Err(err("revocation heads are numbered from 1"));
        }
        parse_hash("revocation root", &self.root)?;
        Ok(())
    }

    pub fn sign(self, key: &SigningKey) -> Result<SignedRevocationHead> {
        self.check()?;
        crate::authz::sign(REVOCATION_HEAD, self, key)
    }
}

impl SignedRevocationHead {
    /// Well formed and signed by `governance_key` (hex).
    pub fn verify(&self, governance_key: &str) -> Result<()> {
        self.body.check()?;
        crate::authz::verify(REVOCATION_HEAD, self, governance_key)
    }
}

/// What a member found when it compared the control plane's latest
/// checkpoint with the one it witnessed last.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Extension {
    /// The latest checkpoint extends the last witnessed one (or is it).
    Consistent,
    /// The control plane signed two statements that cannot both be true:
    /// evidence anyone holding its public key can check.
    Equivocation(Box<EquivocationProof>),
    /// The latest checkpoint is smaller than the last witnessed one and
    /// signed no earlier: the control plane lost events it had signed.
    Rollback(Box<RollbackProof>),
    /// The latest checkpoint is smaller than the last witnessed one and
    /// signed earlier: an old checkpoint served again. Not evidence of
    /// anything the control plane signed (a stale answer cannot be told
    /// from a network fault), but not an extension either.
    Stale,
}

/// Whether `new` extends `old` (the checkpoint a member witnessed last),
/// given the control plane's signed consistency proof from `old`'s size
/// to `new`'s (needed when `new` is larger). Both checkpoints and the
/// proof must be signed by `control_key` (hex) and belong to one
/// partition, otherwise the answer is an error and no evidence: a
/// checkpoint or proof that is not the control plane's own proves nothing
/// against it.
pub fn check_extension(
    control_key: &str,
    old: &SignedProjectCheckpoint,
    new: &SignedProjectCheckpoint,
    proof: Option<&SignedConsistencyProof>,
) -> Result<Extension> {
    old.verify(control_key)?;
    new.verify(control_key)?;
    let (o, n) = (&old.body, &new.body);
    if o.partition != n.partition {
        return Err(err("the checkpoints are of different partitions"));
    }
    let evidence = |consistency: Option<SignedConsistencyProof>| EquivocationProof {
        a: old.clone(),
        b: new.clone(),
        consistency,
    };
    if n.size < o.size {
        return Ok(if n.at >= o.at {
            Extension::Rollback(Box::new(RollbackProof {
                previous: old.clone(),
                latest: new.clone(),
            }))
        } else {
            Extension::Stale
        });
    }
    if n.size == o.size {
        return Ok(if n.root == o.root {
            Extension::Consistent
        } else {
            Extension::Equivocation(Box::new(evidence(None)))
        });
    }
    let p = proof.ok_or_else(|| {
        err("the control plane gave no consistency proof from the last witnessed checkpoint")
    })?;
    p.verify_signature(control_key)?;
    let b = &p.body;
    if b.partition != o.partition
        || b.first != o.size
        || b.second != n.size
        || b.first_root != o.root
        || b.second_root != n.root
    {
        return Err(err(
            "the consistency proof is not between the two checkpoints",
        ));
    }
    Ok(match b.verify() {
        Ok(()) => Extension::Consistent,
        Err(_) => Extension::Equivocation(Box::new(evidence(Some(p.clone())))),
    })
}

/// How two checkpoints contradict each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Equivocation {
    /// The same partition and size with different roots.
    SameSizeDifferentRoots,
    /// The smaller tree is not a prefix of the larger: the control plane's
    /// own signed consistency proof between them fails.
    Inconsistent,
}

/// Two checkpoints the control plane signed that cannot both be true:
/// evidence anyone holding its public key can check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EquivocationProof {
    pub a: SignedProjectCheckpoint,
    pub b: SignedProjectCheckpoint,
    /// For checkpoints of different sizes: the consistency proof the
    /// control plane served between them, which fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency: Option<SignedConsistencyProof>,
}

/// What a pair of checkpoints (and a consistency proof) shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The control plane equivocated.
    Equivocation(Equivocation),
    /// The checkpoints agree, or the control plane's own consistency proof
    /// between them verifies: no evidence.
    Consistent,
}

/// A rollback: the control plane signed a checkpoint of `previous.size`
/// events and, no earlier, signed one of fewer events of the same
/// partition. Both signatures are the control plane's own, so anyone
/// holding its public key can check it; the member's copy of `previous`
/// is what a rollback is measured against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackProof {
    pub previous: SignedProjectCheckpoint,
    pub latest: SignedProjectCheckpoint,
}

impl RollbackProof {
    /// `Ok` when both checkpoints are signed by `control_key` (hex), are of
    /// one partition, and the later-signed one is the smaller.
    pub fn check(&self, control_key: &str) -> Result<()> {
        self.previous.verify(control_key)?;
        self.latest.verify(control_key)?;
        let (p, l) = (&self.previous.body, &self.latest.body);
        if p.partition != l.partition {
            return Err(err("the checkpoints are of different partitions"));
        }
        if l.size >= p.size {
            return Err(err(
                "the latest checkpoint is not smaller than the previous",
            ));
        }
        if l.at < p.at {
            return Err(err(
                "the smaller checkpoint was signed before the larger: not a rollback",
            ));
        }
        Ok(())
    }
}

impl EquivocationProof {
    /// `Ok` when the proof shows the control plane (`control_key`, hex)
    /// equivocated; an error otherwise (forged, unrelated or consistent
    /// checkpoints).
    pub fn check(&self, control_key: &str) -> Result<Equivocation> {
        match self.assess(control_key)? {
            Verdict::Equivocation(e) => Ok(e),
            Verdict::Consistent => Err(err("the checkpoints are consistent")),
        }
    }

    /// Like [`Self::check`], with the absence of evidence as a value:
    /// `Err` is for inputs that are not the control plane's (forged,
    /// edited, of different partitions, a missing or unrelated proof).
    pub fn assess(&self, control_key: &str) -> Result<Verdict> {
        self.a.verify(control_key)?;
        self.b.verify(control_key)?;
        let (s, l) = if self.a.body.size <= self.b.body.size {
            (&self.a.body, &self.b.body)
        } else {
            (&self.b.body, &self.a.body)
        };
        if s.partition != l.partition {
            return Err(err("the checkpoints are of different partitions"));
        }
        if s.size == l.size {
            return Ok(if s.root != l.root {
                Verdict::Equivocation(Equivocation::SameSizeDifferentRoots)
            } else {
                Verdict::Consistent
            });
        }
        let p = self.consistency.as_ref().ok_or_else(|| {
            err("checkpoints of different sizes need the control plane's consistency proof between them")
        })?;
        p.verify_signature(control_key)?;
        let b = &p.body;
        if b.partition != s.partition
            || b.first != s.size
            || b.second != l.size
            || b.first_root != s.root
            || b.second_root != l.root
        {
            return Err(err("the consistency proof is for other checkpoints"));
        }
        Ok(match b.verify() {
            Ok(()) => Verdict::Consistent,
            Err(_) => Verdict::Equivocation(Equivocation::Inconsistent),
        })
    }
}

/// The member organizations of a governed project when its log had `size`
/// events, from the project's membership events (`membership.added` and
/// `membership.removed`, in order; others are ignored) and `baseline`, the
/// organizations that are members now (the owner, and members of a project
/// that predates the events, have no event of their own and are members
/// from the start). An organization is a member from its `membership.added`
/// event (as a member, never an auditor organization) until its
/// `membership.removed` event; an invitation removed before it was
/// accepted never counts. Sorted.
pub fn members_at(events: &[GovEvent], size: u64, baseline: &[String]) -> Vec<String> {
    // Per organization: whether it was a member before its first event,
    // and whether it is one after its events up to `size`.
    let mut state: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for e in events {
        let Some(org) = e.org.clone() else { continue };
        let added = match e.kind.as_str() {
            kind::MEMBERSHIP_ADDED => true,
            kind::MEMBERSHIP_REMOVED => false,
            _ => continue,
        };
        let counts = e.refs.get("participation").is_none_or(|p| p == "member");
        let active = e.refs.get("status").is_none_or(|s| s == "active");
        let initial = !added && counts && active;
        let entry = state.entry(org).or_insert((initial, initial));
        if e.pseq <= size {
            entry.1 = added && counts;
        }
    }
    for o in baseline {
        state.entry(o.clone()).or_insert((true, true));
    }
    state
        .into_iter()
        .filter(|(_, (_, at))| *at)
        .map(|(o, _)| o)
        .collect()
}
