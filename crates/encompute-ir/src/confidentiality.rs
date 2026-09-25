//! Confidentiality declarations (ADR-010): who owns a value, who may learn
//! it, what it may be used for, and how it may be released. They describe
//! requirements, not mechanisms: nothing here chooses FHE, MPC, secure
//! aggregation or a TEE, and nothing changes how a program executes.
//!
//! A program may declare parties, assets (with policies), its purpose, which
//! secret input is which asset, explicit derivations (e.g. "this value is a
//! gradient, releasable only in aggregate", if the source assets allow it),
//! and where each output goes (kept sealed, revealed to a party, or public).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Code, Error, Result};
use crate::types::ValueId;

fn bad(msg: impl Into<String>) -> Error {
    Error::new(Code::PolicyDeclaration, msg)
}

/// A party ID: 1–64 characters of `a-z 0-9 - _ .`, starting with a letter
/// or digit (`hospital-a`). An authorization principal, not a host.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PartyId(String);

/// Free text (party names, purposes): 1–128 characters, no quotes or
/// control characters (they would corrupt the canonical text form).
pub fn check_text(what: &str, s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 128 || s.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
        return Err(bad(format!(
            "{what} {s:?} must be 1-128 characters without quotes, backslashes or control characters"
        )));
    }
    Ok(())
}

/// Checked identifier for parties and assets.
pub fn check_id(what: &str, s: &str) -> Result<()> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-_.".contains(&c));
    if ok {
        Ok(())
    } else {
        Err(bad(format!(
            "{what} {s:?} must be 1-64 characters of a-z, 0-9, '-', '_', '.'"
        )))
    }
}

impl PartyId {
    pub fn new(s: &str) -> Result<Self> {
        check_id("party", s)?;
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Party {
    pub id: PartyId,
    pub name: String,
}

/// What kind of confidential asset a value is. Descriptive: it does not
/// change execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Tensor,
    Dataset,
    Model,
    Embedding,
    Gradient,
    ModelUpdate,
    Checkpoint,
    Adapter,
    OptimizerState,
    Output,
    Generic,
}

impl AssetKind {
    pub const ALL: [AssetKind; 11] = [
        AssetKind::Tensor,
        AssetKind::Dataset,
        AssetKind::Model,
        AssetKind::Embedding,
        AssetKind::Gradient,
        AssetKind::ModelUpdate,
        AssetKind::Checkpoint,
        AssetKind::Adapter,
        AssetKind::OptimizerState,
        AssetKind::Output,
        AssetKind::Generic,
    ];

    pub fn name(self) -> &'static str {
        match self {
            AssetKind::Tensor => "tensor",
            AssetKind::Dataset => "dataset",
            AssetKind::Model => "model",
            AssetKind::Embedding => "embedding",
            AssetKind::Gradient => "gradient",
            AssetKind::ModelUpdate => "model_update",
            AssetKind::Checkpoint => "checkpoint",
            AssetKind::Adapter => "adapter",
            AssetKind::OptimizerState => "optimizer_state",
            AssetKind::Output => "output",
            AssetKind::Generic => "generic",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == s)
    }
}

impl fmt::Display for AssetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How a value may leave confidential computation, from most to least
/// restrictive (the derived `Ord` is this order):
/// - `Never`: nobody learns it, not even its owners;
/// - `OwnerOnly`: only its owners;
/// - `AllowedParties`: only its readers;
/// - `AggregateOnly`: only as part of an aggregate over several parties'
///   contributions, to its readers;
/// - `Public`: anyone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Release {
    Never,
    OwnerOnly,
    AllowedParties,
    AggregateOnly,
    Public,
}

impl Release {
    pub fn name(self) -> &'static str {
        match self {
            Release::Never => "never",
            Release::OwnerOnly => "owner_only",
            Release::AllowedParties => "allowed_parties",
            Release::AggregateOnly => "aggregate_only",
            Release::Public => "public",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Release::Never,
            Release::OwnerOnly,
            Release::AllowedParties,
            Release::AggregateOnly,
            Release::Public,
        ]
        .into_iter()
        .find(|r| r.name() == s)
    }
}

impl fmt::Display for Release {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// An asset's policy as declared by its owners.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetPolicy {
    pub owners: BTreeSet<PartyId>,
    /// Who may read the asset (owners are not readers unless listed).
    pub readers: BTreeSet<PartyId>,
    /// Purposes the asset may be used for.
    pub purposes: BTreeSet<String>,
    pub release: Release,
    /// Derived values of these kinds may be released up to the given
    /// level to the given parties (e.g. gradients `aggregate_only` to the
    /// coordinator): the owners' consent to an explicit, weaker
    /// derivation. Nothing else may weaken the policy.
    pub derive: BTreeMap<AssetKind, DerivePermission>,
}

/// Owners' consent for derived values of one kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivePermission {
    /// The weakest release allowed.
    pub release: Release,
    /// Who may receive them (when released).
    pub to: BTreeSet<PartyId>,
}

/// A declared confidential asset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetDecl {
    pub id: String,
    pub kind: AssetKind,
    pub policy: AssetPolicy,
}

/// An explicit derivation: `value` is an asset of `kind` with `release`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Derivation {
    pub value: ValueId,
    pub kind: AssetKind,
    pub release: Release,
}

/// Where an output goes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "to", content = "party")]
pub enum OutputRelease {
    /// Stays confidential: handed on encrypted, revealed to nobody here.
    #[default]
    Sealed,
    /// Revealed to one party.
    Party(PartyId),
    /// Revealed to anyone.
    Public,
}

/// All confidentiality declarations of a program.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confidentiality {
    /// What the computation is for; must be allowed by every input asset.
    pub purpose: Option<String>,
    pub parties: Vec<Party>,
    pub assets: Vec<AssetDecl>,
    /// Secret input name → asset ID.
    pub inputs: BTreeMap<String, String>,
    pub derivations: Vec<Derivation>,
    /// Output name → where it goes (absent: sealed).
    pub outputs: BTreeMap<String, OutputRelease>,
}

impl Confidentiality {
    pub fn party(&self, id: &str) -> Option<&Party> {
        self.parties.iter().find(|p| p.id.as_str() == id)
    }

    pub fn asset(&self, id: &str) -> Option<&AssetDecl> {
        self.assets.iter().find(|a| a.id == id)
    }

    pub fn output(&self, name: &str) -> &OutputRelease {
        const SEALED: OutputRelease = OutputRelease::Sealed;
        self.outputs.get(name).unwrap_or(&SEALED)
    }

    /// Structural checks: unique IDs, every referenced party and asset
    /// declared, owners non-empty, purposes non-empty strings.
    pub fn validate(&self) -> Result<()> {
        if let Some(p) = &self.purpose {
            check_text("purpose", p)?;
        }
        let mut seen = BTreeSet::new();
        for p in &self.parties {
            check_text("party name", &p.name)?;
            if !seen.insert(p.id.as_str()) {
                return Err(bad(format!("party {} is declared twice", p.id)));
            }
        }
        let party = |id: &PartyId, at: &str| {
            if self.party(id.as_str()).is_none() {
                Err(bad(format!("{at}: unknown party {id}")))
            } else {
                Ok(())
            }
        };
        let mut assets = BTreeSet::new();
        for a in &self.assets {
            check_id("asset", &a.id)?;
            if !assets.insert(a.id.as_str()) {
                return Err(bad(format!("asset {} is declared twice", a.id)));
            }
            if a.policy.owners.is_empty() {
                return Err(bad(format!("asset {} has no owner", a.id)));
            }
            for p in a
                .policy
                .owners
                .iter()
                .chain(&a.policy.readers)
                .chain(a.policy.derive.values().flat_map(|d| &d.to))
            {
                party(p, &format!("asset {}", a.id))?;
            }
            for p in &a.policy.purposes {
                check_text(&format!("asset {} purpose", a.id), p)?;
            }
            for (k, d) in &a.policy.derive {
                if d.release == Release::Public && !d.to.is_empty() {
                    return Err(bad(format!(
                        "asset {}: {k} derivations released as public reach anyone; a recipient \
                         list contradicts that",
                        a.id
                    )));
                }
            }
        }
        for (input, asset) in &self.inputs {
            if self.asset(asset).is_none() {
                return Err(bad(format!("input {input:?}: unknown asset {asset}")));
            }
        }
        for o in self.outputs.values() {
            if let OutputRelease::Party(p) = o {
                party(p, "output")?;
            }
        }
        Ok(())
    }
}
