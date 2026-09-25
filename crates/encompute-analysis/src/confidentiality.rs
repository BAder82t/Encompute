//! Confidentiality analysis (ADR-010): the policy of every value, and the
//! flows a program's declarations forbid.
//!
//! A value's policy is the join of its operands' policies, which is at
//! least as restrictive as every input:
//! - owners: union (everyone with a stake);
//! - audience (who may learn it): intersection;
//! - purposes: intersection;
//! - release: the most restrictive;
//! - derivation permissions: kinds allowed by every source, each at the
//!   most restrictive release, to the parties every source allows.
//!
//! Policies weaken only through an explicit derivation that every source
//! asset permits. Violations are compile errors ENC1901–ENC1906.

use std::collections::{BTreeMap, BTreeSet};

use encompute_ir::confidentiality::{
    AssetDecl, AssetKind, Confidentiality, DerivePermission, OutputRelease, PartyId, Release,
};
use encompute_ir::{Code, Error, Op, Program, Result, ValueId};
use serde::Serialize;

/// The effective policy of a value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Policy {
    pub owners: BTreeSet<PartyId>,
    /// Who may learn the value; `None`: anyone (public data).
    pub audience: Option<BTreeSet<PartyId>>,
    /// Purposes it may serve; `None`: any.
    pub purposes: Option<BTreeSet<String>>,
    pub release: Release,
    /// Permitted derivations; `None`: unrestricted (public data).
    pub derive: Option<BTreeMap<AssetKind, DerivePermission>>,
    pub kind: AssetKind,
    /// Declared assets it is derived from.
    pub sources: BTreeSet<String>,
}

impl Policy {
    /// Public data: the identity of `join`.
    pub fn public() -> Self {
        Self {
            owners: BTreeSet::new(),
            audience: None,
            purposes: None,
            release: Release::Public,
            derive: None,
            kind: AssetKind::Generic,
            sources: BTreeSet::new(),
        }
    }

    /// The policy an asset's owners declared.
    pub fn of_asset(a: &AssetDecl) -> Self {
        let p = &a.policy;
        let audience = match p.release {
            Release::Never => BTreeSet::new(),
            Release::OwnerOnly => p.owners.clone(),
            Release::AllowedParties | Release::AggregateOnly => p.readers.clone(),
            Release::Public => {
                return Self {
                    owners: p.owners.clone(),
                    sources: [a.id.clone()].into(),
                    kind: a.kind,
                    purposes: Some(p.purposes.clone()),
                    derive: Some(p.derive.clone()),
                    ..Self::public()
                }
            }
        };
        Self {
            owners: p.owners.clone(),
            audience: Some(audience),
            purposes: Some(p.purposes.clone()),
            release: p.release,
            derive: Some(p.derive.clone()),
            kind: a.kind,
            sources: [a.id.clone()].into(),
        }
    }

    /// The least restrictive policy at least as restrictive as both.
    pub fn join(&self, other: &Policy) -> Policy {
        fn meet<T: Ord + Clone>(
            a: &Option<BTreeSet<T>>,
            b: &Option<BTreeSet<T>>,
        ) -> Option<BTreeSet<T>> {
            match (a, b) {
                (None, x) | (x, None) => x.clone(),
                (Some(a), Some(b)) => Some(a.intersection(b).cloned().collect()),
            }
        }
        let derive = match (&self.derive, &other.derive) {
            (None, x) | (x, None) => x.clone(),
            (Some(a), Some(b)) => Some(
                a.iter()
                    .filter_map(|(k, da)| {
                        b.get(k).map(|db| {
                            (
                                *k,
                                DerivePermission {
                                    release: da.release.min(db.release),
                                    to: da.to.intersection(&db.to).cloned().collect(),
                                },
                            )
                        })
                    })
                    .collect(),
            ),
        };
        Policy {
            owners: self.owners.union(&other.owners).cloned().collect(),
            audience: meet(&self.audience, &other.audience),
            purposes: meet(&self.purposes, &other.purposes),
            release: self.release.min(other.release),
            derive,
            kind: AssetKind::Generic,
            sources: self.sources.union(&other.sources).cloned().collect(),
        }
    }

    /// Whether this value may be revealed to party `p`.
    pub fn may_reveal_to(&self, p: &PartyId) -> bool {
        match self.release {
            Release::Never | Release::AggregateOnly => false,
            _ => self.audience.as_ref().is_none_or(|a| a.contains(p)),
        }
    }
}

/// A node of the asset graph: a declared asset, an explicit derivation,
/// or an output.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AssetNode {
    /// Declared asset ID, `derived:%N`, or `output:NAME`.
    pub label: String,
    pub value: Option<ValueId>,
    pub policy: Policy,
    /// Where an output goes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<OutputRelease>,
}

/// `from` flows into `to` through these operations.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Flow {
    pub from: String,
    pub to: String,
    pub ops: Vec<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ConfidentialityReport {
    pub purpose: Option<String>,
    pub nodes: Vec<AssetNode>,
    pub flows: Vec<Flow>,
    pub warnings: Vec<String>,
}

fn err(code: Code, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

fn set<T: std::fmt::Display>(s: &BTreeSet<T>) -> String {
    if s.is_empty() {
        "nobody".into()
    } else {
        s.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Analyze `program`'s confidentiality declarations; `None` if it has none.
pub fn analyze(program: &Program) -> Result<Option<ConfidentialityReport>> {
    let Some(c) = program.confidentiality() else {
        return Ok(None);
    };
    c.validate()?;
    let derivations: BTreeMap<ValueId, _> = c.derivations.iter().map(|d| (d.value, d)).collect();
    let mut policies: Vec<Policy> = Vec::with_capacity(program.nodes().len());
    // Nearest asset labels above each value, and the operations since them.
    let mut nearest: Vec<BTreeSet<String>> = Vec::with_capacity(program.nodes().len());
    let mut ops: Vec<BTreeSet<&'static str>> = Vec::with_capacity(program.nodes().len());
    let mut nodes: Vec<AssetNode> = vec![];
    let mut flows: Vec<Flow> = vec![];
    for a in &c.assets {
        nodes.push(AssetNode {
            label: a.id.clone(),
            value: None,
            policy: Policy::of_asset(a),
            destination: None,
        });
    }
    let mut warnings = vec![];
    for (id, node) in program.iter() {
        let (mut policy, near, mut via) = match &node.op {
            Op::Input { name, .. } => {
                let asset_id = c.inputs.get(name).ok_or_else(|| {
                    err(
                        Code::PolicyDeclaration,
                        format!(
                            "secret input {name:?} is not bound to an asset; every secret input \
                             of a program with confidentiality declarations must be"
                        ),
                    )
                })?;
                let asset = c.asset(asset_id).expect("validated");
                check_purpose(c, asset)?;
                (
                    Policy::of_asset(asset),
                    [asset_id.clone()].into(),
                    BTreeSet::new(),
                )
            }
            Op::Const { .. } => (Policy::public(), BTreeSet::new(), BTreeSet::new()),
            op => {
                let mut p = Policy::public();
                let (mut near, mut via) = (BTreeSet::new(), BTreeSet::new());
                for o in op.operands() {
                    p = p.join(&policies[o.index()]);
                    near.extend(nearest[o.index()].iter().cloned());
                    via.extend(ops[o.index()].iter().copied());
                }
                via.insert(op.mnemonic());
                (p, near, via)
            }
        };
        let mut near = near;
        if let Some(d) = derivations.get(&id) {
            let is_input = matches!(node.op, Op::Input { .. });
            policy = derive(policy, id, d.kind, d.release, is_input)?;
            let label = format!("derived:{id}");
            for from in &near {
                flows.push(Flow {
                    from: from.clone(),
                    to: label.clone(),
                    ops: via.iter().copied().collect(),
                });
            }
            nodes.push(AssetNode {
                label: label.clone(),
                value: Some(id),
                policy: policy.clone(),
                destination: None,
            });
            near = [label].into();
            via = BTreeSet::new();
        }
        policies.push(policy);
        nearest.push(near);
        ops.push(via);
    }
    for o in program.outputs() {
        let p = &policies[o.value.index()];
        let dest = c.output(&o.name).clone();
        check_output(&o.name, p, &dest)?;
        if dest == OutputRelease::Sealed && p.release == Release::AggregateOnly {
            warnings.push(format!(
                "output {:?} ({}) may only be released as part of an aggregate: it needs an \
                 aggregation boundary (e.g. secure aggregation) before any party learns it",
                o.name, p.kind
            ));
        }
        let label = format!("output:{}", o.name);
        for from in &nearest[o.value.index()] {
            flows.push(Flow {
                from: from.clone(),
                to: label.clone(),
                ops: ops[o.value.index()].iter().copied().collect(),
            });
        }
        nodes.push(AssetNode {
            label,
            value: Some(o.value),
            policy: p.clone(),
            destination: Some(dest),
        });
    }
    Ok(Some(ConfidentialityReport {
        purpose: c.purpose.clone(),
        nodes,
        flows,
        warnings,
    }))
}

fn check_purpose(c: &Confidentiality, asset: &AssetDecl) -> Result<()> {
    let allowed = &asset.policy.purposes;
    match &c.purpose {
        Some(p) if allowed.contains(p) => Ok(()),
        Some(p) => Err(err(
            Code::PurposeViolation,
            format!(
                "asset {} cannot be used for purpose {p:?}: it allows only {}",
                asset.id,
                set(allowed)
            ),
        )),
        None if allowed.is_empty() => Ok(()),
        None => Err(err(
            Code::PurposeViolation,
            format!(
                "the program declares no purpose, but asset {} may only be used for {}",
                asset.id,
                set(allowed)
            ),
        )),
    }
}

/// Apply an explicit derivation. Restricting is always allowed; weakening
/// only as far as every source asset permits for `kind`.
/// Kinds are the program's claims about its values; an owner's derivation
/// permission is consent for values the (reviewed) program labels that
/// kind. To keep a label from borrowing another kind's permission, only a
/// computed value (not an input) may be labelled, and a value that already
/// has a kind keeps it.
fn derive(
    mut p: Policy,
    id: ValueId,
    kind: AssetKind,
    release: Release,
    is_input: bool,
) -> Result<Policy> {
    if p.kind != AssetKind::Generic && p.kind != kind {
        return Err(err(
            Code::Declassification,
            format!("{id} is a {} and cannot be relabelled as a {kind}", p.kind),
        ));
    }
    if release > p.release && is_input {
        return Err(err(
            Code::Declassification,
            format!(
                "{id} is an input asset: only values computed from it may be derived under a \
                 weaker policy"
            ),
        ));
    }
    if release <= p.release {
        p.release = release;
        p.kind = kind;
        if release == Release::Never {
            p.audience = Some(BTreeSet::new());
        }
        return Ok(p);
    }
    let permitted = match &p.derive {
        None => None,
        Some(d) => Some(d.get(&kind).ok_or_else(|| {
            err(
                Code::Declassification,
                format!(
                    "{id} cannot become a {kind} released as {release}: its sources ({}) do not \
                     permit {kind} derivations",
                    set(&p.sources)
                ),
            )
        })?),
    };
    if let Some(perm) = permitted {
        if release > perm.release {
            return Err(err(
                Code::Declassification,
                format!(
                    "{id} cannot become a {kind} released as {release}: its sources ({}) allow \
                     at most {}",
                    set(&p.sources),
                    perm.release
                ),
            ));
        }
        p.audience = if release == Release::Public {
            None
        } else {
            Some(perm.to.clone())
        };
    }
    p.release = release;
    p.kind = kind;
    Ok(p)
}

fn check_output(name: &str, p: &Policy, dest: &OutputRelease) -> Result<()> {
    let what = || {
        if p.sources.is_empty() {
            format!("output {name:?}")
        } else {
            format!("output {name:?} (derived from {})", set(&p.sources))
        }
    };
    match dest {
        OutputRelease::Sealed => Ok(()),
        OutputRelease::Public if p.release == Release::Public && p.audience.is_none() => Ok(()),
        OutputRelease::Public => Err(err(
            Code::PublicRelease,
            format!(
                "confidential value flows to a public output: {} has release {}; it must \
                 stay sealed or pass through a permitted derivation",
                what(),
                p.release
            ),
        )),
        OutputRelease::Party(to) if p.release == Release::AggregateOnly => Err(err(
            Code::AggregationRequired,
            format!(
                "{} may only be released as part of an aggregate; revealing it to {to} \
                 directly is forbidden: it needs an aggregation boundary",
                what()
            ),
        )),
        OutputRelease::Party(to) if p.may_reveal_to(to) => Ok(()),
        OutputRelease::Party(to) => Err(err(
            Code::UnauthorizedParty,
            format!(
                "party {to} is not authorized to learn {}: release {}, audience {}",
                what(),
                p.release,
                p.audience.as_ref().map_or("anyone".into(), set)
            ),
        )),
    }
}
