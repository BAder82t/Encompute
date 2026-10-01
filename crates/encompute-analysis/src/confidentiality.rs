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
//!   most restrictive release, to the parties every source allows;
//! - release forms: the forms every source allows.
//!
//! Policies weaken only through an explicit derivation that every source
//! asset permits. Violations are compile errors ENC1901–ENC1907: a value
//! released from sources that declare release forms must provably take
//! one of them (ENC1907).
//!
//! An `aggregate` declaration (ADR-012) lowers an output to an
//! [`AggregationBoundary`]: the output must be the sum of one input per
//! party, the codec must not overflow, and the aggregate gets a derived
//! policy. That boundary is what lets an `aggregate_only` value reach its
//! recipient; the secure-aggregation runtime enforces it.

use std::collections::{BTreeMap, BTreeSet};

use encompute_ir::confidentiality::{
    forms_within, meet_forms, AggregationFunction, AggregationRule, AssetDecl, AssetKind,
    AssetPolicy, Confidentiality, DerivePermission, DpMechanism, FixedPointCodec, OutputRelease,
    PartyId, PrivacyBudget, Release, ReleaseForm,
};
use encompute_ir::{Code, Elem, Error, Op, Program, Result, Shape, ValueId};
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
    /// The forms it may be released in; `None`: any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forms: Option<BTreeSet<ReleaseForm>>,
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
            forms: None,
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
                    forms: p.forms.clone(),
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
            forms: p.forms.clone(),
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
            forms: meet_forms(&self.forms, &other.forms),
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
    /// Aggregation boundaries: the mechanism satisfying `aggregate_only`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aggregations: Vec<AggregationBoundary>,
    /// Outputs that release information from privacy-budgeted assets: the
    /// accounting points (ADR-013).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub privacy_releases: Vec<PrivacyRelease>,
    pub warnings: Vec<String>,
}

/// An output that releases information from budgeted assets, and the
/// mechanism that pays for it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PrivacyRelease {
    pub output: String,
    /// Budgeted source assets, each charged for this release.
    pub charged: Vec<(String, PrivacyBudget)>,
    pub mechanism: DpMechanism,
    pub recipient: OutputRelease,
}

/// One party's contribution to an aggregate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Contribution {
    pub party: PartyId,
    pub input: String,
    pub asset: String,
    /// The asset's privacy budget, charged when the aggregate is released.
    pub budget: Option<PrivacyBudget>,
}

/// A lowered `aggregate` declaration.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AggregationBoundary {
    pub output: String,
    pub function: AggregationFunction,
    pub minimum: usize,
    /// Parties that may collude with the coordinator (declared).
    pub colluding: usize,
    /// Secure-aggregation threshold: `max(minimum, ⌊(n + colluding)/2⌋ + 1)`;
    /// the round completes only with at least this many parties.
    pub threshold: usize,
    pub codec: FixedPointCodec,
    /// One per party, ordered by party ID.
    pub contributions: Vec<Contribution>,
    pub vector_len: usize,
    pub recipient: OutputRelease,
    /// Differential privacy on the aggregate, if declared.
    pub dp: Option<DpMechanism>,
    /// The joined policy of the contributions (before aggregation).
    pub contribution_policy: Policy,
    /// The aggregate's derived policy: owners and purposes inherited, the
    /// recipients every contribution allows, never public unless every
    /// contribution is.
    pub aggregate_policy: Policy,
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
    Ok(run(program, false)?.map(|(r, _)| r))
}

/// The release forms each output of `program` is released in: those it
/// provably takes (see [`provable_forms`]) that its sources allow. A
/// bounded category counts only under a bound its sources declared: an
/// integer is otherwise a value, however small its range. Runs the same
/// analysis as [`analyze`] (a program that does not compile is refused the
/// same way); `None` without confidentiality declarations.
pub fn output_forms(program: &Program) -> Result<Option<BTreeMap<String, BTreeSet<ReleaseForm>>>> {
    Ok(run(program, true)?.map(|(_, f)| f))
}

/// Asset kinds that are derived artifacts (`DerivedArtifact`).
const ARTIFACTS: [AssetKind; 4] = [
    AssetKind::Model,
    AssetKind::ModelUpdate,
    AssetKind::Checkpoint,
    AssetKind::Adapter,
];

/// Every release form an output provably takes, from what the analysis
/// knows about it: a scalar `bool` is `Boolean` and a category bounded by
/// 1; a scalar integer proven to lie in `[0, hi]` is a category bounded by
/// `hi`; an aggregation boundary's output is `Aggregate` (and
/// `DpAggregate` with differential privacy); a value labelled a model,
/// model update, checkpoint or adapter is a `DerivedArtifact`. Anything
/// else takes no form the compiler can prove.
pub fn provable_forms(
    elem: Elem,
    shape: Shape,
    range: Option<(i128, i128)>,
    aggregated: bool,
    dp: bool,
    kind: AssetKind,
) -> BTreeSet<ReleaseForm> {
    let mut out = BTreeSet::new();
    if shape == Shape::Scalar {
        if elem == Elem::Bool {
            out.insert(ReleaseForm::Boolean);
            out.insert(ReleaseForm::BoundedCategory { max: 1 });
        } else if let Some((lo, hi)) = range.filter(|_| elem.is_exact()) {
            if lo >= 0 && hi >= 0 && hi <= u64::MAX as i128 {
                out.insert(ReleaseForm::BoundedCategory { max: hi as u64 });
            }
        }
    }
    if aggregated {
        out.insert(ReleaseForm::Aggregate);
        if dp {
            out.insert(ReleaseForm::DpAggregate);
        }
    }
    if ARTIFACTS.contains(&kind) {
        out.insert(ReleaseForm::DerivedArtifact);
    }
    out
}

/// Whether an output that provably takes forms `provable` may be released
/// under `allowed` (`None`: any form).
pub fn admissible(
    provable: &BTreeSet<ReleaseForm>,
    allowed: &Option<BTreeSet<ReleaseForm>>,
) -> bool {
    match allowed {
        None => true,
        Some(a) => provable.iter().any(|&p| a.iter().any(|&f| p.within(f))),
    }
}

type Forms = BTreeMap<String, BTreeSet<ReleaseForm>>;

/// The provable forms an output is released in under `allowed`: those
/// within an allowed form (any, without forms), bounded categories only
/// under a declared bound.
fn released_forms(
    provable: BTreeSet<ReleaseForm>,
    allowed: &Option<BTreeSet<ReleaseForm>>,
) -> BTreeSet<ReleaseForm> {
    provable
        .into_iter()
        .filter(|&f| match allowed {
            None => !matches!(f, ReleaseForm::BoundedCategory { .. }),
            Some(a) => a.iter().any(|&g| f.within(g)),
        })
        .collect()
}

fn run(program: &Program, all_forms: bool) -> Result<Option<(ConfidentialityReport, Forms)>> {
    let Some(c) = program.confidentiality() else {
        return Ok(None);
    };
    c.validate()?;
    // Integer ranges prove bounded categories; only exact programs have
    // them, and only programs with forms (or asking for them) need them.
    let ranges = if all_forms || c.assets.iter().any(|a| a.policy.forms.is_some()) {
        match crate::exact::semantics(program) {
            Ok(crate::exact::Semantics::Exact) => crate::exact::int_ranges(program).ok(),
            _ => None,
        }
    } else {
        None
    };
    let mut forms: Forms = BTreeMap::new();
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
    let mut aggregations = vec![];
    let mut privacy_releases = vec![];
    for o in program.outputs() {
        let dest = c.output(&o.name).clone();
        let sources = &policies[o.value.index()].sources;
        let aggregated = c.aggregation(&o.name).is_some();
        let dp = c.aggregation(&o.name).and_then(|a| a.dp.clone());
        let ty = program.node(o.value).ty;
        let provable = |kind| {
            provable_forms(
                ty.elem,
                ty.shape,
                ranges.as_ref().and_then(|r| r[o.value.index()]),
                aggregated,
                dp.is_some(),
                kind,
            )
        };
        if let Some(r) = privacy_release(
            c,
            &o.name,
            sources,
            &dest,
            aggregated,
            dp.as_ref(),
            &mut warnings,
        )? {
            privacy_releases.push(r);
        }
        if let Some(rule) = c.aggregation(&o.name) {
            let b = boundary(program, c, rule, o.value, &policies[o.value.index()], &dest)?;
            check_output(&o.name, &b.aggregate_policy, &dest)?;
            let p = provable(b.aggregate_policy.kind);
            check_form(&o.name, &b.aggregate_policy, true, &p)?;
            forms.insert(o.name.clone(), released_forms(p, &b.aggregate_policy.forms));
            for (id, name, _, r) in program.inputs() {
                if b.contributions.iter().any(|k| k.input == name)
                    && (r.lo < b.codec.clip_min || r.hi > b.codec.clip_max)
                {
                    warnings.push(format!(
                        "input {name:?} ({id}) ranges over [{}, {}] but aggregate {:?} clips \
                         each value to [{}, {}]: clipping changes what is aggregated",
                        r.lo, r.hi, o.name, b.codec.clip_min, b.codec.clip_max
                    ));
                }
            }
            let label = format!("aggregate:{}", o.name);
            for k in &b.contributions {
                flows.push(Flow {
                    from: k.asset.clone(),
                    to: label.clone(),
                    ops: vec!["secure_aggregation"],
                });
            }
            nodes.push(AssetNode {
                label,
                value: Some(o.value),
                policy: b.aggregate_policy.clone(),
                destination: Some(dest),
            });
            aggregations.push(b);
            continue;
        }
        let p = &policies[o.value.index()];
        check_output(&o.name, p, &dest)?;
        let provable = provable(p.kind);
        check_form(&o.name, p, dest != OutputRelease::Sealed, &provable)?;
        forms.insert(o.name.clone(), released_forms(provable, &p.forms));
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
    if !aggregations.is_empty() {
        warnings.push(
            "secure aggregation hides each party's contribution from everyone, including the \
             coordinator; it does not limit what the aggregate itself reveals about a party \
             (that needs differential privacy)"
                .into(),
        );
    }
    Ok(Some((
        ConfidentialityReport {
            purpose: c.purpose.clone(),
            nodes,
            flows,
            aggregations,
            privacy_releases,
            warnings,
        },
        forms,
    )))
}

/// Release-boundary detection: an output that leaves confidential
/// computation (to a party, or public) and derives from budgeted assets is
/// a privacy release; it must go through a DP mechanism, which charges
/// every budgeted source. Sealed outputs of encrypted computation stay
/// confidential and cost nothing. A secure-aggregation aggregate is always
/// a release, whatever its destination: the protocol unmasks it to the
/// coordinator, which writes it out (review finding DP-1).
fn privacy_release(
    c: &Confidentiality,
    output: &str,
    sources: &BTreeSet<String>,
    dest: &OutputRelease,
    aggregated: bool,
    dp: Option<&DpMechanism>,
    warnings: &mut Vec<String>,
) -> Result<Option<PrivacyRelease>> {
    let charged: Vec<(String, PrivacyBudget)> = sources
        .iter()
        .filter_map(|s| {
            c.asset(s)
                .and_then(|a| a.policy.privacy.clone())
                .map(|b| (s.clone(), b))
        })
        .collect();
    let releases = aggregated || !matches!(dest, OutputRelease::Sealed);
    if let Some(m) = dp {
        // A named level's noise must be exactly the level's for the charged
        // units (review finding DP-4): `explain` and the trust report show
        // the level, so it may not label other noise.
        let units: Vec<_> = charged.iter().map(|(_, b)| b.unit.clone()).collect();
        m.check_preset(&units).map_err(|e| {
            err(
                Code::PrivacyPolicy,
                format!("output {output:?}: {}", e.message),
            )
        })?;
    }
    match (charged.is_empty(), releases, dp) {
        (true, _, Some(_)) => {
            warnings.push(format!(
                "output {output:?} adds differential-privacy noise but no source asset has a \
                 privacy budget: nothing is accounted"
            ));
            Ok(None)
        }
        (true, _, None) | (false, false, _) => Ok(None),
        (false, true, None) => Err(err(
            Code::PrivacyPolicy,
            format!(
                "output {output:?} releases information from privacy-budgeted asset{} {} \
                 without a privacy mechanism: declare `dp` on its aggregation{}",
                if charged.len() == 1 { "" } else { "s" },
                charged
                    .iter()
                    .map(|(a, _)| a.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                if aggregated && matches!(dest, OutputRelease::Sealed) {
                    " (a secure-aggregation aggregate is released to the coordinator even \
                     when sealed)"
                } else {
                    ""
                }
            ),
        )),
        (false, true, Some(m)) => {
            for (a, b) in &charged {
                let organization =
                    b.unit == encompute_ir::confidentiality::PrivacyUnit::Organization;
                if let Some(q) = m.sampling_rate {
                    if organization {
                        return Err(err(
                            Code::PrivacyPolicy,
                            format!(
                                "output {output:?} Poisson-samples asset {a}'s privacy units, but its unit is organization: which parties contribute is public, so organizations cannot be sampled. Use a unit inside a party (patient, user, record) with per-example clipping"
                            ),
                        ));
                    }
                    warnings.push(format!(
                        "asset {a}'s budget protects each {unit}: the contributing (attested) workload samples each {unit} with probability {q} and clips each sampled {unit}'s gradient to L2 norm {c} (DP-SGD); the protocol only bounds each coordinate",
                        unit = b.unit,
                        c = m.clip_norm
                    ));
                    continue;
                }
                if !organization {
                    // Review finding DP-4 (ENC-SF-2026-068): nothing clips one unit inside a
                    // party's contribution, so a unit is charged as if it
                    // could change that whole contribution.
                    warnings.push(format!(
                        "asset {a}'s budget protects each {unit}, but only each party's whole \
                         contribution is clipped (to L2 norm {c}): one {unit} is charged as if \
                         it could change it entirely (sensitivity 2 x {c}, as for an \
                         organization). Per-{unit} clipping needs Poisson sampling (DP-SGD) \
                         in an attested workload",
                        unit = b.unit,
                        c = m.clip_norm
                    ));
                }
            }
            Ok(Some(PrivacyRelease {
                output: output.to_owned(),
                charged,
                mechanism: m.clone(),
                recipient: dest.clone(),
            }))
        }
    }
}

/// The inputs an output sums, each once: `None` if it is not a pure sum.
fn summands(
    program: &Program,
    v: ValueId,
    out: &mut Vec<ValueId>,
) -> std::result::Result<(), String> {
    match &program.node(v).op {
        Op::Input { .. } => {
            if out.contains(&v) {
                return Err(format!("input {v} is added more than once"));
            }
            out.push(v);
            Ok(())
        }
        Op::Add(a, b) => {
            summands(program, *a, out)?;
            summands(program, *b, out)
        }
        op => Err(format!("{v} is `{}`", op.mnemonic())),
    }
}

fn boundary(
    program: &Program,
    c: &Confidentiality,
    rule: &AggregationRule,
    value: ValueId,
    joined: &Policy,
    dest: &OutputRelease,
) -> Result<AggregationBoundary> {
    let plan_err = |m: String| {
        err(
            Code::AggregationPlan,
            format!("aggregate {:?}: {m}", rule.output),
        )
    };
    let mut leaves = vec![];
    summands(program, value, &mut leaves).map_err(|m| {
        plan_err(format!(
            "secure aggregation computes only a sum of one input per party, but {m}"
        ))
    })?;
    let mut contributions = vec![];
    for leaf in leaves {
        let Op::Input { name, .. } = &program.node(leaf).op else {
            unreachable!("summands returns inputs")
        };
        let asset = c
            .inputs
            .get(name)
            .and_then(|a| c.asset(a))
            .ok_or_else(|| plan_err(format!("input {name:?} is not bound to an asset")))?;
        let mut owners = asset.policy.owners.iter();
        let (Some(party), None) = (owners.next(), owners.next()) else {
            return Err(plan_err(format!(
                "asset {} must have exactly one owner, the party contributing it",
                asset.id
            )));
        };
        if contributions
            .iter()
            .any(|k: &Contribution| &k.party == party)
        {
            return Err(plan_err(format!(
                "party {party} contributes more than one input; each party contributes one"
            )));
        }
        contributions.push(Contribution {
            party: party.clone(),
            input: name.clone(),
            asset: asset.id.clone(),
            budget: asset.policy.privacy.clone(),
        });
    }
    contributions.sort_by(|a, b| a.party.cmp(&b.party));
    let n = contributions.len();
    if rule.minimum > n {
        return Err(plan_err(format!(
            "minimum {} exceeds the {n} contributing parties",
            rule.minimum
        )));
    }
    // Privacy against a coordinator colluding with `colluding` parties needs
    // t > (n + colluding) / 2 (Bonawitz et al. 2017).
    let threshold = rule.minimum.max((n + rule.colluding) / 2 + 1);
    if rule.colluding >= n || threshold > n {
        return Err(plan_err(format!(
            "{n} parties cannot tolerate {} colluding with the coordinator: that needs a \
             threshold of {threshold}, more than the parties there are",
            rule.colluding
        )));
    }
    rule.codec.check_overflow(n)?;
    if rule.dp.is_some() && !(rule.codec.clip_min <= 0.0 && 0.0 <= rule.codec.clip_max) {
        return Err(err(
            Code::PrivacyPolicy,
            format!(
                "aggregate {:?}: differential privacy needs a clip range containing 0 (got \
                 [{}, {}]), so that clipping never increases a contribution's norm",
                rule.output, rule.codec.clip_min, rule.codec.clip_max
            ),
        ));
    }
    if matches!(joined.release, Release::Never | Release::OwnerOnly) {
        return Err(err(
            Code::Declassification,
            format!(
                "aggregate {:?}: its contributions have release {}, which forbids releasing \
                 them even as an aggregate",
                rule.output, joined.release
            ),
        ));
    }
    let vector_len = match program.node(value).ty.shape {
        Shape::Scalar => 1,
        Shape::Vector(n) => n,
        Shape::Matrix(r, c) => r * c,
    };
    // Contributions of one kind (all gradients, say) keep it.
    let kinds: BTreeSet<AssetKind> = contributions
        .iter()
        .filter_map(|k| c.asset(&k.asset).map(|a| a.kind))
        .collect();
    let mut joined = joined.clone();
    if let (1, Some(k)) = (kinds.len(), kinds.first()) {
        joined.kind = *k;
    }
    let mut aggregate_policy = joined.clone();
    if joined.release != Release::Public {
        aggregate_policy.release = Release::AllowedParties;
    }
    Ok(AggregationBoundary {
        output: rule.output.clone(),
        function: rule.function,
        minimum: rule.minimum,
        colluding: rule.colluding,
        threshold,
        codec: rule.codec,
        contributions,
        vector_len,
        recipient: dest.clone(),
        dp: rule.dp.clone(),
        contribution_policy: joined,
        aggregate_policy,
    })
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

/// A released output (to a party, public, or through an aggregation
/// boundary) whose sources declare release forms must provably take one
/// of them (ENC1907). A sealed output releases nothing.
fn check_form(
    name: &str,
    p: &Policy,
    releases: bool,
    provable: &BTreeSet<ReleaseForm>,
) -> Result<()> {
    if !releases || admissible(provable, &p.forms) {
        return Ok(());
    }
    let list = |s: &BTreeSet<ReleaseForm>| {
        if s.is_empty() {
            "none".to_owned()
        } else {
            s.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    Err(err(
        Code::ReleaseForm,
        format!(
            "output {name:?} (derived from {}) may be released only as {}, but the compiler \
             proves it is only {}: release a value of an allowed form (a boolean, an integer \
             proven within the category bound, an aggregate), or keep it sealed",
            set(&p.sources),
            list(p.forms.as_ref().expect("admissible without forms")),
            list(provable)
        ),
    ))
}

/// Whether `declared`, an asset's policy as a program declares it, is at
/// least as strict as `registered`, the policy its owner registered, for a
/// program run for `purpose`: the same owners, a release no weaker,
/// readers and purposes within the registered ones (and the purpose among
/// them), forms and derivations within the registered ones, the same
/// privacy budget. A program therefore never declares a weaker policy than
/// its owner registered. Purposes are ENC1903, forms ENC1907, anything
/// else ENC1904.
pub fn refines(declared: &AssetPolicy, registered: &AssetPolicy, purpose: &str) -> Result<()> {
    within_policy(
        declared,
        registered,
        Some(purpose),
        "the program declares a weaker policy than its owner registered",
    )
}

/// Whether `declared`, a derived result's onward policy, is no wider than
/// `ceiling`, the join of its parents' registered policies
/// ([`join_registered`]): the same owners, a release no weaker, readers,
/// purposes, forms and derivations within the ceiling's, the same privacy
/// budget. Purposes are ENC1903, forms ENC1907, anything else ENC1904.
pub fn no_wider(declared: &AssetPolicy, ceiling: &AssetPolicy) -> Result<()> {
    within_policy(
        declared,
        ceiling,
        None,
        "the derived result's policy is wider than its parents'",
    )
}

/// The join of the policies the owners of a result's parents registered:
/// every owner, the weakest release none of them exceeds, the readers,
/// purposes and derivations all of them allow, the forms all of them
/// admit. Never wider than any parent's. Parents under different privacy
/// budgets have no join (ENC1904): a result of them is not recorded.
pub fn join_registered(policies: &[AssetPolicy]) -> Result<AssetPolicy> {
    let (first, rest) = policies
        .split_first()
        .ok_or_else(|| err(Code::Declassification, "a derived result has parents"))?;
    let mut out = first.clone();
    for p in rest {
        if p.privacy != out.privacy {
            return Err(err(
                Code::Declassification,
                "the parents carry different privacy budgets: their result has no joined policy",
            ));
        }
        out.owners = out.owners.union(&p.owners).cloned().collect();
        out.readers = out.readers.intersection(&p.readers).cloned().collect();
        out.purposes = out.purposes.intersection(&p.purposes).cloned().collect();
        out.release = out.release.min(p.release);
        out.derive = out
            .derive
            .iter()
            .filter_map(|(k, a)| {
                p.derive.get(k).map(|b| {
                    (
                        *k,
                        DerivePermission {
                            release: a.release.min(b.release),
                            to: a.to.intersection(&b.to).cloned().collect(),
                        },
                    )
                })
            })
            .collect();
        out.forms = meet_forms(&out.forms, &p.forms);
    }
    Ok(out)
}

fn within_policy(
    declared: &AssetPolicy,
    registered: &AssetPolicy,
    purpose: Option<&str>,
    what: &str,
) -> Result<()> {
    let weaker = |m: String| err(Code::Declassification, format!("{what}: {m}"));
    if declared.owners != registered.owners {
        return Err(weaker(format!(
            "owners {} instead of {}",
            set(&declared.owners),
            set(&registered.owners)
        )));
    }
    if declared.release > registered.release {
        return Err(weaker(format!(
            "release {} is weaker than {}",
            declared.release, registered.release
        )));
    }
    if !declared.readers.is_subset(&registered.readers) {
        return Err(weaker(format!(
            "readers {} are not among {}",
            set(&declared.readers),
            set(&registered.readers)
        )));
    }
    let purposes_ok = match purpose {
        Some(purpose) => {
            registered.purposes.contains(purpose)
                && declared
                    .purposes
                    .iter()
                    .all(|p| p == purpose && registered.purposes.contains(p))
        }
        None => declared.purposes.is_subset(&registered.purposes),
    };
    if !purposes_ok {
        return Err(err(
            Code::PurposeViolation,
            match purpose {
                Some(purpose) => format!(
                    "the program declares purposes {} for an asset its owner registered for {}; \
                     it may declare only {purpose:?}, and only if the owner registered it",
                    set(&declared.purposes),
                    set(&registered.purposes)
                ),
                None => format!(
                    "{what}: purposes {} are not among {}",
                    set(&declared.purposes),
                    set(&registered.purposes)
                ),
            },
        ));
    }
    if !forms_within(&declared.forms, &registered.forms) {
        let list = |f: &Option<BTreeSet<ReleaseForm>>| match f {
            None => "any form".to_owned(),
            Some(s) => format!(
                "[{}]",
                s.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        return Err(err(
            Code::ReleaseForm,
            format!(
                "the program declares release forms {} for an asset its owner registered with {}",
                list(&declared.forms),
                list(&registered.forms)
            ),
        ));
    }
    for (k, d) in &declared.derive {
        match registered.derive.get(k) {
            Some(r) if d.release <= r.release && d.to.is_subset(&r.to) => {}
            _ => {
                return Err(weaker(format!(
                    "{k} derivations {} to {} are not permitted by the owner",
                    d.release,
                    set(&d.to)
                )))
            }
        }
    }
    if declared.privacy != registered.privacy {
        return Err(weaker("another privacy budget".into()));
    }
    Ok(())
}
