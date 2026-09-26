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

/// Whose privacy a budget protects: the unit two neighbouring datasets
/// differ by. Explicit, because one training example is not always one
/// person.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyUnit {
    Record,
    User,
    Patient,
    Device,
    Organization,
    Custom(String),
}

impl PrivacyUnit {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "record" => Self::Record,
            "user" => Self::User,
            "patient" => Self::Patient,
            "device" => Self::Device,
            "organization" => Self::Organization,
            other => {
                check_id("privacy unit", other)
                    .map_err(|e| Error::new(Code::PrivacyPolicy, e.message))?;
                Self::Custom(other.to_owned())
            }
        })
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Record => "record",
            Self::User => "user",
            Self::Patient => "patient",
            Self::Device => "device",
            Self::Organization => "organization",
            Self::Custom(s) => s,
        }
    }
}

impl fmt::Display for PrivacyUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// An asset's differential-privacy budget: every release derived from it
/// is charged, and a release that would exceed `(epsilon, delta)` for its
/// `unit` is refused.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyBudget {
    pub unit: PrivacyUnit,
    #[serde(with = "exact_f64")]
    pub epsilon: f64,
    #[serde(with = "exact_f64")]
    pub delta: f64,
}

// Validated finite.
impl Eq for PrivacyBudget {}

impl PrivacyBudget {
    pub fn validate(&self) -> Result<()> {
        if !(self.epsilon.is_finite() && self.epsilon > 0.0) {
            return Err(Error::new(
                Code::PrivacyPolicy,
                format!(
                    "privacy budget epsilon must be positive, got {}",
                    self.epsilon
                ),
            ));
        }
        if !(self.delta.is_finite() && (0.0..1.0).contains(&self.delta)) {
            return Err(Error::new(
                Code::PrivacyPolicy,
                format!("privacy budget delta must be in [0, 1), got {}", self.delta),
            ));
        }
        if self.delta == 0.0 {
            return Err(Error::new(
                Code::PrivacyPolicy,
                "privacy budget delta must be positive: Gaussian mechanisms need delta > 0",
            ));
        }
        Ok(())
    }
}

/// The privacy accountant (and its version) every budget is accounted
/// with: part of the `PrivacyPolicyId`, so a workload cannot switch
/// accounting while claiming the approved configuration.
pub const PRIVACY_ACCOUNTANT: &str = "zcdp-cks2020";

/// Named privacy levels: a per-asset budget and the noise that goes with
/// it, so applications can say `privacy="strong"` and `explain` shows what
/// that means. `(name, epsilon, delta, noise_multiplier)`; the clip norm is
/// 1.0 (contributions are clipped to unit L2 norm). Each level's noise
/// affords about ten full-participation releases (no sampling
/// amplification) of a record-, patient- or user-level budget.
pub const PRIVACY_PRESETS: [(&str, f64, f64, f64); 3] = [
    ("standard", 8.0, 1e-5, 2.2),
    ("strong", 3.0, 1e-6, 6.0),
    ("maximum", 1.0, 1e-7, 18.0),
];

/// Patient-level privacy levels for DP-SGD (per-example clipping, Poisson
/// sampling, Rényi DP accounting), `(name, epsilon, delta,
/// noise_multiplier)`. The sampling rate comes from the run (expected batch
/// over the smallest dataset), and the preview says how many steps the
/// budget affords before training starts.
pub const PATIENT_PRIVACY_PRESETS: [(&str, f64, f64, f64); 2] = [
    ("standard-patient", 8.0, 1e-5, 1.0),
    ("strong-patient", 3.0, 1e-6, 1.2),
];

/// The budget and mechanism of a named privacy level.
pub fn privacy_preset(name: &str, unit: PrivacyUnit) -> Result<(PrivacyBudget, DpMechanism)> {
    if PATIENT_PRIVACY_PRESETS.iter().any(|p| p.0 == name) {
        return Err(Error::new(
            Code::PrivacyPolicy,
            format!(
                "{name:?} is a DP-SGD level: it needs per-example clipping and a sampling rate, so only fine-tuning uses it"
            ),
        ));
    }
    let (_, epsilon, delta, noise_multiplier) = PRIVACY_PRESETS
        .iter()
        .find(|p| p.0 == name)
        .copied()
        .ok_or_else(|| {
            Error::new(
                Code::PrivacyPolicy,
                format!("unknown privacy level {name:?} (standard, strong, maximum)"),
            )
        })?;
    Ok((
        PrivacyBudget {
            unit,
            epsilon,
            delta,
        },
        DpMechanism {
            kind: DpKind::DiscreteGaussian,
            clip_norm: 1.0,
            noise_multiplier,
            sampling_rate: None,
        },
    ))
}

/// A differential-privacy mechanism on an aggregation boundary: each
/// party's vector is clipped to L2 norm `clip_norm`, and discrete Gaussian
/// noise with standard deviation `noise_multiplier * clip_norm` is added to
/// the integer aggregate before release.
///
/// With `sampling_rate` (DP-SGD), each party's vector is instead the sum
/// of its Poisson-sampled privacy units' gradients, each clipped to
/// `clip_norm` by the attested training workload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpMechanism {
    pub kind: DpKind,
    #[serde(with = "exact_f64")]
    pub clip_norm: f64,
    #[serde(with = "exact_f64")]
    pub noise_multiplier: f64,
    /// Poisson sampling rate of the privacy units in each release (DP-SGD):
    /// every unit is included independently with this probability, and the
    /// accountant amplifies by it (RDP). Absent: every unit contributes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_exact_f64"
    )]
    pub sampling_rate: Option<f64>,
}

/// The accountant for sampled (DP-SGD) releases: Rényi DP of Poisson
/// subsampling (Zhu and Wang 2019, Theorem 6) over the discrete Gaussian.
pub const SAMPLED_PRIVACY_ACCOUNTANT: &str = "rdp-poisson-zw2019";

impl Eq for DpMechanism {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpKind {
    /// Canonne, Kamath and Steinke (2020): exact integer sampling, no
    /// floating-point attack surface.
    DiscreteGaussian,
}

impl DpKind {
    pub fn name(self) -> &'static str {
        match self {
            DpKind::DiscreteGaussian => "discrete_gaussian",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        (s == "discrete_gaussian").then_some(DpKind::DiscreteGaussian)
    }
}

impl DpMechanism {
    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::new(Code::PrivacyPolicy, m));
        if !(self.clip_norm.is_finite() && self.clip_norm > 0.0) {
            return bad(format!(
                "clip_norm must be positive, got {}",
                self.clip_norm
            ));
        }
        if !(self.noise_multiplier.is_finite() && self.noise_multiplier > 0.0) {
            return bad(format!(
                "noise_multiplier must be positive (no noise is no privacy), got {}",
                self.noise_multiplier
            ));
        }
        if let Some(q) = self.sampling_rate {
            if !(q.is_finite() && q > 0.0 && q < 1.0) {
                return bad(format!(
                    "sampling_rate must be in (0, 1) (Poisson sampling), got {q}"
                ));
            }
        }
        Ok(())
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
    /// Differential-privacy budget for everything released from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<PrivacyBudget>,
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

/// How contributions combine into an aggregate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationFunction {
    Sum,
    Mean,
}

impl AggregationFunction {
    pub fn name(self) -> &'static str {
        match self {
            AggregationFunction::Sum => "sum",
            AggregationFunction::Mean => "mean",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sum" => Some(AggregationFunction::Sum),
            "mean" => Some(AggregationFunction::Mean),
            _ => None,
        }
    }
}

/// Fixed-point encoding of real values for secure aggregation, which sums
/// integers modulo `2^modulus_bits`. Nothing about it is hidden: clipping
/// and rounding change what is aggregated, so they appear in `explain`,
/// the round manifest and the receipt.
///
/// Encode: clip `x` to `[clip_min, clip_max]`, then
/// `q = round((x - clip_min) * scale)` (half away from zero), an integer
/// in `[0, levels]`. Decode a sum of `n` codes: `S / scale + n * clip_min`.
/// Each value is off by at most `0.5 / scale` (plus clipping).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedPointCodec {
    #[serde(with = "exact_f64")]
    pub clip_min: f64,
    #[serde(with = "exact_f64")]
    pub clip_max: f64,
    pub scale: u64,
    pub modulus_bits: u32,
}

/// Clip bounds as exact decimal strings (Rust's shortest round-trip form):
/// hashed identities (policy, aggregation spec) use canonical JSON, which
/// carries no floats.
mod opt_exact_f64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(x: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
        match x {
            Some(x) => s.serialize_str(&format!("{x:?}")),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<f64>, D::Error> {
        let s = Option::<String>::deserialize(d)?;
        s.map(|s| match s.parse::<f64>() {
            Ok(x) if x.is_finite() && format!("{x:?}") == s => Ok(x),
            _ => Err(serde::de::Error::custom(format!(
                "{s:?} is not an exact finite number"
            ))),
        })
        .transpose()
    }
}

mod exact_f64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(x: &f64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{x:?}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
        let s = String::deserialize(d)?;
        match s.parse::<f64>() {
            Ok(x) if x.is_finite() && format!("{x:?}") == s => Ok(x),
            _ => Err(serde::de::Error::custom(format!(
                "{s:?} is not an exact finite number"
            ))),
        }
    }
}

// Clip bounds are validated finite (never NaN), so equality is total.
impl Eq for FixedPointCodec {}

impl FixedPointCodec {
    /// Largest code: `round((clip_max - clip_min) * scale)`.
    pub fn levels(&self) -> u64 {
        ((self.clip_max - self.clip_min) * self.scale as f64).round() as u64
    }

    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::new(Code::AggregationPlan, m));
        if !(self.clip_min.is_finite() && self.clip_max.is_finite())
            || self.clip_min >= self.clip_max
        {
            return bad(format!(
                "clip range [{}, {}] must be finite with min < max",
                self.clip_min, self.clip_max
            ));
        }
        if self.scale == 0 {
            return bad("scale must be at least 1".into());
        }
        // At most 2^62 so sums (and sums plus privacy noise) fit an i64.
        if !(8..=62).contains(&self.modulus_bits) {
            return bad(format!(
                "modulus must be 2^8 to 2^62, got 2^{}",
                self.modulus_bits
            ));
        }
        // Codes must be exact integers in an f64.
        let span = (self.clip_max - self.clip_min) * self.scale as f64;
        if span > (1u64 << 53) as f64 {
            return bad(format!(
                "clip range times scale ({span:e}) exceeds 2^53: codes would lose precision"
            ));
        }
        Ok(())
    }

    /// Largest possible sum of `participants` codes.
    pub fn max_aggregate(&self, participants: usize) -> u128 {
        self.levels() as u128 * participants as u128
    }

    /// Refuses a codec whose sum over `participants` could wrap the modulus
    /// and silently corrupt the aggregate.
    pub fn check_overflow(&self, participants: usize) -> Result<()> {
        self.validate()?;
        let max = self.max_aggregate(participants);
        let modulus = 1u128 << self.modulus_bits;
        if max >= modulus {
            return Err(Error::new(
                Code::AggregationOverflow,
                format!(
                    "secure aggregation may overflow: {participants} participants x maximum \
                     encoded value {} = maximum aggregate {max}, but the modulus is 2^{} = \
                     {modulus}; increase the modulus or reduce the clip range or scale",
                    self.levels(),
                    self.modulus_bits
                ),
            ));
        }
        Ok(())
    }

    pub fn encode(&self, x: f64) -> u64 {
        let c = if x.is_nan() {
            self.clip_min
        } else {
            x.clamp(self.clip_min, self.clip_max)
        };
        (((c - self.clip_min) * self.scale as f64).round() as u64).min(self.levels())
    }

    /// The real sum of `n` values whose codes sum to `sum` (which privacy
    /// noise can make negative).
    pub fn decode_sum(&self, sum: i64, n: usize) -> f64 {
        sum as f64 / self.scale as f64 + n as f64 * self.clip_min
    }

    /// The largest error a single encoded value carries (excluding
    /// clipping).
    pub fn resolution(&self) -> f64 {
        0.5 / self.scale as f64
    }
}

/// A declared aggregation boundary: output `output` is the `function` of
/// one contribution per party, computed by secure aggregation and released
/// only if at least `minimum` parties contributed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregationRule {
    pub output: String,
    pub function: AggregationFunction,
    pub minimum: usize,
    /// How many parties may collude with the coordinator without learning
    /// an honest party's contribution. Secure aggregation needs a threshold
    /// `t > (n + colluding) / 2`, so this is declared, never assumed.
    pub colluding: usize,
    pub codec: FixedPointCodec,
    /// Differential privacy applied to the aggregate before release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dp: Option<DpMechanism>,
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
    /// Aggregation boundaries (secure aggregation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aggregations: Vec<AggregationRule>,
}

impl Confidentiality {
    pub fn party(&self, id: &str) -> Option<&Party> {
        self.parties.iter().find(|p| p.id.as_str() == id)
    }

    pub fn asset(&self, id: &str) -> Option<&AssetDecl> {
        self.assets.iter().find(|a| a.id == id)
    }

    pub fn aggregation(&self, output: &str) -> Option<&AggregationRule> {
        self.aggregations.iter().find(|a| a.output == output)
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
            if let Some(b) = &a.policy.privacy {
                b.validate()?;
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
        let mut aggregated = BTreeSet::new();
        for a in &self.aggregations {
            if !aggregated.insert(a.output.as_str()) {
                return Err(Error::new(
                    Code::AggregationPlan,
                    format!("output {:?} is aggregated twice", a.output),
                ));
            }
            if a.minimum < 2 {
                return Err(Error::new(
                    Code::AggregationPlan,
                    format!(
                        "aggregate {:?}: minimum must be at least 2 (one contribution is not an aggregate)",
                        a.output
                    ),
                ));
            }
            a.codec.validate()?;
            if let Some(dp) = &a.dp {
                dp.validate()?;
            }
        }
        Ok(())
    }
}
