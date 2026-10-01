//! Placement: where work may run and who may run it (public-sector
//! governance, residency and operators).
//!
//! A [`Location`] says where a machine is: the provider, its region and
//! optionally its zone, with the jurisdiction taken from a versioned
//! [`locations`] table, never from the party that declares the location. A
//! [`PlacementConstraints`] document is one party's rule about where its
//! data, ciphertexts, keys or evidence may be handled and who may operate
//! the machines. Constraints from several sources are combined so that
//! adding a source can only shrink what is admitted:
//!
//! - allowed sets (regions, operators, evaluators) intersect; an absent set
//!   does not restrict;
//! - prohibited locations union, and **deny wins**: a location matching any
//!   prohibited pattern is refused even when an allowed pattern matches;
//! - the minimum evidence level is the maximum.
//!
//! A region or zone missing from the table never matches an allowed
//! pattern, a pattern naming an unknown value is refused when it is
//! declared, and a machine whose location is unknown is inadmissible under
//! any constraint. Region is not jurisdiction: a region names where a
//! machine is, not whose law reaches it, which is why constraints also
//! name operators.
//!
//! Every identity here is `SHA256(domain || 0x00 || canonical JSON)`, and
//! absent optional fields are not serialized, so adding one later keeps
//! every existing digest.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use encompute_ir::{Code, Error, Result};

use crate::canonical::canonical_json;
use crate::hash::{hex, tagged};

pub const PLACEMENT_VERSION: u32 = 1;

const PLACEMENT: &str = "encompute.placement.v1";
const LOCATIONS: &str = "encompute.locations-table.v1";
const EVIDENCE: &str = "encompute.location-evidence.v1";

fn refuse(m: impl Into<String>) -> Error {
    Error::new(Code::GovernanceResidency, m)
}

/// How a location is known. Ordered: each level is strictly stronger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationEvidence {
    /// The service says so itself. Never satisfies production.
    SelfDeclared,
    /// Signed by a human `security_admin` of the operator organization,
    /// audited and recorded in the governance log.
    OperatorDeclared,
    /// Taken from a verified TEE attestation (the cloud's own zone claim).
    Attested,
}

impl LocationEvidence {
    pub fn as_str(self) -> &'static str {
        match self {
            LocationEvidence::SelfDeclared => "self_declared",
            LocationEvidence::OperatorDeclared => "operator_declared",
            LocationEvidence::Attested => "attested",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "self_declared" => Some(Self::SelfDeclared),
            "operator_declared" => Some(Self::OperatorDeclared),
            "attested" => Some(Self::Attested),
            _ => None,
        }
    }

    /// How reports label it: attested or declared.
    pub fn label(self) -> &'static str {
        match self {
            LocationEvidence::Attested => "attested",
            _ => "declared",
        }
    }
}

impl fmt::Display for LocationEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a machine is. The jurisdiction comes from the table.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub jurisdiction: String,
    pub provider: String,
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
}

impl Location {
    /// The location of `provider`'s `region` (and `zone`), with the
    /// jurisdiction the table gives it; refused when the table does not
    /// know it. Nothing the declarer says can set the jurisdiction.
    pub fn resolve(provider: &str, region: &str, zone: Option<&str>) -> Result<Self> {
        let Some(jurisdiction) = locations::jurisdiction_of(provider, region) else {
            return Err(refuse(format!(
                "the location table does not know region {region:?} of provider {provider:?}: \
                 an unknown location is never admitted"
            )));
        };
        if let Some(z) = zone {
            if !locations::zone_belongs(provider, region, z) {
                return Err(refuse(format!(
                    "zone {z:?} is not a zone of {provider:?} region {region:?}"
                )));
            }
        }
        Ok(Self {
            jurisdiction: jurisdiction.to_owned(),
            provider: provider.to_owned(),
            region: region.to_owned(),
            zone: zone.map(str::to_owned),
        })
    }

    /// Whether the jurisdiction is the table's for this provider and
    /// region (a forged jurisdiction fails).
    pub fn check(&self) -> Result<()> {
        let want = Self::resolve(&self.provider, &self.region, self.zone.as_deref())?;
        if want.jurisdiction != self.jurisdiction {
            return Err(refuse(format!(
                "{}/{} is in {}, not {}",
                self.provider, self.region, want.jurisdiction, self.jurisdiction
            )));
        }
        Ok(())
    }

    /// `provider/region[/zone] (jurisdiction)`.
    pub fn display(&self) -> String {
        match &self.zone {
            Some(z) => format!(
                "{}/{}/{z} ({})",
                self.provider, self.region, self.jurisdiction
            ),
            None => format!("{}/{} ({})", self.provider, self.region, self.jurisdiction),
        }
    }

    /// The table-version-bound digest of a location and its evidence: what
    /// an operator signs and a plan or grant records.
    pub fn evidence_digest(&self, evidence: LocationEvidence, source: &str) -> String {
        #[derive(Serialize)]
        struct E<'a> {
            location: &'a Location,
            evidence: LocationEvidence,
            source: &'a str,
            table: String,
        }
        hex(&tagged(
            EVIDENCE,
            &canonical_json(&E {
                location: self,
                evidence,
                source,
                table: locations::digest(),
            })
            .expect("strings only"),
        ))
    }
}

/// A set of locations: each field present must match; an absent field
/// matches anything. At least one field is present.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocationPattern {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
}

impl LocationPattern {
    pub fn jurisdiction(j: &str) -> Self {
        Self {
            jurisdiction: Some(j.to_owned()),
            provider: None,
            region: None,
            zone: None,
        }
    }

    pub fn region(provider: &str, region: &str) -> Self {
        Self {
            jurisdiction: None,
            provider: Some(provider.to_owned()),
            region: Some(region.to_owned()),
            zone: None,
        }
    }

    pub fn provider(provider: &str) -> Self {
        Self {
            jurisdiction: None,
            provider: Some(provider.to_owned()),
            region: None,
            zone: None,
        }
    }

    /// A pattern naming only values the table knows: an unknown value
    /// could never match, so a typo would silently admit or fail to
    /// prohibit; it is refused instead.
    pub fn check(&self) -> Result<()> {
        if self.jurisdiction.is_none()
            && self.provider.is_none()
            && self.region.is_none()
            && self.zone.is_none()
        {
            return Err(refuse("a location pattern names at least one field"));
        }
        if let Some(j) = &self.jurisdiction {
            if !locations::jurisdictions().contains(j.as_str()) {
                return Err(refuse(format!("unknown jurisdiction {j:?}")));
            }
        }
        if let Some(p) = &self.provider {
            if !locations::providers().contains(&p.as_str()) {
                return Err(refuse(format!("unknown provider {p:?}")));
            }
        }
        if let Some(r) = &self.region {
            let known = match &self.provider {
                Some(p) => locations::jurisdiction_of(p, r).is_some(),
                None => locations::any_provider_has_region(r),
            };
            if !known {
                return Err(refuse(format!("unknown region {r:?}")));
            }
            if let (Some(j), Some(p)) = (&self.jurisdiction, &self.provider) {
                if locations::jurisdiction_of(p, r) != Some(j.as_str()) {
                    return Err(refuse(format!("{p}/{r} is not in {j}")));
                }
            }
        }
        if let Some(z) = &self.zone {
            let (Some(p), Some(r)) = (&self.provider, &self.region) else {
                return Err(refuse("a zone pattern also names its provider and region"));
            };
            if !locations::zone_belongs(p, r, z) {
                return Err(refuse(format!("zone {z:?} is not a zone of {p}/{r}")));
            }
        }
        Ok(())
    }

    fn field_matches(want: &Option<String>, have: &str) -> bool {
        want.as_deref().is_none_or(|w| w == have)
    }

    /// Whether `l` is inside this pattern (every present field equal; a
    /// zone pattern needs a zone). Used for **allowed** sets: it takes a
    /// known match to admit.
    pub fn contains(&self, l: &Location) -> bool {
        Self::field_matches(&self.jurisdiction, &l.jurisdiction)
            && Self::field_matches(&self.provider, &l.provider)
            && Self::field_matches(&self.region, &l.region)
            && match (&self.zone, &l.zone) {
                (None, _) => true,
                (Some(p), Some(z)) => p == z,
                (Some(_), None) => false,
            }
    }

    /// Whether `l` may be inside this pattern. Used for **prohibited**
    /// sets: a location that does not say its zone might be in the
    /// prohibited one, so it matches (deny wins).
    pub fn may_contain(&self, l: &Location) -> bool {
        Self::field_matches(&self.jurisdiction, &l.jurisdiction)
            && Self::field_matches(&self.provider, &l.provider)
            && Self::field_matches(&self.region, &l.region)
            && match (&self.zone, &l.zone) {
                (None, _) | (Some(_), None) => true,
                (Some(p), Some(z)) => p == z,
            }
    }
}

/// What a constraint covers. Ciphertexts copied to a prohibited location
/// stay FHE-protected, but an owner may still require more.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Steps that handle plaintext (an owner's client, a TEE decryptor).
    Plaintext,
    /// Steps that handle ciphertexts (an evaluator, a SecAgg coordinator).
    Ciphertext,
    /// Brokers, KMS and the decryptor's key store.
    Keys,
    /// Stored evidence.
    Evidence,
}

impl Scope {
    pub const ALL: [Scope; 4] = [
        Scope::Plaintext,
        Scope::Ciphertext,
        Scope::Keys,
        Scope::Evidence,
    ];
}

fn all_scopes() -> BTreeSet<Scope> {
    Scope::ALL.into_iter().collect()
}

fn is_all_scopes(s: &BTreeSet<Scope>) -> bool {
    s.len() == Scope::ALL.len()
}

fn default_evidence() -> LocationEvidence {
    LocationEvidence::SelfDeclared
}

fn is_default_evidence(e: &LocationEvidence) -> bool {
    *e == LocationEvidence::SelfDeclared
}

/// One party's rule about where work may run and who may run it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementConstraints {
    /// Where work may run; absent: no restriction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_regions: Option<BTreeSet<LocationPattern>>,
    /// Where it may never run. Deny wins.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub prohibited_locations: BTreeSet<LocationPattern>,
    /// Organizations that may operate the machines; absent: any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_operators: Option<BTreeSet<String>>,
    /// Evaluators that may run it; absent: any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_evaluators: Option<BTreeSet<String>>,
    /// The weakest location evidence accepted.
    #[serde(
        default = "default_evidence",
        skip_serializing_if = "is_default_evidence"
    )]
    pub min_evidence: LocationEvidence,
    /// What it covers; absent: all four scopes.
    #[serde(default = "all_scopes", skip_serializing_if = "is_all_scopes")]
    pub applies_to: BTreeSet<Scope>,
}

impl Default for PlacementConstraints {
    fn default() -> Self {
        Self {
            allowed_regions: None,
            prohibited_locations: BTreeSet::new(),
            allowed_operators: None,
            allowed_evaluators: None,
            min_evidence: LocationEvidence::SelfDeclared,
            applies_to: all_scopes(),
        }
    }
}

/// Why one constraint refused a machine: which field.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Refused {
    /// The machine's location is unknown or not given, and a constraint
    /// needs it.
    UnknownLocation,
    /// `allowed_regions` does not admit the location.
    AllowedRegions,
    /// A prohibited pattern matches the location.
    ProhibitedLocations,
    /// `allowed_operators` does not name the operator.
    AllowedOperators,
    /// `allowed_evaluators` does not name the evaluator.
    AllowedEvaluators,
    /// The evidence is weaker than `min_evidence`.
    MinEvidence,
}

impl Refused {
    /// The constraint field, for messages that must not reveal values.
    pub fn field(&self) -> &'static str {
        match self {
            Refused::UnknownLocation => "location",
            Refused::AllowedRegions => "allowed_regions",
            Refused::ProhibitedLocations => "prohibited_locations",
            Refused::AllowedOperators => "allowed_operators",
            Refused::AllowedEvaluators => "allowed_evaluators",
            Refused::MinEvidence => "min_evidence",
        }
    }
}

/// A machine to judge: where it is, how that is known, who operates it.
#[derive(Clone, Debug)]
pub struct Machine<'a> {
    pub id: &'a str,
    pub operator: &'a str,
    pub location: Option<&'a Location>,
    pub evidence: LocationEvidence,
}

impl PlacementConstraints {
    /// Well formed: patterns and names known, nothing empty that would
    /// refuse everything by accident, at least one scope.
    pub fn check(&self) -> Result<()> {
        if let Some(a) = &self.allowed_regions {
            if a.is_empty() {
                return Err(refuse(
                    "allowed_regions is empty, which admits nothing: omit it for no restriction",
                ));
            }
            for p in a {
                p.check()?;
            }
        }
        for p in &self.prohibited_locations {
            p.check()?;
        }
        for (what, s) in [
            ("allowed_operators", &self.allowed_operators),
            ("allowed_evaluators", &self.allowed_evaluators),
        ] {
            if let Some(s) = s {
                if s.is_empty() {
                    return Err(refuse(format!(
                        "{what} is empty, which admits nothing: omit it for no restriction"
                    )));
                }
                for n in s {
                    if n.is_empty() || n.len() > 200 || n.chars().any(|c| c.is_control()) {
                        return Err(refuse(format!("{what} names an invalid identifier")));
                    }
                }
            }
        }
        if self.applies_to.is_empty() {
            return Err(refuse("applies_to names at least one scope"));
        }
        Ok(())
    }

    pub fn is_unrestricted(&self) -> bool {
        self.allowed_regions.is_none()
            && self.prohibited_locations.is_empty()
            && self.allowed_operators.is_none()
            && self.allowed_evaluators.is_none()
            && self.min_evidence == LocationEvidence::SelfDeclared
    }

    /// Whether this constraint covers any of `scopes`.
    pub fn applies(&self, scopes: &[Scope]) -> bool {
        scopes.iter().any(|s| self.applies_to.contains(s))
    }

    /// Why this constraint refuses `m`, empty when it admits it.
    pub fn refusals(&self, m: &Machine<'_>) -> Vec<Refused> {
        let mut out = vec![];
        let needs_location =
            self.allowed_regions.is_some() || !self.prohibited_locations.is_empty();
        match m.location {
            None if needs_location => out.push(Refused::UnknownLocation),
            None => {}
            Some(l) => {
                // A location that fails the table's check (a forged
                // jurisdiction, an unknown region) is as good as unknown.
                if l.check().is_err() {
                    if needs_location {
                        out.push(Refused::UnknownLocation);
                    }
                } else {
                    if self
                        .allowed_regions
                        .as_ref()
                        .is_some_and(|a| !a.iter().any(|p| p.contains(l)))
                    {
                        out.push(Refused::AllowedRegions);
                    }
                    if self.prohibited_locations.iter().any(|p| p.may_contain(l)) {
                        out.push(Refused::ProhibitedLocations);
                    }
                }
            }
        }
        if self
            .allowed_operators
            .as_ref()
            .is_some_and(|a| !a.contains(m.operator))
        {
            out.push(Refused::AllowedOperators);
        }
        if self
            .allowed_evaluators
            .as_ref()
            .is_some_and(|a| !a.contains(m.id))
        {
            out.push(Refused::AllowedEvaluators);
        }
        // Evidence is judged whenever a location or any placement rule is
        // in play: a constraint that asks for evidence asks for it of
        // every machine.
        if m.evidence < self.min_evidence {
            out.push(Refused::MinEvidence);
        }
        out
    }

    /// The combination of two constraints: allowed sets intersect (an
    /// absent set does not restrict), prohibited sets union, evidence is
    /// the maximum, scopes union (each covers what it covers). Monotone:
    /// the result admits no machine either input refuses.
    pub fn combine(&self, other: &Self) -> Self {
        fn meet<T: Ord + Clone>(
            a: &Option<BTreeSet<T>>,
            b: &Option<BTreeSet<T>>,
        ) -> Option<BTreeSet<T>> {
            match (a, b) {
                (None, x) | (x, None) => x.clone(),
                (Some(a), Some(b)) => Some(a.intersection(b).cloned().collect()),
            }
        }
        Self {
            // Patterns of different shapes intersect only where they meet:
            // keep every pattern of one that the other's patterns contain
            // (see `meet_regions`).
            allowed_regions: meet_regions(&self.allowed_regions, &other.allowed_regions),
            prohibited_locations: self
                .prohibited_locations
                .union(&other.prohibited_locations)
                .cloned()
                .collect(),
            allowed_operators: meet(&self.allowed_operators, &other.allowed_operators),
            allowed_evaluators: meet(&self.allowed_evaluators, &other.allowed_evaluators),
            min_evidence: self.min_evidence.max(other.min_evidence),
            applies_to: self.applies_to.union(&other.applies_to).copied().collect(),
        }
    }

    /// Whether `self` is at least as tight as `other`: it admits nothing
    /// `other` refuses. Used for "any member may tighten".
    pub fn tightens(&self, other: &Self) -> bool {
        let regions = match (&self.allowed_regions, &other.allowed_regions) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(a), Some(b)) => a.iter().all(|p| b.iter().any(|q| pattern_within(p, q))),
        };
        let prohibited = other.prohibited_locations.iter().all(|q| {
            self.prohibited_locations
                .iter()
                .any(|p| pattern_within(q, p))
        });
        let subset = |a: &Option<BTreeSet<String>>, b: &Option<BTreeSet<String>>| match (a, b) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(a), Some(b)) => a.is_subset(b),
        };
        regions
            && prohibited
            && subset(&self.allowed_operators, &other.allowed_operators)
            && subset(&self.allowed_evaluators, &other.allowed_evaluators)
            && self.min_evidence >= other.min_evidence
            && other.applies_to.is_subset(&self.applies_to)
    }

    /// `SHA256("encompute.placement.v1" || 0x00 || canonical JSON)`, hex.
    pub fn digest(&self) -> String {
        hex(&tagged(
            PLACEMENT,
            &canonical_json(self).expect("strings and sets only"),
        ))
    }
}

/// Whether every location in `inner` is in `outer`.
fn pattern_within(inner: &LocationPattern, outer: &LocationPattern) -> bool {
    let f = |i: &Option<String>, o: &Option<String>| o.is_none() || i == o;
    // A region pattern is within its jurisdiction pattern when the table
    // says the region is there.
    let jurisdiction_ok = match (&inner.jurisdiction, &outer.jurisdiction) {
        (_, None) => true,
        (Some(i), Some(o)) => i == o,
        (None, Some(o)) => match (&inner.provider, &inner.region) {
            (Some(p), Some(r)) => locations::jurisdiction_of(p, r) == Some(o.as_str()),
            _ => false,
        },
    };
    jurisdiction_ok
        && f(&inner.provider, &outer.provider)
        && f(&inner.region, &outer.region)
        && f(&inner.zone, &outer.zone)
}

/// The intersection of two allowed-region sets as a set of patterns: the
/// narrower pattern of every overlapping pair (so a jurisdiction pattern
/// meeting a region pattern inside it yields the region).
fn meet_regions(
    a: &Option<BTreeSet<LocationPattern>>,
    b: &Option<BTreeSet<LocationPattern>>,
) -> Option<BTreeSet<LocationPattern>> {
    match (a, b) {
        (None, x) | (x, None) => x.clone(),
        (Some(a), Some(b)) => {
            let mut out = BTreeSet::new();
            for p in a {
                for q in b {
                    if pattern_within(p, q) {
                        out.insert(p.clone());
                    } else if pattern_within(q, p) {
                        out.insert(q.clone());
                    }
                }
            }
            Some(out)
        }
    }
}

/// One source of constraints: whose, which assets it concerns (empty: the
/// whole project), and the constraints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementSource {
    /// `project` or an organization.
    pub origin: Origin,
    pub constraints: PlacementConstraints,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Origin {
    /// The project's constraints: every member holds them.
    Project(String),
    /// An organization's own constraints (an owner's authorization).
    Organization(String),
}

impl Origin {
    pub fn describe(&self) -> String {
        match self {
            Origin::Project(p) => format!("project {p}"),
            Origin::Organization(o) => format!("an input owned by {o}"),
        }
    }
}

/// Judges `m` against every source that covers one of `scopes`: the
/// sources that refuse it, each with the fields that refused. Empty when
/// every covering source admits it. With no covering source, the machine
/// is admitted by the constraints (other floors still apply).
pub fn refusals<'a>(
    sources: &'a [PlacementSource],
    scopes: &[Scope],
    m: &Machine<'_>,
) -> Vec<(&'a Origin, Vec<Refused>)> {
    sources
        .iter()
        .filter(|s| s.constraints.applies(scopes))
        .filter_map(|s| {
            let r = s.constraints.refusals(m);
            (!r.is_empty()).then_some((&s.origin, r))
        })
        .collect()
}

/// The digest of a set of sources, order-independent.
pub fn sources_digest(sources: &[PlacementSource]) -> String {
    let mut s: Vec<&PlacementSource> = sources.iter().collect();
    s.sort_by(|a, b| (&a.origin, a.constraints.digest()).cmp(&(&b.origin, b.constraints.digest())));
    hex(&tagged(
        PLACEMENT,
        &canonical_json(&s).expect("strings and sets only"),
    ))
}

/// The versioned locations table: provider regions and their
/// jurisdictions. A stale table fails closed (an unknown region never
/// matches), which can block jobs until it is updated.
pub mod locations {
    use std::collections::BTreeSet;

    use serde::Serialize;

    use super::{hex, tagged, LOCATIONS};

    /// Bump on every change; the digest goes into plans.
    pub const TABLE_VERSION: u32 = 1;

    /// `(provider, region, jurisdiction)`. Jurisdictions are ISO 3166-1
    /// alpha-2 country codes. `onprem` regions are the countries of
    /// organizations' own premises (no zones).
    pub const TABLE: &[(&str, &str, &str)] = &[
        // Google Cloud.
        ("gcp", "us-central1", "US"),
        ("gcp", "us-east1", "US"),
        ("gcp", "us-east4", "US"),
        ("gcp", "us-east5", "US"),
        ("gcp", "us-south1", "US"),
        ("gcp", "us-west1", "US"),
        ("gcp", "us-west2", "US"),
        ("gcp", "us-west3", "US"),
        ("gcp", "us-west4", "US"),
        ("gcp", "northamerica-northeast1", "CA"),
        ("gcp", "northamerica-northeast2", "CA"),
        ("gcp", "southamerica-east1", "BR"),
        ("gcp", "southamerica-west1", "CL"),
        ("gcp", "europe-west1", "BE"),
        ("gcp", "europe-west2", "GB"),
        ("gcp", "europe-west3", "DE"),
        ("gcp", "europe-west4", "NL"),
        ("gcp", "europe-west6", "CH"),
        ("gcp", "europe-west8", "IT"),
        ("gcp", "europe-west9", "FR"),
        ("gcp", "europe-west10", "DE"),
        ("gcp", "europe-west12", "IT"),
        ("gcp", "europe-north1", "FI"),
        ("gcp", "europe-southwest1", "ES"),
        ("gcp", "europe-central2", "PL"),
        ("gcp", "asia-east1", "TW"),
        ("gcp", "asia-east2", "HK"),
        ("gcp", "asia-northeast1", "JP"),
        ("gcp", "asia-northeast2", "JP"),
        ("gcp", "asia-northeast3", "KR"),
        ("gcp", "asia-south1", "IN"),
        ("gcp", "asia-south2", "IN"),
        ("gcp", "asia-southeast1", "SG"),
        ("gcp", "asia-southeast2", "ID"),
        ("gcp", "australia-southeast1", "AU"),
        ("gcp", "australia-southeast2", "AU"),
        ("gcp", "me-west1", "IL"),
        ("gcp", "me-central1", "QA"),
        ("gcp", "me-central2", "SA"),
        ("gcp", "africa-south1", "ZA"),
        // Amazon Web Services.
        ("aws", "us-east-1", "US"),
        ("aws", "us-east-2", "US"),
        ("aws", "us-west-1", "US"),
        ("aws", "us-west-2", "US"),
        ("aws", "ca-central-1", "CA"),
        ("aws", "eu-west-1", "IE"),
        ("aws", "eu-west-2", "GB"),
        ("aws", "eu-west-3", "FR"),
        ("aws", "eu-central-1", "DE"),
        ("aws", "eu-central-2", "CH"),
        ("aws", "eu-north-1", "SE"),
        ("aws", "eu-south-1", "IT"),
        ("aws", "eu-south-2", "ES"),
        ("aws", "ap-northeast-1", "JP"),
        ("aws", "ap-northeast-2", "KR"),
        ("aws", "ap-southeast-1", "SG"),
        ("aws", "ap-southeast-2", "AU"),
        ("aws", "ap-south-1", "IN"),
        ("aws", "sa-east-1", "BR"),
        ("aws", "me-south-1", "BH"),
        ("aws", "me-central-1", "AE"),
        ("aws", "af-south-1", "ZA"),
        // Microsoft Azure.
        ("azure", "eastus", "US"),
        ("azure", "eastus2", "US"),
        ("azure", "westus2", "US"),
        ("azure", "westus3", "US"),
        ("azure", "centralus", "US"),
        ("azure", "canadacentral", "CA"),
        ("azure", "northeurope", "IE"),
        ("azure", "westeurope", "NL"),
        ("azure", "francecentral", "FR"),
        ("azure", "germanywestcentral", "DE"),
        ("azure", "switzerlandnorth", "CH"),
        ("azure", "swedencentral", "SE"),
        ("azure", "uksouth", "GB"),
        ("azure", "norwayeast", "NO"),
        ("azure", "polandcentral", "PL"),
        ("azure", "italynorth", "IT"),
        ("azure", "japaneast", "JP"),
        ("azure", "koreacentral", "KR"),
        ("azure", "southeastasia", "SG"),
        ("azure", "australiaeast", "AU"),
        ("azure", "uaenorth", "AE"),
        ("azure", "southafricanorth", "ZA"),
        ("azure", "brazilsouth", "BR"),
        ("azure", "centralindia", "IN"),
        // An organization's own premises, by country.
        ("onprem", "at", "AT"),
        ("onprem", "au", "AU"),
        ("onprem", "be", "BE"),
        ("onprem", "ca", "CA"),
        ("onprem", "ch", "CH"),
        ("onprem", "de", "DE"),
        ("onprem", "es", "ES"),
        ("onprem", "fi", "FI"),
        ("onprem", "fr", "FR"),
        ("onprem", "gb", "GB"),
        ("onprem", "ie", "IE"),
        ("onprem", "it", "IT"),
        ("onprem", "jp", "JP"),
        ("onprem", "nl", "NL"),
        ("onprem", "pl", "PL"),
        ("onprem", "se", "SE"),
        ("onprem", "us", "US"),
    ];

    pub fn jurisdiction_of(provider: &str, region: &str) -> Option<&'static str> {
        TABLE
            .iter()
            .find(|(p, r, _)| *p == provider && *r == region)
            .map(|(_, _, j)| *j)
    }

    pub fn any_provider_has_region(region: &str) -> bool {
        TABLE.iter().any(|(_, r, _)| *r == region)
    }

    pub fn providers() -> BTreeSet<&'static str> {
        TABLE.iter().map(|(p, _, _)| *p).collect()
    }

    pub fn jurisdictions() -> BTreeSet<&'static str> {
        TABLE.iter().map(|(_, _, j)| *j).collect()
    }

    /// Whether `zone` is a zone of `provider`'s `region`: a Google Cloud
    /// zone is `<region>-<letter>`, an AWS zone `<region><letter>`, an
    /// Azure availability zone `1` to `3`. Premises have no zones.
    pub fn zone_belongs(provider: &str, region: &str, zone: &str) -> bool {
        if jurisdiction_of(provider, region).is_none() {
            return false;
        }
        let letter = |s: &str| s.len() == 1 && s.bytes().all(|b| b.is_ascii_lowercase());
        match provider {
            "gcp" => zone
                .strip_prefix(region)
                .and_then(|r| r.strip_prefix('-'))
                .is_some_and(letter),
            "aws" => zone.strip_prefix(region).is_some_and(letter),
            "azure" => matches!(zone, "1" | "2" | "3"),
            _ => false,
        }
    }

    /// The region of a Google Compute Engine zone (`us-central1-a`), when
    /// the table knows it: what a Confidential Space attestation names.
    pub fn gce_zone_region(zone: &str) -> Option<&'static str> {
        let (region, letter) = zone.rsplit_once('-')?;
        TABLE
            .iter()
            .find(|(p, r, _)| *p == "gcp" && *r == region)
            .filter(|_| zone_belongs("gcp", region, zone) && letter.len() == 1)
            .map(|(_, r, _)| *r)
    }

    /// The table's digest: its version and every row.
    pub fn digest() -> String {
        #[derive(Serialize)]
        struct T<'a> {
            version: u32,
            rows: &'a [(&'a str, &'a str, &'a str)],
        }
        hex(&tagged(
            LOCATIONS,
            &crate::canonical::canonical_json(&T {
                version: TABLE_VERSION,
                rows: TABLE,
            })
            .expect("strings only"),
        ))
    }
}
