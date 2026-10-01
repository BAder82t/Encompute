//! The placement vocabulary: the locations table, patterns, constraints and
//! their identities (INV-233 building blocks).

use encompute_verification::placement::*;

#[test]
fn the_table_resolves_jurisdictions_and_zones() {
    let l = Location::resolve("gcp", "europe-west3", Some("europe-west3-b")).unwrap();
    assert_eq!(l.jurisdiction, "DE");
    l.check().unwrap();
    assert_eq!(
        Location::resolve("aws", "eu-central-1", Some("eu-central-1a"))
            .unwrap()
            .jurisdiction,
        "DE"
    );
    assert!(Location::resolve("aws", "eu-central-1", Some("eu-central-1ab")).is_err());
    assert!(Location::resolve("azure", "westeurope", Some("2")).is_ok());
    assert!(Location::resolve("azure", "westeurope", Some("9")).is_err());
    assert!(Location::resolve("onprem", "de", Some("a")).is_err());
    assert!(Location::resolve("gcp", "europe-west3", Some("europe-west1-b")).is_err());
}

#[test]
fn a_gce_zone_names_its_region() {
    assert_eq!(
        locations::gce_zone_region("us-central1-a"),
        Some("us-central1")
    );
    assert_eq!(
        locations::gce_zone_region("europe-west3-c"),
        Some("europe-west3")
    );
    assert_eq!(locations::gce_zone_region("europe-west99-a"), None);
    assert_eq!(locations::gce_zone_region("us-central1"), None);
    assert_eq!(locations::gce_zone_region("us-central1-ab"), None);
    assert_eq!(locations::gce_zone_region(""), None);
}

#[test]
fn the_table_digest_is_stable_and_every_row_is_consistent() {
    assert_eq!(locations::digest(), locations::digest());
    assert_eq!(locations::digest().len(), 64);
    let mut seen = std::collections::BTreeSet::new();
    for (p, r, j) in locations::TABLE {
        assert!(seen.insert((*p, *r)), "{p}/{r} twice");
        assert!(j.len() == 2 && j.chars().all(|c| c.is_ascii_uppercase()));
        Location::resolve(p, r, None).unwrap().check().unwrap();
    }
}

#[test]
fn patterns_name_known_values_only() {
    assert!(LocationPattern::jurisdiction("DE").check().is_ok());
    assert!(LocationPattern::jurisdiction("ZZ").check().is_err());
    assert!(LocationPattern::region("gcp", "europe-west3")
        .check()
        .is_ok());
    assert!(LocationPattern::region("aws", "europe-west3")
        .check()
        .is_err());
    assert!(LocationPattern::provider("gcp").check().is_ok());
    assert!(LocationPattern::provider("oracle").check().is_err());
    let empty = LocationPattern {
        jurisdiction: None,
        provider: None,
        region: None,
        zone: None,
    };
    assert!(empty.check().is_err());
    // A region that is not in the named jurisdiction.
    let mut p = LocationPattern::region("gcp", "europe-west3");
    p.jurisdiction = Some("US".into());
    assert!(p.check().is_err());
    // A zone needs its provider and region.
    let mut z = LocationPattern::jurisdiction("DE");
    z.zone = Some("europe-west3-a".into());
    assert!(z.check().is_err());
}

#[test]
fn constraints_digest_ignores_defaults_and_binds_content() {
    let a = PlacementConstraints::default();
    // Defaults are not serialized: the canonical form is the empty object.
    assert_eq!(serde_json::to_string(&a).unwrap(), "{}");
    let b: PlacementConstraints = serde_json::from_str("{}").unwrap();
    assert_eq!(a, b);
    assert_eq!(a.digest(), b.digest());
    let mut c = a.clone();
    c.min_evidence = LocationEvidence::Attested;
    assert_ne!(a.digest(), c.digest());
    assert!(serde_json::from_str::<PlacementConstraints>(r#"{"allowed_region":[]}"#).is_err());
}

#[test]
fn the_evidence_digest_binds_location_level_source_and_table() {
    let l = Location::resolve("gcp", "europe-west3", None).unwrap();
    let d = l.evidence_digest(LocationEvidence::OperatorDeclared, "alice");
    assert_ne!(d, l.evidence_digest(LocationEvidence::Attested, "alice"));
    assert_ne!(
        d,
        l.evidence_digest(LocationEvidence::OperatorDeclared, "bob")
    );
    let other = Location::resolve("gcp", "europe-west1", None).unwrap();
    assert_ne!(
        d,
        other.evidence_digest(LocationEvidence::OperatorDeclared, "alice")
    );
}

#[test]
fn evidence_levels_are_ordered() {
    assert!(LocationEvidence::SelfDeclared < LocationEvidence::OperatorDeclared);
    assert!(LocationEvidence::OperatorDeclared < LocationEvidence::Attested);
    assert_eq!(LocationEvidence::Attested.label(), "attested");
    assert_eq!(LocationEvidence::OperatorDeclared.label(), "declared");
    assert_eq!(LocationEvidence::SelfDeclared.label(), "declared");
    for e in [
        LocationEvidence::SelfDeclared,
        LocationEvidence::OperatorDeclared,
        LocationEvidence::Attested,
    ] {
        assert_eq!(LocationEvidence::parse(e.as_str()), Some(e));
    }
}
