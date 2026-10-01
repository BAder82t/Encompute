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

fn pin(
    key: &str,
    operator: &str,
    region: Option<(&str, &str)>,
    ev: LocationEvidence,
) -> EvaluatorPin {
    EvaluatorPin {
        receipt_key: key.into(),
        operator: operator.into(),
        location: region.map(|(p, r)| Location::resolve(p, r, None).unwrap()),
        evidence: ev,
    }
}

#[test]
fn a_client_judges_what_it_pinned_by_its_own_constraints() {
    use encompute_ir::Code;
    let key = "ab".repeat(32);
    let de = PlacementConstraints {
        allowed_regions: Some([LocationPattern::jurisdiction("DE")].into()),
        ..PlacementConstraints::default()
    };
    let good = pin(
        &key,
        "platform",
        Some(("gcp", "europe-west3")),
        LocationEvidence::OperatorDeclared,
    );
    check_pinned_placement(&de, &key, std::slice::from_ref(&good), None).unwrap();
    // The key matches in any case.
    check_pinned_placement(&de, &key.to_uppercase(), std::slice::from_ref(&good), None).unwrap();
    let refused =
        |c: &PlacementConstraints, pins: &[EvaluatorPin], rec: Option<&GrantPlacement>| {
            let e = check_pinned_placement(c, &key, pins, rec).unwrap_err();
            assert_eq!(e.code, Code::GovernanceClientPlacement, "{e}");
            e.message
        };
    // Elsewhere, nothing pinned, another key pinned, unknown location.
    let us = pin(
        &key,
        "platform",
        Some(("gcp", "us-central1")),
        LocationEvidence::OperatorDeclared,
    );
    assert!(refused(&de, &[us], None).contains("allowed_regions"));
    assert!(refused(&de, &[], None).contains("pin set says nothing"));
    let other = pin(
        &"cd".repeat(32),
        "platform",
        Some(("gcp", "europe-west3")),
        LocationEvidence::Attested,
    );
    assert!(refused(&de, &[other], None).contains("pin set says nothing"));
    let unknown = pin(&key, "platform", None, LocationEvidence::Attested);
    assert!(refused(&de, &[unknown], None).contains("location"));
    // Prohibited wins, operators and evidence count.
    let mut no_us = PlacementConstraints::default();
    no_us
        .prohibited_locations
        .insert(LocationPattern::jurisdiction("DE"));
    assert!(refused(&no_us, std::slice::from_ref(&good), None).contains("prohibited_locations"));
    let ops = PlacementConstraints {
        allowed_operators: Some(["opco".to_owned()].into()),
        ..PlacementConstraints::default()
    };
    assert!(refused(&ops, std::slice::from_ref(&good), None).contains("allowed_operators"));
    let attested = PlacementConstraints {
        min_evidence: LocationEvidence::Attested,
        ..PlacementConstraints::default()
    };
    assert!(refused(&attested, std::slice::from_ref(&good), None).contains("min_evidence"));
    // The control plane's record must agree with the pin.
    let said = GrantPlacement {
        operator: "platform".into(),
        location: good.location.clone(),
        evidence: LocationEvidence::OperatorDeclared,
        evidence_digest: None,
    };
    check_pinned_placement(&de, &key, std::slice::from_ref(&good), Some(&said)).unwrap();
    for lie in [
        GrantPlacement {
            operator: "opco".into(),
            ..said.clone()
        },
        GrantPlacement {
            evidence: LocationEvidence::Attested,
            ..said.clone()
        },
        GrantPlacement {
            location: Some(Location::resolve("gcp", "europe-west1", None).unwrap()),
            ..said.clone()
        },
        GrantPlacement {
            location: None,
            ..said.clone()
        },
    ] {
        assert!(refused(&de, std::slice::from_ref(&good), Some(&lie)).contains("record"));
    }
    // Invalid constraints are refused, and constraints about other scopes
    // say nothing about ciphertexts.
    let typo = PlacementConstraints {
        allowed_regions: Some([LocationPattern::region("gcp", "europe-west99")].into()),
        ..PlacementConstraints::default()
    };
    refused(&typo, std::slice::from_ref(&good), None);
    let mut keys_only = de.clone();
    keys_only.applies_to = [Scope::Keys].into();
    check_pinned_placement(&keys_only, &key, &[], None).unwrap();
}
