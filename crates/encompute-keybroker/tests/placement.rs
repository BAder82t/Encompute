//! Attested placement at the owner's key broker (INV-233): a key is
//! released to a workload only if the zone its attestation names satisfies
//! the project's constraints (the document its binding's digest names,
//! carried by the signed ticket) and the owner's own (in the authorization
//! installed at the broker). Missing evidence never passes: no document, no
//! zone, or a zone the locations table does not know, is a refusal.
//! Releases without any constraint are unchanged.

mod common;

use common::*;
use encompute_ir::Code;
use encompute_verification::placement::{LocationPattern, PlacementConstraints};

fn code<T>(r: encompute_ir::Result<T>) -> Code {
    match r {
        Ok(_) => panic!("a key was released"),
        Err(e) => e.code,
    }
}

fn allow(jurisdiction: &str) -> PlacementConstraints {
    PlacementConstraints {
        allowed_regions: Some([LocationPattern::jurisdiction(jurisdiction)].into()),
        ..PlacementConstraints::default()
    }
}

/// A world whose project constraints are `c` (the binding names their
/// digest, the ticket carries them) and whose evaluator attests to `zone`.
fn placed(c: PlacementConstraints, zone: Option<&str>) -> World {
    let mut b = binding();
    b.placement_digest = Some(c.digest());
    let mut w = world_with(b, authorization());
    w.placement = Some(c);
    w.zone = zone.map(|z| ("gcp".to_owned(), z.to_owned()));
    w
}

#[test]
fn a_zone_inside_the_constraints_releases_the_key() {
    let mut w = placed(allow("DE"), Some("europe-west3-b"));
    w.release_fresh().unwrap();
}

#[test]
fn broker_refuses_zone_outside_placement() {
    let mut w = placed(allow("DE"), Some("us-central1-a"));
    let e = w.release_fresh().unwrap_err();
    assert_eq!(e.code, Code::GovernanceResidency);
    assert!(e.message.contains("allowed_regions"), "{e}");
    // Prohibited beats allowed, whatever else matches.
    let mut c = allow("DE");
    c.prohibited_locations
        .insert(LocationPattern::region("gcp", "europe-west3"));
    let mut w = placed(c, Some("europe-west3-a"));
    assert_eq!(code(w.release_fresh()), Code::GovernanceResidency);
    // A prohibited zone is refused whichever zone of it.
    let mut c = PlacementConstraints::default();
    c.prohibited_locations.insert(LocationPattern {
        jurisdiction: None,
        provider: Some("gcp".into()),
        region: Some("europe-west3".into()),
        zone: Some("europe-west3-a".into()),
    });
    assert_eq!(
        code(placed(c.clone(), Some("europe-west3-a")).release_fresh()),
        Code::GovernanceResidency
    );
    placed(c, Some("europe-west3-b")).release_fresh().unwrap();
}

#[test]
fn missing_placement_evidence_is_a_refusal() {
    // The attestation names no zone.
    assert_eq!(
        code(placed(allow("DE"), None).release_fresh()),
        Code::GovernanceResidency
    );
    // A zone the table does not know is never admitted.
    assert_eq!(
        code(placed(allow("DE"), Some("mars-west1-a")).release_fresh()),
        Code::GovernanceResidency
    );
    // A prohibition cannot be dodged by naming no zone either.
    let mut c = PlacementConstraints::default();
    c.prohibited_locations
        .insert(LocationPattern::jurisdiction("US"));
    assert_eq!(
        code(placed(c, None).release_fresh()),
        Code::GovernanceResidency
    );
}

#[test]
fn a_digest_with_no_matching_document_releases_nothing() {
    // The binding names constraints; the ticket carries none.
    let mut w = placed(allow("DE"), Some("europe-west3-a"));
    w.placement = None;
    assert_eq!(code(w.release_fresh()), Code::GovernanceResidency);
    // The ticket carries another document (a looser one): the ticket's own
    // consistency check refuses it before the broker reads a field.
    let mut w = placed(allow("DE"), Some("us-central1-a"));
    w.placement = Some(PlacementConstraints::default());
    let e = w.release_fresh().unwrap_err();
    assert_eq!(e.code, Code::GovernanceReleaseTicket, "{e}");
}

#[test]
fn the_owners_own_constraints_apply_alone() {
    // No project constraints at all; the owner's authorization keeps its
    // key in Germany.
    let mut a = authorization();
    a.limits.placement = Some(allow("DE"));
    let mut w = world_with(binding(), a.clone());
    w.zone = Some(("gcp".into(), "us-central1-a".into()));
    assert_eq!(code(w.release_fresh()), Code::GovernanceResidency);
    let mut w = world_with(binding(), a);
    w.zone = Some(("gcp".into(), "europe-west3-c".into()));
    w.release_fresh().unwrap();
    // The owner's rule is part of what it signed: a copy without it is
    // another authorization (see the trust crate), so the broker cannot be
    // handed a looser one under the same ID.
}

#[test]
fn project_and_owner_constraints_both_hold() {
    let mut a = authorization();
    a.limits.placement = Some(allow("DE"));
    let mut b = binding();
    let project = allow("US");
    b.placement_digest = Some(project.digest());
    let mut w = world_with(b, a);
    w.placement = Some(project);
    // Each is satisfied by a different zone: none satisfies both.
    for zone in ["europe-west3-a", "us-central1-a"] {
        w.zone = Some(("gcp".into(), zone.into()));
        assert_eq!(code(w.release_fresh()), Code::GovernanceResidency, "{zone}");
    }
}

#[test]
fn constraints_about_other_scopes_do_not_gate_a_key_release() {
    use encompute_verification::placement::Scope;
    // A rule about ciphertexts only says nothing about where a key goes.
    let mut c = allow("DE");
    c.applies_to = [Scope::Ciphertext].into();
    placed(c, Some("us-central1-a")).release_fresh().unwrap();
    // A rule about keys does.
    let mut c = allow("DE");
    c.applies_to = [Scope::Keys].into();
    assert_eq!(
        code(placed(c, Some("us-central1-a")).release_fresh()),
        Code::GovernanceResidency
    );
}

#[test]
fn operators_and_evaluators_are_the_control_planes_to_enforce() {
    // A broker sees neither: a constraint naming only them releases to an
    // attested workload (the control plane that issued the ticket judged
    // the operator), and says so rather than guessing.
    let c = PlacementConstraints {
        allowed_operators: Some(["platform".to_owned()].into()),
        ..PlacementConstraints::default()
    };
    placed(c, None).release_fresh().unwrap();
}

#[test]
fn releases_without_constraints_are_unchanged() {
    let mut w = world();
    w.release_fresh().unwrap();
    // A zone nobody asked about changes nothing either.
    let mut w = world();
    w.zone = Some(("gcp".into(), "mars-west1-a".into()));
    w.release_fresh().unwrap();
}

#[test]
fn control_plane_cannot_drop_project_constraints_when_the_owner_pinned_them() {
    let project = allow("DE");
    let mut a = authorization();
    a.limits.project_placement_digest = Some(project.digest());
    // A binding that names no project constraints at all (the control
    // plane dropped them): refused, though the zone is in the US.
    let mut w = world_with(binding(), a.clone());
    w.zone = Some(("gcp".into(), "us-central1-a".into()));
    assert_eq!(code(w.release_fresh()), Code::GovernanceResidency);
    // A binding that names looser constraints than the owner pinned.
    let loose = PlacementConstraints::default();
    let mut b = binding();
    b.placement_digest = Some(loose.digest());
    let mut w = world_with(b, a.clone());
    w.placement = Some(loose);
    w.zone = Some(("gcp".into(), "us-central1-a".into()));
    assert_eq!(code(w.release_fresh()), Code::GovernanceResidency);
    // Bound to exactly what the owner pinned, from a German zone: released.
    let mut b = binding();
    b.placement_digest = Some(project.digest());
    let mut w = world_with(b, a);
    w.placement = Some(project);
    w.zone = Some(("gcp".into(), "europe-west3-a".into()));
    w.release_fresh().unwrap();
    // Without a pin the digest is the control plane's own choice: nothing
    // to compare (the project's constraints are enforced by it alone).
    let mut w = world();
    w.zone = Some(("gcp".into(), "us-central1-a".into()));
    w.release_fresh().unwrap();
}
