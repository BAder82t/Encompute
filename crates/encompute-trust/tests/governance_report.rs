//! The cross-agency trust report (INV-244): every governance row comes
//! from signed evidence, against the caller's own pins. A missing anchor,
//! a missing piece of evidence or an unverifiable proof is UNCHECKED or NOT
//! EVIDENCED, never a pass.

use std::collections::{BTreeMap, BTreeSet};

use encompute_trust::authz::{GovernanceKey, GovernanceKeyStatus};
use encompute_trust::fixture::*;
use encompute_trust::govlog::kind;
use encompute_trust::{
    Anchors, AuthorizationEntry, GovernanceReport, ReportOptions, Status, TrustGraph, Verdict,
};
use encompute_verification::governance::ReleaseClass;

type Edit = Box<dyn Fn(&mut Fixture)>;

fn show(fx: &Fixture) -> GovernanceReport {
    fx.graph
        .governance_report(&fx.evidence, &fx.audit, &fx.options())
        .unwrap()
}

fn status(r: &GovernanceReport, name: &str) -> Status {
    r.row(name).unwrap().status
}

fn passes(s: Status) -> bool {
    matches!(
        s,
        Status::Verified
            | Status::Satisfied
            | Status::Authorized
            | Status::Attested
            | Status::Complete
            | Status::NotApplicable
    )
}

fn details(r: &GovernanceReport, name: &str) -> String {
    r.row(name).unwrap().details.join(" | ")
}

#[test]
fn a_whole_cross_agency_job_verifies() {
    let fx = Fixture::build();
    let r = show(&fx);
    assert!(
        r.base
            .rows
            .iter()
            .filter(|b| b.name != "Owner authorization")
            .all(|b| !matches!(b.status, Status::Failed | Status::Unchecked)),
        "{}",
        r.base
    );
    for (name, want) in [
        ("Project", Status::Satisfied),
        ("Organizations", Status::Satisfied),
        ("Key custody", Status::Satisfied),
        ("Purpose", Status::Satisfied),
        ("Source assets", Status::Satisfied),
        ("Linkage", Status::NotApplicable),
        ("Raw data centralized", Status::Satisfied),
        ("Ownership retained", Status::Satisfied),
        ("Location", Status::NotApplicable),
        ("Mechanism", Status::Satisfied),
        ("Approvals", Status::Satisfied),
        ("Authorization window", Status::Satisfied),
        ("Unauthorized releases", Status::Satisfied),
        ("Privacy policy", Status::NotApplicable),
        ("Execution evidence", Status::Satisfied),
        ("Audit chain", Status::Satisfied),
    ] {
        assert_eq!(status(&r, name), want, "{name}: {}", details(&r, name));
    }
    let value = |n: &str| r.row(n).unwrap().value.clone();
    assert_eq!(value("Raw data centralized").as_deref(), Some("NO"));
    assert_eq!(value("Ownership retained").as_deref(), Some("YES"));
    assert_eq!(value("Unauthorized releases").as_deref(), Some("NONE"));
    assert_eq!(
        value("Authorization window").as_deref(),
        Some("VALID AT GRANT")
    );
    // The one thing this release cannot evidence is who holds a result's
    // key: it is never claimed, so the verdict is not SATISFIED.
    assert_eq!(status(&r, "Decryption control"), Status::NotPresent);
    assert_eq!(r.verdict, Verdict::NotFullyEvidenced);
    assert_eq!(
        r.unmet,
        vec!["Decryption control is not evidenced".to_owned()]
    );
    // The legal boundary ends the report.
    assert!(r.to_string().trim_end().ends_with(r.legal_boundary));
}

#[test]
fn missing_anchors_are_unchecked_not_satisfied() {
    // No control-plane key: the grant (the binding, the time, the set of
    // authorizations) was not verified, so nothing resting on it passes.
    let fx = Fixture::build();
    let mut o = fx.options();
    o.anchors.control_plane = None;
    let r = fx
        .graph
        .governance_report(&fx.evidence, &fx.audit, &o)
        .unwrap();
    for row in &r.rows {
        assert!(
            !passes(row.status),
            "{} passed without the control plane's key: {:?}",
            row.name,
            row.details
        );
    }
    assert_ne!(r.verdict, Verdict::Satisfied);
    assert_eq!(status(&r, "Audit chain"), Status::Unchecked);

    // No organization keys: nothing signed by an organization is checked.
    let mut o = fx.options();
    o.anchors.organizations.clear();
    let r = fx
        .graph
        .governance_report(&fx.evidence, &fx.audit, &o)
        .unwrap();
    for name in [
        "Project",
        "Organizations",
        "Source assets",
        "Ownership retained",
        "Approvals",
        "Authorization window",
        "Unauthorized releases",
        "Audit chain",
    ] {
        assert_eq!(status(&r, name), Status::Unchecked, "{name}");
    }
    assert_ne!(r.verdict, Verdict::Satisfied);

    // One organization not pinned: its part is unchecked, the other's is.
    let mut o = fx.options();
    o.anchors.organizations.remove(BEN);
    let r = fx
        .graph
        .governance_report(&fx.evidence, &fx.audit, &o)
        .unwrap();
    assert_eq!(status(&r, "Organizations"), Status::Unchecked);
    assert!(details(&r, "Source assets").contains(BEN));

    // No log in the evidence: the revocation checks cannot run.
    let mut audit = fx.audit.clone();
    audit.checkpoint = None;
    audit.events.clear();
    audit.revocation_heads.clear();
    audit.witnesses.clear();
    let r = fx
        .graph
        .governance_report(&fx.evidence, &audit, &fx.options())
        .unwrap();
    assert_eq!(status(&r, "Audit chain"), Status::NotPresent);
    assert_eq!(status(&r, "Authorization window"), Status::Unchecked);
    assert_ne!(r.verdict, Verdict::Satisfied);

    // No evaluator key pinned: the base execution row is unchecked and so
    // is the verdict.
    let mut o = fx.options();
    o.base.anchors = Anchors::default();
    let r = fx
        .graph
        .governance_report(&fx.evidence, &fx.audit, &o)
        .unwrap();
    assert_eq!(r.verdict, Verdict::NotFullyEvidenced);
    assert!(
        r.unmet.iter().any(|u| u.starts_with("Execution")),
        "{:?}",
        r.unmet
    );
}

#[test]
fn a_tampered_report_or_cached_attribute_changes_nothing() {
    let fx = Fixture::build();
    // A label, an attribute and an edge the evidence does not imply.
    let mut g = fx.graph.clone();
    let id = g
        .nodes
        .iter()
        .find(|(_, n)| n.kind == encompute_trust::NodeKind::Execution)
        .map(|(k, _)| k.clone())
        .unwrap();
    g.nodes.get_mut(&id).unwrap().label = "execution of something else".into();
    let r = g
        .governance_report(&fx.evidence, &fx.audit, &fx.options())
        .unwrap();
    assert_eq!(r.base.rows[0].name, "Evidence");
    assert_eq!(r.base.rows[0].status, Status::Failed);
    assert_eq!(r.verdict, Verdict::NotSatisfied);

    let mut g = fx.graph.clone();
    g.nodes
        .get_mut(&id)
        .unwrap()
        .attrs
        .insert("verdict".into(), "SATISFIED".into());
    let r = g
        .governance_report(&fx.evidence, &fx.audit, &fx.options())
        .unwrap();
    assert_eq!(r.verdict, Verdict::NotSatisfied);

    // A removed node is evidence omitted: the rows that read it do not
    // pass.
    let mut g = fx.graph.clone();
    g.nodes
        .retain(|_, n| n.kind != encompute_trust::NodeKind::Plan);
    g.edges
        .retain(|e| !e.from.starts_with("plan:") && !e.to.starts_with("plan:"));
    let r = g
        .governance_report(&fx.evidence, &fx.audit, &fx.options())
        .unwrap();
    assert!(!passes(status(&r, "Raw data centralized")));
    assert_eq!(
        r.row("Raw data centralized").unwrap().value.as_deref(),
        Some("UNKNOWN")
    );
    assert!(!passes(status(&r, "Mechanism")));
    assert!(!passes(status(&r, "Key custody")));
}

/// Every edit of the signed evidence is refused by one row or another: no
/// edit leaves the verdict where it was.
#[test]
fn every_governance_evidence_edit_fails() {
    let fx = Fixture::build();
    let baseline = show(&fx);
    assert_eq!(baseline.verdict, Verdict::NotFullyEvidenced);
    let edits: Vec<(&str, Edit)> = vec![
        (
            "grant issue time",
            Box::new(|f| f.evidence.grant.issued_at += 1),
        ),
        (
            "grant evaluator",
            Box::new(|f| f.evidence.grant.evaluator = "evil".into()),
        ),
        (
            "grant not_after",
            Box::new(|f| f.evidence.grant.governance.as_mut().unwrap().not_after += 1),
        ),
        (
            "grant authorization set",
            Box::new(|f| {
                f.evidence
                    .grant
                    .governance
                    .as_mut()
                    .unwrap()
                    .authorization_set_id = h('0')
            }),
        ),
        (
            "grant binding",
            Box::new(|f| {
                f.evidence
                    .grant
                    .governance
                    .as_mut()
                    .unwrap()
                    .binding
                    .inputs
                    .get_mut("age")
                    .unwrap()
                    .digest_commitment = h('0')
            }),
        ),
        (
            "spec",
            Box::new(|f| f.evidence.spec.backend_version = "9".into()),
        ),
        (
            "spec governance id",
            Box::new(|f| f.evidence.spec.governance_id = None),
        ),
        (
            "purpose",
            Box::new(|f| f.evidence.purpose.description = "other".into()),
        ),
        (
            "purpose window",
            Box::new(|f| f.evidence.purpose.valid_until += 1),
        ),
        (
            "acceptance",
            Box::new(|f| f.evidence.purpose_acceptances[0].body.accepted_at += 1),
        ),
        (
            "acceptance removed",
            Box::new(|f| {
                f.evidence.purpose_acceptances.pop();
            }),
        ),
        (
            "authorization body",
            Box::new(|f| {
                if let AuthorizationEntry::Signed { document } = &mut f.evidence.authorizations[0] {
                    document.body.valid_until += 1;
                }
            }),
        ),
        (
            "authorization signature",
            Box::new(|f| {
                if let AuthorizationEntry::Signed { document } = &mut f.evidence.authorizations[0] {
                    document.signature = "00".repeat(64);
                }
            }),
        ),
        (
            "authorization omitted",
            Box::new(|f| {
                f.evidence.authorizations.pop();
            }),
        ),
        (
            "authorization added",
            Box::new(|f| {
                let e = f.evidence.authorizations[0].clone();
                f.evidence.authorizations.push(e);
            }),
        ),
        (
            "release record body",
            Box::new(|f| f.evidence.release_records[0].body.output_commitment = h('0')),
        ),
        (
            "release record omitted",
            Box::new(|f| f.evidence.release_records.clear()),
        ),
        (
            "checkpoint root",
            Box::new(|f| f.audit.checkpoint.as_mut().unwrap().body.root = h('0')),
        ),
        ("event", Box::new(|f| f.audit.events[0].event.at += 1)),
        (
            "event omitted",
            Box::new(|f| {
                f.audit.events.pop();
            }),
        ),
        ("event reordered", Box::new(|f| f.audit.events.swap(0, 1))),
        (
            "head",
            Box::new(|f| f.audit.revocation_heads[0].body.at += 1),
        ),
        (
            "head omitted",
            Box::new(|f| {
                f.audit.revocation_heads.pop();
            }),
        ),
        ("witness", Box::new(|f| f.audit.witnesses[0].body.at += 1)),
    ];
    for (what, edit) in edits {
        let mut f = Fixture::build();
        edit(&mut f);
        let r = show(&f);
        assert_ne!(r.verdict, Verdict::Satisfied, "{what}");
        let changed = r
            .rows
            .iter()
            .zip(&baseline.rows)
            .any(|(a, b)| a.status != b.status || a.details != b.details);
        assert!(changed, "an edit of the {what} changed no row");
        // And what it changes is never towards a pass.
        for (a, b) in r.rows.iter().zip(&baseline.rows) {
            assert!(
                !(passes(a.status) && !passes(b.status)),
                "the {what} turned {} into a pass",
                a.name
            );
        }
    }
}

#[test]
fn execution_time_validity_never_fails_a_historical_audit() {
    let fx = Fixture::build();
    // Long after every window closed.
    let mut o = fx.options();
    o.now = Some(T0 + 10_000_000);
    let r = fx
        .graph
        .governance_report(&fx.evidence, &fx.audit, &o)
        .unwrap();
    assert_eq!(status(&r, "Authorization window"), Status::Satisfied);
    assert!(
        r.authorization_now.iter().all(|l| l.contains("EXPIRED")),
        "{:?}",
        r.authorization_now
    );
    assert_eq!(r.verdict, Verdict::NotFullyEvidenced);

    // Not yet valid when the grant was issued: failed.
    let f = Fixture::with(Knobs {
        valid_from: T0 + 1,
        ..Knobs::default()
    });
    let r = show(&f);
    assert_eq!(status(&r, "Authorization window"), Status::Failed);
    // Already expired when the grant was issued: failed.
    let f = Fixture::with(Knobs {
        valid_from: T0 - 1000,
        valid_until: T0,
        ..Knobs::default()
    });
    assert_eq!(status(&show(&f), "Authorization window"), Status::Failed);
}

fn revocation(
    org: &str,
    k: &str,
    refs: &[(&str, &str)],
    at: u64,
) -> (String, String, BTreeMap<String, String>, u64) {
    (
        org.to_owned(),
        k.to_owned(),
        refs.iter()
            .map(|(a, b)| ((*a).into(), (*b).into()))
            .collect(),
        at,
    )
}

#[test]
fn revocations_count_from_their_time_and_are_never_retroactive() {
    let id = |f: &Fixture| f.evidence.authorizations[0].id();
    let probe = Fixture::build();
    let auth = id(&probe);
    let org = match &probe.evidence.authorizations[0] {
        AuthorizationEntry::Signed { document } => document.body.party.clone(),
        _ => unreachable!(),
    };
    let rev = |kind_: &str, refs: &[(&str, &str)], at: u64| {
        Fixture::with(Knobs {
            revocations: vec![revocation(&org, kind_, refs, at)],
            head_at: T0 + 6000,
            ..Knobs::default()
        })
    };
    let kid = encompute_trust::authz::governance_key_id(&pk(&probe.tax));
    // Revoked while the grant was still usable: the run's own time is not
    // evidenced, so whether it came first is UNCHECKED, never a pass.
    for f in [
        rev(
            kind::AUTHORIZATION_REVOKED,
            &[("authorization_id", &auth)],
            T0 + 5,
        ),
        rev(kind::GOVERNANCE_KEY_REVOKED, &[("key_id", &kid)], T0 + 5),
    ] {
        let r = show(&f);
        assert_eq!(status(&r, "Authorization window"), Status::Unchecked);
        assert!(details(&r, "Authorization window").contains("not evidenced"));
    }
    // Revoked after the grant expired: history stays valid, the revocation
    // shows, and now says REVOKED.
    let f = rev(
        kind::AUTHORIZATION_REVOKED,
        &[("authorization_id", &auth)],
        T0 + 5000,
    );
    let mut o = f.options();
    o.now = Some(T0 + 6000);
    let r = f
        .graph
        .governance_report(&f.evidence, &f.audit, &o)
        .unwrap();
    assert_eq!(
        status(&r, "Authorization window"),
        Status::Satisfied,
        "{}",
        details(&r, "Authorization window")
    );
    assert!(
        r.authorization_now.iter().any(|l| l.contains("REVOKED")),
        "{:?}",
        r.authorization_now
    );
    assert_eq!(r.revocations.len(), 1);
    assert_eq!(r.revocations[0].at, T0 + 5000);
    // Revoked at or before the run: failed.
    let f = rev(
        kind::AUTHORIZATION_REVOKED,
        &[("authorization_id", &auth)],
        T0,
    );
    assert_eq!(status(&show(&f), "Authorization window"), Status::Failed);
    // Its governance key revoked before it was used: failed.
    let f = rev(kind::GOVERNANCE_KEY_REVOKED, &[("key_id", &kid)], T0 - 5);
    assert_eq!(status(&show(&f), "Authorization window"), Status::Failed);
    // A key revoked after the grant expired leaves it valid.
    let f = rev(kind::GOVERNANCE_KEY_REVOKED, &[("key_id", &kid)], T0 + 5000);
    assert_eq!(status(&show(&f), "Authorization window"), Status::Satisfied);
}

#[test]
fn a_stale_revocation_head_is_not_covered_for_a_later_run() {
    let fx = Fixture::build();
    let r = show(&fx);
    assert_eq!(status(&r, "Audit chain"), Status::Satisfied);
    // The same heads, for a use after they were dated: UNCHECKED, never
    // covered.
    let mut o = fx.options();
    o.as_of = Some(fx.knobs.head_at + 1);
    let r = fx
        .graph
        .governance_report(&fx.evidence, &fx.audit, &o)
        .unwrap();
    assert_eq!(status(&r, "Audit chain"), Status::Unchecked);
    assert!(details(&r, "Audit chain").contains("UNCHECKED"));
    assert_ne!(r.verdict, Verdict::Satisfied);
    // The head's date is what the report says it covers.
    let r = show(&fx);
    let notes = r.audit_notes.join(" | ");
    assert!(
        notes.contains(&format!("as of {}", fx.knobs.head_at)),
        "{notes}"
    );
}

#[test]
fn approvals_need_a_quorum_of_distinct_humans() {
    let f = Fixture::with(Knobs {
        approvers: 1,
        ..Knobs::default()
    });
    let r = show(&f);
    assert_eq!(status(&r, "Approvals"), Status::Failed);
    // The submitter among the approvers of a card.
    let fx = Fixture::build();
    let mut ev = fx.shared();
    if let AuthorizationEntry::Card { card } = &mut ev.authorizations[0] {
        ev.submitter = Some(card.approvals[0].approver.clone());
    }
    let r = fx
        .graph
        .governance_report(&ev, &fx.audit, &fx.options())
        .unwrap();
    assert_eq!(status(&r, "Approvals"), Status::Failed);
    assert!(details(&r, "Approvals").contains("submitter"));
}

#[test]
fn a_shared_view_is_unchecked_until_the_owner_discloses() {
    let fx = Fixture::build();
    let shared = fx.shared();
    let r = fx
        .graph
        .governance_report(&shared, &fx.audit, &fx.options())
        .unwrap();
    // The cards' signatures cannot be checked: what rests on them is
    // UNCHECKED, never a pass.
    // Neither can "nothing is declared" rest on a card's body.
    for name in ["Linkage", "Privacy policy"] {
        assert_eq!(status(&r, name), Status::Unchecked, "{name}");
    }
    for name in [
        "Source assets",
        "Approvals",
        "Authorization window",
        "Ownership retained",
        "Purpose",
    ] {
        assert_eq!(status(&r, name), Status::Unchecked, "{name}");
    }
    assert_ne!(r.verdict, Verdict::Satisfied);
    assert!(
        !r.to_string().contains("person-"),
        "approvers stay pseudonyms"
    );

    // The owners disclose the signed documents the cards name: the report
    // is the one of the signed evidence.
    let mut o = fx.options();
    o.disclosures = fx.documents();
    let r = fx.graph.governance_report(&shared, &fx.audit, &o).unwrap();
    assert_eq!(r.verdict, Verdict::NotFullyEvidenced);
    assert_eq!(
        r.unmet,
        vec!["Decryption control is not evidenced".to_owned()]
    );

    // A document no card names, or one edited, replaces nothing.
    let mut o = fx.options();
    let mut doc = fx.documents().remove(0);
    doc.body.valid_until += 1;
    o.disclosures = vec![doc];
    let r = fx.graph.governance_report(&shared, &fx.audit, &o).unwrap();
    assert_eq!(status(&r, "Source assets"), Status::Unchecked);
}

#[test]
fn features_without_evidence_are_not_applicable_only_with_backing() {
    let r = show(&Fixture::build());
    for n in ["Linkage", "Location", "Privacy policy"] {
        assert_eq!(status(&r, n), Status::NotApplicable, "{n}");
    }
    // Declared in the signed binding or authorizations, and not evidenced
    // in this release: NOT PRESENT, which blocks the verdict.
    let r = show(&Fixture::with(Knobs {
        linkage: true,
        ..Knobs::default()
    }));
    assert_eq!(status(&r, "Linkage"), Status::NotPresent);
    let r = show(&Fixture::with(Knobs {
        placement: true,
        ..Knobs::default()
    }));
    assert_eq!(status(&r, "Location"), Status::NotPresent);
    let r = show(&Fixture::with(Knobs {
        privacy_policy: true,
        ..Knobs::default()
    }));
    assert_ne!(status(&r, "Privacy policy"), Status::NotApplicable);
    assert!(!passes(status(&r, "Privacy policy")));
    assert_eq!(
        r.row("Decryption control").unwrap().value.as_deref(),
        Some("NOT EVIDENCED")
    );
}

#[test]
fn releases_are_none_only_with_signed_records_within_what_owners_allowed() {
    // No record at all: nothing is claimed.
    let r = show(&Fixture::with(Knobs {
        release_record: false,
        ..Knobs::default()
    }));
    assert_eq!(status(&r, "Unauthorized releases"), Status::NotPresent);
    assert_eq!(
        r.row("Unauthorized releases").unwrap().value.as_deref(),
        Some("UNKNOWN")
    );
    // A record wider than an owner's recipients.
    let r = show(&Fixture::with(Knobs {
        recipients: BTreeSet::from(["someone-else".to_owned()]),
        ..Knobs::default()
    }));
    assert_eq!(status(&r, "Unauthorized releases"), Status::Failed);
    // A record in a class an owner never allowed.
    let r = show(&Fixture::with(Knobs {
        release_class: ReleaseClass::Never,
        recipients: BTreeSet::new(),
        ..Knobs::default()
    }));
    assert_eq!(status(&r, "Unauthorized releases"), Status::Failed);
    // A second record of one output.
    let f = Fixture::build();
    let mut ev = f.evidence.clone();
    let dup = ev.release_records[0].clone();
    ev.release_records.push(dup);
    let r = f
        .graph
        .governance_report(&ev, &f.audit, &f.options())
        .unwrap();
    assert_eq!(status(&r, "Unauthorized releases"), Status::Failed);
}

#[test]
fn ownership_is_retained_only_when_each_owner_signed_for_its_own_version() {
    let f = Fixture::build();
    // Benefits signs an authorization of tax's version.
    let mut ev = f.evidence.clone();
    let doc = match &ev.authorizations[0] {
        AuthorizationEntry::Signed { document } => document.body.clone(),
        _ => unreachable!(),
    };
    let mut forged = doc;
    forged.party = BEN.into();
    forged.approvals.clear();
    let signed = forged.sign(&f.ben).unwrap();
    ev.authorizations[0] = AuthorizationEntry::Signed {
        document: Box::new(signed),
    };
    let r = f
        .graph
        .governance_report(&ev, &f.audit, &f.options())
        .unwrap();
    assert_eq!(
        r.row("Ownership retained").unwrap().value.as_deref(),
        Some("NO")
    );
    assert_eq!(status(&r, "Ownership retained"), Status::Failed);
    assert_ne!(r.verdict, Verdict::Satisfied);
}

#[test]
fn caller_pinned_governance_keys_override_a_bundles_own_anchors() {
    // A v2 authorization in the graph, signed with a key the bundle itself
    // anchors as the organization's: it verifies under the bundle's own
    // anchor, and fails once the caller pins the real key.
    let fx = Fixture::build();
    let attacker = key(66);
    let mut g = TrustGraph::new();
    g.add_program(PROGRAM).unwrap();
    g.add_governance_keys(&[GovernanceKey {
        organization: TAX.into(),
        public_key: pk(&attacker),
        status: GovernanceKeyStatus::Active,
        revoked_at: None,
    }])
    .unwrap();
    let mut doc = match &fx.evidence.authorizations[0] {
        AuthorizationEntry::Signed { document } => document.body.clone(),
        _ => unreachable!(),
    };
    doc.party = TAX.into();
    doc.program = encompute_verification::governance::ProgramRef::Program {
        program_id: encompute_trust::program_id(&encompute_ir::parse(PROGRAM).unwrap().to_string()),
    };
    doc.approvals.clear();
    // The anchor needs the party in the graph.
    let s = doc.sign(&attacker).unwrap();
    g.add_authorization_v2(s).unwrap();
    let unpinned = g.report(&ReportOptions::default()).unwrap();
    assert_eq!(unpinned.rows[0].status, Status::Verified, "{unpinned}");
    let pinned = g
        .report(&ReportOptions {
            anchors: Anchors {
                governance_keys: BTreeMap::from([(TAX.to_owned(), pk(&fx.tax))]),
                ..Anchors::default()
            },
            ..ReportOptions::default()
        })
        .unwrap();
    assert_eq!(pinned.rows[0].status, Status::Failed, "{pinned}");
    // The report still names the bundle it was given.
    assert_eq!(pinned.root, unpinned.root);
}

#[test]
fn the_as_of_time_never_goes_below_the_run() {
    // A caller asking for an earlier time gets the run's: a head dated
    // before the grant says nothing of revocations since.
    let f = Fixture::with(Knobs {
        head_at: T0 - 5,
        ..Knobs::default()
    });
    let mut o = f.options();
    o.as_of = Some(1);
    let r = f
        .graph
        .governance_report(&f.evidence, &f.audit, &o)
        .unwrap();
    assert_eq!(status(&r, "Audit chain"), Status::Unchecked);
}

#[test]
fn every_participant_must_witness_whatever_the_member_list_says() {
    let fx = Fixture::build();
    assert_eq!(status(&show(&fx), "Audit chain"), Status::Satisfied);
    // The control plane's (unsigned) member list drops an organization that
    // has not witnessed: it still has to.
    for org in [OTHER, BEN, TAX] {
        let mut a = fx.audit.clone();
        a.witnesses.retain(|w| w.body.organization != org);
        a.members.retain(|m| m != org);
        let r = fx
            .graph
            .governance_report(&fx.evidence, &a, &fx.options())
            .unwrap();
        assert_eq!(
            status(&r, "Audit chain"),
            Status::Unchecked,
            "{org} dropped"
        );
        assert!(details(&r, "Audit chain").contains("witnessed"), "{org}");
    }
}

#[test]
fn a_submitter_pseudonym_cannot_be_compared_with_raw_approvers_of_its_own_organization() {
    // The submitter belongs to the owner: its approvers are shown by
    // identity and it by pseudonym, so separation cannot be checked.
    let f = Fixture::with(Knobs {
        submitter: TAX,
        ..Knobs::default()
    });
    let r = show(&f);
    assert_eq!(status(&r, "Approvals"), Status::Unchecked);
    assert!(details(&r, "Approvals").contains("cannot be checked"));
    // From another organization the same approvers are not in question.
    assert_eq!(
        status(&show(&Fixture::build()), "Approvals"),
        Status::Satisfied
    );
}

#[test]
fn duplicate_heads_cost_no_more_than_their_number() {
    let fx = Fixture::build();
    let mut a = fx.audit.clone();
    let h = a.revocation_heads[0].clone();
    for _ in 0..1000 {
        a.revocation_heads.push(h.clone());
    }
    let t = std::time::Instant::now();
    let r = fx
        .graph
        .governance_report(&fx.evidence, &a, &fx.options())
        .unwrap();
    assert!(
        t.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        t.elapsed()
    );
    assert!(r.row("Audit chain").is_some());
}

fn audit_of(r: &GovernanceReport) -> String {
    format!(
        "{} | {}",
        details(r, "Audit chain"),
        r.audit_notes.join(" | ")
    )
}

fn with_audit(
    f: &Fixture,
    edit: impl FnOnce(&mut encompute_trust::AuditEvidence),
) -> GovernanceReport {
    let mut a = f.audit.clone();
    edit(&mut a);
    f.graph
        .governance_report(&f.evidence, &a, &f.options())
        .unwrap()
}

fn with_pinned_members(
    f: &Fixture,
    edit: impl FnOnce(&mut encompute_trust::AuditEvidence),
) -> GovernanceReport {
    let mut a = f.audit.clone();
    edit(&mut a);
    let mut o = f.options();
    o.anchors.project_members = [TAX, BEN, OTHER].map(String::from).into();
    f.graph.governance_report(&f.evidence, &a, &o).unwrap()
}

/// A late event: after the owners' heads, so only the tail shows it.
fn late(kind_: &str, subject: &str) -> Knobs {
    Knobs {
        late: vec![(TAX.to_owned(), kind_.to_owned(), subject.to_owned())],
        ..Knobs::default()
    }
}

#[test]
fn exporter_omitting_a_late_revocation_is_detected() {
    let f = Fixture::with(late(kind::AUTHORIZATION_REVOKED, "row"));
    // Whole, the late revocation is seen (the owner owes a head: UNCHECKED).
    assert_ne!(status(&show(&f), "Audit chain"), Status::Satisfied);
    // Left out of the run, the run no longer reaches the checkpoint: the
    // verifier refuses it, it does not read as covered.
    let r = with_audit(&f, |a| {
        a.events.pop();
    });
    assert_eq!(
        status(&r, "Audit chain"),
        Status::Failed,
        "{}",
        audit_of(&r)
    );
    assert!(details(&r, "Audit chain").contains("left out"));
    assert_ne!(status(&r, "Authorization window"), Status::Satisfied);
}

#[test]
fn exporter_omitting_a_job_cancel_event_is_detected() {
    let f = Fixture::with(late(kind::JOB_CANCELLED, JOB));
    assert_eq!(status(&show(&f), "Audit chain"), Status::Failed);
    let r = with_audit(&f, |a| {
        a.events.pop();
    });
    assert_eq!(status(&r, "Audit chain"), Status::Failed);
    assert!(
        details(&r, "Audit chain").contains("left out"),
        "{}",
        audit_of(&r)
    );
}

#[test]
fn run_with_a_gap_is_refused() {
    let f = Fixture::with(Knobs {
        filler: 5,
        ..Knobs::default()
    });
    for k in [0, 3, 6] {
        let r = with_audit(&f, |a| {
            a.events.remove(k);
        });
        // Removing the first one is only a later start; any other is a gap.
        if k == 0 {
            continue;
        }
        assert_eq!(status(&r, "Audit chain"), Status::Failed, "gap at {k}");
        assert!(details(&r, "Audit chain").contains("contiguous"));
    }
    // A duplicate is out of sequence too.
    let r = with_audit(&f, |a| {
        let e = a.events[2].clone();
        a.events.insert(3, e);
    });
    assert_eq!(status(&r, "Audit chain"), Status::Failed);
}

#[test]
fn run_not_reaching_the_checkpoint_size_is_refused() {
    let f = Fixture::build();
    let r = with_audit(&f, |a| {
        a.events.pop();
    });
    assert_eq!(status(&r, "Audit chain"), Status::Failed);
    assert!(details(&r, "Audit chain").contains("checkpoint"));
    // An empty run under a checkpoint is the same.
    let r = with_audit(&f, |a| a.events.clear());
    assert_eq!(status(&r, "Audit chain"), Status::Failed);
}

#[test]
fn run_from_the_latest_head_is_sufficient() {
    // Twenty events of other jobs, then both authorizations' issuance,
    // then the heads.
    let f = Fixture::with(Knobs {
        filler: 20,
        ..Knobs::default()
    });
    assert_eq!(status(&show(&f), "Audit chain"), Status::Satisfied);
    // The run may begin at the first issuance: nothing about the
    // authorizations can precede it, and the heads cover what came before
    // (the verifier pins the project's members, which a partial run cannot
    // show).
    let r = with_pinned_members(&f, |a| {
        a.events.drain(..20);
        a.head_leaves.insert(TAX.into(), leaves_of(&f, TAX));
        a.head_leaves.insert(BEN.into(), leaves_of(&f, BEN));
    });
    assert_eq!(
        status(&r, "Audit chain"),
        Status::Satisfied,
        "{}",
        audit_of(&r)
    );
    assert_eq!(status(&r, "Authorization window"), Status::Satisfied);
    // Later than that, nothing shows the authorizations' history.
    let r = with_audit(&f, |a| {
        a.events.drain(..21);
    });
    assert_eq!(status(&r, "Audit chain"), Status::Unchecked);
    assert!(audit_of(&r).contains("fresh revocation head"));
    assert_eq!(status(&r, "Authorization window"), Status::Unchecked);
}

#[test]
fn no_head_requires_the_full_run_or_unchecked() {
    let f = Fixture::with(Knobs {
        filler: 5,
        heads: false,
        ..Knobs::default()
    });
    // No head: owed, UNCHECKED, whatever the run.
    assert_eq!(status(&show(&f), "Audit chain"), Status::Unchecked);
    let r = with_audit(&f, |a| {
        a.events.drain(..6);
    });
    assert_eq!(status(&r, "Audit chain"), Status::Unchecked);
    assert_eq!(status(&r, "Authorization window"), Status::Unchecked);
}

#[test]
fn membership_event_omission_cannot_drop_a_witness_requirement() {
    let f = Fixture::with(Knobs {
        filler: 3,
        ..Knobs::default()
    });
    // A run that does not begin at the log's start cannot show who joined
    // before it: the control plane's list stays required, never dropped.
    let r = with_audit(&f, |a| {
        a.events.drain(..3);
        a.members.push("org-z".into());
    });
    assert_eq!(status(&r, "Audit chain"), Status::Unchecked);
    // An organization of the job dropped from the list still has to
    // witness.
    let r = with_audit(&f, |a| {
        a.events.drain(..3);
        a.witnesses.retain(|w| w.body.organization != BEN);
        a.members.retain(|m| m != BEN);
    });
    assert_eq!(status(&r, "Audit chain"), Status::Unchecked);
    // Whole and honest it is fine.
    assert_eq!(status(&show(&f), "Audit chain"), Status::Satisfied);
}

/// The leaves an owner's latest head covers, from the whole log.
fn leaves_of(f: &Fixture, org: &str) -> Vec<String> {
    let events: Vec<_> = f.audit.events.iter().map(|e| e.event.clone()).collect();
    let head = events
        .iter()
        .rposition(|e| e.kind == kind::REVOCATION_HEAD_SIGNED && e.org.as_deref() == Some(org))
        .unwrap();
    encompute_trust::govlog::revocation_leaves(&events[..head], org)
}

fn key_revoked_early(filler: usize) -> Fixture {
    let probe = Fixture::build();
    let kid = encompute_trust::authz::governance_key_id(&pk(&probe.tax));
    Fixture::with(Knobs {
        filler,
        early: vec![(
            TAX.to_owned(),
            kind::GOVERNANCE_KEY_REVOKED.to_owned(),
            "gk_1".to_owned(),
            vec![("key_id".to_owned(), kid)],
        )],
        ..Knobs::default()
    })
}

#[test]
fn key_revoked_before_a_partial_run_start_is_detected_with_the_leaf_list() {
    let f = key_revoked_early(2);
    // The whole log shows a key revoked before its authorization was issued.
    assert_eq!(status(&show(&f), "Authorization window"), Status::Failed);
    // A run that starts at the issuances hides it: with the head's leaf list
    // (checked against its signed root) it is seen, and what cannot be told
    // is UNCHECKED, never a pass.
    let cut = 3; // 2 filler + the early key revocation
    let r = with_pinned_members(&f, |a| {
        a.events.drain(..cut);
        a.head_leaves.insert(TAX.into(), leaves_of(&f, TAX));
        a.head_leaves.insert(BEN.into(), leaves_of(&f, BEN));
    });
    assert_eq!(status(&r, "Authorization window"), Status::Unchecked);
    assert!(
        details(&r, "Authorization window").contains("key"),
        "{}",
        details(&r, "Authorization window")
    );
    // A leaf list that is not the one the head covers is not believed.
    let r = with_pinned_members(&f, |a| {
        a.events.drain(..cut);
        a.head_leaves.insert(TAX.into(), vec![]);
        a.head_leaves.insert(BEN.into(), vec![]);
    });
    assert_eq!(status(&r, "Authorization window"), Status::Unchecked);
    assert!(details(&r, "Authorization window").contains("not the ones"));
    // With nothing revoked, the same partial run is checkable.
    let g = Fixture::with(Knobs {
        filler: 2,
        ..Knobs::default()
    });
    let r = with_pinned_members(&g, |a| {
        a.events.drain(..2);
        a.head_leaves.insert(TAX.into(), leaves_of(&g, TAX));
        a.head_leaves.insert(BEN.into(), leaves_of(&g, BEN));
    });
    assert_eq!(
        status(&r, "Authorization window"),
        Status::Satisfied,
        "{}",
        details(&r, "Authorization window")
    );
}

#[test]
fn partial_run_without_leaf_list_is_unchecked() {
    let g = Fixture::with(Knobs {
        filler: 2,
        ..Knobs::default()
    });
    let r = with_pinned_members(&g, |a| {
        a.events.drain(..2);
    });
    assert_eq!(status(&r, "Authorization window"), Status::Unchecked);
    assert!(details(&r, "Authorization window").contains("leaves"));
}

#[test]
fn omitted_member_cannot_shrink_the_required_set() {
    let f = Fixture::with(Knobs {
        filler: 3,
        ..Knobs::default()
    });
    // A partial run with the project's members not pinned: the exporter's
    // own list cannot make the quorum pass.
    let r = with_audit(&f, |a| {
        a.events.drain(..3);
    });
    assert_eq!(status(&r, "Audit chain"), Status::Unchecked);
    assert!(details(&r, "Audit chain").contains("not pinned"));
    // Whole, the log shows the members: no pin needed.
    assert_eq!(status(&show(&f), "Audit chain"), Status::Satisfied);
}

#[test]
fn pinned_members_must_all_witness() {
    let f = Fixture::with(Knobs {
        filler: 3,
        ..Knobs::default()
    });
    let pinned = |members: &[&str]| {
        let mut a = f.audit.clone();
        a.events.drain(..3);
        let mut o = f.options();
        o.anchors.project_members = members.iter().map(|m| (*m).to_owned()).collect();
        f.graph.governance_report(&f.evidence, &a, &o).unwrap()
    };
    assert_eq!(
        status(&pinned(&[TAX, BEN, OTHER]), "Audit chain"),
        Status::Satisfied
    );
    // A member the verifier knows, who never witnessed.
    let r = pinned(&[TAX, BEN, OTHER, "org-z"]);
    assert_eq!(status(&r, "Audit chain"), Status::Unchecked);
    assert!(details(&r, "Audit chain").contains("witnessed"));
}

#[test]
fn an_empty_authorization_set_is_never_complete() {
    let f = Fixture::build();
    let owners: std::collections::BTreeSet<String> = [TAX, BEN].map(String::from).into();
    let found = encompute_trust::check_audit(
        &f.audit,
        &f.anchors,
        &owners,
        &owners,
        &Default::default(),
        T0,
    );
    assert!(!found.complete);
}

#[test]
fn a_stale_older_checkpoint_hides_what_came_after_it() {
    use encompute_trust::govlog::{hash_hex, root, InclusionProof, ProjectCheckpoint};
    let f = Fixture::build();
    // The control plane's older, validly signed checkpoint over the first
    // events only (before the heads): its proofs verify, and the run is
    // contiguous to it. Nothing after it, the heads included, is shown.
    let events: Vec<_> = f.audit.events.iter().map(|e| e.event.clone()).collect();
    let m = events
        .iter()
        .position(|e| e.kind == kind::REVOCATION_HEAD_SIGNED)
        .unwrap();
    let leaves: Vec<_> = events[..m].iter().map(|e| e.leaf_hash().unwrap()).collect();
    let cp = ProjectCheckpoint {
        version: 1,
        partition: format!("p:{PROJECT}"),
        size: m as u64,
        root: hash_hex(&root(&leaves)),
        gseq: m as u64,
        at: T0 + 30,
    }
    .sign(&f.control)
    .unwrap();
    let r = with_audit(&f, |a| {
        a.checkpoint = Some(cp.clone());
        a.events = events[..m]
            .iter()
            .enumerate()
            .map(|(i, e)| encompute_trust::AuditEntry {
                event: e.clone(),
                proof: InclusionProof::from_leaves(&format!("p:{PROJECT}"), &leaves, i as u64)
                    .unwrap(),
            })
            .collect();
        a.witnesses.clear();
        a.revocation_heads.clear();
    });
    assert_ne!(status(&r, "Audit chain"), Status::Satisfied);
    assert_ne!(r.verdict, Verdict::Satisfied);
}

// --- placement and operator separation (INV-233, INV-234, INV-244) -----------

use encompute_trust::governance::HONEST_CONTROL_PLANE;
use encompute_verification::placement::{
    GrantPlacement, Location, LocationEvidence, LocationPattern, PlacementConstraints,
};

fn grant_at(operator: &str, region: &str, evidence: LocationEvidence) -> GrantPlacement {
    GrantPlacement {
        operator: operator.into(),
        location: Some(Location::resolve("gcp", region, None).unwrap()),
        evidence,
        evidence_digest: None,
        endpoint_digest: None,
    }
}

fn owners_want(region: &str) -> PlacementConstraints {
    PlacementConstraints {
        allowed_regions: Some(BTreeSet::from([LocationPattern::region("gcp", region)])),
        ..PlacementConstraints::default()
    }
}

/// The text of a row that says anything about operators, separation or
/// where the evaluator ran.
fn placement_texts(r: &GovernanceReport) -> Vec<String> {
    let mut out = vec![];
    for row in &r.rows {
        let mut texts: Vec<&str> = row.details.iter().map(String::as_str).collect();
        texts.extend(row.value.as_deref());
        for t in texts {
            let low = t.to_lowercase();
            if low.contains("operator") || low.contains("separation") {
                out.push(format!("{}: {t}", row.name));
            }
        }
        if row.name == "Location"
            && row
                .value
                .as_deref()
                .is_some_and(|v| v.contains("declared") || v.contains("attested"))
        {
            out.push(format!("{}: {}", row.name, row.value.clone().unwrap()));
        }
    }
    out
}

#[test]
fn report_operator_separation_carries_the_honest_control_plane_qualifier() {
    let variants = [
        // Separated, owners' rules met.
        Knobs {
            owner_placement: Some(owners_want("europe-west3")),
            grant_placement: Some(grant_at(OTHER, "europe-west3", LocationEvidence::Attested)),
            ..Knobs::default()
        },
        // The operator owns a source.
        Knobs {
            owner_placement: Some(owners_want("europe-west3")),
            grant_placement: Some(grant_at(TAX, "europe-west3", LocationEvidence::Attested)),
            ..Knobs::default()
        },
        // The operator receives the output.
        Knobs {
            placement: true,
            grant_placement: Some(grant_at(
                TAX,
                "europe-west3",
                LocationEvidence::OperatorDeclared,
            )),
            ..Knobs::default()
        },
    ];
    let mut claims = 0;
    for k in variants {
        let r = show(&Fixture::with(k));
        for t in placement_texts(&r) {
            claims += 1;
            assert!(
                t.contains(HONEST_CONTROL_PLANE),
                "a statement about operators or placement lacks {HONEST_CONTROL_PLANE:?}: {t}"
            );
        }
    }
    assert!(claims >= 6, "the report said too little to check: {claims}");

    // It does say that operators are separated, and says so with the
    // qualifier.
    let r = show(&Fixture::with(Knobs {
        owner_placement: Some(owners_want("europe-west3")),
        grant_placement: Some(grant_at(OTHER, "europe-west3", LocationEvidence::Attested)),
        ..Knobs::default()
    }));
    let loc = r.row("Location").unwrap();
    assert!(loc
        .details
        .iter()
        .any(|d| d.starts_with("operator separation:") && d.ends_with(HONEST_CONTROL_PLANE)));
    // Separation is never claimed when the operator is an owner or a
    // recipient: the row fails and says why.
    let r = show(&Fixture::with(Knobs {
        grant_placement: Some(grant_at(TAX, "europe-west3", LocationEvidence::Attested)),
        placement: true,
        ..Knobs::default()
    }));
    let loc = r.row("Location").unwrap();
    assert_eq!(loc.status, Status::Failed);
    assert!(!loc
        .details
        .iter()
        .any(|d| d.starts_with("operator separation:")));
}

#[test]
fn report_location_row_uses_signed_grant_placement_only_when_present() {
    // Declared by an owner, but the grant records no placement: nothing is
    // evidenced, however plausible.
    let r = show(&Fixture::with(Knobs {
        owner_placement: Some(owners_want("europe-west3")),
        ..Knobs::default()
    }));
    let loc = r.row("Location").unwrap();
    assert_eq!(loc.status, Status::NotPresent);
    assert_eq!(loc.value.as_deref(), Some("NOT EVIDENCED"));

    // The grant's placement inside the owners' signed rules: satisfied, as
    // declared or attested (never more) and with the qualifier.
    let ok = |evidence| {
        show(&Fixture::with(Knobs {
            owner_placement: Some(owners_want("europe-west3")),
            grant_placement: Some(grant_at(OTHER, "europe-west3", evidence)),
            ..Knobs::default()
        }))
    };
    let r = ok(LocationEvidence::OperatorDeclared);
    let loc = r.row("Location").unwrap();
    assert_eq!(loc.status, Status::Satisfied);
    let v = loc.value.clone().unwrap();
    assert!(v.contains("declared") && !v.contains("attested"), "{v}");
    assert!(v.contains(HONEST_CONTROL_PLANE));
    assert!(ok(LocationEvidence::Attested)
        .row("Location")
        .unwrap()
        .value
        .clone()
        .unwrap()
        .contains("attested"));

    // Another region than the owners' signed rule allows: failed.
    let r = show(&Fixture::with(Knobs {
        owner_placement: Some(owners_want("europe-west3")),
        grant_placement: Some(grant_at(OTHER, "europe-west4", LocationEvidence::Attested)),
        ..Knobs::default()
    }));
    assert_eq!(status(&r, "Location"), Status::Failed);

    // An owner that wants better evidence than the grant records.
    let mut want = owners_want("europe-west3");
    want.min_evidence = LocationEvidence::Attested;
    let r = show(&Fixture::with(Knobs {
        owner_placement: Some(want),
        grant_placement: Some(grant_at(
            OTHER,
            "europe-west3",
            LocationEvidence::OperatorDeclared,
        )),
        ..Knobs::default()
    }));
    assert_eq!(status(&r, "Location"), Status::Failed);

    // The evaluator's own word is not evidence.
    let r = ok(LocationEvidence::SelfDeclared);
    assert_eq!(status(&r, "Location"), Status::Unchecked);

    // The project's constraints are only a digest here: never satisfied.
    let r = show(&Fixture::with(Knobs {
        placement: true,
        owner_placement: Some(owners_want("europe-west3")),
        grant_placement: Some(grant_at(OTHER, "europe-west3", LocationEvidence::Attested)),
        ..Knobs::default()
    }));
    assert_eq!(status(&r, "Location"), Status::Unchecked);
    assert_ne!(r.verdict, Verdict::Satisfied);

    // An owner's pin of other project constraints than the job's binding.
    let r = show(&Fixture::with(Knobs {
        placement: true,
        owner_project_pin: Some("9".repeat(64)),
        grant_placement: Some(grant_at(OTHER, "europe-west3", LocationEvidence::Attested)),
        ..Knobs::default()
    }));
    assert_eq!(status(&r, "Location"), Status::Failed);

    // A placement in the grant that nobody declared a rule for is not a
    // claim: nothing is declared, so the row stays not applicable.
    let r = show(&Fixture::with(Knobs {
        grant_placement: Some(grant_at(OTHER, "europe-west3", LocationEvidence::Attested)),
        ..Knobs::default()
    }));
    assert_eq!(status(&r, "Location"), Status::NotApplicable);
}

/// A governed job that releases a differential-privacy aggregate is charged
/// to a project's scope and its sources' populations, not to the sources'
/// own ledgers that the per-asset budget row reads: the report says the
/// budget is not evidenced (never a pass, and never a failure for a budget
/// no program declares), whether or not an authorization pins the scope.
#[test]
fn a_governed_dp_release_is_not_evidenced_never_a_budget_pass_or_fail() {
    for privacy_policy in [false, true] {
        let r = show(&Fixture::with(Knobs {
            dp_aggregate: true,
            privacy_policy,
            ..Knobs::default()
        }));
        assert_eq!(status(&r, "Privacy policy"), Status::NotPresent);
        let d = details(&r, "Privacy policy");
        assert!(
            d.contains("scope") && d.contains("population") && d.contains("not evidenced"),
            "{d}"
        );
        assert_eq!(
            r.row("Privacy policy").unwrap().value.as_deref(),
            Some("NOT EVIDENCED")
        );
    }
    assert_ne!(
        show(&Fixture::with(Knobs {
            dp_aggregate: true,
            ..Knobs::default()
        }))
        .verdict,
        Verdict::Satisfied
    );
}

/// An owner up the lineage of a source authorizes it without owning an
/// input of the binding: an evaluator that organization operates breaks
/// operator separation all the same, and the row says so.
#[test]
fn a_lineage_owner_operating_the_evaluator_breaks_separation() {
    let operated_by_other = |lineage_owner| {
        show(&Fixture::with(Knobs {
            placement: true,
            lineage_owner,
            grant_placement: Some(grant_at(OTHER, "europe-west3", LocationEvidence::Attested)),
            ..Knobs::default()
        }))
    };
    // Nobody up the lineage: the operator owns nothing here.
    assert!(operated_by_other(false)
        .row("Location")
        .unwrap()
        .details
        .iter()
        .any(|d| d.starts_with("operator separation:")));
    // A lineage owner's own evaluator.
    let r = operated_by_other(true);
    let loc = r.row("Location").unwrap();
    assert_eq!(loc.status, Status::Failed, "{loc:?}");
    assert!(
        loc.details
            .iter()
            .any(|d| d.contains("operator separation is broken")),
        "{loc:?}"
    );
}
