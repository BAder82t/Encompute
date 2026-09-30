//! Release tickets: the control plane's short-lived, single-use request to
//! an owner's key broker for one key release in one scheduled job. Every
//! field is signed under the ticket's own domain, by the pinned control
//! plane only; a ticket lives at most 300 seconds; its execution spec and
//! governance binding must be the ones its IDs name.

use std::collections::{BTreeMap, BTreeSet};

use encompute_ir::Code;
use encompute_verification::governance::{
    GovernanceBinding, GovernanceInput, GovernanceOutput, ReleaseClass,
};
use encompute_verification::ticket::{
    ReleaseTicket, TicketKind, KEY_TICKET, MAX_TICKET_TTL_SECS, TICKET_SKEW_SECS, TICKET_VERSION,
};
use encompute_verification::{ExecutionSpec, ServiceSigner};

const NOW: u64 = 1_900_000_000;

fn h(c: char) -> String {
    c.to_string().repeat(64)
}

fn control() -> ServiceSigner {
    ServiceSigner::from_seed("control-plane", &[42; 32]).unwrap()
}

fn binding() -> GovernanceBinding {
    GovernanceBinding {
        version: 1,
        project: "prj_1".into(),
        purpose_id: h('1'),
        linkage_policy_id: None,
        inputs: BTreeMap::from([(
            "income".into(),
            GovernanceInput {
                asset_version_id: h('3'),
                digest_commitment: h('4'),
                organization: "tax-agency".into(),
            },
        )]),
        outputs: BTreeMap::from([(
            "eligible".into(),
            GovernanceOutput {
                release_class: ReleaseClass::BooleanOnly,
                recipients: BTreeSet::from(["benefits-agency".into()]),
            },
        )]),
        placement_digest: None,
        project_policy_digest: None,
    }
}

fn spec() -> ExecutionSpec {
    ExecutionSpec {
        version: 1,
        program_id: h('a'),
        plan_id: h('b'),
        parameter_set_id: h('c'),
        plan_kind: "exact".into(),
        plan_version: 1,
        semantics: "exact".into(),
        scheme: "BinFHE".into(),
        backend: "openfhe-exact".into(),
        backend_version: "1.5.1".into(),
        policy_id: Some(h('d')),
        privacy_policy_id: None,
        governance_id: None,
    }
    .governed(&binding())
}

/// A consistent, unsigned ticket (every optional field set).
fn ticket() -> ReleaseTicket {
    let b = binding();
    let s = spec();
    ReleaseTicket {
        version: TICKET_VERSION,
        ticket_id: h('e'),
        kind: TicketKind::KeyRelease,
        organization: "tax-agency".into(),
        broker: "tax-broker".into(),
        asset_version_id: h('3'),
        authorization_ids: BTreeSet::from([h('5')]),
        job_id: "job_1".into(),
        project: b.project.clone(),
        purpose_id: b.purpose_id.clone(),
        governance_id: b.id().hex(),
        plan_id: h('6'),
        execution_spec_id: s.id().hex(),
        policy_id: s.policy_id.clone(),
        workload_or_recipient: h('7'),
        placement_digest: None,
        execution_spec: s,
        binding: b,
        not_before: NOW,
        not_after: NOW + MAX_TICKET_TTL_SECS,
        anchor_counter: 9,
        issuer: String::new(),
        issuer_public_key: String::new(),
        signature: String::new(),
    }
}

fn signed() -> ReleaseTicket {
    ticket().sign(&control()).unwrap()
}

#[test]
fn a_signed_ticket_verifies_under_the_pinned_control_key() {
    let t = signed();
    assert_eq!(t.issuer, "control-plane");
    assert_eq!(t.issuer_public_key, control().public_key_hex());
    t.verify(&control().public_key_hex(), NOW).unwrap();
    // The signature is under the ticket's own domain.
    assert_eq!(KEY_TICKET, "encompute.key-release-ticket.v1");
    let other_domain = control()
        .sign("encompute.job-grant.v1", &t.unsigned())
        .unwrap();
    let mut x = t.clone();
    x.signature = other_domain;
    assert_eq!(
        x.verify(&control().public_key_hex(), NOW).unwrap_err().code,
        Code::GovernanceReleaseTicket
    );
}

/// A named change to one field.
type Change<'a> = (&'a str, &'a dyn Fn(&mut ReleaseTicket));

#[test]
fn ticket_every_field_changes_signature() {
    let t = signed();
    let key = control().public_key_hex();
    let changes: &[Change] = &[
        ("version", &|t| t.version = 2),
        ("ticket_id", &|t| t.ticket_id = h('f')),
        ("kind", &|t| t.kind = TicketKind::Export),
        ("organization", &|t| {
            t.organization = "benefits-agency".into()
        }),
        ("broker", &|t| t.broker = "other-broker".into()),
        ("asset_version_id", &|t| t.asset_version_id = h('8')),
        ("authorization_ids", &|t| {
            t.authorization_ids.insert(h('9'));
        }),
        ("job_id", &|t| t.job_id = "job_2".into()),
        ("project", &|t| t.project = "prj_2".into()),
        ("purpose_id", &|t| t.purpose_id = h('2')),
        ("governance_id", &|t| t.governance_id = h('2')),
        ("plan_id", &|t| t.plan_id = h('2')),
        ("execution_spec_id", &|t| t.execution_spec_id = h('2')),
        ("policy_id", &|t| t.policy_id = None),
        ("workload_or_recipient", &|t| {
            t.workload_or_recipient = h('2')
        }),
        ("placement_digest", &|t| t.placement_digest = Some(h('2'))),
        ("execution_spec", &|t| {
            t.execution_spec.backend_version = "1.5.2".into()
        }),
        ("binding", &|t| {
            t.binding.project_policy_digest = Some(h('2'))
        }),
        ("not_before", &|t| t.not_before -= 1),
        ("not_after", &|t| t.not_after -= 1),
        ("anchor_counter", &|t| t.anchor_counter += 1),
        ("issuer", &|t| t.issuer = "control-plane-2".into()),
        ("issuer_public_key", &|t| t.issuer_public_key = h('2')),
        ("signature", &|t| t.signature = "00".repeat(64)),
    ];
    let v = serde_json::to_value(&t).unwrap();
    let mut keys: BTreeSet<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    // Absent (not serialized) when the binding declares no placement.
    keys.insert("placement_digest");
    let covered: BTreeSet<&str> = changes.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, covered, "the sweep must change every field");
    for (field, change) in changes {
        let mut x = t.clone();
        change(&mut x);
        let e = x.verify(&key, NOW + 1).expect_err(field);
        assert_eq!(e.code, Code::GovernanceReleaseTicket, "{field}: {e}");
    }
    // Round trip: unknown fields are refused, the bytes are stable.
    let back: ReleaseTicket = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(back, t);
    let mut extra = v;
    extra["ttl"] = 600.into();
    assert!(serde_json::from_value::<ReleaseTicket>(extra).is_err());
}

#[test]
fn ticket_signed_by_other_key_refused() {
    let pinned = control().public_key_hex();
    // Another signer, naming itself: not the pinned control plane.
    let rogue = ServiceSigner::from_seed("control-plane", &[43; 32]).unwrap();
    let t = ticket().sign(&rogue).unwrap();
    t.verify(&rogue.public_key_hex(), NOW).unwrap();
    let e = t.verify(&pinned, NOW).unwrap_err();
    assert_eq!(e.code, Code::GovernanceReleaseTicket, "{e}");
    // Another signer, claiming the pinned key: the signature fails.
    let mut t = ticket().sign(&rogue).unwrap();
    t.issuer_public_key = pinned.clone();
    let e = t.verify(&pinned, NOW).unwrap_err();
    assert_eq!(e.code, Code::GovernanceReleaseTicket, "{e}");
}

#[test]
fn ticket_window_over_300s_refused() {
    let key = control().public_key_hex();
    let mut t = ticket();
    t.not_after = t.not_before + MAX_TICKET_TTL_SECS + 1;
    let t = t.sign(&control()).unwrap();
    let e = t.verify(&key, NOW + 1).unwrap_err();
    assert_eq!(e.code, Code::GovernanceReleaseTicket, "{e}");
    // An empty or inverted window.
    for (a, b) in [(NOW, NOW), (NOW + 10, NOW)] {
        let mut t = ticket();
        (t.not_before, t.not_after) = (a, b);
        let t = t.sign(&control()).unwrap();
        assert_eq!(
            t.verify(&key, NOW).unwrap_err().code,
            Code::GovernanceReleaseTicket
        );
    }
}

/// Skew is applied toward denial: never before `not_before`, and not in
/// the last `TICKET_SKEW_SECS` before `not_after`.
#[test]
fn ticket_time_checks_lean_toward_denial() {
    let key = control().public_key_hex();
    let t = signed();
    assert!(t.verify(&key, NOW - 1).is_err(), "before not_before");
    t.verify(&key, NOW).unwrap();
    let last_ok = t.not_after - TICKET_SKEW_SECS - 1;
    t.verify(&key, last_ok).unwrap();
    for at in [last_ok + 1, t.not_after - 1, t.not_after, t.not_after + 1] {
        let e = t.verify(&key, at).unwrap_err();
        assert_eq!(e.code, Code::GovernanceReleaseTicket, "at {at}: {e}");
    }
}

#[test]
fn ticket_spec_or_binding_not_matching_ids_refused() {
    let key = control().public_key_hex();
    let cases: &[Change] = &[
        // The carried spec is not the one the ID names.
        ("spec", &|t| {
            t.execution_spec.backend_version = "1.5.2".into()
        }),
        // The carried binding is not the one the ID names.
        ("binding", &|t| {
            t.binding.project_policy_digest = Some(h('2'))
        }),
        // The spec names another governance binding.
        ("spec governance", &|t| {
            t.execution_spec.governance_id = Some(h('2'));
            t.execution_spec_id = t.execution_spec.id().hex();
        }),
        // The body's project, purpose or policy disagrees with the binding
        // or spec.
        ("project", &|t| t.project = "prj_2".into()),
        ("purpose", &|t| t.purpose_id = h('2')),
        ("policy", &|t| t.policy_id = Some(h('2'))),
        ("placement", &|t| t.placement_digest = Some(h('2'))),
        // The asset version is not a source of this organization.
        ("asset version", &|t| t.asset_version_id = h('8')),
        ("organization", &|t| {
            t.organization = "benefits-agency".into()
        }),
        // No authorization, malformed IDs.
        ("no authorization", &|t| t.authorization_ids.clear()),
        ("ticket id", &|t| t.ticket_id = "not-hex".into()),
        ("recipient", &|t| {
            t.workload_or_recipient = "evaluator-1".into()
        }),
        ("plan", &|t| t.plan_id = "pln_1".into()),
    ];
    for (what, change) in cases {
        let mut t = ticket();
        change(&mut t);
        assert!(t.check_consistent().is_err(), "{what}");
        // Signed as it is, it still does not verify.
        let t = t.sign(&control()).unwrap();
        let e = t.verify(&key, NOW).unwrap_err();
        assert_eq!(e.code, Code::GovernanceReleaseTicket, "{what}: {e}");
    }
    ticket().check_consistent().unwrap();
}

#[test]
fn a_ticket_id_is_random() {
    let a = ReleaseTicket::new_ticket_id().unwrap();
    let b = ReleaseTicket::new_ticket_id().unwrap();
    assert_eq!(a.len(), 64);
    assert_ne!(a, b);
}
