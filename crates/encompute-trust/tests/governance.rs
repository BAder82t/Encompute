//! Owner authorizations v2 (governed projects): one owner-signed document
//! per (organization, purpose, program, asset version), signed with the
//! organization's governance key. Every field is bound by its ID and its
//! signature; approvals are four-eyes statements over the unapproved body;
//! a v1 authorization is untouched.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;

use encompute_ir::Code;
use encompute_trust::authz::{
    governance_key_id, ApprovalEvidence, AuthorizationLimits, AuthorizationSetId, AuthorizationV2,
    GovernanceKey, GovernanceKeyStatus, PurposeAcceptance, RevocationV2, SignedAuthorizationV2,
};
use encompute_trust::{Evidence, NodeKind, ReportOptions, Status, TrustGraph};
use encompute_verification::governance::{ProgramRef, ProgramSetId, ReleaseClass};
use encompute_verification::hex;

/// One change to an authorization body.
type Edit = Box<dyn Fn(&mut AuthorizationV2)>;

fn h(c: char) -> String {
    c.to_string().repeat(64)
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(k: &SigningKey) -> String {
    hex(&k.verifying_key().to_bytes())
}

/// Every optional field set, so each can be changed.
fn body() -> AuthorizationV2 {
    AuthorizationV2 {
        version: 2,
        party: "tax-agency".into(),
        project: "prj_1".into(),
        purpose_id: h('1'),
        asset_version_id: h('2'),
        asset_digest_commitment: h('3'),
        program: ProgramRef::Program { program_id: h('a') },
        policy_id: h('4'),
        privacy_policy_id: Some(h('5')),
        linkage_policy_id: Some(h('6')),
        release_class: ReleaseClass::BooleanOnly,
        recipients: BTreeSet::from(["benefits-agency".into()]),
        privacy_scope_id: Some(h('7')),
        execution_spec_ids: Some(BTreeSet::from([h('8')])),
        limits: AuthorizationLimits {
            max_executions: Some(10),
            max_releases: Some(10),
            max_subjects_per_job: Some(1000),
            max_evaluations_per_subject: Some(1),
        },
        per_job_four_eyes: false,
        valid_from: 1_000,
        valid_until: 2_000,
        issued_at: 900,
        nonce: "ab".repeat(16),
        approvals: vec![],
    }
}

fn approval(b: &AuthorizationV2, subject: &str, role: &str) -> ApprovalEvidence {
    ApprovalEvidence {
        statement_digest: b.approval_statement("https://idp.tax.example", subject, role),
        approver_subject: subject.into(),
        idp_issuer: "https://idp.tax.example".into(),
        auth_time: Some(950),
        acr: None,
        amr: None,
        role: role.into(),
        organization: b.party.clone(),
        at: 960,
    }
}

fn approved() -> AuthorizationV2 {
    let mut b = body();
    b.approvals = vec![
        approval(&b, "alice", "data_owner"),
        approval(&b, "bob", "security_admin"),
    ];
    b
}

#[test]
fn every_authorization_field_changes_its_id() {
    let b = approved();
    b.check().unwrap();
    let fields: Vec<(&str, Edit)> = vec![
        ("version", Box::new(|b| b.version = 3)),
        ("party", Box::new(|b| b.party = "benefits-agency".into())),
        ("project", Box::new(|b| b.project = "prj_2".into())),
        ("purpose_id", Box::new(|b| b.purpose_id = h('9'))),
        (
            "asset_version_id",
            Box::new(|b| b.asset_version_id = h('9')),
        ),
        (
            "asset_digest_commitment",
            Box::new(|b| b.asset_digest_commitment = h('9')),
        ),
        (
            "program",
            Box::new(|b| b.program = ProgramRef::Program { program_id: h('b') }),
        ),
        ("policy_id", Box::new(|b| b.policy_id = h('9'))),
        (
            "privacy_policy_id",
            Box::new(|b| b.privacy_policy_id = None),
        ),
        (
            "linkage_policy_id",
            Box::new(|b| b.linkage_policy_id = None),
        ),
        (
            "release_class",
            Box::new(|b| b.release_class = ReleaseClass::AggregateOnly),
        ),
        (
            "recipients",
            Box::new(|b| {
                b.recipients.insert("tax-agency".into());
            }),
        ),
        ("privacy_scope_id", Box::new(|b| b.privacy_scope_id = None)),
        (
            "execution_spec_ids",
            Box::new(|b| b.execution_spec_ids = None),
        ),
        ("limits", Box::new(|b| b.limits.max_executions = Some(11))),
        (
            "per_job_four_eyes",
            Box::new(|b| b.per_job_four_eyes = true),
        ),
        ("valid_from", Box::new(|b| b.valid_from = 1_001)),
        ("valid_until", Box::new(|b| b.valid_until = 2_001)),
        ("issued_at", Box::new(|b| b.issued_at = 901)),
        ("nonce", Box::new(|b| b.nonce = "cd".repeat(16))),
        (
            "approvals",
            Box::new(|b| {
                b.approvals.pop();
            }),
        ),
    ];
    let keys: BTreeSet<String> = serde_json::to_value(&b)
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let covered: BTreeSet<String> = fields.iter().map(|(k, _)| k.to_string()).collect();
    assert_eq!(keys, covered, "the sweep must change every field");
    let mut seen = BTreeSet::from([b.id()]);
    for (f, change) in &fields {
        let mut x = b.clone();
        change(&mut x);
        assert!(
            seen.insert(x.id()),
            "{f} does not change the authorization ID"
        );
    }
    assert!(b.display_id().starts_with("encauth2:"));
}

#[test]
fn a_signed_authorization_verifies_only_under_its_governance_key() {
    let (gk, other) = (key(1), key(2));
    let s = approved().sign(&gk).unwrap();
    s.verify(&pk(&gk)).unwrap();
    assert_eq!(s.id(), approved().id());
    // Another key (another organization's, or the owner's party key).
    let e = s.verify(&pk(&other)).unwrap_err();
    assert_eq!(e.code, Code::TrustAuthorization);
    let forged = approved().sign(&other).unwrap();
    assert!(forged.verify(&pk(&gk)).is_err());
    // A tampered body: every change breaks the signature.
    for f in [
        |b: &mut AuthorizationV2| b.valid_until += 1,
        |b: &mut AuthorizationV2| b.purpose_id = h('9'),
        |b: &mut AuthorizationV2| b.project = "prj_other".into(),
        |b: &mut AuthorizationV2| b.program = ProgramRef::Program { program_id: h('b') },
        |b: &mut AuthorizationV2| {
            b.recipients.insert("fraud-unit".into());
        },
    ] {
        let mut t = s.clone();
        f(&mut t.body);
        assert!(t.verify(&pk(&gk)).is_err());
    }
    // A reissued signature under the right key but a malformed signature.
    let mut bad = s.clone();
    bad.signature = "00".repeat(64);
    assert!(bad.verify(&pk(&gk)).is_err());
    // Strict parsing: unknown fields and versions are refused.
    let mut v = serde_json::to_value(&s).unwrap();
    v["body"]["wildcard"] = serde_json::json!(true);
    assert!(serde_json::from_value::<SignedAuthorizationV2>(v).is_err());
    let mut v1 = approved();
    v1.version = 1;
    assert!(v1.sign(&gk).unwrap().verify(&pk(&gk)).is_err());
}

#[test]
fn an_authorization_is_well_formed_and_its_window_is_strict() {
    // Unapproved, so each change is refused for itself (a change to an
    // approved body also invalidates its approvals).
    let b = body();
    b.check().unwrap();
    assert!(!b.is_valid_at(999));
    assert!(b.is_valid_at(1_000) && b.is_valid_at(1_999));
    assert!(!b.is_valid_at(2_000), "expiry is strict");
    let bad: Vec<Edit> = vec![
        Box::new(|b| b.valid_until = b.valid_from),
        Box::new(|b| b.purpose_id = "".into()),
        Box::new(|b| b.purpose_id = "*".into()),
        Box::new(|b| {
            b.program = ProgramRef::Program {
                program_id: "*".into(),
            }
        }),
        Box::new(|b| {
            b.program = ProgramRef::ProgramSet {
                program_set_id: h('c'),
                programs: BTreeSet::from([h('a')]),
            }
        }),
        Box::new(|b| b.project.clear()),
        Box::new(|b| b.recipients.clear()),
        Box::new(|b| b.nonce = "short".into()),
        Box::new(|b| b.asset_version_id = "v1".into()),
        Box::new(|b| b.policy_id = "".into()),
    ];
    for (i, f) in bad.iter().enumerate() {
        let mut x = b.clone();
        f(&mut x);
        assert!(x.check().is_err(), "change {i} was accepted");
    }
    // A program set is fine when its ID matches its members.
    let mut set = b.clone();
    set.program = ProgramRef::ProgramSet {
        program_set_id: ProgramSetId::of([h('a'), h('b')]).unwrap().hex(),
        programs: BTreeSet::from([h('a'), h('b')]),
    };
    set.check().unwrap();
    assert!(set.program.covers(&h('b')));
}

#[test]
fn approvals_are_statements_over_the_unapproved_body() {
    let b = approved();
    // The statement ignores approvals already collected, but binds the
    // body, the approver and the role.
    let mut more = b.clone();
    more.approvals.clear();
    assert_eq!(
        more.approval_statement("https://idp.tax.example", "alice", "data_owner"),
        b.approvals[0].statement_digest
    );
    assert_ne!(
        b.approval_statement("https://idp.tax.example", "alice", "security_admin"),
        b.approvals[0].statement_digest
    );
    let mut other_body = body();
    other_body.valid_until += 1;
    assert_ne!(
        other_body.approval_statement("https://idp.tax.example", "alice", "data_owner"),
        b.approvals[0].statement_digest
    );
    b.check_approvals().unwrap();
    // Two distinct humans, with one data owner and one security admin.
    let rule = BTreeMap::from([("data_owner".to_string(), 1), ("security_admin".into(), 1)]);
    b.check_quorum(2, &rule).unwrap();

    // One person twice is one approver.
    let mut twice = body();
    twice.approvals = vec![
        approval(&twice, "alice", "data_owner"),
        approval(&twice, "alice", "security_admin"),
    ];
    assert_eq!(
        twice.check_quorum(2, &rule).unwrap_err().code,
        Code::GovernanceFourEyesIncomplete
    );
    // A missing role.
    let mut roles = body();
    roles.approvals = vec![
        approval(&roles, "alice", "data_owner"),
        approval(&roles, "carol", "data_owner"),
    ];
    assert_eq!(
        roles.check_quorum(2, &rule).unwrap_err().code,
        Code::GovernanceFourEyesIncomplete
    );
    // An approval statement for another body, or by another organization.
    let mut stale = body();
    stale.approvals = vec![approval(&other_body, "alice", "data_owner")];
    assert!(stale.check_approvals().is_err());
    let mut foreign = body();
    let mut a = approval(&foreign, "mallory", "data_owner");
    a.organization = "benefits-agency".into();
    foreign.approvals = vec![a];
    assert!(foreign.check_approvals().is_err());
    // The signed document is checked the same way.
    let gk = key(1);
    assert!(stale.sign(&gk).unwrap().verify(&pk(&gk)).is_err());
}

#[test]
fn revocations_and_purpose_acceptances_are_signed_by_the_governance_key() {
    let (gk, other) = (key(1), key(2));
    let r = RevocationV2 {
        version: 2,
        party: "tax-agency".into(),
        authorization: approved().id(),
        reason: "the statute changed".into(),
        issued_at: 1_500,
    }
    .sign(&gk)
    .unwrap();
    r.verify(&pk(&gk)).unwrap();
    assert!(r.verify(&pk(&other)).is_err());
    let mut t = r.clone();
    t.body.authorization = h('f');
    assert!(t.verify(&pk(&gk)).is_err());

    let acc = PurposeAcceptance {
        version: 1,
        organization: "tax-agency".into(),
        project: "prj_1".into(),
        purpose_id: h('1'),
        accepted_at: 950,
    };
    let s = acc.clone().sign(&gk).unwrap();
    s.verify(&pk(&gk)).unwrap();
    assert!(s.verify(&pk(&other)).is_err());
    for f in [
        |a: &mut PurposeAcceptance| a.purpose_id = h('2'),
        |a: &mut PurposeAcceptance| a.project = "prj_2".into(),
        |a: &mut PurposeAcceptance| a.organization = "benefits-agency".into(),
    ] {
        let mut t = s.clone();
        f(&mut t.body);
        assert!(t.verify(&pk(&gk)).is_err());
    }
    // Key IDs are fingerprints of the public key.
    assert_ne!(governance_key_id(&pk(&gk)), governance_key_id(&pk(&other)));
    assert_eq!(governance_key_id(&pk(&gk)).len(), 64);
}

#[test]
fn an_authorization_set_is_order_independent() {
    let (a, b) = (h('a'), h('b'));
    assert_eq!(
        AuthorizationSetId::of([a.clone(), b.clone()]).unwrap(),
        AuthorizationSetId::of([b.clone(), a.clone()]).unwrap()
    );
    assert_ne!(
        AuthorizationSetId::of([a.clone()]).unwrap(),
        AuthorizationSetId::of([a.clone(), b.clone()]).unwrap()
    );
    assert!(AuthorizationSetId::of(Vec::<String>::new()).is_err());
    assert!(AuthorizationSetId::of([a.clone(), a]).is_err());
}

/// A graph with the program, and an authorization of it by `tax-agency`.
fn graph_and_authorization() -> (TrustGraph, String, AuthorizationV2) {
    let mut g = TrustGraph::new();
    let prog = g.add_program(PROGRAM).unwrap();
    let mut b = body();
    b.program = ProgramRef::Program {
        program_id: prog.trim_start_matches("program:").to_owned(),
    };
    b.approvals = vec![
        approval(&b, "alice", "data_owner"),
        approval(&b, "bob", "security_admin"),
    ];
    (g, prog, b)
}

fn anchor(org: &str, k: &SigningKey, status: GovernanceKeyStatus) -> GovernanceKey {
    GovernanceKey {
        organization: org.into(),
        public_key: pk(k),
        status,
    }
}

#[test]
fn a_v2_authorization_joins_the_trust_graph_under_its_anchored_governance_key() {
    let gk = key(1);
    let (mut g, prog, b) = graph_and_authorization();
    g.add_governance_keys(&[anchor("tax-agency", &gk, GovernanceKeyStatus::Active)])
        .unwrap();
    // Anchoring the same key again changes nothing.
    g.add_governance_keys(&[anchor("tax-agency", &gk, GovernanceKeyStatus::Active)])
        .unwrap();
    let s = b.sign(&gk).unwrap();
    let id = g.add_authorization_v2(s.clone()).unwrap();
    let n = g.node(&id).unwrap();
    assert_eq!(n.kind, NodeKind::Authorization);
    assert!(matches!(n.evidence, Some(Evidence::AuthorizationV2(_))));
    // Rebuilt from its evidence alone, it is the same node, with no
    // problem.
    let (rebuilt, problems) = g.rebuild();
    assert!(problems.is_empty(), "{problems:?}");
    assert!(rebuilt.node(&id).is_some());
    rebuilt.check_edges().unwrap();
    assert!(rebuilt
        .out(&id, encompute_trust::EdgeKind::Authorizes)
        .any(|p| p == prog));
    // The anchor is not evidence: the report's evidence row does not fail
    // on it.
    let rep = g.report(&ReportOptions::default()).unwrap();
    let ev = rep.rows.iter().find(|r| r.name == "Evidence").unwrap();
    assert_eq!(ev.status, Status::Verified, "{rep}");
    // An authorization by a party the graph does not know is refused.
    let mut stranger = s.body.clone();
    stranger.party = "stranger".into();
    stranger.approvals.clear();
    assert!(g.add_authorization_v2(stranger.sign(&gk).unwrap()).is_err());
    // A governance key only anchors for a party in the graph, and must be
    // an Ed25519 key.
    assert!(g
        .add_governance_keys(&[anchor("stranger", &gk, GovernanceKeyStatus::Active)])
        .is_err());
    let mut bad = anchor("tax-agency", &gk, GovernanceKeyStatus::Active);
    bad.public_key = "zz".into();
    assert!(g.clone().add_governance_keys(&[bad]).is_err());
}

#[test]
fn a_v2_authorization_without_an_anchored_governance_key_is_refused() {
    let gk = key(1);
    let (mut g, _, b) = graph_and_authorization();
    let s = b.sign(&gk).unwrap();
    // The party is in the graph, but no governance key is anchored for it.
    let e = g.add_authorization_v2(s.clone()).unwrap_err();
    assert_eq!(e.code, Code::TrustAuthorization);
    assert!(e.message.contains("governance key"), "{}", e.message);
    // Another key anchored for the party does not make this one known.
    g.add_governance_keys(&[anchor("tax-agency", &key(3), GovernanceKeyStatus::Active)])
        .unwrap();
    assert!(g.add_authorization_v2(s).is_err());
    assert!(g.of(NodeKind::Authorization).next().is_none());
}

#[test]
fn a_substituted_governance_key_is_refused() {
    let (gk, attacker) = (key(1), key(2));
    let (mut g, _, b) = graph_and_authorization();
    g.add_governance_keys(&[anchor("tax-agency", &gk, GovernanceKeyStatus::Active)])
        .unwrap();
    // Signed by the attacker's key, which names itself.
    let forged = b.clone().sign(&attacker).unwrap();
    let e = g.add_authorization_v2(forged.clone()).unwrap_err();
    assert_eq!(e.code, Code::TrustAuthorization);
    // Signed by the attacker, claiming the anchored key.
    let mut claimed = forged;
    claimed.public_key = pk(&gk);
    assert!(g.add_authorization_v2(claimed).is_err());
    // The anchor cannot be replaced: another active key is refused.
    let e = g
        .add_governance_keys(&[anchor("tax-agency", &attacker, GovernanceKeyStatus::Active)])
        .unwrap_err();
    assert!(
        e.message.contains("another governance key"),
        "{}",
        e.message
    );
    assert!(g
        .add_authorization_v2(b.clone().sign(&attacker).unwrap())
        .is_err());
    assert!(g.of(NodeKind::Authorization).next().is_none());
    // The anchored key still verifies.
    g.add_authorization_v2(b.sign(&gk).unwrap()).unwrap();
}

#[test]
fn a_revoked_governance_key_is_refused() {
    let (old, new) = (key(1), key(2));
    let (mut g, _, b) = graph_and_authorization();
    g.add_governance_keys(&[anchor("tax-agency", &old, GovernanceKeyStatus::Active)])
        .unwrap();
    g.add_governance_keys(&[anchor("tax-agency", &old, GovernanceKeyStatus::Revoked)])
        .unwrap();
    let e = g
        .add_authorization_v2(b.clone().sign(&old).unwrap())
        .unwrap_err();
    assert_eq!(e.code, Code::GovernanceKeyRevoked);
    // Revocation is final: anchoring the key as active again does not
    // revive it.
    g.add_governance_keys(&[anchor("tax-agency", &old, GovernanceKeyStatus::Active)])
        .unwrap();
    let e = g
        .add_authorization_v2(b.clone().sign(&old).unwrap())
        .unwrap_err();
    assert_eq!(e.code, Code::GovernanceKeyRevoked);
    // Once the old key is revoked, a new one may be anchored (rotation).
    g.add_governance_keys(&[anchor("tax-agency", &new, GovernanceKeyStatus::Active)])
        .unwrap();
    let id = g.add_authorization_v2(b.sign(&new).unwrap()).unwrap();
    let (_, problems) = g.rebuild();
    assert!(problems.is_empty(), "{problems:?}");
    assert!(g.node(&id).is_some());
}

#[test]
fn a_bundle_with_a_v2_authorization_not_under_its_anchored_key_fails_rebuild() {
    let (gk, attacker) = (key(1), key(2));
    let (mut g, _, b) = graph_and_authorization();
    g.add_governance_keys(&[anchor("tax-agency", &gk, GovernanceKeyStatus::Active)])
        .unwrap();
    let id = g
        .add_authorization_v2(b.clone().sign(&gk).unwrap())
        .unwrap();
    let evidence_fails = |bundle: &TrustGraph| {
        let (_, problems) = bundle.rebuild();
        assert!(
            problems
                .iter()
                .any(|p| p.starts_with(&id) && p.contains("invalid evidence")),
            "{problems:?}"
        );
        let rep = bundle.report(&ReportOptions::default()).unwrap();
        let ev = rep.rows.iter().find(|r| r.name == "Evidence").unwrap();
        assert_eq!(ev.status, Status::Failed, "{rep}");
        assert!(!rep.satisfied);
    };
    // The same body (so the same node ID) re-signed by the attacker.
    let mut swapped = g.clone();
    swapped.nodes.get_mut(&id).unwrap().evidence = Some(Evidence::AuthorizationV2(Box::new(
        b.clone().sign(&attacker).unwrap(),
    )));
    evidence_fails(&swapped);
    // A tampered body under the original signature.
    let mut tampered = g.clone();
    if let Some(Evidence::AuthorizationV2(a)) = &mut tampered.nodes.get_mut(&id).unwrap().evidence {
        a.body.recipients.insert("fraud-unit".into());
    }
    let (_, problems) = tampered.rebuild();
    assert!(
        problems.iter().any(|p| p.contains("invalid evidence")),
        "{problems:?}"
    );
    // The anchor stripped from the bundle: nothing verifies the signature.
    let mut unanchored = g.clone();
    unanchored
        .nodes
        .get_mut("party:tax-agency")
        .unwrap()
        .attrs
        .retain(|k, _| !k.starts_with("governance_key"));
    evidence_fails(&unanchored);
    // The anchored key marked revoked in the bundle.
    let mut revoked = g.clone();
    revoked
        .add_governance_keys(&[anchor("tax-agency", &gk, GovernanceKeyStatus::Revoked)])
        .unwrap();
    evidence_fails(&revoked);
}

const PROGRAM: &str = "encompute 0.1
program eligibility precision 0.001 purpose \"benefits-eligibility\"
party \"tax-agency\" \"Tax Agency\"
asset \"income\" dataset owners [\"tax-agency\"] readers [\"tax-agency\"] purposes [\"benefits-eligibility\"] release allowed_parties
%0 = input \"income\" [0.0, 120.0] asset \"income\" : secret u8
%1 = const [18.0] : public u8
%2 = ge %0, %1 : secret bool
output \"out\" = %2 to \"tax-agency\"
";
