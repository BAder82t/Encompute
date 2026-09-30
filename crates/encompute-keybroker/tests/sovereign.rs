//! Two-part release at an owner's key broker (governed projects): a key
//! leaves only with the owner's signed authorization, verified under the
//! owner's pinned governance key, and a valid, single-use control-plane
//! ticket for the scheduled job. Checks run in a fixed order and refuse at
//! the first failure; each refusal has its own code. Non-governed release
//! is unchanged.

mod common;

use std::collections::BTreeSet;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use common::*;
use encompute_attestation::{GRANT_VERSION, GRANT_VERSION_GOVERNED};
use encompute_ir::Code;
use encompute_keybroker::{
    BrokerMode, DevelopmentFileStore, GovernanceConfig, KeyBroker, LocalKekStore,
};
use encompute_trust::authz::{AuthorizationLimits, RevocationV2};
use encompute_verification::governance::{ProgramRef, ReleaseClass};
use encompute_verification::ticket::TicketKind;

fn code<T>(r: encompute_ir::Result<T>) -> Code {
    match r {
        Ok(_) => panic!("a key was released"),
        Err(e) => e.code,
    }
}

fn tmp(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "encompute-kb-sovereign-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn release_with_active_authorization() {
    let mut w = world();
    let s = w.session();
    let handle = w.attest(&s);
    let ticket = w.ticket();
    let (grant, receipt) = w
        .release(&w.request(&handle, Some(ticket.clone())))
        .unwrap();
    assert_eq!(s.open(&grant).unwrap().as_slice(), KEY);
    // A version 3 grant naming the authorization, project, purpose, window
    // end and ticket.
    assert_eq!(grant.header.version, GRANT_VERSION_GOVERNED);
    let g = grant.header.governance.as_ref().unwrap();
    assert_eq!(g.authorization_id, w.authorization_id());
    assert_eq!(g.project, PROJECT);
    assert_eq!(g.purpose_id, h('1'));
    assert_eq!(g.valid_until, T0 + 3600);
    assert_eq!(g.ticket_id.as_deref(), Some(ticket.ticket_id.as_str()));
    assert!(grant.header.expires_at <= T0 + 3600);
    // The receipt is signed with the grant key, binds the grant, and never
    // carries the key.
    receipt.verify(&w.broker.grant_public_key()).unwrap();
    assert_eq!(receipt.grant_digest, grant.digest().unwrap());
    assert_eq!(receipt.authorization_id, w.authorization_id());
    assert_eq!(
        receipt.ticket_id.as_deref(),
        Some(ticket.ticket_id.as_str())
    );
    assert_eq!(receipt.job_id.as_deref(), Some("job_1"));
    assert_eq!(receipt.asset_version_id, asset_version());
    assert_eq!(receipt.organization, ORG);
    let text = serde_json::to_string(&receipt).unwrap();
    assert!(!text.contains(&hex_of(KEY)));
    let mut forged = receipt.clone();
    forged.job_id = Some("job_2".into());
    assert!(forged.verify(&w.broker.grant_public_key()).is_err());
    // The release is counted.
    let c = &w.broker.state().counters[&w.authorization_id()];
    assert_eq!(c.releases, 1);
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn ticket_without_local_authorization_refused() {
    let clock = Arc::new(AtomicU64::new(T0));
    let spec = spec_for(&binding());
    let mut b = bare_broker(&clock, &spec)
        .with_governance(governance())
        .unwrap();
    b.bind_version(ASSET, &asset_version()).unwrap();
    b.pin_governance_key(&governance_public_key()).unwrap();
    // The same world, but nothing installed.
    let mut w = World {
        broker: b,
        clock,
        evaluator: encompute_verification::EvaluatorSigner::from_seed(&[9; 32]),
        binding: binding(),
        spec,
        authorization: signed(authorization()),
    };
    let s = w.session();
    let handle = w.attest(&s);
    let req = w.request(&handle, Some(w.ticket()));
    assert_eq!(code(w.release(&req)), Code::GovernanceAuthorizationMissing);
    // Another installed authorization does not stand in for it.
    let mut other = authorization();
    other.nonce = "cd".repeat(16);
    w.broker.install_authorization(&signed(other)).unwrap();
    assert_eq!(code(w.release(&req)), Code::GovernanceAuthorizationMissing);
}

#[test]
fn forged_ticket_refused() {
    let mut w = world();
    let s = w.session();
    let handle = w.attest(&s);
    // Signed, then edited: another job, a longer window, another spec ID.
    for edit in [
        &(|t: &mut encompute_verification::ticket::ReleaseTicket| t.job_id = "job_2".into())
            as &dyn Fn(&mut encompute_verification::ticket::ReleaseTicket),
        &|t| t.not_after += 1,
        &|t| t.anchor_counter += 1,
        &|t| t.signature = "00".repeat(64),
    ] {
        let mut t = w.ticket();
        edit(&mut t);
        let req = w.request(&handle, Some(t));
        assert_eq!(code(w.release(&req)), Code::GovernanceReleaseTicket);
    }
    // No ticket at all, where tickets are required.
    let req = w.request(&handle, None);
    assert_eq!(code(w.release(&req)), Code::GovernanceReleaseTicket);
}

#[test]
fn unpinned_ticket_signer_refused() {
    let mut w = world();
    let s = w.session();
    let handle = w.attest(&s);
    let rogue =
        encompute_verification::ServiceSigner::from_seed("control-plane", &[43; 32]).unwrap();
    let t = w.ticket_body().sign(&rogue).unwrap();
    let req = w.request(&handle, Some(t));
    assert_eq!(code(w.release(&req)), Code::GovernanceReleaseTicket);
    // A governed broker with no control-plane key configured accepts no
    // ticket at all.
    let clock = Arc::new(AtomicU64::new(T0));
    let spec = spec_for(&binding());
    let mut b = bare_broker(&clock, &spec);
    b.bind_version(ASSET, &asset_version()).unwrap();
    b.pin_governance_key(&governance_public_key()).unwrap();
    b.install_authorization(&w.authorization).unwrap();
    let mut w2 = World {
        broker: b,
        clock,
        evaluator: encompute_verification::EvaluatorSigner::from_seed(&[9; 32]),
        binding: binding(),
        spec,
        authorization: w.authorization.clone(),
    };
    let s = w2.session();
    let handle = w2.attest(&s);
    let req = w2.request(&handle, Some(w2.ticket()));
    assert_eq!(code(w2.release(&req)), Code::GovernanceReleaseTicket);
}

#[test]
fn replayed_ticket_refused() {
    let mut w = world();
    let ticket = w.ticket();
    let s = w.session();
    let handle = w.attest(&s);
    w.release(&w.request(&handle, Some(ticket.clone())))
        .unwrap();
    // Again, in a fresh session of the same workload.
    let s2 = w.session();
    let handle = w.attest(&s2);
    assert_eq!(
        code(w.release(&w.request(&handle, Some(ticket.clone())))),
        Code::GovernanceReleaseTicket
    );
    // After a restart: seen tickets are part of the authenticated state.
    let dir = tmp("replay");
    let path = dir.join("broker.json");
    w.broker.save(&path).unwrap();
    let c = w.clock.clone();
    w.broker = KeyBroker::load(&path, verifier(), Box::new(DevelopmentFileStore))
        .unwrap()
        .with_clock(move || c.load(std::sync::atomic::Ordering::SeqCst))
        .with_governance(governance())
        .unwrap();
    let s3 = w.session();
    let handle = w.attest(&s3);
    assert_eq!(
        code(w.release(&w.request(&handle, Some(ticket)))),
        Code::GovernanceReleaseTicket
    );
    // A fresh ticket works.
    w.release_fresh().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn expired_ticket_refused_with_skew_toward_denial() {
    let mut w = world();
    let ticket = w.ticket(); // [T0, T0 + 300)
    let s = w.session();
    // Within the last 60 seconds of the window: refused.
    w.set_now(T0 + 240);
    let handle = w.attest(&s);
    assert_eq!(
        code(w.release(&w.request(&handle, Some(ticket.clone())))),
        Code::GovernanceReleaseTicket
    );
    // Not valid yet.
    w.set_now(T0 - 1);
    let handle = w.attest(&s);
    assert_eq!(
        code(w.release(&w.request(&handle, Some(ticket.clone())))),
        Code::GovernanceReleaseTicket
    );
    // The last second allowed. A refused ticket was not consumed.
    w.set_now(T0 + 239);
    let handle = w.attest(&s);
    w.release(&w.request(&handle, Some(ticket))).unwrap();
}

#[test]
fn ticket_for_other_org_refused() {
    let mut w = world();
    let s = w.session();
    let handle = w.attest(&s);
    // For another broker.
    let mut t = w.ticket_body();
    t.broker = "benefits-broker".into();
    let req = w.request(&handle, Some(t.sign(&control()).unwrap()));
    assert_eq!(code(w.release(&req)), Code::GovernanceReleaseTicket);
    // For another organization (its source is not this organization's).
    let mut t = w.ticket_body();
    t.organization = "benefits-agency".into();
    let req = w.request(&handle, Some(t.sign(&control()).unwrap()));
    assert_eq!(code(w.release(&req)), Code::GovernanceReleaseTicket);
}

#[test]
fn ticket_for_other_job_or_spec_refused() {
    let mut w = world();
    let s = w.session();
    let handle = w.attest(&s);
    // Issued to another evaluator.
    let mut t = w.ticket_body();
    t.workload_or_recipient = h('7');
    let req = w.request(&handle, Some(t.sign(&control()).unwrap()));
    assert_eq!(code(w.release(&req)), Code::GovernanceReleaseTicket);
    // For another execution spec (a consistent ticket, but not the spec
    // the workload attested).
    let mut t = w.ticket_body();
    t.execution_spec.backend_version = "1.5.2".into();
    t.execution_spec_id = t.execution_spec.id().hex();
    let req = w.request(&handle, Some(t.sign(&control()).unwrap()));
    assert_eq!(code(w.release(&req)), Code::GovernanceReleaseTicket);
    // Not naming the authorization the request is under.
    let mut t = w.ticket_body();
    t.authorization_ids = BTreeSet::from([h('5')]);
    let req = w.request(&handle, Some(t.sign(&control()).unwrap()));
    assert_eq!(code(w.release(&req)), Code::GovernanceReleaseTicket);
    // A decryption or export ticket is not a key-release ticket.
    for kind in [TicketKind::Decrypt, TicketKind::Export] {
        let mut t = w.ticket_body();
        t.kind = kind;
        let req = w.request(&handle, Some(t.sign(&control()).unwrap()));
        assert_eq!(code(w.release(&req)), Code::GovernanceReleaseTicket);
    }
    // The honest ticket still works (none of the above was consumed).
    w.release(&w.request(&handle, Some(w.ticket()))).unwrap();
}

#[test]
fn authorization_from_unpinned_governance_key_refused() {
    let clock = Arc::new(AtomicU64::new(T0));
    let spec = spec_for(&binding());
    let mut b = bare_broker(&clock, &spec);
    b.bind_version(ASSET, &asset_version()).unwrap();
    // No governance key pinned yet: nothing installs.
    let e = b
        .install_authorization(&signed(authorization()))
        .unwrap_err();
    assert_eq!(e.code, Code::GovernanceKeyRevoked, "{e}");
    b.pin_governance_key(&governance_public_key()).unwrap();
    // Signed by another key.
    let forged = authorization().sign(&rogue_governance_key()).unwrap();
    let e = b.install_authorization(&forged).unwrap_err();
    assert_eq!(e.code, Code::GovernanceKeyRevoked, "{e}");
    // Signed by another key but naming the pinned one.
    let mut forged = forged;
    forged.public_key = governance_public_key();
    let e = b.install_authorization(&forged).unwrap_err();
    assert_eq!(e.code, Code::GovernanceKeyRevoked, "{e}");
    // Edited after signing.
    let mut edited = signed(authorization());
    edited.body.valid_until += 3600;
    let e = b.install_authorization(&edited).unwrap_err();
    assert_eq!(e.code, Code::GovernanceKeyRevoked, "{e}");
    // Another organization's authorization, even if this key signed it.
    let mut other = authorization();
    other.party = "benefits-agency".into();
    let e = b.install_authorization(&signed(other)).unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationMissing, "{e}");
    assert!(b.state().authorizations.is_empty());
    // The pin is set once.
    let other_key = encompute_verification::hex(&rogue_governance_key().verifying_key().to_bytes());
    assert!(b.pin_governance_key(&other_key).is_err());
    b.pin_governance_key(&governance_public_key()).unwrap();
    b.install_authorization(&signed(authorization())).unwrap();
}

#[test]
fn ticket_refused_after_owner_revokes_locally_even_if_control_offline() {
    // Local revocation by the owner (no control plane involved).
    let mut w = world();
    w.release_fresh().unwrap();
    let id = w.authorization_id();
    w.broker.revoke_authorization_local(&id, None).unwrap();
    assert_eq!(
        code(w.release_fresh()),
        Code::GovernanceAuthorizationRevoked
    );
    // Reinstalling a revoked authorization does not revive it.
    let e = w
        .broker
        .install_authorization(&w.authorization.clone())
        .unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationRevoked, "{e}");
    assert_eq!(
        code(w.release_fresh()),
        Code::GovernanceAuthorizationRevoked
    );

    // An owner-signed revocation, verified under the pinned key.
    let mut w = world();
    let r = RevocationV2 {
        version: 2,
        party: ORG.into(),
        authorization: w.authorization_id(),
        reason: "withdrawn".into(),
        issued_at: T0,
    };
    let forged = r.clone().sign(&rogue_governance_key()).unwrap();
    assert!(w.broker.revoke_authorization_signed(&forged).is_err());
    w.release_fresh().unwrap();
    w.broker
        .revoke_authorization_signed(&r.sign(&governance_key()).unwrap())
        .unwrap();
    assert_eq!(
        code(w.release_fresh()),
        Code::GovernanceAuthorizationRevoked
    );
}

#[test]
fn expiry_at_valid_until_boundary_refused() {
    let mut w = world();
    let until = T0 + 3600;
    w.set_now(until - 1);
    w.release_fresh().unwrap();
    w.set_now(until);
    assert_eq!(
        code(w.release_fresh()),
        Code::GovernanceAuthorizationExpired
    );
    // Not valid yet.
    w.set_now(T0 - 101);
    assert_eq!(
        code(w.release_fresh()),
        Code::GovernanceAuthorizationExpired
    );
    // The grant never outlives the authorization.
    w.set_now(until - 10);
    let (g, _) = w.release_fresh().unwrap();
    assert!(g.header.expires_at <= until, "{}", g.header.expires_at);
}

#[test]
fn attestation_issued_after_valid_until_refused() {
    let mut w = world();
    let until = T0 + 3600;
    w.set_now(until - 30);
    let s = w.session();
    // Evidence dated after the window's end (inside the attestation clock
    // skew, so the session opens).
    let e = w.evidence_at(&s, until + 10);
    let info = w.broker.verify_attestation(&e).unwrap();
    let req = w.request(&info.session, Some(w.ticket()));
    assert_eq!(code(w.release(&req)), Code::GovernanceAuthorizationExpired);
}

#[test]
fn program_policy_linkage_not_covered_refused() {
    type Edit = Box<dyn Fn(&mut encompute_trust::authz::AuthorizationV2)>;
    let cases: Vec<(&str, Edit, Code)> = vec![
        (
            "another program",
            Box::new(|a| a.program = ProgramRef::Program { program_id: h('9') }),
            Code::GovernanceProgramNotAuthorized,
        ),
        (
            "another policy",
            Box::new(|a| a.policy_id = h('9')),
            Code::GovernanceProgramNotAuthorized,
        ),
        (
            "another privacy policy",
            Box::new(|a| a.privacy_policy_id = Some(h('9'))),
            Code::GovernanceProgramNotAuthorized,
        ),
        (
            "pinned to other specs",
            Box::new(|a| a.execution_spec_ids = Some(BTreeSet::from([h('9')]))),
            Code::GovernanceProgramNotAuthorized,
        ),
        (
            "another linkage policy",
            Box::new(|a| a.linkage_policy_id = Some(h('9'))),
            Code::GovernanceLinkageMismatch,
        ),
        (
            "another purpose",
            Box::new(|a| a.purpose_id = h('9')),
            Code::GovernancePurposeMismatch,
        ),
        (
            "another project",
            Box::new(|a| a.project = "prj_2".into()),
            Code::GovernancePurposeMismatch,
        ),
        (
            "another version",
            Box::new(|a| a.asset_version_id = h('8')),
            Code::GovernanceAssetVersionMismatch,
        ),
        (
            "another digest commitment",
            Box::new(|a| a.asset_digest_commitment = h('8')),
            Code::GovernanceAssetVersionMismatch,
        ),
        (
            "a narrower release class",
            Box::new(|a| a.release_class = ReleaseClass::AggregateOnly),
            Code::GovernanceReleaseClass,
        ),
        (
            "other recipients",
            Box::new(|a| a.recipients = BTreeSet::from(["police".into()])),
            Code::GovernanceReleaseClass,
        ),
    ];
    for (what, edit, expected) in cases {
        let mut a = authorization();
        edit(&mut a);
        let mut w = world_with(binding(), a);
        assert_eq!(code(w.release_fresh()), expected, "{what}");
    }
    // A program set that includes the program covers it.
    let mut a = authorization();
    let programs = BTreeSet::from([h('a'), h('9')]);
    a.program = ProgramRef::ProgramSet {
        program_set_id: encompute_verification::governance::ProgramSetId::of(programs.clone())
            .unwrap()
            .hex(),
        programs,
    };
    world_with(binding(), a).release_fresh().unwrap();
    // A pin that names this spec covers it.
    let mut a = authorization();
    a.execution_spec_ids = Some(BTreeSet::from([spec_for(&binding()).id().hex()]));
    world_with(binding(), a).release_fresh().unwrap();
}

#[test]
fn max_releases_exhausted_refused() {
    let mut a = authorization();
    a.limits = AuthorizationLimits {
        max_releases: Some(2),
        max_executions: Some(1000),
        ..Default::default()
    };
    let mut w = world_with(binding(), a);
    w.release_fresh().unwrap();
    // Counted and recorded when prepared, before any grant exists.
    let s = w.session();
    let handle = w.attest(&s);
    let req = w.request(&handle, Some(w.ticket()));
    let pending = w.broker.prepare_governed_release(&req).unwrap();
    assert_eq!(w.broker.state().counters[&w.authorization_id()].releases, 2);
    assert!(w
        .broker
        .state()
        .seen_tickets
        .contains_key(&req.ticket.as_ref().unwrap().ticket_id));
    // The pending release is dropped (as when persisting fails): no grant,
    // and the release stays counted.
    drop(pending);
    let e = w.release_fresh().unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationLimit, "{e}");
    assert_eq!(e.code.as_str(), "ENC2714");
}

#[test]
fn max_executions_counts_jobs() {
    let mut a = authorization();
    a.limits = AuthorizationLimits {
        max_executions: Some(1),
        max_releases: Some(1000),
        ..Default::default()
    };
    let mut w = world_with(binding(), a);
    w.release_fresh().unwrap();
    // The same job again (a retry) is within the limit.
    w.release_fresh().unwrap();
    // Another job is not.
    let s = w.session();
    let handle = w.attest(&s);
    let mut t = w.ticket_body();
    t.job_id = "job_2".into();
    let req = w.request(&handle, Some(t.sign(&control()).unwrap()));
    assert_eq!(code(w.release(&req)), Code::GovernanceAuthorizationLimit);
}

#[test]
fn declared_placement_refused() {
    let mut b = binding();
    b.placement_digest = Some(h('5'));
    let mut w = world_with(b, authorization());
    assert_eq!(code(w.release_fresh()), Code::GovernanceResidency);
}

/// The development escape (no ticket) exists only for a development broker
/// in an environment that says, explicitly, that it is development; an
/// authorization is still required.
#[test]
fn dev_escape_refused_in_production() {
    let no_ticket = GovernanceConfig {
        control_key: control().public_key_hex(),
        require_ticket: false,
    };
    // Only this test reads or sets ENCOMPUTE_ENV in this binary.
    std::env::remove_var("ENCOMPUTE_ENV");
    let clock = Arc::new(AtomicU64::new(T0));
    let spec = spec_for(&binding());
    let e = bare_broker(&clock, &spec)
        .with_governance(no_ticket.clone())
        .err()
        .unwrap();
    assert_eq!(e.code, Code::InsecureConfiguration, "{e}");
    assert_eq!(e.code.as_str(), "ENC2605");
    std::env::set_var("ENCOMPUTE_ENV", "production");
    let e = bare_broker(&clock, &spec)
        .with_governance(no_ticket.clone())
        .err()
        .unwrap();
    assert_eq!(e.code, Code::InsecureConfiguration, "{e}");
    // A production broker refuses it whatever the environment says.
    std::env::set_var("ENCOMPUTE_ENV", "development");
    let prod = KeyBroker::new(
        BROKER,
        BrokerMode::Production,
        verifier(),
        Box::new(LocalKekStore::from_key([5; 32])),
    )
    .unwrap();
    let e = prod.with_governance(no_ticket.clone()).err().unwrap();
    assert_eq!(e.code, Code::InsecureConfiguration, "{e}");
    // Development broker, development environment: no ticket needed, but
    // the workload names the attested spec and binding, and the
    // authorization is still checked.
    let mut b = bare_broker(&clock, &spec)
        .with_governance(no_ticket)
        .unwrap();
    std::env::remove_var("ENCOMPUTE_ENV");
    b.bind_version(ASSET, &asset_version()).unwrap();
    b.pin_governance_key(&governance_public_key()).unwrap();
    let mut w = World {
        broker: b,
        clock,
        evaluator: encompute_verification::EvaluatorSigner::from_seed(&[9; 32]),
        binding: binding(),
        spec: spec.clone(),
        authorization: signed(authorization()),
    };
    let s = w.session();
    let handle = w.attest(&s);
    let mut req = w.request(&handle, None);
    req.execution_spec = Some(spec.clone());
    req.binding = Some(binding());
    assert_eq!(code(w.release(&req)), Code::GovernanceAuthorizationMissing);
    w.broker
        .install_authorization(&w.authorization.clone())
        .unwrap();
    let (g, r) = w.release(&req).unwrap();
    assert_eq!(s.open(&g).unwrap().as_slice(), KEY);
    assert_eq!(g.header.governance.as_ref().unwrap().ticket_id, None);
    assert_eq!(r.ticket_id, None);
    // Without the facts, nothing to check coverage against: refused.
    let handle = w.attest(&s);
    let req = w.request(&handle, None);
    assert_eq!(code(w.release(&req)), Code::GovernanceReleaseTicket);
    // Facts that are not the attested execution are refused.
    let handle = w.attest(&s);
    let mut req = w.request(&handle, None);
    let mut other = spec;
    other.backend_version = "1.5.2".into();
    req.execution_spec = Some(other);
    req.binding = Some(binding());
    assert_eq!(code(w.release(&req)), Code::GovernanceProgramNotAuthorized);
}

#[test]
fn ungoverned_secret_refused_on_governed_broker() {
    // A governed broker (governance key pinned) with an unbound secret.
    let clock = Arc::new(AtomicU64::new(T0));
    let spec = spec_for(&binding());
    let mut b = bare_broker(&clock, &spec)
        .with_governance(governance())
        .unwrap();
    b.pin_governance_key(&governance_public_key()).unwrap();
    b.install_authorization(&signed(authorization())).unwrap();
    let mut w = World {
        broker: b,
        clock,
        evaluator: encompute_verification::EvaluatorSigner::from_seed(&[9; 32]),
        binding: binding(),
        spec,
        authorization: signed(authorization()),
    };
    let s = w.session();
    let handle = w.attest(&s);
    // The 0.3 path refuses it (default deny)...
    let e = w.broker.release_key(&handle, ASSET).unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationMissing, "{e}");
    // ...and the governed path needs its version bound.
    let req = w.request(&handle, Some(w.ticket()));
    assert_eq!(code(w.release(&req)), Code::GovernanceAssetVersionMismatch);
    // Bound, it is released on the governed path only.
    w.broker.bind_version(ASSET, &asset_version()).unwrap();
    let e = w.broker.release_key(&handle, ASSET).unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationMissing, "{e}");
    w.release(&w.request(&handle, Some(w.ticket()))).unwrap();
}

#[test]
fn a_bound_version_is_immutable() {
    let clock = Arc::new(AtomicU64::new(T0));
    let mut b = bare_broker(&clock, &spec_for(&binding()));
    assert!(b.bind_version(ASSET, "not-hex").is_err());
    assert!(b.bind_version("missing", &asset_version()).is_err());
    b.bind_version(ASSET, &asset_version()).unwrap();
    b.bind_version(ASSET, &asset_version()).unwrap();
    let e = b.bind_version(ASSET, &h('8')).unwrap_err();
    assert_eq!(e.code, Code::GovernanceAssetVersionMismatch, "{e}");
    // A bound secret is governed: the 0.3 path never releases it, even
    // before a governance key is pinned.
    let mut w = World {
        broker: b,
        clock,
        evaluator: encompute_verification::EvaluatorSigner::from_seed(&[9; 32]),
        binding: binding(),
        spec: spec_for(&binding()),
        authorization: signed(authorization()),
    };
    let s = w.session();
    let handle = w.attest(&s);
    let e = w.broker.release_key(&handle, ASSET).unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationMissing, "{e}");
}

#[test]
fn an_expired_asset_is_never_released() {
    let mut w = world();
    w.release_fresh().unwrap();
    w.broker.expire_for(ORG, ASSET).unwrap();
    assert_eq!(code(w.release_fresh()), Code::KeyRelease);
    // Another organization's expiry never touches this broker's keys.
    let mut w = world();
    assert!(w.broker.expire_for("benefits-agency", ASSET).is_err());
    w.release_fresh().unwrap();
}

#[test]
fn governed_state_is_authenticated() {
    // Counters, seen tickets and local revocations are under the state MAC:
    // an edited state file does not open.
    let clock = Arc::new(AtomicU64::new(T0));
    let spec = spec_for(&binding());
    let c = clock.clone();
    let mut b = KeyBroker::new(
        BROKER,
        BrokerMode::Development,
        verifier(),
        Box::new(LocalKekStore::from_key([5; 32])),
    )
    .unwrap()
    .with_clock(move || c.load(std::sync::atomic::Ordering::SeqCst));
    b.set_organization(ORG).unwrap();
    b.add_secret(ASSET, None, release_policy(&spec)).unwrap();
    b.bind_version(ASSET, &asset_version()).unwrap();
    b.pin_governance_key(&governance_public_key()).unwrap();
    b.install_authorization(&signed(authorization())).unwrap();
    let id = signed(authorization()).id();
    b.revoke_authorization_local(&id, Some(T0 + 10)).unwrap();
    let dir = tmp("mac");
    let path = dir.join("broker.json");
    b.save(&path).unwrap();
    let kek = || Box::new(LocalKekStore::from_key([5; 32]));
    KeyBroker::load(&path, verifier(), kek()).unwrap();
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for (what, edit) in [
        (
            "revocation cleared",
            &(|v: &mut serde_json::Value| {
                v["revoked_authorizations"] = serde_json::json!({});
            }) as &dyn Fn(&mut serde_json::Value),
        ),
        ("revocation delayed", &|v| {
            v["revoked_authorizations"][id.as_str()] = (T0 + 1_000_000).into();
        }),
        ("key unpinned", &|v| {
            v.as_object_mut().unwrap().remove("governance_key");
        }),
        ("version unbound", &|v| {
            v["secrets"][ASSET]
                .as_object_mut()
                .unwrap()
                .remove("asset_version_id");
        }),
    ] {
        let mut v = original.clone();
        edit(&mut v);
        std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
        assert!(KeyBroker::load(&path, verifier(), kek()).is_err(), "{what}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A broker state written by 0.3.0 (governance did not exist) opens, its
/// MAC verifies, and it serializes to the same bytes: states without
/// governance data are unchanged.
#[test]
fn v1_broker_state_bytes_and_mac_unchanged() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/broker-state-0.3.json");
    let bytes = std::fs::read(&path).unwrap();
    let b = KeyBroker::load(
        &path,
        verifier(),
        Box::new(LocalKekStore::from_key([5; 32])),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_string_pretty(b.state()).unwrap(),
        String::from_utf8(bytes).unwrap().trim_end()
    );
    assert_eq!(
        b.state().mac.as_deref(),
        Some("d17ff0764bede4825b3dbace4a9e8709e2583553968d077cc0c8c836510e2d6f")
    );
    assert!(b.state().governance_key.is_none());
}

#[test]
fn v1_broker_release_unchanged() {
    // A broker without governance releases version 2 grants, as in 0.3.
    let clock = Arc::new(AtomicU64::new(T0));
    let spec = spec_for(&binding());
    let mut w = World {
        broker: bare_broker(&clock, &spec),
        clock,
        evaluator: encompute_verification::EvaluatorSigner::from_seed(&[9; 32]),
        binding: binding(),
        spec,
        authorization: signed(authorization()),
    };
    let s = w.session();
    let handle = w.attest(&s);
    let g = w.broker.release_key(&handle, ASSET).unwrap();
    assert_eq!(g.header.version, GRANT_VERSION);
    assert!(g.header.governance.is_none());
    assert!(!serde_json::to_string(&g).unwrap().contains("governance"));
    assert_eq!(s.open(&g).unwrap().as_slice(), KEY);
}

/// Revocations the owner or operator records for authorizations not
/// (yet) installed are kept, so a later install is refused, but only up to
/// a cap: past it, new ones are refused and none already recorded is
/// dropped.
#[test]
fn revoked_authorizations_are_bounded() {
    use encompute_keybroker::MAX_REVOKED_AUTHORIZATIONS;
    let mut w = world();
    let id = |n: usize| format!("{n:064x}");
    for n in 0..MAX_REVOKED_AUTHORIZATIONS {
        w.broker
            .revoke_authorization_local(&id(n), Some(T0))
            .unwrap();
    }
    let e = w
        .broker
        .revoke_authorization_local(&id(MAX_REVOKED_AUTHORIZATIONS), Some(T0))
        .unwrap_err();
    assert_eq!(e.code, Code::KeyRelease, "{e}");
    assert!(e.message.contains("revoked"), "{e}");
    assert_eq!(
        w.broker.state().revoked_authorizations.len(),
        MAX_REVOKED_AUTHORIZATIONS
    );
    assert!(w.broker.state().revoked_authorizations.contains_key(&id(0)));
    // An already recorded one can still be moved earlier (no new entry).
    w.broker
        .revoke_authorization_local(&id(0), Some(T0 - 5))
        .unwrap();
    assert_eq!(w.broker.state().revoked_authorizations[&id(0)], T0 - 5);
}

#[test]
fn install_of_revoked_authorization_refused() {
    // The owner revokes (signed) an authorization before it reaches this
    // broker: it is never installed afterwards.
    let clock = Arc::new(AtomicU64::new(T0));
    let spec = spec_for(&binding());
    let mut b = bare_broker(&clock, &spec);
    b.pin_governance_key(&governance_public_key()).unwrap();
    let a = signed(authorization());
    let r = RevocationV2 {
        version: 2,
        party: ORG.into(),
        authorization: a.id(),
        reason: "withdrawn".into(),
        issued_at: T0,
    };
    b.revoke_authorization_signed(&r.sign(&governance_key()).unwrap())
        .unwrap();
    let e = b.install_authorization(&a).unwrap_err();
    assert_eq!(e.code, Code::GovernanceAuthorizationRevoked, "{e}");
    assert!(b.state().authorizations.is_empty());
}

/// A ticket's contents are used only after its signature by the pinned
/// control plane verifies: a forged ticket gets the ticket error, never a
/// coverage verdict (no oracle for unsigned tickets).
#[test]
fn unsigned_ticket_refused_before_coverage_checks() {
    // The authorization is for another purpose, so coverage would refuse
    // with ENC2702.
    let mut a = authorization();
    a.purpose_id = h('9');
    let mut w = world_with(binding(), a);
    let s = w.session();
    let handle = w.attest(&s);
    let rogue =
        encompute_verification::ServiceSigner::from_seed("control-plane", &[43; 32]).unwrap();
    for forged in [
        w.ticket_body().sign(&rogue).unwrap(),
        {
            let mut t = w.ticket();
            t.signature = "00".repeat(64);
            t
        },
        {
            let mut t = w.ticket();
            t.job_id = "job_2".into();
            t
        },
    ] {
        let req = w.request(&handle, Some(forged));
        assert_eq!(code(w.release(&req)), Code::GovernanceReleaseTicket);
    }
    // Signed honestly, the same request reaches coverage.
    let req = w.request(&handle, Some(w.ticket()));
    assert_eq!(code(w.release(&req)), Code::GovernancePurposeMismatch);
}

/// The governance binding's per-asset broker map is checked by the broker
/// itself: a release of a key the binding maps to another broker, or does
/// not map at all, is refused, whatever the ticket says; a binding mapping
/// it to this broker releases as before.
#[test]
fn governed_broker_refuses_asset_bound_to_another_broker() {
    let with = |map: &[(&String, &str)]| {
        let mut b = binding();
        b.asset_brokers = map
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        world_with(b, authorization())
    };
    let v = asset_version();
    let e = with(&[(&v, "benefits-broker")])
        .release_fresh()
        .unwrap_err();
    assert_eq!(e.code, Code::GovernanceCustody, "{e}");
    assert!(e.message.contains("benefits-broker"), "{e}");
    // Mapped under another version: this key's version is left out.
    let e = with(&[(&h('9'), BROKER)]).release_fresh().unwrap_err();
    assert_eq!(e.code, Code::GovernanceCustody, "{e}");
    with(&[(&v, BROKER), (&h('9'), "benefits-broker")])
        .release_fresh()
        .unwrap();
    // No map: unchanged.
    world_with(binding(), authorization())
        .release_fresh()
        .unwrap();
}

/// The key broker decides an output's release class against the owner's
/// ceiling with the owners' release-class order, exhaustively, and with
/// the very function the control plane uses at submission
/// (`governance::release_within`): the two never disagree, and neither
/// keeps an exact-match copy of its own.
#[test]
fn broker_and_control_plane_use_the_same_class_order() {
    use encompute_verification::governance::release_within;
    for requested in ReleaseClass::ALL {
        for ceiling in ReleaseClass::ALL {
            let mut b = binding();
            for o in b.outputs.values_mut() {
                o.release_class = requested;
                // Never released means released to nobody.
                if requested == ReleaseClass::Never {
                    o.recipients.clear();
                }
            }
            let mut a = authorization();
            a.release_class = ceiling;
            let mut w = world_with(b, a);
            let released = w.release_fresh();
            let expected = release_within(requested, ceiling);
            assert_eq!(
                released.is_ok(),
                expected,
                "{} under {}: {:?}",
                requested.as_str(),
                ceiling.as_str(),
                released.err()
            );
            if !expected {
                assert_eq!(code(released), Code::GovernanceReleaseClass);
            }
        }
    }
    // One shared function: both call it, and neither compares classes
    // itself.
    let broker = include_str!("../src/governed.rs");
    let control = include_str!("../../encompute-control/src/ops/jobs.rs");
    for (who, src) in [("broker", broker), ("control plane", control)] {
        assert!(src.contains("release_within(o.release_class,"), "{who}");
        assert!(
            !src.contains("o.release_class == "),
            "{who} compares classes itself"
        );
    }
}

/// Probing controls at the broker (fail closed, the control plane's own
/// check): a boolean-only authorization without max_executions and
/// max_releases is never installed, and one job releases at most
/// max_outputs_per_job boolean-only outputs (one when absent).
#[test]
fn broker_enforces_probing_limits() {
    let mut w = world();
    for (e, r) in [(None, Some(5)), (Some(5), None), (None, None)] {
        let mut a = authorization();
        a.nonce = "cd".repeat(16);
        a.limits.max_executions = e;
        a.limits.max_releases = r;
        assert_eq!(
            code(w.broker.install_authorization(&signed(a))),
            Code::GovernanceReleaseClass
        );
    }
    w.release_fresh().unwrap();
    // Two boolean-only outputs in one execution.
    let mut two = binding();
    let o = two.outputs["eligible"].clone();
    two.outputs.insert("eligible-too".into(), o);
    let mut w = world_with(two.clone(), authorization());
    assert_eq!(code(w.release_fresh()), Code::GovernanceReleaseClass);
    let mut a = authorization();
    a.limits.max_outputs_per_job = Some(2);
    let mut w = world_with(two, a);
    w.release_fresh().unwrap();
}
