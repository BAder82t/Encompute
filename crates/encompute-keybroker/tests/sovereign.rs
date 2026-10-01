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
        require_ticket: false,
        ..GovernanceConfig::new(&control().public_key_hex())
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

// --- exports of derived results (the custodian's broker) --------------------------

const RESULT: &str = "eligibility-result";
/// Another organization whose data the result derives from.
const LINEAGE: &str = "statistics-agency";

fn lineage_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[23; 32])
}

fn lineage_pk() -> String {
    encompute_verification::hex(&lineage_key().verifying_key().to_bytes())
}

/// The control plane's attestation of `org`'s governance key `public_key`
/// (active, or revoked at `revoked_at`), issued at `issued_at`, signed by
/// `signer`.
fn attestation_by(
    signer: &encompute_verification::ServiceSigner,
    org: &str,
    public_key: &str,
    revoked_at: Option<u64>,
    issued_at: u64,
) -> encompute_trust::authz::SignedGovernanceKeyAttestation {
    encompute_trust::authz::GovernanceKeyAttestation {
        version: 1,
        organization: org.into(),
        key_id: encompute_trust::authz::governance_key_id(public_key),
        public_key: public_key.into(),
        status: if revoked_at.is_some() {
            encompute_trust::authz::GovernanceKeyStatus::Revoked
        } else {
            encompute_trust::authz::GovernanceKeyStatus::Active
        },
        revoked_at,
        issued_at,
    }
    .sign(signer)
    .unwrap()
}

/// The control plane's attestation of `LINEAGE`'s active key `public_key`.
fn attested(
    public_key: &str,
    issued_at: u64,
) -> encompute_trust::authz::SignedGovernanceKeyAttestation {
    attestation_by(&control(), LINEAGE, public_key, None, issued_at)
}

/// The control plane's co-signature of `record`, bound as `key_ref` at the
/// world's broker.
fn cosigned(
    record: &encompute_trust::authz::SignedReleaseRecord,
    key_ref: &str,
) -> encompute_trust::authz::SignedDerivedReleaseCosignature {
    cosigned_by(&control(), record, key_ref)
}

fn cosigned_by(
    signer: &encompute_verification::ServiceSigner,
    record: &encompute_trust::authz::SignedReleaseRecord,
    key_ref: &str,
) -> encompute_trust::authz::SignedDerivedReleaseCosignature {
    encompute_trust::authz::DerivedReleaseCosignature {
        version: 1,
        organization: record.body.party.clone(),
        asset_id: "ast_derived".into(),
        broker: BROKER.into(),
        key_ref: key_ref.into(),
        derived_version_id: record.body.derived_version_id.clone(),
        release_record_id: record.id(),
        lineage_owners: record.body.lineage_owners.clone(),
        issued_at: T0,
    }
    .sign(signer)
    .unwrap()
}

/// The lineage owner's authorization of the parent version (the world's
/// source), signed with its own key.
fn lineage_authorization(
    edit: impl FnOnce(&mut encompute_trust::authz::AuthorizationV2),
) -> encompute_trust::authz::SignedAuthorizationV2 {
    let mut a = authorization();
    a.party = LINEAGE.into();
    a.nonce = "ef".repeat(16);
    edit(&mut a);
    a.sign(&lineage_key()).unwrap()
}
const RESULT_KEY: &[u8] = b"derived result key, 32 bytes...";
const RECIPIENT: &str = "benefits-agency";

fn derived_version() -> String {
    h('e')
}

/// The custodian's broker (this world's organization) holding a derived
/// result's key, the custodian's signed release record of it naming one
/// recipient under its export key, and that recipient's key pair.
fn export_world() -> (
    World,
    encompute_trust::authz::SignedReleaseRecord,
    encompute_attestation::ExportRecipient,
) {
    let mut w = world();
    w.broker
        .add_secret(
            RESULT,
            Some(encompute_keybroker::KeyMaterial::from_bytes(RESULT_KEY).unwrap()),
            release_policy(&w.spec),
        )
        .unwrap();
    let recipient = encompute_attestation::ExportRecipient::generate();
    let record = release_record(&w, &recipient.public_key_hex())
        .sign(&governance_key())
        .unwrap();
    w.broker
        .bind_derived_version(RESULT, &record, &cosigned(&record, RESULT))
        .unwrap();
    w.broker
        .pin_lineage_governance_key(LINEAGE, &attested(&lineage_pk(), T0))
        .unwrap();
    w.broker
        .install_authorization(&lineage_authorization(|_| {}))
        .unwrap();
    (w, record, recipient)
}

fn release_record(w: &World, export_key: &str) -> encompute_trust::authz::ReleaseRecord {
    encompute_trust::authz::ReleaseRecord {
        version: 1,
        party: ORG.into(),
        project: PROJECT.into(),
        purpose_id: h('1'),
        job_id: "job_1".into(),
        governance_id: w.binding.id().hex(),
        output: "eligible".into(),
        output_commitment: h('f'),
        derived_version_id: derived_version(),
        release_class: ReleaseClass::BooleanOnly,
        parents: BTreeSet::from([asset_version()]),
        authorization_ids: BTreeSet::from([lineage_authorization(|_| {}).id()]),
        onward_policy_id: h('d'),
        recipients: std::collections::BTreeMap::from([(RECIPIENT.into(), export_key.into())]),
        lineage_owners: std::collections::BTreeMap::from([(
            LINEAGE.into(),
            encompute_trust::authz::governance_key_id(&lineage_pk()),
        )]),
        issued_at: T0,
    }
}

/// An export ticket of the result for `recipient` under `key`, unsigned.
fn export_ticket_body(
    w: &World,
    recipient: &str,
    key: &str,
) -> encompute_verification::ticket::ReleaseTicket {
    let mut t = w.ticket_body();
    t.authorization_ids = BTreeSet::from([lineage_authorization(|_| {}).id()]);
    t.kind = TicketKind::Export;
    t.asset_version_id = derived_version();
    t.recipient = Some(recipient.into());
    t.workload_or_recipient = key.into();
    t
}

fn export_request(
    ticket: encompute_verification::ticket::ReleaseTicket,
    record: &encompute_trust::authz::SignedReleaseRecord,
) -> encompute_keybroker::GovernedExportRequest {
    encompute_keybroker::GovernedExportRequest {
        asset_id: RESULT.into(),
        ticket,
        release_record: record.clone(),
    }
}

fn export(
    w: &mut World,
    req: &encompute_keybroker::GovernedExportRequest,
) -> encompute_ir::Result<(
    encompute_attestation::EncryptedKeyGrant,
    encompute_attestation::KeyReleaseReceipt,
)> {
    let p = w.broker.prepare_governed_export(req)?;
    w.broker.finish_release(p)
}

/// The custodian's broker exports a derived result's key only to a
/// recipient its signed release record names, sealed to the export key the
/// record gives it: another recipient, another key, a ticket of another
/// kind (decryption included), a source key, or a record the pinned
/// governance key did not sign releases nothing, and none of those spends
/// the honest ticket.
#[test]
fn broker_export_only_for_named_recipient() {
    let (mut w, record, recipient) = export_world();
    let key = recipient.public_key_hex();
    let honest = export_ticket_body(&w, RECIPIENT, &key)
        .sign(&control())
        .unwrap();
    // A recipient the record does not name.
    let other = export_ticket_body(&w, "other-co", &key)
        .sign(&control())
        .unwrap();
    assert_eq!(
        code(export(&mut w, &export_request(other, &record))),
        Code::GovernanceReleaseClass
    );
    // The named recipient, under a key the record does not give it.
    let intruder = encompute_attestation::ExportRecipient::generate();
    let redirected = export_ticket_body(&w, RECIPIENT, &intruder.public_key_hex())
        .sign(&control())
        .unwrap();
    assert_eq!(
        code(export(&mut w, &export_request(redirected, &record))),
        Code::GovernanceReleaseTicket
    );
    // A key-release or decryption ticket is not an export ticket.
    for kind in [TicketKind::KeyRelease, TicketKind::Decrypt] {
        let mut t = export_ticket_body(&w, RECIPIENT, &key);
        t.kind = kind;
        assert_eq!(
            code(export(
                &mut w,
                &export_request(t.sign(&control()).unwrap(), &record)
            )),
            Code::GovernanceReleaseTicket,
            "{kind:?}"
        );
    }
    // Not naming exactly the authorizations the result was released under.
    let mut t = export_ticket_body(&w, RECIPIENT, &key);
    t.authorization_ids.insert(h('5'));
    assert_eq!(
        code(export(
            &mut w,
            &export_request(t.sign(&control()).unwrap(), &record)
        )),
        Code::GovernanceReleaseTicket
    );
    // An unsigned (forged) ticket.
    let mut forged = honest.clone();
    forged.signature = "00".repeat(64);
    assert_eq!(
        code(export(&mut w, &export_request(forged, &record))),
        Code::GovernanceReleaseTicket
    );
    // A record not signed by the pinned governance key.
    let rogue = release_record(&w, &key)
        .sign(&rogue_governance_key())
        .unwrap();
    assert_eq!(
        code(export(&mut w, &export_request(honest.clone(), &rogue))),
        Code::GovernanceKeyRevoked
    );
    // A source key is never exported.
    let mut src = export_request(honest.clone(), &record);
    src.asset_id = ASSET.into();
    assert_eq!(
        code(export(&mut w, &src)),
        Code::GovernanceAssetVersionMismatch
    );
    // The honest export: sealed to the recipient's key, opened by it only.
    let (grant, receipt) = export(&mut w, &export_request(honest.clone(), &record)).unwrap();
    assert_eq!(recipient.open(&grant).unwrap().as_slice(), RESULT_KEY);
    assert!(intruder.open(&grant).is_err());
    assert_eq!(grant.header.version, GRANT_VERSION_GOVERNED);
    assert_eq!(
        grant
            .header
            .governance
            .as_ref()
            .unwrap()
            .ticket_id
            .as_deref(),
        Some(honest.ticket_id.as_str())
    );
    receipt.verify(&w.broker.grant_public_key()).unwrap();
    assert_eq!(receipt.asset_version_id, derived_version());
    assert_eq!(receipt.authorization_id, record.id());
    assert_eq!(receipt.grant_digest, grant.digest().unwrap());
    // A derived result's binding is fixed: it is never re-bound as a
    // source version, nor a source as a derived result.
    assert_eq!(
        code(w.broker.bind_version(RESULT, &derived_version())),
        Code::GovernanceAssetVersionMismatch
    );
    assert_eq!(
        code(
            w.broker
                .bind_derived_version(ASSET, &record, &cosigned(&record, ASSET))
        ),
        Code::GovernanceAssetVersionMismatch
    );
}

/// An export ticket is single-use at the custodian's broker, across a
/// restart (the seen-ticket set is part of the authenticated state).
#[test]
fn replayed_export_ticket_refused_2712() {
    let (mut w, record, recipient) = export_world();
    let ticket = export_ticket_body(&w, RECIPIENT, &recipient.public_key_hex())
        .sign(&control())
        .unwrap();
    export(&mut w, &export_request(ticket.clone(), &record)).unwrap();
    assert_eq!(
        code(export(&mut w, &export_request(ticket.clone(), &record))),
        Code::GovernanceReleaseTicket
    );
    let dir = tmp("export-replay");
    let path = dir.join("broker.json");
    w.broker.save(&path).unwrap();
    let c = w.clock.clone();
    w.broker = KeyBroker::load(&path, verifier(), Box::new(DevelopmentFileStore))
        .unwrap()
        .with_clock(move || c.load(std::sync::atomic::Ordering::SeqCst))
        .with_governance(governance())
        .unwrap();
    assert_eq!(
        code(export(&mut w, &export_request(ticket, &record))),
        Code::GovernanceReleaseTicket
    );
    // A fresh ticket exports.
    let fresh = export_ticket_body(&w, RECIPIENT, &recipient.public_key_hex())
        .sign(&control())
        .unwrap();
    export(&mut w, &export_request(fresh, &record)).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

// --- a derived result's key at its custodian's broker: every lineage owner --------

/// The custodian's broker (this world's organization) holding the key of a
/// derived result (bound to the world's version, so the world's execution
/// reads it), whose record names `LINEAGE` as a lineage owner; its own
/// authorization installed. `pin`: `LINEAGE`'s key pinned; `install`: its
/// authorization (edited by `edit`) installed.
fn derived_world(
    pin: bool,
    install: bool,
    edit: impl FnOnce(&mut encompute_trust::authz::AuthorizationV2),
) -> (World, String) {
    let clock = Arc::new(AtomicU64::new(T0));
    let spec = spec_for(&binding());
    let mut b = bare_broker(&clock, &spec)
        .with_governance(governance())
        .unwrap();
    b.pin_governance_key(&governance_public_key()).unwrap();
    let mut w = World {
        broker: b,
        clock,
        evaluator: encompute_verification::EvaluatorSigner::from_seed(&[9; 32]),
        binding: binding(),
        spec,
        authorization: signed(authorization()),
    };
    let mut record = release_record(&w, &h('7'));
    record.derived_version_id = asset_version();
    let record = record.sign(&governance_key()).unwrap();
    w.broker
        .bind_derived_version(ASSET, &record, &cosigned(&record, ASSET))
        .unwrap();
    w.broker.install_authorization(&w.authorization).unwrap();
    if pin {
        w.broker
            .pin_lineage_governance_key(LINEAGE, &attested(&lineage_pk(), T0))
            .unwrap();
    }
    let lineage = lineage_authorization(edit);
    if install {
        w.broker.install_authorization(&lineage).unwrap();
    }
    (w, lineage.id())
}

/// A ticket naming the custodian's and the lineage owner's authorization.
fn derived_ticket(w: &World, lineage: &str) -> encompute_verification::ticket::ReleaseTicket {
    let mut t = w.ticket_body();
    t.authorization_ids = BTreeSet::from([w.authorization_id(), lineage.to_owned()]);
    t.sign(&control()).unwrap()
}

fn release_derived(
    w: &mut World,
    lineage: &str,
) -> encompute_ir::Result<(
    encompute_attestation::EncryptedKeyGrant,
    encompute_attestation::KeyReleaseReceipt,
)> {
    let s = w.session();
    let handle = w.attest(&s);
    let req = w.request(&handle, Some(derived_ticket(w, lineage)));
    w.release(&req)
}

/// Without an installed authorization of the lineage owner, or with a
/// ticket that does not name it, the custodian's own authorization
/// releases nothing (ENC2701).
#[test]
fn custodian_broker_refuses_without_lineage_owner_authorization() {
    let (mut w, lineage) = derived_world(true, false, |_| {});
    assert_eq!(
        code(release_derived(&mut w, &lineage)),
        Code::GovernanceAuthorizationMissing
    );
    w.broker
        .install_authorization(&lineage_authorization(|_| {}))
        .unwrap();
    // Installed, but the ticket names only the custodian's.
    let s = w.session();
    let handle = w.attest(&s);
    let req = w.request(&handle, Some(w.ticket()));
    assert_eq!(code(w.release(&req)), Code::GovernanceAuthorizationMissing);
    // A lineage authorization that does not cover the execution (another
    // program) does not count either.
    let (mut w2, other) = derived_world(true, true, |a| {
        a.program = ProgramRef::Program { program_id: h('9') }
    });
    assert_eq!(
        code(release_derived(&mut w2, &other)),
        Code::GovernanceProgramNotAuthorized
    );
    // Named and installed: released.
    release_derived(&mut w, &lineage).unwrap();
}

/// A lineage owner whose governance key the custodian's owner has not
/// pinned (or pinned another key for) gets nothing installed, and nothing
/// is released (ENC2708).
#[test]
fn custodian_broker_refuses_unpinned_lineage_owner_key() {
    let (mut w, lineage) = derived_world(false, false, |_| {});
    assert_eq!(
        code(
            w.broker
                .install_authorization(&lineage_authorization(|_| {}))
        ),
        Code::GovernanceAuthorizationMissing
    );
    assert_eq!(
        code(release_derived(&mut w, &lineage)),
        Code::GovernanceKeyRevoked
    );
    // Another key pinned for the lineage owner than the record names.
    let other = encompute_verification::hex(
        &ed25519_dalek::SigningKey::from_bytes(&[24; 32])
            .verifying_key()
            .to_bytes(),
    );
    w.broker
        .pin_lineage_governance_key(LINEAGE, &attested(&other, T0))
        .unwrap();
    assert_eq!(
        code(release_derived(&mut w, &lineage)),
        Code::GovernanceKeyRevoked
    );
    // A pin is never replaced by an attestation that is not later.
    assert_eq!(
        code(
            w.broker
                .pin_lineage_governance_key(LINEAGE, &attested(&lineage_pk(), T0))
        ),
        Code::GovernanceKeyRevoked
    );
}

/// With the custodian's and every lineage owner's authorization installed
/// and named, the key is released, counted against both.
#[test]
fn custodian_broker_releases_with_all_lineage_authorizations() {
    let (mut w, lineage) = derived_world(true, true, |_| {});
    let (grant, receipt) = release_derived(&mut w, &lineage).unwrap();
    receipt.verify(&w.broker.grant_public_key()).unwrap();
    assert_eq!(grant.header.version, GRANT_VERSION_GOVERNED);
    let counters = &w.broker.state().counters;
    assert_eq!(counters[&w.authorization_id()].releases, 1);
    assert_eq!(counters[&lineage].releases, 1);
}

/// The lineage owner's limits hold at the custodian's broker: each release
/// counts against its authorization, persisted, and once its
/// `max_releases` is used up nothing more is released (ENC2714), whatever
/// the custodian's own allows.
#[test]
fn lineage_counters_at_custodian_broker() {
    let (mut w, lineage) = derived_world(true, true, |a| a.limits.max_releases = Some(1));
    release_derived(&mut w, &lineage).unwrap();
    assert_eq!(
        code(release_derived(&mut w, &lineage)),
        Code::GovernanceAuthorizationLimit
    );
    let dir = tmp("lineage-counters");
    let path = dir.join("broker.json");
    w.broker.save(&path).unwrap();
    let c = w.clock.clone();
    w.broker = KeyBroker::load(&path, verifier(), Box::new(DevelopmentFileStore))
        .unwrap()
        .with_clock(move || c.load(std::sync::atomic::Ordering::SeqCst))
        .with_governance(governance())
        .unwrap();
    assert_eq!(w.broker.state().counters[&lineage].releases, 1);
    assert_eq!(
        code(release_derived(&mut w, &lineage)),
        Code::GovernanceAuthorizationLimit
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

// --- what the custodian's broker takes from the control plane -------------------

/// A lineage owner's governance key is pinned at the custodian's broker only
/// from the control plane's attestation of it, signed under the pinned
/// control-plane key: a broker without a control-plane key pins nothing,
/// and a pin is never made from the bare key.
#[test]
fn lineage_key_pin_requires_control_plane_attestation() {
    let (mut w, lineage) = derived_world(false, false, |_| {});
    // Without a control-plane key configured, nothing is attested.
    let clock = Arc::new(AtomicU64::new(T0));
    let mut bare = bare_broker(&clock, &w.spec);
    bare.pin_governance_key(&governance_public_key()).unwrap();
    assert_eq!(
        code(bare.pin_lineage_governance_key(LINEAGE, &attested(&lineage_pk(), T0))),
        Code::GovernanceKeyRevoked
    );
    assert!(bare.state().lineage_keys.is_empty());
    // Attested by the pinned control plane: pinned, and the lineage owner's
    // authorization is installed and released under.
    assert!(w
        .broker
        .pin_lineage_governance_key(LINEAGE, &attested(&lineage_pk(), T0))
        .unwrap());
    let pinned = &w.broker.state().lineage_keys[LINEAGE];
    assert_eq!(pinned.key.public_key, lineage_pk());
    assert_eq!(pinned.attested_at, T0);
    w.broker
        .install_authorization(&lineage_authorization(|_| {}))
        .unwrap();
    release_derived(&mut w, &lineage).unwrap();
    // The same attestation again changes nothing.
    w.broker
        .pin_lineage_governance_key(LINEAGE, &attested(&lineage_pk(), T0))
        .unwrap();
    // Its own organization's key is never a lineage key.
    let own = attestation_by(&control(), ORG, &governance_public_key(), None, T0);
    assert_eq!(
        code(w.broker.pin_lineage_governance_key(ORG, &own)),
        Code::KeyRelease
    );
}

/// An attestation not signed by the pinned control-plane key (another
/// service key, a tampered body, a stripped signature, a key ID that is not
/// the key's) pins nothing (ENC2708).
#[test]
fn forged_attestation_refused() {
    let (mut w, _) = derived_world(false, false, |_| {});
    let rogue =
        encompute_verification::ServiceSigner::from_seed("control-plane", &[77; 32]).unwrap();
    let by_rogue = attestation_by(&rogue, LINEAGE, &lineage_pk(), None, T0);
    // Claiming the pinned control plane's key does not help either.
    let mut claimed = by_rogue.clone();
    claimed.issuer_public_key = control().public_key_hex();
    let other = encompute_verification::hex(
        &ed25519_dalek::SigningKey::from_bytes(&[24; 32])
            .verifying_key()
            .to_bytes(),
    );
    let mut tampered = attested(&lineage_pk(), T0);
    tampered.body.public_key = other.clone();
    tampered.body.key_id = encompute_trust::authz::governance_key_id(&other);
    let mut stripped = attested(&lineage_pk(), T0);
    stripped.signature = "00".repeat(64);
    let mut wrong_id = attested(&lineage_pk(), T0);
    wrong_id.body.key_id = h('8');
    for (what, a) in [
        ("another signer", by_rogue),
        ("claimed issuer", claimed),
        ("tampered", tampered),
        ("stripped", stripped),
        ("wrong key ID", wrong_id),
    ] {
        assert_eq!(
            code(w.broker.pin_lineage_governance_key(LINEAGE, &a)),
            Code::GovernanceKeyRevoked,
            "{what}"
        );
    }
    assert!(w.broker.state().lineage_keys.is_empty());
}

/// An attestation of another organization's key is not one of the lineage
/// owner's (ENC2708): a custodian cannot pin a key the control plane
/// attested for someone else under the lineage owner's name.
#[test]
fn attestation_for_other_org_refused() {
    let (mut w, _) = derived_world(false, false, |_| {});
    let elsewhere = attestation_by(&control(), "other-agency", &lineage_pk(), None, T0);
    assert_eq!(
        code(w.broker.pin_lineage_governance_key(LINEAGE, &elsewhere)),
        Code::GovernanceKeyRevoked
    );
    assert!(w.broker.state().lineage_keys.is_empty());
}

/// A later attestation of another key for the lineage owner (a rotation)
/// replaces the pin, and survives a restart; an earlier one never rolls it
/// back. Authorizations signed by the old key are no longer used, and a
/// result whose record names the old key fails closed (ENC2708).
#[test]
fn rotated_lineage_key_replaces_pin() {
    let (mut w, lineage) = derived_world(true, true, |_| {});
    release_derived(&mut w, &lineage).unwrap();
    let rotated = ed25519_dalek::SigningKey::from_bytes(&[25; 32]);
    let rotated_pk = encompute_verification::hex(&rotated.verifying_key().to_bytes());
    assert!(w
        .broker
        .pin_lineage_governance_key(LINEAGE, &attested(&rotated_pk, T0 + 10))
        .unwrap());
    assert_eq!(
        w.broker.state().lineage_keys[LINEAGE].key.public_key,
        rotated_pk
    );
    // The old key's attestation, earlier, does not roll it back.
    assert_eq!(
        code(
            w.broker
                .pin_lineage_governance_key(LINEAGE, &attested(&lineage_pk(), T0 + 5))
        ),
        Code::GovernanceKeyRevoked
    );
    // The result's record names the old key: nothing is released.
    assert_eq!(
        code(release_derived(&mut w, &lineage)),
        Code::GovernanceKeyRevoked
    );
    // The pin is part of the persisted state.
    let dir = tmp("lineage-rotation");
    let path = dir.join("broker.json");
    w.broker.save(&path).unwrap();
    let b = KeyBroker::load(&path, verifier(), Box::new(DevelopmentFileStore))
        .unwrap()
        .with_governance(governance())
        .unwrap();
    assert_eq!(b.state().lineage_keys[LINEAGE].key.public_key, rotated_pk);
    assert_eq!(b.state().lineage_keys[LINEAGE].attested_at, T0 + 10);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The control plane's attestation that the lineage owner's key was
/// revoked unpins it: nothing it signed is installed or released under
/// any more, and it is never pinned again, whatever later active
/// attestation of it is presented.
#[test]
fn revoked_lineage_key_unpins() {
    let (mut w, lineage) = derived_world(true, true, |_| {});
    release_derived(&mut w, &lineage).unwrap();
    let revoked = attestation_by(&control(), LINEAGE, &lineage_pk(), Some(T0 + 1), T0 + 1);
    assert!(!w
        .broker
        .pin_lineage_governance_key(LINEAGE, &revoked)
        .unwrap());
    assert!(!w.broker.state().lineage_keys.contains_key(LINEAGE));
    assert!(w
        .broker
        .state()
        .revoked_lineage_keys
        .contains_key(&encompute_trust::authz::governance_key_id(&lineage_pk())));
    assert_eq!(
        code(release_derived(&mut w, &lineage)),
        Code::GovernanceKeyRevoked
    );
    let mut fresh = lineage_authorization(|_| {}).body;
    fresh.nonce = "aa".repeat(16);
    assert_eq!(
        code(
            w.broker
                .install_authorization(&fresh.sign(&lineage_key()).unwrap())
        ),
        Code::GovernanceAuthorizationMissing
    );
    assert_eq!(
        code(
            w.broker
                .pin_lineage_governance_key(LINEAGE, &attested(&lineage_pk(), T0 + 100))
        ),
        Code::GovernanceKeyRevoked
    );
    // A forged revocation is refused like any forged attestation.
    let rogue =
        encompute_verification::ServiceSigner::from_seed("control-plane", &[77; 32]).unwrap();
    let (mut w2, _) = derived_world(true, true, |_| {});
    assert_eq!(
        code(w2.broker.pin_lineage_governance_key(
            LINEAGE,
            &attestation_by(&rogue, LINEAGE, &lineage_pk(), Some(T0), T0)
        )),
        Code::GovernanceKeyRevoked
    );
    assert!(w2.broker.state().lineage_keys.contains_key(LINEAGE));
}

/// A derived result's key is bound only with the control plane's
/// co-signature of exactly the custodian's record, for this broker and
/// key, under the pinned control-plane key (ENC2704): none configured, a
/// forged one, or one of another record, key or broker binds nothing.
#[test]
fn bind_derived_version_requires_control_plane_cosignature() {
    let (w, record, _) = export_world();
    let fresh = |w: &World| {
        let clock = Arc::new(AtomicU64::new(T0));
        let mut b = bare_broker(&clock, &w.spec)
            .with_governance(governance())
            .unwrap();
        b.pin_governance_key(&governance_public_key()).unwrap();
        b.add_secret(
            RESULT,
            Some(encompute_keybroker::KeyMaterial::from_bytes(RESULT_KEY).unwrap()),
            release_policy(&w.spec),
        )
        .unwrap();
        b
    };
    // No control-plane key configured.
    let clock = Arc::new(AtomicU64::new(T0));
    let mut bare = bare_broker(&clock, &w.spec);
    bare.pin_governance_key(&governance_public_key()).unwrap();
    bare.add_secret(
        RESULT,
        Some(encompute_keybroker::KeyMaterial::from_bytes(RESULT_KEY).unwrap()),
        release_policy(&w.spec),
    )
    .unwrap();
    assert_eq!(
        code(bare.bind_derived_version(RESULT, &record, &cosigned(&record, RESULT))),
        Code::GovernanceAssetVersionMismatch
    );
    let mut b = fresh(&w);
    let rogue =
        encompute_verification::ServiceSigner::from_seed("control-plane", &[77; 32]).unwrap();
    let mut stripped = cosigned(&record, RESULT);
    stripped.signature = "00".repeat(64);
    let mut other_broker = cosigned(&record, RESULT).body;
    other_broker.broker = "another-broker".into();
    let mut other_record = release_record(&w, &h('7'));
    other_record.output = "another-output".into();
    let other_record = other_record.sign(&governance_key()).unwrap();
    for (what, c) in [
        ("another signer", cosigned_by(&rogue, &record, RESULT)),
        ("stripped", stripped),
        ("another key", cosigned(&record, ASSET)),
        ("another broker", other_broker.sign(&control()).unwrap()),
        ("another record", cosigned(&other_record, RESULT)),
    ] {
        assert_eq!(
            code(b.bind_derived_version(RESULT, &record, &c)),
            Code::GovernanceAssetVersionMismatch,
            "{what}"
        );
        assert!(
            b.state().secrets[RESULT].asset_version_id.is_none(),
            "{what}"
        );
    }
    // Co-signed: bound to the result and its lineage owners.
    b.bind_derived_version(RESULT, &record, &cosigned(&record, RESULT))
        .unwrap();
    let s = &b.state().secrets[RESULT];
    assert!(s.derived);
    assert_eq!(s.lineage_owners, record.body.lineage_owners);
}

/// A custodian's record that leaves a lineage owner out is never bound:
/// the control plane co-signed the record it validated against the
/// result's real ancestry, which names every lineage owner, and the
/// custodian cannot co-sign its own (ENC2704). Without the binding the
/// key releases and exports nothing.
#[test]
fn bind_with_record_omitting_owner_refused() {
    let (w, record, recipient) = export_world();
    let clock = Arc::new(AtomicU64::new(T0));
    let mut b = bare_broker(&clock, &w.spec)
        .with_governance(governance())
        .unwrap();
    b.pin_governance_key(&governance_public_key()).unwrap();
    b.add_secret(
        RESULT,
        Some(encompute_keybroker::KeyMaterial::from_bytes(RESULT_KEY).unwrap()),
        release_policy(&w.spec),
    )
    .unwrap();
    // The custodian's own record without the lineage owner, signed with
    // its governance key.
    let mut omitting = release_record(&w, &recipient.public_key_hex());
    omitting.lineage_owners.clear();
    let omitting = omitting.sign(&governance_key()).unwrap();
    // The control plane co-signed the honest record, not this one.
    assert_eq!(
        code(b.bind_derived_version(RESULT, &omitting, &cosigned(&record, RESULT))),
        Code::GovernanceAssetVersionMismatch
    );
    // A co-signature whose lineage owners were edited does not verify.
    let mut edited = cosigned(&record, RESULT);
    edited.body.lineage_owners.clear();
    edited.body.release_record_id = omitting.id();
    assert_eq!(
        code(b.bind_derived_version(RESULT, &omitting, &edited)),
        Code::GovernanceAssetVersionMismatch
    );
    // A co-signature made by the custodian itself is not the control
    // plane's.
    let custodian = encompute_verification::ServiceSigner::from_seed(BROKER, &[21; 32]).unwrap();
    assert_eq!(
        code(b.bind_derived_version(
            RESULT,
            &omitting,
            &cosigned_by(&custodian, &omitting, RESULT)
        )),
        Code::GovernanceAssetVersionMismatch
    );
    assert!(b.state().secrets[RESULT].asset_version_id.is_none());
}

// --- a lineage owner's key rotation, attestation age, the pinned control key ----

/// The lineage owner's rotated key and its signing key.
fn rotated_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[25; 32])
}

fn rotated_pk() -> String {
    encompute_verification::hex(&rotated_key().verifying_key().to_bytes())
}

/// The lineage owner's authorization of the parent version, signed with
/// its rotated key.
fn rotated_authorization() -> encompute_trust::authz::SignedAuthorizationV2 {
    let mut a = authorization();
    a.party = LINEAGE.into();
    a.nonce = "cd".repeat(16);
    a.sign(&rotated_key()).unwrap()
}

/// The control plane's co-signature of derived_world's record as bound
/// (key `ASSET`), edited by `edit`.
fn recosigned(
    w: &World,
    edit: impl FnOnce(&mut encompute_trust::authz::DerivedReleaseCosignature),
) -> encompute_trust::authz::SignedDerivedReleaseCosignature {
    let s = &w.broker.state().secrets[ASSET];
    let b = s.derived_binding.clone().unwrap();
    let mut c = encompute_trust::authz::DerivedReleaseCosignature {
        version: 1,
        organization: ORG.into(),
        asset_id: b.asset_id,
        broker: BROKER.into(),
        key_ref: ASSET.into(),
        derived_version_id: s.asset_version_id.clone().unwrap(),
        release_record_id: b.release_record_id,
        lineage_owners: std::collections::BTreeMap::from([(
            LINEAGE.into(),
            encompute_trust::authz::governance_key_id(&rotated_pk()),
        )]),
        issued_at: T0 + 20,
    };
    edit(&mut c);
    c.sign(&control()).unwrap()
}

/// A lineage owner's key rotation strands the derived result bound under
/// the old key ID (ENC2708), even with the owner's new authorization
/// installed under its newly attested key, until the custodian's broker
/// accepts the control plane's re-issued co-signature naming the new key;
/// then it is released again, and the re-binding survives a restart.
#[test]
fn rotation_strands_until_rebound() {
    let (mut w, lineage) = derived_world(true, true, |_| {});
    release_derived(&mut w, &lineage).unwrap();
    // The lineage owner rotates: the control plane attests the new key,
    // and the owner signs a new authorization with it.
    w.set_now(T0 + 10);
    assert!(w
        .broker
        .pin_lineage_governance_key(LINEAGE, &attested(&rotated_pk(), T0 + 10))
        .unwrap());
    let renewed = rotated_authorization();
    w.broker.install_authorization(&renewed).unwrap();
    assert_eq!(
        code(release_derived(&mut w, &renewed.id())),
        Code::GovernanceKeyRevoked
    );
    // The control plane re-issues the co-signature with the new key ID.
    assert!(w
        .broker
        .rebind_derived_lineage(ASSET, &recosigned(&w, |_| {}))
        .unwrap());
    let s = &w.broker.state().secrets[ASSET];
    assert_eq!(
        s.lineage_owners[LINEAGE],
        encompute_trust::authz::governance_key_id(&rotated_pk())
    );
    assert_eq!(s.derived_binding.as_ref().unwrap().cosigned_at, T0 + 20);
    release_derived(&mut w, &renewed.id()).unwrap();
    // The same co-signature again is not newer: refused, nothing changes.
    assert_eq!(
        code(
            w.broker
                .rebind_derived_lineage(ASSET, &recosigned(&w, |_| {}))
        ),
        Code::GovernanceAssetVersionMismatch
    );
    // Persisted with the state.
    let dir = tmp("lineage-rebind");
    let path = dir.join("broker.json");
    w.broker.save(&path).unwrap();
    let b = KeyBroker::load(&path, verifier(), Box::new(DevelopmentFileStore)).unwrap();
    assert_eq!(
        b.state().secrets[ASSET].lineage_owners[LINEAGE],
        encompute_trust::authz::governance_key_id(&rotated_pk())
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A re-issued co-signature naming a key the custodian's broker has not
/// pinned from the control plane's attestation (ENC2708), signed by anyone
/// but the pinned control plane, or not newer than the binding in force
/// (ENC2704), re-binds nothing.
#[test]
fn rebind_with_unattested_key_refused() {
    let (mut w, _) = derived_world(true, true, |_| {});
    let before = w.broker.state().secrets[ASSET].lineage_owners.clone();
    // The rotated key was never attested here.
    assert_eq!(
        code(
            w.broker
                .rebind_derived_lineage(ASSET, &recosigned(&w, |_| {}))
        ),
        Code::GovernanceKeyRevoked
    );
    w.broker
        .pin_lineage_governance_key(LINEAGE, &attested(&rotated_pk(), T0 + 10))
        .unwrap();
    // Another signer, or a stripped signature.
    let rogue =
        encompute_verification::ServiceSigner::from_seed("control-plane", &[77; 32]).unwrap();
    let mut forged = recosigned(&w, |_| {}).body;
    forged.issued_at = T0 + 30;
    let forged = encompute_trust::authz::DerivedReleaseCosignature::sign(forged, &rogue).unwrap();
    let mut stripped = recosigned(&w, |_| {});
    stripped.signature = "00".repeat(64);
    // Not newer than the co-signature the key is bound under.
    let stale = recosigned(&w, |c| c.issued_at = T0);
    for (what, c) in [
        ("another signer", forged),
        ("stripped", stripped),
        ("stale", stale),
    ] {
        assert_eq!(
            code(w.broker.rebind_derived_lineage(ASSET, &c)),
            Code::GovernanceAssetVersionMismatch,
            "{what}"
        );
    }
    assert_eq!(w.broker.state().secrets[ASSET].lineage_owners, before);
    // An unbound or source key is never re-bound.
    assert_eq!(
        code(
            w.broker
                .rebind_derived_lineage("no-such-key", &recosigned(&w, |_| {}))
        ),
        Code::KeyRelease
    );
}

/// A re-binding changes only the lineage owners' key IDs: a co-signature
/// of another record, version, asset, key or broker, or one that adds or
/// drops a lineage owner, is refused (ENC2704) and the binding stays.
#[test]
fn rebind_cannot_change_record_or_owners() {
    let (mut w, _) = derived_world(true, true, |_| {});
    w.broker
        .pin_lineage_governance_key(LINEAGE, &attested(&rotated_pk(), T0 + 10))
        .unwrap();
    // A second organization the broker pinned too, to add.
    let extra = attestation_by(&control(), "extra-agency", &lineage_pk(), None, T0 + 10);
    w.broker
        .pin_lineage_governance_key("extra-agency", &extra)
        .unwrap();
    let before = w.broker.state().secrets[ASSET].clone();
    let cases: Vec<(
        &str,
        encompute_trust::authz::SignedDerivedReleaseCosignature,
    )> = vec![
        (
            "another record",
            recosigned(&w, |c| c.release_record_id = h('9')),
        ),
        (
            "another version",
            recosigned(&w, |c| c.derived_version_id = h('8')),
        ),
        (
            "another asset",
            recosigned(&w, |c| c.asset_id = "ast_other".into()),
        ),
        ("another key", recosigned(&w, |c| c.key_ref = RESULT.into())),
        (
            "another broker",
            recosigned(&w, |c| c.broker = "another-broker".into()),
        ),
        (
            "another custodian",
            recosigned(&w, |c| c.organization = "other-agency".into()),
        ),
        (
            "an owner dropped",
            recosigned(&w, |c| c.lineage_owners.clear()),
        ),
        (
            "an owner added",
            recosigned(&w, |c| {
                c.lineage_owners.insert(
                    "extra-agency".into(),
                    encompute_trust::authz::governance_key_id(&lineage_pk()),
                );
            }),
        ),
    ];
    for (what, c) in cases {
        assert_eq!(
            code(w.broker.rebind_derived_lineage(ASSET, &c)),
            Code::GovernanceAssetVersionMismatch,
            "{what}"
        );
        let s = &w.broker.state().secrets[ASSET];
        assert_eq!(s.lineage_owners, before.lineage_owners, "{what}");
        assert_eq!(s.derived_binding, before.derived_binding, "{what}");
        assert_eq!(s.asset_version_id, before.asset_version_id, "{what}");
    }
}

/// A lineage owner's pinned key is relied on only while its attestation is
/// fresh: once older than the configured maximum age (24 hours unless
/// configured shorter), nothing derived from its data is released until
/// the control plane attests the key again (ENC2708, "re-attest"). Every
/// governed broker has a maximum age: zero or more than 7 days is
/// refused.
#[test]
fn stale_lineage_attestation_needs_reattest() {
    assert_eq!(
        governance().lineage_attestation_max_age_secs,
        24 * 3600,
        "the default"
    );
    let (mut w, lineage) = derived_world(true, true, |_| {});
    w.broker = w
        .broker
        .with_governance(GovernanceConfig {
            lineage_attestation_max_age_secs: 60,
            ..governance()
        })
        .unwrap();
    release_derived(&mut w, &lineage).unwrap();
    w.set_now(T0 + 61);
    let e = {
        let s = w.session();
        let handle = w.attest(&s);
        let req = w.request(&handle, Some(derived_ticket(&w, &lineage)));
        w.release(&req).unwrap_err()
    };
    assert_eq!(e.code, Code::GovernanceKeyRevoked, "{e}");
    assert!(e.message.contains("re-attest"), "{e}");
    // Attested again: released.
    w.broker
        .pin_lineage_governance_key(LINEAGE, &attested(&lineage_pk(), T0 + 61))
        .unwrap();
    release_derived(&mut w, &lineage).unwrap();
    for bad in [
        0,
        encompute_keybroker::MAX_LINEAGE_ATTESTATION_MAX_AGE_SECS + 1,
    ] {
        let clock = Arc::new(AtomicU64::new(T0));
        let r = bare_broker(&clock, &w.spec).with_governance(GovernanceConfig {
            lineage_attestation_max_age_secs: bad,
            ..governance()
        });
        assert_eq!(
            r.err().map(|e| e.code),
            Some(Code::InsecureConfiguration),
            "{bad}"
        );
    }
}

/// The longest maximum age a governed broker accepts for a lineage
/// attestation is 7 days: exactly 7 days is accepted, one second more (and
/// the former 30-day limit) is refused (ENC2605), and the default stays 24
/// hours.
#[test]
fn lineage_attestation_max_age_is_at_most_seven_days() {
    assert_eq!(
        encompute_keybroker::MAX_LINEAGE_ATTESTATION_MAX_AGE_SECS,
        7 * 24 * 3600
    );
    assert_eq!(
        encompute_keybroker::DEFAULT_LINEAGE_ATTESTATION_MAX_AGE_SECS,
        24 * 3600
    );
    let spec = derived_world(true, true, |_| {}).0.spec;
    let with = |secs: u64| {
        let clock = Arc::new(AtomicU64::new(T0));
        bare_broker(&clock, &spec)
            .with_governance(GovernanceConfig {
                lineage_attestation_max_age_secs: secs,
                ..governance()
            })
            .map(|_| ())
            .map_err(|e| e.code)
    };
    assert_eq!(with(24 * 3600), Ok(()));
    assert_eq!(with(7 * 24 * 3600), Ok(()));
    for bad in [7 * 24 * 3600 + 1, 30 * 24 * 3600] {
        assert_eq!(with(bad), Err(Code::InsecureConfiguration), "{bad}");
    }
}

/// The control-plane key is pinned in the broker's state the first time
/// the broker is configured with it, durably: a later configuration with
/// another key is refused (ENC2605), and only the owner's explicit
/// replacement changes it, after which the old key's tickets are refused.
#[test]
fn control_key_pinned_in_broker_state() {
    let dir = tmp("control-key");
    let path = dir.join("broker.json");
    let clock = Arc::new(AtomicU64::new(T0));
    let spec = spec_for(&binding());
    let b = bare_broker(&clock, &spec);
    assert_eq!(b.pinned_control_key(), None);
    let b = b.with_governance(governance()).unwrap();
    assert_eq!(
        b.pinned_control_key(),
        Some(control().public_key_hex().as_str())
    );
    b.save(&path).unwrap();
    let other =
        encompute_verification::ServiceSigner::from_seed("control-plane", &[78; 32]).unwrap();
    let load = || KeyBroker::load(&path, verifier(), Box::new(DevelopmentFileStore)).unwrap();
    // The same key again is fine; another is refused.
    load().with_governance(governance()).unwrap();
    let e = load()
        .with_governance(GovernanceConfig::new(&other.public_key_hex()))
        .err()
        .unwrap();
    assert_eq!(e.code, Code::InsecureConfiguration, "{e}");
    assert!(e.message.contains("--replace-control-key"), "{e}");
    let mut b = load();
    assert_eq!(
        code(b.pin_control_key(&other.public_key_hex())),
        Code::InsecureConfiguration
    );
    // Replacing the pinned key with itself is refused, and records nothing.
    assert_eq!(
        code(b.replace_control_key(&control().public_key_hex())),
        Code::InsecureConfiguration
    );
    assert!(b.state().control_key_history.is_empty());
    // The owner's explicit replacement, recorded in the state itself.
    let previous = b.replace_control_key(&other.public_key_hex()).unwrap();
    assert_eq!(previous, Some(control().public_key_hex()));
    let h = &b.state().control_key_history;
    assert_eq!(h.len(), 1);
    assert_eq!(
        h[0].previous_key.as_deref(),
        Some(control().public_key_hex().as_str())
    );
    assert_eq!(h[0].new_key, other.public_key_hex());
    // On the broker's clock (this broker was loaded with the real one).
    assert!(h[0].at.abs_diff(encompute_verification::service::now()) < 60);
    b.save(&path).unwrap();
    // Durable: persisted under the state's MAC.
    assert_eq!(
        load().state().control_key_history,
        b.state().control_key_history
    );
    let b = load()
        .with_governance(GovernanceConfig::new(&other.public_key_hex()))
        .unwrap();
    assert_eq!(
        b.pinned_control_key(),
        Some(other.public_key_hex().as_str())
    );
    assert_eq!(
        load().with_governance(governance()).err().map(|e| e.code),
        Some(Code::InsecureConfiguration)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
