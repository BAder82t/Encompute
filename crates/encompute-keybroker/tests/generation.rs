//! The broker state's generation mark: restoring an older authentic state
//! file (one that still holds an unrevoked authorization, a counter below
//! its limit, or lacks a used ticket) is refused, as is a forked state; a
//! crash between writing the file and advancing the mark recovers; a mark
//! that conflicts or cannot be reached grants nothing. A governed
//! production broker needs a mark, and a broker without one behaves as in
//! 0.3.

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use common::*;
use encompute_attestation::{unix_now, Attester};
use encompute_ir::{Code, Error, Result};
use encompute_keybroker::generation::{mark_conflict, mark_unavailable};
use encompute_keybroker::{
    serve_with_control, BrokerClient, BrokerMode, ControlChannel, DevelopmentFileMark,
    DevelopmentFileStore, GenerationMark, KeyBroker, LocalKekStore, Mark, MarkRead, StoreSecurity,
    MARK_UNAVAILABLE,
};
use encompute_trust::authz::RevocationV2;
use encompute_verification::http::Server;
use encompute_verification::service::{seal, Scope};
use encompute_verification::ticket::ReleaseTicket;

const ME: &str = "keybroker-tax";

// --- a test-only mark in memory -------------------------------------------------

#[derive(Default)]
struct Inner {
    mark: Option<Mark>,
    cas: u64,
    unreachable: bool,
    conflict_next: bool,
}

/// A mark in memory, shared by its clones (a "KMS" that outlives broker
/// restarts), that can be made unreachable or made to conflict.
#[derive(Clone)]
struct MemoryMark {
    inner: Arc<Mutex<Inner>>,
    security: StoreSecurity,
}

impl MemoryMark {
    fn new(security: StoreSecurity) -> Self {
        Self {
            inner: Arc::default(),
            security,
        }
    }

    fn dev() -> Self {
        Self::new(StoreSecurity::DevelopmentOnly)
    }

    fn set_unreachable(&self, v: bool) {
        self.inner.lock().unwrap().unreachable = v;
    }

    /// The next advance finds the mark advanced by someone else.
    fn conflict_next(&self) {
        self.inner.lock().unwrap().conflict_next = true;
    }

    fn generation(&self) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .mark
            .as_ref()
            .map(|m| m.generation)
    }

    fn boxed(&self) -> Box<dyn GenerationMark> {
        Box::new(self.clone())
    }
}

impl GenerationMark for MemoryMark {
    fn describe(&self) -> String {
        "memory".into()
    }

    fn security(&self) -> StoreSecurity {
        self.security
    }

    fn read(&self) -> Result<MarkRead> {
        let i = self.inner.lock().unwrap();
        if i.unreachable {
            return Err(mark_unavailable("memory", "connection refused"));
        }
        Ok(MarkRead {
            mark: i.mark.clone(),
            cas: i.cas,
        })
    }

    fn advance(&self, mark: &Mark, expected_cas: u64) -> Result<u64> {
        let mut i = self.inner.lock().unwrap();
        if i.unreachable {
            return Err(mark_unavailable("memory", "connection refused"));
        }
        if std::mem::take(&mut i.conflict_next) {
            // Someone else wrote a mark in between.
            i.cas += 1;
        }
        if i.cas != expected_cas {
            return Err(mark_conflict("memory"));
        }
        i.cas += 1;
        i.mark = Some(mark.clone());
        Ok(i.cas)
    }
}

// --- helpers ------------------------------------------------------------------

fn tmp() -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "encompute-kb-generation-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn copy(from: &Path, to: &Path) {
    std::fs::copy(from, to).unwrap();
}

fn reopen(path: &Path, mark: &MemoryMark) -> Result<KeyBroker> {
    KeyBroker::load_with_mark(
        path,
        verifier(),
        Box::new(DevelopmentFileStore),
        mark.boxed(),
    )
}

fn rollback_code<T>(r: Result<T>) -> Error {
    match r {
        Ok(_) => panic!("expected ENC2713"),
        Err(e) => {
            assert_eq!(e.code, Code::GovernanceBrokerStateRollback, "{e}");
            assert_eq!(e.code.as_str(), "ENC2713");
            e
        }
    }
}

fn file_generation(path: &Path) -> u64 {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    v["generation"].as_u64().unwrap()
}

/// A governed world on the real clock whose state is saved at `path` under
/// `mark`, with the authorization installed (limit: 2 releases).
fn saved_world(path: &Path, mark: &MemoryMark) -> World {
    let mut a = authorization();
    let now = unix_now();
    a.valid_from = now - 100;
    a.valid_until = now + 3600;
    a.issued_at = now - 200;
    a.limits.max_releases = Some(2);
    let spec = spec_for(&binding());
    let clock = Arc::new(AtomicU64::new(now));
    let mut b = bare_broker(&clock, &spec)
        .with_generation_mark(mark.boxed())
        .unwrap();
    b.bind_version(ASSET, &asset_version()).unwrap();
    b.pin_governance_key(&governance_public_key()).unwrap();
    let authorization = signed(a);
    b.install_authorization(&authorization).unwrap();
    b.save(path).unwrap();
    World {
        broker: b,
        clock,
        evaluator: encompute_verification::EvaluatorSigner::from_seed(&[9; 32]),
        binding: binding(),
        spec,
        authorization,
        placement: None,
        zone: None,
    }
}

/// A broker process over the state at `path`, guarded by `mark`.
fn start(path: &Path, mark: &MemoryMark) -> String {
    let b = reopen(path, mark)
        .unwrap()
        .with_governance(governance())
        .unwrap();
    let server = Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr());
    let path = path.to_owned();
    std::thread::spawn(move || {
        let ch = ControlChannel::new(ME, "control-plane", &control().public_key_hex(), ORG);
        let b = Mutex::new(b);
        serve_with_control(&b, server, 10_000, Some(&ch), &|b| b.save(&path))
    });
    url
}

/// Attests a fresh session at the broker at `url` and asks for the key
/// with `ticket`: the HTTP status and body.
fn release_over_http(w: &World, url: &str, ticket: ReleaseTicket) -> (u16, serde_json::Value) {
    let client = BrokerClient::new(url);
    let s = w.session();
    let c = client.challenge().unwrap();
    let b = s.binding(
        &c,
        &w.spec.id().hex(),
        w.spec.policy_id.as_deref(),
        ARTIFACT,
    );
    let e = hw().attester(IMAGE).attest(&c, &b).unwrap();
    let info = client.attest(&e).unwrap();
    let req = w.request(&info.session, Some(ticket));
    match ureq::post(&format!("{url}/v1/release/governed")).send_json(&req) {
        Ok(r) => (r.status(), r.into_json().unwrap()),
        Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap()),
        Err(e) => panic!("{e}"),
    }
}

/// A signed control-plane message to the broker at `url`.
fn deliver(url: &str, kind: &str, payload: serde_json::Value) -> (u16, serde_json::Value) {
    let cp = control();
    let m = seal(
        &cp,
        kind,
        ME,
        Scope {
            organization: Some(ORG.into()),
            ..Scope::default()
        },
        &payload,
        3600,
    )
    .unwrap();
    let body = serde_json::to_vec(&m).unwrap();
    let h = cp
        .sign_request("POST", "/v1/messages", ME, &Default::default(), &body)
        .unwrap();
    let mut r = ureq::post(&format!("{url}/v1/messages"));
    for (k, v) in h.to_pairs() {
        r = r.set(k, &v);
    }
    match r.send_bytes(&body) {
        Ok(r) => (r.status(), r.into_json().unwrap()),
        Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap()),
        Err(e) => panic!("{e}"),
    }
}

// --- tests --------------------------------------------------------------------

#[test]
fn broker_state_rollback_refused_by_kms_generation() {
    let dir = tmp();
    let state = dir.join("broker.json");
    let mark = MemoryMark::dev();
    let mut w = world();
    w.broker = std::mem::replace(&mut w.broker, bare_broker(&w.clock, &w.spec))
        .with_generation_mark(mark.boxed())
        .unwrap();
    // A: the authorization installed and unrevoked, no release counted, no
    // ticket used.
    w.broker.save(&state).unwrap();
    let a = dir.join("a.json");
    copy(&state, &a);
    // B: one release counted under a used ticket.
    let t = w.ticket();
    let s = w.session();
    let handle = w.attest(&s);
    w.release(&w.request(&handle, Some(t.clone()))).unwrap();
    w.broker.save(&state).unwrap();
    let b = dir.join("b.json");
    copy(&state, &b);
    // C: the owner revoked the authorization.
    w.broker
        .revoke_authorization_local(&w.authorization_id(), None)
        .unwrap();
    w.broker.save(&state).unwrap();
    assert_eq!(mark.generation(), Some(file_generation(&state)));

    // Restoring A (unrevoked, counter below its limit, ticket unused) or B
    // (unrevoked) over C is refused, with or without the mark configured.
    for older in [&a, &b] {
        copy(older, &state);
        let e = rollback_code(reopen(&state, &mark));
        assert!(e.message.contains("older"), "{e}");
        rollback_code(KeyBroker::load(
            &state,
            verifier(),
            Box::new(DevelopmentFileStore),
        ));
        rollback_code(KeyBroker::load_legacy(
            &state,
            verifier(),
            Box::new(DevelopmentFileStore),
        ));
    }
    // The latest state opens, and still holds the revocation.
    w.broker.save(&state).unwrap();
    let b = reopen(&state, &mark).unwrap();
    assert!(b
        .state()
        .revoked_authorizations
        .contains_key(&w.authorization_id()));
    assert!(b.state().seen_tickets.contains_key(&t.ticket_id));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn forked_state_same_generation_refused() {
    let dir = tmp();
    let state = dir.join("broker.json");
    let mark = MemoryMark::dev();
    let w = saved_world(&state, &mark);
    // Two brokers open the same state (a copy was started twice).
    let mut one = reopen(&state, &mark).unwrap();
    let mut two = reopen(&state, &mark).unwrap();
    one.revoke_authorization_local(&w.authorization_id(), None)
        .unwrap();
    one.save(&state).unwrap();
    let revoked = dir.join("revoked.json");
    copy(&state, &revoked);
    // The second one's save loses the compare-and-set: refused, though its
    // file was written.
    two.challenge().unwrap();
    let e = rollback_code(two.save(&state));
    assert!(!e.message.starts_with(MARK_UNAVAILABLE), "{e}");
    assert_eq!(file_generation(&state), file_generation(&revoked));
    // Its file has the mark's generation but another MAC: a fork, refused.
    let e = rollback_code(reopen(&state, &mark));
    assert!(e.message.contains("forked"), "{e}");
    // The state the mark recorded opens.
    copy(&revoked, &state);
    reopen(&state, &mark).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn crash_between_save_and_mark_recovers() {
    let dir = tmp();
    let state = dir.join("broker.json");
    let mark = MemoryMark::dev();
    let w = saved_world(&state, &mark);
    let before = file_generation(&state);
    assert_eq!(mark.generation(), Some(before));
    let mut b = reopen(&state, &mark).unwrap();
    b.revoke_authorization_local(&w.authorization_id(), None)
        .unwrap();
    // The file is written, the mark is not advanced (the process "dies").
    mark.set_unreachable(true);
    let e = rollback_code(b.save(&state));
    assert!(e.message.starts_with(MARK_UNAVAILABLE), "{e}");
    assert_eq!(file_generation(&state), before + 1);
    // A retry rewrites the same generation: the state never runs further
    // ahead of its mark than one save.
    let e = rollback_code(b.save(&state));
    assert!(e.message.starts_with(MARK_UNAVAILABLE), "{e}");
    assert_eq!(file_generation(&state), before + 1);
    // An unreachable mark refuses to open the state (fails closed).
    let e = rollback_code(reopen(&state, &mark));
    assert!(e.message.starts_with(MARK_UNAVAILABLE), "{e}");
    drop(b);
    // Back: the state one save ahead is accepted, the mark advanced, and
    // the revocation kept.
    mark.set_unreachable(false);
    let b = reopen(&state, &mark).unwrap();
    assert_eq!(mark.generation(), Some(before + 1));
    assert!(b
        .state()
        .revoked_authorizations
        .contains_key(&w.authorization_id()));
    // A state more than one save ahead was saved without its mark: refused.
    let mut ahead: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    ahead["generation"] = (before + 3).into();
    std::fs::write(&state, serde_json::to_vec(&ahead).unwrap()).unwrap();
    rollback_code(reopen(&state, &mark));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cas_conflict_denies_release() {
    let dir = tmp();
    let state = dir.join("broker.json");
    let mark = MemoryMark::dev();
    let w = saved_world(&state, &mark);
    let url = start(&state, &mark);
    // Someone else advances the mark between this broker's write and its
    // compare-and-set: no grant.
    mark.conflict_next();
    let t = w.ticket();
    let (status, body) = release_over_http(&w, &url, t.clone());
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["code"], "ENC2713", "{body}");
    assert!(body.get("grant").is_none());
    // The ticket stays spent in the running broker (toward denial).
    let (status, body) = release_over_http(&w, &url, t);
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["code"], "ENC2712", "{body}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn mark_unreachable_fails_closed() {
    let dir = tmp();
    let state = dir.join("broker.json");
    let mark = MemoryMark::dev();
    let w = saved_world(&state, &mark);
    let url = start(&state, &mark);
    mark.set_unreachable(true);
    let t = w.ticket();
    let (status, body) = release_over_http(&w, &url, t.clone());
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["code"], "ENC2713", "{body}");
    assert!(body.get("grant").is_none());
    // Reachable again: the ticket stays spent, a new one is granted.
    mark.set_unreachable(false);
    let (status, body) = release_over_http(&w, &url, t);
    assert_eq!(body["code"], "ENC2712", "{body}");
    assert_eq!(status, 403);
    let (status, body) = release_over_http(&w, &url, w.ticket());
    assert_eq!(status, 200, "{body}");
    assert!(body.get("grant").is_some());
    // A broker does not start while its mark is unreachable.
    mark.set_unreachable(true);
    let e = rollback_code(reopen(&state, &mark));
    assert!(e.message.starts_with(MARK_UNAVAILABLE), "{e}");
    std::fs::remove_dir_all(&dir).unwrap();
}

fn production_broker() -> KeyBroker {
    let clock = Arc::new(AtomicU64::new(T0));
    let spec = spec_for(&binding());
    let c = clock.clone();
    let mut b = KeyBroker::new(
        BROKER,
        BrokerMode::Production,
        verifier(),
        Box::new(LocalKekStore::from_key([5; 32])),
    )
    .unwrap()
    .with_clock(move || c.load(Ordering::SeqCst));
    b.set_organization(ORG).unwrap();
    b.add_secret(
        ASSET,
        Some(encompute_keybroker::KeyMaterial::from_bytes(KEY).unwrap()),
        {
            let mut p = release_policy(&spec);
            p.allow_development = false;
            p.allowed_tee = vec![encompute_attestation::TeeKind::AmdSevSnp];
            p
        },
    )
    .unwrap();
    b.bind_version(ASSET, &asset_version()).unwrap();
    b
}

#[test]
fn governed_production_broker_requires_a_mark() {
    let dir = tmp();
    // Not governed yet: no mark needed.
    let mut b = production_broker();
    assert!(!b.requires_generation_mark());
    b.check_generation_mark().unwrap();
    // Governed and in production: refused without a mark.
    b.pin_governance_key(&governance_public_key()).unwrap();
    assert!(b.requires_generation_mark());
    let e = b.check_generation_mark().unwrap_err();
    assert_eq!(e.code, Code::InsecureConfiguration, "{e}");
    let w = world();
    let e = b
        .prepare_governed_release(&w.request(&h('0'), Some(w.ticket())))
        .unwrap_err();
    assert_eq!(e.code, Code::InsecureConfiguration, "{e}");
    // Served, it refuses to install authorizations.
    let state = dir.join("broker.json");
    b.save(&state).unwrap();
    let served = KeyBroker::load(
        &state,
        verifier(),
        Box::new(LocalKekStore::from_key([5; 32])),
    )
    .unwrap();
    let server = Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr());
    std::thread::spawn(move || {
        let ch = ControlChannel::new(ME, "control-plane", &control().public_key_hex(), ORG);
        let b = Mutex::new(served);
        serve_with_control(&b, server, 10_000, Some(&ch), &|_| Ok(()))
    });
    let e = BrokerClient::new(&url)
        .install_authorization(&w.authorization)
        .unwrap_err();
    assert_eq!(e.code, Code::InsecureConfiguration, "{e}");
    // Every persisting route refuses the same way, with an error that says
    // the change was not recorded (a revocation is never dropped silently:
    // the owner revokes offline, the control plane's outbox retries).
    let r = RevocationV2 {
        version: 2,
        party: ORG.into(),
        authorization: w.authorization_id(),
        reason: "withdrawn".into(),
        issued_at: T0 - 1,
    }
    .sign(&governance_key())
    .unwrap();
    let e = BrokerClient::new(&url)
        .revoke_authorization(&r)
        .unwrap_err();
    assert_eq!(e.code, Code::InsecureConfiguration, "{e}");
    assert!(e.message.contains("not recorded"), "{e}");
    let (status, body) = deliver(
        &url,
        "authorization.revoked",
        serde_json::json!({"authorization_id": w.authorization_id()}),
    );
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["code"], "ENC2605", "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("not recorded"),
        "{body}"
    );
    let (status, body) = deliver(&url, "asset.revoked", serde_json::json!({"key_ref": ASSET}));
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["code"], "ENC2605", "{body}");
    // A development mark is refused for a production broker.
    let e = production_broker()
        .with_generation_mark(Box::new(DevelopmentFileMark::new(
            &dir.join("mark.json"),
            BROKER,
        )))
        .err()
        .unwrap();
    assert_eq!(e.code, Code::InsecureConfiguration, "{e}");
    // With a production mark it serves governed releases.
    let mark = MemoryMark::new(StoreSecurity::Production);
    let mut b = production_broker()
        .with_generation_mark(mark.boxed())
        .unwrap();
    b.pin_governance_key(&governance_public_key()).unwrap();
    b.check_generation_mark().unwrap();
    b.install_authorization(&w.authorization).unwrap();
    b.save(&state).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn no_mark_keeps_0_3_behaviour() {
    let dir = tmp();
    let state = dir.join("broker.json");
    let clock = Arc::new(AtomicU64::new(T0));
    let spec = spec_for(&binding());
    let mut b = bare_broker(&clock, &spec);
    assert!(!b.has_generation_mark());
    b.save(&state).unwrap();
    let older = dir.join("older.json");
    copy(&state, &older);
    b.revoke(ASSET, None).unwrap();
    b.save(&state).unwrap();
    assert_eq!(file_generation(&state), 2);
    // The state carries no mark flag.
    let text = std::fs::read_to_string(&state).unwrap();
    assert!(!text.contains("generation_marked"), "{text}");
    // Restoring an older authentic copy is not detected without a mark (a
    // known limitation).
    copy(&older, &state);
    let b = KeyBroker::load(&state, verifier(), Box::new(DevelopmentFileStore)).unwrap();
    assert!(!b.secret(ASSET).unwrap().versions[&1].revoked);
    // A governed development broker serves without a mark.
    let mut w = world();
    assert!(!w.broker.requires_generation_mark());
    w.release_fresh().unwrap();
    // A file mark (development) guards a development broker, and it is a
    // separate file.
    let mark_path = dir.join("mark.json");
    let b = KeyBroker::load(&state, verifier(), Box::new(DevelopmentFileStore))
        .unwrap()
        .with_generation_mark(Box::new(DevelopmentFileMark::new(&mark_path, BROKER)))
        .unwrap();
    b.save(&state).unwrap();
    b.save(&state).unwrap();
    copy(&older, &state);
    rollback_code(KeyBroker::load_with_mark(
        &state,
        verifier(),
        Box::new(DevelopmentFileStore),
        Box::new(DevelopmentFileMark::new(&mark_path, BROKER)),
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn divergent_file_at_mark_plus_one_refused() {
    let dir = tmp();
    let state = dir.join("broker.json");
    let mark = MemoryMark::dev();
    let w = saved_world(&state, &mark);
    let n1 = file_generation(&state);
    // A divergent history from the same authentic state, under another
    // mark: its file one save past the real mark's generation.
    let base = dir.join("base.json");
    copy(&state, &base);
    let other = MemoryMark::dev();
    let fork = reopen(&base, &other).err().unwrap();
    assert_eq!(fork.code, Code::GovernanceBrokerStateRollback);
    other.inner.lock().unwrap().mark = mark.inner.lock().unwrap().mark.clone();
    other.inner.lock().unwrap().cas = 1;
    let mut d = reopen(&base, &other).unwrap();
    d.challenge().unwrap();
    d.save(&base).unwrap();
    d.challenge().unwrap();
    d.save(&base).unwrap();
    let divergent = dir.join("divergent.json");
    copy(&base, &divergent);
    // The real history: one save committed, then the owner's revocation
    // written while the mark was unreachable (a crash before the mark).
    let mut b = reopen(&state, &mark).unwrap();
    b.challenge().unwrap();
    b.save(&state).unwrap();
    assert_eq!(mark.generation(), Some(n1 + 1));
    b.revoke_authorization_local(&w.authorization_id(), None)
        .unwrap();
    mark.set_unreachable(true);
    rollback_code(b.save(&state));
    mark.set_unreachable(false);
    drop(b);
    let pending = dir.join("pending.json");
    copy(&state, &pending);
    assert_eq!(file_generation(&pending), n1 + 2);
    assert_eq!(file_generation(&divergent), n1 + 2);
    // The divergent file has the right number but is not chained to the
    // mark's MAC: refused, and the mark is not advanced.
    copy(&divergent, &state);
    let e = rollback_code(reopen(&state, &mark));
    assert!(e.message.contains("chained"), "{e}");
    assert_eq!(mark.generation(), Some(n1 + 1));
    // The pending write is chained to it: accepted, revocation kept.
    copy(&pending, &state);
    let b = reopen(&state, &mark).unwrap();
    assert!(b
        .state()
        .revoked_authorizations
        .contains_key(&w.authorization_id()));
    assert_eq!(mark.generation(), Some(n1 + 2));
    std::fs::remove_dir_all(&dir).unwrap();
}
