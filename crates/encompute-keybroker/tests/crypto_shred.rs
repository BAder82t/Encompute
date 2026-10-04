//! Revocation crypto-shreds. Destroying a key in the current state file is
//! not enough: an older copy of the state file still holds it, wrapped
//! under the KEK, and the KEK has not changed. A revocation therefore also
//! replaces the KEK, in the same change (one save, one generation mark
//! advance), and the old KEK is destroyed once the state that needs the new
//! one is recorded.
//!
//! These tests restore older state files with the current KEK, with a copy
//! of the old KEK, and across crashes at each step of a revocation. They
//! need no services (the root key is a development one).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use encompute_attestation::mock::{MockHardware, MockProvider};
use encompute_attestation::{AttestationPolicy, Attester, TeeKind, Verifier, WorkloadSession};
use encompute_ir::Code;
use encompute_keybroker::generation::mark_unavailable;
use encompute_keybroker::{
    serve_with_control, BrokerMode, ControlChannel, DevelopmentFileMark, DevelopmentRootKey,
    GenerationMark, KeyBroker, KeyContext, KeyMaterial, LocalKekStore, Mark, MarkRead,
    RootWrappedKekStore, SecretStore, StoreSecurity, StoredKey,
};
use encompute_verification::service::{seal, signed_call, Scope};
use encompute_verification::{EvaluatorSigner, ServiceSigner};
use serde_json::Value;

type Result<T, E = encompute_ir::Error> = std::result::Result<T, E>;

const SPEC: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const POLICY: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const ARTIFACT: &str = "33333333333333333333333333333333333333333333333333333333333333cc";
const IMAGE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const T0: u64 = 1_900_000_000;
const PATIENTS: &[u8; 32] = b"hospital patient-data key 32 by.";
const LABS: &[u8; 32] = b"hospital laboratory key, 32 byte";
const ORG: &str = "hospital-a";
const BROKER: &str = "hospital";

fn hw() -> MockHardware {
    MockHardware::from_seed(&[7; 32])
}

fn verifier() -> Verifier {
    Verifier::new().with(MockProvider::new(&hw().public_key()).unwrap())
}

fn policy() -> AttestationPolicy {
    let mut p = AttestationPolicy::new(SPEC, Some(POLICY));
    p.allowed_tee = vec![TeeKind::Mock];
    p.allowed_images = vec![IMAGE.into()];
    p.allow_development = true;
    p
}

fn tmp(name: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "encompute-shred-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// An attested (mock) workload asks `broker` for `asset`: its key, or the
/// error code.
fn release(broker: &mut KeyBroker, asset: &str) -> Result<Vec<u8>, Code> {
    let session = WorkloadSession::new(&EvaluatorSigner::from_seed(&[9; 32]).identity());
    let ch = broker.challenge().unwrap();
    let e = hw()
        .attester(IMAGE)
        .issued_at(T0)
        .attest(&ch, &session.binding(&ch, SPEC, Some(POLICY), ARTIFACT))
        .unwrap();
    let info = broker.verify_attestation(&e).map_err(|e| e.code)?;
    let g = broker
        .release_key(&info.session, asset)
        .map_err(|e| e.code)?;
    Ok(session.open(&g).unwrap().to_vec())
}

/// A broker holding `patients` and `labs` under `store`.
fn broker(store: Box<dyn SecretStore>) -> KeyBroker {
    let mut b = KeyBroker::new(BROKER, BrokerMode::Development, verifier(), store)
        .unwrap()
        .with_clock(|| T0);
    for (asset, key) in [("patients", PATIENTS), ("labs", LABS)] {
        b.add_secret(asset, Some(KeyMaterial::from_bytes(key).unwrap()), policy())
            .unwrap();
    }
    b
}

fn read_json(p: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn kek_id(path: &Path) -> String {
    LocalKekStore::open_or_create(path)
        .unwrap()
        .key_id()
        .unwrap()
}

/// The stored key of `asset`'s version 1 in a saved state file.
fn stored(state: &Path, asset: &str) -> StoredKey {
    serde_json::from_value(read_json(state)["secrets"][asset]["versions"]["1"]["key"].clone())
        .unwrap()
}

/// Whether `store` recovers `asset`'s version 1 key from the state file at
/// `state`, without the broker's own checks: only the cryptography.
fn recovers(store: &dyn SecretStore, state: &Path, asset: &str) -> Option<Vec<u8>> {
    let ctx = KeyContext {
        broker_id: BROKER,
        asset_id: asset,
        version: 1,
    };
    store
        .unwrap_for_release(&ctx, &stored(state, asset))
        .ok()
        .map(|k| k.as_bytes().to_vec())
}

/// Files in `dir` named for a pending (rotated, not yet live) KEK.
fn pending(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".next."))
        .collect();
    v.sort();
    v
}

fn local(kek: &Path) -> Box<dyn SecretStore> {
    Box::new(LocalKekStore::open_or_create(kek).unwrap())
}

fn reopen(state: &Path, kek: &Path) -> Result<KeyBroker, Code> {
    KeyBroker::load(state, verifier(), local(kek))
        .map(|b| b.with_clock(|| T0))
        .map_err(|e| e.code)
}

fn reopen_marked(state: &Path, kek: &Path, mark: Box<dyn GenerationMark>) -> Result<KeyBroker> {
    KeyBroker::load_with_mark(state, verifier(), local(kek), mark)
}

fn file_mark(dir: &Path) -> Box<dyn GenerationMark> {
    Box::new(DevelopmentFileMark::new(&dir.join("mark.json"), BROKER))
}

// --- the shred ------------------------------------------------------------------

/// After a revocation, the older state file (with the revoked key still
/// wrapped in it) and the KEK that is current afterwards do not yield the
/// key: neither the broker nor the cryptography does. A copy of the old KEK
/// still does, which is why the old KEK must not survive (see the root key
/// test below for backups).
#[test]
fn revoking_shreds_the_old_state_for_the_current_kek() {
    let dir = tmp("local");
    let (kek, state) = (dir.join("kek"), dir.join("broker.json"));
    let (old_state, old_kek) = (dir.join("old.json"), dir.join("old-kek"));
    let mut b = broker(local(&kek));
    b.save(&state).unwrap();
    std::fs::copy(&state, &old_state).unwrap();
    std::fs::copy(&kek, &old_kek).unwrap();
    let before = kek_id(&kek);
    assert_eq!(release(&mut b, "patients").unwrap(), PATIENTS);

    assert_eq!(b.revoke_all("patients").unwrap(), vec![1]);
    // The in-memory change alone has not touched the live KEK file: it is
    // replaced only once the state that needs the new one is saved.
    assert_eq!(kek_id(&kek), before);
    assert_eq!(pending(&dir).len(), 1);
    b.save(&state).unwrap();

    let after = kek_id(&kek);
    assert_ne!(after, before, "the revocation replaced the KEK");
    assert_eq!(read_json(&state)["kek_id"], after.as_str());
    assert!(pending(&dir).is_empty(), "{:?}", pending(&dir));
    // The surviving key is released from the new state; the revoked one is not.
    let mut live = reopen(&state, &kek).unwrap();
    assert_eq!(release(&mut live, "labs").unwrap(), LABS);
    assert_eq!(release(&mut live, "patients"), Err(Code::KeyRelease));

    // Restoring the old state file: the broker does not open it under the
    // current KEK...
    std::fs::copy(&old_state, &state).unwrap();
    assert_eq!(reopen(&state, &kek).err(), Some(Code::KeyRelease));
    // ...and the cryptography does not give the revoked key back to it.
    let current = LocalKekStore::open_or_create(&kek).unwrap();
    assert_eq!(recovers(&current, &state, "patients"), None);
    // A copy of the old KEK does (the residual: it must be destroyed too).
    let old = LocalKekStore::open_or_create(&old_kek).unwrap();
    assert_eq!(
        recovers(&old, &state, "patients"),
        Some(PATIENTS.to_vec()),
        "the harness recovers a key when it has the old KEK"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A revocation of a version, and an idempotent repeat, behave the same:
/// one rotation per change, none when nothing was revoked now.
#[test]
fn only_a_revocation_that_changed_something_rotates() {
    let dir = tmp("idem");
    let (kek, state) = (dir.join("kek"), dir.join("broker.json"));
    let mut b = broker(local(&kek));
    b.save(&state).unwrap();
    let k0 = kek_id(&kek);
    b.revoke("patients", None).unwrap();
    b.save(&state).unwrap();
    let k1 = kek_id(&kek);
    assert_ne!(k0, k1);
    // Again: nothing to revoke, so nothing rotates.
    assert!(b.revoke_all("patients").unwrap().is_empty());
    b.save(&state).unwrap();
    assert_eq!(kek_id(&kek), k1);
    // An unrelated change (a new asset's key) never rotates.
    b.add_secret("imaging", None, policy()).unwrap();
    b.save(&state).unwrap();
    assert_eq!(kek_id(&kek), k1);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A store with no KEK it can replace shreds nothing, and says so: the key
/// is destroyed in the current state, and an old state file is as it was.
#[test]
fn a_store_without_a_replaceable_kek_shreds_nothing() {
    // A KEK held in memory only (tests, embedding): no file to replace.
    let mut b = broker(Box::new(LocalKekStore::from_key([5; 32])));
    assert_eq!(b.rotate_kek().unwrap(), None);
    b.revoke_all("patients").unwrap();
    assert_eq!(b.state().kek_id, LocalKekStore::from_key([5; 32]).key_id());
    // Development plaintext storage.
    let mut b = broker(Box::new(encompute_keybroker::DevelopmentFileStore));
    assert_eq!(b.rotate_kek().unwrap(), None);
    b.revoke_all("patients").unwrap();
}

/// Several revocations before one save replace the KEK once the state is
/// written, and the live file is never left naming a key no state needs.
#[test]
fn several_revocations_before_a_save_are_one_state_under_one_new_kek() {
    let dir = tmp("several");
    let (kek, state) = (dir.join("kek"), dir.join("broker.json"));
    let mut b = broker(local(&kek));
    b.save(&state).unwrap();
    let before = kek_id(&kek);
    b.revoke_all("patients").unwrap();
    b.revoke_all("labs").unwrap();
    assert_eq!(pending(&dir).len(), 2, "each rotation's key is kept apart");
    b.save(&state).unwrap();
    assert_ne!(kek_id(&kek), before);
    assert!(pending(&dir).is_empty());
    let mut live = reopen(&state, &kek).unwrap();
    assert_eq!(release(&mut live, "labs"), Err(Code::KeyRelease));
    assert_eq!(release(&mut live, "patients"), Err(Code::KeyRelease));
    std::fs::remove_dir_all(&dir).unwrap();
}

// --- crashes ----------------------------------------------------------------------

/// The broker stops after the revocation but before it saved anything: the
/// state file and the KEK are the old ones and open, the pending key is an
/// orphan that no state needs, and the next committed rotation removes it.
#[test]
fn a_crash_before_the_state_is_written_changes_nothing() {
    let dir = tmp("crash-before");
    let (kek, state) = (dir.join("kek"), dir.join("broker.json"));
    let mut b = broker(local(&kek));
    b.save(&state).unwrap();
    let before = kek_id(&kek);
    b.revoke_all("patients").unwrap();
    drop(b);
    assert_eq!(pending(&dir).len(), 1);
    let mut b = reopen(&state, &kek).unwrap();
    assert_eq!(kek_id(&kek), before);
    // The revocation was never recorded: the control plane retries it.
    assert_eq!(release(&mut b, "patients").unwrap(), PATIENTS);
    b.revoke_all("patients").unwrap();
    b.save(&state).unwrap();
    assert!(pending(&dir).is_empty(), "the orphan is removed");
    assert_ne!(kek_id(&kek), before);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The broker stops after it wrote the state (naming the new KEK) but
/// before the new KEK replaced the old: the next start finds the pending
/// key, opens the state with it, and finishes the replacement.
#[test]
fn a_crash_between_the_state_and_the_kek_replacement_recovers() {
    let dir = tmp("crash-after");
    let (kek, state) = (dir.join("kek"), dir.join("broker.json"));
    let (old_kek, crashed) = (dir.join("old-kek"), dir.join("crashed-kek"));
    let mut b = broker(local(&kek));
    b.save(&state).unwrap();
    std::fs::copy(&kek, &old_kek).unwrap();
    b.revoke_all("patients").unwrap();
    // The crash happens inside `save`, after the state is renamed into
    // place: reproduce its disk with the finished save's own files.
    let pending_file = dir.join(&pending(&dir)[0]);
    std::fs::copy(&pending_file, &crashed).unwrap();
    b.save(&state).unwrap();
    let new_id = kek_id(&kek);
    // The disk as the crash left it: the state under the new KEK, the new
    // KEK still pending, the old one live.
    std::fs::copy(&old_kek, &kek).unwrap();
    std::fs::copy(&crashed, dir.join(format!("kek.next.{new_id}"))).unwrap();
    assert_ne!(kek_id(&kek), new_id);

    let mut b = reopen(&state, &kek).unwrap();
    assert_eq!(kek_id(&kek), new_id, "the start finished the replacement");
    assert!(pending(&dir).is_empty());
    assert_eq!(release(&mut b, "labs").unwrap(), LABS);
    assert_eq!(release(&mut b, "patients"), Err(Code::KeyRelease));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A mark that fails to advance wraps the shred in the same atomicity as
/// the revocation itself: the state is written (naming the new KEK) but the
/// old KEK stays live and nothing is acknowledged; the retry completes it.
#[derive(Clone)]
struct FlakyMark {
    inner: Arc<Mutex<DevelopmentFileMark>>,
    down: Arc<AtomicBool>,
}

impl GenerationMark for FlakyMark {
    fn describe(&self) -> String {
        "flaky".into()
    }
    fn security(&self) -> StoreSecurity {
        StoreSecurity::DevelopmentOnly
    }
    fn read(&self) -> Result<MarkRead> {
        self.inner.lock().unwrap().read()
    }
    fn advance(&self, mark: &Mark, expected_cas: u64) -> Result<u64> {
        if self.down.load(Ordering::SeqCst) {
            return Err(mark_unavailable("flaky", "connection refused"));
        }
        self.inner.lock().unwrap().advance(mark, expected_cas)
    }
}

#[test]
fn the_kek_is_replaced_only_after_the_generation_mark_advanced() {
    let dir = tmp("mark");
    let (kek, state) = (dir.join("kek"), dir.join("broker.json"));
    let flaky = FlakyMark {
        inner: Arc::new(Mutex::new(DevelopmentFileMark::new(
            &dir.join("mark.json"),
            BROKER,
        ))),
        down: Arc::default(),
    };
    let mut b = broker(local(&kek))
        .with_generation_mark(Box::new(flaky.clone()))
        .unwrap();
    b.save(&state).unwrap();
    let before = kek_id(&kek);
    b.revoke_all("patients").unwrap();

    // The KMS is unreachable: the save fails, the old KEK stays live.
    flaky.down.store(true, Ordering::SeqCst);
    let e = b.save(&state).unwrap_err();
    assert_eq!(e.code, Code::GovernanceBrokerStateRollback, "{e}");
    assert_eq!(kek_id(&kek), before);
    assert_eq!(pending(&dir).len(), 1);

    // The retry, with the KMS back, completes the revocation and the shred.
    flaky.down.store(false, Ordering::SeqCst);
    b.save(&state).unwrap();
    assert_ne!(kek_id(&kek), before);
    assert!(pending(&dir).is_empty());

    // A restart under the mark opens the state and releases only the
    // surviving key.
    let mut b = reopen_marked(&state, &kek, Box::new(flaky.clone()))
        .unwrap()
        .with_clock(|| T0);
    assert_eq!(release(&mut b, "labs").unwrap(), LABS);
    assert_eq!(release(&mut b, "patients"), Err(Code::KeyRelease));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The broker stops after writing the state but before advancing the mark
/// (one save ahead, chained to the mark): on restart the state opens with
/// the pending KEK, the mark is advanced, and only then is the KEK made
/// live. A state refused by the mark never promotes a key.
#[test]
fn a_state_one_ahead_of_its_mark_opens_with_the_pending_kek() {
    let dir = tmp("ahead");
    let (kek, state) = (dir.join("kek"), dir.join("broker.json"));
    let (old_kek, old_mark) = (dir.join("old-kek"), dir.join("old-mark.json"));
    let mut b = broker(local(&kek))
        .with_generation_mark(file_mark(&dir))
        .unwrap();
    b.save(&state).unwrap();
    std::fs::copy(&kek, &old_kek).unwrap();
    std::fs::copy(dir.join("mark.json"), &old_mark).unwrap();
    b.revoke_all("patients").unwrap();
    let pending_name = pending(&dir)[0].clone();
    let pending_copy = dir.join("pending-copy");
    std::fs::copy(dir.join(&pending_name), &pending_copy).unwrap();
    b.save(&state).unwrap();
    let new_id = kek_id(&kek);
    // The disk of a crash before the mark advanced: the mark one behind,
    // the old KEK live, the new one pending.
    std::fs::copy(&old_mark, dir.join("mark.json")).unwrap();
    std::fs::copy(&old_kek, &kek).unwrap();
    std::fs::copy(&pending_copy, dir.join(&pending_name)).unwrap();

    let mut b = reopen_marked(&state, &kek, file_mark(&dir))
        .unwrap()
        .with_clock(|| T0);
    assert_eq!(kek_id(&kek), new_id);
    assert!(pending(&dir).is_empty());
    assert_eq!(release(&mut b, "patients"), Err(Code::KeyRelease));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A refused state does not promote a pending key: a state that names the
/// pending KEK but does not continue the mark's history is refused (ENC2713)
/// and the old KEK stays live.
#[test]
fn a_refused_state_promotes_no_pending_kek() {
    let dir = tmp("refused");
    let (kek, state) = (dir.join("kek"), dir.join("broker.json"));
    let (old_kek, old_state) = (dir.join("old-kek"), dir.join("old.json"));
    let mut b = broker(local(&kek))
        .with_generation_mark(file_mark(&dir))
        .unwrap();
    b.save(&state).unwrap();
    std::fs::copy(&state, &old_state).unwrap();
    std::fs::copy(&kek, &old_kek).unwrap();
    b.revoke_all("patients").unwrap();
    let pending_name = pending(&dir)[0].clone();
    let pending_copy = dir.join("pending-copy");
    std::fs::copy(dir.join(&pending_name), &pending_copy).unwrap();
    b.save(&state).unwrap();
    let new_state = dir.join("new.json");
    std::fs::copy(&state, &new_state).unwrap();
    let new_id = kek_id(&kek);
    // Two further saves under the mark: the new state is now older than it.
    b.save(&state).unwrap();
    b.save(&state).unwrap();
    std::fs::copy(&old_kek, &kek).unwrap();
    std::fs::copy(&pending_copy, dir.join(&pending_name)).unwrap();
    std::fs::copy(&new_state, &state).unwrap();
    let e = reopen_marked(&state, &kek, file_mark(&dir)).err().unwrap();
    assert_eq!(e.code, Code::GovernanceBrokerStateRollback, "{e}");
    assert_ne!(kek_id(&kek), new_id, "nothing was promoted");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Restoring an older state file under a mark is refused whatever KEK goes
/// with it, including the old KEK from a backup (the replay of an
/// authentic state after the revocation).
#[test]
fn replaying_an_old_state_with_its_old_kek_is_refused_by_the_mark() {
    let dir = tmp("replay");
    let (kek, state) = (dir.join("kek"), dir.join("broker.json"));
    let (old_kek, old_state) = (dir.join("old-kek"), dir.join("old.json"));
    let mut b = broker(local(&kek))
        .with_generation_mark(file_mark(&dir))
        .unwrap();
    b.save(&state).unwrap();
    std::fs::copy(&state, &old_state).unwrap();
    std::fs::copy(&kek, &old_kek).unwrap();
    b.revoke_all("patients").unwrap();
    b.save(&state).unwrap();
    let live_kek = dir.join("live-kek");
    std::fs::copy(&kek, &live_kek).unwrap();

    std::fs::copy(&old_state, &state).unwrap();
    std::fs::copy(&old_kek, &kek).unwrap();
    let e = reopen_marked(&state, &kek, file_mark(&dir)).err().unwrap();
    assert_eq!(e.code, Code::GovernanceBrokerStateRollback, "{e}");
    // Old state, current KEK: it does not even open.
    std::fs::copy(&live_kek, &kek).unwrap();
    assert!(reopen_marked(&state, &kek, file_mark(&dir)).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

// --- a failed rotation is owed, not dropped -------------------------------------------

/// If the new KEK cannot be made durable (here, a read-only key
/// directory), the revocation still applies in memory and the error is
/// reported, so the control plane retries; the retry, with the directory
/// writable again, rotates (an idempotent revocation never skips the shred).
#[cfg(unix)]
#[test]
fn a_failed_rotation_is_retried_by_the_repeated_revocation() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp("owed");
    let keys = dir.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let (kek, state) = (keys.join("kek"), dir.join("broker.json"));
    let mut b = broker(local(&kek));
    b.save(&state).unwrap();
    let before = kek_id(&kek);
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o500)).unwrap();
    // Root can write anywhere: the check is meaningful only for others.
    let writable = std::fs::File::create(keys.join("probe")).is_ok();
    if !writable {
        let e = b.revoke_all("patients").unwrap_err();
        assert_eq!(e.code, Code::KeyRelease, "{e}");
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Already revoked in memory; the repeat revokes nothing new and
        // still rotates.
        assert!(b.revoke_all("patients").unwrap().is_empty());
        b.save(&state).unwrap();
        assert_ne!(kek_id(&kek), before);
    } else {
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
        eprintln!("SKIPPED: the directory is writable despite mode 0500 (running as root)");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

// --- through the control plane's message ----------------------------------------------

/// A control-plane `asset.revoked` message shreds like a local revocation:
/// the broker's own persist step writes the state, and the KEK on disk is
/// the new one when the message is acknowledged.
#[test]
fn a_control_plane_revocation_message_shreds() {
    let dir = tmp("message");
    let (kek, state) = (dir.join("kek"), dir.join("broker.json"));
    let old_state = dir.join("old.json");
    let mut b = broker(local(&kek));
    b.set_organization("modelco").unwrap();
    b.save(&state).unwrap();
    std::fs::copy(&state, &old_state).unwrap();
    let before = kek_id(&kek);
    let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
    let server = encompute_verification::http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr());
    let channel = ControlChannel::new(
        "keybroker-modelco",
        "control-plane",
        &control.public_key_hex(),
        "modelco",
    );
    let path = state.clone();
    std::thread::spawn(move || {
        let b = Mutex::new(b);
        serve_with_control(&b, server, 1000, Some(&channel), &|b| b.save(&path))
    });
    let m = seal(
        &control,
        "asset.revoked",
        "keybroker-modelco",
        Scope {
            organization: Some("modelco".into()),
            ..Scope::default()
        },
        &serde_json::json!({"asset": "ast_1", "key_ref": "patients", "key_version": 1}),
        300,
    )
    .unwrap();
    let v = signed_call(
        &ureq::AgentBuilder::new().build(),
        &control,
        &url,
        "keybroker-modelco",
        "POST",
        "/v1/messages",
        &Default::default(),
        &serde_json::to_value(&m).unwrap(),
    )
    .unwrap();
    assert_eq!(v["revoked_versions"], serde_json::json!([1]));
    let after = kek_id(&kek);
    assert_ne!(after, before);
    assert_eq!(read_json(&state)["kek_id"], after.as_str());
    assert!(pending(&dir).is_empty());
    // The state from before the message, with the KEK that is current.
    std::fs::copy(&old_state, &state).unwrap();
    let current = LocalKekStore::open_or_create(&kek).unwrap();
    assert_eq!(recovers(&current, &state, "patients"), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

// --- a root-wrapped KEK -------------------------------------------------------------

fn root_store(wrapped: &Path, root: &Path) -> RootWrappedKekStore {
    RootWrappedKekStore::open_or_create(
        wrapped,
        Box::new(DevelopmentRootKey::open(root).unwrap()),
        ORG,
    )
    .unwrap()
}

/// With a KEK wrapped under a root key, a revocation replaces the wrapped
/// KEK too; but its old wrapped copy (a backup) still opens while the root
/// key version that wraps it does. Rotating the root key and retiring its
/// older versions closes that: the backup's wrapped KEK, and so the old
/// state file's revoked key, are gone for good.
#[test]
fn a_root_wrapped_kek_is_shredded_by_retiring_the_old_root_versions() {
    let dir = tmp("root");
    let (wrapped, root, state) = (
        dir.join("kek.wrapped.json"),
        dir.join("root.json"),
        dir.join("broker.json"),
    );
    let (old_state, old_wrapped) = (dir.join("old.json"), dir.join("old.wrapped.json"));
    let mut b = broker(Box::new(root_store(&wrapped, &root)));
    b.save(&state).unwrap();
    std::fs::copy(&state, &old_state).unwrap();
    std::fs::copy(&wrapped, &old_wrapped).unwrap();
    let before = read_json(&wrapped)["kek_id"].clone();

    b.revoke_all("patients").unwrap();
    b.save(&state).unwrap();
    let after = read_json(&wrapped)["kek_id"].clone();
    let new_state = dir.join("new.json");
    std::fs::copy(&state, &new_state).unwrap();
    assert_ne!(before, after, "the wrapped KEK was replaced");
    assert!(pending(&dir).is_empty());
    let mut live = KeyBroker::load(&state, verifier(), Box::new(root_store(&wrapped, &root)))
        .unwrap()
        .with_clock(|| T0);
    assert_eq!(release(&mut live, "labs").unwrap(), LABS);
    assert_eq!(release(&mut live, "patients"), Err(Code::KeyRelease));

    // The old state with the current wrapped KEK: shredded.
    std::fs::copy(&old_state, &state).unwrap();
    assert_eq!(
        recovers(&root_store(&wrapped, &root), &state, "patients"),
        None
    );
    // The backup's wrapped KEK is still opened by the unretired root key:
    // the residual, until the root versions are retired.
    let backup = root_store(&old_wrapped, &root);
    assert_eq!(
        recovers(&backup, &state, "patients"),
        Some(PATIENTS.to_vec())
    );
    drop(backup);

    // Rotate the root key (re-wrapping the live KEK under version 2) and
    // retire version 1.
    let mut s = root_store(&wrapped, &root);
    let r = s.rotate_root().unwrap();
    assert_eq!((r.old_version, r.new_version), (1, 2));
    assert_eq!(s.retire_older_root_versions().unwrap(), 2);
    let e = RootWrappedKekStore::open_or_create(
        &old_wrapped,
        Box::new(DevelopmentRootKey::open(&root).unwrap()),
        ORG,
    )
    .err()
    .expect("the backup's wrapped KEK no longer opens");
    assert_eq!(e.code, Code::KeyRelease);
    // The live broker is unaffected: its state and wrapped KEK still open.
    std::fs::copy(&new_state, &state).unwrap();
    let mut live = KeyBroker::load(&state, verifier(), Box::new(root_store(&wrapped, &root)))
        .unwrap()
        .with_clock(|| T0);
    assert_eq!(release(&mut live, "labs").unwrap(), LABS);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A crash between the state and the wrapped KEK's replacement recovers
/// for a root-wrapped KEK as for a local one.
#[test]
fn a_root_wrapped_crash_between_the_state_and_the_replacement_recovers() {
    let dir = tmp("root-crash");
    let (wrapped, root, state) = (
        dir.join("kek.wrapped.json"),
        dir.join("root.json"),
        dir.join("broker.json"),
    );
    let (old_wrapped, new_wrapped) = (dir.join("old.wrapped.json"), dir.join("new.wrapped.json"));
    let mut b = broker(Box::new(root_store(&wrapped, &root)));
    b.save(&state).unwrap();
    std::fs::copy(&wrapped, &old_wrapped).unwrap();
    b.revoke_all("patients").unwrap();
    b.save(&state).unwrap();
    std::fs::copy(&wrapped, &new_wrapped).unwrap();
    let new_id = read_json(&wrapped)["kek_id"].as_str().unwrap().to_owned();
    // The crash's disk: the old wrapped KEK live, the new one pending.
    std::fs::copy(&old_wrapped, &wrapped).unwrap();
    std::fs::copy(
        &new_wrapped,
        dir.join(format!("kek.wrapped.json.next.{new_id}")),
    )
    .unwrap();
    let mut b = KeyBroker::load(&state, verifier(), Box::new(root_store(&wrapped, &root)))
        .unwrap()
        .with_clock(|| T0);
    assert_eq!(read_json(&wrapped)["kek_id"], new_id.as_str());
    assert!(pending(&dir).is_empty());
    assert_eq!(release(&mut b, "labs").unwrap(), LABS);
    assert_eq!(release(&mut b, "patients"), Err(Code::KeyRelease));
    std::fs::remove_dir_all(&dir).unwrap();
}
