//! Key broker restarts during key release and revocation. A restarted
//! broker is a new server over the persisted state file (what a new
//! process sees). Challenges and attested sessions are in memory only:
//! after a restart a workload re-attests, and nothing issued before the
//! crash releases a key. A revocation that was not persisted was not
//! acknowledged, so the control plane delivers it again; applied twice it
//! changes nothing.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use serde_json::json;

use encompute_attestation::mock::{MockHardware, MockProvider};
use encompute_attestation::{AttestationPolicy, Attester, TeeKind, Verifier, WorkloadSession};
use encompute_ir::Code;
use encompute_keybroker::{
    serve_with_control, BrokerClient, BrokerMode, ControlChannel, DevelopmentFileStore, KeyBroker,
    KeyMaterial,
};
use encompute_verification::http::Server;
use encompute_verification::service::{seal, Scope};
use encompute_verification::{EvaluatorSigner, ServiceSigner};

const SPEC: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const POLICY: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const ARTIFACT: &str = "33333333333333333333333333333333333333333333333333333333333333cc";
const IMAGE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const ME: &str = "keybroker-a";
const KEY: &[u8] = b"patients key";

fn hw() -> MockHardware {
    MockHardware::from_seed(&[7; 32])
}

fn verifier() -> Verifier {
    Verifier::new().with(MockProvider::new(&hw().public_key()).unwrap())
}

fn control() -> ServiceSigner {
    ServiceSigner::from_seed("control-plane", &[42; 32]).unwrap()
}

/// A directory of its own for each call: the tests run in parallel, and
/// the clock alone (microseconds on macOS) can give two of them one path.
fn tmp() -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "encompute-kb-restart-{}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn new_state(path: &Path) {
    let mut b = KeyBroker::new(
        "hospital",
        BrokerMode::Development,
        verifier(),
        Box::new(DevelopmentFileStore),
    )
    .unwrap();
    // A broker serves one organization; revocations name it.
    b.set_organization("hospital").unwrap();
    let mut p = AttestationPolicy::new(SPEC, Some(POLICY));
    p.allowed_tee = vec![TeeKind::Mock];
    p.allowed_images = vec![IMAGE.into()];
    p.allow_development = true;
    b.add_secret("patients", Some(KeyMaterial::from_bytes(KEY).unwrap()), p)
        .unwrap();
    b.save(path).unwrap();
}

/// A broker process over the state at `path`; `fail_persist` makes its
/// next state write fail (a crash before the write reached the disk).
fn start(path: &Path, fail_persist: &'static AtomicBool) -> BrokerClient {
    let b = KeyBroker::load(path, verifier(), Box::new(DevelopmentFileStore)).unwrap();
    let server = Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr());
    let path = path.to_owned();
    std::thread::spawn(move || {
        let ch = ControlChannel::new(ME, "control-plane", &control().public_key_hex(), "hospital");
        let b = Mutex::new(b);
        serve_with_control(&b, server, 10_000, Some(&ch), &|b| {
            if fail_persist.swap(false, Ordering::SeqCst) {
                return Err(encompute_ir::Error::new(
                    Code::KeyRelease,
                    "the process died before the state was written",
                ));
            }
            b.save(&path)
        })
    });
    BrokerClient::new(&url)
}

fn session() -> WorkloadSession {
    WorkloadSession::new(&EvaluatorSigner::from_seed(&[9; 32]).identity())
}

fn evidence(
    c: &encompute_attestation::AttestationChallenge,
    s: &WorkloadSession,
) -> encompute_attestation::AttestationEvidence {
    hw().attester(IMAGE)
        .attest(c, &s.binding(c, SPEC, Some(POLICY), ARTIFACT))
        .unwrap()
}

#[test]
fn a_restart_forgets_challenges_and_sessions_never_keys() {
    let dir = tmp();
    let state = dir.join("broker.json");
    new_state(&state);
    static NEVER: AtomicBool = AtomicBool::new(false);
    let b = start(&state, &NEVER);
    let s = session();
    // A challenge issued, then the broker restarts before it is answered.
    let ch = b.challenge().unwrap();
    let b = start(&state, &NEVER);
    let e = b.attest(&evidence(&ch, &s)).unwrap_err();
    assert_eq!(e.code, Code::Freshness, "{e}");
    // A session opened, then the broker restarts before the release.
    let ch = b.challenge().unwrap();
    let info = b.attest(&evidence(&ch, &s)).unwrap();
    let b = start(&state, &NEVER);
    let e = b.release(&info.session, "patients").unwrap_err();
    assert_eq!(e.code, Code::KeyRelease, "{e}");
    // The workload attests again and gets its key.
    let ch = b.challenge().unwrap();
    let info = b.attest(&evidence(&ch, &s)).unwrap();
    let g = b.release(&info.session, "patients").unwrap();
    assert_eq!(s.open(&g).unwrap().as_slice(), KEY);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_unpersisted_revocation_is_not_acknowledged_and_is_applied_on_redelivery() {
    let dir = tmp();
    let state = dir.join("broker.json");
    new_state(&state);
    static FAIL_ONCE: AtomicBool = AtomicBool::new(true);
    static NEVER: AtomicBool = AtomicBool::new(false);
    let cp = control();
    let m = seal(
        &cp,
        "asset.revoked",
        ME,
        Scope {
            organization: Some("hospital".into()),
            ..Scope::default()
        },
        &json!({"asset": "ast_1", "key_ref": "patients", "key_version": 1}),
        3600,
    )
    .unwrap();
    let body = serde_json::to_vec(&m).unwrap();
    let deliver = |b: &BrokerClient| {
        let h = cp
            .sign_request("POST", "/v1/messages", ME, &Default::default(), &body)
            .unwrap();
        let mut r = ureq::post(&format!("{}/v1/messages", b.url()));
        for (k, v) in h.to_pairs() {
            r = r.set(k, &v);
        }
        match r.send_bytes(&body) {
            Ok(r) => (r.status(), r.into_json::<serde_json::Value>().unwrap()),
            Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap()),
            Err(e) => panic!("{e}"),
        }
    };
    // The write fails (the process dies there): not acknowledged, so the
    // control plane's outbox keeps the message.
    let b = start(&state, &FAIL_ONCE);
    let (s, v) = deliver(&b);
    assert_ne!(s, 200, "{v}");
    // The restarted broker still holds the key (nothing was persisted) and
    // would release it, until the redelivery arrives.
    let b = start(&state, &NEVER);
    let s1 = session();
    let ch = b.challenge().unwrap();
    let info = b.attest(&evidence(&ch, &s1)).unwrap();
    assert_eq!(
        s1.open(&b.release(&info.session, "patients").unwrap())
            .unwrap()
            .as_slice(),
        KEY
    );
    let (s, v) = deliver(&b);
    assert_eq!((s, &v["revoked_versions"]), (200, &json!([1])), "{v}");
    // Delivered again (at least once): no change. Restarted: still revoked.
    let (s, v) = deliver(&b);
    assert_eq!((s, &v["revoked_versions"]), (200, &json!([])), "{v}");
    let b = start(&state, &NEVER);
    let ch = b.challenge().unwrap();
    let info = b.attest(&evidence(&ch, &s1)).unwrap();
    let e = b.release(&info.session, "patients").unwrap_err();
    assert_eq!(e.code, Code::KeyRelease, "{e}");
    std::fs::remove_dir_all(&dir).unwrap();
}
