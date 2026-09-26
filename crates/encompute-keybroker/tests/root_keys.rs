//! Customer-managed root keys: the broker's KEK wrapped under an
//! organization's root key in OpenBao/Vault Transit (or, for development, a
//! local file). Wrap, unwrap, rotate, revoke, disable, the wrong
//! organization, the wrong key version and an unavailable provider: every
//! failure is an error, never a fallback to local or plaintext keys.
//!
//! The OpenBao tests need a Transit engine: set `ENCOMPUTE_TEST_BAO_ADDR`
//! and `ENCOMPUTE_TEST_BAO_TOKEN` (a dev server is enough:
//! `bao server -dev`, then `bao secrets enable transit`). Without them they
//! are skipped, unless `ENCOMPUTE_REQUIRE_SERVICES=1` (CI), where a missing
//! service fails the test.

use std::path::{Path, PathBuf};

use encompute_attestation::mock::{MockHardware, MockProvider};
use encompute_attestation::{AttestationPolicy, Attester, TeeKind, Verifier, WorkloadSession};
use encompute_ir::Code;
use encompute_keybroker::{
    BrokerMode, DevelopmentRootKey, KeyBroker, KeyMaterial, OpenBaoTransit, RootKeyProvider,
    RootWrappedKekStore, SecretStore,
};
use encompute_verification::EvaluatorSigner;
use zeroize::Zeroizing;

const SPEC: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const POLICY: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const ARTIFACT: &str = "33333333333333333333333333333333333333333333333333333333333333cc";
const IMAGE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const T0: u64 = 1_900_000_000;
const KEY: &[u8; 32] = b"hospital patient-data key 32 by.";

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
    let d = std::env::temp_dir().join(format!(
        "encompute-root-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// An attested workload asks `broker` for `asset`: the key, or the error code.
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

fn broker(mode: BrokerMode, store: Box<dyn SecretStore>) -> KeyBroker {
    let mut b = KeyBroker::new("hospital", mode, verifier(), store)
        .unwrap()
        .with_clock(|| T0);
    b.add_secret(
        "patients",
        Some(KeyMaterial::from_bytes(KEY).unwrap()),
        policy(),
    )
    .unwrap();
    b
}

fn reopen(state: &Path, store: Box<dyn SecretStore>) -> Result<KeyBroker, Code> {
    KeyBroker::load(state, verifier(), store)
        .map(|b| b.with_clock(|| T0))
        .map_err(|e| e.code)
}

#[test]
fn development_root_key_wraps_rotates_and_is_refused_in_production() {
    let dir = tmp("dev");
    let roots = dir.join("roots.json");
    let kek = dir.join("kek.wrapped.json");
    let store = |org: &str| {
        RootWrappedKekStore::open_or_create(
            &kek,
            Box::new(DevelopmentRootKey::open(&roots).unwrap()),
            org,
        )
    };
    let mut b = broker(
        BrokerMode::Development,
        Box::new(store("hospital-a").unwrap()),
    );
    assert_eq!(release(&mut b, "patients").unwrap(), KEY);
    let state = dir.join("broker.json");
    b.save(&state).unwrap();
    let text = std::fs::read_to_string(&state).unwrap();
    assert!(text.contains(RootWrappedKekStore::NAME));
    let hex_key: String = KEY.iter().map(|x| format!("{x:02x}")).collect();
    assert!(!text.contains(&hex_key), "{text}");

    // Root rotation re-wraps the KEK only; asset keys are untouched.
    let mut s = store("hospital-a").unwrap();
    let r = s.rotate_root().unwrap();
    assert_eq!((r.old_version, r.new_version), (1, 2));
    assert_eq!(std::fs::read_to_string(&state).unwrap(), text);
    let mut b = reopen(&state, Box::new(store("hospital-a").unwrap())).unwrap();
    assert_eq!(release(&mut b, "patients").unwrap(), KEY);

    // Another organization's name cannot open this KEK.
    assert_eq!(store("hospital-b").err().unwrap().code, Code::KeyRelease);

    // A production broker refuses a development root key.
    let e = KeyBroker::new(
        "hospital",
        BrokerMode::Production,
        verifier(),
        Box::new(store("hospital-a").unwrap()),
    )
    .err()
    .unwrap();
    assert_eq!(e.code, Code::KeyRelease);
    assert!(e.message.contains("development only"), "{e}");
    std::fs::remove_dir_all(&dir).unwrap();
}

// --- OpenBao / Vault Transit -----------------------------------------------------

struct Bao {
    addr: String,
    token: String,
}

fn bao() -> Option<Bao> {
    match (
        std::env::var("ENCOMPUTE_TEST_BAO_ADDR"),
        std::env::var("ENCOMPUTE_TEST_BAO_TOKEN"),
    ) {
        (Ok(addr), Ok(token)) => Some(Bao { addr, token }),
        _ if std::env::var("ENCOMPUTE_REQUIRE_SERVICES").is_ok() => {
            panic!("ENCOMPUTE_REQUIRE_SERVICES is set but ENCOMPUTE_TEST_BAO_ADDR is not")
        }
        _ => {
            eprintln!("SKIPPED: set ENCOMPUTE_TEST_BAO_ADDR and ENCOMPUTE_TEST_BAO_TOKEN");
            None
        }
    }
}

impl Bao {
    fn admin(&self, method: &str, path: &str, body: serde_json::Value) {
        let url = format!("{}/v1/{path}", self.addr);
        let r = ureq::request(method, &url)
            .set("X-Vault-Token", &self.token)
            .send_json(body);
        match r {
            Ok(_) | Err(ureq::Error::Status(400, _)) => {} // mount already enabled
            Err(e) => panic!("{method} {path}: {e}"),
        }
    }

    /// A fresh root key for one organization.
    fn new_key(&self, name: &str) -> String {
        self.admin(
            "POST",
            "sys/mounts/transit",
            serde_json::json!({"type": "transit"}),
        );
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let key = format!(
            "{name}-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        self.admin(
            "POST",
            &format!("transit/keys/{key}"),
            serde_json::json!({}),
        );
        key
    }

    fn provider(&self, key: &str) -> Box<dyn RootKeyProvider> {
        Box::new(
            OpenBaoTransit::new(
                &self.addr,
                "transit",
                key,
                Zeroizing::new(self.token.clone()),
            )
            .unwrap(),
        )
    }
}

#[test]
fn openbao_wraps_unwraps_rotates_rewraps_and_revokes() {
    let Some(bao) = bao() else { return };
    let key = bao.new_key("org-a");
    let dir = tmp("bao");
    let kek = dir.join("kek.wrapped.json");
    let store =
        RootWrappedKekStore::open_or_create(&kek, bao.provider(&key), "hospital-a").unwrap();
    assert_eq!(store.wrapped().key_version, 1);
    assert!(store.wrapped().ciphertext.starts_with("vault:v1:"));
    // A production store: a production broker accepts it. (The releases
    // below use development attestation, so they run on a development
    // broker with the same store.)
    let open = || RootWrappedKekStore::open_or_create(&kek, bao.provider(&key), "hospital-a");
    KeyBroker::new(
        "hospital",
        BrokerMode::Production,
        verifier(),
        Box::new(open().unwrap()),
    )
    .unwrap();
    let mut b = broker(BrokerMode::Development, Box::new(store));
    assert_eq!(release(&mut b, "patients").unwrap(), KEY);
    let state = dir.join("broker.json");
    b.save(&state).unwrap();
    let before = std::fs::read_to_string(&state).unwrap();

    // Reopened through the provider: same KEK, same keys.
    let mut b = reopen(&state, Box::new(open().unwrap())).unwrap();
    assert_eq!(release(&mut b, "patients").unwrap(), KEY);

    // Root rotation: the KEK is re-wrapped under version 2 inside the
    // provider; the broker's state (every asset key) is unchanged.
    let r = open().unwrap().rotate_root().unwrap();
    assert_eq!((r.old_version, r.new_version), (1, 2));
    assert!(r.key_ref.ends_with(&format!("/transit/keys/{key}")));
    let s = open().unwrap();
    assert!(s.wrapped().ciphertext.starts_with("vault:v2:"));
    assert_eq!(std::fs::read_to_string(&state).unwrap(), before);
    let mut b = reopen(&state, Box::new(s)).unwrap();
    assert_eq!(release(&mut b, "patients").unwrap(), KEY);

    // Revocation destroys the asset key: no new release.
    b.revoke("patients", None).unwrap();
    assert_eq!(release(&mut b, "patients").unwrap_err(), Code::KeyRelease);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn openbao_failures_never_fall_back() {
    let Some(bao) = bao() else { return };
    let key_a = bao.new_key("org-a");
    let key_b = bao.new_key("org-b");
    let dir = tmp("bao-fail");
    let kek = dir.join("kek.wrapped.json");
    RootWrappedKekStore::open_or_create(&kek, bao.provider(&key_a), "hospital-a").unwrap();
    let v1 = std::fs::read(&kek).unwrap();
    let refused = |r: encompute_ir::Result<RootWrappedKekStore>| {
        let e = r.err().expect("opened");
        assert_eq!(e.code, Code::KeyRelease, "{e}");
        e.message
    };

    // Wrong organization: the file names another one.
    refused(RootWrappedKekStore::open_or_create(
        &kek,
        bao.provider(&key_a),
        "hospital-b",
    ));
    // Another organization's root key: refused by name, and a forged file
    // naming it does not decrypt (the ciphertext is bound to root key A).
    refused(RootWrappedKekStore::open_or_create(
        &kek,
        bao.provider(&key_b),
        "hospital-a",
    ));
    let mut forged: serde_json::Value = serde_json::from_slice(&v1).unwrap();
    forged["key_ref"] = bao.provider(&key_b).key_ref().into();
    std::fs::write(&kek, serde_json::to_vec(&forged).unwrap()).unwrap();
    let m = refused(RootWrappedKekStore::open_or_create(
        &kek,
        bao.provider(&key_b),
        "hospital-a",
    ));
    assert!(m.contains("refused"), "{m}");
    // The wrapped KEK moved to another organization's file does not open:
    // the organization is authenticated data.
    let mut moved: serde_json::Value = serde_json::from_slice(&v1).unwrap();
    moved["organization"] = "hospital-b".into();
    std::fs::write(&kek, serde_json::to_vec(&moved).unwrap()).unwrap();
    refused(RootWrappedKekStore::open_or_create(
        &kek,
        bao.provider(&key_a),
        "hospital-b",
    ));
    std::fs::write(&kek, &v1).unwrap();

    // Wrong key version: after rotation, the customer retires version 1.
    let mut s =
        RootWrappedKekStore::open_or_create(&kek, bao.provider(&key_a), "hospital-a").unwrap();
    s.rotate_root().unwrap();
    bao.admin(
        "POST",
        &format!("transit/keys/{key_a}/config"),
        serde_json::json!({"min_decryption_version": 2}),
    );
    RootWrappedKekStore::open_or_create(&kek, bao.provider(&key_a), "hospital-a").unwrap();
    let stale = dir.join("stale.json");
    std::fs::write(&stale, &v1).unwrap();
    refused(RootWrappedKekStore::open_or_create(
        &stale,
        bao.provider(&key_a),
        "hospital-a",
    ));

    // Disabled (deleted) root key: nothing opens.
    bao.admin(
        "POST",
        &format!("transit/keys/{key_a}/config"),
        serde_json::json!({"deletion_allowed": true}),
    );
    bao.admin(
        "DELETE",
        &format!("transit/keys/{key_a}"),
        serde_json::json!({}),
    );
    refused(RootWrappedKekStore::open_or_create(
        &kek,
        bao.provider(&key_a),
        "hospital-a",
    ));

    // Provider unavailable, or a bad token: an error, not a fallback.
    let down = OpenBaoTransit::new(
        "http://127.0.0.1:1",
        "transit",
        &key_b,
        Zeroizing::new(bao.token.clone()),
    )
    .unwrap();
    let m = refused(RootWrappedKekStore::open_or_create(
        &dir.join("new.json"),
        Box::new(down),
        "hospital-a",
    ));
    assert!(m.contains("unavailable"), "{m}");
    assert!(
        !dir.join("new.json").exists(),
        "no KEK was written without the provider"
    );
    let bad =
        OpenBaoTransit::new(&bao.addr, "transit", &key_b, Zeroizing::new("wrong".into())).unwrap();
    refused(RootWrappedKekStore::open_or_create(
        &dir.join("new.json"),
        Box::new(bad),
        "hospital-a",
    ));
    assert!(!dir.join("new.json").exists());

    // Plain HTTP only on loopback; an empty token is refused.
    let tok = || Zeroizing::new("t".to_owned());
    assert!(OpenBaoTransit::new("http://bao.internal:8200", "transit", "k", tok()).is_err());
    assert!(OpenBaoTransit::new("https://bao.internal:8200", "transit", "k", tok()).is_ok());
    assert!(OpenBaoTransit::new("https://bao.internal:8200", "transit", "../k", tok()).is_err());
    assert!(OpenBaoTransit::new(
        "https://bao.internal:8200",
        "transit",
        "k",
        Zeroizing::new(String::new())
    )
    .is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}
