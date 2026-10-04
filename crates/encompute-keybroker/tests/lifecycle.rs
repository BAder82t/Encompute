//! Key lifecycle review: create, wrap, unwrap, rotate (asset keys and the
//! organization's root key), disable, revoke, destroy and restore, all
//! through the OpenBao/Vault Transit root key provider; and, for every piece
//! of configuration, proof that a production broker never falls back to
//! development storage.
//!
//! The OpenBao tests need a Transit engine: set `ENCOMPUTE_TEST_BAO_ADDR`
//! and `ENCOMPUTE_TEST_BAO_TOKEN` (a dev server is enough: `bao server
//! -dev`). Without them they are skipped, unless `ENCOMPUTE_REQUIRE_SERVICES`
//! is set (CI), where a missing service fails the test.

use std::path::{Path, PathBuf};

use encompute_attestation::mock::{MockHardware, MockProvider};
use encompute_attestation::{AttestationPolicy, Attester, TeeKind, Verifier, WorkloadSession};
use encompute_ir::Code;
use encompute_keybroker::{
    BrokerMode, DevelopmentFileStore, DevelopmentRootKey, KeyBroker, KeyMaterial, LocalKekStore,
    OpenBaoTransit, RootKeyProvider, RootWrappedKekStore, SecretStore,
};
use encompute_verification::EvaluatorSigner;
use serde_json::{json, Value};
use zeroize::Zeroizing;

const SPEC: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const POLICY: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const ARTIFACT: &str = "33333333333333333333333333333333333333333333333333333333333333cc";
const IMAGE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const T0: u64 = 1_900_000_000;
const KEY: &[u8; 32] = b"hospital patient-data key 32 by.";
const ORG: &str = "hospital-a";

// --- helpers --------------------------------------------------------------------

fn hw() -> MockHardware {
    MockHardware::from_seed(&[7; 32])
}

fn verifier() -> Verifier {
    Verifier::new().with(MockProvider::new(&hw().public_key()).unwrap())
}

/// A development release policy (mock TEE): releases in these tests run on
/// development brokers that use the same production (OpenBao) store.
fn dev_policy() -> AttestationPolicy {
    let mut p = AttestationPolicy::new(SPEC, Some(POLICY));
    p.allowed_tee = vec![TeeKind::Mock];
    p.allowed_images = vec![IMAGE.into()];
    p.allow_development = true;
    p
}

/// A production release policy (real TEE only).
fn prod_policy() -> AttestationPolicy {
    let mut p = AttestationPolicy::new(SPEC, Some(POLICY));
    p.allowed_tee = vec![TeeKind::IntelTdx];
    p.allowed_images = vec![IMAGE.into()];
    p
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "encompute-lifecycle-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// An attested (mock) workload asks `broker` for `asset`: the key, or the
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

/// A development broker holding `KEY` for `patients`.
fn dev_broker(store: Box<dyn SecretStore>) -> KeyBroker {
    let mut b = KeyBroker::new("hospital", BrokerMode::Development, verifier(), store)
        .unwrap()
        .with_clock(|| T0);
    b.add_secret(
        "patients",
        Some(KeyMaterial::from_bytes(KEY).unwrap()),
        dev_policy(),
    )
    .unwrap();
    b
}

fn reopen(state: &Path, store: Box<dyn SecretStore>) -> Result<KeyBroker, Code> {
    KeyBroker::load(state, verifier(), store)
        .map(|b| b.with_clock(|| T0))
        .map_err(|e| e.code)
}

fn code<T>(r: encompute_ir::Result<T>) -> Code {
    match r {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e.code,
    }
}

fn read_json(p: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn write_json(p: &Path, v: &Value) {
    std::fs::write(p, serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

/// The stored form (`wrapped`, `destroyed`, `plaintext`) of a key version in
/// a saved state file.
fn form(state: &Path, asset: &str, v: u64) -> String {
    read_json(state)["secrets"][asset]["versions"][v.to_string()]["key"]["form"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// --- OpenBao / Vault Transit ------------------------------------------------------

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

fn unique(name: &str) -> String {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!(
        "{name}-{}-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

impl Bao {
    /// An API call as `token`: (status, body).
    fn call_as(&self, token: &str, method: &str, path: &str, body: Value) -> (u16, Value) {
        let url = format!("{}/v1/{path}", self.addr);
        let r = ureq::request(method, &url)
            .set("X-Vault-Token", token)
            .send_json(body);
        let (status, resp) = match r {
            Ok(resp) => (resp.status(), resp),
            Err(ureq::Error::Status(s, resp)) => (s, resp),
            Err(e) => panic!("{method} {path}: {e}"),
        };
        (status, resp.into_json().unwrap_or(Value::Null))
    }

    /// An admin call that must succeed (400 = mount already enabled).
    fn admin(&self, method: &str, path: &str, body: Value) -> Value {
        let (s, v) = self.call_as(&self.token, method, path, body);
        assert!(s < 300 || s == 400, "{method} {path}: {s} {v}");
        v
    }

    /// A fresh root key for one organization, on the `transit` mount.
    fn new_key(&self, name: &str) -> String {
        self.admin("POST", "sys/mounts/transit", json!({"type": "transit"}));
        let key = unique(name);
        self.admin("POST", &format!("transit/keys/{key}"), json!({}));
        key
    }

    fn provider_as(&self, mount: &str, key: &str, token: &str) -> Box<dyn RootKeyProvider> {
        Box::new(OpenBaoTransit::new(&self.addr, mount, key, Zeroizing::new(token.into())).unwrap())
    }

    fn provider(&self, key: &str) -> Box<dyn RootKeyProvider> {
        self.provider_as("transit", key, &self.token)
    }

    fn open(&self, kek: &Path, key: &str) -> encompute_ir::Result<RootWrappedKekStore> {
        RootWrappedKekStore::open_or_create(kek, self.provider(key), ORG)
    }

    /// A token limited to `capabilities` on `key`'s transit endpoints.
    fn limited_token(&self, key: &str, rules: &[(&str, &str)]) -> String {
        let hcl: String = rules
            .iter()
            .map(|(endpoint, caps)| {
                format!("path \"transit/{endpoint}/{key}\" {{ capabilities = [{caps}] }}\n")
            })
            .collect();
        let name = unique("lifecycle-policy");
        self.admin(
            "PUT",
            &format!("sys/policies/acl/{name}"),
            json!({"policy": hcl}),
        );
        let v = self.admin(
            "POST",
            "auth/token/create",
            json!({"policies": [name], "no_default_policy": true, "ttl": "10m"}),
        );
        v["auth"]["client_token"].as_str().unwrap().to_owned()
    }

    fn min_decryption_version(&self, key: &str, v: u64) {
        self.admin(
            "POST",
            &format!("transit/keys/{key}/config"),
            json!({"min_decryption_version": v}),
        );
    }

    fn delete_key(&self, key: &str) {
        self.admin(
            "POST",
            &format!("transit/keys/{key}/config"),
            json!({"deletion_allowed": true}),
        );
        self.admin("DELETE", &format!("transit/keys/{key}"), json!({}));
    }
}

/// Create → wrap → unwrap → rotate → revoke → rotate for asset keys, with a
/// root-wrapped KEK in OpenBao. Wrapped keys are bound to their broker,
/// asset and version.
#[test]
fn lifecycle_create_wrap_unwrap_and_rotate_asset_keys() {
    let Some(bao) = bao() else { return };
    let key = bao.new_key("lc-create");
    let dir = tmp("create");
    let kek = dir.join("kek.wrapped.json");
    let state = dir.join("broker.json");

    // Create: a random KEK, wrapped by root key version 1; the file names
    // the organization, provider and root key, never the KEK.
    let store = bao.open(&kek, &key).unwrap();
    let w = read_json(&kek);
    assert_eq!(w["organization"], ORG);
    assert_eq!(w["provider"], "openbao-transit");
    assert!(w["key_ref"]
        .as_str()
        .unwrap()
        .ends_with(&format!("/transit/keys/{key}")));
    assert_eq!(w["key_version"], 1);
    assert!(w["ciphertext"].as_str().unwrap().starts_with("vault:v1:"));
    let kek_id = store.wrapped().kek_id.clone();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&kek).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // Wrap: the state file holds the asset key wrapped under that KEK.
    let b = dev_broker(Box::new(store));
    b.save(&state).unwrap();
    let s = read_json(&state);
    assert_eq!(s["store"], RootWrappedKekStore::NAME);
    assert_eq!(s["kek_id"], kek_id.as_str());
    let v1 = &s["secrets"]["patients"]["versions"]["1"]["key"];
    assert_eq!(v1["form"], "wrapped");
    assert_eq!(v1["store"], RootWrappedKekStore::NAME);
    assert_eq!(v1["kek_id"], kek_id.as_str());
    let text = std::fs::read_to_string(&state).unwrap();
    assert!(!text.contains(&hex(KEY)), "plaintext key in {text}");

    // Unwrap: only for release, through the provider after a reopen.
    let mut b = reopen(&state, Box::new(bao.open(&kek, &key).unwrap())).unwrap();
    assert_eq!(release(&mut b, "patients").unwrap(), KEY);

    // Rotate: version 2 is a fresh key and the only one released.
    assert_eq!(b.rotate_key("patients").unwrap(), 2);
    let k2 = release(&mut b, "patients").unwrap();
    assert_eq!(k2.len(), 32);
    assert_ne!(k2, KEY);
    b.save(&state).unwrap();
    assert_eq!(form(&state, "patients", 1), "wrapped");
    assert_eq!(form(&state, "patients", 2), "wrapped");
    let mut b = reopen(&state, Box::new(bao.open(&kek, &key).unwrap())).unwrap();
    assert_eq!(release(&mut b, "patients").unwrap(), k2);

    // Revoking the current version stops release until the next rotation.
    assert_eq!(b.revoke("patients", None).unwrap(), 2);
    assert_eq!(release(&mut b, "patients").err().unwrap(), Code::KeyRelease);
    assert_eq!(b.rotate_key("patients").unwrap(), 3);
    let k3 = release(&mut b, "patients").unwrap();
    assert!(k3 != KEY && k3 != k2);
    b.save(&state).unwrap();

    // Binding: version 1's wrapped key moved into version 3's slot is an
    // edit of the authenticated state, so the broker does not open; nothing
    // is released in its place.
    let mut s = read_json(&state);
    s["secrets"]["patients"]["versions"]["3"]["key"] =
        s["secrets"]["patients"]["versions"]["1"]["key"].clone();
    write_json(&state, &s);
    assert_eq!(
        reopen(&state, Box::new(bao.open(&kek, &key).unwrap()))
            .err()
            .unwrap(),
        Code::KeyRelease
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Root rotation re-wraps only the KEK; once the customer retires old root
/// versions, an old wrapped KEK no longer opens. A token that may not rotate
/// leaves everything as it was.
#[test]
fn lifecycle_root_key_rotation_rewraps_only_the_kek() {
    let Some(bao) = bao() else { return };
    let key = bao.new_key("lc-rotate");
    let dir = tmp("rotate");
    let kek = dir.join("kek.wrapped.json");
    let state = dir.join("broker.json");
    let b = dev_broker(Box::new(bao.open(&kek, &key).unwrap()));
    b.save(&state).unwrap();
    let state_v1 = std::fs::read(&state).unwrap();
    let kek_v1 = std::fs::read(&kek).unwrap();

    let mut s = bao.open(&kek, &key).unwrap();
    let kek_id = s.wrapped().kek_id.clone();
    let r = s.rotate_root().unwrap();
    assert_eq!((r.old_version, r.new_version), (1, 2));
    assert_eq!(r.organization, ORG);
    let r = s.rotate_root().unwrap();
    assert_eq!((r.old_version, r.new_version), (2, 3));
    let w = read_json(&kek);
    assert_eq!(w["key_version"], 3);
    assert!(w["ciphertext"].as_str().unwrap().starts_with("vault:v3:"));
    assert_eq!(w["kek_id"], kek_id.as_str(), "the KEK itself is unchanged");
    assert_eq!(
        std::fs::read(&state).unwrap(),
        state_v1,
        "asset keys untouched"
    );

    // The customer retires versions 1 and 2: the current KEK still opens,
    // a backup of the version-1 wrapped KEK does not.
    bao.min_decryption_version(&key, 3);
    let mut b = reopen(&state, Box::new(bao.open(&kek, &key).unwrap())).unwrap();
    assert_eq!(release(&mut b, "patients").unwrap(), KEY);
    let old = dir.join("kek.v1.json");
    std::fs::write(&old, &kek_v1).unwrap();
    let e = bao.open(&old, &key).err().unwrap();
    assert_eq!(e.code, Code::KeyRelease);
    assert!(e.message.contains("refused"), "{e}");

    // A token that may encrypt and decrypt but not rotate: rotation fails
    // and the wrapped KEK on disk is unchanged.
    let token = bao.limited_token(
        &key,
        &[("encrypt", "\"update\""), ("decrypt", "\"update\"")],
    );
    let before = std::fs::read(&kek).unwrap();
    let mut s =
        RootWrappedKekStore::open_or_create(&kek, bao.provider_as("transit", &key, &token), ORG)
            .unwrap();
    assert_eq!(code(s.rotate_root()), Code::KeyRelease);
    assert_eq!(std::fs::read(&kek).unwrap(), before);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Disabling the root key in any way the provider offers (retired versions,
/// a revoked token, a token without decrypt, a disabled mount, a deleted
/// key) stops every reopen with ENC2004. A broker already open keeps its KEK
/// in memory until it restarts.
#[test]
fn lifecycle_disabled_root_key_refuses_every_reopen() {
    let Some(bao) = bao() else { return };
    let dir = tmp("disable");
    let refused = |r: encompute_ir::Result<RootWrappedKekStore>| {
        let e = r.err().expect("opened");
        assert_eq!(e.code, Code::KeyRelease, "{e}");
        e.message
    };

    // min_decryption_version above the wrapped KEK's version.
    let key = bao.new_key("lc-min");
    let kek = dir.join("min.json");
    let state = dir.join("min-broker.json");
    let mut open_broker = dev_broker(Box::new(bao.open(&kek, &key).unwrap()));
    open_broker.save(&state).unwrap();
    bao.admin("POST", &format!("transit/keys/{key}/rotate"), json!({}));
    bao.min_decryption_version(&key, 2);
    let m = refused(bao.open(&kek, &key));
    assert!(m.contains("refused"), "{m}");
    // Residual: the running broker still holds its KEK.
    assert_eq!(release(&mut open_broker, "patients").unwrap(), KEY);

    // A token revoked after the broker was set up.
    let key = bao.new_key("lc-token");
    let kek = dir.join("token.json");
    let token = bao.limited_token(
        &key,
        &[("encrypt", "\"update\""), ("decrypt", "\"update\"")],
    );
    let as_token = |kek: &Path| {
        RootWrappedKekStore::open_or_create(kek, bao.provider_as("transit", &key, &token), ORG)
    };
    as_token(&kek).unwrap();
    as_token(&kek).unwrap();
    bao.admin("POST", "auth/token/revoke", json!({"token": token}));
    let m = refused(as_token(&kek));
    assert!(m.contains("refused (403)"), "{m}");
    assert!(!m.contains(&token), "the token is never printed: {m}");
    // Nor can it create a new KEK.
    refused(as_token(&dir.join("token-new.json")));
    assert!(!dir.join("token-new.json").exists());

    // A token that may encrypt (create) but not decrypt.
    let key = bao.new_key("lc-nodecrypt");
    let kek = dir.join("nodecrypt.json");
    let token = bao.limited_token(&key, &[("encrypt", "\"update\"")]);
    let p = || bao.provider_as("transit", &key, &token);
    RootWrappedKekStore::open_or_create(&kek, p(), ORG).unwrap();
    refused(RootWrappedKekStore::open_or_create(&kek, p(), ORG));

    // The whole Transit mount disabled.
    let mount = unique("lc-mount");
    bao.admin(
        "POST",
        &format!("sys/mounts/{mount}"),
        json!({"type": "transit"}),
    );
    bao.admin("POST", &format!("{mount}/keys/org"), json!({}));
    let kek = dir.join("mount.json");
    let p = || bao.provider_as(&mount, "org", &bao.token);
    RootWrappedKekStore::open_or_create(&kek, p(), ORG).unwrap();
    bao.admin("DELETE", &format!("sys/mounts/{mount}"), json!({}));
    refused(RootWrappedKekStore::open_or_create(&kek, p(), ORG));

    // The root key deleted.
    let key = bao.new_key("lc-deleted");
    let kek = dir.join("deleted.json");
    let state = dir.join("deleted-broker.json");
    dev_broker(Box::new(bao.open(&kek, &key).unwrap()))
        .save(&state)
        .unwrap();
    bao.delete_key(&key);
    refused(bao.open(&kek, &key));
    // Nothing falls back: the state file does not open with any
    // development store either.
    assert_eq!(
        reopen(&state, Box::new(DevelopmentFileStore))
            .err()
            .unwrap(),
        Code::KeyRelease
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Revocation destroys the material in the state file: the version is
/// `destroyed`, its ciphertext is gone, it is never released again, and
/// neither a KEK re-wrap nor a root rotation brings it back.
#[test]
fn lifecycle_revoked_versions_are_destroyed_for_good() {
    let Some(bao) = bao() else { return };
    let key = bao.new_key("lc-destroy");
    let dir = tmp("destroy");
    let kek = dir.join("kek.wrapped.json");
    let state = dir.join("broker.json");
    let mut b = dev_broker(Box::new(bao.open(&kek, &key).unwrap()));
    b.rotate_key("patients").unwrap();
    b.save(&state).unwrap();
    let ct1 = read_json(&state)["secrets"]["patients"]["versions"]["1"]["key"]["ciphertext"]
        .as_str()
        .unwrap()
        .to_owned();

    // Revoke an old version: destroyed, not merely flagged.
    assert_eq!(b.revoke("patients", Some(1)).unwrap(), 1);
    b.save(&state).unwrap();
    assert_eq!(form(&state, "patients", 1), "destroyed");
    assert_eq!(
        read_json(&state)["secrets"]["patients"]["versions"]["1"]["revoked"],
        true
    );
    assert!(!std::fs::read_to_string(&state).unwrap().contains(&ct1));
    let k2 = release(&mut b, "patients").unwrap();

    // Revoke everything (the control plane's revocation): idempotent.
    assert_eq!(b.revoke_all("patients").unwrap(), vec![2]);
    assert_eq!(b.revoke_all("patients").unwrap(), Vec::<u64>::new());
    assert_eq!(release(&mut b, "patients").err().unwrap(), Code::KeyRelease);
    b.save(&state).unwrap();
    assert_eq!(form(&state, "patients", 2), "destroyed");

    // Clearing the revoked flag in the file is an edit of the
    // authenticated state: the broker does not open (and there would be
    // no material to unwrap anyway).
    let saved = std::fs::read(&state).unwrap();
    let mut s = read_json(&state);
    s["secrets"]["patients"]["versions"]["2"]["revoked"] = false.into();
    write_json(&state, &s);
    assert_eq!(
        reopen(&state, Box::new(bao.open(&kek, &key).unwrap()))
            .err()
            .unwrap(),
        Code::KeyRelease
    );
    std::fs::write(&state, &saved).unwrap();

    // Root rotation, then a re-wrap under a brand-new root-wrapped KEK:
    // destroyed versions stay destroyed.
    bao.open(&kek, &key).unwrap().rotate_root().unwrap();
    let mut b = reopen(&state, Box::new(bao.open(&kek, &key).unwrap())).unwrap();
    let kek2 = dir.join("kek2.wrapped.json");
    b.rewrap(Box::new(bao.open(&kek2, &key).unwrap())).unwrap();
    b.save(&state).unwrap();
    assert_eq!(form(&state, "patients", 1), "destroyed");
    assert_eq!(form(&state, "patients", 2), "destroyed");
    let mut b = reopen(&state, Box::new(bao.open(&kek2, &key).unwrap())).unwrap();
    let r = release(&mut b, "patients");
    assert_eq!(r.err().unwrap(), Code::KeyRelease);

    // A new version is a new key, never the destroyed ones.
    b.rotate_key("patients").unwrap();
    let k3 = release(&mut b, "patients").unwrap();
    assert!(k3 != KEY && k3 != k2);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Back up the broker state and the wrapped KEK, lose them, restore them:
/// the broker reopens through OpenBao with the same keys. A restore under
/// the wrong organization, root key or KEK is refused.
#[test]
fn lifecycle_restore_metadata_from_backup() {
    let Some(bao) = bao() else { return };
    let key = bao.new_key("lc-restore");
    let other = bao.new_key("lc-restore-other");
    let dir = tmp("restore");
    let backup = tmp("restore-backup");
    let kek = dir.join("kek.wrapped.json");
    let state = dir.join("broker.json");
    dev_broker(Box::new(bao.open(&kek, &key).unwrap()))
        .save(&state)
        .unwrap();
    for f in ["broker.json", "kek.wrapped.json"] {
        std::fs::copy(dir.join(f), backup.join(f)).unwrap();
    }
    let restore = || {
        for f in ["broker.json", "kek.wrapped.json"] {
            std::fs::copy(backup.join(f), dir.join(f)).unwrap();
        }
    };

    // Lost: the state file does not open, and a missing wrapped KEK is
    // replaced by a NEW one that the state refuses (no key is released
    // under it).
    std::fs::remove_file(&state).unwrap();
    std::fs::remove_file(&kek).unwrap();
    assert_eq!(
        reopen(&state, Box::new(DevelopmentFileStore))
            .err()
            .unwrap(),
        Code::KeyRelease
    );
    let fresh = bao.open(&kek, &key).unwrap();
    std::fs::copy(backup.join("broker.json"), &state).unwrap();
    assert_eq!(
        reopen(&state, Box::new(fresh)).err().unwrap(),
        Code::KeyRelease
    );

    // Restored: same KEK, same keys, through the provider.
    restore();
    let mut b = reopen(&state, Box::new(bao.open(&kek, &key).unwrap())).unwrap();
    assert_eq!(release(&mut b, "patients").unwrap(), KEY);

    let refused = |r: encompute_ir::Result<RootWrappedKekStore>| {
        let e = r.err().expect("opened");
        assert_eq!(e.code, Code::KeyRelease, "{e}");
        e.message
    };
    // Restored into another organization's deployment.
    refused(RootWrappedKekStore::open_or_create(
        &kek,
        bao.provider(&key),
        "hospital-b",
    ));
    // The organization edited to match: it is authenticated data.
    let mut w = read_json(&kek);
    w["organization"] = "hospital-b".into();
    write_json(&kek, &w);
    refused(RootWrappedKekStore::open_or_create(
        &kek,
        bao.provider(&key),
        "hospital-b",
    ));
    restore();
    // Opened with another root key: refused by reference; the reference
    // edited to match does not decrypt.
    refused(bao.open(&kek, &other));
    let mut w = read_json(&kek);
    w["key_ref"] = bao.provider(&other).key_ref().into();
    write_json(&kek, &w);
    let m = refused(bao.open(&kek, &other));
    assert!(m.contains("refused"), "{m}");
    restore();
    // A tampered KEK fingerprint.
    let mut w = read_json(&kek);
    w["kek_id"] = "00".repeat(16).into();
    write_json(&kek, &w);
    let m = refused(bao.open(&kek, &key));
    assert!(m.contains("fingerprint"), "{m}");
    restore();
    // A state file naming another KEK, or another broker's wrapped KEK.
    let mut s = read_json(&state);
    s["kek_id"] = "00".repeat(16).into();
    write_json(&state, &s);
    assert_eq!(
        reopen(&state, Box::new(bao.open(&kek, &key).unwrap()))
            .err()
            .unwrap(),
        Code::KeyRelease
    );
    restore();
    let foreign = dir.join("foreign.json");
    let foreign_store = bao.open(&foreign, &key).unwrap();
    assert_eq!(
        reopen(&state, Box::new(foreign_store)).err().unwrap(),
        Code::KeyRelease
    );
    // The untouched backup still opens.
    let mut b = reopen(&state, Box::new(bao.open(&kek, &key).unwrap())).unwrap();
    assert_eq!(release(&mut b, "patients").unwrap(), KEY);
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&backup).unwrap();
}

/// A revocation crypto-shreds: it destroys the key in the broker's state
/// file and replaces the KEK, so restoring an OLDER state file (taken before
/// the revocation) with the current wrapped KEK no longer opens, and the
/// revoked key is not released. (Before the shred, this very restore
/// released the revoked key.) A copy of the old wrapped KEK is dealt with
/// by retiring the old root key versions: see the next test.
#[test]
fn lifecycle_restoring_an_older_state_file_cannot_release_a_revoked_key() {
    let Some(bao) = bao() else { return };
    let key = bao.new_key("lc-rollback");
    let dir = tmp("rollback");
    let kek = dir.join("kek.wrapped.json");
    let state = dir.join("broker.json");
    let old = dir.join("broker.before-revocation.json");
    dev_broker(Box::new(bao.open(&kek, &key).unwrap()))
        .save(&state)
        .unwrap();
    std::fs::copy(&state, &old).unwrap();
    let kek_before = read_json(&kek)["kek_id"].clone();

    let mut b = reopen(&state, Box::new(bao.open(&kek, &key).unwrap())).unwrap();
    b.revoke_all("patients").unwrap();
    b.save(&state).unwrap();
    assert_eq!(form(&state, "patients", 1), "destroyed");
    assert_ne!(
        read_json(&kek)["kek_id"],
        kek_before,
        "the KEK was replaced"
    );
    let mut b = reopen(&state, Box::new(bao.open(&kek, &key).unwrap())).unwrap();
    assert_eq!(release(&mut b, "patients").err().unwrap(), Code::KeyRelease);

    // Even after a root rotation that retires the old root version.
    let mut s = bao.open(&kek, &key).unwrap();
    s.rotate_root().unwrap();
    bao.min_decryption_version(&key, 2);

    // Restore the pre-revocation state file.
    std::fs::copy(&old, &state).unwrap();
    assert_eq!(form(&state, "patients", 1), "wrapped");
    assert_eq!(
        reopen(&state, Box::new(bao.open(&kek, &key).unwrap()))
            .err()
            .unwrap(),
        Code::KeyRelease,
        "a rolled-back state file does not open under the KEK that replaced its own"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The wrapped KEK a backup holds is not secret and opens while the root
/// key version that wraps it does: until then, the backup's old state file
/// and its wrapped KEK still yield the revoked key. Rotating the root key
/// and retiring the old versions (`retire_older_root_versions`, after every
/// other KEK under the key was re-wrapped) destroys that for good, in the
/// KMS.
#[test]
fn lifecycle_retiring_old_root_versions_closes_the_backups_copy_of_the_kek() {
    let Some(bao) = bao() else { return };
    let key = bao.new_key("lc-retire");
    let dir = tmp("retire");
    let (kek, state) = (dir.join("kek.wrapped.json"), dir.join("broker.json"));
    let (old_kek, old_state) = (dir.join("old.kek.json"), dir.join("old.broker.json"));
    dev_broker(Box::new(bao.open(&kek, &key).unwrap()))
        .save(&state)
        .unwrap();
    std::fs::copy(&kek, &old_kek).unwrap();
    std::fs::copy(&state, &old_state).unwrap();
    let mut b = reopen(&state, Box::new(bao.open(&kek, &key).unwrap())).unwrap();
    b.revoke_all("patients").unwrap();
    b.save(&state).unwrap();
    let new_state = dir.join("new.broker.json");
    std::fs::copy(&state, &new_state).unwrap();

    // The backup (old state and its own wrapped KEK) still opens: the
    // residual until the old root versions are retired.
    std::fs::copy(&old_state, &state).unwrap();
    let mut b = reopen(&state, Box::new(bao.open(&old_kek, &key).unwrap())).unwrap();
    assert_eq!(release(&mut b, "patients").unwrap(), KEY);

    let mut s = bao.open(&kek, &key).unwrap();
    let r = s.rotate_root().unwrap();
    assert_eq!(s.retire_older_root_versions().unwrap(), r.new_version);
    assert_eq!(code(bao.open(&old_kek, &key)), Code::KeyRelease);
    // The live broker still opens.
    std::fs::copy(&new_state, &state).unwrap();
    let mut b = reopen(&state, Box::new(bao.open(&kek, &key).unwrap())).unwrap();
    assert_eq!(release(&mut b, "patients").err().unwrap(), Code::KeyRelease);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The manual route to the same end, to a KEK in another file (a revocation
/// now replaces the KEK itself): after revoking, re-wrap the surviving keys
/// under a NEW KEK, rotate the root key and retire the old root versions.
/// The pre-revocation backup (state + wrapped KEK) then no longer opens.
#[test]
fn lifecycle_revocation_survives_rollback_after_kek_rotation_and_root_retirement() {
    let Some(bao) = bao() else { return };
    let key = bao.new_key("lc-mitigate");
    let dir = tmp("mitigate");
    let backup = tmp("mitigate-backup");
    let kek = dir.join("kek.wrapped.json");
    let state = dir.join("broker.json");
    let mut b = dev_broker(Box::new(bao.open(&kek, &key).unwrap()));
    b.add_secret("labs", None, dev_policy()).unwrap();
    b.save(&state).unwrap();
    for f in ["broker.json", "kek.wrapped.json"] {
        std::fs::copy(dir.join(f), backup.join(f)).unwrap();
    }
    let labs = release(&mut b, "labs").unwrap();

    b.revoke_all("patients").unwrap();
    let kek2 = dir.join("kek2.wrapped.json");
    b.rewrap(Box::new(bao.open(&kek2, &key).unwrap())).unwrap();
    b.save(&state).unwrap();
    bao.open(&kek2, &key).unwrap().rotate_root().unwrap();
    bao.min_decryption_version(&key, 2);
    std::fs::remove_file(&kek).unwrap();

    // The live broker: the surviving key is still released, the revoked
    // one is not.
    let mut b = reopen(&state, Box::new(bao.open(&kek2, &key).unwrap())).unwrap();
    assert_eq!(release(&mut b, "labs").unwrap(), labs);
    assert_eq!(release(&mut b, "patients").err().unwrap(), Code::KeyRelease);

    // Rolled back: the old wrapped KEK no longer opens, and the old state
    // file does not open under the new KEK.
    for f in ["broker.json", "kek.wrapped.json"] {
        std::fs::copy(backup.join(f), dir.join(f)).unwrap();
    }
    assert_eq!(code(bao.open(&kek, &key)), Code::KeyRelease);
    assert_eq!(
        reopen(&state, Box::new(bao.open(&kek2, &key).unwrap()))
            .err()
            .unwrap(),
        Code::KeyRelease
    );
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&backup).unwrap();
}

// --- no fallback to development storage in production -----------------------------

fn local_kek(dir: &Path) -> Box<dyn SecretStore> {
    Box::new(LocalKekStore::open_or_create(&dir.join("local.kek")).unwrap())
}

fn dev_root_store(dir: &Path) -> RootWrappedKekStore {
    RootWrappedKekStore::open_or_create(
        &dir.join("dev-kek.wrapped.json"),
        Box::new(DevelopmentRootKey::open(&dir.join("dev-roots.json")).unwrap()),
        ORG,
    )
    .unwrap()
}

/// A production broker with a production store, holding a key under a
/// production policy.
fn prod_broker(store: Box<dyn SecretStore>) -> KeyBroker {
    let mut b = KeyBroker::new("hospital", BrokerMode::Production, verifier(), store)
        .unwrap()
        .with_clock(|| T0);
    b.add_secret(
        "patients",
        Some(KeyMaterial::from_bytes(KEY).unwrap()),
        prod_policy(),
    )
    .unwrap();
    b
}

/// Every development piece is refused by a production broker, with the
/// exact error code, and a refusal changes nothing.
fn assert_production_refuses_development(
    dir: &Path,
    prod_store: impl Fn() -> Box<dyn SecretStore>,
) {
    let refused_with = |c: Code, r: encompute_ir::Result<KeyBroker>, what: &str| {
        let e = r.err().unwrap_or_else(|| panic!("{what}: accepted"));
        assert_eq!(e.code, c, "{what}: {e}");
        e.message
    };
    let new =
        |s: Box<dyn SecretStore>| KeyBroker::new("hospital", BrokerMode::Production, verifier(), s);

    // Development stores and root keys, for a new broker.
    let m = refused_with(
        Code::KeyRelease,
        new(Box::new(DevelopmentFileStore)),
        "file store",
    );
    assert!(m.contains("development only"), "{m}");
    let m = refused_with(
        Code::KeyRelease,
        new(Box::new(dev_root_store(dir))),
        "dev root",
    );
    assert!(m.contains("development only"), "{m}");

    // A production state file, opened with development stores.
    let state = dir.join("prod-broker.json");
    let mut b = prod_broker(prod_store());
    b.save(&state).unwrap();
    let saved = std::fs::read(&state).unwrap();
    for (what, s) in [
        (
            "file store",
            Box::new(DevelopmentFileStore) as Box<dyn SecretStore>,
        ),
        ("dev root", Box::new(dev_root_store(dir))),
    ] {
        let r = KeyBroker::load(&state, verifier(), s);
        let m = refused_with(Code::KeyRelease, r, what);
        assert!(m.contains("development only"), "{what}: {m}");
    }
    // The mode flipped to development in the file: the development store
    // still does not match the store the keys are in.
    let mut s = read_json(&state);
    s["mode"] = "development".into();
    write_json(&state, &s);
    let r = KeyBroker::load(&state, verifier(), Box::new(DevelopmentFileStore));
    let m = refused_with(Code::KeyRelease, r, "flipped mode");
    assert!(m.contains("open it with that store"), "{m}");
    std::fs::write(&state, &saved).unwrap();

    // Rewrap to development storage: refused, and nothing moved.
    for s in [
        Box::new(DevelopmentFileStore) as Box<dyn SecretStore>,
        Box::new(dev_root_store(dir)),
    ] {
        let e = b.rewrap(s).expect_err("rewrap accepted");
        assert_eq!(e.code, Code::KeyRelease, "{e}");
        assert!(e.message.contains("cannot move keys"), "{e}");
    }
    b.save(&state).unwrap();
    let unsealed = |b: &[u8]| {
        let mut v: Value = serde_json::from_slice(b).unwrap();
        let o = v.as_object_mut().unwrap();
        o.remove("generation");
        o.remove("mac");
        v
    };
    assert_eq!(
        unsealed(&std::fs::read(&state).unwrap()),
        unsealed(&saved),
        "only the generation and its MAC change"
    );
    assert_eq!(form(&state, "patients", 1), "wrapped");

    // Development policies and development (mock) evidence.
    let e = b.add_secret("labs", None, dev_policy()).err().unwrap();
    assert_eq!(e.code, Code::WorkloadPolicy, "{e}");
    let e = b.set_policy("patients", dev_policy()).err().unwrap();
    assert_eq!(e.code, Code::WorkloadPolicy, "{e}");
    assert!(b.secret("labs").is_none());
    assert_eq!(
        release(&mut b, "patients").err().unwrap(),
        Code::WorkloadPolicy
    );
    // A production policy naming the mock TEE is invalid everywhere.
    let mut p = prod_policy();
    p.allowed_tee = vec![TeeKind::Mock];
    let e = b.add_secret("labs", None, p).err().unwrap();
    assert_eq!(e.code, Code::WorkloadPolicy, "{e}");
}

#[test]
fn production_never_falls_back_to_development_storage_local_kek() {
    let dir = tmp("prod-local");
    assert_production_refuses_development(&dir, || local_kek(&dir));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn production_never_falls_back_to_development_storage_openbao() {
    let Some(bao) = bao() else { return };
    let key = bao.new_key("lc-prod");
    let dir = tmp("prod-bao");
    let kek = dir.join("kek.wrapped.json");
    assert_production_refuses_development(&dir, || Box::new(bao.open(&kek, &key).unwrap()));

    // The production broker reopens through OpenBao, and only through it.
    let state = dir.join("prod-broker.json");
    let b = reopen(&state, Box::new(bao.open(&kek, &key).unwrap())).unwrap();
    assert_eq!(b.mode(), BrokerMode::Production);
    assert_eq!(
        reopen(&state, local_kek(&dir)).err().unwrap(),
        Code::KeyRelease
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Provider misconfiguration: missing or empty token, plain HTTP off
/// loopback, a malformed mount or key, an unreachable provider, a wrong
/// token, a wrong mount or key. Each is ENC2004 and writes no KEK.
#[test]
fn production_provider_misconfiguration_is_refused() {
    let tok = |t: &str| Zeroizing::new(t.to_owned());
    let bad = |r: encompute_ir::Result<OpenBaoTransit>, what: &str| {
        let e = r.err().unwrap_or_else(|| panic!("{what}: accepted"));
        assert_eq!(e.code, Code::KeyRelease, "{what}: {e}");
        e.message
    };
    let m = bad(
        OpenBaoTransit::new("https://bao.internal:8200", "transit", "k", tok("")),
        "empty token",
    );
    assert!(m.contains("token"), "{m}");
    for addr in [
        "http://bao.internal:8200",
        "http://10.0.0.5:8200",
        "http://127.0.0.1.evil.example:8200",
        "http://localhost.evil.example",
        "http://127.0.0.1@evil.example:8200",
        "http://127.0.0.1:8200@evil.example",
        "http://localhost:@evil.example",
        "http://[::1].evil.example",
        "bao.internal:8200",
        "ftp://bao.internal",
    ] {
        let m = bad(OpenBaoTransit::new(addr, "transit", "k", tok("t")), addr);
        assert!(m.contains("https"), "{addr}: {m}");
    }
    for addr in [
        "https://bao.internal:8200",
        "http://127.0.0.1:58200",
        "http://localhost",
        "http://localhost:8200/",
        "http://[::1]:8200",
    ] {
        OpenBaoTransit::new(addr, "transit", "k", tok("t"))
            .unwrap_or_else(|e| panic!("{addr}: {e}"));
    }
    for (mount, key) in [
        ("", "k"),
        ("transit", ""),
        ("../sys", "k"),
        ("transit", "k/rotate"),
    ] {
        bad(
            OpenBaoTransit::new("https://bao.internal:8200", mount, key, tok("t")),
            &format!("{mount}/{key}"),
        );
    }

    let dir = tmp("misconfig");
    let kek = dir.join("kek.wrapped.json");
    let unreachable =
        OpenBaoTransit::new("http://127.0.0.1:1", "transit", "org", tok("t")).unwrap();
    let e = RootWrappedKekStore::open_or_create(&kek, Box::new(unreachable), ORG)
        .err()
        .unwrap();
    assert_eq!(e.code, Code::KeyRelease, "{e}");
    assert!(e.message.contains("unavailable"), "{e}");
    assert!(!kek.exists(), "no KEK without the provider");
    let e = RootWrappedKekStore::open_or_create(&kek, Box::new(NeverProvider), "")
        .err()
        .unwrap();
    assert_eq!(e.code, Code::KeyRelease, "{e}");

    if let Some(bao) = bao() {
        let key = bao.new_key("lc-misconfig");
        bao.open(&kek, &key).unwrap();
        let saved = std::fs::read(&kek).unwrap();
        // A wrong token, a wrong mount, a wrong key: refused, file unchanged.
        let wrong_token = bao.provider_as("transit", &key, "not-a-token");
        let e = RootWrappedKekStore::open_or_create(&kek, wrong_token, ORG)
            .err()
            .unwrap();
        assert_eq!(e.code, Code::KeyRelease, "{e}");
        assert!(e.message.contains("refused (403)"), "{e}");
        let wrong_mount = bao.provider_as("transit-missing", &key, &bao.token);
        let e = RootWrappedKekStore::open_or_create(&kek, wrong_mount, ORG)
            .err()
            .unwrap();
        assert_eq!(e.code, Code::KeyRelease, "{e}");
        let wrong_key = bao.provider_as("transit", "no-such-key", &bao.token);
        let e = RootWrappedKekStore::open_or_create(&kek, wrong_key, ORG)
            .err()
            .unwrap();
        assert_eq!(e.code, Code::KeyRelease, "{e}");
        assert_eq!(std::fs::read(&kek).unwrap(), saved);
        // A new KEK through a mount that does not exist is never written.
        let new = dir.join("new.json");
        let e = RootWrappedKekStore::open_or_create(
            &new,
            bao.provider_as(&unique("no-mount"), "org", &bao.token),
            ORG,
        )
        .err()
        .unwrap();
        assert_eq!(e.code, Code::KeyRelease, "{e}");
        assert!(!new.exists());
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A provider that must never be consulted (the organization check comes
/// first).
struct NeverProvider;

impl RootKeyProvider for NeverProvider {
    fn provider(&self) -> &'static str {
        "never"
    }
    fn key_ref(&self) -> String {
        "never".into()
    }
    fn security(&self) -> encompute_keybroker::StoreSecurity {
        encompute_keybroker::StoreSecurity::Production
    }
    fn encrypt(&self, _: &[u8], _: &[u8]) -> encompute_ir::Result<(String, u64)> {
        panic!("consulted")
    }
    fn decrypt(&self, _: &str, _: &[u8]) -> encompute_ir::Result<Zeroizing<Vec<u8>>> {
        panic!("consulted")
    }
    fn rewrap(&self, _: &str, _: &[u8]) -> encompute_ir::Result<(String, u64)> {
        panic!("consulted")
    }
    fn rotate(&self) -> encompute_ir::Result<u64> {
        panic!("consulted")
    }
}
