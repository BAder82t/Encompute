//! The broker's state file is authenticated under its KEK (review finding
//! KB-2): whoever can write `broker.json` or its backup, but holds neither
//! the KEK nor the root key, cannot change what is released, or to whom.

use encompute_attestation::mock::{MockHardware, MockProvider};
use encompute_attestation::{
    AttestationPolicy, Attester, DebugPolicy, TcbStatus, TeeKind, Verifier, WorkloadSession,
};
use encompute_ir::Code;
use encompute_keybroker::{
    BrokerMode, KeyBroker, KeyContext, KeyMaterial, LocalKekStore, SecretStore, StoreSecurity,
    StoredKey,
};
use encompute_verification::EvaluatorSigner;
use serde_json::Value;

const SPEC: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const POLICY: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const ARTIFACT: &str = "33333333333333333333333333333333333333333333333333333333333333cc";
const IMAGE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const EVIL_IMAGE: &str = "sha256:6666666666666666666666666666666666666666666666666666666666666666";
const KEK: [u8; 32] = [5; 32];

fn hw() -> MockHardware {
    MockHardware::from_seed(&[7; 32])
}

fn verifier() -> Verifier {
    Verifier::new().with(MockProvider::new(&hw().public_key()).unwrap())
}

fn kek() -> Box<dyn SecretStore> {
    Box::new(LocalKekStore::from_key(KEK))
}

fn policy() -> AttestationPolicy {
    let mut p = AttestationPolicy::new(SPEC, Some(POLICY));
    p.allowed_tee = vec![TeeKind::Mock];
    p.allowed_images = vec![IMAGE.into()];
    p.allow_development = true;
    p
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "encompute-kb-state-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A development-mode broker whose keys are wrapped under a KEK, holding
/// `patients` (rotated once: version 1 is superseded, not revoked).
fn saved_broker(path: &std::path::Path) {
    let mut b = KeyBroker::new("hospital", BrokerMode::Development, verifier(), kek()).unwrap();
    b.set_organization("hospital").unwrap();
    b.add_secret(
        "patients",
        Some(KeyMaterial::from_bytes(b"patients-key-v1").unwrap()),
        policy(),
    )
    .unwrap();
    b.rotate_key("patients").unwrap();
    b.save(path).unwrap();
}

/// Attests as `image` and asks for `patients`.
fn release_to(b: &mut KeyBroker, image: &str) -> encompute_ir::Result<Vec<u8>> {
    let session = WorkloadSession::new(&EvaluatorSigner::generate().unwrap().identity());
    let c = b.challenge().unwrap();
    let e = hw()
        .attester(image)
        .attest(&c, &session.binding(&c, SPEC, Some(POLICY), ARTIFACT))
        .unwrap();
    let (_, grant) = b.release_with(&e, "patients")?;
    Ok(session.open(&grant).unwrap().to_vec())
}

fn edit(path: &std::path::Path, f: impl FnOnce(&mut Value)) {
    let mut v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    f(&mut v);
    std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

/// Review finding KB-2 (ENC-SF-2026-043, the proof of concept, inverted): adding the
/// attacker's image to a release policy in the state file no longer
/// releases the key to it; the edited file does not open at all. The same
/// holds for every other field that gates release.
#[test]
fn an_edited_state_file_does_not_open() {
    let dir = tmp("edit");
    let path = dir.join("broker.json");
    saved_broker(&path);
    let saved = std::fs::read(&path).unwrap();

    // The untouched state opens, releases to the approved image only.
    let mut b = KeyBroker::load(&path, verifier(), kek()).unwrap();
    assert_eq!(
        release_to(&mut b, EVIL_IMAGE).unwrap_err().code,
        Code::WorkloadPolicy
    );
    assert_eq!(
        release_to(&mut b, IMAGE).unwrap().len(),
        32,
        "the current (rotated) key"
    );

    type Edit = (&'static str, Box<dyn Fn(&mut Value)>);
    let edits: Vec<Edit> = vec![
        (
            "attacker image allowed",
            Box::new(|v| {
                v["secrets"]["patients"]["release_policy"]["allowed_images"]
                    .as_array_mut()
                    .unwrap()
                    .push(EVIL_IMAGE.into())
            }),
        ),
        (
            "images replaced",
            Box::new(|v| {
                v["secrets"]["patients"]["release_policy"]["allowed_images"] =
                    serde_json::json!([EVIL_IMAGE])
            }),
        ),
        (
            "debug allowed",
            Box::new(|v| {
                v["secrets"]["patients"]["release_policy"]["debug"] =
                    serde_json::to_value(DebugPolicy::Allowed).unwrap()
            }),
        ),
        (
            "minimum TCB lowered",
            Box::new(|v| {
                v["secrets"]["patients"]["release_policy"]["minimum_tcb"] =
                    serde_json::to_value(TcbStatus::Unknown).unwrap()
            }),
        ),
        (
            "evidence age widened",
            Box::new(|v| {
                v["secrets"]["patients"]["release_policy"]["max_evidence_age_secs"] =
                    u64::MAX.into()
            }),
        ),
        (
            "execution spec replaced",
            Box::new(|v| {
                v["secrets"]["patients"]["release_policy"]["execution_spec_id"] =
                    "ff".repeat(32).into()
            }),
        ),
        (
            "mode flipped",
            Box::new(|v| v["mode"] = "production".into()),
        ),
        (
            "organization changed",
            Box::new(|v| v["organization"] = "attacker".into()),
        ),
        (
            "asset organization changed",
            Box::new(|v| v["secrets"]["patients"]["organization"] = "attacker".into()),
        ),
        (
            "superseded key version made current again",
            Box::new(|v| v["secrets"]["patients"]["key_version"] = 1.into()),
        ),
        (
            "current version marked revoked",
            Box::new(|v| v["secrets"]["patients"]["versions"]["2"]["revoked"] = true.into()),
        ),
        (
            "grant-signing key removed (a new one would be made)",
            Box::new(|v| {
                v.as_object_mut().unwrap().remove("grant_signing_key");
            }),
        ),
        (
            "generation rewound",
            Box::new(|v| v["generation"] = 0.into()),
        ),
        (
            "MAC of another state",
            Box::new(|v| v["mac"] = "00".repeat(32).into()),
        ),
        ("MAC malformed", Box::new(|v| v["mac"] = "zz".into())),
    ];
    for (what, f) in edits {
        std::fs::write(&path, &saved).unwrap();
        edit(&path, |v| f(v));
        let e = KeyBroker::load(&path, verifier(), kek())
            .err()
            .unwrap_or_else(|| panic!("{what}: the edited state opened"));
        assert_eq!(e.code, Code::KeyRelease, "{what}: {e}");
        assert!(e.message.contains("fails authentication"), "{what}: {e}");
        // ... and the owner's legacy path does not accept it either: a
        // state with a MAC must verify.
        assert!(
            KeyBroker::load_legacy(&path, verifier(), kek()).is_err(),
            "{what}"
        );
    }

    // Re-serializing the same content (whitespace, field order) is not an
    // edit.
    std::fs::write(&path, &saved).unwrap();
    edit(&path, |_| {});
    let mut b = KeyBroker::load(&path, verifier(), kek()).unwrap();
    assert!(release_to(&mut b, IMAGE).is_ok());

    // A KEK the state was not saved under does not open it (as before).
    std::fs::write(&path, &saved).unwrap();
    assert!(KeyBroker::load(
        &path,
        verifier(),
        Box::new(LocalKekStore::from_key([6; 32]))
    )
    .is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Review finding KB-2 (ENC-SF-2026-043): legitimate changes (through the broker) are
/// re-authenticated on save, and every save advances the generation.
#[test]
fn owner_changes_are_reauthenticated_and_generations_advance() {
    let dir = tmp("owner");
    let path = dir.join("broker.json");
    saved_broker(&path);
    let generation = |p: &std::path::Path| {
        serde_json::from_slice::<Value>(&std::fs::read(p).unwrap()).unwrap()["generation"]
            .as_u64()
            .unwrap()
    };
    let g0 = generation(&path);
    assert!(g0 >= 1);

    let mut b = KeyBroker::load(&path, verifier(), kek()).unwrap();
    let mut wider = policy();
    wider.allowed_images.push(EVIL_IMAGE.into());
    b.set_policy("patients", wider).unwrap();
    b.save(&path).unwrap();
    assert_eq!(generation(&path), g0 + 1);
    b.save(&path).unwrap();
    assert_eq!(generation(&path), g0 + 2);

    let mut b = KeyBroker::load(&path, verifier(), kek()).unwrap();
    assert!(
        release_to(&mut b, EVIL_IMAGE).is_ok(),
        "the owner's own policy change"
    );
    b.revoke_all("patients").unwrap();
    b.save(&path).unwrap();
    assert_eq!(generation(&path), g0 + 3);
    let mut b = KeyBroker::load(&path, verifier(), kek()).unwrap();
    assert_eq!(
        release_to(&mut b, IMAGE).unwrap_err().code,
        Code::KeyRelease
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Review finding KB-2 (ENC-SF-2026-043): a state file from an earlier Encompute (no MAC) is
/// never silently accepted, whatever mode it claims; its owner
/// authenticates it explicitly (`encompute keys upgrade-state`).
#[test]
fn an_unauthenticated_state_needs_its_owner_to_upgrade_it() {
    let dir = tmp("legacy");
    let path = dir.join("broker.json");
    saved_broker(&path);
    // What an earlier Encompute wrote: no generation, no MAC.
    edit(&path, |v| {
        let o = v.as_object_mut().unwrap();
        o.remove("mac");
        o.remove("generation");
    });
    let legacy = std::fs::read(&path).unwrap();
    for mode in ["development", "production"] {
        std::fs::write(&path, &legacy).unwrap();
        edit(&path, |v| v["mode"] = mode.into());
        let e = KeyBroker::load(&path, verifier(), kek()).err().unwrap();
        assert_eq!(e.code, Code::KeyRelease, "{mode}: {e}");
        assert!(e.message.contains("upgrade-state"), "{mode}: {e}");
    }

    // The owner's explicit upgrade: the next save authenticates it.
    std::fs::write(&path, &legacy).unwrap();
    let b = KeyBroker::load_legacy(&path, verifier(), kek()).unwrap();
    assert!(b.state().mac.is_none());
    b.save(&path).unwrap();
    let mut b = KeyBroker::load(&path, verifier(), kek()).unwrap();
    assert!(b.state().mac.is_some());
    assert!(release_to(&mut b, IMAGE).is_ok());

    // Once upgraded, an edit is refused again.
    edit(&path, |v| {
        v["secrets"]["patients"]["release_policy"]["allowed_images"] =
            serde_json::json!([EVIL_IMAGE])
    });
    assert!(KeyBroker::load(&path, verifier(), kek()).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A production-grade store that cannot authenticate state (a KMS store
/// that did not implement it).
struct NoStateMac(LocalKekStore);

impl SecretStore for NoStateMac {
    fn name(&self) -> &'static str {
        "no-state-mac"
    }
    fn security(&self) -> StoreSecurity {
        StoreSecurity::Production
    }
    fn key_id(&self) -> Option<String> {
        Some("k".into())
    }
    fn wrap(&self, ctx: &KeyContext<'_>, key: &KeyMaterial) -> encompute_ir::Result<StoredKey> {
        self.0.wrap(ctx, key)
    }
    fn unwrap_for_release(
        &self,
        ctx: &KeyContext<'_>,
        stored: &StoredKey,
    ) -> encompute_ir::Result<KeyMaterial> {
        self.0.unwrap_for_release(ctx, stored)
    }
}

/// Review finding KB-2 (ENC-SF-2026-043): fail closed. A production store that cannot
/// authenticate the state backs no broker, new or reopened.
#[test]
fn a_production_store_must_authenticate_state() {
    let store = || Box::new(NoStateMac(LocalKekStore::from_key(KEK))) as Box<dyn SecretStore>;
    for mode in [BrokerMode::Production, BrokerMode::Development] {
        let e = KeyBroker::new("hospital", mode, verifier(), store())
            .err()
            .unwrap();
        assert_eq!(e.code, Code::KeyRelease, "{e}");
        assert!(e.message.contains("cannot authenticate"), "{e}");
    }
}
