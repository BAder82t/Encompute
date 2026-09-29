//! `encompute governance`: an organization signs, with its own governance
//! key file and outside the control plane, an authorization body, a purpose
//! acceptance or a revocation. The signed output verifies under that key
//! only; a malformed or wildcard body is refused before anything is
//! signed.

use std::path::PathBuf;
use std::process::Command;

use encompute_runtime::trust::authz::{
    governance_key_id, AuthorizationV2, SignedAuthorizationV2, SignedPurposeAcceptance,
    SignedRevocationV2,
};
use encompute_runtime::verification::governance::{ProgramRef, ReleaseClass};

fn encompute(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_encompute"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into(),
        String::from_utf8_lossy(&out.stderr).into(),
    )
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "encompute-cli-governance-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn body() -> AuthorizationV2 {
    AuthorizationV2 {
        version: 2,
        party: "tax-agency".into(),
        project: "prj_1".into(),
        purpose_id: "1".repeat(64),
        asset_version_id: "2".repeat(64),
        asset_digest_commitment: "3".repeat(64),
        program: ProgramRef::Program {
            program_id: "a".repeat(64),
        },
        policy_id: "4".repeat(64),
        privacy_policy_id: None,
        linkage_policy_id: None,
        release_class: ReleaseClass::BooleanOnly,
        recipients: ["benefits-agency".to_string()].into(),
        privacy_scope_id: None,
        execution_spec_ids: None,
        limits: Default::default(),
        per_job_four_eyes: false,
        valid_from: 1_000,
        valid_until: 2_000,
        issued_at: 900,
        nonce: "ab".repeat(16),
        approvals: vec![],
    }
}

#[test]
fn an_organization_signs_its_authorization_with_its_own_key_file() {
    let d = dir("sign");
    let key = d.join("governance.key");
    let key_s = key.to_str().unwrap();
    let (c, out, err) = encompute(&["governance", "keygen", "--out", key_s]);
    assert_eq!(c, 0, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let pk = v["public_key"].as_str().unwrap().to_owned();
    assert_eq!(v["key_id"], governance_key_id(&pk).as_str());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the private key is readable only by its owner");
    }
    // Never overwrites a key.
    let (c, _, _) = encompute(&["governance", "keygen", "--out", key_s]);
    assert_ne!(c, 0);

    // The document to sign, as `GET /v1/authorizations/{id}` shows it (the
    // whole response, or just its body).
    let b = body();
    let response = d.join("authorization.json");
    std::fs::write(
        &response,
        serde_json::to_vec(&serde_json::json!({"id": "atz_1", "status": "approved", "body": b}))
            .unwrap(),
    )
    .unwrap();
    let (c, out, err) = encompute(&[
        "governance",
        "sign",
        "--key",
        key_s,
        response.to_str().unwrap(),
    ]);
    assert_eq!(c, 0, "{err}");
    // It shows what is being signed.
    assert!(err.contains("tax-agency") && err.contains("prj_1"), "{err}");
    let signed: SignedAuthorizationV2 = serde_json::from_str(&out).unwrap();
    assert_eq!(signed.body, b);
    signed.verify(&pk).unwrap();
    assert!(signed.verify(&"0".repeat(64)).is_err());

    // `--signature-only` prints what `POST /v1/authorizations/{id}/signature` takes.
    let (c, out, _) = encompute(&[
        "governance",
        "sign",
        "--key",
        key_s,
        "--signature-only",
        response.to_str().unwrap(),
    ]);
    assert_eq!(c, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["public_key"], pk.as_str());
    assert_eq!(v["signature"], signed.signature.as_str());
    assert_eq!(v.as_object().unwrap().len(), 2);

    // A wildcard program is refused before signing.
    let mut wild = serde_json::to_value(body()).unwrap();
    wild["program"] = serde_json::json!({"kind": "program", "program_id": "*"});
    let bad = d.join("wild.json");
    std::fs::write(&bad, serde_json::to_vec(&wild).unwrap()).unwrap();
    let (c, out, _) = encompute(&["governance", "sign", "--key", key_s, bad.to_str().unwrap()]);
    assert_ne!(c, 0);
    assert!(out.is_empty());
}

#[test]
fn acceptances_and_revocations_are_signed_too() {
    let d = dir("kinds");
    let key = d.join("k");
    let key_s = key.to_str().unwrap();
    let (_, out, _) = encompute(&["governance", "keygen", "--out", key_s]);
    let pk = serde_json::from_str::<serde_json::Value>(&out).unwrap()["public_key"]
        .as_str()
        .unwrap()
        .to_owned();

    let acc = d.join("acceptance.json");
    std::fs::write(
        &acc,
        serde_json::to_vec(
            &serde_json::json!({"version": 1, "organization": "tax-agency",
            "project": "prj_1", "purpose_id": "1".repeat(64), "accepted_at": 1000}),
        )
        .unwrap(),
    )
    .unwrap();
    let (c, out, err) = encompute(&[
        "governance",
        "sign",
        "--key",
        key_s,
        "--kind",
        "purpose-acceptance",
        acc.to_str().unwrap(),
    ]);
    assert_eq!(c, 0, "{err}");
    let s: SignedPurposeAcceptance = serde_json::from_str(&out).unwrap();
    s.verify(&pk).unwrap();

    let rev = d.join("revocation.json");
    std::fs::write(
        &rev,
        serde_json::to_vec(&serde_json::json!({"version": 2, "party": "tax-agency",
            "authorization": "5".repeat(64), "reason": "superseded", "issued_at": 1000}))
        .unwrap(),
    )
    .unwrap();
    let (c, out, err) = encompute(&[
        "governance",
        "sign",
        "--key",
        key_s,
        "--kind",
        "revocation",
        rev.to_str().unwrap(),
    ]);
    assert_eq!(c, 0, "{err}");
    let s: SignedRevocationV2 = serde_json::from_str(&out).unwrap();
    s.verify(&pk).unwrap();
}
