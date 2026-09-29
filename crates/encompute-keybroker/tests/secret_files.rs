//! Files holding key material or credentials are checked when they already
//! exist (review notes KB-n): a KEK file others can read, and an OpenBao
//! token file others can write, are refused.
//!
//! One test per process touches the environment (`BAO_*`): keep it that
//! way.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use encompute_ir::Code;
use encompute_keybroker::{LocalKekStore, OpenBaoTransit};

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("encompute-kb-files-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn chmod(p: &std::path::Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Review note KB-n (ENC-SF-2026-063): an existing KEK file must be private to its owner.
#[test]
fn an_existing_kek_file_must_be_private() {
    let dir = tmp("kek");
    let kek = dir.join("broker.kek");
    LocalKekStore::open_or_create(&kek).unwrap();
    assert_eq!(
        std::fs::metadata(&kek).unwrap().permissions().mode() & 0o777,
        0o600
    );
    LocalKekStore::open_or_create(&kek).unwrap();
    for mode in [0o644, 0o640, 0o604, 0o660, 0o606] {
        chmod(&kek, mode);
        let e = LocalKekStore::open_or_create(&kek).err().unwrap();
        assert_eq!(e.code, Code::KeyRelease, "{mode:o}: {e}");
        assert!(e.message.contains("chmod 600"), "{mode:o}: {e}");
    }
    chmod(&kek, 0o400);
    LocalKekStore::open_or_create(&kek).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Review note KB-n (ENC-SF-2026-063): the OpenBao token file (`BAO_TOKEN_FILE`) must not be
/// writable by anyone but its owner, who could substitute the token. A
/// mounted secret readable through its mount (Compose keeps the host's
/// 0644) is accepted.
#[test]
fn the_openbao_token_file_must_not_be_writable_by_others() {
    let dir = tmp("token");
    let token = dir.join("bao-token");
    std::fs::write(&token, "s.token\n").unwrap();
    std::env::set_var("BAO_ADDR", "http://127.0.0.1:8200");
    std::env::set_var("BAO_TOKEN_FILE", &token);
    for mode in [0o600, 0o400, 0o644, 0o444] {
        chmod(&token, mode);
        assert!(
            OpenBaoTransit::from_env("transit", "org").is_ok(),
            "{mode:o}"
        );
    }
    for mode in [0o620, 0o602, 0o666, 0o664] {
        chmod(&token, mode);
        let e = OpenBaoTransit::from_env("transit", "org").err().unwrap();
        assert_eq!(e.code, Code::KeyRelease, "{mode:o}: {e}");
        assert!(
            e.message.contains("writable by its owner only"),
            "{mode:o}: {e}"
        );
    }
    // Not a regular file.
    std::env::set_var("BAO_TOKEN_FILE", &dir);
    assert!(OpenBaoTransit::from_env("transit", "org").is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}
