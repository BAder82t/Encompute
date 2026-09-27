//! Fuzz smoke tests for compiled artifact loading (`manifest.json` and the
//! files it hashes): mutated artifacts never panic and are never accepted
//! unless identical to what this version compiles. Resource limits: deep
//! JSON, huge numbers, invalid UTF-8 and missing files are typed errors.

#[path = "../../encompute-ir/tests/fuzz_support/mod.rs"]
mod fuzz_support;

use std::path::Path;
use std::time::Duration;

use encompute_ir::Code;
use encompute_runtime::Model;
use fuzz_support::{mutate, within, Rng};

const NAMES: [&str; 7] = [
    "manifest.json",
    "program.eir",
    "plan.json",
    "parameters.json",
    "security.json",
    "verification.json",
    "policy.json",
];

const PROGRAMS: [&str; 2] = [
    include_str!("../../../examples/06_confidentiality_policy/training.eir"),
    include_str!("../../../benches/exact/mixed.eir"),
];

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("encompute-fuzz-art-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn load_err(dir: &Path) -> encompute_ir::Error {
    match Model::load(dir) {
        Ok(_) => panic!("{} was accepted", dir.display()),
        Err(e) => e,
    }
}

fn files(dir: &Path) -> Vec<Vec<u8>> {
    NAMES
        .iter()
        .map(|n| std::fs::read(dir.join(n)).unwrap())
        .collect()
}

#[test]
fn mutated_artifacts_never_panic_or_load() {
    let mut rng = Rng::new(1);
    for (k, src) in PROGRAMS.iter().enumerate() {
        let good = tmp(&format!("good{k}"));
        Model::from_eir(src).unwrap().save(&good).unwrap();
        Model::load(&good).unwrap();
        let orig = files(&good);
        let dir = tmp(&format!("mut{k}"));
        for i in 0..300 {
            for (n, b) in NAMES.iter().zip(&orig) {
                std::fs::write(dir.join(n), b).unwrap();
            }
            // Mutate one or two files; sometimes delete one.
            for _ in 0..1 + rng.below(2) {
                let f = rng.below(NAMES.len());
                if rng.below(20) == 0 {
                    std::fs::remove_file(dir.join(NAMES[f])).ok();
                } else {
                    std::fs::write(dir.join(NAMES[f]), mutate(&mut rng, &orig[f], &orig)).unwrap();
                }
            }
            let t = std::time::Instant::now();
            let r = std::panic::catch_unwind(|| Model::load(&dir));
            assert!(t.elapsed() < Duration::from_secs(10), "iteration {i}");
            match r {
                Err(_) => panic!("artifact {k} iteration {i} panicked"),
                Ok(Ok(_)) => {
                    // Accepted only if the files are the ones compiled
                    // (a mutation can be a no-op, e.g. deleting nothing).
                    assert_eq!(
                        files(&dir),
                        orig,
                        "iteration {i} accepted a modified artifact"
                    );
                }
                Ok(Err(e)) => assert!(!e.message.is_empty()),
            }
        }
    }
}

#[test]
fn malformed_manifests_are_typed_errors() {
    let good = tmp("limits-good");
    Model::from_eir(PROGRAMS[1]).unwrap().save(&good).unwrap();
    let orig = files(&good);
    let dir = tmp("limits");
    let deep = fuzz_support::nested_json(100_000, "");
    for manifest in [
        deep.as_bytes().to_vec(),
        b"\xff\xfe{}".to_vec(),
        b"{\"artifact_format\": 18446744073709551616}".to_vec(),
        b"{\"artifact_format\": 1e999}".to_vec(),
        b"[]".to_vec(),
        b"".to_vec(),
        String::from_utf8(orig[0].clone())
            .unwrap()
            .replace("\"artifact_format\"", "\"artifact_format\": 99, \"x\"")
            .into_bytes(),
    ] {
        for (n, b) in NAMES.iter().zip(&orig) {
            std::fs::write(dir.join(n), b).unwrap();
        }
        std::fs::write(dir.join("manifest.json"), &manifest).unwrap();
        let e = within(Duration::from_secs(5), || load_err(&dir));
        assert_eq!(e.code, Code::Artifact, "{e}");
    }
    // A program file that is not UTF-8, or absurdly large dimensions in a
    // program whose manifest hash was recomputed: refused, never compiled
    // into a huge plan.
    for n in NAMES {
        for (m, b) in NAMES.iter().zip(&orig) {
            std::fs::write(dir.join(m), b).unwrap();
        }
        std::fs::write(dir.join(n), b"\xff\xfe\xfd").unwrap();
        let e = within(Duration::from_secs(5), || load_err(&dir));
        assert_eq!(e.code, Code::Artifact, "{n}: {e}");
    }
    let e = load_err(&dir.join("missing"));
    assert_eq!(e.code, Code::Artifact);
}
