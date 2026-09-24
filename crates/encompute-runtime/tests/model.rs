mod common;

use std::fs;

use common::logistic;
use encompute_ir::Code;
use encompute_runtime::{sample_inputs, Mode, Model};

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("encompute-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    d
}

#[test]
fn artifact_round_trips_and_is_reproducible() {
    let m = Model::compile(logistic(8, 1)).unwrap();
    let (a, b) = (tmp("a.encompute"), tmp("b.encompute"));
    m.save(&a).unwrap();
    Model::compile(logistic(8, 1)).unwrap().save(&b).unwrap();
    for f in [
        "program.eir",
        "plan.json",
        "parameters.json",
        "security.json",
        "manifest.json",
    ] {
        assert_eq!(
            fs::read(a.join(f)).unwrap(),
            fs::read(b.join(f)).unwrap(),
            "{f} differs"
        );
    }
    let loaded = Model::load(&a).unwrap();
    assert_eq!(loaded.program(), m.program());
    assert_eq!(loaded.compiled().plan, m.compiled().plan);

    let security = fs::read_to_string(a.join("security.json")).unwrap();
    assert!(security.contains("\"evaluator_receives_secret_key\": false"));
    assert!(security.contains("IND-CPA-D"));
    for f in fs::read_dir(&a).unwrap() {
        let body = fs::read_to_string(f.unwrap().path()).unwrap();
        // No key fields and no OpenFHE key serialization (cereal JSON or binary).
        for needle in [
            "\"secret_key\":",
            "\"private_key\":",
            "\"sk\":",
            "PrivateKey",
            "EvalKey",
            "cereal",
        ] {
            assert!(!body.contains(needle), "key material marker {needle:?}");
        }
    }
}

#[test]
fn tampered_artifacts_are_rejected() {
    let dir = tmp("t.encompute");
    Model::compile(logistic(8, 1)).unwrap().save(&dir).unwrap();
    let plan = dir.join("plan.json");
    let body = fs::read_to_string(&plan).unwrap();
    fs::write(&plan, body.replacen("\"depth\"", "\"depth\" ", 1)).unwrap();
    let e = Model::load(&dir).err().unwrap();
    assert_eq!(e.code, Code::Artifact);
    assert!(e.message.contains("manifest hash"), "{}", e.message);
    assert_eq!(
        Model::load(&tmp("missing.encompute")).err().unwrap().code,
        Code::Artifact
    );
}

#[test]
fn modes_explain_and_bench() {
    let m = Model::compile(logistic(8, 1)).unwrap();
    let inputs = sample_inputs(m.program(), 5, 0);
    let clear = m.run(Mode::Clear, &inputs).unwrap();
    let mock = m.run(Mode::Mock, &inputs).unwrap();
    assert!((clear["score"][0] - mock["score"][0]).abs() < 1e-3);
    // Keys are generated once per mode and reused.
    let again = m.run(Mode::Mock, &inputs).unwrap();
    assert!((again["score"][0] - mock["score"][0]).abs() < 1e-3);

    let rep = m.test(Mode::Mock, 50, 1).unwrap();
    assert!(rep.passed);
    let text = m.explain(Some(&rep));
    for needle in [
        "Privacy",
        "encrypted by the client",
        "rotation keys",
        "Chebyshev degree",
        "ring dimension",
        "measured",
        "PASS",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in\n{text}");
    }
    let b = m.bench(Mode::Mock, 3).unwrap();
    assert!(
        b.sizes_estimated
            && b.request_bytes > 0
            && b.response_bytes > 0
            && b.evaluation_key_bytes > 0
    );

    assert_eq!("gpu".parse::<Mode>().unwrap_err().code, Code::BadInput);
    assert!(m.test(Mode::Clear, 1, 0).is_err());
    if !encompute_runtime::has_openfhe() {
        assert_eq!(
            m.run(Mode::Encrypted, &inputs).unwrap_err().code,
            Code::Backend
        );
    }
}

#[test]
fn manifest_records_versioned_provenance() {
    let dir = tmp("prov.encompute");
    Model::compile(logistic(8, 1)).unwrap().save(&dir).unwrap();
    let path = dir.join("manifest.json");
    let m: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(m["artifact_format"], 2);
    assert_eq!(m["compiler"]["ir_version"], encompute_ir::IR_VERSION);
    assert_eq!(
        m["crypto"]["parameter_selector_version"],
        encompute_ckks::PARAMETER_SELECTOR_VERSION
    );
    assert_eq!(m["crypto"]["backend_version"], "1.5.1");

    // A different parameter selector version is rejected even though every
    // file hash still matches.
    let bumped = fs::read_to_string(&path).unwrap().replace(
        "\"parameter_selector_version\": 1",
        "\"parameter_selector_version\": 0",
    );
    fs::write(&path, bumped).unwrap();
    let e = Model::load(&dir).err().unwrap();
    assert_eq!(e.code, Code::Artifact);
    assert!(
        e.message.contains("parameter_selector_version"),
        "{}",
        e.message
    );
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(300))]

    /// Corrupted artifacts are rejected with an error, never a panic, including
    /// when the corruption comes with a matching manifest hash.
    #[test]
    fn corrupted_artifacts_never_panic(
        file in 0usize..5,
        edits in proptest::collection::vec((proptest::prelude::any::<usize>(), proptest::prelude::any::<u8>(), 0u8..3), 1..6),
        fix_hash in proptest::prelude::any::<bool>(),
    ) {
        let names = ["program.eir", "plan.json", "parameters.json", "security.json", "manifest.json"];
        let dir = tmp(&format!("fuzz-{}.encompute", rand_suffix(&edits)));
        Model::compile(logistic(4, 1)).unwrap().save(&dir).unwrap();
        let path = dir.join(names[file]);
        let mut bytes = fs::read(&path).unwrap();
        for (pos, byte, kind) in edits {
            let i = pos % (bytes.len() + 1);
            match kind {
                0 if i < bytes.len() => bytes[i] = byte,
                1 => bytes.insert(i, byte),
                _ if i < bytes.len() => { bytes.truncate(i); }
                _ => {}
            }
        }
        fs::write(&path, &bytes).unwrap();
        if fix_hash && file < 4 {
            let m = dir.join("manifest.json");
            let mut v: serde_json::Value = serde_json::from_str(&fs::read_to_string(&m).unwrap()).unwrap();
            v["files"][names[file]] = serde_json::Value::String(sha256_hex(&bytes));
            fs::write(&m, serde_json::to_string_pretty(&v).unwrap()).unwrap();
        }
        if let Ok(model) = Model::load(&dir) {
            // Only a no-op edit (e.g. whitespace the recompile reproduces) may load,
            // and then it must be the same program.
            let original = Model::compile(logistic(4, 1)).unwrap();
            proptest::prop_assert_eq!(model.program(), original.program());
        }
        let _ = fs::remove_dir_all(&dir);
    }
}

fn rand_suffix(edits: &[(usize, u8, u8)]) -> u64 {
    edits.iter().fold(0u64, |h, (a, b, c)| {
        h.wrapping_mul(31)
            .wrapping_add(*a as u64 ^ ((*b as u64) << 8) ^ ((*c as u64) << 16))
    })
}
