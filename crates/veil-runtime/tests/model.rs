mod common;

use std::fs;

use common::logistic;
use veil_ir::Code;
use veil_runtime::{sample_inputs, Mode, Model};

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("veil-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    d
}

#[test]
fn artifact_round_trips_and_is_reproducible() {
    let m = Model::compile(logistic(8, 1)).unwrap();
    let (a, b) = (tmp("a.veil"), tmp("b.veil"));
    m.save(&a).unwrap();
    Model::compile(logistic(8, 1)).unwrap().save(&b).unwrap();
    for f in [
        "program.vlir",
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
    assert!(security.contains("\"server_can_decrypt\": false"));
    assert!(security.contains("IND-CPA-D"));
    for f in fs::read_dir(&a).unwrap() {
        let body = fs::read_to_string(f.unwrap().path())
            .unwrap()
            .to_lowercase();
        assert!(
            !body.contains("secret_key") && !body.contains("private"),
            "no key material"
        );
    }
}

#[test]
fn tampered_artifacts_are_rejected() {
    let dir = tmp("t.veil");
    Model::compile(logistic(8, 1)).unwrap().save(&dir).unwrap();
    let plan = dir.join("plan.json");
    let body = fs::read_to_string(&plan).unwrap();
    fs::write(&plan, body.replacen("\"depth\"", "\"depth\" ", 1)).unwrap();
    let e = Model::load(&dir).err().unwrap();
    assert_eq!(e.code, Code::Artifact);
    assert!(e.message.contains("manifest hash"), "{}", e.message);
    assert_eq!(
        Model::load(&tmp("missing.veil")).err().unwrap().code,
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
    assert!(b.sizes_estimated && b.input_ciphertext_bytes > b.output_ciphertext_bytes);

    assert_eq!("gpu".parse::<Mode>().unwrap_err().code, Code::BadInput);
    assert!(m.test(Mode::Clear, 1, 0).is_err());
    if !veil_runtime::has_openfhe() {
        assert_eq!(
            m.run(Mode::Encrypted, &inputs).unwrap_err().code,
            Code::Backend
        );
    }
}
