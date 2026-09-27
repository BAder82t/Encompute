//! `encompute migrate`: current artifacts made by the real tools are
//! reported current and left byte-identical; older versions are upgraded
//! into a new copy, kept as-is, or refused, as documented in its help.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

const ADULT: &str = "encompute 0.1
program adult precision 0.001
%0 = input \"age\" [0.0, 120.0] : secret u8
%1 = const [18.0] : public u8
%2 = ge %0, %1 : secret bool
output \"adult\" = %2
";

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

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("encompute-migrate-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Every file under `p` (or `p` itself) with its bytes and mtime.
fn snapshot(p: &Path) -> BTreeMap<PathBuf, (Vec<u8>, SystemTime)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![p.to_owned()];
    while let Some(q) = stack.pop() {
        if q.is_dir() {
            for e in std::fs::read_dir(&q).unwrap() {
                stack.push(e.unwrap().path());
            }
        } else {
            let m = std::fs::metadata(&q).unwrap().modified().unwrap();
            out.insert(q.clone(), (std::fs::read(&q).unwrap(), m));
        }
    }
    out
}

fn listing(p: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    v.sort();
    v
}

/// `migrate PATH` in every read-only form: exit `want`, and PATH untouched.
fn check_readonly(path: &Path, want: i32, out_dir: &Path) -> String {
    let before = snapshot(path);
    let (code, out, err) = encompute(&["migrate", s(path), "--check"]);
    assert_eq!(code, want, "--check {}: {out}{err}", path.display());
    let (code, json, err) = encompute(&["migrate", s(path), "--check", "--json"]);
    assert_eq!(code, want, "{json}{err}");
    serde_json::from_str::<serde_json::Value>(&json).unwrap();
    let (code, _, err) = encompute(&["migrate", s(path)]);
    assert_eq!(code, want, "{err}");
    if want != 1 {
        // Nothing to write: --out writes nothing either.
        std::fs::create_dir_all(out_dir).unwrap();
        let listed = listing(out_dir);
        let (code, _, err) = encompute(&["migrate", s(path), "--out", s(out_dir)]);
        assert_eq!(code, want, "{err}");
        assert_eq!(listing(out_dir), listed, "nothing written");
    }
    assert_eq!(snapshot(path), before, "{} was modified", path.display());
    out
}

fn refused(path: &Path, code_str: &str) -> String {
    let before = if path.exists() {
        snapshot(path)
    } else {
        BTreeMap::new()
    };
    let (code, out, err) = encompute(&["migrate", s(path), "--check"]);
    assert_eq!(code, 2, "{out}{err}");
    assert!(err.contains(&format!("error[{code_str}]")), "{err}");
    if path.exists() {
        assert_eq!(snapshot(path), before);
    }
    err
}

fn edit_json(path: &Path, f: impl FnOnce(&mut serde_json::Value)) {
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    f(&mut v);
    std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

fn sha256(b: &[u8]) -> String {
    encompute_runtime::training::sha256_hex(b)
}

fn compile(dir: &Path) -> PathBuf {
    std::fs::write(dir.join("adult.eir"), ADULT).unwrap();
    let art = dir.join("adult.encompute");
    let (code, _, err) = encompute(&["compile", s(&dir.join("adult.eir")), "-o", s(&art)]);
    assert_eq!(code, 0, "{err}");
    art
}

#[test]
fn model_artifact_current_upgraded_and_refused() {
    let dir = scratch("model");
    let art = compile(&dir);
    let out = check_readonly(&art, 0, &dir.join("unused"));
    assert!(
        out.contains("compiled model artifact, format 5: current"),
        "{out}"
    );

    // Format 4 (before policy.json): regenerated from program.eir.
    let v4 = dir.join("v4").join("adult.encompute");
    copy_dir(&art, &v4);
    std::fs::remove_file(v4.join("policy.json")).unwrap();
    edit_json(&v4.join("manifest.json"), |m| {
        m["artifact_format"] = 4.into();
        m["files"].as_object_mut().unwrap().remove("policy.json");
    });
    let out = check_readonly(&v4, 1, &dir.join("unused"));
    assert!(
        out.contains("format 4: upgrade to format 5 available"),
        "{out}"
    );
    assert!(encompute_runtime::Model::load(&v4).is_err());
    let before = snapshot(&v4);
    let dest = dir.join("migrated");
    let (code, out, err) = encompute(&["migrate", s(&v4), "--out", s(&dest), "--json"]);
    assert_eq!(code, 0, "{out}{err}");
    let j: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(j["status"], "upgraded");
    assert_eq!(j["version"], 4);
    assert_eq!(snapshot(&v4), before, "the input is never modified");
    let up = dest.join("adult.encompute");
    encompute_runtime::Model::load(&up).expect("the normal loader accepts the upgrade");
    for f in listing(&art) {
        let name = f.file_name().unwrap();
        assert_eq!(
            std::fs::read(&f).unwrap(),
            std::fs::read(up.join(name)).unwrap()
        );
    }
    assert_eq!(listing(&dest), vec![up.clone()], "no temporary left behind");
    check_readonly(&up, 0, &dir.join("unused"));
    // Never over an existing output.
    let err = refused_write(&v4, &dest);
    assert!(err.contains("exists"), "{err}");
    // Never inside the input.
    let (code, _, err) = encompute(&["migrate", s(&v4), "--out", s(&v4.join("x"))]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("inside the input"), "{err}");
    assert!(!v4.join("x").exists());
    assert_eq!(snapshot(&v4), before);

    // Current format, metadata from another Encompute version.
    let stale = dir.join("stale").join("adult.encompute");
    copy_dir(&art, &stale);
    edit_json(&stale.join("manifest.json"), |m| {
        m["compiler"]["version"] = "0.0.1".into();
    });
    let out = check_readonly(&stale, 1, &dir.join("unused"));
    assert!(out.contains("metadata written by encompute 0.0.1"), "{out}");
    let (code, _, err) = encompute(&["migrate", s(&stale), "--out", s(&dir.join("stale-out"))]);
    assert_eq!(code, 0, "{err}");
    encompute_runtime::Model::load(&dir.join("stale-out/adult.encompute")).unwrap();

    // A changed compiled plan is not metadata: refused, recompile.
    let plan = dir.join("plan").join("adult.encompute");
    copy_dir(&v4, &plan);
    let text = std::fs::read_to_string(plan.join("plan.json")).unwrap() + " ";
    std::fs::write(plan.join("plan.json"), &text).unwrap();
    edit_json(&plan.join("manifest.json"), |m| {
        m["files"]["plan.json"] = sha256(text.as_bytes()).into();
    });
    let err = refused(&plan, "ENC1401");
    assert!(
        err.contains("plan.json differs") && err.contains("recompile"),
        "{err}"
    );

    // A modified file (hash mismatch): refused.
    let bad = dir.join("bad").join("adult.encompute");
    copy_dir(&v4, &bad);
    std::fs::write(bad.join("security.json"), "{}").unwrap();
    let err = refused(&bad, "ENC1401");
    assert!(err.contains("modified"), "{err}");
    // The same damage at the current format.
    let bad5 = dir.join("bad5").join("adult.encompute");
    copy_dir(&art, &bad5);
    std::fs::write(bad5.join("security.json"), "{}").unwrap();
    refused(&bad5, "ENC1401");

    // Unknown (0), the unversioned 0.1 layout (1), and future formats.
    for (f, what) in [
        (Some(0), "not a version"),
        (None, "not a version"),
        (Some(999), "newer"),
    ] {
        let d = dir.join(format!("f{f:?}")).join("adult.encompute");
        copy_dir(&art, &d);
        edit_json(&d.join("manifest.json"), |m| match f {
            Some(f) => m["artifact_format"] = f.into(),
            None => {
                m.as_object_mut().unwrap().remove("artifact_format");
            }
        });
        let err = refused(&d, "ENC1602");
        assert!(err.contains(what), "{err}");
    }
    // A manifest that is not JSON.
    let d = dir.join("garbled").join("adult.encompute");
    copy_dir(&art, &d);
    std::fs::write(d.join("manifest.json"), "{").unwrap();
    refused(&d, "ENC1401");

    // --check and --out together are a usage error.
    let (code, _, _) = encompute(&["migrate", s(&art), "--check", "--out", s(&dest)]);
    assert_eq!(code, 2);
}

fn refused_write(input: &Path, out: &Path) -> String {
    let (code, o, err) = encompute(&["migrate", s(input), "--out", s(out)]);
    assert_eq!(code, 2, "{o}{err}");
    assert!(err.contains("error[ENC1401]"), "{err}");
    err
}

#[test]
fn keys_and_envelopes() {
    let dir = scratch("keys");
    let art = compile(&dir);
    let keys = dir.join("keys");
    let (code, _, err) = encompute(&[
        "keys",
        "generate",
        s(&art),
        "-o",
        s(&keys),
        "--mode",
        "mock",
    ]);
    assert_eq!(code, 0, "{err}");
    let out = check_readonly(&keys, 0, &dir.join("unused"));
    assert!(out.contains("key directory, format 1: current"), "{out}");
    let out = check_readonly(&keys.join("eval.keys"), 0, &dir.join("unused"));
    assert!(out.contains("envelope, format 1: current"), "{out}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(keys.join("secret.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "permissions untouched");
    }

    // Envelope format bytes 4..6: 0 (never existed) and 999 (future).
    for (v, code, what) in [
        (0u16, "ENC1602", "not a version"),
        (999, "ENC1602", "newer"),
    ] {
        let d = dir.join(format!("keys{v}"));
        copy_dir(&keys, &d);
        let mut b = std::fs::read(d.join("eval.keys")).unwrap();
        b[4..6].copy_from_slice(&v.to_le_bytes());
        std::fs::write(d.join("eval.keys"), &b).unwrap();
        let err = refused(&d, code);
        assert!(err.contains(what), "{err}");
    }
    // A corrupted secret key envelope (checksum).
    let d = dir.join("corrupt");
    copy_dir(&keys, &d);
    let mut b = std::fs::read(d.join("secret.key")).unwrap();
    let n = b.len();
    b[n - 40] ^= 1;
    std::fs::write(d.join("secret.key"), &b).unwrap();
    refused(&d, "ENC1601");
}

fn serve() -> String {
    use encompute_evaluator::server::{Evaluator, Limits};
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    std::thread::spawn(move || {
        Evaluator::new(encompute_evaluator::Backends::MOCK, Limits::default()).serve(server)
    });
    url
}

#[test]
fn execution_receipts() {
    let dir = scratch("receipt");
    let art = compile(&dir);
    let keys = dir.join("keys");
    let (code, _, err) = encompute(&[
        "keys",
        "generate",
        s(&art),
        "-o",
        s(&keys),
        "--mode",
        "mock",
    ]);
    assert_eq!(code, 0, "{err}");
    let receipt = dir.join("result.receipt.json");
    let (code, _, err) = encompute(&[
        "run",
        s(&art),
        "--remote",
        &serve(),
        "--keys",
        s(&keys),
        "--input",
        "age=30",
        "--save-receipt",
        s(&receipt),
    ]);
    assert_eq!(code, 0, "{err}");
    let out = check_readonly(&receipt, 0, &dir.join("unused"));
    assert!(
        out.contains("execution receipt, version 3: current"),
        "{out}"
    );
    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();

    let with_version = |v: u64, name: &str| {
        let mut r = raw.clone();
        r["receipt"]["version"] = v.into();
        let p = dir.join(name);
        std::fs::write(&p, serde_json::to_vec(&r).unwrap()).unwrap();
        p
    };
    // Versions 1 and 2 are signed: kept as-is, exit 3, never rewritten.
    for v in [1, 2] {
        let p = with_version(v, &format!("v{v}.json"));
        let out = check_readonly(&p, 3, &dir.join("out"));
        assert!(
            out.contains("kept as-is") && out.contains("signature"),
            "{out}"
        );
    }
    let err = refused(&with_version(0, "v0.json"), "ENC1602");
    assert!(err.contains("not a version"), "{err}");
    let err = refused(&with_version(999, "v999.json"), "ENC1602");
    assert!(err.contains("newer"), "{err}");
    // A current receipt whose signature no longer verifies.
    let mut r = raw.clone();
    r["receipt"]["backend"] = "openfhe".into();
    let p = dir.join("tampered.json");
    std::fs::write(&p, serde_json::to_vec(&r).unwrap()).unwrap();
    refused(&p, "ENC1606");
}

#[test]
fn privacy_ledgers() {
    use encompute_runtime::dp::ledger::{Genesis, Ledger, LEDGER_VERSION};
    use encompute_runtime::dp::PrivacyEvent;
    let dir = scratch("ledger");
    let ledgers = dir.join("ledgers");
    std::fs::create_dir_all(&ledgers).unwrap();
    let (budget, mechanism) = encompute_ir::confidentiality::privacy_preset(
        "standard",
        encompute_ir::confidentiality::PrivacyUnit::Patient,
    )
    .unwrap();
    for asset in ["gradient-a", "gradient-b"] {
        let mut l = Ledger::open(
            &ledgers.join(format!("{asset}.ledger")),
            &Genesis {
                version: LEDGER_VERSION,
                asset_id: asset.into(),
                budget: budget.clone(),
                privacy_policy_id: "ab".repeat(32),
            },
        )
        .unwrap();
        l.append(PrivacyEvent::Reserve {
            event_id: format!("e-{asset}"),
            policy_id: None,
            execution_spec_id: None,
            round_id: Some("r1".into()),
            output: "g".into(),
            mechanism: mechanism.clone(),
            sensitivity: 1000,
            sigma2: 1 << 40,
            vector_len: 4,
            rng: "csprng".into(),
        })
        .unwrap();
        l.append(PrivacyEvent::Commit {
            event_id: format!("e-{asset}"),
            output_commitment: "cd".repeat(32),
        })
        .unwrap();
    }
    let out = check_readonly(&ledgers, 0, &dir.join("unused"));
    assert!(
        out.contains("privacy ledger directory, version 1: current"),
        "{out}"
    );
    let one = ledgers.join("gradient-a.ledger");
    let out = check_readonly(&one, 0, &dir.join("unused"));
    assert!(out.contains("privacy ledger, version 1: current"), "{out}");

    // The genesis version is hash-chained: never rewritten; 0 and 999 refused.
    let text = std::fs::read_to_string(&one).unwrap();
    for (v, what) in [(0, "not a version"), (999, "newer")] {
        let d = dir.join(format!("l{v}"));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("gradient-a.ledger");
        std::fs::write(
            &p,
            text.replacen("\"version\":1", &format!("\"version\":{v}"), 1),
        )
        .unwrap();
        let err = refused(&p, "ENC1602");
        assert!(err.contains(what), "{err}");
        let err = refused(&d, "ENC1602");
        assert!(err.contains(what), "{err}");
    }
    // An edited entry breaks the chain.
    let d = dir.join("tampered");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("gradient-a.ledger"),
        text.replace("\"sensitivity\":1000", "\"sensitivity\":1"),
    )
    .unwrap();
    refused(&d, "ENC2202");
}

#[test]
fn plan_and_trust_bundle() {
    let dir = scratch("trust");
    let art = compile(&dir);
    let infra = dir.join("infra.json");
    std::fs::write(
        &infra,
        r#"{"tees": [{"tee": "intel-tdx", "provider": "gcp-confidential-space"}],
            "key_broker": true}"#,
    )
    .unwrap();
    let plan = dir.join("plan.json");
    let (code, out, err) = encompute(&[
        "plan",
        s(&art),
        "--infrastructure",
        s(&infra),
        "-o",
        s(&plan),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let out = check_readonly(&plan, 0, &dir.join("unused"));
    assert!(
        out.contains("confidential execution plan, version 1: current"),
        "{out}"
    );
    let bundle = dir.join("trust.json");
    let (code, out, err) = encompute(&[
        "trust",
        "init",
        s(&art),
        "--plan",
        s(&plan),
        "--bundle",
        s(&bundle),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let out = check_readonly(&bundle, 0, &dir.join("unused"));
    assert!(out.contains("trust bundle, version 1: current"), "{out}");

    // Content-addressed: other versions are refused, never rewritten.
    for (src, name) in [(&plan, "plan"), (&bundle, "bundle")] {
        for (v, what) in [(0, "not a version"), (999, "newer")] {
            let p = dir.join(format!("{name}{v}.json"));
            std::fs::copy(src, &p).unwrap();
            edit_json(&p, |j| j["version"] = v.into());
            let err = refused(&p, "ENC1602");
            assert!(err.contains(what), "{err}");
        }
    }
}

#[test]
fn checkpoints_sealed_assets_and_adapter_records() {
    use encompute_runtime::training::adapter::{AdapterRecord, ADAPTER_VERSION};
    use encompute_runtime::training::checkpoint::CHECKPOINT_VERSION;
    use encompute_runtime::training::{seal, seal_asset, seal_checkpoint, CheckpointHeader};
    let dir = scratch("training");
    let key = [9u8; 32];
    let payload = b"adapter weights and optimizer state";
    let header = |version| CheckpointHeader {
        version,
        project: "p".into(),
        training_spec_id: "ab".repeat(32),
        run_id: "run-1".into(),
        round: 2,
        adapter_id: "adapter-2".into(),
        payload_digest: encompute_runtime::training::sha256_hex(payload),
        policy_id: None,
        privacy_policy_id: None,
        ledgers: BTreeMap::new(),
        lineage_root: None,
    };
    let ckpt = dir.join("round-2.enc");
    std::fs::write(
        &ckpt,
        seal_checkpoint(&key, &header(CHECKPOINT_VERSION), payload).unwrap(),
    )
    .unwrap();
    let out = check_readonly(&ckpt, 0, &dir.join("unused"));
    assert!(
        out.contains("sealed training checkpoint, version 1: current"),
        "{out}"
    );
    let asset = dir.join("model.sealed");
    std::fs::write(
        &asset,
        seal_asset(&key, "model", "p", "base", b"weights").unwrap(),
    )
    .unwrap();
    let out = check_readonly(&asset, 0, &dir.join("unused"));
    assert!(out.contains("sealed asset, version 1: current"), "{out}");
    // The header is authenticated under a key migrate never has: another
    // version cannot be rewritten, and 0 / 999 are refused.
    for (v, what) in [(0, "not a version"), (999, "newer")] {
        let p = dir.join(format!("ckpt{v}.enc"));
        std::fs::write(&p, seal(&key, &header(v), payload).unwrap()).unwrap();
        let err = refused(&p, "ENC1602");
        assert!(err.contains(what), "{err}");
    }

    let signer = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    let record = |version| AdapterRecord {
        version,
        project: "p".into(),
        adapter_id: "adapter-2".into(),
        round: 2,
        previous: Some("adapter-1".into()),
        training_spec_id: "ab".repeat(32),
        run_id: "run-1".into(),
        aggregation_receipt_id: "cd".repeat(32),
        aggregation_output: "g".into(),
        adapter_digest: "ef".repeat(32),
        base_model: "base".into(),
        datasets: vec!["d".into()],
    };
    let rec = dir.join("adapter-record.json");
    let signed = record(ADAPTER_VERSION).sign(&signer).unwrap();
    std::fs::write(&rec, serde_json::to_vec_pretty(&signed).unwrap()).unwrap();
    let out = check_readonly(&rec, 0, &dir.join("unused"));
    assert!(
        out.contains("signed adapter record, version 1: current"),
        "{out}"
    );
    for (v, what) in [(0, "not a version"), (999, "newer")] {
        let p = dir.join(format!("record{v}.json"));
        let signed = record(v).sign(&signer).unwrap();
        std::fs::write(&p, serde_json::to_vec_pretty(&signed).unwrap()).unwrap();
        let err = refused(&p, "ENC1602");
        assert!(err.contains(what), "{err}");
    }
    // A current record edited after signing.
    let mut forged = signed;
    forged.record.round = 3;
    let p = dir.join("forged.json");
    std::fs::write(&p, serde_json::to_vec_pretty(&forged).unwrap()).unwrap();
    let err = refused(&p, "ENC2501");
    assert!(err.contains("signature is invalid"), "{err}");
}

#[test]
fn attestation_policy_and_signed_round_objects() {
    use encompute_runtime::attestation::{AttestationPolicy, POLICY_VERSION};
    let dir = scratch("attest");
    let policy = dir.join("policy.json");
    let p = AttestationPolicy::new(&"ab".repeat(32), None);
    assert_eq!(p.version, POLICY_VERSION);
    std::fs::write(&policy, serde_json::to_vec_pretty(&p).unwrap()).unwrap();
    let out = check_readonly(&policy, 0, &dir.join("unused"));
    assert!(
        out.contains("attestation policy, version 1: current"),
        "{out}"
    );
    edit_json(&policy, |j| j["version"] = 999.into());
    refused(&policy, "ENC1602");
    // Signed objects of other versions are refused before any parsing.
    for (name, body) in [
        (
            "aggregation.receipt.json",
            r#"{"manifest": {"version": 999}, "coordinator_key": "", "signature": ""}"#,
        ),
        ("attestation.json", r#"{"version": 0, "evidence": {}}"#),
    ] {
        let f = dir.join(name);
        std::fs::write(&f, body).unwrap();
        refused(&f, "ENC1602");
    }
    // At the current version they must parse: a stub is corrupted.
    let f = dir.join("stub.receipt.json");
    std::fs::write(
        &f,
        r#"{"manifest": {"version": 1}, "coordinator_key": "", "signature": ""}"#,
    )
    .unwrap();
    refused(&f, "ENC2104");
}

#[test]
fn party_state_upgrade() {
    let dir = scratch("state");
    // The old `aggregate join --state` format: a bare sequence number.
    let old = dir.join("hospital-a.state");
    std::fs::write(&old, "7\n").unwrap();
    let out = check_readonly(&old, 1, &dir.join("unused"));
    assert!(
        out.contains("aggregation party state, version 0: upgrade to version 1"),
        "{out}"
    );
    let before = snapshot(&old);
    let (code, out, err) = encompute(&["migrate", s(&old), "--out", s(&dir.join("new"))]);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(snapshot(&old), before);
    let new = dir.join("new/hospital-a.state");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&new).unwrap()).unwrap();
    assert_eq!(v, serde_json::json!({"sequence": 7, "checkpoints": {}}));
    let out = check_readonly(&new, 0, &dir.join("unused"));
    assert!(out.contains("version 1: current"), "{out}");
    let err = refused_write(&old, &dir.join("new"));
    assert!(err.contains("exists"), "{err}");
}

#[test]
fn unknown_and_unreadable_inputs() {
    let dir = scratch("unknown");
    let empty = dir.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let err = refused(&empty, "ENC1401");
    assert!(err.contains("not an Encompute artifact"), "{err}");
    let text = dir.join("notes.txt");
    std::fs::write(&text, "hello").unwrap();
    refused(&text, "ENC1401");
    let json = dir.join("other.json");
    std::fs::write(&json, r#"{"name": "x"}"#).unwrap();
    refused(&json, "ENC1401");
    let binary = dir.join("blob.bin");
    std::fs::write(&binary, [0xffu8, 0, 1, 2]).unwrap();
    refused(&binary, "ENC1401");
    refused(&dir.join("missing"), "ENC1401");
    // A truncated envelope and a sealed file with a garbled header.
    let env = dir.join("truncated.bin");
    std::fs::write(&env, b"ENCM\x01").unwrap();
    refused(&env, "ENC1601");
    let sealed = dir.join("garbled.enc");
    std::fs::write(&sealed, b"ENCSEAL1\x02\x00\x00\x00{]").unwrap();
    refused(&sealed, "ENC2502");
}
