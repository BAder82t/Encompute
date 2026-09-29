//! `encompute keys ...` configuration: a production broker never falls back
//! to development storage, whatever is misconfigured (no KEK, a development
//! root key, a missing or empty token, plain HTTP off loopback, an
//! unreachable provider, a malformed `--root-key`), and development
//! policies and evidence are refused. With `ENCOMPUTE_TEST_BAO_ADDR` and
//! `ENCOMPUTE_TEST_BAO_TOKEN` set, the lifecycle also runs through OpenBao
//! Transit (skipped without them, unless `ENCOMPUTE_REQUIRE_SERVICES`).

use std::path::{Path, PathBuf};
use std::process::Command;

const IMAGE: &str = "sha256:7777777777777777777777777777777777777777777777777777777777777777";

/// Runs the CLI with only `env` from the provider environment.
fn encompute(args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_encompute"));
    for v in [
        "BAO_ADDR",
        "VAULT_ADDR",
        "BAO_TOKEN",
        "VAULT_TOKEN",
        "BAO_TOKEN_FILE",
        "VAULT_TOKEN_FILE",
    ] {
        c.env_remove(v);
    }
    let out = c.args(args).envs(env.iter().copied()).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into(),
        String::from_utf8_lossy(&out.stderr).into(),
    )
}

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let d = std::env::temp_dir().join(format!(
            "encompute-cli-keys-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }

    fn p(&self, f: &str) -> String {
        self.0.join(f).to_str().unwrap().to_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn ok(args: &[&str], env: &[(&str, &str)]) -> String {
    let (code, out, err) = encompute(args, env);
    assert_eq!(code, 0, "{args:?}: {out}{err}");
    out
}

/// Fails with `code` (e.g. `ENC2004`) on stderr.
fn refused(args: &[&str], env: &[(&str, &str)], code: &str) -> String {
    let (c, out, err) = encompute(args, env);
    assert_ne!(c, 0, "{args:?} accepted: {out}{err}");
    assert!(
        err.contains(&format!("error[{code}]")),
        "{args:?}: {out}{err}"
    );
    err
}

/// A compiled model, a mock hardware root, and a production and a
/// development release policy for it. Returns the mock root.
fn setup(d: &Dir) -> String {
    std::fs::write(
        d.p("m.eir"),
        "encompute 0.1\nprogram m precision 0.01\n%0 = input \"x\" [-1.0, 1.0] : secret scalar\n\
         output \"y\" = %0\n",
    )
    .unwrap();
    ok(&["compile", &d.p("m.eir"), "-o", &d.p("m.encompute")], &[]);
    let root = ok(&["attest", "mock-root", &d.p("hw.seed")], &[])
        .trim()
        .to_owned();
    let m = d.p("m.encompute");
    let policy = |tee: &str, dev: bool| {
        let mut a = vec![
            "attest",
            "policy",
            m.as_str(),
            "--backend",
            "mock",
            "--image",
            IMAGE,
            "--tee",
            tee,
        ];
        if dev {
            a.push("--development");
        }
        ok(&a, &[])
    };
    std::fs::write(d.p("prod-policy.json"), policy("tdx", false)).unwrap();
    std::fs::write(d.p("dev-policy.json"), policy("mock", true)).unwrap();
    root
}

fn protect<'a>(d: &'a Dir, policy: &'a str, extra: &[&'a str]) -> Vec<String> {
    let mut a: Vec<String> = [
        "keys",
        "protect",
        "--asset",
        "weights",
        "--policy",
        &d.p(policy),
        "--broker-id",
        "modelco",
        "--broker",
        &d.p("b.json"),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.extend(extra.iter().map(|s| s.to_string()));
    a
}

fn strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

#[test]
fn production_keys_commands_never_fall_back_to_development_storage() {
    let d = Dir::new("prod");
    let root = setup(&d);
    let broker = Path::new(&d.0).join("b.json");

    // No KEK: the development file store is refused for a production broker.
    let a = protect(&d, "prod-policy.json", &[]);
    let e = refused(&strs(&a), &[], "ENC2004");
    assert!(e.contains("development only"), "{e}");
    assert!(!broker.exists());
    // A development root key.
    let roots = d.p("roots.json");
    let dev_root = format!("development:{roots}");
    let dev_wrapped = d.p("dev-kek.wrapped.json");
    let a = protect(
        &d,
        "prod-policy.json",
        &[
            "--root-key",
            &dev_root,
            "--organization",
            "modelco",
            "--wrapped-kek",
            &dev_wrapped,
        ],
    );
    refused(&strs(&a), &[], "ENC2004");
    assert!(!broker.exists());
    // (The refusal comes after the development root key and its wrapped
    // KEK were created on disk: nothing is protected by them.)
    assert!(Path::new(&dev_wrapped).exists());
    // A development policy.
    let kek = d.p("k.kek");
    let a = protect(&d, "dev-policy.json", &["--kek", &kek]);
    refused(&strs(&a), &[], "ENC2002");
    assert!(!broker.exists());

    // A production broker under a local KEK.
    let a = protect(&d, "prod-policy.json", &["--kek", &kek]);
    let out = ok(&strs(&a), &[]);
    assert!(out.contains("(production)"), "{out}");
    let saved = std::fs::read(&broker).unwrap();
    let b = d.p("b.json");

    // Reopened without its KEK, or with a development root key: refused,
    // and the state file is unchanged.
    refused(
        &["keys", "rotate", "--asset", "weights", "--broker", &b],
        &[],
        "ENC2004",
    );
    refused(
        &[
            "keys",
            "rotate",
            "--asset",
            "weights",
            "--broker",
            &b,
            "--root-key",
            &dev_root,
            "--organization",
            "modelco",
            "--wrapped-kek",
            &dev_wrapped,
        ],
        &[],
        "ENC2004",
    );
    refused(&["keys", "challenge", "--broker", &b], &[], "ENC2004");
    assert_eq!(std::fs::read(&broker).unwrap(), saved);

    // Development (mock) evidence to a production broker: refused.
    let c = ok(&["keys", "challenge", "--broker", &b, "--kek", &kek], &[]);
    std::fs::write(d.p("c.json"), c).unwrap();
    ok(
        &[
            "workload",
            "attest",
            &d.p("m.encompute"),
            "--backend",
            "mock",
            "--challenge",
            &d.p("c.json"),
            "--identity",
            &d.p("eval.id"),
            "--attester",
            "mock",
            "--mock-seed",
            &d.p("hw.seed"),
            "--mock-image",
            IMAGE,
            "--out",
            &d.p("ev.json"),
        ],
        &[],
    );
    let (code, out, err) = encompute(
        &[
            "keys",
            "release",
            "--asset",
            "weights",
            "--attestation",
            &d.p("ev.json"),
            "--mock-root",
            &root,
            "--broker",
            &b,
            "--kek",
            &kek,
            "--out",
            &d.p("grant.json"),
        ],
        &[],
    );
    assert_eq!(code, 1, "{out}{err}");
    assert!(
        out.contains("KEY RELEASE          REFUSED: ENC2002"),
        "{out}"
    );
    assert!(!Path::new(&d.p("grant.json")).exists());
}

#[test]
fn openbao_root_key_misconfiguration_is_refused() {
    let d = Dir::new("misconfig");
    setup(&d);
    let wrapped = d.p("kek.wrapped.json");
    let token_file = d.p("empty.token");
    std::fs::write(&token_file, "\n").unwrap();
    let with = |root_key: &str, org: Option<&str>| {
        let mut a = protect(
            &d,
            "prod-policy.json",
            &["--root-key", root_key, "--wrapped-kek", &wrapped],
        );
        if let Some(o) = org {
            a.extend(["--organization".to_owned(), o.to_owned()]);
        }
        a
    };
    let transit = with("openbao:transit/modelco", Some("modelco"));
    type Case<'a> = (&'a str, Vec<String>, Vec<(&'a str, &'a str)>, &'a str);
    let cases: Vec<Case> = vec![
        (
            "no address",
            transit.clone(),
            vec![("BAO_TOKEN", "t")],
            "BAO_ADDR",
        ),
        (
            "no token",
            transit.clone(),
            vec![("BAO_ADDR", "https://bao.internal:8200")],
            "BAO_TOKEN",
        ),
        (
            "empty token",
            transit.clone(),
            vec![("BAO_ADDR", "https://bao.internal:8200"), ("BAO_TOKEN", "")],
            "token",
        ),
        (
            "empty token file",
            transit.clone(),
            vec![
                ("BAO_ADDR", "https://bao.internal:8200"),
                ("BAO_TOKEN_FILE", &token_file),
                ("BAO_TOKEN", "a-token-that-must-not-be-used"),
            ],
            "token",
        ),
        (
            "plain http",
            transit.clone(),
            vec![("BAO_ADDR", "http://bao.internal:8200"), ("BAO_TOKEN", "t")],
            "https",
        ),
        (
            "loopback look-alike",
            transit.clone(),
            vec![
                ("BAO_ADDR", "http://127.0.0.1.evil.example:8200"),
                ("BAO_TOKEN", "t"),
            ],
            "https",
        ),
        (
            "unreachable",
            transit.clone(),
            vec![("BAO_ADDR", "http://127.0.0.1:1"), ("BAO_TOKEN", "t")],
            "unavailable",
        ),
        (
            "no key name",
            with("openbao:transit", Some("modelco")),
            vec![],
            "openbao:MOUNT/KEY",
        ),
        (
            "unknown provider",
            with("aws:alias/k", Some("modelco")),
            vec![],
            "openbao:MOUNT/KEY",
        ),
        (
            "no organization",
            with("openbao:transit/modelco", None),
            vec![],
            "--organization",
        ),
    ];
    for (what, args, env, msg) in cases {
        let e = refused(&strs(&args), &env, "ENC2004");
        assert!(e.contains(msg), "{what}: {e}");
        assert!(!e.contains("a-token-that-must-not-be-used"), "{what}: {e}");
        assert!(!Path::new(&wrapped).exists(), "{what}: a KEK was written");
        assert!(
            !Path::new(&d.p("b.json")).exists(),
            "{what}: a broker was written"
        );
    }
}

// --- OpenBao ----------------------------------------------------------------------

fn bao() -> Option<(String, String)> {
    match (
        std::env::var("ENCOMPUTE_TEST_BAO_ADDR"),
        std::env::var("ENCOMPUTE_TEST_BAO_TOKEN"),
    ) {
        (Ok(a), Ok(t)) => Some((a, t)),
        _ if std::env::var("ENCOMPUTE_REQUIRE_SERVICES").is_ok() => {
            panic!("ENCOMPUTE_REQUIRE_SERVICES is set but ENCOMPUTE_TEST_BAO_ADDR is not")
        }
        _ => {
            eprintln!("SKIPPED: set ENCOMPUTE_TEST_BAO_ADDR and ENCOMPUTE_TEST_BAO_TOKEN");
            None
        }
    }
}

fn bao_admin(addr: &str, token: &str, path: &str, body: serde_json::Value) {
    let r = ureq::post(&format!("{addr}/v1/{path}"))
        .set("X-Vault-Token", token)
        .send_json(body);
    match r {
        Ok(_) | Err(ureq::Error::Status(400, _)) => {} // mount already enabled
        Err(e) => panic!("{path}: {e}"),
    }
}

#[test]
fn openbao_keys_lifecycle_through_the_cli() {
    let Some((addr, token)) = bao() else { return };
    let d = Dir::new("bao");
    setup(&d);
    bao_admin(
        &addr,
        &token,
        "sys/mounts/transit",
        serde_json::json!({"type": "transit"}),
    );
    let key = format!(
        "cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    bao_admin(
        &addr,
        &token,
        &format!("transit/keys/{key}"),
        serde_json::json!({}),
    );
    let token_file = d.p("bao.token");
    std::fs::write(&token_file, format!("{token}\n")).unwrap();
    // As deployed: a token file only its owner can write (the umask alone
    // leaves it group-writable on some systems, and the broker refuses that).
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let env = [
        ("BAO_ADDR", addr.as_str()),
        ("BAO_TOKEN_FILE", token_file.as_str()),
    ];
    let root_key = format!("openbao:transit/{key}");
    let wrapped = d.p("kek.wrapped.json");
    let b = d.p("b.json");
    let file = |org: &str| -> Vec<String> {
        [
            "--broker",
            &b,
            "--root-key",
            &root_key,
            "--organization",
            org,
            "--wrapped-kek",
            &wrapped,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    };
    let run = |cmd: &[&str], org: &str| {
        let mut a: Vec<String> = cmd.iter().map(|s| s.to_string()).collect();
        a.extend(file(org));
        a
    };

    // Create: a production broker whose KEK is wrapped in OpenBao.
    let mut a = protect(&d, "prod-policy.json", &[]);
    a.retain(|x| x != "--broker" && x != &b);
    a.extend(file("modelco"));
    let out = ok(&strs(&a), &env);
    assert!(out.contains("(production)"), "{out}");
    let w: serde_json::Value = serde_json::from_slice(&std::fs::read(&wrapped).unwrap()).unwrap();
    assert_eq!(w["organization"], "modelco");
    assert_eq!(w["key_version"], 1);
    let state = std::fs::read_to_string(&b).unwrap();
    assert!(state.contains("root-wrapped-kek") && !state.contains("plaintext"));

    // Rotate, revoke, rotate the root key.
    let out = ok(
        &strs(&run(&["keys", "rotate", "--asset", "weights"], "modelco")),
        &env,
    );
    assert!(out.contains("key version 2"), "{out}");
    let out = ok(
        &strs(&run(
            &["keys", "revoke", "--asset", "weights", "--version", "1"],
            "modelco",
        )),
        &env,
    );
    assert!(out.contains("key version 1 revoked"), "{out}");
    let s: serde_json::Value = serde_json::from_slice(&std::fs::read(&b).unwrap()).unwrap();
    assert_eq!(
        s["secrets"]["weights"]["versions"]["1"]["key"]["form"],
        "destroyed"
    );
    let before = std::fs::read(&b).unwrap();
    let out = ok(&strs(&run(&["keys", "rotate-root"], "modelco")), &env);
    assert!(out.contains("version 1 -> 2"), "{out}");
    assert_eq!(std::fs::read(&b).unwrap(), before, "asset keys untouched");
    ok(&strs(&run(&["keys", "challenge"], "modelco")), &env);

    // Another organization, or no provider token: refused.
    refused(
        &strs(&run(&["keys", "challenge"], "otherco")),
        &env,
        "ENC2004",
    );
    refused(
        &strs(&run(&["keys", "challenge"], "modelco")),
        &[("BAO_ADDR", addr.as_str()), ("BAO_TOKEN", "wrong")],
        "ENC2004",
    );

    // The wrapped KEK lost: refused (a new KEK does not open the old
    // keys); restored from backup: the broker opens again.
    let backup = std::fs::read(&wrapped).unwrap();
    std::fs::remove_file(&wrapped).unwrap();
    let e = refused(
        &strs(&run(&["keys", "challenge"], "modelco")),
        &env,
        "ENC2004",
    );
    assert!(e.contains("open it with that store"), "{e}");
    std::fs::write(&wrapped, &backup).unwrap();
    ok(&strs(&run(&["keys", "challenge"], "modelco")), &env);
}

/// Review finding KB-2 (ENC-SF-2026-043): a broker state file without its authentication tag
/// (one written before 0.3.0-rc.4, or with the tag stripped) is refused, and
/// opens again only after its owner has checked and confirmed it.
#[test]
fn an_unauthenticated_broker_state_needs_its_owner_to_upgrade_it() {
    let d = Dir::new("upgrade");
    setup(&d);
    let kek = d.p("k.kek");
    let b = d.p("b.json");
    ok(
        &strs(&protect(&d, "prod-policy.json", &["--kek", &kek])),
        &[],
    );
    let rotate = [
        "keys", "rotate", "--asset", "weights", "--broker", &b, "--kek", &kek,
    ];

    // Strip the tag and the generation, as in an older state file.
    let mut state: serde_json::Value = serde_json::from_slice(&std::fs::read(&b).unwrap()).unwrap();
    let o = state.as_object_mut().unwrap();
    assert!(o.remove("mac").is_some(), "the saved state carries a mac");
    o.remove("generation");
    // Non-default release gates, which the owner must be shown before confirming.
    let p = &mut state["secrets"]["weights"]["release_policy"];
    p["require_gpu_attestation"] = serde_json::json!(true);
    p["max_evidence_age_secs"] = serde_json::json!(90);
    std::fs::write(&b, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    let legacy = std::fs::read(&b).unwrap();

    let e = refused(&rotate, &[], "ENC2004");
    assert!(e.contains("upgrade-state"), "{e}");
    // Shown, not authenticated, without --confirm.
    let upgrade = ["keys", "upgrade-state", "--broker", &b, "--kek", &kek];
    let (code, out, err) = encompute(&upgrade, &[]);
    assert_eq!(code, 1, "{out}{err}");
    assert!(
        out.contains("NOT AUTHENTICATED") && out.contains(IMAGE),
        "{out}"
    );
    // Every field that gates release is shown, so --confirm authenticates
    // only what the owner saw.
    for shown in [
        "Mode",
        "Organization",
        "Current version",
        "Revoked versions",
        "Execution",
        "Policy ",
        "Privacy policy",
        "Artifact",
        "TEEs",
        "Minimum TCB",
        "Debug",
        "GPU attestation   required",
        "Max evidence age  90 s",
        "Mock evidence     refused",
        "Policy format",
    ] {
        assert!(out.contains(shown), "{shown:?} not shown:\n{out}");
    }
    assert_eq!(std::fs::read(&b).unwrap(), legacy);
    // Confirmed: authenticated, and usable again.
    let mut confirmed = upgrade.to_vec();
    confirmed.push("--confirm");
    let out = ok(&confirmed, &[]);
    assert!(out.contains("now authenticated"), "{out}");
    ok(&rotate, &[]);
    // A later edit is refused again.
    let mut state: serde_json::Value = serde_json::from_slice(&std::fs::read(&b).unwrap()).unwrap();
    state["mode"] = serde_json::json!("development");
    std::fs::write(&b, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    refused(&rotate, &[], "ENC2004");
}
