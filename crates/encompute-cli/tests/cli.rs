use std::process::Command;

const MODEL: &str = "encompute 0.1
program score precision 0.001
%0 = input \"x\" [-1.0, 1.0] : secret vector<3>
%1 = const [0.5, -0.25, 2.0] : public vector<3>
%2 = dot %1, %0 : secret scalar
%3 = sigmoid %2 : secret scalar
output \"score\" = %3
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

#[test]
fn compile_run_test_explain_bench() {
    let dir = std::env::temp_dir().join(format!("encompute-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("score.eir");
    std::fs::write(&src, MODEL).unwrap();
    let art = dir.join("score.encompute");

    let (code, out, err) = encompute(&[
        "compile",
        src.to_str().unwrap(),
        "-o",
        art.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("wrote"));

    let a = art.to_str().unwrap();
    let (code, out, _) = encompute(&["run", a, "--input", "x=1,0,-0.5"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let want = 1.0 / (1.0 + (-(0.5f64 - 1.0)).exp());
    assert!((v["score"][0].as_f64().unwrap() - want).abs() < 1e-12);

    let (code, out, _) = encompute(&["run", a, "--input", "x=1,0,-0.5", "--mode", "mock"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!((v["score"][0].as_f64().unwrap() - want).abs() < 1e-3);

    let (code, out, _) = encompute(&["test", a, "--cases", "50"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("PASS"));

    let (code, out, _) = encompute(&["explain", a, "--measure", "10"]);
    assert_eq!(code, 0);
    assert!(out.contains("degree") && out.contains("Accuracy (measured"));

    let (code, out, _) = encompute(&["bench", a, "--reps", "2", "--json"]);
    assert_eq!(code, 0);
    assert!(out.contains("evaluate_ms"));

    let (code, _, err) = encompute(&["run", a, "--input", "x=5,0,0"]);
    assert_eq!(code, 2);
    assert!(err.contains("error[ENC1102]"), "{err}");
}

#[test]
fn keys_and_audit() {
    let dir = std::env::temp_dir().join(format!("encompute-audit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("score.eir");
    std::fs::write(&src, MODEL).unwrap();
    let art = dir.join("score.encompute");
    let keys = dir.join("score.keys");
    let (a, k) = (art.to_str().unwrap(), keys.to_str().unwrap());
    assert_eq!(encompute(&["compile", src.to_str().unwrap(), "-o", a]).0, 0);
    let (code, out, err) = encompute(&["keys", "generate", a, "-o", k, "--mode", "mock"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("wrote"));

    let (code, out, _) = encompute(&["audit", a, "--keys", k]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("PASS  keys.secret_permissions"));
    assert!(out.contains("WARN  ckks.decryption_oracle"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let secret = keys.join("secret.key");
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (code, out, _) = encompute(&["audit", a, "--keys", k]);
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("FAIL  keys.secret_permissions"));
        // Replacing a secret.key with a wider mode (--force) leaves an
        // owner-only one.
        let (code, _, err) =
            encompute(&["keys", "generate", a, "-o", k, "--mode", "mock", "--force"]);
        assert_eq!(code, 0, "{err}");
        let mode = std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret.key is {mode:o}");
    }
}

const ADULT: &str = "encompute 0.1
program adult precision 0.001
%0 = input \"age\" [0.0, 120.0] : secret u8
%1 = const [18.0] : public u8
%2 = ge %0, %1 : secret bool
output \"adult\" = %2
";

fn serve() -> String {
    use encompute_evaluator::server::{Evaluator, Limits};
    let server = encompute_verification::http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr());
    std::thread::spawn(move || {
        Evaluator::new(encompute_evaluator::Backends::MOCK, Limits::default()).serve(server)
    });
    url
}

/// `run --remote` verifies the evaluator's receipt before decrypting;
/// `verify` checks saved receipts and never claims an execution proof.
#[test]
fn remote_receipts_and_verify() {
    let dir = std::env::temp_dir().join(format!("encompute-cli-receipt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |f: &str| dir.join(f).to_str().unwrap().to_owned();
    std::fs::write(dir.join("adult.eir"), ADULT).unwrap();
    let (code, _, err) = encompute(&["compile", &p("adult.eir"), "-o", &p("adult.encompute")]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = encompute(&[
        "keys",
        "generate",
        &p("adult.encompute"),
        "-o",
        &p("keys"),
        "--mode",
        "mock",
    ]);
    assert_eq!(code, 0, "{err}");

    let url = serve();
    let run = |url: &str, age: &str| {
        encompute(&[
            "run",
            &p("adult.encompute"),
            "--remote",
            url,
            "--keys",
            &p("keys"),
            "--input",
            &format!("age={age}"),
            "--save-receipt",
            &p("result.receipt.json"),
            "--save-envelopes",
            &p("exchange"),
        ])
    };
    let (code, out, err) = run(&url, "30");
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.trim(), "{\n  \"adult\": true\n}");
    assert!(err.contains("Evaluator receipt       verified"), "{err}");
    assert!(err.contains("Execution proof         not present"), "{err}");
    assert!(err.contains("on first use"), "{err}");
    let pinned = std::fs::read_to_string(dir.join("keys/evaluator.pub")).unwrap();
    // The pin is public and written 0644 whatever the umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let pin = dir.join("keys/evaluator.pub");
        std::fs::remove_file(&pin).unwrap();
        let out = Command::new("sh")
            .arg("-c")
            .arg("umask 077; exec \"$@\"")
            .arg("sh")
            .arg(env!("CARGO_BIN_EXE_encompute"))
            .args([
                "run",
                &p("adult.encompute"),
                "--remote",
                &url,
                "--keys",
                &p("keys"),
                "--input",
                "age=30",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let mode = std::fs::metadata(&pin).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "evaluator.pub is {mode:o}");
        assert_eq!(std::fs::read_to_string(&pin).unwrap(), pinned);
    }

    let receipt = p("result.receipt.json");
    // The evaluator here is the mock backend (test infrastructure): these
    // checks are about the bindings, so they accept mock explicitly.
    let verify = |extra: &[&str]| {
        let mut args = vec!["verify", receipt.as_str(), "--allow-mock"];
        args.extend_from_slice(extra);
        encompute(&args)
    };
    let full = [
        "--model",
        &p("adult.encompute"),
        "--request",
        &p("exchange/request.bin"),
        "--response",
        &p("exchange/response.bin"),
        "--trust-evaluator",
        pinned.trim(),
    ];
    let (code, out, _) = verify(&full);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("RECEIPT VERIFIED\nEXECUTION PROOF NOT PRESENT"),
        "{out}"
    );
    assert!(!out.contains("EXECUTION VERIFIED"));
    assert!(out.contains("TRANSCRIPT AVAILABLE"), "{out}");
    // Without --allow-mock the same receipt is refused: the mock backend
    // encrypts nothing, whoever made the request.
    let mut strict = vec!["verify", receipt.as_str()];
    strict.extend_from_slice(&full);
    let (code, out, _) = encompute(&strict);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("INVALID: the receipt is for the mock backend, which encrypts nothing"),
        "{out}"
    );
    assert!(!out.contains("RECEIPT VERIFIED"), "{out}");
    let (code, out, _) = encompute(&["verify", receipt.as_str()]);
    assert_eq!(
        code, 1,
        "a partial check of a mock receipt is refused too: {out}"
    );

    // The transcript command prints the semantic program, never values.
    let (code, out, err) = encompute(&["transcript", &p("adult.encompute"), "--backend", "mock"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("GE_CONST   r0 18") && out.contains("enctrace1:"),
        "{out}"
    );
    assert!(
        out.contains("TRANSCRIPT AVAILABLE\nEXECUTION PROOF NOT PRESENT"),
        "{out}"
    );
    let listing = out
        .split("Instructions")
        .nth(1)
        .unwrap()
        .split("Outputs")
        .next()
        .unwrap();
    assert!(!listing.contains("30"), "no runtime input value: {listing}");
    let (code, out, _) = encompute(&["explain", &p("adult.encompute")]);
    assert_eq!(code, 0);
    assert!(
        out.contains("Verification") && out.contains("proof coverage"),
        "{out}"
    );

    let (code, out, _) = verify(&[]);
    assert_eq!(code, 3, "incomplete verification is not success: {out}");
    assert!(
        out.contains("RECEIPT SIGNATURE VALID (some bindings not checked)"),
        "{out}"
    );
    assert!(out.contains("NOT CHECKED"), "{out}");
    assert!(
        out.contains("Evidence        receipt only (no execution proof)"),
        "{out}"
    );
    // SF-12: without --request, the key and request bindings are reported
    // as unchecked, never as verified.
    // (Without the request envelope, the backend comes from --backend.)
    let (code, out, _) = verify(&[
        full[0],
        full[1],
        full[4],
        full[5],
        full[6],
        full[7],
        "--backend",
        "mock",
    ]);
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("Artifact        checked"), "{out}");
    assert!(out.contains("Key             NOT CHECKED"), "{out}");
    assert!(out.contains("NOT CHECKED: key ID, request\n"), "{out}");
    assert!(!out.contains("RECEIPT VERIFIED"), "{out}");

    // SF-12: the evidence kind is checked against the artifact. A receipt
    // (validly signed by a trusted key) naming an execution proof the mock
    // program does not have is refused; one naming a proof that is not
    // checked here is never reported as fully verified.
    {
        use encompute_runtime::verification::{EvaluatorSigner, SignedExecutionReceipt};
        let signer = EvaluatorSigner::from_seed(&[42; 32]);
        let s = SignedExecutionReceipt::from_bytes(&std::fs::read(&receipt).unwrap()).unwrap();
        let mut r = s.receipt.clone();
        r.evaluator_id = signer.identity().evaluator_id();
        r.evidence = serde_json::from_value(serde_json::json!({
            "kind": "vfhe", "relation": "fhe_evaluation_v1", "protocol": "reexec",
            "protocol_version": 1, "verification_key_id": "aa".repeat(32),
            "proof_digest": "bb".repeat(32),
        }))
        .unwrap();
        let forged = p("forged.receipt.json");
        std::fs::write(&forged, r.sign(&signer).unwrap().to_bytes().unwrap()).unwrap();
        let key = signer.identity().public_key_hex();
        let mut args = vec!["verify", forged.as_str(), "--allow-mock"];
        args.extend_from_slice(&full[..6]);
        args.extend_from_slice(&["--trust-evaluator", &key]);
        let (code, out, _) = encompute(&args);
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("receipt evidence does not match"), "{out}");
        assert!(out.contains("execution proof (reexec v1"), "{out}");
        let (code, out, _) = encompute(&["verify", &forged, "--allow-mock"]);
        assert_eq!(code, 3, "{out}");
        assert!(
            out.contains("EXECUTION PROOF NAMED BUT NOT CHECKED"),
            "{out}"
        );
    }

    // The expected backend comes from the verifier, not the receipt.
    let mut other_backend = full.to_vec();
    other_backend.extend_from_slice(&["--backend", "tfhe-rs"]);
    let (code, out, _) = verify(&other_backend);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("INVALID"), "{out}");

    // A response from another execution does not match.
    let (code, _, err) = run(&url, "10");
    assert_eq!(code, 0, "{err}");
    std::fs::copy(dir.join("exchange/response.bin"), dir.join("other.bin")).unwrap();
    let (code, _, _) = run(&url, "30");
    assert_eq!(code, 0);
    let mut wrong = full.to_vec();
    let other = p("other.bin");
    wrong[5] = &other;
    let (code, out, _) = verify(&wrong);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("INVALID") && out.contains("output commitment"),
        "{out}"
    );

    // Another trusted key.
    let mut untrusted = full.to_vec();
    let zero = "11".repeat(32);
    untrusted[7] = &zero;
    let (code, out, _) = verify(&untrusted);
    assert_eq!(code, 1, "{out}");

    // An edited receipt.
    let text = std::fs::read_to_string(dir.join("result.receipt.json")).unwrap();
    std::fs::write(
        dir.join("result.receipt.json"),
        text.replace("\"scheme\":\"BinFHE\"", "\"scheme\":\"CKKS\""),
    )
    .unwrap();
    let (code, out, _) = verify(&full);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("EXECUTION PROOF NOT PRESENT"));

    // A new evaluator (new identity) is refused: the pinned key differs.
    let (code, _, err) = run(&serve(), "30");
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("ENC1606"), "{err}");
}

/// The trusted evaluator key (pinned, or given with `--trust-evaluator`) is
/// compared with the evaluator's announced identity before the program,
/// evaluation keys or ciphertexts are sent; and a pin file that cannot be
/// read is refused, never silently replaced by trust on first use.
#[test]
fn evaluator_trust_is_checked_before_sending_and_a_bad_pin_fails_closed() {
    let dir = std::env::temp_dir().join(format!("encompute-cli-pin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |f: &str| dir.join(f).to_str().unwrap().to_owned();
    std::fs::write(dir.join("adult.eir"), ADULT).unwrap();
    let (code, _, err) = encompute(&["compile", &p("adult.eir"), "-o", &p("adult.encompute")]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = encompute(&[
        "keys",
        "generate",
        &p("adult.encompute"),
        "-o",
        &p("keys"),
        "--mode",
        "mock",
    ]);
    assert_eq!(code, 0, "{err}");
    let run = |url: &str, extra: &[&str]| {
        let mut args = vec![
            "run",
            p("adult.encompute").leak(),
            "--remote",
            url,
            "--keys",
            p("keys").leak(),
            "--input",
            "age=30",
        ];
        args.extend_from_slice(extra);
        encompute(&args)
    };
    let programs = |url: &str| -> usize {
        let info: serde_json::Value = ureq::get(&format!("{url}/v1/info"))
            .call()
            .unwrap()
            .into_json()
            .unwrap();
        info["programs"].as_array().map_or(0, Vec::len)
    };

    let trusted = serve();
    let (code, _, err) = run(
        &trusted,
        &[
            "--save-receipt",
            p("r.json").leak(),
            "--save-envelopes",
            p("x").leak(),
        ],
    );
    assert_eq!(code, 0, "{err}");
    // A mock run and its receipt say plainly that nothing was encrypted.
    assert!(err.contains("mock: the inputs were NOT encrypted"), "{err}");
    let pin = dir.join("keys/evaluator.pub");
    let pinned = std::fs::read_to_string(&pin).unwrap();
    let (code, out, _) = encompute(&[
        "verify",
        &p("r.json"),
        "--allow-mock",
        "--trust-evaluator",
        pinned.trim(),
        "--model",
        &p("adult.encompute"),
        "--request",
        &p("x/request.bin"),
        "--response",
        &p("x/response.bin"),
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("MOCK BACKEND: the inputs were NOT encrypted"),
        "{out}"
    );

    // Another evaluator: refused before anything is uploaded to it.
    let other = serve();
    let (code, _, err) = run(&other, &[]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("ENC1606"), "{err}");
    assert_eq!(
        programs(&other),
        0,
        "the program was sent to an untrusted evaluator"
    );
    let key = pinned.trim().to_owned();
    let (code, _, err) = run(&other, &["--trust-evaluator", &key]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("ENC1606"), "{err}");
    assert_eq!(
        programs(&other),
        0,
        "the program was sent to an untrusted evaluator"
    );

    // A corrupt pin file is refused and kept, not re-pinned.
    std::fs::write(&pin, [0xff, 0xfe, 0x00, 0x80]).unwrap();
    let (code, _, err) = run(&other, &[]);
    assert_ne!(
        code, 0,
        "a corrupt pin was replaced by trust on first use: {err}"
    );
    assert_eq!(std::fs::read(&pin).unwrap(), [0xff, 0xfe, 0x00, 0x80]);
    assert_eq!(programs(&other), 0);
    std::fs::write(&pin, &pinned).unwrap();
    let (code, _, err) = run(&trusted, &[]);
    assert_eq!(code, 0, "{err}");
}

#[test]
fn privacy_explain_and_graph() {
    let dir = std::env::temp_dir().join(format!("encompute-cli-privacy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("step.eir");
    std::fs::write(
        &src,
        r#"encompute 0.1
program step precision 0.01 purpose "disease-training"
party "hospital-a" "Hospital A"
party "modelco" "ModelCo"
party "coordinator" "Coordinator"
asset "patients" dataset owners ["hospital-a"] readers ["hospital-a"] purposes ["disease-training"] release never derive [gradient aggregate_only to ["coordinator"]]
asset "weights" model owners ["modelco"] readers ["modelco"] purposes ["disease-training"] release never derive [gradient aggregate_only to ["coordinator"]]
%0 = input "x" [-1.0, 1.0] asset "patients" : secret vector<4>
%1 = input "w" [-1.0, 1.0] asset "weights" : secret vector<4>
%2 = mul %0, %1 : secret vector<4>
derive %2 gradient aggregate_only
output "gradient" = %2
"#,
    )
    .unwrap();
    let art = dir.join("step.encompute");
    let (code, _, err) = encompute(&[
        "compile",
        src.to_str().unwrap(),
        "-o",
        art.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}");
    let (code, out, err) = encompute(&["privacy", "explain", art.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    for want in [
        "CONFIDENTIALITY GRAPH",
        "encpolicy1:",
        "patients + weights",
        "aggregate_only",
        "aggregation boundary",
    ] {
        assert!(out.contains(want), "{want}: {out}");
    }
    let (code, out, _) = encompute(&["privacy", "graph", art.to_str().unwrap(), "--format", "dot"]);
    assert_eq!(code, 0);
    assert!(
        out.starts_with("digraph confidentiality")
            && out.contains("\"patients\" -> \"derived:%2\""),
        "{out}"
    );
    // Leaking the gradient is a compile error.
    std::fs::write(
        &src,
        std::fs::read_to_string(&src).unwrap().replace(
            "output \"gradient\" = %2",
            "output \"gradient\" = %2 to \"coordinator\"",
        ),
    )
    .unwrap();
    let (code, _, err) = encompute(&[
        "compile",
        src.to_str().unwrap(),
        "-o",
        art.to_str().unwrap(),
    ]);
    assert_eq!(code, 2);
    assert!(err.contains("ENC1905"), "{err}");
}

#[test]
fn attestation_and_key_release() {
    let dir = std::env::temp_dir().join(format!("encompute-cli-attest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |f: &str| dir.join(f).to_str().unwrap().to_owned();
    std::fs::write(
        p("m.eir"),
        "encompute 0.1\nprogram m precision 0.01\n%0 = input \"x\" [-1.0, 1.0] : secret scalar\n\
         output \"y\" = %0\n",
    )
    .unwrap();
    let ok = |args: &[&str]| {
        let (code, out, err) = encompute(args);
        assert_eq!(code, 0, "{args:?}: {out}{err}");
        out
    };
    ok(&["compile", &p("m.eir"), "-o", &p("m.encompute")]);
    let root = ok(&["attest", "mock-root", &p("hw.seed")])
        .trim()
        .to_owned();
    let image = format!("sha256:{}", "7".repeat(64));
    let policy = ok(&[
        "attest",
        "policy",
        &p("m.encompute"),
        "--backend",
        "mock",
        "--image",
        &image,
        "--tee",
        "mock",
        "--development",
    ]);
    std::fs::write(p("policy.json"), &policy).unwrap();
    // Production policies cannot name the mock TEE.
    let (code, _, err) = encompute(&[
        "attest",
        "policy",
        &p("m.encompute"),
        "--image",
        &image,
        "--tee",
        "mock",
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("ENC2002"), "{err}");
    let key = "k".repeat(32);
    std::fs::write(p("asset.key"), &key).unwrap();
    ok(&[
        "keys",
        "protect",
        "--asset",
        "weights",
        "--policy",
        &p("policy.json"),
        "--key-file",
        &p("asset.key"),
        "--broker-id",
        "modelco",
        "--development",
        "--broker",
        &p("b.json"),
    ]);
    let attest = |image: &str, out: &str| {
        let c = ok(&["keys", "challenge", "--broker", &p("b.json")]);
        std::fs::write(p("c.json"), c).unwrap();
        ok(&[
            "workload",
            "attest",
            &p("m.encompute"),
            "--backend",
            "mock",
            "--challenge",
            &p("c.json"),
            "--identity",
            &p("eval.id"),
            "--attester",
            "mock",
            "--mock-seed",
            &p("hw.seed"),
            "--mock-image",
            image,
            "--out",
            &p(out),
        ]);
    };
    let release = |ev: &str| {
        encompute(&[
            "keys",
            "release",
            "--asset",
            "weights",
            "--attestation",
            &p(ev),
            "--mock-root",
            &root,
            "--broker",
            &p("b.json"),
            "--out",
            &p("grant.json"),
        ])
    };
    attest(&image, "ev.json");
    let (code, out, err) = release("ev.json");
    assert_eq!(code, 0, "{out}{err}");
    for line in [
        "ATTESTATION          VERIFIED",
        "POLICY               SATISFIED",
        "KEY RELEASE          AUTHORIZED",
    ] {
        assert!(out.contains(line), "{out}");
    }
    let hex_key: String = key.bytes().map(|b| format!("{b:02x}")).collect();
    let grant = std::fs::read_to_string(p("grant.json")).unwrap();
    assert!(!out.contains(&key) && !grant.contains(&key) && !grant.contains(&hex_key));
    // Replay.
    let (code, out, _) = release("ev.json");
    assert_eq!(code, 1);
    assert!(out.contains("ENC2003"), "{out}");
    // Another image.
    attest("sha256:evil", "evil.json");
    let (code, out, _) = release("evil.json");
    assert_eq!(code, 1);
    assert!(out.contains("POLICY               NOT SATISFIED"), "{out}");
    // Evidence checks offline, against a policy.
    let out = ok(&[
        "attest",
        "verify",
        &p("ev.json"),
        "--policy",
        &p("policy.json"),
        "--mock-root",
        &root,
    ]);
    assert!(
        out.contains("ATTESTATION VERIFIED") && out.contains("DEVELOPMENT"),
        "{out}"
    );
    let (code, out, _) = encompute(&[
        "attest",
        "verify",
        &p("evil.json"),
        "--policy",
        &p("policy.json"),
        "--mock-root",
        &root,
    ]);
    assert_eq!(code, 1);
    assert!(out.contains("ATTESTATION REJECTED"), "{out}");
    // Revoked.
    ok(&[
        "keys",
        "revoke",
        "--asset",
        "weights",
        "--broker",
        &p("b.json"),
    ]);
    attest(&image, "ev2.json");
    let (code, out, _) = release("ev2.json");
    assert_eq!(code, 1);
    assert!(out.contains("revoked"), "{out}");
    ok(&[
        "keys",
        "rotate",
        "--asset",
        "weights",
        "--broker",
        &p("b.json"),
    ]);
    attest(&image, "ev3.json");
    assert_eq!(release("ev3.json").0, 0);
    // The broker file is the owner's alone.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(p("b.json")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn secure_aggregation_round() {
    let dir = std::env::temp_dir().join(format!("encompute-cli-secagg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |f: &str| dir.join(f).to_str().unwrap().to_owned();
    let mut eir = String::from(
        "encompute 0.1\nprogram fedavg precision 0.001 purpose \"t\"\nparty \"coordinator\" \"C\"\n",
    );
    for x in ["a", "b", "c"] {
        eir.push_str(&format!("party \"hospital-{x}\" \"H\"\n"));
    }
    for x in ["a", "b", "c"] {
        eir.push_str(&format!(
            "asset \"gradient-{x}\" gradient owners [\"hospital-{x}\"] readers [\"coordinator\"] \
             purposes [\"t\"] release aggregate_only\n"
        ));
    }
    for (i, x) in ["a", "b", "c"].iter().enumerate() {
        eir.push_str(&format!(
            "%{i} = input \"g{x}\" [-1.0, 1.0] asset \"gradient-{x}\" : secret vector<4>\n"
        ));
    }
    eir.push_str(
        "%3 = add %0, %1 : secret vector<4>\n%4 = add %3, %2 : secret vector<4>\n\
         output \"g\" = %4 to \"coordinator\"\n\
         aggregate \"g\" sum minimum 3 colluding 2 clip [-1.0, 1.0] scale 1000 modulus 16\n",
    );
    std::fs::write(p("f.eir"), eir).unwrap();
    let ok = |args: &[&str]| {
        let (code, out, err) = encompute(args);
        assert_eq!(code, 0, "{args:?}: {out}{err}");
        out
    };
    ok(&["compile", &p("f.eir"), "-o", &p("f.encompute")]);
    let out = ok(&["explain", &p("f.encompute")]);
    assert!(out.contains("MULTI-PARTY EXECUTION"), "{out}");
    let mut ids = vec![];
    for x in ["a", "b", "c"] {
        ids.push(
            ok(&[
                "aggregate",
                "identity",
                "--party",
                &format!("hospital-{x}"),
                "--key",
                &p(&format!("{x}.key")),
            ])
            .trim()
            .to_owned(),
        );
        std::fs::write(p(&format!("{x}.json")), "[0.25, -0.5, 1.0, 0.0]").unwrap();
    }
    std::fs::write(p("parties.json"), format!("[{}]", ids.join(","))).unwrap();
    // The coordinator's key, known to the parties out of band.
    let coord: serde_json::Value = serde_json::from_str(&ok(&[
        "aggregate",
        "identity",
        "--party",
        "coordinator",
        "--key",
        &p("coord.key"),
    ]))
    .unwrap();
    let coord_key = coord["public_key"].as_str().unwrap().to_owned();
    let (bundle, parties) = (p("trust.json"), p("parties.json"));
    let report = |extra: &[&str]| {
        let mut a = vec![
            "trust",
            "report",
            "--bundle",
            &bundle,
            "--parties",
            &parties,
            "--coordinator-key",
            &coord_key,
        ];
        a.extend_from_slice(extra);
        encompute(&a)
    };
    // The plan: Encompute chooses secure aggregation for the declared
    // aggregate-only gradients; every side binds its ID.
    let out = ok(&["plan", &p("f.encompute"), "-o", &p("plan.json")]);
    assert!(out.contains("secure aggregation"), "{out}");
    assert!(out.contains("ALL TRUST REQUIREMENTS SATISFIED"), "{out}");
    // A trust bundle: the program, its plan, the consortium, each owner's
    // approval.
    ok(&[
        "trust",
        "init",
        &p("f.encompute"),
        "--parties",
        &p("parties.json"),
        "--plan",
        &p("plan.json"),
        "--bundle",
        &p("trust.json"),
    ]);
    for x in ["a", "b"] {
        ok(&[
            "trust",
            "authorize",
            "--party",
            &format!("hospital-{x}"),
            "--key",
            &p(&format!("{x}.key")),
            "--bundle",
            &p("trust.json"),
        ]);
    }
    let port = 20000 + std::process::id() % 20000;
    let url = format!("http://127.0.0.1:{port}");
    // A coordinator for round `sequence`, ready once it accepts connections.
    let serve = |sequence: &str, out: &str| {
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_encompute"))
            .args([
                "aggregate",
                "serve",
                &p("f.encompute"),
                "--parties",
                &p("parties.json"),
                "--plan",
                &p("plan.json"),
                "--key",
                &p("coord.key"),
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--stage-timeout",
                "20",
                "--sequence",
                sequence,
                "--out",
                &p(out),
                "--receipt",
                &p("receipt.json"),
                "--trust-bundle",
                &p("trust.json"),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        while std::net::TcpStream::connect(("127.0.0.1", port as u16)).is_err() {
            assert!(start.elapsed().as_secs() < 20, "coordinator did not start");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        child
    };
    let coordinator = serve("1", "agg.json");
    let joins: Vec<_> = ["a", "b", "c"]
        .iter()
        .map(|x| {
            let args: Vec<String> = [
                "aggregate",
                "join",
                &p("f.encompute"),
                "--parties",
                &p("parties.json"),
                "--plan",
                &p("plan.json"),
                "--coordinator",
                &url,
                "--party",
                &format!("hospital-{x}"),
                "--key",
                &p(&format!("{x}.key")),
                "--values",
                &p(&format!("{x}.json")),
                "--state",
                &p(&format!("{x}.round")),
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            std::thread::spawn(move || {
                let a: Vec<&str> = args.iter().map(String::as_str).collect();
                encompute(&a)
            })
        })
        .collect();
    for j in joins {
        let (code, out, err) = j.join().unwrap();
        assert_eq!(code, 0, "{out}{err}");
        assert!(out.contains("CONTRIBUTION ACCEPTED"), "{out}");
    }
    let o = coordinator.wait_with_output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        o.status.success() && out.contains("AGGREGATION COMPLETE"),
        "{out}"
    );
    let agg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(p("agg.json")).unwrap()).unwrap();
    assert_eq!(agg["values"], serde_json::json!([0.75, -1.5, 3.0, 0.0]));
    let out = ok(&[
        "aggregate",
        "verify",
        &p("receipt.json"),
        &p("f.encompute"),
        "--parties",
        &p("parties.json"),
        "--plan",
        &p("plan.json"),
        "--aggregate",
        &p("agg.json"),
    ]);
    assert!(out.contains("AGGREGATION RECEIPT VERIFIED"), "{out}");
    // The trust report: hospital C has not approved the program yet.
    let (code, out, _) = report(&[]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("no valid authorization from hospital-c"),
        "{out}"
    );
    ok(&[
        "trust",
        "authorize",
        "--party",
        "hospital-c",
        "--key",
        &p("c.key"),
        "--bundle",
        &p("trust.json"),
    ]);
    let (code, out, _) = report(&["--require", "Private aggregation"]);
    assert_eq!(code, 0, "{out}");
    for want in [
        "Plan                    SATISFIED",
        "PLAN SATISFIED BY OBSERVED EXECUTION",
        "Owner authorization     AUTHORIZED",
        "Private aggregation     VERIFIED",
        "Lineage                 COMPLETE",
        "TRUST REQUIREMENTS SATISFIED",
    ] {
        assert!(out.contains(want), "{want}\n{out}");
    }
    let out = ok(&[
        "trust",
        "lineage",
        "gradient-a",
        "--bundle",
        &p("trust.json"),
    ]);
    assert!(out.contains("aggregate:"), "{out}");
    assert!(ok(&["trust", "graph", "--bundle", &p("trust.json")]).starts_with("digraph trust"));
    // A revocation reaches every aggregate derived from the asset.
    let out = ok(&[
        "trust",
        "revoke",
        "--party",
        "hospital-a",
        "--key",
        &p("a.key"),
        "--asset",
        "gradient-a",
        "--reason",
        "consent withdrawn",
        "--bundle",
        &p("trust.json"),
    ]);
    assert!(out.contains("derived from it: 1"), "{out}");
    let (code, out, _) = report(&[]);
    assert_eq!(code, 1);
    assert!(out.contains("retrain or unlearn"), "{out}");
    // Without trusted keys, nothing in the bundle vouches for itself.
    let (code, out, _) = encompute(&["trust", "report", "--bundle", &p("trust.json")]);
    assert_eq!(code, 1);
    assert!(out.contains("PRESENT (not checked)"), "{out}");
    // A coordinator offering round 1 again: the party's state refuses it.
    let mut replay = serve("1", "agg2.json");
    let (code, _, err) = encompute(&[
        "aggregate",
        "join",
        &p("f.encompute"),
        "--parties",
        &p("parties.json"),
        "--plan",
        &p("plan.json"),
        "--coordinator",
        &url,
        "--party",
        "hospital-a",
        "--key",
        &p("a.key"),
        "--values",
        &p("a.json"),
        "--state",
        &p("a.round"),
        "--timeout",
        "2",
    ]);
    replay.kill().unwrap();
    let _ = replay.wait();
    assert_ne!(code, 0);
    assert!(err.contains("ENC2102") && err.contains("replay"), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Parties that require an attested coordinator contribute to an approved
/// one and refuse a coordinator running another image.
#[test]
fn attested_coordinator_round() {
    let dir = std::env::temp_dir().join(format!("encompute-cli-coord-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |f: &str| dir.join(f).to_str().unwrap().to_owned();
    let mut eir = String::from(
        "encompute 0.1\nprogram fedavg precision 0.001 purpose \"t\"\nparty \"coordinator\" \"C\"\n",
    );
    for x in ["a", "b"] {
        eir.push_str(&format!("party \"hospital-{x}\" \"H\"\n"));
    }
    for x in ["a", "b"] {
        eir.push_str(&format!(
            "asset \"gradient-{x}\" gradient owners [\"hospital-{x}\"] readers [\"coordinator\"] \
             purposes [\"t\"] release aggregate_only\n"
        ));
    }
    for (i, x) in ["a", "b"].iter().enumerate() {
        eir.push_str(&format!(
            "%{i} = input \"g{x}\" [-1.0, 1.0] asset \"gradient-{x}\" : secret vector<4>\n"
        ));
    }
    eir.push_str(
        "%2 = add %0, %1 : secret vector<4>\noutput \"g\" = %2 to \"coordinator\"\n\
         aggregate \"g\" sum minimum 2 colluding 1 clip [-1.0, 1.0] scale 1000 modulus 16\n",
    );
    std::fs::write(p("f.eir"), eir).unwrap();
    let ok = |args: &[&str]| {
        let (code, out, err) = encompute(args);
        assert_eq!(code, 0, "{args:?}: {out}{err}");
        out
    };
    ok(&["compile", &p("f.eir"), "-o", &p("f.encompute")]);
    let root = ok(&["attest", "mock-root", &p("hw.seed")])
        .trim()
        .to_owned();
    let image = format!("sha256:{}", "8".repeat(64));
    let policy = ok(&[
        "aggregate",
        "coordinator-policy",
        &p("f.encompute"),
        "--image",
        &image,
        "--tee",
        "mock",
        "--development",
    ]);
    std::fs::write(p("coord-policy.json"), policy).unwrap();
    let mut ids = vec![];
    for x in ["a", "b"] {
        ids.push(
            ok(&[
                "aggregate",
                "identity",
                "--party",
                &format!("hospital-{x}"),
                "--key",
                &p(&format!("{x}.key")),
            ])
            .trim()
            .to_owned(),
        );
        std::fs::write(p(&format!("{x}.json")), "[0.5, -0.25, 1.0, 0.0]").unwrap();
    }
    std::fs::write(p("parties.json"), format!("[{}]", ids.join(","))).unwrap();
    let port = 22000 + std::process::id() % 20000;
    let run = |image: &str, seq: &str| {
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_encompute"))
            .args([
                "aggregate",
                "serve",
                &p("f.encompute"),
                "--parties",
                &p("parties.json"),
                "--coordinator-policy",
                &p("coord-policy.json"),
                "--key",
                &p("coord.key"),
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--stage-timeout",
                "5",
                "--sequence",
                seq,
                "--attester",
                "mock",
                "--mock-seed",
                &p("hw.seed"),
                "--mock-image",
                image,
                "--out",
                &p("agg.json"),
                "--receipt",
                &p("receipt.json"),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        while std::net::TcpStream::connect(("127.0.0.1", port as u16)).is_err() {
            assert!(start.elapsed().as_secs() < 20, "coordinator did not start");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let url = format!("http://127.0.0.1:{port}");
        let joins: Vec<_> = ["a", "b"]
            .iter()
            .map(|x| {
                let args: Vec<String> = [
                    "aggregate",
                    "join",
                    &p("f.encompute"),
                    "--parties",
                    &p("parties.json"),
                    "--coordinator-policy",
                    &p("coord-policy.json"),
                    "--mock-root",
                    &root,
                    "--coordinator",
                    &url,
                    "--party",
                    &format!("hospital-{x}"),
                    "--key",
                    &p(&format!("{x}.key")),
                    "--values",
                    &p(&format!("{x}.json")),
                    "--state",
                    &p(&format!("{x}-{seq}.state")),
                    "--timeout",
                    "10",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect();
                std::thread::spawn(move || {
                    let a: Vec<&str> = args.iter().map(String::as_str).collect();
                    encompute(&a)
                })
            })
            .collect();
        let results: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
        results
    };
    for (code, out, err) in run(&image, "1") {
        assert_eq!(code, 0, "{out}{err}");
        assert!(out.contains("CONTRIBUTION ACCEPTED"), "{out}");
    }
    for (code, _, err) in run("sha256:unapproved", "2") {
        assert_ne!(code, 0);
        assert!(err.contains("ENC2002"), "{err}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `plan`, `check` and `explain --deep` (ADR-015): with no encrypted
/// backend or TEE available, a secret input has nowhere safe to go, so
/// planning fails with a reason per candidate; a TEE with a key broker
/// makes a plan.
#[test]
fn plan_check_and_explain_deep() {
    let dir = std::env::temp_dir().join(format!("encompute-plan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("adult.eir");
    std::fs::write(&src, ADULT).unwrap();
    let s = src.to_str().unwrap();
    let infra = dir.join("infra.json");
    std::fs::write(
        &infra,
        r#"{"tees": [{"tee": "intel-tdx", "provider": "gcp-confidential-space"}],
            "key_broker": true}"#,
    )
    .unwrap();
    let i = infra.to_str().unwrap();
    let (fhe_built, _, _) = encompute(&["plan", s]);
    if fhe_built != 0 {
        let (_, out, _) = encompute(&["plan", s]);
        assert!(out.contains("PLANNING FAILED"), "{out}");
        assert!(out.contains("no requirement was weakened"), "{out}");
        let (code, out, _) = encompute(&["check", s]);
        assert_eq!(code, 1);
        assert!(out.contains("program valid   OK"), "{out}");
        assert!(out.contains("plan exists     NO"), "{out}");
    }
    let plan = dir.join("plan.json");
    let (code, out, err) = encompute(&[
        "plan",
        s,
        "--infrastructure",
        i,
        "-o",
        plan.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("ALL TRUST REQUIREMENTS SATISFIED"), "{out}");
    assert!(err.contains("encplan1:"), "{err}");
    let (code, out, _) = encompute(&["check", s, "--infrastructure", i]);
    assert_eq!(code, 0, "{out}");
    let (code, out, _) = encompute(&["explain", s, "--deep"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("Candidates") && out.contains("Security assumptions"),
        "{out}"
    );
    // Strong profile with only a development TEE: refused.
    std::fs::write(
        &infra,
        r#"{"tees": [{"tee": "mock", "provider": "mock"}], "key_broker": true}"#,
    )
    .unwrap();
    let (code, _, _) = encompute(&["plan", s, "--infrastructure", i, "--profile", "maximum"]);
    assert_eq!(code, 1);
}

/// Secret key files another user can read are refused (ENC2605): a
/// client's `secret.key` and a party identity key must be 0600.
#[cfg(unix)]
#[test]
fn secret_key_files_readable_by_others_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("encompute-cli-modes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |f: &str| dir.join(f).to_str().unwrap().to_owned();
    let chmod = |f: &str, mode: u32| {
        std::fs::set_permissions(dir.join(f), std::fs::Permissions::from_mode(mode)).unwrap()
    };
    std::fs::write(dir.join("adult.eir"), ADULT).unwrap();
    let (code, _, err) = encompute(&["compile", &p("adult.eir"), "-o", &p("adult.encompute")]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = encompute(&[
        "keys",
        "generate",
        &p("adult.encompute"),
        "-o",
        &p("keys"),
        "--mode",
        "mock",
    ]);
    assert_eq!(code, 0, "{err}");
    let url = serve();
    let run = || {
        encompute(&[
            "run",
            &p("adult.encompute"),
            "--remote",
            &url,
            "--keys",
            &p("keys"),
            "--input",
            "age=30",
        ])
    };
    let (code, _, err) = run();
    assert_eq!(code, 0, "{err}");

    for mode in [0o644, 0o640, 0o604] {
        chmod("keys/secret.key", mode);
        let (code, _, err) = run();
        assert_ne!(code, 0, "secret.key at {mode:o} was used: {err}");
        assert!(
            err.contains("ENC2605") && err.contains("chmod 600"),
            "{err}"
        );
    }
    chmod("keys/secret.key", 0o600);
    let (code, _, err) = run();
    assert_eq!(code, 0, "{err}");

    // A party identity key, reused by `aggregate identity` and signing.
    let (code, _, err) = encompute(&[
        "aggregate",
        "identity",
        "--party",
        "p",
        "--key",
        &p("p.key"),
    ]);
    assert_eq!(code, 0, "{err}");
    chmod("p.key", 0o644);
    let (code, _, err) = encompute(&[
        "aggregate",
        "identity",
        "--party",
        "p",
        "--key",
        &p("p.key"),
    ]);
    assert_ne!(code, 0, "a 0644 party key was used: {err}");
    assert!(err.contains("ENC2605"), "{err}");
    chmod("p.key", 0o600);
    let (code, identity, err) = encompute(&[
        "aggregate",
        "identity",
        "--party",
        "p",
        "--key",
        &p("p.key"),
    ]);
    assert_eq!(code, 0, "{err}");
    std::fs::write(dir.join("parties.json"), format!("[{}]", identity.trim())).unwrap();

    // The same key signing an owner authorization in a trust bundle.
    std::fs::write(
        dir.join("owned.eir"),
        "encompute 0.1\nprogram owned precision 0.001 purpose \"x\"\nparty \"p\" \"P\"\n\
         asset \"a\" dataset owners [\"p\"] readers [\"p\"] purposes [\"x\"] release owner_only\n\
         %0 = input \"v\" [0.0, 10.0] asset \"a\" : secret u8\n%1 = const [3.0] : public u8\n\
         %2 = ge %0, %1 : secret bool\noutput \"y\" = %2 to \"p\"\n",
    )
    .unwrap();
    let (code, _, err) = encompute(&["compile", &p("owned.eir"), "-o", &p("owned.encompute")]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = encompute(&[
        "trust",
        "init",
        &p("owned.encompute"),
        "--parties",
        &p("parties.json"),
        "--bundle",
        &p("t.json"),
    ]);
    assert_eq!(code, 0, "{err}");
    let authorize = || {
        encompute(&[
            "trust",
            "authorize",
            "--party",
            "p",
            "--key",
            &p("p.key"),
            "--bundle",
            &p("t.json"),
        ])
    };
    chmod("p.key", 0o644);
    let (code, _, err) = authorize();
    assert_ne!(code, 0, "a 0644 party key signed an authorization: {err}");
    assert!(err.contains("ENC2605"), "{err}");
    chmod("p.key", 0o600);
    let (code, _, err) = authorize();
    assert_eq!(code, 0, "{err}");
}

/// `keys generate` never replaces an existing secret key unless asked
/// (`--force`): results encrypted under it would become undecryptable. A
/// replacement is written to temporary files and renamed into place, so a
/// failure leaves the old keys whole.
#[test]
fn keys_generate_never_replaces_a_secret_key_without_force() {
    let dir = std::env::temp_dir().join(format!("encompute-cli-regen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |f: &str| dir.join(f).to_str().unwrap().to_owned();
    std::fs::write(dir.join("adult.eir"), ADULT).unwrap();
    let (code, _, err) = encompute(&["compile", &p("adult.eir"), "-o", &p("adult.encompute")]);
    assert_eq!(code, 0, "{err}");
    let generate = |extra: &[&str]| {
        let mut args = vec![
            "keys".to_owned(),
            "generate".to_owned(),
            p("adult.encompute"),
            "-o".to_owned(),
            p("keys"),
            "--mode".to_owned(),
            "mock".to_owned(),
        ];
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        encompute(&args)
    };
    let read = |f: &str| std::fs::read(dir.join("keys").join(f)).unwrap();
    let (code, _, err) = generate(&[]);
    assert_eq!(code, 0, "{err}");
    let (secret, eval) = (read("secret.key"), read("eval.keys"));
    std::fs::write(dir.join("keys/evaluator.pub"), "pinned\n").unwrap();

    // Without --force: refused, nothing changed.
    let (code, _, err) = generate(&[]);
    assert_ne!(code, 0, "a secret key was replaced without --force");
    assert!(err.contains("ENC1605") && err.contains("--force"), "{err}");
    assert_eq!(read("secret.key"), secret);
    assert_eq!(read("eval.keys"), eval);

    // With --force: a new key pair, owner-only, the evaluator pin kept, no
    // temporary files left behind.
    let (code, _, err) = generate(&["--force"]);
    assert_eq!(code, 0, "{err}");
    assert_ne!(read("secret.key"), secret);
    assert_ne!(read("eval.keys"), eval);
    assert_eq!(read("evaluator.pub"), b"pinned\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("keys/secret.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "secret.key is {mode:o}");
    }
    let mut names: Vec<String> = std::fs::read_dir(dir.join("keys"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["eval.keys", "evaluator.pub", "secret.key"]);
}

/// `trust report` does not say SATISFIED for a bundle with no evidence of a
/// run (risk R-04): it requires an execution, aggregation or training run
/// unless `--allow-no-run`, and it says what it covered.
#[test]
fn a_trust_report_requires_evidence_of_a_run() {
    let dir = std::env::temp_dir().join(format!("encompute-cli-coverage-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |f: &str| dir.join(f).to_str().unwrap().to_owned();
    std::fs::write(dir.join("adult.eir"), ADULT).unwrap();
    let (code, _, err) = encompute(&["compile", &p("adult.eir"), "-o", &p("adult.encompute")]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = encompute(&[
        "trust",
        "init",
        &p("adult.encompute"),
        "--bundle",
        &p("t.json"),
    ]);
    assert_eq!(code, 0, "{err}");

    // A bare program: no run, no policy.
    let (code, out, _) = encompute(&["trust", "report", "--bundle", &p("t.json")]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("Policy                  NOT PRESENT"), "{out}");
    assert!(out.contains("TRUST REQUIREMENTS NOT SATISFIED"), "{out}");
    assert!(out.contains("no evidence of a run"), "{out}");
    let (code, out, _) = encompute(&[
        "trust",
        "report",
        "--bundle",
        &p("t.json"),
        "--allow-no-run",
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("TRUST REQUIREMENTS SATISFIED"), "{out}");
    assert!(out.contains("COVERS     Evidence, Program"), "{out}");

    // With an execution receipt against a trusted evaluator key.
    let (code, _, err) = encompute(&[
        "keys",
        "generate",
        &p("adult.encompute"),
        "-o",
        &p("keys"),
        "--mode",
        "mock",
    ]);
    assert_eq!(code, 0, "{err}");
    let url = serve();
    let (code, _, err) = encompute(&[
        "run",
        &p("adult.encompute"),
        "--remote",
        &url,
        "--keys",
        &p("keys"),
        "--input",
        "age=30",
        "--save-receipt",
        &p("r.json"),
    ]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = encompute(&["trust", "add", &p("r.json"), "--bundle", &p("t.json")]);
    assert_eq!(code, 0, "{err}");
    let key = std::fs::read_to_string(dir.join("keys/evaluator.pub")).unwrap();
    // A mock-backend execution encrypted nothing: not evidence of a run
    // unless allowed explicitly.
    let (code, out, _) = encompute(&[
        "trust",
        "report",
        "--bundle",
        &p("t.json"),
        "--evaluator-key",
        key.trim(),
    ]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("Execution               FAILED"), "{out}");
    assert!(out.contains("mock backend"), "{out}");
    let (code, out, _) = encompute(&[
        "trust",
        "report",
        "--bundle",
        &p("t.json"),
        "--evaluator-key",
        key.trim(),
        "--allow-mock",
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("Execution               VERIFIED"), "{out}");
    assert!(
        out.contains("COVERS     Evidence, Program, Execution"),
        "{out}"
    );
    let (code, out, _) = encompute(&[
        "trust",
        "report",
        "--bundle",
        &p("t.json"),
        "--evaluator-key",
        key.trim(),
        "--allow-mock",
        "--json",
    ]);
    assert_eq!(code, 0, "{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["satisfied"], true);
    assert_eq!(
        v["covered"],
        serde_json::json!(["Evidence", "Program", "Execution"])
    );
}

/// `run --remote` reads `eval.keys` (about 525 MiB for exact programs) only
/// when the evaluator lacks the keys, not on every run.
#[test]
fn evaluation_keys_are_read_only_when_the_evaluator_lacks_them() {
    let dir = std::env::temp_dir().join(format!("encompute-cli-lazykeys-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |f: &str| dir.join(f).to_str().unwrap().to_owned();
    std::fs::write(dir.join("adult.eir"), ADULT).unwrap();
    let (code, _, err) = encompute(&["compile", &p("adult.eir"), "-o", &p("adult.encompute")]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = encompute(&[
        "keys",
        "generate",
        &p("adult.encompute"),
        "-o",
        &p("keys"),
        "--mode",
        "mock",
    ]);
    assert_eq!(code, 0, "{err}");
    let key_of = |url: &str| -> String {
        let info: serde_json::Value = ureq::get(&format!("{url}/v1/info"))
            .call()
            .unwrap()
            .into_json()
            .unwrap();
        info["evaluator"]["public_key"].as_str().unwrap().to_owned()
    };
    let run = |url: &str| {
        let key = key_of(url);
        encompute(&[
            "run",
            &p("adult.encompute"),
            "--remote",
            url,
            "--keys",
            &p("keys"),
            "--trust-evaluator",
            &key,
            "--input",
            "age=30",
        ])
    };
    let url = serve();
    let (code, _, err) = run(&url);
    assert_eq!(code, 0, "{err}");
    let good = std::fs::read(dir.join("keys/eval.keys")).unwrap();

    // The evaluator holds the keys now: the file is not read at all, so
    // even a corrupt one does not matter.
    std::fs::write(dir.join("keys/eval.keys"), b"not an envelope").unwrap();
    let (code, out, err) = run(&url);
    assert_eq!(code, 0, "eval.keys was read although not needed: {err}");
    assert_eq!(out.trim(), "{\n  \"adult\": true\n}");

    // A fresh evaluator lacks them: the file is read (and here refused).
    let fresh = serve();
    let (code, _, err) = run(&fresh);
    assert_ne!(code, 0, "{err}");
    std::fs::write(dir.join("keys/eval.keys"), &good).unwrap();
    let (code, _, err) = run(&fresh);
    assert_eq!(code, 0, "{err}");
}
