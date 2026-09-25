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
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
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

    let receipt = p("result.receipt.json");
    let verify = |extra: &[&str]| {
        let mut args = vec!["verify", receipt.as_str()];
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

    let (code, out, _) = verify(&[]);
    assert_eq!(code, 3, "incomplete verification is not success: {out}");
    assert!(
        out.contains("RECEIPT SIGNATURE VALID (some bindings not checked)"),
        "{out}"
    );
    assert!(out.contains("NOT CHECKED"), "{out}");

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
        text.replace("\"scheme\":\"TFHE\"", "\"scheme\":\"CKKS\""),
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
