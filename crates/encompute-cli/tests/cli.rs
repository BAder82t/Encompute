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
    assert!(out.contains("TRANSCRIPT AVAILABLE"), "{out}");

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
    // A trust bundle: the program, the consortium, each owner's approval.
    ok(&[
        "trust",
        "init",
        &p("f.encompute"),
        "--parties",
        &p("parties.json"),
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
