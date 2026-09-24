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
    assert!(out.contains("Chebyshev degree") && out.contains("measured"));

    let (code, out, _) = encompute(&["bench", a, "--reps", "2", "--json"]);
    assert_eq!(code, 0);
    assert!(out.contains("evaluate_ms"));

    let (code, _, err) = encompute(&["run", a, "--input", "x=5,0,0"]);
    assert_eq!(code, 2);
    assert!(err.contains("error[ENC1102]"), "{err}");
}
