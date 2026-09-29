//! `encompute jobs run` pins evaluator keys: the control plane names the
//! evaluator and its receipt key, and a compromised control plane must not
//! be able to choose which key the client accepts (review finding EV-4).
//! Before this fix the CLI trusted whatever key the control plane returned,
//! and printed "Evaluator receipt verified (registered key)".

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};

const TRUSTED: &str = "abababababababababababababababababababababababababababababababab";
const ROGUE: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

const MODEL: &str = "encompute 0.1
program score precision 0.001
%0 = input \"x\" [-1.0, 1.0] : secret vector<3>
%1 = const [0.5, -0.25, 2.0] : public vector<3>
%2 = dot %1, %0 : secret scalar
output \"score\" = %2
";

type Log = Arc<Mutex<Vec<String>>>;

/// A one-request-per-connection HTTP stub: records `METHOD path` and
/// answers with `reply(method, path)` (status, JSON body).
fn stub(reply: impl Fn(&str, &str) -> (u16, String) + Send + 'static) -> (String, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let log: Log = Arc::default();
    let seen = log.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let mut r = BufReader::new(conn.try_clone().unwrap());
            let mut line = String::new();
            if r.read_line(&mut line).is_err() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (method, path) = (
                parts.next().unwrap_or("").to_owned(),
                parts.next().unwrap_or("").to_owned(),
            );
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    if k.eq_ignore_ascii_case("content-length") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut body = vec![0; len];
            let _ = r.read_exact(&mut body);
            seen.lock().unwrap().push(format!("{method} {path}"));
            let (status, body) = reply(&method, &path);
            let _ = write!(
                conn,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (url, log)
}

/// A (well-formed, unsigned) job grant: the client only forwards it.
fn grant() -> serde_json::Value {
    use encompute_verification::service::{JobGrant, JOB_GRANT_VERSION};
    serde_json::to_value(JobGrant {
        version: JOB_GRANT_VERSION,
        job_id: "job_1".into(),
        organization: "o".into(),
        project: "prj_1".into(),
        plan_id: "pln_1".into(),
        spec_id: "s".repeat(64),
        program_id: "p".repeat(64),
        evaluator: "evaluator-1".into(),
        backend: "mock".into(),
        profile: "p".into(),
        issued_at: 0,
        expires_at: 1,
        issuer: "control-plane".into(),
        issuer_public_key: String::new(),
        signature: String::new(),
    })
    .unwrap()
}

/// A control plane scheduling every job on `evaluator` with `receipt_key`.
fn control_plane(evaluator: &str, receipt_key: &str) -> (String, Log) {
    let (evaluator, receipt_key) = (evaluator.to_owned(), receipt_key.to_owned());
    stub(move |_, path| match path {
        "/v1/plans" => (200, r#"{"id": "pln_1"}"#.into()),
        "/v1/jobs" => (
            200,
            serde_json::json!({"id": "job_1", "state": "queued", "grant": grant(),
                "evaluator_url": evaluator, "evaluator_receipt_key": receipt_key})
            .to_string(),
        ),
        _ => (404, r#"{"code": "ENC2603", "message": "no"}"#.into()),
    })
}

struct Setup {
    dir: std::path::PathBuf,
    model: String,
}

fn setup(name: &str) -> Setup {
    let dir =
        std::env::temp_dir().join(format!("encompute-jobs-run-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("m.eir"), MODEL).unwrap();
    let model = dir.join("m.encompute").display().to_string();
    let out = Command::new(env!("CARGO_BIN_EXE_encompute"))
        .args([
            "compile",
            &dir.join("m.eir").display().to_string(),
            "-o",
            &model,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = Command::new(env!("CARGO_BIN_EXE_encompute"))
        .args([
            "keys",
            "generate",
            "--mode",
            "mock",
            &model,
            "-o",
            &dir.join("keys").display().to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Setup { dir, model }
}

/// Runs `encompute jobs run` against `control` with `args` and `env`;
/// returns (exit code, stderr).
fn jobs_run(s: &Setup, control: &str, args: &[&str], env: &[(&str, &str)]) -> (i32, String) {
    let keys = s.dir.join("keys").display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_encompute"));
    cmd.args([
        "jobs",
        "run",
        &s.model,
        "--project",
        "prj_1",
        "--purpose",
        "t",
    ])
    .args(["-i", "x=0.1,0.2,0.3", "--keys", &keys])
    .args(args)
    .env("ENCOMPUTE_CONTROL_URL", control)
    .env("ENCOMPUTE_TOKEN", "t")
    .env("XDG_CONFIG_HOME", &s.dir);
    for k in [
        "ENCOMPUTE_TRUSTED_EVALUATORS",
        "ENCOMPUTE_ALLOW_UNPINNED_EVALUATOR",
        "ENCOMPUTE_ENV",
        "ENCOMPUTE_SERVICE_ID",
        "ENCOMPUTE_SERVICE_KEY_FILE",
    ] {
        cmd.env_remove(k);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into(),
    )
}

#[test]
fn a_key_outside_the_pin_set_is_refused_before_anything_is_sent() {
    let s = setup("pin");
    let (evaluator, sent) = stub(|_, _| (500, "{}".into()));
    let (control, _) = control_plane(&evaluator, ROGUE);
    for (args, env) in [
        (&["--trust-evaluator", TRUSTED][..], &[][..]),
        (&[][..], &[("ENCOMPUTE_TRUSTED_EVALUATORS", TRUSTED)][..]),
        // An explicitly empty pin set refuses every key.
        (&[][..], &[("ENCOMPUTE_TRUSTED_EVALUATORS", " , ")][..]),
    ] {
        let (code, err) = jobs_run(&s, &control, args, env);
        assert_ne!(code, 0, "{err}");
        assert!(
            err.contains("ENC2607") && err.contains("not among the trusted evaluators"),
            "{err}"
        );
    }
    assert!(
        sent.lock().unwrap().is_empty(),
        "the evaluator was contacted: {:?}",
        sent.lock().unwrap()
    );
}

#[test]
fn without_a_pin_the_job_is_refused_unless_explicitly_in_development() {
    let s = setup("unpinned");
    let (evaluator, sent) = stub(|_, _| (500, "{}".into()));
    let (control, asked) = control_plane(&evaluator, ROGUE);
    let (code, err) = jobs_run(&s, &control, &[], &[]);
    assert_ne!(code, 0);
    assert!(
        err.contains("ENC2605") && err.contains("--trust-evaluator"),
        "{err}"
    );
    assert!(
        asked.lock().unwrap().is_empty(),
        "refused before submitting"
    );
    // The development opt-out is refused in production.
    let (code, err) = jobs_run(
        &s,
        &control,
        &["--allow-unpinned-evaluator"],
        &[("ENCOMPUTE_ENV", "production")],
    );
    assert_ne!(code, 0);
    assert!(
        err.contains("ENC2605") && err.contains("production"),
        "{err}"
    );
    assert!(sent.lock().unwrap().is_empty());
    // In development it proceeds to the evaluator (which then fails here).
    let (code, _) = jobs_run(&s, &control, &["--allow-unpinned-evaluator"], &[]);
    assert_ne!(code, 0);
    assert!(!sent.lock().unwrap().is_empty());
}

#[test]
fn a_pinned_key_proceeds_to_the_evaluator() {
    let s = setup("pinned");
    let (evaluator, sent) = stub(|_, _| (500, "{}".into()));
    let key = encompute_verification::EvaluatorSigner::generate()
        .unwrap()
        .identity()
        .public_key_hex();
    let (control, _) = control_plane(&evaluator, &key);
    let (code, err) = jobs_run(
        &s,
        &control,
        &["--trust-evaluator", &key.to_uppercase()],
        &[],
    );
    // The stub evaluator fails the run; the pin let it through.
    assert_ne!(code, 0);
    assert!(
        !err.contains("trusted evaluators") && !err.contains("ENC2605"),
        "{err}"
    );
    assert!(!sent.lock().unwrap().is_empty(), "{err}");
}
