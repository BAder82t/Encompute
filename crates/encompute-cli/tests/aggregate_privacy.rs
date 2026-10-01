//! Privacy at the aggregation boundary, through the CLI.
//!
//! - Review finding DP-1 (ENC-SF-2026-047): a budgeted aggregate with no `to` and no `dp` (a
//!   `Sealed` destination) compiled, ran without `--ledger`, and released
//!   the exact sum with no charge. Every aggregate is a release: it no
//!   longer compiles.
//! - Review finding SA-1 (ENC-SF-2026-048): under a control plane, a coordinator whose
//!   `--control-asset` mappings miss a budgeted asset (or are malformed)
//!   refuses before the round opens: no party contributes.

use std::process::{Command, Stdio};

fn encompute(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_encompute"))
        .args(args)
        .env_remove("ENCOMPUTE_CONTROL_URL")
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into(),
        String::from_utf8_lossy(&out.stderr).into(),
    )
}

fn workdir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "encompute-cli-aggprivacy-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Three hospitals with patient-level budgets; `to` completes the output
/// line and `dp` the aggregate declaration.
fn program(to: &str, dp: &str) -> String {
    let mut eir = String::from(
        "encompute 0.1\nprogram fedavg precision 0.001 purpose \"t\"\nparty \"coordinator\" \"C\"\n",
    );
    for x in ["a", "b", "c"] {
        eir.push_str(&format!("party \"hospital-{x}\" \"H\"\n"));
    }
    for x in ["a", "b", "c"] {
        eir.push_str(&format!(
            "asset \"gradient-{x}\" gradient owners [\"hospital-{x}\"] readers [\"coordinator\"] \
             purposes [\"t\"] release aggregate_only privacy unit \"patient\" epsilon 3.0 \
             delta 1e-6\n"
        ));
    }
    for (i, x) in ["a", "b", "c"].iter().enumerate() {
        eir.push_str(&format!(
            "%{i} = input \"g{x}\" [-1.0, 1.0] asset \"gradient-{x}\" : secret vector<4>\n"
        ));
    }
    eir.push_str(&format!(
        "%3 = add %0, %1 : secret vector<4>\n%4 = add %3, %2 : secret vector<4>\n\
         output \"g\" = %4{to}\n\
         aggregate \"g\" sum minimum 3 colluding 2 clip [-1.0, 1.0] scale 4096 modulus 40{dp}\n"
    ));
    eir
}

const DP: &str = " dp discrete_gaussian clip_norm 1.0 noise_multiplier 12.0";

#[test]
fn a_sealed_budgeted_aggregate_without_dp_does_not_compile() {
    let dir = workdir("sealed");
    let p = |f: &str| dir.join(f).to_str().unwrap().to_owned();
    // The review's proof of concept: example 09 without `to` and `dp`.
    std::fs::write(p("sealed.eir"), program("", "")).unwrap();
    let (code, out, err) = encompute(&["compile", &p("sealed.eir"), "-o", &p("sealed.encompute")]);
    assert_ne!(code, 0, "{out}{err}");
    assert!(err.contains("ENC2203"), "{err}");
    assert!(err.contains("even when sealed"), "{err}");
    assert!(!std::path::Path::new(&p("sealed.encompute")).exists());
    // Sealed with DP compiles: the aggregate is charged like any release.
    std::fs::write(p("sealed-dp.eir"), program("", DP)).unwrap();
    let (code, out, err) = encompute(&[
        "compile",
        &p("sealed-dp.eir"),
        "-o",
        &p("sealed-dp.encompute"),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_control_plane_coordinator_needs_every_budgeted_mapping_before_the_round() {
    let dir = workdir("mapping");
    let p = |f: &str| dir.join(f).to_str().unwrap().to_owned();
    std::fs::write(p("f.eir"), program(" to \"coordinator\"", DP)).unwrap();
    let ok = |args: &[&str]| {
        let (code, out, err) = encompute(args);
        assert_eq!(code, 0, "{args:?}: {out}{err}");
        out
    };
    ok(&["compile", &p("f.eir"), "-o", &p("f.encompute")]);
    let mut ids = vec![];
    for x in ["a", "b", "c"] {
        let key = p(&format!("{x}.key"));
        let party = format!("hospital-{x}");
        ids.push(
            ok(&["aggregate", "identity", "--party", &party, "--key", &key])
                .trim()
                .to_owned(),
        );
    }
    std::fs::write(p("parties.json"), format!("[{}]", ids.join(","))).unwrap();
    let cases: [&[&str]; 4] = [
        // No mapping at all.
        &[],
        // One budgeted asset left out.
        &[
            "--control-asset",
            "gradient-a=ds-a",
            "--control-asset",
            "gradient-b=ds-b",
        ],
        // Misspelt.
        &[
            "--control-asset",
            "gradient-a=ds-a",
            "--control-asset",
            "gradient-b=ds-b",
            "--control-asset",
            "gradient_c=ds-c",
        ],
        // Malformed.
        &[
            "--control-asset",
            "gradient-a=ds-a",
            "--control-asset",
            "gradient-b=ds-b",
            "--control-asset",
            "gradient-c",
        ],
    ];
    for (i, mapping) in cases.iter().enumerate() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let listen = format!("127.0.0.1:{port}");
        let (ledger, out, receipt) = (
            p(&format!("ledger-{i}")),
            p(&format!("agg-{i}.json")),
            p(&format!("receipt-{i}.json")),
        );
        let mut args = vec![
            "aggregate",
            "serve",
            &p("f.encompute"),
            "--parties",
            &p("parties.json"),
            "--key",
            &p("coord.key"),
            "--listen",
            &listen,
            "--stage-timeout",
            "5",
            "--ledger",
            &ledger,
            "--out",
            &out,
            "--receipt",
            &receipt,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        args.extend(mapping.iter().map(|a| a.to_string()));
        let o = Command::new(env!("CARGO_BIN_EXE_encompute"))
            .args(&args)
            // A control plane is configured (the mapping is checked first).
            .env("ENCOMPUTE_CONTROL_URL", "http://127.0.0.1:9")
            .env("ENCOMPUTE_SERVICE_ID", "coordinator")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();
        let (stdout, stderr) = (
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr),
        );
        assert!(!o.status.success(), "case {i}: {stdout}{stderr}");
        assert!(stderr.contains("--control-asset"), "case {i}: {stderr}");
        assert!(
            !stdout.contains("AGGREGATION COMPLETE"),
            "case {i}: {stdout}"
        );
        assert!(!std::path::Path::new(&out).exists(), "case {i}: released");
        // It never listened: no party could contribute.
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    }
    let _ = std::fs::remove_dir_all(&dir);
}
