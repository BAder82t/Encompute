//! Regression (soak finding): a coordinator configured for a control plane
//! it cannot report to (here: ENCOMPUTE_CONTROL_URL set, as after
//! `encompute login`, but no service identity) used to run the round,
//! release the aggregate and exit at once, so every party failed with
//! "connection refused". It now refuses before the round starts: no party
//! contributes, and nothing is released without a reservation.

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

#[test]
fn a_coordinator_that_cannot_report_refuses_before_the_round() {
    let dir = std::env::temp_dir().join(format!("encompute-cli-aggreport-{}", std::process::id()));
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
    let mut ids = vec![];
    for x in ["a", "b", "c"] {
        let key = p(&format!("{x}.key"));
        let party = format!("hospital-{x}");
        ids.push(
            ok(&["aggregate", "identity", "--party", &party, "--key", &key])
                .trim()
                .to_owned(),
        );
        std::fs::write(p(&format!("{x}.json")), "[0.25, -0.5, 1.0, 0.0]").unwrap();
    }
    std::fs::write(p("parties.json"), format!("[{}]", ids.join(","))).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let coordinator = Command::new(env!("CARGO_BIN_EXE_encompute"))
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
            "1",
            "--out",
            &p("agg.json"),
            "--receipt",
            &p("receipt.json"),
        ])
        // Reporting is attempted and fails: no ENCOMPUTE_SERVICE_ID.
        .env("ENCOMPUTE_CONTROL_URL", "http://127.0.0.1:9")
        .env_remove("ENCOMPUTE_SERVICE_ID")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let o = coordinator.wait_with_output().unwrap();
    let (out, err) = (
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr),
    );
    assert!(!o.status.success(), "{out}{err}");
    assert!(err.contains("ENC2605"), "{err}");
    assert!(!out.contains("AGGREGATION COMPLETE"), "{out}");
    assert!(
        !std::path::Path::new(&p("agg.json")).exists(),
        "nothing is released"
    );
    // It never listened: no party could contribute.
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
