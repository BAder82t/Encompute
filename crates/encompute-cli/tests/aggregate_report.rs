//! Regression (soak finding): a coordinator whose control-plane report
//! fails (here: ENCOMPUTE_CONTROL_URL set, as after `encompute login`, but
//! no service identity) must still give the parties the window to collect
//! the receipt of the aggregate it already released. It used to exit at
//! once, and every party failed with "connection refused".

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
fn failed_control_report_still_lets_parties_collect_the_receipt() {
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
    let start = std::time::Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(start.elapsed().as_secs() < 20, "coordinator did not start");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let url = format!("http://127.0.0.1:{port}");
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
        assert_eq!(code, 0, "a party could not collect the receipt: {out}{err}");
        assert!(out.contains("CONTRIBUTION ACCEPTED"), "{out}");
    }
    let o = coordinator.wait_with_output().unwrap();
    let (out, err) = (
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr),
    );
    assert!(out.contains("AGGREGATION COMPLETE"), "{out}");
    // The failed report is still an error of the coordinator.
    assert!(!o.status.success(), "{out}{err}");
    assert!(err.contains("ENC2605"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
