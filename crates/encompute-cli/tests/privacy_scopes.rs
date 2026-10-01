//! Privacy populations and scopes, through the CLI: the hard cap, scopes
//! below it, and a coordinator that never creates one.

use std::process::Command;

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
        "encompute-cli-scopes-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_scope_cannot_exceed_its_population_and_a_cap_is_allocated_once() {
    let dir = workdir("alloc");
    let l = dir.join("ledger");
    let l = l.to_str().unwrap();
    let ok = |args: &[&str]| {
        let (code, out, err) = encompute(args);
        assert_eq!(code, 0, "{args:?}: {out}{err}");
        out
    };
    let out = ok(&[
        "privacy",
        "population",
        "--ledger",
        l,
        "--id",
        "pop-a",
        "--organization",
        "region-a",
        "--series",
        "residents",
        "--unit",
        "patient",
        "--epsilon",
        "1.0",
        "--delta",
        "1e-6",
    ]);
    assert!(
        out.contains("POPULATION pop-a created") && out.contains("rho cap"),
        "{out}"
    );
    // Allocated once: a second creation (a "reset") is refused.
    let (code, _, err) = encompute(&[
        "privacy",
        "population",
        "--ledger",
        l,
        "--id",
        "pop-a",
        "--organization",
        "region-a",
        "--series",
        "residents",
        "--unit",
        "patient",
        "--epsilon",
        "5.0",
        "--delta",
        "1e-6",
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("ENC2720"), "{err}");
    // A scope above the population's cap: refused.
    let (code, _, err) = encompute(&[
        "privacy",
        "scope",
        "--ledger",
        l,
        "--population",
        "pop-a",
        "--id",
        "scp-a",
        "--project",
        "health",
        "--purpose",
        "surveillance-2027",
        "--epsilon",
        "2.0",
        "--asset",
        "counts-a",
    ]);
    assert_ne!(code, 0);
    assert!(
        err.contains("ENC2720") && err.contains("authoritative"),
        "{err}"
    );
    // Within it: allocated, and the scoping entry written.
    let scoping = dir.join("scoping.json");
    let s = scoping.to_str().unwrap();
    ok(&[
        "privacy",
        "scope",
        "--ledger",
        l,
        "--population",
        "pop-a",
        "--id",
        "scp-a",
        "--project",
        "health",
        "--purpose",
        "surveillance-2027",
        "--epsilon",
        "0.5",
        "--asset",
        "counts-a",
        "--scoping",
        s,
    ]);
    let entries: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&scoping).unwrap()).unwrap();
    assert_eq!(entries["counts-a"]["scope"]["asset_id"], "scp-a");
    assert_eq!(entries["counts-a"]["population"]["asset_id"], "pop-a");
    // A scope of a population that does not exist: refused.
    let (code, _, err) = encompute(&[
        "privacy",
        "scope",
        "--ledger",
        l,
        "--population",
        "pop-none",
        "--id",
        "scp-x",
        "--project",
        "health",
        "--purpose",
        "p",
        "--epsilon",
        "0.1",
        "--asset",
        "x",
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("ENC2720"), "{err}");
    // The budget report names both kinds.
    let out = ok(&["privacy", "budget", "--ledger", l]);
    assert!(
        out.contains("Population pop-a") && out.contains("Scope scp-a"),
        "{out}"
    );
    assert!(
        out.contains("population pop-a; project health, purpose surveillance-2027"),
        "{out}"
    );
    // Both are current ledger formats for `migrate`.
    let (code, out, err) = encompute(&["migrate", "--check", l]);
    assert_eq!(code, 0, "{out}{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
