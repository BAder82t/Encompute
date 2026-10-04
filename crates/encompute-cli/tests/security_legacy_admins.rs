//! `encompute security legacy-service-admins` against a real control plane
//! (review finding CP-A-2): it prints every service account that still
//! holds security_admin with the call that removes it, and exits 1 while
//! any exists and 0 once none does, so runbooks and CI can gate on it.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`. Its database is dropped when the
//! test ends.

// The shared test database harness (a template clone per test; see there).
#[path = "../../encompute-control/tests/common/testdb.rs"]
mod testdb;

use std::process::Command;
use std::sync::Arc;

use serde_json::{json, Value};

use encompute_control::anchor::DirAnchor;
use encompute_control::authn::{dev_token, Authenticator, DEV_ISSUER};
use encompute_control::config::Env;
use encompute_control::db::Db;
use encompute_control::Control;
use encompute_verification::ServiceSigner;

const SECRET: &str = "cli-test-development-secret";

struct Plane {
    url: String,
    db: String,
    agent: ureq::Agent,
    home: std::path::PathBuf,
}

impl Plane {
    fn call(&self, who: &str, method: &str, path: &str, body: Value) -> Value {
        let r = self
            .agent
            .request(method, &format!("{}{path}", self.url))
            .set(
                "Authorization",
                &format!("Bearer {}", dev_token(SECRET, who, 3600).unwrap()),
            );
        let r = if body.is_null() {
            r.call()
        } else {
            r.send_json(body)
        };
        r.unwrap_or_else(|e| panic!("{method} {path}: {e}"))
            .into_json()
            .unwrap()
    }

    /// Runs the CLI as `who`: (exit code, stdout).
    fn cli(&self, who: &str, args: &[&str]) -> (i32, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_encompute"))
            .args(args)
            .env("ENCOMPUTE_CONTROL_URL", &self.url)
            .env("ENCOMPUTE_TOKEN", dev_token(SECRET, who, 3600).unwrap())
            .env_remove("ENCOMPUTE_SERVICE_ID")
            .env_remove("ENCOMPUTE_SERVICE_KEY_FILE")
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.home)
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned()
                + &String::from_utf8_lossy(&out.stderr),
        )
    }
}

fn start() -> Option<Plane> {
    let db = testdb::fresh_database()?;
    let dir = testdb::tmp_dir("cli-legacy");
    let d = Db::connect(&db).unwrap();
    d.migrate().unwrap();
    let control = Control::with_parts(
        Env::Development,
        "control-plane",
        d,
        Authenticator::new(
            Env::Development,
            "control-plane",
            vec![],
            Some(zeroize::Zeroizing::new(SECRET.into())),
        ),
        ServiceSigner::from_seed("control-plane", &[42; 32]).unwrap(),
        Box::new(DirAnchor::new(dir.join("anchor")).unwrap()),
        None,
        5,
    )
    .unwrap();
    control
        .bootstrap(DEV_ISSUER, "platform-admin", None)
        .unwrap();
    let server = encompute_verification::http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr());
    let control = Arc::new(control);
    std::thread::spawn(move || encompute_control::api::serve_on(control, server));
    Some(Plane {
        url,
        db,
        agent: ureq::AgentBuilder::new().build(),
        home: dir,
    })
}

#[test]
fn legacy_service_admins_command_exits_1_until_they_are_removed() {
    let Some(p) = start() else { return };
    p.call(
        "platform-admin",
        "POST",
        "/v1/organizations",
        json!({"id": "modelco", "display_name": "modelco",
               "admin": {"issuer": DEV_ISSUER, "subject": "b-admin"}}),
    );
    // None yet: exit 0.
    let (code, out) = p.cli("b-admin", &["security", "legacy-service-admins"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("no service account holds security_admin"),
        "{out}"
    );

    // A service account given security_admin before the fix (direct SQL:
    // no API path grants it any more).
    let s = ServiceSigner::from_seed("b-legacy-bot", &[81; 32]).unwrap();
    p.call(
        "b-admin",
        "POST",
        "/v1/organizations/modelco/service-accounts",
        json!({"id": "b-legacy-bot", "kind": "automation", "public_key": s.public_key_hex(),
               "roles": ["operator"]}),
    );
    postgres::Client::connect(&p.db, postgres::NoTls)
        .unwrap()
        .execute(
            "INSERT INTO memberships (principal_id, organization_id, role)
             VALUES ('b-legacy-bot', 'modelco', 'security_admin')",
            &[],
        )
        .unwrap();

    for who in ["b-admin", "platform-admin"] {
        let (code, out) = p.cli(who, &["security", "legacy-service-admins"]);
        assert_eq!(code, 1, "{who}: {out}");
        assert!(out.contains("LEGACY: 1 service account(s)"), "{out}");
        assert!(out.contains("refused from 0.4.0"), "{out}");
        let row = out
            .lines()
            .find(|l| l.starts_with("modelco ") && l.contains("b-legacy-bot"))
            .unwrap_or_else(|| panic!("no row: {out}"));
        assert!(
            row.contains("automation") && row.contains("active"),
            "{row}"
        );
        assert!(
            out.contains(
                r#"POST /v1/organizations/modelco/memberships/remove {"principal":"b-legacy-bot","role":"security_admin"}"#
            ),
            "{out}"
        );
    }
    let (code, out) = p.cli("b-admin", &["security", "legacy-service-admins", "--json"]);
    assert_eq!(code, 1, "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["count"], 1);

    // Removed through the membership route: exit 0.
    p.call(
        "b-admin",
        "POST",
        "/v1/organizations/modelco/memberships/remove",
        json!({"principal": "b-legacy-bot", "role": "security_admin"}),
    );
    let (code, out) = p.cli("b-admin", &["security", "legacy-service-admins"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("no service account holds security_admin"),
        "{out}"
    );
}
