//! The control plane starts, migrates, and serves a world of two
//! organizations sharing a project.

mod common;

use common::*;
use serde_json::json;

#[test]
fn world_builds_and_migrations_are_idempotent() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let me = t.ok(&w.a_dev, "GET", "/v1/whoami", None);
    assert_eq!(me["organization"], "hospital-a");
    let p = t.ok(
        &w.a_dev,
        "GET",
        &format!("/v1/projects/{}", w.project),
        None,
    );
    assert_eq!(p["members"], json!(["hospital-a", "modelco"]));
    assert_eq!(t.control.db.migrate().unwrap(), 4);
    assert_eq!(t.control.db.schema_version().unwrap(), 4);
    let (s, _) = t.call(&As::Nobody, "GET", "/live", None);
    assert_eq!(s, 200);
    let (s, _) = t.call(&As::Nobody, "GET", "/ready", None);
    assert_eq!(s, 200);
}

/// Test hygiene: every database the harness creates for a test (a fresh
/// one, and backups of it) is dropped when the test ends, whether it passes
/// or panics, even with connections still open.
#[test]
fn a_test_leaves_no_database_behind() {
    let Some(admin) = test_admin_url() else {
        return;
    };
    let exists = |name: &str| -> bool {
        let mut c = postgres::Client::connect(&admin, postgres::NoTls).unwrap();
        c.query_one(
            "SELECT count(*) FROM pg_database WHERE datname = $1",
            &[&name],
        )
        .unwrap()
        .get::<_, i64>(0)
            == 1
    };
    for panics in [false, true] {
        let names = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let seen = names.clone();
        let test = std::thread::spawn(move || {
            let t = setup().unwrap();
            let live = db_name(&t.env0.url);
            let backup = format!("{live}_hyg");
            let env0 = t.env0;
            drop(t.control);
            backup_database(&env0.url, &backup);
            seen.lock().unwrap().extend([live, backup]);
            // Left open, as a crashed test would leave it.
            let open = postgres::Client::connect(&env0.url, postgres::NoTls).unwrap();
            std::mem::forget(open);
            assert!(!panics, "a failing test");
        });
        assert_eq!(test.join().is_err(), panics);
        let names = names.lock().unwrap().clone();
        assert_eq!(names.len(), 2);
        for n in &names {
            assert!(!exists(n), "{n} was left behind (panicked: {panics})");
        }
    }
}

/// The columns, indexes and applied migrations of a database, in a
/// comparable form.
fn schema_of(url: &str) -> Vec<String> {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    let mut out = vec![];
    for q in [
        "SELECT table_name || '.' || column_name || ' ' || data_type || ' ' || is_nullable
           FROM information_schema.columns WHERE table_schema = 'public' ORDER BY 1",
        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' ORDER BY 1",
        "SELECT version || ' ' || name || ' ' || checksum FROM schema_migrations ORDER BY version",
    ] {
        out.extend(
            c.query(q, &[])
                .unwrap()
                .iter()
                .map(|r| r.get::<_, String>(0)),
        );
    }
    out
}

/// The fast mode must not change what a test sees: a template clone has
/// exactly the schema the control plane's own migrations build from an
/// empty database, and clones do not share state.
#[test]
fn a_template_clone_equals_a_cold_migrated_database() {
    let Some(clone) = template_clone() else {
        return;
    };
    let cold = unmigrated_database().unwrap();
    let db = encompute_control::db::Db::connect(&cold).unwrap();
    let last = encompute_control::db::MIGRATIONS.last().unwrap().0;
    assert_eq!(db.migrate().unwrap(), last);
    assert_eq!(schema_of(&clone), schema_of(&cold));
    // Each clone is its own database.
    let other = template_clone().unwrap();
    assert_ne!(db_name(&clone), db_name(&other));
    let mut a = postgres::Client::connect(&clone, postgres::NoTls).unwrap();
    a.batch_execute(
        "INSERT INTO organizations (id, display_name, status, policy_namespace) VALUES ('o', 'o', 'active', 'o')",
    )
    .unwrap();
    let mut b = postgres::Client::connect(&other, postgres::NoTls).unwrap();
    let n: i64 = b
        .query_one("SELECT count(*) FROM organizations", &[])
        .unwrap()
        .get(0);
    assert_eq!(n, 0, "a write to one clone showed in another");
}

/// The template is read-only: marked as a template, and refusing every
/// connection, so no test can run against it.
#[test]
fn the_template_accepts_no_connections() {
    let Some(admin) = test_admin_url() else {
        return;
    };
    let name = template_database_name(&admin);
    let mut c = postgres::Client::connect(&admin, postgres::NoTls).unwrap();
    let row = c
        .query_one(
            "SELECT datistemplate, datallowconn FROM pg_database WHERE datname = $1",
            &[&name],
        )
        .unwrap();
    assert!(row.get::<_, bool>(0), "{name} is not marked as a template");
    assert!(!row.get::<_, bool>(1), "{name} accepts connections");
    assert!(postgres::Client::connect(&url_for(&admin, name), postgres::NoTls).is_err());
}
