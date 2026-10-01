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
    assert_eq!(t.control.db.migrate().unwrap(), 17);
    assert_eq!(t.control.db.schema_version().unwrap(), 17);
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
    let Ok(admin) = std::env::var("ENCOMPUTE_TEST_DATABASE_URL") else {
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
