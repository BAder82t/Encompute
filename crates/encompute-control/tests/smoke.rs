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
    assert_eq!(t.control.db.migrate().unwrap(), 1);
    assert_eq!(t.control.db.schema_version().unwrap(), 1);
    let (s, _) = t.call(&As::Nobody, "GET", "/live", None);
    assert_eq!(s, 200);
    let (s, _) = t.call(&As::Nobody, "GET", "/ready", None);
    assert_eq!(s, 200);
}
