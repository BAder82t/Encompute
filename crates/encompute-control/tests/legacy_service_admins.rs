//! Review finding CP-A-2: security_admin is for people. No path grants it
//! to a service account; accounts that got it before the fix keep it (it
//! is never stripped silently) but are reported on every start (log line,
//! audit event, gauge), listed by `GET /v1/security/legacy-service-admins`,
//! never count as a policy's second pair of eyes, and lose it through the
//! ordinary membership removal.

mod common;

use std::sync::Arc;

use common::*;
use serde_json::{json, Value};

use encompute_verification::ServiceSigner;

const ROUTE: &str = "/v1/security/legacy-service-admins";

fn signer(id: &str, b: u8) -> Arc<ServiceSigner> {
    Arc::new(ServiceSigner::from_seed(id, &[b; 32]).unwrap())
}

/// An automation account of `org` registered through the API with
/// `roles`, then given security_admin by direct SQL: the state a
/// deployment that granted it before the fix is in.
fn legacy_account(t: &T, admin: &As, org: &str, id: &str, b: u8) -> As {
    let s = signer(id, b);
    t.ok(
        admin,
        "POST",
        &format!("/v1/organizations/{org}/service-accounts"),
        Some(
            json!({"id": id, "kind": "automation", "public_key": s.public_key_hex(),
                    "roles": ["operator"]}),
        ),
    );
    let mut c = postgres::Client::connect(&t.env0.url, postgres::NoTls).unwrap();
    c.execute(
        "INSERT INTO memberships (principal_id, organization_id, role) VALUES ($1, $2, 'security_admin')",
        &[&id, &org],
    )
    .unwrap();
    As::Service(s)
}

fn ids(v: &Value) -> Vec<String> {
    v["service_accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            format!(
                "{}/{}",
                a["organization"].as_str().unwrap(),
                a["id"].as_str().unwrap()
            )
        })
        .collect()
}

fn legacy_events(t: &T, auditor: &As) -> Vec<Value> {
    t.ok(auditor, "GET", "/v1/audit?limit=1000", None)
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "security.legacy_service_admins")
        .cloned()
        .collect()
}

fn gauge(t: &T) -> String {
    t.control
        .metrics
        .render()
        .lines()
        .find(|l| l.starts_with("encompute_legacy_service_admins{"))
        .unwrap_or("")
        .to_owned()
}

/// Review finding CP-A-2: a legacy security_admin service account is
/// reported at startup (audit event in its organization's trail, gauge,
/// the list the startup log line names), listed to its organization (and
/// the platform) only, cannot approve or propose a policy, and is gone
/// from every report once an organization admin removes the role.
#[test]
fn legacy_security_admin_service_accounts_are_reported_until_removed() {
    let Some(w) = world() else { return };
    let World {
        t,
        platform,
        a_admin,
        a_auditor,
        b_admin,
        b_auditor,
        b_dev,
        b_sec,
        project,
        evaluator,
        ..
    } = w;
    // A fresh deployment has none, and nothing is audited for it.
    assert_eq!(t.ok(&platform, "GET", ROUTE, None)["count"], 0);
    assert!(legacy_events(&t, &b_auditor).is_empty());
    assert_eq!(
        gauge(&t),
        "encompute_legacy_service_admins{label=\"all\"} 0"
    );

    let b_bot = legacy_account(&t, &b_admin, "modelco", "b-legacy-bot", 81);
    legacy_account(&t, &a_admin, "hospital-a", "a-legacy-bot", 82);
    let t = t.restarted();

    // Startup: one audit event per affected organization, in its own trail.
    let ev = legacy_events(&t, &b_auditor);
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(ev[0]["refs"]["service_accounts"], "b-legacy-bot");
    assert_eq!(ev[0]["refs"]["count"], "1");
    assert_eq!(ev[0]["refs"]["refused_from"], "0.4.0");
    assert_eq!(ev[0]["actor"], "control-plane");
    let ev = legacy_events(&t, &a_auditor);
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(ev[0]["refs"]["service_accounts"], "a-legacy-bot");
    assert_eq!(
        gauge(&t),
        "encompute_legacy_service_admins{label=\"all\"} 2"
    );
    // What the startup warning line names.
    let named: Vec<String> = t
        .control
        .warn_legacy_service_admins()
        .unwrap()
        .iter()
        .map(|a| {
            format!(
                "{}/{}",
                a["organization"].as_str().unwrap(),
                a["id"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(named, ["hospital-a/a-legacy-bot", "modelco/b-legacy-bot"]);

    // The route: the platform sees all, an organization its own.
    let all = t.ok(&platform, "GET", ROUTE, None);
    assert_eq!(all["count"], 2);
    assert_eq!(
        ids(&all),
        ["hospital-a/a-legacy-bot", "modelco/b-legacy-bot"]
    );
    let mine = t.ok(&b_admin, "GET", ROUTE, None);
    assert_eq!(ids(&mine), ["modelco/b-legacy-bot"]);
    let a = &mine["service_accounts"][0];
    assert_eq!(a["kind"], "automation");
    assert_eq!(a["status"], "active");
    assert!(a["created_at"].as_str().unwrap().ends_with('Z'), "{a}");
    assert!(a["last_activity"].is_null(), "no audited action yet: {a}");
    assert_eq!(
        a["remove"],
        json!({"method": "POST", "path": "/v1/organizations/modelco/memberships/remove",
               "body": {"principal": "b-legacy-bot", "role": "security_admin"}})
    );
    assert_eq!(
        ids(&t.ok(&b_auditor, "GET", ROUTE, None)),
        ["modelco/b-legacy-bot"]
    );
    assert_eq!(
        ids(&t.ok(&a_admin, "GET", ROUTE, None)),
        ["hospital-a/a-legacy-bot"]
    );
    let (s, v) = t.call(&b_dev, "GET", ROUTE, None);
    assert_eq!(s, 403, "an ML developer listed them: {v}");
    let (s, v) = t.call(&evaluator.service, "GET", ROUTE, None);
    assert_eq!(s, 403, "a platform service listed them: {v}");

    // The legacy account keeps its reads, but is never four eyes.
    let pol = t.ok(
        &b_sec,
        "POST",
        &format!("/v1/projects/{project}/policies"),
        Some(json!({"legacy": true})),
    );
    let pid = pol["id"].as_str().unwrap();
    let (s, v) = t.call(&b_bot, "POST", &format!("/v1/policies/{pid}/approve"), None);
    assert_eq!(s, 403, "a legacy service admin approved a policy: {v}");
    let (s, v) = t.call(
        &b_bot,
        "POST",
        &format!("/v1/projects/{project}/policies"),
        Some(json!({"by": "bot"})),
    );
    assert_eq!(s, 403, "a legacy service admin proposed a policy: {v}");
    t.ok(&b_bot, "GET", "/v1/audit?limit=5", None);

    // Removal through the ordinary route.
    let v = t.ok(
        &b_admin,
        "POST",
        "/v1/organizations/modelco/memberships/remove",
        Some(json!({"principal": "b-legacy-bot", "role": "security_admin"})),
    );
    assert_eq!(v["removed"], json!(["security_admin"]));
    assert_eq!(t.ok(&b_admin, "GET", ROUTE, None)["count"], 0);
    assert_eq!(
        ids(&t.ok(&platform, "GET", ROUTE, None)),
        ["hospital-a/a-legacy-bot"]
    );
    t.control.tick();
    assert_eq!(
        gauge(&t),
        "encompute_legacy_service_admins{label=\"all\"} 1"
    );
    // Its other role stays; the next start audits only hospital-a again.
    let t = t.restarted();
    assert_eq!(
        legacy_events(&t, &b_auditor).len(),
        2,
        "modelco is not audited again"
    );
    assert_eq!(legacy_events(&t, &a_auditor).len(), 3);
    t.ok(
        &a_admin,
        "POST",
        "/v1/organizations/hospital-a/memberships/remove",
        Some(json!({"principal": "a-legacy-bot", "role": "security_admin"})),
    );
    assert_eq!(t.ok(&platform, "GET", ROUTE, None)["count"], 0);
    let t = t.restarted();
    assert_eq!(
        legacy_events(&t, &a_auditor).len(),
        3,
        "none left: nothing audited"
    );
    assert_eq!(
        gauge(&t),
        "encompute_legacy_service_admins{label=\"all\"} 0"
    );
}

/// Review finding CP-A-2: no path grants security_admin to a service
/// account. Registration refuses it for every kind and organization (and
/// alone or with other roles, leaving nothing behind); a service ID can
/// never be a person's ID (memberships are keyed by principal ID, so it
/// would inherit that person's roles); users, organization admins and the
/// bootstrap admin are people; and no migration writes a membership.
#[test]
fn no_path_grants_security_admin_to_a_service_account() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let s = signer("x", 90);
    for (who, org, id, kind, roles) in [
        (
            &w.b_admin,
            "modelco",
            "b-auto",
            "automation",
            json!(["security_admin"]),
        ),
        (
            &w.b_admin,
            "modelco",
            "b-auto",
            "automation",
            json!(["operator", "security_admin"]),
        ),
        (
            &w.b_admin,
            "modelco",
            "keybroker-b",
            "keybroker",
            json!(["security_admin"]),
        ),
        (
            &w.platform,
            "platform",
            "p-auto",
            "automation",
            json!(["security_admin"]),
        ),
        (
            &w.platform,
            "platform",
            "p-broker",
            "keybroker",
            json!(["security_admin"]),
        ),
    ] {
        let (st, v) = t.call(
            who,
            "POST",
            &format!("/v1/organizations/{org}/service-accounts"),
            Some(json!({"id": id, "kind": kind, "public_key": s.public_key_hex(), "roles": roles})),
        );
        assert_eq!(st, 400, "{org}/{id} ({kind}) got security_admin: {v}");
    }
    // Nothing was left behind by the refused registration.
    t.ok(
        &w.b_admin,
        "POST",
        "/v1/organizations/modelco/service-accounts",
        Some(
            json!({"id": "b-auto", "kind": "automation", "public_key": s.public_key_hex(),
                    "roles": ["operator"]}),
        ),
    );
    // A service account cannot take a security admin's principal ID.
    let sec_id = t.ok(&w.b_sec, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let s2 = signer("y", 91);
    let (st, v) = t.call(
        &w.b_admin,
        "POST",
        "/v1/organizations/modelco/service-accounts",
        Some(json!({"id": sec_id, "kind": "automation", "public_key": s2.public_key_hex()})),
    );
    assert_eq!(st, 400, "a service account took a person's ID: {v}");
    assert!(
        encompute_verification::service::check_service_id(&sec_id).is_err(),
        "user IDs are outside the service ID namespace"
    );
    // Users (including organization admins) are people.
    let v = t.ok(
        &w.b_admin,
        "POST",
        "/v1/organizations/modelco/users",
        Some(
            json!({"issuer": encompute_control::authn::DEV_ISSUER, "subject": "b-sec3",
                    "roles": ["security_admin"]}),
        ),
    );
    assert!(encompute_verification::service::check_service_id(v["id"].as_str().unwrap()).is_err());
    // Bootstrap, organization creation and user creation above granted
    // roles: none of them to a service account.
    assert_eq!(t.ok(&w.platform, "GET", ROUTE, None)["count"], 0);
    let mut c = postgres::Client::connect(&t.env0.url, postgres::NoTls).unwrap();
    let n: i64 = c
        .query_one(
            "SELECT count(*) FROM memberships m JOIN service_accounts s ON s.id = m.principal_id
              WHERE m.role = 'security_admin'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(n, 0);
    for (v, name, sql) in encompute_control::db::MIGRATIONS {
        let sql = sql.to_lowercase();
        assert!(
            !sql.contains("insert into memberships") && !sql.contains("update memberships"),
            "migration {v} ({name}) grants a role"
        );
    }
}
