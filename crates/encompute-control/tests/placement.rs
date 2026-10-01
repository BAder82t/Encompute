//! Residency and operators at the control plane (INV-233, INV-234): an
//! evaluator's operator is its service account's organization; its
//! location is its own claim (self-declared) until a person who is a
//! security admin of the operator declares it; a changed location loses
//! its evidence; stale evidence is not evidence; an operator's own
//! evaluator never runs a standard job.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use std::sync::Arc;

use serde_json::{json, Value};

use common::*;
use encompute_verification::{EvaluatorSigner, ServiceSigner};

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

/// Asserts `(status, body)` is a refusal with `c`.
fn refused(r: (u16, Value), c: &str) {
    assert!(r.0 >= 400, "expected {c}, got {} {}", r.0, r.1);
    assert_eq!(code(&r.1), c, "{} {}", r.0, r.1);
}

const PROFILES: &[&str] = &["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"];

/// An evaluator service account held by `org` (registered by `admin`) and
/// its first registration, reporting `location` when it is `Some`.
fn org_evaluator(t: &T, admin: &As, org: &str, id: &str, location: Option<Value>) -> Evaluator {
    let seed = {
        let mut s = [0u8; 32];
        for (i, b) in id.bytes().enumerate() {
            s[i % 32] ^= b;
        }
        s[31] ^= 0x71;
        s
    };
    let signer = Arc::new(ServiceSigner::from_seed(id, &seed).unwrap());
    t.ok(
        admin,
        "POST",
        &format!("/v1/organizations/{org}/service-accounts"),
        Some(
            json!({"id": id, "kind": "evaluator", "public_key": signer.public_key_hex(),
                    "url": format!("http://{id}.internal:8750")}),
        ),
    );
    let receipt = EvaluatorSigner::from_seed(&seed.map(|b| b ^ 0x33));
    let e = Evaluator {
        id: id.into(),
        service: As::Service(signer.clone()),
        signer,
        receipt,
    };
    let (s, v) = register(t, &e, location);
    assert_eq!(s, 201, "{v}");
    e
}

/// Registers (or re-registers) `e`.
fn register(t: &T, e: &Evaluator, location: Option<Value>) -> (u16, Value) {
    let mut body = json!({"id": e.id, "url": format!("http://{}.internal:8750", e.id),
                "receipt_key": e.receipt.identity().public_key_hex(),
                "backends": ["openfhe", "openfhe-exact"], "profiles": PROFILES,
                "openfhe_version": "1.5.1", "capacity": 4});
    if let Some(l) = location {
        body["location"] = l;
    }
    t.call(&e.service, "POST", "/v1/evaluators", Some(body))
}

fn gcp(region: &str) -> Value {
    json!({"provider": "gcp", "region": region})
}

/// The listing entry of evaluator `id`, as `who` sees it.
fn listed(t: &T, who: &As, id: &str) -> Value {
    let all = t.ok(who, "GET", "/v1/evaluators", None);
    all.as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("{id} not listed: {all}"))
}

fn declare(t: &T, who: &As, ev: &str, location: Value) -> (u16, Value) {
    t.call(
        who,
        "POST",
        &format!("/v1/evaluators/{ev}/location-declarations"),
        Some(location),
    )
}

/// The platform's own security admin (the operator of platform evaluators).
fn platform_sec(w: &World) -> As {
    user(&w.t, &w.platform, "platform", "p-sec", &["security_admin"])
}

#[test]
fn an_evaluator_reports_a_self_declared_location() {
    let Some(w) = world() else { return };
    let e = org_evaluator(
        &w.t,
        &w.b_admin,
        "modelco",
        "ev-modelco",
        Some(gcp("europe-west3")),
    );
    let v = listed(&w.t, &w.platform, "ev-modelco");
    assert_eq!(v["operator"], "modelco");
    assert_eq!(v["location_evidence"], "self_declared");
    // The jurisdiction comes from the table, never from the evaluator.
    assert_eq!(v["location"]["jurisdiction"], "DE", "{v}");
    assert_eq!(v["location_evidence_digest"], Value::Null);
    // The platform's own evaluator has the platform as its operator and no
    // location until one is reported.
    let p = listed(&w.t, &w.platform, "evaluator-1");
    assert_eq!(p["operator"], "platform");
    assert_eq!(p["location"], Value::Null);
    assert_eq!(p["location_evidence"], "self_declared");

    // An evaluator cannot claim a jurisdiction itself.
    let (s, body) = register(
        &w.t,
        &e,
        Some(json!({"provider": "gcp", "region": "europe-west3", "jurisdiction": "FR"})),
    );
    assert_eq!(s, 400, "{body}");
    // An unknown region is refused, and nothing changes.
    refused(register(&w.t, &e, Some(gcp("europe-west99"))), "ENC2723");
    refused(
        register(
            &w.t,
            &e,
            Some(json!({"provider": "gcp", "region": "europe-west3", "zone": "us-central1-a"})),
        ),
        "ENC2723",
    );
    let v = listed(&w.t, &w.platform, "ev-modelco");
    assert_eq!(v["location"]["region"], "europe-west3", "{v}");
}

#[test]
fn a_service_account_cannot_declare_a_location() {
    let Some(w) = world() else { return };
    let e = org_evaluator(&w.t, &w.b_admin, "modelco", "ev-modelco", None);
    // The evaluator itself.
    refused(
        declare(&w.t, &e.service, "ev-modelco", gcp("europe-west3")),
        "ENC2723",
    );
    // An automation key holding the operator's admin and security roles.
    let bot = Arc::new(ServiceSigner::from_seed("mc-bot", &[77; 32]).unwrap());
    w.t.ok(
        &w.b_admin,
        "POST",
        "/v1/organizations/modelco/service-accounts",
        Some(
            json!({"id": "mc-bot", "kind": "automation", "public_key": bot.public_key_hex(),
                    "roles": ["organization_admin", "data_owner", "ml_developer"]}),
        ),
    );
    refused(
        declare(&w.t, &As::Service(bot), "ev-modelco", gcp("europe-west3")),
        "ENC2723",
    );
    let v = listed(&w.t, &w.platform, "ev-modelco");
    assert_eq!(v["location"], Value::Null, "{v}");
    assert_eq!(v["location_evidence"], "self_declared");
    // The platform's evaluator, by its own identity.
    refused(
        declare(
            &w.t,
            &w.evaluator.service,
            "evaluator-1",
            gcp("europe-west3"),
        ),
        "ENC2723",
    );
}

#[test]
fn only_the_operators_security_admin_declares_a_location() {
    let Some(w) = world() else { return };
    org_evaluator(
        &w.t,
        &w.b_admin,
        "modelco",
        "ev-modelco",
        Some(gcp("us-central1")),
    );
    // Another organization's security admin: the evaluator is not theirs
    // to see.
    let other_sec = user(&w.t, &w.c_admin, "other-co", "c-sec", &["security_admin"]);
    let (s, v) = declare(&w.t, &other_sec, "ev-modelco", gcp("europe-west3"));
    assert_eq!(s, 404, "{v}");
    // The operator's own people without security_admin.
    for who in [&w.b_dev, &w.b_owner, &w.b_admin] {
        let (s, v) = declare(&w.t, who, "ev-modelco", gcp("europe-west3"));
        assert_eq!(s, 403, "{v}");
    }
    // The platform's operator does not declare for an organization's
    // evaluator either.
    let (s, v) = declare(&w.t, &w.platform, "ev-modelco", gcp("europe-west3"));
    assert!(s == 403 || s == 404, "{s} {v}");
    assert_eq!(
        listed(&w.t, &w.platform, "ev-modelco")["location_evidence"],
        "self_declared"
    );

    // Its security admin does, and the evidence says so.
    let (s, v) = declare(
        &w.t,
        &w.b_sec,
        "ev-modelco",
        json!({"provider": "gcp", "region": "europe-west3", "zone": "europe-west3-b", "valid_for_days": 30}),
    );
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["evidence"], "operator_declared");
    assert_eq!(v["location"]["jurisdiction"], "DE");
    let l = listed(&w.t, &w.platform, "ev-modelco");
    assert_eq!(l["location_evidence"], "operator_declared");
    assert_eq!(l["location"]["zone"], "europe-west3-b");
    assert_eq!(l["location_evidence_digest"], v["evidence_digest"]);
    assert_eq!(l["location_evidence_digest"].as_str().unwrap().len(), 64);
    // It names the person, in the audit trail and the declarations table.
    let audit = w.t.ok(
        &w.b_auditor,
        "GET",
        "/v1/audit?organization=modelco&limit=1000",
        None,
    );
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "evaluator.location_declared"
                && e["actor"].as_str().is_some_and(|a| a.starts_with("usr_"))
                && e["refs"]["location"] == "gcp/europe-west3/europe-west3-b"),
        "{audit}"
    );

    // The platform's evaluator is declared by the platform's security admin.
    let psec = platform_sec(&w);
    let (s, v) = declare(&w.t, &psec, "evaluator-1", gcp("europe-west1"));
    assert_eq!(s, 201, "{v}");
    assert_eq!(
        listed(&w.t, &w.platform, "evaluator-1")["location_evidence"],
        "operator_declared"
    );
    // An unknown location or period is refused.
    refused(
        declare(&w.t, &psec, "evaluator-1", gcp("europe-west99")),
        "ENC2723",
    );
    let (s, _) = declare(
        &w.t,
        &psec,
        "evaluator-1",
        json!({"provider": "gcp", "region": "europe-west1", "valid_for_days": 0}),
    );
    assert_eq!(s, 400);
    let (s, _) = declare(
        &w.t,
        &psec,
        "evaluator-1",
        json!({"provider": "gcp", "region": "europe-west1", "valid_for_days": 4000}),
    );
    assert_eq!(s, 400);
    // No evaluator, no declaration.
    let (s, _) = declare(&w.t, &psec, "evaluator-nope", gcp("europe-west1"));
    assert_eq!(s, 404);
}

#[test]
fn a_changed_location_loses_the_declaration() {
    let Some(w) = world() else { return };
    let e = org_evaluator(
        &w.t,
        &w.b_admin,
        "modelco",
        "ev-modelco",
        Some(gcp("europe-west3")),
    );
    let (s, _) = declare(&w.t, &w.b_sec, "ev-modelco", gcp("europe-west3"));
    assert_eq!(s, 201);
    let digest = listed(&w.t, &w.platform, "ev-modelco")["location_evidence_digest"].clone();
    assert_ne!(digest, Value::Null);
    // A restart reporting nothing, or the same location, keeps it.
    assert_eq!(register(&w.t, &e, None).0, 201);
    assert_eq!(register(&w.t, &e, Some(gcp("europe-west3"))).0, 201);
    let l = listed(&w.t, &w.platform, "ev-modelco");
    assert_eq!(l["location_evidence"], "operator_declared", "{l}");
    assert_eq!(l["location_evidence_digest"], digest);
    // Re-registering with a new location after the declaration: the
    // declaration vouched for the old machine, not this one.
    assert_eq!(register(&w.t, &e, Some(gcp("us-central1"))).0, 201);
    let l = listed(&w.t, &w.platform, "ev-modelco");
    assert_eq!(l["location_evidence"], "self_declared", "{l}");
    assert_eq!(l["location_evidence_digest"], Value::Null);
    assert_eq!(l["location"]["jurisdiction"], "US");
    // The change is in the audit trail.
    let audit = w.t.ok(
        &w.b_auditor,
        "GET",
        "/v1/audit?organization=modelco&limit=1000",
        None,
    );
    assert!(audit
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["action"] == "evaluator.location_changed"));
    // The declaration history is kept (append-only).
    let mut c = w.t.control.db.conn().unwrap();
    let n: i64 = c
        .query_one("SELECT count(*) FROM evaluator_location_declarations WHERE evaluator_id = 'ev-modelco'", &[])
        .unwrap()
        .get(0);
    assert_eq!(n, 1);
    assert!(c
        .execute(
            "UPDATE evaluator_location_declarations SET operator = 'x'",
            &[]
        )
        .is_err());
    assert!(c
        .execute("DELETE FROM evaluator_location_declarations", &[])
        .is_err());
    assert!(c
        .batch_execute("TRUNCATE evaluator_location_declarations")
        .is_err());
}

#[test]
fn stale_evidence_is_not_evidence_and_attested_is_not_replaced() {
    let Some(w) = world() else { return };
    org_evaluator(
        &w.t,
        &w.b_admin,
        "modelco",
        "ev-modelco",
        Some(gcp("europe-west3")),
    );
    let (s, _) = declare(&w.t, &w.b_sec, "ev-modelco", gcp("europe-west3"));
    assert_eq!(s, 201);
    let offers = |t: &T| {
        let mut c = t.control.db.conn().unwrap();
        encompute_control::placement::evaluator_offers(&mut *c).unwrap()
    };
    let o = offers(&w.t)
        .into_iter()
        .find(|o| o.id == "ev-modelco")
        .unwrap();
    assert_eq!(o.evidence.as_str(), "operator_declared");
    assert_eq!(o.operator, "modelco");
    // The declaration lapses: the evaluator counts as self-declared, with
    // no evidence digest.
    w.t.control
        .db
        .conn()
        .unwrap()
        .execute("UPDATE evaluators SET location_valid_until = now() - interval '1 second' WHERE id = 'ev-modelco'", &[])
        .unwrap();
    let o = offers(&w.t)
        .into_iter()
        .find(|o| o.id == "ev-modelco")
        .unwrap();
    assert_eq!(o.evidence.as_str(), "self_declared");
    assert_eq!(o.evidence_digest, None);
    assert!(o.location.is_some(), "the location is still the claim");
    // The database refuses evidence without its digest or validity.
    let mut c = w.t.control.db.conn().unwrap();
    assert!(c
        .execute("UPDATE evaluators SET location_evidence = 'attested', location_evidence_digest = NULL WHERE id = 'ev-modelco'", &[])
        .is_err());
    // A fresh attested location is not replaced by a declaration.
    c.execute(
        "UPDATE evaluators SET location_evidence = 'attested', location_evidence_digest = $1,
                location_valid_until = now() + interval '1 hour' WHERE id = 'ev-modelco'",
        &[&"a".repeat(64)],
    )
    .unwrap();
    refused(
        declare(&w.t, &w.b_sec, "ev-modelco", gcp("us-central1")),
        "ENC2723",
    );
    assert_eq!(
        listed(&w.t, &w.platform, "ev-modelco")["location_evidence"],
        "attested"
    );
}

#[test]
fn an_organization_lists_only_the_evaluators_it_operates() {
    let Some(w) = world() else { return };
    org_evaluator(&w.t, &w.b_admin, "modelco", "ev-modelco", None);
    org_evaluator(&w.t, &w.a_admin, "hospital-a", "ev-hospital", None);
    let mine = w.t.ok(&w.b_admin, "GET", "/v1/evaluators", None);
    let ids: Vec<&str> = mine
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["ev-modelco"], "{mine}");
    // Security admins too; developers and owners see nothing.
    let mine = w.t.ok(&w.b_sec, "GET", "/v1/evaluators", None);
    assert_eq!(mine.as_array().unwrap().len(), 1);
    let (s, _) = w.t.call(&w.b_dev, "GET", "/v1/evaluators", None);
    assert!(s == 403 || s == 404, "{s}");
    // The platform sees all of them.
    let all = w.t.ok(&w.platform, "GET", "/v1/evaluators", None);
    assert_eq!(all.as_array().unwrap().len(), 3);
    // Only an organization's own admin creates its evaluator accounts, and
    // SecAgg coordinators stay platform services.
    let (s, _) = w.t.call(
        &w.b_dev,
        "POST",
        "/v1/organizations/modelco/service-accounts",
        Some(json!({"id": "ev-sneaky", "kind": "evaluator",
                    "public_key": ServiceSigner::from_seed("ev-sneaky", &[5; 32]).unwrap().public_key_hex()})),
    );
    assert_eq!(s, 403);
    let (s, _) = w.t.call(
        &w.b_admin,
        "POST",
        "/v1/organizations/modelco/service-accounts",
        Some(json!({"id": "sa-agg", "kind": "secagg",
                    "public_key": ServiceSigner::from_seed("sa-agg", &[6; 32]).unwrap().public_key_hex()})),
    );
    assert_eq!(s, 400);
}

#[test]
fn an_operators_evaluator_never_runs_a_standard_job() {
    let Some(w) = world() else { return };
    // modelco's evaluator is faster and healthy.
    let fast = org_evaluator(
        &w.t,
        &w.b_admin,
        "modelco",
        "aaa-modelco-eval",
        Some(gcp("europe-west3")),
    );
    let _ = fast;
    let p = w.t.ok(
        &w.b_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": w.project, "program": EXACT})),
    );
    let plan = p["id"].as_str().unwrap();
    let (s, v) = w.job(plan, &[], "k-standard-1");
    assert_eq!(s, 201, "{v}");
    let view = w.t.ok(
        &w.b_dev,
        "GET",
        &format!("/v1/jobs/{}", v["id"].as_str().unwrap()),
        None,
    );
    // The lowest evaluator ID would have won the tie: it is not eligible.
    assert_eq!(view["evaluator"], "evaluator-1", "{view}");
    // With the platform's evaluator drained, the job waits: it never falls
    // back to the operator's evaluator.
    w.t.ok(
        &w.platform,
        "POST",
        "/v1/evaluators/evaluator-1/status",
        Some(json!({"status": "draining"})),
    );
    let (s, v) = w.job(plan, &[], "k-standard-2");
    assert_eq!(s, 201, "{v}");
    let view = w.t.ok(
        &w.b_dev,
        "GET",
        &format!("/v1/jobs/{}", v["id"].as_str().unwrap()),
        None,
    );
    assert_eq!(view["state"], "authorized", "{view}");
    assert_eq!(view["evaluator"], Value::Null);
    // And the catalog of a standard project counts only the platform's
    // backends: with only the operator's evaluator able to run
    // `openfhe-exact`, a standard plan could not be made.
}
