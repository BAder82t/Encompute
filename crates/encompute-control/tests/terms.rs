//! Job terms: a project's members agree which jobs it runs at all (specs,
//! purposes, submitters, evaluators, a total and a window), and the control
//! plane admits, schedules and grants nothing outside them. (Governed
//! projects: `governed_jobs.rs`, `job_terms_govern_governed_jobs_too`.)
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use std::sync::Arc;

use common::*;
use serde_json::{json, Value};

fn now() -> u64 {
    encompute_verification::service::now()
}

/// A plan of `program` by modelco's developer: (plan ID, spec ID).
fn plan(w: &World, program: &str) -> (String, String) {
    let p = w.t.ok(
        &w.b_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": w.project, "program": program})),
    );
    (
        p["id"].as_str().unwrap().into(),
        p["spec_id"].as_str().unwrap().into(),
    )
}

fn terms(specs: &[&str], max_jobs: u64, keys: &[String], not_after: u64) -> Value {
    json!({"specs": specs, "purposes": ["medical-training"], "submitters": ["modelco"],
           "evaluator_keys": keys, "max_jobs": max_jobs,
           "not_before": now() - 10, "not_after": not_after, "reference": "encagr1:test"})
}

fn receipt_key(e: &Evaluator) -> String {
    e.receipt.identity().public_key_hex()
}

/// modelco proposes `doc`; hospital-a accepts. Returns the terms' ID.
fn agree(w: &World, doc: Value) -> String {
    let p = w.t.ok(
        &w.b_admin,
        "POST",
        &format!("/v1/projects/{}/terms", w.project),
        Some(doc),
    );
    assert_eq!(p["status"], "proposed", "{p}");
    let id = p["id"].as_str().unwrap().to_owned();
    let a =
        w.t.ok(&w.a_admin, "POST", &format!("/v1/terms/{id}/accept"), None);
    assert_eq!(a["status"], "active", "{a}");
    id
}

fn denied_reasons(w: &World) -> Vec<String> {
    w.t.control
        .db
        .conn()
        .unwrap()
        .query(
            "SELECT refs->>'reason' FROM audit_events WHERE action = 'job.denied' ORDER BY seq",
            &[],
        )
        .unwrap()
        .iter()
        .filter_map(|r| r.get::<_, Option<String>>(0))
        .collect()
}

#[test]
fn jobs_are_admitted_only_within_terms_every_member_accepted() {
    let Some(w) = world() else { return };
    let (exact, spec) = plan(&w, EXACT);
    let (approx, _) = plan(&w, APPROX);
    // No terms yet: the project runs jobs as before.
    let (s, v) = w.job(&exact, &[], "before");
    assert_eq!(s, 201, "{v}");
    assert!(v["terms"].is_null(), "{v}");

    let doc = terms(&[&spec], 2, &[receipt_key(&w.evaluator)], now() + 3600);
    let p = w.t.ok(
        &w.b_admin,
        "POST",
        &format!("/v1/projects/{}/terms", w.project),
        Some(doc),
    );
    let id = p["id"].as_str().unwrap().to_owned();
    // Proposed, not yet accepted by hospital-a: not in force.
    assert_eq!(p["accepted_by"], json!(["modelco"]));
    assert_eq!(w.job(&approx, &[], "proposed-only").0, 201);
    let a =
        w.t.ok(&w.a_admin, "POST", &format!("/v1/terms/{id}/accept"), None);
    assert_eq!(a["status"], "active");
    assert_eq!(a["accepted_by"], json!(["hospital-a", "modelco"]));

    // Within the terms: the agreed spec, purpose and submitter.
    let (s, v) = w.job(&exact, &[], "in-1");
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["terms"], json!(id));
    // Another program (another spec).
    let (s, v) = w.job(&approx, &[], "other-spec");
    assert_eq!(s, 403, "{v}");
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("outside the project's job terms"),
        "{v}"
    );
    // Another purpose.
    let (s, v) = w.t.call_with(
        &w.b_dev,
        "POST",
        "/v1/jobs",
        Some(
            json!({"project": w.project, "plan": exact, "purpose": "marketing",
                    "source_assets": [], "requested_output": "out"}),
        ),
        &[("Idempotency-Key", "other-purpose")],
    );
    assert_eq!(s, 403, "{v}");
    // A member that is not a submitter.
    let (s, v) = w.t.call_with(
        &w.a_dev,
        "POST",
        "/v1/jobs",
        Some(
            json!({"project": w.project, "plan": exact, "purpose": "medical-training",
                    "source_assets": [], "requested_output": "out"}),
        ),
        &[("Idempotency-Key", "not-a-submitter")],
    );
    assert_eq!(s, 403, "{v}");
    // The second job is the last the terms allow; a retry of an admitted
    // submission is the same job, not another one.
    assert_eq!(w.job(&exact, &[], "in-2").0, 201);
    assert_eq!(w.job(&exact, &[], "in-2").0, 200);
    let (s, v) = w.job(&exact, &[], "in-3");
    assert_eq!(s, 403, "{v}");
    assert!(
        v["message"].as_str().unwrap().contains("allow 2 job(s)"),
        "{v}"
    );
    let reasons = denied_reasons(&w);
    for r in [
        "terms_spec",
        "terms_purpose",
        "terms_submitter",
        "terms_limit",
    ] {
        assert!(
            reasons.iter().any(|x| x == r),
            "{r} not audited in {reasons:?}"
        );
    }
    // Both organizations see the jobs under the terms (no grant, no
    // evaluator URL); a stranger does not.
    let jobs =
        w.t.ok(&w.a_admin, "GET", &format!("/v1/terms/{id}/jobs"), None);
    assert_eq!(jobs.as_array().unwrap().len(), 2, "{jobs}");
    assert_eq!(jobs[0]["spec_id"], json!(spec));
    assert_eq!(jobs[0]["organization"], "modelco");
    assert_eq!(jobs[0]["purpose"], "medical-training");
    assert_eq!(jobs[0]["started"], false);
    assert!(jobs[0]["grant"].is_null() && jobs[0]["evaluator_url"].is_null());
    w.t.ok(&w.b_dev, "GET", &format!("/v1/terms/{id}/jobs"), None);
    assert_eq!(
        w.t.call(&w.c_admin, "GET", &format!("/v1/terms/{id}/jobs"), None)
            .0,
        404
    );
    let listed = w.t.ok(
        &w.b_dev,
        "GET",
        &format!("/v1/projects/{}/terms", w.project),
        None,
    );
    assert_eq!(listed[0]["jobs"], 2);
    assert_eq!(listed[0]["terms"]["reference"], "encagr1:test");
    // An organization that left the project no longer sees them.
    w.t.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/projects/{}/members/remove", w.project),
        Some(json!({"organization": "hospital-a"})),
    );
    assert_eq!(
        w.t.call(&w.a_admin, "GET", &format!("/v1/terms/{id}/jobs"), None)
            .0,
        404
    );
}

#[test]
fn terms_are_agreed_by_people_in_every_member_organization() {
    let Some(w) = world() else { return };
    let (_, spec) = plan(&w, EXACT);
    let doc = terms(&[&spec], 5, &[receipt_key(&w.evaluator)], now() + 3600);
    let url = format!("/v1/projects/{}/terms", w.project);
    // Not an organization admin; modelco's automation account; a platform
    // service and a stranger (not members: not found).
    assert_eq!(w.t.call(&w.b_dev, "POST", &url, Some(doc.clone())).0, 403);
    let bot =
        Arc::new(encompute_verification::ServiceSigner::from_seed("b-bot", &[71; 32]).unwrap());
    w.t.ok(
        &w.b_admin,
        "POST",
        "/v1/organizations/modelco/service-accounts",
        Some(
            json!({"id": "b-bot", "kind": "automation", "public_key": bot.public_key_hex(),
                    "roles": ["organization_admin"]}),
        ),
    );
    let (s, v) = w.t.call(&As::Service(bot), "POST", &url, Some(doc.clone()));
    assert_eq!(s, 403, "{v}");
    assert!(v["message"].as_str().unwrap().contains("person"), "{v}");
    assert_eq!(
        w.t.call(&w.evaluator.service, "POST", &url, Some(doc.clone()))
            .0,
        404
    );
    assert_eq!(w.t.call(&w.c_admin, "POST", &url, Some(doc.clone())).0, 404);
    // Malformed: unknown field, no limit, empty lists, a non-member
    // submitter, a window that ends before it starts, a key that is not a
    // key, a spec that is not a spec ID, a reference that is free text.
    let edit = |k: &str, v: Value| {
        let mut d = doc.clone();
        d[k] = v;
        d
    };
    for bad in [
        json!({"specs": [spec], "extra": 1}),
        edit("max_jobs", json!(0)),
        edit("specs", json!([])),
        edit("submitters", json!(["other-co"])),
        edit("not_after", doc["not_before"].clone()),
        edit("evaluator_keys", json!(["zz"])),
        edit("specs", json!([spec.to_uppercase()])),
        edit("reference", json!("an agreement")),
    ] {
        let (s, v) = w.t.call(&w.b_admin, "POST", &url, Some(bad));
        assert_eq!(s, 400, "{v}");
    }
    let p = w.t.ok(&w.b_admin, "POST", &url, Some(doc.clone()));
    let id = p["id"].as_str().unwrap().to_owned();
    let accept = format!("/v1/terms/{id}/accept");
    // The proposer's organization has accepted already; hospital-a's
    // developer is not its admin; the stranger sees nothing.
    assert_eq!(w.t.call(&w.b_admin, "POST", &accept, None).0, 409);
    assert_eq!(w.t.call(&w.a_dev, "POST", &accept, None).0, 403);
    assert_eq!(w.t.call(&w.c_admin, "POST", &accept, None).0, 404);
    let a = w.t.ok(&w.a_admin, "POST", &accept, None);
    assert_eq!(a["status"], "active");
    // Active terms are not accepted again.
    assert_eq!(w.t.call(&w.a_admin, "POST", &accept, None).0, 409);

    // New terms replace them only once every member accepted those too.
    let mut looser = doc.clone();
    looser["max_jobs"] = json!(500);
    let p2 = w.t.ok(&w.b_admin, "POST", &url, Some(looser));
    let id2 = p2["id"].as_str().unwrap().to_owned();
    let listed = w.t.ok(&w.b_admin, "GET", &url, None);
    let status = |v: &Value, id: &str| {
        v.as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"] == id)
            .unwrap()["status"]
            .clone()
    };
    assert_eq!(status(&listed, &id), "active");
    assert_eq!(status(&listed, &id2), "proposed");
    w.t.ok(&w.a_admin, "POST", &format!("/v1/terms/{id2}/accept"), None);
    let listed = w.t.ok(&w.b_admin, "GET", &url, None);
    assert_eq!(status(&listed, &id), "superseded");
    assert_eq!(status(&listed, &id2), "active");
    // The database keeps them as they were agreed.
    let mut c = w.t.control.db.conn().unwrap();
    assert!(c
        .execute(
            "UPDATE job_terms SET document = '{}' WHERE id = $1",
            &[&id2]
        )
        .is_err());
    assert!(c
        .execute(
            "UPDATE job_terms SET status = 'active' WHERE id = $1",
            &[&id]
        )
        .is_err());
    assert!(c
        .execute(
            "DELETE FROM job_terms_acceptances WHERE terms_id = $1",
            &[&id2]
        )
        .is_err());
    assert!(c
        .execute(
            "UPDATE projects SET terms_required = false WHERE id = $1",
            &[&w.project]
        )
        .is_err());
}

#[test]
fn a_project_that_requires_terms_runs_nothing_until_they_are_accepted() {
    let Some(w) = world() else { return };
    let p = w.t.ok(
        &w.b_dev,
        "POST",
        "/v1/projects",
        Some(json!({"organization": "modelco", "name": "bound", "terms_required": true})),
    );
    assert_eq!(p["terms_required"], true);
    let project = p["id"].as_str().unwrap().to_owned();
    let pl = w.t.ok(
        &w.b_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": project, "program": EXACT})),
    );
    let submit = |key: &str| {
        w.t.call_with(
            &w.b_dev,
            "POST",
            "/v1/jobs",
            Some(
                json!({"project": project, "plan": pl["id"], "purpose": "medical-training",
                        "source_assets": [], "requested_output": "out"}),
            ),
            &[("Idempotency-Key", key)],
        )
    };
    let (s, v) = submit("no-terms");
    assert_eq!(s, 403, "{v}");
    assert!(denied_reasons(&w).contains(&"terms_none_active".to_owned()));
    let doc = json!({"specs": [pl["spec_id"]], "purposes": ["medical-training"], "submitters": ["modelco"],
                     "evaluator_keys": [receipt_key(&w.evaluator)], "max_jobs": 1,
                     "not_before": now() - 10, "not_after": now() + 3600});
    // A single-member project: its own admin's proposal is everyone's.
    let t = w.t.ok(
        &w.b_admin,
        "POST",
        &format!("/v1/projects/{project}/terms"),
        Some(doc),
    );
    assert_eq!(t["status"], "active", "{t}");
    let (s, v) = submit("under-terms");
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["terms"], t["id"]);
}

#[test]
fn jobs_are_scheduled_only_on_the_named_evaluators_and_granted_until_the_end() {
    let Some(w) = world() else { return };
    let (exact, spec) = plan(&w, EXACT);
    // Another evaluator that can run the job as well as evaluator-1 (which
    // the scheduler prefers on a tie, by ID).
    let other = evaluator(
        &w.t,
        &w.platform,
        "evaluator-x",
        &["openfhe", "openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
        4,
    );
    // Terms naming evaluator-x's receipt key, ending in ten minutes: the
    // job goes there, and its grant expires before the end, not an hour
    // after scheduling.
    let end = now() + 600;
    let id = agree(&w, terms(&[&spec], 3, &[receipt_key(&other)], end));
    let (_, v) = w.job(&exact, &[], "named");
    let job = v["id"].as_str().unwrap();
    let v = w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None);
    assert_eq!(v["state"], "queued", "{v}");
    assert_eq!(v["evaluator"], "evaluator-x", "{v}");
    assert_eq!(v["grant"]["expires_at"], json!(end - 1));
    assert_eq!(v["terms"], json!(id));

    // New terms naming only a key no registered evaluator has: neither
    // ready evaluator with capacity is used, and once the terms end the job
    // fails, anchored as ended.
    let stranger = encompute_verification::EvaluatorSigner::from_seed(&[77; 32])
        .identity()
        .public_key_hex();
    let short = now() + 3;
    agree(&w, terms(&[&spec], 3, &[stranger], short));
    let (_, v) = w.job(&exact, &[], "unnamed");
    let job = v["id"].as_str().unwrap().to_owned();
    let v = w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None);
    assert_eq!(v["state"], "authorized", "{v}");
    assert!(v["evaluator"].is_null());
    while now() < short {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    w.t.control.schedule_pending().unwrap();
    let v = w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None);
    assert_eq!(v["state"], "failed", "{v}");
    assert!(anchored(&w.t, NegSet::EndedJobs, &job));
    // And no new job is admitted after the end.
    let (s, v) = w.job(&exact, &[], "after-end");
    assert_eq!(s, 403, "{v}");
    assert!(denied_reasons(&w).contains(&"terms_window".to_owned()));
}

#[test]
fn concurrent_submissions_never_exceed_the_terms() {
    let Some(w) = world() else { return };
    let (exact, spec) = plan(&w, EXACT);
    let id = agree(
        &w,
        terms(&[&spec], 3, &[receipt_key(&w.evaluator)], now() + 3600),
    );
    let w = Arc::new(w);
    let statuses: Vec<u16> = (0..10)
        .map(|i| {
            let (w, exact) = (w.clone(), exact.clone());
            std::thread::spawn(move || w.job(&exact, &[], &format!("race-{i}")).0)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    assert_eq!(
        statuses.iter().filter(|s| **s == 201).count(),
        3,
        "{statuses:?}"
    );
    assert_eq!(
        statuses.iter().filter(|s| **s == 403).count(),
        7,
        "{statuses:?}"
    );
    let n: i64 =
        w.t.control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT count(*) FROM jobs WHERE terms_id = $1", &[&id])
            .unwrap()
            .get(0);
    assert_eq!(n, 3);
}
