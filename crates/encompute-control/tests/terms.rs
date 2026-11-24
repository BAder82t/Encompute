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

use encompute_evaluator::{compile_program, execution_spec, transcript_for, Ids};
use encompute_verification::{
    output_commitment, request_commitment, EvaluatorSigner, ExecutionReceipt,
};

const KEY_ID: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

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
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("take effect when every member organization has accepted them"),
        "{v}"
    );
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
    // Numbered under the terms, and read in pages.
    assert_eq!(
        (jobs[0]["seq"].clone(), jobs[1]["seq"].clone()),
        (json!(1), json!(2))
    );
    let page = w.t.ok(
        &w.a_admin,
        "GET",
        &format!("/v1/terms/{id}/jobs?limit=1"),
        None,
    );
    assert_eq!(page.as_array().unwrap().len(), 1, "{page}");
    assert_eq!(page[0]["id"], jobs[0]["id"]);
    let page = w.t.ok(
        &w.a_admin,
        "GET",
        &format!("/v1/terms/{id}/jobs?after=1"),
        None,
    );
    assert_eq!(page.as_array().unwrap().len(), 1, "{page}");
    assert_eq!(page[0]["id"], jobs[1]["id"]);
    for bad in ["after=abc", "after=-1", "limit=0", "limit=1001"] {
        let (s, v) = w.t.call(
            &w.a_admin,
            "GET",
            &format!("/v1/terms/{id}/jobs?{bad}"),
            None,
        );
        assert_eq!(s, 400, "{bad}: {v}");
    }
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
    // Accepting active terms again (a retry) answers them as they are and
    // records nothing new.
    let accepted = |w: &World| -> i64 {
        w.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT count(*) FROM audit_events WHERE action = 'terms.accepted' AND resource_id = $1",
                &[&id],
            )
            .unwrap()
            .get(0)
    };
    let before = accepted(&w);
    let again = w.t.ok(&w.a_admin, "POST", &accept, None);
    assert_eq!(again, a);
    assert_eq!(accepted(&w), before);

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
    // Superseded terms are never accepted, not even again.
    assert_eq!(w.t.call(&w.a_admin, "POST", &accept, None).0, 409);
    assert_eq!(w.t.call(&w.b_admin, "POST", &accept, None).0, 409);
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
    // Requiring terms is anchored from the project's first moment.
    assert!(anchored(&w.t, NegSet::TermsRequired, &project));
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
    // Counted by the database, and numbered 1 to 3.
    let t = terms_view(&w, &id);
    assert_eq!(t["jobs"], 3, "{t}");
    let jobs =
        w.t.ok(&w.b_dev, "GET", &format!("/v1/terms/{id}/jobs"), None);
    let seqs: Vec<i64> = jobs
        .as_array()
        .unwrap()
        .iter()
        .map(|j| j["seq"].as_i64().unwrap())
        .collect();
    assert_eq!(seqs, [1, 2, 3], "{jobs}");
}

/// `signer`'s receipt for [`EXACT`] over these bytes.
fn receipt(signer: &EvaluatorSigner, request: &[u8], response: &[u8]) -> Value {
    let p = encompute_ir::parse(EXACT).unwrap();
    let c = compile_program(&p).unwrap();
    let spec = execution_spec(&Ids::of(&p, &c), &c, c.target_backend());
    let th = transcript_for(&c, &spec).map(|t| t.id().hex());
    let r = ExecutionReceipt::new(
        &spec,
        th.as_deref(),
        KEY_ID,
        request,
        response,
        &signer.identity(),
    )
    .unwrap()
    .sign(signer)
    .unwrap();
    serde_json::to_value(r).unwrap()
}

fn terms_view(w: &World, id: &str) -> Value {
    let url = format!("/v1/projects/{}/terms", w.project);
    w.t.ok(&w.b_dev, "GET", &url, None)
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == id)
        .unwrap()
        .clone()
}

fn terms_status(w: &World, id: &str) -> Value {
    terms_view(w, id)["status"].clone()
}

#[test]
fn terms_that_take_effect_supersede_every_older_proposal() {
    let Some(w) = world() else { return };
    let (_, spec) = plan(&w, EXACT);
    let url = format!("/v1/projects/{}/terms", w.project);
    let key = receipt_key(&w.evaluator);
    // A (loose) and B (strict) are proposed; B is accepted first.
    let a = w.t.ok(
        &w.b_admin,
        "POST",
        &url,
        Some(terms(
            &[&spec],
            1000,
            std::slice::from_ref(&key),
            now() + 3600,
        )),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let b = agree(
        &w,
        terms(&[&spec], 1, std::slice::from_ref(&key), now() + 3600),
    );
    assert_eq!(terms_status(&w, &a), "superseded");
    assert_eq!(terms_status(&w, &b), "active");
    // A can never be accepted, so never replace B.
    let (s, v) =
        w.t.call(&w.a_admin, "POST", &format!("/v1/terms/{a}/accept"), None);
    assert_eq!(s, 409, "{v}");
    assert_eq!(terms_status(&w, &b), "active");
    // Recorded, and anchored, as superseded; the proposer's trail says so.
    assert!(anchored(&w.t, NegSet::SupersededTerms, &a));
    let n: i64 = w
        .t
        .control
        .db
        .conn()
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_events
              WHERE action = 'terms.superseded' AND resource_id = $1 AND organization_id = 'modelco'",
            &[&a],
        )
        .unwrap()
        .get(0);
    assert_eq!(n, 1);

    // At most eight proposals await acceptance at once.
    let mut open = vec![];
    for i in 0..8 {
        let mut d = terms(&[&spec], 10 + i, std::slice::from_ref(&key), now() + 3600);
        d["reference"] = json!(format!("p-{i}"));
        open.push(
            w.t.ok(&w.b_admin, "POST", &url, Some(d))["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let (s, v) = w.t.call(
        &w.b_admin,
        "POST",
        &url,
        Some(terms(
            &[&spec],
            99,
            std::slice::from_ref(&key),
            now() + 3600,
        )),
    );
    assert_eq!(s, 409, "{v}");
    // The limit is modelco's own: hospital-a can still propose.
    let theirs = w.t.ok(
        &w.a_admin,
        "POST",
        &url,
        Some(terms(
            &[&spec],
            98,
            std::slice::from_ref(&key),
            now() + 3600,
        )),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // One taking effect supersedes the other seven: room again.
    w.t.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/terms/{}/accept", open[3]),
        None,
    );
    assert_eq!(terms_status(&w, &theirs), "superseded");
    for (i, id) in open.iter().enumerate() {
        let want = if i == 3 { "active" } else { "superseded" };
        assert_eq!(terms_status(&w, id), want, "{id}");
    }
    assert_eq!(terms_status(&w, &b), "superseded");
    w.t.ok(
        &w.b_admin,
        "POST",
        &url,
        Some(terms(
            &[&spec],
            99,
            std::slice::from_ref(&key),
            now() + 3600,
        )),
    );
}

#[test]
fn a_job_under_terms_runs_only_with_a_receipt_key_they_name() {
    let Some(w) = world() else { return };
    let (exact, spec) = plan(&w, EXACT);
    agree(
        &w,
        terms(&[&spec], 5, &[receipt_key(&w.evaluator)], now() + 3600),
    );
    let queued = |key: &str| {
        let (s, v) = w.job(&exact, &[], key);
        assert_eq!(s, 201, "{v}");
        assert_eq!(v["state"], "queued", "{v}");
        v["id"].as_str().unwrap().to_owned()
    };
    let state =
        |job: &str| w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None)["state"].clone();
    let other = EvaluatorSigner::from_seed(&[91; 32]);
    let (req, resp) = (b"request bytes".to_vec(), b"response bytes".to_vec());

    // A job running under the key the terms name, whose evaluator's key
    // then changes under it (a re-registration fails such a job too; here
    // only the key changes): the evaluator's receipt under the new key is
    // refused, and the client's completion with it fails the job.
    let running = queued("running");
    w.t.ok(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{running}/start"),
        None,
    );
    w.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE evaluators SET receipt_key = $1 WHERE id = 'evaluator-1'",
            &[&other.identity().public_key_hex()],
        )
        .unwrap();
    let r = receipt(&other, &req, &resp);
    let (s, v) = w.t.call(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{running}/receipt"),
        Some(json!({"receipt": r})),
    );
    assert_eq!(s, 403, "{v}");
    let (s, v) = w.t.call(
        &w.b_dev,
        "POST",
        &format!("/v1/jobs/{running}/complete"),
        Some(
            json!({"receipt": r, "request_commitment": request_commitment(&req),
                    "output_commitment": output_commitment(&resp), "key_id": KEY_ID}),
        ),
    );
    assert!(s >= 400, "{s} {v}");
    let v =
        w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{running}"), None);
    assert_eq!(v["state"], "failed", "{v}");
    assert!(v["error"].as_str().unwrap().contains("terms"), "{v}");
    assert!(anchored(&w.t, NegSet::EndedJobs, &running));

    // A job queued on the evaluator before it registers again with another
    // key goes back to be scheduled (on an evaluator the terms name: here
    // none is left), and does not start where it was.
    w.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE evaluators SET receipt_key = $1 WHERE id = 'evaluator-1'",
            &[&receipt_key(&w.evaluator)],
        )
        .unwrap();
    let waiting = queued("waiting");
    w.t.ok(
        &w.evaluator.service,
        "POST",
        "/v1/evaluators",
        Some(
            json!({"id": "evaluator-1", "url": "http://evaluator-1.internal:8750",
                    "receipt_key": other.identity().public_key_hex(),
                    "backends": ["openfhe", "openfhe-exact"],
                    "profiles": ["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
                    "openfhe_version": "1.5.1", "capacity": 4}),
        ),
    );
    let v =
        w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{waiting}"), None);
    assert_eq!(v["state"], "authorized", "{v}");
    assert!(v["evaluator"].is_null() && v["grant"].is_null(), "{v}");
    let requeued: i64 = w
        .t
        .control
        .db
        .conn()
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_events WHERE action = 'job.requeued' AND resource_id = $1
                AND refs->>'reason' = 'receipt_key_not_in_terms'",
            &[&waiting],
        )
        .unwrap()
        .get(0);
    assert_eq!(requeued, 1);
    let (s, v) = w.t.call(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{waiting}/start"),
        None,
    );
    // Not its job any more.
    assert_eq!(s, 404, "{v}");
    // Registered again with the key the terms name: scheduled there again.
    w.t.ok(
        &w.evaluator.service,
        "POST",
        "/v1/evaluators",
        Some(
            json!({"id": "evaluator-1", "url": "http://evaluator-1.internal:8750",
                    "receipt_key": receipt_key(&w.evaluator),
                    "backends": ["openfhe", "openfhe-exact"],
                    "profiles": ["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
                    "openfhe_version": "1.5.1", "capacity": 4}),
        ),
    );
    w.t.control.schedule_pending().unwrap();
    assert_eq!(state(&waiting), "queued");
    // Registering again with a key the terms name leaves its jobs queued.
    w.t.ok(
        &w.evaluator.service,
        "POST",
        "/v1/evaluators",
        Some(
            json!({"id": "evaluator-1", "url": "http://evaluator-1.internal:8750",
                    "receipt_key": receipt_key(&w.evaluator),
                    "backends": ["openfhe", "openfhe-exact"],
                    "profiles": ["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
                    "openfhe_version": "1.5.1", "capacity": 4}),
        ),
    );
    let v =
        w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{waiting}"), None);
    assert_eq!(
        (v["state"].clone(), v["evaluator"].clone()),
        (json!("queued"), json!("evaluator-1")),
        "{v}"
    );
    // A key changed some other way than a registration: the job does not
    // start.
    w.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE evaluators SET receipt_key = $1 WHERE id = 'evaluator-1'",
            &[&other.identity().public_key_hex()],
        )
        .unwrap();
    let (s, v) = w.t.call(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{waiting}/start"),
        None,
    );
    assert_eq!(s, 403, "{v}");
    assert_eq!(state(&waiting), "queued");
}

/// Stops `t` and backs its database up as `name`: (the stopped harness,
/// the backup's name).
fn stop_and_back_up(t: T, name: &str) -> (Env0, String) {
    let url = t.env0.url.clone();
    let env0 = t.env0;
    drop(t.control);
    let backup = format!("{}_{name}", url.rsplit('/').next().unwrap());
    backup_database(&url, &backup);
    (env0, backup)
}

#[test]
fn a_restore_never_brings_superseded_terms_back() {
    let Some(w) = world() else { return };
    let (exact, spec) = plan(&w, EXACT);
    let key = receipt_key(&w.evaluator);
    // Loose terms are active when the backup is taken.
    let loose = agree(
        &w,
        terms(&[&spec], 1000, std::slice::from_ref(&key), now() + 3600),
    );
    let World {
        t,
        a_admin,
        b_admin,
        b_dev,
        project,
        ..
    } = w;
    let (env0, backup) = stop_and_back_up(t, "trbk");
    let t = env0.started();
    // Strict terms replace them, and the replacement is anchored.
    let strict = {
        let p = t.ok(
            &b_admin,
            "POST",
            &format!("/v1/projects/{project}/terms"),
            Some(terms(&[&spec], 1, std::slice::from_ref(&key), now() + 3600)),
        );
        let id = p["id"].as_str().unwrap().to_owned();
        t.ok(&a_admin, "POST", &format!("/v1/terms/{id}/accept"), None);
        id
    };
    assert!(anchored(&t, NegSet::SupersededTerms, &loose));
    let env0 = t.env0;
    drop(t.control);
    // The backup still has the loose terms active.
    restore_keeping_log(&env0, &backup);
    let e = env0
        .start()
        .err()
        .expect("a restore brought superseded terms back silently");
    assert!(e.message.contains("JOB TERMS STATE ROLLBACK"), "{e}");
    assert!(e.message.contains(&loose), "{e}");
    let notes = run_recovery(&env0);
    assert!(
        notes
            .iter()
            .any(|n| n.contains(&loose) && n.contains("superseded again")),
        "{notes:?}"
    );
    // The loose terms stay superseded, the strict ones were lost with the
    // restore: the project runs nothing until its members agree again.
    let t = env0.started();
    let listed = t.ok(
        &b_dev,
        "GET",
        &format!("/v1/projects/{project}/terms"),
        None,
    );
    assert_eq!(listed[0]["id"], json!(loose));
    assert_eq!(listed[0]["status"], "superseded");
    assert!(!listed.to_string().contains(&strict), "{listed}");
    let (s, v) = t.call_with(
        &b_dev,
        "POST",
        "/v1/jobs",
        Some(
            json!({"project": project, "plan": exact, "purpose": "medical-training",
                    "source_assets": [], "requested_output": "out"}),
        ),
        &[("Idempotency-Key", "after-restore")],
    );
    assert_eq!(s, 403, "{v}");
    assert!(
        v["message"].as_str().unwrap().contains("none are active"),
        "{v}"
    );
    t.restarted();
}

#[test]
fn a_restore_never_lifts_a_projects_requirement_of_terms() {
    let Some(w) = world() else { return };
    let (exact, spec) = plan(&w, EXACT);
    let key = receipt_key(&w.evaluator);
    let World {
        t,
        a_admin,
        b_admin,
        b_dev,
        project,
        ..
    } = w;
    // The backup: a project without terms.
    let (env0, backup) = stop_and_back_up(t, "rqbk");
    let t = env0.started();
    // Its first terms take effect: it requires terms from now on.
    let p = t.ok(
        &b_admin,
        "POST",
        &format!("/v1/projects/{project}/terms"),
        Some(terms(
            &[&spec],
            1000,
            std::slice::from_ref(&key),
            now() + 3600,
        )),
    );
    let id = p["id"].as_str().unwrap().to_owned();
    t.ok(&a_admin, "POST", &format!("/v1/terms/{id}/accept"), None);
    assert!(anchored(&t, NegSet::TermsRequired, &project));
    let env0 = t.env0;
    drop(t.control);
    restore_keeping_log(&env0, &backup);
    let e = env0
        .start()
        .err()
        .expect("a restore lifted a project's requirement of terms silently");
    assert!(
        e.message.contains("TERMS REQUIREMENT STATE ROLLBACK"),
        "{e}"
    );
    assert!(e.message.contains(&project), "{e}");
    let notes = run_recovery(&env0);
    assert!(
        notes
            .iter()
            .any(|n| n.contains(&project) && n.contains("requirement of job terms re-applied")),
        "{notes:?}"
    );
    // It requires terms again; those it had were lost with the restore.
    let t = env0.started();
    let (s, v) = t.call_with(
        &b_dev,
        "POST",
        "/v1/jobs",
        Some(
            json!({"project": project, "plan": exact, "purpose": "medical-training",
                    "source_assets": [], "requested_output": "out"}),
        ),
        &[("Idempotency-Key", "after-restore")],
    );
    assert_eq!(s, 403, "{v}");
    assert!(
        v["message"].as_str().unwrap().contains("none are active"),
        "{v}"
    );
    t.restarted();
}

#[test]
fn jobs_waiting_for_a_full_evaluator_never_hold_up_the_scheduler() {
    let Some(w) = world() else { return };
    let (exact, spec) = plan(&w, EXACT);
    // Terms naming only evaluator-x, which runs one job at a time: the
    // first job takes it, and the next hundred (the scheduler's batch)
    // wait for it.
    let x = evaluator(
        &w.t,
        &w.platform,
        "evaluator-x",
        &["openfhe", "openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
        1,
    );
    agree(&w, terms(&[&spec], 101, &[receipt_key(&x)], now() + 3600));
    for i in 0..101 {
        let (s, v) = w.job(&exact, &[], &format!("waiting-{i}"));
        assert_eq!(s, 201, "{v}");
        assert_eq!(
            v["state"],
            if i == 0 { "queued" } else { "authorized" },
            "{v}"
        );
    }
    // Newer terms name evaluator-1, which is away (draining) when the next
    // job comes.
    agree(
        &w,
        terms(&[&spec], 1, &[receipt_key(&w.evaluator)], now() + 3600),
    );
    let set_status = |status: &str| {
        w.t.control
            .db
            .conn()
            .unwrap()
            .execute(
                "UPDATE evaluators SET status = $1 WHERE id = 'evaluator-1'",
                &[&status],
            )
            .unwrap();
    };
    set_status("draining");
    let (s, v) = w.job(&exact, &[], "runnable");
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["state"], "authorized", "{v}");
    let job = v["id"].as_str().unwrap().to_owned();
    // Back: the scheduler's next pass places it, whatever waits ahead (for
    // an evaluator that is full, or one their terms do not name).
    set_status("ready");
    w.t.control.schedule_pending().unwrap();
    let v = w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None);
    assert_eq!(v["state"], "queued", "{v}");
    assert_eq!(v["evaluator"], "evaluator-1", "{v}");
}

#[test]
fn proposed_terms_take_effect_when_the_last_member_yet_to_accept_leaves() {
    let Some(w) = world() else { return };
    let (_, spec) = plan(&w, EXACT);
    let members = format!("/v1/projects/{}/members", w.project);
    let invite = || {
        let body = Some(json!({"organization": "other-co"}));
        w.t.ok(&w.b_admin, "POST", &members, body.clone());
        w.t.ok(&w.c_admin, "POST", &members, body);
    };
    // modelco proposes, hospital-a accepts; other-co has not.
    let propose = |max_jobs: u64| -> String {
        let doc = terms(
            &[&spec],
            max_jobs,
            &[receipt_key(&w.evaluator)],
            now() + 3600,
        );
        let p = w.t.ok(
            &w.b_admin,
            "POST",
            &format!("/v1/projects/{}/terms", w.project),
            Some(doc),
        );
        let id = p["id"].as_str().unwrap().to_owned();
        let a =
            w.t.ok(&w.a_admin, "POST", &format!("/v1/terms/{id}/accept"), None);
        assert_eq!(a["status"], "proposed", "{a}");
        id
    };
    invite();
    let id = propose(3);
    // hospital-a accepted already: accepting again changes nothing.
    assert_eq!(
        w.t.call(&w.a_admin, "POST", &format!("/v1/terms/{id}/accept"), None)
            .0,
        409
    );
    // other-co, the only member yet to accept, leaves: they take effect,
    // and their activation says why.
    let r = w.t.ok(
        &w.c_admin,
        "POST",
        &format!("{members}/remove"),
        Some(json!({"organization": "other-co"})),
    );
    assert_eq!(r["terms_activated"], json!(id), "{r}");
    assert_eq!(terms_status(&w, &id), "active");
    let why: Vec<(String, String)> =
        w.t.control
            .db
            .conn()
            .unwrap()
            .query(
                "SELECT refs->>'reason', refs->>'member' FROM audit_events
              WHERE action = 'terms.activated' AND resource_id = $1",
                &[&id],
            )
            .unwrap()
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
    assert_eq!(why.len(), 2, "{why:?}");
    assert!(
        why.iter()
            .all(|w| w == &("member_left".into(), "other-co".into())),
        "{why:?}"
    );
    assert!(anchored(&w.t, NegSet::TermsRequired, &w.project));

    // A removal that did not settle the terms (a recovery re-applying it,
    // say): accepting them again, by a member that has, makes them take
    // effect.
    invite();
    let next = propose(4);
    w.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "DELETE FROM project_members WHERE project_id = $1 AND organization_id = 'other-co'",
            &[&w.project],
        )
        .unwrap();
    assert_eq!(terms_status(&w, &next), "proposed");
    let a = w.t.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/terms/{next}/accept"),
        None,
    );
    assert_eq!(a["status"], "active", "{a}");
    assert_eq!(terms_status(&w, &id), "superseded");
    assert!(anchored(&w.t, NegSet::SupersededTerms, &id));
}

#[test]
fn the_database_counts_and_numbers_jobs_under_terms_and_holds_their_limit() {
    let Some(w) = world() else { return };
    let (exact, spec) = plan(&w, EXACT);
    let key = receipt_key(&w.evaluator);
    let doc = |max_jobs: u64| terms(&[&spec], max_jobs, std::slice::from_ref(&key), now() + 3600);
    let first = agree(&w, doc(2));
    let (s, v) = w.job(&exact, &[], "only");
    assert_eq!(s, 201, "{v}");
    let job = v["id"].as_str().unwrap().to_owned();
    let mut c = w.t.control.db.conn().unwrap();
    // Copies of the job, under `terms`, inserted around the control plane:
    // the database counts and numbers them, up to the terms' limit.
    let copy = |c: &mut postgres::Client, id: &str, terms: &str| {
        c.execute(
            "INSERT INTO jobs
             SELECT (jsonb_populate_record(NULL::jobs, to_jsonb(j) || jsonb_build_object(
                         'id', $2::text, 'idempotency_key', $2::text,
                         'terms_id', $3::text, 'terms_seq', NULL))).*
               FROM jobs j WHERE j.id = $1",
            &[&job, &id, &terms],
        )
        .map_err(|e| {
            e.as_db_error()
                .map(|d| d.message().to_owned())
                .unwrap_or_default()
        })
    };
    let seq = |c: &mut postgres::Client, id: &str| -> i64 {
        c.query_one("SELECT terms_seq FROM jobs WHERE id = $1", &[&id])
            .unwrap()
            .get(0)
    };
    copy(&mut c, "job-copy-1", &first).unwrap();
    assert_eq!(seq(&mut c, "job-copy-1"), 2);
    let refused = copy(&mut c, "job-copy-2", &first).unwrap_err();
    assert!(refused.contains("every job they allow"), "{refused}");
    assert_eq!(terms_view(&w, &first)["jobs"], 2);
    // The count never goes down, and a job's number never changes.
    assert!(c
        .execute(
            "UPDATE job_terms SET jobs_submitted = 0 WHERE id = $1",
            &[&first]
        )
        .is_err());
    assert!(c
        .execute("UPDATE jobs SET terms_seq = 7 WHERE id = $1", &[&job])
        .is_err());
    // Nor beyond max_jobs (recovery raises it only to an anchored count,
    // which never is).
    let raised = c
        .execute(
            "UPDATE job_terms SET jobs_submitted = jobs_submitted + 5 WHERE id = $1",
            &[&first],
        )
        .unwrap_err();
    assert!(
        raised
            .as_db_error()
            .unwrap()
            .message()
            .contains("never exceeds"),
        "{raised}"
    );
    // Under superseded terms nothing is inserted, though they would allow
    // more; under the active ones a job is counted and numbered.
    let second = agree(&w, doc(5));
    let third = agree(&w, doc(5));
    let refused = copy(&mut c, "job-copy-3", &second).unwrap_err();
    assert!(refused.contains("not active"), "{refused}");
    // Nor under another project's terms.
    let other = w.t.ok(
        &w.b_dev,
        "POST",
        "/v1/projects",
        Some(json!({"organization": "modelco", "name": "elsewhere"})),
    );
    let refused = c
        .execute(
            "INSERT INTO jobs
             SELECT (jsonb_populate_record(NULL::jobs, to_jsonb(j) || jsonb_build_object(
                         'id', 'job-elsewhere', 'idempotency_key', 'elsewhere',
                         'project_id', $2::text, 'terms_id', $3::text, 'terms_seq', NULL))).*
               FROM jobs j WHERE j.id = $1",
            &[&job, &other["id"].as_str().unwrap(), &third],
        )
        .unwrap_err();
    assert!(
        refused
            .as_db_error()
            .unwrap()
            .message()
            .contains("not active in the job's project"),
        "{refused}"
    );
    copy(&mut c, "job-copy-4", &third).unwrap();
    assert_eq!(seq(&mut c, "job-copy-4"), 1);
    assert_eq!(terms_view(&w, &third)["jobs"], 1);
    // Nor a job without terms in a project that requires them.
    let refused = c
        .execute(
            "INSERT INTO jobs
             SELECT (jsonb_populate_record(NULL::jobs, to_jsonb(j) || jsonb_build_object(
                         'id', 'job-no-terms', 'idempotency_key', 'no-terms',
                         'terms_id', NULL, 'terms_seq', NULL))).*
               FROM jobs j WHERE j.id = $1",
            &[&job],
        )
        .unwrap_err();
    assert!(
        refused
            .as_db_error()
            .unwrap()
            .message()
            .contains("runs jobs only under job terms"),
        "{refused}"
    );
}

/// The audit events of `action` about `id`: (actor, reason, member).
fn audited(w: &World, action: &str, id: &str) -> Vec<(String, Option<String>, Option<String>)> {
    w.t.control
        .db
        .conn()
        .unwrap()
        .query(
            "SELECT actor, refs->>'reason', refs->>'member' FROM audit_events
              WHERE action = $1 AND resource_id = $2 ORDER BY seq",
            &[&action, &id],
        )
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect()
}

/// other-co joins the project (modelco invites, other-co's admin accepts).
fn other_co_joins(w: &World) {
    let members = format!("/v1/projects/{}/members", w.project);
    let body = Some(json!({"organization": "other-co"}));
    w.t.ok(&w.b_admin, "POST", &members, body.clone());
    w.t.ok(&w.c_admin, "POST", &members, body);
}

/// An organization that joins the project after its terms took effect
/// consents to them before its data is used under them: a job over its
/// asset is refused (`terms_owner`) until it accepts the active terms,
/// which records its acceptance and changes nothing else; then the job is
/// admitted, and the organization sees the jobs under them.
#[test]
fn an_organization_that_joins_later_accepts_the_terms_before_its_data_is_used() {
    let Some(w) = world() else { return };
    let c_owner = user(&w.t, &w.c_admin, "other-co", "c-owner", &["data_owner"]);
    let d = w.t.ok(
        &c_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": "other-co", "kind": "dataset", "name": "claims-2026",
                    "digest": "c".repeat(64), "privacy_budget": budget(3.0)}),
        ),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (over, spec) = plan(
        &w,
        &exact_over(&d, "other-co", "dataset", "medical-training"),
    );
    // modelco and hospital-a agree terms naming that program's spec.
    let id = agree(
        &w,
        terms(&[&spec], 5, &[receipt_key(&w.evaluator)], now() + 3600),
    );
    let activated_at = |w: &World| -> String {
        w.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT activated_at::text FROM job_terms WHERE id = $1",
                &[&id],
            )
            .unwrap()
            .get(0)
    };
    let before = (activated_at(&w), audited(&w, "terms.activated", &id).len());
    // other-co joins later and approves its dataset for modelco.
    other_co_joins(&w);
    w.t.ok(
        &c_owner,
        "POST",
        &format!("/v1/assets/{d}/approvals"),
        Some(json!({"project": w.project, "purpose": "medical-training"})),
    );
    // Its data is not used under terms it has not accepted.
    let (s, v) = w.job(&over, &[&d], "before-consent");
    assert_eq!(s, 403, "{v}");
    let m = v["message"].as_str().unwrap();
    assert!(
        m.contains("other-co") && m.contains("must accept the terms"),
        "{v}"
    );
    assert!(denied_reasons(&w).contains(&"terms_owner".to_owned()));
    let jobs = format!("/v1/terms/{id}/jobs");
    assert_eq!(w.t.call(&w.c_admin, "GET", &jobs, None).0, 404);
    // It accepts the active terms: recorded, nothing else changes.
    let a =
        w.t.ok(&w.c_admin, "POST", &format!("/v1/terms/{id}/accept"), None);
    assert_eq!(a["status"], "active", "{a}");
    assert_eq!(
        a["accepted_by"],
        json!(["hospital-a", "modelco", "other-co"])
    );
    assert_eq!(audited(&w, "terms.accepted", &id).len(), 2);
    assert_eq!(
        (activated_at(&w), audited(&w, "terms.activated", &id).len()),
        before
    );
    assert_eq!(terms_status(&w, &id), "active");
    // Now the job is admitted under them, and other-co sees it.
    let (s, v) = w.job(&over, &[&d], "after-consent");
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["terms"], json!(id));
    let listed = w.t.ok(&w.c_admin, "GET", &jobs, None);
    assert_eq!(listed[0]["id"], v["id"], "{listed}");
    // Accepting again answers the terms as they are.
    let again =
        w.t.ok(&w.c_admin, "POST", &format!("/v1/terms/{id}/accept"), None);
    assert_eq!(again["accepted_by"], a["accepted_by"]);
    assert_eq!(audited(&w, "terms.accepted", &id).len(), 2);
}

/// An acceptance that activated terms committed, but anchoring what it
/// committed failed: the client got an error. Accepting them again
/// succeeds once the anchor holds the activation (on another thread than
/// the failed call, which keeps no obligation to retry there).
#[test]
fn accepting_terms_again_after_their_anchoring_failed_anchors_them() {
    let Some(w) = world() else { return };
    let (_, spec) = plan(&w, EXACT);
    let doc = terms(&[&spec], 5, &[receipt_key(&w.evaluator)], now() + 3600);
    let World {
        t,
        a_admin,
        b_admin,
        project,
        ..
    } = w;
    let env0 = t.env0;
    drop(t.control);
    let (t, fail) = env0.start_flaky();
    let p = t.ok(
        &b_admin,
        "POST",
        &format!("/v1/projects/{project}/terms"),
        Some(doc),
    );
    let id = p["id"].as_str().unwrap().to_owned();
    let accept = format!("/v1/terms/{id}/accept");
    fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let (s, v) = t.call(&a_admin, "POST", &accept, None);
    assert_ne!(s, 200, "{v}");
    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    let status: String = t
        .control
        .db
        .conn()
        .unwrap()
        .query_one("SELECT status FROM job_terms WHERE id = $1", &[&id])
        .unwrap()
        .get(0);
    assert_eq!(status, "active", "the acceptance committed");
    assert!(!anchored(&t, NegSet::TermsRequired, &project));
    let (s, v) = std::thread::scope(|scope| {
        scope
            .spawn(|| t.call(&a_admin, "POST", &accept, None))
            .join()
            .unwrap()
    });
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "active", "{v}");
    assert!(anchored(&t, NegSet::TermsRequired, &project));
}

/// A settle after a removal that did not happen (it failed; here the
/// removal's row is deleted directly) is retried by the control plane's
/// periodic pass: the terms every remaining member accepted take effect,
/// recorded by the control plane with `reason: settled`.
#[test]
fn the_periodic_pass_settles_terms_a_removal_left_complete() {
    let Some(w) = world() else { return };
    let (_, spec) = plan(&w, EXACT);
    other_co_joins(&w);
    let p = w.t.ok(
        &w.b_admin,
        "POST",
        &format!("/v1/projects/{}/terms", w.project),
        Some(terms(
            &[&spec],
            3,
            &[receipt_key(&w.evaluator)],
            now() + 3600,
        )),
    );
    let id = p["id"].as_str().unwrap().to_owned();
    let a =
        w.t.ok(&w.a_admin, "POST", &format!("/v1/terms/{id}/accept"), None);
    assert_eq!(a["status"], "proposed", "{a}");
    // A pass while other-co is a member settles nothing.
    w.t.control.tick();
    assert_eq!(terms_status(&w, &id), "proposed");
    w.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "DELETE FROM project_members WHERE project_id = $1 AND organization_id = 'other-co'",
            &[&w.project],
        )
        .unwrap();
    assert_eq!(terms_status(&w, &id), "proposed");
    w.t.control.tick();
    assert_eq!(terms_status(&w, &id), "active");
    let why = audited(&w, "terms.activated", &id);
    assert_eq!(why.len(), 2, "{why:?}");
    assert!(
        why.iter()
            .all(|x| x == &("control-plane".into(), Some("settled".into()), None)),
        "{why:?}"
    );
    assert!(anchored(&w.t, NegSet::TermsRequired, &w.project));
    // Settled once.
    w.t.control.tick();
    assert_eq!(audited(&w, "terms.activated", &id).len(), 2);
    // A project with no active member has nobody to agree terms for it: a
    // proposal left there is never settled.
    let mut c = w.t.control.db.conn().unwrap();
    c.execute(
        "INSERT INTO job_terms (id, project_id, organization_id, digest, document, status, created_by)
         SELECT 'terms-orphan', project_id, organization_id, digest, document, 'proposed', created_by
           FROM job_terms WHERE id = $1",
        &[&id],
    )
    .unwrap();
    c.execute(
        "DELETE FROM project_members WHERE project_id = $1",
        &[&w.project],
    )
    .unwrap();
    w.t.control.tick();
    let status: String = c
        .query_one(
            "SELECT status FROM job_terms WHERE id = 'terms-orphan'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(status, "proposed");
}

/// Whether the governance log's admission of `job` under job terms is
/// anchored.
fn admission_anchored(t: &T, job: &str) -> bool {
    let size = t.control.anchor.snapshot().glog_size;
    t.control
        .db
        .conn()
        .unwrap()
        .query_opt(
            "SELECT gseq FROM governance_events WHERE kind = 'terms.job_admitted' AND subject_id = $1",
            &[&job],
        )
        .unwrap()
        .is_some_and(|r| r.get::<_, i64>(0) <= size)
}

#[test]
fn a_restore_never_lowers_the_count_of_jobs_under_terms() {
    let Some(w) = world() else { return };
    let (exact, spec) = plan(&w, EXACT);
    let key = receipt_key(&w.evaluator);
    let id = agree(
        &w,
        terms(&[&spec], 3, std::slice::from_ref(&key), now() + 3600),
    );
    let (s, v) = w.job(&exact, &[], "first");
    assert_eq!(s, 201, "{v}");
    let World {
        t, b_dev, project, ..
    } = w;
    let submit = |t: &T, key: &str| {
        t.call_with(
            &b_dev,
            "POST",
            "/v1/jobs",
            Some(
                json!({"project": project, "plan": exact, "purpose": "medical-training",
                        "source_assets": [], "requested_output": "out"}),
            ),
            &[("Idempotency-Key", key)],
        )
    };
    // The backup counts one job under the terms.
    let (env0, backup) = stop_and_back_up(t, "tcbk");
    let t = env0.started();
    // The other two they allow, each anchored before it is acknowledged.
    for key in ["second", "third"] {
        let (s, v) = submit(&t, key);
        assert_eq!(s, 201, "{v}");
        assert!(admission_anchored(&t, v["id"].as_str().unwrap()), "{v}");
    }
    let env0 = t.env0;
    drop(t.control);
    // Restored (the governance log put back): the database counts one.
    restore_keeping_log(&env0, &backup);
    let e = env0
        .start()
        .err()
        .expect("a restore lowered the count of jobs under terms silently");
    assert!(e.message.contains("JOB TERMS COUNT STATE ROLLBACK"), "{e}");
    assert!(e.message.contains(&id), "{e}");
    let notes = run_recovery(&env0);
    assert!(
        notes
            .iter()
            .any(|n| n.contains(&id) && n.contains("raised from 1 to 3")),
        "{notes:?}"
    );
    // Recovery again changes nothing.
    let size = |env0: &Env0| -> i64 {
        let mut c = postgres::Client::connect(&env0.url, postgres::NoTls).unwrap();
        c.query_one("SELECT gseq FROM governance_head WHERE id", &[])
            .unwrap()
            .get(0)
    };
    let log = size(&env0);
    let again = run_recovery(&env0);
    assert!(again.is_empty(), "{again:?}");
    assert_eq!(size(&env0), log);
    let t = env0.started();
    let restored: i64 = t
        .control
        .db
        .conn()
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_events WHERE action = 'terms.count_restored' AND resource_id = $1",
            &[&id],
        )
        .unwrap()
        .get(0);
    assert_eq!(restored, 1);
    // The terms still allow three jobs in all: none more is admitted.
    let listed = t.ok(
        &b_dev,
        "GET",
        &format!("/v1/projects/{project}/terms"),
        None,
    );
    assert_eq!(listed[0]["jobs"], 3, "{listed}");
    let (s, v) = submit(&t, "fourth");
    assert_eq!(s, 403, "{v}");
    assert!(
        v["message"].as_str().unwrap().contains("allow 3 job(s)"),
        "{v}"
    );
    t.restarted();
}

/// A submission admitted under terms whose anchoring failed (the client
/// got an error, the job committed) is anchored before a retry with the
/// same `Idempotency-Key` acknowledges it (on another thread than the
/// failed call, which keeps no obligation to retry there).
#[test]
fn a_retried_submission_under_terms_is_anchored_before_it_is_acknowledged() {
    let Some(w) = world() else { return };
    let (exact, spec) = plan(&w, EXACT);
    agree(
        &w,
        terms(&[&spec], 3, &[receipt_key(&w.evaluator)], now() + 3600),
    );
    let World {
        t, b_dev, project, ..
    } = w;
    let env0 = t.env0;
    drop(t.control);
    let (t, fail) = env0.start_flaky();
    let submit = || {
        t.call_with(
            &b_dev,
            "POST",
            "/v1/jobs",
            Some(
                json!({"project": project, "plan": exact, "purpose": "medical-training",
                        "source_assets": [], "requested_output": "out"}),
            ),
            &[("Idempotency-Key", "flaky")],
        )
    };
    fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let (s, v) = submit();
    assert_ne!(s, 201, "{v}");
    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    let job: String = t
        .control
        .db
        .conn()
        .unwrap()
        .query_one("SELECT id FROM jobs WHERE idempotency_key = 'flaky'", &[])
        .unwrap()
        .get(0);
    assert!(
        !admission_anchored(&t, &job),
        "the admission committed unanchored"
    );
    let (s, v) = std::thread::scope(|scope| scope.spawn(submit).join().unwrap());
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["id"], json!(job));
    assert!(admission_anchored(&t, &job));
}

/// The scheduler's periodic pass rotates: more than its batch of older
/// authorized jobs that cannot be placed (a profile no evaluator
/// registers) keep a newer job that can waiting for at most two passes.
#[test]
fn jobs_that_cannot_be_placed_never_keep_a_newer_job_waiting() {
    let Some(w) = world() else { return };
    let (exact, _) = plan(&w, EXACT);
    let (s, v) = w.job(&exact, &[], "model");
    assert_eq!(s, 201, "{v}");
    let model = v["id"].as_str().unwrap().to_owned();
    let mut c = w.t.control.db.conn().unwrap();
    // 150 older copies of it, authorized, for a profile nobody runs.
    let n = c
        .execute(
            "INSERT INTO jobs
             SELECT (jsonb_populate_record(NULL::jobs, to_jsonb(j) || jsonb_build_object(
                         'id', 'job-stuck-' || n, 'idempotency_key', 'stuck-' || n,
                         'state', 'authorized', 'profile', 'NO_EVALUATOR_RUNS_THIS',
                         'evaluator_id', NULL, 'job_grant', NULL, 'estimated_ms', NULL,
                         'created_at', now() - interval '1 hour' + n * interval '1 second'))).*
               FROM jobs j, generate_series(1, 150) AS n WHERE j.id = $1",
            &[&model],
        )
        .unwrap();
    assert_eq!(n, 150);
    let set_status = |c: &mut postgres::Client, status: &str| {
        c.execute(
            "UPDATE evaluators SET status = $1 WHERE id = 'evaluator-1'",
            &[&status],
        )
        .unwrap();
    };
    // A newer job, submitted while its evaluator is away.
    set_status(&mut c, "draining");
    let (s, v) = w.job(&exact, &[], "newer");
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["state"], "authorized", "{v}");
    let job = v["id"].as_str().unwrap().to_owned();
    set_status(&mut c, "ready");
    let state = || w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None)["state"].clone();
    // The first pass tries the hundred oldest; the second the rest, and
    // the newer job.
    w.t.control.schedule_pending().unwrap();
    assert_eq!(state(), "authorized");
    w.t.control.schedule_pending().unwrap();
    assert_eq!(state(), "queued");
    // The others still wait, and the next passes go round them again.
    let stuck: i64 = c
        .query_one(
            "SELECT count(*) FROM jobs WHERE profile = 'NO_EVALUATOR_RUNS_THIS' AND state = 'authorized'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(stuck, 150);
    w.t.control.schedule_pending().unwrap();
    w.t.control.schedule_pending().unwrap();
}

/// Submissions racing an acceptance that replaces the active terms: each
/// job is admitted under the terms that were active when it committed
/// (none under the superseded terms after their replacement), and each set
/// of terms counts and numbers exactly its jobs.
#[test]
fn concurrent_acceptance_and_submissions_count_exactly() {
    let Some(w) = world() else { return };
    let (exact, spec) = plan(&w, EXACT);
    let key = receipt_key(&w.evaluator);
    let doc = || terms(&[&spec], 1000, std::slice::from_ref(&key), now() + 3600);
    let first = agree(&w, doc());
    let p = w.t.ok(
        &w.b_admin,
        "POST",
        &format!("/v1/projects/{}/terms", w.project),
        Some(doc()),
    );
    let next = p["id"].as_str().unwrap().to_owned();
    let w = Arc::new(w);
    // Eight submitters keep submitting while the acceptance runs: it starts
    // once some jobs exist under the first terms, and each submitter sends
    // one more after it returned, so jobs land on both sides of it and
    // others race it.
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    let made = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let mut handles = vec![];
    for i in 0..8 {
        let (w, exact, made, done) = (w.clone(), exact.clone(), made.clone(), done.clone());
        handles.push(std::thread::spawn(move || {
            let mut out = vec![];
            for k in 0.. {
                let last = done.load(SeqCst);
                out.push(w.job(&exact, &[], &format!("race-{i}-{k}")).0);
                made.fetch_add(1, SeqCst);
                if last {
                    break;
                }
            }
            out
        }));
    }
    let accept = {
        let (w, next, made, done) = (w.clone(), next.clone(), made.clone(), done.clone());
        std::thread::spawn(move || {
            while made.load(SeqCst) < 4 {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            let a = w.t.ok(
                &w.a_admin,
                "POST",
                &format!("/v1/terms/{next}/accept"),
                None,
            );
            done.store(true, SeqCst);
            a
        })
    };
    let statuses: Vec<u16> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    assert_eq!(accept.join().unwrap()["status"], "active");
    assert!(statuses.iter().all(|s| *s == 201), "{statuses:?}");
    let mut c = w.t.control.db.conn().unwrap();
    // The activation's audit position: every job under the first terms
    // committed before it, every job under the next after it.
    let activated: i64 = c
        .query_one(
            "SELECT min(seq) FROM audit_events WHERE action = 'terms.activated' AND resource_id = $1",
            &[&next],
        )
        .unwrap()
        .get(0);
    let mut total = 0;
    for (terms, before) in [(&first, true), (&next, false)] {
        let created: Vec<i64> = c
            .query(
                "SELECT seq FROM audit_events WHERE action = 'job.created' AND refs->>'terms' = $1",
                &[terms],
            )
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        // Jobs on both sides of the activation, none on the wrong one.
        assert!(!created.is_empty(), "{terms}: no job under them");
        assert!(
            created.iter().all(|s| (*s < activated) == before),
            "{terms}: {created:?} around {activated}"
        );
        let seqs: Vec<i64> = c
            .query(
                "SELECT terms_seq FROM jobs WHERE terms_id = $1 ORDER BY terms_seq",
                &[terms],
            )
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert_eq!(seqs, (1..=seqs.len() as i64).collect::<Vec<_>>());
        assert_eq!(seqs.len(), created.len());
        assert_eq!(terms_view(&w, terms)["jobs"], json!(seqs.len()));
        // And the governance log recorded each admission with its number.
        let logged: Vec<i64> = c
            .query(
                "SELECT (body #>> '{refs,seq}')::bigint FROM governance_events
                  WHERE kind = 'terms.job_admitted' AND body #>> '{refs,terms}' = $1 ORDER BY gseq",
                &[terms],
            )
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert_eq!(logged, seqs);
        total += seqs.len();
    }
    assert_eq!(total, statuses.len());
}

/// A database that ran schema version 19 (jobs under terms, neither
/// counted nor numbered) gets each set of terms' count of jobs and each
/// job's number under them, in the order the jobs were submitted, and the
/// database counts from there.
#[test]
fn migration_20_counts_and_numbers_the_jobs_of_a_version_19_database() {
    let Some(url) = unmigrated_database() else {
        return;
    };
    let db = encompute_control::db::Db::connect(&url).unwrap();
    assert_eq!(db.migrate_to(19).unwrap(), 19);
    let digest = "d".repeat(64);
    let doc = json!({"max_jobs": 5}).to_string();
    let mut c = db.conn().unwrap();
    c.batch_execute(&format!(
        "INSERT INTO organizations (id, display_name, status, policy_namespace) VALUES ('o', 'o', 'active', 'o');
         INSERT INTO projects (id, organization_id, name, status) VALUES ('p', 'o', 'p', 'active');
         INSERT INTO plans (id, organization_id, project_id, program_id, spec_id, program, document, created_by)
              VALUES ('pl', 'o', 'p', 'x', 'y', '', '{{}}', 'u');
         INSERT INTO job_terms (id, project_id, organization_id, digest, document, status, created_by, activated_at)
              VALUES ('terms-old', 'p', 'o', '{digest}', '{doc}', 'superseded', 'u', now()),
                     ('terms-now', 'p', 'o', '{digest}', '{doc}', 'active', 'u', now());"
    ))
    .unwrap();
    for (id, terms, ago) in [
        ("j-b", Some("terms-now"), 30),
        ("j-a", Some("terms-now"), 30),
        ("j-c", Some("terms-now"), 10),
        ("j-z", Some("terms-old"), 60),
        ("j-none", None, 20),
    ] {
        c.execute(
            "INSERT INTO jobs (id, organization_id, project_id, plan_id, spec_id, program_id, purpose, source_assets,
                               requested_output, scheme, backend, profile, state, initiated_by, idempotency_key,
                               request_digest, terms_id, created_at)
             VALUES ($1, 'o', 'p', 'pl', 'y', 'x', 'p', '[]', 'out', 'exact', 'openfhe-exact', 'P', 'authorized',
                     'u', $1, 'd', $2, '2026-11-01 12:00:00+00'::timestamptz - make_interval(secs => $3))",
            &[&id, &terms, &(ago as f64)],
        )
        .unwrap();
    }
    drop(c);
    assert_eq!(db.migrate().unwrap(), 20);
    let mut c = db.conn().unwrap();
    let seq = |c: &mut postgres::Client, id: &str| -> Option<i64> {
        c.query_one("SELECT terms_seq FROM jobs WHERE id = $1", &[&id])
            .unwrap()
            .get(0)
    };
    let count = |c: &mut postgres::Client, id: &str| -> i64 {
        c.query_one("SELECT jobs_submitted FROM job_terms WHERE id = $1", &[&id])
            .unwrap()
            .get(0)
    };
    // In order of submission, ties by ID.
    assert_eq!(seq(&mut c, "j-a"), Some(1));
    assert_eq!(seq(&mut c, "j-b"), Some(2));
    assert_eq!(seq(&mut c, "j-c"), Some(3));
    assert_eq!(seq(&mut c, "j-z"), Some(1));
    assert_eq!(seq(&mut c, "j-none"), None);
    assert_eq!(count(&mut c, "terms-now"), 3);
    assert_eq!(count(&mut c, "terms-old"), 1);
    // The next job under the active terms is counted and numbered by the
    // database; the count never goes down, and numbers never change.
    c.execute(
        "INSERT INTO jobs (id, organization_id, project_id, plan_id, spec_id, program_id, purpose, source_assets,
                           requested_output, scheme, backend, profile, state, initiated_by, idempotency_key,
                           request_digest, terms_id)
         VALUES ('j-d', 'o', 'p', 'pl', 'y', 'x', 'p', '[]', 'out', 'exact', 'openfhe-exact', 'P', 'authorized',
                 'u', 'j-d', 'd', 'terms-now')",
        &[],
    )
    .unwrap();
    assert_eq!(seq(&mut c, "j-d"), Some(4));
    assert_eq!(count(&mut c, "terms-now"), 4);
    assert!(c
        .execute(
            "UPDATE job_terms SET jobs_submitted = 3 WHERE id = 'terms-now'",
            &[]
        )
        .is_err());
    assert!(c
        .execute("UPDATE jobs SET terms_seq = 9 WHERE id = 'j-a'", &[])
        .is_err());
    assert!(c
        .execute(
            "INSERT INTO jobs (id, organization_id, project_id, plan_id, spec_id, program_id, purpose, source_assets,
                               requested_output, scheme, backend, profile, state, initiated_by, idempotency_key,
                               request_digest, terms_id)
             VALUES ('j-e', 'o', 'p', 'pl', 'y', 'x', 'p', '[]', 'out', 'exact', 'openfhe-exact', 'P', 'authorized',
                     'u', 'j-e', 'd', 'terms-old')",
            &[],
        )
        .is_err());
}
