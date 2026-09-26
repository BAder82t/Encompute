//! Jobs: idempotent submission, the state machine, capability-aware
//! scheduling, the lifecycle with a real signed receipt and trust report,
//! duplicate and reordered messages, revocation, and restart recovery.

mod common;

use std::sync::Arc;

use common::*;
use serde_json::{json, Value};

use encompute_control::model::JobState;
use encompute_control::transport::{seal, Faults, InMemoryTransport, MessageTransport, Scope};
use encompute_evaluator::{compile_program, execution_spec, transcript_for, Ids};
use encompute_verification::{output_commitment, request_commitment, ExecutionReceipt};

const KEY_ID: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

fn state(w: &World, job: &str) -> String {
    w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None)["state"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The evaluator's signed receipt for `program` over these exact bytes.
fn receipt(e: &Evaluator, program: &str, request: &[u8], response: &[u8]) -> Value {
    let p = encompute_ir::parse(program).unwrap();
    let c = compile_program(&p).unwrap();
    let spec = execution_spec(&Ids::of(&p, &c), &c, c.target_backend());
    let th = transcript_for(&c, &spec).map(|t| t.id().hex());
    let r = ExecutionReceipt::new(
        &spec,
        th.as_deref(),
        KEY_ID,
        request,
        response,
        &e.receipt.identity(),
    )
    .unwrap()
    .sign(&e.receipt)
    .unwrap();
    serde_json::to_value(r).unwrap()
}

fn completed_message(e: &Evaluator, job: &str, receipt: &Value) -> Value {
    serde_json::to_value(
        seal(
            &e.signer,
            "job.completed",
            "control-plane",
            Scope {
                job: Some(job.into()),
                ..Scope::default()
            },
            &json!({"receipt": receipt, "evaluation_ms": 1500}),
            300,
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn state_machine_is_explicit() {
    use JobState::*;
    let legal = [
        (Created, Planning),
        (Planning, Planned),
        (Planned, WaitingForApproval),
        (Planned, Authorized),
        (WaitingForApproval, Authorized),
        (Authorized, Queued),
        (Queued, Running),
        (Running, Verifying),
        (Verifying, Succeeded),
    ];
    for from in JobState::ALL {
        for to in JobState::ALL {
            let want = legal.contains(&(from, to))
                || (matches!(to, Failed | Cancelled) && !from.is_terminal());
            assert_eq!(from.can_go_to(to), want, "{from:?} -> {to:?}");
        }
    }
}

#[test]
fn submission_is_idempotent_even_concurrently() {
    let Some(w) = world() else { return };
    let plan = w.plan(EXACT);
    let (s1, a) = w.job(&plan, &[], "same-key");
    let (s2, b) = w.job(&plan, &[], "same-key");
    assert_eq!((s1, s2), (201, 200));
    assert_eq!(a["id"], b["id"]);
    // The same key for another request is refused.
    let (s, v) = w.t.call_with(
        &w.b_dev, "POST", "/v1/jobs",
        Some(json!({"project": w.project, "plan": plan, "purpose": "other", "source_assets": [], "requested_output": "out"})),
        &[("Idempotency-Key", "same-key")],
    );
    assert_eq!(s, 409, "{v}");
    // Missing key.
    let (s, _) = w.t.call(&w.b_dev, "POST", "/v1/jobs", Some(json!({})));
    assert_eq!(s, 400);
    // Eight concurrent submissions of one request: one job.
    let w = Arc::new(w);
    let ids: Vec<String> = (0..8)
        .map(|_| {
            let (w, plan) = (w.clone(), plan.clone());
            std::thread::spawn(move || {
                let (s, v) = w.job(&plan, &[], "racing-key");
                assert!(s == 200 || s == 201, "{s} {v}");
                v["id"].as_str().unwrap().to_owned()
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    assert!(ids.iter().all(|i| i == &ids[0]), "{ids:?}");
    let n: i64 =
        w.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT count(*) FROM jobs WHERE idempotency_key = 'racing-key'",
                &[],
            )
            .unwrap()
            .get(0);
    assert_eq!(n, 1);
}

#[test]
fn jobs_run_only_on_compatible_ready_evaluators() {
    let Some(w) = world() else { return };
    let t = &w.t;
    // evaluator-1 (exact + CKKS, capacity 4) drains: nothing new goes there.
    t.ok(
        &w.platform,
        "POST",
        "/v1/evaluators/evaluator-1/status",
        Some(json!({"status": "draining"})),
    );
    let exact = w.plan(EXACT);
    let approx = w.plan(APPROX);
    let (_, j) = w.job(&exact, &[], "e-1");
    let j = j["id"].as_str().unwrap().to_owned();
    assert_eq!(state(&w, &j), "authorized", "no ready evaluator: it waits");
    // A CKKS-only evaluator cannot take an exact job.
    let ckks = evaluator(
        t,
        &w.platform,
        "evaluator-ckks",
        &["openfhe"],
        &["OPENFHE_CKKS_HE_STD128_V1"],
        1,
    );
    t.control.schedule_pending().unwrap();
    assert_eq!(state(&w, &j), "authorized");
    // ...but takes a CKKS job, up to its capacity (1).
    let (_, a1) = w.job(&approx, &[], "a-1");
    let (_, a2) = w.job(&approx, &[], "a-2");
    let (a1, a2) = (
        a1["id"].as_str().unwrap().to_owned(),
        a2["id"].as_str().unwrap().to_owned(),
    );
    assert_eq!(state(&w, &a1), "queued");
    assert_eq!(
        t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{a1}"), None)["evaluator"],
        ckks.id
    );
    assert_eq!(state(&w, &a2), "authorized", "at capacity");
    // An exact evaluator appears: the exact job is placed there.
    let exact_ev = evaluator(
        t,
        &w.platform,
        "evaluator-exact",
        &["openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1"],
        2,
    );
    t.control.schedule_pending().unwrap();
    let v = t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{j}"), None);
    assert_eq!(v["state"], "queued");
    assert_eq!(v["evaluator"], exact_ev.id);
    assert_eq!(v["grant"]["profile"], "BINFHE_STD128_GINX_BITS_V1");
    assert_eq!(v["evaluator_url"], "http://evaluator-exact.internal:8750");
    // Silent evaluators become unhealthy and get no work.
    t.control.db.conn().unwrap()
        .execute("UPDATE evaluators SET last_heartbeat = now() - interval '10 minutes' WHERE id = 'evaluator-exact'", &[])
        .unwrap();
    t.control.expire_evaluators().unwrap();
    let (_, j2) = w.job(&exact, &[], "e-2");
    assert_eq!(state(&w, j2["id"].as_str().unwrap()), "authorized");
    // Research backends are never registered for scheduling.
    let (s, v) = t.call(&exact_ev.service, "POST", "/v1/evaluators", Some(json!({
        "id": "evaluator-exact", "url": "http://x", "receipt_key": exact_ev.receipt.identity().public_key_hex(),
        "backends": ["tfhe-rs"], "profiles": ["x"], "openfhe_version": "1.5.1", "capacity": 1})));
    assert_eq!(s, 500, "{v}");
    assert_eq!(v["code"], "ENC2605");
}

#[test]
fn lifecycle_receipt_trust_and_duplicate_messages() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let plan = w.plan(EXACT);
    let (_, j) = w.job(&plan, &[], "life-1");
    let job = j["id"].as_str().unwrap().to_owned();
    let v = t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None);
    assert_eq!(v["state"], "queued");
    assert_eq!(v["grant"]["evaluator"], "evaluator-1");
    // The evaluator asks to start: once.
    t.ok(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    let (s, _) = t.call(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    assert_eq!(s, 409, "a started job never starts again");
    // The evaluator reports its receipt; the transport duplicates and
    // reorders the message: applied once.
    let (req, resp) = (
        b"request envelope bytes".to_vec(),
        b"response envelope bytes".to_vec(),
    );
    let r = receipt(&w.evaluator, EXACT, &req, &resp);
    let msg = completed_message(&w.evaluator, &job, &r);
    let flaky = InMemoryTransport::with_faults(Faults {
        duplicate: true,
        reorder: true,
        drop_every: 0,
    });
    flaky
        .send("control", &serde_json::from_value(msg.clone()).unwrap())
        .unwrap();
    let delivered = flaky.drain();
    assert_eq!(delivered.len(), 2);
    let mut outcomes = vec![];
    for (_, m) in delivered {
        outcomes.push(t.ok(
            &w.evaluator.service,
            "POST",
            "/v1/messages",
            Some(serde_json::to_value(m).unwrap()),
        ));
    }
    assert_eq!(outcomes[1]["duplicate"], true, "{outcomes:?}");
    assert_eq!(state(&w, &job), "verifying");
    // Another service cannot report for this evaluator.
    let other = evaluator(
        t,
        &w.platform,
        "evaluator-9",
        &["openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1"],
        1,
    );
    let (s, _) = t.call(&other.service, "POST", "/v1/messages", Some(msg.clone()));
    assert_eq!(s, 401, "the sender must be the calling service");
    // The client completes with its own commitments to the exact bytes.
    let done = t.ok(
        &w.b_dev,
        "POST",
        &format!("/v1/jobs/{job}/complete"),
        Some(json!({
        "receipt": r, "request_commitment": request_commitment(&req),
        "output_commitment": output_commitment(&resp), "key_id": KEY_ID})),
    );
    assert_eq!(done["state"], "succeeded");
    let tr = t.ok(&w.b_dev, "GET", &format!("/v1/trust/{job}"), None);
    assert_eq!(tr["verdict"], "SATISFIED", "{tr}");
    assert!(
        tr["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["status"] == "VERIFIED"),
        "{tr}"
    );
    // Finished jobs cannot be cancelled.
    let (s, _) = t.call(&w.b_dev, "POST", &format!("/v1/jobs/{job}/cancel"), None);
    assert_eq!(s, 409);
    // Trust is rebuilt from the evidence on every request, never read from
    // a stored flag: evidence edited in the database (a commitment) turns
    // the report NOT SATISFIED although the job's state still says
    // succeeded.
    t.control.db.conn().unwrap().execute(
        "UPDATE jobs SET evidence = jsonb_set(evidence, '{output_commitment}', '\"forged\"') WHERE id = $1",
        &[&job],
    ).unwrap();
    let tr = t.ok(&w.b_dev, "GET", &format!("/v1/trust/{job}"), None);
    assert_eq!(tr["state"], "succeeded");
    assert_eq!(tr["verdict"], "NOT SATISFIED", "{tr}");

    // A second job: the client's commitments do not match the receipt.
    let (_, j2) = w.job(&plan, &[], "life-2");
    let job2 = j2["id"].as_str().unwrap().to_owned();
    t.ok(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job2}/start"),
        None,
    );
    let r2 = receipt(&w.evaluator, EXACT, &req, &resp);
    let (s, v) = t.call(
        &w.b_dev,
        "POST",
        &format!("/v1/jobs/{job2}/complete"),
        Some(json!({
        "receipt": r2, "request_commitment": request_commitment(b"other bytes"),
        "output_commitment": output_commitment(&resp), "key_id": KEY_ID})),
    );
    assert_eq!(s, 400, "{v}");
    assert_eq!(v["code"], encompute_ir::Code::Receipt.as_str());
    assert_eq!(state(&w, &job2), "failed");
    let tr = t.ok(&w.b_dev, "GET", &format!("/v1/trust/{job2}"), None);
    assert_eq!(tr["verdict"], "NOT SATISFIED");
    // A receipt signed by an unregistered key is refused.
    let (_, j3) = w.job(&plan, &[], "life-3");
    let job3 = j3["id"].as_str().unwrap().to_owned();
    t.ok(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job3}/start"),
        None,
    );
    let rogue = receipt(&other, EXACT, &req, &resp);
    let (s, _) = t.call(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job3}/receipt"),
        Some(json!({"receipt": rogue})),
    );
    assert_eq!(s, 400);
    // Audit: the lifecycle is recorded, and the chain verifies.
    let events = t.ok(&w.b_auditor, "GET", "/v1/audit?limit=1000", None);
    let actions: Vec<&str> = events
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for a in [
        "job.created",
        "job.scheduled",
        "job.started",
        "job.executed",
        "job.succeeded",
        "trust.failed",
    ] {
        assert!(actions.contains(&a), "{a} missing from {actions:?}");
    }
    let mut c = t.control.db.conn().unwrap();
    encompute_control::audit::verify_chain(&mut *c).unwrap();
}

#[test]
fn revocation_stops_future_use() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let kb =
        encompute_verification::ServiceSigner::from_seed("keybroker-modelco", &[21; 32]).unwrap();
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({
        "id": "keybroker-modelco", "kind": "keybroker", "public_key": kb.public_key_hex(),
        "url": "http://keybroker-modelco.internal:8760"})),
    );
    let plan = w.plan(EXACT);
    // A job using B's model is queued (grant issued) but not started.
    let (_, j) = w.job(&plan, &[&w.model_b], "rv-1");
    let job = j["id"].as_str().unwrap().to_owned();
    assert_eq!(state(&w, &job), "queued");
    let out = t.ok(
        &w.b_owner,
        "POST",
        &format!("/v1/assets/{}/revoke", w.model_b),
        None,
    );
    assert_eq!(out["failed_jobs"], json!([job]));
    assert_eq!(state(&w, &job), "failed");
    // The evaluator holding the grant cannot start it.
    let (s, _) = t.call(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    assert_eq!(s, 409);
    // No new job may use it.
    let (s, v) = w.job(&plan, &[&w.model_b], "rv-2");
    assert_eq!(s, 409, "{v}");
    // The key broker is told (signed, addressed to it), at least once.
    let sent = t.transport.drain();
    assert_eq!(sent.len(), 1);
    let (url, m) = &sent[0];
    assert_eq!(url, "http://keybroker-modelco.internal:8760");
    assert_eq!(m.kind, "asset.revoked");
    assert_eq!(m.recipient, "keybroker-modelco");
    encompute_control::transport::open(
        m,
        &t.control.signer.public_key_hex(),
        "keybroker-modelco",
        m.created_at,
    )
    .unwrap();
    // Revoking twice is harmless; lineage shows the status.
    let again = t.ok(
        &w.b_owner,
        "POST",
        &format!("/v1/assets/{}/revoke", w.model_b),
        None,
    );
    assert_eq!(again["already"], true);
    let lin = t.ok(
        &w.b_owner,
        "GET",
        &format!("/v1/assets/{}/lineage", w.model_b),
        None,
    );
    assert_eq!(lin["status"], "revoked");
}

#[test]
fn restart_preserves_jobs_and_never_replays() {
    let Some(w) = world() else { return };
    let plan = w.plan(EXACT);
    let (_, j) = w.job(&plan, &[], "rs-1");
    let running = j["id"].as_str().unwrap().to_owned();
    w.t.ok(
        &w.evaluator.service,
        "POST",
        &format!("/v1/jobs/{running}/start"),
        None,
    );
    let (_, j) = w.job(&plan, &[], "rs-2");
    let queued = j["id"].as_str().unwrap().to_owned();
    let World {
        t,
        b_dev,
        evaluator: ev,
        ..
    } = w;
    let t = t.restart().unwrap();
    let get = |id: &str| {
        t.ok(&b_dev, "GET", &format!("/v1/jobs/{id}"), None)["state"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(get(&running), "running");
    assert_eq!(get(&queued), "queued");
    // The evaluator was lost and the grants expired: the running job fails
    // (it is never replayed); the queued one, never started, fails too and
    // is resubmitted by its owner.
    t.control
        .db
        .conn()
        .unwrap()
        .batch_execute(
            "UPDATE evaluators SET last_heartbeat = now() - interval '10 minutes';
         UPDATE jobs SET job_grant = jsonb_set(job_grant, '{expires_at}', '1')",
        )
        .unwrap();
    t.control.expire_evaluators().unwrap();
    assert_eq!(get(&running), "failed");
    assert_eq!(get(&queued), "failed");
    let v = t.ok(&b_dev, "GET", &format!("/v1/jobs/{running}"), None);
    assert!(v["error"].as_str().unwrap().contains("not replayed"), "{v}");
    let _ = ev;
}
