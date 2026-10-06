//! Cost-aware scheduling: evaluators advertise a machine profile, plans
//! carry a gate estimate, and the scheduler prefers the evaluator with the
//! lowest estimated completion time, but only among those the hard
//! constraints allow (backend, profile, health, freshness, capacity).
//! Also: schema version 2 applies to a version-1 database, and plans made
//! before estimates existed still load.

mod common;

use common::*;
use serde_json::{json, Value};

use encompute_control::db::Db;
use encompute_control::{estimated_ms, GATE_MS};

const EXACT_PROFILE: &str = "BINFHE_STD128_GINX_BITS_V1";
const CKKS_PROFILE: &str = "OPENFHE_CKKS_HE_STD128_V1";

fn fast() -> Value {
    json!({"cpu_model": "Test CPU 64", "logical_cores": 64, "memory_bytes": 1u64 << 38,
           "benchmark_profile": "openfhe-1.5.1/test-64", "max_parallel_gates": 64})
}

/// A plan of `program` and its gate estimate.
fn plan(w: &World, program: &str) -> (String, u64) {
    let p = w.t.ok(
        &w.b_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": w.project, "program": program})),
    );
    (
        p["id"].as_str().unwrap().into(),
        p["estimated_gates"].as_u64().unwrap(),
    )
}

/// Submits a job and returns its view.
fn submit(w: &World, plan: &str, key: &str) -> Value {
    let (s, v) = w.job(plan, &[], key);
    assert_eq!(s, 201, "{v}");
    w.t.ok(
        &w.b_dev,
        "GET",
        &format!("/v1/jobs/{}", v["id"].as_str().unwrap()),
        None,
    )
}

#[test]
fn estimate_formula() {
    // No profile: one core.
    assert_eq!(estimated_ms(0, 100, None, None), 100 * GATE_MS);
    // min(max_parallel_gates, logical_cores).
    assert_eq!(estimated_ms(0, 100, Some(4), Some(8)), 100 * GATE_MS / 4);
    assert_eq!(estimated_ms(0, 100, Some(16), Some(8)), 100 * GATE_MS / 8);
    assert_eq!(estimated_ms(0, 100, None, Some(10)), 100 * GATE_MS / 10);
    // Queued work counts; a job without an estimate is one unit.
    assert_eq!(estimated_ms(300, 100, Some(4), Some(4)), 400 * GATE_MS / 4);
    assert_eq!(estimated_ms(0, 0, None, None), GATE_MS);
    assert_eq!(estimated_ms(u64::MAX, u64::MAX, None, None), u64::MAX);
}

#[test]
fn prefers_the_fastest_least_loaded_compatible_evaluator() {
    let Some(w) = world() else { return };
    let t = &w.t;
    // evaluator-1 (from the world) has no machine profile: one core.
    evaluator_with(
        t,
        &w.platform,
        "evaluator-fast",
        &["openfhe-exact"],
        &[EXACT_PROFILE],
        20,
        json!({"logical_cores": 16, "max_parallel_gates": 8}),
    );
    let (exact, gates) = plan(&w, EXACT);
    assert!(gates > 0, "an exact plan estimates its bootstrapped gates");
    // Eight gates at a time: the fast evaluator is best until its queue
    // costs as much as the idle single-core one (7 jobs), then the tie goes
    // to the lower evaluator ID.
    for k in 1..=8u64 {
        let v = submit(&w, &exact, &format!("load-{k}"));
        assert_eq!(v["state"], "queued");
        assert_eq!(v["estimated_gates"], gates);
        if k < 8 {
            assert_eq!(v["evaluator"], "evaluator-fast", "job {k}");
            assert_eq!(v["estimated_ms"], k * gates * GATE_MS / 8);
            assert_eq!(v["evaluator_parallel_gates"], 8);
        } else {
            assert_eq!(v["evaluator"], "evaluator-1", "job {k}: tie, lowest ID");
            assert_eq!(v["estimated_ms"], gates * GATE_MS);
            assert_eq!(v["evaluator_parallel_gates"], Value::Null);
        }
    }
    // The chosen estimate is audited (integer milliseconds).
    let audit = t.ok(&w.b_auditor, "GET", "/v1/audit?limit=1000", None);
    let scheduled: Vec<&Value> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "job.scheduled")
        .collect();
    assert_eq!(scheduled.len(), 8, "{audit}");
    let int = |v: &Value| v.as_str().and_then(|s| s.parse::<u64>().ok());
    assert!(scheduled.iter().any(|e| {
        e["refs"]["evaluator"] == "evaluator-fast"
            && int(&e["refs"]["estimated_ms"]) == Some(gates * GATE_MS / 8)
            && int(&e["refs"]["estimated_gates"]) == Some(gates)
    }));
    // A CKKS plan has no gate estimate; it still schedules (one unit).
    let (approx, g) = plan(&w, APPROX);
    assert_eq!(g, 0);
    let v = submit(&w, &approx, "ckks-1");
    assert_eq!(v["evaluator"], "evaluator-1");
    assert_eq!(v["estimated_gates"], 0);
    assert_eq!(v["estimated_ms"], (1 + gates) * GATE_MS);
}

#[test]
fn hard_constraints_beat_cost() {
    let Some(w) = world() else { return };
    let t = &w.t;
    // Fast evaluators that must never get the exact job.
    evaluator_with(
        t,
        &w.platform,
        "fast-ckks-only",
        &["openfhe"],
        &[CKKS_PROFILE],
        50,
        fast(),
    );
    evaluator_with(
        t,
        &w.platform,
        "fast-other-profile",
        &["openfhe-exact"],
        &["OTHER_PROFILE"],
        50,
        fast(),
    );
    evaluator_with(
        t,
        &w.platform,
        "fast-draining",
        &["openfhe-exact"],
        &[EXACT_PROFILE],
        50,
        fast(),
    );
    let unhealthy = evaluator_with(
        t,
        &w.platform,
        "fast-unhealthy",
        &["openfhe-exact"],
        &[EXACT_PROFILE],
        50,
        fast(),
    );
    evaluator_with(
        t,
        &w.platform,
        "fast-silent",
        &["openfhe-exact"],
        &[EXACT_PROFILE],
        50,
        fast(),
    );
    evaluator_with(
        t,
        &w.platform,
        "fast-full",
        &["openfhe-exact"],
        &[EXACT_PROFILE],
        1,
        fast(),
    );
    t.ok(
        &w.platform,
        "POST",
        "/v1/evaluators/fast-draining/status",
        Some(json!({"status": "draining"})),
    );
    t.ok(
        &unhealthy.service,
        "POST",
        "/v1/evaluators/fast-unhealthy/status",
        Some(json!({"status": "unhealthy"})),
    );
    t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE evaluators SET last_heartbeat = now() - interval '10 minutes' WHERE id = 'fast-silent'",
            &[],
        )
        .unwrap();
    let (exact, gates) = plan(&w, EXACT);
    // The only fast, compatible, healthy one with room takes the first job...
    let first = submit(&w, &exact, "first");
    assert_eq!(first["evaluator"], "fast-full");
    // ...and is then full: the slow evaluator gets the next, though the
    // full one would still be faster.
    assert!(estimated_ms(gates, gates, Some(64), Some(64)) < gates * GATE_MS);
    let second = submit(&w, &exact, "second");
    assert_eq!(second["evaluator"], "evaluator-1");
    assert_eq!(second["estimated_ms"], gates * GATE_MS);
}

#[test]
fn registration_with_and_without_a_machine_profile() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let e = evaluator_with(
        t,
        &w.platform,
        "evaluator-profiled",
        &["openfhe-exact"],
        &[EXACT_PROFILE],
        2,
        fast(),
    );
    let list = t.ok(&w.platform, "GET", "/v1/evaluators", None);
    let find = |list: &Value, id: &str| {
        list.as_array()
            .unwrap()
            .iter()
            .find(|x| x["id"] == id)
            .cloned()
            .unwrap()
    };
    let p = find(&list, "evaluator-profiled");
    assert_eq!(p["cpu_model"], "Test CPU 64");
    assert_eq!(p["logical_cores"], 64);
    assert_eq!(p["memory_bytes"], 1u64 << 38);
    assert_eq!(p["benchmark_profile"], "openfhe-1.5.1/test-64");
    assert_eq!(p["max_parallel_gates"], 64);
    // The world's evaluator registered without one.
    let old = find(&list, "evaluator-1");
    for k in [
        "cpu_model",
        "logical_cores",
        "memory_bytes",
        "benchmark_profile",
        "max_parallel_gates",
    ] {
        assert_eq!(old[k], Value::Null, "{k}");
    }
    // Nonsense values are refused.
    let base = json!({"id": "evaluator-profiled", "url": "http://evaluator-profiled.internal:8750",
                      "receipt_key": e.receipt.identity().public_key_hex(),
                      "backends": ["openfhe-exact"], "profiles": [EXACT_PROFILE],
                      "openfhe_version": "1.5.1", "capacity": 2});
    for bad in [
        json!({"logical_cores": 0}),
        json!({"max_parallel_gates": -1}),
        json!({"max_parallel_gates": 1_000_000}),
        json!({"memory_bytes": 0}),
        json!({"cpu_model": ""}),
        json!({"benchmark_profile": "x".repeat(300)}),
    ] {
        let mut body = base.clone();
        body.as_object_mut()
            .unwrap()
            .extend(bad.as_object().unwrap().clone());
        let (s, v) = t.call(&e.service, "POST", "/v1/evaluators", Some(body));
        assert_eq!(s, 400, "{bad}: {v}");
    }
    // Re-registering without a profile clears it.
    t.ok(&e.service, "POST", "/v1/evaluators", Some(base));
    let p = find(
        &t.ok(&w.platform, "GET", "/v1/evaluators", None),
        "evaluator-profiled",
    );
    assert_eq!(p["logical_cores"], Value::Null);
    assert_eq!(p["max_parallel_gates"], Value::Null);
}

#[test]
fn plans_without_estimates_still_load_and_schedule() {
    let Some(w) = world() else { return };
    let (exact, _) = plan(&w, EXACT);
    // A plan document as schema version 1 wrote it.
    w.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE plans SET document = document - 'estimated_gates' WHERE id = $1",
            &[&exact],
        )
        .unwrap();
    let v = submit(&w, &exact, "old-plan");
    assert_eq!(v["state"], "queued");
    assert_eq!(v["evaluator"], "evaluator-1");
    assert_eq!(v["estimated_gates"], 0);
    assert_eq!(v["estimated_ms"], GATE_MS);
    let id = v["id"].as_str().unwrap();
    // The trust report loads the stored plan document too.
    let r = w.t.ok(&w.b_dev, "GET", &format!("/v1/trust/{id}"), None);
    assert_eq!(r["job"], id, "{r}");
}

#[test]
fn migration_2_applies_to_a_version_1_database() {
    // An old schema, never the template: migrations are what this tests.
    let Some(url) = unmigrated_database() else {
        return;
    };
    let db = Db::connect(&url).unwrap();
    assert_eq!(db.migrate_to(1).unwrap(), 1);
    assert_eq!(db.schema_version().unwrap(), 1);
    // Version-1 rows: an evaluator and a job, without the new columns.
    db.conn()
        .unwrap()
        .batch_execute(
            "INSERT INTO organizations (id, display_name, status, policy_namespace) VALUES ('o', 'o', 'active', 'o');
             INSERT INTO projects (id, organization_id, name, status) VALUES ('p', 'o', 'p', 'active');
             INSERT INTO plans (id, organization_id, project_id, program_id, spec_id, program, document, created_by)
                  VALUES ('pl', 'o', 'p', 'x', 'y', '', '{}', 'u');
             INSERT INTO service_accounts (id, kind, public_key, status) VALUES ('ev', 'evaluator', 'k', 'active');
             INSERT INTO evaluators (id, service_account, url, receipt_key, backends, profiles, openfhe_version, capacity, status)
                  VALUES ('ev', 'ev', 'http://ev', 'rk', '[]', '[]', '1.5.1', 1, 'ready');
             INSERT INTO jobs (id, organization_id, project_id, plan_id, spec_id, program_id, purpose, source_assets,
                               requested_output, scheme, backend, profile, state, initiated_by, idempotency_key, request_digest)
                  VALUES ('j', 'o', 'p', 'pl', 'y', 'x', 'p', '[]', 'out', 'exact', 'openfhe-exact', 'P', 'authorized', 'u', 'k', 'd');",
        )
        .unwrap();
    assert_eq!(db.migrate().unwrap(), 18);
    assert_eq!(db.schema_version().unwrap(), 18);
    assert_eq!(db.migrate().unwrap(), 18, "idempotent");
    let mut c = db.conn().unwrap();
    let e = c
        .query_one(
            "SELECT logical_cores, max_parallel_gates, cpu_model FROM evaluators WHERE id = 'ev'",
            &[],
        )
        .unwrap();
    assert_eq!(e.get::<_, Option<i32>>(0), None);
    assert_eq!(e.get::<_, Option<i32>>(1), None);
    assert_eq!(e.get::<_, Option<String>>(2), None);
    let j = c
        .query_one(
            "SELECT estimated_gates, estimated_ms FROM jobs WHERE id = 'j'",
            &[],
        )
        .unwrap();
    assert_eq!(j.get::<_, i64>(0), 0);
    assert_eq!(j.get::<_, Option<i64>>(1), None);
}
