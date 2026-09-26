//! Authentication, authorization and tenant isolation.
//!
//! Every API route is exercised four ways: unauthenticated (401), with the
//! wrong role inside the organization (403, where roles apply), from another
//! tenant (404: other tenants' resources do not even confirm existence), and
//! authorized (2xx). Then the cross-tenant attack suite, and forged, expired
//! and production-refused credentials.

mod common;

use std::sync::Arc;

use common::*;
use serde_json::{json, Value};

use encompute_control::authn::{Authenticator, DEV_ISSUER};
use encompute_control::config::{Env, JwksSource, OidcIssuer};
use encompute_ir::Code;
use encompute_verification::ServiceSigner;

struct Row {
    name: &'static str,
    method: &'static str,
    path: String,
    body: Option<Value>,
    ok: As,
    wrong_role: Option<As>,
    wrong_tenant: As,
    headers: Vec<(&'static str, String)>,
}

fn call(w: &World, who: &As, r: &Row) -> (u16, Value) {
    let h: Vec<(&str, &str)> = r.headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
    w.t.call_with(who, r.method, &r.path, r.body.clone(), &h)
}

#[test]
fn every_route_authenticates_authorizes_and_isolates() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let p = w.project.clone();
    let plan = w.plan(EXACT);
    let (s, job) = w.job(&plan, &[], "k-1");
    assert_eq!(s, 201, "{job}");
    let job = job["id"].as_str().unwrap().to_owned();
    let (_, job2) = w.job(&plan, &[], "k-2");
    let job2 = job2["id"].as_str().unwrap().to_owned();
    let second = evaluator(
        t,
        &w.platform,
        "evaluator-2",
        &["openfhe"],
        &["OPENFHE_CKKS_HE_STD128_V1"],
        1,
    );
    let spare = t.ok(
        &w.a_owner,
        "POST",
        "/v1/assets",
        Some(json!({"organization": "hospital-a", "kind": "dataset", "name": "spare", "digest": "c".repeat(64)})),
    );
    let spare = spare["id"].as_str().unwrap().to_owned();
    let d = w.dataset_a.clone();
    let reserve_body = |id: &str| Some(reserve(id, 1_000_000));
    let policy = t.ok(
        &w.b_sec,
        "POST",
        &format!("/v1/projects/{p}/policies"),
        Some(json!({"retention_days": 30})),
    );
    let policy = policy["id"].as_str().unwrap().to_owned();
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations",
        Some(json!({"id": "joiner", "display_name": "Joiner"})),
    );
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({"id": "secagg-9", "kind": "secagg",
                    "public_key": ServiceSigner::from_seed("secagg-9", &[12; 32]).unwrap().public_key_hex()})),
    );

    let rows = vec![
        Row {
            name: "create organization",
            method: "POST",
            path: "/v1/organizations".into(),
            body: Some(json!({"id": "new-org", "display_name": "New"})),
            ok: w.platform.clone(),
            wrong_role: None,
            wrong_tenant: w.a_admin.clone(),
            headers: vec![],
        },
        Row {
            name: "read organization",
            method: "GET",
            path: "/v1/organizations/hospital-a".into(),
            body: None,
            ok: w.a_dev.clone(),
            wrong_role: None,
            wrong_tenant: w.b_dev.clone(),
            headers: vec![],
        },
        Row {
            name: "add user",
            method: "POST",
            path: "/v1/organizations/hospital-a/users".into(),
            body: Some(json!({"issuer": DEV_ISSUER, "subject": "a-new", "roles": ["auditor"]})),
            ok: w.a_admin.clone(),
            wrong_role: Some(w.a_dev.clone()),
            wrong_tenant: w.b_admin.clone(),
            headers: vec![],
        },
        Row {
            name: "add service account",
            method: "POST",
            path: "/v1/organizations/hospital-a/service-accounts".into(),
            body: Some(json!({"id": "a-ci", "kind": "automation",
                                "public_key": ServiceSigner::from_seed("a-ci", &[7; 32]).unwrap().public_key_hex(),
                                "roles": ["ml_developer"]})),
            ok: w.a_admin.clone(),
            wrong_role: Some(w.a_dev.clone()),
            wrong_tenant: w.b_admin.clone(),
            headers: vec![],
        },
        Row {
            name: "create project",
            method: "POST",
            path: "/v1/projects".into(),
            body: Some(json!({"organization": "modelco", "name": "second"})),
            ok: w.b_dev.clone(),
            wrong_role: Some(w.b_auditor.clone()),
            wrong_tenant: w.a_dev.clone(),
            headers: vec![],
        },
        Row {
            name: "list projects",
            method: "GET",
            path: "/v1/projects".into(),
            body: None,
            ok: w.a_dev.clone(),
            wrong_role: None,
            wrong_tenant: w.c_dev.clone(),
            headers: vec![],
        },
        Row {
            name: "read project",
            method: "GET",
            path: format!("/v1/projects/{p}"),
            body: None,
            ok: w.a_dev.clone(),
            wrong_role: None,
            wrong_tenant: w.c_dev.clone(),
            headers: vec![],
        },
        Row {
            name: "add project member",
            method: "POST",
            path: format!("/v1/projects/{p}/members"),
            body: Some(json!({"organization": "joiner"})),
            ok: w.b_admin.clone(),
            wrong_role: Some(w.b_dev.clone()),
            wrong_tenant: w.c_admin.clone(),
            headers: vec![],
        },
        Row {
            name: "propose policy",
            method: "POST",
            path: format!("/v1/projects/{p}/policies"),
            body: Some(json!({"retention_days": 7})),
            ok: w.b_sec.clone(),
            wrong_role: Some(w.b_dev.clone()),
            wrong_tenant: w.c_admin.clone(),
            headers: vec![],
        },
        Row {
            name: "approve policy",
            method: "POST",
            path: format!("/v1/policies/{policy}/approve"),
            body: None,
            ok: w.b_sec2.clone(),
            wrong_role: Some(w.b_dev.clone()),
            wrong_tenant: w.c_admin.clone(),
            headers: vec![],
        },
        Row {
            name: "register asset",
            method: "POST",
            path: "/v1/assets".into(),
            body: Some(
                json!({"organization": "hospital-a", "kind": "dataset", "name": "d2", "digest": "d".repeat(64)}),
            ),
            ok: w.a_owner.clone(),
            wrong_role: Some(w.a_dev.clone()),
            wrong_tenant: w.b_owner.clone(),
            headers: vec![],
        },
        Row {
            name: "list assets",
            method: "GET",
            path: "/v1/assets".into(),
            body: None,
            ok: w.a_dev.clone(),
            wrong_role: None,
            wrong_tenant: w.c_dev.clone(),
            headers: vec![],
        },
        Row {
            name: "read asset",
            method: "GET",
            path: format!("/v1/assets/{d}"),
            body: None,
            ok: w.a_dev.clone(),
            wrong_role: None,
            wrong_tenant: w.b_dev.clone(),
            headers: vec![],
        },
        Row {
            name: "asset lineage",
            method: "GET",
            path: format!("/v1/assets/{d}/lineage"),
            body: None,
            ok: w.a_dev.clone(),
            wrong_role: None,
            wrong_tenant: w.b_dev.clone(),
            headers: vec![],
        },
        Row {
            name: "approve asset",
            method: "POST",
            path: format!("/v1/assets/{d}/approvals"),
            body: Some(json!({"project": p, "purpose": "medical-training"})),
            ok: w.a_owner.clone(),
            wrong_role: Some(w.a_dev.clone()),
            wrong_tenant: w.b_owner.clone(),
            headers: vec![],
        },
        Row {
            name: "revoke asset",
            method: "POST",
            path: format!("/v1/assets/{spare}/revoke"),
            body: None,
            ok: w.a_owner.clone(),
            wrong_role: Some(w.a_dev.clone()),
            wrong_tenant: w.b_owner.clone(),
            headers: vec![],
        },
        Row {
            name: "create plan",
            method: "POST",
            path: "/v1/plans".into(),
            body: Some(json!({"project": p, "program": EXACT})),
            ok: w.b_dev.clone(),
            wrong_role: Some(w.b_auditor.clone()),
            wrong_tenant: w.c_dev.clone(),
            headers: vec![],
        },
        Row {
            name: "submit job",
            method: "POST",
            path: "/v1/jobs".into(),
            body: Some(
                json!({"project": p, "plan": plan, "purpose": "medical-training", "source_assets": [], "requested_output": "out"}),
            ),
            ok: w.b_dev.clone(),
            wrong_role: Some(w.b_auditor.clone()),
            wrong_tenant: w.c_dev.clone(),
            headers: vec![("Idempotency-Key", "k-matrix".into())],
        },
        Row {
            name: "list jobs",
            method: "GET",
            path: "/v1/jobs".into(),
            body: None,
            ok: w.b_dev.clone(),
            wrong_role: None,
            wrong_tenant: w.c_dev.clone(),
            headers: vec![],
        },
        Row {
            name: "read job",
            method: "GET",
            path: format!("/v1/jobs/{job}"),
            body: None,
            ok: w.b_dev.clone(),
            wrong_role: None,
            wrong_tenant: w.c_dev.clone(),
            headers: vec![],
        },
        Row {
            name: "trust report",
            method: "GET",
            path: format!("/v1/trust/{job}"),
            body: None,
            ok: w.b_dev.clone(),
            wrong_role: None,
            wrong_tenant: w.c_dev.clone(),
            headers: vec![],
        },
        Row {
            name: "cancel job",
            method: "POST",
            path: format!("/v1/jobs/{job2}/cancel"),
            body: None,
            ok: w.b_dev.clone(),
            wrong_role: Some(w.b_auditor.clone()),
            wrong_tenant: w.c_dev.clone(),
            headers: vec![],
        },
        Row {
            name: "start job",
            method: "POST",
            path: format!("/v1/jobs/{job}/start"),
            body: None,
            ok: w.evaluator.service.clone(),
            wrong_role: Some(w.b_dev.clone()),
            wrong_tenant: second.service.clone(),
            headers: vec![],
        },
        Row {
            name: "complete job",
            method: "POST",
            path: format!("/v1/jobs/{job}/complete"),
            body: Some(
                json!({"receipt": {}, "request_commitment": "x", "output_commitment": "y", "key_id": "z"}),
            ),
            ok: w.b_dev.clone(),
            wrong_role: Some(w.b_auditor.clone()),
            wrong_tenant: w.c_dev.clone(),
            headers: vec![],
        },
        Row {
            name: "register evaluator",
            method: "POST",
            path: "/v1/evaluators".into(),
            body: Some(
                json!({"id": "evaluator-1", "url": "http://evaluator-1.internal:8750",
                                "receipt_key": w.evaluator.receipt.identity().public_key_hex(),
                                "backends": ["openfhe", "openfhe-exact"],
                                "profiles": ["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
                                "openfhe_version": "1.5.1", "capacity": 4}),
            ),
            ok: w.evaluator.service.clone(),
            wrong_role: Some(w.b_dev.clone()),
            wrong_tenant: second.service.clone(),
            headers: vec![],
        },
        Row {
            name: "list evaluators",
            method: "GET",
            path: "/v1/evaluators".into(),
            body: None,
            ok: w.platform.clone(),
            wrong_role: None,
            wrong_tenant: w.a_admin.clone(),
            headers: vec![],
        },
        Row {
            name: "evaluator status",
            method: "POST",
            path: "/v1/evaluators/evaluator-1/status".into(),
            body: Some(json!({"status": "ready"})),
            ok: w.evaluator.service.clone(),
            wrong_role: Some(w.b_dev.clone()),
            wrong_tenant: second.service.clone(),
            headers: vec![],
        },
        Row {
            name: "privacy view",
            method: "GET",
            path: format!("/v1/privacy/{d}"),
            body: None,
            ok: w.a_auditor.clone(),
            wrong_role: Some(w.a_dev.clone()),
            wrong_tenant: w.b_auditor.clone(),
            headers: vec![],
        },
        Row {
            name: "privacy export",
            method: "GET",
            path: format!("/v1/privacy/{d}/ledger"),
            body: None,
            ok: w.a_auditor.clone(),
            wrong_role: Some(w.a_dev.clone()),
            wrong_tenant: w.b_auditor.clone(),
            headers: vec![],
        },
        Row {
            name: "privacy spend",
            method: "POST",
            path: format!("/v1/privacy/{d}/events"),
            body: reserve_body("e-matrix"),
            ok: w.a_owner.clone(),
            wrong_role: Some(w.a_dev.clone()),
            wrong_tenant: w.b_owner.clone(),
            headers: vec![],
        },
        Row {
            name: "authorize privacy spender",
            method: "POST",
            path: format!("/v1/privacy/{d}/spenders"),
            body: Some(json!({"service": "secagg-9"})),
            ok: w.a_owner.clone(),
            wrong_role: Some(w.a_dev.clone()),
            wrong_tenant: w.b_owner.clone(),
            headers: vec![],
        },
        Row {
            name: "audit trail",
            method: "GET",
            path: "/v1/audit?organization=hospital-a".into(),
            body: None,
            ok: w.a_auditor.clone(),
            wrong_role: Some(w.a_dev.clone()),
            wrong_tenant: w.b_auditor.clone(),
            headers: vec![],
        },
        Row {
            name: "audit checkpoint",
            method: "POST",
            path: "/v1/audit/checkpoints".into(),
            body: None,
            ok: w.platform.clone(),
            wrong_role: None,
            wrong_tenant: w.a_admin.clone(),
            headers: vec![],
        },
    ];
    let mut report = vec![];
    for r in &rows {
        let (s, v) = call(&w, &As::Nobody, r);
        assert_eq!(s, 401, "{}: unauthenticated got {s} {v}", r.name);
        if let Some(who) = &r.wrong_role {
            let (s, v) = call(&w, who, r);
            assert_eq!(s, 403, "{}: wrong role got {s} {v}", r.name);
        }
        let (s, v) = call(&w, &r.wrong_tenant, r);
        if ["list projects", "list assets", "list jobs"].contains(&r.name) {
            // Collections are filtered: another tenant sees none of these.
            assert_eq!(s, 200, "{}: {s} {v}", r.name);
            for secret in [&p, &d, &job, &w.model_b] {
                assert!(
                    !v.to_string().contains(secret.as_str()),
                    "{}: {secret} leaked to another tenant: {v}",
                    r.name
                );
            }
            let (s, _) = call(&w, &r.ok, r);
            assert_eq!(s, 200);
            report.push(r.name);
            continue;
        }
        assert!(s == 404 || s == 403, "{}: wrong tenant got {s} {v}", r.name);
        if s == 403 {
            // Services acting outside their own identity are forbidden, not
            // hidden: they know their own ID.
            assert!(
                matches!(r.wrong_tenant, As::Service(_)),
                "{}: tenant data must be not found, got 403",
                r.name
            );
        }
        let (s, v) = call(&w, &r.ok, r);
        if r.name == "complete job" {
            // Authorized: it reaches receipt validation (an empty receipt is
            // malformed), not an authentication or authorization error.
            assert_eq!(s, 400, "{}: {s} {v}", r.name);
            assert!(v["message"].as_str().unwrap().starts_with("receipt"), "{v}");
        } else {
            assert!(
                (200..300).contains(&s),
                "{}: authorized got {s} {v}",
                r.name
            );
        }
        report.push(r.name);
    }
    assert_eq!(report.len(), rows.len());
    // Unknown routes are 404 even when authenticated; messages need a service.
    let (s, _) = t.call(&w.a_dev, "GET", "/v1/nothing", None);
    assert_eq!(s, 404);
    let (s, _) = t.call(&w.a_dev, "POST", "/v1/messages", Some(json!({})));
    assert_eq!(s, 403);
    let (s, _) = t.call(&As::Nobody, "POST", "/v1/messages", Some(json!({})));
    assert_eq!(s, 401);
}

#[test]
fn cross_tenant_attacks_fail() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let d = w.dataset_a.clone();
    let plan = w.plan(EXACT);
    // B's job, using only B's assets.
    let (s, bjob) = w.job(&plan, &[&w.model_b], "b-1");
    assert_eq!(s, 201, "{bjob}");
    let bjob = bjob["id"].as_str().unwrap().to_owned();
    let refused = |who: &As, m: &str, url: &str, body: Option<Value>, what: &str| {
        let (s, v) = t.call(who, m, url, body);
        assert!(s == 404 || s == 403, "{what}: {s} {v}");
        assert_ne!(v["code"], "ENC0000");
    };

    // Organization A (c: an outsider) reads B's project, assets, jobs.
    refused(
        &w.c_dev,
        "GET",
        &format!("/v1/projects/{}", w.project),
        None,
        "outsider reads project",
    );
    refused(
        &w.a_dev,
        "GET",
        &format!("/v1/assets/{}", w.model_b),
        None,
        "A reads B's unshared model",
    );
    // A requests B's wrapped key reference (the key_ref is asset metadata).
    let (s, v) = t.call(&w.a_dev, "GET", "/v1/assets", None);
    assert_eq!(s, 200);
    assert!(
        !v.to_string().contains("keybroker-modelco"),
        "B's key reference leaked: {v}"
    );
    // A reads B's privacy budget and audit events.
    refused(
        &w.b_auditor,
        "GET",
        &format!("/v1/privacy/{d}"),
        None,
        "B reads A's budget",
    );
    refused(
        &w.a_auditor,
        "GET",
        "/v1/audit?organization=modelco",
        None,
        "A reads B's audit",
    );
    // An auditor without an organization filter gets only its own.
    let own = t.ok(&w.a_auditor, "GET", "/v1/audit", None);
    assert!(own
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["organization"] == "hospital-a"));
    // A submits B's asset without B's approval.
    let (s, v) = t.call_with(
        &w.a_admin,
        "POST",
        "/v1/jobs",
        Some(
            json!({"project": w.project, "plan": plan, "purpose": "medical-training",
                    "source_assets": [w.model_b], "requested_output": "out"}),
        ),
        &[("Idempotency-Key", "a-1")],
    );
    assert!(s == 403 || s == 404, "{s} {v}");
    // B uses A's dataset without A's approval for this purpose.
    let (s, v) = w.job(&plan, &[&d], "b-2");
    assert_eq!(s, 404, "an unshared asset is not visible: {v}");
    t.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{d}/approvals"),
        Some(json!({"project": w.project, "purpose": "other-purpose"})),
    );
    let (s, v) = w.job(&plan, &[&d], "b-3");
    assert_eq!(s, 403, "approved for another purpose only: {v}");
    assert_eq!(v["code"], Code::Forbidden.as_str());
    // A inserts evidence into B's trust graph / completes B's job.
    refused(
        &w.a_admin,
        "POST",
        &format!("/v1/jobs/{bjob}/complete"),
        Some(
            json!({"receipt": {}, "request_commitment": "x", "output_commitment": "y", "key_id": "z"}),
        ),
        "A completes B's job",
    );
    // A reuses B's JobId: read, cancel, trust.
    refused(
        &w.a_dev,
        "GET",
        &format!("/v1/jobs/{bjob}"),
        None,
        "A reads B's job",
    );
    refused(
        &w.a_admin,
        "POST",
        &format!("/v1/jobs/{bjob}/cancel"),
        None,
        "A cancels B's job",
    );
    refused(
        &w.a_dev,
        "GET",
        &format!("/v1/trust/{bjob}"),
        None,
        "A reads B's trust report",
    );
    // A uses B's service account: without B's key the signature fails; with
    // its own key under B's name, too.
    let b_ci = Arc::new(ServiceSigner::from_seed("b-ci", &[9; 32]).unwrap());
    t.ok(&w.b_admin, "POST", "/v1/organizations/modelco/service-accounts",
         Some(json!({"id": "b-ci", "kind": "automation", "public_key": b_ci.public_key_hex(), "roles": ["ml_developer"]})));
    let forged = Arc::new(ServiceSigner::from_seed("b-ci", &[10; 32]).unwrap());
    let (s, v) = t.call(&As::Service(forged), "GET", "/v1/jobs", None);
    assert_eq!(s, 401, "{v}");
    assert_eq!(v["code"], Code::ServiceAuthentication.as_str());
    // B's genuine automation account sees only B.
    let jobs = t.ok(&As::Service(b_ci.clone()), "GET", "/v1/jobs", None);
    assert_eq!(jobs.as_array().unwrap().len(), 1);
    // A's admin cannot register a service account for B, or claim a platform kind.
    refused(
        &w.a_admin,
        "POST",
        "/v1/organizations/modelco/service-accounts",
        Some(json!({"id": "evil", "kind": "automation", "public_key": b_ci.public_key_hex()})),
        "A registers into B",
    );
    let (s, _) = t.call(&w.a_admin, "POST", "/v1/organizations/hospital-a/service-accounts",
        Some(json!({"id": "evil-eval", "kind": "evaluator", "public_key": ServiceSigner::from_seed("x", &[11; 32]).unwrap().public_key_hex()})));
    assert_eq!(s, 400, "tenants cannot register platform evaluators");
    // A disabled service account is refused.
    t.ok(
        &w.b_admin,
        "POST",
        "/v1/organizations/modelco/service-accounts/b-ci/disable",
        None,
    );
    let (s, _) = t.call(&As::Service(b_ci), "GET", "/v1/jobs", None);
    assert_eq!(s, 401);
    // Platform admins create organizations but cannot read tenant data.
    refused(
        &w.platform,
        "GET",
        &format!("/v1/assets/{d}"),
        None,
        "platform reads tenant asset",
    );
    refused(
        &w.platform,
        "GET",
        "/v1/audit?organization=hospital-a",
        None,
        "platform reads tenant audit",
    );
}

#[test]
fn credentials_are_checked() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let unauth = |who: As| {
        let (s, v) = t.call(&who, "GET", "/v1/whoami", None);
        assert_eq!(s, 401, "{v}");
    };
    unauth(As::Raw("garbage".into()));
    unauth(As::Raw(
        encompute_control::authn::dev_token("another-secret", "a-dev", 60).unwrap(),
    ));
    unauth(As::User("never-registered".into()));
    // Expired (beyond the 60 s leeway).
    let expired = {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        encode(
            &Header::new(Algorithm::HS256),
            &json!({"iss": DEV_ISSUER, "sub": "a-dev", "aud": "encompute", "exp": 1_000_000}),
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap()
    };
    unauth(As::Raw(expired));
    // A signed service request replayed.
    let s = Arc::new(
        ServiceSigner::from_seed("evaluator-1", &{
            let mut s = [0u8; 32];
            for (i, b) in "evaluator-1".bytes().enumerate() {
                s[i % 32] ^= b;
            }
            s[31] ^= 0x5a;
            s
        })
        .unwrap(),
    );
    let h = s
        .sign_request(
            "GET",
            "/v1/whoami",
            "control-plane",
            &Default::default(),
            b"",
        )
        .unwrap();
    let headers: Vec<(String, String)> = h
        .to_pairs()
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
    let req = || encompute_control::api::Request {
        method: "GET".into(),
        url: "/v1/whoami".into(),
        headers: headers.clone(),
        body: vec![],
    };
    assert_eq!(
        encompute_control::api::handle(&t.control, &req()).status,
        200
    );
    let again = encompute_control::api::handle(&t.control, &req());
    assert_eq!(again.status, 401, "replay accepted");
    assert!(String::from_utf8_lossy(&again.body).contains("replayed"));
}

/// A test identity provider (ES256), keys generated at run time.
struct Idp {
    key: p256::SecretKey,
    kid: &'static str,
}

impl Idp {
    fn new(kid: &'static str) -> Self {
        Self {
            key: p256::SecretKey::random(&mut rand_core::OsRng),
            kid,
        }
    }

    fn jwk(&self) -> Value {
        let mut j: Value = serde_json::from_str(&self.key.public_key().to_jwk_string()).unwrap();
        j["kid"] = json!(self.kid);
        j["alg"] = json!("ES256");
        j["use"] = json!("sig");
        j
    }

    fn token(&self, iss: &str, aud: &str, sub: &str, exp: u64) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use p256::pkcs8::EncodePrivateKey;
        let pem = self.key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap();
        let mut h = Header::new(Algorithm::ES256);
        h.kid = Some(self.kid.into());
        encode(
            &h,
            &json!({"iss": iss, "sub": sub, "aud": aud, "exp": exp}),
            &EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }
}

#[test]
fn oidc_tokens_and_production_refusals() {
    let idp = Idp::new("key-1");
    let forger = Idp::new("key-1");
    let issuer = "https://login.hospital-a.example";
    let jwks = json!({"keys": [idp.jwk()]}).to_string();
    let oidc = vec![OidcIssuer {
        issuer: issuer.into(),
        audience: "encompute".into(),
        jwks: JwksSource::Inline(jwks),
    }];
    let exp = encompute_verification::service::now() + 600;
    for env in [Env::Development, Env::Production] {
        let a = Authenticator::new(
            env,
            "control-plane",
            oidc.clone(),
            Some(zeroize::Zeroizing::new(SECRET.into())),
        );
        assert_eq!(
            a.verify_token(&idp.token(issuer, "encompute", "alice", exp))
                .unwrap()
                .1,
            "alice"
        );
        let refused = |tok: String| {
            assert_eq!(
                a.verify_token(&tok).unwrap_err().code,
                Code::Unauthenticated
            )
        };
        refused(forger.token(issuer, "encompute", "alice", exp));
        refused(idp.token(issuer, "other-app", "alice", exp));
        refused(idp.token("https://evil.example", "encompute", "alice", exp));
        refused(idp.token(issuer, "encompute", "alice", 1_000));
        // A development token: accepted only in development mode.
        let dev = encompute_control::authn::dev_token(SECRET, "alice", 600).unwrap();
        match env {
            Env::Development => assert_eq!(a.verify_token(&dev).unwrap().0, DEV_ISSUER),
            Env::Production => {
                let e = a.verify_token(&dev).unwrap_err();
                assert!(e.message.contains("production"), "{e}");
            }
        }
        // An identity provider cannot sign with a shared secret (algorithm
        // confusion): an HS256 token naming the issuer is refused.
        let hs = {
            use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
            let mut h = Header::new(Algorithm::HS256);
            h.kid = Some("key-1".into());
            encode(
                &h,
                &json!({"iss": issuer, "sub": "alice", "aud": "encompute", "exp": exp}),
                &EncodingKey::from_secret(idp.jwk()["x"].as_str().unwrap().as_bytes()),
            )
            .unwrap()
        };
        refused(hs);
    }
    // Registered users log in through the identity provider.
    let Some(url) = fresh_database() else { return };
    let env0 = Env0 {
        url,
        anchor_dir: tmp_dir("oidc"),
        seed: [3; 32],
        oidc,
        env: Env::Development,
    };
    let t = env0.start().unwrap();
    t.control
        .bootstrap(issuer, "alice", Some("alice@hospital-a.example"))
        .unwrap();
    let me = t.ok(
        &As::Raw(idp.token(issuer, "encompute", "alice", exp)),
        "GET",
        "/v1/whoami",
        None,
    );
    assert_eq!(me["organization"], "platform");
    let (s, _) = t.call(
        &As::Raw(idp.token(issuer, "encompute", "mallory", exp)),
        "GET",
        "/v1/whoami",
        None,
    );
    assert_eq!(
        s, 401,
        "an authenticated but unregistered identity has no access"
    );
}
