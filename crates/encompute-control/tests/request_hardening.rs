//! Request handling hardening: authorization before work, identity tokens
//! with bounded lifetimes, nothing internal echoed to unauthenticated
//! callers, replay windows, ambiguous query strings, metrics access, and
//! what a job's viewers learn.

mod common;

use std::sync::Arc;

use common::*;
use encompute_control::api::{handle, Request};
use encompute_control::authn::{Authenticator, DEV_ISSUER};
use encompute_control::config::{Env, JwksSource, MetricsAccess, OidcIssuer};
use encompute_ir::Code;
use encompute_verification::service::{now, MAX_CLOCK_SKEW_SECS};
use encompute_verification::ServiceSigner;
use serde_json::{json, Value};

fn hs256(claims: Value) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap()
}

/// Review finding CP-A-8(a) (ENC-SF-2026-060): a caller outside the project gets "not
/// found" before its program is parsed or compiled (rc.3 compiled up to 4
/// MiB first, and answered with the parse error).
#[test]
fn planning_is_authorized_before_compiling() {
    let Some(w) = world() else { return };
    let (s, v) = w.t.call(
        &w.c_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": w.project, "program": "not a program"})),
    );
    assert_eq!((s, v["code"].as_str()), (404, Some("ENC2603")), "{v}");
    // A member still gets the parse error.
    let (s, _) = w.t.call(
        &w.b_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": w.project, "program": "not a program"})),
    );
    assert_eq!(s, 400);
}

/// Review finding CP-A-8(c) (ENC-SF-2026-060): identity tokens need an issue time in the
/// past, a not-before in the past, and a lifetime within the maximum
/// (rc.3 accepted a token valid for years, or not yet valid).
#[test]
fn identity_tokens_have_bounded_lifetimes() {
    let a = Authenticator::new(
        Env::Development,
        "control-plane",
        vec![],
        Some(zeroize::Zeroizing::new(SECRET.into())),
    );
    let t = now();
    let base = |extra: Value| {
        let mut c = json!({"iss": DEV_ISSUER, "sub": "a-dev", "aud": "encompute", "exp": t + 600});
        c.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        hs256(c)
    };
    a.verify_token(&base(json!({"iat": t}))).unwrap();
    let refused = |tok: String, what: &str| {
        let e = a.verify_token(&tok).unwrap_err();
        assert_eq!(e.code, Code::Unauthenticated, "{what}: {e}");
    };
    refused(base(json!({})), "no issue time");
    refused(base(json!({"iat": t + 3600})), "issued in the future");
    refused(base(json!({"iat": t, "nbf": t + 3600})), "not yet valid");
    refused(
        base(json!({"iat": t, "exp": t + 10 * 365 * 24 * 3600})),
        "ten-year token",
    );
    // The maximum is configurable.
    let short = Authenticator::new(
        Env::Development,
        "control-plane",
        vec![],
        Some(zeroize::Zeroizing::new(SECRET.into())),
    )
    .with_max_token_lifetime(300);
    assert!(short.verify_token(&base(json!({"iat": t}))).is_err());
}

/// Review finding CP-A-8(b) (ENC-SF-2026-060): an unauthenticated caller learns nothing of
/// the identity provider's configuration (rc.3 echoed the JWKS URL or file
/// path and the error), and an unknown key refetches at most once a minute.
#[test]
fn identity_provider_errors_are_not_echoed() {
    let dir = tmp_dir("jwks");
    let path = dir.join("secret-location-jwks.json");
    let a = Authenticator::new(
        Env::Development,
        "control-plane",
        vec![OidcIssuer {
            issuer: "https://login.example".into(),
            audience: "encompute".into(),
            jwks: JwksSource::File(path.clone()),
        }],
        None,
    );
    let tok = {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use p256::pkcs8::EncodePrivateKey;
        let k = p256::SecretKey::random(&mut rand_core::OsRng);
        let pem = k.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap();
        let mut h = Header::new(Algorithm::ES256);
        h.kid = Some("k1".into());
        encode(
            &h,
            &json!({"iss": "https://login.example", "sub": "x", "aud": "encompute",
                    "exp": now() + 600, "iat": now()}),
            &EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap()
    };
    let e = a.verify_token(&tok).unwrap_err();
    assert_eq!(e.code, Code::Unauthenticated);
    assert!(!e.message.contains("secret-location"), "{e}");
    assert!(!e.message.contains(dir.to_str().unwrap()), "{e}");
    // The file appears (without the key): within the minute, no refetch;
    // the answer is the same generic one.
    std::fs::write(&path, json!({"keys": []}).to_string()).unwrap();
    let e = a.verify_token(&tok).unwrap_err();
    assert!(!e.message.contains("secret-location"), "{e}");
}

/// Review finding CP-A-7 (ENC-SF-2026-059): a used nonce is kept past the end of the window
/// in which its request could be accepted (its own time plus the skew),
/// with a margin; on rc.3 retention ended exactly there for a request
/// dated at the edge of the skew.
#[test]
fn nonces_outlive_their_acceptance_window() {
    let Some(w) = world() else { return };
    let s = match &w.evaluator.service {
        As::Service(s) => s.clone(),
        _ => unreachable!(),
    };
    // A request dated as far ahead as the skew allows.
    let ts = now() + MAX_CLOCK_SKEW_SECS - 1;
    let h = signed_at(&s, "GET", "/v1/whoami", ts);
    let r = handle(
        &w.t.control,
        &Request {
            method: "GET".into(),
            url: "/v1/whoami".into(),
            headers: h,
            body: vec![],
        },
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let mut c = w.t.control.db.conn().unwrap();
    let expires: std::time::SystemTime = c
        .query_one(
            "SELECT expires_at FROM request_nonces WHERE sender = $1 ORDER BY expires_at DESC LIMIT 1",
            &[&s.id()],
        )
        .unwrap()
        .get(0);
    let expires = expires
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        expires >= ts + MAX_CLOCK_SKEW_SECS + 60,
        "kept until {expires}, acceptable until {}",
        ts + MAX_CLOCK_SKEW_SECS
    );
    // Pruning (by the same clock) keeps it.
    encompute_control::authn::prune_nonces(&mut *c).unwrap();
    let n: i64 = c
        .query_one(
            "SELECT count(*) FROM request_nonces WHERE sender = $1",
            &[&s.id()],
        )
        .unwrap()
        .get(0);
    assert!(n >= 1);
}

/// Signed request headers dated `ts` (the signing statement, as the
/// verification crate builds it).
fn signed_at(s: &Arc<ServiceSigner>, method: &str, path: &str, ts: u64) -> Vec<(String, String)> {
    use encompute_verification::service::{sha256_hex, SERVICE_REQUEST};
    #[derive(serde::Serialize)]
    struct St<'a> {
        method: &'a str,
        path: &'a str,
        sender: &'a str,
        recipient: &'a str,
        timestamp: u64,
        nonce: &'a str,
        bind: std::collections::BTreeMap<String, String>,
        body_sha256: String,
    }
    let mut h = s
        .sign_request(method, path, "control-plane", &Default::default(), b"")
        .unwrap();
    h.timestamp = ts;
    h.signature = s
        .sign(
            SERVICE_REQUEST,
            &St {
                method,
                path,
                sender: &h.sender,
                recipient: &h.recipient,
                timestamp: ts,
                nonce: &h.nonce,
                bind: Default::default(),
                body_sha256: sha256_hex(b""),
            },
        )
        .unwrap();
    h.to_pairs()
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
}

/// Review finding CP-A-8(g) (ENC-SF-2026-060): a query string naming a parameter twice is
/// refused (the signature covers it sorted, the parser kept the last).
#[test]
fn duplicate_query_parameters_are_refused() {
    let Some(w) = world() else { return };
    let (s, v) =
        w.t.call(&w.a_auditor, "GET", "/v1/audit?after=0&after=5", None);
    assert_eq!(s, 400, "{v}");
    let (s, _) =
        w.t.call(&w.a_auditor, "GET", "/v1/audit?after=0&limit=5", None);
    assert_eq!(s, 200);
    let s = match &w.evaluator.service {
        As::Service(s) => s.clone(),
        _ => unreachable!(),
    };
    let (st, _) =
        w.t.call(&As::Service(s), "GET", "/v1/jobs?project=a&project=b", None);
    assert_eq!(st, 400);
}

/// Review finding CP-A-8(f) (ENC-SF-2026-060): the evaluator's URL and receipt key, like the
/// grant, go only to the submitting organization, as api.md says (rc.3
/// gave them to the source assets' owners too).
#[test]
fn only_the_submitter_learns_the_evaluator() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    w.t.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{d}/approvals"),
        Some(json!({"project": w.project, "purpose": "medical-training"})),
    );
    let plan = w.plan(&exact_over(&d, "hospital-a", "dataset", "medical-training"));
    let (s, j) = w.job(&plan, &[&d], "ev-1");
    assert_eq!(s, 201, "{j}");
    let id = j["id"].as_str().unwrap();
    let mine = w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{id}"), None);
    assert!(mine["evaluator_url"].is_string(), "{mine}");
    assert!(mine["evaluator_receipt_key"].is_string(), "{mine}");
    let owner = w.t.ok(&w.a_owner, "GET", &format!("/v1/jobs/{id}"), None);
    assert!(owner["evaluator_url"].is_null(), "{owner}");
    assert!(owner["evaluator_receipt_key"].is_null(), "{owner}");
    assert!(owner["grant"].is_null(), "{owner}");
}

/// Review finding CP-A-8(h) (ENC-SF-2026-060): in production `/metrics` needs the metrics
/// token (or an explicit opt-in); rc.3 served it to anyone.
#[test]
fn production_metrics_need_the_metrics_token() {
    let Some(url) = fresh_database() else { return };
    let get = |c: &encompute_control::Control, auth: Option<&str>| {
        let mut headers = vec![];
        if let Some(a) = auth {
            headers.push(("Authorization".to_owned(), format!("Bearer {a}")));
        }
        handle(
            c,
            &Request {
                method: "GET".into(),
                url: "/metrics".into(),
                headers,
                body: vec![],
            },
        )
        .status
    };
    let db = encompute_control::db::Db::connect(&url).unwrap();
    db.migrate().unwrap();
    let mut c = encompute_control::Control::with_parts(
        Env::Production,
        "control-plane",
        db,
        Authenticator::new(Env::Production, "control-plane", vec![], None),
        ServiceSigner::from_seed("control-plane", &[9; 32]).unwrap(),
        Box::new(encompute_control::anchor::DirAnchor::new(tmp_dir("metrics")).unwrap()),
        None,
        5,
    )
    .unwrap_or_else(|e| panic!("the control plane failed to start: {e}"));
    assert_eq!(get(&c, None), 401, "production default: closed");
    c.metrics_access = MetricsAccess::Token(zeroize::Zeroizing::new("scrape-secret".into()));
    assert_eq!(get(&c, None), 401);
    assert_eq!(get(&c, Some("wrong")), 401);
    assert_eq!(get(&c, Some("scrape-secret")), 200);
    c.metrics_access = MetricsAccess::Public;
    assert_eq!(get(&c, None), 200);
    // Development's default stays public.
    let Some(t) = setup() else { return };
    assert_eq!(t.call(&As::Nobody, "GET", "/metrics", None).0, 200);
}
