//! Network attacks on the control plane, over real HTTP on loopback: the
//! bounded server in front of the API, then authentication, tenancy,
//! signed-request replay and freshness, duplicate and expired messages,
//! signatures, oversized and slow requests, bad artifact references, and
//! an evaluator (with its control link) refusing jobs it was not granted.
//!
//! `isolation.rs` already covers every route's authorization matrix
//! in-process; here each attack crosses a real socket and asserts the
//! specific refusal (status and ENC code).

mod common;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use serde_json::{json, Value};

use encompute_control::authn::DEV_ISSUER;
use encompute_control::config::{Env, JwksSource, OidcIssuer};
use encompute_verification::http::Limits;
use encompute_verification::service::{now, seal, Scope, SERVICE_MESSAGE, SERVICE_REQUEST};
use encompute_verification::{MessageEnvelope, ServiceSigner};

const UNAUTHENTICATED: &str = "ENC2601";
const NOT_FOUND: &str = "ENC2603";
const SERVICE_AUTH: &str = "ENC2607";
const BAD_INPUT: &str = "ENC1102";

fn refused(r: (u16, Value), status: u16, code: &str, what: &str) -> Value {
    assert_eq!(r.0, status, "{what}: {}", r.1);
    assert_eq!(r.1["code"], code, "{what}: {}", r.1);
    r.1
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
            &json!({"iss": iss, "sub": sub, "aud": aud, "exp": exp,
                     "iat": encompute_verification::service::now()}),
            &EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }
}

fn bearer(t: &str) -> Vec<(String, String)> {
    vec![("Authorization".into(), format!("Bearer {t}"))]
}

#[test]
fn invalid_authentication_is_refused_over_the_wire() {
    let Some(url) = fresh_database() else { return };
    let idp = Idp::new("key-1");
    let forger = Idp::new("key-1");
    let issuer = "https://login.hospital-a.example";
    let env0 = Env0 {
        url,
        anchor_dir: tmp_dir("net-oidc"),
        seed: [5; 32],
        oidc: vec![OidcIssuer {
            issuer: issuer.into(),
            audience: "encompute".into(),
            jwks: JwksSource::Inline(json!({"keys": [idp.jwk()]}).to_string()),
        }],
        env: Env::Development,
    };
    let t = env0.start().unwrap();
    t.control.bootstrap(issuer, "alice", None).unwrap();
    let c = Client::new(live(&t.control, Limits::default()));
    let exp = now() + 600;
    let whoami = |h: Vec<(String, String)>| c.raw("GET", "/v1/whoami", &h, b"");

    // The genuine token works.
    let (s, v) = whoami(bearer(&idp.token(issuer, "encompute", "alice", exp)));
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["organization"], "platform");

    let cases: Vec<(&str, Vec<(String, String)>)> = vec![
        ("missing credentials", vec![]),
        ("garbage bearer", bearer("garbage")),
        ("three garbage segments", bearer("a.b.c")),
        (
            "not a bearer token",
            vec![("Authorization".into(), "Basic YWxpY2U6cGFzcw==".into())],
        ),
        (
            "expired OIDC token",
            bearer(&idp.token(issuer, "encompute", "alice", now() - 3600)),
        ),
        (
            "wrong issuer",
            bearer(&idp.token("https://evil.example", "encompute", "alice", exp)),
        ),
        (
            "forged signing key under the real kid",
            bearer(&forger.token(issuer, "encompute", "alice", exp)),
        ),
        (
            "wrong audience",
            bearer(&idp.token(issuer, "other-app", "alice", exp)),
        ),
        (
            "unregistered identity",
            bearer(&idp.token(issuer, "encompute", "mallory", exp)),
        ),
        (
            "development token signed with another secret",
            bearer(&encompute_control::authn::dev_token("not-the-secret", "alice", 600).unwrap()),
        ),
        ("oversized token", bearer(&"A".repeat(20 << 10))),
    ];
    for (what, h) in cases {
        refused(whoami(h), 401, UNAUTHENTICATED, what);
    }
    // alg=none: an unsigned token naming the trusted issuer.
    let none = {
        use base64::Engine;
        let e = |v: Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string().as_bytes())
        };
        format!(
            "{}.{}.",
            e(json!({"alg": "none", "typ": "JWT", "kid": "key-1"})),
            e(json!({"iss": issuer, "sub": "alice", "aud": "encompute", "exp": exp}))
        )
    };
    refused(whoami(bearer(&none)), 401, UNAUTHENTICATED, "alg none");
    // A development token in the issuer's name (algorithm confusion).
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
    refused(whoami(bearer(&hs)), 401, UNAUTHENTICATED, "HS256 confusion");
    // Health endpoints need nothing; everything under /v1 needs a caller.
    assert_eq!(c.raw("GET", "/live", &[], b"").0, 200);
    refused(
        c.raw("GET", "/v1/projects", &[], b""),
        401,
        UNAUTHENTICATED,
        "no credentials on a data route",
    );
}

#[test]
fn cross_tenant_access_is_refused_over_the_wire() {
    let Some(w) = world() else { return };
    let c = Client::new(live(&w.t.control, Limits::default()));
    let plan = w.plan(EXACT);
    let (s, bjob) = w.job(&plan, &[&w.model_b], "net-b-1");
    assert_eq!(s, 201, "{bjob}");
    let bjob = bjob["id"].as_str().unwrap().to_owned();
    let d = &w.dataset_a;
    let hidden = [
        (&w.a_dev, "GET", format!("/v1/assets/{}", w.model_b)),
        (&w.c_dev, "GET", format!("/v1/projects/{}", w.project)),
        (&w.b_auditor, "GET", format!("/v1/privacy/{d}")),
        (&w.b_auditor, "GET", format!("/v1/privacy/{d}/ledger")),
        (&w.a_dev, "GET", format!("/v1/jobs/{bjob}")),
        (&w.a_dev, "GET", format!("/v1/trust/{bjob}")),
        (&w.a_admin, "POST", format!("/v1/jobs/{bjob}/cancel")),
        (&w.b_owner, "POST", format!("/v1/assets/{d}/revoke")),
        (&w.platform, "GET", format!("/v1/assets/{d}")),
    ];
    for (who, m, url) in hidden {
        refused(c.call(who, m, &url, None), 404, NOT_FOUND, &url);
    }
    // B spends A's privacy budget: not even told it exists.
    refused(
        c.call(
            &w.b_owner,
            "POST",
            &format!("/v1/privacy/{d}/events"),
            Some(reserve("net-x", 1_000_000)),
        ),
        404,
        NOT_FOUND,
        "B spends A's budget",
    );
    // A's auditor asks for B's audit trail.
    refused(
        c.call(&w.a_auditor, "GET", "/v1/audit?organization=modelco", None),
        404,
        NOT_FOUND,
        "A reads B's audit",
    );
    // A service key under B's account name.
    let forged = Arc::new(ServiceSigner::from_seed("evaluator-1", &[77; 32]).unwrap());
    refused(
        c.call(&As::Service(forged), "GET", "/v1/jobs", None),
        401,
        SERVICE_AUTH,
        "forged service key",
    );
    // Nothing of B leaked into A's listings.
    let v = c.ok(&w.a_dev, "GET", "/v1/jobs", None);
    assert!(!v.to_string().contains(&bjob), "{v}");
}

/// The request statement a service signs (field for field).
#[derive(serde::Serialize)]
struct Statement<'a> {
    method: &'a str,
    path: &'a str,
    sender: &'a str,
    recipient: &'a str,
    timestamp: u64,
    nonce: &'a str,
    bind: &'a BTreeMap<String, String>,
    body_sha256: String,
}

/// A validly signed request with a chosen timestamp and nonce.
fn signed(
    s: &ServiceSigner,
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: u64,
    nonce: &str,
) -> Vec<(String, String)> {
    let mut h = s
        .sign_request(method, path, "control-plane", &Default::default(), body)
        .unwrap();
    h.timestamp = timestamp;
    h.nonce = nonce.into();
    h.signature = s
        .sign(
            SERVICE_REQUEST,
            &Statement {
                method,
                path,
                sender: &h.sender,
                recipient: &h.recipient,
                timestamp,
                nonce,
                bind: &h.bind,
                body_sha256: encompute_verification::service::sha256_hex(body),
            },
        )
        .unwrap();
    h.to_pairs()
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
}

fn set(h: &mut [(String, String)], name: &str, value: &str) {
    for (k, v) in h.iter_mut() {
        if k == name {
            *v = value.into();
        }
    }
}

fn nonce(i: u32) -> String {
    format!("{i:032x}")
}

#[test]
fn signed_requests_are_fresh_single_use_and_bound() {
    let Some(t) = setup() else { return };
    t.control
        .bootstrap(DEV_ISSUER, "platform-admin", None)
        .unwrap();
    let platform = As::User("platform-admin".into());
    let ev = evaluator(
        &t,
        &platform,
        "evaluator-1",
        &["openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1"],
        1,
    );
    let s = &ev.signer;
    let c = Client::new(live(&t.control, Limits::default()));
    let get = |h: &[(String, String)]| c.raw("GET", "/v1/whoami", h, b"");

    // The helper signs exactly what the server verifies.
    let fresh = signed(s, "GET", "/v1/whoami", b"", now(), &nonce(1));
    assert_eq!(get(&fresh).0, 200);
    // Replayed: the nonce is spent (and stays spent across a restart).
    let v = refused(get(&fresh), 401, SERVICE_AUTH, "replay");
    assert!(v["message"].as_str().unwrap().contains("replayed"), "{v}");

    // Expired or from the future (beyond ±300 s); inside the window is fine.
    for (i, ts) in [(2, now() - 301), (3, now() + 301), (4, now() - 3600)] {
        let v = refused(
            get(&signed(s, "GET", "/v1/whoami", b"", ts, &nonce(i))),
            401,
            SERVICE_AUTH,
            "stale timestamp",
        );
        assert!(v["message"].as_str().unwrap().contains("expired"), "{v}");
    }
    assert_eq!(
        get(&signed(s, "GET", "/v1/whoami", b"", now() - 290, &nonce(5))).0,
        200
    );

    // Wrong signatures.
    let base = || signed(s, "GET", "/v1/whoami", b"", now(), &nonce(rand_u32()));
    let mut h = base();
    let sig = h
        .iter()
        .find(|(k, _)| k == "Encompute-Signature")
        .unwrap()
        .1
        .clone();
    let flipped = format!(
        "{}{}",
        if sig.starts_with('0') { "1" } else { "0" },
        &sig[1..]
    );
    set(&mut h, "Encompute-Signature", &flipped);
    refused(get(&h), 401, SERVICE_AUTH, "flipped signature");
    let mut h = base();
    set(&mut h, "Encompute-Signature", "zz");
    refused(get(&h), 401, SERVICE_AUTH, "malformed signature");
    let other = ServiceSigner::from_seed("evaluator-1", &[99; 32]).unwrap();
    refused(
        get(&signed(&other, "GET", "/v1/whoami", b"", now(), &nonce(6))),
        401,
        SERVICE_AUTH,
        "signed by another key",
    );
    let mut h = base();
    set(&mut h, "Encompute-Timestamp", &(now() - 1).to_string());
    refused(get(&h), 401, SERVICE_AUTH, "timestamp edited after signing");
    let mut h = base();
    set(&mut h, "Encompute-Nonce", "not-hex");
    refused(get(&h), 401, SERVICE_AUTH, "malformed nonce");
    let mut h = base();
    h.retain(|(k, _)| k != "Encompute-Sender");
    refused(get(&h), 401, SERVICE_AUTH, "missing sender");
    let mut h = base();
    set(&mut h, "Encompute-Sender", "evaluator-404");
    refused(get(&h), 401, SERVICE_AUTH, "unknown sender");
    // Bound to method, path, body and recipient.
    let h = signed(s, "GET", "/v1/jobs", b"", now(), &nonce(7));
    refused(get(&h), 401, SERVICE_AUTH, "signed for another path");
    let h = signed(s, "POST", "/v1/whoami", b"", now(), &nonce(8));
    refused(get(&h), 401, SERVICE_AUTH, "signed for another method");
    let body = br#"{"status":"ready"}"#;
    let h = signed(
        s,
        "POST",
        "/v1/evaluators/evaluator-1/status",
        body,
        now(),
        &nonce(9),
    );
    refused(
        c.raw(
            "POST",
            "/v1/evaluators/evaluator-1/status",
            &h,
            br#"{"status":"draining"}"#,
        ),
        401,
        SERVICE_AUTH,
        "body swapped after signing",
    );
    let mut h = s
        .sign_request("GET", "/v1/whoami", "keybroker-a", &Default::default(), b"")
        .unwrap()
        .to_pairs()
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect::<Vec<_>>();
    refused(get(&h), 401, SERVICE_AUTH, "addressed to another service");
    set(&mut h, "Encompute-Recipient", "control-plane");
    refused(get(&h), 401, SERVICE_AUTH, "recipient edited after signing");

    // A restart does not forget spent nonces.
    let t = t.restart().unwrap();
    let c = Client::new(live(&t.control, Limits::default()));
    let v = refused(
        c.raw("GET", "/v1/whoami", &fresh, b""),
        401,
        SERVICE_AUTH,
        "replay after restart",
    );
    assert!(v["message"].as_str().unwrap().contains("replayed"), "{v}");
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).unwrap();
    u32::from_le_bytes(b) | 0x1000_0000
}

/// A SecAgg service the owner of `asset` authorized to spend its budget.
fn secagg_spender(w: &World, asset: &str) -> Arc<ServiceSigner> {
    let s = Arc::new(ServiceSigner::from_seed("secagg-1", &[31; 32]).unwrap());
    w.t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({"id": "secagg-1", "kind": "secagg", "public_key": s.public_key_hex()})),
    );
    w.t.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/privacy/{asset}/spenders"),
        Some(json!({"service": "secagg-1"})),
    );
    s
}

fn keybroker(w: &World) -> Arc<ServiceSigner> {
    let kb = Arc::new(ServiceSigner::from_seed("keybroker-modelco", &[21; 32]).unwrap());
    w.t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({"id": "keybroker-modelco", "kind": "keybroker",
                    "public_key": kb.public_key_hex(), "url": "http://kb.internal:8760"})),
    );
    kb
}

/// Re-signs a message after its fields were edited (a validly signed
/// message with chosen times).
fn resign(s: &ServiceSigner, mut m: MessageEnvelope) -> MessageEnvelope {
    m.signature = s.sign(SERVICE_MESSAGE, &m.statement()).unwrap();
    m
}

#[test]
fn duplicate_messages_apply_once_even_concurrently() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    let spender = secagg_spender(&w, &d);
    let kb = keybroker(&w);
    let c = Arc::new(Client::new(live(&w.t.control, Limits::default())));
    let privacy = seal(
        &spender,
        "privacy.event",
        "control-plane",
        Scope::default(),
        &json!({"asset": d, "event": reserve("round-1", 1_000_000)}),
        300,
    )
    .unwrap();
    let release = seal(
        &kb,
        "key.release",
        "control-plane",
        Scope::default(),
        &json!({"asset": "model-7", "allowed": true}),
        300,
    )
    .unwrap();
    // Each message delivered 8 times at once, then 4 more times in order;
    // every delivery is a distinct, validly signed request.
    for (who, m) in [(&spender, &privacy), (&kb, &release)] {
        let body = serde_json::to_value(m).unwrap();
        let outcomes: Vec<Value> = (0..8)
            .map(|_| {
                let (c, who, body) = (c.clone(), As::Service((*who).clone()), body.clone());
                std::thread::spawn(move || c.ok(&who, "POST", "/v1/messages", Some(body)))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .chain((0..4).map(|_| {
                c.ok(
                    &As::Service((*who).clone()),
                    "POST",
                    "/v1/messages",
                    Some(body.clone()),
                )
            }))
            .collect();
        let dups = outcomes.iter().filter(|o| o["duplicate"] == true).count();
        assert_eq!(dups, 11, "{}: {outcomes:?}", m.kind);
    }
    // One ledger entry, one audit record of the release.
    let view =
        w.t.ok(&w.a_auditor, "GET", &format!("/v1/privacy/{d}"), None);
    assert_eq!(view["entries"], 1, "{view}");
    let mut conn = w.t.control.db.conn().unwrap();
    let n: i64 = conn
        .query_one(
            "SELECT count(*) FROM audit_events WHERE action = 'key.release.allowed'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(n, 1, "a duplicated key release report is recorded once");
    encompute_control::audit::verify_chain(&mut *conn).unwrap();
}

#[test]
fn expired_forged_and_misaddressed_messages_are_refused() {
    let Some(w) = world() else { return };
    let d = w.dataset_a.clone();
    let spender = secagg_spender(&w, &d);
    let c = Client::new(live(&w.t.control, Limits::default()));
    let who = As::Service(spender.clone());
    let msg = |event: &str| {
        seal(
            &spender,
            "privacy.event",
            "control-plane",
            Scope::default(),
            &json!({"asset": d, "event": reserve(event, 1_000_000)}),
            300,
        )
        .unwrap()
    };
    let post = |m: &MessageEnvelope| {
        c.call(
            &who,
            "POST",
            "/v1/messages",
            Some(serde_json::to_value(m).unwrap()),
        )
    };
    let t0 = now();
    let mut m = msg("e-expired");
    m.created_at = t0 - 7200;
    m.expires_at = t0 - 3600;
    let v = refused(post(&resign(&spender, m)), 401, SERVICE_AUTH, "expired");
    assert!(v["message"].as_str().unwrap().contains("expired"), "{v}");
    let mut m = msg("e-future");
    m.created_at = t0 + 3600;
    m.expires_at = t0 + 7200;
    let v = refused(post(&resign(&spender, m)), 401, SERVICE_AUTH, "future");
    assert!(v["message"].as_str().unwrap().contains("future"), "{v}");
    // Edited after signing: the payload, or a bound field.
    let mut m = msg("e-payload");
    m.payload["event"] = reserve("e-other", 1);
    refused(post(&m), 401, SERVICE_AUTH, "payload edited");
    let mut m = msg("e-expiry");
    m.expires_at += 3600;
    refused(post(&m), 401, SERVICE_AUTH, "expiry edited");
    let mut m = msg("e-sig");
    m.signature = "00".repeat(64);
    refused(post(&m), 401, SERVICE_AUTH, "forged signature");
    // Addressed elsewhere, or claiming another sender.
    let mut m = msg("e-addr");
    m.recipient = "keybroker-a".into();
    refused(
        post(&resign(&spender, m)),
        401,
        SERVICE_AUTH,
        "misaddressed",
    );
    let mut m = msg("e-sender");
    m.sender = "evaluator-1".into();
    refused(
        post(&resign(&spender, m)),
        401,
        SERVICE_AUTH,
        "sender is not the caller",
    );
    // A user cannot post messages.
    refused(
        c.call(
            &w.a_owner,
            "POST",
            "/v1/messages",
            Some(serde_json::to_value(msg("e-user")).unwrap()),
        ),
        403,
        "ENC2602",
        "user posts a message",
    );
    // Nothing was spent.
    let view =
        w.t.ok(&w.a_auditor, "GET", &format!("/v1/privacy/{d}"), None);
    assert_eq!(view["entries"], 0, "{view}");
}

fn legit_ok(c: &Client, who: &As) -> Duration {
    let t = Instant::now();
    c.ok(who, "GET", "/v1/whoami", None);
    t.elapsed()
}

#[test]
fn oversized_and_malformed_requests_are_refused_before_the_api() {
    let Some(w) = world() else { return };
    let addr = live(
        &w.t.control,
        Limits {
            threads: 2,
            ..Limits::default()
        },
    );
    let c = Client::new(addr);
    let tok = token("a-dev");
    // A body over the limit (8 MiB): 413, before authentication.
    let big = vec![b'x'; encompute_control::api::MAX_BODY + 1];
    refused(
        c.raw("POST", "/v1/projects", &bearer(&tok), &big),
        413,
        BAD_INPUT,
        "oversized body",
    );
    // A huge Content-Length with a small body: refused at once, and the
    // connection thread is released (twice as many as there are threads).
    for _ in 0..4 {
        let t = Instant::now();
        let r = raw_exchange(
            addr,
            format!(
                "POST /v1/projects HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {tok}\r\nContent-Length: 1000000000000\r\n\r\n{{}}"
            )
            .as_bytes(),
        );
        assert_eq!(status_of(&r), 413, "{r}");
        assert_eq!(body_of(&r)["code"], BAD_INPUT);
        assert!(t.elapsed() < Duration::from_secs(5));
    }
    assert!(legit_ok(&c, &w.a_dev) < Duration::from_secs(5));
    // Chunked bodies (no length), conflicting lengths, and a smuggled
    // second request.
    let r = raw_exchange(
        addr,
        b"POST /v1/projects HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
    );
    assert_eq!(status_of(&r), 411, "{r}");
    let r = raw_exchange(
        addr,
        b"POST /v1/projects HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 40\r\n\r\n{}",
    );
    assert_eq!(status_of(&r), 400, "{r}");
    let r = raw_exchange(
        addr,
        b"POST /v1/projects HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}GET /v1/whoami HTTP/1.1\r\n\r\n",
    );
    assert_eq!(status_of(&r), 400, "{r}");
    // Oversized headers.
    let r = raw_exchange(
        addr,
        format!(
            "GET /v1/whoami HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
            "a".repeat(80 << 10)
        )
        .as_bytes(),
    );
    assert_eq!(status_of(&r), 431, "{r}");
    let many: String = (0..100).map(|i| format!("X-H{i}: v\r\n")).collect();
    let r = raw_exchange(
        addr,
        format!("GET /v1/whoami HTTP/1.1\r\n{many}\r\n").as_bytes(),
    );
    assert_eq!(status_of(&r), 431, "{r}");
    // Not HTTP/1.x, or garbage.
    for bad in [
        &b"GET /v1/whoami HTTP/2.0\r\n\r\n"[..],
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\r\n\r\n",
        b"GET http://evil.example/ HTTP/1.1\r\n\r\n",
        b"GET /v1/whoami HTTP/1.1\r\nX-Bad: a\x00b\r\n\r\n",
    ] {
        assert_eq!(status_of(&raw_exchange(addr, bad)), 400);
    }
    // Malformed JSON bodies reach the API, which refuses them cleanly.
    refused(
        c.raw("POST", "/v1/projects", &bearer(&tok), b"{not json"),
        400,
        BAD_INPUT,
        "malformed JSON",
    );
    let deep = "[".repeat(100_000);
    refused(
        c.raw("POST", "/v1/projects", &bearer(&tok), deep.as_bytes()),
        400,
        BAD_INPUT,
        "deeply nested JSON",
    );
    refused(
        c.call(
            &w.b_dev,
            "POST",
            "/v1/projects",
            Some(json!({"organization": "modelco", "name": "p", "extra": 1})),
        ),
        400,
        BAD_INPUT,
        "unknown field",
    );
    // Still serving.
    assert!(legit_ok(&c, &w.a_dev) < Duration::from_secs(5));
}

#[test]
fn slow_clients_cannot_starve_the_server() {
    let Some(w) = world() else { return };
    let addr = live(
        &w.t.control,
        Limits {
            threads: 4,
            head_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(1),
            body_timeout: Duration::from_secs(2),
            ..Limits::default()
        },
    );
    let c = Client::new(addr);
    let open = |bytes: &[u8]| {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(bytes).unwrap();
        s
    };
    let started = Instant::now();
    // A head that never ends, a body that never arrives, and a head
    // trickled one byte at a time (each byte inside the idle window).
    let stuck_head = open(b"GET /v1/whoami HTTP/1.1\r\nX-Slow: ");
    let stuck_body = open(b"POST /v1/projects HTTP/1.1\r\nContent-Length: 100\r\n\r\n{\"or");
    let trickle = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        let head =
            b"GET /v1/whoami HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n";
        for b in head.iter() {
            if s.write_all(&[*b]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    });
    // Other clients are served meanwhile, promptly.
    for _ in 0..5 {
        assert!(legit_ok(&c, &w.a_dev) < Duration::from_secs(1));
    }
    // Each slow client is cut off with 408 at its deadline.
    for mut s in [stuck_head, stuck_body] {
        let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert_eq!(status_of(&out), 408, "{out}");
    }
    let out = trickle.join().unwrap();
    assert_eq!(
        status_of(&out),
        408,
        "the total deadline stops a trickle: {out}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));

    // A flood of stalled connections (three times the threads): every
    // thread is taken for at most its deadline, then the queue drains; a
    // legitimate client waits a bounded time, never indefinitely.
    let flood: Vec<TcpStream> = (0..12)
        .map(|_| open(b"GET /v1/whoami HTTP/1.1\r\n"))
        .collect();
    let t = Instant::now();
    let waited = legit_ok(&c, &w.a_dev);
    assert!(waited < Duration::from_secs(12), "{waited:?}");
    assert!(t.elapsed() < Duration::from_secs(12));
    drop(flood);
    assert!(legit_ok(&c, &w.a_dev) < Duration::from_secs(3));
}

#[test]
fn bad_artifact_references_are_refused() {
    let Some(w) = world() else { return };
    let c = Client::new(live(&w.t.control, Limits::default()));
    let plan = w.plan(EXACT);
    let unknown = "ast_0000000000000000000000000000dead";
    // Unknown asset IDs, anywhere an asset is referenced.
    let (s, v) = c.call_with(
        &w.b_dev,
        "POST",
        "/v1/jobs",
        Some(
            json!({"project": w.project, "plan": plan, "purpose": "medical-training",
                    "source_assets": [unknown], "requested_output": "out"}),
        ),
        &[("Idempotency-Key", "bad-ref-1")],
    );
    refused((s, v), 404, NOT_FOUND, "job over an unknown asset");
    let asset = |extra: Value| {
        let mut b = json!({"organization": "hospital-a", "kind": "dataset",
                           "name": format!("d-{}", rand_u32()), "digest": "e".repeat(64)});
        b.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        c.call(&w.a_owner, "POST", "/v1/assets", Some(b))
    };
    refused(
        asset(json!({"parents": [unknown]})),
        404,
        NOT_FOUND,
        "unknown parent",
    );
    for (m, url, body) in [
        ("GET", format!("/v1/assets/{unknown}"), None),
        ("GET", format!("/v1/assets/{unknown}/lineage"), None),
        ("POST", format!("/v1/assets/{unknown}/revoke"), None),
        (
            "POST",
            format!("/v1/assets/{unknown}/approvals"),
            Some(json!({"project": w.project, "purpose": "x"})),
        ),
        ("GET", format!("/v1/privacy/{unknown}"), None),
        (
            "POST",
            format!("/v1/privacy/{unknown}/events"),
            Some(reserve("e", 1_000_000)),
        ),
        ("GET", "/v1/assets/..%2f..%2fetc%2fpasswd".to_owned(), None),
        ("GET", "/v1/jobs/job_does_not_exist".to_owned(), None),
    ] {
        refused(c.call(&w.a_owner, m, &url, body), 404, NOT_FOUND, &url);
    }
    // Dot segments in the path (sent raw: HTTP clients normalize them)
    // go nowhere.
    let tok = token("a-owner");
    for path in [
        "/v1/assets/../organizations/hospital-a",
        "/v1/assets/./../../v1/organizations/hospital-a",
    ] {
        let r = raw_exchange(
            c.base.trim_start_matches("http://").parse().unwrap(),
            format!("GET {path} HTTP/1.1\r\nAuthorization: Bearer {tok}\r\n\r\n").as_bytes(),
        );
        assert_eq!(status_of(&r), 404, "{path}: {r}");
        assert_eq!(body_of(&r)["code"], NOT_FOUND, "{r}");
    }
    // Unknown plan.
    refused(
        c.call_with(
            &w.b_dev,
            "POST",
            "/v1/jobs",
            Some(
                json!({"project": w.project, "plan": "pln_missing", "purpose": "p",
                        "source_assets": [], "requested_output": "out"}),
            ),
            &[("Idempotency-Key", "bad-ref-2")],
        ),
        404,
        NOT_FOUND,
        "unknown plan",
    );
    // Path traversal in storage URIs.
    for uri in [
        "../../etc/passwd",
        "s3://bucket/datasets/../../other-tenant/secret.parquet",
        "file:///srv/data/..%2f..%2fetc%2fshadow",
        "gs://bucket/a/%2e%2e/b",
        "datasets\\..\\secret",
        "s3://bucket/ spaced",
        "..",
    ] {
        refused(
            asset(json!({"storage_uri": uri})),
            400,
            BAD_INPUT,
            &format!("storage_uri {uri}"),
        );
    }
    let ok = asset(json!({"storage_uri": "s3://bucket/datasets/patients..v2/part-0.parquet"}));
    assert_eq!(ok.0, 201, "{}", ok.1);
    // Malformed digests.
    for digest in [
        "A".repeat(64),
        "a".repeat(63),
        "a".repeat(65),
        format!("sha512:{}", "a".repeat(64)),
        format!("sha256:{}", "g".repeat(64)),
        String::new(),
        format!("{} ", "a".repeat(64)),
    ] {
        refused(
            asset(json!({"digest": digest})),
            400,
            BAD_INPUT,
            &format!("digest {digest:?}"),
        );
    }
}

/// An evaluator with a control link only runs jobs its control plane
/// granted: every forged, foreign, expired or reused grant is refused, and
/// a restarted evaluator cannot run a started job again.
#[test]
fn evaluator_runs_only_granted_jobs_once() {
    use encompute_evaluator::control::ControlLink;
    use encompute_evaluator::server::{Evaluator as Ev, Limits as EvLimits};
    use encompute_evaluator::Backends;
    use encompute_verification::JobGrant;

    let Some(w) = world() else { return };
    let control_url = format!("http://{}", live(&w.t.control, Limits::default()));
    let control_key = w.t.control.signer.public_key_hex();
    let seed_of = |id: &str| {
        let mut s = [0u8; 32];
        for (i, b) in id.bytes().enumerate() {
            s[i % 32] ^= b;
        }
        s[31] ^= 0x5a;
        s
    };
    let start_evaluator = |id: &str| {
        let link = ControlLink::new(
            &control_url,
            "control-plane",
            &control_key,
            ServiceSigner::from_seed(id, &seed_of(id)).unwrap(),
        );
        let ev = Ev::new(Backends::MOCK, EvLimits::default()).with_control(Arc::new(link));
        let pid = ev.add_program(EXACT).unwrap();
        let server = encompute_verification::http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr());
        std::thread::spawn(move || ev.serve(server));
        (url, pid)
    };
    let (ev1, pid) = start_evaluator("evaluator-1");
    let _second = evaluator(
        &w.t,
        &w.platform,
        "evaluator-2",
        &["openfhe"],
        &["OPENFHE_CKKS_HE_STD128_V1"],
        1,
    );
    let (ev2, _) = start_evaluator("evaluator-2");
    let plan = w.plan(EXACT);
    let (_, j) = w.job(&plan, &[], "grant-1");
    let job = j["id"].as_str().unwrap().to_owned();
    let v = w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None);
    assert_eq!(v["program_id"], pid.as_str());
    let grant: JobGrant = serde_json::from_value(v["grant"].clone()).unwrap();
    let run = |ev: &str, pid: &str, grant: Option<String>| {
        let mut r = ureq::post(&format!("{ev}/v1/programs/{pid}/jobs"));
        if let Some(g) = grant {
            r = r.set("Encompute-Job-Grant", &g);
        }
        match r.send_bytes(b"not an envelope") {
            Ok(r) => (r.status(), r.into_json::<Value>().unwrap_or(Value::Null)),
            Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap_or(Value::Null)),
            Err(e) => panic!("{e}"),
        }
    };
    // The control plane's own key signs test grants below (it is the
    // harness's seed); a grant signed by anyone else is refused.
    let control = ServiceSigner::from_seed("control-plane", &[42; 32]).unwrap();
    let signed_grant = |edit: &dyn Fn(&mut JobGrant), by: &ServiceSigner| {
        let mut g = grant.clone();
        edit(&mut g);
        g.issuer_public_key = by.public_key_hex();
        g.signature = by
            .sign(encompute_verification::service::JOB_GRANT, &g.unsigned())
            .unwrap();
        g.to_header()
    };
    let mallory = ServiceSigner::from_seed("control-plane", &[43; 32]).unwrap();
    let cases: Vec<(&str, &str, Option<String>)> = vec![
        ("no grant", &ev1, None),
        ("garbage grant", &ev1, Some("zz-not-hex".into())),
        (
            "grant signed by another key",
            &ev1,
            Some(signed_grant(&|_| {}, &mallory)),
        ),
        (
            "grant edited after signing",
            &ev1,
            Some({
                let mut g = grant.clone();
                g.job_id = "job_other".into();
                g.to_header()
            }),
        ),
        (
            "expired grant",
            &ev1,
            Some(signed_grant(
                &|g| {
                    g.issued_at = now() - 7200;
                    g.expires_at = now() - 3600;
                },
                &control,
            )),
        ),
        (
            "grant for another program",
            &ev1,
            Some(signed_grant(
                &|g| g.program_id = "prg_other".into(),
                &control,
            )),
        ),
        ("grant for another evaluator", &ev2, Some(grant.to_header())),
    ];
    for (what, ev, g) in cases {
        let (s, v) = run(ev, &pid, g);
        assert_eq!(s, 401, "{what}: {v}");
        assert_eq!(v["code"], SERVICE_AUTH, "{what}: {v}");
    }
    assert_eq!(
        w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None)["state"],
        "queued",
        "no refused grant started the job"
    );
    // The genuine grant starts the job (the garbage body then fails to
    // parse: authorization came first).
    let (s, v) = run(&ev1, &pid, Some(grant.to_header()));
    assert_eq!(s, 400, "{v}");
    assert_eq!(v["code"], "ENC1601", "{v}");
    assert_eq!(
        w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None)["state"],
        "running"
    );
    // Reused on the same evaluator.
    let (s, v) = run(&ev1, &pid, Some(grant.to_header()));
    assert_eq!((s, v["code"].as_str()), (401, Some(SERVICE_AUTH)), "{v}");
    // A restarted evaluator (fresh memory) holding the same grant: the
    // control plane refuses to start a job twice.
    let (ev1b, _) = start_evaluator("evaluator-1");
    let (s, v) = run(&ev1b, &pid, Some(grant.to_header()));
    assert_eq!((s, v["code"].as_str()), (409, Some("ENC2604")), "{v}");
    // A job cancelled after scheduling never starts.
    let (_, j2) = w.job(&plan, &[], "grant-2");
    let job2 = j2["id"].as_str().unwrap().to_owned();
    let v = w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job2}"), None);
    let g2: JobGrant = serde_json::from_value(v["grant"].clone()).unwrap();
    w.t.ok(&w.b_dev, "POST", &format!("/v1/jobs/{job2}/cancel"), None);
    let (s, v) = run(&ev1b, &pid, Some(g2.to_header()));
    assert_eq!((s, v["code"].as_str()), (409, Some("ENC2604")), "{v}");
    // An unreachable control plane: the job is refused (503), not run.
    let link = ControlLink::new(
        "http://127.0.0.1:1",
        "control-plane",
        &control_key,
        ServiceSigner::from_seed("evaluator-1", &seed_of("evaluator-1")).unwrap(),
    );
    let ev = Ev::new(Backends::MOCK, EvLimits::default()).with_control(Arc::new(link));
    ev.add_program(EXACT).unwrap();
    let server = encompute_verification::http::Server::http("127.0.0.1:0").unwrap();
    let orphan = format!("http://{}", server.server_addr());
    std::thread::spawn(move || ev.serve(server));
    let (_, j3) = w.job(&plan, &[], "grant-3");
    let v = w.t.ok(
        &w.b_dev,
        "GET",
        &format!("/v1/jobs/{}", j3["id"].as_str().unwrap()),
        None,
    );
    let g3: JobGrant = serde_json::from_value(v["grant"].clone()).unwrap();
    let (s, v) = run(&orphan, &pid, Some(g3.to_header()));
    assert_eq!((s, v["code"].as_str()), (503, Some("ENC2606")), "{v}");
}
