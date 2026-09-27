//! Network attacks on the key broker's HTTP server, on loopback: control
//! messages that are unsigned, forged, misaddressed, stale, replayed or
//! duplicated; oversized, malformed and unauthenticated requests; request
//! floods; and slow clients, which must not hold the broker (it used to
//! serve one request at a time: one stalled body blocked every release).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use encompute_attestation::mock::{MockHardware, MockProvider};
use encompute_attestation::{AttestationPolicy, TeeKind, Verifier};
use encompute_keybroker::{
    serve_with_control, serve_with_limit, BrokerMode, ControlChannel, DevelopmentFileStore,
    KeyBroker, KeyMaterial,
};
use encompute_verification::http::{Limits, Server};
use encompute_verification::service::{now, seal, sha256_hex, Scope, SERVICE_MESSAGE};
use encompute_verification::{MessageEnvelope, ServiceSigner};

const SPEC: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const POLICY: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const IMAGE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const ME: &str = "keybroker-a";

fn control() -> ServiceSigner {
    ServiceSigner::from_seed("control-plane", &[42; 32]).unwrap()
}

fn broker() -> KeyBroker {
    let hw = MockHardware::from_seed(&[7; 32]);
    let verifier = Verifier::new().with(MockProvider::new(&hw.public_key()).unwrap());
    let mut b = KeyBroker::new(
        "hospital",
        BrokerMode::Development,
        verifier,
        Box::new(DevelopmentFileStore),
    )
    .unwrap();
    // A broker serves one organization; revocations name it.
    b.set_organization("hospital").unwrap();
    let mut p = AttestationPolicy::new(SPEC, Some(POLICY));
    p.allowed_tee = vec![TeeKind::Mock];
    p.allowed_images = vec![IMAGE.into()];
    p.allow_development = true;
    b.add_secret(
        "patients",
        Some(KeyMaterial::from_bytes(b"patients key").unwrap()),
        p,
    )
    .unwrap();
    b
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "encompute-kb-net-{tag}-{}-{}",
        std::process::id(),
        now()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Serves a broker (persisted to `state`) that accepts revocations from
/// the control plane.
fn start(state: PathBuf, limits: Limits) -> SocketAddr {
    let b = broker();
    b.save(&state).unwrap();
    start_from(state, limits)
}

/// Serves the broker saved at `state` (a restart).
fn start_from(state: PathBuf, limits: Limits) -> SocketAddr {
    let hw = MockHardware::from_seed(&[7; 32]);
    let verifier = Verifier::new().with(MockProvider::new(&hw.public_key()).unwrap());
    let b = KeyBroker::load(&state, verifier, Box::new(DevelopmentFileStore)).unwrap();
    let server = Server::http("127.0.0.1:0").unwrap().with_limits(limits);
    let addr = server.server_addr();
    let ch = ControlChannel::new(ME, "control-plane", &control().public_key_hex(), "hospital");
    std::thread::spawn(move || {
        let b = Mutex::new(b);
        serve_with_control(&b, server, 10_000, Some(&ch), &|b| b.save(&state))
    });
    addr
}

fn post(addr: SocketAddr, path: &str, headers: &[(String, String)], body: &[u8]) -> (u16, Value) {
    let mut r = ureq::post(&format!("http://{addr}{path}"));
    for (k, v) in headers {
        r = r.set(k, v);
    }
    match r.send_bytes(body) {
        Ok(r) => (r.status(), r.into_json().unwrap_or(Value::Null)),
        Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap_or(Value::Null)),
        Err(e) => panic!("{path}: {e}"),
    }
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

/// Headers of a request signed by `s` to `recipient` at `timestamp`.
fn signed_at(
    s: &ServiceSigner,
    recipient: &str,
    body: &[u8],
    timestamp: u64,
) -> Vec<(String, String)> {
    let mut h = s
        .sign_request("POST", "/v1/messages", recipient, &Default::default(), body)
        .unwrap();
    h.timestamp = timestamp;
    h.signature = s
        .sign(
            encompute_verification::service::SERVICE_REQUEST,
            &Statement {
                method: "POST",
                path: "/v1/messages",
                sender: &h.sender,
                recipient: &h.recipient,
                timestamp,
                nonce: &h.nonce,
                bind: &h.bind,
                body_sha256: sha256_hex(body),
            },
        )
        .unwrap();
    h.to_pairs()
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
}

fn signed(s: &ServiceSigner, body: &[u8]) -> Vec<(String, String)> {
    signed_at(s, ME, body, now())
}

fn revocation(by: &ServiceSigner, to: &str) -> MessageEnvelope {
    seal(
        by,
        "asset.revoked",
        to,
        Scope {
            organization: Some("hospital".into()),
            ..Scope::default()
        },
        &json!({"asset": "ast_1", "key_ref": "patients", "key_version": 1}),
        3600,
    )
    .unwrap()
}

fn bytes(m: &MessageEnvelope) -> Vec<u8> {
    serde_json::to_vec(m).unwrap()
}

fn refused(r: (u16, Value), status: u16, code: &str, what: &str) -> Value {
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (status, Some(code)),
        "{what}: {}",
        r.1
    );
    r.1
}

fn stored_form(state: &PathBuf) -> String {
    let v: Value = serde_json::from_slice(&std::fs::read(state).unwrap()).unwrap();
    v["secrets"]["patients"]["versions"]["1"]["key"]["form"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn control_messages_are_authenticated_fresh_and_applied_once() {
    let dir = tmp("control");
    let state = dir.join("broker.json");
    let addr = start(state.clone(), Limits::default());
    let cp = control();
    let m = revocation(&cp, ME);
    let body = bytes(&m);
    let auth = "ENC2607";

    refused(
        post(addr, "/v1/messages", &[], &body),
        403,
        auth,
        "unsigned",
    );
    let mallory = ServiceSigner::from_seed("control-plane", &[43; 32]).unwrap();
    refused(
        post(addr, "/v1/messages", &signed(&mallory, &body), &body),
        403,
        auth,
        "signed by another key under the control plane's name",
    );
    let evaluator = ServiceSigner::from_seed("evaluator-1", &[44; 32]).unwrap();
    refused(
        post(addr, "/v1/messages", &signed(&evaluator, &body), &body),
        403,
        auth,
        "another service",
    );
    refused(
        post(
            addr,
            "/v1/messages",
            &signed_at(&cp, "keybroker-b", &body, now()),
            &body,
        ),
        403,
        auth,
        "addressed to another broker",
    );
    for ts in [now() - 301, now() + 301] {
        let v = refused(
            post(addr, "/v1/messages", &signed_at(&cp, ME, &body, ts), &body),
            403,
            auth,
            "stale timestamp",
        );
        assert!(v["message"].as_str().unwrap().contains("expired"), "{v}");
    }
    let mut h = signed(&cp, &body);
    for (k, v) in h.iter_mut() {
        if k == "Encompute-Signature" {
            *v = format!("{}{}", if v.starts_with('0') { "1" } else { "0" }, &v[1..]);
        }
    }
    refused(
        post(addr, "/v1/messages", &h, &body),
        403,
        auth,
        "flipped signature",
    );
    // A validly signed request carrying a tampered, expired or misaddressed
    // message.
    let mut x = m.clone();
    x.payload["key_ref"] = json!("other-asset");
    let xb = bytes(&x);
    refused(
        post(addr, "/v1/messages", &signed(&cp, &xb), &xb),
        403,
        auth,
        "payload edited after sealing",
    );
    let mut x = m.clone();
    x.created_at = now() - 7200;
    x.expires_at = now() - 3600;
    x.signature = cp.sign(SERVICE_MESSAGE, &x.statement()).unwrap();
    let xb = bytes(&x);
    refused(
        post(addr, "/v1/messages", &signed(&cp, &xb), &xb),
        403,
        auth,
        "expired message",
    );
    let x = revocation(&cp, "keybroker-b");
    let xb = bytes(&x);
    refused(
        post(addr, "/v1/messages", &signed(&cp, &xb), &xb),
        403,
        auth,
        "message for another broker",
    );
    let x = seal(&cp, "asset.restored", ME, Scope::default(), &json!({}), 60).unwrap();
    let xb = bytes(&x);
    refused(
        post(addr, "/v1/messages", &signed(&cp, &xb), &xb),
        403,
        "ENC1102",
        "unknown message kind",
    );
    assert_eq!(stored_form(&state), "plaintext", "nothing was revoked yet");

    // The genuine revocation: applied and persisted; the same request
    // replayed is refused; the same message delivered again is a no-op.
    let h = signed(&cp, &body);
    let (s, v) = post(addr, "/v1/messages", &h, &body);
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["revoked_versions"], json!([1]));
    assert_eq!(stored_form(&state), "destroyed");
    let v = refused(
        post(addr, "/v1/messages", &h, &body),
        403,
        auth,
        "replayed request",
    );
    assert!(v["message"].as_str().unwrap().contains("replayed"), "{v}");
    for _ in 0..3 {
        let (s, v) = post(addr, "/v1/messages", &signed(&cp, &body), &body);
        assert_eq!((s, &v["revoked_versions"]), (200, &json!([])), "{v}");
    }
    // After a restart the broker reopens its persisted state: the key stays
    // destroyed, and a delivery (or a replay the in-memory nonce set no
    // longer remembers) changes nothing.
    let addr = start_from(state.clone(), Limits::default());
    let (s, v) = post(addr, "/v1/messages", &h, &body);
    assert_eq!((s, &v["revoked_versions"]), (200, &json!([])), "{v}");
    assert_eq!(stored_form(&state), "destroyed");
    std::fs::remove_dir_all(&dir).unwrap();
}

fn raw(addr: SocketAddr, bytes: &[u8]) -> String {
    let mut c = TcpStream::connect(addr).unwrap();
    let _ = c.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = c.write_all(bytes);
    let mut out = vec![];
    let _ = c.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn status(reply: &str) -> u16 {
    reply.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0)
}

#[test]
fn oversized_malformed_and_unauthenticated_requests_are_refused() {
    let dir = tmp("malformed");
    let addr = start(
        dir.join("broker.json"),
        Limits {
            threads: 2,
            ..Limits::default()
        },
    );
    // Bodies over 96 KiB: refused before reading; a huge declared length
    // with nothing behind it does not hold a thread.
    refused(
        post(addr, "/v1/attest", &[], &vec![b'x'; (96 << 10) + 1]),
        413,
        "ENC1102",
        "oversized",
    );
    for _ in 0..4 {
        let t = Instant::now();
        let r = raw(
            addr,
            b"POST /v1/release HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n{}",
        );
        assert_eq!(status(&r), 413, "{r}");
        assert!(t.elapsed() < Duration::from_secs(5));
    }
    let r = raw(
        addr,
        b"POST /v1/release HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
    );
    assert_eq!(status(&r), 411, "{r}");
    let r = raw(
        addr,
        b"POST /v1/release HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}POST /v1/release HTTP/1.1\r\n\r\n",
    );
    assert_eq!(status(&r), 400, "{r}");
    // No attested session, malformed requests, unknown endpoints.
    refused(
        post(
            addr,
            "/v1/release",
            &[],
            json!({"session": "00".repeat(32), "asset_id": "patients"})
                .to_string()
                .as_bytes(),
        ),
        403,
        "ENC2004",
        "release without attestation",
    );
    refused(
        post(
            addr,
            "/v1/release",
            &[],
            json!({"session": "00".repeat(32), "asset_id": "../../etc/passwd"})
                .to_string()
                .as_bytes(),
        ),
        403,
        "ENC2004",
        "traversal in the asset ID",
    );
    refused(
        post(addr, "/v1/release", &[], b"{\"session\": 1"),
        400,
        "ENC1701",
        "malformed JSON",
    );
    refused(
        post(
            addr,
            "/v1/release",
            &[],
            br#"{"session": "a", "asset_id": "b", "grant_to": "me"}"#,
        ),
        400,
        "ENC1701",
        "unknown field",
    );
    assert_ne!(post(addr, "/v1/attest", &[], b"garbage evidence").0, 200);
    refused(
        post(addr, "/v1/keys", &[], b"{}"),
        400,
        "ENC1701",
        "no endpoint",
    );
    let (s, v) = match ureq::get(&format!("http://{addr}/v1/release")).call() {
        Err(ureq::Error::Status(s, r)) => (s, r.into_json::<Value>().unwrap()),
        other => panic!("{other:?}"),
    };
    assert_eq!((s, v["code"].as_str()), (400, Some("ENC1701")), "{v}");
    // Still serving.
    assert_eq!(post(addr, "/v1/challenge", &[], b"").0, 200);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn request_floods_are_limited_per_address() {
    let server = Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr();
    std::thread::spawn(move || serve_with_limit(&Mutex::new(broker()), server, 5));
    for _ in 0..5 {
        assert_eq!(post(addr, "/v1/challenge", &[], b"").0, 200);
    }
    refused(
        post(addr, "/v1/challenge", &[], b""),
        429,
        "ENC2003",
        "sixth request in a minute",
    );
}

#[test]
fn slow_clients_cannot_hold_the_broker() {
    let dir = tmp("slow");
    let addr = start(
        dir.join("broker.json"),
        Limits {
            threads: 4,
            head_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            body_timeout: Duration::from_secs(1),
            ..Limits::default()
        },
    );
    let open = |b: &[u8]| {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b).unwrap();
        s
    };
    let started = Instant::now();
    // A stalled head and a stalled body (a revocation that never arrives).
    let slow = [
        open(b"POST /v1/challenge HTTP/1.1\r\nX-Slow: "),
        open(b"POST /v1/messages HTTP/1.1\r\nContent-Length: 5000\r\n\r\n{\"protocol_version\""),
    ];
    for _ in 0..5 {
        let t = Instant::now();
        assert_eq!(post(addr, "/v1/challenge", &[], b"").0, 200);
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    }
    for mut s in slow {
        let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert_eq!(status(&out), 408, "{out}");
    }
    assert!(started.elapsed() < Duration::from_secs(8));
    std::fs::remove_dir_all(&dir).unwrap();
}
