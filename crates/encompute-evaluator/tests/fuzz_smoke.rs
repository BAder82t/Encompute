//! Fuzz smoke tests for the evaluator's HTTP bodies (programs, key
//! envelopes, job envelopes, grant headers) on the mock backend: through
//! the engine directly (thousands of inputs) and through the real HTTP
//! server with one handler thread, which must answer every request and
//! stay alive (a handler panic would kill its only thread). Resource
//! limits: bodies over the limits and declared lengths near u64::MAX are
//! refused without being read.

#[path = "../../encompute-ir/tests/fuzz_support/mod.rs"]
mod fuzz_support;

use std::io::Read;
use std::time::Duration;

use encompute_backend::{CkksClient, MockClient, MockConfig};
use encompute_evaluator::engine::{Engine, Local};
use encompute_evaluator::server::{Evaluator, Limits};
use encompute_evaluator::{BackendKind, Backends, EvaluatorSession, Ids};
use encompute_protocol::{sha256_hex, Envelope, Header, Kind};
use fuzz_support::{mutate, run, Rng};

const PROGRAM: &str = "encompute 0.1\nprogram w precision 0.001\n\
%0 = input \"x\" [-1.0, 1.0] : secret vector<4>\n\
%1 = const [0.5, -1.0, 0.25, 2.0] : public vector<4>\n\
%2 = dot %1, %0 : secret scalar\n\
output \"d\" = %2\n";

const EXACT: &str = include_str!("../../../benches/exact/mixed.eir");

fn header(kind: Kind, ids: &Ids, key_id: &str) -> Header {
    Header {
        kind,
        scheme: "CKKS".into(),
        backend: "mock".into(),
        backend_version: "0".into(),
        parameter_set_id: ids.parameter_set_id.clone(),
        program_id: matches!(kind, Kind::Inputs).then(|| ids.program_id.clone()),
        key_id: Some(key_id.into()),
        items: vec![],
    }
}

/// (program ID, key envelope, inputs envelope).
fn envelopes() -> (String, Vec<u8>, Vec<u8>) {
    let s =
        EvaluatorSession::new(encompute_ir::parse(PROGRAM).unwrap(), BackendKind::Mock).unwrap();
    let c = s.compiled().ckks().unwrap();
    let ids = s.ids().clone();
    let client = MockClient::new(
        &c.params,
        &c.plan.rotations,
        MockConfig {
            seed: 5,
            noise: false,
        },
    );
    let payload = client.evaluation_keys().unwrap();
    let key_id = sha256_hex(&payload);
    let keys = Envelope::new(
        header(Kind::EvaluationKeys, &ids, &key_id),
        vec![("keys".into(), payload)],
    )
    .encode();
    let ct = client
        .encrypt(&c.plan.encode_input(0, &[0.5, 0.25, -0.5, 1.0]))
        .unwrap();
    let inputs =
        Envelope::new(header(Kind::Inputs, &ids, &key_id), vec![("x".into(), ct)]).encode();
    (ids.program_id, keys, inputs)
}

/// Re-checksums a mutated envelope body so decoding goes past the digest.
fn reseal(bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let body = &bytes[..bytes.len().saturating_sub(32)];
    let mut v = body.to_vec();
    v.extend_from_slice(&sha2::Sha256::digest(body));
    v
}

#[test]
fn mutated_bodies_never_panic_the_engine() {
    let engine = Local::new(Backends::MOCK);
    let (pid, keys, inputs) = envelopes();
    assert_eq!(engine.add_program(PROGRAM).unwrap().program_id, pid);
    engine.register_keys(&pid, &keys).unwrap();
    engine.execute(&pid, &inputs).unwrap();
    run(
        "evaluator-envelopes",
        &[keys.clone(), inputs.clone()],
        4000,
        Duration::from_secs(2),
        |bytes| {
            for b in [bytes.to_vec(), reseal(bytes)] {
                let _ = engine.register_keys(&pid, &b);
                let _ = engine.execute(&pid, &b);
            }
            let _ = engine.has_key(&pid, &String::from_utf8_lossy(bytes));
        },
    );
    run(
        "evaluator-programs",
        &[PROGRAM.as_bytes().to_vec(), EXACT.as_bytes().to_vec()],
        1500,
        Duration::from_secs(5),
        |bytes| {
            if let Ok(t) = std::str::from_utf8(bytes) {
                let _ = Local::new(Backends::MOCK).add_program(t);
            }
        },
    );
}

fn post(agent: &ureq::Agent, url: &str, body: &[u8], grant: Option<&str>) -> Result<u16, String> {
    let mut r = agent.post(url);
    if let Some(g) = grant {
        r = r.set("Encompute-Job-Grant", g);
    }
    match r.send_bytes(body) {
        Ok(resp) => Ok(resp.status()),
        Err(ureq::Error::Status(s, _)) => Ok(s),
        Err(e) => Err(e.to_string()),
    }
}

#[test]
fn the_http_server_answers_every_mutated_request() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let ev = Evaluator::new(
        Backends::MOCK,
        Limits {
            max_program: 64 << 10,
            max_keys: 1 << 20,
            max_inputs: 1 << 20,
            kept_results: 4,
            http_threads: 1,
        },
    );
    std::thread::spawn(move || ev.serve(server));
    let base = format!("http://127.0.0.1:{port}");
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(20))
        .build();
    let (pid, keys, inputs) = envelopes();
    assert_eq!(
        post(
            &agent,
            &format!("{base}/v1/programs"),
            PROGRAM.as_bytes(),
            None
        ),
        Ok(200)
    );
    assert_eq!(
        post(
            &agent,
            &format!("{base}/v1/programs/{pid}/keys"),
            &keys,
            None
        ),
        Ok(200)
    );
    assert_eq!(
        post(
            &agent,
            &format!("{base}/v1/programs/{pid}/jobs"),
            &inputs,
            None
        ),
        Ok(200)
    );

    let mut rng = Rng::new(42);
    let routes = [
        (format!("{base}/v1/programs"), PROGRAM.as_bytes().to_vec()),
        (format!("{base}/v1/programs/{pid}/keys"), keys.clone()),
        (format!("{base}/v1/programs/{pid}/jobs"), inputs.clone()),
    ];
    for i in 0..300 {
        let (url, seed) = &routes[i % routes.len()];
        let mut body = mutate(&mut rng, seed, &[]);
        if i % 2 == 1 && !url.ends_with("/programs") {
            body = reseal(&body);
        }
        let grant = (i % 7 == 0).then(|| "zz".repeat(i % 50));
        let status = post(&agent, url, &body, grant.as_deref())
            .unwrap_or_else(|e| panic!("request {i} to {url} got no answer: {e}"));
        assert!(status != 0, "request {i}");
    }
    // Paths with odd segments and methods.
    for path in [
        "/v1/programs/%00/jobs",
        "/v1/jobs/x/result",
        "/v1/programs//keys",
        "/../../etc/passwd",
    ] {
        let _ = agent.get(&format!("{base}{path}")).call();
    }
    // Over-limit bodies: refused (413) without reading them.
    let big = vec![b'a'; (64 << 10) + 1];
    assert_eq!(
        post(&agent, &format!("{base}/v1/programs"), &big, None),
        Ok(413)
    );
    // Still alive: the only handler thread never panicked.
    let info = agent.get(&format!("{base}/v1/info")).call().unwrap();
    assert_eq!(info.status(), 200);
}

/// A request declaring a body of 2^63 bytes is refused from the header,
/// without reading or allocating it.
#[test]
fn huge_declared_content_lengths_are_refused() {
    use std::io::Write;
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let ev = Evaluator::new(Backends::MOCK, Limits::default());
    std::thread::spawn(move || ev.serve(server));
    for len in [u64::MAX, 1 << 63, (4 << 30) + 1] {
        let t = std::time::Instant::now();
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            s,
            "POST /v1/programs/x/keys HTTP/1.1\r\nHost: x\r\nContent-Length: {len}\r\n\r\nabc"
        )
        .unwrap();
        let mut head = [0u8; 12];
        s.read_exact(&mut head).unwrap();
        let head = String::from_utf8_lossy(&head);
        assert!(
            head.starts_with("HTTP/1.1 4") || head.starts_with("HTTP/1.1 5"),
            "{len}: {head}"
        );
        assert!(t.elapsed() < Duration::from_secs(5), "{len}");
    }
}
