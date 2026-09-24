//! Client ↔ evaluator over real HTTP on localhost (mock backend).

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;

use common::logistic;
use encompute_evaluator::server::{Evaluator, Limits};
use encompute_ir::{evaluate, Code};
use encompute_runtime::{sample_inputs, BackendKind, Mode, Model, Remote};

fn spawn(limits: Limits) -> String {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    std::thread::spawn(move || Evaluator::new(BackendKind::Mock, limits).serve(server));
    url
}

#[test]
fn remote_round_trip_uploads_program_and_keys_once() {
    let url = spawn(Limits::default());
    let remote = Remote::new(&url);
    let info = remote.info().unwrap();
    assert_eq!(info["holds_secret_keys"], false);
    assert_eq!(info["programs"].as_array().unwrap().len(), 0);

    let m = Model::compile(logistic(16, 1)).unwrap();
    let client = m.new_client(Mode::Mock).unwrap();
    let inputs = sample_inputs(m.program(), 4, 0);
    let (out, stats) = remote.run(&client, m.program(), None, &inputs).unwrap();
    let want = evaluate(m.program(), &inputs).unwrap();
    assert!((out["score"][0] - want["score"][0]).abs() < 1e-3);
    assert!(
        stats.evaluation_key_bytes_uploaded > 0
            && stats.request_bytes > 0
            && stats.response_bytes > 0
    );

    let (_, again) = remote.run(&client, m.program(), None, &inputs).unwrap();
    assert_eq!(again.evaluation_key_bytes_uploaded, 0, "keys are reused");
    assert_eq!(
        remote.info().unwrap()["programs"].as_array().unwrap().len(),
        1
    );

    // A restored client (no evaluation keys in hand) works once keys are registered…
    let restored = encompute_runtime::ClientSession::restore(
        m.ids(),
        &m.compiled().plan,
        &m.compiled().params,
        &client.secret_key_envelope().unwrap(),
    )
    .unwrap();
    assert!(remote.run(&restored, m.program(), None, &inputs).is_ok());
    // …and a new client whose keys were never uploaded is refused.
    let stranger = encompute_runtime::ClientSession::restore(
        m.ids(),
        &m.compiled().plan,
        &m.compiled().params,
        &m.new_client(Mode::Mock)
            .unwrap()
            .secret_key_envelope()
            .unwrap(),
    )
    .unwrap();
    assert_ne!(stranger.key_id(), client.key_id());
    assert_eq!(
        remote
            .run(&stranger, m.program(), None, &inputs)
            .unwrap_err()
            .code,
        Code::WrongKey
    );
}

#[test]
fn malformed_requests_are_rejected_with_codes() {
    let url = spawn(Limits {
        max_inputs: 4096,
        ..Limits::default()
    });
    let m = Model::compile(logistic(4, 1)).unwrap();
    let remote = Remote::new(&url);
    let pid = m.ids().program_id;
    remote.ensure_program(m.program(), &pid).unwrap();

    let post = |path: &str, body: &[u8]| match ureq::post(&format!("{url}{path}")).send_bytes(body)
    {
        Ok(r) => (r.status(), r.into_string().unwrap()),
        Err(ureq::Error::Status(s, r)) => (s, r.into_string().unwrap()),
        Err(e) => panic!("{e}"),
    };
    let (s, b) = post(
        &format!("/v1/programs/{pid}/jobs"),
        b"garbage-bytes-garbage-bytes-garbage-bytes-garbage",
    );
    assert_eq!(s, 400, "{b}");
    assert!(b.contains("ENC1601"));
    let (s, b) = post(&format!("/v1/programs/{pid}/jobs"), &vec![7u8; 10_000]);
    assert_eq!(s, 413, "{b}");
    let (s, _) = post("/v1/programs/nope/jobs", b"x");
    assert_eq!(s, 404);
    let (s, b) = post("/v1/programs", &[0xff, 0xfe, 0x00]);
    assert_eq!(s, 400, "{b}");
    let (s, b) = post(
        "/v1/programs",
        b"encompute 0.1\nprogram p precision 0.1\n%0 = frob\n",
    );
    assert_eq!(s, 400, "{b}");
    assert!(b.contains("ENC1302"));
    let (s, _) = post(&format!("/v1/programs/{pid}/keys"), b"not keys");
    assert_eq!(s, 400);
    let (s, _) = post("/v1/nowhere", b"");
    assert_eq!(s, 404);
    match ureq::get(&format!("{url}/v1/jobs/unknown/result")).call() {
        Err(ureq::Error::Status(404, _)) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn unreachable_or_dropping_evaluators_are_remote_errors() {
    // Nothing listening.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", dead.local_addr().unwrap());
    drop(dead);
    assert_eq!(Remote::new(&url).info().unwrap_err().code, Code::Remote);

    // Accepts, reads a little, then hangs up mid-request.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        for s in l.incoming().take(2) {
            let mut s = s.unwrap();
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n{\"trunc");
        }
    });
    let e = Remote::new(&url).info().unwrap_err();
    assert_eq!(e.code, Code::Remote, "{e}");
}
