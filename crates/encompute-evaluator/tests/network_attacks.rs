//! Network attacks on the evaluator's HTTP server, on loopback: oversized
//! uploads (declared and real), chunked bodies, unknown or traversing
//! program and job references, malformed envelopes, and slow clients,
//! which hold one connection thread for a bounded time and never the
//! evaluator. (Jobs without a valid control-plane grant are refused in
//! `encompute-control`'s `network_attacks.rs`, which runs an evaluator with
//! its control link against a live control plane.)

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use serde_json::Value;

use encompute_evaluator::server::{Evaluator, Limits};
use encompute_evaluator::Backends;
use encompute_verification::http;

const PROGRAM: &str = "encompute 0.1
program adult precision 0.001
%0 = input \"age\" [0.0, 120.0] : secret u8
%1 = const [18.0] : public u8
%2 = ge %0, %1 : secret bool
output \"out\" = %2
";

fn start(limits: Limits, http_limits: http::Limits) -> (SocketAddr, String) {
    let ev = Evaluator::new(Backends::MOCK, limits);
    let pid = ev.add_program(PROGRAM).unwrap();
    let server = http::Server::http("127.0.0.1:0")
        .unwrap()
        .with_limits(http_limits);
    let addr = server.server_addr();
    std::thread::spawn(move || ev.serve(server));
    (addr, pid)
}

fn call(addr: SocketAddr, method: &str, path: &str, body: &[u8]) -> (u16, Value) {
    let r = ureq::request(method, &format!("http://{addr}{path}"));
    let out = if body.is_empty() {
        r.call()
    } else {
        r.send_bytes(body)
    };
    match out {
        Ok(r) => (r.status(), r.into_json().unwrap_or(Value::Null)),
        Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap_or(Value::Null)),
        Err(e) => panic!("{method} {path}: {e}"),
    }
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

fn refused(r: (u16, Value), status: u16, code: &str, what: &str) {
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (status, Some(code)),
        "{what}: {}",
        r.1
    );
}

#[test]
fn oversized_and_malformed_uploads_are_refused() {
    let (addr, pid) = start(
        Limits {
            max_program: 4096,
            max_keys: 8192,
            max_inputs: 8192,
            http_threads: 2,
            ..Limits::default()
        },
        http::Limits::default(),
    );
    // Real bodies over each route's limit.
    refused(
        call(addr, "POST", "/v1/programs", &vec![b'x'; 4097]),
        413,
        "ENC1701",
        "program",
    );
    refused(
        call(
            addr,
            "POST",
            &format!("/v1/programs/{pid}/keys"),
            &vec![0; 8193],
        ),
        413,
        "ENC1701",
        "keys",
    );
    refused(
        call(
            addr,
            "POST",
            &format!("/v1/programs/{pid}/jobs"),
            &vec![0; 8193],
        ),
        413,
        "ENC1701",
        "inputs",
    );
    // A huge declared length with a small body: refused at once, and the
    // two connection threads are not held.
    for _ in 0..4 {
        let t = Instant::now();
        let r = raw(
            addr,
            format!(
                "POST /v1/programs/{pid}/keys HTTP/1.1\r\nContent-Length: 100000000000\r\n\r\nENCK"
            )
            .as_bytes(),
        );
        assert_eq!(status(&r), 413, "{r}");
        assert!(t.elapsed() < Duration::from_secs(5));
    }
    let r = raw(
        addr,
        b"POST /v1/programs HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n",
    );
    assert_eq!(status(&r), 411, "{r}");
    // Malformed content reaches the evaluator, which refuses it.
    refused(
        call(addr, "POST", "/v1/programs", &[0xff, 0xfe, 0x00]),
        400,
        "ENC1302",
        "non-UTF-8 program",
    );
    refused(
        call(addr, "POST", "/v1/programs", b"not a program"),
        400,
        "ENC1302",
        "unparsable program",
    );
    let (s, v) = call(
        addr,
        "POST",
        &format!("/v1/programs/{pid}/jobs"),
        b"ENC\x00garbage envelope",
    );
    assert_eq!(s, 400, "{v}");
    assert_eq!(v["code"], "ENC1601", "{v}");
    let (s, _) = call(addr, "GET", "/v1/info", b"");
    assert_eq!(s, 200);
}

#[test]
fn unknown_and_traversing_references_are_not_found() {
    let (addr, pid) = start(Limits::default(), http::Limits::default());
    refused(
        call(
            addr,
            "POST",
            "/v1/programs/prg_does_not_exist/jobs",
            b"ENC\x00",
        ),
        404,
        "ENC1604",
        "unknown program",
    );
    for path in [
        "/v1/jobs/job_missing/result".to_owned(),
        "/v1/jobs/job_missing/receipt".to_owned(),
        "/v1/jobs/..%2f..%2fetc%2fpasswd/result".to_owned(),
        format!("/v1/programs/{pid}/keys/..%2f..%2fkeys"),
        "/v1/programs/../../etc/passwd".to_owned(),
    ] {
        let r = raw(addr, format!("GET {path} HTTP/1.1\r\n\r\n").as_bytes());
        assert_eq!(status(&r), 404, "{path}: {r}");
    }
    // Only origin-form targets are served.
    assert_eq!(
        status(&raw(
            addr,
            b"GET http://evil.example/v1/info HTTP/1.1\r\n\r\n"
        )),
        400
    );
}

#[test]
fn slow_clients_cannot_hold_the_evaluator() {
    let (addr, _) = start(
        Limits {
            http_threads: 3,
            ..Limits::default()
        },
        http::Limits {
            head_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            body_timeout: Duration::from_secs(1),
            ..http::Limits::default()
        },
    );
    let open = |b: &[u8]| {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b).unwrap();
        s
    };
    let started = Instant::now();
    let slow = [
        open(b"GET /v1/info HTTP/1.1\r\nX-Slow: "),
        open(b"POST /v1/programs HTTP/1.1\r\nContent-Length: 2000\r\n\r\nencompute 0.1\n"),
    ];
    for _ in 0..5 {
        let t = Instant::now();
        assert_eq!(call(addr, "GET", "/v1/info", b"").0, 200);
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    }
    for mut s in slow {
        let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert_eq!(status(&out), 408, "{out}");
    }
    assert!(started.elapsed() < Duration::from_secs(8));
}
