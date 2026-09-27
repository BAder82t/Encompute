//! The evaluation-key cache: bounded, shared by the sessions of a process,
//! and never running one client's ciphertexts under another client's keys.
//! One test: the bound is read once per process.

mod common;

use common::logistic;
use encompute_evaluator::server::{Evaluator, Limits};
use encompute_ir::Code;
use encompute_runtime::{sample_inputs, BackendKind, Backends, ClientSession, EvaluatorSession};

#[test]
fn bounded_shared_and_isolated() {
    let p = logistic(8, 1);
    let inputs = sample_inputs(&p, 3, 0);
    let ev = EvaluatorSession::new(p.clone(), BackendKind::Mock).unwrap();
    let client = |seed| {
        ClientSession::generate(ev.ids().clone(), ev.compiled(), BackendKind::Mock, seed).unwrap()
    };
    let (a, b) = (client(1), client(2));
    let size = a.evaluation_keys().unwrap().len();
    // Room for one key set, not two.
    std::env::set_var("ENCOMPUTE_KEY_CACHE_BYTES", (size * 3 / 2).to_string());

    ev.register_keys(a.evaluation_keys().unwrap()).unwrap();
    let req_a = a.encrypt(&p, &inputs).unwrap();
    let (out, _) = ev.execute(&req_a).unwrap();
    assert!(a.decrypt(&out).is_ok());

    // Another session of the same program registers another client's keys.
    let other = EvaluatorSession::new(p.clone(), BackendKind::Mock).unwrap();
    other.register_keys(b.evaluation_keys().unwrap()).unwrap();
    let req_b = b.encrypt(&p, &inputs).unwrap();
    assert!(other.execute(&req_b).is_ok());

    // b's keys, though cached, were never registered with `ev`.
    assert!(!ev.has_key(b.key_id()));
    assert_eq!(ev.execute(&req_b).unwrap_err().code, Code::WrongKey);
    // a's keys were evicted to stay within the bound: reported missing, so
    // the client uploads them again.
    assert!(!ev.has_key(a.key_id()));
    assert_eq!(ev.execute(&req_a).unwrap_err().code, Code::WrongKey);
    ev.register_keys(a.evaluation_keys().unwrap()).unwrap();
    assert!(ev.has_key(a.key_id()));
    assert!(ev.execute(&req_a).is_ok());

    // Metrics: counters only.
    let server = encompute_verification::http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}/metrics", server.server_addr());
    std::thread::spawn(move || Evaluator::new(Backends::MOCK, Limits::default()).serve(server));
    let resp = ureq::get(&url).call().unwrap();
    assert!(resp.content_type().starts_with("text/plain"));
    let text = resp.into_string().unwrap();
    let metric = |name: &str| -> f64 {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{name} ")))
            .unwrap_or_else(|| panic!("{name} missing:\n{text}"))
            .parse()
            .unwrap()
    };
    assert_eq!(metric("encompute_key_cache_loads_total"), 3.0);
    assert!(metric("encompute_key_cache_evictions_total") >= 2.0);
    assert_eq!(metric("encompute_key_cache_entries"), 1.0);
    assert!(metric("encompute_key_cache_bytes") <= (size * 3 / 2) as f64);
    assert!(!text.contains(a.key_id()) && !text.contains(b.key_id()));
}
