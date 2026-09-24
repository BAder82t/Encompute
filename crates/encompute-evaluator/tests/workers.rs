//! Worker processes: concurrent jobs, crash isolation, restart with replay.
//! Uses the mock backend and builds client envelopes directly (this crate
//! must not depend on the client runtime).

use std::path::PathBuf;
use std::sync::Arc;

use encompute_backend::{CkksClient, MockClient, MockConfig};
use encompute_evaluator::engine::Engine;
use encompute_evaluator::pool::Pool;
use encompute_evaluator::{BackendKind, EvaluatorSession};
use encompute_ir::{Builder, Program, Range, Shape};
use encompute_protocol::{sha256_hex, Envelope, Header, Kind};

fn program() -> Program {
    let mut b = Builder::new("w", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(4), Range::new(-1.0, 1.0))
        .unwrap();
    let w = b
        .constant(Shape::Vector(4), vec![0.5, -1.0, 0.25, 2.0])
        .unwrap();
    let d = b.dot(w, x).unwrap();
    b.output("d", d).unwrap();
    b.finish().unwrap()
}

fn header(kind: Kind, ids: &encompute_evaluator::Ids, key_id: &str) -> Header {
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

fn exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_encompute-evaluator"))
}

#[test]
fn concurrent_jobs_crash_isolation_and_replay() {
    let p = program();
    let local = EvaluatorSession::new(p.clone(), BackendKind::Mock).unwrap();
    let (ids, plan, params) = (
        local.ids().clone(),
        local.compiled().plan.clone(),
        local.compiled().params.clone(),
    );
    let client = MockClient::new(
        &params,
        &plan.rotations,
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

    let pool = Arc::new(Pool::start(BackendKind::Mock, exe(), 3).unwrap());
    assert_eq!(
        pool.add_program(&p.to_string()).unwrap().program_id,
        ids.program_id
    );
    assert_eq!(pool.register_keys(&ids.program_id, &keys).unwrap(), key_id);
    let pids = pool.worker_pids();
    assert!(pids.iter().all(Option::is_some));

    let request = |v: f64| {
        let x = vec![v, 0.5, -0.5, 0.25];
        let ct = client.encrypt(&plan.encode_input(0, &x)).unwrap();
        (
            Envelope::new(header(Kind::Inputs, &ids, &key_id), vec![("x".into(), ct)]).encode(),
            0.5 * v - 0.5 - 0.125 + 0.5,
        )
    };
    let decrypt = |out: &[u8]| {
        let env = Envelope::decode(out).unwrap();
        client.decrypt(env.items()[0].1).unwrap()[0]
    };

    // 24 concurrent jobs over 3 workers.
    let handles: Vec<_> = (0..24)
        .map(|i| {
            let (pool, pid) = (pool.clone(), ids.program_id.clone());
            let (req, want) = request(i as f64 / 24.0);
            std::thread::spawn(move || (pool.execute(&pid, &req).unwrap().0, want))
        })
        .collect();
    for h in handles {
        let (out, want) = h.join().unwrap();
        assert!((decrypt(&out) - want).abs() < 1e-3);
    }

    // Kill every worker process; the pool restarts each on next use and
    // replays the program and keys, so later jobs succeed.
    for pid in pids.into_iter().flatten() {
        let _ = std::process::Command::new("kill")
            .arg("-9")
            .arg(pid.to_string())
            .status();
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
    let mut failures = 0;
    for i in 0..9 {
        let (req, want) = request(i as f64 / 9.0);
        match pool.execute(&ids.program_id, &req) {
            Ok((out, _)) => assert!((decrypt(&out) - want).abs() < 1e-3),
            Err(e) => {
                assert!(e.message.contains("restarted"), "{e}");
                failures += 1;
            }
        }
    }
    assert!(
        failures <= 3,
        "at most one failed job per killed worker, got {failures}"
    );
    let new_pids = pool.worker_pids();
    assert!(
        new_pids.iter().flatten().count() == 3,
        "all workers restarted: {new_pids:?}"
    );
}
