//! A simple benchmark of the privacy spend's latency (anchored before it
//! returns): `cargo test -p encompute-control --test spend_latency --
//! --ignored --nocapture`. Prints the p50, p95 and p99 of sequential spends
//! on one ledger, and of eight concurrent spenders on eight ledgers.

mod common;

use std::time::Instant;

use common::*;

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[(((v.len() - 1) as f64) * p).round() as usize]
}

fn report(what: &str, v: &mut [f64]) {
    eprintln!(
        "SPEND LATENCY {what}: n={} p50={:.2}ms p95={:.2}ms p99={:.2}ms",
        v.len(),
        pct(v, 0.50),
        pct(v, 0.95),
        pct(v, 0.99)
    );
}

#[test]
#[ignore = "a benchmark"]
fn spend_latency() {
    let Some(w) = world() else { return };
    let n: usize = std::env::var("SPENDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    w.t.control.spend_limit.set(u32::MAX);
    let d = w.dataset_a.clone();
    let mut lat = vec![];
    for i in 0..n {
        let t0 = Instant::now();
        let (s, v) = w.t.call(
            &w.a_owner,
            "POST",
            &format!("/v1/privacy/{d}/events"),
            Some(reserve(&format!("b-{i}"), 40_000_000)),
        );
        assert_eq!(s, 200, "{v}");
        lat.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    report("sequential", &mut lat);
    // Eight spenders on eight ledgers at once.
    let ledgers: Vec<String> = (0..8)
        .map(|i| {
            w.t.ok(
                &w.a_owner,
                "POST",
                "/v1/assets",
                Some(serde_json::json!({"organization": "hospital-a", "kind": "dataset",
                    "name": format!("bench-{i}"), "digest": format!("{i:x}").repeat(64)[..64].to_string(),
                    "privacy_budget": budget(3.0)})),
            )["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    let per = n / 4;
    let all = std::sync::Mutex::new(vec![]);
    std::thread::scope(|s| {
        for (k, l) in ledgers.iter().enumerate() {
            let (w, all) = (&w, &all);
            s.spawn(move || {
                let mut mine = vec![];
                for i in 0..per {
                    let t0 = Instant::now();
                    let (st, v) = w.t.call(
                        &w.a_owner,
                        "POST",
                        &format!("/v1/privacy/{l}/events"),
                        Some(reserve(&format!("c-{k}-{i}"), 40_000_000)),
                    );
                    assert_eq!(st, 200, "{v}");
                    mine.push(t0.elapsed().as_secs_f64() * 1000.0);
                }
                all.lock().unwrap().extend(mine);
            });
        }
    });
    report("8 concurrent ledgers", &mut all.into_inner().unwrap());
    for l in w.t.control.metrics.render().lines() {
        if l.contains("mirror_write_seconds") {
            eprintln!("{l}");
        }
    }
}
