//! Throughput of the evaluator: in-process (OpenFHE serialized) vs worker
//! processes, with concurrent clients over HTTP.
//!
//!     cargo run --release --features openfhe -p encompute-runtime --example concurrency -- \
//!         target/release/encompute-evaluator <model.encompute> [jobs] [clients]

use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use encompute_runtime::{sample_inputs, ClientSession, Mode, Model, Remote};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (exe, model) = (&args[1], args[2].clone());
    let jobs: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(32);
    let clients: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(8);
    let m = Model::load(std::path::Path::new(&model)).expect("artifact");
    let client = m.new_client(Mode::Encrypted).expect("keys");
    let secret = Arc::new(client.secret_key_envelope().expect("secret"));
    // Each client thread restores its own client from the secret key.
    let restore = |m: &Model, secret: &[u8]| {
        ClientSession::restore(m.ids(), m.compiled(), secret).expect("restore")
    };
    let cores = std::thread::available_parallelism().map_or(1, |c| c.get());
    println!(
        "model {} ({} jobs, {clients} concurrent clients, {cores} cores)",
        m.program().name(),
        jobs
    );
    println!(
        "{:<22} {:>10} {:>12} {:>12} {:>14}",
        "evaluator", "jobs/s", "p50 ms", "p95 ms", "peak RSS/proc"
    );

    for (port, workers) in [(18760u16, 0usize), (18761, 1), (18762, 2), (18763, 4)] {
        let _server = Server(
            Command::new(exe)
                .args([
                    "serve",
                    &model,
                    "--listen",
                    &format!("127.0.0.1:{port}"),
                    "--workers",
                    &workers.to_string(),
                ])
                .stderr(Stdio::null())
                .spawn()
                .expect("evaluator"),
        );
        let url = format!("http://127.0.0.1:{port}");
        let remote = Remote::new(&url);
        let t0 = Instant::now();
        while remote.info().is_err() {
            assert!(
                t0.elapsed() < Duration::from_secs(60),
                "evaluator did not start"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // Warm-up: registers keys in every worker.
        let inputs = sample_inputs(m.program(), 2, 0);
        remote
            .run(&client, m.program(), None, &inputs)
            .expect("warm-up");

        let start = Instant::now();
        let per = jobs.div_ceil(clients);
        let handles: Vec<_> = (0..clients)
            .map(|c| {
                let (model, secret, url) = (model.clone(), secret.clone(), url.clone());
                std::thread::spawn(move || {
                    let m = Model::load(std::path::Path::new(&model)).expect("artifact");
                    let client = restore(&m, &secret);
                    let remote = Remote::new(&url);
                    let (mut lat, mut rss) = (vec![], 0u64);
                    for j in 0..per {
                        let inputs = sample_inputs(m.program(), 3 + c * per + j, 1);
                        let t = Instant::now();
                        let (_, stats) = remote
                            .run(&client, m.program(), None, &inputs)
                            .expect("job");
                        lat.push(t.elapsed().as_secs_f64() * 1e3);
                        rss = rss.max(stats.evaluator_peak_rss_bytes);
                    }
                    (lat, rss)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let rss = results.iter().map(|r| r.1).max().unwrap_or(0);
        let mut lat: Vec<f64> = results.into_iter().flat_map(|r| r.0).collect();
        let secs = start.elapsed().as_secs_f64();
        lat.sort_by(f64::total_cmp);
        let name = if workers == 0 {
            "in-process".to_owned()
        } else {
            format!("{workers} worker processes")
        };
        println!(
            "{name:<22} {:>10.2} {:>12.1} {:>12.1} {:>14}",
            lat.len() as f64 / secs,
            lat[lat.len() / 2],
            lat[lat.len() * 95 / 100],
            format!("{} MiB", rss >> 20)
        );
    }
}
