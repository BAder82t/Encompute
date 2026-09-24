//! `encompute-evaluator`: the evaluator service. Holds no secret key and
//! links no client crypto (0.2 plan, D1/D2).
//!
//!     encompute-evaluator serve <program.eir | model.encompute/>... [--listen ADDR]
//!                               [--backend openfhe|mock] [--workers N]
//!     encompute-evaluator worker --backend openfhe|mock     (started by serve)

use std::process::ExitCode;
use std::sync::Arc;

use encompute_evaluator::engine::{Engine, Local};
use encompute_evaluator::pool::{run_worker, Pool};
use encompute_evaluator::server::{Evaluator, Limits};
use encompute_evaluator::BackendKind;

fn usage() -> ExitCode {
    eprintln!(
        "usage: encompute-evaluator serve <program.eir | model.encompute/>... \
         [--listen 127.0.0.1:8750] [--backend openfhe|mock] [--workers N]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().cloned() else {
        return usage();
    };
    let mut listen = "127.0.0.1:8750".to_owned();
    let mut backend = if cfg!(feature = "openfhe") {
        "openfhe"
    } else {
        "mock"
    }
    .to_owned();
    let mut workers = 0usize;
    let mut programs = vec![];
    let mut it = args.into_iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => listen = it.next().unwrap_or_default(),
            "--backend" => backend = it.next().unwrap_or_default(),
            "--workers" => match it.next().and_then(|n| n.parse().ok()) {
                Some(n) => workers = n,
                None => return usage(),
            },
            _ if a.starts_with("--") => return usage(),
            _ => programs.push(a),
        }
    }
    let kind = match backend.as_str() {
        "openfhe" => BackendKind::OpenFhe,
        "mock" => BackendKind::Mock,
        _ => return usage(),
    };
    match cmd.as_str() {
        "worker" => match run_worker(kind) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("worker: {e}");
                ExitCode::from(1)
            }
        },
        "serve" => serve(kind, &backend, &listen, workers, &programs),
        _ => usage(),
    }
}

fn serve(
    kind: BackendKind,
    backend: &str,
    listen: &str,
    workers: usize,
    programs: &[String],
) -> ExitCode {
    let engine: Arc<dyn Engine> = if workers == 0 {
        Arc::new(Local::new(kind))
    } else {
        let exe = std::env::current_exe().expect("own path");
        match Pool::start(kind, exe, workers) {
            Ok(p) => Arc::new(p),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        }
    };
    let ev = Evaluator::with_engine(engine, Limits::default(), workers);
    for p in programs {
        let path = std::path::Path::new(p);
        let file = if path.is_dir() {
            path.join("program.eir")
        } else {
            path.to_owned()
        };
        let loaded = std::fs::read_to_string(&file)
            .map_err(|e| format!("{}: {e}", file.display()))
            .and_then(|t| ev.add_program(&t).map_err(|e| e.to_string()));
        match loaded {
            Ok(id) => eprintln!("loaded {} as program {id}", file.display()),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        }
    }
    let server = match tiny_http::Server::http(listen) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot listen on {listen}: {e}");
            return ExitCode::from(2);
        }
    };
    let addr = server
        .server_addr()
        .to_ip()
        .map_or(listen.to_owned(), |a| a.to_string());
    let mode = if workers == 0 {
        "in-process".to_owned()
    } else {
        format!("{workers} worker processes")
    };
    eprintln!(
        "encompute-evaluator ({backend}, {mode}) listening on http://{addr}; holds no secret keys; \
         no TLS, use a TLS proxy for remote clients"
    );
    ev.serve(server);
    ExitCode::SUCCESS
}
