//! `encompute-evaluator`: the evaluator service. Holds no secret key and
//! links no client crypto (0.2 plan, D1/D2).
//!
//!     encompute-evaluator serve <program.eir | model.encompute/> [--listen ADDR] [--backend openfhe|mock]

use std::process::ExitCode;

use encompute_evaluator::server::{Evaluator, Limits};
use encompute_evaluator::BackendKind;

fn usage() -> ExitCode {
    eprintln!(
        "usage: encompute-evaluator serve <program.eir | model.encompute/> \
         [--listen 127.0.0.1:8750] [--backend openfhe|mock]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("serve") {
        return usage();
    }
    let mut listen = "127.0.0.1:8750".to_owned();
    let mut backend = if cfg!(feature = "openfhe") {
        "openfhe"
    } else {
        "mock"
    }
    .to_owned();
    let mut programs = vec![];
    let mut it = args.into_iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => listen = it.next().unwrap_or_default(),
            "--backend" => backend = it.next().unwrap_or_default(),
            _ if a.starts_with("--") => return usage(),
            _ => programs.push(a),
        }
    }
    let kind = match backend.as_str() {
        "openfhe" => BackendKind::OpenFhe,
        "mock" => BackendKind::Mock,
        _ => return usage(),
    };
    let mut ev = Evaluator::new(kind, Limits::default());
    for p in &programs {
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
    let server = match tiny_http::Server::http(&listen) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot listen on {listen}: {e}");
            return ExitCode::from(2);
        }
    };
    let addr = server
        .server_addr()
        .to_ip()
        .map(|a| a.to_string())
        .unwrap_or(listen);
    eprintln!("encompute-evaluator ({backend}) listening on http://{addr} — holds no secret keys; no TLS, use a TLS proxy for remote clients");
    ev.serve(server);
    ExitCode::SUCCESS
}
