//! `encompute-evaluator`: the evaluator service. Holds no secret key and
//! links no client crypto.
//!
//!     encompute-evaluator serve <program.eir | model.encompute/>... [--listen ADDR]
//!                               [--backend mock|openfhe|openfhe-exact|tfhe-rs]... [--workers N]
//!                               [--identity FILE] [--attestation FILE]
//!     encompute-evaluator worker --backend …     (started by serve)
//!
//! Each program runs on the backend for its semantics: approximate programs
//! on OpenFHE CKKS, exact ones on OpenFHE exact (BinFHE), where built;
//! `--backend mock` serves both on the mock. `tfhe-rs` exists only in
//! research builds.
//!
//! `--identity FILE` holds the evaluator's receipt-signing key (created,
//! mode 0600, if missing). Without it the identity is ephemeral and clients
//! that pinned it will refuse receipts after a restart. `--attestation
//! FILE` is the attestation record of the workload session this evaluator
//! runs in (it must bind the identity's key); receipts then bind it.

use std::process::ExitCode;
use std::sync::Arc;

use encompute_attestation::AttestationRecord;
use encompute_evaluator::control::ControlLink;
use encompute_evaluator::engine::{Engine, Local};
use encompute_evaluator::pool::{run_worker, Pool};
use encompute_evaluator::server::{Evaluator, Limits};
use encompute_evaluator::{BackendKind, Backends};
use encompute_verification::EvaluatorSigner;

fn usage() -> ExitCode {
    eprintln!(
        "usage: encompute-evaluator serve <program.eir | model.encompute/>... \
         [--listen 127.0.0.1:8750] [--backend mock|openfhe|openfhe-exact|tfhe-rs]... [--workers N] \
         [--identity FILE] [--attestation FILE]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().cloned() else {
        return usage();
    };
    let mut listen = "127.0.0.1:8750".to_owned();
    let mut backends = Backends::for_build();
    let mut workers = 0usize;
    let mut identity: Option<String> = None;
    let mut attestation: Option<String> = None;
    let mut programs = vec![];
    let mut it = args.into_iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => listen = it.next().unwrap_or_default(),
            "--backend" | "--approx-backend" | "--exact-backend" => {
                let value = it.next().unwrap_or_default();
                match BackendKind::parse(&value) {
                    Some(k) if !k.built() => {
                        if k == BackendKind::TfheRs {
                            eprintln!(
                                "error: BACKEND UNAVAILABLE: TFHE-rs is available only in research \
                                 builds (the `research-tfhe-rs` feature)"
                            );
                        } else {
                            eprintln!("error: this evaluator was built without {}", k.name());
                        }
                        return ExitCode::from(2);
                    }
                    _ => match backends.apply(&a, &value) {
                        Some(b) => backends = b,
                        None => return usage(),
                    },
                }
            }
            "--identity" => identity = it.next(),
            "--attestation" => attestation = it.next(),
            "--workers" => match it.next().and_then(|n| n.parse().ok()) {
                Some(n) => workers = n,
                None => return usage(),
            },
            _ if a.starts_with("--") => return usage(),
            _ => programs.push(a),
        }
    }
    match cmd.as_str() {
        "worker" => match run_worker(backends) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("worker: {e}");
                ExitCode::from(1)
            }
        },
        "serve" => match load_identity(identity.as_deref()) {
            Ok(signer) => serve(
                backends,
                &listen,
                workers,
                &programs,
                signer,
                attestation.as_deref(),
            ),
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
        _ => usage(),
    }
}

/// The receipt-signing key: read from `path`, created there if missing, or
/// ephemeral without a path.
fn load_identity(path: Option<&str>) -> Result<EvaluatorSigner, String> {
    let Some(path) = path else {
        eprintln!("notice: ephemeral evaluator identity; use --identity FILE to keep it");
        return EvaluatorSigner::generate().map_err(|e| e.to_string());
    };
    #[cfg(unix)]
    if let Ok(m) = std::fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = m.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{path} is mode {mode:o}: the signing key must not be readable by others (chmod 600)"
            ));
        }
    }
    match std::fs::read(path) {
        Ok(b) => {
            let seed: [u8; 32] = b
                .try_into()
                .map_err(|_| format!("{path}: not an evaluator identity (32 bytes)"))?;
            Ok(EvaluatorSigner::from_seed(&seed))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let signer = EvaluatorSigner::generate().map_err(|e| e.to_string())?;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            use std::io::Write;
            opts.open(path)
                .and_then(|mut f| f.write_all(&signer.seed()))
                .map_err(|e| format!("{path}: {e}"))?;
            eprintln!("created evaluator identity {path}");
            Ok(signer)
        }
        Err(e) => Err(format!("{path}: {e}")),
    }
}

/// The backends and parameter profiles this build registers. Mock and
/// research backends are never offered to a control plane.
fn capabilities(b: Backends) -> (Vec<&'static str>, Vec<&'static str>) {
    let mut caps = vec![];
    let mut profiles = vec![];
    if b.approx == BackendKind::OpenFhe {
        caps.push("openfhe");
        profiles.push(encompute_evaluator::CKKS_PROFILE);
    }
    if b.exact == BackendKind::OpenFheExact {
        caps.push("openfhe-exact");
        profiles.push(encompute_exact::bits::OPENFHE_EXACT_PROFILE);
    }
    (caps, profiles)
}

fn serve(
    backends: Backends,
    listen: &str,
    workers: usize,
    programs: &[String],
    signer: EvaluatorSigner,
    attestation: Option<&str>,
) -> ExitCode {
    let engine: Arc<dyn Engine> = if workers == 0 {
        Arc::new(Local::new(backends))
    } else {
        let exe = std::env::current_exe().expect("own path");
        match Pool::start(backends, exe, workers) {
            Ok(p) => Arc::new(p),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        }
    };
    let evaluator_id = signer.identity().evaluator_id();
    let receipt_key = signer.identity().public_key_hex();
    let mut ev = Evaluator::with_engine(engine, Limits::default(), workers, signer);
    if let Some(path) = attestation {
        let record = std::fs::read(path)
            .map_err(|e| format!("{path}: {e}"))
            .and_then(|b| AttestationRecord::from_bytes(&b).map_err(|e| format!("{path}: {e}")));
        match record.and_then(|r| ev.with_attestation(r).map_err(|e| e.to_string())) {
            Ok(attested) => ev = attested,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        }
    }
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
        "encompute-evaluator (approximate: {}, exact: {}; {mode}) listening on http://{addr}; \
         holds no secret keys; no TLS, use a TLS proxy for remote clients",
        backends.approx.name(),
        backends.exact.name()
    );
    eprintln!("evaluator identity enc-eval:{evaluator_id} (signs execution receipts)");
    if backends.exact == BackendKind::TfheRs {
        eprintln!(
            "notice: the TFHE-rs backend is for research use only; commercial use needs a \
             patent license from Zama (see THIRD_PARTY_NOTICES.md)"
        );
    }
    match ControlLink::from_env() {
        Ok(None) => {}
        Ok(Some(link)) => {
            let link = Arc::new(link);
            let (caps, profiles) = capabilities(backends);
            let advertise = std::env::var("ENCOMPUTE_ADVERTISE_URL")
                .unwrap_or_else(|_| format!("http://{addr}"));
            let capacity = std::env::var("ENCOMPUTE_CAPACITY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(workers.max(1) as u32);
            // The control plane may still be starting: retry for a minute.
            let mut registered = Err(encompute_ir::Error::new(
                encompute_ir::Code::Remote,
                "not tried",
            ));
            for _ in 0..30 {
                registered = link.register(&advertise, &receipt_key, &caps, &profiles, capacity);
                if !matches!(&registered, Err(e) if e.code == encompute_ir::Code::Remote) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            if let Err(e) = registered {
                eprintln!(
                    "error[{}]: registering with the control plane: {}",
                    e.code.as_str(),
                    e.message
                );
                return ExitCode::from(2);
            }
            eprintln!(
                "registered with the control plane as {} ({}; {}; capacity {capacity}); runs granted jobs only",
                link.id(),
                caps.join(", "),
                profiles.join(", ")
            );
            link.run(std::time::Duration::from_secs(10));
            ev = ev.with_control(link);
        }
        Err(e) => {
            eprintln!("error[{}]: {}", e.code.as_str(), e.message);
            return ExitCode::from(2);
        }
    }
    ev.serve(server);
    ExitCode::SUCCESS
}
