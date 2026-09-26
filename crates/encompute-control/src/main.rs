//! `encompute-control`: the control plane service.
//!
//!     encompute-control serve              start the API (and background work)
//!     encompute-control migrate            apply database migrations
//!     encompute-control verify-state       check the database extends the state anchor
//!     encompute-control bootstrap --issuer ISS --subject SUB [--email E]
//!     encompute-control recover --operator NAME
//!     encompute-control dev-token --subject SUB      (development only)
//!     encompute-control public-key FILE              a service key file's public key
//!
//! Configuration and secrets come from the environment and mounted files
//! (see `config.rs` and docs/deployment.md), never from arguments.

use std::process::ExitCode;
use std::sync::Arc;

use encompute_control::config::Config;
use encompute_control::control::Control;
use encompute_ir::{Code, Error};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn run(args: &[String]) -> Result<(), Error> {
    let cmd = args.first().map(String::as_str).unwrap_or("");
    if cmd == "public-key" {
        // The public key of a service key file (for registration): never
        // prints the secret.
        let file = args
            .get(1)
            .ok_or_else(|| Error::new(Code::BadInput, "public-key FILE"))?;
        let s =
            encompute_verification::ServiceSigner::from_file("any", std::path::Path::new(file))?;
        println!("{}", s.public_key_hex());
        return Ok(());
    }
    if cmd == "dev-token" {
        let secret =
            encompute_control::config::secret("ENCOMPUTE_DEV_TOKEN_SECRET")?.ok_or_else(|| {
                Error::new(
                    Code::InsecureConfiguration,
                    "set ENCOMPUTE_DEV_TOKEN_SECRET",
                )
            })?;
        if std::env::var("ENCOMPUTE_ENV").as_deref() == Ok("production") {
            return Err(Error::new(
                Code::InsecureConfiguration,
                "no development tokens in production mode",
            ));
        }
        let sub = arg(args, "--subject").ok_or_else(|| Error::new(Code::BadInput, "--subject"))?;
        println!(
            "{}",
            encompute_control::authn::dev_token(&secret, &sub, 12 * 3600)?
        );
        return Ok(());
    }
    let cfg = Config::from_env()?;
    match cmd {
        "migrate" => {
            let db = encompute_control::db::Db::connect(&cfg.database_url)?;
            println!("schema version {}", db.migrate()?);
        }
        "verify-state" => {
            Control::start(&cfg)?;
            println!("STATE VERIFIED: the database extends the state anchor");
        }
        "bootstrap" => {
            let c = Control::start(&cfg)?;
            let issuer =
                arg(args, "--issuer").ok_or_else(|| Error::new(Code::BadInput, "--issuer"))?;
            let subject =
                arg(args, "--subject").ok_or_else(|| Error::new(Code::BadInput, "--subject"))?;
            let id = c.bootstrap(&issuer, &subject, arg(args, "--email").as_deref())?;
            println!("platform admin {id}");
        }
        "recover" => {
            let operator =
                arg(args, "--operator").ok_or_else(|| Error::new(Code::BadInput, "--operator"))?;
            // Recovery opens the database without the startup check.
            let db = encompute_control::db::Db::connect(&cfg.database_url)?;
            db.migrate()?;
            let signer = encompute_control::control::load_signer(&cfg)?;
            let store = encompute_control::anchor::open_store(&cfg.anchor)?;
            let c = Control::for_recovery(&cfg, db, signer, store)?;
            for n in c.recover(&operator)? {
                println!("{n}");
            }
            c.verify_state(true)?;
            println!("RECOVERED: frozen ledgers are treated as exhausted");
        }
        "serve" => {
            let c = Arc::new(Control::start(&cfg)?);
            c.run_background();
            let workers = std::env::var("ENCOMPUTE_WORKERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8);
            encompute_control::api::serve(c, &cfg.listen, workers)?;
        }
        _ => {
            eprintln!("usage: encompute-control serve | migrate | verify-state | bootstrap --issuer ISS --subject SUB | recover --operator NAME | dev-token --subject SUB");
            return Err(Error::new(Code::BadInput, "unknown command"));
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error[{}]: {}", e.code.as_str(), e.message);
            ExitCode::from(2)
        }
    }
}
