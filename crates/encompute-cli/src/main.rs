//! `encompute` command-line tool.

mod aggregate;
mod attest;
mod trust;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};
use encompute_ir::{Code, Error, Inputs, Result};
use encompute_runtime::verification::{
    output_commitment, request_commitment, EvaluatorIdentity, ExecutionProof,
    SignedExecutionReceipt, VerificationState,
};
use encompute_runtime::{BackendKind, BenchDetail, ClientSession, Mode, Model, Remote, TestReport};

#[derive(Parser)]
#[command(
    name = "encompute",
    version,
    about = "Compiler and runtime for private computation"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compile a `.eir` file, or a Python function `file.py:function`, into a `.encompute` artifact.
    Compile {
        source: String,
        /// Output directory (default: <name>.encompute next to the source).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Run a model on inputs, e.g. `--input x=0.5,-1,0.25` or `--input ok=true`.
    Run {
        model: PathBuf,
        #[arg(short, long = "input", value_name = "NAME=V1,V2,...")]
        inputs: Vec<String>,
        /// JSON file mapping input names to numbers or lists.
        #[arg(long)]
        inputs_file: Option<PathBuf>,
        #[arg(long, default_value = "clear")]
        mode: String,
        /// Evaluator URL: encrypt here, compute there, decrypt here.
        #[arg(long)]
        remote: Option<String>,
        /// Key directory from `encompute keys generate` (with --remote).
        #[arg(long)]
        keys: Option<PathBuf>,
        /// Evaluator public key (hex) to trust for receipts. Default: the key
        /// pinned in the key directory (evaluator.pub), pinned on first use.
        #[arg(long)]
        trust_evaluator: Option<String>,
        /// Write the evaluator's signed receipt here (with --remote).
        #[arg(long)]
        save_receipt: Option<PathBuf>,
        /// Write the exchanged request.bin and response.bin here, so
        /// `encompute verify` can check the receipt's commitments later.
        #[arg(long)]
        save_envelopes: Option<PathBuf>,
    },
    /// Confidentiality: who owns each value, who may learn it, what it may
    /// be used for, and where it goes.
    Privacy {
        #[command(subcommand)]
        cmd: PrivacyCmd,
    },
    /// Print the semantic transcript of an exact program: the operations a
    /// future execution proof must follow. Never contains runtime values.
    Transcript {
        model: PathBuf,
        /// Backend of the execution spec (default: the artifact's target,
        /// tfhe-rs; mock runs use `--backend mock`).
        #[arg(long)]
        backend: Option<String>,
        /// Canonical JSON instead of the listing.
        #[arg(long)]
        json: bool,
    },
    /// Check a saved execution receipt: signature, evaluator, and (when
    /// given) the artifact, request and response it binds. A receipt is a
    /// signed claim, not a proof of correct execution.
    Verify {
        receipt: PathBuf,
        /// The artifact the receipt should be for.
        #[arg(long)]
        model: Option<PathBuf>,
        /// The inputs envelope sent (from --save-envelopes).
        #[arg(long)]
        request: Option<PathBuf>,
        /// The outputs envelope received.
        #[arg(long)]
        response: Option<PathBuf>,
        /// Evaluator public key (hex) you trust.
        #[arg(long)]
        trust_evaluator: Option<String>,
        /// The backend you expected (mock, openfhe, tfhe-rs). Default: from
        /// the request envelope, which you made; never from the receipt.
        #[arg(long)]
        backend: Option<String>,
        /// Execution proof (`proof.bin` from --save-envelopes): verified by
        /// re-execution (research build).
        #[arg(long)]
        proof: Option<PathBuf>,
        /// Your evaluation keys (`eval.keys`), needed to verify a proof.
        #[arg(long)]
        evaluation_keys: Option<PathBuf>,
        /// The attestation record the receipt binds (from the evaluator's
        /// `/v1/attestation`).
        #[arg(long)]
        attestation: Option<PathBuf>,
        /// The attestation policy the workload must satisfy.
        #[arg(long)]
        attestation_policy: Option<PathBuf>,
        #[command(flatten)]
        trust: attest::TrustArgs,
    },
    /// Verify workload attestation evidence; write attestation policies.
    Attest {
        #[command(subcommand)]
        cmd: attest::AttestCmd,
    },
    /// The trust graph: assets, owners' authorizations, lineage and every
    /// piece of evidence, checked as one trust report.
    Trust {
        #[command(subcommand)]
        cmd: trust::TrustCmd,
    },
    /// Secure aggregation rounds: coordinate, contribute, verify.
    Aggregate {
        #[command(subcommand)]
        cmd: aggregate::AggregateCmd,
    },
    /// Inside a TEE: attest and receive asset keys from key brokers.
    Workload {
        #[command(subcommand)]
        cmd: attest::WorkloadCmd,
    },
    /// Manage client keys, and protect asset keys in a key broker.
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Start an evaluator for a model (runs `encompute-evaluator serve`).
    Serve {
        model: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8750")]
        listen: String,
        /// mock, openfhe or tfhe-rs (default: real cryptography where built).
        #[arg(long)]
        backend: Vec<String>,
    },
    /// Check an artifact (and optionally keys and the evaluator binary) against the security model.
    Audit {
        model: PathBuf,
        #[arg(long)]
        keys: Option<PathBuf>,
        #[arg(long)]
        evaluator: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Compare encrypted (or mock) execution with plaintext on sampled inputs.
    Test {
        model: PathBuf,
        #[arg(long, default_value_t = 1000)]
        cases: usize,
        #[arg(long, default_value_t = 42)]
        seed: u64,
        #[arg(long, default_value = "mock")]
        mode: String,
        #[arg(long)]
        json: bool,
    },
    /// Show the execution plan, parameters and precision.
    Explain {
        model: PathBuf,
        /// Also measure the error over this many cases.
        #[arg(long)]
        measure: Option<usize>,
        #[arg(long, default_value = "mock")]
        mode: String,
        /// Preview the next differential-privacy release against the
        /// ledgers in this directory.
        #[arg(long)]
        ledger: Option<PathBuf>,
    },
    /// Time keygen, encryption, evaluation and decryption.
    Bench {
        model: PathBuf,
        #[arg(long, default_value_t = 5)]
        reps: usize,
        #[arg(long, default_value = "mock")]
        mode: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PrivacyCmd {
    /// Parties, assets with their derived policies, flows and warnings;
    /// with `--ledger`, each budget's spent, remaining and next release.
    Explain {
        model: PathBuf,
        /// The coordinator's privacy ledger directory.
        #[arg(long)]
        ledger: Option<PathBuf>,
    },
    /// The confidentiality graph (Graphviz DOT).
    Graph {
        model: PathBuf,
        #[arg(long, default_value = "dot")]
        format: String,
    },
    /// Differential-privacy budgets: spent, remaining, and every release,
    /// from the privacy ledgers.
    Budget {
        /// The coordinator's ledger directory.
        #[arg(long)]
        ledger: PathBuf,
        /// One asset only.
        #[arg(long)]
        asset: Option<String>,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Generate a key pair for a model: `secret.key` (stays here, mode 0600)
    /// and `eval.keys` (sent to the evaluator).
    Generate {
        model: PathBuf,
        /// Output directory (default: <name>.keys next to the model).
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "encrypted")]
        mode: String,
    },
    #[command(flatten)]
    Broker(attest::BrokerCmd),
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error[{}]: {}", e.code, e.message);
            ExitCode::from(2)
        }
    }
}

fn load(path: &Path) -> Result<Model> {
    if path.is_dir() {
        Model::load(path)
    } else {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::new(Code::Artifact, format!("{}: {e}", path.display())))?;
        Model::from_eir(&text)
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Cmd::Compile { source, output } => compile(&source, output),
        Cmd::Run {
            model,
            inputs,
            inputs_file,
            mode,
            remote,
            keys,
            trust_evaluator,
            save_receipt,
            save_envelopes,
        } => {
            let m = load(&model)?;
            let inputs = parse_inputs(&inputs, inputs_file.as_deref())?;
            let out = match remote {
                None => m.run(mode.parse()?, &inputs)?,
                Some(url) => {
                    let dir = keys.ok_or_else(|| {
                        Error::new(
                            Code::WrongKey,
                            "--remote needs --keys DIR (encompute keys generate)",
                        )
                    })?;
                    let read = |f: &str| {
                        std::fs::read(dir.join(f)).map_err(|e| {
                            Error::new(Code::WrongKey, format!("{}: {e}", dir.join(f).display()))
                        })
                    };
                    let mut client =
                        ClientSession::restore(m.ids(), m.compiled(), &read("secret.key")?)?;
                    let eval_keys = read("eval.keys").ok();
                    // Needed to verify execution proofs by re-execution.
                    if let Some(k) = &eval_keys {
                        client.attach_evaluation_keys(k)?;
                    }
                    let remote = Remote::new(&url);
                    let trusted = trusted_evaluator(&remote, &dir, trust_evaluator.as_deref())?;
                    let run = remote.run(
                        &client,
                        m.program(),
                        eval_keys.as_deref(),
                        &inputs,
                        &trusted,
                    )?;
                    let stats = &run.stats;
                    eprintln!(
                        "remote: request {} KiB, response {} KiB, keys uploaded {} KiB, evaluator {:.1} ms, round trip {:.1} ms",
                        stats.request_bytes / 1024,
                        stats.response_bytes / 1024,
                        stats.evaluation_key_bytes_uploaded / 1024,
                        stats.evaluator_ms,
                        stats.round_trip_ms
                    );
                    eprintln!("Evaluator receipt       verified");
                    match (&run.state, &run.proof) {
                        (VerificationState::ExecutionVerified(v), _) => {
                            eprintln!(
                                "Execution proof         verified ({}, {})",
                                v.protocol(),
                                v.relation()
                            );
                            eprintln!("Encrypted result        accepted");
                            eprintln!("VERIFIED PRIVATE EXECUTION");
                        }
                        _ => {
                            eprintln!("Execution proof         not present");
                            eprintln!("Encrypted result        accepted (receipt only)");
                        }
                    }
                    let io = |p: &Path, e: std::io::Error| {
                        Error::new(Code::Artifact, format!("{}: {e}", p.display()))
                    };
                    if let Some(p) = &save_receipt {
                        std::fs::write(p, run.receipt.to_bytes()?).map_err(|e| io(p, e))?;
                    }
                    if let Some(d) = &save_envelopes {
                        std::fs::create_dir_all(d).map_err(|e| io(d, e))?;
                        std::fs::write(d.join("request.bin"), &run.request)
                            .map_err(|e| io(d, e))?;
                        std::fs::write(d.join("response.bin"), &run.response)
                            .map_err(|e| io(d, e))?;
                        if let Some(p) = &run.proof {
                            std::fs::write(d.join("proof.bin"), p.to_bytes()?)
                                .map_err(|e| io(d, e))?;
                        }
                    }
                    run.outputs
                }
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&m.outputs_json(&out)).unwrap()
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Privacy {
            cmd: PrivacyCmd::Budget { ledger, asset },
        } => {
            print!(
                "{}",
                encompute_runtime::privacy_budget_report(&ledger, asset.as_deref())?
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Privacy { cmd } => {
            let (m, out) = match cmd {
                PrivacyCmd::Explain { model, ledger } => {
                    let m = load(&model)?;
                    let mut out = m.privacy_explain()?;
                    if let (Some(text), Some(dir)) = (out.as_mut(), ledger) {
                        text.push('\n');
                        text.push_str(&m.privacy_status(&dir)?);
                    }
                    (m, out)
                }
                PrivacyCmd::Graph { model, format } => {
                    if format != "dot" {
                        return Err(Error::new(Code::BadInput, "only --format dot is supported"));
                    }
                    let m = load(&model)?;
                    let out = m.privacy_dot()?;
                    (m, out)
                }
                PrivacyCmd::Budget { .. } => unreachable!("handled above"),
            };
            match out {
                Some(text) => print!("{text}"),
                None => println!(
                    "{} declares no parties or assets: every secret input stays with the client \
                     that encrypts it (see ADR-010 to declare a confidentiality policy)",
                    m.program().name()
                ),
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Transcript {
            model,
            backend,
            json,
        } => {
            let m = load(&model)?;
            let kind = match backend.as_deref() {
                None => BackendKind::TfheRs,
                Some(b) => BackendKind::parse(b)
                    .ok_or_else(|| Error::new(Code::BadInput, format!("unknown backend {b:?}")))?,
            };
            let t = encompute_runtime::verification_transcript(&m, kind).ok_or_else(|| {
                Error::new(
                    Code::Unsupported,
                    "no transcript: CKKS programs are not transcribed yet (exact programs only)",
                )
            })?;
            if json {
                println!(
                    "{}",
                    String::from_utf8(t.canonical_bytes()?).expect("UTF-8")
                );
            } else {
                let section = |t: &str| println!("\n{t}\n{}", "─".repeat(40));
                println!("Transcript v{}", t.transcript_version);
                section("Spec");
                println!(
                    "encspec1:{} ({} {})",
                    t.spec_id,
                    kind.label().0,
                    kind.label().1
                );
                section("Inputs");
                for i in &t.inputs {
                    println!("#{} {:<16} {} {}", i.position, i.name, i.visibility, i.ty);
                }
                section("Instructions");
                print!("{}", t.listing());
                section("Outputs");
                for o in &t.outputs {
                    println!("{:<16} r{} : {}", o.name, o.register, o.ty);
                }
                section("Transcript");
                println!("{}", t.id());
                println!("\nTRANSCRIPT AVAILABLE\nEXECUTION PROOF NOT PRESENT");
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Verify {
            receipt,
            model,
            request,
            response,
            trust_evaluator,
            backend,
            proof,
            evaluation_keys,
            attestation,
            attestation_policy,
            trust,
        } => verify(
            &receipt,
            model.as_deref(),
            request.as_deref(),
            response.as_deref(),
            trust_evaluator.as_deref(),
            backend.as_deref(),
            proof.as_deref(),
            evaluation_keys.as_deref(),
            Attested {
                record: attestation.as_deref(),
                policy: attestation_policy.as_deref(),
                trust: &trust,
            },
        ),
        Cmd::Attest { cmd } => attest::attest(cmd),
        Cmd::Aggregate { cmd } => aggregate::aggregate(cmd),
        Cmd::Trust { cmd } => trust::trust(cmd),
        Cmd::Workload { cmd } => attest::workload(cmd),
        Cmd::Keys {
            cmd: KeysCmd::Broker(cmd),
        } => attest::broker(cmd),
        Cmd::Keys {
            cmd:
                KeysCmd::Generate {
                    model,
                    output,
                    mode,
                },
        } => {
            let m = load(&model)?;
            let client = m.new_client(mode.parse()?)?;
            let dir = output
                .unwrap_or_else(|| model.with_file_name(format!("{}.keys", m.program().name())));
            write_keys(&dir, &client)?;
            println!("wrote {} (key {})", dir.display(), &client.key_id()[..16]);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Audit {
            model,
            keys,
            evaluator,
            json,
        } => {
            use encompute_runtime::audit::{audit, Status};
            let m = load(&model)?;
            let checks = audit(&m, keys.as_deref(), evaluator.as_deref());
            if json {
                println!("{}", serde_json::to_string_pretty(&checks).unwrap());
            } else {
                for c in &checks {
                    let s = serde_json::to_value(c.status).unwrap();
                    println!("{:<5} {:<28} {}", s.as_str().unwrap(), c.id, c.detail);
                }
            }
            Ok(if checks.iter().any(|c| c.status == Status::Fail) {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        Cmd::Serve {
            model,
            listen,
            backend,
        } => {
            let exe = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("encompute-evaluator")))
                .filter(|p| p.exists())
                .unwrap_or_else(|| PathBuf::from("encompute-evaluator"));
            let status = Command::new(&exe)
                .arg("serve")
                .arg(&model)
                .args(["--listen", &listen])
                .args(backend.iter().flat_map(|b| ["--backend", b.as_str()]))
                .status()
                .map_err(|e| {
                    Error::new(Code::Remote, format!("cannot start {}: {e}", exe.display()))
                })?;
            Ok(if status.success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Cmd::Test {
            model,
            cases,
            seed,
            mode,
            json,
        } => {
            let m = load(&model)?;
            let rep = m.test(mode.parse()?, cases, seed)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&rep).unwrap());
            } else {
                print_test(&rep);
            }
            Ok(if rep.passed() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Cmd::Explain {
            model,
            measure,
            mode,
            ledger,
        } => {
            let m = load(&model)?;
            let measured = match measure {
                Some(n) => Some(m.measure(mode.parse()?, n, 3)?),
                None => None,
            };
            print!("{}", m.explain(measured.as_ref()));
            if let Some(dir) = ledger {
                print!("\n{}", m.privacy_preview(&dir)?);
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Bench {
            model,
            reps,
            mode,
            json,
        } => {
            let m = load(&model)?;
            let b = m.bench(mode.parse::<Mode>()?, reps)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&b).unwrap());
            } else {
                let est = if b.sizes_estimated {
                    " (estimated)"
                } else {
                    ""
                };
                match &b.detail {
                    BenchDetail::Approximate {
                        ring_dim,
                        slots,
                        depth,
                        rotation_keys,
                    } => println!(
                        "{} backend, N = {ring_dim}, {slots} slots, depth {depth}, {rotation_keys} rotation keys, median of {}",
                        b.backend, b.reps
                    ),
                    BenchDetail::Exact {
                        parameter_profile,
                        operations,
                    } => {
                        println!(
                            "{} backend (exact), profile {parameter_profile}, median of {}",
                            b.backend, b.reps
                        );
                        let ops: Vec<String> =
                            operations.iter().map(|(k, n)| format!("{n} {k}")).collect();
                        println!("  operations {}", ops.join(", "));
                    }
                }
                println!("  keygen     {:>10.2} ms", b.keygen_ms);
                println!("  encrypt    {:>10.2} ms", b.encrypt_ms);
                println!("  evaluate   {:>10.2} ms", b.evaluate_ms);
                println!("  decrypt    {:>10.2} ms", b.decrypt_ms);
                println!(
                    "  bytes      eval keys {} KiB, request {} KiB, response {} KiB{est}",
                    b.evaluation_key_bytes / 1024,
                    b.request_bytes / 1024,
                    b.response_bytes / 1024
                );
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// The evaluator identity to trust: `--trust-evaluator`, else the key
/// pinned in the key directory, else the announced one, pinned now (trust on
/// first use). A later change of identity fails receipt verification.
fn trusted_evaluator(
    remote: &Remote,
    keys: &Path,
    flag: Option<&str>,
) -> Result<EvaluatorIdentity> {
    let pin = keys.join("evaluator.pub");
    if let Some(hex) = flag {
        return EvaluatorIdentity::from_public_key_hex(hex.trim());
    }
    if let Ok(hex) = std::fs::read_to_string(&pin) {
        return EvaluatorIdentity::from_public_key_hex(hex.trim());
    }
    let announced = remote.evaluator_identity()?;
    std::fs::write(&pin, format!("{}\n", announced.public_key_hex()))
        .map_err(|e| Error::new(Code::Artifact, format!("{}: {e}", pin.display())))?;
    eprintln!(
        "trusting evaluator enc-eval:{} on first use (pinned in {})",
        announced.evaluator_id(),
        pin.display()
    );
    Ok(announced)
}

fn short(s: &str) -> &str {
    s.char_indices().nth(16).map_or(s, |(i, _)| &s[..i])
}

/// `verify`'s attestation flags.
struct Attested<'a> {
    record: Option<&'a Path>,
    policy: Option<&'a Path>,
    trust: &'a attest::TrustArgs,
}

// One parameter per command-line flag.
#[allow(clippy::too_many_arguments)]
fn verify(
    receipt: &Path,
    model: Option<&Path>,
    request: Option<&Path>,
    response: Option<&Path>,
    trust: Option<&str>,
    backend: Option<&str>,
    proof: Option<&Path>,
    evaluation_keys: Option<&Path>,
    attested: Attested<'_>,
) -> Result<ExitCode> {
    let read = |p: &Path| {
        std::fs::read(p).map_err(|e| Error::new(Code::Artifact, format!("{}: {e}", p.display())))
    };
    let signed = SignedExecutionReceipt::from_bytes(&read(receipt)?)?;
    let r = &signed.receipt;
    let own = EvaluatorIdentity::from_public_key_hex(&signed.evaluator_public_key)?;
    let trusted = match trust {
        Some(hex) => Some(EvaluatorIdentity::from_public_key_hex(hex.trim())?),
        None => None,
    };
    let model = match model {
        Some(p) => Some(load(p)?),
        None => None,
    };
    let request_bytes = request.map(read).transpose()?;
    let rc = request_bytes.as_deref().map(request_commitment);
    // The key the request was made under, from its envelope header.
    let request_header = match &request_bytes {
        Some(b) => Some(encompute_protocol::Envelope::decode(b)?.header),
        None => None,
    };
    let request_key = request_header.as_ref().and_then(|h| h.key_id.clone());
    // The backend expected: --backend, else the request envelope (made by
    // the verifier's own client), never the receipt's claim.
    let expected_backend = match (backend, &request_header) {
        (Some(b), _) => Some(b.to_owned()),
        (None, Some(h)) => Some(h.backend.clone()),
        (None, None) => None,
    };
    let kind = match &expected_backend {
        Some(b) => Some(
            BackendKind::parse(b)
                .ok_or_else(|| Error::new(Code::Receipt, format!("unknown backend {b:?}")))?,
        ),
        None => None,
    };
    // The spec the receipt must state: the artifact's, on that backend.
    let spec = match (&model, kind) {
        (Some(m), Some(k)) => Some(encompute_runtime::verification_spec(m, k)),
        _ => None,
    };
    let oc = response
        .map(read)
        .transpose()?
        .map(|b| output_commitment(&b));

    let section = |t: &str| println!("\n{t}\n{}", "─".repeat(40));
    println!("Execution Receipt");
    section("Execution");
    println!("  {:<16}{}", "ID", r.execution_id);
    println!("  {:<16}encspec1:{}", "Spec", short(&r.spec_id));
    println!("  {:<16}{}", "Program", short(&r.program_id));
    println!("  {:<16}{}", "Plan", short(&r.plan_id));
    println!("  {:<16}{}", "Parameters", short(&r.parameter_set_id));
    println!("  {:<16}{}", "Key", short(&r.key_id));
    println!(
        "  {:<16}{} {} {}",
        "Scheme", r.scheme, r.backend, r.backend_version
    );
    println!("  {:<16}{}", "Request", short(&r.request_commitment));
    println!("  {:<16}{}", "Output", short(&r.output_commitment));

    // The signature against the trusted key (or, without one, the
    // receipt's own), then each binding that can be checked here.
    let evaluator = trusted.as_ref().unwrap_or(&own);
    let mut result = signed.verify_signature(evaluator);
    let mut bind = |what: &str, got: &str, want: Option<String>| {
        if let (Ok(()), Some(w)) = (&result, want) {
            if got != w {
                result = Err(Error::new(
                    Code::Receipt,
                    format!("receipt {what} does not match"),
                ));
            }
        }
    };
    if let Some(s) = &spec {
        bind("spec ID", &r.spec_id, Some(s.id().hex()));
        bind("program ID", &r.program_id, Some(s.program_id.clone()));
        bind("plan ID", &r.plan_id, Some(s.plan_id.clone()));
        bind(
            "parameter-set ID",
            &r.parameter_set_id,
            Some(s.parameter_set_id.clone()),
        );
        bind("scheme", &r.scheme, Some(s.scheme.clone()));
        bind("backend", &r.backend, Some(s.backend.clone()));
        bind(
            "backend version",
            &r.backend_version,
            Some(s.backend_version.clone()),
        );
    }
    if let (None, Some(b)) = (&spec, &expected_backend) {
        bind("backend", &r.backend, Some(b.clone()));
    }
    bind("request commitment", &r.request_commitment, rc.clone());
    if request_bytes.is_some() {
        bind(
            "key ID",
            &r.key_id,
            Some(request_key.clone().unwrap_or_default()),
        );
    }
    bind("output commitment", &r.output_commitment, oc.clone());
    // The transcript the artifact's plan implies on that backend.
    let transcript = match (&model, kind) {
        (Some(m), Some(k)) => {
            Some(encompute_runtime::verification_transcript(m, k).map(|t| t.id().hex()))
        }
        _ => None,
    };
    if let (Ok(()), Some(want)) = (&result, &transcript) {
        if r.transcript_hash != *want {
            result = Err(Error::new(
                Code::Transcript,
                "transcript commitment mismatch: the receipt binds another transcript",
            ));
        }
    }
    section("Evaluator");
    println!("  {:<16}enc-eval:{}", "ID", short(&r.evaluator_id));
    println!(
        "  {:<16}{}",
        "Trusted",
        if trusted.is_some() {
            "yes (--trust-evaluator)"
        } else {
            "NOT CHECKED (no --trust-evaluator): signature checked against the receipt's own key"
        }
    );
    println!(
        "  {:<16}{}",
        "Signature",
        if result.is_ok() { "VALID" } else { "see below" }
    );
    section("Bindings");
    let checked = |b: bool| if b { "checked" } else { "NOT CHECKED" };
    println!("  {:<16}{}", "Artifact", checked(spec.is_some()));
    if let Some(p) = spec.as_ref().and_then(|s| s.policy_id.as_ref()) {
        println!("  {:<16}checked (encpolicy1:{})", "Policy", short(p));
    }
    println!("  {:<16}{}", "Backend", checked(expected_backend.is_some()));
    println!("  {:<16}{}", "Request", checked(rc.is_some()));
    println!("  {:<16}{}", "Response", checked(oc.is_some()));
    println!("  {:<16}{}", "Transcript", checked(transcript.is_some()));
    // The execution proof: only with every binding in hand.
    let complete = trusted.is_some() && spec.is_some() && rc.is_some() && oc.is_some();
    let proof_state = match (&result, proof, &model, &request_bytes, &trusted) {
        (Ok(()), Some(p), Some(m), Some(req), Some(t)) if complete => {
            let resp = read(response.expect("complete"))?;
            let keys = match evaluation_keys {
                Some(k) => read(k)?,
                None => {
                    return Err(Error::new(
                        Code::Unverified,
                        "verifying a proof needs --evaluation-keys (your eval.keys)",
                    ))
                }
            };
            let p = ExecutionProof::from_bytes(&read(p)?)?;
            Some(
                encompute_runtime::verify_execution_offline(m, &signed, t, req, &resp, &p, &keys)
                    .map(|s| (s, p)),
            )
        }
        _ => None,
    };
    section("Execution proof");
    match &proof_state {
        Some(Ok((VerificationState::ExecutionVerified(v), p))) => {
            println!("  {:<16}{}", "Relation", v.relation());
            println!("  {:<16}{}", "Protocol", v.protocol());
            println!(
                "  {:<16}encvk1:{}",
                "Verif. key",
                short(v.verification_key_id())
            );
            println!("  {:<16}{} bytes", "Proof size", p.to_bytes()?.len());
            println!("  {:<16}VALID", "Status");
        }
        Some(Ok(_)) | None => {
            if let Some(t) = &r.transcript_hash {
                println!("  {:<16}enctrace1:{}", "Transcript", short(t));
            }
            println!(
                "  {:<16}{}",
                "Status",
                if proof.is_some() {
                    "NOT CHECKED (needs a complete verification)"
                } else {
                    "NOT PRESENT"
                }
            );
        }
        Some(Err(e)) => println!("  {:<16}INVALID: {}", "Status", e.message),
    }
    section("Workload attestation");
    let attestation = match (&r.attestation, attested.record, attested.policy) {
        (None, None, _) => {
            println!("  {:<16}NOT ATTESTED (no attested workload)", "Status");
            None
        }
        (Some(a), None, _) => {
            println!("  {:<16}{}", "Session", short(&a.workload_session_id));
            println!(
                "  {:<16}NOT CHECKED (needs --attestation and --attestation-policy)",
                "Status"
            );
            None
        }
        (_, Some(_), None) => {
            return Err(Error::new(
                Code::WorkloadPolicy,
                "--attestation needs --attestation-policy",
            ))
        }
        (_, Some(rec), Some(pol)) => {
            let record = encompute_runtime::attestation::AttestationRecord::from_bytes(
                &std::fs::read(rec)
                    .map_err(|e| Error::new(Code::Artifact, format!("{}: {e}", rec.display())))?,
            )?;
            let policy: encompute_runtime::attestation::AttestationPolicy = serde_json::from_slice(
                &std::fs::read(pol)
                    .map_err(|e| Error::new(Code::Artifact, format!("{}: {e}", pol.display())))?,
            )
            .map_err(|e| Error::new(Code::WorkloadPolicy, format!("{}: {e}", pol.display())))?;
            let verifier = attested.trust.verifier(None)?;
            Some(encompute_runtime::attested::verify_receipt_attestation(
                &signed, &record, &verifier, &policy,
            ))
        }
    };
    match &attestation {
        Some(Ok(w)) => {
            println!("  {:<16}{}", "Provider", w.provider);
            println!("  {:<16}{}", "TEE", w.tee_kind);
            println!(
                "  {:<16}{}",
                "Image",
                w.image_digest.as_deref().unwrap_or("(none)")
            );
            println!(
                "  {:<16}{}",
                "Session",
                short(&encompute_runtime::attestation::WorkloadSession::session_id_of(&w.binding)?)
            );
            println!("  {:<16}VALID", "Status");
        }
        Some(Err(e)) => {
            println!("  {:<16}INVALID: {}", "Status", e.message);
            if result.is_ok() {
                result = Err(e.clone());
            }
        }
        None => {}
    }
    section("Receipt");
    if matches!(attestation, Some(Ok(_))) && result.is_ok() {
        println!("WORKLOAD ATTESTATION VALID");
    }
    match (result, proof_state) {
        (Ok(()), Some(Ok((VerificationState::ExecutionVerified(_), _)))) => {
            println!("RECEIPT VERIFIED");
            println!("EXECUTION VERIFIED");
            println!("\nVERIFIED PRIVATE EXECUTION");
            Ok(ExitCode::SUCCESS)
        }
        (Ok(()), Some(Err(e))) => {
            println!("RECEIPT VERIFIED");
            println!("EXECUTION PROOF INVALID: {}", e.message);
            Ok(ExitCode::from(1))
        }
        (Ok(()), _) => {
            if r.transcript_hash.is_some() {
                println!("TRANSCRIPT AVAILABLE");
            }
            if complete {
                println!("RECEIPT VERIFIED");
            } else {
                println!("RECEIPT SIGNATURE VALID (some bindings not checked)");
            }
            println!("EXECUTION PROOF NOT PRESENT");
            // Exit 0 only for a fully verified receipt; 3 when bindings
            // were left unchecked.
            Ok(if complete {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(3)
            })
        }
        (Err(e), _) => {
            println!("INVALID: {}", e.message);
            println!("EXECUTION PROOF NOT PRESENT");
            Ok(ExitCode::from(1))
        }
    }
}

fn print_test(rep: &TestReport) {
    match rep {
        TestReport::Approximate(rep) => {
            println!(
                "{} cases on {} (seed {}), precision {:e}",
                rep.cases, rep.backend, rep.seed, rep.precision
            );
            for o in &rep.outputs {
                println!(
                    "  {:<12} max error {:.3e}  mean {:.3e}  worst case #{}",
                    o.name, o.max_abs, o.mean_abs, o.worst_case
                );
            }
        }
        TestReport::Exact(rep) => {
            println!(
                "{} exact cases on {} (seed {})",
                rep.cases, rep.backend, rep.seed
            );
            println!("  matches     {:>8}", rep.matches);
            println!("  mismatches  {:>8}", rep.mismatches);
        }
    }
    println!("{}", if rep.passed() { "PASS" } else { "FAIL" });
    if let Some(f) = rep.failing() {
        println!("failing case #{}: inputs {:?}", f.case, f.inputs);
        println!("  expected {:?}\n  got      {:?}", f.expected, f.got);
    }
}

fn compile(source: &str, output: Option<PathBuf>) -> Result<ExitCode> {
    let file = match source.rsplit_once(':') {
        Some((f, _)) if f.ends_with(".py") => f,
        _ => source,
    };
    let path = Path::new(file);
    if path.extension().is_some_and(|e| e == "py") {
        // Tracing Python needs the Python SDK; delegate to it.
        let mut cmd = Command::new(std::env::var("PYTHON").unwrap_or_else(|_| "python3".into()));
        cmd.args(["-m", "encompute", "compile", source]);
        if let Some(o) = &output {
            cmd.arg("-o").arg(o);
        }
        let status = cmd.status().map_err(|e| {
            Error::new(
                Code::Artifact,
                format!("could not run python3 -m encompute: {e}"),
            )
        })?;
        return Ok(if status.success() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        });
    }
    let m = load(path)?;
    let out =
        output.unwrap_or_else(|| path.with_file_name(format!("{}.encompute", m.program().name())));
    m.save(&out)?;
    println!("wrote {}", out.display());
    Ok(ExitCode::SUCCESS)
}

fn write_keys(dir: &Path, client: &ClientSession) -> Result<()> {
    let io = |e: std::io::Error| Error::new(Code::Artifact, format!("{}: {e}", dir.display()));
    std::fs::create_dir_all(dir).map_err(io)?;
    let secret = dir.join("secret.key");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    let envelope = client.secret_key_envelope()?;
    opts.open(&secret)
        .and_then(|mut f| f.write_all(&envelope))
        .map_err(io)?;
    let keys = client
        .evaluation_keys()
        .expect("fresh client has evaluation keys");
    std::fs::write(dir.join("eval.keys"), keys).map_err(io)?;
    Ok(())
}

fn parse_inputs(args: &[String], file: Option<&Path>) -> Result<Inputs> {
    let bad = |m: String| Error::new(Code::BadInput, m);
    let mut inputs = Inputs::new();
    if let Some(f) = file {
        let text = std::fs::read_to_string(f).map_err(|e| bad(format!("{}: {e}", f.display())))?;
        let v: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&text).map_err(|e| bad(format!("{}: {e}", f.display())))?;
        for (k, v) in v {
            let vals = match v {
                serde_json::Value::Number(n) => vec![n.as_f64().unwrap()],
                serde_json::Value::Bool(b) => vec![f64::from(u8::from(b))],
                serde_json::Value::Array(a) => a
                    .iter()
                    .map(|x| {
                        x.as_f64()
                            .ok_or_else(|| bad(format!("input {k}: not a number: {x}")))
                    })
                    .collect::<Result<_>>()?,
                other => {
                    return Err(bad(format!(
                        "input {k}: expected number or list, got {other}"
                    )))
                }
            };
            inputs.insert(k, vals);
        }
    }
    for a in args {
        let (k, v) = a
            .split_once('=')
            .ok_or_else(|| bad(format!("expected NAME=V1,V2,..., got {a:?}")))?;
        let vals = v
            .split(',')
            .map(|x| match x.trim() {
                "true" => Ok(1.0),
                "false" => Ok(0.0),
                x => x
                    .parse::<f64>()
                    .map_err(|_| bad(format!("input {k}: bad number {x:?}"))),
            })
            .collect::<Result<_>>()?;
        inputs.insert(k.to_owned(), vals);
    }
    Ok(inputs)
}
