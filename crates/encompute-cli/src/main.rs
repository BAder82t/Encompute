//! `encompute` command-line tool.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};
use encompute_ir::{Code, Error, Inputs, Result};
use encompute_runtime::{BenchDetail, ClientSession, Mode, Model, Remote, TestReport};

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
    },
    /// Manage client keys.
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
                    let client =
                        ClientSession::restore(m.ids(), m.compiled(), &read("secret.key")?)?;
                    let eval_keys = read("eval.keys").ok();
                    let (out, stats) = Remote::new(&url).run(
                        &client,
                        m.program(),
                        eval_keys.as_deref(),
                        &inputs,
                    )?;
                    eprintln!(
                        "remote: request {} KiB, response {} KiB, keys uploaded {} KiB, evaluator {:.1} ms, round trip {:.1} ms",
                        stats.request_bytes / 1024,
                        stats.response_bytes / 1024,
                        stats.evaluation_key_bytes_uploaded / 1024,
                        stats.evaluator_ms,
                        stats.round_trip_ms
                    );
                    out
                }
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&m.outputs_json(&out)).unwrap()
            );
            Ok(ExitCode::SUCCESS)
        }
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
        } => {
            let m = load(&model)?;
            let measured = match measure {
                Some(n) => Some(m.measure(mode.parse()?, n, 3)?),
                None => None,
            };
            print!("{}", m.explain(measured.as_ref()));
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
