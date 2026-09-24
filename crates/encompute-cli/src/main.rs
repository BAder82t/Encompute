//! `encompute` command-line tool.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};
use encompute_ir::{Code, Error, Inputs, Result};
use encompute_runtime::{Mode, Model};

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
    /// Run a model on inputs, e.g. `--input x=0.5,-1,0.25`.
    Run {
        model: PathBuf,
        #[arg(short, long = "input", value_name = "NAME=V1,V2,...")]
        inputs: Vec<String>,
        /// JSON file mapping input names to numbers or lists.
        #[arg(long)]
        inputs_file: Option<PathBuf>,
        #[arg(long, default_value = "clear")]
        mode: String,
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
        } => {
            let m = load(&model)?;
            let inputs = parse_inputs(&inputs, inputs_file.as_deref())?;
            let out = m.run(mode.parse()?, &inputs)?;
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
            Ok(ExitCode::SUCCESS)
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
                println!("{}", if rep.passed { "PASS" } else { "FAIL" });
                if let Some(f) = &rep.failing {
                    println!("failing case #{}: inputs {:?}", f.case, f.inputs);
                    println!("  expected {:?}\n  got      {:?}", f.expected, f.got);
                }
            }
            Ok(if rep.passed {
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
            let rep = match measure {
                Some(n) => Some(m.test(mode.parse()?, n, 42)?),
                None => None,
            };
            print!("{}", m.explain(rep.as_ref()));
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
                println!(
                    "{} backend, N = {}, {} slots, depth {}, {} rotation keys, median of {}",
                    b.backend, b.ring_dim, b.slots, b.depth, b.rotation_keys, b.reps
                );
                println!("  keygen     {:>10.2} ms", b.keygen_ms);
                println!("  encrypt    {:>10.2} ms", b.encrypt_ms);
                println!("  evaluate   {:>10.2} ms", b.evaluate_ms);
                println!("  decrypt    {:>10.2} ms", b.decrypt_ms);
                println!(
                    "  ciphertexts in {} KiB, out {} KiB{est}",
                    b.input_ciphertext_bytes / 1024,
                    b.output_ciphertext_bytes / 1024
                );
            }
            Ok(ExitCode::SUCCESS)
        }
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
            .map(|x| {
                x.trim()
                    .parse::<f64>()
                    .map_err(|_| bad(format!("input {k}: bad number {x:?}")))
            })
            .collect::<Result<_>>()?;
        inputs.insert(k.to_owned(), vals);
    }
    Ok(inputs)
}
