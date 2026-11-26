//! `encompute` command-line tool.

mod aggregate;
mod attest;
mod control;
mod governance;
mod governance_bundle;
mod governance_explain;
mod launcher_sim;
mod migrate;
mod plan;
mod trust;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};
use encompute_ir::{Code, Error, Inputs, Result};
use encompute_runtime::verification::{
    output_commitment, request_commitment, EvaluatorIdentity, ExecutionProof,
    SignedExecutionReceipt, VerificationEvidence, VerificationState,
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
        /// Backend of the execution spec (default: the artifact's target:
        /// openfhe-exact for BinFHE, openfhe for BGV; mock runs use
        /// `--backend mock`).
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
        /// The backend you expected (mock, openfhe, openfhe-exact; tfhe-rs in
        /// research builds only). Default: from the request envelope, which
        /// you made; never from the receipt.
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
        /// Accept a receipt for the mock backend, which encrypts nothing
        /// (development and tests only). Refused by default.
        #[arg(long)]
        allow_mock: bool,
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
        cmd: Box<aggregate::AggregateCmd>,
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
    /// Log in to a control plane: saves its URL and an OIDC token (read
    /// from --token-file or standard input, never an argument).
    Login {
        #[arg(long)]
        url: String,
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// Projects on the control plane.
    Projects {
        #[command(subcommand)]
        cmd: control::ProjectsCmd,
    },
    /// The control plane's asset registry (metadata only).
    Assets {
        #[command(subcommand)]
        cmd: control::AssetsCmd,
    },
    /// Jobs on the control plane: submit, run, status, cancel.
    Jobs {
        #[command(subcommand)]
        cmd: control::JobsCmd,
    },
    /// Governed projects: create a governance key file and sign
    /// authorizations, purpose acceptances and revocations with it, outside
    /// the control plane.
    Governance {
        #[command(subcommand)]
        cmd: governance::GovernanceCmd,
    },
    /// Security checks on the control plane (`security legacy-service-admins`
    /// exits 1 while any service account still holds security_admin).
    Security {
        #[command(subcommand)]
        cmd: control::SecurityCmd,
    },
    /// Start an evaluator for a model (runs `encompute-evaluator serve`).
    Serve {
        model: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8750")]
        listen: String,
        /// mock, openfhe or openfhe-exact; tfhe-rs in research builds only
        /// (default: real cryptography where built).
        #[arg(long)]
        backend: Vec<String>,
    },
    /// Check an artifact (and optionally keys and the evaluator binary)
    /// against the security model. `encompute audit list` shows the control
    /// plane's audit trail instead.
    Audit {
        model: PathBuf,
        /// With `audit list`: the organization (default: yours).
        #[arg(long)]
        organization: Option<String>,
        /// With `audit list`: events after this sequence number.
        #[arg(long, default_value_t = 0)]
        after: u64,
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
    /// Choose the protection mechanisms that satisfy the program's trust
    /// requirements (or fail: PLANNING FAILED), and explain every choice.
    Plan {
        model: PathBuf,
        #[command(flatten)]
        opts: plan::PlanOpts,
        /// Write the plan (canonical JSON) for `aggregate --plan` and the
        /// trust bundle.
        #[arg(short, long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Also show every candidate considered and the assumptions.
        #[arg(long)]
        deep: bool,
    },
    /// Which backends and research features this build includes.
    Info,
    /// An adapter's lineage: base model, training data, configuration,
    /// aggregation, privacy spend, history and the evidence verdicts.
    Lineage {
        adapter: String,
        #[command(flatten)]
        bundle: trust::Bundle,
        #[command(flatten)]
        anchors: trust::AnchorArgs,
        #[command(flatten)]
        trust: attest::TrustArgs,
    },
    /// Export an adapter publicly: EXPORT DENIED unless every parent (base
    /// model, datasets, updates) permits it.
    Export {
        adapter: String,
        #[command(flatten)]
        bundle: trust::Bundle,
        #[command(flatten)]
        anchors: trust::AnchorArgs,
        #[command(flatten)]
        trust: attest::TrustArgs,
    },
    /// Run a confidential training project (a Python file calling
    /// `project.finetune`).
    Train { project: PathBuf },
    /// Is the program valid, its policy and privacy valid, and does a plan
    /// exist?
    Check {
        model: PathBuf,
        #[command(flatten)]
        opts: plan::PlanOpts,
    },
    /// Check a saved artifact's version against this build; upgrade older
    /// ones into a new copy.
    ///
    /// The kind is found by structure: a compiled model directory
    /// (manifest.json), a key directory (secret.key, eval.keys), a privacy
    /// ledger directory (*.ledger) or ledger file, an execution receipt, a
    /// trust bundle, a confidential execution plan, a sealed checkpoint or
    /// asset, a signed adapter record, an aggregation receipt, an
    /// attestation record or policy, an envelope, or an aggregation party
    /// state file (`aggregate join --state`).
    ///
    /// The input is never modified. An upgrade is written only with --out
    /// DIR, as DIR/<name of PATH>, under a temporary name then renamed; an
    /// existing DIR/<name> is never overwritten. --check never writes.
    /// Migrations change metadata only: key material is never rewritten,
    /// nothing is re-signed, and signed, sealed, hash-chained or
    /// content-addressed objects are never rewritten.
    ///
    /// Upgrades: a model artifact of format 2, 3 or 4, or of the current
    /// format with metadata written by another Encompute version, has its
    /// derived files (security.json, verification.json, policy.json,
    /// manifest.json) regenerated from program.eir, only if its program,
    /// plan, parameters and backend are byte-identical to what this build
    /// compiles (otherwise it is refused: recompile and regenerate keys). A
    /// party state holding a bare sequence number becomes JSON. Execution
    /// receipts of version 1 and 2 are kept as-is: rewriting them would
    /// invalidate the evaluator's signature.
    ///
    /// Exit status: 0 current, or the upgrade was written; 1 an upgrade is
    /// available and nothing was written; 3 an older version is kept as-is;
    /// 2 refused: error[ENC1401] unrecognized or unreadable input, or an
    /// existing output; error[ENC1602] a version newer than this build or
    /// one it never knew; a corrupted object fails with its kind's own code
    /// (e.g. ENC1401 artifact, ENC1601 envelope or keys, ENC1606 receipt,
    /// ENC2202 ledger).
    Migrate {
        #[command(flatten)]
        args: migrate::MigrateArgs,
    },
    /// Show the execution plan, parameters and precision. With
    /// `--governance`, explain a governed cross-agency computation in
    /// words instead (see below).
    Explain {
        /// The model (not with `--governance`).
        model: Option<PathBuf>,
        /// Explain a governed job's computation for a non-specialist, from
        /// its governance evidence bundle, verified here against your own
        /// pins (`--pins`), never on the server's word. Online:
        /// `--governance JOB` fetches the bundle (`GET
        /// /v1/jobs/{id}/governance-bundle`); offline: `--governance
        /// --bundle FILE.encgov.json`. Sections that did not verify print
        /// `not verified: <why>`. Exit codes as `encompute governance
        /// verify`.
        #[arg(long, num_args = 0..=1, value_name = "JOB")]
        governance: Option<Option<String>>,
        /// `--governance`: a bundle file, to explain offline.
        #[arg(long, requires = "governance")]
        bundle: Option<PathBuf>,
        /// `--governance JOB`: `shared` or `org`.
        #[arg(long, default_value = "shared", value_parser = ["shared", "org"], requires = "governance")]
        view: String,
        /// `--governance JOB --view org`: your organization.
        #[arg(long, requires = "governance")]
        organization: Option<String>,
        /// `--governance JOB`: the control plane's URL.
        #[arg(long, requires = "governance")]
        url: Option<String>,
        #[command(flatten)]
        checks: governance_bundle::Checks,
        /// Also show the planner's candidates, rejected alternatives,
        /// assumptions and estimated costs.
        #[arg(long)]
        deep: bool,
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

#[derive(clap::Args)]
struct PopulationArgs {
    /// The ledger directory the coordinator serves from.
    #[arg(long)]
    ledger: PathBuf,
    #[arg(long)]
    id: String,
    /// The owning organization (a party ID).
    #[arg(long)]
    organization: String,
    /// The dataset series every version of which it accounts for.
    #[arg(long)]
    series: String,
    /// The privacy unit the cap protects (patient, user, record, ...).
    #[arg(long)]
    unit: String,
    #[arg(long)]
    epsilon: f64,
    #[arg(long)]
    delta: f64,
}

#[derive(clap::Args)]
struct ScopeArgs {
    #[arg(long)]
    ledger: PathBuf,
    #[arg(long)]
    population: String,
    #[arg(long)]
    id: String,
    #[arg(long)]
    project: String,
    #[arg(long)]
    purpose: String,
    #[arg(long)]
    program: Option<String>,
    /// The scope's cap: no more than the population's.
    #[arg(long)]
    epsilon: f64,
    /// The asset this scope serves in the aggregation.
    #[arg(long)]
    asset: String,
    /// Add the entry to this `--scoping` file (created if missing)
    /// instead of printing it.
    #[arg(long)]
    scoping: Option<PathBuf>,
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
        /// Preview what this many releases (training rounds) would cost
        /// each budget, before anything runs; exits 1 if over budget.
        #[arg(long)]
        rounds: Option<u64>,
        /// Estimate for a governed project's scopes: an aggregate that
        /// declares no `max_sources_per_unit` is charged for every
        /// participant, as enforcement does.
        #[arg(long)]
        scoped: bool,
    },
    /// The confidentiality graph (Graphviz DOT).
    Graph {
        model: PathBuf,
        #[arg(long, default_value = "dot")]
        format: String,
    },
    /// Create a privacy population in a ledger directory: the hard cap on
    /// everything released from one organization's series of datasets,
    /// whatever the project, purpose or version. It is created once, by the
    /// owners, and never raised.
    Population(Box<PopulationArgs>),
    /// Allocate a scope of a population to one project and purpose (and,
    /// optionally, program): its releases are charged to the scope and to
    /// the population, and must fit in both. Prints the entry for the
    /// `--scoping` file of the aggregation's asset.
    Scope(Box<ScopeArgs>),
    /// Create the local ledgers of the populations and scopes a `--scoping`
    /// file names (a coordinator's, or a party's own copy to check what it
    /// is shown): idempotent, and refused when a ledger already there is
    /// another one.
    Seed {
        /// The `--scoping` file every party approved.
        #[arg(long)]
        scoping: PathBuf,
        #[arg(long)]
        ledger: PathBuf,
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
        /// Replace an existing `secret.key` in the output directory. Results
        /// encrypted under the old key can then no longer be decrypted.
        #[arg(long)]
        force: bool,
    },
    #[command(flatten)]
    Broker(Box<attest::BrokerCmd>),
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

/// Creates the ledger of a new population or scope in `dir` (never over an
/// existing one: a cap is allocated once).
fn create_ledger(dir: &Path, g: &encompute_runtime::dp::Genesis) -> Result<()> {
    encompute_runtime::dp::check_asset_file_name(&g.asset_id)?;
    std::fs::create_dir_all(dir)
        .map_err(|e| Error::new(Code::PrivacyLedger, format!("{}: {e}", dir.display())))?;
    let path = dir.join(format!("{}.ledger", g.asset_id));
    if path.exists() {
        return Err(Error::new(
            Code::GovernancePrivacyAllocation,
            format!(
                "{} exists: a population or scope is allocated once, and its cap never changes",
                path.display()
            ),
        ));
    }
    drop(encompute_runtime::dp::Ledger::open(&path, g)?);
    Ok(())
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
                    let secret = encompute_verification::read_secret_file(
                        &dir.join("secret.key"),
                        encompute_verification::SecretFile::Private,
                        |e| {
                            Error::new(
                                Code::WrongKey,
                                format!("{}: {e}", dir.join("secret.key").display()),
                            )
                        },
                    )?;
                    let mut client = ClientSession::restore(m.ids(), m.compiled(), &secret)?;
                    // Evaluation keys (about 525 MiB for exact programs) are
                    // read now only to verify an execution proof by
                    // re-execution; otherwise only if the evaluator lacks
                    // them (run_with_keys_file).
                    if m.compiled().proof_required() {
                        if let Ok(k) = read("eval.keys") {
                            client.attach_evaluation_keys(&k)?;
                        }
                    }
                    let remote = Remote::new(&url);
                    let trusted = trusted_evaluator(&remote, &dir, trust_evaluator.as_deref())?;
                    // Before the program, evaluation keys or ciphertexts
                    // go anywhere: an evaluator announcing another identity
                    // is refused now. The announcement is unauthenticated;
                    // the receipt check after execution stays the binding
                    // one.
                    let announced = remote.evaluator_identity()?;
                    if announced.public_key() != trusted.public_key() {
                        return Err(Error::new(
                            Code::Receipt,
                            format!(
                                "the evaluator at {url} announces enc-eval:{}, not the trusted \
                                 enc-eval:{}; nothing was sent",
                                announced.evaluator_id(),
                                trusted.evaluator_id()
                            ),
                        ));
                    }
                    let run = remote.run_with_keys_file(
                        &client,
                        m.program(),
                        &dir.join("eval.keys"),
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
                    if client.kind() == BackendKind::Mock {
                        eprintln!(
                            "Backend                 mock: the inputs were NOT encrypted \
                             (development and tests only)"
                        );
                    }
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
        Cmd::Privacy {
            cmd: PrivacyCmd::Population(args),
        } => {
            let PopulationArgs {
                ledger,
                id,
                organization,
                series,
                unit,
                epsilon,
                delta,
            } = *args;
            let budget = encompute_ir::confidentiality::PrivacyBudget {
                unit: encompute_ir::confidentiality::PrivacyUnit::parse(&unit)?,
                epsilon,
                delta,
            };
            let g = encompute_runtime::dp::scoped::population_genesis(
                &id,
                &organization,
                &series,
                budget,
            )?;
            create_ledger(&ledger, &g)?;
            println!(
                "POPULATION {id} created: {organization}'s series {series}, epsilon {epsilon} \
                 delta {delta:e} per {unit} (rho cap {:.6})\ndigest {}",
                encompute_runtime::dp::accountant::rho_cap(&g.budget)?,
                g.digest()?
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Privacy {
            cmd: PrivacyCmd::Seed { scoping, ledger },
        } => {
            let all: std::collections::BTreeMap<String, encompute_runtime::secagg::ScopedBudget> =
                serde_json::from_slice(&std::fs::read(&scoping).map_err(|e| {
                    Error::new(Code::Artifact, format!("{}: {e}", scoping.display()))
                })?)
                .map_err(|e| Error::new(Code::BadInput, format!("{}: {e}", scoping.display())))?;
            std::fs::create_dir_all(&ledger).map_err(|e| {
                Error::new(Code::PrivacyLedger, format!("{}: {e}", ledger.display()))
            })?;
            for (asset, sb) in &all {
                encompute_runtime::dp::scoped::check_genesis_pair(&sb.population, &sb.scope)?;
                for g in [&sb.population, &sb.scope] {
                    encompute_runtime::dp::check_asset_file_name(&g.asset_id)?;
                    // Created when missing; an existing ledger must be this
                    // genesis's own (open checks it).
                    drop(encompute_runtime::dp::Ledger::open(
                        &ledger.join(format!("{}.ledger", g.asset_id)),
                        g,
                    )?);
                }
                println!(
                    "SEEDED {asset}: population {} and scope {}",
                    sb.population.asset_id, sb.scope.asset_id
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Privacy {
            cmd: PrivacyCmd::Scope(args),
        } => {
            let ScopeArgs {
                ledger,
                population,
                id,
                project,
                purpose,
                program,
                epsilon,
                asset,
                scoping,
            } = *args;
            let pop =
                encompute_runtime::dp::ledger::read(&ledger.join(format!("{population}.ledger")))
                    .map_err(|e| {
                    Error::new(
                        Code::GovernancePrivacyAllocation,
                        format!(
                            "population {population} is not in {}: {}",
                            ledger.display(),
                            e.message
                        ),
                    )
                })?;
            let budget = encompute_ir::confidentiality::PrivacyBudget {
                epsilon,
                ..pop.genesis.budget.clone()
            };
            let g = encompute_runtime::dp::scoped::scope_genesis(
                &id,
                &pop.genesis,
                &project,
                &purpose,
                program.as_deref(),
                budget,
            )?;
            create_ledger(&ledger, &g)?;
            let entry = encompute_runtime::secagg::ScopedBudget {
                population: pop.genesis,
                scope: g,
            };
            let mut all: std::collections::BTreeMap<
                String,
                encompute_runtime::secagg::ScopedBudget,
            > = match &scoping {
                Some(p) if p.exists() => serde_json::from_slice(
                    &std::fs::read(p)
                        .map_err(|e| Error::new(Code::Artifact, format!("{}: {e}", p.display())))?,
                )
                .map_err(|e| Error::new(Code::BadInput, format!("{}: {e}", p.display())))?,
                _ => Default::default(),
            };
            all.insert(asset.clone(), entry);
            let text = serde_json::to_string_pretty(&all).expect("serializable");
            match &scoping {
                Some(p) => {
                    std::fs::write(p, format!("{text}\n"))
                        .map_err(|e| Error::new(Code::Artifact, format!("{}: {e}", p.display())))?;
                    println!("SCOPE {id} allocated for asset {asset}: {}", p.display());
                }
                None => println!("{text}"),
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Privacy { cmd } => {
            let (m, out) = match cmd {
                PrivacyCmd::Explain {
                    model,
                    ledger,
                    rounds: Some(rounds),
                    scoped,
                } => {
                    let m = load(&model)?;
                    let rows = m.privacy_projection_in(rounds, scoped)?;
                    let mut out = m.privacy_explain()?.unwrap_or_default();
                    if let Some(dir) = ledger {
                        out.push('\n');
                        out.push_str(&m.privacy_status(&dir)?);
                    }
                    print!("{out}\n{}", encompute_runtime::render_preview(&rows));
                    return Ok(if rows.iter().all(|r| r.allowed) {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    });
                }
                PrivacyCmd::Explain { model, ledger, .. } => {
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
                PrivacyCmd::Budget { .. }
                | PrivacyCmd::Population(_)
                | PrivacyCmd::Scope(_)
                | PrivacyCmd::Seed { .. } => {
                    unreachable!("handled above")
                }
            };
            match out {
                Some(text) => print!("{text}"),
                None => println!(
                    "{} declares no parties or assets: every secret input stays with the client \
                     that encrypts it (declare parties and assets to give it a confidentiality policy)",
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
                None => m.compiled().target_backend(),
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
            allow_mock,
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
            allow_mock,
        ),
        Cmd::Attest { cmd } => attest::attest(cmd),
        Cmd::Aggregate { cmd } => aggregate::aggregate(*cmd),
        Cmd::Trust { cmd } => trust::trust(cmd),
        Cmd::Workload { cmd } => attest::workload(cmd),
        Cmd::Keys {
            cmd: KeysCmd::Broker(cmd),
        } => attest::broker(*cmd),
        Cmd::Keys {
            cmd:
                KeysCmd::Generate {
                    model,
                    output,
                    mode,
                    force,
                },
        } => {
            let m = load(&model)?;
            let dir = output
                .unwrap_or_else(|| model.with_file_name(format!("{}.keys", m.program().name())));
            // Before generating (seconds and gigabytes for exact programs):
            // never replace a secret key unless asked.
            let secret = dir.join("secret.key");
            if !force && std::fs::symlink_metadata(&secret).is_ok() {
                return Err(Error::new(
                    Code::WrongKey,
                    format!(
                        "{} exists: replacing it would make every result encrypted under it \
                         undecryptable. Use another directory, or --force to replace it",
                        secret.display()
                    ),
                ));
            }
            let client = m.new_client(mode.parse()?)?;
            write_keys(&dir, &client)?;
            println!("wrote {} (key {})", dir.display(), &client.key_id()[..16]);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Audit {
            model,
            organization,
            after,
            ..
        } if model.as_os_str() == "list" && !model.exists() => {
            control::audit_list(organization.as_deref(), after)?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Login { url, token_file } => {
            control::login(&url, token_file.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Projects { cmd } => {
            control::projects(cmd)?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Assets { cmd } => {
            control::assets(cmd)?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Jobs { cmd } => {
            control::jobs(cmd, load)?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Security { cmd } => control::security(cmd),
        Cmd::Governance { cmd } => governance::governance(cmd),
        Cmd::Audit {
            model,
            keys,
            evaluator,
            json,
            ..
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
        Cmd::Plan {
            model,
            opts,
            out,
            json,
            deep,
        } => plan::plan(&model, &opts, out.as_deref(), json, deep),
        Cmd::Check { model, opts } => plan::check(&model, &opts),
        Cmd::Migrate { args } => migrate::migrate(&args),
        Cmd::Lineage {
            adapter,
            bundle,
            anchors,
            trust,
        } => trust::lineage(&adapter, &bundle.bundle, &anchors, &trust),
        Cmd::Export {
            adapter,
            bundle,
            anchors,
            trust,
        } => trust::export(&adapter, &bundle.bundle, &anchors, &trust),
        Cmd::Train { project } => {
            let python = std::env::var("PYTHON").unwrap_or_else(|_| "python3".into());
            let me =
                std::env::current_exe().map_err(|e| Error::new(Code::BadInput, format!("{e}")))?;
            let status = Command::new(&python)
                .arg(&project)
                .env("ENCOMPUTE_CLI", me)
                .status()
                .map_err(|e| Error::new(Code::BadInput, format!("{python}: {e}")))?;
            Ok(if status.success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Cmd::Info => {
            let yes = |b: bool| if b { "yes" } else { "no" };
            println!("encompute {}", env!("CARGO_PKG_VERSION"));
            println!(
                "openfhe             {}",
                yes(encompute_runtime::has_openfhe())
            );
            println!(
                "openfhe-exact       {}",
                yes(encompute_runtime::has_openfhe_exact())
            );
            println!("tfhe-rs             {}", yes(encompute_runtime::has_tfhe()));
            println!(
                "verified-execution  {}",
                yes(encompute_runtime::planning::available_catalog().verified_execution)
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Explain {
            model,
            governance,
            bundle,
            view,
            organization,
            url,
            checks,
            deep,
            measure,
            mode,
            ledger,
        } => {
            if let Some(job) = governance {
                if model.is_some() {
                    return Err(Error::new(
                        Code::Artifact,
                        "explain --governance takes a job or a bundle, not a model",
                    ));
                }
                return governance_bundle::explain(
                    job.as_deref(),
                    bundle.as_deref(),
                    &view,
                    organization.as_deref(),
                    url.as_deref(),
                    &checks,
                );
            }
            let Some(model) = model else {
                return Err(Error::new(
                    Code::Artifact,
                    "explain needs a model (or --governance JOB, or --governance --bundle FILE)",
                ));
            };
            let m = load(&model)?;
            let measured = match measure {
                Some(n) => Some(m.measure(mode.parse()?, n, 3)?),
                None => None,
            };
            print!("{}", m.explain(measured.as_ref()));
            if let Some(dir) = ledger {
                print!("\n{}", m.privacy_preview(&dir)?);
            }
            if deep {
                if let Some(o) = m.explain_optimization() {
                    print!("\n{o}");
                }
                let opts = plan::PlanOpts {
                    profile: "standard".into(),
                    infrastructure: None,
                    training: None,
                    prefer: "latency".into(),
                    local_only: false,
                    region: None,
                    allow_development: false,
                };
                print!("\n{}", plan::deep(&model, &opts)?);
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
    match std::fs::read_to_string(&pin) {
        Ok(hex) => return EvaluatorIdentity::from_public_key_hex(hex.trim()),
        // Only a missing pin means first use. A pin that exists but cannot
        // be read is refused: replacing it would trust whoever answers now.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(Error::new(
                Code::Receipt,
                format!(
                    "{}: the pinned evaluator key cannot be read ({e}); restore it, remove it \
                     to pin again on first use, or pass --trust-evaluator",
                    pin.display()
                ),
            ))
        }
    }
    let announced = remote.evaluator_identity()?;
    // Public: readable by all, whatever the umask.
    let io = |e: std::io::Error| Error::new(Code::Artifact, format!("{}: {e}", pin.display()));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&pin).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o644))
                .map_err(io)?;
        }
        f.write_all(format!("{}\n", announced.public_key_hex()).as_bytes())
            .map_err(io)?;
    }
    eprintln!(
        "trusting evaluator enc-eval:{} on first use (pinned in {})",
        announced.evaluator_id(),
        pin.display()
    );
    if plain_http_to_remote_host(remote.base_url()) {
        eprintln!(
            "warning: the evaluator key was pinned over plain HTTP to another host: anyone on \
             the path could have substituted it. Compare it with the evaluator's operator, or \
             pass --trust-evaluator."
        );
    }
    Ok(announced)
}

/// Plain `http://` to a host other than loopback.
fn plain_http_to_remote_host(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Userinfo is not the host.
    let host_port = authority.rsplit('@').next().unwrap_or("");
    let host = match host_port.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host_port.split(':').next().unwrap_or(""),
    };
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    !loopback
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
    allow_mock: bool,
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
    // The evidence the receipt must carry, as the online client expects it:
    // an execution proof exactly when the artifact requires one on a real
    // backend, otherwise none.
    let proof_expected = match (&model, kind) {
        (Some(m), Some(k)) => Some(m.compiled().proof_required() && k != BackendKind::Mock),
        _ => None,
    };
    let names_proof = !matches!(r.evidence, VerificationEvidence::None);

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
    match &r.evidence {
        VerificationEvidence::None => {
            println!("  {:<16}receipt only (no execution proof)", "Evidence")
        }
        VerificationEvidence::Vfhe {
            protocol,
            protocol_version,
            proof_digest,
            ..
        } => println!(
            "  {:<16}execution proof ({protocol} v{protocol_version}, proof {})",
            "Evidence",
            short(proof_digest)
        ),
    }

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
    bind(
        "evidence",
        if names_proof {
            "execution proof"
        } else {
            "none"
        },
        proof_expected.map(|p| if p { "execution proof" } else { "none" }.to_owned()),
    );
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
    println!(
        "  {:<16}{}",
        "Evidence kind",
        checked(proof_expected.is_some())
    );
    println!("  {:<16}{}", "Key", checked(rc.is_some()));
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
                } else if names_proof {
                    "NAMED BY THE RECEIPT, NOT CHECKED (no --proof)"
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
    // The mock backend encrypts nothing. A valid receipt for a mock run is
    // still only a mock run, and the expected backend may come from a
    // request envelope someone else made: refused unless asked for.
    let mock = r.backend == "mock" || kind == Some(BackendKind::Mock);
    if mock && !allow_mock && result.is_ok() {
        result = Err(Error::new(
            Code::Receipt,
            "the receipt is for the mock backend, which encrypts nothing: pass --allow-mock to \
             accept it (development and tests only)",
        ));
    }
    section("Receipt");
    if mock {
        println!("MOCK BACKEND: the inputs were NOT encrypted (development and tests only)");
    }
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
                let unchecked: Vec<&str> = [
                    ("trusted evaluator key", trusted.is_some()),
                    ("artifact", spec.is_some()),
                    ("evidence kind", proof_expected.is_some()),
                    ("key ID", rc.is_some()),
                    ("request", rc.is_some()),
                    ("response", oc.is_some()),
                ]
                .iter()
                .filter(|(_, ok)| !ok)
                .map(|(what, _)| *what)
                .collect();
                println!("NOT CHECKED: {}", unchecked.join(", "));
            }
            if names_proof {
                println!("EXECUTION PROOF NAMED BUT NOT CHECKED");
            } else {
                println!("EXECUTION PROOF NOT PRESENT");
            }
            // Exit 0 only for a fully verified receipt with nothing left
            // unchecked; 3 when bindings, or a proof the receipt names,
            // were left unchecked.
            Ok(if complete && !names_proof {
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

/// Write a key pair. Each file is written to a new temporary file (the
/// secret one created 0600) and renamed into place, evaluation keys first
/// and the secret key last: an existing secret key is never truncated.
fn write_keys(dir: &Path, client: &ClientSession) -> Result<()> {
    let envelope = zeroize::Zeroizing::new(client.secret_key_envelope()?);
    let keys = client
        .evaluation_keys()
        .expect("fresh client has evaluation keys");
    write_key_pair(dir, keys, &envelope)
}

fn write_key_pair(dir: &Path, keys: &[u8], envelope: &[u8]) -> Result<()> {
    write_key_pair_as(dir, keys, envelope, &temp_suffix()?)
}

/// A random suffix for this run's temporary files. A temporary file left
/// by a killed run (`kill -9`, power loss) never takes the name of a later
/// run's, as one named by process ID could once that ID is reused.
fn temp_suffix() -> Result<String> {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b)
        .map_err(|e| Error::new(Code::Artifact, format!("no randomness: {e}")))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn write_key_pair_as(dir: &Path, keys: &[u8], envelope: &[u8], suffix: &str) -> Result<()> {
    let io =
        |p: &Path, e: std::io::Error| Error::new(Code::Artifact, format!("{}: {e}", p.display()));
    std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
    // Both files are written and synced before either replaces anything,
    // so a failure while writing (a full disk) leaves the previous pair
    // untouched. The secret key is renamed last: a crash between the two
    // renames leaves the previous secret key, and what was encrypted under
    // it, beside the new evaluation keys, which are refused before any
    // upload (`run --remote`, `jobs run`, the Python SDK) and replaced by
    // running `keys generate --force` again.
    let eval =
        Staged::write(&dir.join("eval.keys"), keys, false, suffix).map_err(|(p, e)| io(&p, e))?;
    let secret = Staged::write(&dir.join("secret.key"), envelope, true, suffix)
        .map_err(|(p, e)| io(&p, e))?;
    eval.commit().map_err(|(p, e)| io(&p, e))?;
    secret.commit().map_err(|(p, e)| {
        Error::new(
            Code::Artifact,
            format!(
                "{}: {e}. The new eval.keys is already in place beside the previous secret \
                 key, which stays usable for what was encrypted under it; the pair is \
                 mismatched until `encompute keys generate --force` runs again",
                p.display()
            ),
        )
    })?;
    sync_dir(dir);
    Ok(())
}

/// A file written and synced under a temporary name in its directory
/// (`.NAME.tmp-SUFFIX`, created new), renamed over its path by
/// [`Staged::commit`]; removed if never committed.
struct Staged {
    tmp: PathBuf,
    path: PathBuf,
    committed: bool,
}

impl Staged {
    fn write(
        path: &Path,
        bytes: &[u8],
        secret: bool,
        suffix: &str,
    ) -> std::result::Result<Self, (PathBuf, std::io::Error)> {
        use std::io::Write;
        let name = path
            .file_name()
            .map_or_else(Default::default, |n| n.to_owned());
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(&name);
        tmp_name.push(format!(".tmp-{suffix}"));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        if secret {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = secret;
        let tmp = path.with_file_name(tmp_name);
        let mut f = opts.open(&tmp).map_err(|e| (tmp.clone(), e))?;
        // From here on the temporary file is ours: dropped, it is removed.
        let staged = Self {
            tmp,
            path: path.to_owned(),
            committed: false,
        };
        f.write_all(bytes)
            .and_then(|()| f.sync_all())
            .map_err(|e| (staged.path.clone(), e))?;
        Ok(staged)
    }

    fn commit(mut self) -> std::result::Result<(), (PathBuf, std::io::Error)> {
        std::fs::rename(&self.tmp, &self.path).map_err(|e| (self.path.clone(), e))?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// Make the renames in `dir` durable where the file system can sync a
/// directory. Best effort: the pair is already in place, and some file
/// systems (network and FUSE mounts) refuse to sync directories.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
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

#[cfg(test)]
mod tests {
    use super::plain_http_to_remote_host as warned;

    /// Both files of a pair are written before either replaces anything:
    /// when the secret key cannot be written, the previous pair stays as it
    /// was and no temporary file is left behind.
    #[test]
    fn a_key_pair_is_written_whole_or_not_at_all() {
        let dir = std::env::temp_dir().join(format!("encompute-keypair-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        super::write_key_pair(&dir, b"eval 1", b"secret 1").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                |f: &str| std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode("secret.key"), 0o600);
        }

        // The secret key's temporary name is taken: it cannot be written.
        let blocked = dir.join(".secret.key.tmp-blocked");
        std::fs::create_dir(&blocked).unwrap();
        assert!(super::write_key_pair_as(&dir, b"eval 2", b"secret 2", "blocked").is_err());
        let read = |f: &str| std::fs::read(dir.join(f)).unwrap();
        assert_eq!(read("eval.keys"), b"eval 1");
        assert_eq!(read("secret.key"), b"secret 1");
        std::fs::remove_dir(&blocked).unwrap();
        let mut left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["eval.keys", "secret.key"]);

        super::write_key_pair(&dir, b"eval 2", b"secret 2").unwrap();
        assert_eq!(read("eval.keys"), b"eval 2");
        assert_eq!(read("secret.key"), b"secret 2");

        // The secret key cannot be renamed into place after the evaluation
        // keys were: the error says the pair is mismatched and how to fix
        // it, and no temporary file is left behind.
        let other =
            std::env::temp_dir().join(format!("encompute-keypair-rename-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&other);
        std::fs::create_dir_all(other.join("secret.key")).unwrap();
        std::fs::write(other.join("secret.key").join("x"), b"").unwrap();
        let e = super::write_key_pair(&other, b"eval 3", b"secret 3").unwrap_err();
        assert!(
            e.message.contains("mismatched") && e.message.contains("keys generate --force"),
            "{}",
            e.message
        );
        assert_eq!(std::fs::read(other.join("eval.keys")).unwrap(), b"eval 3");
        let mut left: Vec<_> = std::fs::read_dir(&other)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["eval.keys", "secret.key"]);
        let _ = std::fs::remove_dir_all(&other);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_killed_runs_temporary_files_do_not_block_keys_generate() {
        // What an earlier run killed mid-write leaves, under the names a
        // run with this process ID used to choose.
        let dir =
            std::env::temp_dir().join(format!("encompute-keypair-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stale = [
            format!(".eval.keys.tmp-{}", std::process::id()),
            format!(".secret.key.tmp-{}", std::process::id()),
        ];
        for f in &stale {
            std::fs::write(dir.join(f), b"stale").unwrap();
        }
        super::write_key_pair(&dir, b"eval 1", b"secret 1").unwrap();
        super::write_key_pair(&dir, b"eval 2", b"secret 2").unwrap();
        let read = |f: &str| std::fs::read(dir.join(f)).unwrap();
        assert_eq!(read("eval.keys"), b"eval 2");
        assert_eq!(read("secret.key"), b"secret 2");
        // Neither run took or removed another run's files, and neither
        // left its own.
        let mut left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        let mut want = vec!["eval.keys".to_owned(), "secret.key".to_owned()];
        want.extend(stale.iter().cloned());
        want.sort();
        assert_eq!(left, want);
        for f in &stale {
            assert_eq!(read(f), b"stale");
        }
        // Each run picks its own suffix.
        let (a, b) = (super::temp_suffix().unwrap(), super::temp_suffix().unwrap());
        assert_ne!(a, b);
        assert!(
            a.len() == 16 && a.bytes().all(|c| c.is_ascii_hexdigit()),
            "{a}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pinning_over_plain_http_to_another_host_is_warned() {
        for quiet in [
            "https://eval.example",
            "http://127.0.0.1:8750",
            "http://localhost:8750/",
            "http://[::1]:8750",
        ] {
            assert!(!warned(quiet), "{quiet}");
        }
        for loud in [
            "http://eval.example:8750",
            "http://10.0.0.5:8750",
            "http://localhost.evil.net",
            "http://127.0.0.1@evil.net",
            "http://[::2]:8750",
        ] {
            assert!(warned(loud), "{loud}");
        }
    }
}
