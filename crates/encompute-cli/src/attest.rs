//! Attestation and policy-gated key release (ADR-011): `encompute attest`,
//! the broker commands under `encompute keys`, and `encompute workload`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;

use clap::{Args, Subcommand};
use encompute_ir::{Code, Error, Result};
use encompute_runtime::attestation::gcp::{ConfidentialSpaceAttester, ConfidentialSpaceProvider};
use encompute_runtime::attestation::mock::{MockHardware, MockProvider};
use encompute_runtime::attestation::{
    unix_now, AttestationEvidence, AttestationPolicy, AttestationRecord, Attester, DebugPolicy,
    TcbStatus, TeeKind, VerifiedWorkload, Verifier, WorkloadSession,
};
use encompute_runtime::keybroker::{
    acquire_keys, BrokerClient, BrokerMode, DevelopmentFileStore, KeyBroker, KeyMaterial,
    LocalKekStore, SecretStore,
};
use encompute_runtime::verification::EvaluatorSigner;
use encompute_runtime::{BackendKind, Model};

use crate::{load, short};

fn io(p: &Path, e: std::io::Error) -> Error {
    Error::new(Code::Artifact, format!("{}: {e}", p.display()))
}

fn read(p: &Path) -> Result<Vec<u8>> {
    std::fs::read(p).map_err(|e| io(p, e))
}

fn section(t: &str) {
    println!("\n{t}\n{}", "─".repeat(40));
}

/// Which attestation providers to trust.
#[derive(Args, Clone, Default)]
pub struct TrustArgs {
    /// Confidential Space: Google's token-signing keys, as a JWKS file or
    /// `google` to fetch the current ones.
    #[arg(long)]
    pub jwks: Option<String>,
    /// Confidential Space: the audience tokens must name (brokers always
    /// use their own ID).
    #[arg(long)]
    pub audience: Option<String>,
    /// DEVELOPMENT ONLY: accept mock evidence from this mock root (hex
    /// public key, from `encompute attest mock-root`).
    #[arg(long)]
    pub mock_root: Option<String>,
}

impl TrustArgs {
    pub(crate) fn verifier(&self, default_audience: Option<&str>) -> Result<Verifier> {
        let mut v = Verifier::new();
        if let Some(j) = &self.jwks {
            let jwks = if j == "google" {
                encompute_runtime::attested::fetch_google_jwks()?
            } else {
                String::from_utf8(read(Path::new(j))?)
                    .map_err(|_| Error::new(Code::Attestation, "the JWKS file is not UTF-8"))?
            };
            let aud = self
                .audience
                .as_deref()
                .or(default_audience)
                .ok_or_else(|| {
                    Error::new(Code::Attestation, "Confidential Space needs --audience")
                })?;
            v = v.with(ConfidentialSpaceProvider::new(&jwks, aud)?);
        }
        if let Some(h) = &self.mock_root {
            let b = hex32(h, "mock root")?;
            v = v.with(MockProvider::new(&b)?);
        }
        if v.providers().is_empty() {
            return Err(Error::new(
                Code::Attestation,
                "no attestation provider is trusted: pass --jwks (Confidential Space) or \
                 --mock-root (development)",
            ));
        }
        Ok(v)
    }
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    let b: Option<Vec<u8>> = (s.len() == 64)
        .then(|| {
            (0..32)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
                .collect()
        })
        .flatten();
    b.and_then(|b| b.try_into().ok())
        .ok_or_else(|| Error::new(Code::Attestation, format!("{what} must be 32 bytes of hex")))
}

fn tee(s: &str) -> Result<TeeKind> {
    Ok(match s {
        "intel_tdx" | "tdx" => TeeKind::IntelTdx,
        "amd_sev_snp" | "sev-snp" => TeeKind::AmdSevSnp,
        "amd_sev" | "sev" => TeeKind::AmdSev,
        "nvidia_confidential_gpu" => TeeKind::NvidiaConfidentialGpu,
        "mock" => TeeKind::Mock,
        _ => {
            return Err(Error::new(
                Code::WorkloadPolicy,
                format!("unknown TEE {s:?} (intel_tdx, amd_sev_snp, amd_sev, mock)"),
            ))
        }
    })
}

fn read_policy(p: &Path) -> Result<AttestationPolicy> {
    let policy: AttestationPolicy = serde_json::from_slice(&read(p)?)
        .map_err(|e| Error::new(Code::WorkloadPolicy, format!("{}: {e}", p.display())))?;
    policy.validate()?;
    Ok(policy)
}

/// A record or bare evidence.
fn read_evidence(p: &Path) -> Result<(AttestationEvidence, bool)> {
    let b = read(p)?;
    if let Ok(r) = AttestationRecord::from_bytes(&b) {
        return Ok((r.evidence, true));
    }
    Ok((AttestationEvidence::from_bytes(&b)?, false))
}

fn print_workload(w: &VerifiedWorkload, session: Option<&str>) {
    let provider = match w.provider.as_str() {
        "gcp-confidential-space" => "Google Confidential Space",
        "mock" => "mock (DEVELOPMENT ONLY)",
        p => p,
    };
    section("Provider");
    println!("  {provider}");
    section("TEE");
    println!("  {}", w.tee_kind);
    section("Workload");
    println!(
        "  {:<13}{}",
        "Image",
        w.image_digest.as_deref().unwrap_or("(none)")
    );
    println!(
        "  {:<13}{}",
        "Debug",
        if w.debug_enabled {
            "ENABLED"
        } else {
            "disabled"
        }
    );
    section("Bindings");
    let b = &w.binding;
    println!(
        "  {:<13}encspec1:{}",
        "Execution",
        short(&b.execution_spec_id)
    );
    if let Some(p) = &b.policy_id {
        println!("  {:<13}encpolicy1:{}", "Policy", short(p));
    }
    println!("  {:<13}{}", "Artifact", short(&b.artifact_digest));
    println!("  {:<13}{}", "Evaluator", short(&b.evaluator_public_key));
    if let Some(s) = session {
        println!("  {:<13}{}", "Session", short(s));
    }
    section("TCB");
    println!("  {:<13}{}", "Status", w.tcb_status);
}

#[derive(Subcommand)]
pub enum AttestCmd {
    /// Verify attestation evidence (or an attestation record) against an
    /// attestation policy.
    Verify {
        evidence: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[command(flatten)]
        trust: TrustArgs,
    },
    /// Print an attestation policy for an artifact: its execution spec,
    /// confidentiality policy and artifact digest, plus where it may run.
    Policy {
        model: PathBuf,
        /// Backend of the execution spec (mock, openfhe, tfhe-rs).
        #[arg(long, default_value = "openfhe")]
        backend: String,
        /// Allowed workload image digests (`sha256:…`).
        #[arg(long, required = true)]
        image: Vec<String>,
        /// Allowed TEEs: intel_tdx, amd_sev_snp, amd_sev (mock for development).
        #[arg(long, required = true)]
        tee: Vec<String>,
        /// unknown, out_of_date, supported or current.
        #[arg(long, default_value = "supported")]
        minimum_tcb: String,
        #[arg(long)]
        allow_debug: bool,
        #[arg(long)]
        require_gpu: bool,
        /// Accept development-only (mock) evidence. Never in production.
        #[arg(long)]
        development: bool,
    },
    /// DEVELOPMENT ONLY: create a mock hardware root (a seed file, mode
    /// 0600) and print its public key for `--mock-root`.
    MockRoot { seed: PathBuf },
}

pub fn attest(cmd: AttestCmd) -> Result<ExitCode> {
    match cmd {
        AttestCmd::Verify {
            evidence,
            policy,
            trust,
        } => {
            let (e, is_record) = read_evidence(&evidence)?;
            let policy = read_policy(&policy)?;
            let verifier = trust.verifier(None)?;
            // A record is history (its session ended); fresh evidence must
            // not have expired. Challenges are the broker's to check.
            let now = (!is_record).then(unix_now);
            let session = WorkloadSession::session_id_of(&e.binding)?;
            println!("WORKLOAD ATTESTATION");
            let result = verifier
                .verify_claims(&e, now)
                .and_then(|w| policy.check(&w).map(|()| w));
            match result {
                Ok(w) => {
                    print_workload(&w, Some(&session));
                    section("Result");
                    if w.security != encompute_runtime::attestation::Security::Production {
                        println!("  DEVELOPMENT EVIDENCE: protects nothing");
                    }
                    println!("  Freshness    checked by the key broker's challenge");
                    println!("ATTESTATION VERIFIED");
                    Ok(ExitCode::SUCCESS)
                }
                Err(err) => {
                    section("Result");
                    println!("  {err}");
                    println!("ATTESTATION REJECTED");
                    Ok(ExitCode::from(1))
                }
            }
        }
        AttestCmd::Policy {
            model,
            backend,
            image,
            tee: tees,
            minimum_tcb,
            allow_debug,
            require_gpu,
            development,
        } => {
            let m = load(&model)?;
            let kind = BackendKind::parse(&backend)
                .ok_or_else(|| Error::new(Code::BadInput, format!("unknown backend {backend}")))?;
            let mut p = encompute_runtime::attested::attestation_policy(&m, kind);
            p.allowed_images = image;
            p.allowed_tee = tees.iter().map(|t| tee(t)).collect::<Result<_>>()?;
            p.minimum_tcb = match minimum_tcb.as_str() {
                "unknown" => TcbStatus::Unknown,
                "out_of_date" => TcbStatus::OutOfDate,
                "supported" => TcbStatus::Supported,
                "current" => TcbStatus::Current,
                t => {
                    return Err(Error::new(
                        Code::BadInput,
                        format!("unknown TCB status {t}"),
                    ))
                }
            };
            p.debug = if allow_debug {
                DebugPolicy::Allowed
            } else {
                DebugPolicy::Forbidden
            };
            p.require_gpu_attestation = require_gpu;
            p.allow_development = development;
            p.validate()?;
            println!("{}", serde_json::to_string_pretty(&p).expect("JSON"));
            Ok(ExitCode::SUCCESS)
        }
        AttestCmd::MockRoot { seed } => {
            let hw = mock_hardware(&seed)?;
            eprintln!("DEVELOPMENT ONLY: mock evidence protects nothing");
            println!("{}", hex(&hw.public_key()));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn write_private(p: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(p)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| io(p, e))
}

fn mock_hardware(seed: &Path) -> Result<MockHardware> {
    if seed.exists() {
        let b: [u8; 32] = read(seed)?
            .try_into()
            .map_err(|_| Error::new(Code::Attestation, "a mock root seed file is 32 bytes"))?;
        return Ok(MockHardware::from_seed(&b));
    }
    let signer = EvaluatorSigner::generate()?;
    write_private(seed, &signer.seed())?;
    Ok(MockHardware::from_seed(&signer.seed()))
}

// ---- broker (owner side) ------------------------------------------------

#[derive(Args, Clone)]
pub struct BrokerFile {
    /// The broker's state file (mode 0600).
    #[arg(long, default_value = "broker.json")]
    pub broker: PathBuf,
    /// Key-encryption key file (32 bytes, created mode 0600 if missing):
    /// keys in the state file are wrapped under it. Required for
    /// production brokers; without it keys are stored in plaintext
    /// (development only).
    #[arg(long)]
    pub kek: Option<PathBuf>,
}

impl BrokerFile {
    fn store(&self) -> Result<Box<dyn SecretStore>> {
        Ok(match &self.kek {
            Some(p) => Box::new(LocalKekStore::open_or_create(p)?),
            None => Box::new(DevelopmentFileStore),
        })
    }
}

#[derive(Subcommand)]
pub enum BrokerCmd {
    /// Protect an asset key under an attestation policy (creates the broker
    /// state on first use).
    Protect {
        #[arg(long)]
        asset: String,
        /// Attestation policy (from `encompute attest policy`).
        #[arg(long)]
        policy: PathBuf,
        /// Key file to protect (default: a fresh random 32-byte key).
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// The broker's ID, and the audience workloads attest to (first use).
        #[arg(long)]
        broker_id: Option<String>,
        /// A development broker (accepts mock evidence where policies allow).
        #[arg(long)]
        development: bool,
        #[command(flatten)]
        file: BrokerFile,
    },
    /// Issue a challenge (debug: normally over `keys serve`).
    Challenge {
        #[command(flatten)]
        file: BrokerFile,
    },
    /// Verify attestation evidence and release an asset key, sealed to the
    /// attested session (debug: normally over `keys serve`).
    Release {
        #[arg(long)]
        asset: String,
        /// Attestation evidence (JSON).
        #[arg(long)]
        attestation: PathBuf,
        /// Where to write the sealed key grant.
        #[arg(long, default_value = "grant.json")]
        out: PathBuf,
        #[command(flatten)]
        trust: TrustArgs,
        #[command(flatten)]
        file: BrokerFile,
    },
    /// Replace an asset's key with a new version.
    Rotate {
        #[arg(long)]
        asset: String,
        #[command(flatten)]
        file: BrokerFile,
    },
    /// Revoke a key version (default: the current one).
    Revoke {
        #[arg(long)]
        asset: String,
        #[arg(long)]
        version: Option<u64>,
        #[command(flatten)]
        file: BrokerFile,
    },
    /// Serve challenges, attestation and key release over HTTP.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8760")]
        listen: String,
        #[command(flatten)]
        trust: TrustArgs,
        #[command(flatten)]
        file: BrokerFile,
    },
}

fn open_broker(file: &BrokerFile, trust: Option<&TrustArgs>) -> Result<KeyBroker> {
    let state: encompute_runtime::keybroker::BrokerState =
        serde_json::from_slice(&read(&file.broker)?)
            .map_err(|e| Error::new(Code::KeyRelease, format!("{}: {e}", file.broker.display())))?;
    let verifier = match trust {
        Some(t) => {
            // A broker's audience is its own ID: evidence addressed to
            // another broker is never accepted here.
            if t.audience.as_deref().is_some_and(|a| a != state.broker_id) {
                return Err(Error::new(
                    Code::Attestation,
                    format!(
                        "a broker's audience is its ID ({}); drop --audience",
                        state.broker_id
                    ),
                ));
            }
            t.verifier(Some(&state.broker_id))?
        }
        None => Verifier::new(),
    };
    KeyBroker::load(&file.broker, verifier, file.store()?)
}

pub fn broker(cmd: BrokerCmd) -> Result<ExitCode> {
    match cmd {
        BrokerCmd::Protect {
            asset,
            policy,
            key_file,
            broker_id,
            development,
            file,
        } => {
            let mut b = if file.broker.exists() {
                open_broker(&file, None)?
            } else {
                let id = broker_id.ok_or_else(|| {
                    Error::new(Code::KeyRelease, "a new broker needs --broker-id")
                })?;
                let mode = if development {
                    BrokerMode::Development
                } else {
                    BrokerMode::Production
                };
                KeyBroker::new(&id, mode, Verifier::new(), file.store()?)?
            };
            let key = match &key_file {
                Some(p) => Some(KeyMaterial::from_bytes(&zeroize::Zeroizing::new(read(p)?))?),
                None => None,
            };
            let v = b.add_secret(&asset, key, read_policy(&policy)?)?;
            b.save(&file.broker)?;
            println!(
                "{:<20}{asset}\n{:<20}{v}\n{:<20}{} ({})",
                "Asset",
                "Key version",
                "Broker",
                b.id(),
                match b.mode() {
                    BrokerMode::Production => "production",
                    BrokerMode::Development => "DEVELOPMENT",
                }
            );
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::Challenge { file } => {
            let mut b = open_broker(&file, None)?;
            let c = b.challenge()?;
            b.save(&file.broker)?;
            println!("{}", serde_json::to_string_pretty(&c).expect("JSON"));
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::Release {
            asset,
            attestation,
            out,
            trust,
            file,
        } => {
            let mut b = open_broker(&file, Some(&trust))?;
            let e = AttestationEvidence::from_bytes(&read(&attestation)?)?;
            let result = b.release_with(&e, &asset);
            // The challenge is consumed whatever the outcome.
            b.save(&file.broker)?;
            let binding = &e.binding;
            println!("{:<21}{asset}", "Asset");
            if let Some(p) = &binding.policy_id {
                println!("{:<21}encpolicy1:{}", "Policy", short(p));
            }
            println!(
                "{:<21}encspec1:{}",
                "Execution",
                short(&binding.execution_spec_id)
            );
            println!(
                "{:<21}{}",
                "Session",
                short(&WorkloadSession::session_id_of(binding)?)
            );
            println!();
            match result {
                Ok((w, grant)) => {
                    std::fs::write(&out, serde_json::to_vec_pretty(&grant).expect("JSON"))
                        .map_err(|e| io(&out, e))?;
                    println!(
                        "{:<21}VERIFIED ({}, {})",
                        "ATTESTATION", w.provider, w.tee_kind
                    );
                    println!("{:<21}SATISFIED", "POLICY");
                    println!(
                        "{:<21}AUTHORIZED (key version {}, sealed to the session: {})",
                        "KEY RELEASE",
                        grant.header.key_version,
                        out.display()
                    );
                    Ok(ExitCode::SUCCESS)
                }
                Err(err) => {
                    let (a, p) = match err.code {
                        Code::WorkloadPolicy => ("VERIFIED", "NOT SATISFIED"),
                        Code::KeyRelease => ("VERIFIED", "SATISFIED"),
                        _ => ("REJECTED", "NOT EVALUATED"),
                    };
                    println!("{:<21}{a}", "ATTESTATION");
                    println!("{:<21}{p}", "POLICY");
                    println!("{:<21}REFUSED: {err}", "KEY RELEASE");
                    Ok(ExitCode::from(1))
                }
            }
        }
        BrokerCmd::Rotate { asset, file } => {
            let mut b = open_broker(&file, None)?;
            let v = b.rotate_key(&asset)?;
            b.save(&file.broker)?;
            println!("{asset}: key version {v} is now current");
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::Revoke {
            asset,
            version,
            file,
        } => {
            let mut b = open_broker(&file, None)?;
            let v = b.revoke(&asset, version)?;
            b.save(&file.broker)?;
            println!("{asset}: key version {v} revoked");
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::Serve {
            listen,
            trust,
            file,
        } => {
            let b = open_broker(&file, Some(&trust))?;
            let server = tiny_http::Server::http(&listen)
                .map_err(|e| Error::new(Code::Remote, format!("{listen}: {e}")))?;
            eprintln!(
                "key broker {} ({:?}) on http://{listen}, trusting: {}",
                b.id(),
                b.mode(),
                trust.verifier(Some(b.id()))?.providers().join(", ")
            );
            encompute_runtime::keybroker::serve(&Mutex::new(b), &server);
            Ok(ExitCode::SUCCESS)
        }
    }
}

// ---- workload (TEE side) --------------------------------------------------

/// The attester a workload uses.
#[derive(Args)]
pub struct AttesterArgs {
    /// confidential-space, or mock (development only).
    #[arg(long, default_value = "confidential-space")]
    attester: String,
    /// Mock root seed (mock attester).
    #[arg(long)]
    mock_seed: Option<PathBuf>,
    /// Mock attester: the image digest to claim.
    #[arg(long)]
    mock_image: Option<String>,
}

impl AttesterArgs {
    fn attester(&self) -> Result<Box<dyn Attester>> {
        match self.attester.as_str() {
            "confidential-space" => Ok(Box::new(ConfidentialSpaceAttester::default())),
            "mock" => {
                let seed = self.mock_seed.as_ref().ok_or_else(|| {
                    Error::new(Code::Attestation, "the mock attester needs --mock-seed")
                })?;
                let image = self.mock_image.as_ref().ok_or_else(|| {
                    Error::new(Code::Attestation, "the mock attester needs --mock-image")
                })?;
                eprintln!("DEVELOPMENT ONLY: mock attestation protects nothing");
                Ok(Box::new(mock_hardware(seed)?.attester(image)))
            }
            a => Err(Error::new(
                Code::Attestation,
                format!("unknown attester {a}"),
            )),
        }
    }
}

#[derive(Subcommand)]
pub enum WorkloadCmd {
    /// Inside the TEE: attest to each broker and receive the asset keys,
    /// sealed to this session. Writes the attestation record the
    /// evaluator's receipts bind; never writes or prints keys.
    Keys {
        model: PathBuf,
        /// Backend of the execution spec (mock, openfhe, tfhe-rs).
        #[arg(long, default_value = "openfhe")]
        backend: String,
        /// `ASSET@URL`, once per asset.
        #[arg(long = "key", required = true)]
        keys: Vec<String>,
        /// The evaluator identity (created if missing), shared with
        /// `encompute-evaluator serve --identity`.
        #[arg(long)]
        identity: PathBuf,
        #[command(flatten)]
        attester: AttesterArgs,
        /// Where to write the attestation record.
        #[arg(long, default_value = "attestation.json")]
        record: PathBuf,
    },
    /// Debug: answer one challenge file (from `keys challenge`) with
    /// evidence, for `keys release`. The session key is discarded, so the
    /// resulting grant cannot be opened.
    Attest {
        model: PathBuf,
        #[arg(long, default_value = "openfhe")]
        backend: String,
        /// The challenge (JSON).
        #[arg(long)]
        challenge: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[command(flatten)]
        attester: AttesterArgs,
        /// Where to write the evidence.
        #[arg(long, default_value = "evidence.json")]
        out: PathBuf,
    },
}

fn identity(path: &Path) -> Result<EvaluatorSigner> {
    if path.exists() {
        let seed: [u8; 32] = read(path)?
            .try_into()
            .map_err(|_| Error::new(Code::Receipt, "an evaluator identity file is 32 bytes"))?;
        return Ok(EvaluatorSigner::from_seed(&seed));
    }
    let s = EvaluatorSigner::generate()?;
    write_private(path, &s.seed())?;
    Ok(s)
}

fn spec_of(
    model: &Path,
    backend: &str,
) -> Result<(Model, encompute_runtime::verification::ExecutionSpec)> {
    let m: Model = load(model)?;
    let kind = BackendKind::parse(backend)
        .ok_or_else(|| Error::new(Code::BadInput, format!("unknown backend {backend}")))?;
    let spec = encompute_runtime::verification_spec(&m, kind);
    Ok((m, spec))
}

pub fn workload(cmd: WorkloadCmd) -> Result<ExitCode> {
    let (model, backend, keys, id_path, attester, record) = match cmd {
        WorkloadCmd::Keys {
            model,
            backend,
            keys,
            identity,
            attester,
            record,
        } => (model, backend, keys, identity, attester, record),
        WorkloadCmd::Attest {
            model,
            backend,
            challenge,
            identity: id_path,
            attester,
            out,
        } => {
            let (m, spec) = spec_of(&model, &backend)?;
            let c: encompute_runtime::attestation::AttestationChallenge =
                serde_json::from_slice(&read(&challenge)?).map_err(|e| {
                    Error::new(Code::Freshness, format!("{}: {e}", challenge.display()))
                })?;
            let session = WorkloadSession::new(&identity(&id_path)?.identity());
            let binding = session.binding(
                &c,
                &spec.id().hex(),
                spec.policy_id.as_deref(),
                &m.artifact_digest(),
            );
            let e = attester.attester()?.attest(&c, &binding)?;
            std::fs::write(&out, e.to_bytes()?).map_err(|x| io(&out, x))?;
            println!(
                "evidence for challenge {} written to {}",
                short(&c.nonce),
                out.display()
            );
            return Ok(ExitCode::SUCCESS);
        }
    };
    let (m, spec) = spec_of(&model, &backend)?;
    let attester = attester.attester()?;
    let requests = keys
        .iter()
        .map(|k| {
            let (asset, url) = k.split_once('@').ok_or_else(|| {
                Error::new(Code::BadInput, format!("--key {k}: expected ASSET@URL"))
            })?;
            Ok((BrokerClient::new(url), asset.to_owned()))
        })
        .collect::<Result<Vec<_>>>()?;
    let signer = identity(&id_path)?;
    let session = WorkloadSession::new(&signer.identity());
    let got = acquire_keys(
        attester.as_ref(),
        &session,
        &spec.id().hex(),
        spec.policy_id.as_deref(),
        &m.artifact_digest(),
        &requests,
    )?;
    println!("{:<14}{}", "Session", short(&session.session_id()));
    println!("{:<14}encspec1:{}", "Execution", short(&spec.id().hex()));
    for k in &got {
        println!(
            "{:<14}{} v{} from {}: RECEIVED ({} bytes, sealed to this session)",
            "Key",
            k.asset_id,
            k.header.key_version,
            k.header.broker_id,
            k.key.len()
        );
    }
    // The receipts bind one record: the first broker's.
    if let Some(first) = got.first() {
        std::fs::write(&record, first.record.to_bytes()?).map_err(|e| io(&record, e))?;
        println!(
            "{:<14}{} (attestation {})",
            "Record",
            record.display(),
            short(&first.record.id()?)
        );
    }
    Ok(ExitCode::SUCCESS)
}
