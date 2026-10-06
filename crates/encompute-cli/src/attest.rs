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
    acquire_keys, BrokerClient, BrokerMode, DevelopmentFileMark, DevelopmentFileStore,
    ExpectedState, GenerationMark, GovernanceConfig, KeyBroker, KeyMaterial, LocalKekStore,
    OpenBaoKvMark, SecretStore,
};
use encompute_runtime::trust::authz::{SignedAuthorizationV2, SignedRevocationV2};
use encompute_runtime::verification::{hex, EvaluatorSigner};
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
            let google = j == "google";
            let jwks = if google {
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
            let mut p = ConfidentialSpaceProvider::new(&jwks, aud)?;
            if google {
                // Google rotates its token-signing keys: a long-running
                // broker refetches them (on an unknown key ID, and hourly).
                p = p.with_refresh(
                    encompute_runtime::attested::fetch_google_jwks,
                    GOOGLE_JWKS_MAX_AGE_SECS,
                );
            }
            v = v.with(p);
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

/// How long Google's fetched token-signing keys are used before they are
/// fetched again (a withdrawn key then stops being trusted).
const GOOGLE_JWKS_MAX_AGE_SECS: u64 = 3600;

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

pub(crate) fn tee(s: &str) -> Result<TeeKind> {
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
    /// DEVELOPMENT ONLY: serve Confidential Space launcher tokens on a Unix
    /// socket, signed with a test key, so the real attester and a
    /// production broker can be exercised without Google Cloud. Brokers
    /// accept them only with the matching `--jwks`; no hardware is involved.
    SimulateLauncher {
        /// The Unix socket the attester connects to.
        #[arg(long)]
        socket: PathBuf,
        /// RSA private key (PEM) standing in for Google's signing key.
        #[arg(long)]
        key: PathBuf,
        /// Its key ID in the JWKS.
        #[arg(long, default_value = "test-key-1")]
        kid: String,
        /// The container image digest the tokens measure.
        #[arg(long)]
        image: String,
        /// Report a debug-enabled VM.
        #[arg(long)]
        debug: bool,
        #[arg(long, default_value = "GCP_INTEL_TDX")]
        hwmodel: String,
        #[arg(long, default_value_t = 3600)]
        lifetime: u64,
    },
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
        AttestCmd::SimulateLauncher {
            socket,
            key,
            kid,
            image,
            debug,
            hwmodel,
            lifetime,
        } => {
            let pem = read(&key)?;
            let key = jsonwebtoken::EncodingKey::from_rsa_pem(&pem)
                .map_err(|e| Error::new(Code::Attestation, format!("{}: {e}", key.display())))?;
            crate::launcher_sim::LauncherSim {
                key,
                kid,
                image_digest: image,
                debug,
                hwmodel,
                lifetime,
            }
            .serve(&socket)?;
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
    /// A customer-managed root key wrapping the broker's KEK:
    /// `openbao:MOUNT/KEY` (OpenBao or Vault Transit; BAO_ADDR and
    /// BAO_TOKEN_FILE from the environment) or `development:FILE`.
    #[arg(long, conflicts_with = "kek")]
    pub root_key: Option<String>,
    /// The organization this broker serves (set once, recorded with every
    /// key): the root key's owner, and the only organization whose
    /// revocations are accepted.
    #[arg(long)]
    pub organization: Option<String>,
    /// Where the root-wrapped KEK is kept (not secret).
    #[arg(long, default_value = "kek.wrapped.json")]
    pub wrapped_kek: PathBuf,
    /// Where the state's generation mark is kept, so that an older copy of
    /// the state file is refused: `openbao` (a KV-v2 engine, --kv-mount;
    /// BAO_ADDR and the token as for the root key) or `file:PATH`
    /// (development only). A governed production broker needs one; once a
    /// state is saved under a mark, every command on it needs the mark.
    #[arg(long)]
    pub generation_mark: Option<String>,
    /// The KV-v2 mount holding the generation mark (with
    /// `--generation-mark openbao`).
    #[arg(long)]
    pub kv_mount: Option<String>,
    /// When the generation mark is first created from the state file: the
    /// generation the file must have (otherwise the first start trusts the
    /// file as found). Not used once the mark exists.
    #[arg(long)]
    pub expect_generation: Option<u64>,
    /// With --expect-generation: the state MAC (hex, as in the state file)
    /// the file must have.
    #[arg(long, requires = "expect_generation")]
    pub expect_state_mac: Option<String>,
}

impl BrokerFile {
    fn root(&self) -> Result<Option<encompute_runtime::keybroker::RootWrappedKekStore>> {
        use encompute_runtime::keybroker::{
            DevelopmentRootKey, OpenBaoTransit, RootKeyProvider, RootWrappedKekStore,
        };
        let Some(spec) = &self.root_key else {
            return Ok(None);
        };
        let org = self
            .organization
            .as_deref()
            .ok_or_else(|| Error::new(Code::KeyRelease, "--root-key needs --organization"))?;
        let provider: Box<dyn RootKeyProvider> = match spec.split_once(':') {
            Some(("openbao", rest)) => {
                let (mount, key) = rest
                    .split_once('/')
                    .ok_or_else(|| Error::new(Code::KeyRelease, "openbao:MOUNT/KEY"))?;
                Box::new(OpenBaoTransit::from_env(mount, key)?)
            }
            Some(("development", file)) => {
                eprintln!("DEVELOPMENT ONLY: a local root key protects nothing");
                Box::new(DevelopmentRootKey::open(std::path::Path::new(file))?)
            }
            _ => {
                return Err(Error::new(
                    Code::KeyRelease,
                    "--root-key openbao:MOUNT/KEY or development:FILE",
                ))
            }
        };
        Ok(Some(RootWrappedKekStore::open_or_create(
            &self.wrapped_kek,
            provider,
            org,
        )?))
    }

    /// The generation mark of broker `broker_id`, if configured.
    fn mark(&self, broker_id: &str) -> Result<Option<Box<dyn GenerationMark>>> {
        let usage = || {
            Error::new(
                Code::KeyRelease,
                "--generation-mark openbao (with --kv-mount MOUNT) or file:PATH",
            )
        };
        let Some(spec) = &self.generation_mark else {
            if self.kv_mount.is_some() || self.expect_generation.is_some() {
                return Err(usage());
            }
            return Ok(None);
        };
        Ok(Some(match (spec.as_str(), spec.split_once(':')) {
            ("openbao", _) => {
                let mount = self.kv_mount.as_deref().ok_or_else(usage)?;
                Box::new(OpenBaoKvMark::from_env(mount, broker_id)?)
            }
            (_, Some(("file", path))) if !path.is_empty() && self.kv_mount.is_none() => {
                eprintln!("DEVELOPMENT ONLY: a generation mark in a local file protects little");
                Box::new(DevelopmentFileMark::new(Path::new(path), broker_id))
            }
            _ => return Err(usage()),
        }))
    }

    /// What the operator expects of the state when its mark is first
    /// created.
    fn expected(&self) -> Option<ExpectedState> {
        self.expect_generation.map(|generation| ExpectedState {
            generation,
            state_mac: self.expect_state_mac.clone(),
        })
    }

    fn store(&self) -> Result<Box<dyn SecretStore>> {
        if let Some(r) = self.root()? {
            return Ok(Box::new(r));
        }
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
    /// Revoke a key version (default: the current one). Also replaces the
    /// KEK, so an older copy of the state file no longer yields the revoked
    /// key under the KEK that is current afterwards (a copy of the old KEK
    /// itself does: see `rotate-root --retire-old-versions`).
    Revoke {
        #[arg(long)]
        asset: String,
        #[arg(long)]
        version: Option<u64>,
        #[command(flatten)]
        file: BrokerFile,
    },
    /// Re-wrap every key under a new KEK (rotation), or move development
    /// plaintext keys under one.
    Rewrap {
        /// The new key-encryption key file (created, mode 0600, if missing).
        #[arg(long)]
        new_kek: PathBuf,
        #[command(flatten)]
        file: BrokerFile,
    },
    /// Rotate the organization's root key and re-wrap the KEK under the new
    /// version (asset keys are untouched).
    RotateRoot {
        #[command(flatten)]
        file: BrokerFile,
        /// Record the rotation in the control plane's audit trail (needs
        /// `encompute login` as the organization's security admin).
        #[arg(long)]
        report: bool,
        /// Then retire every older root key version for good, so a wrapped
        /// KEK from an older backup can never be opened again. Irreversible
        /// and shared by every KEK wrapped under this root key: first
        /// rotate-root for every other broker of the organization.
        #[arg(long)]
        retire_old_versions: bool,
    },
    /// Authenticate a broker state file written by an earlier Encompute
    /// (before states were authenticated under the KEK). Prints what the
    /// state releases, and to whom; check it against your own records (an
    /// unauthenticated file may have been edited), then rerun with
    /// --confirm.
    UpgradeState {
        /// Authenticate the state as printed.
        #[arg(long)]
        confirm: bool,
        #[command(flatten)]
        file: BrokerFile,
    },
    /// Governed projects: pin the owner organization's governance key at
    /// this broker. From then on only authorizations it signed are
    /// installed, and every key is released only in a governed release.
    GovernanceKey {
        #[command(subcommand)]
        cmd: GovernanceKeyCmd,
    },
    /// Governed projects: bind an asset's key to one registered source
    /// version (its version ID, 64 hex characters). Set once; a bound key
    /// is released only with its owner's authorization and a release
    /// ticket.
    BindVersion {
        asset: String,
        version_id: String,
        /// The version is a derived result this organization holds as
        /// custodian: the organization's signed release record of it (JSON),
        /// which binds the key to the result and its lineage owners.
        #[arg(long, value_name = "RELEASE_RECORD", requires = "cosignature")]
        derived: Option<PathBuf>,
        /// With --derived: the control plane's co-signature of the record
        /// (`release_cosignature`, returned when the result was recorded).
        #[arg(long, value_name = "COSIGNATURE", requires = "derived")]
        cosignature: Option<PathBuf>,
        #[command(flatten)]
        control: ControlKeyArg,
        #[command(flatten)]
        file: BrokerFile,
    },
    /// Governed projects: after a lineage owner rotated its governance key,
    /// re-bind a derived result's key to the owners' current keys, under
    /// the control plane's re-issued co-signature (from POST
    /// /v1/assets/{id}/release-cosignature). Only the lineage owners' key
    /// IDs change, each to the key pinned here from the control plane's
    /// attestation (pin-lineage first).
    RebindLineage {
        asset: String,
        /// The re-issued co-signature (JSON: `release_cosignature`).
        #[arg(long, value_name = "COSIGNATURE")]
        cosignature: PathBuf,
        #[command(flatten)]
        control: ControlKeyArg,
        #[command(flatten)]
        file: BrokerFile,
    },
    /// Governed projects: install or revoke the owner's authorizations at
    /// this broker.
    Authorization {
        #[command(subcommand)]
        cmd: AuthorizationCmd,
    },
    /// Serve challenges, attestation and key release over HTTP. With
    /// ENCOMPUTE_CONTROL_PUBLIC_KEY and ENCOMPUTE_SERVICE_ID set, also accept
    /// revocations from that control plane, for the one organization this
    /// broker serves (--organization).
    /// A governed production broker (governance key pinned) needs a
    /// generation mark (--generation-mark openbao --kv-mount MOUNT): it
    /// refuses to start without one.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8760")]
        listen: String,
        /// Requests allowed per source address per minute.
        #[arg(long, default_value_t = encompute_runtime::keybroker::REQUESTS_PER_MINUTE)]
        requests_per_minute: u32,
        /// The control plane's public key (64 hex characters): governed
        /// releases need a release ticket it signed. Defaults to
        /// ENCOMPUTE_CONTROL_PUBLIC_KEY.
        #[arg(long)]
        control_key: Option<String>,
        /// Development only (a development broker with
        /// ENCOMPUTE_ENV=development): release governed keys without a
        /// release ticket. The owner's authorization is still required.
        #[arg(long)]
        no_require_ticket: bool,
        /// Replace the control-plane key pinned in the broker's state with
        /// --control-key (only after the control plane's key really
        /// changed). Printed as an audit line.
        #[arg(long, requires = "control_key")]
        replace_control_key: bool,
        /// How old, in seconds, a lineage owner's key attestation may be
        /// when a release or export of a derived result relies on it;
        /// older, re-attest it (pin-lineage) first. 24 hours by default,
        /// at most 7 days (604800).
        #[arg(long, default_value_t = encompute_runtime::keybroker::DEFAULT_LINEAGE_ATTESTATION_MAX_AGE_SECS)]
        lineage_attestation_max_age: u64,
        #[command(flatten)]
        trust: TrustArgs,
        #[command(flatten)]
        file: BrokerFile,
    },
}

/// The control plane's public key, which statements it signed (key
/// attestations, co-signatures) are verified under.
#[derive(Args)]
pub struct ControlKeyArg {
    /// The control plane's public key (64 hex characters). Defaults to
    /// ENCOMPUTE_CONTROL_PUBLIC_KEY. The first use pins it in the broker's
    /// state; later uses must name the same key.
    #[arg(long = "control-key")]
    control_key: Option<String>,
    /// Replace the control-plane key pinned in the broker's state with
    /// this one (only after the control plane's key really changed). The
    /// replacement is printed as an audit line.
    #[arg(long)]
    replace_control_key: bool,
}

/// Replaces `b`'s pinned control-plane key with `key` (the owner's
/// explicit act), printing the audit line that records it.
fn replace_control_key(b: &mut KeyBroker, key: &str) -> Result<()> {
    let previous = b.replace_control_key(key)?;
    eprintln!(
        "AUDIT key_broker.control_key.replaced broker={} organization={} previous={} new={key} at={}",
        b.id(),
        b.organization().unwrap_or("-"),
        previous.as_deref().unwrap_or("-"),
        encompute_verification::service::now()
    );
    Ok(())
}

impl ControlKeyArg {
    /// `b`, accepting statements signed by the control plane's key: the
    /// key pinned in its state (pinned now if none is), or, with
    /// --replace-control-key, this one replacing it.
    fn configure(&self, mut b: KeyBroker) -> Result<KeyBroker> {
        let key = self
            .control_key
            .clone()
            .or_else(|| std::env::var("ENCOMPUTE_CONTROL_PUBLIC_KEY").ok())
            .ok_or_else(|| {
                Error::new(
                    Code::GovernanceKeyRevoked,
                    "the control plane's public key is needed to verify what it signed: \
                     --control-key, or ENCOMPUTE_CONTROL_PUBLIC_KEY",
                )
            })?;
        if self.replace_control_key {
            replace_control_key(&mut b, &key)?;
        }
        b.with_governance(GovernanceConfig::new(&key))
    }
}

#[derive(Subcommand)]
pub enum GovernanceKeyCmd {
    /// Pin the organization's governance public key (set once).
    Pin {
        /// The governance public key (64 hex characters, as `encompute
        /// governance keygen` prints it).
        #[arg(long)]
        key: String,
        #[command(flatten)]
        file: BrokerFile,
    },
    /// Pin the governance key of another organization whose data this
    /// organization's derived results come from, from the control plane's
    /// signed attestation of it (--attestation FILE, or fetched with --url):
    /// its authorizations of their use are then installed and required
    /// here. A later attestation of another key replaces the pin (a
    /// rotation); an attestation that the key was revoked unpins it.
    PinLineage {
        /// The other organization.
        #[arg(long = "for", id = "lineage_owner", value_name = "ORG")]
        organization: String,
        /// The control plane's attestation (JSON, from GET
        /// /v1/organizations/{org}/governance-key-attestation).
        #[arg(long, conflicts_with = "url", required_unless_present = "url")]
        attestation: Option<PathBuf>,
        /// Fetch the attestation from this control plane (logged in, or
        /// ENCOMPUTE_TOKEN).
        #[arg(long)]
        url: Option<String>,
        /// With --url: the key to attest (its key ID; default the active
        /// key). Name the pinned key to learn whether it was revoked.
        #[arg(long, requires = "url")]
        key_id: Option<String>,
        #[command(flatten)]
        control: ControlKeyArg,
        #[command(flatten)]
        file: BrokerFile,
    },
}

#[derive(Subcommand)]
pub enum AuthorizationCmd {
    /// Install an owner-signed authorization (from `encompute governance
    /// sign`). It is verified under the pinned governance key. With --url,
    /// installed at that running broker; otherwise in the state file.
    Install {
        document: PathBuf,
        /// A running broker's URL.
        #[arg(long)]
        url: Option<String>,
        #[command(flatten)]
        file: BrokerFile,
    },
    /// Revoke an authorization at this broker. By ID, offline in the state
    /// file (the owner's own act: it takes effect at once, with or without
    /// the control plane); or an owner-signed revocation (--revocation),
    /// in the state file or at a running broker (--url).
    Revoke {
        /// The authorization ID (64 hex characters).
        id: Option<String>,
        /// Why (printed, for the operator's records).
        #[arg(long)]
        reason: Option<String>,
        /// An owner-signed revocation (from `encompute governance sign
        /// --kind revocation`).
        #[arg(long)]
        revocation: Option<PathBuf>,
        /// A running broker's URL (with --revocation).
        #[arg(long)]
        url: Option<String>,
        #[command(flatten)]
        file: BrokerFile,
    },
}

fn read_json<T: serde::de::DeserializeOwned>(p: &Path, what: &str) -> Result<T> {
    serde_json::from_slice(&read(p)?)
        .map_err(|e| Error::new(Code::BadInput, format!("{}: not {what}: {e}", p.display())))
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
    match file.mark(&state.broker_id)? {
        Some(m) => KeyBroker::load_with_mark_expecting(
            &file.broker,
            verifier,
            file.store()?,
            m,
            file.expected().as_ref(),
        ),
        None => KeyBroker::load(&file.broker, verifier, file.store()?),
    }
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
                let b = KeyBroker::new(&id, mode, Verifier::new(), file.store()?)?;
                match file.mark(&id)? {
                    Some(m) => b.with_generation_mark_expecting(m, file.expected().as_ref())?,
                    None => b,
                }
            };
            if let Some(org) = &file.organization {
                b.set_organization(org)?;
            }
            let key = match &key_file {
                Some(p) => Some(KeyMaterial::from_bytes(&zeroize::Zeroizing::new(read(p)?))?),
                None => None,
            };
            let v = b.add_secret(&asset, key, read_policy(&policy)?)?;
            b.save(&file.broker)?;
            println!(
                "{:<20}{asset}\n{:<20}{v}\n{:<20}{} ({})\n{:<20}{}",
                "Asset",
                "Key version",
                "Broker",
                b.id(),
                match b.mode() {
                    BrokerMode::Production => "production",
                    BrokerMode::Development => "DEVELOPMENT",
                },
                "Grant key",
                b.grant_public_key()
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
            let kek = b.state().kek_id.clone();
            let v = b.revoke(&asset, version)?;
            b.save(&file.broker)?;
            println!("{asset}: key version {v} revoked");
            if b.state().kek_id != kek {
                println!(
                    "KEK replaced ({} -> {}): an older state file no longer yields the revoked key \
                     under the current KEK",
                    kek.as_deref().unwrap_or("?"),
                    b.state().kek_id.as_deref().unwrap_or("?")
                );
            } else {
                println!(
                    "NOT SHREDDED: this store has no KEK it can replace; an older state file \
                     still holds the key"
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::Rewrap { new_kek, file } => {
            let mut b = open_broker(&file, None)?;
            b.rewrap(Box::new(LocalKekStore::open_or_create(&new_kek)?))?;
            b.save(&file.broker)?;
            println!(
                "keys re-wrapped under KEK {}; open this broker with --kek {}",
                b.state().kek_id.as_deref().unwrap_or("?"),
                new_kek.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::RotateRoot {
            file,
            report,
            retire_old_versions,
        } => {
            let mut s = file.root()?.ok_or_else(|| {
                Error::new(
                    Code::KeyRelease,
                    "rotate-root needs --root-key and --organization",
                )
            })?;
            let r = s.rotate_root()?;
            println!(
                "root key {} ({}) of {}: version {} -> {}; the KEK was re-wrapped, asset keys unchanged",
                r.key_ref, r.provider, r.organization, r.old_version, r.new_version
            );
            if report {
                let c = crate::control::ControlClient::from_env(None)?;
                c.post(
                    &format!("/v1/organizations/{}/key-rotations", r.organization),
                    serde_json::to_value(&r).expect("serializable"),
                )?;
                println!("recorded in the control plane's audit trail");
            }
            if retire_old_versions {
                let v = s.retire_older_root_versions()?;
                println!(
                    "root key versions older than {v} retired: a wrapped KEK from an older backup \
                     can no longer be opened"
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::UpgradeState { confirm, file } => {
            let b = KeyBroker::load_legacy(&file.broker, Verifier::new(), file.store()?)?;
            print_state(&b);
            if b.state().mac.is_some() {
                println!("\nthe state is already authenticated under its KEK");
                return Ok(ExitCode::SUCCESS);
            }
            if !confirm {
                println!(
                    "\nNOT AUTHENTICATED: check the policies, mode and organization above, \
                     then rerun with --confirm"
                );
                return Ok(ExitCode::from(1));
            }
            b.save(&file.broker)?;
            match b.state().kek_id.as_deref() {
                Some(k) => println!("\nthe state is now authenticated under KEK {k}"),
                None => println!(
                    "\nDEVELOPMENT ONLY: plaintext storage has no KEK; the state is not \
                     authenticated"
                ),
            }
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::GovernanceKey {
            cmd: GovernanceKeyCmd::Pin { key, file },
        } => {
            let mut b = open_broker(&file, None)?;
            if let Some(org) = &file.organization {
                b.set_organization(org)?;
            }
            b.pin_governance_key(&key)?;
            b.save(&file.broker)?;
            println!(
                "governance key {} of {} pinned: only authorizations it signed are installed, \
                 and keys are released only in governed releases",
                encompute_runtime::trust::authz::governance_key_id(&key),
                b.organization().unwrap_or("?")
            );
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::GovernanceKey {
            cmd:
                GovernanceKeyCmd::PinLineage {
                    organization,
                    attestation,
                    url,
                    key_id,
                    control,
                    file,
                },
        } => {
            let a: encompute_runtime::trust::authz::SignedGovernanceKeyAttestation =
                match (attestation, url) {
                    (Some(path), _) => read_json(&path, "a governance key attestation")?,
                    (None, Some(url)) => {
                        let c = crate::control::ControlClient::from_env(Some(&url))?;
                        let mut path =
                            format!("/v1/organizations/{organization}/governance-key-attestation");
                        if let Some(k) = &key_id {
                            path.push_str(&format!("?key_id={k}"));
                        }
                        serde_json::from_value(c.get(&path)?).map_err(|e| {
                            Error::new(
                                Code::BadInput,
                                format!("the control plane's attestation: {e}"),
                            )
                        })?
                    }
                    (None, None) => unreachable!("clap requires --attestation or --url"),
                };
            let mut b = control.configure(open_broker(&file, None)?)?;
            let pinned = b.pin_lineage_governance_key(&organization, &a)?;
            b.save(&file.broker)?;
            if pinned {
                println!(
                    "governance key {} of {organization} pinned (attested at {}): its \
                     authorizations of results derived from its data are installed and \
                     required here",
                    a.body.key_id, a.body.issued_at
                );
            } else {
                println!(
                    "governance key {} of {organization} was revoked: it is no longer pinned, and \
                     nothing it signed is used here",
                    a.body.key_id
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::BindVersion {
            asset,
            version_id,
            derived,
            cosignature,
            control,
            file,
        } => {
            let mut b = open_broker(&file, None)?;
            if let (Some(path), Some(cosigned)) = (derived, cosignature) {
                let record: encompute_runtime::trust::authz::SignedReleaseRecord =
                    read_json(&path, "a signed release record")?;
                let cosignature: encompute_runtime::trust::authz::SignedDerivedReleaseCosignature =
                    read_json(&cosigned, "the control plane's co-signature")?;
                if record.body.derived_version_id != version_id {
                    return Err(Error::new(
                        Code::GovernanceAssetVersionMismatch,
                        "the release record is for another version",
                    ));
                }
                b = control.configure(b)?;
                b.bind_derived_version(&asset, &record, &cosignature)?;
                b.save(&file.broker)?;
                println!("{asset}: bound to derived result {version_id} (co-signed by the control plane)");
            } else {
                b.bind_version(&asset, &version_id)?;
                b.save(&file.broker)?;
                println!("{asset}: bound to source version {version_id}");
            }
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::RebindLineage {
            asset,
            cosignature,
            control,
            file,
        } => {
            let c: encompute_runtime::trust::authz::SignedDerivedReleaseCosignature =
                read_json(&cosignature, "the control plane's co-signature")?;
            let mut b = control.configure(open_broker(&file, None)?)?;
            let changed = b.rebind_derived_lineage(&asset, &c)?;
            b.save(&file.broker)?;
            println!(
                "{asset}: {} (co-signed by the control plane at {})",
                if changed {
                    "re-bound to its lineage owners' current governance keys"
                } else {
                    "already bound to its lineage owners' current governance keys"
                },
                c.body.issued_at
            );
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::Authorization {
            cmd:
                AuthorizationCmd::Install {
                    document,
                    url,
                    file,
                },
        } => {
            let a: SignedAuthorizationV2 = read_json(&document, "a signed authorization")?;
            let id = match url {
                Some(u) => BrokerClient::new(&u).install_authorization(&a)?,
                None => {
                    let mut b = open_broker(&file, None)?;
                    let id = b.install_authorization(&a)?;
                    b.save(&file.broker)?;
                    id
                }
            };
            println!(
                "authorization {id} installed: {} in project {}, valid [{}, {})",
                a.body.party, a.body.project, a.body.valid_from, a.body.valid_until
            );
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::Authorization {
            cmd:
                AuthorizationCmd::Revoke {
                    id,
                    reason,
                    revocation,
                    url,
                    file,
                },
        } => {
            let id = match (revocation, id, url) {
                (Some(p), None, url) => {
                    let r: SignedRevocationV2 = read_json(&p, "a signed revocation")?;
                    match url {
                        Some(u) => BrokerClient::new(&u).revoke_authorization(&r)?,
                        None => {
                            let mut b = open_broker(&file, None)?;
                            b.revoke_authorization_signed(&r)?;
                            b.save(&file.broker)?;
                        }
                    }
                    r.body.authorization
                }
                (None, Some(id), None) => {
                    let mut b = open_broker(&file, None)?;
                    b.revoke_authorization_local(&id, None)?;
                    b.save(&file.broker)?;
                    id
                }
                _ => {
                    return Err(Error::new(
                        Code::BadInput,
                        "revoke an authorization by ID (in the state file), or pass \
                         --revocation FILE (optionally with --url)",
                    ))
                }
            };
            println!(
                "authorization {id} revoked at this broker{}",
                reason.map(|r| format!(": {r}")).unwrap_or_default()
            );
            Ok(ExitCode::SUCCESS)
        }
        BrokerCmd::Serve {
            listen,
            requests_per_minute,
            control_key,
            no_require_ticket,
            replace_control_key: replace,
            lineage_attestation_max_age,
            trust,
            file,
        } => {
            let mut b = open_broker(&file, Some(&trust))?;
            let control_key =
                control_key.or_else(|| std::env::var("ENCOMPUTE_CONTROL_PUBLIC_KEY").ok());
            if let (true, Some(k)) = (replace, &control_key) {
                replace_control_key(&mut b, k)?;
            }
            b = match control_key {
                Some(k) => b.with_governance(GovernanceConfig {
                    require_ticket: !no_require_ticket,
                    lineage_attestation_max_age_secs: lineage_attestation_max_age,
                    ..GovernanceConfig::new(&k)
                })?,
                None if no_require_ticket => {
                    return Err(Error::new(
                        Code::InsecureConfiguration,
                        "--no-require-ticket needs the control plane's key (--control-key)",
                    ))
                }
                None => b,
            };
            // A governed production broker needs a generation mark.
            b.check_generation_mark()?;
            // Keeps a grant-signing key created for an older state file.
            b.save(&file.broker)?;
            let control = match std::env::var("ENCOMPUTE_CONTROL_PUBLIC_KEY") {
                Ok(key) => {
                    // Revocations are accepted only from the pinned control
                    // plane.
                    if b.pinned_control_key().is_some_and(|k| k != key) {
                        return Err(Error::new(
                            Code::InsecureConfiguration,
                            "ENCOMPUTE_CONTROL_PUBLIC_KEY is not the control-plane key pinned in \
                             the broker's state: pass it with --control-key \
                             --replace-control-key if the control plane's key really changed",
                        ));
                    }
                    b.pin_control_key(&key)?;
                    // A broker serves one organization; revocations name it.
                    let org = file.organization.as_deref().ok_or_else(|| {
                        Error::new(
                            Code::InsecureConfiguration,
                            "a broker accepting revocations serves one organization: pass --organization",
                        )
                    })?;
                    b.set_organization(org)?;
                    b.save(&file.broker)?;
                    Some(encompute_runtime::keybroker::ControlChannel::new(
                        &std::env::var("ENCOMPUTE_SERVICE_ID").map_err(|_| {
                            Error::new(Code::InsecureConfiguration, "set ENCOMPUTE_SERVICE_ID")
                        })?,
                        &std::env::var("ENCOMPUTE_CONTROL_ID")
                            .unwrap_or_else(|_| "control-plane".into()),
                        &key,
                        org,
                    ))
                }
                Err(_) => None,
            };
            // Report key releases to the control plane (audit trail).
            let control = match (
                control,
                std::env::var("ENCOMPUTE_CONTROL_URL"),
                std::env::var("ENCOMPUTE_SERVICE_KEY_FILE"),
            ) {
                (Some(c), Ok(url), Ok(key)) => {
                    let me = c.me.clone();
                    Some(c.with_reporter(
                        &url,
                        encompute_verification::ServiceSigner::from_file(&me, Path::new(&key))?,
                    ))
                }
                (c, _, _) => c,
            };
            let server = encompute_verification::http::Server::http(&listen)
                .map_err(|e| Error::new(Code::Remote, format!("{listen}: {e}")))?;
            eprintln!(
                "key broker {} ({:?}) on http://{listen}, trusting: {}",
                b.id(),
                b.mode(),
                trust.verifier(Some(b.id()))?.providers().join(", ")
            );
            eprintln!(
                "grant signing key {} (workloads pin it: ASSET@URL#KEY)",
                b.grant_public_key()
            );
            if let Some(c) = &control {
                eprintln!(
                    "accepting revocations for {} from control plane {} as {}",
                    c.organization, c.control_id, c.me
                );
            }
            let path = file.broker.clone();
            encompute_runtime::keybroker::serve_with_control(
                &Mutex::new(b),
                server,
                requests_per_minute,
                control.as_ref(),
                &|b| b.save(&path),
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// What a broker state releases, and to whom (for `keys upgrade-state`).
fn print_state(b: &KeyBroker) {
    let s = b.state();
    println!("{:<14}{}", "Broker", s.broker_id);
    println!(
        "{:<14}{}",
        "Mode",
        match s.mode {
            BrokerMode::Production => "production",
            BrokerMode::Development => "DEVELOPMENT",
        }
    );
    println!(
        "{:<14}{}",
        "Organization",
        s.organization.as_deref().unwrap_or("(none)")
    );
    println!("{:<14}{}", "Grant key", b.grant_public_key());
    if let Some(k) = &s.governance_key {
        println!("{:<14}{} (governed)", "Governance", k.key_id());
        println!(
            "{:<14}{} installed, {} revoked",
            "Authorizations",
            s.authorizations.len(),
            s.revoked_authorizations.len()
        );
    }
    for (asset, k) in &s.secrets {
        let p = &k.release_policy;
        let revoked: Vec<String> = k
            .versions
            .iter()
            .filter(|(_, v)| v.revoked)
            .map(|(n, _)| n.to_string())
            .collect();
        section(&format!("Asset {asset}"));
        println!("  {:<18}{}", "Current version", k.key_version);
        if let Some(v) = &k.asset_version_id {
            println!("  {:<18}{v}", "Source version");
        }
        if k.expired {
            println!("  {:<18}EXPIRED", "Retention");
        }
        println!(
            "  {:<18}{}",
            "Revoked versions",
            if revoked.is_empty() {
                "(none)".into()
            } else {
                revoked.join(", ")
            }
        );
        println!(
            "  {:<18}{}",
            "Organization",
            k.organization.as_deref().unwrap_or("(none)")
        );
        println!("  {:<18}encspec1:{}", "Execution", p.execution_spec_id);
        println!(
            "  {:<18}{}",
            "Policy",
            p.policy_id.as_deref().unwrap_or("(none)")
        );
        println!(
            "  {:<18}{}",
            "Privacy policy",
            p.privacy_policy_id.as_deref().unwrap_or("(none)")
        );
        println!(
            "  {:<18}{}",
            "Artifact",
            p.artifact_digest.as_deref().unwrap_or("(any)")
        );
        for i in &p.allowed_images {
            println!("  {:<18}{i}", "Image");
        }
        let tees: Vec<String> = p.allowed_tee.iter().map(|t| t.to_string()).collect();
        println!("  {:<18}{}", "TEEs", tees.join(", "));
        println!("  {:<18}{}", "Minimum TCB", p.minimum_tcb);
        println!(
            "  {:<18}{}",
            "Debug",
            match p.debug {
                DebugPolicy::Allowed => "ALLOWED",
                DebugPolicy::Forbidden => "forbidden",
            }
        );
        println!(
            "  {:<18}{}",
            "GPU attestation",
            if p.require_gpu_attestation {
                "required"
            } else {
                "not required"
            }
        );
        println!("  {:<18}{} s", "Max evidence age", p.max_evidence_age_secs);
        println!(
            "  {:<18}{}",
            "Mock evidence",
            if p.allow_development {
                "ACCEPTED (development only)"
            } else {
                "refused"
            }
        );
        println!("  {:<18}{}", "Policy format", p.version);
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
    pub(crate) fn attester(&self) -> Result<Box<dyn Attester>> {
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
        /// `ASSET@URL#BROKER_KEY`, once per asset. BROKER_KEY pins the
        /// broker's grant-signing key (as `keys serve` prints it) and must
        /// come from the attested image, never from the host. Required with
        /// a hardware attester; grants from two signers in one session are
        /// refused. `ASSET@URL` without a key: development (mock) only.
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
                Error::new(
                    Code::BadInput,
                    format!("--key {k}: expected ASSET@URL[#BROKER_KEY]"),
                )
            })?;
            Ok((BrokerClient::parse(url)?, asset.to_owned()))
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
