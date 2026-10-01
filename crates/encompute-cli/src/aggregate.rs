//! `encompute aggregate`: secure aggregation rounds (ADR-012).
//!
//! Every party builds the aggregation spec from its own copy of the
//! artifact and the consortium's `parties.json`, and joins only a round of
//! exactly that spec.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Subcommand};
use encompute_ir::confidentiality::PartyId;
use encompute_ir::{Code, Error, Result};
use encompute_runtime::attestation::{AttestationPolicy, AttestationRecord};
use encompute_runtime::secagg::service::{
    join_checked, CoordinatorService, ParticipantClient, PartyState,
};
use encompute_runtime::secagg::{
    identity_of, party_key_from_seed, verify_aggregation_receipt, AggregateAsset,
    AggregationReceipt, AggregationSpec, PartyIdentity, RoundCoordinator, ScopedBudget,
};

use crate::attest::TrustArgs;
use crate::{load, short};

fn io(p: &Path, e: std::io::Error) -> Error {
    Error::new(Code::Artifact, format!("{}: {e}", p.display()))
}

fn read(p: &Path) -> Result<Vec<u8>> {
    std::fs::read(p).map_err(|e| io(p, e))
}

fn json<T: for<'de> serde::Deserialize<'de>>(p: &Path) -> Result<T> {
    serde_json::from_slice(&read(p)?)
        .map_err(|e| Error::new(Code::AggregationPlan, format!("{}: {e}", p.display())))
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

/// An identity key file (32-byte seed, mode 0600), created if missing.
fn key_file(p: &Path) -> Result<ed25519_dalek::SigningKey> {
    if p.exists() {
        let seed: [u8; 32] = read(p)?
            .try_into()
            .map_err(|_| Error::new(Code::AggregationUnauthorized, "a key file is 32 bytes"))?;
        return Ok(party_key_from_seed(&seed));
    }
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut())
        .map_err(|e| Error::new(Code::AggregationProtocol, format!("no randomness: {e}")))?;
    write_private(p, seed.as_ref())?;
    Ok(party_key_from_seed(&seed))
}

/// A party's `--state`: the last round joined and, per budgeted asset, the
/// last privacy-ledger checkpoint seen. (A bare number is the old format.)
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct PartyStateFile {
    pub(crate) sequence: Option<u64>,
    #[serde(default)]
    pub(crate) checkpoints: std::collections::BTreeMap<String, encompute_runtime::dp::Checkpoint>,
}

impl PartyStateFile {
    pub(crate) fn read(p: &Path) -> Result<Self> {
        let text = String::from_utf8(read(p)?)
            .map_err(|_| Error::new(Code::AggregationBinding, "state file is not UTF-8"))?;
        if let Ok(n) = text.trim().parse::<u64>() {
            return Ok(Self {
                sequence: Some(n),
                ..Self::default()
            });
        }
        serde_json::from_str(&text)
            .map_err(|e| Error::new(Code::AggregationBinding, format!("{}: {e}", p.display())))
    }
}

/// The largest round sequence a coordinator may use or a party accepts:
/// exactly representable in every JSON reader, and far from overflow. A
/// party that recorded `u64::MAX` could never join that spec again.
const MAX_SEQUENCE: u64 = (1 << 53) - 1;

/// The `--state` file as `aggregate join` keeps it (review finding SA-2):
/// the last round joined *per aggregation spec* (`sequences`, keyed by the
/// spec ID) next to the older global `sequence`, which stays a floor for
/// every spec. Each update runs under an exclusive lock on `STATE.lock`,
/// re-reads the file, only ever raises what it records, and replaces the
/// file atomically (temporary file, fsync, rename): concurrent joins and
/// crashes can neither lose a round nor tear the file.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct JoinState {
    #[serde(flatten)]
    base: PartyStateFile,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    sequences: std::collections::BTreeMap<String, u64>,
}

impl JoinState {
    fn read(p: &Path) -> Result<Self> {
        if !p.exists() {
            return Ok(Self::default());
        }
        let text = String::from_utf8(read(p)?)
            .map_err(|_| Error::new(Code::AggregationBinding, "state file is not UTF-8"))?;
        if text.trim().parse::<u64>().is_ok() {
            return Ok(Self {
                base: PartyStateFile::read(p)?,
                ..Self::default()
            });
        }
        serde_json::from_str(&text)
            .map_err(|e| Error::new(Code::AggregationBinding, format!("{}: {e}", p.display())))
    }

    /// The last round of `spec_id` joined: never below the older global
    /// sequence.
    fn last_sequence(&self, spec_id: &str) -> Option<u64> {
        match (self.base.sequence, self.sequences.get(spec_id).copied()) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }

    fn record_sequence(&mut self, spec_id: &str, n: u64) {
        let e = self.sequences.entry(spec_id.to_owned()).or_insert(n);
        *e = (*e).max(n);
    }

    /// Keeps the furthest checkpoint seen of each asset's ledger.
    fn record_checkpoint(&mut self, asset: &str, cp: encompute_runtime::dp::Checkpoint) {
        match self.base.checkpoints.get(asset) {
            Some(old) if old.seq > cp.seq => {}
            _ => {
                self.base.checkpoints.insert(asset.to_owned(), cp);
            }
        }
    }

    /// Replaces `p` atomically: a temporary file (mode 0600) in the same
    /// directory, fsynced, renamed over `p`, and the directory fsynced.
    fn write(&self, p: &Path) -> Result<()> {
        use std::io::Write;
        let bytes = serde_json::to_vec_pretty(self).expect("JSON");
        let tmp = sibling(p, "tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(&tmp)
            .and_then(|mut f| {
                f.write_all(&bytes)?;
                f.sync_all()
            })
            .map_err(|e| io(&tmp, e))?;
        std::fs::rename(&tmp, p).map_err(|e| io(p, e))?;
        if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
            #[cfg(unix)]
            std::fs::File::open(dir)
                .and_then(|d| d.sync_all())
                .map_err(|e| io(dir, e))?;
        }
        Ok(())
    }

    /// Runs `f` on the current state under the state's exclusive lock and
    /// writes the result.
    fn update<T>(p: &Path, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let lock_path = sibling(p, "lock");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| io(&lock_path, e))?;
        lock.lock().map_err(|e| io(&lock_path, e))?;
        let mut st = Self::read(p)?;
        let out = f(&mut st)?;
        st.write(p)?;
        drop(lock);
        Ok(out)
    }
}

/// `STATE.<ext>` next to the state file.
fn sibling(p: &Path, ext: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

/// What fixes the spec: the same flags on every side.
#[derive(Args, Clone)]
pub struct SpecArgs {
    /// The aggregation program's artifact (or `.eir`).
    model: PathBuf,
    /// The consortium's party identities (from `aggregate identity`).
    #[arg(long)]
    parties: PathBuf,
    /// The aggregated output (default: the only one).
    #[arg(long)]
    output: Option<String>,
    /// The training program's execution spec ID contributions come from.
    #[arg(long)]
    training_spec: Option<String>,
    /// Require attested contribution workloads under this policy.
    #[arg(long)]
    attestation_policy: Option<PathBuf>,
    /// Require an attested coordinator under this policy (from `aggregate
    /// coordinator-policy`): parties contribute only to a coordinator that
    /// provably runs the approved plan and privacy configuration.
    #[arg(long)]
    coordinator_policy: Option<PathBuf>,
    /// The approved confidential execution plan (from `encompute plan
    /// -o`): the round is bound to its ID and must provide its mechanisms.
    #[arg(long)]
    plan: Option<PathBuf>,
    /// The privacy scopes this aggregation is charged to (from `encompute
    /// privacy scope`): each budgeted asset's releases are charged to its
    /// scope and its population instead of its own ledger. Bound into the
    /// spec ID, so every party approves the same allocation.
    #[arg(long)]
    scoping: Option<PathBuf>,
}

impl SpecArgs {
    fn spec(&self) -> Result<AggregationSpec> {
        let m = load(&self.model)?;
        let plan = m.aggregation_plan(self.output.as_deref())?;
        let ids: Vec<PartyIdentity> = json(&self.parties)?;
        let mut ordered = vec![];
        for p in &plan.participants {
            ordered.push(
                ids.iter()
                    .find(|i| i.party == p.party)
                    .cloned()
                    .ok_or_else(|| {
                        Error::new(
                            Code::AggregationPlan,
                            format!(
                                "{} lists no identity for {}",
                                self.parties.display(),
                                p.party
                            ),
                        )
                    })?,
            );
        }
        let approved = match &self.plan {
            Some(p) => Some(crate::plan::approved(p, m.program(), &plan.output)?),
            None => None,
        };
        let plan = match &approved {
            Some((id, _)) => plan.with_execution_plan(id),
            None => plan,
        };
        let plan = match &self.scoping {
            Some(p) => plan.with_scopes(json::<BTreeMap<String, ScopedBudget>>(p)?)?,
            None => plan,
        };
        let mut spec = AggregationSpec::new(plan, ordered)?;
        spec.training_execution_spec_id = self.training_spec.clone();
        if let Some(p) = &self.attestation_policy {
            spec.attestation = Some(json::<AttestationPolicy>(p)?);
        }
        if let Some(p) = &self.coordinator_policy {
            spec.coordinator_attestation = Some(json::<AttestationPolicy>(p)?);
        }
        if let Some((_, step)) = &approved {
            crate::plan::check_round(step, &spec)?;
        }
        spec.validate()?;
        Ok(spec)
    }
}

#[derive(Subcommand)]
pub enum AggregateCmd {
    /// Create (or show) a party's aggregation identity key; prints the
    /// entry for the consortium's parties.json.
    Identity {
        #[arg(long)]
        party: String,
        #[arg(long)]
        key: PathBuf,
    },
    /// Coordinate one round: collect masked contributions, release only the
    /// aggregate (to `--out`) with a signed receipt.
    Serve {
        #[command(flatten)]
        spec: SpecArgs,
        /// The coordinator's receipt-signing key (created if missing).
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8770")]
        listen: String,
        /// This round's number; must increase from round to round.
        #[arg(long, default_value_t = 1)]
        sequence: u64,
        /// Seconds a stage waits for late parties before counting them as
        /// dropped.
        #[arg(long, default_value_t = 60)]
        stage_timeout: u64,
        #[arg(short, long, default_value = "aggregate.json")]
        out: PathBuf,
        /// Privacy ledger directory (required for DP aggregations; keep it
        /// across rounds and restarts).
        #[arg(long)]
        ledger: Option<PathBuf>,
        /// Record the finished round in this trust bundle.
        #[arg(long)]
        trust_bundle: Option<PathBuf>,
        #[arg(long, default_value = "aggregation-receipt.json")]
        receipt: PathBuf,
        #[command(flatten)]
        trust: TrustArgs,
        /// How the coordinator attests itself, when the spec requires it.
        #[command(flatten)]
        attester: crate::attest::AttesterArgs,
        /// Report this round to a control plane (ENCOMPUTE_CONTROL_URL,
        /// ENCOMPUTE_SERVICE_ID, ENCOMPUTE_SERVICE_KEY_FILE): its privacy
        /// events for these assets (`LEDGER_ASSET=CONTROL_ASSET_ID`,
        /// repeatable) and its duration.
        #[arg(long = "control-asset")]
        control_assets: Vec<String>,
    },
    /// Print the attestation policy a coordinator must satisfy: this plan,
    /// its confidentiality and privacy policies, on these images and TEEs.
    CoordinatorPolicy {
        model: PathBuf,
        #[arg(long)]
        output: Option<String>,
        #[arg(long, required = true)]
        image: Vec<String>,
        /// intel_tdx, amd_sev_snp, amd_sev (mock for development).
        #[arg(long, required = true)]
        tee: Vec<String>,
        #[arg(long)]
        development: bool,
        /// The approved confidential execution plan the rounds run under.
        #[arg(long)]
        plan: Option<PathBuf>,
    },
    /// Contribute this party's private vector to the coordinator's round.
    Join {
        #[command(flatten)]
        spec: SpecArgs,
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        party: String,
        #[arg(long)]
        key: PathBuf,
        /// JSON array of numbers: this party's contribution (`-`: stdin).
        #[arg(long)]
        values: PathBuf,
        /// Records the last round joined and refuses older or repeated
        /// ones: keep it across runs. It is written before contributing, so
        /// a round that fails midway cannot be rejoined; the coordinator
        /// starts a new round (higher --sequence) instead. Rerunning a round
        /// with different survivors would let a coordinator subtract two
        /// aggregates and recover this party's vector.
        #[arg(long)]
        state: PathBuf,
        /// Attestation record of the workload holding the party key.
        #[arg(long)]
        attestation: Option<PathBuf>,
        #[arg(long, default_value_t = 600)]
        timeout: u64,
        /// Providers trusted for the coordinator's attestation.
        #[command(flatten)]
        trust: TrustArgs,
    },
    /// Check an aggregation receipt (and the aggregate, if you hold it).
    Verify {
        receipt: PathBuf,
        #[command(flatten)]
        spec: SpecArgs,
        #[arg(long)]
        aggregate: Option<PathBuf>,
        /// The coordinator key (hex) you trust.
        #[arg(long)]
        trust_coordinator: Option<String>,
    },
}

fn print_manifest(r: &AggregationReceipt) {
    let m = &r.manifest;
    let join = |v: &[PartyId]| {
        if v.is_empty() {
            "none".to_owned()
        } else {
            v.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", ")
        }
    };
    println!("{:<16}encround1:{}", "Round", short(&m.round_id));
    println!("{:<16}encagg1:{}", "Spec", short(&m.spec_id));
    if let Some(p) = &m.policy_id {
        println!("{:<16}encpolicy1:{}", "Policy", short(p));
    }
    println!("{:<16}{} v{}", "Protocol", m.protocol, m.protocol_version);
    println!("{:<16}{}", "Contributors", join(&m.contributors));
    println!("{:<16}{}", "Dropped", join(&m.dropped));
    println!(
        "{:<16}{} (threshold {}, private against {} colluding)",
        "Minimum", m.minimum, m.threshold, m.max_colluding
    );
    println!(
        "{:<16}{} x {} values, fixed point clip [{}, {}] scale {} mod 2^{}",
        "Encoding",
        m.function.name(),
        m.vector_len,
        m.codec.clip_min,
        m.codec.clip_max,
        m.codec.scale,
        m.codec.modulus_bits
    );
}

pub fn aggregate(cmd: AggregateCmd) -> Result<ExitCode> {
    match cmd {
        AggregateCmd::Identity { party, key } => {
            let party = PartyId::new(&party)?;
            let k = key_file(&key)?;
            println!(
                "{}",
                serde_json::to_string(&identity_of(&party, &k)).expect("JSON")
            );
            Ok(ExitCode::SUCCESS)
        }
        AggregateCmd::Serve {
            spec,
            key,
            listen,
            sequence,
            stage_timeout,
            out,
            ledger,
            trust_bundle,
            receipt,
            trust,
            attester,
            control_assets,
        } => {
            let started = std::time::Instant::now();
            if sequence == 0 || sequence > MAX_SEQUENCE {
                return Err(Error::new(
                    Code::AggregationBinding,
                    format!("--sequence must be between 1 and {MAX_SEQUENCE}"),
                ));
            }
            let spec = spec.spec()?;
            let verifier = match &spec.attestation {
                Some(_) => Some(trust.verifier(None)?),
                None => None,
            };
            let now = encompute_runtime::attestation::unix_now();
            let mut coord = RoundCoordinator::open(spec, sequence, key_file(&key)?, verifier, now)?;
            if let Some(dir) = &ledger {
                std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
                coord = coord.with_ledger(dir)?;
            } else if coord.spec.plan.dp.is_some()
                || coord
                    .spec
                    .plan
                    .participants
                    .iter()
                    .any(|p| p.budget.is_some())
            {
                // Every aggregate of a budgeted asset is a release, charged
                // to its ledger (review finding DP-1).
                return Err(Error::new(
                    Code::PrivacyLedger,
                    "an aggregation of privacy-budgeted assets needs --ledger DIR",
                ));
            }
            if coord.spec.coordinator_attestation.is_some() {
                let record = coord.attest(attester.attester()?.as_ref())?;
                eprintln!("coordinator attested (record {})", short(&record.id()?));
            }
            let round_id = coord.round_id()?;
            // With a control plane, its configuration is checked before the
            // round starts: parties never contribute to a round whose
            // release could not be reserved.
            let sender = match std::env::var("ENCOMPUTE_CONTROL_URL") {
                Ok(_) => {
                    // Every budgeted contributor's asset must map to its
                    // control-plane asset, or its spend would never be
                    // reserved there (review finding SA-1).
                    let budgeted: Vec<&str> = coord
                        .spec
                        .plan
                        .participants
                        .iter()
                        .filter(|p| p.budget.is_some())
                        .map(|p| p.asset.as_str())
                        .collect();
                    control_mapping(&control_assets, &budgeted)?;
                    Some(control_sender(&round_id)?)
                }
                Err(_) => None,
            };
            let svc = CoordinatorService::new(coord, Duration::from_secs(stage_timeout))?;
            let server = encompute_verification::http::Server::http(&listen)
                .map_err(|e| Error::new(Code::Remote, format!("{listen}: {e}")))?;
            svc.spawn(server);
            eprintln!(
                "aggregation round encround1:{} on http://{listen}",
                short(&round_id)
            );
            let (asset, r) = svc.run_to_completion()?;
            let written = std::cell::Cell::new(false);
            let write_output = || -> Result<()> {
                written.set(true);
                std::fs::write(&out, serde_json::to_vec_pretty(&asset).expect("JSON"))
                    .map_err(|e| io(&out, e))?;
                std::fs::write(&receipt, r.to_bytes()?).map_err(|e| io(&receipt, e))?;
                if let Some(b) = &trust_bundle {
                    let mut g = crate::trust::open(b)?;
                    g.add_aggregation(r.clone())?;
                    crate::trust::save(b, &g)?;
                }
                Ok(())
            };
            // With a control plane, the round's privacy spend is reserved
            // there before the aggregate is written: a release never exists
            // without a durable reservation.
            let reported = if let Some(sender) = sender {
                let charged: Vec<&str> = r
                    .manifest
                    .privacy
                    .iter()
                    .map(|p| p.asset_id.as_str())
                    .collect();
                let sent = release_after_reserve(
                    &round_id,
                    ledger.as_deref(),
                    &control_assets,
                    &charged,
                    started.elapsed().as_millis() as u64,
                    sender,
                    write_output,
                );
                match sent {
                    Ok(n) => Some(n),
                    // Nothing was released: no receipt window is needed.
                    Err(e) if !written.get() => return Err(e),
                    // Released, but reporting after the release failed: let
                    // participants collect the receipt, then report the error.
                    Err(e) => {
                        eprintln!("{e}");
                        std::thread::sleep(Duration::from_secs(2));
                        return Err(e);
                    }
                }
            } else {
                write_output()?;
                None
            };
            println!("AGGREGATION COMPLETE");
            print_manifest(&r);
            println!(
                "{:<16}{} ({} values)",
                "Aggregate",
                out.display(),
                asset.values.len()
            );
            println!("{:<16}{}", "Receipt", receipt.display());
            if let Some(n) = reported {
                println!(
                    "{:<16}{n} privacy events reported to the control plane",
                    "Control plane"
                );
            }
            // Let participants collect the receipt before exiting.
            std::thread::sleep(Duration::from_secs(2));
            Ok(ExitCode::SUCCESS)
        }
        AggregateCmd::CoordinatorPolicy {
            model,
            output,
            image,
            tee,
            development,
            plan: approved,
        } => {
            let m = load(&model)?;
            let mut plan = m.aggregation_plan(output.as_deref())?;
            if let Some(p) = &approved {
                let (id, _) = crate::plan::approved(p, m.program(), &plan.output)?;
                plan = plan.with_execution_plan(&id);
            }
            let mut p = AttestationPolicy::new(&plan.id()?, plan.policy_id.as_deref());
            p.privacy_policy_id = plan.privacy_policy_id.clone();
            p.artifact_digest = Some(plan.program_id.clone());
            p.allowed_images = image;
            p.allowed_tee = tee
                .iter()
                .map(|t| crate::attest::tee(t))
                .collect::<Result<_>>()?;
            p.allow_development = development;
            p.validate()?;
            println!("{}", serde_json::to_string_pretty(&p).expect("JSON"));
            Ok(ExitCode::SUCCESS)
        }
        AggregateCmd::Join {
            spec,
            coordinator,
            party,
            key,
            values,
            state,
            attestation,
            timeout,
            trust,
        } => {
            let approved = spec.spec()?;
            let verifier = match &approved.coordinator_attestation {
                Some(_) => Some(trust.verifier(Some(&format!("encagg1:{}", approved.id()?)))?),
                None => None,
            };
            let party = PartyId::new(&party)?;
            // `-`: read from stdin, so a training worker's update never
            // touches the disk.
            let values: Vec<f64> = if values.as_os_str() == "-" {
                let mut s = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
                    .map_err(|e| Error::new(Code::BadInput, format!("stdin: {e}")))?;
                serde_json::from_str(&s)
                    .map_err(|e| Error::new(Code::BadInput, format!("stdin: {e}")))?
            } else {
                json(&values)?
            };
            let spec_id = approved.id()?;
            let asset = approved.plan.participant(&party).map(|p| p.asset.clone());
            let attestation = match &attestation {
                Some(p) => Some(AttestationRecord::from_bytes(&read(p)?)?),
                None => None,
            };
            let identity = key_file(&key)?;
            let client = ParticipantClient::new(&coordinator, Duration::from_secs(timeout));
            // Checked and recorded under the state's lock: two concurrent
            // joins cannot both accept the same round (review finding
            // SA-2).
            let p = JoinState::update(&state, |st| {
                let seen = asset
                    .as_ref()
                    .and_then(|a| st.base.checkpoints.get(a).cloned());
                let p = join_checked(
                    &client,
                    &approved,
                    &party,
                    identity,
                    &values,
                    PartyState {
                        attestation,
                        last_sequence: st.last_sequence(&spec_id),
                        seen,
                        verifier: verifier.as_ref(),
                        known: st.base.checkpoints.clone(),
                    },
                )?;
                if p.round.sequence > MAX_SEQUENCE {
                    return Err(Error::new(
                        Code::AggregationBinding,
                        format!(
                            "round {} is beyond the largest sequence {MAX_SEQUENCE}: refused",
                            p.round.sequence
                        ),
                    ));
                }
                st.record_sequence(&spec_id, p.round.sequence);
                Ok(p)
            })?;
            let coordinator_key = p.round.coordinator_key.clone();
            let r = client.participate(p)?;
            verify_aggregation_receipt(&r, &approved, None, None)?;
            // Remember where this asset's ledger stands: a later ledger must
            // extend it (rollback and reset detection).
            // Remember where every budgeted asset's ledger stands (all are
            // signed into the receipt): a later ledger must extend each, so
            // this party also protects the others' budgets.
            let mut spent = None;
            for pr in &r.manifest.privacy {
                encompute_runtime::dp::verify_privacy_receipt(
                    pr,
                    Some(&coordinator_key),
                    None,
                    None,
                )?;
                if Some(&pr.asset_id) == asset.as_ref() {
                    spent = Some(format!(
                        "{:<16}epsilon {} spent of {} (this round {})",
                        "Privacy", pr.cumulative_epsilon, pr.budget_epsilon, pr.epsilon_cost
                    ));
                }
            }
            JoinState::update(&state, |st| {
                for pr in &r.manifest.privacy {
                    st.record_checkpoint(
                        &pr.asset_id,
                        encompute_runtime::dp::Checkpoint {
                            seq: pr.ledger_seq,
                            root: pr.ledger_root.clone(),
                        },
                    );
                }
                Ok(())
            })?;
            println!("CONTRIBUTION ACCEPTED (only the aggregate is released)");
            print_manifest(&r);
            if let Some(line) = spent {
                println!("{line}");
            }
            Ok(ExitCode::SUCCESS)
        }
        AggregateCmd::Verify {
            receipt,
            spec,
            aggregate,
            trust_coordinator,
        } => {
            let spec = spec.spec()?;
            let r = AggregationReceipt::from_bytes(&read(&receipt)?)?;
            let asset: Option<AggregateAsset> = aggregate.as_deref().map(json).transpose()?;
            print_manifest(&r);
            match verify_aggregation_receipt(
                &r,
                &spec,
                trust_coordinator.as_deref(),
                asset.as_ref(),
            ) {
                Ok(()) => {
                    println!(
                        "{:<16}{}",
                        "Coordinator",
                        if trust_coordinator.is_some() {
                            "trusted (--trust-coordinator)"
                        } else {
                            "NOT CHECKED (no --trust-coordinator)"
                        }
                    );
                    if asset.is_some() {
                        println!("{:<16}matches the receipt", "Aggregate");
                    }
                    println!("AGGREGATION RECEIPT VERIFIED");
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    println!("INVALID: {e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
    }
}

/// A signed-message sender to the control plane for this round.
fn control_sender(round_id: &str) -> Result<impl FnMut(&str, serde_json::Value) -> Result<()>> {
    use encompute_verification::service::{seal, signed_call, Scope};
    let env = |k: &str| {
        std::env::var(k).map_err(|_| Error::new(Code::InsecureConfiguration, format!("set {k}")))
    };
    let url = env("ENCOMPUTE_CONTROL_URL")?;
    let control = std::env::var("ENCOMPUTE_CONTROL_ID").unwrap_or_else(|_| "control-plane".into());
    let me = encompute_verification::ServiceSigner::from_file(
        &env("ENCOMPUTE_SERVICE_ID")?,
        Path::new(&env("ENCOMPUTE_SERVICE_KEY_FILE")?),
    )?;
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build();
    let round_id = round_id.to_owned();
    Ok(
        move |kind: &str, payload: serde_json::Value| -> Result<()> {
            let m = seal(
                &me,
                kind,
                &control,
                Scope {
                    round: Some(round_id.clone()),
                    ..Scope::default()
                },
                &payload,
                24 * 3600,
            )?;
            let body = serde_json::to_value(&m).expect("serializable");
            signed_call(
                &agent,
                &me,
                &url,
                &control,
                "POST",
                "/v1/messages",
                &Default::default(),
                &body,
            )
            .map(|_| ())
        },
    )
}

/// Tries a control-plane message a few times: privacy events are
/// idempotent (the control plane charges a duplicate event once).
fn send_retrying(
    send: &mut impl FnMut(&str, serde_json::Value) -> Result<()>,
    kind: &str,
    payload: serde_json::Value,
) -> Result<()> {
    const ATTEMPTS: u32 = 3;
    let mut attempt = 1;
    loop {
        match send(kind, payload.clone()) {
            Ok(()) => return Ok(()),
            Err(e) if attempt >= ATTEMPTS => return Err(e),
            Err(_) => {
                std::thread::sleep(Duration::from_millis(250 * u64::from(attempt)));
                attempt += 1;
            }
        }
    }
}

/// Parses `--control-asset LEDGER_ASSET=CONTROL_ASSET_ID` values strictly
/// and requires one for every asset in `budgeted` (review finding SA-1: a
/// malformed or missing mapping used to be skipped, so that asset's spend
/// was released without a control-plane reservation).
fn control_mapping<'a>(
    control_assets: &'a [String],
    budgeted: &[&str],
) -> Result<std::collections::BTreeMap<&'a str, &'a str>> {
    let bad = |m: String| Error::new(Code::InsecureConfiguration, m);
    let mut map = std::collections::BTreeMap::new();
    for m in control_assets {
        let (local, remote) = m
            .split_once('=')
            .filter(|(l, r)| !l.trim().is_empty() && !r.trim().is_empty())
            .ok_or_else(|| {
                bad(format!(
                    "--control-asset {m:?} is not LEDGER_ASSET=CONTROL_ASSET_ID"
                ))
            })?;
        if map.insert(local, remote).is_some() {
            return Err(bad(format!("--control-asset maps {local} more than once")));
        }
    }
    let missing: Vec<&str> = budgeted
        .iter()
        .copied()
        .filter(|a| !map.contains_key(a))
        .collect();
    if !missing.is_empty() {
        return Err(bad(format!(
            "with a control plane, every privacy-budgeted asset needs --control-asset \
             LEDGER_ASSET=CONTROL_ASSET_ID, so its spend is reserved there before release; \
             missing: {}",
            missing.join(", ")
        )));
    }
    Ok(map)
}

/// Releases a finished round through the control plane, as signed
/// messages, in an order that never releases unrecorded privacy spend:
/// 1. every reservation of this round (for the mapped assets; the control
///    plane enforces the budget again and records the spend durably);
/// 2. only then `write_output` (the release);
/// 3. the commits and the round's duration.
///
/// Every asset the round `charged` must be mapped and have its local
/// ledger, holding this round's reservation; otherwise nothing is sent or
/// released.
///
/// If a reservation fails (after retries) nothing is written, and the
/// noisy aggregate is dropped with the process. If a later message fails,
/// the release exists but its spend is already recorded as reserved; the
/// error says so, and resending is safe.
fn release_after_reserve(
    round_id: &str,
    ledger: Option<&Path>,
    control_assets: &[String],
    charged: &[&str],
    duration_ms: u64,
    mut send: impl FnMut(&str, serde_json::Value) -> Result<()>,
    write_output: impl FnOnce() -> Result<()>,
) -> Result<usize> {
    use encompute_runtime::dp::PrivacyEvent;
    let map = control_mapping(control_assets, charged)?;
    let (mut reserves, mut commits) = (vec![], vec![]);
    let mut reserved = std::collections::BTreeSet::new();
    if !charged.is_empty() && ledger.is_none() {
        return Err(Error::new(
            Code::PrivacyLedger,
            "the round charged privacy budgets but the coordinator has no --ledger",
        ));
    }
    if let Some(dir) = ledger {
        for (local, remote) in &map {
            let path = dir.join(format!("{local}.ledger"));
            if !path.exists() {
                if charged.contains(local) {
                    return Err(Error::new(
                        Code::PrivacyLedger,
                        format!(
                            "asset {local} was charged, but its ledger {} is missing: nothing \
                             is released",
                            path.display()
                        ),
                    ));
                }
                continue;
            }
            let view = encompute_runtime::dp::ledger::read(&path)?;
            let mine: std::collections::BTreeSet<String> = view
                .entries
                .iter()
                .filter_map(|e| match &e.event {
                    PrivacyEvent::Reserve {
                        event_id,
                        round_id: Some(r),
                        ..
                    } if r == round_id => Some(event_id.clone()),
                    _ => None,
                })
                .collect();
            for e in &view.entries {
                if mine.contains(e.event.event_id()) {
                    let m = serde_json::json!({"asset": remote, "event": e.event});
                    match e.event {
                        PrivacyEvent::Reserve { .. } => {
                            reserved.insert(*local);
                            reserves.push(m)
                        }
                        PrivacyEvent::Commit { .. } => commits.push(m),
                    }
                }
            }
        }
    }
    // The reserved assets are exactly the charged ones, or nothing is
    // released.
    let unreserved: Vec<&str> = charged
        .iter()
        .copied()
        .filter(|a| !reserved.contains(a))
        .collect();
    if !unreserved.is_empty() {
        return Err(Error::new(
            Code::PrivacyLedger,
            format!(
                "no reservation of this round in the ledger of {}: nothing is released",
                unreserved.join(", ")
            ),
        ));
    }
    let sent = reserves.len() + commits.len();
    for m in reserves {
        send_retrying(&mut send, "privacy.event", m).map_err(|e| {
            Error::new(
                e.code,
                format!(
                    "the control plane did not record this round's privacy reservation, so \
                     the aggregate was not released: {}",
                    e.message
                ),
            )
        })?;
    }
    write_output()?;
    let pending = |e: Error| {
        Error::new(
            e.code,
            format!(
                "the aggregate was released and its privacy spend is reserved at the control \
                 plane, but the round's completion was not delivered (resending is safe): {}",
                e.message
            ),
        )
    };
    for m in commits {
        send_retrying(&mut send, "privacy.event", m).map_err(pending)?;
    }
    send_retrying(
        &mut send,
        "secagg.round.completed",
        serde_json::json!({"duration_ms": duration_ms}),
    )
    .map_err(pending)?;
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use encompute_ir::confidentiality::{
        DpKind, DpMechanism, FixedPointCodec, PrivacyBudget, PrivacyUnit,
    };
    use encompute_runtime::dp::{release, Charged, Csprng, ReleaseSpec};
    use std::cell::RefCell;

    const ROUND: &str = "ab";
    const CHARGED: [&str; 2] = ["gradient-a", "gradient-b"];

    /// A ledger directory holding one DP release of round `ROUND`, charged
    /// to gradient-a and gradient-b.
    fn released_ledgers(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("encompute-cli-sf10-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let budget = PrivacyBudget {
            unit: PrivacyUnit::Patient,
            epsilon: 10.0,
            delta: 1e-6,
        };
        let spec = ReleaseSpec {
            round_id: ROUND.into(),
            output: "g".into(),
            policy_id: None,
            privacy_policy_id: "bb".repeat(32),
            execution_spec_id: None,
            mechanism: DpMechanism {
                kind: DpKind::DiscreteGaussian,
                clip_norm: 1.0,
                noise_multiplier: 5.0,
                sampling_rate: None,
                preset: None,
            },
            codec: FixedPointCodec {
                clip_min: -1.0,
                clip_max: 1.0,
                scale: 256,
                modulus_bits: 32,
            },
            vector_len: 4,
            charged: ["gradient-a", "gradient-b"]
                .map(|a| Charged::asset(a, budget.clone()))
                .to_vec(),
            sources_per_unit: 1,
            layout_id: None,
        };
        release(
            &spec,
            &d,
            &[1, 2, 3, 4],
            &mut Csprng::from_os().unwrap(),
            &ed25519_dalek::SigningKey::from_bytes(&[4; 32]),
        )
        .unwrap();
        d
    }

    fn is_reserve(m: &serde_json::Value) -> bool {
        m["event"]["kind"] == "reserve"
    }

    /// SF-10: whichever control-plane message fails, either nothing is
    /// released, or every reservation of the round was recorded first.
    #[test]
    fn release_never_precedes_the_control_plane_reservation() {
        let dir = released_ledgers("order");
        let assets = ["gradient-a=ds-a".to_owned(), "gradient-b=ds-b".to_owned()];
        // Messages in order: 2 reservations, 2 commits, the completion.
        for fail_at in 0..5 {
            let recorded = RefCell::new(vec![]);
            let released = RefCell::new(false);
            let send = |kind: &str, p: serde_json::Value| -> Result<()> {
                // Fails persistently at message `fail_at` (every retry).
                if recorded.borrow().len() == fail_at {
                    return Err(Error::new(Code::Remote, "control plane down"));
                }
                recorded.borrow_mut().push((kind.to_owned(), p));
                Ok(())
            };
            let r = release_after_reserve(ROUND, Some(&dir), &assets, &CHARGED, 7, send, || {
                // The release: every reservation is already recorded.
                let rec = recorded.borrow();
                let reserved = rec.iter().filter(|(_, p)| is_reserve(p)).count();
                assert_eq!(
                    reserved, 2,
                    "released before the reservations were recorded"
                );
                *released.borrow_mut() = true;
                Ok(())
            });
            assert!(r.is_err(), "failure at message {fail_at} was not reported");
            let released = *released.borrow();
            assert_eq!(released, fail_at >= 2, "fail at {fail_at}");
            if released {
                assert!(r.unwrap_err().message.contains("reserved"));
            }
        }
        // A transient failure is retried; everything is delivered once.
        let recorded = RefCell::new(vec![]);
        let flaky = RefCell::new(true);
        let send = |kind: &str, _: serde_json::Value| -> Result<()> {
            if std::mem::replace(&mut *flaky.borrow_mut(), false) {
                return Err(Error::new(Code::Remote, "timeout"));
            }
            recorded.borrow_mut().push(kind.to_owned());
            Ok(())
        };
        let released = RefCell::new(false);
        let sent = release_after_reserve(ROUND, Some(&dir), &assets, &CHARGED, 7, send, || {
            *released.borrow_mut() = true;
            Ok(())
        })
        .unwrap();
        assert_eq!(sent, 4);
        assert!(*released.borrow());
        assert_eq!(recorded.borrow().len(), 5);
    }

    /// Review finding SA-1 (ENC-SF-2026-048): with a control plane, a budgeted asset whose
    /// `--control-asset` mapping is missing, misspelt or malformed, or whose
    /// local ledger is missing, used to be skipped: its spend was released
    /// with no control-plane reservation. Now nothing is sent or released.
    #[test]
    fn unmapped_budgeted_assets_release_nothing() {
        let dir = released_ledgers("unmapped");
        let cases: [&[&str]; 5] = [
            &[],
            &["gradient-a=ds-a"],
            &["gradient-a=ds-a", "gradient-b"],
            &["gradient-a=ds-a", "gradient-b="],
            &["gradient-a=ds-a", "gradient-bb=ds-b"],
        ];
        for assets in cases {
            let assets: Vec<String> = assets.iter().map(|a| a.to_string()).collect();
            let sent = RefCell::new(0);
            let released = RefCell::new(false);
            let r = release_after_reserve(
                ROUND,
                Some(&dir),
                &assets,
                &CHARGED,
                7,
                |_: &str, _: serde_json::Value| {
                    *sent.borrow_mut() += 1;
                    Ok(())
                },
                || {
                    *released.borrow_mut() = true;
                    Ok(())
                },
            );
            assert!(r.is_err(), "{assets:?} was released");
            assert_eq!(*sent.borrow(), 0, "{assets:?}");
            assert!(!*released.borrow(), "{assets:?}");
        }
        // Mapped, but the charged asset's ledger is missing, or there is no
        // ledger directory at all.
        let empty = std::env::temp_dir().join(format!("encompute-cli-sa1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&empty);
        std::fs::create_dir_all(&empty).unwrap();
        let assets = ["gradient-a=ds-a".to_owned(), "gradient-b=ds-b".to_owned()];
        for ledger in [Some(empty.as_path()), None] {
            let released = RefCell::new(false);
            let r = release_after_reserve(
                ROUND,
                ledger,
                &assets,
                &CHARGED,
                7,
                |_: &str, _: serde_json::Value| Ok(()),
                || {
                    *released.borrow_mut() = true;
                    Ok(())
                },
            );
            assert!(r.is_err() && !*released.borrow());
        }
        // A charged asset with no reservation of this round is refused too.
        let r = release_after_reserve(
            "cd",
            Some(&dir),
            &assets,
            &CHARGED,
            7,
            |_: &str, _: serde_json::Value| Ok(()),
            || panic!("released without a reservation"),
        );
        assert!(r.is_err());
        // Before the round: every budgeted asset must be mapped.
        assert!(control_mapping(&assets[..1], &CHARGED).is_err());
        assert!(control_mapping(&["gradient-a".to_owned()], &[]).is_err());
        assert_eq!(control_mapping(&assets, &CHARGED).unwrap().len(), 2);
    }

    fn state_path(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("encompute-cli-sa2-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("party.state")
    }

    /// Review finding SA-2 (ENC-SF-2026-071): concurrent joins sharing one `--state` file
    /// used to read, then write it without a lock, so one could lose the
    /// other's round (and a replay would be accepted). Under the lock every
    /// update sees the previous one.
    #[test]
    fn concurrent_state_updates_are_never_lost() {
        let p = state_path("race");
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let p = p.clone();
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        JoinState::update(&p, |st| {
                            let next = st.last_sequence("spec").unwrap_or(0) + 1;
                            std::thread::sleep(Duration::from_millis(1));
                            st.record_sequence("spec", next);
                            Ok(())
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(JoinState::read(&p).unwrap().last_sequence("spec"), Some(40));
        assert!(!sibling(&p, "tmp").exists(), "no temporary file is left");
    }

    /// Review finding SA-2 (ENC-SF-2026-071): the state only ever moves forward, per spec,
    /// and older files keep protecting every spec.
    #[test]
    fn state_is_monotonic_and_per_spec() {
        let p = state_path("mono");
        JoinState::update(&p, |st| {
            st.record_sequence("a", 7);
            st.record_sequence("a", 3);
            st.record_checkpoint(
                "gradient-a",
                encompute_runtime::dp::Checkpoint {
                    seq: 10,
                    root: "r10".into(),
                },
            );
            st.record_checkpoint(
                "gradient-a",
                encompute_runtime::dp::Checkpoint {
                    seq: 4,
                    root: "r4".into(),
                },
            );
            Ok(())
        })
        .unwrap();
        let st = JoinState::read(&p).unwrap();
        assert_eq!(st.last_sequence("a"), Some(7));
        assert_eq!(st.base.checkpoints["gradient-a"].seq, 10);
        // Another spec's rounds are not blocked by spec a's.
        assert_eq!(st.last_sequence("b"), None);
        // The file stays readable as the older format (by `migrate`).
        PartyStateFile::read(&p).unwrap();
        // An older bare-number file is a floor for every spec.
        std::fs::write(&p, "12\n").unwrap();
        let st = JoinState::read(&p).unwrap();
        assert_eq!(st.last_sequence("a"), Some(12));
        assert_eq!(st.last_sequence("b"), Some(12));
        // A failed update writes nothing.
        let r: Result<()> = JoinState::update(&p, |st| {
            st.record_sequence("a", 99);
            Err(Error::new(Code::AggregationBinding, "refused"))
        });
        assert!(r.is_err());
        assert_eq!(JoinState::read(&p).unwrap().last_sequence("a"), Some(12));
    }
}
