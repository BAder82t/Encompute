//! `encompute aggregate`: secure aggregation rounds (ADR-012).
//!
//! Every party builds the aggregation spec from its own copy of the
//! artifact and the consortium's `parties.json`, and joins only a round of
//! exactly that spec.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Subcommand};
use encompute_ir::confidentiality::PartyId;
use encompute_ir::{Code, Error, Result};
use encompute_runtime::attestation::{AttestationPolicy, AttestationRecord};
use encompute_runtime::secagg::service::{join, CoordinatorService, ParticipantClient};
use encompute_runtime::secagg::{
    identity_of, party_key_from_seed, verify_aggregation_receipt, AggregateAsset,
    AggregationReceipt, AggregationSpec, PartyIdentity, RoundCoordinator,
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
        let mut spec = AggregationSpec::new(plan, ordered)?;
        spec.training_execution_spec_id = self.training_spec.clone();
        if let Some(p) = &self.attestation_policy {
            spec.attestation = Some(json::<AttestationPolicy>(p)?);
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
        #[arg(long, default_value = "aggregation-receipt.json")]
        receipt: PathBuf,
        #[command(flatten)]
        trust: TrustArgs,
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
        /// JSON array of numbers: this party's contribution.
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
            receipt,
            trust,
        } => {
            let spec = spec.spec()?;
            let verifier = match &spec.attestation {
                Some(_) => Some(trust.verifier(None)?),
                None => None,
            };
            let now = encompute_runtime::attestation::unix_now();
            let coord = RoundCoordinator::open(spec, sequence, key_file(&key)?, verifier, now)?;
            let round_id = coord.round_id()?;
            let svc = CoordinatorService::new(coord, Duration::from_secs(stage_timeout))?;
            let server = tiny_http::Server::http(&listen)
                .map_err(|e| Error::new(Code::Remote, format!("{listen}: {e}")))?;
            svc.spawn(server);
            eprintln!(
                "aggregation round encround1:{} on http://{listen}",
                short(&round_id)
            );
            let (asset, r) = svc.run_to_completion()?;
            std::fs::write(&out, serde_json::to_vec_pretty(&asset).expect("JSON"))
                .map_err(|e| io(&out, e))?;
            std::fs::write(&receipt, r.to_bytes()?).map_err(|e| io(&receipt, e))?;
            println!("AGGREGATION COMPLETE");
            print_manifest(&r);
            println!(
                "{:<16}{} ({} values)",
                "Aggregate",
                out.display(),
                asset.values.len()
            );
            println!("{:<16}{}", "Receipt", receipt.display());
            // Let participants collect the receipt before exiting.
            std::thread::sleep(Duration::from_secs(2));
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
        } => {
            let approved = spec.spec()?;
            let party = PartyId::new(&party)?;
            let values: Vec<f64> = json(&values)?;
            let last: Option<u64> = if state.exists() {
                Some(json(&state)?)
            } else {
                None
            };
            let attestation = match &attestation {
                Some(p) => Some(AttestationRecord::from_bytes(&read(p)?)?),
                None => None,
            };
            let client = ParticipantClient::new(&coordinator, Duration::from_secs(timeout));
            let p = join(
                &client,
                &approved,
                &party,
                key_file(&key)?,
                &values,
                attestation,
                last,
            )?;
            let sequence = p.round.sequence;
            std::fs::write(&state, sequence.to_string()).map_err(|e| io(&state, e))?;
            let r = client.participate(p)?;
            verify_aggregation_receipt(&r, &approved, None, None)?;
            println!("CONTRIBUTION ACCEPTED (only the aggregate is released)");
            print_manifest(&r);
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
