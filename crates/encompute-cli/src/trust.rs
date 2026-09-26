//! `encompute trust`: the trust graph (ADR-014) as a bundle file.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use encompute_ir::{Code, Error, Result};
use encompute_runtime::attestation::AttestationRecord;
use encompute_runtime::dp::PrivacyReceipt;
use encompute_runtime::secagg::{AggregationReceipt, AggregationSpec, PartyIdentity};
use encompute_runtime::trust::{
    node_id, Anchors, Authorization, EdgeKind, NodeKind, ReportOptions, Revocation, TrustGraph,
    AUTHORIZATION_VERSION,
};
use encompute_runtime::verification::SignedExecutionReceipt;

use crate::attest::TrustArgs;
use crate::load;

fn io(p: &Path, e: std::io::Error) -> Error {
    Error::new(Code::Artifact, format!("{}: {e}", p.display()))
}

fn read(p: &Path) -> Result<Vec<u8>> {
    std::fs::read(p).map_err(|e| io(p, e))
}

pub(crate) fn open(p: &Path) -> Result<TrustGraph> {
    TrustGraph::from_bytes(&read(p)?)
}

pub(crate) fn save(p: &Path, g: &TrustGraph) -> Result<()> {
    std::fs::write(p, g.to_bytes()?).map_err(|e| io(p, e))
}

#[derive(Args, Clone)]
pub struct Bundle {
    /// The trust bundle file.
    #[arg(long, default_value = "trust.json")]
    pub bundle: PathBuf,
}

#[derive(Subcommand)]
pub enum TrustCmd {
    /// Start a bundle from a program (and, for aggregations, the
    /// consortium's party identities).
    Init {
        model: PathBuf,
        #[arg(long)]
        parties: Option<PathBuf>,
        /// The approved confidential execution plan (`encompute plan -o`):
        /// recorded, and bound into the aggregation spec.
        #[arg(long)]
        plan: Option<PathBuf>,
        /// The coordinator attestation policy the rounds require (as given
        /// to `aggregate serve` and `join`).
        #[arg(long)]
        coordinator_policy: Option<PathBuf>,
        /// The attestation policy contributors must satisfy (as given to
        /// `aggregate serve` and `join`); required for DP-SGD.
        #[arg(long)]
        attestation_policy: Option<PathBuf>,
        #[command(flatten)]
        bundle: Bundle,
    },
    /// An owner approves the bundle's program for its assets.
    Authorize {
        #[arg(long)]
        party: String,
        /// The party's identity key (from `aggregate identity`).
        #[arg(long)]
        key: PathBuf,
        /// One asset (default: every asset the party owns).
        #[arg(long)]
        asset: Option<String>,
        /// Unix time the approval expires.
        #[arg(long)]
        expires_at: Option<u64>,
        #[command(flatten)]
        bundle: Bundle,
    },
    /// An owner withdraws an asset from now on.
    Revoke {
        #[arg(long)]
        party: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        asset: String,
        #[arg(long)]
        reason: String,
        #[command(flatten)]
        bundle: Bundle,
    },
    /// Add evidence: aggregation receipts, execution receipts, attestation
    /// records, privacy receipts, specs and approved plans (detected by
    /// content).
    Add {
        evidence: Vec<PathBuf>,
        #[command(flatten)]
        bundle: Bundle,
    },
    /// Check everything: the trust report. Signatures are checked only
    /// against the keys given here (obtained out of band, never from the
    /// bundle); evidence without one is reported as unchecked.
    Report {
        #[command(flatten)]
        bundle: Bundle,
        #[command(flatten)]
        anchors: AnchorArgs,
        #[command(flatten)]
        trust: TrustArgs,
        #[arg(long)]
        json: bool,
    },
    /// What a node was derived from, and what was derived from it.
    Lineage {
        node: String,
        #[command(flatten)]
        bundle: Bundle,
    },
    /// The graph (Graphviz DOT).
    Graph {
        #[command(flatten)]
        bundle: Bundle,
    },
}

/// What the verifier trusts, obtained out of band (never from the bundle).
#[derive(Args, Clone, Default)]
pub struct AnchorArgs {
    /// The consortium's party identities (`parties.json`).
    #[arg(long)]
    pub parties: Option<PathBuf>,
    /// A trusted aggregation coordinator's key (hex); repeatable.
    #[arg(long = "coordinator-key")]
    pub coordinator_keys: Vec<String>,
    /// A trusted evaluator's receipt key (hex); repeatable.
    #[arg(long = "evaluator-key")]
    pub evaluator_keys: Vec<String>,
    /// A report row that must be present, e.g. "Privacy budget";
    /// repeatable.
    #[arg(long)]
    pub require: Vec<String>,
    /// The attestation policy execution and training workloads must
    /// satisfy (from `encompute attest policy`); rounds use their spec's
    /// own.
    #[arg(long)]
    pub execution_policy: Option<PathBuf>,
}

/// The bundle and its trust report under `anchors`.
pub(crate) fn checked(
    bundle: &Path,
    a: &AnchorArgs,
    trust: &TrustArgs,
) -> Result<(TrustGraph, encompute_runtime::trust::TrustReport)> {
    let g = open(bundle)?;
    let verifier = trust.verifier(None).ok();
    let mut anchors = Anchors {
        coordinators: a.coordinator_keys.iter().cloned().collect(),
        evaluators: a.evaluator_keys.iter().cloned().collect(),
        ..Anchors::default()
    };
    if let Some(p) = &a.parties {
        let ids: Vec<PartyIdentity> = serde_json::from_slice(&read(p)?)
            .map_err(|e| Error::new(Code::TrustGraph, format!("{}: {e}", p.display())))?;
        anchors.parties = ids
            .into_iter()
            .map(|i| (i.party.to_string(), i.public_key))
            .collect();
    }
    let execution_policy: Option<encompute_runtime::attestation::AttestationPolicy> =
        match &a.execution_policy {
            Some(p) => Some(
                serde_json::from_slice(&read(p)?)
                    .map_err(|e| Error::new(Code::TrustGraph, format!("{}: {e}", p.display())))?,
            ),
            None => None,
        };
    let r = g.report(&ReportOptions {
        anchors,
        verifier: verifier.as_ref(),
        execution_policy: execution_policy.as_ref(),
        require: a.require.clone(),
        ..ReportOptions::default()
    })?;
    Ok((g, r))
}

/// `encompute lineage`: an adapter's full lineage and evidence verdicts.
pub fn lineage(
    adapter: &str,
    bundle: &Path,
    a: &AnchorArgs,
    trust: &TrustArgs,
) -> Result<ExitCode> {
    let (g, r) = checked(bundle, a, trust)?;
    print!(
        "{}",
        encompute_runtime::trust::lineage::adapter_lineage(&g, adapter, &r)?
    );
    Ok(if r.satisfied {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// `encompute export`: permitted only if every parent's policy allows it,
/// no parent was revoked, and the run's trust report is satisfied.
pub fn export(adapter: &str, bundle: &Path, a: &AnchorArgs, trust: &TrustArgs) -> Result<ExitCode> {
    let (g, r) = checked(bundle, a, trust)?;
    let (spec, program) = encompute_runtime::trust::lineage::adapter_context(&g, adapter)?;
    let p = encompute_ir::parse(&program)?;
    let parents: Vec<String> = std::iter::once(&spec.base_model.asset_id)
        .chain(
            spec.datasets
                .iter()
                .flat_map(|d| [&d.asset_id, &d.gradient_asset]),
        )
        .map(|x| node_id(NodeKind::Asset, x))
        .collect();
    let revoked: Vec<&str> = r
        .revoked
        .keys()
        .filter(|k| parents.contains(k))
        .map(|k| k.trim_start_matches("asset:"))
        .collect();
    if !revoked.is_empty() {
        println!(
            "EXPORT DENIED: {adapter} derives from revoked assets: {}",
            revoked.join(", ")
        );
        return Ok(ExitCode::from(1));
    }
    if !r.satisfied {
        println!(
            "EXPORT DENIED: the run that produced {adapter} does not satisfy its trust \
             requirements:\n  {}",
            r.unmet.join("\n  ")
        );
        return Ok(ExitCode::from(1));
    }
    match encompute_runtime::training::check_export(&p, &spec, adapter) {
        Ok(()) => {
            println!("EXPORT PERMITTED: every parent of {adapter} allows public release");
            Ok(ExitCode::SUCCESS)
        }
        Err(e) if e.code == Code::ExportDenied => {
            println!("{}", e.message);
            Ok(ExitCode::from(1))
        }
        Err(e) => Err(e),
    }
}

fn key_file(p: &Path) -> Result<ed25519_dalek::SigningKey> {
    let seed: [u8; 32] = read(p)?
        .try_into()
        .map_err(|_| Error::new(Code::TrustAuthorization, "a key file is 32 bytes"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

/// A program's ID, policy ID, privacy policy ID and purpose.
type ProgramIds = (String, Option<String>, Option<String>, Option<String>);

/// The bundle's one program: its ID, policies and purpose.
fn program(g: &TrustGraph) -> Result<ProgramIds> {
    let mut ps = g.of(NodeKind::Program);
    let (id, n) = ps
        .next()
        .ok_or_else(|| Error::new(Code::TrustGraph, "the bundle has no program"))?;
    let key = |k: NodeKind| {
        g.out(id, EdgeKind::GovernedBy)
            .find(|x| x.starts_with(&format!("{}:", k.prefix())))
            .map(|x| x.split_once(':').expect("id").1.to_owned())
    };
    Ok((
        id.trim_start_matches("program:").to_owned(),
        key(NodeKind::Policy),
        key(NodeKind::PrivacyPolicy),
        n.attrs.get("purpose").cloned(),
    ))
}

fn add_evidence(g: &mut TrustGraph, bytes: &[u8]) -> Result<String> {
    if let Ok(r) = serde_json::from_slice::<AggregationReceipt>(bytes) {
        return g.add_aggregation(r);
    }
    if let Ok(r) = SignedExecutionReceipt::from_bytes(bytes) {
        return g.add_execution_receipt(r);
    }
    if let Ok(r) = AttestationRecord::from_bytes(bytes) {
        return g.add_attestation(r);
    }
    if let Ok(r) = serde_json::from_slice::<PrivacyReceipt>(bytes) {
        return g.add_privacy_receipt(r);
    }
    if let Ok(s) = serde_json::from_slice::<AggregationSpec>(bytes) {
        return g.add_aggregation_spec(s);
    }
    if let Ok(p) = encompute_runtime::planner::ConfidentialExecutionPlan::from_bytes(bytes) {
        return g.add_plan(p);
    }
    if let Ok(s) = serde_json::from_slice::<encompute_runtime::training::TrainingSpec>(bytes) {
        return g.add_training_spec(s);
    }
    if let Ok(r) = serde_json::from_slice::<encompute_runtime::training::SignedAdapterRecord>(bytes)
    {
        return g.add_adapter(r);
    }
    if let Ok(r) =
        serde_json::from_slice::<encompute_runtime::training::SignedWorkerEvidence>(bytes)
    {
        return g.add_worker_evidence(r);
    }
    Err(Error::new(
        Code::TrustEvidence,
        "not a receipt, record or spec Encompute knows",
    ))
}

pub fn trust(cmd: TrustCmd) -> Result<ExitCode> {
    match cmd {
        TrustCmd::Init {
            model,
            parties,
            plan,
            coordinator_policy,
            attestation_policy,
            bundle,
        } => {
            let m = load(&model)?;
            let mut g = TrustGraph::new();
            let prog = g.add_program(&m.program().to_string())?;
            let plan_id = match &plan {
                Some(p) => {
                    let p = encompute_runtime::planner::ConfidentialExecutionPlan::from_bytes(
                        &read(p)?,
                    )?;
                    let id = p.id()?.hex();
                    g.add_plan(p)?;
                    Some(id)
                }
                None => None,
            };
            if let Some(p) = parties {
                let ids: Vec<PartyIdentity> = serde_json::from_slice(&read(&p)?)
                    .map_err(|e| Error::new(Code::TrustGraph, format!("{}: {e}", p.display())))?;
                g.add_party_keys(&ids)?;
                if let Ok(mut plan) = m.aggregation_plan(None) {
                    if let Some(id) = &plan_id {
                        plan = plan.with_execution_plan(id);
                    }
                    let ordered: Vec<PartyIdentity> = plan
                        .participants
                        .iter()
                        .filter_map(|pp| ids.iter().find(|i| i.party == pp.party).cloned())
                        .collect();
                    let mut spec = AggregationSpec::new(plan, ordered)?;
                    if let Some(p) = &coordinator_policy {
                        spec.coordinator_attestation =
                            Some(serde_json::from_slice(&read(p)?).map_err(|e| {
                                Error::new(Code::TrustGraph, format!("{}: {e}", p.display()))
                            })?);
                    }
                    if let Some(p) = &attestation_policy {
                        spec.attestation =
                            Some(serde_json::from_slice(&read(p)?).map_err(|e| {
                                Error::new(Code::TrustGraph, format!("{}: {e}", p.display()))
                            })?);
                    }
                    g.add_aggregation_spec(spec)?;
                }
            }
            save(&bundle.bundle, &g)?;
            println!("trust bundle {} for {prog}", bundle.bundle.display());
            Ok(ExitCode::SUCCESS)
        }
        TrustCmd::Authorize {
            party,
            key,
            asset,
            expires_at,
            bundle,
        } => {
            let mut g = open(&bundle.bundle)?;
            let (program_id, policy_id, privacy_policy_id, purpose) = program(&g)?;
            let pnode = node_id(NodeKind::Party, &party);
            let assets: Vec<String> = match asset {
                Some(a) => vec![a],
                None => g
                    .out(&pnode, EdgeKind::Owns)
                    .map(|a| a.trim_start_matches("asset:").to_owned())
                    .collect(),
            };
            if assets.is_empty() {
                return Err(Error::new(
                    Code::TrustAuthorization,
                    format!("{party} owns no asset"),
                ));
            }
            let k = key_file(&key)?;
            for a in &assets {
                let s = Authorization {
                    version: AUTHORIZATION_VERSION,
                    party: party.clone(),
                    asset: a.clone(),
                    program_id: program_id.clone(),
                    policy_id: policy_id.clone(),
                    privacy_policy_id: privacy_policy_id.clone(),
                    purpose: purpose.clone(),
                    issued_at: encompute_runtime::attestation::unix_now(),
                    expires_at,
                }
                .sign(&k)?;
                g.add_authorization(s)?;
                println!("{party} approves program {} for {a}", &program_id[..16]);
            }
            save(&bundle.bundle, &g)?;
            Ok(ExitCode::SUCCESS)
        }
        TrustCmd::Revoke {
            party,
            key,
            asset,
            reason,
            bundle,
        } => {
            let mut g = open(&bundle.bundle)?;
            let s = Revocation {
                version: AUTHORIZATION_VERSION,
                party: party.clone(),
                asset: asset.clone(),
                authorization: None,
                reason,
                issued_at: encompute_runtime::attestation::unix_now(),
            }
            .sign(&key_file(&key)?)?;
            g.add_revocation(s)?;
            let down = g.downstream(&node_id(NodeKind::Asset, &asset));
            save(&bundle.bundle, &g)?;
            println!("{party} revoked {asset}; derived from it: {}", down.len());
            for d in down {
                println!("  {d}");
            }
            Ok(ExitCode::SUCCESS)
        }
        TrustCmd::Add { evidence, bundle } => {
            let mut g = open(&bundle.bundle)?;
            for p in &evidence {
                let id = add_evidence(&mut g, &read(p)?)
                    .map_err(|e| Error::new(e.code, format!("{}: {}", p.display(), e.message)))?;
                println!("added {id}");
            }
            save(&bundle.bundle, &g)?;
            Ok(ExitCode::SUCCESS)
        }
        TrustCmd::Report {
            bundle,
            anchors,
            trust,
            json,
        } => {
            let (_, r) = checked(&bundle.bundle, &anchors, &trust)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r).expect("JSON"));
            } else {
                print!("{r}");
            }
            Ok(if r.satisfied {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        TrustCmd::Lineage { node, bundle } => {
            let g = open(&bundle.bundle)?;
            let id = if node.contains(':') {
                node
            } else {
                node_id(NodeKind::Asset, &node)
            };
            if g.node(&id).is_none() {
                return Err(Error::new(Code::TrustGraph, format!("no node {id}")));
            }
            println!("{id}");
            println!("  derived from: {:?}", g.upstream(&id));
            println!("  derived into: {:?}", g.downstream(&id));
            Ok(ExitCode::SUCCESS)
        }
        TrustCmd::Graph { bundle } => {
            let g = open(&bundle.bundle)?;
            let q = |s: &str| format!("\"{}\"", s.replace('"', "\\\""));
            let mut s = String::from("digraph trust {\n  rankdir=LR;\n  node [shape=box];\n");
            for (id, n) in &g.nodes {
                let ev = if n.evidence.is_some() {
                    "\\n(evidence)"
                } else {
                    ""
                };
                s.push_str(&format!(
                    "  {} [label={}];\n",
                    q(id),
                    q(&format!("{}{ev}", n.label))
                ));
            }
            for e in &g.edges {
                s.push_str(&format!(
                    "  {} -> {} [label={}];\n",
                    q(&e.from),
                    q(&e.to),
                    q(&format!("{:?}", e.kind).to_lowercase())
                ));
            }
            s.push_str("}\n");
            print!("{s}");
            Ok(ExitCode::SUCCESS)
        }
    }
}
