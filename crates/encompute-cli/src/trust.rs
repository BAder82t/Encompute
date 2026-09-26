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
        /// The consortium's party identities (`parties.json`).
        #[arg(long)]
        parties: Option<PathBuf>,
        /// A trusted aggregation coordinator's key (hex); repeatable.
        #[arg(long = "coordinator-key")]
        coordinator_keys: Vec<String>,
        /// A trusted evaluator's receipt key (hex); repeatable.
        #[arg(long = "evaluator-key")]
        evaluator_keys: Vec<String>,
        /// A report row that must be present, e.g. "Privacy budget";
        /// repeatable.
        #[arg(long)]
        require: Vec<String>,
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
                    g.add_aggregation_spec(AggregationSpec::new(plan, ordered)?)?;
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
            parties,
            coordinator_keys,
            evaluator_keys,
            require,
            trust,
            json,
        } => {
            let g = open(&bundle.bundle)?;
            let verifier = trust.verifier(None).ok();
            let mut anchors = Anchors {
                coordinators: coordinator_keys.into_iter().collect(),
                evaluators: evaluator_keys.into_iter().collect(),
                ..Anchors::default()
            };
            if let Some(p) = parties {
                let ids: Vec<PartyIdentity> = serde_json::from_slice(&read(&p)?)
                    .map_err(|e| Error::new(Code::TrustGraph, format!("{}: {e}", p.display())))?;
                anchors.parties = ids
                    .into_iter()
                    .map(|i| (i.party.to_string(), i.public_key))
                    .collect();
            }
            let r = g.report(&ReportOptions {
                anchors,
                verifier: verifier.as_ref(),
                require,
                ..ReportOptions::default()
            })?;
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
