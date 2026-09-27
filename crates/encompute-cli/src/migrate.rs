//! `encompute migrate`: find a persistent artifact's kind and version, say
//! whether this build reads it as it is, and upgrade older versions into a
//! new copy.
//!
//! Migrations transform metadata only. They never touch key material, never
//! re-sign, and never rewrite an object whose bytes are signed, sealed,
//! hash-chained or content-addressed: those are current, refused, or kept
//! as-is. The input is never modified; an upgrade is written to `--out DIR`
//! through a temporary name and a rename.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use encompute_ir::{Code, Error, Result};
use encompute_protocol::sha256_hex as sha256;
use encompute_runtime::verification::{EvaluatorIdentity, SignedExecutionReceipt};
use encompute_runtime::Model;
use serde_json::Value;
use zeroize::Zeroize;

use crate::aggregate::PartyStateFile;

#[derive(Args)]
pub struct MigrateArgs {
    /// The artifact: a `.encompute` directory, a key directory, a privacy
    /// ledger directory or `.ledger` file, or a receipt, trust bundle,
    /// plan, checkpoint, sealed asset, adapter record, attestation record
    /// or policy, envelope, or aggregation state file.
    path: PathBuf,
    /// Only report; never write. Exit 0 if current, 1 if an upgrade is
    /// available, 3 if an older version is kept as-is.
    #[arg(long, conflicts_with = "out")]
    check: bool,
    /// Write the upgraded copy to DIR/<name of PATH> (DIR is created; an
    /// existing DIR/<name> is never overwritten). Without it nothing is
    /// written.
    #[arg(long, value_name = "DIR")]
    out: Option<PathBuf>,
    /// One JSON object instead of the line.
    #[arg(long)]
    json: bool,
}

/// Exit status: an older version that stays as it is.
const KEPT_AS_IS: u8 = 3;

/// A file's bytes (key "") or a directory's top-level files by name.
type Tree = BTreeMap<String, Vec<u8>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Model,
    Keys,
    Envelope,
    ExecutionReceipt,
    TrustBundle,
    Checkpoint,
    SealedAsset,
    AdapterRecord,
    Ledger,
    LedgerDir,
    Plan,
    AggregationReceipt,
    AttestationRecord,
    AttestationPolicy,
    PartyState,
}

impl Kind {
    fn id(self) -> &'static str {
        match self {
            Kind::Model => "model_artifact",
            Kind::Keys => "key_directory",
            Kind::Envelope => "envelope",
            Kind::ExecutionReceipt => "execution_receipt",
            Kind::TrustBundle => "trust_bundle",
            Kind::Checkpoint => "checkpoint",
            Kind::SealedAsset => "sealed_asset",
            Kind::AdapterRecord => "adapter_record",
            Kind::Ledger => "privacy_ledger",
            Kind::LedgerDir => "privacy_ledger_directory",
            Kind::Plan => "execution_plan",
            Kind::AggregationReceipt => "aggregation_receipt",
            Kind::AttestationRecord => "attestation_record",
            Kind::AttestationPolicy => "attestation_policy",
            Kind::PartyState => "aggregation_party_state",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Kind::Model => "compiled model artifact",
            Kind::Keys => "key directory",
            Kind::Envelope => "envelope",
            Kind::ExecutionReceipt => "execution receipt",
            Kind::TrustBundle => "trust bundle",
            Kind::Checkpoint => "sealed training checkpoint",
            Kind::SealedAsset => "sealed asset",
            Kind::AdapterRecord => "signed adapter record",
            Kind::Ledger => "privacy ledger",
            Kind::LedgerDir => "privacy ledger directory",
            Kind::Plan => "confidential execution plan",
            Kind::AggregationReceipt => "aggregation receipt",
            Kind::AttestationRecord => "attestation record",
            Kind::AttestationPolicy => "attestation policy",
            Kind::PartyState => "aggregation party state",
        }
    }

    fn version_word(self) -> &'static str {
        match self {
            Kind::Model | Kind::Keys | Kind::Envelope => "format",
            _ => "version",
        }
    }

    /// The version this build writes.
    fn current(self) -> u32 {
        use encompute_runtime as rt;
        match self {
            Kind::Model => rt::ARTIFACT_FORMAT,
            Kind::Keys | Kind::Envelope => u32::from(encompute_protocol::FORMAT_VERSION),
            Kind::ExecutionReceipt => rt::verification::RECEIPT_VERSION,
            Kind::TrustBundle => rt::trust::graph::GRAPH_VERSION,
            Kind::Checkpoint => rt::training::checkpoint::CHECKPOINT_VERSION,
            Kind::SealedAsset => rt::training::seal::ASSET_VERSION,
            Kind::AdapterRecord => rt::training::adapter::ADAPTER_VERSION,
            Kind::Ledger | Kind::LedgerDir => rt::dp::ledger::LEDGER_VERSION,
            Kind::Plan => rt::planner::PLAN_VERSION,
            Kind::AggregationReceipt => rt::secagg::round::RECEIPT_VERSION,
            Kind::AttestationRecord => rt::attestation::RECORD_VERSION,
            Kind::AttestationPolicy => rt::attestation::POLICY_VERSION,
            // 0: a bare sequence number; 1: JSON.
            Kind::PartyState => 1,
        }
    }

    /// The code for a malformed, tampered or unreadable object of this kind.
    fn code(self) -> Code {
        match self {
            Kind::Model => Code::Artifact,
            Kind::Keys | Kind::Envelope => Code::Envelope,
            Kind::ExecutionReceipt => Code::Receipt,
            Kind::TrustBundle => Code::TrustGraph,
            Kind::Checkpoint | Kind::SealedAsset => Code::Checkpoint,
            Kind::AdapterRecord => Code::TrainingSpec,
            Kind::Ledger | Kind::LedgerDir => Code::PrivacyLedger,
            Kind::Plan => Code::PlanInvalid,
            Kind::AggregationReceipt => Code::AggregationProtocol,
            Kind::AttestationRecord => Code::Attestation,
            Kind::AttestationPolicy => Code::WorkloadPolicy,
            Kind::PartyState => Code::AggregationBinding,
        }
    }

    /// Older versions this build keeps as they are, and why.
    fn kept_as_is(self, v: u32) -> Option<&'static str> {
        match (self, v) {
            (Kind::ExecutionReceipt, 1 | 2) => Some(
                "the evaluator signed the version with the receipt, so any rewrite would \
                 invalidate its signature; this build's `encompute verify` reads version 3 only",
            ),
            _ => None,
        }
    }

    /// The upgrade steps, applied in sequence up to [`Kind::current`].
    fn steps(self) -> &'static [Step] {
        match self {
            Kind::Model => MODEL_STEPS,
            Kind::PartyState => PARTY_STATE_STEPS,
            _ => &[],
        }
    }
}

/// One registered upgrade: a `from` tree becomes a `to` tree.
struct Step {
    from: u32,
    to: u32,
    apply: fn(Tree) -> Result<Tree>,
}

/// Formats 2 (0.2), 3 (exact plans) and 4 (`verification.json`) regenerate
/// every derived file from `program.eir`, only when the stored program,
/// plan, parameters and backend are exactly what this build compiles.
const MODEL_STEPS: &[Step] = &[
    Step {
        from: 2,
        to: 5,
        apply: rederive_artifact,
    },
    Step {
        from: 3,
        to: 5,
        apply: rederive_artifact,
    },
    Step {
        from: 4,
        to: 5,
        apply: rederive_artifact,
    },
];

const PARTY_STATE_STEPS: &[Step] = &[Step {
    from: 0,
    to: 1,
    apply: party_state_json,
}];

fn run_steps(kind: Kind, mut v: u32, mut tree: Tree) -> Result<Tree> {
    while v != kind.current() {
        let step = kind.steps().iter().find(|s| s.from == v).ok_or_else(|| {
            Error::new(
                Code::Incompatible,
                format!("no migration from {} version {v}", kind.label()),
            )
        })?;
        debug_assert!(step.to > step.from);
        tree = (step.apply)(tree)?;
        v = step.to;
    }
    Ok(tree)
}

struct Found {
    path: PathBuf,
    kind: Kind,
    version: u32,
    tree: Tree,
    dir: bool,
}

impl Drop for Found {
    /// A key directory's tree holds the secret key's envelope.
    fn drop(&mut self) {
        for b in self.tree.values_mut() {
            b.zeroize();
        }
    }
}

enum Status {
    Current,
    /// `tree` is the upgraded content; `note` qualifies the old version.
    Upgrade {
        note: Option<String>,
        tree: Tree,
    },
    KeptAsIs(&'static str),
}

fn unreadable(p: &Path, e: std::io::Error) -> Error {
    Error::new(Code::Artifact, format!("{}: {e}", p.display()))
}

fn corrupt(kind: Kind, path: &Path, m: impl std::fmt::Display) -> Error {
    Error::new(
        kind.code(),
        format!("{} ({}): {m}", kind.label(), path.display()),
    )
}

fn unknown(path: &Path) -> Error {
    Error::new(
        Code::Artifact,
        format!(
            "{}: not an Encompute artifact this build recognizes",
            path.display()
        ),
    )
}

/// Largest single file read (evaluation keys can be large).
const MAX_FILE: u64 = 4 << 30;

fn read_file(p: &Path) -> Result<Vec<u8>> {
    let len = std::fs::metadata(p).map_err(|e| unreadable(p, e))?.len();
    if len > MAX_FILE {
        return Err(Error::new(
            Code::Artifact,
            format!("{} is too large", p.display()),
        ));
    }
    std::fs::read(p).map_err(|e| unreadable(p, e))
}

fn detect(path: &Path) -> Result<Found> {
    let meta = std::fs::metadata(path).map_err(|e| unreadable(path, e))?;
    let (kind, version, tree) = if meta.is_dir() {
        detect_dir(path)?
    } else {
        let bytes = read_file(path)?;
        let (kind, version) = detect_file(path, &bytes)?;
        (kind, version, Tree::from([(String::new(), bytes)]))
    };
    Ok(Found {
        path: path.to_owned(),
        kind,
        version,
        tree,
        dir: meta.is_dir(),
    })
}

fn detect_dir(path: &Path) -> Result<(Kind, u32, Tree)> {
    // Top-level regular files only; each kind reads just the ones it owns.
    let mut names = Vec::new();
    for e in std::fs::read_dir(path).map_err(|e| unreadable(path, e))? {
        let e = e.map_err(|e| unreadable(path, e))?;
        if e.path().is_file() {
            if let Some(n) = e.file_name().to_str() {
                names.push(n.to_owned());
            }
        }
    }
    let has = |n: &str| names.iter().any(|x| x == n);
    let load = |tree: &mut Tree, names: &[String]| -> Result<()> {
        for n in names {
            tree.insert(n.clone(), read_file(&path.join(n))?);
        }
        Ok(())
    };
    if has("manifest.json") {
        let mut t = Tree::new();
        let files: Vec<String> = names
            .iter()
            .filter(|n| *n == "program.eir" || n.ends_with(".json"))
            .cloned()
            .collect();
        load(&mut t, &files)?;
        let m: Value = serde_json::from_slice(&t["manifest.json"])
            .map_err(|e| corrupt(Kind::Model, path, format!("manifest.json: {e}")))?;
        let v = match m.get("artifact_format") {
            // The 0.1 layout had no format number.
            None => 1,
            Some(f) => version_of(Kind::Model, path, f)?,
        };
        return Ok((Kind::Model, v, t));
    }
    if has("secret.key") || has("eval.keys") {
        let mut t = Tree::new();
        let present: Vec<String> = ["secret.key", "eval.keys", "evaluator.pub"]
            .iter()
            .filter(|n| has(n))
            .map(|n| n.to_string())
            .collect();
        load(&mut t, &present)?;
        let mut version = None;
        for (name, bytes) in &t {
            if name == "evaluator.pub" {
                continue;
            }
            let v = envelope_version(Kind::Keys, &path.join(name), bytes)?;
            check_known(Kind::Keys, path, v)?;
            version = Some(v);
        }
        return Ok((Kind::Keys, version.expect("a key file"), t));
    }
    let ledgers: Vec<String> = names
        .into_iter()
        .filter(|n| n.ends_with(".ledger"))
        .collect();
    if !ledgers.is_empty() {
        let mut t = Tree::new();
        load(&mut t, &ledgers)?;
        let mut version = 0;
        for (name, bytes) in &t {
            let v = ledger_version(Kind::LedgerDir, &path.join(name), bytes)?;
            check_known(Kind::LedgerDir, &path.join(name), v)?;
            version = v;
        }
        return Ok((Kind::LedgerDir, version, t));
    }
    Err(unknown(path))
}

fn version_of(kind: Kind, path: &Path, v: &Value) -> Result<u32> {
    v.as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| corrupt(kind, path, format!("version {v} is not a number")))
}

fn envelope_version(kind: Kind, path: &Path, b: &[u8]) -> Result<u32> {
    if b.len() < 6 || &b[..4] != encompute_protocol::MAGIC {
        return Err(corrupt(kind, path, "not an Encompute envelope"));
    }
    Ok(u32::from(u16::from_le_bytes([b[4], b[5]])))
}

fn ledger_version(kind: Kind, path: &Path, b: &[u8]) -> Result<u32> {
    let first = b.split(|&c| c == b'\n').next().unwrap_or_default();
    let g: Value =
        serde_json::from_slice(first).map_err(|e| corrupt(kind, path, format!("genesis: {e}")))?;
    version_of(kind, path, g.get("version").unwrap_or(&Value::Null))
}

fn detect_file(path: &Path, b: &[u8]) -> Result<(Kind, u32)> {
    if b.starts_with(encompute_protocol::MAGIC) {
        return Ok((Kind::Envelope, envelope_version(Kind::Envelope, path, b)?));
    }
    if b.starts_with(b"ENCSEAL1") {
        let h: Value = encompute_runtime::training::seal::peek(b)?;
        let kind = if h.get("training_spec_id").is_some() {
            Kind::Checkpoint
        } else if h.get("asset_id").is_some() {
            Kind::SealedAsset
        } else {
            return Err(corrupt(Kind::SealedAsset, path, "unknown sealed header"));
        };
        let v = version_of(kind, path, h.get("version").unwrap_or(&Value::Null))?;
        return Ok((kind, v));
    }
    let Ok(text) = std::str::from_utf8(b) else {
        return Err(unknown(path));
    };
    if text.trim().parse::<u64>().is_ok() {
        return Ok((Kind::PartyState, 0));
    }
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        if let Some((kind, ptr)) = classify(&v) {
            let version = match ptr {
                Some(ptr) => version_of(kind, path, v.pointer(ptr).unwrap_or(&Value::Null))?,
                None => kind.current(),
            };
            return Ok((kind, version));
        }
        return Err(unknown(path));
    }
    // A ledger: a genesis line, then one entry per line.
    let first = text.lines().next().unwrap_or_default();
    if let Ok(v) = serde_json::from_str::<Value>(first) {
        if let Some((Kind::Ledger, _)) = classify(&v) {
            return Ok((Kind::Ledger, ledger_version(Kind::Ledger, path, b)?));
        }
    }
    Err(unknown(path))
}

/// A JSON object's kind, by its fields, and where its version is.
fn classify(v: &Value) -> Option<(Kind, Option<&'static str>)> {
    let o = v.as_object()?;
    let has = |k: &str| o.contains_key(k);
    Some(
        if has("receipt") && has("evaluator_public_key") && has("signature") {
            (Kind::ExecutionReceipt, Some("/receipt/version"))
        } else if has("manifest") && has("coordinator_key") && has("signature") {
            (Kind::AggregationReceipt, Some("/manifest/version"))
        } else if has("record") && has("signer_key") && has("signature") {
            (Kind::AdapterRecord, Some("/record/version"))
        } else if has("nodes") && has("edges") {
            (Kind::TrustBundle, Some("/version"))
        } else if has("asset_id") && has("budget") && has("privacy_policy_id") {
            (Kind::Ledger, Some("/version"))
        } else if has("program_id") && has("requirements") && has("steps") {
            (Kind::Plan, Some("/version"))
        } else if has("execution_spec_id") && has("allowed_tee") {
            (Kind::AttestationPolicy, Some("/version"))
        } else if has("evidence") && has("version") && o.len() == 2 {
            (Kind::AttestationRecord, Some("/version"))
        } else if !o.is_empty() && o.keys().all(|k| k == "sequence" || k == "checkpoints") {
            (Kind::PartyState, None)
        } else {
            return None;
        },
    )
}

/// Refuses versions newer than this build, and versions it never knew.
fn check_known(kind: Kind, path: &Path, v: u32) -> Result<()> {
    let cur = kind.current();
    if v > cur {
        return Err(Error::new(
            Code::Incompatible,
            format!(
                "{} ({}): version {v} is newer than this Encompute ({}) reads (version {cur}); \
                 use a newer Encompute",
                kind.label(),
                path.display(),
                env!("CARGO_PKG_VERSION")
            ),
        ));
    }
    if v != cur && kind.kept_as_is(v).is_none() && !kind.steps().iter().any(|s| s.from == v) {
        let mut known: Vec<String> = kind.steps().iter().map(|s| s.from.to_string()).collect();
        known.extend(
            (0..cur)
                .filter(|&o| kind.kept_as_is(o).is_some())
                .map(|o| o.to_string()),
        );
        known.push(cur.to_string());
        return Err(Error::new(
            Code::Incompatible,
            format!(
                "{} ({}): version {v} is not a version this Encompute knows (it reads {})",
                kind.label(),
                path.display(),
                known.join(", ")
            ),
        ));
    }
    Ok(())
}

fn assess(f: &Found) -> Result<Status> {
    check_known(f.kind, &f.path, f.version)?;
    if f.version == f.kind.current() {
        return check_current(f);
    }
    if let Some(why) = f.kind.kept_as_is(f.version) {
        return Ok(Status::KeptAsIs(why));
    }
    let tree = run_steps(f.kind, f.version, f.tree.clone())?;
    Ok(Status::Upgrade { note: None, tree })
}

/// A current-version object: verify it the way its reader does.
fn check_current(f: &Found) -> Result<Status> {
    let (kind, path) = (f.kind, f.path.as_path());
    let bytes = || f.tree.get("").map(Vec::as_slice).unwrap_or_default();
    let bad = |e: Error| corrupt(kind, path, e.message);
    match kind {
        Kind::Model => return model_current(f),
        Kind::Keys => {
            for (name, b) in &f.tree {
                if name == "evaluator.pub" {
                    let hex = String::from_utf8_lossy(b);
                    EvaluatorIdentity::from_public_key_hex(hex.trim()).map_err(bad)?;
                    continue;
                }
                let env = encompute_protocol::Envelope::decode(b).map_err(bad)?;
                let want = if name == "secret.key" {
                    encompute_protocol::Kind::SecretKey
                } else {
                    encompute_protocol::Kind::EvaluationKeys
                };
                if env.header.kind != want {
                    return Err(corrupt(
                        kind,
                        path,
                        format!("{name} holds {:?}, not {want:?}", env.header.kind),
                    ));
                }
            }
        }
        Kind::Envelope => {
            encompute_protocol::Envelope::decode(bytes()).map_err(bad)?;
        }
        Kind::ExecutionReceipt => {
            let r = SignedExecutionReceipt::from_bytes(bytes())?;
            // Integrity only: the signature by the key it names. Whether that
            // key is trusted is for `encompute verify`.
            let own = EvaluatorIdentity::from_public_key_hex(&r.evaluator_public_key)?;
            r.verify_signature(&own)?;
        }
        Kind::TrustBundle => {
            encompute_runtime::trust::graph::TrustGraph::from_bytes(bytes())?;
        }
        Kind::Checkpoint => {
            encompute_runtime::training::seal::peek::<encompute_runtime::training::CheckpointHeader>(
                bytes(),
            )?;
        }
        Kind::SealedAsset => {
            encompute_runtime::training::seal::peek::<encompute_runtime::training::AssetHeader>(
                bytes(),
            )?;
        }
        Kind::AdapterRecord => {
            let r: encompute_runtime::training::SignedAdapterRecord =
                serde_json::from_slice(bytes()).map_err(|e| corrupt(kind, path, e))?;
            r.verify(None)?;
        }
        Kind::Ledger => {
            encompute_runtime::dp::ledger::read(path)?;
        }
        Kind::LedgerDir => {
            for name in f.tree.keys() {
                encompute_runtime::dp::ledger::read(&path.join(name))?;
            }
        }
        Kind::Plan => {
            encompute_runtime::planner::model::ConfidentialExecutionPlan::from_bytes(bytes())?;
        }
        Kind::AggregationReceipt => {
            encompute_runtime::secagg::AggregationReceipt::from_bytes(bytes())?;
        }
        Kind::AttestationRecord => {
            encompute_runtime::attestation::AttestationRecord::from_bytes(bytes())?;
        }
        Kind::AttestationPolicy => {
            serde_json::from_slice::<encompute_runtime::attestation::AttestationPolicy>(bytes())
                .map_err(|e| corrupt(kind, path, e))?;
        }
        Kind::PartyState => {
            PartyStateFile::read(path)?;
        }
    }
    Ok(Status::Current)
}

/// Current format: current if `Model::load` accepts it. Otherwise, if only
/// derived metadata written by another Encompute version differs, the
/// same regeneration as older formats applies.
fn model_current(f: &Found) -> Result<Status> {
    let err = match Model::load(&f.path) {
        Ok(_) => return Ok(Status::Current),
        Err(e) => e,
    };
    let manifest: Value = serde_json::from_slice(&f.tree["manifest.json"])
        .map_err(|e| corrupt(Kind::Model, &f.path, format!("manifest.json: {e}")))?;
    let built_by = manifest["compiler"]["version"].as_str().unwrap_or_default();
    if built_by.is_empty() || built_by == env!("CARGO_PKG_VERSION") {
        // Written by this very version: a mismatch is damage, not age.
        return Err(err);
    }
    let tree = rederive_artifact(f.tree.clone())?;
    Ok(Status::Upgrade {
        note: Some(format!("metadata written by encompute {built_by}")),
        tree,
    })
}

/// Regenerates an artifact's derived files (`security.json`,
/// `verification.json`, `policy.json`, `manifest.json`) from its
/// `program.eir`, after checking every file against the old manifest's
/// hashes, and only if the program, plan and parameters (and so every key,
/// ciphertext and ID bound to them) are byte-identical to what this build
/// compiles and the backend is the same. Anything else needs a recompile.
fn rederive_artifact(tree: Tree) -> Result<Tree> {
    let bad = |m: String| Error::new(Code::Artifact, m);
    let manifest: Value = serde_json::from_slice(
        tree.get("manifest.json")
            .ok_or_else(|| bad("manifest.json is missing".into()))?,
    )
    .map_err(|e| bad(format!("manifest.json: {e}")))?;
    let hashes = manifest["files"]
        .as_object()
        .ok_or_else(|| bad("manifest.json lists no file hashes".into()))?;
    for (name, want) in hashes {
        let body = tree
            .get(name)
            .ok_or_else(|| bad(format!("{name} is missing")))?;
        if want.as_str() != Some(sha256(body).as_str()) {
            return Err(bad(format!(
                "{name} does not match its manifest hash; the artifact was modified"
            )));
        }
    }
    let program = tree
        .get("program.eir")
        .filter(|_| hashes.contains_key("program.eir"))
        .ok_or_else(|| bad("program.eir is missing".into()))?;
    let text = std::str::from_utf8(program).map_err(|_| bad("program.eir is not UTF-8".into()))?;
    let model = Model::from_eir(text)?;
    let fresh = model.artifact_contents();
    let recompile = |what: &str| {
        bad(format!(
            "{what} differs from what this Encompute ({}) compiles, so keys, ciphertexts and \
             receipts made for it would not match; migration only regenerates metadata: \
             recompile the artifact and regenerate keys",
            env!("CARGO_PKG_VERSION")
        ))
    };
    for name in ["program.eir", "plan.json", "parameters.json"] {
        if !hashes.contains_key(name) || tree[name] != fresh[name].as_bytes() {
            return Err(recompile(name));
        }
    }
    let fresh_manifest: Value = serde_json::from_str(&fresh["manifest.json"]).expect("JSON");
    for ptr in [
        "/crypto/scheme",
        "/crypto/backend",
        "/crypto/backend_version",
    ] {
        if manifest.pointer(ptr) != fresh_manifest.pointer(ptr) {
            return Err(recompile(&format!("manifest {ptr}")));
        }
    }
    Ok(fresh
        .into_iter()
        .map(|(n, b)| (n.to_owned(), b.into_bytes()))
        .collect())
}

/// Party state 0 (a bare sequence number) to 1 (JSON), as `aggregate
/// join` writes it.
fn party_state_json(tree: Tree) -> Result<Tree> {
    let text = std::str::from_utf8(&tree[""]).unwrap_or_default();
    let n: u64 = text.trim().parse().map_err(|_| {
        Error::new(
            Code::AggregationBinding,
            "party state is not a sequence number",
        )
    })?;
    let st = PartyStateFile {
        sequence: Some(n),
        checkpoints: BTreeMap::new(),
    };
    Ok(Tree::from([(
        String::new(),
        serde_json::to_vec_pretty(&st).expect("JSON"),
    )]))
}

/// Writes `tree` as `out/<name of input>`: never over an existing path,
/// never inside the input, through a temporary name and a rename.
fn write_out(f: &Found, tree: &Tree, out: &Path) -> Result<PathBuf> {
    let name = f
        .path
        .file_name()
        .ok_or_else(|| Error::new(Code::Artifact, "the input has no file name"))?;
    // Resolve --out through its nearest existing ancestor before creating
    // anything, so an --out inside the input is refused untouched.
    let mut existing = if out.is_absolute() {
        out.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|e| unreadable(out, e))?
            .join(out)
    };
    let mut rest = Vec::new();
    while existing.symlink_metadata().is_err() {
        match (existing.file_name(), existing.parent()) {
            (Some(n), Some(p)) => {
                rest.push(n.to_owned());
                existing = p.to_owned();
            }
            _ => break,
        }
    }
    let mut planned = existing.canonicalize().map_err(|e| unreadable(out, e))?;
    planned.extend(rest.iter().rev());
    let in_abs = f.path.canonicalize().map_err(|e| unreadable(&f.path, e))?;
    if f.dir && planned.starts_with(&in_abs) {
        return Err(Error::new(
            Code::Artifact,
            "--out is inside the input; migrate never modifies its input",
        ));
    }
    std::fs::create_dir_all(out).map_err(|e| unreadable(out, e))?;
    let out_abs = out.canonicalize().map_err(|e| unreadable(out, e))?;
    let dest = out_abs.join(name);
    if dest.symlink_metadata().is_ok() {
        return Err(Error::new(
            Code::Artifact,
            format!("{} exists; migrate never overwrites", dest.display()),
        ));
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let tmp = out_abs.join(format!(
        ".{}.migrate-{}-{nonce}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let io = |p: &Path, e: std::io::Error| unreadable(p, e);
    let write = |p: &Path, b: &[u8]| -> Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(p)
            .map_err(|e| io(p, e))?;
        file.write_all(b).map_err(|e| io(p, e))?;
        file.sync_all().map_err(|e| io(p, e))
    };
    let result = if f.dir {
        (|| {
            std::fs::create_dir(&tmp).map_err(|e| io(&tmp, e))?;
            for (n, b) in tree {
                write(&tmp.join(n), b)?;
            }
            if dest.symlink_metadata().is_ok() {
                return Err(Error::new(
                    Code::Artifact,
                    format!("{} exists; migrate never overwrites", dest.display()),
                ));
            }
            std::fs::rename(&tmp, &dest).map_err(|e| io(&dest, e))
        })()
    } else {
        (|| {
            write(&tmp, &tree[""])?;
            // A hard link never replaces an existing file.
            std::fs::hard_link(&tmp, &dest).map_err(|e| io(&dest, e))?;
            std::fs::remove_file(&tmp).map_err(|e| io(&tmp, e))
        })()
    };
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_file(&tmp);
    }
    result.map(|()| dest)
}

pub fn migrate(a: &MigrateArgs) -> Result<ExitCode> {
    let f = detect(&a.path)?;
    let status = assess(&f)?;
    let cur = f.kind.current();
    let word = f.kind.version_word();
    let (state, detail, written, code) = match &status {
        Status::Current => (
            "current",
            "current; nothing to do".to_owned(),
            None,
            ExitCode::SUCCESS,
        ),
        Status::KeptAsIs(why) => (
            "kept_as_is",
            format!("older version kept as-is, not rewritten: {why}"),
            None,
            ExitCode::from(KEPT_AS_IS),
        ),
        Status::Upgrade { note, tree } => {
            let note = note.as_ref().map_or(String::new(), |n| format!("({n}) "));
            match &a.out {
                Some(out) if !a.check => {
                    let dest = write_out(&f, tree, out)?;
                    (
                        "upgraded",
                        format!("{note}upgraded to {word} {cur}; wrote {}", dest.display()),
                        Some(dest),
                        ExitCode::SUCCESS,
                    )
                }
                _ => (
                    "upgrade_available",
                    format!(
                        "{note}upgrade to {word} {cur} available; nothing written \
                         (write it with `encompute migrate {} --out DIR`)",
                        f.path.display()
                    ),
                    None,
                    ExitCode::from(1),
                ),
            }
        }
    };
    if a.json {
        let v = serde_json::json!({
            "path": f.path.display().to_string(),
            "kind": f.kind.id(),
            "version": f.version,
            "current_version": cur,
            "status": state,
            "detail": detail,
            "written": written.map(|p| p.display().to_string()),
        });
        println!("{}", serde_json::to_string_pretty(&v).expect("JSON"));
    } else {
        println!(
            "{}: {}, {word} {}: {detail}",
            f.path.display(),
            f.kind.label(),
            f.version
        );
    }
    Ok(code)
}
