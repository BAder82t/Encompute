//! `encompute governance export | verify | report | countersign`: the
//! governance evidence bundle (one signed `.encgov.json`, ADR-027).
//!
//! Verification is local and offline, against a pins file the verifier
//! obtained itself (`--pins`): trust in a report is exactly trust in those
//! pins, never in the bundle or in the control plane that served it.
//!
//! One table of exit codes, for `verify`, `report` and the check `export`
//! runs before it writes anything:
//!
//! | code | meaning |
//! |---|---|
//! | 0 | every row satisfied (or accepted: see the flags) |
//! | 1 | not satisfied: a row failed, or a pinned key contradicts the evidence |
//! | 2 | malformed, forged or refused: not a bundle, an edit, a forged signature, a leak |
//! | 3 | something is unchecked, not evidenced, or no pin was given |
//!
//! `--allow-unchecked` accepts unchecked and not-evidenced rows (exit 0);
//! `--allow-unpinned` accepts running without `--pins`. A run that is
//! both unpinned and unchecked needs both. Neither flag ever accepts a
//! failure.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use serde_json::{json, Value};

use encompute_ir::{Code, Error, Result};
use encompute_runtime::trust::authz::SignedAuthorizationV2;
use encompute_runtime::trust::{
    GovernanceBundle, Outcome, Pins, ReportOptions, Verified, VerifyOptions, EXIT_CODES,
};
use encompute_verification::canonical::canonical_json;

fn io(p: &Path, e: std::io::Error) -> Error {
    Error::new(Code::Artifact, format!("{}: {e}", p.display()))
}

fn err(m: impl Into<String>) -> Error {
    Error::new(Code::GovernanceBundleUnverified, m)
}

#[derive(Args)]
pub struct Checks {
    /// The pins file: the organizations' governance keys, the control
    /// plane's key and the evaluators' keys, each with where you obtained
    /// it (never taken from the bundle).
    #[arg(long)]
    pub pins: Option<PathBuf>,
    /// Accept running without `--pins`: nothing signed is then checked, and
    /// without this flag such a run exits 3.
    #[arg(long)]
    pub allow_unpinned: bool,
    /// Accept rows that are unchecked or not evidenced (a key not pinned, a
    /// signature that cannot be checked, evidence this release does not
    /// have). Without it they exit 3. Never accepts a failure.
    #[arg(long)]
    pub allow_unchecked: bool,
    /// The time (Unix seconds) the check is for: a revocation head must be
    /// dated at or after it. Default: the grant's signed time.
    #[arg(long)]
    pub as_of: Option<u64>,
    /// A signed authorization an owner disclosed (JSON file: one document
    /// or an array), to check what a shared view only shows as a card.
    #[arg(long = "disclosure")]
    pub disclosures: Vec<PathBuf>,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// The bundle (`<project>-<job>.encgov.json`).
    pub bundle: PathBuf,
    #[command(flatten)]
    pub checks: Checks,
    /// Print the result as JSON instead of text (`verify` prints JSON;
    /// `report` prints the report).
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct ExportArgs {
    /// The governed job.
    pub job: String,
    /// `shared` (the same bytes for every member and auditor) or `org`
    /// (adds your own organization's signed authorizations).
    #[arg(long, default_value = "shared", value_parser = ["shared", "org"])]
    pub view: String,
    /// `--view org`: your organization.
    #[arg(long)]
    pub organization: Option<String>,
    /// Where to write it (default `<project>-<job>.encgov.json`; an
    /// existing file is never overwritten).
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Sign the exported bundle as `--sign-as` with this governance key
    /// file (attribution: who vouches for this package).
    #[arg(long, requires = "sign_as")]
    pub sign_key: Option<PathBuf>,
    #[arg(long, requires = "sign_key")]
    pub sign_as: Option<String>,
    /// The control plane's URL (default: the saved login or
    /// ENCOMPUTE_CONTROL_URL).
    #[arg(long)]
    pub url: Option<String>,
    #[command(flatten)]
    pub checks: Checks,
}

#[derive(Args)]
pub struct CountersignArgs {
    pub bundle: PathBuf,
    /// Your organization's governance key file.
    #[arg(long)]
    pub key: PathBuf,
    /// Your organization.
    #[arg(long)]
    pub organization: String,
    /// Write here instead of replacing the bundle.
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[command(flatten)]
    pub checks: Checks,
}

fn read_bundle(p: &Path) -> Result<GovernanceBundle> {
    GovernanceBundle::from_bytes(&std::fs::read(p).map_err(|e| io(p, e))?)
}

fn load_pins(p: Option<&Path>) -> Result<Pins> {
    match p {
        None => Ok(Pins::default()),
        Some(p) => Pins::from_bytes(&std::fs::read(p).map_err(|e| io(p, e))?),
    }
}

fn load_disclosures(files: &[PathBuf]) -> Result<Vec<SignedAuthorizationV2>> {
    let mut out = vec![];
    for f in files {
        let v: Value = serde_json::from_slice(&std::fs::read(f).map_err(|e| io(f, e))?)
            .map_err(|e| err(format!("{}: {e}", f.display())))?;
        // A document, an array of documents, or a `GET /v1/authorizations`
        // answer (its `signed` field).
        let items = match v {
            Value::Array(a) => a,
            one => vec![one],
        };
        for i in items {
            let doc = if i.get("body").is_some() && i.get("signature").is_some() {
                i
            } else {
                i.get("signed").cloned().unwrap_or(Value::Null)
            };
            out.push(
                serde_json::from_value(doc).map_err(|e| {
                    err(format!("{}: not a signed authorization: {e}", f.display()))
                })?,
            );
        }
    }
    Ok(out)
}

/// The exit code of a verification, from the one table (see the module).
pub fn exit_code(outcome: Outcome, unpinned: bool, c: &Checks) -> u8 {
    let mut code = match outcome {
        Outcome::Satisfied => 0,
        Outcome::NotSatisfied => 1,
        Outcome::Refused => 2,
        Outcome::Unchecked => {
            if c.allow_unchecked {
                0
            } else {
                3
            }
        }
    };
    if code == 0 && unpinned && !c.allow_unpinned {
        code = 3;
    }
    code
}

fn verify_with(b: &GovernanceBundle, c: &Checks) -> Result<(Verified, u8)> {
    let pins = load_pins(c.pins.as_deref())?;
    let unpinned = c.pins.is_none() || pins.is_empty();
    let v = b.verify(&VerifyOptions {
        pins: &pins,
        base: ReportOptions::default(),
        disclosures: load_disclosures(&c.disclosures)?,
        as_of: c.as_of,
        now: None,
    })?;
    let code = exit_code(v.outcome, unpinned, c);
    Ok((v, code))
}

fn summary(v: &Verified, code: u8) -> Value {
    json!({
        "bundle_id": v.bundle_id,
        "view": v.view,
        "verdict": v.report.verdict,
        "exit_code": code,
        "exit_codes": EXIT_CODES,
        "signatures": v.signatures,
        "base_rows": v.report.base.rows,
        "rows": v.report.rows,
        "revocations": v.report.revocations,
        "authorization_now": v.report.authorization_now,
        "audit": v.report.audit_notes,
        "unmet": v.report.unmet,
        "notes": v.notes,
        "legal_boundary": v.report.legal_boundary,
    })
}

fn explain_exit(code: u8) {
    match code {
        3 => eprintln!(
            "exit 3: something is unchecked, not evidenced or unpinned; pass --allow-unchecked (and, without --pins, --allow-unpinned) to accept that"
        ),
        1 => eprintln!("exit 1: not satisfied: a row failed"),
        _ => {}
    }
}

pub fn verify(a: VerifyArgs) -> Result<ExitCode> {
    let b = read_bundle(&a.bundle)?;
    let (v, code) = verify_with(&b, &a.checks)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&summary(&v, code)).expect("serializable")
    );
    explain_exit(code);
    Ok(ExitCode::from(code))
}

pub fn report(a: VerifyArgs) -> Result<ExitCode> {
    let b = read_bundle(&a.bundle)?;
    let (v, code) = verify_with(&b, &a.checks)?;
    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary(&v, code)).expect("serializable")
        );
    } else {
        println!("bundle {} ({} view)", v.bundle_id, v.view);
        for s in &v.signatures {
            println!("signed by {}: {:?}", s.organization, s.status);
        }
        for n in &v.notes {
            println!("note: {n}");
        }
        println!();
        print!("{}", v.report);
    }
    explain_exit(code);
    Ok(ExitCode::from(code))
}

/// Writes a new file, never over an existing one.
fn write_new(p: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| io(p, e))
}

fn key_file(p: &Path) -> Result<ed25519_dalek::SigningKey> {
    let seed: [u8; 32] = std::fs::read(p)
        .map_err(|e| io(p, e))?
        .try_into()
        .map_err(|_| err("a governance key file is a 32-byte seed"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

pub fn export(a: ExportArgs) -> Result<ExitCode> {
    let c = crate::control::ControlClient::from_env(a.url.as_deref())?;
    let mut q = format!("view={}", a.view);
    if let Some(o) = &a.organization {
        q.push_str(&format!("&organization={o}"));
    }
    let v = c.get(&format!("/v1/jobs/{}/governance-bundle?{q}", a.job))?;
    // The exporter's own check, before anything is written: the control
    // plane's answer must be a bundle (digests, graph root, the view's
    // rules, no plaintext), canonical, and what it can verify against the
    // pins must not fail.
    let mut b: GovernanceBundle = GovernanceBundle::from_bytes(
        &canonical_json(&v).map_err(|e| err(format!("the answer is not a bundle: {e}")))?,
    )?;
    let (verified, code) = verify_with(&b, &a.checks)?;
    if code == 1 {
        eprintln!("refusing to write: the bundle does not verify");
        eprint!("{}", verified.report);
        return Ok(ExitCode::from(1));
    }
    if code == 3 {
        eprintln!(
            "refusing to write a bundle this machine could not verify (only its digests and shape were checked)"
        );
        explain_exit(3);
        return Ok(ExitCode::from(3));
    }
    if let (Some(k), Some(org)) = (&a.sign_key, &a.sign_as) {
        b.sign(org, &key_file(k)?)?;
    }
    let out = a.out.clone().unwrap_or_else(|| {
        PathBuf::from(format!("{}-{}.encgov.json", b.manifest.project_id, a.job))
    });
    write_new(&out, &b.to_bytes()?)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "written": out,
            "bundle_id": verified.bundle_id,
            "view": verified.view,
            "checked_against_pins": a.checks.pins.is_some(),
            "verdict": verified.report.verdict,
            "signed": a.sign_as,
        }))
        .expect("serializable")
    );
    Ok(ExitCode::SUCCESS)
}

pub fn countersign(a: CountersignArgs) -> Result<ExitCode> {
    let mut b = read_bundle(&a.bundle)?;
    // Sign only what verifies at least as far as this machine can tell: a
    // countersignature is a statement that this package is vouched for.
    let (verified, code) = verify_with(&b, &a.checks)?;
    if code == 1 {
        eprintln!("refusing to countersign: the bundle does not verify");
        return Ok(ExitCode::from(1));
    }
    if code == 3 {
        eprintln!("refusing to countersign a bundle this machine could not verify");
        explain_exit(3);
        return Ok(ExitCode::from(3));
    }
    b.sign(&a.organization, &key_file(&a.key)?)?;
    let bytes = b.to_bytes()?;
    match &a.out {
        Some(o) => write_new(o, &bytes)?,
        None => {
            // Replace the bundle atomically.
            let tmp = a.bundle.with_extension("tmp");
            let _ = std::fs::remove_file(&tmp);
            write_new(&tmp, &bytes)?;
            std::fs::rename(&tmp, &a.bundle).map_err(|e| io(&a.bundle, e))?;
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "bundle_id": verified.bundle_id,
            "countersigned_as": a.organization,
            "signatures": b.signatures.iter().map(|s| &s.organization).collect::<Vec<_>>(),
        }))
        .expect("serializable")
    );
    Ok(ExitCode::SUCCESS)
}
