//! `encompute governance`: an organization's consent in a governed project
//! is a signature by its governance key, made outside the control plane.
//! The control plane stores only the public key.
//!
//! This release signs with a local Ed25519 key file (32-byte seed, mode
//! 0600). Signing inside the organization's KMS or HSM (the key never
//! leaving it) is planned; until then keep the key file offline, on the
//! signer's machine only.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};
use serde_json::{json, Value};

use encompute_ir::{Code, Error, Result};
use encompute_runtime::trust::authz::{
    governance_key_id, AuthorizationV2, PurposeAcceptance, RevocationV2,
};
use encompute_runtime::verification::governance::ProgramRef;
use encompute_runtime::verification::hex;

#[derive(Clone, Copy, ValueEnum)]
pub enum SignKind {
    /// An owner authorization (v2) with its approvals: the body shown by
    /// `GET /v1/authorizations/{id}` (the whole response or its `body`).
    Authorization,
    /// An organization's acceptance of a purpose.
    PurposeAcceptance,
    /// An owner's revocation of an authorization.
    Revocation,
}

#[derive(Subcommand)]
pub enum GovernanceCmd {
    /// Create a governance key file (32-byte Ed25519 seed, mode 0600; never
    /// overwrites one). Prints the public key and its key ID to register
    /// with `POST /v1/organizations/{org}/governance-keys`.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a document with the organization's governance key file. The
    /// document is checked (never a wildcard program, a known version, a
    /// well-formed window) and summarized on stderr before it is signed;
    /// the signed document goes to stdout.
    Sign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long, value_enum, default_value = "authorization")]
        kind: SignKind,
        /// Print only `{"public_key", "signature"}`, the body of
        /// `POST /v1/authorizations/{id}/signature`.
        #[arg(long)]
        signature_only: bool,
        document: PathBuf,
    },
}

fn err(m: impl Into<String>) -> Error {
    Error::new(Code::TrustAuthorization, m)
}

fn io(p: &Path, e: std::io::Error) -> Error {
    Error::new(Code::Artifact, format!("{}: {e}", p.display()))
}

fn key_file(p: &Path) -> Result<ed25519_dalek::SigningKey> {
    let seed: [u8; 32] = std::fs::read(p)
        .map_err(|e| io(p, e))?
        .try_into()
        .map_err(|_| err("a governance key file is a 32-byte seed"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
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

fn parse<T: serde::de::DeserializeOwned>(v: Value, what: &str) -> Result<T> {
    serde_json::from_value(v).map_err(|e| err(format!("not a {what}: {e}")))
}

fn print(v: &impl serde::Serialize) {
    println!("{}", serde_json::to_string_pretty(v).expect("serializable"));
}

pub fn governance(cmd: GovernanceCmd) -> Result<ExitCode> {
    match cmd {
        GovernanceCmd::Keygen { out } => {
            let mut seed = zeroize::Zeroizing::new([0u8; 32]);
            getrandom::getrandom(&mut *seed).map_err(|e| err(format!("no randomness: {e}")))?;
            write_private(&out, &*seed)?;
            let pk = hex(&ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes());
            print(&json!({"public_key": pk, "key_id": governance_key_id(&pk)}));
            Ok(ExitCode::SUCCESS)
        }
        GovernanceCmd::Sign {
            key,
            kind,
            signature_only,
            document,
        } => {
            let v: Value =
                serde_json::from_slice(&std::fs::read(&document).map_err(|e| io(&document, e))?)
                    .map_err(|e| err(format!("{}: {e}", document.display())))?;
            let k = key_file(&key)?;
            let pk = hex(&k.verifying_key().to_bytes());
            let signed = match kind {
                SignKind::Authorization => {
                    // The whole `GET /v1/authorizations/{id}` response, or
                    // just its body.
                    let body = match v.get("body") {
                        Some(b) if v.get("version").is_none() => b.clone(),
                        _ => v,
                    };
                    let b: AuthorizationV2 = parse(body, "v2 authorization")?;
                    b.check()?;
                    let program = match &b.program {
                        ProgramRef::Program { program_id } => format!("program {program_id}"),
                        ProgramRef::ProgramSet {
                            program_set_id,
                            programs,
                        } => format!("program set {program_set_id} ({} programs)", programs.len()),
                    };
                    eprintln!(
                        "signing authorization {}\n  party {} in project {}\n  purpose {}\n  version {}\n  {program}\n  release {} to {}\n  valid [{}, {})\n  approvals {}",
                        b.display_id(),
                        b.party,
                        b.project,
                        b.purpose_id,
                        b.asset_version_id,
                        b.release_class.as_str(),
                        b.recipients.iter().cloned().collect::<Vec<_>>().join(", "),
                        b.valid_from,
                        b.valid_until,
                        b.approvals.len()
                    );
                    serde_json::to_value(b.sign(&k)?).expect("serializable")
                }
                SignKind::PurposeAcceptance => {
                    let a: PurposeAcceptance = parse(v, "purpose acceptance")?;
                    eprintln!(
                        "signing {}'s acceptance of purpose {} in project {}",
                        a.organization, a.purpose_id, a.project
                    );
                    let s = a.sign(&k)?;
                    s.verify(&pk)?;
                    serde_json::to_value(s).expect("serializable")
                }
                SignKind::Revocation => {
                    let r: RevocationV2 = parse(v, "v2 revocation")?;
                    eprintln!(
                        "signing {}'s revocation of authorization {}",
                        r.party, r.authorization
                    );
                    let s = r.sign(&k)?;
                    s.verify(&pk)?;
                    serde_json::to_value(s).expect("serializable")
                }
            };
            if signature_only {
                print(
                    &json!({"public_key": signed["public_key"], "signature": signed["signature"]}),
                );
            } else {
                print(&signed);
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
