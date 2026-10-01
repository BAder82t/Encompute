//! `encompute governance`: an organization's consent in a governed project
//! is a signature by its governance key, made outside the control plane.
//! The control plane stores only the public key.
//!
//! This release signs with a local Ed25519 key file (32-byte seed, mode
//! 0600). Signing inside the organization's KMS or HSM (the key never
//! leaving it) is planned; until then keep the key file offline, on the
//! signer's machine only.
//!
//! `witness` and `check-equivocation` are a member organization's check on
//! the control plane itself: the control plane signs a checkpoint of a
//! project's governance log, each member countersigns it after checking it
//! extends the last one that member witnessed, and two signed checkpoints
//! that cannot both be true are evidence anyone can verify.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};
use serde_json::{json, Value};

use encompute_ir::{Code, Error, Result};
use encompute_runtime::trust::authz::{
    governance_key_id, AuthorizationV2, PurposeAcceptance, RevocationV2,
};
use encompute_runtime::trust::govlog::{
    check_extension, check_revocation_heads, members_at, revocation_root, revocation_state,
    CheckpointWitness, Equivocation, EquivocationProof, Extension, GovEvent, HeadEquivocation,
    HeadVerdict, InclusionProof, Partition, RevocationHead, RollbackProof, SignedCheckpointWitness,
    SignedConsistencyProof, SignedProjectCheckpoint, SignedRevocationHead, Verdict, GOVLOG_VERSION,
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
    /// An organization's revocation head for a governed project: the
    /// root over every revocation it made there. The draft is fetched from
    /// the control plane (or read from a file written by an earlier fetch),
    /// its root RECOMPUTED here from the leaves it lists, and only then
    /// signed. The signed head is the body of
    /// `POST /v1/projects/{id}/revocation-heads`.
    RevocationHead,
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
        /// `--kind revocation-head`: the governed project.
        #[arg(long)]
        project: Option<String>,
        /// `--kind revocation-head`: the organization whose head it is.
        #[arg(long)]
        organization: Option<String>,
        /// `--kind revocation-head`: the control plane's URL (default: the
        /// saved login or ENCOMPUTE_CONTROL_URL).
        #[arg(long)]
        url: Option<String>,
        /// `--kind revocation-head`: the owner's own record of what it
        /// revoked in the project (a JSON array of leaves, or one per
        /// line, such as `authorization.revoked:<id>`). The draft is
        /// refused when it omits one: the control plane's list is not
        /// taken on its word alone.
        #[arg(long)]
        expect_leaves: Option<PathBuf>,
        /// `--kind revocation-head`: recompute the draft's root and print
        /// the head that would be signed; sign nothing.
        #[arg(long)]
        verify_draft: bool,
        /// The document to sign. For `--kind revocation-head` optional: a
        /// draft saved from `GET /v1/projects/{id}/revocation-heads/{org}/draft`
        /// (otherwise `--project` and `--organization` fetch it).
        document: Option<PathBuf>,
    },
    /// Countersign a governed project's latest checkpoint as a member
    /// organization. Fetches the control plane's latest signed checkpoint
    /// and its consistency proof from the one witnessed last (kept in
    /// `--state`), checks the control plane's signatures and that the new
    /// checkpoint extends the old one, signs a witness with the
    /// organization's governance key file and submits it (the caller is a
    /// security admin of the organization). Run it from a cron job. Exits 0
    /// when witnessed (or already witnessed), 1 on an inconsistency (an
    /// equivocation proof is written next to the state file as
    /// `STATE.equivocation.json`; nothing is signed), 2 on an error.
    Witness {
        /// The governed project.
        #[arg(long)]
        project: String,
        /// The member organization the witness is for.
        #[arg(long)]
        organization: String,
        /// The organization's governance key file.
        #[arg(long)]
        key: PathBuf,
        /// Where the last witnessed checkpoint is kept (created on first
        /// use; it also pins the control plane's public key).
        #[arg(long)]
        state: PathBuf,
        /// The control plane's public key (hex), instead of trusting the
        /// first answer of `/v1/info` (the state file pins it afterwards).
        #[arg(long)]
        control_key: Option<String>,
        /// The control plane's URL (default: the saved login or
        /// ENCOMPUTE_CONTROL_URL).
        #[arg(long)]
        url: Option<String>,
    },
    /// Check a governed project's log as a reader, trusting nothing the
    /// control plane computed: fetch every page of
    /// `GET /v1/projects/{id}/audit`, verify the checkpoint's signature
    /// and EVERY event's inclusion proof against it, recompute the members
    /// at the checkpoint's size from the verified membership events, verify
    /// each witness signature against the organizations' pinned governance
    /// keys (`--pins`: a JSON object, organization to public key) and
    /// print whether the checkpoint is `witnessed` as computed here. Exits
    /// 1 when the control plane's members or label differ, or a revocation
    /// head contradicts the log; 2 when a proof or signature fails; 3
    /// without `--pins` (`--allow-unpinned` accepts that) or when any
    /// organization's revocation head is UNCHECKED (`--allow-unchecked`
    /// accepts that). With `--pins` each organization's revocation head is
    /// judged through the verified events: the log names its latest head,
    /// which must be supplied, verify under the pinned key and be dated at
    /// or after `--as-of` (default now); a head owed, withheld or under an
    /// older key is UNCHECKED, never covered. Membership events are listed for
    /// the reader to check (an invitation shown as removed, a join that is
    /// missing).
    VerifyAudit {
        #[arg(long)]
        project: String,
        /// The control plane's public key (hex, from a trusted source).
        #[arg(long)]
        control_key: String,
        #[arg(long)]
        pins: Option<PathBuf>,
        /// Accept a run without `--pins`: witness signatures and revocation
        /// heads are then not verified. Without this flag such a run exits
        /// 3 (nothing contradicted, nothing proved), so a script cannot
        /// mistake it for a pass.
        #[arg(long)]
        allow_unpinned: bool,
        /// Accept UNCHECKED revocation heads (none, owed, withheld, older
        /// than `--as-of`, under an older key). Without this flag any
        /// UNCHECKED organization exits 3.
        #[arg(long)]
        allow_unchecked: bool,
        /// The time (Unix seconds) the check is for: a head must be dated
        /// at or after it to say anything of revocations up to then.
        /// Default: now.
        #[arg(long)]
        as_of: Option<u64>,
        /// A file of signed revocation heads (one or an array) to check
        /// beside the control plane's, for example an owner's own copy.
        #[arg(long = "heads")]
        extra_heads: Vec<PathBuf>,
        #[arg(long)]
        url: Option<String>,
    },
    /// Check two signed checkpoints (each a checkpoint or the answer of
    /// `GET /v1/projects/{id}/checkpoints/latest`, which may carry the
    /// control plane's consistency proof; or one equivocation proof file
    /// written by `witness`, or a rollback proof) for evidence the control
    /// plane equivocated or rolled back: the same size with different
    /// roots, a larger tree that does not extend a smaller one shown by the
    /// control plane's own signed consistency proof, or a smaller
    /// checkpoint signed after a larger one. Exits 0 when they prove it, 1 when they do not
    /// (consistent), 2 when an input is unreadable, forged, edited or of
    /// different partitions.
    CheckEquivocation {
        /// The control plane's public key (hex), or the state file of
        /// `witness`, which pins it.
        #[arg(long, required_unless_present_any = ["state", "org_key"])]
        control_key: Option<String>,
        #[arg(long)]
        state: Option<PathBuf>,
        /// An organization's public key (hex): the two files are signed
        /// revocation heads (or one file holds `{a, b}`) and the check is
        /// whether that organization signed two roots for one number.
        #[arg(long)]
        org_key: Option<String>,
        a: PathBuf,
        /// Omit when `a` is an equivocation proof file.
        b: Option<PathBuf>,
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

fn read_json(p: &Path) -> Result<Value> {
    serde_json::from_slice(&std::fs::read(p).map_err(|e| io(p, e))?)
        .map_err(|e| err(format!("{}: {e}", p.display())))
}

/// What `witness` keeps between runs.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessState {
    project: String,
    organization: String,
    /// The control plane's public key, pinned.
    control_key: String,
    /// The checkpoint witnessed last.
    last: SignedProjectCheckpoint,
}

fn load_state(p: &Path) -> Result<Option<WitnessState>> {
    if !p.exists() {
        return Ok(None);
    }
    serde_json::from_value(read_json(p)?)
        .map(Some)
        .map_err(|e| err(format!("{}: not a witness state: {e}", p.display())))
}

/// Writes `bytes` to `p` through a uniquely named temporary file created
/// exclusively with mode 0600, then renames it over `p`.
fn write_atomic(p: &Path, bytes: &[u8]) -> Result<()> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut name = p.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.{nanos}.tmp", std::process::id()));
    let tmp = p.with_file_name(name);
    write_private(&tmp, bytes)?;
    std::fs::rename(&tmp, p).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        io(p, e)
    })
}

/// A checkpoint, and the consistency proof beside it if the file has one:
/// a bare signed checkpoint or an answer of `checkpoints/latest`.
fn checkpoint_file(p: &Path) -> Result<(SignedProjectCheckpoint, Option<SignedConsistencyProof>)> {
    let v = read_json(p)?;
    let (cp, proof) = match v.get("checkpoint") {
        Some(c) => (c.clone(), v.get("consistency").cloned()),
        None => (v, None),
    };
    let cp = parse(cp, "signed project checkpoint")?;
    let proof = match proof {
        Some(Value::Null) | None => None,
        Some(x) => Some(parse(x, "signed consistency proof")?),
    };
    Ok((cp, proof))
}

fn witness_cmd(
    project: &str,
    organization: &str,
    key: &Path,
    state: &Path,
    control_key: Option<&str>,
    url: Option<&str>,
) -> Result<ExitCode> {
    let k = key_file(key)?;
    let partition = Partition::Project(project.to_owned()).to_string();
    let saved = load_state(state)?;
    if let Some(s) = &saved {
        if s.project != project || s.organization != organization {
            return Err(err(format!(
                "{} belongs to {} in {}, not {organization} in {project}",
                state.display(),
                s.organization,
                s.project
            )));
        }
        if control_key.is_some_and(|c| c != s.control_key) {
            return Err(err(
                "the control plane's public key differs from the one this state file pinned",
            ));
        }
    }
    let c = crate::control::ControlClient::from_env(url)?;
    let served_key = c.get("/v1/info")?["public_key"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::new(
                Code::Remote,
                "the control plane did not give its public key",
            )
        })?;
    let control_key = match (&saved, control_key) {
        (Some(s), _) => s.control_key.clone(),
        (None, Some(c)) => c.to_owned(),
        (None, None) => {
            eprintln!("pinning the control plane's public key {served_key} (first use)");
            served_key.clone()
        }
    };
    if served_key != control_key {
        return Err(err(
            "the control plane's public key is not the pinned one: refusing to witness",
        ));
    }
    let path = match &saved {
        Some(s) => format!(
            "/v1/projects/{project}/checkpoints/latest?since={}",
            s.last.body.size
        ),
        None => format!("/v1/projects/{project}/checkpoints/latest"),
    };
    let answer = c.get(&path)?;
    if answer["checkpoint"].is_null() {
        eprintln!("the control plane has no checkpoint of {partition} yet: nothing to witness");
        print(&json!({"project": project, "nothing_to_witness": true}));
        return Ok(ExitCode::SUCCESS);
    }
    let latest: SignedProjectCheckpoint = parse(answer["checkpoint"].clone(), "checkpoint")?;
    latest.verify(&control_key)?;
    if latest.body.partition != partition {
        return Err(err(format!(
            "the checkpoint is of {}, not {partition}",
            latest.body.partition
        )));
    }
    if let Some(s) = &saved {
        let proof: Option<SignedConsistencyProof> = match &answer["consistency"] {
            Value::Null => None,
            v => Some(parse(v.clone(), "consistency proof")?),
        };
        match check_extension(&control_key, &s.last, &latest, proof.as_ref())? {
            Extension::Consistent => {}
            Extension::Stale => {
                eprintln!(
                    "STALE: the control plane's latest checkpoint of {partition} (size {}) is smaller than the one witnessed (size {}) and was signed earlier: an old answer, not evidence; nothing was signed",
                    latest.body.size, s.last.body.size
                );
                return Ok(ExitCode::from(1));
            }
            Extension::Rollback(r) => {
                let out = state.with_extension("equivocation.json");
                write_atomic(&out, &serde_json::to_vec_pretty(&*r).expect("serializable"))?;
                eprintln!(
                    "ROLLBACK: the control plane signed a checkpoint of {partition} with {} events after one with {}; nothing was signed. Evidence: {}",
                    latest.body.size,
                    s.last.body.size,
                    out.display()
                );
                return Ok(ExitCode::from(1));
            }
            Extension::Equivocation(e) => {
                let out = state.with_extension("equivocation.json");
                write_atomic(&out, &serde_json::to_vec_pretty(&*e).expect("serializable"))?;
                eprintln!(
                    "INCONSISTENT: the control plane's checkpoint of {partition} at size {} does not extend the one witnessed at size {}; nothing was signed. Evidence: {}",
                    latest.body.size,
                    s.last.body.size,
                    out.display()
                );
                return Ok(ExitCode::from(1));
            }
        }
        if s.last == latest {
            print(&json!({"project": project, "size": latest.body.size,
                          "root": latest.body.root, "already_witnessed": true}));
            return Ok(ExitCode::SUCCESS);
        }
    }
    let witness = CheckpointWitness {
        version: GOVLOG_VERSION,
        organization: organization.to_owned(),
        partition,
        size: latest.body.size,
        root: latest.body.root.clone(),
        at: encompute_runtime::verification::service::now(),
    }
    .sign(&k)?;
    let reply = c.post(
        &format!(
            "/v1/projects/{project}/checkpoints/{}/witnesses",
            latest.body.size
        ),
        serde_json::to_value(&witness).expect("serializable"),
    )?;
    write_atomic(
        state,
        &serde_json::to_vec_pretty(&WitnessState {
            project: project.to_owned(),
            organization: organization.to_owned(),
            control_key,
            last: latest.clone(),
        })
        .expect("serializable"),
    )?;
    print(
        &json!({"project": project, "size": latest.body.size, "root": latest.body.root,
                  "witness_status": reply["witness_status"],
                  "missing_witnesses": reply["missing_witnesses"]}),
    );
    Ok(ExitCode::SUCCESS)
}

/// Whether an organization signed two revocation heads of one number with
/// different roots (exit 0: proven; 1: not).
fn check_head_equivocation(org_key: &str, a: &Path, b: Option<&Path>) -> Result<ExitCode> {
    let proof: HeadEquivocation = match b {
        None => parse(read_json(a)?, "head equivocation proof")?,
        Some(b) => HeadEquivocation {
            a: parse(read_json(a)?, "signed revocation head")?,
            b: parse(read_json(b)?, "signed revocation head")?,
        },
    };
    match proof.verify(org_key) {
        Ok(()) => {
            println!(
                "OWNER EQUIVOCATION: {} signed two roots for revocation head {} of project {}",
                proof.a.body.organization, proof.a.body.seq, proof.a.body.project
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            println!("no owner equivocation proven: {}", e.message);
            Ok(ExitCode::from(1))
        }
    }
}

fn check_equivocation_cmd(
    control_key: Option<&str>,
    state: Option<&Path>,
    a: &Path,
    b: Option<&Path>,
) -> Result<ExitCode> {
    let key = match (control_key, state) {
        (Some(k), _) => k.to_owned(),
        (None, Some(s)) => {
            load_state(s)?
                .ok_or_else(|| err(format!("{}: no such state file", s.display())))?
                .control_key
        }
        (None, None) => return Err(err("name the control plane's public key")),
    };
    let proven = |what: String| {
        println!("{what}");
        Ok(ExitCode::SUCCESS)
    };
    let rollback = |r: &RollbackProof| {
        proven(format!(
            "ROLLBACK: the control plane signed a checkpoint of {} with {} events after one with {}",
            r.latest.body.partition, r.latest.body.size, r.previous.body.size
        ))
    };
    let proof = match b {
        None => {
            let v = read_json(a)?;
            if v.get("previous").is_some() {
                let r: RollbackProof = parse(v, "rollback proof")?;
                r.check(&key)?;
                return rollback(&r);
            }
            parse::<EquivocationProof>(v, "equivocation proof")?
        }
        Some(b) => {
            let (x, px) = checkpoint_file(a)?;
            let (y, py) = checkpoint_file(b)?;
            let consistency = px.or(py);
            if consistency.is_none() && x.body.size != y.body.size {
                // No consistency proof between different sizes: a rollback
                // if the smaller was signed no earlier than the larger.
                let (previous, latest) = if x.body.size > y.body.size {
                    (x.clone(), y.clone())
                } else {
                    (y.clone(), x.clone())
                };
                let r = RollbackProof { previous, latest };
                if r.check(&key).is_ok() {
                    return rollback(&r);
                }
            }
            EquivocationProof {
                a: x,
                b: y,
                consistency,
            }
        }
    };
    match proof.assess(&key)? {
        Verdict::Equivocation(how) => {
            let how = match how {
                Equivocation::SameSizeDifferentRoots => "same_size_different_roots",
                Equivocation::Inconsistent => "inconsistent",
            };
            proven(format!(
                "EQUIVOCATION: the control plane signed two checkpoints of {} that cannot both be true ({how}); sizes {} and {}",
                proof.a.body.partition, proof.a.body.size, proof.b.body.size
            ))
        }
        Verdict::Consistent => {
            println!("no equivocation: the checkpoints agree or the control plane's proof between them verifies");
            Ok(ExitCode::from(1))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_audit_cmd(
    project: &str,
    control_key: &str,
    pins: Option<&Path>,
    allow_unpinned: bool,
    allow_unchecked: bool,
    as_of: Option<u64>,
    extra_heads: &[PathBuf],
    url: Option<&str>,
) -> Result<ExitCode> {
    let pins: Option<std::collections::BTreeMap<String, String>> = match pins {
        Some(p) => Some(parse(
            read_json(p)?,
            "pins file (organization to public key)",
        )?),
        None => None,
    };
    let c = crate::control::ControlClient::from_env(url)?;
    let partition = Partition::Project(project.to_owned()).to_string();
    let bad = |m: String| Error::new(Code::TrustEvidence, m);
    // Every page, against one checkpoint.
    let (mut first, mut events): (Option<Value>, Vec<(GovEvent, String, InclusionProof)>) =
        (None, vec![]);
    let mut after = 0u64;
    loop {
        let page = c.get(&format!(
            "/v1/projects/{project}/audit?after={after}&limit=200"
        ))?;
        if page["checkpoint"].is_null() {
            println!("no checkpoint of {partition} yet: nothing to verify");
            return Ok(if pins.is_none() && !allow_unpinned {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            });
        }
        match &first {
            None => first = Some(page.clone()),
            Some(f) if f["checkpoint"] != page["checkpoint"] => {
                return Err(bad(
                    "the checkpoint changed while the pages were read: run it again".into(),
                ))
            }
            Some(_) => {}
        }
        for e in page["events"].as_array().cloned().unwrap_or_default() {
            events.push((
                parse(e["event"].clone(), "event")?,
                e["leaf_hash"].as_str().unwrap_or("").to_owned(),
                parse(e["inclusion_proof"].clone(), "inclusion proof")?,
            ));
        }
        match page["next"].as_u64() {
            Some(n) if n > after => after = n,
            Some(_) => return Err(bad("the pages do not advance".into())),
            None => break,
        }
    }
    let first = first.expect("one page at least");
    let cp: SignedProjectCheckpoint = parse(first["checkpoint"].clone(), "checkpoint")?;
    cp.verify(control_key)?;
    if cp.body.partition != partition {
        return Err(bad(format!(
            "the checkpoint is of {}, not {partition}",
            cp.body.partition
        )));
    }
    if events.len() as u64 != cp.body.size {
        return Err(bad(format!(
            "the control plane gave {} events of a checkpoint of {}",
            events.len(),
            cp.body.size
        )));
    }
    for (i, (e, leaf, proof)) in events.iter().enumerate() {
        if e.pseq != i as u64 + 1 {
            return Err(bad(format!(
                "event {} is out of order or missing",
                i as u64 + 1
            )));
        }
        if *leaf != encompute_runtime::trust::govlog::hash_hex(&e.leaf_hash()?) {
            return Err(bad(format!(
                "event {}: its leaf hash is not its own",
                e.pseq
            )));
        }
        cp.includes(e, proof)
            .map_err(|x| bad(format!("event {}: {}", e.pseq, x.message)))?;
    }
    let claimed: Vec<String> = serde_json::from_value(first["members"].clone()).unwrap_or_default();
    let all: Vec<GovEvent> = events.iter().map(|(e, _, _)| e.clone()).collect();
    let local = members_at(&all, cp.body.size, &claimed);
    let mut sorted = claimed.clone();
    sorted.sort();
    let members_match = local == sorted;
    // Organizations with no membership event of their own: members on the
    // control plane's word (the owner, or a project older than the events).
    let eventful: std::collections::BTreeSet<&str> = all
        .iter()
        .filter(|e| e.kind.starts_with("membership."))
        .filter_map(|e| e.org.as_deref())
        .collect();
    let on_its_word: Vec<&String> = local
        .iter()
        .filter(|o| !eventful.contains(o.as_str()))
        .collect();
    let membership: Vec<Value> = all
        .iter()
        .filter(|e| e.kind.starts_with("membership."))
        .map(|e| json!({"position": e.pseq, "kind": e.kind, "organization": e.org,
                         "participation": e.refs.get("participation"), "status": e.refs.get("status")}))
        .collect();
    let mut notes: Vec<String> = vec![];
    for e in &all {
        if e.kind == "membership.removed" && e.refs.get("status").is_some_and(|s| s == "invited") {
            notes.push(format!(
                "event {}: {} is shown as an invitation withdrawn (never a member): check that it never was one",
                e.pseq,
                e.org.as_deref().unwrap_or("?")
            ));
        }
    }
    // Witnesses.
    let witnesses: Vec<SignedCheckpointWitness> =
        serde_json::from_value(first["witnesses"].clone()).unwrap_or_default();
    let mut verified: Vec<String> = vec![];
    if let Some(pins) = &pins {
        for w in &witnesses {
            let org = &w.body.organization;
            let ok = pins
                .get(org)
                .is_some_and(|k| *k == w.public_key && w.verify(k).is_ok())
                && w.body.witnesses(&cp.body);
            if ok {
                verified.push(org.clone());
            } else {
                notes.push(format!(
                    "the witness of {org} does not verify under its pinned key (or is not for this checkpoint)"
                ));
            }
        }
        for o in &local {
            if !pins.contains_key(o) {
                notes.push(format!(
                    "no pinned key for member {o}: its witness cannot count"
                ));
            }
        }
    }
    // Revocation heads, judged through the log: the verified events name
    // each organization's latest head, which must be supplied (the control
    // plane's, plus any `--heads` files) and verify under the pinned key.
    let mut heads: Vec<SignedRevocationHead> =
        serde_json::from_value(first["revocation_heads"].clone()).unwrap_or_default();
    for f in extra_heads {
        let v = read_json(f)?;
        match v {
            Value::Array(items) => {
                for i in items {
                    heads.push(parse(i, "signed revocation head")?);
                }
            }
            one => heads.push(parse(one, "signed revocation head")?),
        }
    }
    let as_of = as_of.unwrap_or_else(encompute_runtime::verification::service::now);
    let mut head_mismatch = false;
    let mut unchecked = false;
    let mut revocations: Vec<Value> = vec![];
    let head_orgs: std::collections::BTreeSet<String> = all
        .iter()
        .filter(|e| {
            e.kind == "revocation_head.signed"
                || encompute_runtime::trust::govlog::kind::REVOCATIONS.contains(&e.kind.as_str())
        })
        .filter_map(|e| e.org.clone())
        .chain(heads.iter().map(|h| h.body.organization.clone()))
        .collect();
    for org in &head_orgs {
        let st = revocation_state(&all, org);
        let (status, reason, equivocation) = match pins.as_ref().map(|p| p.get(org)) {
            None => ("UNVERIFIED (no --pins)".to_owned(), String::new(), None),
            Some(None) => {
                notes.push(format!(
                    "no pinned key for {org}: its revocation head cannot be checked"
                ));
                unchecked = true;
                ("UNCHECKED (no pinned key)".to_owned(), String::new(), None)
            }
            Some(Some(k)) => {
                let c = check_revocation_heads(&all, &heads, org, project, as_of, k, None);
                let status = match c.verdict {
                    HeadVerdict::Covered => "COVERED".to_owned(),
                    HeadVerdict::HeadTooOld => {
                        unchecked = true;
                        "UNCHECKED".to_owned()
                    }
                    other => {
                        head_mismatch = true;
                        other.label().to_owned()
                    }
                };
                (status, c.reason, c.equivocation)
            }
        };
        revocations.push(json!({
            "organization": org,
            "revocations": st.leaves.len(),
            "head_seq": st.last_head.as_ref().map(|h| h.0),
            "pending_since": st.pending_since,
            "status": status,
            "reason": reason,
            "equivocation": equivocation,
        }));
    }
    let server_label = first["witness_status"].as_str().unwrap_or("").to_owned();
    let local_label = match &pins {
        Some(_) => {
            if !local.is_empty() && local.iter().all(|o| verified.contains(o)) {
                "witnessed"
            } else {
                "unwitnessed"
            }
        }
        None => "unverified",
    };
    let server_witnessed_by: Vec<String> =
        serde_json::from_value(first["witnessed_by"].clone()).unwrap_or_default();
    let mut mismatch = !members_match || head_mismatch;
    if pins.is_some() {
        mismatch |= local_label != server_label;
        mismatch |= server_witnessed_by.iter().any(|o| !verified.contains(o));
    }
    if !members_match {
        notes.push(format!(
            "the control plane lists members {sorted:?}; the verified events give {local:?}"
        ));
    }
    if pins.is_none() {
        notes.push(
            "witness signatures not verified (nor revocation heads): no --pins; the control plane's label is its own word"
                .into(),
        );
    }
    print(&json!({
        "project": project,
        "checkpoint": {"size": cp.body.size, "root": cp.body.root},
        "events_verified": events.len(),
        "members": local,
        "members_on_the_control_plane_s_word": on_its_word,
        "membership_events": membership,
        "witnesses_verified": pins.is_some(),
        "witnessed_by_verified": verified,
        "witness_status": local_label,
        "witness_status_per_the_control_plane": server_label,
        "revocation_heads": revocations,
        "mismatch": mismatch,
        "unpinned": pins.is_none(),
        "notes": notes,
    }));
    if mismatch {
        return Ok(ExitCode::from(1));
    }
    if unchecked && !allow_unchecked {
        eprintln!(
            "exit 3: a revocation head is UNCHECKED (none, owed, withheld, older than --as-of or under an older key); \
             pass --allow-unchecked to accept this"
        );
        return Ok(ExitCode::from(3));
    }
    if pins.is_none() && !allow_unpinned {
        eprintln!(
            "exit 3: no --pins, so witness signatures and revocation heads were not verified; \
             pass --pins, or --allow-unpinned to accept this"
        );
        return Ok(ExitCode::from(3));
    }
    Ok(ExitCode::SUCCESS)
}

/// Signs an organization's revocation head from the control plane's draft
/// (fetched, or a saved one): the root is recomputed here from the leaves
/// the draft lists and the draft is refused when it is not the control
/// plane's own, so a head is never signed over a root nobody checked.
/// `verify_draft` prints the head that would be signed and signs nothing.
fn sign_revocation_head(
    expect_leaves: Option<&Path>,
    key: &Path,
    project: Option<&str>,
    organization: Option<&str>,
    url: Option<&str>,
    verify_draft: bool,
    document: Option<&Path>,
) -> Result<ExitCode> {
    let draft = match document {
        Some(p) => read_json(p)?,
        None => {
            let (Some(p), Some(o)) = (project, organization) else {
                return Err(err(
                    "--kind revocation-head needs --project and --organization (or a saved draft file)",
                ));
            };
            crate::control::ControlClient::from_env(url)?
                .get(&format!("/v1/projects/{p}/revocation-heads/{o}/draft"))?
        }
    };
    let text = |k: &str| draft[k].as_str().map(str::to_owned);
    let (Some(d_project), Some(d_org), Some(claimed), Some(seq)) = (
        text("project"),
        text("organization"),
        text("root"),
        draft["seq"].as_u64(),
    ) else {
        return Err(err(
            "not a revocation head draft: it needs project, organization, seq, leaves and root",
        ));
    };
    for (flag, got, what) in [
        (project, &d_project, "project"),
        (organization, &d_org, "organization"),
    ] {
        if flag.is_some_and(|f| f != got) {
            return Err(err(format!(
                "the draft is for {what} {got}, not {}",
                flag.unwrap_or("")
            )));
        }
    }
    let leaves: Vec<String> = serde_json::from_value(draft["leaves"].clone())
        .map_err(|e| err(format!("the draft's leaves: {e}")))?;
    let mut sorted = leaves.clone();
    sorted.sort();
    sorted.dedup();
    if sorted != leaves {
        return Err(err(
            "the draft's leaves are not sorted and distinct: refusing to sign",
        ));
    }
    if let Some(f) = expect_leaves {
        let text = std::fs::read_to_string(f).map_err(|e| io(f, e))?;
        let expected: Vec<String> = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_owned)
                .collect(),
        };
        let missing: Vec<&String> = expected.iter().filter(|e| !leaves.contains(e)).collect();
        if !missing.is_empty() {
            return Err(err(format!(
                "the draft omits {} revocation(s) your own records list ({}): refusing to sign",
                missing.len(),
                missing
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }
    let recomputed = encompute_runtime::trust::govlog::hash_hex(&revocation_root(&leaves)?);
    if recomputed != claimed {
        return Err(err(format!(
            "the draft's root {claimed} is not the root of the {} leaves it lists ({recomputed}): refusing to sign",
            leaves.len()
        )));
    }
    let previous_at = draft["previous"]["at"].as_u64().unwrap_or(0);
    let at = encompute_runtime::verification::service::now().max(previous_at);
    let head = RevocationHead {
        version: GOVLOG_VERSION,
        organization: d_org.clone(),
        project: d_project.clone(),
        seq,
        root: recomputed,
        at,
    };
    head.check()?;
    eprintln!(
        "revocation head {seq} of {d_org} in project {d_project}\n  {} revocations, root {}\n  dated {at}",
        leaves.len(),
        head.root
    );
    for l in &leaves {
        eprintln!("    {l}");
    }
    if let Some(since) = draft["pending_since"].as_u64() {
        eprintln!("  a head has been owed since {since}");
    }
    if verify_draft {
        eprintln!("verified: the root is the root of these leaves; nothing signed");
        print(&json!({"would_sign": head, "leaves": leaves}));
        return Ok(ExitCode::SUCCESS);
    }
    let k = key_file(key)?;
    let signed = head.sign(&k)?;
    signed.verify(&hex(&k.verifying_key().to_bytes()))?;
    print(&signed);
    Ok(ExitCode::SUCCESS)
}

pub fn governance(cmd: GovernanceCmd) -> Result<ExitCode> {
    match cmd {
        GovernanceCmd::Witness {
            project,
            organization,
            key,
            state,
            control_key,
            url,
        } => witness_cmd(
            &project,
            &organization,
            &key,
            &state,
            control_key.as_deref(),
            url.as_deref(),
        ),
        GovernanceCmd::VerifyAudit {
            project,
            control_key,
            pins,
            allow_unpinned,
            allow_unchecked,
            as_of,
            extra_heads,
            url,
        } => verify_audit_cmd(
            &project,
            &control_key,
            pins.as_deref(),
            allow_unpinned,
            allow_unchecked,
            as_of,
            &extra_heads,
            url.as_deref(),
        ),
        GovernanceCmd::CheckEquivocation {
            control_key,
            state,
            org_key,
            a,
            b,
        } => {
            if let Some(k) = org_key {
                return check_head_equivocation(&k, &a, b.as_deref());
            }
            check_equivocation_cmd(control_key.as_deref(), state.as_deref(), &a, b.as_deref())
        }
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
            project,
            organization,
            url,
            verify_draft,
            expect_leaves,
            document,
        } => {
            if matches!(kind, SignKind::RevocationHead) {
                return sign_revocation_head(
                    expect_leaves.as_deref(),
                    &key,
                    project.as_deref(),
                    organization.as_deref(),
                    url.as_deref(),
                    verify_draft,
                    document.as_deref(),
                );
            }
            let document = document.ok_or_else(|| err("a document to sign is needed"))?;
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
                SignKind::RevocationHead => unreachable!("handled above"),
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
