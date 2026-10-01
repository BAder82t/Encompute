//! INV-247: `encompute governance witness` and `check-equivocation`.
//!
//! A member organization countersigns a project's checkpoint only after
//! checking it extends the one it witnessed last; two checkpoints the
//! control plane signed that cannot both be true are evidence anyone can
//! verify. The equivocation tests run against scripted control planes (no
//! database); the last test runs members against a real one (needs
//! PostgreSQL, `ENCOMPUTE_TEST_DATABASE_URL`; skipped without it unless
//! `ENCOMPUTE_REQUIRE_SERVICES=1`).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use encompute_runtime::trust::govlog::{
    hash_hex, rfc6962_leaf, root, CheckpointWitness, ConsistencyProof, EquivocationProof, GovEvent,
    Hash, InclusionProof, ProjectCheckpoint, RollbackProof, SignedProjectCheckpoint,
};
use encompute_verification::ServiceSigner;

const PROJECT: &str = "prj_1";
const PARTITION: &str = "p:prj_1";

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "encompute-cli-witness-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn control_signer() -> ServiceSigner {
    ServiceSigner::from_seed("control-plane", &[42; 32]).unwrap()
}

fn leaf(tag: &str, i: usize) -> Hash {
    rfc6962_leaf(format!("{tag}-{i}").as_bytes())
}

fn leaves(tag: &str, n: usize) -> Vec<Hash> {
    (0..n).map(|i| leaf(tag, i)).collect()
}

/// A checkpoint over `ls` signed by the control plane.
fn checkpoint(ls: &[Hash], at: u64) -> SignedProjectCheckpoint {
    ProjectCheckpoint {
        version: 1,
        partition: PARTITION.into(),
        size: ls.len() as u64,
        root: hash_hex(&root(ls)),
        gseq: ls.len() as u64,
        at,
    }
    .sign(&control_signer())
    .unwrap()
}

/// What a scripted control plane answers.
#[derive(Default)]
struct Script {
    /// The answer of `checkpoints/latest` (a function of `since`).
    latest: Option<Box<dyn Fn(Option<u64>) -> Value + Send>>,
    /// The answer of `audit` (a function of `after` and `limit`).
    audit: Option<Box<dyn Fn(u64, u64) -> Value + Send>>,
    /// `/v1/info`'s public key.
    key: String,
    /// The witnesses it received.
    posts: Vec<Value>,
}

struct Fake {
    url: String,
    script: Arc<Mutex<Script>>,
}

impl Fake {
    fn start() -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let script = Arc::new(Mutex::new(Script {
            key: control_signer().public_key_hex(),
            ..Script::default()
        }));
        let s = script.clone();
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut r = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                if r.read_line(&mut first).is_err() {
                    continue;
                }
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).unwrap_or(0) <= 2 {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; len];
                r.read_exact(&mut body).unwrap();
                let mut parts = first.split_whitespace();
                let (method, target) = (parts.next().unwrap(), parts.next().unwrap());
                let (path, query) = target.split_once('?').unwrap_or((target, ""));
                let mut s = s.lock().unwrap();
                let (status, v) = if path == "/v1/info" {
                    (
                        200,
                        json!({"public_key": s.key, "service": "control-plane"}),
                    )
                } else if method == "GET" && path.ends_with("/audit") {
                    let q = |n: &str| {
                        query
                            .split('&')
                            .find_map(|p| p.strip_prefix(&format!("{n}=")))
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0)
                    };
                    match &s.audit {
                        Some(f) => (200, f(q("after"), q("limit"))),
                        None => (404, json!({"code": "ENC2603", "message": "none"})),
                    }
                } else if method == "GET" && path.ends_with("/checkpoints/latest") {
                    let since = query.strip_prefix("since=").and_then(|v| v.parse().ok());
                    match &s.latest {
                        Some(f) => (200, f(since)),
                        None => (404, json!({"code": "ENC2603", "message": "none"})),
                    }
                } else if method == "POST" && path.contains("/checkpoints/") {
                    s.posts.push(serde_json::from_slice(&body).unwrap());
                    (
                        201,
                        json!({"witness_status": "unwitnessed", "missing_witnesses": ["other"]}),
                    )
                } else {
                    (404, json!({"code": "ENC2603", "message": "no route"}))
                };
                let b = serde_json::to_vec(&v).unwrap();
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    b.len()
                );
                let _ = stream.write_all(&b);
            }
        });
        Self { url, script }
    }

    /// Serves `cp` (and, for a `since`, `proof`).
    fn serve(
        &self,
        cp: SignedProjectCheckpoint,
        proof: impl Fn(u64) -> Option<Value> + Send + 'static,
    ) {
        self.script.lock().unwrap().latest = Some(Box::new(move |since| {
            json!({"checkpoint": cp,
                   "consistency": since.and_then(&proof).unwrap_or(Value::Null),
                   "witness_status": "unwitnessed"})
        }));
    }

    fn posts(&self) -> Vec<Value> {
        self.script.lock().unwrap().posts.clone()
    }
}

struct Member {
    key: PathBuf,
    state: PathBuf,
    dir: PathBuf,
}

impl Member {
    fn new(d: &Path, name: &str) -> Self {
        let key = d.join(format!("{name}.key"));
        let out = Command::new(env!("CARGO_BIN_EXE_encompute"))
            .args(["governance", "keygen", "--out", key.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(out.status.success());
        Self {
            key,
            state: d.join(format!("{name}.state.json")),
            dir: d.to_path_buf(),
        }
    }

    fn witness(&self, url: &str, org: &str, extra: &[&str]) -> (i32, String, String) {
        let mut args = vec![
            "governance",
            "witness",
            "--project",
            PROJECT,
            "--organization",
            org,
            "--key",
            self.key.to_str().unwrap(),
            "--state",
            self.state.to_str().unwrap(),
            "--url",
            url,
        ];
        args.extend_from_slice(extra);
        let out = Command::new(env!("CARGO_BIN_EXE_encompute"))
            .args(&args)
            .env("ENCOMPUTE_TOKEN", "test-token")
            .env_remove("ENCOMPUTE_SERVICE_ID")
            .env_remove("ENCOMPUTE_SERVICE_KEY_FILE")
            .env("HOME", &self.dir)
            .env("XDG_CONFIG_HOME", &self.dir)
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into(),
            String::from_utf8_lossy(&out.stderr).into(),
        )
    }

    fn last(&self) -> SignedProjectCheckpoint {
        let v: Value = serde_json::from_slice(&std::fs::read(&self.state).unwrap()).unwrap();
        serde_json::from_value(v["last"].clone()).unwrap()
    }
}

fn check(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_encompute"))
        .args(["governance", "check-equivocation"])
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

fn write(d: &Path, name: &str, v: &impl serde::Serialize) -> String {
    let p = d.join(name);
    std::fs::write(&p, serde_json::to_vec_pretty(v).unwrap()).unwrap();
    p.to_str().unwrap().to_owned()
}

/// The control plane shows two members different histories of one size:
/// both members witness what they were shown, and the two signed
/// checkpoints they hold, put side by side, prove the equivocation.
#[test]
fn an_equivocating_control_plane_is_detected_by_the_cli() {
    let d = dir("split");
    let (to_tax, to_ben) = (Fake::start(), Fake::start());
    to_tax.serve(checkpoint(&leaves("honest", 3), 100), |_| None);
    to_ben.serve(checkpoint(&leaves("forked", 3), 100), |_| None);
    let (tax, ben) = (Member::new(&d, "tax"), Member::new(&d, "ben"));
    let (c, out, err) = tax.witness(&to_tax.url, "tax-agency", &[]);
    assert_eq!(c, 0, "{out} {err}");
    let (c, out, err) = ben.witness(&to_ben.url, "benefits-agency", &[]);
    assert_eq!(c, 0, "{out} {err}");
    // Each sent one witness, for what it was shown.
    assert_eq!(to_tax.posts().len(), 1);
    assert_eq!(
        to_tax.posts()[0]["body"]["root"],
        hash_hex(&root(&leaves("honest", 3))).as_str()
    );
    assert_eq!(
        to_ben.posts()[0]["body"]["root"],
        hash_hex(&root(&leaves("forked", 3))).as_str()
    );

    // They compare what they hold.
    let (a, b) = (
        write(&d, "a.json", &tax.last()),
        write(&d, "b.json", &ben.last()),
    );
    let key = control_signer().public_key_hex();
    let (c, out) = check(&["--control-key", &key, &a, &b]);
    assert_eq!(c, 0, "{out}");
    assert!(
        out.contains("EQUIVOCATION") && out.contains("same_size_different_roots"),
        "{out}"
    );
    // The pinned key of a state file does the same.
    let (c, out) = check(&["--state", tax.state.to_str().unwrap(), &a, &b]);
    assert_eq!(c, 0, "{out}");
    // The same checkpoint twice proves nothing.
    let (c, out) = check(&["--control-key", &key, &a, &a]);
    assert_eq!(c, 1, "{out}");
    assert!(out.contains("no equivocation"), "{out}");
    // A checkpoint someone else signed is no evidence: an error.
    let stranger = ServiceSigner::from_seed("control-plane", &[7; 32]).unwrap();
    let forged = ProjectCheckpoint {
        version: 1,
        partition: PARTITION.into(),
        size: 3,
        root: hash_hex(&root(&leaves("made-up", 3))),
        gseq: 3,
        at: 100,
    }
    .sign(&stranger)
    .unwrap();
    let f = write(&d, "forged.json", &forged);
    let (c, out) = check(&["--control-key", &key, &a, &f]);
    assert_eq!(c, 2, "{out}");
    // Nothing to check against: an error.
    let (c, _) = check(&[&a, &b]);
    assert_eq!(c, 2);
}

/// A member refuses to sign a checkpoint that does not extend the one it
/// witnessed: a fork at the same size, an inconsistent larger tree, a
/// smaller one. It signs nothing, exits 1 and writes the evidence.
#[test]
fn witness_refuses_what_does_not_extend_and_writes_the_evidence() {
    let d = dir("fork");
    let fake = Fake::start();
    let m = Member::new(&d, "tax");
    let key = control_signer().public_key_hex();
    let honest = leaves("honest", 9);
    // The consistency proof the control plane signs from a size to the
    // first `n` events.
    let proof_from = |n: usize| {
        let honest = honest[..n].to_vec();
        move |first: u64| {
            Some(
                serde_json::to_value(
                    ConsistencyProof::from_leaves(PARTITION, &honest, first)
                        .unwrap()
                        .sign(&control_signer())
                        .unwrap(),
                )
                .unwrap(),
            )
        }
    };

    // First use: pins the control plane's key and witnesses.
    fake.serve(checkpoint(&honest[..3], 100), |_| None);
    let (c, out, err) = m.witness(&fake.url, "tax-agency", &[]);
    assert_eq!(c, 0, "{out} {err}");
    assert!(err.contains("pinning"), "{err}");
    assert_eq!(fake.posts().len(), 1);
    let witness = &fake.posts()[0];
    assert_eq!(witness["body"]["organization"], "tax-agency");
    assert_eq!(witness["body"]["partition"], PARTITION);
    assert_eq!(witness["body"]["size"], 3);

    // Again with nothing new: nothing is signed or sent.
    let (c, out, _) = m.witness(&fake.url, "tax-agency", &[]);
    assert_eq!(c, 0);
    assert!(out.contains("already_witnessed"), "{out}");
    assert_eq!(fake.posts().len(), 1);

    // A larger tree that extends it: witnessed, and the state moves on.
    fake.serve(checkpoint(&honest[..7], 110), proof_from(7));
    let (c, out, err) = m.witness(&fake.url, "tax-agency", &[]);
    assert_eq!(c, 0, "{out} {err}");
    assert_eq!(fake.posts().len(), 2);
    assert_eq!(m.last().body.size, 7);

    // A fork at the same size: refused, evidence written, nothing sent.
    fake.serve(checkpoint(&leaves("forked", 7), 111), |_| None);
    let (c, _, err) = m.witness(&fake.url, "tax-agency", &[]);
    assert_eq!(c, 1, "{err}");
    assert!(err.contains("INCONSISTENT"), "{err}");
    assert_eq!(fake.posts().len(), 2);
    let evidence = d.join("tax.state.equivocation.json");
    let proof: EquivocationProof =
        serde_json::from_slice(&std::fs::read(&evidence).unwrap()).unwrap();
    proof.check(&key).unwrap();
    // Anyone can verify the file alone.
    let (c, out) = check(&["--control-key", &key, evidence.to_str().unwrap()]);
    assert_eq!(c, 0, "{out}");
    // The state still holds what was witnessed.
    assert_eq!(m.last().body.size, 7);
    std::fs::remove_file(&evidence).unwrap();

    // A larger tree whose signed consistency proof fails (the control plane
    // served a tree that does not contain what it signed before).
    let forked_9 = {
        let mut ls = leaves("honest", 9);
        ls[2] = leaf("rewritten", 2);
        ls
    };
    let bad = {
        let forked_9 = forked_9.clone();
        let witnessed_root = hash_hex(&root(&honest[..7]));
        move |first: u64| {
            let mut p = ConsistencyProof::from_leaves(PARTITION, &forked_9, first).unwrap();
            // It claims to extend what was witnessed; the path cannot.
            p.first_root = witnessed_root.clone();
            Some(serde_json::to_value(p.sign(&control_signer()).unwrap()).unwrap())
        }
    };
    fake.serve(checkpoint(&forked_9, 112), bad);
    let (c, _, err) = m.witness(&fake.url, "tax-agency", &[]);
    assert_eq!(c, 1, "{err}");
    let proof: EquivocationProof =
        serde_json::from_slice(&std::fs::read(&evidence).unwrap()).unwrap();
    proof.check(&key).unwrap();
    std::fs::remove_file(&evidence).unwrap();

    // A larger tree without a consistency proof: an error, no signature.
    fake.serve(checkpoint(&honest, 113), |_| None);
    let (c, _, err) = m.witness(&fake.url, "tax-agency", &[]);
    assert_eq!(c, 2, "{err}");
    assert!(!evidence.exists(), "no proof, no evidence");

    // A smaller tree: the control plane lost what it signed.
    fake.serve(checkpoint(&honest[..5], 114), |_| None);
    let (c, _, err) = m.witness(&fake.url, "tax-agency", &[]);
    assert_eq!(c, 1, "{err}");
    assert!(evidence.exists());
    std::fs::remove_file(&evidence).unwrap();
    assert_eq!(fake.posts().len(), 2, "nothing was signed after the fork");

    // Another control plane key than the pinned one: refused.
    fake.serve(checkpoint(&honest, 115), proof_from(9));
    fake.script.lock().unwrap().key = ServiceSigner::from_seed("control-plane", &[7; 32])
        .unwrap()
        .public_key_hex();
    let (c, _, err) = m.witness(&fake.url, "tax-agency", &[]);
    assert_eq!(c, 2, "{err}");
    assert!(err.contains("pinned"), "{err}");
    // A state file belongs to its organization and project.
    fake.script.lock().unwrap().key = key;
    let (c, _, err) = m.witness(&fake.url, "benefits-agency", &[]);
    assert_eq!(c, 2, "{err}");
    assert_eq!(fake.posts().len(), 2);
    // And a checkpoint of another partition is not this project's.
    let other = ProjectCheckpoint {
        version: 1,
        partition: "p:prj_other".into(),
        size: 9,
        root: hash_hex(&root(&honest)),
        gseq: 9,
        at: 116,
    }
    .sign(&control_signer())
    .unwrap();
    fake.serve(other, |_| None);
    let (c, _, _) = m.witness(&fake.url, "tax-agency", &[]);
    assert_eq!(c, 2);
}

/// The key given on the command line must match the control plane's own.
#[test]
fn witness_pins_the_control_key_it_is_given() {
    let d = dir("pin");
    let fake = Fake::start();
    fake.serve(checkpoint(&leaves("honest", 2), 100), |_| None);
    let m = Member::new(&d, "tax");
    let (c, _, err) = m.witness(
        &fake.url,
        "tax-agency",
        &["--control-key", &"ab".repeat(32)],
    );
    assert_eq!(c, 2, "{err}");
    assert!(fake.posts().is_empty());
    let key = control_signer().public_key_hex();
    let (c, _, err) = m.witness(&fake.url, "tax-agency", &["--control-key", &key]);
    assert_eq!(c, 0, "{err}");
}

/// A control plane that signs a smaller checkpoint after a larger one:
/// the member refuses to sign, writes a rollback proof, and anyone holding
/// the control plane's key verifies it. A smaller checkpoint signed
/// earlier is a stale answer: refused, no evidence.
#[test]
fn control_plane_rollback_is_detected_and_provable() {
    let d = dir("rollback");
    let fake = Fake::start();
    let m = Member::new(&d, "tax");
    let key = control_signer().public_key_hex();
    let honest = leaves("honest", 9);
    fake.serve(checkpoint(&honest[..7], 100), |_| None);
    let (c, out, err) = m.witness(&fake.url, "tax-agency", &[]);
    assert_eq!(c, 0, "{out} {err}");

    // Stale: signed earlier than what was witnessed.
    fake.serve(checkpoint(&honest[..5], 50), |_| None);
    let (c, _, err) = m.witness(&fake.url, "tax-agency", &[]);
    assert_eq!(c, 1, "{err}");
    assert!(err.contains("STALE"), "{err}");
    let evidence = d.join("tax.state.equivocation.json");
    assert!(!evidence.exists());

    // Rolled back: signed later, with fewer events.
    fake.serve(checkpoint(&honest[..5], 200), |_| None);
    let (c, _, err) = m.witness(&fake.url, "tax-agency", &[]);
    assert_eq!(c, 1, "{err}");
    assert!(err.contains("ROLLBACK"), "{err}");
    assert_eq!(fake.posts().len(), 1, "nothing was signed");
    let proof: RollbackProof = serde_json::from_slice(&std::fs::read(&evidence).unwrap()).unwrap();
    proof.check(&key).unwrap();
    assert_eq!(proof.previous.body.size, 7);
    assert_eq!(proof.latest.body.size, 5);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&evidence).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    // Anyone verifies the file alone, or the two checkpoints.
    let (c, out) = check(&["--control-key", &key, evidence.to_str().unwrap()]);
    assert_eq!(c, 0, "{out}");
    assert!(out.contains("ROLLBACK"), "{out}");
    let (a, b) = (
        write(&d, "prev.json", &proof.previous),
        write(&d, "late.json", &proof.latest),
    );
    let (c, out) = check(&["--control-key", &key, &a, &b]);
    assert_eq!(c, 0, "{out}");
    assert!(out.contains("ROLLBACK"), "{out}");
}

#[test]
fn forged_rollback_evidence_refused() {
    let d = dir("forged-rollback");
    let key = control_signer().public_key_hex();
    let honest = leaves("honest", 9);
    let big = checkpoint(&honest[..7], 100);
    let small = checkpoint(&honest[..5], 200);
    let good = write(
        &d,
        "good.json",
        &RollbackProof {
            previous: big.clone(),
            latest: small.clone(),
        },
    );
    assert_eq!(check(&["--control-key", &key, &good]).0, 0);
    // Signed by someone else.
    let stranger = ServiceSigner::from_seed("control-plane", &[7; 32]).unwrap();
    let fake_small = small.body.clone().sign(&stranger).unwrap();
    let forged = write(
        &d,
        "forged.json",
        &RollbackProof {
            previous: big.clone(),
            latest: fake_small,
        },
    );
    assert_eq!(check(&["--control-key", &key, &forged]).0, 2);
    // Edited after signing.
    let mut edited = small.clone();
    edited.body.size = 4;
    let e = write(
        &d,
        "edited.json",
        &RollbackProof {
            previous: big.clone(),
            latest: edited,
        },
    );
    assert_eq!(check(&["--control-key", &key, &e]).0, 2);
    // The smaller one signed first: no rollback.
    let early = checkpoint(&honest[..5], 50);
    let o = write(
        &d,
        "order.json",
        &RollbackProof {
            previous: big.clone(),
            latest: early.clone(),
        },
    );
    assert_eq!(check(&["--control-key", &key, &o]).0, 2);
    let (a, b) = (write(&d, "a.json", &big), write(&d, "b.json", &early));
    assert_ne!(check(&["--control-key", &key, &a, &b]).0, 0);
    // The larger signed no later than the smaller, the other way round.
    let swapped = write(
        &d,
        "swapped.json",
        &RollbackProof {
            previous: small,
            latest: big,
        },
    );
    assert_eq!(check(&["--control-key", &key, &swapped]).0, 2);
}

// --- verify-audit ---------------------------------------------------------------------

fn gov_event(pseq: u64, kind: &str, org: &str, refs: &[(&str, &str)]) -> GovEvent {
    GovEvent {
        v: 1,
        partition: PARTITION.into(),
        pseq,
        kind: kind.into(),
        subject: format!("sub_{pseq}"),
        org: Some(org.into()),
        at: 1_800_000_000 + pseq,
        refs: refs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

fn org_key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn org_pk(seed: u8) -> String {
    encompute_runtime::verification::hex(&org_key(seed).verifying_key().to_bytes())
}

/// What a scripted control plane answers `audit` with.
struct Audit {
    events: Vec<GovEvent>,
    cp: SignedProjectCheckpoint,
    leaves: Vec<Hash>,
    witnesses: Vec<Value>,
    members: Vec<String>,
    label: String,
    witnessed_by: Vec<String>,
}

impl Audit {
    fn new(events: Vec<GovEvent>) -> Self {
        let leaves: Vec<Hash> = events.iter().map(|e| e.leaf_hash().unwrap()).collect();
        Self {
            cp: checkpoint(&leaves, 100),
            leaves,
            events,
            witnesses: vec![],
            members: vec![],
            label: "unwitnessed".into(),
            witnessed_by: vec![],
        }
    }

    fn witness(&mut self, org: &str, seed: u8) {
        let w = CheckpointWitness {
            version: 1,
            organization: org.into(),
            partition: PARTITION.into(),
            size: self.cp.body.size,
            root: self.cp.body.root.clone(),
            at: 100,
        }
        .sign(&org_key(seed))
        .unwrap();
        self.witnesses.push(serde_json::to_value(w).unwrap());
    }

    /// The page after `after` (at most two events, whatever `limit` says).
    fn page(&self, after: u64, _limit: u64) -> Value {
        let rest: Vec<&GovEvent> = self
            .events
            .iter()
            .filter(|e| e.pseq > after)
            .take(2)
            .collect();
        let events: Vec<Value> = rest
            .iter()
            .map(|e| {
                json!({"event": e, "leaf_hash": hash_hex(&e.leaf_hash().unwrap()),
                       "inclusion_proof": InclusionProof::from_leaves(
                           PARTITION, &self.leaves, e.leaf_index()).unwrap()})
            })
            .collect();
        let last = rest.last().map_or(after, |e| e.pseq);
        json!({"project": PROJECT, "checkpoint": self.cp, "witnesses": self.witnesses,
               "witness_status": self.label, "members": self.members,
               "witnessed_by": self.witnessed_by, "missing_witnesses": [],
               "events": events,
               "next": if last < self.cp.body.size { json!(last) } else { Value::Null }})
    }
}

fn verify_audit(fake: &Fake, extra: &[&str]) -> (i32, String, String) {
    let key = control_signer().public_key_hex();
    let mut args = vec![
        "governance",
        "verify-audit",
        "--project",
        PROJECT,
        "--control-key",
        &key,
        "--url",
        &fake.url,
    ];
    args.extend_from_slice(extra);
    let out = Command::new(env!("CARGO_BIN_EXE_encompute"))
        .args(&args)
        .env("ENCOMPUTE_TOKEN", "test-token")
        .env_remove("ENCOMPUTE_SERVICE_ID")
        .env_remove("ENCOMPUTE_SERVICE_KEY_FILE")
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into(),
        String::from_utf8_lossy(&out.stderr).into(),
    )
}

fn serve_audit(fake: &Fake, a: Audit) {
    fake.script.lock().unwrap().audit = Some(Box::new(move |after, limit| a.page(after, limit)));
}

fn world() -> Audit {
    // tax owns the project (no join event); benefits joined at 1.
    let mut a = Audit::new(vec![
        gov_event(
            1,
            "membership.added",
            "benefits-agency",
            &[("participation", "member")],
        ),
        gov_event(2, "role.removed", "tax-agency", &[]),
        gov_event(3, "role.removed", "tax-agency", &[]),
        gov_event(4, "role.removed", "benefits-agency", &[]),
        gov_event(5, "role.removed", "tax-agency", &[]),
    ]);
    a.members = vec!["benefits-agency".into(), "tax-agency".into()];
    a
}

/// The reader verifies every proof and recomputes the label itself: a
/// control plane that says `witnessed` without every member's signature,
/// hides a member, edits an event or signs a witness with the wrong key is
/// caught; without pins the output says the witnesses are not verified.
#[test]
fn verify_audit_recomputes_the_label_and_catches_a_mislabelling_control_plane() {
    let d = dir("verify-audit");
    let fake = Fake::start();
    let pins = write(
        &d,
        "pins.json",
        &json!({"tax-agency": org_pk(1), "benefits-agency": org_pk(2)}),
    );

    // Honest and fully witnessed (over several pages).
    let mut a = world();
    a.witness("tax-agency", 1);
    a.witness("benefits-agency", 2);
    a.label = "witnessed".into();
    a.witnessed_by = a.members.clone();
    serve_audit(&fake, a);
    let (c, out, err) = verify_audit(&fake, &["--pins", &pins]);
    assert_eq!(c, 0, "{out} {err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["events_verified"], 5, "{v}");
    assert_eq!(v["witness_status"], "witnessed", "{v}");
    assert_eq!(v["witnesses_verified"], true, "{v}");
    assert_eq!(
        v["members_on_the_control_plane_s_word"],
        json!(["tax-agency"]),
        "{v}"
    );
    assert_eq!(v["membership_events"].as_array().unwrap().len(), 1, "{v}");

    // Without pins: proofs verify, the witnesses do not, and it says so.
    let (c, out, _) = verify_audit(&fake, &[]);
    assert_eq!(c, 0, "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["witnesses_verified"], false, "{v}");
    assert_eq!(v["witness_status"], "unverified", "{v}");
    assert!(out.contains("witness signatures not verified"), "{out}");

    // Mislabelled: benefits never signed, the control plane says it did.
    let mut a = world();
    a.witness("tax-agency", 1);
    a.label = "witnessed".into();
    a.witnessed_by = a.members.clone();
    serve_audit(&fake, a);
    let (c, out, _) = verify_audit(&fake, &["--pins", &pins]);
    assert_eq!(c, 1, "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["witness_status"], "unwitnessed", "{v}");
    assert_eq!(v["mismatch"], true, "{v}");

    // A witness signed by a key that is not the organization's pinned one.
    let mut a = world();
    a.witness("tax-agency", 1);
    a.witness("benefits-agency", 9);
    a.label = "witnessed".into();
    a.witnessed_by = a.members.clone();
    serve_audit(&fake, a);
    let (c, out, _) = verify_audit(&fake, &["--pins", &pins]);
    assert_eq!(c, 1, "{out}");
    assert!(
        out.contains("does not verify under its pinned key"),
        "{out}"
    );

    // A member the control plane leaves out of its list: the join event
    // says otherwise.
    let mut a = world();
    a.members = vec!["tax-agency".into()];
    a.witness("tax-agency", 1);
    a.label = "witnessed".into();
    a.witnessed_by = a.members.clone();
    serve_audit(&fake, a);
    let (c, out, _) = verify_audit(&fake, &["--pins", &pins]);
    assert_eq!(c, 1, "{out}");
    assert!(out.contains("verified events give"), "{out}");

    // An event edited after the checkpoint was signed: its proof fails.
    let mut a = world();
    a.events[2].subject = "rewritten".into();
    serve_audit(&fake, a);
    let (c, _, err) = verify_audit(&fake, &["--pins", &pins]);
    assert_eq!(c, 2, "{err}");

    // An invitation shown as withdrawn is listed for the reader.
    let mut a = Audit::new(vec![
        gov_event(
            1,
            "membership.added",
            "benefits-agency",
            &[("participation", "member")],
        ),
        gov_event(
            2,
            "membership.removed",
            "guest-agency",
            &[("participation", "member"), ("status", "invited")],
        ),
    ]);
    a.members = vec!["benefits-agency".into(), "tax-agency".into()];
    serve_audit(&fake, a);
    let (c, out, _) = verify_audit(&fake, &[]);
    assert_eq!(c, 0, "{out}");
    assert!(
        out.contains("guest-agency") && out.contains("never a member"),
        "{out}"
    );

    // Not a checkpoint of the control plane's key.
    let key = "ab".repeat(32);
    let out = Command::new(env!("CARGO_BIN_EXE_encompute"))
        .args([
            "governance",
            "verify-audit",
            "--project",
            PROJECT,
            "--control-key",
            &key,
            "--url",
            &fake.url,
        ])
        .env("ENCOMPUTE_TOKEN", "t")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

// --- members against a real control plane -----------------------------------------

mod real {
    use super::*;
    use encompute_control::anchor::DirAnchor;
    use encompute_control::authn::{dev_token, Authenticator, DEV_ISSUER};
    use encompute_control::config::Env;
    use encompute_control::db::Db;
    use encompute_control::govlog::{self, Draft};
    use encompute_control::Control;
    use encompute_runtime::trust::govlog::{kind, Partition};

    const SECRET: &str = "cli-test-development-secret";

    struct Plane {
        url: String,
        control: Arc<Control>,
        agent: ureq::Agent,
        dir: PathBuf,
    }

    fn start() -> Option<Plane> {
        let admin = match std::env::var("ENCOMPUTE_TEST_DATABASE_URL") {
            Ok(u) => u,
            Err(_) if std::env::var("ENCOMPUTE_REQUIRE_SERVICES").is_ok() => {
                panic!("ENCOMPUTE_REQUIRE_SERVICES is set but ENCOMPUTE_TEST_DATABASE_URL is not")
            }
            Err(_) => {
                eprintln!("SKIPPED: set ENCOMPUTE_TEST_DATABASE_URL");
                return None;
            }
        };
        let name = format!(
            "enc_cli_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros()
                % 1_000_000
        );
        postgres::Client::connect(&admin, postgres::NoTls)
            .unwrap()
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .unwrap();
        let (base, _) = admin.rsplit_once('/').unwrap();
        let db = format!("{base}/{name}");
        let d = dir("real");
        let control = Control::with_parts(
            Env::Development,
            "control-plane",
            {
                let x = Db::connect(&db).unwrap();
                x.migrate().unwrap();
                x
            },
            Authenticator::new(
                Env::Development,
                "control-plane",
                vec![],
                Some(zeroize::Zeroizing::new(SECRET.into())),
            ),
            control_signer(),
            Box::new(DirAnchor::new(d.join("anchor")).unwrap()),
            None,
            5,
        )
        .unwrap();
        control
            .bootstrap(DEV_ISSUER, "platform-admin", None)
            .unwrap();
        let server = encompute_verification::http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr());
        let control = Arc::new(control);
        let c = control.clone();
        std::thread::spawn(move || encompute_control::api::serve_on(c, server));
        Some(Plane {
            url,
            control,
            agent: ureq::AgentBuilder::new().build(),
            dir: d,
        })
    }

    impl Plane {
        fn call(&self, who: &str, method: &str, path: &str, body: Value) -> Value {
            let r = self
                .agent
                .request(method, &format!("{}{path}", self.url))
                .set(
                    "Authorization",
                    &format!("Bearer {}", dev_token(SECRET, who, 3600).unwrap()),
                );
            let r = if body.is_null() {
                r.call()
            } else {
                r.send_json(body)
            };
            r.unwrap_or_else(|e| panic!("{method} {path}: {e}"))
                .into_json()
                .unwrap()
        }

        fn witness(&self, who: &str, m: &Member, org: &str) -> (i32, String) {
            let out = Command::new(env!("CARGO_BIN_EXE_encompute"))
                .args([
                    "governance",
                    "witness",
                    "--project",
                    &self.project(),
                    "--organization",
                    org,
                    "--key",
                    m.key.to_str().unwrap(),
                    "--state",
                    m.state.to_str().unwrap(),
                ])
                .env("ENCOMPUTE_CONTROL_URL", &self.url)
                .env("ENCOMPUTE_TOKEN", dev_token(SECRET, who, 3600).unwrap())
                .env_remove("ENCOMPUTE_SERVICE_ID")
                .env_remove("ENCOMPUTE_SERVICE_KEY_FILE")
                .env("HOME", &self.dir)
                .env("XDG_CONFIG_HOME", &self.dir)
                .output()
                .unwrap();
            (
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stdout).into_owned()
                    + &String::from_utf8_lossy(&out.stderr),
            )
        }

        fn project(&self) -> String {
            std::fs::read_to_string(self.dir.join("project")).unwrap()
        }
    }

    /// Each member organization witnesses with its own key file and a
    /// security admin's credentials; the control plane labels the
    /// checkpoint `witnessed` once both have, and a later checkpoint is
    /// witnessed after the consistency check.
    #[test]
    fn members_witness_with_the_cli_against_a_real_control_plane() {
        let Some(p) = start() else { return };
        for (org, admin) in [("tax-agency", "t-admin"), ("benefits-agency", "b-admin")] {
            p.call(
                "platform-admin",
                "POST",
                "/v1/organizations",
                json!({"id": org, "display_name": org,
                       "admin": {"issuer": DEV_ISSUER, "subject": admin}}),
            );
        }
        for (org, admin, sec1, sec2) in [
            ("tax-agency", "t-admin", "t-sec1", "t-sec2"),
            ("benefits-agency", "b-admin", "b-sec1", "b-sec2"),
        ] {
            for sec in [sec1, sec2] {
                p.call(
                    admin,
                    "POST",
                    &format!("/v1/organizations/{org}/users"),
                    json!({"issuer": DEV_ISSUER, "subject": sec, "roles": ["security_admin"]}),
                );
            }
        }
        let proj = p.call(
            "t-admin",
            "POST",
            "/v1/projects",
            json!({"organization": "tax-agency", "name": "eligibility", "governance": "governed",
                   "organizations": ["benefits-agency"]}),
        )["id"]
            .as_str()
            .unwrap()
            .to_owned();
        std::fs::write(p.dir.join("project"), &proj).unwrap();
        p.call(
            "b-admin",
            "POST",
            &format!("/v1/projects/{proj}/members"),
            json!({"organization": "benefits-agency"}),
        );
        // Governance keys: made by the CLI, registered through the API.
        let tax = Member::new(&p.dir, "tax");
        let ben = Member::new(&p.dir, "ben");
        for (m, org, admin, approver) in [
            (&tax, "tax-agency", "t-admin", "t-sec1"),
            (&ben, "benefits-agency", "b-admin", "b-sec1"),
        ] {
            let pubkey = {
                use ed25519_dalek::SigningKey;
                let seed: [u8; 32] = std::fs::read(&m.key).unwrap().try_into().unwrap();
                encompute_runtime::verification::hex(
                    &SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
                )
            };
            let id = p.call(
                admin,
                "POST",
                &format!("/v1/organizations/{org}/governance-keys"),
                json!({"public_key": pubkey, "kms_key_ref": "vault:transit/governance"}),
            )["id"]
                .as_str()
                .unwrap()
                .to_owned();
            p.call(
                approver,
                "POST",
                &format!("/v1/organizations/{org}/governance-keys/{id}/approve"),
                Value::Null,
            );
        }
        p.control.checkpoint_log().unwrap();

        let (c, out) = p.witness("t-sec1", &tax, "tax-agency");
        assert_eq!(c, 0, "{out}");
        assert!(out.contains("\"unwitnessed\""), "{out}");
        let (c, out) = p.witness("b-sec1", &ben, "benefits-agency");
        assert_eq!(c, 0, "{out}");
        assert!(out.contains("\"witnessed\""), "{out}");
        // Nothing new: nothing sent.
        let (c, out) = p.witness("t-sec1", &tax, "tax-agency");
        assert_eq!(c, 0, "{out}");
        assert!(out.contains("already_witnessed"), "{out}");

        // The log grows; tax witnesses the extension (checked against its
        // own last witness through the signed consistency proof).
        let before = tax.last().body.size;
        p.control
            .db
            .tx(|t| {
                for i in 0..5 {
                    govlog::append(
                        t,
                        Draft::new(
                            Partition::Project(proj.clone()),
                            kind::ROLE_REMOVED,
                            &format!("rol_cli_{i}"),
                        ),
                    )?;
                }
                Ok(())
            })
            .unwrap();
        p.control.checkpoint_log().unwrap();
        let (c, out) = p.witness("t-sec1", &tax, "tax-agency");
        assert_eq!(c, 0, "{out}");
        assert_eq!(tax.last().body.size, before + 5);
        let latest = p.call(
            "b-admin",
            "GET",
            &format!("/v1/projects/{proj}/checkpoints/latest"),
            Value::Null,
        );
        assert_eq!(latest["witness_status"], "unwitnessed", "{latest}");
        assert_eq!(latest["witnessed_by"], json!(["tax-agency"]), "{latest}");
        let (c, _) = p.witness("b-sec1", &ben, "benefits-agency");
        assert_eq!(c, 0);
        let latest = p.call(
            "b-admin",
            "GET",
            &format!("/v1/projects/{proj}/checkpoints/latest"),
            Value::Null,
        );
        assert_eq!(latest["witness_status"], "witnessed", "{latest}");

        // The control plane's checkpoints compare equal between members.
        let (a, b) = (
            write(&p.dir, "a.json", &tax.last()),
            write(&p.dir, "b.json", &ben.last()),
        );
        let (c, out) = check(&["--state", tax.state.to_str().unwrap(), &a, &b]);
        assert_eq!(c, 1, "{out}");
    }
}
