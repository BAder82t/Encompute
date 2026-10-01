//! INV-243 at the command line: `encompute governance export | verify |
//! report | countersign`. A bundle is exported from a scripted control
//! plane, checked by the exporter before anything is written, and verified
//! offline against the verifier's own pins, with one table of exit codes
//! (0 satisfied or accepted, 1 not satisfied, 2 malformed or refused, 3
//! unchecked or unpinned).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use encompute_trust::bundle::OrganizationPin;
use encompute_trust::fixture::*;
use encompute_trust::{GovernanceBundle, Pin, Pins, Provenance};

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "encompute-cli-bundle-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A scripted control plane serving one answer for the bundle route.
struct Fake {
    url: String,
    answer: Arc<Mutex<Value>>,
    queries: Arc<Mutex<Vec<String>>>,
}

impl Fake {
    fn start() -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let answer = Arc::new(Mutex::new(Value::Null));
        let queries = Arc::new(Mutex::new(vec![]));
        let (a, q) = (answer.clone(), queries.clone());
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
                let target = first.split_whitespace().nth(1).unwrap().to_owned();
                q.lock().unwrap().push(target.clone());
                let (status, v) = if target.contains("/governance-bundle") {
                    (200, a.lock().unwrap().clone())
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
        Self {
            url,
            answer,
            queries,
        }
    }

    fn serve(&self, b: &GovernanceBundle) {
        *self.answer.lock().unwrap() = serde_json::to_value(b).unwrap();
    }
}

fn shared(fx: &Fixture) -> GovernanceBundle {
    GovernanceBundle::build(
        "shared",
        T0 + 200,
        "encompute-control",
        fx.graph.clone(),
        fx.shared(),
        fx.audit.clone(),
        Provenance::default(),
    )
    .unwrap()
}

fn pins(fx: &Fixture) -> Pins {
    let from = "the agency's official key page".to_owned();
    let org = |k: &ed25519_dalek::SigningKey| OrganizationPin {
        identity_key: pk(k),
        obtained: from.clone(),
    };
    Pins {
        organizations: [
            (TAX.to_owned(), org(&fx.tax)),
            (BEN.to_owned(), org(&fx.ben)),
        ]
        .into(),
        control_plane: Some(Pin {
            key: fx.control.public_key_hex(),
            obtained: "checked by phone".into(),
        }),
        evaluators: vec![Pin {
            key: fx.evaluator.identity().public_key_hex(),
            obtained: from.clone(),
        }],
        ..Pins::default()
    }
}

fn write_json(d: &Path, name: &str, v: &impl serde::Serialize) -> String {
    let p = d.join(name);
    std::fs::write(&p, serde_json::to_vec_pretty(v).unwrap()).unwrap();
    p.to_str().unwrap().to_owned()
}

fn run(d: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_encompute"))
        .args(["governance"])
        .args(args)
        .env("ENCOMPUTE_TOKEN", "test-token")
        .env_remove("ENCOMPUTE_SERVICE_ID")
        .env_remove("ENCOMPUTE_SERVICE_KEY_FILE")
        .env("HOME", d)
        .env("XDG_CONFIG_HOME", d)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into(),
        String::from_utf8_lossy(&out.stderr).into(),
    )
}

fn key_file(d: &Path, name: &str, seed: u8) -> String {
    let p = d.join(name);
    std::fs::write(&p, [seed; 32]).unwrap();
    p.to_str().unwrap().to_owned()
}

/// The signed documents the owners disclosed.
fn disclosures(d: &Path, fx: &Fixture) -> String {
    write_json(d, "disclosed.json", &fx.documents())
}

#[test]
fn export_then_offline_verify() {
    let d = dir("e2e");
    let fx = Fixture::build();
    let fake = Fake::start();
    fake.serve(&shared(&fx));
    let p = write_json(&d, "pins.json", &pins(&fx));
    let out = d.join("job.encgov.json");
    let o = out.to_str().unwrap();
    // The exporter checks what it fetched against the pins before writing:
    // everything this release can evidence is checked, and the one thing it
    // cannot (who holds a result's key) leaves the bundle not fully
    // evidenced, which the exporter refuses unless that is accepted.
    let (code, _, e) = run(
        &d,
        &["export", JOB, "--url", &fake.url, "--pins", &p, "--out", o],
    );
    assert_eq!(code, 3, "{e}");
    assert!(
        !out.exists(),
        "nothing is written for a bundle that cannot be verified"
    );
    let (code, so, e) = run(
        &d,
        &[
            "export",
            JOB,
            "--url",
            &fake.url,
            "--pins",
            &p,
            "--out",
            o,
            "--allow-unchecked",
        ],
    );
    assert_eq!(code, 0, "{so}{e}");
    assert!(out.exists());
    assert!(fake
        .queries
        .lock()
        .unwrap()
        .iter()
        .any(|q| q.contains("view=shared")));
    // Offline, from the file alone, against the verifier's own pins.
    let disc = disclosures(&d, &fx);
    let (code, so, _) = run(
        &d,
        &[
            "verify",
            o,
            "--pins",
            &p,
            "--disclosure",
            &disc,
            "--allow-unchecked",
        ],
    );
    assert_eq!(code, 0, "{so}");
    let v: Value = serde_json::from_str(&so).unwrap();
    assert_eq!(v["verdict"], "not_fully_evidenced");
    assert_eq!(v["unmet"], json!(["Decryption control is not evidenced"]));
    assert_eq!(v["exit_code"], 0);
    // Without accepting what is not evidenced, the same check exits 3.
    let (code, _, e) = run(&d, &["verify", o, "--pins", &p, "--disclosure", &disc]);
    assert_eq!(code, 3, "{e}");
    // The report, in words, ends with the legal boundary.
    let (code, so, _) = run(
        &d,
        &[
            "report",
            o,
            "--pins",
            &p,
            "--disclosure",
            &disc,
            "--allow-unchecked",
        ],
    );
    assert_eq!(code, 0);
    assert!(so.contains("CROSS-AGENCY TRUST REPORT"), "{so}");
    assert!(
        so.trim_end()
            .lines()
            .last()
            .unwrap()
            .contains("not legal advice"),
        "{so}"
    );
    // An organization's export asks for its view.
    let (code, _, e) = run(
        &d,
        &[
            "export",
            JOB,
            "--view",
            "org",
            "--organization",
            TAX,
            "--url",
            &fake.url,
            "--pins",
            &p,
            "--allow-unchecked",
            "--out",
            d.join("org.encgov.json").to_str().unwrap(),
        ],
    );
    // The scripted server answers with the shared bundle: an organization's
    // view must say so, and the verifier does not mind (the view rules are
    // the bundle's own).
    assert_eq!(code, 0, "{e}");
    assert!(fake
        .queries
        .lock()
        .unwrap()
        .iter()
        .any(|q| q.contains("view=org") && q.contains("organization=tax-agency")));
    // A file that exists is never overwritten.
    let (code, _, _) = run(
        &d,
        &[
            "export",
            JOB,
            "--url",
            &fake.url,
            "--pins",
            &p,
            "--out",
            o,
            "--allow-unchecked",
        ],
    );
    assert_eq!(code, 2);
}

#[test]
fn exit_codes_follow_one_table() {
    let d = dir("exit");
    let fx = Fixture::build();
    let b = shared(&fx);
    let path = d.join("b.encgov.json");
    std::fs::write(&path, b.to_bytes().unwrap()).unwrap();
    let f = path.to_str().unwrap();
    let p = write_json(&d, "pins.json", &pins(&fx));
    let disc = disclosures(&d, &fx);
    // 3: no pins (nothing signed was checked), unless accepted; and
    // accepting that does not accept rows that stay unchecked.
    assert_eq!(run(&d, &["verify", f]).0, 3);
    assert_eq!(run(&d, &["verify", f, "--allow-unpinned"]).0, 3);
    assert_eq!(run(&d, &["verify", f, "--allow-unchecked"]).0, 3);
    assert_eq!(
        run(&d, &["verify", f, "--allow-unpinned", "--allow-unchecked"]).0,
        0
    );
    // 3: pinned, but the shared view's cards cannot be checked.
    assert_eq!(run(&d, &["verify", f, "--pins", &p]).0, 3);
    // 0 only with the disclosures and the accepted gap.
    assert_eq!(
        run(
            &d,
            &[
                "verify",
                f,
                "--pins",
                &p,
                "--disclosure",
                &disc,
                "--allow-unchecked"
            ]
        )
        .0,
        0
    );
    // 1: a pinned key contradicts the evidence; no flag accepts that.
    let mut wrong = pins(&fx);
    wrong.organizations.get_mut(TAX).unwrap().identity_key = pk(&key(99));
    let w = write_json(&d, "wrong.json", &wrong);
    for extra in [
        &["--allow-unchecked"][..],
        &["--allow-unpinned", "--allow-unchecked"],
    ] {
        let mut a = vec!["verify", f, "--pins", &w];
        a.extend_from_slice(extra);
        assert_eq!(run(&d, &a).0, 1, "{extra:?}");
    }
    // 2: an edit, an unknown field, a forged signature, junk, a bad pins file.
    let text = std::fs::read_to_string(&path).unwrap();
    let edited = d.join("edited.encgov.json");
    std::fs::write(&edited, text.replacen("act-12", "act-13", 1)).unwrap();
    assert_eq!(
        run(
            &d,
            &[
                "verify",
                edited.to_str().unwrap(),
                "--pins",
                &p,
                "--allow-unchecked"
            ]
        )
        .0,
        2
    );
    let junk = d.join("junk.encgov.json");
    std::fs::write(&junk, b"{}").unwrap();
    assert_eq!(
        run(
            &d,
            &[
                "verify",
                junk.to_str().unwrap(),
                "--allow-unpinned",
                "--allow-unchecked"
            ]
        )
        .0,
        2
    );
    assert_eq!(
        run(&d, &["verify", d.join("missing").to_str().unwrap()]).0,
        2
    );
    let badpins = d.join("badpins.json");
    std::fs::write(&badpins, b"{\"organizations\": 3}").unwrap();
    assert_eq!(
        run(&d, &["verify", f, "--pins", badpins.to_str().unwrap()]).0,
        2
    );
    // The documented table is the one printed.
    let (_, so, _) = run(&d, &["verify", f, "--allow-unpinned", "--allow-unchecked"]);
    assert!(so.contains("3 unchecked"), "{so}");
}

#[test]
fn export_refuses_what_it_cannot_verify() {
    let d = dir("refuse");
    let fx = Fixture::build();
    let fake = Fake::start();
    let p = write_json(&d, "pins.json", &pins(&fx));
    let out = d.join("x.encgov.json");
    let o = out.to_str().unwrap();
    let go = |extra: &[&str]| {
        let mut a = vec!["export", JOB, "--url", &fake.url, "--out", o];
        a.extend_from_slice(extra);
        run(&d, &a)
    };
    // Unpinned: only digests and shape could be checked.
    fake.serve(&shared(&fx));
    assert_eq!(go(&[]).0, 3);
    assert!(!out.exists());
    // Pins that contradict the evidence.
    let mut wrong = pins(&fx);
    wrong.control_plane.as_mut().unwrap().key = pk(&key(99));
    let w = write_json(&d, "wrong.json", &wrong);
    assert_eq!(go(&["--pins", &w, "--allow-unchecked"]).0, 1);
    assert!(!out.exists());
    // An answer that is not a bundle, or a leaking one.
    *fake.answer.lock().unwrap() = json!({"nothing": true});
    assert_eq!(go(&["--pins", &p, "--allow-unchecked"]).0, 2);
    let mut leaky = serde_json::to_value(shared(&fx)).unwrap();
    leaky["governance"]["authorizations"][0] =
        json!({"form": "signed", "document": fx.documents()[0]});
    *fake.answer.lock().unwrap() = leaky;
    assert_eq!(
        go(&["--pins", &p, "--allow-unchecked", "--allow-unpinned"]).0,
        2
    );
    assert!(!out.exists());
}

/// No value of the sources reaches an export: the bundle is made of
/// identifiers, digests and commitments, and the exporter refuses a string
/// that is neither.
#[test]
fn no_source_value_appears_in_any_export() {
    let d = dir("canary");
    let fx = Fixture::build();
    let fake = Fake::start();
    let p = write_json(&d, "pins.json", &pins(&fx));
    // A canary source value, as a record the control plane might hold.
    let canary = "CANARY-SSN-078-05-1120-and-more-text-that-makes-it-a-record".repeat(6);
    // A bundle built from the evidence never contains it...
    let b = shared(&fx);
    fake.serve(&b);
    let out = d.join("c.encgov.json");
    let (code, so, e) = run(
        &d,
        &[
            "export",
            JOB,
            "--url",
            &fake.url,
            "--pins",
            &p,
            "--allow-unchecked",
            "--out",
            out.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{so}{e}");
    let bytes = std::fs::read_to_string(&out).unwrap();
    assert!(!bytes.contains("CANARY"));
    for private in [
        "person-0",
        "person-1",
        "idp.example",
        "key_ref",
        "storage_uri",
    ] {
        assert!(!bytes.contains(private), "the export contains {private}");
    }
    // ...and one that does (a record where an identifier belongs) is
    // refused by the exporter and by the verifier.
    let mut v = serde_json::to_value(&b).unwrap();
    v["governance"]["job_id"] = json!(canary);
    *fake.answer.lock().unwrap() = v;
    let out2 = d.join("c2.encgov.json");
    let (code, _, e) = run(
        &d,
        &[
            "export",
            JOB,
            "--url",
            &fake.url,
            "--pins",
            &p,
            "--allow-unchecked",
            "--out",
            out2.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 2, "{e}");
    assert!(e.contains("ENC2727") || e.contains("ENC2729"), "{e}");
    assert!(!out2.exists());
}

#[test]
fn countersign_adds_attribution_and_nothing_else() {
    let d = dir("countersign");
    let fx = Fixture::build();
    let b = shared(&fx);
    let path = d.join("b.encgov.json");
    std::fs::write(&path, b.to_bytes().unwrap()).unwrap();
    let f = path.to_str().unwrap();
    let p = write_json(&d, "pins.json", &pins(&fx));
    let disc = disclosures(&d, &fx);
    let k = key_file(&d, "tax.key", 1);
    // It signs only what verifies as far as this machine can tell.
    let (code, _, _) = run(&d, &["countersign", f, "--key", &k, "--organization", TAX]);
    assert_eq!(code, 3);
    let (code, so, e) = run(
        &d,
        &[
            "countersign",
            f,
            "--key",
            &k,
            "--organization",
            TAX,
            "--pins",
            &p,
            "--disclosure",
            &disc,
            "--allow-unchecked",
        ],
    );
    assert_eq!(code, 0, "{so}{e}");
    let (code, so, _) = run(
        &d,
        &[
            "verify",
            f,
            "--pins",
            &p,
            "--disclosure",
            &disc,
            "--allow-unchecked",
        ],
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&so).unwrap();
    assert_eq!(v["signatures"][0]["organization"], TAX);
    assert_eq!(v["signatures"][0]["status"], "verified");
    assert_eq!(v["bundle_id"], b.id().unwrap());
    // A second organization countersigns the same BundleId.
    let k2 = key_file(&d, "ben.key", 2);
    let (code, _, _) = run(
        &d,
        &[
            "countersign",
            f,
            "--key",
            &k2,
            "--organization",
            BEN,
            "--pins",
            &p,
            "--disclosure",
            &disc,
            "--allow-unchecked",
        ],
    );
    assert_eq!(code, 0);
    let (_, so, _) = run(
        &d,
        &[
            "verify",
            f,
            "--pins",
            &p,
            "--disclosure",
            &disc,
            "--allow-unchecked",
        ],
    );
    let v: Value = serde_json::from_str(&so).unwrap();
    assert_eq!(v["signatures"].as_array().unwrap().len(), 2);
    // A key that is not the pinned organization's: the bundle is refused.
    let wrong = key_file(&d, "wrong.key", 99);
    let (code, _, _) = run(
        &d,
        &[
            "countersign",
            f,
            "--key",
            &wrong,
            "--organization",
            TAX,
            "--pins",
            &p,
            "--disclosure",
            &disc,
            "--allow-unchecked",
        ],
    );
    assert_eq!(
        code, 0,
        "countersigning succeeds; the verifier then refuses the forgery"
    );
    let (code, _, _) = run(
        &d,
        &[
            "verify",
            f,
            "--pins",
            &p,
            "--disclosure",
            &disc,
            "--allow-unchecked",
        ],
    );
    assert_eq!(code, 2);
}

fn explain(d: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_encompute"))
        .arg("explain")
        .args(args)
        .env("ENCOMPUTE_TOKEN", "test-token")
        .env_remove("ENCOMPUTE_SERVICE_ID")
        .env_remove("ENCOMPUTE_SERVICE_KEY_FILE")
        .env("HOME", d)
        .env("XDG_CONFIG_HOME", d)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into(),
        String::from_utf8_lossy(&out.stderr).into(),
    )
}

const SECTIONS: [&str; 9] = [
    "WHAT WAS COMPUTED",
    "WHO OWNED THE DATA",
    "WHY",
    "WHO APPROVED",
    "WHERE IT RAN",
    "WHAT WAS RELEASED",
    "WHICH PROTECTIONS APPLIED",
    "WHAT EVIDENCE EXISTS",
    "WHAT THIS DOES NOT TELL YOU",
];

#[test]
fn explain_governance_in_words_from_verified_evidence_only() {
    let d = dir("explain");
    let fx = Fixture::build();
    let b = shared(&fx);
    let path = d.join("b.encgov.json");
    std::fs::write(&path, b.to_bytes().unwrap()).unwrap();
    let f = path.to_str().unwrap();
    let p = write_json(&d, "pins.json", &pins(&fx));
    let disc = disclosures(&d, &fx);
    // Offline, verified against the pins and the owners' disclosures: every
    // section in order, the plain-language rows, the legal boundary last.
    let (code, so, e) = explain(
        &d,
        &[
            "--governance",
            "--bundle",
            f,
            "--pins",
            &p,
            "--disclosure",
            &disc,
            "--allow-unchecked",
        ],
    );
    assert_eq!(code, 0, "{so}{e}");
    let mut at = 0;
    for s in SECTIONS.iter().chain(&["VERDICT"]) {
        let i = so[at..]
            .find(&format!("\n{s}\n"))
            .unwrap_or_else(|| panic!("{s} missing or out of order in\n{so}"));
        at += i + 1;
    }
    for want in [
        "Raw data centralized: NO",
        "Ownership retained: YES",
        "Key custody: INDEPENDENT",
        "Legal reference: act-12 (recorded, not checked)",
        "owned by tax-agency",
        "owned by benefits-agency",
        "Decryption control: not verified",
        "No placement constraint was declared",
        "CROSS-AGENCY REQUIREMENTS NOT FULLY EVIDENCED",
    ] {
        assert!(so.contains(want), "missing {want:?} in\n{so}");
    }
    assert!(
        so.trim_end()
            .lines()
            .last()
            .unwrap()
            .contains("not legal advice"),
        "{so}"
    );
    assert!(!so.contains("person-"), "approvers stay pseudonyms");
    // Without the owners' disclosure a section built on a card is not
    // verified, and says why; without accepting that the exit is 3.
    let (code, so, _) = explain(&d, &["--governance", "--bundle", f, "--pins", &p]);
    assert_eq!(code, 3);
    assert!(so.contains("not verified: Source assets"), "{so}");
    assert!(so.contains("not verified: Approvals"), "{so}");
    // Without pins nothing signed was checked: the explanation says so
    // instead of presenting the claims.
    let (code, so, _) = explain(&d, &["--governance", "--bundle", f]);
    assert_eq!(code, 3);
    assert!(so.contains("not verified"), "{so}");
    assert!(!so.contains("Raw data centralized: NO"), "{so}");
    // Online: the bundle comes from the control plane and is verified
    // here; the server's own opinion is never shown.
    let fake = Fake::start();
    fake.serve(&b);
    let (code, so, e) = explain(
        &d,
        &[
            "--governance",
            JOB,
            "--url",
            &fake.url,
            "--pins",
            &p,
            "--disclosure",
            &disc,
            "--allow-unchecked",
        ],
    );
    assert_eq!(code, 0, "{so}{e}");
    assert!(fake
        .queries
        .lock()
        .unwrap()
        .iter()
        .any(|q| q.contains("view=shared")));
    assert!(so.contains("Raw data centralized: NO"));
    // A bundle that was edited on its way is refused, not explained.
    let mut v = serde_json::to_value(&b).unwrap();
    v["governance"]["grant"]["issued_at"] = json!(T0 + 1);
    *fake.answer.lock().unwrap() = v;
    let (code, so, _) = explain(
        &d,
        &[
            "--governance",
            JOB,
            "--url",
            &fake.url,
            "--pins",
            &p,
            "--allow-unchecked",
        ],
    );
    assert_eq!(code, 2);
    assert!(!so.contains("WHAT WAS COMPUTED"), "{so}");
    // Standard explain is unchanged: a model, and not both.
    let (code, _, e) = explain(&d, &[]);
    assert_eq!(code, 2, "{e}");
    let (code, _, _) = explain(&d, &["model.encompute", "--governance", "--bundle", f]);
    assert_eq!(code, 2);
}
