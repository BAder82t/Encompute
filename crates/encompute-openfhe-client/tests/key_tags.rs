//! Review finding EV-2 (ENC-SF-2026-035): OpenFHE keeps relinearization and rotation keys in
//! process-wide maps keyed by the secret key's tag, and the tag is sent in
//! the clear in every ciphertext. The evaluator shim used to take the tag
//! from the uploaded framing and skip loading when the tag was already
//! present, and OpenFHE's own loader inserted every deserialized key before
//! the parameter check. So a co-tenant could relabel its own keys with a
//! victim's tag, upload them first (even as a refused upload), and the
//! victim's jobs then relinearized under the attacker's keys: a wrong result
//! under a valid receipt.
//!
//! The victim must be refused, or get a correct result; never a wrong one.
//!
//! In a single process the client's own key generation fills OpenFHE's maps
//! first and hides the bug, so each scenario runs in a separate evaluator
//! process that did not generate any key: this test binary re-executed with
//! `ENCOMPUTE_TEST_KEY_TAG_EVALUATOR` set.

use std::path::{Path, PathBuf};
use std::process::Command;

use encompute_backend::{ExactClient, ExactEvaluator};
use encompute_ir::{Code, Elem};
use encompute_openfhe::BgvEvaluator;
use encompute_openfhe_client::BgvClient;

const CHILD: &str = "ENCOMPUTE_TEST_KEY_TAG_EVALUATOR";
const DEPTH: u32 = 1;
const A: i128 = 123;
const B: i128 = 45;

/// Tag of framed evaluation keys: u32 length, then the tag.
fn tag_of(keys: &[u8]) -> Vec<u8> {
    let n = u32::from_le_bytes(keys[..4].try_into().unwrap()) as usize;
    keys[4..4 + n].to_vec()
}

fn replace_all(bytes: &[u8], from: &[u8], to: &[u8]) -> (Vec<u8>, usize) {
    assert_eq!(from.len(), to.len());
    let (mut out, mut i, mut n) = (Vec::with_capacity(bytes.len()), 0, 0);
    while i < bytes.len() {
        if bytes[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
            n += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    (out, n)
}

/// What the evaluator process reports for the victim's job.
#[derive(Debug, PartialEq)]
enum Outcome {
    Refused(String),
    Result(Vec<u8>),
}

fn evaluator_process(dir: &Path, scenario: &str) -> Outcome {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "evaluator_process_entry",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, format!("{}|{scenario}", dir.display()))
        .status()
        .unwrap();
    assert!(status.success(), "evaluator process for {scenario} failed");
    let out = std::fs::read(dir.join(format!("{scenario}.out"))).unwrap();
    match out.strip_prefix(b"refused:") {
        Some(msg) => Outcome::Refused(String::from_utf8_lossy(msg).into()),
        None => Outcome::Result(out),
    }
}

/// Runs in the evaluator process: loads the attacker's upload (if any),
/// then the victim's keys, then the victim's job `a * b`.
#[test]
fn evaluator_process_entry() {
    let Ok(arg) = std::env::var(CHILD) else {
        return; // only meaningful in a child process
    };
    let (dir, scenario) = arg.split_once('|').unwrap();
    let dir = PathBuf::from(dir);
    let read = |f: &str| std::fs::read(dir.join(f)).unwrap();
    // The attacker's evaluator stays alive while the victim uploads, as a
    // loaded key would on a shared evaluator.
    let mut attacker = BgvEvaluator::new(DEPTH).unwrap();
    let mut other_params = BgvEvaluator::new(DEPTH + 2).unwrap();
    match scenario {
        "baseline" => {}
        // Attacker's keys relabelled with the victim's tag, accepted first.
        "poisoned" => attacker.load_keys(&read("poisoned.keys")).unwrap(),
        // The same upload, refused (other parameters): used to plant the
        // keys anyway.
        "poisoned_refused" => {
            let e = other_params.load_keys(&read("poisoned.keys")).unwrap_err();
            assert_eq!(e.code, Code::WrongParameters, "{e}");
        }
        // Framing names the attacker's own tag; the keys inside carry the
        // victim's.
        "mislabelled" => {
            let e = attacker.load_keys(&read("mislabelled.keys")).unwrap_err();
            assert_eq!(e.code, Code::WrongKey, "{e}");
        }
        other => panic!("unknown scenario {other}"),
    }
    let mut ev = BgvEvaluator::new(DEPTH).unwrap();
    let out = match ev.load_keys(&read("victim.keys")) {
        Err(e) => format!("refused:{:?} {}", e.code, e.message).into_bytes(),
        Ok(()) => {
            // Registering the same keys again (a replay) is accepted.
            BgvEvaluator::new(DEPTH)
                .unwrap()
                .load_keys(&read("victim.keys"))
                .unwrap();
            let a = ev.load(Elem::U16, &read("a.ct")).unwrap();
            let b = ev.load(Elem::U16, &read("b.ct")).unwrap();
            ev.store(&ev.mul(&a, &b).unwrap()).unwrap()
        }
    };
    std::fs::write(dir.join(format!("{scenario}.out")), out).unwrap();
}

#[test]
fn another_clients_keys_under_the_victims_tag_are_never_used() {
    if std::env::var(CHILD).is_ok() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("encompute-key-tags-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let write = |f: &str, b: &[u8]| std::fs::write(dir.join(f), b).unwrap();

    let victim = BgvClient::generate(DEPTH).unwrap();
    let attacker = BgvClient::generate(DEPTH).unwrap();
    let vkeys = victim.evaluation_keys().unwrap();
    let akeys = attacker.evaluation_keys().unwrap();
    let (vt, at) = (tag_of(&vkeys), tag_of(&akeys));
    assert_ne!(vt, at);
    write("victim.keys", &vkeys);
    write("a.ct", &victim.encrypt(Elem::U16, A).unwrap());
    write("b.ct", &victim.encrypt(Elem::U16, B).unwrap());
    // The victim's tag is public: it is in every victim ciphertext.
    let (poisoned, n) = replace_all(&akeys, &at, &vt);
    assert!(n > 1, "tag in the framing and in the keys");
    write("poisoned.keys", &poisoned);
    let framing = 4 + at.len();
    let (inner, _) = replace_all(&akeys[framing..], &at, &vt);
    write(
        "mislabelled.keys",
        &[&akeys[..framing], &inner[..]].concat(),
    );

    let decrypt = |out: &[u8]| victim.decrypt(Elem::U16, out);
    match evaluator_process(&dir, "baseline") {
        Outcome::Result(out) => assert_eq!(decrypt(&out).unwrap(), A * B),
        other => panic!("baseline: {other:?}"),
    }
    // The attacker's relabelled keys were accepted first. They used to
    // make the victim's upload refused (a denial of service: the tag
    // squatted) and, before that, the product came out wrong (63556 for
    // 5535). The evaluator keeps each upload under its own tag, made of
    // the key tag and the SHA-256 of the key material, so the attacker's
    // keys are not in the victim's way: the victim's upload is accepted
    // and the result is correct.
    for scenario in ["poisoned", "poisoned_refused", "mislabelled"] {
        match evaluator_process(&dir, scenario) {
            Outcome::Result(out) => assert_eq!(decrypt(&out).unwrap(), A * B, "{scenario}"),
            other => panic!("{scenario}: {other:?}"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
