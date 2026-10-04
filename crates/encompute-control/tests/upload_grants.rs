//! Evaluator upload grants, issued by the control plane and spent at an
//! evaluator, over real HTTP on loopback.
//!
//! The job grant is visible to the whole submitting organization and names
//! no key, so an evaluator used to take programs and keys with it, any
//! number of times, from anyone who read it. An upload grant goes to the
//! principal that submitted the job (the control plane authenticates it),
//! names the evaluator, the program and the key ID, carries a random ID and
//! an expiry, and admits exactly one upload.

mod common;

use std::sync::Arc;

use common::*;
use serde_json::{json, Value};

use encompute_evaluator::control::ControlLink;
use encompute_evaluator::server::{Evaluator as Ev, Limits as EvLimits};
use encompute_evaluator::Backends;
use encompute_verification::http::Limits;
use encompute_verification::service::{now, H_JOB_GRANT, H_UPLOAD_GRANT, UPLOAD_GRANT};
use encompute_verification::{JobGrant, ServiceSigner, UploadGrant, UploadKind};

const FORBIDDEN: &str = "ENC2602";
const NOT_FOUND: &str = "ENC2603";
const CONFLICT: &str = "ENC2604";
const SERVICE_AUTH: &str = "ENC2607";
const REPLAYED: &str = "ENC2608";
const BAD_INPUT: &str = "ENC1102";

/// An evaluator service that took the control plane's key and counts as
/// started at `started_at`.
fn evaluator_at(
    control_url: &str,
    control_key: &str,
    id: &str,
    started_at: u64,
) -> (String, String) {
    let mut seed = [0u8; 32];
    for (i, b) in id.bytes().enumerate() {
        seed[i % 32] ^= b;
    }
    seed[31] ^= 0x5a;
    let link = ControlLink::new(
        control_url,
        "control-plane",
        control_key,
        ServiceSigner::from_seed(id, &seed).unwrap(),
    )
    .with_started_at(started_at);
    let ev = Ev::new(Backends::MOCK, EvLimits::default()).with_control(Arc::new(link));
    let pid = ev.add_program(EXACT).unwrap();
    let server = encompute_verification::http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr());
    std::thread::spawn(move || ev.serve(server));
    (url, pid)
}

fn upload(ev: &str, program: &str, header: Option<(&str, &str)>) -> (u16, Value) {
    let mut r = ureq::post(&format!("{ev}/v1/programs"));
    if let Some((name, value)) = header {
        r = r.set(name, value);
    }
    match r.send_bytes(program.as_bytes()) {
        Ok(r) => (r.status(), r.into_json::<Value>().unwrap_or(Value::Null)),
        Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap_or(Value::Null)),
        Err(e) => panic!("{e}"),
    }
}

fn asked(w: &World, who: &As, job: &str, body: Value) -> (u16, Value) {
    w.t.call(
        who,
        "POST",
        &format!("/v1/jobs/{job}/upload-grants"),
        Some(body),
    )
}

fn code(v: &(u16, Value)) -> &str {
    v.1["code"].as_str().unwrap_or("")
}

/// What the control plane signs into a grant, who can ask, and when it
/// refuses to.
#[test]
fn only_the_initiator_of_a_queued_job_gets_upload_grants() {
    let Some(w) = world() else { return };
    let plan = w.plan(EXACT);
    let (_, j) = w.job(&plan, &[], "upload-grants-1");
    let job = j["id"].as_str().unwrap().to_owned();
    let view = w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None);
    assert_eq!(view["state"], "queued");
    let job_grant: JobGrant = serde_json::from_value(view["grant"].clone()).unwrap();
    let control_key = w.t.control.signer.public_key_hex();

    // The initiator: a program grant and a keys grant, signed by the control
    // plane, naming the initiator, the job, the evaluator, the program and
    // (for keys) the key.
    let key_id = "ab".repeat(32);
    let (s, program) = asked(&w, &w.b_dev, &job, json!({"kind": "program"}));
    assert_eq!(s, 201, "{program}");
    let (s, keys) = asked(
        &w,
        &w.b_dev,
        &job,
        json!({"kind": "keys", "key_id": key_id}),
    );
    assert_eq!(s, 201, "{keys}");
    let program: UploadGrant = serde_json::from_value(program["grant"].clone()).unwrap();
    let keys: UploadGrant = serde_json::from_value(keys["grant"].clone()).unwrap();
    assert_eq!(program.kind, UploadKind::Program);
    assert_eq!(keys.kind, UploadKind::Keys);
    assert_eq!(program.key_id, "");
    assert_eq!(keys.key_id, key_id);
    assert_ne!(
        program.grant_id, keys.grant_id,
        "every grant has its own ID"
    );
    for g in [&program, &keys] {
        assert_eq!(g.job_id, job);
        assert_eq!(g.organization, "modelco");
        assert_eq!(g.project, w.project);
        assert_eq!(g.client, view["initiated_by"].as_str().unwrap());
        assert_eq!(g.evaluator, job_grant.evaluator);
        assert_eq!(g.program_id, job_grant.program_id);
        assert_eq!(g.issuer_public_key, control_key);
        assert!(
            g.expires_at <= job_grant.expires_at,
            "never outlives the job grant"
        );
        g.verify(
            &control_key,
            &job_grant.evaluator,
            g.kind,
            &job_grant.program_id,
            (g.kind == UploadKind::Keys).then_some(key_id.as_str()),
            now(),
        )
        .unwrap();
    }
    // Asking again is another grant (another nonce), not the same one.
    let (_, again) = asked(&w, &w.b_dev, &job, json!({"kind": "program"}));
    assert_ne!(again["grant"]["grant_id"], json!(program.grant_id));

    // Nobody else, whatever their role: the job grant is the whole
    // organization's to read, so an upload grant is the initiator's alone.
    for (who, what) in [
        (&w.b_admin, "an organization admin"),
        (&w.b_sec, "a security admin"),
        (&w.b_owner, "a model owner"),
    ] {
        let r = asked(&w, who, &job, json!({"kind": "program"}));
        assert_eq!((r.0, code(&r)), (403, FORBIDDEN), "{what}: {}", r.1);
    }
    // Other organizations, an auditor, and the evaluator itself see no such
    // job to ask for.
    for (who, what) in [
        (&w.c_dev, "another organization"),
        (&w.a_dev, "a project member that owns no source"),
        (&w.platform, "the platform admin"),
        (&As::Service(w.evaluator.signer.clone()), "the evaluator"),
    ] {
        let r = asked(&w, who, &job, json!({"kind": "program"}));
        assert!(r.0 == 404 || r.0 == 403, "{what} got {} {}", r.0, r.1);
        assert_ne!(r.0, 201, "{what}");
    }
    // Malformed requests.
    for (body, what) in [
        (json!({"kind": "keys"}), "keys without a key ID"),
        (
            json!({"kind": "keys", "key_id": "ABCD"}),
            "a malformed key ID",
        ),
        (
            json!({"kind": "keys", "key_id": "AB".repeat(32)}),
            "an upper-case key ID",
        ),
        (
            json!({"kind": "program", "key_id": key_id}),
            "a program grant naming keys",
        ),
        (json!({"kind": "weights"}), "an unknown kind"),
        (json!({"kind": "program", "extra": 1}), "an unknown field"),
    ] {
        let r = asked(&w, &w.b_dev, &job, body);
        assert_eq!((r.0, code(&r)), (400, BAD_INPUT), "{what}: {}", r.1);
    }
    // Not for a job that is not scheduled: a cancelled job gets none.
    w.t.ok(&w.b_dev, "POST", &format!("/v1/jobs/{job}/cancel"), None);
    let r = asked(&w, &w.b_dev, &job, json!({"kind": "program"}));
    assert_eq!((r.0, code(&r)), (409, CONFLICT), "{}", r.1);
    // Nor for a job that does not exist.
    let r = asked(&w, &w.b_dev, "job_nonexistent", json!({"kind": "program"}));
    assert_eq!((r.0, code(&r)), (404, NOT_FOUND), "{}", r.1);
}

/// The control plane's grants at a real evaluator: one upload each, however
/// many threads race for it, never after a restart, and never with the job
/// grant that used to open uploads.
#[test]
fn a_control_plane_upload_grant_is_spent_by_one_upload() {
    let Some(w) = world() else { return };
    let control_url = format!("http://{}", live(&w.t.control, Limits::default()));
    let control_key = w.t.control.signer.public_key_hex();
    let (ev, pid) = evaluator_at(
        &control_url,
        &control_key,
        "evaluator-1",
        now().saturating_sub(60),
    );
    let plan = w.plan(EXACT);
    let (_, j) = w.job(&plan, &[], "upload-grants-2");
    let job = j["id"].as_str().unwrap().to_owned();
    let view = w.t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None);
    assert_eq!(view["program_id"], pid.as_str());
    let job_grant: JobGrant = serde_json::from_value(view["grant"].clone()).unwrap();
    let grant = |kind: &str| -> UploadGrant {
        let body = match kind {
            "program" => json!({"kind": "program"}),
            _ => json!({"kind": "keys", "key_id": "cd".repeat(32)}),
        };
        let (s, v) = asked(&w, &w.b_dev, &job, body);
        assert_eq!(s, 201, "{v}");
        serde_json::from_value(v["grant"].clone()).unwrap()
    };

    // The job grant, which the whole organization can read, opens no upload.
    let (s, v) = upload(&ev, EXACT, Some((H_JOB_GRANT, &job_grant.to_header())));
    assert_eq!((s, v["code"].as_str()), (401, Some(SERVICE_AUTH)), "{v}");
    assert!(
        v["message"].as_str().unwrap().contains("upload grant"),
        "the refusal says what to ask for: {v}"
    );

    // A program grant uploads the program once; its replay is refused.
    let g = grant("program");
    let (s, v) = upload(&ev, EXACT, Some((H_UPLOAD_GRANT, &g.to_header())));
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["program_id"], pid.as_str());
    let (s, v) = upload(&ev, EXACT, Some((H_UPLOAD_GRANT, &g.to_header())));
    assert_eq!((s, v["code"].as_str()), (409, Some(REPLAYED)), "{v}");
    // A keys grant is not a program grant.
    let k = grant("keys");
    let (s, v) = upload(&ev, EXACT, Some((H_UPLOAD_GRANT, &k.to_header())));
    assert_eq!((s, v["code"].as_str()), (401, Some(SERVICE_AUTH)), "{v}");

    // Racing uploads of one grant: exactly one is accepted.
    let g = grant("program");
    let header = g.to_header();
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let statuses: Vec<(u16, Value)> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let (ev, header, b) = (ev.clone(), header.clone(), barrier.clone());
                s.spawn(move || {
                    b.wait();
                    upload(&ev, EXACT, Some((H_UPLOAD_GRANT, &header)))
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(
        statuses.iter().filter(|(s, _)| *s == 200).count(),
        1,
        "{statuses:?}"
    );
    assert!(
        statuses
            .iter()
            .filter(|(s, _)| *s != 200)
            .all(|(s, v)| *s == 409 && v["code"] == REPLAYED),
        "{statuses:?}"
    );

    // A restarted evaluator (it starts after these grants were issued, and
    // remembers nothing) accepts none of them, spent or not.
    let spent = g;
    let unspent = grant("program");
    let (restarted, _) = evaluator_at(&control_url, &control_key, "evaluator-1", now() + 2);
    for (what, g) in [("a spent grant", &spent), ("an unspent grant", &unspent)] {
        let (s, v) = upload(&restarted, EXACT, Some((H_UPLOAD_GRANT, &g.to_header())));
        assert_eq!(
            (s, v["code"].as_str()),
            (401, Some(SERVICE_AUTH)),
            "{what}: {v}"
        );
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .contains("before this evaluator started"),
            "{what}: {v}"
        );
    }

    // A grant that was never signed by this control plane.
    let mallory = ServiceSigner::from_seed("control-plane", &[43; 32]).unwrap();
    let mut forged = grant("program");
    forged.issuer_public_key = mallory.public_key_hex();
    forged.signature = mallory.sign(UPLOAD_GRANT, &forged.unsigned()).unwrap();
    let (s, v) = upload(&ev, EXACT, Some((H_UPLOAD_GRANT, &forged.to_header())));
    assert_eq!((s, v["code"].as_str()), (401, Some(SERVICE_AUTH)), "{v}");
    // One edited after signing (another client's name on it).
    let mut edited = grant("program");
    edited.client = "usr_someone_else".into();
    let (s, v) = upload(&ev, EXACT, Some((H_UPLOAD_GRANT, &edited.to_header())));
    assert_eq!((s, v["code"].as_str()), (401, Some(SERVICE_AUTH)), "{v}");
    // The control plane's signature is not what this test is about, so the
    // evaluator-side binding to the program is shown with a grant for
    // another evaluator.
    let (other, _) = evaluator_at(
        &control_url,
        &control_key,
        "evaluator-2",
        now().saturating_sub(60),
    );
    let (s, v) = upload(
        &other,
        EXACT,
        Some((H_UPLOAD_GRANT, &grant("program").to_header())),
    );
    assert_eq!((s, v["code"].as_str()), (401, Some(SERVICE_AUTH)), "{v}");
}
