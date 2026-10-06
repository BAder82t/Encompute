//! The evaluator's HTTP API: with a control plane, program and key uploads
//! need an upload grant (one upload each); without one, local development
//! uploads directly. Job IDs are random, so a result cannot be fetched by
//! guessing.

use std::sync::Arc;

use encompute_backend::{CkksClient, MockClient, MockConfig};
use encompute_evaluator::control::ControlLink;
use encompute_evaluator::server::{Evaluator, Limits};
use encompute_evaluator::{BackendKind, Backends, EvaluatorSession};
use encompute_ir::{Builder, Program, Range, Shape};
use encompute_protocol::{sha256_hex, Envelope, Header, Kind};
use encompute_verification::service::{
    now, JobGrant, UploadGrant, UploadKind, H_JOB_GRANT, H_UPLOAD_GRANT, JOB_GRANT,
    JOB_GRANT_VERSION, UPLOAD_GRANT, UPLOAD_GRANT_VERSION,
};
use encompute_verification::ServiceSigner;

fn program() -> Program {
    let mut b = Builder::new("u", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(4), Range::new(-1.0, 1.0))
        .unwrap();
    let w = b
        .constant(Shape::Vector(4), vec![0.5, -1.0, 0.25, 2.0])
        .unwrap();
    let d = b.dot(w, x).unwrap();
    b.output("d", d).unwrap();
    b.finish().unwrap()
}

struct Fixture {
    eir: String,
    ids: encompute_evaluator::Ids,
    keys: Vec<u8>,
    request: Vec<u8>,
}

fn fixture() -> Fixture {
    let p = program();
    let local = EvaluatorSession::new(p.clone(), BackendKind::Mock).unwrap();
    let c = local.compiled().ckks().unwrap();
    let ids = local.ids().clone();
    let client = MockClient::new(
        &c.params,
        &c.plan.rotations,
        MockConfig {
            seed: 5,
            noise: false,
        },
    );
    let header = |kind: Kind, key_id: &str| Header {
        governance_id: None,
        kind,
        scheme: "CKKS".into(),
        backend: "mock".into(),
        backend_version: "0".into(),
        parameter_set_id: ids.parameter_set_id.clone(),
        program_id: matches!(kind, Kind::Inputs).then(|| ids.program_id.clone()),
        key_id: Some(key_id.into()),
        items: vec![],
    };
    let payload = client.evaluation_keys().unwrap();
    let key_id = sha256_hex(&payload);
    let keys = Envelope::new(
        header(Kind::EvaluationKeys, &key_id),
        vec![("keys".into(), payload)],
    )
    .encode();
    let ct = client
        .encrypt(&c.plan.encode_input(0, &[0.1, 0.5, -0.5, 0.25]))
        .unwrap();
    let request = Envelope::new(header(Kind::Inputs, &key_id), vec![("x".into(), ct)]).encode();
    Fixture {
        eir: p.to_string(),
        ids,
        keys,
        request,
    }
}

fn start(ev: Evaluator) -> String {
    let server = encompute_verification::http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr());
    std::thread::spawn(move || ev.serve(server));
    url
}

/// The reply of a POST: status and JSON body (null when it has none).
fn send(
    url: &str,
    path: &str,
    body: &[u8],
    header: Option<(&str, &str)>,
) -> (u16, serde_json::Value) {
    let mut r = ureq::post(&format!("{url}{path}"));
    if let Some((name, value)) = header {
        r = r.set(name, value);
    }
    match r.send_bytes(body) {
        Ok(r) => (r.status(), r.into_json().unwrap_or_default()),
        Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap_or_default()),
        Err(e) => panic!("{e}"),
    }
}

/// The status of a POST carrying an upload grant (or none).
fn post(url: &str, path: &str, body: &[u8], grant: Option<&str>) -> u16 {
    send(url, path, body, grant.map(|g| (H_UPLOAD_GRANT, g))).0
}

/// A fresh random grant ID.
fn nonce() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).unwrap();
    encompute_verification::hex(&b)
}

fn upload_grant_for(
    control: &ServiceSigner,
    evaluator: &str,
    kind: UploadKind,
    program_id: &str,
    key_id: &str,
) -> UploadGrant {
    let t = now();
    let mut g = UploadGrant {
        version: UPLOAD_GRANT_VERSION,
        grant_id: nonce(),
        kind,
        organization: "modelco".into(),
        project: "prj_1".into(),
        job_id: "job_1".into(),
        client: "usr_victim".into(),
        evaluator: evaluator.into(),
        program_id: program_id.into(),
        key_id: key_id.into(),
        issued_at: t,
        expires_at: t + 600,
        issuer: "control-plane".into(),
        issuer_public_key: control.public_key_hex(),
        signature: String::new(),
    };
    g.signature = control.sign(UPLOAD_GRANT, &g.unsigned()).unwrap();
    g
}

/// A grant for the program (`key_id` empty) of evaluator-1, as a header.
fn grant(control: &ServiceSigner, evaluator: &str, program_id: &str) -> String {
    upload_grant_for(control, evaluator, UploadKind::Program, program_id, "").to_header()
}

/// A grant for one set of keys of evaluator-1, as a header.
fn keys_grant(control: &ServiceSigner, evaluator: &str, program_id: &str, key_id: &str) -> String {
    upload_grant_for(control, evaluator, UploadKind::Keys, program_id, key_id).to_header()
}

/// The job grant that used to open uploads.
fn job_grant(control: &ServiceSigner, evaluator: &str, program_id: &str) -> String {
    let t = now();
    let mut g = JobGrant {
        governance: None,
        version: JOB_GRANT_VERSION,
        job_id: "job_1".into(),
        organization: "modelco".into(),
        project: "prj_1".into(),
        plan_id: "pln_1".into(),
        spec_id: "s".repeat(64),
        program_id: program_id.into(),
        evaluator: evaluator.into(),
        backend: "mock".into(),
        profile: "p".into(),
        issued_at: t,
        expires_at: t + 600,
        issuer: "control-plane".into(),
        issuer_public_key: control.public_key_hex(),
        signature: String::new(),
    };
    g.signature = control.sign(JOB_GRANT, &g.unsigned()).unwrap();
    g.to_header()
}

fn key_id_of(keys: &[u8]) -> String {
    Envelope::decode(keys).unwrap().header.key_id.unwrap()
}

/// Another client's keys: another key ID, otherwise a well-formed upload.
fn other_keys(f: &Fixture) -> Vec<u8> {
    let env = Envelope::decode(&f.keys).unwrap();
    let mut payload = env.payload.clone();
    payload.push(0);
    let mut h = env.header.clone();
    h.key_id = Some(sha256_hex(&payload));
    Envelope::new(h, vec![("keys".into(), payload)]).encode()
}

/// An evaluator linked to a control plane that is never reached (uploads
/// are checked locally), counted as started a minute ago.
fn controlled_since(control: &ServiceSigner, started_at: u64) -> String {
    let link = ControlLink::new(
        "http://127.0.0.1:9",
        "control-plane",
        &control.public_key_hex(),
        ServiceSigner::from_seed("evaluator-1", &[6; 32]).unwrap(),
    )
    .with_started_at(started_at);
    start(Evaluator::new(Backends::MOCK, Limits::default()).with_control(Arc::new(link)))
}

fn controlled(control: &ServiceSigner) -> String {
    controlled_since(control, now() - 60)
}

#[test]
fn uploads_need_a_grant_with_a_control_plane() {
    let f = fixture();
    let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
    let url = controlled(&control);
    let pid = &f.ids.program_id;
    let key_id = key_id_of(&f.keys);
    let good = grant(&control, "evaluator-1", pid);
    let other_evaluator = grant(&control, "evaluator-2", pid);
    let other_program = grant(&control, "evaluator-1", &"0".repeat(64));
    let keys_for_programs = keys_grant(&control, "evaluator-1", pid, &key_id);
    let forged = grant(
        &ServiceSigner::from_seed("control-plane", &[7; 32]).unwrap(),
        "evaluator-1",
        pid,
    );
    let keys = format!("/v1/programs/{pid}/keys");
    // Programs.
    assert_eq!(post(&url, "/v1/programs", f.eir.as_bytes(), None), 401);
    assert_eq!(
        post(&url, "/v1/programs", f.eir.as_bytes(), Some(&forged)),
        401
    );
    assert_eq!(
        post(
            &url,
            "/v1/programs",
            f.eir.as_bytes(),
            Some(&other_evaluator)
        ),
        401
    );
    assert_eq!(
        post(&url, "/v1/programs", f.eir.as_bytes(), Some(&other_program)),
        401
    );
    // A keys grant is not a program grant.
    assert_eq!(
        post(
            &url,
            "/v1/programs",
            f.eir.as_bytes(),
            Some(&keys_for_programs)
        ),
        401
    );
    assert_eq!(
        post(&url, "/v1/programs", f.eir.as_bytes(), Some(&good)),
        200
    );
    // Keys.
    let good_keys = keys_grant(&control, "evaluator-1", pid, &key_id);
    let other_program_keys = keys_grant(&control, "evaluator-1", &"0".repeat(64), &key_id);
    assert_eq!(post(&url, &keys, &f.keys, None), 401);
    assert_eq!(post(&url, &keys, &f.keys, Some(&other_program_keys)), 401);
    // A program grant is not a keys grant.
    assert_eq!(
        post(
            &url,
            &keys,
            &f.keys,
            Some(&grant(&control, "evaluator-1", pid))
        ),
        401
    );
    assert_eq!(post(&url, &keys, &f.keys, Some(&good_keys)), 200);
}

/// Review finding EV-1 (ENC-SF-2026-044): a program upload with a grant for another program
/// was refused (401) only after the program had been compiled and loaded
/// into every worker and the replay list, and listed in `/v1/info`. The
/// grant is now checked against the program's ID before anything is
/// compiled: a refused upload changes no state, and spends no grant.
#[test]
fn a_refused_program_upload_loads_nothing() {
    let f = fixture();
    let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
    let url = controlled(&control);
    let pid = &f.ids.program_id;
    let other_program = grant(&control, "evaluator-1", &"0".repeat(64));
    let good = grant(&control, "evaluator-1", pid);
    for g in [None, Some(other_program.as_str())] {
        assert_eq!(post(&url, "/v1/programs", f.eir.as_bytes(), g), 401);
    }
    // Garbage with a valid grant: refused as unparsable, not compiled, and
    // the grant is still unspent.
    assert_eq!(
        post(&url, "/v1/programs", b"not a program", Some(&good)),
        400
    );
    let (_, info) = get(&url, "/v1/info", Some(&good));
    assert!(
        listed(&info).is_empty(),
        "a refused program was loaded: {info}"
    );
    // Its keys cannot be registered either: the program is not there (and
    // the refusal does not spend the grant for the keys).
    let key_id = key_id_of(&f.keys);
    let keys_g = keys_grant(&control, "evaluator-1", pid, &key_id);
    assert_eq!(
        post(
            &url,
            &format!("/v1/programs/{pid}/keys"),
            &f.keys,
            Some(&keys_g)
        ),
        404
    );
    assert_eq!(
        post(&url, "/v1/programs", f.eir.as_bytes(), Some(&good)),
        200,
        "the failed upload did not use the grant up"
    );
    let (_, info) = get(&url, "/v1/info", Some(&good));
    assert_eq!(listed(&info), vec![pid.clone()]);
    assert_eq!(
        post(
            &url,
            &format!("/v1/programs/{pid}/keys"),
            &f.keys,
            Some(&keys_g)
        ),
        200,
        "nor the keys' grant"
    );
}

/// Review finding EV-5 (ENC-SF-2026-064): with a control plane, `/v1/info` listed every
/// tenant's programs to anyone, and `GET /v1/programs/{p}/keys/{k}` told
/// anyone whether a client's key was registered. The listing now shows only
/// the program a presented upload grant names, and the key lookup needs a
/// grant for exactly those keys.
#[test]
fn with_a_control_plane_programs_and_keys_are_not_advertised() {
    let f = fixture();
    let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
    let url = controlled(&control);
    let pid = &f.ids.program_id;
    let key_id = key_id_of(&f.keys);
    let good = grant(&control, "evaluator-1", pid);
    let good_keys = keys_grant(&control, "evaluator-1", pid, &key_id);
    let other_program = grant(&control, "evaluator-1", &"0".repeat(64));
    let forged = grant(
        &ServiceSigner::from_seed("control-plane", &[7; 32]).unwrap(),
        "evaluator-1",
        pid,
    );
    assert_eq!(
        post(&url, "/v1/programs", f.eir.as_bytes(), Some(&good)),
        200
    );
    assert_eq!(
        post(
            &url,
            &format!("/v1/programs/{pid}/keys"),
            &f.keys,
            Some(&good_keys)
        ),
        200
    );
    // The evaluator's identity and backends are public; programs are not.
    // The job grant that used to list them lists nothing now.
    let job = job_grant(&control, "evaluator-1", pid);
    for g in [None, Some(forged.as_str()), Some(other_program.as_str())] {
        let (status, info) = get(&url, "/v1/info", g);
        assert_eq!(status, 200);
        assert!(info["evaluator"]["public_key"].is_string());
        assert!(listed(&info).is_empty(), "{info}");
    }
    let (status, info) = ureq_get_job_grant(&url, "/v1/info", &job);
    assert_eq!(status, 200);
    assert!(
        listed(&info).is_empty(),
        "a job grant lists a program: {info}"
    );
    assert_eq!(
        listed(&get(&url, "/v1/info", Some(&good)).1),
        vec![pid.clone()],
        "a read still works after the upload spent the grant"
    );
    // The key-presence oracle: a grant for exactly these keys.
    let path = format!("/v1/programs/{pid}/keys/{key_id}");
    for g in [None, Some(forged.as_str()), Some(other_program.as_str())] {
        assert_eq!(get(&url, &path, g).0, 401);
    }
    // A program grant, or a grant for other keys, is no lookup of these.
    assert_eq!(get(&url, &path, Some(&good)).0, 401);
    let other_keys_grant = keys_grant(&control, "evaluator-1", pid, &"f".repeat(64));
    assert_eq!(get(&url, &path, Some(&other_keys_grant)).0, 401);
    assert_eq!(get(&url, &path, Some(&good_keys)).0, 200);
    let absent = format!("/v1/programs/{pid}/keys/{}", "f".repeat(64));
    assert_eq!(get(&url, &absent, Some(&other_keys_grant)).0, 404);
    // And the job grant is refused here too.
    assert_eq!(ureq_get_job_grant(&url, &path, &job).0, 401);
}

/// A GET carrying only a job grant.
fn ureq_get_job_grant(url: &str, path: &str, grant: &str) -> (u16, serde_json::Value) {
    match ureq::get(&format!("{url}{path}"))
        .set(H_JOB_GRANT, grant)
        .call()
    {
        Ok(r) => (r.status(), r.into_json().unwrap_or_default()),
        Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap_or_default()),
        Err(e) => panic!("{e}"),
    }
}

/// Evaluator upload grants were reusable until they expired: an upload
/// spent nothing, so the same header uploaded any number of times, and a
/// copy of it (it is visible to the whole submitting organization) did too.
/// A grant now admits exactly one upload of what it names; the replay is
/// refused with ENC2608 (409), for a program and for keys alike.
#[test]
fn an_upload_grant_admits_exactly_one_upload() {
    let f = fixture();
    let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
    let url = controlled(&control);
    let pid = &f.ids.program_id;
    let key_id = key_id_of(&f.keys);
    let keys = format!("/v1/programs/{pid}/keys");
    let program = grant(&control, "evaluator-1", pid);
    let keys_g = keys_grant(&control, "evaluator-1", pid, &key_id);
    let replayed = |r: (u16, serde_json::Value), what: &str| {
        assert_eq!(
            (r.0, r.1["code"].as_str()),
            (409, Some("ENC2608")),
            "{what}: {}",
            r.1
        );
    };
    assert_eq!(
        send(
            &url,
            "/v1/programs",
            f.eir.as_bytes(),
            Some((H_UPLOAD_GRANT, &program))
        )
        .0,
        200
    );
    assert_eq!(
        send(&url, &keys, &f.keys, Some((H_UPLOAD_GRANT, &keys_g))).0,
        200
    );
    for _ in 0..3 {
        replayed(
            send(
                &url,
                "/v1/programs",
                f.eir.as_bytes(),
                Some((H_UPLOAD_GRANT, &program)),
            ),
            "program",
        );
        replayed(
            send(&url, &keys, &f.keys, Some((H_UPLOAD_GRANT, &keys_g))),
            "keys",
        );
    }
    // A new grant is a new upload (the same keys are registered again, a
    // no-op), so spending a grant does not lock the client out.
    let fresh = keys_grant(&control, "evaluator-1", pid, &key_id);
    assert_eq!(
        send(&url, &keys, &f.keys, Some((H_UPLOAD_GRANT, &fresh))).0,
        200
    );
}

/// The grant names the keys: a copy of it (a co-tenant read the job)
/// uploads nothing but the one set of keys it names, and not even those
/// once the owner has used it.
#[test]
fn an_upload_grant_binds_the_keys_it_names() {
    let f = fixture();
    let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
    let url = controlled(&control);
    let pid = &f.ids.program_id;
    let keys = format!("/v1/programs/{pid}/keys");
    assert_eq!(
        post(
            &url,
            "/v1/programs",
            f.eir.as_bytes(),
            Some(&grant(&control, "evaluator-1", pid))
        ),
        200
    );
    let victim_grant = keys_grant(&control, "evaluator-1", pid, &key_id_of(&f.keys));
    // The attacker holds the victim's grant and uploads its own keys.
    let attacker_keys = other_keys(&f);
    let (s, v) = send(
        &url,
        &keys,
        &attacker_keys,
        Some((H_UPLOAD_GRANT, &victim_grant)),
    );
    assert_eq!((s, v["code"].as_str()), (401, Some("ENC2607")), "{v}");
    // Refused, so the grant is not spent: the victim's own upload works.
    assert_eq!(post(&url, &keys, &f.keys, Some(&victim_grant)), 200);
    // And a copy used afterwards is a replay.
    let (s, v) = send(&url, &keys, &f.keys, Some((H_UPLOAD_GRANT, &victim_grant)));
    assert_eq!((s, v["code"].as_str()), (409, Some("ENC2608")), "{v}");
    // A key ID that does not match the key material is refused, and spends
    // nothing either.
    let mut lying = Envelope::decode(&attacker_keys).unwrap();
    lying.header.key_id = Some(key_id_of(&f.keys));
    let lying = lying.encode();
    let g = keys_grant(&control, "evaluator-1", pid, &key_id_of(&f.keys));
    let (s, v) = send(&url, &keys, &lying, Some((H_UPLOAD_GRANT, &g)));
    assert_eq!(
        (s, v["code"].as_str()),
        (409, Some(encompute_ir::Code::WrongKey.as_str())),
        "{v}"
    );
    assert_eq!(
        post(&url, &keys, &f.keys, Some(&g)),
        200,
        "the grant was not spent"
    );
}

/// Concurrent uses of one grant: exactly one upload succeeds, the others
/// are replays. A failing upload frees the grant, so a legitimate retry
/// after a failure works.
#[test]
fn concurrent_uploads_with_one_grant_succeed_once() {
    let f = fixture();
    let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
    let url = controlled(&control);
    let pid = f.ids.program_id.clone();
    let key_id = key_id_of(&f.keys);
    assert_eq!(
        post(
            &url,
            "/v1/programs",
            f.eir.as_bytes(),
            Some(&grant(&control, "evaluator-1", &pid))
        ),
        200
    );
    let race = |path: &str, body: &[u8], header: &str| -> Vec<(u16, serde_json::Value)> {
        let barrier = Arc::new(std::sync::Barrier::new(8));
        std::thread::scope(|s| {
            let hs: Vec<_> = (0..8)
                .map(|_| {
                    let (url, header, b) = (url.clone(), header.to_owned(), barrier.clone());
                    let (path, body) = (path.to_owned(), body.to_vec());
                    s.spawn(move || {
                        b.wait();
                        send(&url, &path, &body, Some((H_UPLOAD_GRANT, &header)))
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        })
    };
    let check = |results: Vec<(u16, serde_json::Value)>, what: &str| {
        assert_eq!(
            results.iter().filter(|(s, _)| *s == 200).count(),
            1,
            "{what}: {results:?}"
        );
        assert!(
            results
                .iter()
                .filter(|(s, _)| *s != 200)
                .all(|(s, v)| *s == 409 && v["code"] == "ENC2608"),
            "{what}: {results:?}"
        );
    };
    let keys = format!("/v1/programs/{pid}/keys");
    check(
        race(
            &keys,
            &f.keys,
            &keys_grant(&control, "evaluator-1", &pid, &key_id),
        ),
        "keys",
    );
    check(
        race(
            "/v1/programs",
            f.eir.as_bytes(),
            &grant(&control, "evaluator-1", &pid),
        ),
        "program",
    );
}

/// The evaluator remembers spent grants in memory, one node. A restart
/// forgets them, so it accepts no grant issued before it started: a spent
/// grant cannot be used again while it is still unexpired, and the grants
/// not yet used are asked for again.
#[test]
fn a_restarted_evaluator_accepts_no_earlier_grant() {
    let f = fixture();
    let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
    let pid = &f.ids.program_id;
    let first = controlled(&control);
    let spent = grant(&control, "evaluator-1", pid);
    let unspent = grant(&control, "evaluator-1", pid);
    assert_eq!(
        post(&first, "/v1/programs", f.eir.as_bytes(), Some(&spent)),
        200
    );
    assert_eq!(
        post(&first, "/v1/programs", f.eir.as_bytes(), Some(&spent)),
        409
    );
    // The process restarts (two seconds after these grants were issued).
    let second = controlled_since(&control, now() + 2);
    for (what, g) in [("spent", &spent), ("unspent", &unspent)] {
        let (s, v) = send(
            &second,
            "/v1/programs",
            f.eir.as_bytes(),
            Some((H_UPLOAD_GRANT, g)),
        );
        assert_eq!(
            (s, v["code"].as_str()),
            (401, Some("ENC2607")),
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
    // A grant issued after the restart works, once.
    let t = now() + 3;
    let mut after = upload_grant_for(&control, "evaluator-1", UploadKind::Program, pid, "");
    after.issued_at = t;
    after.expires_at = t + 600;
    after.signature = control.sign(UPLOAD_GRANT, &after.unsigned()).unwrap();
    let h = after.to_header();
    assert_eq!(
        post(&second, "/v1/programs", f.eir.as_bytes(), Some(&h)),
        200
    );
    assert_eq!(
        post(&second, "/v1/programs", f.eir.as_bytes(), Some(&h)),
        409
    );
}

/// Old format: a job grant (v1 or governed v2) opened uploads and nothing
/// replaces it silently. It is refused at every upload endpoint with a
/// message that says what to ask the control plane for.
#[test]
fn a_job_grant_no_longer_opens_an_upload() {
    let f = fixture();
    let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
    let url = controlled(&control);
    let pid = &f.ids.program_id;
    let job = job_grant(&control, "evaluator-1", pid);
    let keys = format!("/v1/programs/{pid}/keys");
    for (path, body) in [
        ("/v1/programs".to_owned(), f.eir.as_bytes().to_vec()),
        (keys, f.keys.clone()),
    ] {
        let (s, v) = send(&url, &path, &body, Some((H_JOB_GRANT, &job)));
        assert_eq!(
            (s, v["code"].as_str()),
            (401, Some("ENC2607")),
            "{path}: {v}"
        );
        assert!(
            v["message"].as_str().unwrap().contains("upload grant"),
            "{path}: {v}"
        );
        // Presented in the upload header it does not even parse.
        let (s, v) = send(&url, &path, &body, Some((H_UPLOAD_GRANT, &job)));
        assert_eq!(
            (s, v["code"].as_str()),
            (401, Some("ENC2607")),
            "{path}: {v}"
        );
    }
    let (_, info) = get(&url, "/v1/info", None);
    assert!(listed(&info).is_empty(), "nothing was loaded: {info}");
}

#[test]
fn local_uploads_need_no_grant_and_job_ids_are_random() {
    let f = fixture();
    let run = || {
        let url = start(Evaluator::new(Backends::MOCK, Limits::default()));
        let pid = &f.ids.program_id;
        assert_eq!(post(&url, "/v1/programs", f.eir.as_bytes(), None), 200);
        assert_eq!(
            post(&url, &format!("/v1/programs/{pid}/keys"), &f.keys, None),
            200
        );
        let job: serde_json::Value = ureq::post(&format!("{url}/v1/programs/{pid}/jobs"))
            .send_bytes(&f.request)
            .unwrap()
            .into_json()
            .unwrap();
        let id = job["job_id"].as_str().unwrap().to_owned();
        let mut out = vec![];
        std::io::Read::read_to_end(
            &mut ureq::get(&format!("{url}/v1/jobs/{id}/result"))
                .call()
                .unwrap()
                .into_reader(),
            &mut out,
        )
        .unwrap();
        (id, out)
    };
    // The first job's ID does not derive from the job counter and the
    // output (which whoever sees or predicts the output could compute).
    let ((a, out), (b, _)) = (run(), run());
    let tail = &out[out.len().saturating_sub(32)..];
    let derived = sha256_hex(&[&0u64.to_le_bytes()[..], tail].concat())[..32].to_owned();
    assert_ne!(
        a, derived,
        "the job ID is derived from the counter and output"
    );
    assert_eq!(a.len(), 32);
    assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b);
}

fn get(url: &str, path: &str, grant: Option<&str>) -> (u16, serde_json::Value) {
    let mut r = ureq::get(&format!("{url}{path}"));
    if let Some(g) = grant {
        r = r.set(H_UPLOAD_GRANT, g);
    }
    match r.call() {
        Ok(r) => (r.status(), r.into_json().unwrap_or_default()),
        Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap_or_default()),
        Err(e) => panic!("{e}"),
    }
}

fn listed(info: &serde_json::Value) -> Vec<String> {
    info["programs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["program_id"].as_str().unwrap().to_owned())
        .collect()
}

/// Without a control plane (local development) nothing changes: every
/// program is listed and key lookups need no grant.
#[test]
fn local_info_lists_every_program() {
    let f = fixture();
    let url = start(Evaluator::new(Backends::MOCK, Limits::default()));
    let pid = &f.ids.program_id;
    assert_eq!(post(&url, "/v1/programs", f.eir.as_bytes(), None), 200);
    assert_eq!(listed(&get(&url, "/v1/info", None).1), vec![pid.clone()]);
    let key_id = Envelope::decode(&f.keys).unwrap().header.key_id.unwrap();
    let path = format!("/v1/programs/{pid}/keys/{key_id}");
    assert_eq!(get(&url, &path, None).0, 404);
    assert_eq!(
        post(&url, &format!("/v1/programs/{pid}/keys"), &f.keys, None),
        200
    );
    assert_eq!(get(&url, &path, None).0, 200);
}
