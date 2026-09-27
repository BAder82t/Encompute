//! The evaluator's HTTP API: with a control plane, program and key uploads
//! need a job grant (as jobs do); without one, local development uploads
//! directly. Job IDs are random, so a result cannot be fetched by guessing.

use std::sync::Arc;

use encompute_backend::{CkksClient, MockClient, MockConfig};
use encompute_evaluator::control::ControlLink;
use encompute_evaluator::server::{Evaluator, Limits};
use encompute_evaluator::{BackendKind, Backends, EvaluatorSession};
use encompute_ir::{Builder, Program, Range, Shape};
use encompute_protocol::{sha256_hex, Envelope, Header, Kind};
use encompute_verification::service::{JobGrant, H_JOB_GRANT, JOB_GRANT, JOB_GRANT_VERSION};
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

fn post(url: &str, path: &str, body: &[u8], grant: Option<&str>) -> u16 {
    let mut r = ureq::post(&format!("{url}{path}"));
    if let Some(g) = grant {
        r = r.set(H_JOB_GRANT, g);
    }
    match r.send_bytes(body) {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(s, _)) => s,
        Err(e) => panic!("{e}"),
    }
}

fn grant(control: &ServiceSigner, evaluator: &str, program_id: &str) -> String {
    let now = encompute_verification::service::now();
    let mut g = JobGrant {
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
        issued_at: now,
        expires_at: now + 600,
        issuer: "control-plane".into(),
        issuer_public_key: control.public_key_hex(),
        signature: String::new(),
    };
    g.signature = control.sign(JOB_GRANT, &g.unsigned()).unwrap();
    g.to_header()
}

#[test]
fn uploads_need_a_grant_with_a_control_plane() {
    let f = fixture();
    let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
    // The control plane is never reached: uploads are checked locally.
    let link = ControlLink::new(
        "http://127.0.0.1:9",
        "control-plane",
        &control.public_key_hex(),
        ServiceSigner::from_seed("evaluator-1", &[6; 32]).unwrap(),
    );
    let url = start(Evaluator::new(Backends::MOCK, Limits::default()).with_control(Arc::new(link)));
    let pid = &f.ids.program_id;
    let good = grant(&control, "evaluator-1", pid);
    let other_evaluator = grant(&control, "evaluator-2", pid);
    let other_program = grant(&control, "evaluator-1", &"0".repeat(64));
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
    assert_eq!(
        post(&url, "/v1/programs", f.eir.as_bytes(), Some(&good)),
        200
    );
    // Keys.
    assert_eq!(post(&url, &keys, &f.keys, None), 401);
    assert_eq!(post(&url, &keys, &f.keys, Some(&other_program)), 401);
    assert_eq!(post(&url, &keys, &f.keys, Some(&good)), 200);
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
