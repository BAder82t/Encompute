//! A client's uploads to an evaluator managed by a control plane, over real
//! HTTP on localhost (mock backend), when the evaluator restarted after the
//! control plane issued the upload grant.
//!
//! A restart forgets which grants were spent, so the evaluator accepts no
//! grant issued before it started, nor one of the second it started in
//! (ENC2609). A client refused that way asks the control plane once more,
//! two seconds later, for a new grant. It retries nothing else.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::logistic;
use encompute_evaluator::control::ControlLink;
use encompute_evaluator::server::{Evaluator, Limits};
use encompute_ir::{Code, Result};
use encompute_runtime::{Backends, Mode, Model, Remote, UploadGrantSource};
use encompute_verification::service::{now, UPLOAD_GRANT, UPLOAD_GRANT_VERSION};
use encompute_verification::{ServiceSigner, UploadGrant, UploadKind};

fn signer(id: &str, seed: u8) -> ServiceSigner {
    ServiceSigner::from_seed(id, &[seed; 32]).unwrap()
}

/// An evaluator that pins `control`'s key (the control plane itself is
/// never reached: uploads are checked locally) and counts as started at
/// `started_at`.
fn evaluator_started_at(control: &ServiceSigner, started_at: u64) -> String {
    let link = ControlLink::new(
        "http://127.0.0.1:9",
        "control-plane",
        &control.public_key_hex(),
        signer("evaluator-1", 6),
    )
    .with_started_at(started_at);
    let server = encompute_verification::http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr());
    let ev = Evaluator::new(Backends::MOCK, Limits::default()).with_control(Arc::new(link));
    std::thread::spawn(move || ev.serve(server));
    url
}

/// The control plane's upload grants for one job on evaluator-1, signed
/// by `signer`. The first grant of each kind is issued at `first_at` when
/// it is set, every other one now. It records what it was asked for.
struct Grants {
    signer: ServiceSigner,
    program_id: String,
    first_at: Option<u64>,
    asked: Mutex<Vec<UploadKind>>,
}

impl Grants {
    fn new(signer: ServiceSigner, program_id: &str, first_at: Option<u64>) -> Arc<Self> {
        Arc::new(Self {
            signer,
            program_id: program_id.to_owned(),
            first_at,
            asked: Mutex::new(Vec::new()),
        })
    }

    fn asked(&self) -> Vec<UploadKind> {
        self.asked.lock().unwrap().clone()
    }
}

impl UploadGrantSource for Grants {
    fn upload_grant(&self, kind: UploadKind, key_id: Option<&str>) -> Result<UploadGrant> {
        let mut asked = self.asked.lock().unwrap();
        let first = !asked.contains(&kind);
        asked.push(kind);
        let t = match self.first_at {
            Some(t) if first => t,
            _ => now(),
        };
        let mut g = UploadGrant {
            version: UPLOAD_GRANT_VERSION,
            grant_id: format!("{:032x}", asked.len()),
            kind,
            organization: "modelco".into(),
            project: "prj_1".into(),
            job_id: "job_1".into(),
            client: "usr_initiator".into(),
            evaluator: "evaluator-1".into(),
            program_id: self.program_id.clone(),
            key_id: key_id.unwrap_or_default().into(),
            issued_at: t,
            expires_at: t + 600,
            issuer: "control-plane".into(),
            issuer_public_key: self.signer.public_key_hex(),
            signature: String::new(),
        };
        g.signature = self.signer.sign(UPLOAD_GRANT, &g.unsigned())?;
        Ok(g)
    }
}

/// The race the enterprise golden path hit after it restarted every
/// service: the control plane issued the grant in the second the evaluator
/// started, so the evaluator refused it. The client asks for a new grant
/// two seconds later and the upload goes through, for the program (refused at
/// the upload) and for the keys (refused at the key lookup, before any key
/// is sent).
#[test]
fn a_grant_of_the_second_the_evaluator_started_is_asked_for_again() {
    let control = signer("control-plane", 5);
    let started = now();
    let url = evaluator_started_at(&control, started);
    let m = Model::compile(logistic(8, 1)).unwrap();
    let client = m.new_client(Mode::Mock).unwrap();
    let pid = m.ids().program_id.clone();
    let grants = Grants::new(signer("control-plane", 5), &pid, Some(started));
    let remote = Remote::new(&url).with_upload_grants(grants.clone());

    let t = Instant::now();
    remote.ensure_program(m.program(), &pid).unwrap();
    assert!(t.elapsed() >= Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(grants.asked(), [UploadKind::Program; 2]);

    let keys = client.evaluation_keys().unwrap();
    let t = Instant::now();
    let sent = remote
        .ensure_keys(&pid, client.key_id(), Some(keys))
        .unwrap();
    assert_eq!(sent, keys.len());
    assert!(t.elapsed() >= Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(
        grants.asked()[2..],
        [UploadKind::Keys; 2],
        "{:?}",
        grants.asked()
    );

    // Both are held now: a fresh grant finds them and nothing is sent again.
    assert_eq!(
        remote
            .ensure_keys(&pid, client.key_id(), Some(keys))
            .unwrap(),
        0
    );
    remote.ensure_program(m.program(), &pid).unwrap();
    assert_eq!(grants.asked().len(), 6, "{:?}", grants.asked());
}

/// The new grant is checked like the first, and the client asks once more
/// only after this one refusal. An evaluator that keeps refusing (here it
/// counts as started an hour after the grants are issued, as with a control
/// plane clock far behind the evaluator's) refuses the second grant too, and
/// the client stops there and says so. A grant refused for any other
/// reason (signed by a key the evaluator does not pin) is not asked for
/// again.
#[test]
fn only_the_restart_refusal_is_retried_and_only_once() {
    let control = signer("control-plane", 5);
    let m = Model::compile(logistic(8, 1)).unwrap();
    let client = m.new_client(Mode::Mock).unwrap();
    let pid = m.ids().program_id.clone();
    let keys = client.evaluation_keys().unwrap();

    let url = evaluator_started_at(&control, now() + 3600);
    let grants = Grants::new(signer("control-plane", 5), &pid, None);
    let remote = Remote::new(&url).with_upload_grants(grants.clone());
    let e = remote.ensure_program(m.program(), &pid).unwrap_err();
    assert_eq!(e.code, Code::UploadGrantBeforeStart, "{e}");
    assert!(e.message.contains("refused too"), "{e}");
    assert!(e.message.contains("clock"), "{e}");
    assert_eq!(grants.asked(), [UploadKind::Program; 2]);
    let e = remote
        .ensure_keys(&pid, client.key_id(), Some(keys))
        .unwrap_err();
    assert_eq!(e.code, Code::UploadGrantBeforeStart, "{e}");
    assert_eq!(grants.asked()[2..], [UploadKind::Keys; 2]);

    let url = evaluator_started_at(&control, now() - 60);
    let forged = Grants::new(signer("control-plane", 7), &pid, None);
    let remote = Remote::new(&url).with_upload_grants(forged.clone());
    let e = remote.ensure_program(m.program(), &pid).unwrap_err();
    assert_eq!(e.code, Code::ServiceAuthentication, "{e}");
    let e = remote
        .ensure_keys(&pid, client.key_id(), Some(keys))
        .unwrap_err();
    assert_eq!(e.code, Code::ServiceAuthentication, "{e}");
    assert_eq!(forged.asked(), [UploadKind::Program, UploadKind::Keys]);
}
