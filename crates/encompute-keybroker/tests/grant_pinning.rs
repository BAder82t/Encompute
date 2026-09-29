//! Review finding KB-1 (ENC-SF-2026-036): a workload accepts a key grant only from a broker
//! key it can trust independently of whoever names the broker. The host
//! relays every request to the real broker and substitutes one grant (the
//! output key) with a key of its own, sealed to the public session key and
//! signed by its own grant key.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use encompute_attestation::mock::{MockAttester, MockHardware, MockProvider};
use encompute_attestation::{
    seal_grant, AttestationChallenge, AttestationEvidence, AttestationPolicy, Attester,
    EncryptedKeyGrant, GrantSigner, TeeKind, Verifier, WorkloadBinding, WorkloadSession,
};
use encompute_ir::{Code, Result};
use encompute_keybroker::{
    acquire_keys, serve, BrokerClient, BrokerMode, DevelopmentFileStore, KeyBroker, KeyMaterial,
};
use encompute_verification::http::{Handler, Request, Response, Server};
use encompute_verification::EvaluatorSigner;

const SPEC: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const POLICY: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const ARTIFACT: &str = "33333333333333333333333333333333333333333333333333333333333333cc";
const IMAGE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const BROKER_ID: &str = "modelco";

fn hw() -> MockHardware {
    MockHardware::from_seed(&[7; 32])
}

fn policy() -> AttestationPolicy {
    let mut p = AttestationPolicy::new(SPEC, Some(POLICY));
    p.allowed_tee = vec![TeeKind::Mock];
    p.allowed_images = vec![IMAGE.into()];
    p.allow_development = true;
    p
}

/// Mock evidence, from an attester that presents itself as hardware: the
/// workload applies its production rules (no unpinned broker).
struct Hardware(MockAttester);

impl Attester for Hardware {
    fn provider(&self) -> &'static str {
        "confidential-space"
    }
    fn attest(
        &self,
        challenge: &AttestationChallenge,
        binding: &WorkloadBinding,
    ) -> Result<AttestationEvidence> {
        self.0.attest(challenge, binding)
    }
}

/// Relays everything to the real broker; replaces only the grant for
/// `target` with one sealing an attacker-chosen key, signed by the
/// attacker's own grant key.
struct Mitm {
    real: String,
    target: &'static str,
    binding: Mutex<Option<WorkloadBinding>>,
}

impl Handler for Mitm {
    fn body_limit(&self, _: &Request) -> usize {
        1 << 20
    }
    fn handle(&self, req: Request) -> Response {
        let path = req.path().to_owned();
        if path == "/v1/attest" {
            *self.binding.lock().unwrap() =
                Some(AttestationEvidence::from_bytes(&req.body).unwrap().binding);
        }
        let asked: Option<String> = (path == "/v1/release").then(|| {
            serde_json::from_slice::<serde_json::Value>(&req.body).unwrap()["asset_id"]
                .as_str()
                .unwrap()
                .to_owned()
        });
        let reply = ureq::post(&format!("{}{path}", self.real))
            .send_bytes(&req.body)
            .unwrap()
            .into_string()
            .unwrap();
        let reply = if asked.as_deref() == Some(self.target) {
            let g: EncryptedKeyGrant = serde_json::from_str(&reply).unwrap();
            let evil = GrantSigner::from_seed(&[66; 32]);
            let f = seal_grant(
                g.header,
                self.binding.lock().unwrap().as_ref().unwrap(),
                b"attacker-chosen-output-key-32by.",
                &evil,
            )
            .unwrap();
            serde_json::to_string(&f).unwrap()
        } else {
            reply
        };
        Response::new(200, "application/json", reply.into())
    }
}

/// The real broker (dataset and output keys) and a relay in front of it
/// that substitutes the output key's grant. Returns (real URL, relay URL,
/// the real broker's grant key).
fn setup() -> (String, String, String) {
    let verifier = Verifier::new().with(MockProvider::new(&hw().public_key()).unwrap());
    let mut b = KeyBroker::new(
        BROKER_ID,
        BrokerMode::Development,
        verifier,
        Box::new(DevelopmentFileStore),
    )
    .unwrap();
    for (asset, key) in [
        ("dataset-a", &b"real-dataset-key"[..]),
        ("contribution-a", b"real-output-key"),
    ] {
        b.add_secret(asset, Some(KeyMaterial::from_bytes(key).unwrap()), policy())
            .unwrap();
    }
    let pin = b.grant_public_key();
    let server = Server::http("127.0.0.1:0").unwrap();
    let real = format!("http://{}", server.server_addr());
    let b = Arc::new(Mutex::new(b));
    std::thread::spawn(move || serve(&b, server));
    let proxy = Server::http("127.0.0.1:0").unwrap();
    let relay = format!("http://{}", proxy.server_addr());
    let m = Mitm {
        real: real.clone(),
        target: "contribution-a",
        binding: Mutex::new(None),
    };
    std::thread::spawn(move || proxy.serve(&m));
    (real, relay, pin)
}

fn acquire(attester: &dyn Attester, dataset: BrokerClient, output: BrokerClient) -> Result<()> {
    let session = WorkloadSession::new(&EvaluatorSigner::generate().unwrap().identity());
    acquire_keys(
        attester,
        &session,
        SPEC,
        Some(POLICY),
        ARTIFACT,
        &[
            (dataset, "dataset-a".to_string()),
            (output, "contribution-a".to_string()),
        ],
    )
    .map(|_| ())
}

/// Review finding KB-1 (ENC-SF-2026-036): with a hardware attester, an unpinned broker is
/// refused before any key is requested.
#[test]
fn a_hardware_workload_refuses_an_unpinned_broker() {
    let (real, _, _) = setup();
    let hardware = Hardware(hw().attester(IMAGE));
    let e = acquire(
        &hardware,
        BrokerClient::new(&real),
        BrokerClient::new(&real),
    )
    .unwrap_err();
    assert_eq!(e.code, Code::KeyRelease, "{e}");
    assert!(e.message.contains("not pinned"), "{e}");
}

/// Review finding KB-1 (ENC-SF-2026-036): grants from two signers inside one broker session
/// (the relay substitutes one) are refused, even for an unpinned
/// development broker.
#[test]
fn grants_from_two_signers_in_one_session_are_refused() {
    let (_, relay, _) = setup();
    let e = acquire(
        &hw().attester(IMAGE),
        BrokerClient::new(&relay),
        BrokerClient::new(&relay),
    )
    .unwrap_err();
    assert_eq!(e.code, Code::KeyRelease, "{e}");
    assert!(e.message.contains("more than one broker key"), "{e}");
}

/// Review finding KB-1 (ENC-SF-2026-036): pins chosen by whoever names the broker (the real
/// key for the inputs, the host's own for the output) do not matter once
/// the workload trusts only the broker keys of its attested identity.
#[test]
fn only_broker_keys_from_the_attested_identity_are_trusted() {
    let (real, relay, pin) = setup();
    let evil = GrantSigner::from_seed(&[66; 32]).public_key_hex();
    let trusted = BTreeMap::from([(BROKER_ID.to_string(), pin.clone())]);
    let hardware = Hardware(hw().attester(IMAGE));
    let with = |url: String| {
        BrokerClient::parse(&url)
            .unwrap()
            .trusting(&trusted)
            .unwrap()
    };
    // The host's pin for the output key, the real one for the dataset.
    let e = acquire(
        &hardware,
        with(format!("{relay}#{pin}")),
        with(format!("{relay}#{evil}")),
    )
    .unwrap_err();
    assert_eq!(e.code, Code::KeyRelease, "{e}");
    // No pin at all from the host: the attested identity's is enough, and
    // the substituted grant is refused.
    let e = acquire(&hardware, with(relay.clone()), with(relay.clone())).unwrap_err();
    assert_eq!(e.code, Code::KeyRelease, "{e}");
    assert!(e.message.contains("attested identity"), "{e}");
    // Another broker ID with the attacker's key is not in the map either.
    let e = acquire(
        &hardware,
        with(real.clone()),
        BrokerClient::new(&relay)
            .trusting(&BTreeMap::from([("modelco-2".to_string(), evil.clone())]))
            .unwrap(),
    )
    .unwrap_err();
    assert_eq!(e.code, Code::KeyRelease, "{e}");
    // The honest broker, through the attested identity's pin: both keys.
    acquire(&hardware, with(real.clone()), with(real)).unwrap();
    assert!(BrokerClient::new("http://x")
        .trusting(&BTreeMap::new())
        .is_err());
}
