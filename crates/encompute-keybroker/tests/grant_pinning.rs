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

/// A real broker `id` holding `keys` (asset -> key bytes), released under
/// [`policy`]. Returns (URL, grant key).
fn owner_broker(id: &str, keys: &[(&str, &[u8])]) -> (String, String) {
    let verifier = Verifier::new().with(MockProvider::new(&hw().public_key()).unwrap());
    let mut b = KeyBroker::new(
        id,
        BrokerMode::Development,
        verifier,
        Box::new(DevelopmentFileStore),
    )
    .unwrap();
    for (asset, key) in keys {
        b.add_secret(asset, Some(KeyMaterial::from_bytes(key).unwrap()), policy())
            .unwrap();
    }
    let pin = b.grant_public_key();
    let server = Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr());
    let b = Arc::new(Mutex::new(b));
    std::thread::spawn(move || serve(&b, server));
    (url, pin)
}

/// Owner A's broker, compromised: it relays to `real` (so sessions and
/// bindings are genuine), and answers every release with a key of its own
/// choosing, signed by its own (pinned) grant key and naming `claims` as
/// the broker.
struct OwnerABroker {
    real: String,
    claims: &'static str,
    binding: Mutex<Option<WorkloadBinding>>,
}

const OWNER_A_SEED: [u8; 32] = [77; 32];

impl Handler for OwnerABroker {
    fn body_limit(&self, _: &Request) -> usize {
        1 << 20
    }
    fn handle(&self, req: Request) -> Response {
        let path = req.path().to_owned();
        if path == "/v1/attest" {
            *self.binding.lock().unwrap() =
                Some(AttestationEvidence::from_bytes(&req.body).unwrap().binding);
        }
        let reply = ureq::post(&format!("{}{path}", self.real))
            .send_bytes(&req.body)
            .unwrap()
            .into_string()
            .unwrap();
        let reply = if path == "/v1/release" {
            let g: EncryptedKeyGrant = serde_json::from_str(&reply).unwrap();
            let own = GrantSigner::from_seed(&OWNER_A_SEED);
            let mut header = g.header;
            header.broker_id = self.claims.to_owned();
            header.broker_public_key = own.public_key_hex();
            let f = seal_grant(
                header,
                self.binding.lock().unwrap().as_ref().unwrap(),
                b"owner-a-chosen-contribution-key.",
                &own,
            )
            .unwrap();
            serde_json::to_string(&f).unwrap()
        } else {
            reply
        };
        Response::new(200, "application/json", reply.into())
    }
}

fn relay_as_owner_a(real: &str, claims: &'static str) -> String {
    let proxy = Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", proxy.server_addr());
    let h = OwnerABroker {
        real: real.to_owned(),
        claims,
        binding: Mutex::new(None),
    };
    std::thread::spawn(move || proxy.serve(&h));
    url
}

fn acquire_all(requests: &[(BrokerClient, String)]) -> Result<Vec<(String, Vec<u8>)>> {
    let session = WorkloadSession::new(&EvaluatorSigner::generate().unwrap().identity());
    let hardware = Hardware(hw().attester(IMAGE));
    acquire_keys(&hardware, &session, SPEC, Some(POLICY), ARTIFACT, requests).map(|v| {
        v.into_iter()
            .map(|k| (k.asset_id, k.key.to_vec()))
            .collect()
    })
}

/// The rc.4 grant confusion, with several owners' brokers: owner A's broker
/// (trusted, with its own pinned key) grants a key of its choosing for
/// owner B's contribution key. The per-asset binding refuses it, whether
/// the grant names A's broker or claims to be B's.
#[test]
fn a_grant_for_an_asset_from_another_owners_broker_is_refused() {
    let (b_url, b_pin) = owner_broker(
        "hospital-b-broker",
        &[
            ("dataset-b", b"hospital-b-dataset-key"),
            ("contribution-b", b"hospital-b-output-key"),
        ],
    );
    let a_pin = GrantSigner::from_seed(&OWNER_A_SEED).public_key_hex();
    let trusted = BTreeMap::from([
        ("hospital-a-broker".to_string(), a_pin.clone()),
        ("hospital-b-broker".to_string(), b_pin.clone()),
    ]);
    let binding = BTreeMap::from([
        ("dataset-a".to_string(), "hospital-a-broker".to_string()),
        ("dataset-b".to_string(), "hospital-b-broker".to_string()),
        (
            "contribution-b".to_string(),
            "hospital-b-broker".to_string(),
        ),
    ]);
    let client = |url: &str| {
        BrokerClient::new(url)
            .trusting_per_asset(&trusted, &binding)
            .unwrap()
    };
    // The host routes B's contribution key to A's broker, which answers as
    // itself: a trusted signer, but not the broker bound to that key.
    let as_a = relay_as_owner_a(&b_url, "hospital-a-broker");
    let e = acquire_all(&[
        (client(&b_url), "dataset-b".into()),
        (client(&as_a), "contribution-b".into()),
    ])
    .unwrap_err();
    assert_eq!(e.code, Code::KeyRelease, "{e}");
    assert!(
        e.message
            .contains("binds contribution-b to hospital-b-broker"),
        "{e}"
    );
    // ...or claims to be B's broker: not B's pinned signer.
    let as_b = relay_as_owner_a(&b_url, "hospital-b-broker");
    let e = acquire_all(&[(client(&as_b), "contribution-b".into())]).unwrap_err();
    assert_eq!(e.code, Code::KeyRelease, "{e}");
    assert!(e.message.contains("attested identity"), "{e}");
    // Without the binding the same grant would pass as A's: the reason
    // several brokers need one (refused when trusting both for everything).
    assert!(BrokerClient::new(&as_a).trusting(&trusted).is_err());
    // A key the binding leaves out is not asked for from anyone.
    let e = acquire_all(&[(client(&b_url), "contribution-a".into())]).unwrap_err();
    assert!(
        e.message.contains("binds contribution-a to no key broker"),
        "{e}"
    );
    // The honest path: B's keys from B's broker.
    let got = acquire_all(&[
        (client(&b_url), "dataset-b".into()),
        (client(&b_url), "contribution-b".into()),
    ])
    .unwrap();
    assert_eq!(got[1].1, b"hospital-b-output-key".to_vec());
}

/// Each owner's broker releases that owner's keys, and both are acquired in
/// one workload, each only from its own broker.
#[test]
fn two_owner_brokers_each_release_own_asset() {
    let (a_url, a_pin) = owner_broker(
        "hospital-a-broker",
        &[
            ("dataset-a", b"hospital-a-dataset-key"),
            ("contribution-a", b"hospital-a-output-key"),
        ],
    );
    let (b_url, b_pin) = owner_broker(
        "hospital-b-broker",
        &[
            ("dataset-b", b"hospital-b-dataset-key"),
            ("contribution-b", b"hospital-b-output-key"),
        ],
    );
    let trusted = BTreeMap::from([
        ("hospital-a-broker".to_string(), a_pin),
        ("hospital-b-broker".to_string(), b_pin),
    ]);
    let binding: BTreeMap<String, String> = [
        ("dataset-a", "hospital-a-broker"),
        ("contribution-a", "hospital-a-broker"),
        ("dataset-b", "hospital-b-broker"),
        ("contribution-b", "hospital-b-broker"),
    ]
    .iter()
    .map(|(k, b)| (k.to_string(), b.to_string()))
    .collect();
    let client = |url: &str| {
        BrokerClient::new(url)
            .trusting_per_asset(&trusted, &binding)
            .unwrap()
    };
    let got = acquire_all(&[
        (client(&a_url), "dataset-a".into()),
        (client(&b_url), "dataset-b".into()),
        (client(&a_url), "contribution-a".into()),
        (client(&b_url), "contribution-b".into()),
    ])
    .unwrap();
    let got: BTreeMap<String, Vec<u8>> = got.into_iter().collect();
    assert_eq!(got["dataset-a"], b"hospital-a-dataset-key".to_vec());
    assert_eq!(got["dataset-b"], b"hospital-b-dataset-key".to_vec());
    assert_eq!(got["contribution-a"], b"hospital-a-output-key".to_vec());
    assert_eq!(got["contribution-b"], b"hospital-b-output-key".to_vec());
    // B's key asked of A's broker (which does not hold it) is refused by
    // the broker; even if it held one, its grant would name A.
    assert!(acquire_all(&[(client(&a_url), "contribution-b".into())]).is_err());
    // A binding to a broker whose key is not pinned is refused up front.
    let mut unpinned = binding.clone();
    unpinned.insert("dataset-c".into(), "hospital-c-broker".into());
    let e = BrokerClient::new(&a_url)
        .trusting_per_asset(&trusted, &unpinned)
        .unwrap_err();
    assert!(e.message.contains("not pinned"), "{e}");
}
