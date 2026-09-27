//! Shared fixtures for the fuzz targets and the seed-corpus generator.

use encompute_backend::{CkksClient, MockClient, MockConfig};
use encompute_evaluator::engine::{Engine, Local};
use encompute_evaluator::{BackendKind, Backends, EvaluatorSession, Ids};
use encompute_protocol::{sha256_hex, Envelope, Header, Kind};

/// Separates the parts of a multi-part input (files, headers).
pub const SEP: &[u8] = b"\n--8<--\n";

/// Splits `data` at [`SEP`], at most `n` parts.
pub fn parts(data: &[u8], n: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = data;
    while out.len() + 1 < n {
        match rest.windows(SEP.len()).position(|w| w == SEP) {
            Some(i) => {
                out.push(&rest[..i]);
                rest = &rest[i + SEP.len()..];
            }
            None => break,
        }
    }
    out.push(rest);
    out
}

/// Joins parts with [`SEP`] (the inverse of [`parts`]).
pub fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.join(SEP)
}

/// A small CKKS program: `dot(w, x)` over a secret 4-vector.
pub const PROGRAM: &str = "encompute 0.1\nprogram w precision 0.001\n\
%0 = input \"x\" [-1.0, 1.0] : secret vector<4>\n\
%1 = const [0.5, -1.0, 0.25, 2.0] : public vector<4>\n\
%2 = dot %1, %0 : secret scalar\n\
output \"d\" = %2\n";

/// Fixed seeds: fuzzing must be deterministic.
pub const SERVICE_SEED: [u8; 32] = [7; 32];
pub const PARTY_SEED: [u8; 32] = [9; 32];
pub const SEAL_KEY: [u8; 32] = [11; 32];

/// An in-process mock evaluator with [`PROGRAM`] loaded, and valid key and
/// input envelopes for it.
pub struct MockEvaluator {
    pub engine: Local,
    pub program_id: String,
    pub key_id: String,
    pub keys: Vec<u8>,
    pub inputs: Vec<u8>,
}

fn header(kind: Kind, ids: &Ids, key_id: &str) -> Header {
    Header {
        kind,
        scheme: "CKKS".into(),
        backend: "mock".into(),
        backend_version: "0".into(),
        parameter_set_id: ids.parameter_set_id.clone(),
        program_id: matches!(kind, Kind::Inputs).then(|| ids.program_id.clone()),
        key_id: Some(key_id.into()),
        items: vec![],
    }
}

pub fn mock_evaluator() -> MockEvaluator {
    let p = encompute_ir::parse(PROGRAM).expect("valid program");
    let local = EvaluatorSession::new(p, BackendKind::Mock).expect("mock session");
    let c = local.compiled().ckks().expect("CKKS program");
    let ids = local.ids().clone();
    let client = MockClient::new(
        &c.params,
        &c.plan.rotations,
        MockConfig {
            seed: 5,
            noise: false,
        },
    );
    let payload = client.evaluation_keys().expect("keys");
    let key_id = sha256_hex(&payload);
    let keys = Envelope::new(
        header(Kind::EvaluationKeys, &ids, &key_id),
        vec![("keys".into(), payload)],
    )
    .encode();
    let ct = client
        .encrypt(&c.plan.encode_input(0, &[0.5, 0.25, -0.5, 1.0]))
        .expect("encrypt");
    let inputs =
        Envelope::new(header(Kind::Inputs, &ids, &key_id), vec![("x".into(), ct)]).encode();
    let engine = Local::new(Backends::MOCK);
    let info = engine.add_program(PROGRAM).expect("program loads");
    assert_eq!(info.program_id, ids.program_id);
    engine
        .register_keys(&ids.program_id, &keys)
        .expect("keys load");
    MockEvaluator {
        engine,
        program_id: ids.program_id,
        key_id,
        keys,
        inputs,
    }
}
