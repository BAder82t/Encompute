//! Demo workloads shared by the mock and OpenFHE tests.
#![allow(dead_code)] // each test binary uses a subset

use encompute_backend::rng::Rng;
use encompute_ir::{Builder, Program, Range, Shape};

pub fn logistic(features: usize, seed: u64) -> Program {
    let mut rng = Rng::new(seed);
    let mut b = Builder::new("logistic", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(features), Range::new(-1.0, 1.0))
        .unwrap();
    let w: Vec<f64> = (0..features).map(|_| rng.uniform(-0.4, 0.4)).collect();
    let w = b.constant(Shape::Vector(features), w).unwrap();
    let bias = b.constant(Shape::Scalar, vec![0.25]).unwrap();
    let z = b.dot(w, x).unwrap();
    let z = b.add(z, bias).unwrap();
    let y = b.sigmoid(z).unwrap();
    b.output("score", y).unwrap();
    b.finish().unwrap()
}

pub fn similarity(dim: usize, docs: usize, seed: u64) -> Program {
    let mut rng = Rng::new(seed);
    let mut m = Vec::with_capacity(dim * docs);
    for _ in 0..docs {
        let row: Vec<f64> = (0..dim).map(|_| rng.normal()).collect();
        let norm = row.iter().map(|x| x * x).sum::<f64>().sqrt();
        m.extend(row.iter().map(|x| x / norm));
    }
    let mut b = Builder::new("similarity", 1e-3).unwrap();
    let q = b
        .input("q", Shape::Vector(dim), Range::new(-1.0, 1.0))
        .unwrap();
    let m = b.constant(Shape::Matrix(docs, dim), m).unwrap();
    let s = b.matvec(m, q).unwrap();
    b.output("scores", s).unwrap();
    b.finish().unwrap()
}

use encompute_backend::{CkksClient, CkksEvaluator, MockClient, MockConfig, MockEvaluator};
use encompute_ckks::{CkksParams, CkksPlan};
use encompute_evaluator::{evaluate_encrypted, BackendKind, CompiledProgram, EvaluatorSession};
use encompute_ir::{Inputs, Outputs, Result};
use encompute_runtime::ClientSession;

/// Run a plan on the mock at the plan level (no envelopes), with explicit
/// parameters, rotation keys and noise.
pub fn mock_run(
    plan: &CkksPlan,
    params: &CkksParams,
    rotations: &[u32],
    noise: bool,
    p: &Program,
    inputs: &Inputs,
) -> Result<Outputs> {
    let cfg = MockConfig { seed: 1, noise };
    let client = MockClient::new(params, rotations, cfg.clone());
    let ev = MockEvaluator::new(params, &client.evaluation_keys()?, cfg)?;
    let cts = plan
        .inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| {
            ev.load_ciphertext(&client.encrypt(&plan.encode_input(i, &inputs[&inp.name]))?)
        })
        .collect::<Result<Vec<_>>>()?;
    let outs = evaluate_encrypted(&ev, plan, p, cts)?;
    plan.outputs
        .iter()
        .zip(&outs)
        .map(|(o, ct)| {
            let mut v = client.decrypt(&ev.store_ciphertext(ct)?)?;
            v.truncate(o.len);
            Ok((o.name.clone(), v))
        })
        .collect()
}

/// Client and evaluator sessions for `p` (mock), keys registered.
pub fn mock_sessions(
    p: &Program,
    client_params: Option<&CkksParams>,
    seed: u64,
) -> (ClientSession, EvaluatorSession) {
    let mut ev = EvaluatorSession::new(p.clone(), BackendKind::Mock).unwrap();
    let mut c = ev.compiled().clone();
    if let (Some(params), CompiledProgram::Approx(a)) = (client_params, &mut c) {
        a.params = params.clone();
    }
    let client = ClientSession::generate(ev.ids().clone(), &c, BackendKind::Mock, seed).unwrap();
    ev.register_keys(client.evaluation_keys().unwrap()).unwrap();
    (client, ev)
}

/// Client and evaluator sessions for `p` on OpenFHE, keys registered.
#[cfg(feature = "openfhe")]
pub fn openfhe_sessions(p: &Program) -> (ClientSession, EvaluatorSession) {
    let mut ev = EvaluatorSession::new(p.clone(), BackendKind::OpenFhe).unwrap();
    let client =
        ClientSession::generate(ev.ids().clone(), ev.compiled(), BackendKind::OpenFhe, 0).unwrap();
    ev.register_keys(client.evaluation_keys().unwrap()).unwrap();
    (client, ev)
}
