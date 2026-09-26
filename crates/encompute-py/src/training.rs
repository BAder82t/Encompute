//! Native helpers for confidential fine-tuning (`encompute.torch`): the
//! training spec, attested key acquisition, sealed assets and checkpoints,
//! adapter records and export control. Keys cross into Python only inside
//! the (attested) worker process that acquired them.

use std::path::Path;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use encompute_ir::{Code, Error};
use encompute_runtime::attestation::mock::MockHardware;
use encompute_runtime::attestation::WorkloadSession;
use encompute_runtime::keybroker::{acquire_keys, BrokerClient};
use encompute_runtime::training::{self, CheckpointHeader, ResumeExpectation, TrainingSpec};
use encompute_runtime::verification::EvaluatorSigner;

use crate::err;

fn bad(m: impl Into<String>) -> PyErr {
    err(Error::new(Code::BadInput, m))
}

fn spec(json: &str) -> PyResult<TrainingSpec> {
    let s: TrainingSpec = serde_json::from_str(json).map_err(|e| {
        err(Error::new(
            Code::TrainingSpec,
            format!("training spec: {e}"),
        ))
    })?;
    s.validate().map_err(err)?;
    Ok(s)
}

fn seed32(path: &str) -> PyResult<[u8; 32]> {
    std::fs::read(path)
        .map_err(|e| bad(format!("{path}: {e}")))?
        .try_into()
        .map_err(|_| bad(format!("{path}: a key or seed file is 32 bytes")))
}

fn bytes(py: Python<'_>, b: &[u8]) -> Py<PyBytes> {
    PyBytes::new(py, b).unbind()
}

/// The TrainingSpecId (hex) of a validated spec.
#[pyfunction]
pub fn training_spec_id(spec_json: &str) -> PyResult<String> {
    spec(spec_json)?.id().map_err(err)
}

/// The TrainingRunId (hex) of one execution of a spec.
#[pyfunction]
pub fn training_run_id(spec_json: &str, nonce: &str) -> PyResult<String> {
    spec(spec_json)?.run_id(nonce).map_err(err)
}

/// The attestation policy (JSON) owners release keys under.
#[pyfunction]
pub fn training_attestation_policy(
    spec_json: &str,
    image: &str,
    development: bool,
) -> PyResult<String> {
    let p = spec(spec_json)?
        .attestation_policy(image, development)
        .map_err(err)?;
    Ok(serde_json::to_string_pretty(&p).expect("JSON"))
}

/// The attestation policy DP-SGD contributions must satisfy: a workload
/// running this training code (by digest) in an approved image, bound to
/// the approved plan and policy, holding the contribution key. (The plan,
/// not the training spec, because the spec binds the aggregation spec.)
#[pyfunction]
pub fn contribution_attestation_policy(
    plan_id: &str,
    policy_id: Option<&str>,
    code_digest: &str,
    image: &str,
    development: bool,
) -> PyResult<String> {
    use encompute_runtime::attestation::{AttestationPolicy, TeeKind};
    let mut p = AttestationPolicy::new(plan_id, policy_id);
    p.artifact_digest = Some(code_digest.to_owned());
    p.allowed_images = vec![image.to_owned()];
    p.allowed_tee = if development {
        vec![TeeKind::Mock]
    } else {
        vec![TeeKind::IntelTdx, TeeKind::AmdSevSnp]
    };
    p.allow_development = development;
    p.validate().map_err(err)?;
    Ok(serde_json::to_string_pretty(&p).expect("JSON"))
}

/// Inside a DP-SGD worker (development attestation): an attestation record
/// that this workload, holding `identity` (its contribution key), runs
/// `code_digest` for `plan_id`.
#[pyfunction]
pub fn attest_contribution(
    plan_id: &str,
    policy_id: Option<&str>,
    code_digest: &str,
    identity: &str,
    mock_seed: &str,
    image: &str,
) -> PyResult<String> {
    use encompute_runtime::attestation::{AttestationChallenge, AttestationRecord, Attester};
    let attester = MockHardware::from_seed(&seed32(mock_seed)?).attester(image);
    let signer = EvaluatorSigner::from_seed(&seed32(identity)?);
    let now = encompute_runtime::attestation::unix_now();
    let challenge =
        AttestationChallenge::new("encompute.contribution", now, 24 * 3600).map_err(err)?;
    let binding = WorkloadSession::new(&signer.identity()).binding(
        &challenge,
        plan_id,
        policy_id,
        code_digest,
    );
    let record = AttestationRecord::new(attester.attest(&challenge, &binding).map_err(err)?);
    Ok(String::from_utf8(record.to_bytes().map_err(err)?).expect("JSON"))
}

/// Validates a Hugging Face model package manifest (JSON) and returns its
/// ID (hex; shown as `enchf1:`).
#[pyfunction]
pub fn hf_package_id(manifest_json: &str) -> PyResult<String> {
    let p: training::HfModelPackage = serde_json::from_str(manifest_json).map_err(|e| {
        err(Error::new(
            Code::ModelPackage,
            format!("model package: {e}"),
        ))
    })?;
    p.id().map_err(err)
}

/// Refuses a `model.safetensors.index.json` naming anything but the
/// package's own safetensors files (`files`: a JSON list of names).
#[pyfunction]
pub fn hf_check_index(index_json: &str, files_json: &str) -> PyResult<()> {
    let bad = |e: serde_json::Error| err(Error::new(Code::ModelPackage, format!("index: {e}")));
    let index: serde_json::Value = serde_json::from_str(index_json).map_err(bad)?;
    let files: Vec<String> = serde_json::from_str(files_json).map_err(bad)?;
    training::hf::check_index(&index, &files).map_err(err)
}

/// The tokenizer digest a manifest's files imply (before validation).
#[pyfunction]
pub fn hf_tokenizer_digest(manifest_json: &str) -> PyResult<String> {
    let p: training::HfModelPackage = serde_json::from_str(manifest_json).map_err(|e| {
        err(Error::new(
            Code::ModelPackage,
            format!("model package: {e}"),
        ))
    })?;
    Ok(p.expected_tokenizer_digest())
}

/// Refuses a file that may not enter a model package (remote code,
/// pickled weights, anything unknown).
#[pyfunction]
pub fn hf_check_file(path: &str) -> PyResult<()> {
    training::hf::check_file(path).map_err(err)
}

/// Refuses a `config.json` naming custom code or an unsupported
/// architecture; returns its model type.
#[pyfunction]
pub fn hf_check_config(config_json: &str) -> PyResult<String> {
    let v: serde_json::Value = serde_json::from_str(config_json)
        .map_err(|e| err(Error::new(Code::ModelPackage, format!("config.json: {e}"))))?;
    training::hf::check_config(&v).map_err(err)
}

/// Keys by asset, and the attestation record.
type Acquired = (Vec<(String, Py<PyBytes>)>, String);

/// Inside the worker: attest to the broker as this training spec's
/// workload and receive `assets`' keys, sealed to this session. Returns
/// `({asset: key}, attestation_record_json)`. `identity` is the party's
/// key file (the attestation binds the participant); the mock attester
/// (development only) signs with `mock_seed` claiming `image`.
#[pyfunction]
pub fn acquire_training_keys(
    py: Python<'_>,
    spec_json: &str,
    broker: &str,
    assets: Vec<String>,
    identity: &str,
    mock_seed: &str,
    image: &str,
) -> PyResult<Acquired> {
    let s = spec(spec_json)?;
    let attester = MockHardware::from_seed(&seed32(mock_seed)?).attester(image);
    let signer = EvaluatorSigner::from_seed(&seed32(identity)?);
    let session = WorkloadSession::new(&signer.identity());
    let requests: Vec<_> = assets
        .iter()
        .map(|a| (BrokerClient::new(broker), a.clone()))
        .collect();
    let got = acquire_keys(
        &attester,
        &session,
        &s.id().map_err(err)?,
        s.policy_id.as_deref(),
        &s.code_digest,
        &requests,
    )
    .map_err(err)?;
    let record = got
        .first()
        .map(|k| k.record.to_bytes())
        .transpose()
        .map_err(err)?
        .map(|b| String::from_utf8(b).expect("JSON"))
        .unwrap_or_default();
    Ok((
        got.iter()
            .map(|k| (k.asset_id.clone(), bytes(py, &k.key)))
            .collect(),
        record,
    ))
}

#[pyfunction]
pub fn sha256_hex(data: &[u8]) -> String {
    training::sha256_hex(data)
}

/// Seals an asset under `key`, committing to its digest.
#[pyfunction]
pub fn seal_asset(
    py: Python<'_>,
    key: &[u8],
    kind: &str,
    project: &str,
    asset_id: &str,
    data: &[u8],
) -> PyResult<Py<PyBytes>> {
    Ok(bytes(
        py,
        &training::seal_asset(key, kind, project, asset_id, data).map_err(err)?,
    ))
}

/// Opens a sealed asset, checking it is the committed version.
#[pyfunction]
pub fn open_asset(
    py: Python<'_>,
    key: &[u8],
    sealed: &[u8],
    project: &str,
    asset_id: &str,
    digest: &str,
) -> PyResult<Py<PyBytes>> {
    Ok(bytes(
        py,
        &training::open_asset(key, sealed, project, asset_id, digest).map_err(err)?,
    ))
}

/// Each asset's current privacy-ledger position (JSON map).
#[pyfunction]
pub fn ledger_checkpoints(ledger_dir: &str, assets: Vec<String>) -> PyResult<String> {
    let mut m = std::collections::BTreeMap::new();
    for a in assets {
        let v =
            encompute_runtime::dp::ledger::read(&Path::new(ledger_dir).join(format!("{a}.ledger")))
                .map_err(err)?;
        m.insert(a, v.checkpoint().map_err(err)?);
    }
    Ok(serde_json::to_string(&m).expect("JSON"))
}

/// Seals a checkpoint (header JSON, payload).
#[pyfunction]
pub fn seal_checkpoint(
    py: Python<'_>,
    key: &[u8],
    header_json: &str,
    payload: &[u8],
) -> PyResult<Py<PyBytes>> {
    let h: CheckpointHeader = serde_json::from_str(header_json).map_err(|e| {
        err(Error::new(
            Code::Checkpoint,
            format!("checkpoint header: {e}"),
        ))
    })?;
    Ok(bytes(
        py,
        &training::seal_checkpoint(key, &h, payload).map_err(err)?,
    ))
}

/// Opens a checkpoint for resuming, refusing one from another project,
/// spec or policy, or one behind or ahead of the authoritative ledgers.
#[pyfunction]
#[pyo3(signature = (key, sealed, project, training_spec_id, policy_id, privacy_policy_id, ledger_dir, lost_rounds=Vec::new(), run_id=None))]
#[allow(clippy::too_many_arguments)]
pub fn resume_checkpoint(
    py: Python<'_>,
    key: &[u8],
    sealed: &[u8],
    project: &str,
    training_spec_id: &str,
    policy_id: Option<&str>,
    privacy_policy_id: Option<&str>,
    ledger_dir: &str,
    lost_rounds: Vec<String>,
    run_id: Option<&str>,
) -> PyResult<(String, Py<PyBytes>)> {
    let (h, payload) = training::resume(
        key,
        sealed,
        &ResumeExpectation {
            project,
            training_spec_id,
            policy_id,
            privacy_policy_id,
            ledger_dir: Path::new(ledger_dir),
            lost_rounds: &lost_rounds,
            run_id,
        },
    )
    .map_err(err)?;
    Ok((
        serde_json::to_string(&h).expect("JSON"),
        bytes(py, &payload),
    ))
}

/// The coordinator's signed record of a new adapter (JSON).
#[pyfunction]
#[pyo3(signature = (spec_json, run_id, round, previous, receipt_json, output, adapter_digest, key_file))]
#[allow(clippy::too_many_arguments)]
pub fn sign_adapter_record(
    spec_json: &str,
    run_id: &str,
    round: u32,
    previous: Option<&str>,
    receipt_json: &str,
    output: &str,
    adapter_digest: &str,
    key_file: &str,
) -> PyResult<String> {
    let s = spec(spec_json)?;
    let receipt: encompute_runtime::secagg::AggregationReceipt =
        serde_json::from_str(receipt_json).map_err(|e| bad(format!("aggregation receipt: {e}")))?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed32(key_file)?);
    let r = training::AdapterRecord::new(
        &s,
        run_id,
        round,
        previous,
        &receipt.id().map_err(err)?,
        output,
        adapter_digest,
    )
    .map_err(err)?
    .sign(&key)
    .map_err(err)?;
    Ok(serde_json::to_string_pretty(&r).expect("JSON"))
}

/// The digest of a canonical adapter layout (JSON: version and entries),
/// after validating it.
#[pyfunction]
pub fn layout_digest(layout_json: &str) -> PyResult<String> {
    let l: training::AdapterLayout = serde_json::from_str(layout_json).map_err(|e| {
        err(Error::new(
            Code::TrainingSpec,
            format!("adapter layout: {e}"),
        ))
    })?;
    l.digest().map_err(err)
}

/// Validates a canonical tensor file and returns its entries (JSON);
/// refuses pickles and malformed files before anything is loaded.
#[pyfunction]
pub fn tensor_manifest(data: &[u8]) -> PyResult<String> {
    Ok(serde_json::to_string(&training::tensor_manifest(data).map_err(err)?).expect("JSON"))
}

/// Refuses a public export unless every parent permits it (EXPORT DENIED,
/// naming the restricting parents).
#[pyfunction]
pub fn check_export(eir: &str, spec_json: &str, adapter_id: &str) -> PyResult<()> {
    let p = encompute_ir::parse(eir).map_err(err)?;
    training::check_export(&p, &spec(spec_json)?, adapter_id).map_err(err)
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(training_spec_id, m)?)?;
    m.add_function(wrap_pyfunction!(training_run_id, m)?)?;
    m.add_function(wrap_pyfunction!(training_attestation_policy, m)?)?;
    m.add_function(wrap_pyfunction!(contribution_attestation_policy, m)?)?;
    m.add_function(wrap_pyfunction!(attest_contribution, m)?)?;
    m.add_function(wrap_pyfunction!(hf_package_id, m)?)?;
    m.add_function(wrap_pyfunction!(hf_check_file, m)?)?;
    m.add_function(wrap_pyfunction!(hf_tokenizer_digest, m)?)?;
    m.add_function(wrap_pyfunction!(hf_check_index, m)?)?;
    m.add_function(wrap_pyfunction!(hf_check_config, m)?)?;
    m.add_function(wrap_pyfunction!(acquire_training_keys, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_hex, m)?)?;
    m.add_function(wrap_pyfunction!(seal_asset, m)?)?;
    m.add_function(wrap_pyfunction!(open_asset, m)?)?;
    m.add_function(wrap_pyfunction!(ledger_checkpoints, m)?)?;
    m.add_function(wrap_pyfunction!(seal_checkpoint, m)?)?;
    m.add_function(wrap_pyfunction!(resume_checkpoint, m)?)?;
    m.add_function(wrap_pyfunction!(sign_adapter_record, m)?)?;
    m.add_function(wrap_pyfunction!(check_export, m)?)?;
    m.add_function(wrap_pyfunction!(layout_digest, m)?)?;
    m.add_function(wrap_pyfunction!(tensor_manifest, m)?)?;
    Ok(())
}
