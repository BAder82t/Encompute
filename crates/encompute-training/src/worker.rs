//! Evidence from one confidential training worker: what it trained, where,
//! under which attestation, and what it produced, signed by the key its
//! attestation binds. It carries commitments only: no model, data or
//! gradient.
//!
//! A verifier anywhere can check it without any asset or key:
//! - the signature, by the attested session's signing key;
//! - that the attestation record binds that key, this training spec and
//!   this policy (and the record itself against the provider's roots and
//!   the training spec's attestation policy, with a `Verifier`);
//! - that the model package, dataset, layout, plan and policies are the
//!   training spec's, and so is the configuration it trained with;
//! - that it started from the spec's initial adapter in round 1 (later
//!   rounds: [`crate::adapter::check_input_adapter`] with the previous
//!   round's signed adapter record);
//! - that the output is the sealed artifact it commits to.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use encompute_attestation::AttestationRecord;
use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::{hex, unhex};

use crate::spec::TrainingSpec;
use crate::tagged;

/// 2: the input adapter, the configuration digest and the seed.
pub const WORKER_EVIDENCE_VERSION: u32 = 2;
const EVIDENCE: &str = "encompute.training-worker-evidence.v1";

fn err(m: impl Into<String>) -> Error {
    Error::new(Code::TrainingSpec, m)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerEvidence {
    pub version: u32,
    pub project: String,
    pub training_spec_id: String,
    pub run_id: String,
    pub plan_id: String,
    pub policy_id: Option<String>,
    pub privacy_policy_id: Option<String>,
    pub participant: String,
    pub round: u32,
    pub model_asset: String,
    /// `enchf1:` package ID (hex), for Hugging Face models.
    pub model_package_id: Option<String>,
    pub weights_digest: String,
    pub dataset_asset: String,
    pub dataset_digest: String,
    pub layout_digest: String,
    /// The adapter the worker trained from (`adapter-{round - 1}`) and
    /// SHA-256 of its plaintext.
    pub input_adapter: String,
    pub input_adapter_digest: String,
    /// [`TrainingSpec::config_digest`] of the configuration it trained
    /// with.
    pub config_digest: String,
    /// The round's training seed (organization mode's batch order; DP-SGD
    /// samples from the operating system instead).
    pub seed: u64,
    /// The measured image, as the attestation reports it (read from the
    /// worker's own attestation, never from its job description).
    pub image_digest: String,
    pub attestation_record_id: String,
    pub session_id: String,
    /// The sealed output's asset ID and SHA-256 of the sealed bytes.
    pub output_asset: String,
    pub output_commitment: String,
    /// SHA-256 over a fresh salt and the plaintext output: the worker can
    /// later show what it produced, nobody can guess it.
    pub step_commitment: String,
    /// `vmap` or `reference` per-example gradients (DP-SGD), else `none`.
    pub gradient_path: String,
    /// Exact library versions that ran.
    pub libraries: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWorkerEvidence {
    pub evidence: WorkerEvidence,
    pub signer_key: String,
    pub signature: String,
}

impl WorkerEvidence {
    pub fn sign(self, key: &SigningKey) -> Result<SignedWorkerEvidence> {
        let sig = key.sign(&tagged(EVIDENCE, &[&canonical_json(&self)?]));
        Ok(SignedWorkerEvidence {
            evidence: self,
            signer_key: hex(&key.verifying_key().to_bytes()),
            signature: hex(&sig.to_bytes()),
        })
    }
}

impl SignedWorkerEvidence {
    pub fn id(&self) -> Result<String> {
        Ok(crate::tagged_hex(EVIDENCE, &[&canonical_json(self)?]))
    }

    /// Checks the signature, and that the evidence answers to `spec` and to
    /// `record` (which must bind the signing key, the training spec and its
    /// policies). The record's own verification (provider roots, image,
    /// debug, TCB) is the caller's, with the spec's attestation policy.
    pub fn verify(&self, spec: &TrainingSpec, record: &AttestationRecord) -> Result<()> {
        let e = &self.evidence;
        if e.version != WORKER_EVIDENCE_VERSION {
            return Err(err(format!("worker evidence version {}", e.version)));
        }
        let key = unhex(&self.signer_key)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| VerifyingKey::from_bytes(&b).ok())
            .ok_or_else(|| err("malformed worker evidence key"))?;
        let sig = unhex(&self.signature)
            .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
            .ok_or_else(|| err("malformed worker evidence signature"))?;
        key.verify_strict(&tagged(EVIDENCE, &[&canonical_json(e)?]), &sig)
            .map_err(|_| err("the worker evidence signature is invalid"))?;
        let b = &record.evidence.binding;
        let spec_id = spec.id()?;
        let checks: [(&str, bool); 16] = [
            (
                "the attestation binds another signing key",
                b.evaluator_public_key == self.signer_key,
            ),
            (
                "the attestation is not for this training spec and participant",
                b.execution_spec_id == spec.participant_execution_id(&e.participant)?,
            ),
            (
                "the attestation binds another policy",
                b.policy_id == spec.policy_id,
            ),
            (
                "the attestation binds another privacy policy",
                b.privacy_policy_id == spec.privacy_policy_id,
            ),
            (
                "the attestation binds other training code",
                b.artifact_digest == spec.code_digest,
            ),
            (
                "another training configuration",
                e.config_digest == spec.config_digest()?,
            ),
            (
                "an input adapter that is not the previous round's",
                e.round > 0
                    && e.input_adapter == format!("adapter-{}", e.round - 1)
                    && (e.round > 1 || e.input_adapter_digest == spec.initial_adapter_digest),
            ),
            (
                "another attestation record",
                record.id()? == e.attestation_record_id,
            ),
            ("another session", record.session_id()? == e.session_id),
            ("another training spec", e.training_spec_id == spec_id),
            ("another project", e.project == spec.project),
            ("another plan", e.plan_id == spec.plan_id),
            (
                "other policies",
                e.policy_id == spec.policy_id && e.privacy_policy_id == spec.privacy_policy_id,
            ),
            ("another layout", e.layout_digest == spec.layout_digest),
            (
                "another model",
                e.model_asset == spec.base_model.asset_id
                    && e.weights_digest == spec.base_model.weights_digest
                    && e.model_package_id
                        == spec
                            .base_model
                            .huggingface
                            .as_ref()
                            .map(|p| p.id())
                            .transpose()?,
            ),
            (
                "a dataset the spec does not name for this participant",
                spec.datasets.iter().any(|d| {
                    d.asset_id == e.dataset_asset
                        && d.digest == e.dataset_digest
                        && d.owner == e.participant
                }),
            ),
        ];
        if let Some((what, _)) = checks.iter().find(|(_, ok)| !ok) {
            return Err(err(format!("worker evidence: {what}")));
        }
        if e.round == 0 || e.round > spec.config.rounds {
            return Err(err("worker evidence: a round outside the training spec"));
        }
        for d in [
            &e.output_commitment,
            &e.step_commitment,
            &e.input_adapter_digest,
        ] {
            if d.len() != 64 || !d.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(err("worker evidence: malformed commitment"));
            }
        }
        Ok(())
    }
}
