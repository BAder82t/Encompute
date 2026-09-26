//! Adapters: each global update creates a new adapter asset, recorded by
//! the coordinator in a signed record naming its parents (the previous
//! adapter, the aggregation round, the base model and the datasets), so
//! lineage is never rewritten. Its release policy is derived from every
//! parent: it is exportable only if every parent permits it.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use encompute_ir::confidentiality::{AssetKind, Release};
use encompute_ir::{Code, Error, Program, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::{hex, unhex};

use crate::spec::TrainingSpec;
use crate::tagged;

pub const ADAPTER_VERSION: u32 = 1;
const RECORD: &str = "encompute.adapter-record.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterRecord {
    pub version: u32,
    pub project: String,
    /// E.g. `adapter-3`; never reused.
    pub adapter_id: String,
    pub round: u32,
    /// The adapter this update was applied to (none for the first).
    pub previous: Option<String>,
    pub training_spec_id: String,
    pub run_id: String,
    /// The aggregation receipt whose (noised) aggregate was applied.
    pub aggregation_receipt_id: String,
    pub aggregation_output: String,
    /// SHA-256 of the adapter weights (hex): a commitment, not the weights.
    pub adapter_digest: String,
    pub base_model: String,
    pub datasets: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAdapterRecord {
    pub record: AdapterRecord,
    pub signer_key: String,
    pub signature: String,
}

fn err(m: impl Into<String>) -> Error {
    Error::new(Code::TrainingSpec, m)
}

impl AdapterRecord {
    /// A record for `spec`'s adapter at `round`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        spec: &TrainingSpec,
        run_id: &str,
        round: u32,
        previous: Option<&str>,
        aggregation_receipt_id: &str,
        aggregation_output: &str,
        adapter_digest: &str,
    ) -> Result<Self> {
        Ok(Self {
            version: ADAPTER_VERSION,
            project: spec.project.clone(),
            adapter_id: format!("adapter-{round}"),
            round,
            previous: previous.map(str::to_owned),
            training_spec_id: spec.id()?,
            run_id: run_id.to_owned(),
            aggregation_receipt_id: aggregation_receipt_id.to_owned(),
            aggregation_output: aggregation_output.to_owned(),
            adapter_digest: adapter_digest.to_owned(),
            base_model: spec.base_model.asset_id.clone(),
            datasets: spec.datasets.iter().map(|d| d.asset_id.clone()).collect(),
        })
    }

    pub fn sign(self, key: &SigningKey) -> Result<SignedAdapterRecord> {
        let sig = key.sign(&tagged(RECORD, &[&canonical_json(&self)?]));
        Ok(SignedAdapterRecord {
            record: self,
            signer_key: hex(&key.verifying_key().to_bytes()),
            signature: hex(&sig.to_bytes()),
        })
    }
}

impl SignedAdapterRecord {
    /// Checks the signature (by `trusted`, if given).
    pub fn verify(&self, trusted: Option<&str>) -> Result<()> {
        if trusted.is_some_and(|t| t != self.signer_key) {
            return Err(err("the adapter record was signed by an untrusted key"));
        }
        let key = unhex(&self.signer_key)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| VerifyingKey::from_bytes(&b).ok())
            .ok_or_else(|| err("malformed adapter record key"))?;
        let sig = unhex(&self.signature)
            .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
            .ok_or_else(|| err("malformed adapter record signature"))?;
        key.verify_strict(&tagged(RECORD, &[&canonical_json(&self.record)?]), &sig)
            .map_err(|_| err("the adapter record's signature is invalid"))
    }

    pub fn id(&self) -> Result<String> {
        Ok(crate::tagged_hex(RECORD, &[&canonical_json(self)?]))
    }
}

/// The adapter's release: the most restrictive of what each parent (the
/// model, the datasets and the gradients aggregated) permits for adapters
/// derived from it (its `derive [adapter ...]` permission, else its own
/// release). Returns the release and the parents that restrict it.
pub fn adapter_policy(program: &Program, spec: &TrainingSpec) -> Result<(Release, Vec<String>)> {
    let c = program
        .confidentiality()
        .ok_or_else(|| err("the training program declares no parties or assets"))?;
    let mut parents = vec![spec.base_model.asset_id.clone()];
    for d in &spec.datasets {
        parents.push(d.asset_id.clone());
        parents.push(d.gradient_asset.clone());
    }
    let mut release = Release::Public;
    let mut restricting = vec![];
    for p in &parents {
        let a = c
            .asset(p)
            .ok_or_else(|| err(format!("{p} is not declared by the training program")))?;
        let allowed = a
            .policy
            .derive
            .get(&AssetKind::Adapter)
            .map(|d| d.release)
            .unwrap_or(a.policy.release);
        if allowed != Release::Public {
            restricting.push(format!("{p} ({})", allowed.name()));
        }
        release = release.min(allowed);
    }
    Ok((release, restricting))
}

/// Refuses a public export unless every parent permits one.
pub fn check_export(program: &Program, spec: &TrainingSpec, adapter_id: &str) -> Result<()> {
    let (release, restricting) = adapter_policy(program, spec)?;
    if release == Release::Public {
        return Ok(());
    }
    Err(Error::new(
        Code::ExportDenied,
        format!(
            "EXPORT DENIED: {adapter_id} inherits release restrictions from:\n  {}",
            restricting.join("\n  ")
        ),
    ))
}
