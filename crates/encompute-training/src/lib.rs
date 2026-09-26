//! Confidential fine-tuning (ADR-016). PyTorch does the computation;
//! Encompute controls who may hold what: the training specification every
//! worker attests to, sealed models, datasets, checkpoints and adapters
//! whose keys only attested workloads receive, adapter lineage, export
//! control derived from every parent, and checkpoint resume that can
//! never roll back spent privacy budget.

pub mod adapter;
pub mod checkpoint;
pub mod hf;
pub mod layout;
pub mod seal;
pub mod spec;
pub mod worker;

pub use adapter::{adapter_policy, check_export, AdapterRecord, SignedAdapterRecord};
pub use checkpoint::{resume, seal_checkpoint, CheckpointHeader, ResumeExpectation};
pub use hf::{HfModelPackage, LibraryVersions, PackageFile};
pub use layout::{tensor_manifest, AdapterLayout, LayoutEntry, TensorEntry, LAYOUT_VERSION};
pub use seal::{open, open_asset, peek, seal, seal_asset, sha256_hex, AssetHeader};
pub use spec::{
    DatasetCommitment, DpSgdConfig, ModelCommitment, PeftConfig, TextPreprocessing, TrainingConfig,
    TrainingSpec,
};
pub use worker::{SignedWorkerEvidence, WorkerEvidence, WORKER_EVIDENCE_VERSION};

use sha2::{Digest, Sha256};

/// `SHA256(domain || 0x00 || len-prefixed parts)`.
pub(crate) fn tagged(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}

pub(crate) fn tagged_hex(domain: &str, parts: &[&[u8]]) -> String {
    encompute_verification::hex(&tagged(domain, parts))
}
