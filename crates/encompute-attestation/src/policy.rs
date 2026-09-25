use std::fmt;

use encompute_ir::{Code, Result};
use serde::{Deserialize, Serialize};

use crate::binding::WorkloadBinding;
use crate::util::{err, hex, Digest32};

pub const POLICY_VERSION: u32 = 1;

/// The trusted execution environment evidence came from. Hardware, not
/// cloud: a Confidential Space VM runs on AMD SEV or Intel TDX.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeeKind {
    /// Development only: software, no hardware protection.
    Mock,
    AmdSev,
    AmdSevSnp,
    IntelTdx,
    NvidiaConfidentialGpu,
    Other(String),
}

impl fmt::Display for TeeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TeeKind::Mock => f.write_str("mock (development only)"),
            TeeKind::AmdSev => f.write_str("AMD SEV"),
            TeeKind::AmdSevSnp => f.write_str("AMD SEV-SNP"),
            TeeKind::IntelTdx => f.write_str("Intel TDX"),
            TeeKind::NvidiaConfidentialGpu => f.write_str("NVIDIA confidential GPU"),
            TeeKind::Other(s) => write!(f, "other ({s})"),
        }
    }
}

/// How current the platform's trusted computing base is, normalized from
/// provider claims. Ordered: `Unknown < OutOfDate < Supported < Current`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcbStatus {
    Unknown,
    OutOfDate,
    Supported,
    Current,
}

impl fmt::Display for TcbStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TcbStatus::Unknown => "unknown",
            TcbStatus::OutOfDate => "out_of_date",
            TcbStatus::Supported => "supported",
            TcbStatus::Current => "current",
        })
    }
}

/// Whether evidence can protect anything. Mock evidence is always
/// `DevelopmentOnly`, whatever it claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    DevelopmentOnly,
    Production,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugPolicy {
    #[default]
    Forbidden,
    Allowed,
}

/// GPU attestation claims, for composing CPU and GPU TEEs later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGpu {
    /// Confidential-computing mode is on for every attached GPU.
    pub confidential_mode: bool,
    pub models: Vec<String>,
}

/// Provider-neutral claims about a verified workload. Nothing
/// provider-specific appears here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedWorkload {
    /// The provider that verified the evidence (e.g. `gcp-confidential-space`).
    pub provider: String,
    pub security: Security,
    pub tee_kind: TeeKind,
    /// Digest of what runs (for containers, of the image digest).
    pub workload_measurement: Digest32,
    /// Container image digest (`sha256:…`), where the provider measures one.
    pub image_digest: Option<String>,
    pub debug_enabled: bool,
    pub tcb_status: TcbStatus,
    /// Digest of the raw evidence bytes.
    pub evidence_digest: Digest32,
    /// The binding the evidence commits to.
    pub binding: WorkloadBinding,
    pub issued_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub gpu: Option<VerifiedGpu>,
}

impl VerifiedWorkload {
    pub fn evidence_digest_hex(&self) -> String {
        hex(&self.evidence_digest)
    }
}

fn default_max_age() -> u64 {
    600
}

/// Where a computation may run and what exactly may run there. Checked
/// against [`VerifiedWorkload`] claims. Distinct from the confidentiality
/// policy, which says who owns data and how it may be released.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationPolicy {
    pub version: u32,
    /// Lowercase hex `ExecutionSpecId` the workload must bind.
    pub execution_spec_id: String,
    /// Lowercase hex `PolicyId` the workload must bind (absent: the
    /// workload must bind none).
    #[serde(default)]
    pub policy_id: Option<String>,
    /// If set, the artifact digest the workload must bind.
    #[serde(default)]
    pub artifact_digest: Option<String>,
    pub allowed_tee: Vec<TeeKind>,
    /// Exact image digests (`sha256:…`) allowed to run.
    pub allowed_images: Vec<String>,
    #[serde(default)]
    pub debug: DebugPolicy,
    pub minimum_tcb: TcbStatus,
    #[serde(default)]
    pub require_gpu_attestation: bool,
    /// Accept development-only (mock) evidence. Never in production.
    #[serde(default)]
    pub allow_development: bool,
    /// Evidence older than this (seconds since issue) is stale.
    #[serde(default = "default_max_age")]
    pub max_evidence_age_secs: u64,
}

impl AttestationPolicy {
    /// The defaults for `spec`: no debug, a supported TCB, production
    /// evidence only; TEEs and images must still be listed.
    pub fn new(execution_spec_id: &str, policy_id: Option<&str>) -> Self {
        Self {
            version: POLICY_VERSION,
            execution_spec_id: execution_spec_id.to_owned(),
            policy_id: policy_id.map(str::to_owned),
            artifact_digest: None,
            allowed_tee: Vec::new(),
            allowed_images: Vec::new(),
            debug: DebugPolicy::Forbidden,
            minimum_tcb: TcbStatus::Supported,
            require_gpu_attestation: false,
            allow_development: false,
            max_evidence_age_secs: default_max_age(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        let bad = |m: &str| {
            Err(err(
                Code::WorkloadPolicy,
                format!("attestation policy: {m}"),
            ))
        };
        if self.version != POLICY_VERSION {
            return bad(&format!("version {}", self.version));
        }
        if self.allowed_tee.is_empty() {
            return bad("no TEE is allowed");
        }
        if self.allowed_images.is_empty() {
            return bad("no workload image is allowed");
        }
        if self.allowed_tee.contains(&TeeKind::Mock) && !self.allow_development {
            return bad("the mock TEE needs allow_development");
        }
        Ok(())
    }

    /// Every condition, in order; the first failure is the error.
    pub fn check(&self, w: &VerifiedWorkload) -> Result<()> {
        self.validate()?;
        let deny = |m: String| Err(err(Code::WorkloadPolicy, m));
        if w.security == Security::DevelopmentOnly && !self.allow_development {
            return deny(format!(
                "{} evidence is development-only and this policy requires production evidence",
                w.provider
            ));
        }
        if !self.allowed_tee.contains(&w.tee_kind) {
            return deny(format!("TEE {} is not allowed", w.tee_kind));
        }
        match &w.image_digest {
            Some(i) if self.allowed_images.contains(i) => {}
            Some(i) => return deny(format!("workload image {i} is not allowed")),
            None => return deny("the evidence measures no workload image".into()),
        }
        if w.debug_enabled && self.debug == DebugPolicy::Forbidden {
            return deny("the workload runs with debugging enabled".into());
        }
        if w.tcb_status < self.minimum_tcb {
            return deny(format!(
                "TCB status {} is below the required {}",
                w.tcb_status, self.minimum_tcb
            ));
        }
        if self.require_gpu_attestation && !w.gpu.as_ref().is_some_and(|g| g.confidential_mode) {
            return deny("no confidential GPU was attested".into());
        }
        let b = &w.binding;
        if b.execution_spec_id != self.execution_spec_id {
            return deny(format!(
                "the workload is bound to execution spec {}, not {}",
                b.execution_spec_id, self.execution_spec_id
            ));
        }
        if b.policy_id != self.policy_id {
            return deny(format!(
                "the workload is bound to policy {}, not {}",
                b.policy_id.as_deref().unwrap_or("(none)"),
                self.policy_id.as_deref().unwrap_or("(none)")
            ));
        }
        if let Some(a) = &self.artifact_digest {
            if &b.artifact_digest != a {
                return deny(format!(
                    "the workload is bound to artifact {}, not {a}",
                    b.artifact_digest
                ));
            }
        }
        Ok(())
    }
}
