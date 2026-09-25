//! Development-only attestation: a software key stands in for a hardware
//! root of trust. Evidence is always [`Security::DevelopmentOnly`] and
//! [`TeeKind::Mock`]; production policies and brokers refuse it.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use encompute_ir::{Code, Result};
use encompute_verification::canonical::canonical_json;
use serde::{Deserialize, Serialize};

use crate::binding::{AttestationChallenge, WorkloadBinding};
use crate::policy::{Security, TcbStatus, TeeKind, VerifiedWorkload};
use crate::provider::{
    AttestationEvidence, AttestationProvider, Attester, CLOCK_SKEW_SECS, EVIDENCE_VERSION,
};
use crate::util::{
    check_hex, err, hex, random32, tagged, unix_now, EVIDENCE, MEASUREMENT, MOCK_CLAIMS,
};

pub const PROVIDER: &str = "mock";

/// The claims a mock "hardware root" signs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockClaims {
    /// Hex [`WorkloadBinding::hash`].
    pub binding_hash: String,
    pub image_digest: String,
    pub debug: bool,
    pub tcb: TcbStatus,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockToken {
    pub claims: MockClaims,
    /// Ed25519 over `SHA256("encompute.mock-attestation.v1" || 0x00 || claims)`.
    pub signature: String,
}

/// A stand-in hardware root of trust.
pub struct MockHardware {
    key: SigningKey,
}

impl MockHardware {
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(&random32(Code::Attestation)?))
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// An attester for a workload running `image_digest`.
    pub fn attester(&self, image_digest: &str) -> MockAttester {
        MockAttester {
            key: self.key.clone(),
            image_digest: image_digest.to_owned(),
            debug: false,
            tcb: TcbStatus::Current,
            issued_at: None,
            lifetime: 3600,
        }
    }

    /// Signs arbitrary claims (tests forge variants with it).
    pub fn sign(&self, claims: MockClaims) -> Result<MockToken> {
        let digest = tagged(MOCK_CLAIMS, &canonical_json(&claims)?);
        Ok(MockToken {
            claims,
            signature: hex(&self.key.sign(&digest).to_bytes()),
        })
    }
}

/// Produces mock evidence; builder methods describe the "platform".
pub struct MockAttester {
    key: SigningKey,
    image_digest: String,
    debug: bool,
    tcb: TcbStatus,
    issued_at: Option<u64>,
    lifetime: u64,
}

impl MockAttester {
    pub fn debug(mut self, on: bool) -> Self {
        self.debug = on;
        self
    }

    pub fn tcb(mut self, tcb: TcbStatus) -> Self {
        self.tcb = tcb;
        self
    }

    /// Fixes the issue time (default: now).
    pub fn issued_at(mut self, t: u64) -> Self {
        self.issued_at = Some(t);
        self
    }

    pub fn lifetime(mut self, secs: u64) -> Self {
        self.lifetime = secs;
        self
    }
}

impl Attester for MockAttester {
    fn provider(&self) -> &'static str {
        PROVIDER
    }

    fn attest(
        &self,
        _challenge: &AttestationChallenge,
        binding: &WorkloadBinding,
    ) -> Result<AttestationEvidence> {
        let issued_at = self.issued_at.unwrap_or_else(unix_now);
        let hw = MockHardware {
            key: self.key.clone(),
        };
        let token = hw.sign(MockClaims {
            binding_hash: binding.nonce()?,
            image_digest: self.image_digest.clone(),
            debug: self.debug,
            tcb: self.tcb,
            issued_at,
            expires_at: issued_at.saturating_add(self.lifetime),
        })?;
        Ok(AttestationEvidence {
            version: EVIDENCE_VERSION,
            provider: PROVIDER.into(),
            binding: binding.clone(),
            evidence: String::from_utf8(canonical_json(&token)?).expect("JSON is UTF-8"),
        })
    }
}

/// Verifies mock evidence against a known mock root key.
pub struct MockProvider {
    root: VerifyingKey,
}

impl MockProvider {
    pub fn new(root_public_key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            root: VerifyingKey::from_bytes(root_public_key)
                .map_err(|e| err(Code::Attestation, format!("mock root key: {e}")))?,
        })
    }
}

pub struct MockEvidence {
    binding: WorkloadBinding,
    token: MockToken,
    raw: String,
}

impl AttestationProvider for MockProvider {
    type Evidence = MockEvidence;

    fn name(&self) -> &'static str {
        PROVIDER
    }

    fn parse(&self, raw: &AttestationEvidence) -> Result<MockEvidence> {
        let token: MockToken = serde_json::from_str(&raw.evidence)
            .map_err(|e| err(Code::Attestation, format!("malformed mock evidence: {e}")))?;
        Ok(MockEvidence {
            binding: raw.binding.clone(),
            token,
            raw: raw.evidence.clone(),
        })
    }

    fn verify_claims(&self, e: &MockEvidence, now: Option<u64>) -> Result<VerifiedWorkload> {
        let c = &e.token.claims;
        let sig = check_hex(Code::Attestation, "mock signature", &e.token.signature, 64)?;
        let sig = Signature::from_slice(&sig)
            .map_err(|_| err(Code::Attestation, "malformed mock signature"))?;
        self.root
            .verify_strict(&tagged(MOCK_CLAIMS, &canonical_json(c)?), &sig)
            .map_err(|_| err(Code::Attestation, "mock evidence signature is invalid"))?;
        if c.binding_hash != e.binding.nonce()? {
            return Err(err(
                Code::Attestation,
                "the evidence does not commit to this workload binding",
            ));
        }
        if let Some(now) = now {
            if now >= c.expires_at {
                return Err(err(Code::Freshness, "the evidence has expired"));
            }
            if c.issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
                return Err(err(Code::Freshness, "the evidence is issued in the future"));
            }
        }
        let mut m = b"mock\0".to_vec();
        m.extend_from_slice(c.image_digest.as_bytes());
        Ok(VerifiedWorkload {
            provider: PROVIDER.into(),
            security: Security::DevelopmentOnly,
            tee_kind: TeeKind::Mock,
            workload_measurement: tagged(MEASUREMENT, &m),
            image_digest: Some(c.image_digest.clone()),
            debug_enabled: c.debug,
            tcb_status: c.tcb,
            evidence_digest: tagged(EVIDENCE, e.raw.as_bytes()),
            binding: e.binding.clone(),
            issued_at: Some(c.issued_at),
            expires_at: Some(c.expires_at),
            gpu: None,
        })
    }
}
