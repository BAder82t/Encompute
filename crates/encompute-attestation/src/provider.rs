use encompute_ir::{Code, Result};
use serde::{Deserialize, Serialize};

use crate::binding::{AttestationChallenge, WorkloadBinding};
use crate::policy::{AttestationPolicy, VerifiedWorkload};
use crate::util::{err, unix_now};

pub const EVIDENCE_VERSION: u32 = 1;

/// Tolerated clock difference between broker and evidence issuer.
pub const CLOCK_SKEW_SECS: u64 = 60;

/// Largest evidence envelope accepted (tokens are a few KiB).
pub const MAX_EVIDENCE_BYTES: usize = 64 << 10;

/// Evidence on the wire: which provider made it, the binding it claims to
/// commit to, and the provider's raw evidence (a signed token).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationEvidence {
    pub version: u32,
    pub provider: String,
    pub binding: WorkloadBinding,
    pub evidence: String,
}

impl AttestationEvidence {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encompute_verification::canonical::canonical_json(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(err(Code::Attestation, "attestation evidence is too large"));
        }
        let e: Self = serde_json::from_slice(bytes).map_err(|e| {
            err(
                Code::Attestation,
                format!("malformed attestation evidence: {e}"),
            )
        })?;
        if e.version != EVIDENCE_VERSION {
            return Err(err(
                Code::Attestation,
                format!("attestation evidence version {}", e.version),
            ));
        }
        e.binding.check_form()?;
        Ok(e)
    }
}

/// Verifies one kind of evidence. Implementations check the evidence's
/// signature and that it commits to its binding, and normalize its claims;
/// freshness and policy are checked the same way for every provider.
pub trait AttestationProvider {
    type Evidence;

    /// The provider name evidence envelopes carry.
    fn name(&self) -> &'static str;

    fn parse(&self, raw: &AttestationEvidence) -> Result<Self::Evidence>;

    /// Signature, binding commitment and claims. With `now`, expired
    /// evidence is refused; without, the evidence is checked as a
    /// historical record (receipt audit).
    fn verify_claims(
        &self,
        evidence: &Self::Evidence,
        now: Option<u64>,
    ) -> Result<VerifiedWorkload>;

    /// Full verification against a policy and a fresh challenge.
    fn verify(
        &self,
        evidence: &Self::Evidence,
        expected: &AttestationPolicy,
        challenge: &AttestationChallenge,
    ) -> Result<VerifiedWorkload> {
        let now = unix_now();
        let w = self.verify_claims(evidence, Some(now))?;
        check_freshness(&w, challenge, expected.max_evidence_age_secs, now)?;
        expected.check(&w)?;
        Ok(w)
    }
}

/// Object-safe form of [`AttestationProvider`], for registries.
pub trait DynProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn verify_raw(&self, raw: &AttestationEvidence, now: Option<u64>) -> Result<VerifiedWorkload>;
}

impl<P: AttestationProvider + Send + Sync> DynProvider for P {
    fn name(&self) -> &'static str {
        AttestationProvider::name(self)
    }

    fn verify_raw(&self, raw: &AttestationEvidence, now: Option<u64>) -> Result<VerifiedWorkload> {
        let w = self.verify_claims(&self.parse(raw)?, now)?;
        if w.binding != raw.binding {
            return Err(err(
                Code::Attestation,
                "the evidence does not commit to the binding it was sent with",
            ));
        }
        Ok(w)
    }
}

/// The evidence answers `challenge`, which is still open, and was produced
/// after it and recently.
pub fn check_freshness(
    w: &VerifiedWorkload,
    challenge: &AttestationChallenge,
    max_age: u64,
    now: u64,
) -> Result<()> {
    let stale = |m: &str| Err(err(Code::Freshness, m.to_owned()));
    if w.binding.challenge_nonce != challenge.nonce {
        return stale("the evidence answers a different challenge");
    }
    if now > challenge.expires_at {
        return stale("the challenge has expired");
    }
    let Some(iat) = w.issued_at else {
        return stale("the evidence has no issue time");
    };
    if iat.saturating_add(CLOCK_SKEW_SECS) < challenge.issued_at {
        return stale("the evidence was issued before the challenge");
    }
    if now > iat.saturating_add(max_age) {
        return stale("the evidence is stale");
    }
    if w.expires_at.is_some_and(|exp| now >= exp) {
        return stale("the evidence has expired");
    }
    Ok(())
}

/// A set of providers, dispatching on the envelope's provider name.
#[derive(Default)]
pub struct Verifier {
    providers: Vec<Box<dyn DynProvider>>,
}

impl Verifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, provider: impl DynProvider + 'static) -> Self {
        self.providers.retain(|p| p.name() != provider.name());
        self.providers.push(Box::new(provider));
        self
    }

    pub fn providers(&self) -> Vec<&'static str> {
        self.providers.iter().map(|p| p.name()).collect()
    }

    /// Signature, binding and claims only (see
    /// [`AttestationProvider::verify_claims`]).
    pub fn verify_claims(
        &self,
        raw: &AttestationEvidence,
        now: Option<u64>,
    ) -> Result<VerifiedWorkload> {
        if raw.version != crate::EVIDENCE_VERSION {
            return Err(err(
                Code::Attestation,
                format!("attestation evidence version {}", raw.version),
            ));
        }
        raw.binding.check_form()?;
        let p = self
            .providers
            .iter()
            .find(|p| p.name() == raw.provider)
            .ok_or_else(|| {
                err(
                    Code::Attestation,
                    format!("unknown attestation provider {:?}", raw.provider),
                )
            })?;
        p.verify_raw(raw, now)
    }

    /// Full verification at time `now`.
    pub fn verify(
        &self,
        raw: &AttestationEvidence,
        expected: &AttestationPolicy,
        challenge: &AttestationChallenge,
        now: u64,
    ) -> Result<VerifiedWorkload> {
        let w = self.verify_claims(raw, Some(now))?;
        check_freshness(&w, challenge, expected.max_evidence_age_secs, now)?;
        expected.check(&w)?;
        Ok(w)
    }
}

/// The workload side: produces evidence for a binding from inside the TEE.
/// Evidence is addressed to the challenging broker (`challenge.broker_id`
/// is the audience where the provider has one).
pub trait Attester {
    fn provider(&self) -> &'static str;
    fn attest(
        &self,
        challenge: &AttestationChallenge,
        binding: &WorkloadBinding,
    ) -> Result<AttestationEvidence>;
}
