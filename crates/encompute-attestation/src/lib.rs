//! Workload attestation and policy-gated key release (ADR-011).
//!
//! A data or model owner releases an asset key only to a workload that
//! proves, with hardware attestation, that it runs the approved Encompute
//! artifact under the approved execution spec and confidentiality policy,
//! in an approved TEE, for a fresh session. The proof is carried by a
//! [`WorkloadBinding`]: a hash of the execution spec ID, policy ID,
//! artifact digest, the evaluator's receipt-signing key, an ephemeral
//! session key generated inside the TEE, and the broker's fresh challenge
//! nonce. Evidence must commit to that hash.
//!
//! Providers ([`AttestationProvider`]) verify one kind of evidence and
//! return provider-neutral [`VerifiedWorkload`] claims; nothing
//! provider-specific leaves them. An [`AttestationPolicy`] (where and what
//! may run) is checked against those claims. It is separate from the
//! confidentiality policy (who owns data and how it may be released).
//!
//! Keys are released as [`EncryptedKeyGrant`]s, sealed with HPKE to the
//! attested session key, so only the attested session can open them, never
//! the host that relays them.

mod binding;
pub mod gcp;
mod grant;
pub mod mock;
mod policy;
mod provider;
mod record;
mod util;

pub use binding::{AttestationChallenge, WorkloadBinding, BINDING_VERSION};
pub use grant::{seal_grant, EncryptedKeyGrant, GrantHeader, WorkloadSession, GRANT_VERSION};
pub use policy::{
    AttestationPolicy, DebugPolicy, Security, TcbStatus, TeeKind, VerifiedGpu, VerifiedWorkload,
    POLICY_VERSION,
};
pub use provider::{
    check_freshness, AttestationEvidence, AttestationProvider, Attester, DynProvider, Verifier,
    CLOCK_SKEW_SECS, EVIDENCE_VERSION,
};
pub use record::{AttestationRecord, RECORD_VERSION};
pub use util::{unix_now, Digest32};
