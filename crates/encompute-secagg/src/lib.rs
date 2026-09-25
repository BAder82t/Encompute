//! Secure aggregation for Encompute (ADR-012): several parties each
//! contribute a private vector; only the policy-approved aggregate is
//! released, and nobody (coordinator, cloud operator, other parties)
//! learns an individual contribution.
//!
//! - [`protocol`]: Bonawitz et al. (CCS 2017) secure aggregation with the
//!   active-adversary consistency check. Established cryptography, not a
//!   new protocol.
//! - [`round`]: Encompute's semantics around it: the aggregation plan
//!   lowered from a program's `aggregate` declaration, party identities,
//!   round binding, quantization, thresholds, attestation, the aggregate
//!   asset's derived policy, and signed aggregation receipts.
//! - [`service`]: the coordinator over HTTP, and the participant client.
//!
//! Secure aggregation hides contributions; it does not limit what the
//! aggregate reveals (that needs differential privacy).

mod crypto;
pub mod protocol;
pub mod round;
pub mod service;

pub use round::{
    identity_of, party_key_from_seed, verify_aggregation_receipt, AggregateAsset, AggregatePolicy,
    AggregationManifest, AggregationPlan, AggregationReceipt, AggregationRound, AggregationSpec,
    PartyIdentity, PlanParticipant, RoundCoordinator, RoundParticipant, PROTOCOL, PROTOCOL_VERSION,
};
