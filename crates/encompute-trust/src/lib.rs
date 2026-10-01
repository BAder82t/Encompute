//! The trust graph (ADR-014): assets, owners, policies, authorizations,
//! revocations, lineage, aggregation rounds, privacy releases,
//! attestations and executions in one content-addressed graph, with the
//! evidence for each, and one trust report over all of it.

pub mod authz;
pub mod bundle;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixture;
pub mod governance;
pub mod govlog;
pub mod graph;
mod ingest;
pub mod lineage;
pub mod report;

pub use authz::{
    Authorization, AuthorizationV2, GovernanceKey, GovernanceKeyStatus, ReleaseRecord, Revocation,
    RevocationV2, SignedAuthorization, SignedAuthorizationV2, SignedReleaseRecord,
    SignedRevocation, SignedRevocationV2, AUTHORIZATION_V2_VERSION, AUTHORIZATION_VERSION,
    RELEASE_RECORD_VERSION,
};
pub use bundle::{
    check_no_plaintext, GovernanceBundle, Manifest, Outcome, Pin, Pins, Provenance,
    SignatureFinding, SignatureStatement, SignatureStatus, StatementVerdict, Verified,
    VerifyOptions, BUNDLE_FORMAT, EXIT_CODES, MAX_STRING,
};
pub use governance::{
    check_audit, AuditEntry, AuditEvidence, AuditFindings, AuditState, AuthorizationCard,
    AuthorizationEntry, GovernanceAnchors, GovernanceEvidence, GovernanceOptions, GovernanceReport,
    GovernanceRow, HeadFinding, RevocationNote, SharedApproval, Verdict,
    GOVERNANCE_EVIDENCE_VERSION, GOVERNANCE_ROWS, LEGAL_BOUNDARY, LEGAL_BOUNDARY_ID,
};
pub use graph::{node_id, Edge, EdgeKind, Evidence, Node, NodeKind, TrustGraph};
pub use ingest::{program_id, Rebuilt};
pub use report::{Anchors, FactsFn, ProofCheckFn, ReportOptions, Row, Status, TrustReport, ROWS};

use sha2::{Digest, Sha256};

pub(crate) fn tagged(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    h.update(bytes);
    h.finalize().into()
}

pub(crate) fn tagged_hex(domain: &str, bytes: &[u8]) -> String {
    encompute_verification::hex(&tagged(domain, bytes))
}
