//! Control-plane operations, grouped by resource. Each checks
//! authorization, runs in one transaction, and records its audit event in
//! that transaction.

mod assets;
mod custody;
mod governance;
mod jobs;
mod policies;
mod tenancy;

pub(crate) use assets::withdraw_grants;
pub use assets::{asset_json, check_reservation, least_sensitivity, shared_asset_json};
pub(crate) use custody::require_own_broker;
pub use jobs::{estimated_ms, job_profile, GovernedStage, GATE_MS, HEARTBEAT_TIMEOUT_SECS};
pub use tenancy::{legacy_service_admins, LEGACY_SERVICE_ADMINS_REFUSED_FROM};

/// Takes the transaction-scoped advisory lock of service ID `broker` as a
/// key broker. Registering a service account under that ID and registering
/// an asset whose key names that broker both take it, before any row lock
/// and before the audit head, so each sees the other's committed write:
/// an organization's broker and another organization's asset naming it
/// cannot both be accepted (ENC-SF-2026-041).
pub fn keybroker_lock(
    t: &mut impl postgres::GenericClient,
    broker: &str,
) -> encompute_ir::Result<()> {
    t.execute(
        "SELECT pg_advisory_xact_lock(hashtext('keybroker'), hashtext($1))",
        &[&broker],
    )
    .map(|_| ())
    .map_err(crate::db::db_err)
}
