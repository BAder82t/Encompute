//! Control-plane operations, grouped by resource. Each checks
//! authorization, runs in one transaction, and records its audit event in
//! that transaction.

mod assets;
mod custody;
pub(crate) mod derived;
mod governance;
mod jobs;
pub mod placement;
mod policies;
pub mod privacy_scopes;
mod project_log;
mod retention;
pub(crate) mod revocation_heads;
mod tenancy;

pub(crate) use assets::withdraw_grants;
pub use assets::{
    asset_json, check_reservation, least_sensitivity, shared_asset_json, MIN_RESERVATION_RHO,
};
pub(crate) use custody::require_own_broker;
pub use derived::onward_policy_id;
pub use jobs::governance_bundle::{BUNDLE_RATE, MAX_BUNDLE_EVENTS};
pub use jobs::{estimated_ms, job_profile, GovernedStage, GATE_MS, HEARTBEAT_TIMEOUT_SECS};
pub use project_log::{RateLimit, MAX_PAGE as PROJECT_LOG_MAX_PAGE};

/// Privacy spends per actor and asset a minute by default (an event of the
/// governance log each; a training round is two).
pub const SPEND_RATE: u32 = 1200;
/// Privacy population and scope allocations, proposals, approvals and
/// spender authorizations per caller a minute.
pub const SCOPE_RATE: u32 = 120;
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
