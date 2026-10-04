//! The Encompute control plane.
//!
//! It coordinates: organizations, users and service accounts, projects,
//! assets (metadata only), policies, plans, jobs, evaluator registration
//! and scheduling, privacy budgets, trust reports and the audit trail. It
//! does not compute on protected data, never holds secret keys, and is not
//! a cryptographic trust anchor: trust is rebuilt from signed evidence.
//!
//! Evaluators compute (`encompute-evaluator`); key brokers authorize secret
//! release (`encompute-keybroker`); SecAgg coordinators aggregate. Each is
//! a separate service with its own identity.

pub mod anchor;
mod anchor_migration;
pub mod api;
pub mod audit;
pub mod authn;
pub mod authz;
pub mod config;
pub mod control;
pub mod db;
pub mod govlog;
pub mod log;
pub mod metrics;
pub mod mirror;
pub mod model;
mod ops;
pub mod transport;
pub mod views;

#[doc(hidden)]
pub use anchor_migration::set_migration_test_hook;
pub use control::{Control, Ctx};
pub use ops::placement;
pub use ops::{
    asset_json, check_reservation, estimated_ms, job_profile, keybroker_lock, least_sensitivity,
    legacy_service_admins, onward_policy_id, shared_asset_json, GovernedStage, GATE_MS,
    HEARTBEAT_TIMEOUT_SECS, LEGACY_SERVICE_ADMINS_REFUSED_FROM, MIN_RESERVATION_RHO,
};
