//! Control-plane operations, grouped by resource. Each checks
//! authorization, runs in one transaction, and records its audit event in
//! that transaction.

mod assets;
mod jobs;
mod policies;
mod tenancy;

pub use assets::asset_json;
pub use jobs::{estimated_ms, job_profile, GATE_MS, HEARTBEAT_TIMEOUT_SECS};
