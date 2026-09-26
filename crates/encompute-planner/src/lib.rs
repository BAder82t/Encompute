//! The Encompute planner (ADR-015). Developers declare trust requirements
//! (who owns each asset, who must not see it, what may be released, for
//! what purpose, under what privacy budget, whether results must be
//! verifiable); the planner chooses the protection mechanisms, from those
//! Encompute already has, that satisfy all of them, or fails. Security
//! requirements are hard constraints; cost and latency only choose among
//! plans that satisfy every one. An independent validator
//! ([`verify_plan`]) checks every plan, and the plan's ID binds it into
//! aggregation specs and the trust graph.

mod ids;
pub mod model;
mod planner;
pub mod render;
mod requirements;
mod validate;

pub use ids::{program_id, PlanId};
pub use model::*;
pub use planner::{describe, plan, plan_or_fail, tee_unusable, Planned, PLAN_VERSION, PROVIDERS};
pub use requirements::{derive as derive_requirements, input_asset};
pub use validate::{verify_plan, verify_plan_against};
