//! The assurance checks, by name (`check:<name>` in the catalog).

pub mod planner;
pub mod privacy;
pub mod receipts;
pub mod secagg;

use crate::{CheckResult, Scale};

pub struct Check {
    pub name: &'static str,
    pub run: fn(Scale) -> CheckResult,
}

pub const CHECKS: &[Check] = &[
    Check {
        name: "execution_receipt_mutation",
        run: receipts::execution_receipt_mutation,
    },
    Check {
        name: "secagg_sum_sweep",
        run: secagg::sum_sweep,
    },
    Check {
        name: "secagg_collusion_bound",
        run: secagg::collusion_bound,
    },
    Check {
        name: "secagg_coordinator_sees_no_input",
        run: secagg::coordinator_sees_no_input,
    },
    Check {
        name: "dp_sampler_statistics",
        run: privacy::sampler_statistics,
    },
    Check {
        name: "dp_invalid_noise",
        run: privacy::invalid_noise,
    },
    Check {
        name: "dp_multi_parent_atomicity",
        run: privacy::multi_parent_atomicity,
    },
    Check {
        name: "dp_ledger_tampering",
        run: privacy::ledger_tampering,
    },
    Check {
        name: "dp_receipt_mutation",
        run: privacy::receipt_mutation,
    },
    Check {
        name: "dp_crash_injection",
        run: privacy::crash_injection,
    },
    Check {
        name: "planner_property",
        run: planner::property,
    },
    Check {
        name: "planner_adversarial",
        run: planner::adversarial,
    },
    Check {
        name: "planner_plan_id_binding",
        run: planner::plan_id_binding,
    },
    Check {
        name: "dp_multi_process_double_spend",
        run: privacy::multi_process_double_spend,
    },
];

pub fn find(name: &str) -> Option<&'static Check> {
    CHECKS.iter().find(|c| c.name == name)
}
