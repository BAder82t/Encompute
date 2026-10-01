//! Planning from the runtime (ADR-015): the facts only a compiler knows
//! (does the program compile to an encrypted plan, is it covered by
//! execution proofs), and the backends this build can run.

use encompute_analysis::Semantics;
use encompute_ir::{Program, Result};
use encompute_planner::{
    plan, BackendCatalog, Infrastructure, Planned, PlanningContext, Preferences, Profile,
    ProgramFacts, TrainingDeclaration,
};

/// What the compiler knows about `program`, for the planner.
pub fn planning_facts(program: &Program) -> Result<ProgramFacts> {
    let semantics = encompute_analysis::semantics(program)?;
    let (name, fhe_supported, proof_covered, (binfhe_ms, bgv_ms)) = match semantics {
        Semantics::Approximate => (
            "approximate",
            encompute_ckks::compile(program).is_ok(),
            false,
            (None, None),
        ),
        Semantics::Exact => match encompute_exact::compile(program) {
            Ok(c) => (
                "exact",
                true,
                encompute_evaluator::proof_coverable(&c.plan),
                // The estimates compile_program selects the backend by.
                encompute_evaluator::exact_estimates(&c.plan),
            ),
            Err(_) => ("exact", false, false, (None, None)),
        },
    };
    Ok(ProgramFacts {
        semantics: name.into(),
        fhe_supported,
        proof_covered,
        operations: program.nodes().len() as u64,
        binfhe_ms,
        bgv_ms,
    })
}

/// The encrypted backends this build runs.
pub fn available_catalog() -> BackendCatalog {
    BackendCatalog {
        ckks: crate::has_openfhe(),
        tfhe: crate::has_tfhe(),
        openfhe_exact: crate::has_openfhe(),
        bgv: crate::has_openfhe(),
        verified_execution: cfg!(feature = "vfhe-research"),
    }
}

/// A planning context for `program` in this build.
pub fn planning_context(
    program: &Program,
    profile: Profile,
    infrastructure: Infrastructure,
    preferences: Preferences,
    training: Option<TrainingDeclaration>,
) -> Result<PlanningContext> {
    Ok(PlanningContext {
        profile,
        catalog: available_catalog(),
        infrastructure,
        preferences,
        facts: planning_facts(program)?,
        training,
        custody: Vec::new(),
        placement: None,
    })
}

/// Plans `program` (see [`encompute_planner::plan`]).
pub fn plan_program(program: &Program, ctx: &PlanningContext) -> Result<Planned> {
    plan(program, ctx)
}
