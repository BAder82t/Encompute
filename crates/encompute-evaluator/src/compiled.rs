//! A compiled program of either semantics (0.3): approximate programs lower
//! to a CKKS plan, exact programs to a backend-independent exact plan. The
//! program's semantics choose the lowering; nothing above this point is
//! scheme-specific.

pub use encompute_analysis::Semantics;
use encompute_analysis::{semantics, PrivacyReport};
use encompute_exact::{ExactPlan, ExactProfile};
use encompute_ir::{Program, Result};
use serde::Serialize;

/// Exact plan plus the vetted parameter profile it targets.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExactProgram {
    pub plan: ExactPlan,
    pub privacy: PrivacyReport,
    pub profile: ExactProfile,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CompiledProgram {
    Approx(encompute_ckks::Compiled),
    Exact(ExactProgram),
}

/// Plan-format versions, independent per scheme.
pub const EXACT_PLAN_VERSION: u32 = 1;

/// Compile by semantics: approximate → CKKS, exact → exact plan. Programs
/// mixing both are rejected (0.3).
pub fn compile_program(program: &Program) -> Result<CompiledProgram> {
    Ok(match semantics(program)? {
        Semantics::Approximate => CompiledProgram::Approx(encompute_ckks::compile(program)?),
        Semantics::Exact => {
            let c = encompute_exact::compile(program)?;
            CompiledProgram::Exact(ExactProgram {
                plan: c.plan,
                privacy: c.privacy,
                profile: encompute_tfhe::default_profile(),
            })
        }
    })
}

fn json<T: Serialize>(v: &T) -> String {
    let mut s = serde_json::to_string_pretty(v).expect("serializable");
    s.push('\n');
    s
}

impl CompiledProgram {
    pub fn semantics(&self) -> Semantics {
        match self {
            CompiledProgram::Approx(_) => Semantics::Approximate,
            CompiledProgram::Exact(_) => Semantics::Exact,
        }
    }

    /// Scheme written into envelopes and artifacts.
    pub fn scheme(&self) -> &'static str {
        match self {
            CompiledProgram::Approx(_) => "CKKS",
            CompiledProgram::Exact(_) => "TFHE",
        }
    }

    /// `(kind, version)` of the plan format.
    pub fn plan_format(&self) -> (&'static str, u32) {
        match self {
            CompiledProgram::Approx(_) => ("ckks", encompute_ckks::PLAN_VERSION),
            CompiledProgram::Exact(_) => ("exact", EXACT_PLAN_VERSION),
        }
    }

    pub fn ckks(&self) -> Option<&encompute_ckks::Compiled> {
        match self {
            CompiledProgram::Approx(c) => Some(c),
            CompiledProgram::Exact(_) => None,
        }
    }

    pub fn exact(&self) -> Option<&ExactProgram> {
        match self {
            CompiledProgram::Approx(_) => None,
            CompiledProgram::Exact(e) => Some(e),
        }
    }

    pub fn privacy(&self) -> &PrivacyReport {
        match self {
            CompiledProgram::Approx(c) => &c.privacy,
            CompiledProgram::Exact(e) => &e.privacy,
        }
    }

    /// Canonical `parameters.json`; its SHA-256 is the parameter-set ID.
    pub fn parameters_json(&self) -> String {
        match self {
            CompiledProgram::Approx(c) => c.params.canonical_json(),
            CompiledProgram::Exact(e) => e.profile.canonical_json(),
        }
    }

    /// Canonical `plan.json`.
    pub fn plan_json(&self) -> String {
        match self {
            CompiledProgram::Approx(c) => json(&c.plan),
            CompiledProgram::Exact(e) => json(&e.plan),
        }
    }

    /// Encrypted input names, in plan order.
    pub fn input_names(&self) -> Vec<&str> {
        match self {
            CompiledProgram::Approx(c) => c.plan.inputs.iter().map(|i| i.name.as_str()).collect(),
            CompiledProgram::Exact(e) => e.plan.inputs.iter().map(|i| i.name.as_str()).collect(),
        }
    }
}
