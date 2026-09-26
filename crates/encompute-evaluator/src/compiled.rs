//! A compiled program of either semantics (0.3): approximate programs lower
//! to a CKKS plan, exact programs to a backend-independent exact plan. The
//! program's semantics choose the lowering; nothing above this point is
//! scheme-specific.

pub use encompute_analysis::Semantics;
use encompute_analysis::{semantics, PrivacyReport};
use encompute_exact::{ExactPlan, ExactProfile};
use encompute_ir::{Code, Error, Program, Result, Verification};
use serde::Serialize;

/// Exact plan plus the vetted parameter profile it targets.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExactProgram {
    pub plan: ExactPlan,
    pub privacy: PrivacyReport,
    pub profile: ExactProfile,
    /// `verification required`: the plan targets the proof-capable OpenFHE
    /// BGV backend (ADR-009).
    pub proof_required: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CompiledProgram {
    Approx(encompute_ckks::Compiled),
    Exact(ExactProgram),
}

/// Plan-format versions, independent per scheme.
pub use encompute_exact::EXACT_PLAN_VERSION;

/// Compile by semantics: approximate → CKKS, exact → exact plan. Programs
/// mixing both are refused (0.3). Programs with `verification required`
/// compile to the proof-capable BGV profile, and fail (ENC1801) unless the
/// proof backend covers every instruction.
/// A program whose outputs cross a party boundary only through secure
/// aggregation (ADR-012) never runs on a single evaluator: that would put
/// every party's contribution under one client's key.
pub fn refuse_aggregation(program: &Program) -> Result<()> {
    if let Some(a) = program
        .confidentiality()
        .and_then(|c| c.aggregations.first())
    {
        return Err(Error::new(
            Code::AggregationRequired,
            format!(
                "output {:?} of {} is aggregate-only: it runs only as secure aggregation \
                 (`encompute aggregate`), never on one evaluator",
                a.output,
                program.name()
            ),
        ));
    }
    Ok(())
}

pub fn compile_program(program: &Program) -> Result<CompiledProgram> {
    // Confidentiality violations are compile errors (ENC1901–ENC1906).
    encompute_analysis::confidentiality::analyze(program)?;
    let required = program.verification() == Verification::Required;
    Ok(match semantics(program)? {
        Semantics::Approximate if required => {
            return Err(Error::new(
                Code::Unverified,
                "this program cannot be verified: execution proofs cover exact (integer/Boolean) \
                 programs only; approximate (CKKS) programs support verification=\"receipt\"",
            ))
        }
        Semantics::Approximate => CompiledProgram::Approx(encompute_ckks::compile(program)?),
        Semantics::Exact => {
            let c = encompute_exact::compile(program)?;
            let profile = if required {
                check_coverage(&c.plan)?;
                encompute_exact::bgv::profile(&c.plan)
            } else {
                encompute_tfhe::default_profile()
            };
            CompiledProgram::Exact(ExactProgram {
                plan: c.plan,
                privacy: c.privacy,
                profile,
                proof_required: required,
            })
        }
    })
}

/// Whether execution proofs cover every instruction of `plan`.
pub fn proof_coverable(plan: &ExactPlan) -> bool {
    check_coverage(plan).is_ok()
}

/// Fail unless the proof backend covers every instruction of `plan`.
fn check_coverage(plan: &ExactPlan) -> Result<()> {
    let caps = encompute_exact::bgv::capabilities();
    // Coverage depends on the plan only, not on the spec.
    let t = encompute_exact::semantic_transcript(plan, &"0".repeat(64));
    if let Some(e) = caps.first_unsupported(&t) {
        let (covered, total) = caps.coverage(&t);
        return Err(Error::new(
            Code::Unverified,
            format!(
                "this program cannot be fully verified: unsupported proof operation {} on {} \
                 (instruction {}); available proof coverage {}% ({covered}/{total}, protocol {}: \
                 u8, u16 and bool; add, sub, mul, constants, and/or/xor/not). Use \
                 verification=\"receipt\", or restrict the program to the proven subset",
                e.op,
                e.ty,
                e.index,
                100 * covered / total.max(1),
                caps.protocol
            ),
        ));
    }
    Ok(())
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
            CompiledProgram::Exact(e) if e.profile.backend == "openfhe" => "BGV",
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

    /// Whether an execution proof is required (and possible) for this
    /// program.
    pub fn proof_required(&self) -> bool {
        matches!(self, CompiledProgram::Exact(e) if e.proof_required)
    }

    /// The real backend this program targets: OpenFHE for CKKS and for
    /// BGV exact programs, TFHE-rs for other exact programs.
    pub fn target_backend(&self) -> crate::BackendKind {
        match self {
            CompiledProgram::Approx(_) => crate::BackendKind::OpenFhe,
            CompiledProgram::Exact(e) if e.profile.backend == "openfhe" => {
                crate::BackendKind::OpenFhe
            }
            CompiledProgram::Exact(_) => crate::BackendKind::TfheRs,
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
