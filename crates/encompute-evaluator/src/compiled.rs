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
    /// How an unverified program's backend was selected (BGV or BinFHE, by
    /// estimated cost); `None` for verified programs (always BGV), an
    /// explicit BinFHE request and research backends.
    pub selection: Option<crate::cost::ExactSelection>,
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
            let (profile, selection) = if required {
                check_coverage(&c.plan)?;
                (encompute_exact::bgv::profile(&c.plan), None)
            } else {
                match exact_choice()? {
                    // The whole program runs on OpenFHE BGV (receipts, no
                    // proofs) when it is in the BGV subset and estimated no
                    // slower there, else on OpenFHE BinFHE. TFHE-rs is a
                    // research backend, never chosen by default.
                    ExactChoice::Auto => {
                        let sel = crate::cost::select_exact_scheme(&c.plan);
                        let profile = match sel.scheme {
                            crate::cost::ExactScheme::Bgv => encompute_exact::bgv::profile(&c.plan),
                            crate::cost::ExactScheme::BinFhe => binfhe_profile(&c.plan)?,
                        };
                        (profile, Some(sel))
                    }
                    ExactChoice::BinFhe => (binfhe_profile(&c.plan)?, None),
                    ExactChoice::Research(profile) => (profile, None),
                }
            };
            CompiledProgram::Exact(ExactProgram {
                plan: c.plan,
                privacy: c.privacy,
                profile,
                proof_required: required,
                selection,
            })
        }
    })
}

/// Selects TFHE-rs for exact programs, in research builds only.
pub const RESEARCH_EXACT_BACKEND_ENV: &str = "ENCOMPUTE_RESEARCH_EXACT_BACKEND";

/// The OpenFHE BinFHE profile, for a plan inside its capability matrix
/// (refused here, not at key generation or on the evaluator).
fn binfhe_profile(plan: &ExactPlan) -> Result<ExactProfile> {
    encompute_exact::bits::check_capabilities(plan)?;
    Ok(encompute_exact::bits::openfhe_exact_profile())
}

enum ExactChoice {
    /// OpenFHE BGV or BinFHE, selected per program by estimated cost.
    Auto,
    /// OpenFHE BinFHE, asked for explicitly.
    BinFhe,
    /// A research backend.
    Research(ExactProfile),
}

/// The backend unverified exact programs compile to: OpenFHE (BGV or
/// BinFHE, selected per program), OpenFHE BinFHE when asked for explicitly
/// (`ENCOMPUTE_RESEARCH_EXACT_BACKEND=openfhe-exact`, which runs every
/// program), or TFHE-rs when a research build is asked
/// (`ENCOMPUTE_RESEARCH_EXACT_BACKEND=tfhe-rs`). A production build
/// refuses that request instead of ignoring it.
fn exact_choice() -> Result<ExactChoice> {
    match std::env::var(RESEARCH_EXACT_BACKEND_ENV).as_deref() {
        Err(_) | Ok("") => Ok(ExactChoice::Auto),
        Ok("openfhe-exact") => Ok(ExactChoice::BinFhe),
        Ok("tfhe-rs") if cfg!(feature = "research-tfhe-rs") => Ok(ExactChoice::Research(
            encompute_exact::research::tfhe_rs_profile(),
        )),
        Ok("tfhe-rs") => Err(Error::new(
            Code::Backend,
            "BACKEND UNAVAILABLE: TFHE-rs is available only in research builds (the \
             `research-tfhe-rs` feature); production exact programs run on OpenFHE exact",
        )),
        Ok(other) => Err(Error::new(
            Code::Backend,
            format!("{RESEARCH_EXACT_BACKEND_ENV}={other}: the exact backends are openfhe-exact and (research builds) tfhe-rs"),
        )),
    }
}

/// The calibrated estimates `(binfhe_ms, bgv_ms)` an unverified exact
/// `plan` is selected by (planner facts): BGV's is `None` when the plan is
/// outside the BGV subset or BinFHE was asked for explicitly, so the
/// planner selects what [`compile_program`] compiles to.
pub fn exact_estimates(plan: &ExactPlan) -> (Option<u64>, Option<u64>) {
    let (binfhe, bgv) = crate::cost::estimates(plan);
    match exact_choice() {
        Ok(ExactChoice::Auto) => (binfhe, bgv),
        _ => (binfhe, None),
    }
}

/// Whether execution proofs cover every instruction of `plan`.
pub fn proof_coverable(plan: &ExactPlan) -> bool {
    check_coverage(plan).is_ok()
}

/// The first operation of `plan` outside the BGV subset (which is what
/// execution proofs cover), in words; `None` when every one is inside.
pub(crate) fn bgv_unsupported(plan: &ExactPlan) -> Option<String> {
    let caps = encompute_exact::bgv::capabilities();
    // Coverage depends on the plan only, not on the spec.
    let t = encompute_exact::semantic_transcript(plan, &"0".repeat(64));
    caps.first_unsupported(&t)
        .map(|e| format!("{} on {} (instruction {})", e.op, e.ty, e.index))
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
            CompiledProgram::Exact(e)
                if e.profile.backend == encompute_exact::bits::OPENFHE_EXACT_BACKEND =>
            {
                "BinFHE"
            }
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
            CompiledProgram::Exact(e)
                if e.profile.backend == encompute_exact::bits::OPENFHE_EXACT_BACKEND =>
            {
                crate::BackendKind::OpenFheExact
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
