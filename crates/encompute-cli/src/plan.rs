//! `encompute plan` and `encompute check` (ADR-015): declare the policy,
//! let Encompute choose the mechanisms.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use encompute_ir::{parse, Code, Error, Program, Result};
use encompute_runtime::planner::{
    render, verify_plan, ConfidentialExecutionPlan, ExecutionStep, Infrastructure, Mechanism,
    Objective, Preferences, Profile, StepKind, TrainingDeclaration,
};
use encompute_runtime::planning::{plan_program, planning_context};
use encompute_runtime::secagg::AggregationSpec;
use encompute_runtime::Model;

fn read(p: &Path) -> Result<Vec<u8>> {
    std::fs::read(p).map_err(|e| Error::new(Code::Artifact, format!("{}: {e}", p.display())))
}

fn json<T: serde::de::DeserializeOwned>(p: &Path) -> Result<T> {
    serde_json::from_slice(&read(p)?)
        .map_err(|e| Error::new(Code::BadInput, format!("{}: {e}", p.display())))
}

/// The program of an artifact or `.eir` file (not compiled: a program the
/// compiler would refuse can still be planned, and fail with reasons).
pub fn program_of(p: &Path) -> Result<Program> {
    if p.is_dir() {
        Ok(Model::load(p)?.program().clone())
    } else {
        let text = String::from_utf8(read(p)?)
            .map_err(|_| Error::new(Code::BadInput, "the program is not UTF-8"))?;
        parse(&text)
    }
}

/// How to plan: profile, infrastructure and preferences.
#[derive(Args, Clone)]
pub struct PlanOpts {
    /// Security profile: standard, strong or maximum.
    #[arg(long, default_value = "standard")]
    pub profile: String,
    /// Available infrastructure (JSON: TEEs, key broker, host location).
    #[arg(long)]
    pub infrastructure: Option<PathBuf>,
    /// Training to plan with the program (JSON: model and data assets).
    #[arg(long)]
    pub training: Option<PathBuf>,
    /// Among valid plans, prefer lower latency or lower cost.
    #[arg(long, default_value = "latency")]
    pub prefer: String,
    /// Nothing may run in the cloud.
    #[arg(long)]
    pub local_only: bool,
    /// Every step runs in this region.
    #[arg(long)]
    pub region: Option<String>,
    /// DEVELOPMENT ONLY: accept mock attestation.
    #[arg(long)]
    pub allow_development: bool,
}

impl PlanOpts {
    pub fn context(
        &self,
        program: &Program,
    ) -> Result<encompute_runtime::planner::PlanningContext> {
        let profile = Profile::parse(&self.profile).ok_or_else(|| {
            Error::new(Code::BadInput, "--profile is standard, strong or maximum")
        })?;
        let objective = match self.prefer.as_str() {
            "latency" => Objective::Latency,
            "cost" => Objective::Cost,
            _ => return Err(Error::new(Code::BadInput, "--prefer is latency or cost")),
        };
        let infrastructure: Infrastructure = match &self.infrastructure {
            Some(p) => json(p)?,
            None => Infrastructure::default(),
        };
        let training: Option<TrainingDeclaration> = match &self.training {
            Some(p) => Some(json(p)?),
            None => None,
        };
        planning_context(
            program,
            profile,
            infrastructure,
            Preferences {
                objective,
                local_only: self.local_only,
                region: self.region.clone(),
                allow_development: self.allow_development,
            },
            training,
        )
    }
}

/// `encompute plan`: exits 1 with PLANNING FAILED when no plan exists.
pub fn plan(
    model: &Path,
    opts: &PlanOpts,
    out: Option<&Path>,
    json_out: bool,
    deep: bool,
) -> Result<ExitCode> {
    let program = program_of(model)?;
    let ctx = opts.context(&program)?;
    let planned = plan_program(&program, &ctx)?;
    let Some(p) = &planned.plan else {
        print!("{}", render::failure(&planned));
        if deep {
            print!("\n{}", render::deep(&planned));
        }
        return Ok(ExitCode::from(1));
    };
    // Never hand out a plan the independent validator refuses.
    verify_plan(&program, p)?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(p).expect("JSON"));
    } else {
        print!("{}", render::plan(p));
        if deep {
            print!("\n{}", render::deep(&planned));
        }
    }
    if let Some(o) = out {
        std::fs::write(o, p.to_bytes()?)
            .map_err(|e| Error::new(Code::Artifact, format!("{}: {e}", o.display())))?;
        eprintln!("plan {} written to {}", p.id()?, o.display());
    }
    Ok(ExitCode::SUCCESS)
}

/// `encompute check`: valid program, policy, privacy, and a plan exists.
pub fn check(model: &Path, opts: &PlanOpts) -> Result<ExitCode> {
    let mut ok = true;
    let mut line = |what: &str, r: std::result::Result<(), String>| match r {
        Ok(()) => println!("{what:<16}OK"),
        Err(e) => {
            ok = false;
            println!("{what:<16}NO   {e}");
        }
    };
    let program = match program_of(model) {
        Ok(p) => p,
        Err(e) => {
            line("program valid", Err(e.to_string()));
            return Ok(ExitCode::from(1));
        }
    };
    line(
        "program valid",
        encompute_runtime::planning::planning_facts(&program)
            .map(|_| ())
            .map_err(|e| e.to_string()),
    );
    let analysis = encompute_analysis_check(&program);
    let privacy = |e: &Error| {
        matches!(
            e.code,
            Code::PrivacyPolicy | Code::PrivacyMechanism | Code::PrivacyBudgetExceeded
        )
    };
    line(
        "policy valid",
        match &analysis {
            Err(e) if !privacy(e) => Err(e.to_string()),
            _ => Ok(()),
        },
    );
    line(
        "privacy valid",
        match &analysis {
            Err(e) if privacy(e) => Err(e.to_string()),
            _ => Ok(()),
        },
    );
    let planned = opts
        .context(&program)
        .and_then(|c| plan_program(&program, &c));
    line(
        "plan exists",
        match planned {
            Ok(p) if p.plan.is_some() => Ok(()),
            Ok(_) => Err("PLANNING FAILED (see `encompute plan`)".into()),
            Err(e) => Err(e.to_string()),
        },
    );
    Ok(if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn encompute_analysis_check(program: &Program) -> Result<()> {
    encompute_runtime::planner::derive_requirements(
        program,
        &encompute_runtime::planner::PlanningContext {
            profile: Profile::Standard,
            catalog: Default::default(),
            infrastructure: Default::default(),
            preferences: Default::default(),
            facts: Default::default(),
            training: None,
        },
    )
    .map(|_| ())
}

/// `explain --deep`: the planner's candidates, rejections and assumptions.
pub fn deep(model: &Path, opts: &PlanOpts) -> Result<String> {
    let program = program_of(model)?;
    let ctx = opts.context(&program)?;
    Ok(render::deep(&plan_program(&program, &ctx)?))
}

/// An approved plan for an aggregation round of `output`: validated
/// against the program, with its aggregation step.
pub fn approved(path: &Path, program: &Program, output: &str) -> Result<(String, ExecutionStep)> {
    let p = ConfidentialExecutionPlan::from_bytes(&read(path)?)?;
    verify_plan(program, &p)?;
    let step = p
        .steps
        .iter()
        .find(|s| matches!(&s.kind, StepKind::Aggregate { output: o } if o == output))
        .cloned()
        .ok_or_else(|| {
            Error::new(
                Code::PlanMismatch,
                format!("the plan has no aggregation of {output}"),
            )
        })?;
    Ok((p.id()?.hex(), step))
}

/// The round's spec provides every mechanism the plan's step requires.
pub fn check_round(step: &ExecutionStep, spec: &AggregationSpec) -> Result<()> {
    for m in &step.mechanisms {
        let ok = match m {
            Mechanism::SecureAggregation {
                threshold,
                colluding,
            } => spec.threshold >= *threshold && spec.plan.colluding == *colluding,
            Mechanism::DifferentialPrivacy { .. } => spec.plan.dp.is_some(),
            Mechanism::Attestation { .. } => spec.coordinator_attestation.is_some(),
            _ => true,
        };
        if !ok {
            return Err(Error::new(
                Code::PlanMismatch,
                format!(
                    "the approved plan requires {} for this round (for an attested coordinator, \
                     pass --coordinator-policy)",
                    m.name()
                ),
            ));
        }
    }
    Ok(())
}
