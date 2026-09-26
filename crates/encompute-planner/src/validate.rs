//! The plan validator: checks a plan independently of the planner that
//! made it. A planner bug must not become a security bypass, so nothing
//! here reuses the planner's selection or capability logic. The validator
//! re-derives the requirements from the program and the plan's own
//! context, then checks, with its own rules, that every mechanism is
//! available and supported and every requirement is discharged.

use std::collections::BTreeSet;

use encompute_analysis::confidentiality::analyze;
use encompute_ir::confidentiality::PartyId;
use encompute_ir::{Code, Error, Program, Result};
use encompute_verification::{PolicyId, PrivacyPolicyId};

use crate::ids::program_id;
use crate::model::*;
use crate::planner::PLAN_VERSION;
use crate::requirements::{derive, steps};

/// Checks `plan` for `program`; every problem is listed in the error.
pub fn verify_plan(program: &Program, plan: &ConfidentialExecutionPlan) -> Result<()> {
    let mut p = vec![];
    check(program, plan, &mut p)?;
    if p.is_empty() {
        Ok(())
    } else {
        p.sort();
        p.dedup();
        Err(Error::new(
            Code::PlanInvalid,
            format!("the plan is invalid:\n  - {}", p.join("\n  - ")),
        ))
    }
}

/// Checks `plan` against externally stated requirements as well: every one
/// must be among the plan's (and so discharged by it).
pub fn verify_plan_against(
    program: &Program,
    requirements: &[TrustRequirement],
    plan: &ConfidentialExecutionPlan,
) -> Result<()> {
    verify_plan(program, plan)?;
    let missing: Vec<String> = requirements
        .iter()
        .filter(|r| !plan.requirements.contains(r))
        .map(|r| format!("{r:?}"))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(Error::new(
            Code::PlanInvalid,
            format!("the plan omits requirements: {}", missing.join(", ")),
        ))
    }
}

fn usable(offer: &TeeOffer, ctx: &PlanningContext) -> bool {
    let production = match offer.provider.as_str() {
        "gcp-confidential-space" => true,
        "mock" => false,
        _ => return false,
    };
    !offer.debug_only
        && (production || (ctx.preferences.allow_development && ctx.profile != Profile::Maximum))
        && !(ctx.preferences.local_only && offer.cloud)
        && ctx
            .preferences
            .region
            .as_ref()
            .is_none_or(|r| offer.region.as_ref() == Some(r))
        && ctx.infrastructure.tees.contains(offer)
}

fn check(program: &Program, plan: &ConfidentialExecutionPlan, p: &mut Vec<String>) -> Result<()> {
    let ctx = &plan.context;
    let c = program.confidentiality();
    if plan.version != PLAN_VERSION {
        p.push(format!("plan version {}", plan.version));
    }
    if plan.program_id != program_id(program) {
        p.push("the plan is for another program".into());
    }
    if plan.policy_id != c.map(|c| PolicyId::of(c).hex())
        || plan.privacy_policy_id != c.and_then(PrivacyPolicyId::of).map(|x| x.hex())
    {
        p.push("the plan is for another policy".into());
    }
    // No weakening: exactly the requirements the program and context imply.
    let want = derive(program, ctx)?;
    if plan.requirements != want {
        for r in want.iter().filter(|r| !plan.requirements.contains(r)) {
            p.push(format!("requirement dropped: {r:?}"));
        }
        for r in plan.requirements.iter().filter(|r| !want.contains(r)) {
            p.push(format!("requirement not implied by the program: {r:?}"));
        }
    }
    let report = analyze(program)?;
    let shapes = steps(program, report.as_ref(), ctx)?;
    if shapes.len() != plan.steps.len()
        || shapes
            .iter()
            .zip(&plan.steps)
            .any(|(a, b)| a.id != b.id || a.kind != b.kind || a.assets != b.assets)
    {
        p.push("the plan's steps are not the program's".into());
        return Ok(());
    }
    let semantics = &ctx.facts.semantics;
    let host_ok = !(ctx.preferences.local_only && ctx.infrastructure.host_cloud)
        && ctx
            .preferences
            .region
            .as_ref()
            .is_none_or(|r| ctx.infrastructure.host_region.as_ref() == Some(r));
    let audience = |party: &str, asset: &str| {
        let Ok(q) = PartyId::new(party) else {
            return false;
        };
        c.and_then(|c| c.asset(asset))
            .is_some_and(|a| a.policy.owners.contains(&q) || a.policy.readers.contains(&q))
    };
    // Mechanisms: available, supported, with their prerequisites.
    for s in &plan.steps {
        let m = &s.mechanisms;
        let boundary = match &s.kind {
            StepKind::Aggregate { output } => report
                .as_ref()
                .and_then(|r| r.aggregations.iter().find(|b| &b.output == output)),
            _ => None,
        };
        match &s.placement {
            Placement::UntrustedHost if !host_ok => {
                p.push(format!("{}: ordinary hosts are not allowed here", s.id))
            }
            Placement::Tee(t) if !usable(t, ctx) => {
                p.push(format!("{}: the TEE is not usable", s.id))
            }
            Placement::Party(q) if c.and_then(|c| c.party(q)).is_none() => {
                p.push(format!("{}: {q} is not a declared party", s.id))
            }
            Placement::Parties if boundary.is_none() => p.push(format!(
                "{}: only aggregation runs across the parties",
                s.id
            )),
            _ => {}
        }
        // A placement comes with the mechanism that makes it one.
        let consistent = match &s.placement {
            Placement::Party(q) => m.contains(&Mechanism::LocalExecution { party: q.clone() }),
            Placement::Tee(t) => m.contains(&Mechanism::ConfidentialCompute {
                tee: t.tee.clone(),
                provider: t.provider.clone(),
            }),
            Placement::Parties => m
                .iter()
                .any(|x| matches!(x, Mechanism::SecureAggregation { .. })),
            Placement::UntrustedHost => true,
        };
        if !consistent {
            p.push(format!(
                "{}: its placement lacks the mechanism that provides it",
                s.id
            ));
        }
        for x in m {
            let ok = match x {
                Mechanism::Fhe { scheme, backend } => {
                    ctx.facts.fhe_supported
                        && s.kind == StepKind::Evaluate
                        && s.placement == Placement::UntrustedHost
                        && match scheme {
                            Scheme::Ckks => {
                                semantics == "approximate"
                                    && ctx.catalog.ckks
                                    && backend == "openfhe"
                            }
                            Scheme::Tfhe => {
                                semantics == "exact" && ctx.catalog.tfhe && backend == "tfhe-rs"
                            }
                            Scheme::Bgv => {
                                semantics == "exact" && ctx.catalog.bgv && backend == "openfhe"
                            }
                        }
                }
                Mechanism::VerifiedExecution => {
                    ctx.catalog.verified_execution
                        && ctx.facts.proof_covered
                        && m.iter().any(|y| {
                            matches!(
                                y,
                                Mechanism::Fhe {
                                    scheme: Scheme::Bgv,
                                    ..
                                }
                            )
                        })
                }
                Mechanism::ConfidentialCompute { tee, provider } => {
                    ctx.infrastructure.key_broker
                        && matches!(&s.placement, Placement::Tee(t) if &t.tee == tee && &t.provider == provider)
                        && m.contains(&Mechanism::Attestation {
                            provider: provider.clone(),
                        })
                        && m.contains(&Mechanism::AttestedKeyRelease)
                }
                Mechanism::Attestation { provider } => ctx
                    .infrastructure
                    .tees
                    .iter()
                    .any(|t| &t.provider == provider && usable(t, ctx)),
                Mechanism::AttestedKeyRelease => {
                    ctx.infrastructure.key_broker && matches!(s.placement, Placement::Tee(_))
                }
                Mechanism::SecureAggregation {
                    threshold,
                    colluding,
                } => {
                    boundary.is_some_and(|b| b.threshold == *threshold && b.colluding == *colluding)
                }
                Mechanism::DifferentialPrivacy {
                    noise_multiplier,
                    clip_norm,
                } => boundary.and_then(|b| b.dp.as_ref()).is_some_and(|d| {
                    format!("{:?}", d.noise_multiplier) == *noise_multiplier
                        && format!("{:?}", d.clip_norm) == *clip_norm
                }),
                Mechanism::LocalExecution { party } => {
                    s.placement == Placement::Party(party.clone())
                }
                Mechanism::PolicyEnforcement
                | Mechanism::OwnerAuthorization
                | Mechanism::SignedReceipts => false,
            };
            if !ok {
                p.push(format!(
                    "{}: {} is unavailable, unsupported or lacks its prerequisites",
                    s.id,
                    x.name()
                ));
            }
        }
        if let Some(b) = boundary {
            if b.dp.is_some()
                && !m
                    .iter()
                    .any(|x| matches!(x, Mechanism::DifferentialPrivacy { .. }))
            {
                p.push(format!(
                    "{}: the declared privacy mechanism is missing",
                    s.id
                ));
            }
            if !m
                .iter()
                .any(|x| matches!(x, Mechanism::SecureAggregation { .. }))
            {
                p.push(format!("{}: aggregation without secure aggregation", s.id));
            }
        }
    }
    let step = |id: &str| plan.steps.iter().find(|s| s.id == id);
    let reading = |a: &str| -> Vec<&ExecutionStep> {
        plan.steps
            .iter()
            .filter(|s| s.assets.iter().any(|x| x == a))
            .collect()
    };
    let any = |s: &ExecutionStep, f: &dyn Fn(&Mechanism) -> bool| s.mechanisms.iter().any(f);
    let aggregate = |out: &str| {
        plan.steps
            .iter()
            .find(|s| matches!(&s.kind, StepKind::Aggregate { output } if output == out))
    };
    // Requirements: each discharged.
    for r in &plan.requirements {
        let ok = match r {
            TrustRequirement::HideFrom {
                asset,
                principal: Principal::ComputeHost,
            } => reading(asset).into_iter().all(|s| {
                any(s, &|m| matches!(m, Mechanism::Fhe { .. }))
                    || (matches!(s.placement, Placement::Tee(_))
                        && any(s, &|m| matches!(m, Mechanism::ConfidentialCompute { .. }))
                        && any(s, &|m| matches!(m, Mechanism::Attestation { .. }))
                        && any(s, &|m| matches!(m, Mechanism::AttestedKeyRelease)))
                    || match &s.placement {
                        Placement::Party(q) => s.assets.iter().all(|a| audience(q, a)),
                        Placement::Parties => {
                            any(s, &|m| matches!(m, Mechanism::SecureAggregation { .. }))
                        }
                        _ => false,
                    }
            }),
            TrustRequirement::HideFrom {
                asset,
                principal: Principal::Party(q),
            } => {
                plan.selected_mechanisms.contains(&Mechanism::PolicyEnforcement)
                    && reading(asset)
                        .into_iter()
                        .all(|s| s.placement != Placement::Party(q.clone()))
            }
            TrustRequirement::AggregateOnly { asset, output } => aggregate(output).is_some_and(
                |s| {
                    s.assets.contains(asset)
                        && any(s, &|m| matches!(m, Mechanism::SecureAggregation { .. }))
                },
            ),
            TrustRequirement::MinimumParticipants { output, minimum } => aggregate(output)
                .is_some_and(|s| {
                    any(s, &|m| {
                        matches!(m, Mechanism::SecureAggregation { threshold, .. } if threshold >= minimum)
                    })
                }),
            TrustRequirement::PrivacyBudget { asset, .. } => {
                plan.selected_mechanisms.contains(&Mechanism::PolicyEnforcement)
                    && reading(asset)
                        .into_iter()
                        .filter(|s| matches!(s.kind, StepKind::Aggregate { .. }))
                        .all(|s| any(s, &|m| matches!(m, Mechanism::DifferentialPrivacy { .. })))
            }
            TrustRequirement::RequireAttestation { step: id } => {
                step(id).is_some_and(|s| any(s, &|m| matches!(m, Mechanism::Attestation { .. })))
            }
            TrustRequirement::RequireCorrectness { step: id } => step(id).is_some_and(|s| {
                any(s, &|m| matches!(m, Mechanism::VerifiedExecution))
                    && any(s, &|m| matches!(m, Mechanism::Fhe { scheme: Scheme::Bgv, .. }))
            }),
            TrustRequirement::ExecutionRegion { region } => plan.steps.iter().all(|s| {
                match &s.placement {
                    Placement::Tee(t) => t.region.as_ref() == Some(region),
                    Placement::UntrustedHost => {
                        ctx.infrastructure.host_region.as_ref() == Some(region)
                    }
                    Placement::Party(_) | Placement::Parties => true,
                }
            }),
            TrustRequirement::Purpose { .. } => {
                plan.selected_mechanisms.contains(&Mechanism::PolicyEnforcement)
                    && plan.selected_mechanisms.contains(&Mechanism::OwnerAuthorization)
            }
            TrustRequirement::SignedEvidence => {
                plan.selected_mechanisms.contains(&Mechanism::SignedReceipts)
            }
        };
        if !ok {
            p.push(format!("requirement not satisfied: {r:?}"));
        }
        if !plan.satisfaction.iter().any(|s| &s.requirement == r) {
            p.push(format!("requirement without an explanation: {r:?}"));
        }
    }
    // The summary fields agree with the steps.
    let mut selected: BTreeSet<Mechanism> = plan
        .steps
        .iter()
        .flat_map(|s| s.mechanisms.iter().cloned())
        .collect();
    selected.insert(Mechanism::PolicyEnforcement);
    selected.insert(Mechanism::SignedReceipts);
    if c.is_some() {
        selected.insert(Mechanism::OwnerAuthorization);
    }
    if selected != plan.selected_mechanisms {
        p.push("the selected mechanisms do not match the steps".into());
    }
    let evidence: BTreeSet<EvidenceKind> = selected.iter().flat_map(Mechanism::evidence).collect();
    if evidence != plan.evidence_required {
        p.push("the evidence required does not match the mechanisms".into());
    }
    Ok(())
}
