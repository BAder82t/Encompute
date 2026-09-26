//! Mechanism selection. For each step the planner enumerates every
//! combination of the mechanisms Encompute has that could run it, keeps
//! those that satisfy every hard requirement touching the step (with their
//! prerequisites available), and picks the cheapest by estimated cost. A
//! step with no valid candidate fails the whole plan: requirements are
//! never weakened to find one.

use std::collections::{BTreeMap, BTreeSet};

use encompute_analysis::confidentiality::{analyze, AggregationBoundary};
use encompute_ir::confidentiality::{Confidentiality, PartyId};
use encompute_ir::{Code, Error, Program, Result};
use encompute_verification::{PolicyId, PrivacyPolicyId};

use crate::ids::program_id;
use crate::model::*;
use crate::requirements::{derive, steps, StepShape};

pub const PLAN_VERSION: u32 = 1;

/// Attestation providers Encompute can verify, and whether each is
/// production-grade.
pub const PROVIDERS: &[(&str, bool)] = &[("gcp-confidential-space", true), ("mock", false)];

fn provider_production(p: &str) -> Option<bool> {
    PROVIDERS
        .iter()
        .find(|(n, _)| *n == p)
        .map(|(_, prod)| *prod)
}

/// Why `offer` cannot host a confidential workload here, if it cannot.
pub fn tee_unusable(offer: &TeeOffer, ctx: &PlanningContext) -> Option<String> {
    let Some(production) = provider_production(&offer.provider) else {
        return Some(format!(
            "attestation provider {} is not one Encompute can verify",
            offer.provider
        ));
    };
    if offer.debug_only {
        return Some(format!(
            "{} only runs debug workloads, whose memory the host can read",
            offer.tee
        ));
    }
    if !production && (!ctx.preferences.allow_development || ctx.profile == Profile::Maximum) {
        return Some(format!(
            "{} is development-only attestation",
            offer.provider
        ));
    }
    if ctx.preferences.local_only && offer.cloud {
        return Some(format!(
            "{} runs in the cloud; local-only was required",
            offer.tee
        ));
    }
    if let Some(r) = &ctx.preferences.region {
        if offer.region.as_ref() != Some(r) {
            return Some(format!("{} is not in region {r}", offer.tee));
        }
    }
    None
}

fn host_unusable(ctx: &PlanningContext) -> Option<String> {
    if ctx.preferences.local_only && ctx.infrastructure.host_cloud {
        return Some("ordinary hosts are in the cloud; local-only was required".into());
    }
    if let Some(r) = &ctx.preferences.region {
        if ctx.infrastructure.host_region.as_ref() != Some(r) {
            return Some(format!("ordinary hosts are not in region {r}"));
        }
    }
    None
}

/// May `party` read every asset in `assets`?
fn may_read(c: Option<&Confidentiality>, party: &str, assets: &[String]) -> bool {
    let Ok(p) = PartyId::new(party) else {
        return false;
    };
    assets.iter().all(|a| {
        c.and_then(|c| c.asset(a))
            .is_some_and(|d| d.policy.owners.contains(&p) || d.policy.readers.contains(&p))
    })
}

fn ops(ctx: &PlanningContext) -> u64 {
    ctx.facts.operations.max(1)
}

/// Estimated milliseconds (coarse, per mechanism; never guaranteed).
fn estimate(
    step: &StepShape,
    placement: &Placement,
    mechs: &[Mechanism],
    ctx: &PlanningContext,
    n: u64,
) -> u64 {
    let o = ops(ctx);
    let mut ms: u64 = match (&step.kind, placement) {
        (StepKind::Train { .. }, Placement::Tee(_)) => 90_000,
        (StepKind::Train { .. }, _) => 60_000,
        (StepKind::Aggregate { .. }, _) => 500 + 50 * n * n,
        (StepKind::Evaluate, Placement::Tee(_)) => 1 + o / 50,
        (StepKind::Evaluate, _) => 1 + o / 100,
    };
    for m in mechs {
        ms += match m {
            Mechanism::Fhe { scheme, .. } => match scheme {
                Scheme::Ckks => 40 * o,
                Scheme::Tfhe => 400 * o,
                Scheme::Bgv => 60 * o,
            },
            Mechanism::VerifiedExecution => 180 * o,
            Mechanism::Attestation { .. } => 800,
            Mechanism::AttestedKeyRelease => 200,
            Mechanism::DifferentialPrivacy { .. } => 5,
            _ => 0,
        };
    }
    ms
}

fn score(c: &Candidate, ctx: &PlanningContext) -> u64 {
    match ctx.preferences.objective {
        Objective::Latency => c.estimated_ms,
        // Confidential hardware costs more per hour than ordinary hosts.
        Objective::Cost => match c.placement {
            Placement::Tee(_) => c.estimated_ms.saturating_mul(3),
            _ => c.estimated_ms,
        },
    }
}

/// A candidate's mechanisms and placement, before judging.
struct Option_ {
    placement: Placement,
    mechanisms: Vec<Mechanism>,
    /// Rejected before judging (unavailable, unsupported).
    unavailable: Option<String>,
}

fn attested(offer: &TeeOffer) -> Vec<Mechanism> {
    vec![
        Mechanism::ConfidentialCompute {
            tee: offer.tee.clone(),
            provider: offer.provider.clone(),
        },
        Mechanism::Attestation {
            provider: offer.provider.clone(),
        },
        Mechanism::AttestedKeyRelease,
    ]
}

fn options(
    step: &StepShape,
    c: Option<&Confidentiality>,
    boundary: Option<&AggregationBoundary>,
    ctx: &PlanningContext,
) -> Vec<Option_> {
    let mut out = vec![];
    let host = host_unusable(ctx);
    let tees = || {
        let mut t = ctx.infrastructure.tees.clone();
        t.sort();
        t.dedup();
        t
    };
    let parties: Vec<String> = c
        .map(|c| c.parties.iter().map(|p| p.id.to_string()).collect())
        .unwrap_or_default();
    match &step.kind {
        StepKind::Evaluate | StepKind::Train { .. } => {
            let training = matches!(step.kind, StepKind::Train { .. });
            if !training {
                out.push(Option_ {
                    placement: Placement::UntrustedHost,
                    mechanisms: vec![],
                    unavailable: host.clone(),
                });
            }
            for p in &parties {
                out.push(Option_ {
                    placement: Placement::Party(p.clone()),
                    mechanisms: vec![Mechanism::LocalExecution { party: p.clone() }],
                    unavailable: None,
                });
            }
            let fhe_unsupported = if training {
                Some("general training is not supported under FHE".to_owned())
            } else if !ctx.facts.fhe_supported {
                Some("the program does not compile to an encrypted plan".to_owned())
            } else {
                None
            };
            let schemes: Vec<(Scheme, &str, bool)> = if ctx.facts.semantics == "approximate" {
                vec![(Scheme::Ckks, "openfhe", ctx.catalog.ckks)]
            } else {
                vec![
                    (Scheme::Tfhe, "tfhe-rs", ctx.catalog.tfhe),
                    (Scheme::Bgv, "openfhe", ctx.catalog.bgv),
                ]
            };
            for (scheme, backend, built) in schemes {
                let fhe = Mechanism::Fhe {
                    scheme,
                    backend: backend.into(),
                };
                let why = fhe_unsupported
                    .clone()
                    .or_else(|| (!built).then(|| format!("{} is not available", fhe.name())))
                    .or_else(|| host.clone());
                out.push(Option_ {
                    placement: Placement::UntrustedHost,
                    mechanisms: vec![fhe.clone()],
                    unavailable: why.clone(),
                });
                if scheme == Scheme::Bgv {
                    let why = why
                        .or_else(|| {
                            (!ctx.catalog.verified_execution)
                                .then(|| "verified execution is not available".to_owned())
                        })
                        .or_else(|| {
                            (!ctx.facts.proof_covered).then(|| {
                                "the program is not fully covered by execution proofs".to_owned()
                            })
                        });
                    out.push(Option_ {
                        placement: Placement::UntrustedHost,
                        mechanisms: vec![fhe, Mechanism::VerifiedExecution],
                        unavailable: why,
                    });
                }
            }
            for t in tees() {
                let why = tee_unusable(&t, ctx).or_else(|| {
                    (!ctx.infrastructure.key_broker)
                        .then(|| "no key broker to release keys to the attested workload".into())
                });
                out.push(Option_ {
                    placement: Placement::Tee(t.clone()),
                    mechanisms: attested(&t),
                    unavailable: why,
                });
            }
        }
        StepKind::Aggregate { .. } => {
            let b = boundary.expect("a boundary per aggregate step");
            let mut base = vec![Mechanism::SecureAggregation {
                threshold: b.threshold,
                colluding: b.colluding,
            }];
            if let Some(dp) = &b.dp {
                base.push(Mechanism::DifferentialPrivacy {
                    noise_multiplier: format!("{:?}", dp.noise_multiplier),
                    clip_norm: format!("{:?}", dp.clip_norm),
                });
            }
            out.push(Option_ {
                placement: Placement::Parties,
                mechanisms: base.clone(),
                unavailable: None,
            });
            for t in tees() {
                let mut m = base.clone();
                m.push(Mechanism::Attestation {
                    provider: t.provider.clone(),
                });
                out.push(Option_ {
                    placement: Placement::Parties,
                    mechanisms: m,
                    unavailable: tee_unusable(&t, ctx)
                        .map(|w| format!("an attested coordinator: {w}")),
                });
            }
        }
    }
    out
}

/// Does running `step` this way satisfy `req`? `Err` says why not. (The
/// planner's capability view; `validate` checks plans independently.)
fn satisfies(
    req: &TrustRequirement,
    step: &StepShape,
    placement: &Placement,
    mechs: &[Mechanism],
    c: Option<&Confidentiality>,
    boundary: Option<&AggregationBoundary>,
) -> std::result::Result<Option<String>, String> {
    let has = |f: &dyn Fn(&Mechanism) -> bool| mechs.iter().any(f);
    let reads = |a: &str| step.assets.iter().any(|x| x == a);
    match req {
        TrustRequirement::HideFrom {
            asset,
            principal: Principal::ComputeHost,
        } if reads(asset) => {
            if has(&|m| matches!(m, Mechanism::Fhe { .. })) {
                Ok(Some(format!(
                    "{asset} is encrypted on the client; the host computes on ciphertexts only"
                )))
            } else if has(&|m| matches!(m, Mechanism::ConfidentialCompute { .. }))
                && has(&|m| matches!(m, Mechanism::Attestation { .. }))
                && has(&|m| matches!(m, Mechanism::AttestedKeyRelease))
            {
                Ok(Some(format!(
                    "{asset}'s key is released only to the attested workload; the TEE keeps \
                     its memory from the host"
                )))
            } else if let Placement::Party(p) = placement {
                if may_read(c, p, &step.assets) {
                    Ok(Some(format!(
                        "{asset} is processed at {p}, which may read everything the step reads"
                    )))
                } else {
                    Err(format!("{p} may not read everything {} reads", step.id))
                }
            } else if has(&|m| matches!(m, Mechanism::SecureAggregation { .. })) {
                Ok(Some(format!(
                    "{asset} leaves its owner only masked; the coordinator unmasks the sum alone"
                )))
            } else {
                Err(format!("{asset} would be readable by the compute host"))
            }
        }
        TrustRequirement::HideFrom {
            asset,
            principal: Principal::Party(p),
        } if reads(asset) => match placement {
            Placement::Party(q) if q == p => Err(format!("{p} would run a step reading {asset}")),
            _ => Ok(None),
        },
        TrustRequirement::AggregateOnly { output, asset } if matches!(&step.kind, StepKind::Aggregate { output: o } if o == output) =>
        {
            let b = boundary.expect("aggregate step");
            if has(
                &|m| matches!(m, Mechanism::SecureAggregation { threshold, .. } if *threshold == b.threshold),
            ) {
                Ok(Some(format!(
                    "the only release boundary for {asset} is the aggregation of {output}, with \
                     threshold {}",
                    b.threshold
                )))
            } else {
                Err(format!("{asset} would be revealed individually"))
            }
        }
        TrustRequirement::MinimumParticipants { output, minimum } if matches!(&step.kind, StepKind::Aggregate { output: o } if o == output) => {
            if has(
                &|m| matches!(m, Mechanism::SecureAggregation { threshold, .. } if threshold >= minimum),
            ) {
                Ok(Some(format!(
                    "the round aborts and releases nothing with fewer than {minimum} parties"
                )))
            } else {
                Err(format!(
                    "{output} could be released with fewer than {minimum} parties"
                ))
            }
        }
        TrustRequirement::PrivacyBudget { asset, .. }
            if reads(asset) && matches!(step.kind, StepKind::Aggregate { .. }) =>
        {
            if has(&|m| matches!(m, Mechanism::DifferentialPrivacy { .. })) {
                Ok(Some(format!(
                    "every release of the aggregate adds discrete Gaussian noise and is charged \
                     to {asset}'s ledger"
                )))
            } else {
                Err(format!(
                    "releases from {asset} would not be noised or accounted"
                ))
            }
        }
        TrustRequirement::RequireAttestation { step: s } if *s == step.id => {
            if has(&|m| matches!(m, Mechanism::Attestation { .. })) {
                Ok(Some(format!(
                    "{s}'s workload proves its identity by attestation"
                )))
            } else {
                Err(format!("{s}'s workload would not be attested"))
            }
        }
        TrustRequirement::RequireCorrectness { step: s } if *s == step.id => {
            if has(&|m| matches!(m, Mechanism::VerifiedExecution)) {
                Ok(Some(format!(
                    "{s} carries a re-execution proof the client checks before decrypting"
                )))
            } else {
                Err(format!("{s}'s result would not be verifiable"))
            }
        }
        // Infrastructure the planner chooses must be in the region; a
        // party's own premises are its own.
        TrustRequirement::ExecutionRegion { region } => match placement {
            Placement::Tee(t) if t.region.as_ref() != Some(region) => {
                Err(format!("the TEE is not in {region}"))
            }
            Placement::Tee(_) | Placement::UntrustedHost => Ok(Some(format!(
                "{} runs on infrastructure in {region}",
                step.id
            ))),
            Placement::Party(_) | Placement::Parties => Ok(Some(format!(
                "{} runs on the parties' own premises",
                step.id
            ))),
        },
        _ => Ok(None),
    }
}

fn global_satisfaction(req: &TrustRequirement) -> Option<RequirementSatisfaction> {
    let (by, reason) = match req {
        TrustRequirement::HideFrom {
            asset,
            principal: Principal::Party(p),
        } => (
            vec![Mechanism::PolicyEnforcement],
            format!(
                "the compiler proved no output reveals {asset} to {p}, and no step reading it \
                 runs at {p}"
            ),
        ),
        TrustRequirement::Purpose { asset, purpose } => (
            vec![Mechanism::PolicyEnforcement, Mechanism::OwnerAuthorization],
            format!(
                "the compiler checked {asset} is used only for \"{purpose}\"; its owners approve \
                 this program for that purpose"
            ),
        ),
        TrustRequirement::PrivacyBudget { asset, .. } => (
            vec![Mechanism::PolicyEnforcement],
            format!("the compiler proved every release of {asset} passes a privacy mechanism"),
        ),
        TrustRequirement::SignedEvidence => (
            vec![Mechanism::SignedReceipts],
            "every execution, aggregation and release issues a signed receipt".into(),
        ),
        _ => return None,
    };
    let evidence = by.iter().flat_map(Mechanism::evidence).collect();
    Some(RequirementSatisfaction {
        requirement: req.clone(),
        step: None,
        satisfied_by: by,
        reason,
        evidence,
    })
}

/// Requirements a step must discharge.
fn touches(req: &TrustRequirement, step: &StepShape) -> bool {
    let reads = |a: &str| step.assets.iter().any(|x| x == a);
    match req {
        TrustRequirement::HideFrom { asset, .. } => reads(asset),
        TrustRequirement::AggregateOnly { output, .. }
        | TrustRequirement::MinimumParticipants { output, .. } => {
            matches!(&step.kind, StepKind::Aggregate { output: o } if o == output)
        }
        TrustRequirement::PrivacyBudget { asset, .. } => {
            reads(asset) && matches!(step.kind, StepKind::Aggregate { .. })
        }
        TrustRequirement::RequireAttestation { step: s }
        | TrustRequirement::RequireCorrectness { step: s } => *s == step.id,
        TrustRequirement::ExecutionRegion { .. } => true,
        TrustRequirement::Purpose { .. } | TrustRequirement::SignedEvidence => false,
    }
}

/// The result of planning: a plan, or why none exists, and every
/// candidate considered.
pub struct Planned {
    pub plan: Option<ConfidentialExecutionPlan>,
    pub requirements: Vec<TrustRequirement>,
    pub candidates: Vec<Candidate>,
    /// Steps no candidate could run, with every candidate's reason.
    pub failures: Vec<(String, Vec<String>)>,
}

/// Plans `program` in `ctx`.
pub fn plan(program: &Program, ctx: &PlanningContext) -> Result<Planned> {
    let report = analyze(program)?;
    let c = program.confidentiality();
    let requirements = derive(program, ctx)?;
    let shapes = steps(program, report.as_ref(), ctx)?;
    let mut candidates = vec![];
    let mut failures = vec![];
    let mut chosen: Vec<(ExecutionStep, Vec<RequirementSatisfaction>)> = vec![];
    for step in &shapes {
        let boundary = match &step.kind {
            StepKind::Aggregate { output } => report
                .as_ref()
                .and_then(|r| r.aggregations.iter().find(|b| &b.output == output)),
            _ => None,
        };
        let n = boundary.map_or(0, |b| b.contributions.len() as u64);
        let mut best: Option<(u64, Candidate, Vec<RequirementSatisfaction>)> = None;
        let mut reasons = vec![];
        let mut here = vec![];
        for o in options(step, c, boundary, ctx) {
            let est = estimate(step, &o.placement, &o.mechanisms, ctx, n);
            let mut cand = Candidate {
                step: step.id.clone(),
                placement: o.placement.clone(),
                mechanisms: o.mechanisms.clone(),
                estimated_ms: est,
                rejected: o.unavailable.clone(),
                selected: false,
            };
            let mut sats = vec![];
            if cand.rejected.is_none() {
                for r in requirements.iter().filter(|r| touches(r, step)) {
                    match satisfies(r, step, &o.placement, &o.mechanisms, c, boundary) {
                        Ok(reason) => {
                            if let Some(reason) = reason {
                                let by: Vec<Mechanism> = o.mechanisms.clone();
                                sats.push(RequirementSatisfaction {
                                    requirement: r.clone(),
                                    step: Some(step.id.clone()),
                                    evidence: by.iter().flat_map(Mechanism::evidence).collect(),
                                    satisfied_by: by,
                                    reason,
                                });
                            }
                        }
                        Err(why) => {
                            cand.rejected = Some(why);
                            break;
                        }
                    }
                }
            }
            match &cand.rejected {
                Some(why) => reasons.push(format!(
                    "{}: {why}",
                    describe(&cand.placement, &cand.mechanisms)
                )),
                None => {
                    let s = score(&cand, ctx);
                    let key = serde_json::to_string(&cand.mechanisms).expect("JSON");
                    let better = match &best {
                        None => true,
                        Some((bs, bc, _)) => {
                            (s, key.as_str())
                                < (
                                    *bs,
                                    serde_json::to_string(&bc.mechanisms)
                                        .expect("JSON")
                                        .as_str(),
                                )
                        }
                    };
                    if better {
                        best = Some((s, cand.clone(), sats));
                    }
                }
            }
            here.push(cand);
        }
        match best {
            Some((_, b, sats)) => {
                for c in here.iter_mut() {
                    c.selected = c.placement == b.placement && c.mechanisms == b.mechanisms;
                }
                chosen.push((
                    ExecutionStep {
                        id: step.id.clone(),
                        kind: step.kind.clone(),
                        assets: step.assets.clone(),
                        placement: b.placement,
                        mechanisms: b.mechanisms,
                        estimated_ms: b.estimated_ms,
                    },
                    sats,
                ));
            }
            None => failures.push((step.id.clone(), reasons)),
        }
        candidates.extend(here);
    }
    if !failures.is_empty() {
        return Ok(Planned {
            plan: None,
            requirements,
            candidates,
            failures,
        });
    }
    let mut satisfaction = vec![];
    for r in &requirements {
        if let Some(s) = global_satisfaction(r) {
            satisfaction.push(s);
        }
    }
    let mut steps_out = vec![];
    for (s, sats) in chosen {
        satisfaction.extend(sats);
        steps_out.push(s);
    }
    let mut selected: BTreeSet<Mechanism> = steps_out
        .iter()
        .flat_map(|s| s.mechanisms.iter().cloned())
        .collect();
    selected.insert(Mechanism::PolicyEnforcement);
    selected.insert(Mechanism::SignedReceipts);
    if c.is_some() {
        selected.insert(Mechanism::OwnerAuthorization);
    }
    let evidence_required: BTreeSet<EvidenceKind> =
        selected.iter().flat_map(Mechanism::evidence).collect();
    let estimated_ms = steps_out.iter().map(|s| s.estimated_ms).sum();
    let plan = ConfidentialExecutionPlan {
        version: PLAN_VERSION,
        program_id: program_id(program),
        policy_id: c.map(|c| PolicyId::of(c).hex()),
        privacy_policy_id: c.and_then(PrivacyPolicyId::of).map(|p| p.hex()),
        context: ctx.clone(),
        requirements: requirements.clone(),
        steps: steps_out,
        satisfaction,
        selected_mechanisms: selected,
        evidence_required,
        estimated_ms,
    };
    Ok(Planned {
        plan: Some(plan),
        requirements,
        candidates,
        failures,
    })
}

/// `placement: mechanisms`, for messages.
pub fn describe(p: &Placement, mechs: &[Mechanism]) -> String {
    let at = match p {
        Placement::UntrustedHost => "ordinary host".to_owned(),
        Placement::Tee(t) => format!("{} TEE", t.tee),
        Placement::Party(p) => format!("at {p}"),
        Placement::Parties => "across the parties".to_owned(),
    };
    if mechs.is_empty() {
        format!("{at}, unprotected")
    } else {
        format!(
            "{at}, {}",
            mechs
                .iter()
                .map(Mechanism::name)
                .collect::<Vec<_>>()
                .join(" + ")
        )
    }
}

/// Plans, or fails with PLANNING FAILED and every reason.
pub fn plan_or_fail(program: &Program, ctx: &PlanningContext) -> Result<ConfidentialExecutionPlan> {
    let p = plan(program, ctx)?;
    match p.plan {
        Some(plan) => Ok(plan),
        None => {
            let mut m = String::from("PLANNING FAILED: no execution plan satisfies the policy");
            for (step, reasons) in &p.failures {
                m.push_str(&format!("\n  {step}:"));
                for r in reasons {
                    m.push_str(&format!("\n    - {r}"));
                }
            }
            Err(Error::new(Code::PlanningFailed, m))
        }
    }
}

/// Requirements grouped by the asset or step they concern (for display).
pub fn by_subject(reqs: &[TrustRequirement]) -> BTreeMap<String, Vec<&TrustRequirement>> {
    let mut m: BTreeMap<String, Vec<&TrustRequirement>> = BTreeMap::new();
    for r in reqs {
        let k = match r {
            TrustRequirement::HideFrom { asset, .. }
            | TrustRequirement::AggregateOnly { asset, .. }
            | TrustRequirement::Purpose { asset, .. }
            | TrustRequirement::PrivacyBudget { asset, .. } => asset.clone(),
            TrustRequirement::RequireAttestation { step }
            | TrustRequirement::RequireCorrectness { step } => step.clone(),
            TrustRequirement::MinimumParticipants { output, .. } => output.clone(),
            TrustRequirement::ExecutionRegion { .. } | TrustRequirement::SignedEvidence => {
                "everything".into()
            }
        };
        m.entry(k).or_default().push(r);
    }
    m
}
