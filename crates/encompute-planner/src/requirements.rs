//! Trust requirements, derived from what the program declares: who owns
//! each asset, who may read it, what it may be used for, how it may be
//! released, its privacy budget, and whether results must be verifiable.
//! The profile adds requirements, visibly; it never removes any.

use std::collections::BTreeSet;

use encompute_analysis::confidentiality::{analyze, ConfidentialityReport};
use encompute_ir::confidentiality::{Confidentiality, Release};
use encompute_ir::Verification;
use encompute_ir::{Code, Error, Program, Result};

use crate::model::{PlanningContext, Principal, Profile, StepKind, TrustRequirement};

/// A step before mechanisms are chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepShape {
    pub id: String,
    pub kind: StepKind,
    pub assets: Vec<String>,
}

/// The name under which an unbound secret input is an asset.
pub fn input_asset(input: &str) -> String {
    format!("input:{input}")
}

/// The program's steps: one per aggregation boundary; otherwise one
/// evaluation; plus one training step per declared data asset.
pub fn steps(
    program: &Program,
    report: Option<&ConfidentialityReport>,
    ctx: &PlanningContext,
) -> Result<Vec<StepShape>> {
    let mut out = vec![];
    if let Some(t) = &ctx.training {
        let c = program.confidentiality().ok_or_else(|| {
            Error::new(
                Code::PlanningFailed,
                "training needs declared parties and assets",
            )
        })?;
        for a in std::iter::once(&t.model).chain(&t.data) {
            if c.asset(a).is_none() {
                return Err(Error::new(
                    Code::PlanningFailed,
                    format!("training names {a}, which the program does not declare"),
                ));
            }
        }
        for d in &t.data {
            out.push(StepShape {
                id: format!("train:{d}"),
                kind: StepKind::Train {
                    data: d.clone(),
                    model: t.model.clone(),
                },
                assets: vec![d.clone(), t.model.clone()],
            });
        }
    }
    let boundaries = report.map(|r| r.aggregations.as_slice()).unwrap_or(&[]);
    if boundaries.is_empty() {
        let c = program.confidentiality();
        let mut assets: Vec<String> = program
            .inputs()
            .map(|(_, name, _, _)| {
                c.and_then(|c| c.inputs.get(name).cloned())
                    .unwrap_or_else(|| input_asset(name))
            })
            .collect();
        assets.sort();
        assets.dedup();
        out.push(StepShape {
            id: "evaluate".into(),
            kind: StepKind::Evaluate,
            assets,
        });
    }
    for b in boundaries {
        let mut assets: Vec<String> = b.contributions.iter().map(|x| x.asset.clone()).collect();
        assets.sort();
        assets.dedup();
        out.push(StepShape {
            id: format!("aggregate:{}", b.output),
            kind: StepKind::Aggregate {
                output: b.output.clone(),
            },
            assets,
        });
    }
    Ok(out)
}

fn release(c: Option<&Confidentiality>, asset: &str) -> Release {
    c.and_then(|c| c.asset(asset))
        .map(|a| a.policy.release)
        .unwrap_or(Release::Never)
}

/// Every hard requirement, sorted and deduplicated.
pub fn derive(program: &Program, ctx: &PlanningContext) -> Result<Vec<TrustRequirement>> {
    let report = analyze(program)?;
    let shapes = steps(program, report.as_ref(), ctx)?;
    let c = program.confidentiality();
    let mut r: BTreeSet<TrustRequirement> = BTreeSet::new();
    r.insert(TrustRequirement::SignedEvidence);
    if let Some(c) = c {
        for a in &c.assets {
            // Only the audience (owners and readers) may read an asset.
            for p in &c.parties {
                if !a.policy.owners.contains(&p.id) && !a.policy.readers.contains(&p.id) {
                    r.insert(TrustRequirement::HideFrom {
                        asset: a.id.clone(),
                        principal: Principal::Party(p.id.to_string()),
                    });
                }
            }
            if !a.policy.purposes.is_empty() {
                r.insert(TrustRequirement::Purpose {
                    asset: a.id.clone(),
                    purpose: c.purpose.clone().unwrap_or_default(),
                });
            }
            if let Some(b) = &a.policy.privacy {
                r.insert(TrustRequirement::PrivacyBudget {
                    asset: a.id.clone(),
                    unit: b.unit.to_string(),
                    epsilon: format!("{:?}", b.epsilon),
                    delta: format!("{:?}", b.delta),
                });
            }
        }
    }
    for s in &shapes {
        for a in &s.assets {
            if release(c, a) != Release::Public {
                r.insert(TrustRequirement::HideFrom {
                    asset: a.clone(),
                    principal: Principal::ComputeHost,
                });
            }
        }
        match &s.kind {
            StepKind::Evaluate => {
                if program.verification() == Verification::Required
                    || ctx.profile == Profile::Maximum
                {
                    r.insert(TrustRequirement::RequireCorrectness { step: s.id.clone() });
                }
            }
            StepKind::Aggregate { output } => {
                let b = report
                    .as_ref()
                    .and_then(|x| x.aggregations.iter().find(|b| &b.output == output))
                    .expect("a step per boundary");
                for x in &b.contributions {
                    if release(c, &x.asset) == Release::AggregateOnly {
                        r.insert(TrustRequirement::AggregateOnly {
                            asset: x.asset.clone(),
                            output: output.clone(),
                        });
                    }
                }
                r.insert(TrustRequirement::MinimumParticipants {
                    output: output.clone(),
                    minimum: b.minimum,
                });
                if ctx.profile >= Profile::Strong {
                    r.insert(TrustRequirement::RequireAttestation { step: s.id.clone() });
                }
            }
            StepKind::Train { .. } => {
                if ctx.training.as_ref().is_some_and(|t| t.verified) {
                    r.insert(TrustRequirement::RequireAttestation { step: s.id.clone() });
                }
            }
        }
    }
    if let Some(region) = &ctx.preferences.region {
        r.insert(TrustRequirement::ExecutionRegion {
            region: region.clone(),
        });
    }
    Ok(r.into_iter().collect())
}
