//! Placement in the planner: which evaluators the effective constraints
//! admit, and why the others are refused.
//!
//! Capability, location, operator and evidence are judged together
//! ([`evaluator_unusable`]). The reasons never reveal one organization's
//! private constraint values to another: a refusal by the project's
//! constraints (which every member holds) names the field and the machine;
//! a refusal by an organization's own constraints names only the
//! organization and the field.

use std::collections::BTreeSet;

use encompute_verification::placement::{
    locations, refusals, sources_digest, LocationEvidence, Machine, Origin, PlacementSource,
    Refused, Scope,
};

use crate::model::*;

/// The steps that handle only ciphertexts (an evaluator): the scope their
/// constraints cover.
pub const CIPHERTEXT_STEP: [Scope; 1] = [Scope::Ciphertext];

/// The evaluators admissible for a plan, and each excluded one's reason.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Admission {
    pub admitted: Vec<AdmittedEvaluator>,
    /// `(evaluator, reason)`.
    pub excluded: Vec<(String, String)>,
    /// The excluded evaluators refused for operator separation.
    pub separation: BTreeSet<String>,
    /// Excluded evaluators of organizations outside the project: never
    /// listed in a reason (another tenant's infrastructure is not for the
    /// project's members to see).
    pub hidden: BTreeSet<String>,
}

impl Admission {
    /// Nothing is admitted, and every evaluator that exists was refused
    /// for operator separation (the operators are all source owners or
    /// decryptors): the refusal is about who operates, not where.
    pub fn only_separation_refused(&self) -> bool {
        self.admitted.is_empty()
            && !self.excluded.is_empty()
            && self.separation.len() == self.excluded.len()
    }

    pub fn ids(&self) -> BTreeSet<&str> {
        self.admitted.iter().map(|a| a.id.as_str()).collect()
    }

    /// Why nothing is admitted, for a planning failure.
    pub fn why_none(&self) -> String {
        let shown: Vec<String> = self
            .excluded
            .iter()
            .filter(|(id, _)| !self.hidden.contains(id))
            .map(|(id, why)| format!("evaluator {id}: {why}"))
            .collect();
        let hidden = self.hidden.len();
        match (shown.is_empty(), hidden) {
            (true, 0) => "no evaluator is registered".to_owned(),
            (true, n) => {
                format!("{n} evaluator(s) of organizations outside the project are not admissible")
            }
            (false, 0) => shown.join("; "),
            (false, n) => format!(
                "{}; {n} evaluator(s) of organizations outside the project are not admissible",
                shown.join("; ")
            ),
        }
    }
}

fn describe_refusal(origin: &Origin, why: &[Refused], location: Option<&Location>) -> String {
    let fields: Vec<&str> = why.iter().map(Refused::field).collect();
    match origin {
        // Every member holds the project's constraints.
        Origin::Project(_) => format!(
            "the project's placement excludes it ({}{})",
            fields.join(", "),
            location.map_or(String::new(), |l| format!("; it is at {}", l.display()))
        ),
        // Another organization's values stay private: its name and the
        // field only.
        Origin::Organization(_) => {
            format!("{}: {} excludes it", origin.describe(), fields.join(", "))
        }
    }
}

/// Why `offer` cannot run ciphertext steps of a job whose ciphertexts are
/// also constrained by `extra` (the owners' own constraints, applied where
/// the job is bound), or `None` when it can. `backend` is the encrypted
/// backend the step needs, when it needs one; `decryptors` the
/// organizations that hold a decryption key for the output.
///
/// Judged together, in this order: capability (backend), operator
/// separation, then location, operator and evidence under every covering
/// constraint (deny wins; an unknown location is inadmissible under any
/// location rule; production never accepts a self-declared location).
pub fn evaluator_unusable(
    offer: &EvaluatorOffer,
    backend: Option<&str>,
    pc: &PlacementContext,
    extra: &[PlacementSource],
    decryptors: &BTreeSet<String>,
) -> Option<String> {
    judge(offer, backend, pc, extra, decryptors).map(|u| u.why)
}

/// Why an evaluator is unusable, and whether operator separation is the
/// reason.
pub struct Unusable {
    pub why: String,
    pub separation: bool,
    /// The evaluator's operator takes no part in the project.
    pub outsider: bool,
}

/// The operator of the platform's own evaluators.
pub const PLATFORM_OPERATOR: &str = "platform";

/// [`evaluator_unusable`] with the kind of reason.
pub fn judge(
    offer: &EvaluatorOffer,
    backend: Option<&str>,
    pc: &PlacementContext,
    extra: &[PlacementSource],
    decryptors: &BTreeSet<String>,
) -> Option<Unusable> {
    let no = |why: String| Unusable {
        why,
        separation: false,
        outsider: false,
    };
    if let Some(b) = backend {
        if !offer.backends.iter().any(|x| x == b) {
            return Some(no(format!("it does not offer the {b} backend")));
        }
    }
    // Operator separation: whoever runs the evaluator is neither a source
    // owner nor a decryptor.
    if pc.roles.source_owners.contains(&offer.operator) {
        return Some(Unusable {
            why: format!(
                "its operator {} owns a source of the job (operator separation)",
                offer.operator
            ),
            separation: true,
            outsider: false,
        });
    }
    if pc.roles.decryptors.contains(&offer.operator) || decryptors.contains(&offer.operator) {
        return Some(Unusable {
            why: format!(
                "its operator {} holds a decryption key for the output (operator separation)",
                offer.operator
            ),
            separation: true,
            outsider: false,
        });
    }
    let mut sources: Vec<PlacementSource> = pc.constraints.clone();
    sources.extend(extra.iter().cloned());
    // Deny by default: another tenant's evaluator is admissible only when
    // its operator takes part in the project, or a constraint names the
    // operator or the evaluator. The platform's own are the exception.
    if offer.operator != PLATFORM_OPERATOR
        && !pc.roles.participants.contains(&offer.operator)
        && !sources.iter().any(|s| {
            s.constraints
                .allowed_operators
                .as_ref()
                .is_some_and(|o| o.contains(&offer.operator))
                || s.constraints
                    .allowed_evaluators
                    .as_ref()
                    .is_some_and(|e| e.contains(&offer.id))
        })
    {
        return Some(Unusable {
            why: format!(
                "its operator {} takes no part in the project and no constraint names it",
                offer.operator
            ),
            separation: false,
            outsider: true,
        });
    }
    if pc.production {
        // Production: a self-declared location satisfies nothing. The
        // floor applies wherever a constraint cares about location.
        for s in &mut sources {
            let c = &mut s.constraints;
            if c.allowed_regions.is_some() || !c.prohibited_locations.is_empty() {
                c.min_evidence = c.min_evidence.max(LocationEvidence::OperatorDeclared);
            }
        }
    }
    let machine = Machine {
        id: &offer.id,
        operator: &offer.operator,
        location: offer.location.as_ref(),
        evidence: offer.evidence,
    };
    let bad = refusals(&sources, &CIPHERTEXT_STEP, &machine);
    if bad.is_empty() {
        return None;
    }
    Some(no(bad
        .iter()
        .map(|(o, why)| describe_refusal(o, why, offer.location.as_ref()))
        .collect::<Vec<_>>()
        .join("; ")))
}

/// The evaluators of `ctx` admissible for `backend` (any when `None`),
/// under the plan's shared constraints plus `extra`.
pub fn admission(
    ctx: &PlanningContext,
    backend: Option<&str>,
    extra: &[PlacementSource],
    decryptors: &BTreeSet<String>,
) -> Admission {
    let Some(pc) = &ctx.placement else {
        return Admission::default();
    };
    let mut out = Admission::default();
    let mut offers: Vec<&EvaluatorOffer> = ctx.infrastructure.evaluators.iter().collect();
    offers.sort();
    offers.dedup();
    for o in offers {
        match judge(o, backend, pc, extra, decryptors) {
            Some(u) => {
                if u.separation {
                    out.separation.insert(o.id.clone());
                }
                if u.outsider {
                    out.hidden.insert(o.id.clone());
                }
                out.excluded.push((o.id.clone(), u.why));
            }
            None => out.admitted.push(AdmittedEvaluator {
                id: o.id.clone(),
                operator: o.operator.clone(),
                location: o.location.clone(),
                evidence: o.evidence,
                evidence_digest: o.evidence_digest.clone(),
                endpoint_digest: o.endpoint_digest.clone(),
            }),
        }
    }
    out.admitted.sort();
    out
}

/// The placement a plan records: for every encrypted backend its ciphertext
/// steps use, the evaluators admitted for all of them. `None` outside
/// governed projects.
pub fn plan_placement(ctx: &PlanningContext, steps: &[ExecutionStep]) -> Option<PlanPlacement> {
    let pc = ctx.placement.as_ref()?;
    let backends: BTreeSet<&str> = steps
        .iter()
        .filter(|s| s.placement == Placement::UntrustedHost)
        .flat_map(|s| s.mechanisms.iter())
        .filter_map(|m| match m {
            Mechanism::Fhe { backend, .. } => Some(backend.as_str()),
            _ => None,
        })
        .collect();
    let none = BTreeSet::new();
    let mut admitted: Option<Vec<AdmittedEvaluator>> = None;
    for b in backends {
        let a = admission(ctx, Some(b), &[], &none).admitted;
        admitted = Some(match admitted {
            None => a,
            Some(prev) => prev.into_iter().filter(|x| a.contains(x)).collect(),
        });
    }
    Some(PlanPlacement {
        constraints_digest: sources_digest(&pc.constraints),
        locations_digest: pc.locations_digest.clone(),
        admissible: admitted.unwrap_or_default(),
    })
}

/// The current locations table's digest (what a new plan records).
pub fn locations_digest() -> String {
    locations::digest()
}

/// Whether `ctx`'s placement says a SecAgg coordinator conflicts with a
/// contributor: the coordinator's operator owns a source.
pub fn coordinator_conflict(ctx: &PlanningContext) -> Option<String> {
    let pc = ctx.placement.as_ref()?;
    let c = pc.roles.coordinator.as_ref()?;
    pc.roles.source_owners.contains(c).then(|| {
        format!("the SecAgg coordinator {c} also contributes to the round (operator separation)")
    })
}
