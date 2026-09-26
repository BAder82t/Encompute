//! Plans in words: every requirement, the mechanism that satisfies it, why,
//! and the evidence to expect. Costs are always labelled estimates.

use std::fmt::Write;

use crate::model::*;
use crate::planner::{by_subject, describe, Planned};

const RULE: &str = "────────────────────────────";

pub fn requirement(r: &TrustRequirement) -> String {
    match r {
        TrustRequirement::HideFrom { asset, principal } => {
            format!("{asset} hidden from {principal}")
        }
        TrustRequirement::AggregateOnly { asset, output } => {
            format!("{asset} revealed only inside the aggregate {output}")
        }
        TrustRequirement::Purpose { asset, purpose } => {
            format!("{asset} used only for \"{purpose}\"")
        }
        TrustRequirement::PrivacyBudget {
            asset,
            unit,
            epsilon,
            delta,
        } => format!("{asset}: {unit}-level privacy, ε ≤ {epsilon}, δ ≤ {delta}"),
        TrustRequirement::RequireAttestation { step } => format!("{step}: attested workload"),
        TrustRequirement::RequireCorrectness { step } => {
            format!("{step}: correctness verifiable")
        }
        TrustRequirement::MinimumParticipants { output, minimum } => {
            format!("{output}: at least {minimum} contributors")
        }
        TrustRequirement::ExecutionRegion { region } => format!("everything runs in {region}"),
        TrustRequirement::SignedEvidence => "every execution leaves signed evidence".into(),
    }
}

fn requirements(s: &mut String, reqs: &[TrustRequirement]) {
    let _ = writeln!(s, "Requirements\n{RULE}");
    for (subject, rs) in by_subject(reqs) {
        let _ = writeln!(s, "{subject}");
        for r in rs {
            let _ = writeln!(s, "  {}", requirement(r));
        }
    }
}

/// `encompute plan`.
pub fn plan(p: &ConfidentialExecutionPlan) -> String {
    let mut s = String::new();
    let id = p.id().map(|i| i.to_string()).unwrap_or_default();
    let _ = writeln!(
        s,
        "ENCOMPUTE PLAN\n{id}\nprofile {} ({})\n",
        p.context.profile.name(),
        p.context.profile.expands_to().join("; ")
    );
    requirements(&mut s, &p.requirements);
    let _ = writeln!(s, "\nSelected mechanisms\n{RULE}");
    for st in &p.steps {
        let _ = writeln!(s, "{}", st.id);
        let _ = writeln!(s, "  {}", describe(&st.placement, &st.mechanisms));
        let _ = writeln!(s, "  estimated {} ms", st.estimated_ms);
    }
    let _ = writeln!(s, "\nWhy\n{RULE}");
    for x in &p.satisfaction {
        let _ = writeln!(s, "Requirement   {}", requirement(&x.requirement));
        let _ = writeln!(
            s,
            "Satisfied by  {}",
            x.satisfied_by
                .iter()
                .map(Mechanism::name)
                .collect::<Vec<_>>()
                .join(" + ")
        );
        let _ = writeln!(s, "Reason        {}", x.reason);
        if !x.evidence.is_empty() {
            let _ = writeln!(
                s,
                "Evidence      {}",
                x.evidence
                    .iter()
                    .map(|e| e.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let _ = writeln!(s);
    }
    let _ = writeln!(s, "Evidence required\n{RULE}");
    for e in &p.evidence_required {
        let _ = writeln!(s, "{}", e.name());
    }
    let _ = writeln!(
        s,
        "\nRESULT\nALL TRUST REQUIREMENTS SATISFIED\n(estimated {} ms in total; estimates, not \
         guarantees)",
        p.estimated_ms
    );
    s
}

/// PLANNING FAILED, with every candidate's reason.
pub fn failure(p: &Planned) -> String {
    let mut s = String::from("ENCOMPUTE PLAN\n\n");
    requirements(&mut s, &p.requirements);
    let _ = writeln!(s, "\nNo valid mechanism\n{RULE}");
    for (step, reasons) in &p.failures {
        let _ = writeln!(s, "{step}");
        for r in reasons {
            let _ = writeln!(s, "  - {r}");
        }
    }
    let _ = writeln!(
        s,
        "\nRESULT\nPLANNING FAILED\nNo execution plan satisfies the policy; no requirement \
         was weakened."
    );
    s
}

/// `explain --deep`: every candidate, why it was rejected, assumptions.
pub fn deep(p: &Planned) -> String {
    let mut s = String::from("PLANNER (deep)\n\nCandidates\n");
    let _ = writeln!(s, "{RULE}");
    let mut last = String::new();
    for c in &p.candidates {
        if c.step != last {
            let _ = writeln!(s, "{}", c.step);
            last = c.step.clone();
        }
        let tag = if c.selected {
            "SELECTED".to_owned()
        } else if let Some(r) = &c.rejected {
            format!("rejected: {r}")
        } else {
            "valid, costlier".to_owned()
        };
        let _ = writeln!(
            s,
            "  {} (estimated {} ms)\n    {tag}",
            describe(&c.placement, &c.mechanisms),
            c.estimated_ms
        );
    }
    let _ = writeln!(s, "\nSecurity assumptions\n{RULE}");
    for a in [
        "FHE: the RLWE/LWE parameters meet the security table; the client keeps its secret key",
        "TEE: the hardware vendor's attestation and memory encryption are sound",
        "Secure aggregation: at most the declared number of parties collude with the coordinator",
        "Differential privacy: the discrete Gaussian sampler and zCDP accounting (CKS 2020)",
        "Verified execution: re-execution proofs cover every operation (sound, not succinct)",
        "Owners obtain each other's keys out of band (parties.json)",
    ] {
        let _ = writeln!(s, "- {a}");
    }
    let _ = writeln!(
        s,
        "\nCosts are coarse estimates per mechanism, not measurements or guarantees."
    );
    s
}
