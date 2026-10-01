//! `encompute explain --governance`: a governed computation in words, for
//! a data-protection officer, an auditor or a program owner, rendered from
//! the evidence this machine verified against its own pins, never from the
//! server's opinion of it (ADR-027).
//!
//! Sections, in order: What was computed; Who owned the data; Why; Who
//! approved; Where it ran; What was released; Which protections applied;
//! What evidence exists; What this does not tell you; Verdict. A section
//! (or a line of one) whose evidence did not verify prints
//! `not verified: <why>` in place of its content.

use std::fmt::Write;

use encompute_runtime::trust::{
    GovernanceBundle, GovernanceRow, NodeKind, Status, Verdict, Verified, LEGAL_BOUNDARY,
};
use encompute_verification::governance::ReleaseClass;

const RULE: &str = "────────────────────────";

fn passes(s: Status) -> bool {
    matches!(
        s,
        Status::Verified
            | Status::Satisfied
            | Status::Authorized
            | Status::Attested
            | Status::Complete
            | Status::NotApplicable
    )
}

fn row<'a>(v: &'a Verified, name: &str) -> &'a GovernanceRow {
    v.report
        .row(name)
        .unwrap_or_else(|| panic!("the report has a {name} row"))
}

/// Why a row did not verify, in one line.
fn why(r: &GovernanceRow) -> String {
    let d = r
        .details
        .iter()
        .find(|d| !d.starts_with("ownership means") && !d.starts_with("NO means"))
        .or(r.details.first())
        .cloned()
        .unwrap_or_else(|| "no evidence".into());
    format!("not verified: {} ({d})", r.name)
}

fn class_words(c: ReleaseClass) -> &'static str {
    match c {
        ReleaseClass::Never => "nothing (never released)",
        ReleaseClass::BooleanOnly => "a yes/no (or a bounded category)",
        ReleaseClass::AggregateOnly => "an aggregate",
        ReleaseClass::DpAggregateOnly => "a differentially private aggregate",
        ReleaseClass::AuthorizedAgencyOnly => "a result for authorized agencies only",
        ReleaseClass::DerivedArtifactOnly => "a derived artifact",
    }
}

fn short(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

fn section(out: &mut String, title: &str) {
    let _ = writeln!(out, "\n{title}");
}

/// The explanation of `b`, from what `v` verified.
pub fn render(b: &GovernanceBundle, v: &Verified) -> String {
    let mut o = String::new();
    let gg = b.governance.grant.governance.as_ref();
    let _ = writeln!(o, "GOVERNED COMPUTATION: {}", b.manifest.job_ids.join(", "));
    let _ = writeln!(o, "{RULE}");
    let _ = writeln!(
        o,
        "project {}; bundle {} ({} view)",
        b.manifest.project_id,
        short(&v.bundle_id),
        v.view
    );

    // WHAT WAS COMPUTED
    section(&mut o, "WHAT WAS COMPUTED");
    let exec = row(v, "Execution evidence");
    match (passes(exec.status), gg) {
        (true, Some(gg)) => {
            let name = b
                .trust
                .of(NodeKind::Program)
                .next()
                .map_or("a program", |(_, n)| n.label.as_str());
            let _ = writeln!(
                o,
                "  {name} (program {}) over {} dataset(s), for the purpose {:?}.",
                short(&b.governance.spec.program_id),
                gg.binding.inputs.len(),
                b.governance.purpose.name
            );
            for (out, rel) in &gg.binding.outputs {
                let to: Vec<&str> = rel.recipients.iter().map(String::as_str).collect();
                let _ = writeln!(
                    o,
                    "  Output {out}: {}{}.",
                    class_words(rel.release_class),
                    if to.is_empty() {
                        String::new()
                    } else {
                        format!(", to {}", to.join(", "))
                    }
                );
            }
        }
        _ => {
            let _ = writeln!(o, "  {}", why(exec));
        }
    }

    // WHO OWNED THE DATA
    section(&mut o, "WHO OWNED THE DATA");
    let sources = row(v, "Source assets");
    match (passes(sources.status), gg) {
        (true, Some(gg)) => {
            for (name, i) in &gg.binding.inputs {
                let _ = writeln!(
                    o,
                    "  {name:<12} version {}  owned by {}",
                    short(&i.asset_version_id),
                    i.organization
                );
            }
        }
        _ => {
            let _ = writeln!(o, "  {}", why(sources));
        }
    }
    for (label, name) in [
        ("Key custody", "Key custody"),
        ("Raw data centralized", "Raw data centralized"),
        ("Ownership retained", "Ownership retained"),
    ] {
        let r = row(v, name);
        match (&r.value, passes(r.status)) {
            (Some(val), true) => {
                let _ = writeln!(o, "  {label}: {val}");
            }
            _ => {
                let _ = writeln!(o, "  {label}: {}", why(r));
            }
        }
    }

    // WHY
    section(&mut o, "WHY");
    let purpose = row(v, "Purpose");
    if passes(purpose.status) {
        let p = &b.governance.purpose;
        let _ = writeln!(o, "  Purpose: {}. {}", p.name, p.description);
        match &p.legal_basis_ref {
            Some(l) => {
                let _ = writeln!(o, "  Legal reference: {l} (recorded, not checked).");
            }
            None => {
                let _ = writeln!(o, "  No legal reference was recorded.");
            }
        }
        let project = row(v, "Project");
        if passes(project.status) {
            let _ = writeln!(
                o,
                "  Every organization whose data was used signed its acceptance."
            );
        } else {
            let _ = writeln!(o, "  {}", why(project));
        }
    } else {
        let _ = writeln!(o, "  {}", why(purpose));
    }

    // WHO APPROVED
    section(&mut o, "WHO APPROVED");
    let appr = row(v, "Approvals");
    if passes(appr.status) {
        for d in appr
            .details
            .iter()
            .filter(|d| d.contains("distinct approver"))
        {
            let _ = writeln!(o, "  {d}");
        }
    } else {
        let _ = writeln!(o, "  {}", why(appr));
    }
    let win = row(v, "Authorization window");
    if passes(win.status) {
        let _ = writeln!(
            o,
            "  Every authorization was valid when the job ran (signed time {}), and is judged then, not now.",
            b.governance.grant.issued_at
        );
    } else {
        let _ = writeln!(o, "  {}", why(win));
    }
    for l in &v.report.authorization_now {
        let _ = writeln!(o, "  {l}");
    }

    // WHERE IT RAN
    section(&mut o, "WHERE IT RAN");
    let _ = writeln!(o, "  Evaluator {}.", b.governance.grant.evaluator);
    let mech = row(v, "Mechanism");
    if passes(mech.status) {
        for d in &mech.details {
            let _ = writeln!(o, "  {d}");
        }
    } else {
        let _ = writeln!(o, "  {}", why(mech));
    }
    let loc = row(v, "Location");
    match loc.status {
        Status::NotApplicable => {
            let _ = writeln!(
                o,
                "  No placement constraint was declared; where it ran is not shown."
            );
        }
        _ if passes(loc.status) => {
            // Every line of a passing location row carries its own
            // "assuming an honest control plane".
            if let Some(v) = &loc.value {
                let _ = writeln!(o, "  Placement: {v}");
            }
            for d in &loc.details {
                let _ = writeln!(o, "  {d}");
            }
        }
        _ => {
            let _ = writeln!(o, "  {}", why(loc));
        }
    }

    // WHAT WAS RELEASED
    section(&mut o, "WHAT WAS RELEASED");
    let rel = row(v, "Unauthorized releases");
    if passes(rel.status) {
        for r in &b.governance.release_records {
            let to: Vec<&str> = r.body.recipients.keys().map(String::as_str).collect();
            let _ = writeln!(
                o,
                "  {}: {}, to {}; held by {}. No other release.",
                r.body.output,
                class_words(r.body.release_class),
                to.join(", "),
                r.body.party
            );
        }
        if b.governance.release_records.is_empty() {
            let _ = writeln!(o, "  Nothing was released.");
        }
    } else {
        let _ = writeln!(o, "  {}", why(rel));
    }
    let dec = row(v, "Decryption control");
    let _ = writeln!(
        o,
        "  Decryption control: {}",
        if passes(dec.status) {
            dec.value.clone().unwrap_or_default()
        } else {
            why(dec)
        }
    );

    // WHICH PROTECTIONS APPLIED
    section(&mut o, "WHICH PROTECTIONS APPLIED");
    let priv_ = row(v, "Privacy policy");
    match priv_.status {
        Status::NotApplicable => {
            let _ = writeln!(o, "  No differential-privacy budget applies (no privacy policy in the spec or any authorization).");
        }
        s if passes(s) => {
            let _ = writeln!(o, "  Privacy budgets were spent within their policy.");
        }
        _ => {
            let _ = writeln!(o, "  {}", why(priv_));
        }
    }
    let audit = row(v, "Audit chain");
    if passes(audit.status) {
        let _ = writeln!(
            o,
            "  The project's log is witnessed by every member and every owner's revocation head covers the run."
        );
    } else {
        let _ = writeln!(o, "  {}", why(audit));
    }
    for r in &v.report.revocations {
        let _ = writeln!(
            o,
            "  Revocation: {} {} at {} (it stays on record; nothing is erased{}).",
            r.organization.as_deref().unwrap_or("-"),
            r.kind,
            r.at,
            if r.downstream.is_empty() {
                String::new()
            } else {
                format!("; derived results: {}", r.downstream.join(", "))
            }
        );
    }

    // WHAT EVIDENCE EXISTS
    section(&mut o, "WHAT EVIDENCE EXISTS");
    let signed = b
        .governance
        .authorizations
        .iter()
        .filter(|a| {
            matches!(
                a,
                encompute_runtime::trust::AuthorizationEntry::Signed { .. }
            )
        })
        .count();
    let _ = writeln!(
        o,
        "  {} owner authorization(s) ({} signed documents, {} cards), {} release record(s), {} log event(s) with proofs, {} witness(es), {} revocation head(s), {} signature(s) on this bundle.",
        b.governance.authorizations.len(),
        signed,
        b.governance.authorizations.len() - signed,
        b.governance.release_records.len(),
        b.audit.events.len(),
        b.audit.witnesses.len(),
        b.audit.revocation_heads.len(),
        v.signatures.len()
    );
    for n in &v.notes {
        let _ = writeln!(o, "  {n}");
    }

    // WHAT THIS DOES NOT TELL YOU
    section(&mut o, "WHAT THIS DOES NOT TELL YOU");
    let _ = writeln!(
        o,
        "  Whether the purpose is lawful, or whether any authorization was lawful."
    );
    let _ = writeln!(o, "  What any institution did outside Encompute.");
    let _ = writeln!(
        o,
        "  That a released result can be recalled: it cannot; revocation stops future use only."
    );
    let _ = writeln!(
        o,
        "  That a declared location is true: a declaration is attributable, not proven."
    );
    let _ = writeln!(o, "  Who holds the key to a result, and what that assumes of the evaluator operator: this release does not record it.");
    let _ = writeln!(o, "  Anything about a row marked not verified above.");

    // VERDICT
    section(&mut o, "VERDICT");
    let _ = match v.report.verdict {
        Verdict::Satisfied => writeln!(o, "  CROSS-AGENCY REQUIREMENTS SATISFIED"),
        Verdict::NotFullyEvidenced => {
            writeln!(o, "  CROSS-AGENCY REQUIREMENTS NOT FULLY EVIDENCED")
        }
        Verdict::NotSatisfied => writeln!(o, "  CROSS-AGENCY REQUIREMENTS NOT SATISFIED"),
    };
    for u in &v.report.unmet {
        let _ = writeln!(o, "    - {u}");
    }
    let _ = writeln!(o, "  {LEGAL_BOUNDARY}");
    o
}
