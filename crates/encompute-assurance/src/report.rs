//! The assurance report: runs every check, confirms every referenced test
//! still exists, and states the result per invariant. It never claims more
//! than was tested.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use serde::Serialize;

use crate::catalog::{Invariant, Kind, INVARIANTS, KINDS};
use crate::checks::{Check, CHECKS};
use crate::{run_check, Scale};

pub const PASS: &str = "All tested security invariants satisfied.";

#[derive(Debug, Serialize)]
pub struct CheckRun {
    pub name: String,
    pub passed: bool,
    pub cases: usize,
    pub seconds: f64,
    pub notes: Vec<String>,
    pub violation: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InvariantResult {
    pub id: String,
    pub area: String,
    pub claim: String,
    pub passed: bool,
    pub evidence: Vec<(Kind, String)>,
    /// Kinds of evidence (positive, negative, adversarial, end to end)
    /// this invariant does not yet have.
    pub gaps: Vec<Kind>,
    pub problems: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub version: u32,
    pub scale: Scale,
    pub commit: Option<String>,
    pub passed: bool,
    pub summary: String,
    pub checks: Vec<CheckRun>,
    pub invariants: Vec<InvariantResult>,
    pub scope: &'static str,
}

const SCOPE: &str = "The assurance checks listed here ran at the stated scale. Referenced \
    tests run in the CI jobs that build their features; this report confirms they exist. \
    Testing shows the documented invariants held for the tested cases, modes and boundaries; \
    it does not prove the system secure.";

/// Does `reference` exist: `test:<file>::<fn>` or `script:<file>` under
/// `root`, or `check:<name>` among `checks`?
pub fn reference_exists(root: &Path, checks: &[Check], reference: &str) -> Result<(), String> {
    if let Some(r) = reference.strip_prefix("test:") {
        let (file, func) = r
            .split_once("::")
            .ok_or_else(|| format!("malformed reference {reference}"))?;
        let text = std::fs::read_to_string(root.join(file))
            .map_err(|_| format!("{file} does not exist"))?;
        if !text.contains(&format!("fn {func}(")) {
            return Err(format!("{file} has no test {func}"));
        }
        Ok(())
    } else if let Some(file) = reference.strip_prefix("script:") {
        root.join(file)
            .exists()
            .then_some(())
            .ok_or_else(|| format!("{file} does not exist"))
    } else if let Some(name) = reference.strip_prefix("check:") {
        checks
            .iter()
            .any(|c| c.name == name)
            .then_some(())
            .ok_or_else(|| format!("no check named {name}"))
    } else {
        Err(format!("unknown reference kind {reference}"))
    }
}

/// Runs the checks (all, or those named in `only`) and builds the report.
pub fn run(scale: Scale, root: &Path, only: Option<&[String]>) -> Report {
    build(scale, root, CHECKS, INVARIANTS, only)
}

/// [`run`] over a given catalog and set of checks.
pub fn build(
    scale: Scale,
    root: &Path,
    checks: &[Check],
    catalog: &[Invariant],
    only: Option<&[String]>,
) -> Report {
    let mut runs: BTreeMap<&str, CheckRun> = BTreeMap::new();
    for c in checks {
        if only.is_some_and(|o| !o.iter().any(|n| n == c.name)) {
            continue;
        }
        let t = Instant::now();
        let r = run_check(c, scale);
        let seconds = t.elapsed().as_secs_f64();
        eprintln!(
            "{} {} ({seconds:.1}s)",
            if r.is_ok() { "ok  " } else { "FAIL" },
            c.name
        );
        runs.insert(
            c.name,
            match r {
                Ok(o) => CheckRun {
                    name: c.name.into(),
                    passed: true,
                    cases: o.cases,
                    seconds,
                    notes: o.notes,
                    violation: None,
                },
                Err(v) => CheckRun {
                    name: c.name.into(),
                    passed: false,
                    cases: 0,
                    seconds,
                    notes: vec![],
                    violation: Some(v),
                },
            },
        );
    }
    let invariants: Vec<InvariantResult> = catalog
        .iter()
        .map(|i| judge(i, root, checks, &runs, only.is_some()))
        .collect();
    let failed: Vec<&str> = invariants
        .iter()
        .filter(|i| !i.passed)
        .map(|i| i.id.as_str())
        .collect();
    let passed = failed.is_empty() && runs.values().all(|r| r.passed);
    Report {
        version: 1,
        scale,
        commit: std::env::var("GITHUB_SHA").ok(),
        passed,
        summary: if passed {
            PASS.into()
        } else {
            format!("INVARIANTS VIOLATED: {}", failed.join(", "))
        },
        checks: runs.into_values().collect(),
        invariants,
        scope: SCOPE,
    }
}

fn judge(
    i: &Invariant,
    root: &Path,
    checks: &[Check],
    runs: &BTreeMap<&str, CheckRun>,
    partial: bool,
) -> InvariantResult {
    let mut problems = vec![];
    for (_, e) in i.evidence {
        if let Err(p) = reference_exists(root, checks, e) {
            problems.push(p);
        } else if let Some(name) = e.strip_prefix("check:") {
            match runs.get(name) {
                Some(r) if !r.passed => problems.push(format!(
                    "{name}: {}",
                    r.violation.as_deref().unwrap_or("failed")
                )),
                None if !partial => problems.push(format!("{name} did not run")),
                _ => {}
            }
        }
    }
    problems.sort();
    problems.dedup();
    InvariantResult {
        id: i.id.into(),
        area: i.area.into(),
        claim: i.claim.into(),
        passed: problems.is_empty(),
        evidence: i.evidence.iter().map(|(k, e)| (*k, (*e).into())).collect(),
        gaps: KINDS
            .into_iter()
            .filter(|k| !i.evidence.iter().any(|(e, _)| e == k))
            .collect(),
        problems,
    }
}

fn kind_label(k: Kind) -> &'static str {
    match k {
        Kind::Positive => "positive",
        Kind::Negative => "negative",
        Kind::Adversarial => "adversarial",
        Kind::EndToEnd => "end to end",
    }
}

fn short(e: &str) -> String {
    match e.split_once("::") {
        Some((_, f)) => format!("`{f}`"),
        None => format!("`{}`", e.split_once(':').map_or(e, |(_, r)| r)),
    }
}

impl Report {
    pub fn markdown(&self) -> String {
        let mut s = String::new();
        s += "# Encompute assurance report\n\n";
        s += &format!(
            "**{}**\n\nScale: {:?}. Commit: {}.\n\n{}\n\n",
            self.summary,
            self.scale,
            self.commit.as_deref().unwrap_or("local"),
            self.scope
        );
        s += "## Checks\n\n| Check | Result | Cases | Seconds |\n|---|---|---:|---:|\n";
        for c in &self.checks {
            s += &format!(
                "| {} | {} | {} | {:.1} |\n",
                c.name,
                if c.passed { "pass" } else { "**FAIL**" },
                c.cases,
                c.seconds
            );
        }
        s += "\n## Invariants\n\n| ID | Claim | Positive | Negative | Adversarial | End to end | Result |\n|---|---|---|---|---|---|---|\n";
        for i in &self.invariants {
            let col = |k: Kind| {
                let v: Vec<String> = i
                    .evidence
                    .iter()
                    .filter(|(e, _)| *e == k)
                    .map(|(_, r)| short(r))
                    .collect();
                if v.is_empty() {
                    "gap".to_owned()
                } else {
                    v.join("<br>")
                }
            };
            s += &format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                i.id,
                i.claim,
                col(Kind::Positive),
                col(Kind::Negative),
                col(Kind::Adversarial),
                col(Kind::EndToEnd),
                if i.passed { "pass" } else { "**FAIL**" }
            );
        }
        let failing: Vec<&InvariantResult> = self.invariants.iter().filter(|i| !i.passed).collect();
        if !failing.is_empty() {
            s += "\n## Violations\n\n";
            for i in failing {
                for p in &i.problems {
                    s += &format!("- {}: {p}\n", i.id);
                }
            }
        }
        let gaps: Vec<String> = self
            .invariants
            .iter()
            .filter(|i| !i.gaps.is_empty())
            .map(|i| {
                format!(
                    "- {}: no {} evidence",
                    i.id,
                    i.gaps
                        .iter()
                        .map(|k| kind_label(*k))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
            .collect();
        if !gaps.is_empty() {
            s += &format!(
                "\n## Coverage gaps (tracked, not failures)\n\n{}\n",
                gaps.join("\n")
            );
        }
        s
    }
}
