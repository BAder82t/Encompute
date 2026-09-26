//! Prometheus-compatible metrics (`GET /metrics`, text format 0.0.4).
//!
//! Labels are closed sets (outcome, backend, state): never identifiers,
//! values or anything secret.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;

#[derive(Default)]
struct Series {
    counters: BTreeMap<(String, String), u64>,
    /// name → (sum of seconds, count)
    durations: BTreeMap<(String, String), (f64, u64)>,
    gauges: BTreeMap<(String, String), i64>,
}

#[derive(Default)]
pub struct Metrics {
    s: Mutex<Series>,
}

/// Help text of every metric the control plane exports.
const HELP: &[(&str, &str, &str)] = &[
    (
        "encompute_jobs_total",
        "counter",
        "Jobs by final or current state transition",
    ),
    (
        "encompute_job_duration_seconds",
        "summary",
        "Wall time from job submission to a terminal state",
    ),
    (
        "encompute_evaluation_duration_seconds",
        "summary",
        "Evaluator-reported encrypted evaluation time",
    ),
    (
        "encompute_queue_depth",
        "gauge",
        "Jobs authorized or queued and not yet running",
    ),
    (
        "encompute_plans_failed_total",
        "counter",
        "Plans refused: PLANNING FAILED",
    ),
    (
        "encompute_key_release_denied_total",
        "counter",
        "Key releases or asset uses denied (revoked, unauthorized)",
    ),
    (
        "encompute_privacy_denied_total",
        "counter",
        "Privacy spends refused (budget, frozen ledger)",
    ),
    (
        "encompute_trust_failures_total",
        "counter",
        "Trust reports that did not verify",
    ),
    (
        "encompute_secagg_round_duration_seconds",
        "summary",
        "Secure aggregation round wall time",
    ),
    (
        "encompute_http_requests_total",
        "counter",
        "API requests by status class",
    ),
];

fn check_label(v: &str) -> &str {
    // Closed-set labels only: short words. Anything else is dropped.
    if v.len() <= 32
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        v
    } else {
        "other"
    }
}

impl Metrics {
    pub fn inc(&self, name: &str, label: &str) {
        self.add(name, label, 1)
    }

    pub fn add(&self, name: &str, label: &str, n: u64) {
        let mut s = self.s.lock().unwrap_or_else(|p| p.into_inner());
        *s.counters
            .entry((name.into(), check_label(label).into()))
            .or_default() += n;
    }

    pub fn observe(&self, name: &str, label: &str, seconds: f64) {
        let mut s = self.s.lock().unwrap_or_else(|p| p.into_inner());
        let e = s
            .durations
            .entry((name.into(), check_label(label).into()))
            .or_default();
        e.0 += seconds;
        e.1 += 1;
    }

    pub fn set(&self, name: &str, label: &str, v: i64) {
        let mut s = self.s.lock().unwrap_or_else(|p| p.into_inner());
        s.gauges.insert((name.into(), check_label(label).into()), v);
    }

    pub fn render(&self) -> String {
        let s = self.s.lock().unwrap_or_else(|p| p.into_inner());
        let mut out = String::new();
        for (name, kind, help) in HELP {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} {kind}");
            for ((n, l), v) in &s.counters {
                if n == name {
                    let _ = writeln!(out, "{name}{{label=\"{l}\"}} {v}");
                }
            }
            for ((n, l), v) in &s.gauges {
                if n == name {
                    let _ = writeln!(out, "{name}{{label=\"{l}\"}} {v}");
                }
            }
            for ((n, l), (sum, count)) in &s.durations {
                if n == name {
                    let _ = writeln!(out, "{name}_sum{{label=\"{l}\"}} {sum}");
                    let _ = writeln!(out, "{name}_count{{label=\"{l}\"}} {count}");
                }
            }
        }
        out
    }
}
