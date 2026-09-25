use std::fmt::Write as _;

use encompute_evaluator::{CompiledProgram, ExactProgram};
use encompute_ir::Shape;
use serde::Serialize;

use crate::diff::TestReport;
use crate::model::{has_tfhe, BenchReport, Mode, Model};

/// Measured behaviour of a model: accuracy and cost from real runs.
#[derive(Clone, Debug, Serialize)]
pub struct Measurement {
    pub accuracy: TestReport,
    pub cost: BenchReport,
}

/// Verification readiness (0.4): receipts, transcript, proof coverage.
fn verification(s: &mut String, model: &Model) {
    section(s, "Verification");
    let _ = writeln!(s, "  {:<24}supported (signed by the evaluator)", "receipt");
    match model.transcript_for_target() {
        Some(t) => {
            let caps = encompute_exact::bgv::capabilities();
            let cov = caps.coverage(&t);
            let _ = writeln!(s, "  {:<24}v{}", "transcript", t.transcript_version);
            let _ = writeln!(
                s,
                "  {:<24}{}",
                "transcript hash",
                &t.id().to_string()[..26]
            );
            if model.compiled().proof_required() {
                let _ = writeln!(s, "  {:<24}required", "verification");
                let _ = writeln!(
                    s,
                    "  {:<24}{} (sound, not succinct: verifying costs one evaluation)",
                    "proof backend", caps.protocol
                );
            } else {
                let _ = writeln!(s, "  {:<24}receipt only", "verification");
                let _ = writeln!(
                    s,
                    "  {:<24}none (the {} subset would cover {}/{})",
                    "proof backend", caps.protocol, cov.0, cov.1
                );
            }
            let _ = writeln!(
                s,
                "  {:<24}{}%",
                "proof coverage",
                100 * cov.0 / cov.1.max(1)
            );
        }
        None => {
            let _ = writeln!(
                s,
                "  {:<24}not available (CKKS plans are not transcribed yet)",
                "transcript"
            );
            let _ = writeln!(s, "  {:<24}none", "proof backend");
        }
    }
    let _ = writeln!(
        s,
        "  {:<24}{}",
        "execution proof",
        if model.compiled().proof_required() {
            "REQUIRED: results are decrypted only after the proof verifies"
        } else {
            "NOT PRESENT (a receipt is a signed claim, not a proof)"
        }
    );
}

fn section(s: &mut String, title: &str) {
    let _ = write!(s, "\n{title}\n{}\n", "─".repeat(48));
}

/// Data and timing sections of a measurement (any semantics).
fn cost(s: &mut String, b: &BenchReport) {
    let est = if b.sizes_estimated {
        " (mock format)"
    } else {
        ""
    };
    section(s, &format!("Data (measured, {})", b.backend));
    let _ = writeln!(
        s,
        "  {:<24}{}{est}",
        "encrypted request",
        kib(b.request_bytes)
    );
    let _ = writeln!(
        s,
        "  {:<24}{}{est}",
        "evaluation keys",
        kib(b.evaluation_key_bytes)
    );
    let _ = writeln!(
        s,
        "  {:<24}{}{est}",
        "encrypted response",
        kib(b.response_bytes)
    );
    section(s, &format!("Execution (measured, median of {})", b.reps));
    let _ = writeln!(s, "  {:<24}{:.1} ms", "key generation", b.keygen_ms);
    let _ = writeln!(s, "  {:<24}{:.1} ms", "encryption (client)", b.encrypt_ms);
    let _ = writeln!(s, "  {:<24}{:.1} ms", "evaluation", b.evaluate_ms);
    let _ = writeln!(s, "  {:<24}{:.1} ms", "decryption (client)", b.decrypt_ms);
    let _ = writeln!(
        s,
        "  {:<24}{}",
        "peak memory (process)",
        kib(b.peak_rss_bytes as usize)
    );
}

fn kib(b: usize) -> String {
    if b >= 1 << 20 {
        format!("{:.1} MiB", b as f64 / (1 << 20) as f64)
    } else {
        format!("{:.1} KiB", b as f64 / 1024.0)
    }
}

fn shape(s: Shape) -> String {
    s.to_string()
}

impl Model {
    /// Differential test (`cases`) plus a cost run (`reps`) on `mode`.
    pub fn measure(
        &self,
        mode: Mode,
        cases: usize,
        reps: usize,
    ) -> encompute_ir::Result<Measurement> {
        Ok(Measurement {
            accuracy: self.test(mode, cases, 42)?,
            cost: self.bench(mode, reps)?,
        })
    }

    /// Human-readable execution plan; with a measurement, the data, cost
    /// and accuracy sections show measured values.
    pub fn explain(&self, measured: Option<&Measurement>) -> String {
        let mut s = match self.compiled() {
            CompiledProgram::Approx(c) => self.explain_approx(c, measured),
            CompiledProgram::Exact(e) => self.explain_exact(e, measured),
        };
        self.explain_multi_party(&mut s);
        s
    }

    /// Aggregated outputs run as secure aggregation, not on an evaluator.
    fn explain_multi_party(&self, s: &mut String) {
        let Ok(Some(r)) = encompute_analysis::confidentiality::analyze(self.program()) else {
            return;
        };
        for b in &r.aggregations {
            let k = &b.codec;
            let row = |s: &mut String, k: &str, v: String| {
                let _ = writeln!(s, "  {k:<28}{v}");
            };
            section(s, &format!("MULTI-PARTY EXECUTION  {}", b.output));
            row(s, "participants", b.contributions.len().to_string());
            row(s, "required minimum", b.minimum.to_string());
            row(s, "colluding parties tolerated", b.colluding.to_string());
            row(s, "protocol threshold", b.threshold.to_string());
            row(
                s,
                "dropouts tolerated",
                (b.contributions.len() - b.threshold).to_string(),
            );
            row(s, "protected asset", b.contribution_policy.kind.to_string());
            row(
                s,
                "release policy",
                b.contribution_policy.release.to_string(),
            );
            row(s, "mechanism", "secure aggregation".into());
            row(
                s,
                "protocol",
                format!(
                    "{} v{} (Bonawitz et al. 2017, malicious-coordinator variant)",
                    encompute_secagg::PROTOCOL,
                    encompute_secagg::PROTOCOL_VERSION
                ),
            );
            row(s, "function", b.function.name().into());
            row(s, "vector length", b.vector_len.to_string());
            row(s, "encoding", "fixed point".into());
            row(
                s,
                "clip range",
                format!(
                    "[{}, {}] (values outside are clipped)",
                    k.clip_min, k.clip_max
                ),
            );
            row(
                s,
                "scale",
                format!(
                    "{} (rounding error ≤ {:e} per value)",
                    k.scale,
                    k.resolution()
                ),
            );
            row(
                s,
                "modulus",
                format!(
                    "2^{} (max aggregate {} for {} parties)",
                    k.modulus_bits,
                    k.max_aggregate(b.contributions.len()),
                    b.contributions.len()
                ),
            );
            row(s, "individual updates visible", "no".into());
            let to = match &b.recipient {
                encompute_ir::confidentiality::OutputRelease::Party(p) => p.to_string(),
                encompute_ir::confidentiality::OutputRelease::Public => "public".into(),
                encompute_ir::confidentiality::OutputRelease::Sealed => "nobody (sealed)".into(),
            };
            row(s, "aggregate visible", to);
            row(
                s,
                "differential privacy",
                "none (the aggregate itself is not protected)".into(),
            );
        }
    }

    fn explain_exact(&self, e: &ExactProgram, measured: Option<&Measurement>) -> String {
        let p = self.program();
        let mut s = String::new();
        let _ = writeln!(s, "Encompute execution plan");
        section(&mut s, "Program");
        let _ = writeln!(s, "  {:<24}{}", "name", p.name());
        let _ = writeln!(s, "  {:<24}{}", "program id", &self.ids().program_id[..16]);
        let _ = writeln!(s, "  {:<24}exact integers / Booleans", "semantics");

        section(&mut s, "Privacy");
        for (id, name, _, r) in p.inputs() {
            let _ = writeln!(
                s,
                "  {:<24}secret<{}> in [{}, {}]",
                name,
                p.node(id).ty.elem,
                r.lo,
                r.hi
            );
        }
        for o in &e.privacy.outputs {
            let elem = e
                .plan
                .outputs
                .iter()
                .find(|x| x.name == o.name)
                .map(|x| x.elem);
            let _ = writeln!(
                s,
                "  {:<24}secret<{}> (depends on {})",
                o.name,
                elem.map_or("?".into(), |e| e.to_string()),
                o.depends_on.join(", ")
            );
        }
        let _ = writeln!(
            s,
            "  {:<24}no: it never receives the secret key",
            "evaluator can decrypt"
        );
        for u in &e.privacy.unused_inputs {
            let _ = writeln!(s, "  note: input {u} is not used by any output");
        }

        section(&mut s, "Plan");
        let counts = e.plan.op_counts();
        let count = |ks: &[&str]| {
            counts
                .iter()
                .filter(|(n, _)| ks.contains(n))
                .map(|x| x.1)
                .sum::<usize>()
        };
        let _ = writeln!(
            s,
            "  {:<24}{}",
            "integer operations",
            count(&[
                "add/sub",
                "multiply",
                "multiply by constant",
                "divide by constant",
                "shift",
                "min/max",
                "cast"
            ])
        );
        let _ = writeln!(s, "  {:<24}{}", "comparisons", count(&["comparison"]));
        let _ = writeln!(s, "  {:<24}{}", "Boolean/bitwise ops", count(&["logic"]));
        let _ = writeln!(s, "  {:<24}{}", "selects", count(&["select"]));
        let _ = writeln!(s, "  {:<24}{}", "lookups", count(&["lookup"]));
        let _ = writeln!(s, "  {:<24}{}", "total instructions", e.plan.instrs.len());
        let _ = writeln!(
            s,
            "  {:<24}proven: no operation overflows for inputs in range",
            "integer overflow"
        );

        section(&mut s, "Execution");
        let pr = &e.profile;
        let _ = writeln!(s, "  {:<24}{}", "scheme", self.compiled().scheme());
        let note = match (e.proof_required, has_tfhe(), crate::model::has_openfhe()) {
            (true, _, true) => " (proof-capable: re-execution)",
            (true, _, false) => " (not in this build: mock only)",
            (false, true, _) => " (research use only)",
            (false, false, _) => " (not in this build: mock only)",
        };
        let _ = writeln!(
            s,
            "  {:<24}{} {}{note}",
            "backend", pr.backend, pr.backend_version
        );
        let _ = writeln!(s, "  {:<24}{}", "parameter profile", pr.profile);
        let _ = writeln!(
            s,
            "  {:<24}exact (no approximation error)",
            "result semantics"
        );
        section(&mut s, "Security");
        let _ = writeln!(s, "  {:<24}{}", "target", pr.security);
        let _ = writeln!(
            s,
            "  {:<24}{}",
            "failure probability", pr.failure_probability
        );
        let _ = writeln!(s, "  {:<24}no", "evaluator can decrypt");
        verification(&mut s, self);

        if let Some(m) = measured {
            cost(&mut s, &m.cost);
            if let TestReport::Exact(r) = &m.accuracy {
                section(
                    &mut s,
                    &format!("Correctness (measured, {} cases)", r.cases),
                );
                let _ = writeln!(s, "  {:<24}{}", "matches", r.matches);
                let _ = writeln!(s, "  {:<24}{}", "mismatches", r.mismatches);
                let _ = writeln!(
                    s,
                    "  {:<24}{}",
                    "result",
                    if r.passed { "PASS" } else { "FAIL" }
                );
            }
        } else {
            let _ = writeln!(
                s,
                "\n  run with --measure N for measured bytes, time and correctness"
            );
        }
        s
    }

    fn explain_approx(
        &self,
        c: &encompute_ckks::Compiled,
        measured: Option<&Measurement>,
    ) -> String {
        let p = self.program();
        let (plan, params) = (&c.plan, &c.params);
        let mut s = String::new();
        let _ = writeln!(s, "Encompute execution plan");
        section(&mut s, "Program");
        let _ = writeln!(s, "  {:<24}{}", "name", p.name());
        let _ = writeln!(s, "  {:<24}{}", "program id", &self.ids().program_id[..16]);

        section(&mut s, "Privacy");
        for (_, name, sh, r) in p.inputs() {
            let _ = writeln!(
                s,
                "  {:<24}encrypted {} in [{}, {}]",
                name,
                shape(sh),
                r.lo,
                r.hi
            );
        }
        for o in &c.privacy.outputs {
            let sh = p
                .node(p.outputs().iter().find(|x| x.name == o.name).unwrap().value)
                .ty
                .shape;
            let _ = writeln!(
                s,
                "  {:<24}encrypted {} (depends on {})",
                o.name,
                shape(sh),
                o.depends_on.join(", ")
            );
        }
        let publics = p
            .nodes()
            .iter()
            .filter(|n| matches!(n.op, encompute_ir::Op::Const { .. }))
            .count();
        let _ = writeln!(
            s,
            "  {:<24}{publics} public constants (weights, data)",
            "public"
        );
        let _ = writeln!(
            s,
            "  {:<24}no: it never receives the secret key",
            "evaluator can decrypt"
        );
        for u in &c.privacy.unused_inputs {
            let _ = writeln!(s, "  note: input {u} is not used by any output");
        }
        let _ = writeln!(
            s,
            "  never return decrypted results to the evaluator (CKKS IND-CPA-D)"
        );

        section(&mut s, "Cryptography");
        let _ = writeln!(
            s,
            "  {:<24}CKKS, OpenFHE {}",
            "scheme",
            encompute_ckks::BACKEND_VERSION
        );
        let _ = writeln!(
            s,
            "  {:<24}{} (log2 QP {} of {} allowed)",
            "security", params.security, params.log_qp, params.max_log_qp
        );
        let _ = writeln!(s, "  {:<24}{}", "ring dimension", params.ring_dim);
        let _ = writeln!(s, "  {:<24}{}", "slots", params.slots);
        let _ = writeln!(
            s,
            "  {:<24}2^{} (first modulus {} bits)",
            "scale", params.scale_bits, params.first_mod_bits
        );
        let _ = writeln!(
            s,
            "  {:<24}{} (budget {})",
            "multiplicative depth", plan.depth, params.mult_depth
        );

        section(&mut s, "Operations");
        let count = |k: &str| {
            plan.op_counts()
                .iter()
                .find(|(n, _)| *n == k)
                .map_or(0, |x| x.1)
        };
        let _ = writeln!(s, "  {:<24}{}", "ciphertext multiplies", count("mul"));
        let _ = writeln!(
            s,
            "  {:<24}{}",
            "plaintext multiplies",
            count("mul_plain") + count("mul_const")
        );
        let _ = writeln!(
            s,
            "  {:<24}{} ({} keys)",
            "rotations",
            count("rotate"),
            plan.rotations.len()
        );
        let _ = writeln!(s, "  {:<24}0", "bootstraps");
        let mut v = String::new();
        verification(&mut v, self);
        let _ = writeln!(s, "  {:<24}{}", "total instructions", plan.instrs.len());
        for a in &plan.approximations {
            let ch = &a.chebyshev;
            let _ = writeln!(
                s,
                "  {:<24}{} over [{:.3}, {:.3}], degree {}, error {:.1e}",
                "approximation",
                a.function,
                ch.lo,
                ch.hi,
                ch.degree(),
                ch.max_error
            );
        }

        s.push_str(&v);
        match measured.map(|m| (&m.cost, &m.accuracy)) {
            Some((b, TestReport::Approximate(r))) => {
                cost(&mut s, b);
                section(&mut s, &format!("Accuracy (measured, {} cases)", r.cases));
                let _ = writeln!(s, "  {:<24}{:.1e}", "target error", r.precision);
                for o in &r.outputs {
                    let _ = writeln!(
                        s,
                        "  {:<24}{:.1e} max, {:.1e} mean, {:.1e} relative",
                        o.name, o.max_abs, o.mean_abs, o.max_relative
                    );
                    if let Some(a) = o.argmax_agreement {
                        let _ = writeln!(
                            s,
                            "  {:<24}argmax {:.0}%{}",
                            "",
                            100.0 * a,
                            o.top5_overlap.map_or(String::new(), |t| format!(
                                ", top-5 overlap {:.0}%",
                                100.0 * t
                            ))
                        );
                    }
                }
                let _ = writeln!(
                    s,
                    "  {:<24}{}",
                    "result",
                    if r.passed { "PASS" } else { "FAIL" }
                );
            }
            _ => {
                section(&mut s, "Accuracy (estimated)");
                let e = &c.estimate;
                let _ = writeln!(s, "  {:<24}{:.1e}", "target error", e.target);
                let _ = writeln!(
                    s,
                    "  {:<24}{:.1e} (approximation {:.1e} + CKKS noise {:.1e}, heuristic)",
                    "estimate", e.total, e.approximation, e.ckks_noise
                );
                let _ = writeln!(
                    s,
                    "\n  run with --measure N for measured bytes, time, memory and error"
                );
            }
        }
        s
    }
}
