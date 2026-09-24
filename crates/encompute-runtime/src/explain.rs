use std::fmt::Write as _;

use encompute_ir::Shape;
use serde::Serialize;

use crate::diff::DiffReport;
use crate::model::{BenchReport, Mode, Model};

/// Measured behaviour of a model: accuracy and cost from real runs.
#[derive(Clone, Debug, Serialize)]
pub struct Measurement {
    pub accuracy: DiffReport,
    pub cost: BenchReport,
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
        let (p, c) = (self.program(), self.compiled());
        let (plan, params) = (&c.plan, &c.params);
        let mut s = String::new();
        let section = |s: &mut String, title: &str| {
            let _ = write!(s, "\n{title}\n{}\n", "─".repeat(48));
        };
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

        match measured {
            Some(m) => {
                let (b, r) = (&m.cost, &m.accuracy);
                let est = if b.sizes_estimated {
                    " (mock format)"
                } else {
                    ""
                };
                section(&mut s, &format!("Data (measured, {})", b.backend));
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
                section(
                    &mut s,
                    &format!("Execution (measured, median of {})", b.reps),
                );
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
            None => {
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
