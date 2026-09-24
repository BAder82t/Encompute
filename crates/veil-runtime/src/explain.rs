use std::fmt::Write as _;

use veil_ir::{Op, Shape};

use crate::diff::DiffReport;
use crate::model::Model;

fn shape(s: Shape) -> String {
    match s {
        Shape::Scalar => "scalar".into(),
        Shape::Vector(n) => format!("vector<{n}>"),
        Shape::Matrix(r, c) => format!("matrix<{r}x{c}>"),
    }
}

impl Model {
    /// Human-readable execution plan. Includes the measured error when a
    /// differential test report is given.
    pub fn explain(&self, measured: Option<&DiffReport>) -> String {
        let (p, c) = (self.program(), self.compiled());
        let (plan, params) = (&c.plan, &c.params);
        let mut s = String::new();
        let rule = "─".repeat(60);
        let _ = writeln!(s, "Veil execution plan: {}\n{rule}", p.name());

        let _ = writeln!(s, "Privacy");
        for (_, name, sh, r) in p.inputs() {
            let _ = writeln!(
                s,
                "  input   {name}: {} in [{}, {}], encrypted by the client",
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
                "  output  {}: {}, encrypted; depends on {}",
                o.name,
                shape(sh),
                o.depends_on.join(", ")
            );
        }
        for u in &c.privacy.unused_inputs {
            let _ = writeln!(s, "  note    input {u} is not used by any output");
        }
        let _ = writeln!(
            s,
            "  evaluator holds public and evaluation keys only; it cannot decrypt"
        );
        let _ = writeln!(
            s,
            "  evaluator sees: {}",
            c.privacy.evaluator_observes.join("; ")
        );
        let _ = writeln!(
            s,
            "  never return decrypted results to the evaluator (CKKS IND-CPA-D)"
        );

        let _ = writeln!(s, "\nComputation");
        let _ = writeln!(
            s,
            "  scheme          CKKS, FLEXIBLEAUTO scaling, HYBRID key switching"
        );
        let _ = writeln!(s, "  slots           {}", plan.slots);
        let _ = writeln!(
            s,
            "  depth           {} (budget {})",
            plan.depth, params.mult_depth
        );
        let counts: Vec<String> = plan
            .op_counts()
            .iter()
            .map(|(k, n)| format!("{k} {n}"))
            .collect();
        let _ = writeln!(
            s,
            "  instructions    {}: {}",
            plan.instrs.len(),
            counts.join(", ")
        );
        let rots: Vec<String> = plan.rotations.iter().map(u32::to_string).collect();
        let _ = writeln!(
            s,
            "  rotation keys   {}{}",
            plan.rotations.len(),
            if rots.is_empty() {
                String::new()
            } else {
                format!(": {}", rots.join(" "))
            }
        );
        for a in &plan.approximations {
            let ch = &a.chebyshev;
            let _ = writeln!(
                s,
                "  approximation   {} ({}) over [{:.4}, {:.4}]: Chebyshev degree {}, max error {:.2e}",
                a.function,
                a.value,
                ch.lo,
                ch.hi,
                ch.degree(),
                ch.max_error
            );
        }
        let matvecs = p
            .nodes()
            .iter()
            .filter(|n| matches!(n.op, Op::MatVec(..)))
            .count();
        if matvecs > 0 {
            let _ = writeln!(
                s,
                "  matvec          {matvecs}, hybrid diagonals with baby-step/giant-step rotations"
            );
        }

        let _ = writeln!(s, "\nParameters ({})", params.security);
        let _ = writeln!(s, "  ring dimension  {}", params.ring_dim);
        let _ = writeln!(
            s,
            "  scale           2^{}, first modulus {} bits",
            params.scale_bits, params.first_mod_bits
        );
        let _ = writeln!(
            s,
            "  log2(QP)        {} (limit {} for N = {})",
            params.log_qp, params.max_log_qp, params.ring_dim
        );
        let _ = writeln!(s, "  key switching   {} digits", params.num_large_digits);
        let _ = writeln!(s, "  security table  {}", params.table_source);

        let e = &c.estimate;
        let _ = writeln!(s, "\nPrecision");
        let _ = writeln!(s, "  target          {:.1e} max absolute error", e.target);
        let _ = writeln!(
            s,
            "  estimate        {:.1e} = approximation {:.1e} + CKKS noise {:.1e} (heuristic)",
            e.total, e.approximation, e.ckks_noise
        );
        match measured {
            Some(r) => {
                let _ = writeln!(
                    s,
                    "  measured        {:.1e} over {} cases on {} ({})",
                    r.max_error,
                    r.cases,
                    r.backend,
                    if r.passed { "PASS" } else { "FAIL" }
                );
            }
            None => {
                let _ = writeln!(s, "  measured        not run (veil test)");
            }
        }
        s
    }
}
