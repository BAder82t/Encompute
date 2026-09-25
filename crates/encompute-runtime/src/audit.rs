//! `encompute audit`: checks of a compiled artifact and, optionally, its
//! client keys and evaluator binary against the security model
//! (docs/threat-model.md). Statuses follow fhe-attack-replay:
//! PASS, WARN (a condition the deployment must uphold), FAIL, SKIP, plus
//! INFO for facts about this build.

use std::path::Path;
use std::process::Command;

use encompute_evaluator::CompiledProgram;
use serde::Serialize;

use crate::model::{has_tfhe, Model};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Skip,
    Info,
}

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub status: Status,
    pub detail: String,
}

fn check(id: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        id,
        status,
        detail: detail.into(),
    }
}

/// Audit a loaded artifact. `keys` is a directory from `keys generate`;
/// `evaluator` is the `encompute-evaluator` binary to inspect.
pub fn audit(model: &Model, keys: Option<&Path>, evaluator: Option<&Path>) -> Vec<Check> {
    let mut out = vec![check(
        "artifact.integrity",
        Status::Pass,
        "hashes, versions and recompilation match (checked on load)",
    )];

    let files = model.artifact_files();
    let leaked = files.values().any(|b| {
        [
            "\"secret_key\":",
            "PrivateKey",
            "EvalKey",
            "cereal",
            "ClientKey",
        ]
        .iter()
        .any(|m| b.contains(m))
    });
    out.push(if leaked {
        check(
            "artifact.no_key_material",
            Status::Fail,
            "artifact contains key material",
        )
    } else {
        check(
            "artifact.no_key_material",
            Status::Pass,
            "no key material in artifact files",
        )
    });

    match model.compiled() {
        CompiledProgram::Approx(c) => ckks_checks(&mut out, c),
        CompiledProgram::Exact(e) => exact_checks(&mut out, model, e),
    }

    out.push(match keys {
        None => check(
            "keys.secret_permissions",
            Status::Skip,
            "no --keys directory given",
        ),
        Some(dir) => secret_permissions(&dir.join("secret.key")),
    });

    out.push(match evaluator {
        None => check(
            "evaluator.no_client_crypto",
            Status::Skip,
            "no --evaluator binary given",
        ),
        Some(bin) => evaluator_symbols(bin),
    });
    out
}

fn ckks_checks(out: &mut Vec<Check>, c: &encompute_ckks::Compiled) {
    let p = &c.params;
    out.push(
        if p.log_qp <= p.max_log_qp && p.security == "128-bit classical" {
            check(
                "params.security_128",
                Status::Pass,
                format!(
                    "log2 QP {} ≤ {} for N = {} ({})",
                    p.log_qp, p.max_log_qp, p.ring_dim, p.table_source
                ),
            )
        } else {
            check(
                "params.security_128",
                Status::Fail,
                format!("log2 QP {} > {}", p.log_qp, p.max_log_qp),
            )
        },
    );

    out.push(check(
        "params.selector_version",
        Status::Pass,
        format!(
            "parameter selector v{}, profile {}",
            encompute_ckks::PARAMETER_SELECTOR_VERSION,
            encompute_ckks::PARAMETER_PROFILE
        ),
    ));

    out.push(check(
        "ckks.decryption_oracle",
        Status::Warn,
        "CKKS is not IND-CPA-D secure and no noise flooding is applied: decrypted results must \
         never be returned to the evaluator (Li–Micciancio 2021)",
    ));

    out.push(if c.estimate.approximation > 0.0 {
        check(
            "accuracy.approximations",
            Status::Warn,
            format!(
                "{} function approximation(s), error {:.1e} of the {:.1e} budget; valid only for inputs within their declared ranges",
                c.plan.approximations.len(),
                c.estimate.approximation,
                c.estimate.target
            ),
        )
    } else {
        check("accuracy.approximations", Status::Pass, "no function approximations")
    });
}

fn exact_checks(out: &mut Vec<Check>, model: &Model, e: &encompute_evaluator::ExactProgram) {
    out.push(match e.plan.validate() {
        Ok(()) => check(
            "exact.plan_validated",
            Status::Pass,
            format!(
                "{} instructions, every register typed and defined before use",
                e.plan.instrs.len()
            ),
        ),
        Err(err) => check("exact.plan_validated", Status::Fail, err.message),
    });
    out.push(match encompute_analysis::int_ranges(model.program()) {
        Ok(_) => check(
            "exact.ranges_proven",
            Status::Pass,
            "no operation can overflow its type for inputs within their declared ranges",
        ),
        Err(err) => check("exact.ranges_proven", Status::Fail, err.message),
    });
    let known = if e.proof_required {
        encompute_exact::bgv::profile(&e.plan)
    } else {
        encompute_tfhe::default_profile()
    };
    out.push(if e.profile == known {
        check(
            "params.profile",
            Status::Pass,
            format!(
                "{} {} {}: {} security, failure probability {}",
                known.backend,
                known.backend_version,
                known.profile,
                known.security,
                known.failure_probability
            ),
        )
    } else {
        check(
            "params.profile",
            Status::Fail,
            format!("unrecognized parameter profile {}", e.profile.profile),
        )
    });
    // The stored transcript hash equals the one regenerated from the plan.
    let stored: serde_json::Value =
        serde_json::from_str(&model.artifact_files()["verification.json"]).unwrap_or_default();
    out.push(match model.transcript_for_target() {
        Some(t) if stored["transcript_hash"] == t.id().hex() => check(
            "exact.transcript",
            Status::Pass,
            format!(
                "{} regenerated from plan.json ({} instructions) matches verification.json",
                t.id(),
                t.entries.len()
            ),
        ),
        _ => check(
            "exact.transcript",
            Status::Fail,
            "ENC1702 transcript commitment mismatch: the exact plan does not match the verification metadata",
        ),
    });
    let scheme = model.compiled().scheme();
    out.push(check(
        "exact.bindings",
        Status::Pass,
        format!(
            "envelopes bind scheme {scheme}, backend, parameter set, program, key and transcript"
        ),
    ));
    out.push(if e.proof_required {
        check(
            "exact.verification",
            Status::Pass,
            format!(
                "verification required: every result must carry an execution proof ({}, OpenFHE \
                 BGV); clients never decrypt without a valid proof",
                encompute_exact::bgv::PROTOCOL
            ),
        )
    } else {
        check(
            "exact.verification",
            Status::Info,
            "receipts only: an evaluator can sign a wrong result; use verification=\"required\" \
             for execution proofs",
        )
    });
    out.push(match (e.proof_required, has_tfhe()) {
        (true, _) => check(
            "exact.backend",
            Status::Pass,
            "OpenFHE BGV (BSD 2-Clause): exact modular arithmetic, reproducible byte for byte",
        ),
        (false, true) => check(
            "exact.backend",
            Status::Warn,
            "TFHE-rs backend is research-only in this Encompute configuration; commercial use \
             needs a patent license from Zama",
        ),
        (false, false) => check(
            "exact.backend",
            Status::Info,
            "no production exact cryptographic backend in this build: exact execution uses the \
             mock evaluator (TFHE-rs is behind the research `tfhe-rs` feature)",
        ),
    });
}

fn secret_permissions(path: &Path) -> Check {
    let id = "keys.secret_permissions";
    match std::fs::metadata(path) {
        Err(e) => check(id, Status::Fail, format!("{}: {e}", path.display())),
        #[cfg(unix)]
        Ok(m) => {
            use std::os::unix::fs::PermissionsExt;
            let mode = m.permissions().mode() & 0o777;
            if mode & 0o077 == 0 {
                check(
                    id,
                    Status::Pass,
                    format!("{} is mode {mode:o}", path.display()),
                )
            } else {
                check(
                    id,
                    Status::Fail,
                    format!("{} is mode {mode:o}; run chmod 600", path.display()),
                )
            }
        }
        #[cfg(not(unix))]
        Ok(_) => check(id, Status::Skip, "permission check needs a Unix system"),
    }
}

fn evaluator_symbols(bin: &Path) -> Check {
    let id = "evaluator.no_client_crypto";
    match Command::new("nm").arg(bin).output() {
        Err(e) => check(id, Status::Skip, format!("nm unavailable: {e}")),
        Ok(o) if !o.status.success() => {
            check(id, Status::Fail, format!("nm failed on {}", bin.display()))
        }
        Ok(o) => {
            let syms = String::from_utf8_lossy(&o.stdout);
            if !syms.contains("encompute") {
                // Stripped, or a format this nm cannot read: a pass would be vacuous.
                return check(
                    id,
                    Status::Skip,
                    format!(
                        "{} has no readable Encompute symbols; cannot audit",
                        bin.display()
                    ),
                );
            }
            let client = syms
                .lines()
                .filter(|l| {
                    l.contains("encompute_openfhe_client") || l.contains("encompute_tfhe_client")
                })
                .count();
            if client == 0 {
                check(
                    id,
                    Status::Pass,
                    "no Encompute key-generation, encryption or decryption code; OpenFHE's internal \
                     routines are linked but no secret key ever reaches the evaluator",
                )
            } else {
                check(
                    id,
                    Status::Fail,
                    format!("{client} client-crypto symbols in {}", bin.display()),
                )
            }
        }
    }
}
