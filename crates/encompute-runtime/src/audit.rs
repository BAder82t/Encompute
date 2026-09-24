//! `encompute audit`: checks of a compiled artifact and, optionally, its
//! client keys and evaluator binary against the security model
//! (docs/threat-model.md). Statuses follow fhe-attack-replay:
//! PASS, WARN (a condition the deployment must uphold), FAIL, SKIP.

use std::path::Path;
use std::process::Command;

use serde::Serialize;

use crate::model::Model;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Skip,
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
    let c = model.compiled();
    let p = &c.params;
    let mut out = vec![check(
        "artifact.integrity",
        Status::Pass,
        "hashes, versions and recompilation match (checked on load)",
    )];

    let files = model.artifact_files();
    let leaked = files.values().any(|b| {
        ["\"secret_key\":", "PrivateKey", "EvalKey", "cereal"]
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
            let client = syms
                .lines()
                .filter(|l| l.contains("encompute_openfhe_client"))
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
