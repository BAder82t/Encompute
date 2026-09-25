//! Compiled artifact: a directory `name.encompute/` with
//! `program.eir`, `plan.json` (a CKKS or exact plan), `parameters.json`,
//! `security.json`, `verification.json` (the execution spec receipts refer
//! to) and `manifest.json` (SHA-256 of the others). Never contains keys.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use encompute_evaluator::CompiledProgram;
use encompute_ir::{Code, Error, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::model::Model;

/// Artifact format version; 1 was the unversioned 0.1 layout, 2 the
/// CKKS-only 0.2 layout, 3 added exact plans, 4 `verification.json`.
pub const FORMAT: u32 = 4;
const FILES: [&str; 5] = [
    "program.eir",
    "plan.json",
    "parameters.json",
    "security.json",
    "verification.json",
];

/// `verification.json`: the execution spec for the artifact's target
/// backend (OpenFHE for CKKS, TFHE-rs for exact) and its ID. Mock runs use
/// the same spec with backend "mock".
#[derive(Serialize)]
struct Verification<'a> {
    spec_id: String,
    #[serde(flatten)]
    spec: &'a encompute_verification::ExecutionSpec,
}

#[derive(Serialize)]
struct Manifest<'a> {
    artifact_format: u32,
    program: &'a str,
    compiler: Compiler<'a>,
    crypto: Crypto<'a>,
    /// SHA-256 of each file.
    files: BTreeMap<&'a str, String>,
}

#[derive(Serialize)]
struct Compiler<'a> {
    version: &'a str,
    ir_version: &'a str,
    plan: PlanFormat,
}

/// Each plan format is versioned on its own.
#[derive(Serialize)]
struct PlanFormat {
    kind: &'static str,
    version: u32,
}

#[derive(Serialize)]
struct Crypto<'a> {
    semantics: &'static str,
    scheme: &'static str,
    backend: &'a str,
    backend_version: &'a str,
    parameter_profile: &'a str,
    parameter_selector_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_table: Option<&'a str>,
}

#[derive(Serialize)]
struct Security<'a> {
    semantics: &'static str,
    security_level: &'a str,
    scheme: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_table: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameter_profile: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_probability: Option<&'a str>,
    result_semantics: &'static str,
    evaluator_receives_secret_key: bool,
    plaintext_logging: bool,
    key_ownership: &'static str,
    threat_model: BTreeMap<&'a str, &'a str>,
    conditions: Vec<&'a str>,
    inputs: Vec<Io>,
    outputs: Vec<Io>,
    evaluation_keys: EvalKeys<'a>,
    evaluator_observes: &'a [&'static str],
}

#[derive(Serialize)]
struct Io {
    name: String,
    shape: String,
    /// Exact element type (u8, bool, ...); absent for approximate values.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    elem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    range: Option<[f64; 2]>,
    encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    depends_on: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum EvalKeys<'a> {
    Ckks {
        relinearization: bool,
        rotations: &'a [u32],
    },
    Exact {
        server_key: &'static str,
    },
}

fn io_err(path: &Path, e: std::io::Error) -> Error {
    Error::new(Code::Artifact, format!("{}: {e}", path.display()))
}

fn json<T: Serialize>(v: &T) -> String {
    let mut s = serde_json::to_string_pretty(v).expect("serializable");
    s.push('\n');
    s
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl Model {
    /// File contents of the artifact, deterministic for a given program and
    /// Encompute version.
    pub fn artifact_files(&self) -> BTreeMap<&'static str, String> {
        let (p, c) = (self.program(), self.compiled());
        let privacy = c.privacy();
        let deps: BTreeMap<&str, &Vec<String>> = privacy
            .outputs
            .iter()
            .map(|o| (o.name.as_str(), &o.depends_on))
            .collect();
        let exact_elem = |id: encompute_ir::ValueId| {
            let e = p.node(id).ty.elem;
            e.is_exact().then(|| e.to_string())
        };
        let inputs = p
            .inputs()
            .map(|(id, n, s, r)| Io {
                name: n.into(),
                shape: s.to_string(),
                elem: exact_elem(id),
                range: Some([r.lo, r.hi]),
                encrypted: true,
                depends_on: None,
            })
            .collect();
        let outputs = p
            .outputs()
            .iter()
            .map(|o| Io {
                name: o.name.clone(),
                shape: p.node(o.value).ty.shape.to_string(),
                elem: exact_elem(o.value),
                range: None,
                encrypted: true,
                depends_on: Some(deps[o.name.as_str()].clone()),
            })
            .collect();
        let threat_model = BTreeMap::from([
            (
                "client",
                "trusted: holds the secret key, encrypts inputs, decrypts outputs",
            ),
            (
                "evaluator",
                "honest-but-curious: holds public and evaluation keys only",
            ),
            ("network", "untrusted"),
            ("storage", "untrusted"),
        ]);
        let range_condition =
            "inputs lie within their declared ranges; the client checks this before encrypting";
        let security = match c {
            CompiledProgram::Approx(c) => Security {
                semantics: "approximate",
                security_level: &c.params.security,
                scheme: "CKKS",
                security_table: Some(&c.params.table_source),
                backend: None,
                parameter_profile: None,
                failure_probability: None,
                result_semantics: "approximate, within the declared precision",
                evaluator_receives_secret_key: false,
                plaintext_logging: false,
                key_ownership: "the client generates all keys; the evaluator receives public \
                                and evaluation keys only",
                threat_model,
                conditions: vec![
                    "decrypted results are never returned to the evaluator (CKKS IND-CPA-D, Li–Micciancio 2021)",
                    range_condition,
                ],
                inputs,
                outputs,
                evaluation_keys: EvalKeys::Ckks {
                    relinearization: true,
                    rotations: &c.plan.rotations,
                },
                evaluator_observes: &privacy.evaluator_observes,
            },
            CompiledProgram::Exact(e) => Security {
                semantics: "exact",
                security_level: &e.profile.security,
                scheme: "TFHE",
                security_table: None,
                backend: Some(&e.profile.backend),
                parameter_profile: Some(&e.profile.profile),
                failure_probability: Some(&e.profile.failure_probability),
                result_semantics: "exact",
                evaluator_receives_secret_key: false,
                plaintext_logging: false,
                key_ownership: "the client generates all keys; the evaluator receives the \
                                (compressed) server key only",
                threat_model,
                conditions: vec![
                    range_condition,
                    "integer range analysis proved that no operation overflows for inputs in range",
                ],
                inputs,
                outputs,
                evaluation_keys: EvalKeys::Exact {
                    server_key: "compressed TFHE server key (bootstrapping and key-switching keys)",
                },
                evaluator_observes: &privacy.evaluator_observes,
            },
        };
        let spec = self.target_spec();
        BTreeMap::from([
            ("program.eir", p.to_string()),
            ("plan.json", c.plan_json()),
            ("parameters.json", c.parameters_json()),
            ("security.json", json(&security)),
            (
                "verification.json",
                json(&Verification {
                    spec_id: spec.id().hex(),
                    spec: &spec,
                }),
            ),
        ])
    }

    /// The execution spec on the artifact's target (real) backend.
    pub fn target_spec(&self) -> encompute_verification::ExecutionSpec {
        let kind = match self.compiled() {
            CompiledProgram::Approx(_) => encompute_evaluator::BackendKind::OpenFhe,
            CompiledProgram::Exact(_) => encompute_evaluator::BackendKind::TfheRs,
        };
        encompute_evaluator::execution_spec(&self.ids(), self.compiled(), kind)
    }

    /// Canonical `manifest.json` for these file contents.
    fn manifest_json(&self, files: &BTreeMap<&'static str, String>) -> String {
        let c = self.compiled();
        let (kind, version) = c.plan_format();
        let crypto = match c {
            CompiledProgram::Approx(c) => Crypto {
                semantics: "approximate",
                scheme: "CKKS",
                backend: encompute_ckks::BACKEND,
                backend_version: encompute_ckks::BACKEND_VERSION,
                parameter_profile: encompute_ckks::PARAMETER_PROFILE,
                parameter_selector_version: encompute_ckks::PARAMETER_SELECTOR_VERSION.to_string(),
                security_table: Some(&c.params.table_source),
            },
            CompiledProgram::Exact(e) => Crypto {
                semantics: "exact",
                scheme: "TFHE",
                backend: &e.profile.backend,
                backend_version: &e.profile.backend_version,
                parameter_profile: &e.profile.profile,
                parameter_selector_version: e.profile.parameter_selector_version.clone(),
                security_table: None,
            },
        };
        let manifest = Manifest {
            artifact_format: FORMAT,
            program: self.program().name(),
            compiler: Compiler {
                version: env!("CARGO_PKG_VERSION"),
                ir_version: encompute_ir::IR_VERSION,
                plan: PlanFormat { kind, version },
            },
            crypto,
            files: files
                .iter()
                .map(|(n, b)| (*n, sha256(b.as_bytes())))
                .collect(),
        };
        json(&manifest)
    }

    /// Write the artifact directory (created if missing).
    pub fn save(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir).map_err(|e| io_err(dir, e))?;
        let files = self.artifact_files();
        for (name, body) in &files {
            let path = dir.join(name);
            fs::write(&path, body).map_err(|e| io_err(&path, e))?;
        }
        let manifest = self.manifest_json(&files);
        let path = dir.join("manifest.json");
        fs::write(&path, manifest).map_err(|e| io_err(&path, e))
    }

    /// Load an artifact: verify every file hash, recompile `program.eir`,
    /// and require the stored plan, parameters and manifest to match the
    /// recompiled ones exactly.
    pub fn load(dir: &Path) -> Result<Model> {
        let read = |name: &str| {
            let path = dir.join(name);
            fs::read_to_string(&path).map_err(|e| io_err(&path, e))
        };
        let manifest_text = read("manifest.json")?;
        let manifest: serde_json::Value = serde_json::from_str(&manifest_text)
            .map_err(|e| Error::new(Code::Artifact, format!("manifest.json: {e}")))?;
        if manifest["artifact_format"] != FORMAT {
            return Err(Error::new(
                Code::Artifact,
                format!(
                    "unsupported artifact format {} (this Encompute reads format {FORMAT}); recompile",
                    manifest["artifact_format"]
                ),
            ));
        }
        let mut stored = BTreeMap::new();
        for name in FILES {
            let body = read(name)?;
            let want = manifest["files"][name].as_str().unwrap_or_default();
            if sha256(body.as_bytes()) != want {
                return Err(Error::new(
                    Code::Artifact,
                    format!("{name} does not match its manifest hash; the artifact was modified"),
                ));
            }
            stored.insert(name, body);
        }
        let model = Model::from_eir(&stored["program.eir"])?;
        let fresh = model.artifact_files();
        let fresh_manifest: serde_json::Value =
            serde_json::from_str(&model.manifest_json(&fresh)).expect("valid JSON");
        for ptr in [
            "/compiler/ir_version",
            "/compiler/plan",
            "/crypto/semantics",
            "/crypto/scheme",
            "/crypto/backend",
            "/crypto/backend_version",
            "/crypto/parameter_profile",
            "/crypto/parameter_selector_version",
        ] {
            let got = manifest.pointer(ptr).cloned().unwrap_or_default();
            let want = fresh_manifest.pointer(ptr).cloned().unwrap_or_default();
            if got != want {
                return Err(Error::new(
                    Code::Artifact,
                    format!("artifact {ptr} is {got}, this Encompute uses {want}; recompile the artifact"),
                ));
            }
        }
        if manifest["program"] != model.program().name() {
            return Err(Error::new(
                Code::Artifact,
                "manifest names a different program than program.eir",
            ));
        }
        for name in [
            "plan.json",
            "parameters.json",
            "security.json",
            "verification.json",
        ] {
            if fresh[name] != stored[name] {
                return Err(Error::new(
                    Code::Artifact,
                    format!(
                        "{name} differs from what this Encompute version ({}) compiles; recompile the \
                         artifact (built with {})",
                        env!("CARGO_PKG_VERSION"),
                        manifest["compiler"]["version"]
                    ),
                ));
            }
        }
        // The manifest itself must be exactly what this version writes.
        if model.manifest_json(&fresh) != manifest_text {
            return Err(Error::new(
                Code::Artifact,
                "manifest.json differs from what this Encompute writes; recompile the artifact",
            ));
        }
        Ok(model)
    }
}
