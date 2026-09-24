//! Compiled artifact: a directory `name.encompute/` with
//! `program.eir`, `plan.json`, `parameters.json`, `security.json` and
//! `manifest.json` (SHA-256 of the others). Never contains keys.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use encompute_ir::{Code, Error, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::model::Model;

pub const FORMAT: &str = "encompute-artifact/0.1";
const FILES: [&str; 4] = [
    "program.eir",
    "plan.json",
    "parameters.json",
    "security.json",
];

#[derive(Serialize)]
struct Manifest<'a> {
    format: &'a str,
    encompute_version: &'a str,
    program: &'a str,
    /// OpenFHE release the parameters were checked against.
    backend: &'a str,
    files: BTreeMap<&'a str, String>,
}

#[derive(Serialize)]
struct Security<'a> {
    security_level: &'a str,
    scheme: &'a str,
    security_table: &'a str,
    server_can_decrypt: bool,
    plaintext_logging: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    range: Option<[f64; 2]>,
    encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    depends_on: Option<Vec<String>>,
}

#[derive(Serialize)]
struct EvalKeys<'a> {
    relinearization: bool,
    rotations: &'a [u32],
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
        let deps: BTreeMap<&str, &Vec<String>> = c
            .privacy
            .outputs
            .iter()
            .map(|o| (o.name.as_str(), &o.depends_on))
            .collect();
        let security = Security {
            security_level: &c.params.security,
            scheme: "CKKS",
            security_table: &c.params.table_source,
            server_can_decrypt: false,
            plaintext_logging: false,
            threat_model: BTreeMap::from([
                ("client", "trusted: holds the secret key, encrypts inputs, decrypts outputs"),
                ("evaluator", "honest-but-curious: holds public and evaluation keys only"),
                ("network", "untrusted"),
                ("storage", "untrusted"),
            ]),
            conditions: vec![
                "decrypted results are never returned to the evaluator (CKKS IND-CPA-D, Li–Micciancio 2021)",
                "inputs lie within their declared ranges; the client checks this before encrypting",
            ],
            inputs: p
                .inputs()
                .map(|(_, n, s, r)| Io {
                    name: n.into(),
                    shape: s.to_string(),
                    range: Some([r.lo, r.hi]),
                    encrypted: true,
                    depends_on: None,
                })
                .collect(),
            outputs: p
                .outputs()
                .iter()
                .map(|o| Io {
                    name: o.name.clone(),
                    shape: p.node(o.value).ty.shape.to_string(),
                    range: None,
                    encrypted: true,
                    depends_on: Some(deps[o.name.as_str()].clone()),
                })
                .collect(),
            evaluation_keys: EvalKeys {
                relinearization: true,
                rotations: &c.plan.rotations,
            },
            evaluator_observes: &c.privacy.evaluator_observes,
        };
        BTreeMap::from([
            ("program.eir", p.to_string()),
            ("plan.json", json(&c.plan)),
            ("parameters.json", json(&c.params)),
            ("security.json", json(&security)),
        ])
    }

    /// Write the artifact directory (created if missing).
    pub fn save(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir).map_err(|e| io_err(dir, e))?;
        let files = self.artifact_files();
        for (name, body) in &files {
            let path = dir.join(name);
            fs::write(&path, body).map_err(|e| io_err(&path, e))?;
        }
        let manifest = Manifest {
            format: FORMAT,
            encompute_version: env!("CARGO_PKG_VERSION"),
            program: self.program().name(),
            backend: "openfhe 1.5.1",
            files: files
                .iter()
                .map(|(n, b)| (*n, sha256(b.as_bytes())))
                .collect(),
        };
        let path = dir.join("manifest.json");
        fs::write(&path, json(&manifest)).map_err(|e| io_err(&path, e))
    }

    /// Load an artifact: verify every file hash, recompile `program.eir`,
    /// and require the stored plan and parameters to match the recompiled
    /// ones exactly.
    pub fn load(dir: &Path) -> Result<Model> {
        let read = |name: &str| {
            let path = dir.join(name);
            fs::read_to_string(&path).map_err(|e| io_err(&path, e))
        };
        let manifest: serde_json::Value = serde_json::from_str(&read("manifest.json")?)
            .map_err(|e| Error::new(Code::Artifact, format!("manifest.json: {e}")))?;
        if manifest["format"] != FORMAT {
            return Err(Error::new(
                Code::Artifact,
                format!("unsupported artifact format {}", manifest["format"]),
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
        for name in ["plan.json", "parameters.json", "security.json"] {
            if fresh[name] != stored[name] {
                return Err(Error::new(
                    Code::Artifact,
                    format!(
                        "{name} differs from what this Encompute version ({}) compiles; recompile the \
                         artifact (built with {})",
                        env!("CARGO_PKG_VERSION"),
                        manifest["encompute_version"]
                    ),
                ));
            }
        }
        Ok(model)
    }
}
