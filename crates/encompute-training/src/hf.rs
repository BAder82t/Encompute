//! Hugging Face model packages: the supply-chain boundary between a model
//! repository and a confidential training run.
//!
//! A model owner imports a repository once, outside any confidential
//! workload: the revision is resolved to an immutable commit (or, for a
//! local model, to its content digest), every file is checked and hashed,
//! and the package's ID (`enchf1:`) commits to all of it. Workers never
//! download anything; they load the sealed package locally.
//!
//! Refused, fail closed:
//! - a mutable revision (`main`, a tag): only a 40-digit commit or a
//!   content digest;
//! - remote code: `*.py` files, or a config naming custom code
//!   (`auto_map`, `trust_remote_code`, custom pipelines);
//! - pickled weights (`pytorch_model.bin`, `*.pt`, `*.pkl`, ...): only
//!   safetensors;
//! - any file outside the known configuration, tokenizer and safetensors
//!   files, and a shard index naming anything but the package's own
//!   safetensors files;
//! - an architecture or task this release does not support.

use serde::{Deserialize, Serialize};

use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;

use crate::tagged_hex;

pub const PACKAGE_VERSION: u32 = 1;
const PACKAGE: &str = "encompute.hf-model-package.v1";

/// The architectures and tasks the supported path covers.
pub const SUPPORTED: &[(&str, &str)] = &[
    ("bert", "sequence-classification"),
    ("distilbert", "sequence-classification"),
    ("roberta", "sequence-classification"),
];

/// Configuration and tokenizer files a package may contain, besides
/// `*.safetensors` weights.
pub const CONFIG_FILES: &[&str] = &[
    "config.json",
    "generation_config.json",
    "model.safetensors.index.json",
];
pub const TOKENIZER_FILES: &[&str] = &[
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "added_tokens.json",
    "vocab.txt",
    "vocab.json",
    "merges.txt",
];
/// Weight formats that can run code when loaded (pickles) or are not
/// supported: refused by name, with a pointer to safetensors.
const PICKLED: &[&str] = &[
    ".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".h5", ".msgpack", ".joblib",
];

fn bad(m: impl Into<String>) -> Error {
    Error::new(Code::ModelPackage, m)
}

fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    pub path: String,
    /// SHA-256 (hex).
    pub sha256: String,
    pub size: u64,
}

/// The library versions (major.minor) a package was imported with, and a
/// worker must run: a patch release does not change the package, a minor
/// release does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryVersions {
    pub transformers: String,
    pub peft: String,
    pub torch: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HfModelPackage {
    pub version: u32,
    /// The repository the model came from: metadata, not identity.
    pub repo_id: String,
    /// A 40-digit commit, or `sha256:` and the content digest of a local
    /// model.
    pub revision: String,
    /// `bert`, `distilbert`, `roberta`.
    pub model_type: String,
    /// E.g. `BertForSequenceClassification`.
    pub model_class: String,
    pub task: String,
    pub num_labels: u32,
    /// SHA-256 of `config.json`.
    pub config_digest: String,
    /// SHA-256 over the tokenizer files (names and digests).
    pub tokenizer_digest: String,
    /// Every file, sorted by path.
    pub files: Vec<PackageFile>,
    pub libraries: LibraryVersions,
    /// The repository's declared license, if any (metadata).
    pub license: Option<String>,
}

fn major_minor(name: &str, v: &str) -> Result<()> {
    let parts: Vec<_> = v.split('.').collect();
    if parts.len() == 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        Ok(())
    } else {
        Err(bad(format!(
            "{name} version must be major.minor, not {v:?}"
        )))
    }
}

/// Whether a file name may be in a package; the reason if not.
pub fn check_file(path: &str) -> Result<()> {
    if path.contains('/') || path.contains('\\') || path.starts_with('.') {
        return Err(bad(format!(
            "{path}: packages are flat, without hidden files"
        )));
    }
    if path.ends_with(".py") {
        return Err(bad(format!(
            "{path}: remote code is never run in a confidential workload (no trust_remote_code); \
             package reviewed code into the worker image instead"
        )));
    }
    if PICKLED.iter().any(|s| path.ends_with(s)) {
        return Err(bad(format!(
            "{path}: pickled weights can run code when loaded; only safetensors are accepted \
             (convert them in an isolated step first)"
        )));
    }
    if path.ends_with(".safetensors")
        || CONFIG_FILES.contains(&path)
        || TOKENIZER_FILES.contains(&path)
    {
        return Ok(());
    }
    Err(bad(format!(
        "{path}: not a configuration, tokenizer or safetensors file"
    )))
}

/// Refuses a `config.json` that names custom code or an unsupported
/// architecture.
pub fn check_config(config: &serde_json::Value) -> Result<String> {
    let o = config
        .as_object()
        .ok_or_else(|| bad("config.json is not an object"))?;
    for k in ["auto_map", "trust_remote_code", "custom_pipelines"] {
        if o.contains_key(k) {
            return Err(bad(format!(
                "config.json names custom code ({k}): remote code is never run in a confidential \
                 workload"
            )));
        }
    }
    let t = o
        .get("model_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad("config.json has no model_type"))?;
    if !SUPPORTED.iter().any(|(m, _)| *m == t) {
        return Err(bad(format!(
            "model type {t:?} is not supported yet (bert, distilbert, roberta)"
        )));
    }
    Ok(t.to_owned())
}

/// Refuses a `model.safetensors.index.json` whose `weight_map` names
/// anything but the package's own safetensors files: an index is a list of
/// paths, and a loader would open whatever it names (`../`, an absolute
/// path, another format).
pub fn check_index(index: &serde_json::Value, files: &[String]) -> Result<()> {
    let map = index
        .get("weight_map")
        .and_then(|m| m.as_object())
        .ok_or_else(|| bad("model.safetensors.index.json has no weight_map"))?;
    for (tensor, v) in map {
        let f = v
            .as_str()
            .ok_or_else(|| bad(format!("weight_map[{tensor}] is not a file name")))?;
        check_file(f)?;
        if !f.ends_with(".safetensors") || !files.iter().any(|p| p == f) {
            return Err(bad(format!(
                "weight_map[{tensor}] names {f:?}, which is not one of the package's \
                 safetensors files"
            )));
        }
    }
    Ok(())
}

impl HfModelPackage {
    pub fn validate(&self) -> Result<()> {
        if self.version != PACKAGE_VERSION {
            return Err(bad(format!("model package version {}", self.version)));
        }
        let immutable = hex(&self.revision, 40)
            || self
                .revision
                .strip_prefix("sha256:")
                .is_some_and(|d| hex(d, 64));
        if !immutable {
            return Err(bad(format!(
                "revision {:?} is not immutable: resolve it to a 40-digit commit first (never \
                 main, latest or a tag)",
                self.revision
            )));
        }
        if !SUPPORTED.contains(&(self.model_type.as_str(), self.task.as_str())) {
            return Err(bad(format!(
                "{} for {} is not supported yet",
                self.model_type, self.task
            )));
        }
        if self.num_labels < 2 || self.repo_id.is_empty() || self.model_class.is_empty() {
            return Err(bad(
                "a package needs a repository, a model class and 2+ labels",
            ));
        }
        for d in [&self.config_digest, &self.tokenizer_digest] {
            if !hex(d, 64) {
                return Err(bad(
                    "config and tokenizer digests must be 64 lowercase hex digits",
                ));
            }
        }
        for (i, f) in self.files.iter().enumerate() {
            check_file(&f.path)?;
            if i > 0 && self.files[i - 1].path >= f.path {
                return Err(bad("package files must be sorted by path, distinct"));
            }
            if !hex(&f.sha256, 64) {
                return Err(bad(format!(
                    "{}: digest must be 64 lowercase hex digits",
                    f.path
                )));
            }
        }
        let has = |p: &str| self.files.iter().any(|f| f.path == p);
        if !has("config.json") {
            return Err(bad("a package needs config.json"));
        }
        if !self.files.iter().any(|f| f.path.ends_with(".safetensors")) {
            return Err(bad("a package needs safetensors weights"));
        }
        if self
            .files
            .iter()
            .find(|f| f.path == "config.json")
            .map(|f| &f.sha256)
            != Some(&self.config_digest)
        {
            return Err(bad("config_digest is not config.json's digest"));
        }
        if self.tokenizer_digest != self.expected_tokenizer_digest() {
            return Err(bad("tokenizer_digest does not cover the tokenizer files"));
        }
        major_minor("transformers", &self.libraries.transformers)?;
        major_minor("peft", &self.libraries.peft)?;
        major_minor("torch", &self.libraries.torch)
    }

    /// SHA-256 over the tokenizer files' names and digests, in order.
    pub fn expected_tokenizer_digest(&self) -> String {
        let parts: Vec<Vec<u8>> = self
            .files
            .iter()
            .filter(|f| TOKENIZER_FILES.contains(&f.path.as_str()))
            .map(|f| format!("{}\0{}", f.path, f.sha256).into_bytes())
            .collect();
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        tagged_hex("encompute.hf-tokenizer.v1", &refs)
    }

    /// `SHA256("encompute.hf-model-package.v1" || canonical package)`,
    /// shown as `enchf1:<hex>`.
    pub fn id(&self) -> Result<String> {
        self.validate()?;
        Ok(tagged_hex(PACKAGE, &[&canonical_json(self)?]))
    }
}
