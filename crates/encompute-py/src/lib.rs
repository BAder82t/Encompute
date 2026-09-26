//! `encompute._native`: Python bindings over `encompute_runtime::Model`. The Python
//! frontend (tracing, privacy checks, results) lives in `python/encompute`.

use std::collections::BTreeMap;
use std::path::Path;

mod training;

use encompute_runtime::Mode;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

pyo3::create_exception!(
    _native,
    NativeError,
    PyException,
    "Encompute error: args are (code, message)."
);

fn err(e: encompute_ir::Error) -> PyErr {
    NativeError::new_err((e.code.as_str(), e.message))
}

fn mode(s: &str) -> PyResult<Mode> {
    s.parse().map_err(err)
}

/// A compiled program. Keys are generated per mode on first use and reused.
#[pyclass(unsendable, module = "encompute._native")]
struct Model {
    inner: encompute_runtime::Model,
}

#[pymethods]
impl Model {
    /// Compile `.eir` text.
    #[staticmethod]
    fn compile(eir: &str) -> PyResult<Self> {
        Ok(Self {
            inner: encompute_runtime::Model::from_eir(eir).map_err(err)?,
        })
    }

    /// Load and verify a `.encompute` artifact directory.
    #[staticmethod]
    fn load(path: &str) -> PyResult<Self> {
        Ok(Self {
            inner: encompute_runtime::Model::load(Path::new(path)).map_err(err)?,
        })
    }

    fn name(&self) -> String {
        self.inner.program().name().to_owned()
    }

    fn eir(&self) -> String {
        self.inner.program().to_string()
    }

    /// `[(name, length, is_scalar, lo, hi, elem)]` in definition order;
    /// `elem` is "f64" or an exact type such as "u8" or "bool".
    fn inputs(&self) -> Vec<(String, usize, bool, f64, f64, String)> {
        let p = self.inner.program();
        p.inputs()
            .map(|(id, n, s, r)| {
                (
                    n.to_owned(),
                    s.len(),
                    s == encompute_ir::Shape::Scalar,
                    r.lo,
                    r.hi,
                    p.node(id).ty.elem.to_string(),
                )
            })
            .collect()
    }

    /// `[(name, length, is_scalar, elem)]`.
    fn outputs(&self) -> Vec<(String, usize, bool, String)> {
        let p = self.inner.program();
        p.outputs()
            .iter()
            .map(|o| {
                let t = p.node(o.value).ty;
                (
                    o.name.clone(),
                    t.shape.len(),
                    t.shape == encompute_ir::Shape::Scalar,
                    t.elem.to_string(),
                )
            })
            .collect()
    }

    /// "approximate" or "exact".
    fn semantics(&self) -> &'static str {
        match self.inner.semantics() {
            encompute_runtime::Semantics::Approximate => "approximate",
            encompute_runtime::Semantics::Exact => "exact",
        }
    }

    fn run(
        &self,
        inputs: BTreeMap<String, Vec<f64>>,
        mode_: &str,
    ) -> PyResult<BTreeMap<String, Vec<f64>>> {
        self.inner.run(mode(mode_)?, &inputs).map_err(err)
    }

    fn test_json(&self, mode_: &str, cases: usize, seed: u64) -> PyResult<String> {
        let rep = self.inner.test(mode(mode_)?, cases, seed).map_err(err)?;
        Ok(serde_json::to_string(&rep).expect("serializable"))
    }

    #[pyo3(signature = (measure=None, mode_="mock"))]
    fn explain(&self, measure: Option<usize>, mode_: &str) -> PyResult<String> {
        let measured = match measure {
            Some(n) => Some(self.inner.measure(mode(mode_)?, n, 3).map_err(err)?),
            None => None,
        };
        Ok(self.inner.explain(measured.as_ref()))
    }

    fn bench_json(&self, mode_: &str, reps: usize) -> PyResult<String> {
        let b = self.inner.bench(mode(mode_)?, reps).map_err(err)?;
        Ok(serde_json::to_string(&b).expect("serializable"))
    }

    /// `encompute privacy explain` text, or None without declarations.
    fn privacy_explain(&self) -> PyResult<Option<String>> {
        self.inner.privacy_explain().map_err(err)
    }

    /// The confidentiality graph as Graphviz DOT, or None.
    fn privacy_graph(&self) -> PyResult<Option<String>> {
        self.inner.privacy_dot().map_err(err)
    }

    /// Artifact file contents by name (parameters.json, security.json, ...).
    fn artifact_files(&self) -> BTreeMap<&'static str, String> {
        self.inner.artifact_files()
    }

    fn save(&self, path: &str) -> PyResult<()> {
        self.inner.save(Path::new(path)).map_err(err)
    }

    /// Runs on a remote evaluator with a control plane's job grant (JSON),
    /// trusting the receipt key the evaluator registered. Keys come from
    /// `keys_dir` (`encompute keys generate`) or are generated for this run.
    /// Returns JSON: outputs, the verified receipt, and the commitments the
    /// control plane checks.
    #[pyo3(signature = (url, inputs, grant_json, receipt_key, keys_dir=None))]
    fn run_remote_json(
        &self,
        url: &str,
        inputs: BTreeMap<String, Vec<f64>>,
        grant_json: &str,
        receipt_key: &str,
        keys_dir: Option<&str>,
    ) -> PyResult<String> {
        use encompute_verification::{
            output_commitment, request_commitment, EvaluatorIdentity, JobGrant,
        };
        let m = &self.inner;
        let grant: JobGrant = serde_json::from_str(grant_json).map_err(|e| {
            err(encompute_ir::Error::new(
                encompute_ir::Code::BadInput,
                format!("job grant: {e}"),
            ))
        })?;
        let trusted = EvaluatorIdentity::from_public_key_hex(receipt_key).map_err(err)?;
        let (client, eval_keys) = match keys_dir {
            Some(d) => {
                let d = Path::new(d);
                let read = |f: &str| {
                    std::fs::read(d.join(f)).map_err(|e| {
                        encompute_ir::Error::new(
                            encompute_ir::Code::WrongKey,
                            format!("{}: {e}", d.join(f).display()),
                        )
                    })
                };
                let mut c = encompute_runtime::ClientSession::restore(
                    m.ids(),
                    m.compiled(),
                    &read("secret.key").map_err(err)?,
                )
                .map_err(err)?;
                let k = read("eval.keys").ok();
                if let Some(k) = &k {
                    c.attach_evaluation_keys(k).map_err(err)?;
                }
                (c, k)
            }
            None => (m.new_client(Mode::Encrypted).map_err(err)?, None),
        };
        let run = encompute_runtime::Remote::new(url)
            .with_grant(&grant)
            .run(
                &client,
                m.program(),
                eval_keys.as_deref(),
                &inputs,
                &trusted,
            )
            .map_err(err)?;
        Ok(serde_json::json!({
            "outputs": m.outputs_json(&run.outputs),
            "raw_outputs": run.outputs,
            "receipt": run.receipt,
            "request_commitment": request_commitment(&run.request),
            "output_commitment": output_commitment(&run.response),
            "key_id": client.key_id(),
        })
        .to_string())
    }
}

/// Whether this build includes the OpenFHE backend (mode "encrypted").
#[pyfunction]
fn has_openfhe() -> bool {
    encompute_runtime::has_openfhe()
}

/// Whether this build runs exact programs encrypted (OpenFHE exact).
#[pyfunction]
fn has_exact() -> bool {
    encompute_runtime::has_openfhe_exact()
}

/// Whether this build includes the TFHE-rs backend (research use only).
#[pyfunction]
fn has_tfhe() -> bool {
    encompute_runtime::has_tfhe()
}

/// Named privacy levels: `(name, epsilon, delta, noise_multiplier)`.
#[pyfunction]
fn privacy_presets() -> Vec<(String, f64, f64, f64)> {
    encompute_ir::confidentiality::PRIVACY_PRESETS
        .iter()
        .map(|(n, e, d, z)| (n.to_string(), *e, *d, *z))
        .collect()
}

/// DP-SGD privacy levels: `(name, epsilon, delta, noise_multiplier)`.
#[pyfunction]
fn patient_privacy_presets() -> Vec<(String, f64, f64, f64)> {
    encompute_ir::confidentiality::PATIENT_PRIVACY_PRESETS
        .iter()
        .map(|(n, e, d, z)| (n.to_string(), *e, *d, *z))
        .collect()
}

/// What `rounds` releases would cost each budgeted asset of `.eir` text
/// (JSON rows), and the rendered preview.
#[pyfunction]
fn privacy_preview(eir: &str, rounds: u64) -> PyResult<(String, String)> {
    let m = encompute_runtime::Model::from_eir(eir).map_err(err)?;
    let rows = m.privacy_projection(rounds).map_err(err)?;
    Ok((
        serde_json::to_string(&rows).expect("JSON"),
        encompute_runtime::render_preview(&rows),
    ))
}

fn from_json<T: serde::de::DeserializeOwned>(what: &str, s: Option<&str>) -> PyResult<Option<T>> {
    s.map(|t| {
        serde_json::from_str(t).map_err(|e| {
            err(encompute_ir::Error::new(
                encompute_ir::Code::BadInput,
                format!("{what}: {e}"),
            ))
        })
    })
    .transpose()
}

/// Plans `.eir` text (ADR-015). Returns `(plan_json, text, plan_id)`; on
/// PLANNING FAILED, `plan_json` and `plan_id` are `None` and `text` says
/// why. Every returned plan passed the independent validator.
#[pyfunction]
#[pyo3(signature = (eir, profile="standard", infrastructure=None, training=None, preferences=None, deep=false))]
fn plan(
    eir: &str,
    profile: &str,
    infrastructure: Option<&str>,
    training: Option<&str>,
    preferences: Option<&str>,
    deep: bool,
) -> PyResult<(Option<String>, String, Option<String>)> {
    use encompute_runtime::planner::{render, verify_plan, Profile};
    let program = encompute_ir::parse(eir).map_err(err)?;
    let profile = Profile::parse(profile).ok_or_else(|| {
        err(encompute_ir::Error::new(
            encompute_ir::Code::BadInput,
            "security is standard, strong or maximum",
        ))
    })?;
    let ctx = encompute_runtime::planning::planning_context(
        &program,
        profile,
        from_json("infrastructure", infrastructure)?.unwrap_or_default(),
        from_json("preferences", preferences)?.unwrap_or_default(),
        from_json("training", training)?,
    )
    .map_err(err)?;
    let planned = encompute_runtime::planning::plan_program(&program, &ctx).map_err(err)?;
    let extra = if deep {
        format!("\n{}", render::deep(&planned))
    } else {
        String::new()
    };
    match &planned.plan {
        None => Ok((None, render::failure(&planned) + &extra, None)),
        Some(p) => {
            verify_plan(&program, p).map_err(err)?;
            let id = p.id().map_err(err)?.to_string();
            Ok((
                Some(String::from_utf8(p.to_bytes().map_err(err)?).expect("JSON")),
                render::plan(p) + &extra,
                Some(id),
            ))
        }
    }
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Model>()?;
    m.add_function(wrap_pyfunction!(privacy_presets, m)?)?;
    m.add_function(wrap_pyfunction!(patient_privacy_presets, m)?)?;
    m.add_function(wrap_pyfunction!(privacy_preview, m)?)?;
    m.add_function(wrap_pyfunction!(plan, m)?)?;
    training::register(m)?;
    m.add_function(wrap_pyfunction!(has_openfhe, m)?)?;
    m.add_function(wrap_pyfunction!(has_exact, m)?)?;
    m.add_function(wrap_pyfunction!(has_tfhe, m)?)?;
    m.add("NativeError", m.py().get_type::<NativeError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
