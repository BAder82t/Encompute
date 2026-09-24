//! `encompute._native`: Python bindings over `encompute_runtime::Model`. The Python
//! frontend (tracing, privacy checks, results) lives in `python/encompute`.

use std::collections::BTreeMap;
use std::path::Path;

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

    /// `[(name, length, is_scalar, lo, hi)]` in definition order.
    fn inputs(&self) -> Vec<(String, usize, bool, f64, f64)> {
        self.inner
            .program()
            .inputs()
            .map(|(_, n, s, r)| {
                (
                    n.to_owned(),
                    s.len(),
                    s == encompute_ir::Shape::Scalar,
                    r.lo,
                    r.hi,
                )
            })
            .collect()
    }

    /// `[(name, length, is_scalar)]`.
    fn outputs(&self) -> Vec<(String, usize, bool)> {
        let p = self.inner.program();
        p.outputs()
            .iter()
            .map(|o| {
                let s = p.node(o.value).ty.shape;
                (o.name.clone(), s.len(), s == encompute_ir::Shape::Scalar)
            })
            .collect()
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
        let rep = match measure {
            Some(n) => Some(self.inner.test(mode(mode_)?, n, 42).map_err(err)?),
            None => None,
        };
        Ok(self.inner.explain(rep.as_ref()))
    }

    fn bench_json(&self, mode_: &str, reps: usize) -> PyResult<String> {
        let b = self.inner.bench(mode(mode_)?, reps).map_err(err)?;
        Ok(serde_json::to_string(&b).expect("serializable"))
    }

    /// Artifact file contents by name (parameters.json, security.json, ...).
    fn artifact_files(&self) -> BTreeMap<&'static str, String> {
        self.inner.artifact_files()
    }

    fn save(&self, path: &str) -> PyResult<()> {
        self.inner.save(Path::new(path)).map_err(err)
    }
}

/// Whether this build includes the OpenFHE backend (mode "encrypted").
#[pyfunction]
fn has_openfhe() -> bool {
    encompute_runtime::has_openfhe()
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Model>()?;
    m.add_function(wrap_pyfunction!(has_openfhe, m)?)?;
    m.add("NativeError", m.py().get_type::<NativeError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
