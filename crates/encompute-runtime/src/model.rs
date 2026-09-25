use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, Instant};

use encompute_evaluator::{
    compile_program, BackendKind, CompiledProgram, EvaluatorSession, Ids, Semantics,
};
use encompute_ir::{evaluate, parse, Code, Error, Inputs, Outputs, Program, Result};
use serde::Serialize;

use crate::client::ClientSession;
use crate::diff::{diff_test, sample_inputs, TestReport};

/// How to execute a model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Plaintext reference semantics; no cryptography.
    Clear,
    /// The plan on the mock backend: plaintext stand-ins (with simulated
    /// noise for CKKS). No cryptography.
    Mock,
    /// Real encryption: OpenFHE for approximate programs, TFHE-rs (research
    /// feature) for exact ones.
    Encrypted,
}

impl FromStr for Mode {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "clear" => Ok(Mode::Clear),
            "mock" => Ok(Mode::Mock),
            "encrypted" | "openfhe" => Ok(Mode::Encrypted),
            _ => Err(Error::new(
                Code::BadInput,
                format!("unknown mode {s:?}; use clear, mock or encrypted"),
            )),
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Clear => "clear",
            Mode::Mock => "mock",
            Mode::Encrypted => "encrypted",
        })
    }
}

/// Whether this build includes the OpenFHE backend.
pub fn has_openfhe() -> bool {
    cfg!(feature = "openfhe")
}

/// Whether this build includes the TFHE-rs backend (research use only).
pub fn has_tfhe() -> bool {
    cfg!(feature = "tfhe-rs")
}

/// Client and evaluator for one mode, sharing a process but talking only
/// through envelopes: the same path a remote evaluator takes.
struct Session {
    client: ClientSession,
    evaluator: EvaluatorSession,
}

impl Session {
    fn run(&self, program: &Program, inputs: &Inputs) -> Result<Outputs> {
        let request = self.client.encrypt(program, inputs)?;
        let (response, _) = self.evaluator.execute(&request)?;
        self.client.decrypt(&response)
    }
}

/// A compiled program plus lazily generated keys per mode.
pub struct Model {
    program: Program,
    compiled: CompiledProgram,
    sessions: RefCell<HashMap<Mode, Session>>,
}

/// Timings are medians over `reps` runs, in milliseconds; sizes are the
/// envelopes that would cross the network.
#[derive(Clone, Debug, Serialize)]
pub struct BenchReport {
    pub backend: String,
    pub reps: usize,
    pub keygen_ms: f64,
    pub encrypt_ms: f64,
    pub evaluate_ms: f64,
    pub decrypt_ms: f64,
    pub evaluation_key_bytes: usize,
    pub request_bytes: usize,
    pub response_bytes: usize,
    /// Peak resident memory of this process (client and evaluator both run here).
    pub peak_rss_bytes: u64,
    /// True for the mock backend, whose byte format is not the real one.
    pub sizes_estimated: bool,
    #[serde(flatten)]
    pub detail: BenchDetail,
}

/// Scheme-specific cost figures.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "semantics", rename_all = "lowercase")]
pub enum BenchDetail {
    Approximate {
        ring_dim: u32,
        slots: u32,
        depth: u32,
        rotation_keys: usize,
    },
    Exact {
        parameter_profile: String,
        /// Plan operations by class (comparison, logic, select, lookup, ...).
        operations: std::collections::BTreeMap<String, usize>,
    },
}

impl Model {
    /// Compile by the program's semantics: CKKS for approximate programs,
    /// an exact plan for integer/Boolean ones.
    pub fn compile(program: Program) -> Result<Self> {
        let compiled = compile_program(&program)?;
        Ok(Self {
            program,
            compiled,
            sessions: RefCell::new(HashMap::new()),
        })
    }

    pub fn from_eir(text: &str) -> Result<Self> {
        Self::compile(parse(text)?)
    }

    pub fn program(&self) -> &Program {
        &self.program
    }

    pub fn compiled(&self) -> &CompiledProgram {
        &self.compiled
    }

    pub fn semantics(&self) -> Semantics {
        self.compiled.semantics()
    }

    /// The backend `mode` uses for this program.
    pub fn backend_for(&self, mode: Mode) -> Result<BackendKind> {
        match (mode, self.semantics()) {
            (Mode::Clear, _) => Err(Error::new(Code::BadInput, "clear mode has no keys")),
            (Mode::Mock, _) => Ok(BackendKind::Mock),
            (Mode::Encrypted, Semantics::Approximate) if has_openfhe() => Ok(BackendKind::OpenFhe),
            (Mode::Encrypted, Semantics::Approximate) => Err(Error::new(
                Code::Backend,
                "this build has no OpenFHE backend; rebuild with the `openfhe` feature \
                 (see README) or use mode \"mock\"",
            )),
            (Mode::Encrypted, Semantics::Exact) if has_tfhe() => Ok(BackendKind::TfheRs),
            (Mode::Encrypted, Semantics::Exact) => Err(Error::new(
                Code::Backend,
                "no exact cryptographic backend in this build: TFHE-rs is research-only and \
                 behind the `tfhe-rs` feature (see README); use mode \"mock\"",
            )),
        }
    }

    pub fn ids(&self) -> Ids {
        Ids::of(&self.program, &self.compiled)
    }

    /// Fresh client keys for `mode`.
    pub fn new_client(&self, mode: Mode) -> Result<ClientSession> {
        let kind = self.backend_for(mode)?;
        // Distinct mock keys per client, like real key generation.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        ClientSession::generate(self.ids(), &self.compiled, kind, seed)
    }

    fn new_session(&self, mode: Mode) -> Result<Session> {
        let client = self.new_client(mode)?;
        let mut evaluator = EvaluatorSession::new(self.program.clone(), client.kind())?;
        evaluator.register_keys(client.evaluation_keys().expect("fresh client"))?;
        Ok(Session { client, evaluator })
    }

    fn with_session<T>(&self, mode: Mode, f: impl FnOnce(&Session) -> Result<T>) -> Result<T> {
        if !self.sessions.borrow().contains_key(&mode) {
            let s = self.new_session(mode)?;
            self.sessions.borrow_mut().insert(mode, s);
        }
        f(&self.sessions.borrow()[&mode])
    }

    /// Outputs as JSON with their types: exact integers as integers, bools
    /// as `true`/`false`, approximate values as lists of numbers.
    pub fn outputs_json(&self, outputs: &Outputs) -> serde_json::Value {
        let p = &self.program;
        let map = p
            .outputs()
            .iter()
            .filter_map(|o| {
                let v = outputs.get(&o.name)?;
                let elem = p.node(o.value).ty.elem;
                let j = match elem {
                    encompute_ir::Elem::Bool => serde_json::json!(v[0] != 0.0),
                    e if e.is_exact() => serde_json::json!(v[0] as i64),
                    _ => serde_json::json!(v),
                };
                Some((o.name.clone(), j))
            })
            .collect();
        serde_json::Value::Object(map)
    }

    pub fn run(&self, mode: Mode, inputs: &Inputs) -> Result<Outputs> {
        if mode == Mode::Clear {
            return evaluate(&self.program, inputs);
        }
        self.with_session(mode, |s| s.run(&self.program, inputs))
    }

    /// Differential test of `mode` against the reference semantics.
    pub fn test(&self, mode: Mode, cases: usize, seed: u64) -> Result<TestReport> {
        if mode == Mode::Clear {
            return Err(Error::new(
                Code::BadInput,
                "clear mode is the reference; test mock or encrypted",
            ));
        }
        self.with_session(mode, |s| {
            diff_test(&s.client, &s.evaluator, &self.program, cases, seed)
        })
    }

    /// Time keygen (fresh keys) and each client/evaluator step.
    pub fn bench(&self, mode: Mode, reps: usize) -> Result<BenchReport> {
        if mode == Mode::Clear {
            return Err(Error::new(
                Code::BadInput,
                "nothing to benchmark in clear mode",
            ));
        }
        let reps = reps.max(1);
        let t = Instant::now();
        let s = self.new_session(mode)?;
        let keygen = t.elapsed();
        let (mut enc, mut eval, mut dec) = (vec![], vec![], vec![]);
        let (mut req, mut resp) = (0, 0);
        for rep in 0..reps {
            let inputs = sample_inputs(&self.program, rep + 2, 0);
            let t = Instant::now();
            let request = s.client.encrypt(&self.program, &inputs)?;
            enc.push(t.elapsed());
            let t = Instant::now();
            let (response, _) = s.evaluator.execute(&request)?;
            eval.push(t.elapsed());
            let t = Instant::now();
            s.client.decrypt(&response)?;
            dec.push(t.elapsed());
            (req, resp) = (request.len(), response.len());
        }
        let detail = match &self.compiled {
            CompiledProgram::Approx(c) => BenchDetail::Approximate {
                ring_dim: c.params.ring_dim,
                slots: c.params.slots,
                depth: c.plan.depth,
                rotation_keys: c.plan.rotations.len(),
            },
            CompiledProgram::Exact(e) => BenchDetail::Exact {
                parameter_profile: e.profile.profile.clone(),
                operations: e
                    .plan
                    .op_counts()
                    .into_iter()
                    .map(|(k, n)| (k.to_owned(), n))
                    .collect(),
            },
        };
        Ok(BenchReport {
            backend: s.client.kind().label().0.to_owned(),
            reps,
            detail,
            keygen_ms: ms(keygen),
            encrypt_ms: median_ms(enc),
            evaluate_ms: median_ms(eval),
            decrypt_ms: median_ms(dec),
            evaluation_key_bytes: s.client.evaluation_keys().map_or(0, <[u8]>::len),
            request_bytes: req,
            response_bytes: resp,
            peak_rss_bytes: encompute_evaluator::engine::peak_rss_bytes(),
            sizes_estimated: mode == Mode::Mock,
        })
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn median_ms(mut v: Vec<Duration>) -> f64 {
    v.sort();
    ms(v[v.len() / 2])
}
