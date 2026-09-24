use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, Instant};

use encompute_ckks::{compile, Compiled};
use encompute_evaluator::{EvaluatorSession, Ids};
use encompute_ir::{evaluate, parse, Code, Error, Inputs, Outputs, Program, Result};
use serde::Serialize;

use crate::client::ClientSession;
use crate::diff::{diff_test, sample_inputs, DiffReport};

/// How to execute a model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Plaintext reference semantics; no cryptography.
    Clear,
    /// The CKKS plan on the mock backend (plaintext slots, simulated noise).
    Mock,
    /// The CKKS plan on OpenFHE.
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
    compiled: Compiled,
    sessions: RefCell<HashMap<Mode, Session>>,
}

/// Timings are medians over `reps` runs, in milliseconds; sizes are the
/// envelopes that would cross the network.
#[derive(Clone, Debug, Serialize)]
pub struct BenchReport {
    pub backend: String,
    pub reps: usize,
    pub ring_dim: u32,
    pub slots: u32,
    pub depth: u32,
    pub rotation_keys: usize,
    pub keygen_ms: f64,
    pub encrypt_ms: f64,
    pub evaluate_ms: f64,
    pub decrypt_ms: f64,
    pub evaluation_key_bytes: usize,
    pub request_bytes: usize,
    pub response_bytes: usize,
    /// True for the mock backend, whose byte format is not OpenFHE's.
    pub sizes_estimated: bool,
}

impl Model {
    pub fn compile(program: Program) -> Result<Self> {
        let compiled = compile(&program)?;
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

    pub fn compiled(&self) -> &Compiled {
        &self.compiled
    }

    pub fn ids(&self) -> Ids {
        Ids::of(&self.program, &self.compiled)
    }

    /// Fresh client keys for `mode`.
    pub fn new_client(&self, mode: Mode) -> Result<ClientSession> {
        let c = &self.compiled;
        match mode {
            Mode::Clear => Err(Error::new(Code::BadInput, "clear mode has no keys")),
            Mode::Mock => {
                // Distinct mock keys per client, like real key generation.
                let seed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos() as u64);
                ClientSession::mock(self.ids(), &c.plan, &c.params, seed)
            }
            #[cfg(feature = "openfhe")]
            Mode::Encrypted => ClientSession::openfhe(self.ids(), &c.plan, &c.params),
            #[cfg(not(feature = "openfhe"))]
            Mode::Encrypted => Err(Error::new(
                Code::Backend,
                "this build has no OpenFHE backend; rebuild with the `openfhe` feature \
                 (see README) or use mode \"mock\"",
            )),
        }
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

    pub fn run(&self, mode: Mode, inputs: &Inputs) -> Result<Outputs> {
        if mode == Mode::Clear {
            return evaluate(&self.program, inputs);
        }
        self.with_session(mode, |s| s.run(&self.program, inputs))
    }

    /// Differential test of `mode` against the reference semantics.
    pub fn test(&self, mode: Mode, cases: usize, seed: u64) -> Result<DiffReport> {
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
        let c = &self.compiled;
        Ok(BenchReport {
            backend: s.client.kind().label().0.to_owned(),
            reps,
            ring_dim: c.params.ring_dim,
            slots: c.params.slots,
            depth: c.plan.depth,
            rotation_keys: c.plan.rotations.len(),
            keygen_ms: ms(keygen),
            encrypt_ms: median_ms(enc),
            evaluate_ms: median_ms(eval),
            decrypt_ms: median_ms(dec),
            evaluation_key_bytes: s.client.evaluation_keys().map_or(0, <[u8]>::len),
            request_bytes: req,
            response_bytes: resp,
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
