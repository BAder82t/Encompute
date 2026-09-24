use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, Instant};

use encompute_backend::{CkksBackend, MockBackend, MockConfig, MockSecretKey};
use encompute_ckks::{compile, Compiled};
use encompute_ir::{evaluate, parse, Code, Error, Inputs, Outputs, Program, Result};
use serde::Serialize;

use crate::diff::{diff_test, sample_inputs, DiffReport};
use crate::exec::{decrypt_outputs, encrypt_inputs, evaluate_encrypted};

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

/// Keys and backend for one mode. Both roles live in one process in v0.1.
enum Session {
    Mock(MockBackend, MockSecretKey),
    #[cfg(feature = "openfhe")]
    OpenFhe(
        encompute_openfhe::OpenFheBackend,
        encompute_openfhe::OpenFheSecretKey,
    ),
}

macro_rules! with_backend {
    ($s:expr, |$b:ident, $sk:ident| $body:expr) => {
        match $s {
            Session::Mock($b, $sk) => $body,
            #[cfg(feature = "openfhe")]
            Session::OpenFhe($b, $sk) => $body,
        }
    };
}

/// A compiled program plus lazily generated keys per mode.
pub struct Model {
    program: Program,
    compiled: Compiled,
    sessions: RefCell<HashMap<Mode, Session>>,
}

/// Timings are medians over `reps` runs, in milliseconds.
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
    pub input_ciphertext_bytes: usize,
    pub output_ciphertext_bytes: usize,
    /// True when sizes are computed, not serialized (mock backend).
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

    fn new_session(&self, mode: Mode) -> Result<Session> {
        let c = &self.compiled;
        match mode {
            Mode::Clear => unreachable!("clear mode has no keys"),
            Mode::Mock => {
                let (b, sk) = MockBackend::new(&c.params, &c.plan.rotations, MockConfig::default());
                Ok(Session::Mock(b, sk))
            }
            #[cfg(feature = "openfhe")]
            Mode::Encrypted => {
                let (b, sk) = encompute_openfhe::OpenFheBackend::new(&c.params, &c.plan.rotations)?;
                Ok(Session::OpenFhe(b, sk))
            }
            #[cfg(not(feature = "openfhe"))]
            Mode::Encrypted => Err(Error::new(
                Code::Backend,
                "this build has no OpenFHE backend; rebuild with the `openfhe` feature \
                 (see README) or use mode \"mock\"",
            )),
        }
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
        let (p, plan) = (&self.program, &self.compiled.plan);
        self.with_session(mode, |s| {
            with_backend!(s, |b, sk| crate::exec::run(b, sk, plan, p, inputs))
        })
    }

    /// Differential test of `mode` against the reference semantics.
    pub fn test(&self, mode: Mode, cases: usize, seed: u64) -> Result<DiffReport> {
        if mode == Mode::Clear {
            return Err(Error::new(
                Code::BadInput,
                "clear mode is the reference; test mock or encrypted",
            ));
        }
        let (p, plan) = (&self.program, &self.compiled.plan);
        self.with_session(mode, |s| {
            with_backend!(s, |b, sk| diff_test(b, sk, plan, p, cases, seed))
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
        let session = self.new_session(mode)?;
        let keygen = t.elapsed();
        let (p, c) = (&self.program, &self.compiled);
        with_backend!(&session, |b, sk| {
            let mut times = [vec![], vec![], vec![]];
            let mut sizes = (0, 0);
            let mut dec = vec![];
            for rep in 0..reps {
                let inputs = sample_inputs(p, rep + 2, 0);
                let t = Instant::now();
                let cts = encrypt_inputs(b, &c.plan, p, &inputs)?;
                times[0].push(t.elapsed());
                sizes.0 = cts
                    .iter()
                    .map(|ct| b.ciphertext_bytes(ct))
                    .sum::<Result<usize>>()?;
                let t = Instant::now();
                let outs = evaluate_encrypted(b, &c.plan, p, cts)?;
                times[1].push(t.elapsed());
                sizes.1 = outs
                    .iter()
                    .map(|ct| b.ciphertext_bytes(ct))
                    .sum::<Result<usize>>()?;
                let t = Instant::now();
                decrypt_outputs(b, sk, &c.plan, &outs)?;
                dec.push(t.elapsed());
            }
            times[2] = dec;
            let [enc, eval, dec] = times.map(median_ms);
            Ok(BenchReport {
                backend: b.name().to_owned(),
                reps,
                ring_dim: c.params.ring_dim,
                slots: c.params.slots,
                depth: c.plan.depth,
                rotation_keys: c.plan.rotations.len(),
                keygen_ms: ms(keygen),
                encrypt_ms: enc,
                evaluate_ms: eval,
                decrypt_ms: dec,
                input_ciphertext_bytes: sizes.0,
                output_ciphertext_bytes: sizes.1,
                sizes_estimated: b.name() == "mock",
            })
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
