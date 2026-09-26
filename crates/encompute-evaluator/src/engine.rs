//! What an evaluator does, independent of transport: in-process
//! ([`Local`]) or spread over worker processes ([`crate::pool::Pool`]).

use std::collections::HashMap;
use std::sync::Mutex;

use encompute_ir::{parse, Code, Error, Result};
use serde::{Deserialize, Serialize};

use crate::session::{Backends, EvaluatorSession, ExecTimes};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProgramInfo {
    pub name: String,
    pub program_id: String,
    pub parameter_set_id: String,
    /// "CKKS", "BinFHE", "BGV" or "TFHE" (research).
    pub scheme: String,
    pub backend: String,
    /// What this evaluator executes for the program; receipts state it.
    pub spec: encompute_verification::ExecutionSpec,
    /// Exact programs: the semantic transcript hash receipts bind.
    pub transcript_hash: Option<String>,
    /// The program requires an execution proof (`verification required`).
    #[serde(default)]
    pub proof_required: bool,
}

/// Timings of one job, in milliseconds.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct JobTimes {
    pub load: f64,
    pub evaluate: f64,
    pub store: f64,
    /// Peak resident memory of the process that ran the job, in bytes.
    pub peak_rss_bytes: u64,
}

/// Peak resident set size of this process, in bytes.
pub fn peak_rss_bytes() -> u64 {
    let mut ru = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage writes into the provided, properly sized struct.
    #[allow(unsafe_code)]
    let ok = unsafe { libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr()) } == 0;
    if !ok {
        return 0;
    }
    #[allow(unsafe_code)]
    let max = unsafe { ru.assume_init() }.ru_maxrss as u64;
    // macOS reports bytes, Linux kilobytes.
    if cfg!(target_os = "macos") {
        max
    } else {
        max * 1024
    }
}

impl From<ExecTimes> for JobTimes {
    fn from(t: ExecTimes) -> Self {
        Self {
            load: t.load.as_secs_f64() * 1e3,
            evaluate: t.evaluate.as_secs_f64() * 1e3,
            store: t.store.as_secs_f64() * 1e3,
            peak_rss_bytes: peak_rss_bytes(),
        }
    }
}

pub trait Engine: Send + Sync {
    fn backend(&self) -> Backends;
    fn add_program(&self, eir: &str) -> Result<ProgramInfo>;
    fn programs(&self) -> Vec<ProgramInfo>;
    fn has_key(&self, program_id: &str, key_id: &str) -> Result<bool>;
    fn register_keys(&self, program_id: &str, envelope: &[u8]) -> Result<String>;
    fn execute(&self, program_id: &str, envelope: &[u8]) -> Result<(Vec<u8>, JobTimes)>;
}

pub fn unknown_program() -> Error {
    Error::new(Code::WrongProgram, "program not loaded on this evaluator")
}

/// Sessions in this process. Jobs run one at a time (OpenFHE is serialized
/// per process anyway).
pub struct Local {
    backends: Backends,
    sessions: Mutex<HashMap<String, EvaluatorSession>>,
}

impl Local {
    pub fn new(backends: Backends) -> Self {
        Self {
            backends,
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

fn info(s: &EvaluatorSession) -> ProgramInfo {
    ProgramInfo {
        name: s.program().name().to_owned(),
        program_id: s.ids().program_id.clone(),
        parameter_set_id: s.ids().parameter_set_id.clone(),
        scheme: s.compiled().scheme().to_owned(),
        backend: s.kind().name().to_owned(),
        spec: s.spec().clone(),
        transcript_hash: s.transcript_hash().map(str::to_owned),
        proof_required: s.compiled().proof_required(),
    }
}

impl Engine for Local {
    fn backend(&self) -> Backends {
        self.backends
    }

    fn add_program(&self, eir: &str) -> Result<ProgramInfo> {
        let program = parse(eir)?;
        crate::compiled::refuse_aggregation(&program)?;
        let kind = self
            .backends
            .for_program(&crate::compiled::compile_program(&program)?);
        let session = EvaluatorSession::new(program, kind)?;
        let i = info(&session);
        self.sessions
            .lock()
            .unwrap()
            .entry(i.program_id.clone())
            .or_insert(session);
        Ok(i)
    }

    fn programs(&self) -> Vec<ProgramInfo> {
        let mut v: Vec<_> = self.sessions.lock().unwrap().values().map(info).collect();
        v.sort_by(|a, b| a.program_id.cmp(&b.program_id));
        v
    }

    fn has_key(&self, pid: &str, kid: &str) -> Result<bool> {
        let s = self.sessions.lock().unwrap();
        Ok(s.get(pid).ok_or_else(unknown_program)?.has_key(kid))
    }

    fn register_keys(&self, pid: &str, envelope: &[u8]) -> Result<String> {
        let mut s = self.sessions.lock().unwrap();
        s.get_mut(pid)
            .ok_or_else(unknown_program)?
            .register_keys(envelope)
    }

    fn execute(&self, pid: &str, envelope: &[u8]) -> Result<(Vec<u8>, JobTimes)> {
        let s = self.sessions.lock().unwrap();
        let (out, t) = s.get(pid).ok_or_else(unknown_program)?.execute(envelope)?;
        Ok((out, t.into()))
    }
}
