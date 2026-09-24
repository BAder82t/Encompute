//! Worker processes (0.2 plan, D5). The gateway owns HTTP and forwards work
//! to `encompute-evaluator worker` processes over stdin/stdout. Each worker
//! has its own OpenFHE instance, so a crash or corruption stays in one
//! process; a dead worker is restarted and its programs and keys replayed.
//!
//! Frames: request `op u8 | len u64 LE | payload`; response
//! `status u8 (0 ok, 1 error) | len u64 LE | payload`. Payloads naming a
//! program are `program_id '\n' rest`; error payloads are `code '\n' message`.

use std::collections::VecDeque;
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Condvar, Mutex};

use encompute_ir::{Code, Error, Result};

use crate::engine::{unknown_program, Engine, JobTimes, Local, ProgramInfo};
use crate::session::BackendKind;

const ADD_PROGRAM: u8 = 1;
const REGISTER_KEYS: u8 = 3;
const EXECUTE: u8 = 4;

fn io(e: std::io::Error) -> Error {
    Error::new(Code::Backend, format!("worker I/O: {e}"))
}

fn write_frame(w: &mut impl Write, tag: u8, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&[tag])?;
    w.write_all(&(payload.len() as u64).to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

fn read_frame(r: &mut impl Read) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 9];
    match r.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u64::from_le_bytes(head[1..].try_into().unwrap()) as usize;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some((head[0], body)))
}

fn with_pid(pid: &str, rest: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(pid.len() + 1 + rest.len());
    v.extend_from_slice(pid.as_bytes());
    v.push(b'\n');
    v.extend_from_slice(rest);
    v
}

fn split_pid(payload: &[u8]) -> Result<(&str, &[u8])> {
    let i = payload
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| Error::new(Code::Backend, "malformed worker frame"))?;
    let pid = std::str::from_utf8(&payload[..i])
        .map_err(|_| Error::new(Code::Backend, "bad program ID"))?;
    Ok((pid, &payload[i + 1..]))
}

/// Worker main loop: serve frames from stdin until the gateway closes it.
pub fn run_worker(kind: BackendKind) -> std::io::Result<()> {
    let engine = Local::new(kind);
    let (stdin, stdout) = (std::io::stdin(), std::io::stdout());
    let (mut input, mut output) = (stdin.lock(), stdout.lock());
    while let Some((op, payload)) = read_frame(&mut input)? {
        let result: Result<Vec<u8>> = (|| match op {
            ADD_PROGRAM => {
                let eir = std::str::from_utf8(&payload)
                    .map_err(|_| Error::new(Code::Parse, "not UTF-8"))?;
                Ok(serde_json::to_vec(&engine.add_program(eir)?).unwrap())
            }
            REGISTER_KEYS => {
                let (pid, env) = split_pid(&payload)?;
                Ok(engine.register_keys(pid, env)?.into_bytes())
            }
            EXECUTE => {
                let (pid, env) = split_pid(&payload)?;
                let (out, times) = engine.execute(pid, env)?;
                let t = serde_json::to_vec(&times).unwrap();
                let mut v = (t.len() as u32).to_le_bytes().to_vec();
                v.extend_from_slice(&t);
                v.extend_from_slice(&out);
                Ok(v)
            }
            _ => Err(Error::new(Code::Backend, format!("unknown worker op {op}"))),
        })();
        match result {
            Ok(v) => write_frame(&mut output, 0, &v)?,
            Err(e) => write_frame(
                &mut output,
                1,
                format!("{}\n{}", e.code, e.message).as_bytes(),
            )?,
        }
    }
    Ok(())
}

struct Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Worker {
    fn call(&mut self, op: u8, payload: &[u8]) -> Result<Vec<u8>> {
        write_frame(&mut self.stdin, op, payload).map_err(io)?;
        match read_frame(&mut self.stdout).map_err(io)? {
            Some((0, v)) => Ok(v),
            Some((_, v)) => {
                let text = String::from_utf8_lossy(&v);
                let (code, msg) = text.split_once('\n').unwrap_or(("", &text));
                Err(Error::new(
                    Code::parse(code).unwrap_or(Code::Backend),
                    msg.to_owned(),
                ))
            }
            None => Err(Error::new(Code::Backend, "worker exited")),
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A pool of worker processes behind one [`Engine`].
pub struct Pool {
    kind: BackendKind,
    exe: PathBuf,
    threads_per_worker: usize,
    workers: Vec<Mutex<Option<Worker>>>,
    free: Mutex<VecDeque<usize>>,
    freed: Condvar,
    /// Replayed into restarted workers.
    programs: Mutex<Vec<(ProgramInfo, String)>>,
    keys: Mutex<Vec<(String, String, Vec<u8>)>>,
}

impl Pool {
    /// Start `n` workers running `exe worker --backend …`. Each gets
    /// `OMP_NUM_THREADS = cores / n` unless the variable is already set.
    pub fn start(kind: BackendKind, exe: PathBuf, n: usize) -> Result<Self> {
        let cores = std::thread::available_parallelism().map_or(1, |c| c.get());
        let pool = Self {
            kind,
            exe,
            threads_per_worker: (cores / n.max(1)).max(1),
            workers: (0..n.max(1)).map(|_| Mutex::new(None)).collect(),
            free: Mutex::new((0..n.max(1)).collect()),
            freed: Condvar::new(),
            programs: Mutex::new(vec![]),
            keys: Mutex::new(vec![]),
        };
        for w in &pool.workers {
            *w.lock().unwrap() = Some(pool.spawn()?);
        }
        Ok(pool)
    }

    pub fn size(&self) -> usize {
        self.workers.len()
    }

    /// Process IDs of the running workers (for monitoring and tests).
    pub fn worker_pids(&self) -> Vec<Option<u32>> {
        self.workers
            .iter()
            .map(|w| w.lock().unwrap().as_ref().map(|w| w.child.id()))
            .collect()
    }

    fn spawn(&self) -> Result<Worker> {
        let backend = match self.kind {
            BackendKind::Mock => "mock",
            BackendKind::OpenFhe => "openfhe",
        };
        let mut cmd = Command::new(&self.exe);
        cmd.args(["worker", "--backend", backend])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if std::env::var_os("OMP_NUM_THREADS").is_none() {
            cmd.env("OMP_NUM_THREADS", self.threads_per_worker.to_string());
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| Error::new(Code::Backend, format!("starting worker: {e}")))?;
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut w = Worker {
            child,
            stdin,
            stdout,
        };
        for (_, eir) in self.programs.lock().unwrap().iter() {
            w.call(ADD_PROGRAM, eir.as_bytes())?;
        }
        for (pid, _, env) in self.keys.lock().unwrap().iter() {
            w.call(REGISTER_KEYS, &with_pid(pid, env))?;
        }
        Ok(w)
    }

    /// Run `op` on worker `i`, restarting it once if it died.
    fn call_on(&self, i: usize, op: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let mut slot = self.workers[i].lock().unwrap();
        if slot.is_none() {
            *slot = Some(self.spawn()?);
        }
        let r = slot.as_mut().unwrap().call(op, payload);
        if let Err(e) = &r {
            if e.message.starts_with("worker I/O") || e.message == "worker exited" {
                // Failure isolation: drop the process; the next call restarts it.
                *slot = None;
                return Err(Error::new(
                    Code::Backend,
                    format!("evaluator worker {i} failed; restarted: {}", e.message),
                ));
            }
        }
        r
    }

    fn broadcast(&self, op: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let mut first = None;
        for i in 0..self.workers.len() {
            let v = self.call_on(i, op, payload)?;
            first.get_or_insert(v);
        }
        Ok(first.unwrap_or_default())
    }

    fn acquire(&self) -> usize {
        let mut free = self.free.lock().unwrap();
        loop {
            if let Some(i) = free.pop_front() {
                return i;
            }
            free = self.freed.wait(free).unwrap();
        }
    }

    fn release(&self, i: usize) {
        self.free.lock().unwrap().push_back(i);
        self.freed.notify_one();
    }
}

impl Engine for Pool {
    fn backend(&self) -> BackendKind {
        self.kind
    }

    fn add_program(&self, eir: &str) -> Result<ProgramInfo> {
        let v = self.broadcast(ADD_PROGRAM, eir.as_bytes())?;
        let info: ProgramInfo =
            serde_json::from_slice(&v).map_err(|e| Error::new(Code::Backend, e.to_string()))?;
        let mut ps = self.programs.lock().unwrap();
        if !ps.iter().any(|(p, _)| p.program_id == info.program_id) {
            ps.push((info.clone(), eir.to_owned()));
        }
        Ok(info)
    }

    fn programs(&self) -> Vec<ProgramInfo> {
        let mut v: Vec<_> = self
            .programs
            .lock()
            .unwrap()
            .iter()
            .map(|(p, _)| p.clone())
            .collect();
        v.sort_by(|a, b| a.program_id.cmp(&b.program_id));
        v
    }

    fn has_key(&self, pid: &str, kid: &str) -> Result<bool> {
        if !self
            .programs
            .lock()
            .unwrap()
            .iter()
            .any(|(p, _)| p.program_id == pid)
        {
            return Err(unknown_program());
        }
        Ok(self
            .keys
            .lock()
            .unwrap()
            .iter()
            .any(|(p, k, _)| p == pid && k == kid))
    }

    fn register_keys(&self, pid: &str, envelope: &[u8]) -> Result<String> {
        let kid = String::from_utf8(self.broadcast(REGISTER_KEYS, &with_pid(pid, envelope))?)
            .map_err(|_| Error::new(Code::Backend, "bad key ID from worker"))?;
        let mut keys = self.keys.lock().unwrap();
        if !keys.iter().any(|(p, k, _)| p == pid && *k == kid) {
            keys.push((pid.to_owned(), kid.clone(), envelope.to_vec()));
        }
        Ok(kid)
    }

    fn execute(&self, pid: &str, envelope: &[u8]) -> Result<(Vec<u8>, JobTimes)> {
        let i = self.acquire();
        let r = self.call_on(i, EXECUTE, &with_pid(pid, envelope));
        self.release(i);
        let v = r?;
        let n = u32::from_le_bytes(v[..4].try_into().unwrap()) as usize;
        let times: JobTimes = serde_json::from_slice(&v[4..4 + n])
            .map_err(|e| Error::new(Code::Backend, e.to_string()))?;
        Ok((v[4 + n..].to_vec(), times))
    }
}
