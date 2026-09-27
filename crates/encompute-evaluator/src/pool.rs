//! Worker processes. The gateway owns HTTP and forwards work
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
use crate::session::Backends;

const ADD_PROGRAM: u8 = 1;
const REGISTER_KEYS: u8 = 3;
const EXECUTE: u8 = 4;
const HAS_KEY: u8 = 5;
const KEY_CACHE_STATS: u8 = 6;

fn io(e: std::io::Error) -> Error {
    Error::new(Code::Backend, format!("worker I/O: {e}"))
}

fn write_frame(w: &mut impl Write, tag: u8, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&[tag])?;
    w.write_all(&(payload.len() as u64).to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// Largest frame payload: an evaluation-key upload (at most 4 GiB through
/// HTTP) plus its program ID, with room to spare.
pub const MAX_FRAME: u64 = 8 << 30;

/// Reads one frame; `None` at a clean end of stream. The declared length is
/// untrusted (the peer may be a crashed or compromised process): above
/// [`MAX_FRAME`] it is refused, and the body buffer grows with the bytes
/// actually received, so a short stream fails without allocating the
/// declared size.
#[doc(hidden)]
pub fn read_frame(r: &mut impl Read) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 9];
    match r.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u64::from_le_bytes(head[1..].try_into().expect("8 bytes"));
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("worker frame of {len} bytes exceeds {MAX_FRAME}"),
        ));
    }
    let mut body = Vec::new();
    r.take(len).read_to_end(&mut body)?;
    if body.len() as u64 != len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated worker frame",
        ));
    }
    Ok(Some((head[0], body)))
}

/// Splits a worker's `EXECUTE` reply: `times_len u32 LE | times (JSON) |
/// outputs envelope`.
#[doc(hidden)]
pub fn split_execute_reply(v: &[u8]) -> Result<(JobTimes, &[u8])> {
    let malformed = || Error::new(Code::Backend, "malformed worker reply");
    let n = v
        .get(..4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")) as usize)
        .ok_or_else(malformed)?;
    let times = v.get(4..4 + n).ok_or_else(malformed)?;
    let times: JobTimes =
        serde_json::from_slice(times).map_err(|e| Error::new(Code::Backend, e.to_string()))?;
    Ok((times, &v[4 + n..]))
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
pub fn run_worker(backends: Backends) -> std::io::Result<()> {
    let engine = Local::new(backends);
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
            HAS_KEY => {
                let (pid, kid) = split_pid(&payload)?;
                let kid =
                    std::str::from_utf8(kid).map_err(|_| Error::new(Code::Parse, "not UTF-8"))?;
                Ok(vec![engine.has_key(pid, kid)? as u8])
            }
            KEY_CACHE_STATS => Ok(serde_json::to_vec(&engine.key_cache_stats()).unwrap()),
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
    backends: Backends,
    exe: PathBuf,
    threads_per_worker: usize,
    workers: Vec<Mutex<Option<Worker>>>,
    free: Mutex<VecDeque<usize>>,
    freed: Condvar,
    /// Replayed into restarted workers.
    programs: Mutex<Vec<(ProgramInfo, String)>>,
    /// Registered key envelopes, replayed into restarted workers. Bounded
    /// like the workers' caches: a key evicted here is uploaded again.
    keys: crate::keycache::KeyCache<(String, Vec<u8>)>,
}

impl Pool {
    /// Start `n` workers running `exe worker --backend …`. Each gets
    /// `OMP_NUM_THREADS = cores / n` unless the variable is already set.
    pub fn start(backends: Backends, exe: PathBuf, n: usize) -> Result<Self> {
        let cores = std::thread::available_parallelism().map_or(1, |c| c.get());
        let pool = Self {
            backends,
            exe,
            threads_per_worker: (cores / n.max(1)).max(1),
            workers: (0..n.max(1)).map(|_| Mutex::new(None)).collect(),
            free: Mutex::new((0..n.max(1)).collect()),
            freed: Condvar::new(),
            programs: Mutex::new(vec![]),
            keys: crate::keycache::KeyCache::new(crate::keycache::max_bytes_from_env()),
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
        let mut cmd = Command::new(&self.exe);
        cmd.arg("worker")
            .args(self.backends.args())
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
        for e in self.keys.values() {
            let (pid, env) = &*e;
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
    fn backend(&self) -> Backends {
        self.backends
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
        // Workers evict independently: the key is present only if every
        // worker still holds it (the client then uploads it again).
        for i in 0..self.workers.len() {
            if self.call_on(i, HAS_KEY, &with_pid(pid, kid.as_bytes()))? != [1] {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn register_keys(&self, pid: &str, envelope: &[u8]) -> Result<String> {
        let kid = String::from_utf8(self.broadcast(REGISTER_KEYS, &with_pid(pid, envelope))?)
            .map_err(|_| Error::new(Code::Backend, "bad key ID from worker"))?;
        let key = crate::keycache::CacheKey {
            backend: "replay",
            scope: pid.to_owned(),
            key_id: kid.clone(),
        };
        self.keys.get_or_load(key, envelope.len() as u64, || {
            Ok((pid.to_owned(), envelope.to_vec()))
        })?;
        Ok(kid)
    }

    fn execute(&self, pid: &str, envelope: &[u8]) -> Result<(Vec<u8>, JobTimes)> {
        let i = self.acquire();
        let r = self.call_on(i, EXECUTE, &with_pid(pid, envelope));
        self.release(i);
        let v = r?;
        let (times, out) = split_execute_reply(&v)?;
        Ok((out.to_vec(), times))
    }

    fn key_cache_stats(&self) -> crate::keycache::CacheStats {
        let mut total = crate::keycache::CacheStats::default();
        for i in 0..self.workers.len() {
            if let Ok(s) = self.call_on(i, KEY_CACHE_STATS, &[]).and_then(|v| {
                serde_json::from_slice(&v).map_err(|e| Error::new(Code::Backend, e.to_string()))
            }) {
                total += s;
            }
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(tag: u8, len: u64, body: &[u8]) -> Vec<u8> {
        let mut f = vec![tag];
        f.extend_from_slice(&len.to_le_bytes());
        f.extend_from_slice(body);
        f
    }

    #[test]
    fn frames_round_trip() {
        let mut buf = vec![];
        write_frame(&mut buf, 4, b"pid\npayload").unwrap();
        write_frame(&mut buf, 0, b"").unwrap();
        let mut r = buf.as_slice();
        assert_eq!(
            read_frame(&mut r).unwrap(),
            Some((4, b"pid\npayload".to_vec()))
        );
        assert_eq!(read_frame(&mut r).unwrap(), Some((0, vec![])));
        assert_eq!(read_frame(&mut r).unwrap(), None);
    }

    /// Regression: the declared length was allocated up front, so a frame
    /// claiming 2^63 bytes aborted the reading process (capacity overflow
    /// or out of memory) whatever followed.
    #[test]
    fn huge_declared_lengths_are_refused_without_allocating() {
        let t = std::time::Instant::now();
        for len in [u64::MAX, 1 << 63, MAX_FRAME + 1] {
            let f = frame(0, len, b"short");
            let e = read_frame(&mut f.as_slice()).unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "{len}");
        }
        // Within the limit but truncated: an error, and no 8 GiB buffer.
        let f = frame(0, MAX_FRAME, b"short");
        let e = read_frame(&mut f.as_slice()).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
        let f = frame(0, 6, b"short");
        assert!(read_frame(&mut f.as_slice()).is_err());
        // A truncated header is a clean end of stream.
        assert_eq!(read_frame(&mut &[1u8, 2, 3][..]).unwrap(), None);
        assert!(t.elapsed() < std::time::Duration::from_secs(1));
    }

    /// Regression: a short `EXECUTE` reply from a worker panicked the
    /// gateway's request thread (slice out of bounds).
    #[test]
    fn malformed_execute_replies_are_errors() {
        for v in [
            &b""[..],
            b"\x01",
            b"\x05\0\0\0{}",
            b"\xff\xff\xff\xff{}",
            b"\x02\0\0\0[]",
        ] {
            assert_eq!(split_execute_reply(v).unwrap_err().code, Code::Backend);
        }
        let t = serde_json::to_vec(&JobTimes::default()).unwrap();
        let mut v = (t.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(&t);
        v.extend_from_slice(b"out");
        assert_eq!(split_execute_reply(&v).unwrap().1, b"out");
    }
}
