//! HTTP/1.1 evaluator service.
//!
//! | Method | Path | Body → Response |
//! |---|---|---|
//! | GET  | /v1/info | → protocol, versions, loaded programs (with a control plane: only the program a grant names) |
//! | POST | /v1/programs | `.eir` text → `{program_id}` (job grant with a control plane) |
//! | GET  | /v1/programs/{p}/keys/{k} | → 200 if registered, else 404 (job grant with a control plane) |
//! | POST | /v1/programs/{p}/keys | evaluation-keys envelope → `{key_id}` (job grant with a control plane) |
//! | POST | /v1/programs/{p}/jobs | inputs envelope → `{job_id, timings, receipt}` |
//! | GET  | /v1/jobs/{j}/result | → outputs envelope |
//! | GET  | /v1/jobs/{j}/receipt | → signed execution receipt (canonical JSON) |
//! | GET  | /v1/jobs/{j}/proof | → execution proof (`ENCP`), for programs requiring one |
//! | GET  | /v1/attestation | → the attestation record receipts bind, if attested |
//!
//! Every job gets a receipt signed with the evaluator's identity key,
//! binding the execution spec, key, and the exact request and response
//! bytes. A receipt is a signed claim, not a proof of correct execution.
//!
//! With a control plane ([`Evaluator::with_control`]), program and key
//! uploads carry the job's grant (`Encompute-Job-Grant`), as jobs do, and
//! the grant must name the uploaded program before it is compiled; the key
//! lookup needs one too, and `/v1/info` lists only the program a presented
//! grant names. Without one (local development) they need none. Job IDs are 128-bit
//! random: a result is fetched by its unguessable ID.
//!
//! Upload limits (bytes, environment, read by [`Limits::from_env`]):
//! `ENCOMPUTE_MAX_PROGRAM_BYTES` (default 64 MiB), `ENCOMPUTE_MAX_KEY_BYTES`
//! (default 4 GiB: bootstrapping keys are large; lower it where they are
//! not), `ENCOMPUTE_MAX_INPUT_BYTES` (default 256 MiB).
//!
//! Errors are `{"code": "ENC…", "message": …}`. Logs never contain payloads.
//! No TLS: terminate TLS at a reverse proxy.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use encompute_ir::{Code, Error, Result};
use serde_json::json;

use encompute_attestation::AttestationRecord;
use encompute_verification::{http, EvaluatorSigner, WorkloadAttestationRef};

use crate::engine::{Engine, Local};
use crate::session::{execution_proof, issue_receipt, BackendKind, Backends};

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Get,
    Post,
    Other,
}

#[derive(Clone, Debug)]
pub struct Limits {
    /// Largest accepted `.eir` upload.
    pub max_program: usize,
    /// Largest accepted evaluation-key upload.
    pub max_keys: usize,
    /// Largest accepted inputs envelope.
    pub max_inputs: usize,
    /// Results kept for retrieval (oldest dropped first).
    pub kept_results: usize,
    /// Concurrent HTTP handler threads.
    pub http_threads: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_program: 64 << 20,
            max_keys: 4 << 30,
            max_inputs: 256 << 20,
            kept_results: 64,
            http_threads: 8,
        }
    }
}

impl Limits {
    /// The defaults, with the upload limits from `ENCOMPUTE_MAX_PROGRAM_BYTES`,
    /// `ENCOMPUTE_MAX_KEY_BYTES` and `ENCOMPUTE_MAX_INPUT_BYTES`.
    pub fn from_env() -> Result<Self> {
        let mut l = Self::default();
        for (var, field) in [
            ("ENCOMPUTE_MAX_PROGRAM_BYTES", &mut l.max_program),
            ("ENCOMPUTE_MAX_KEY_BYTES", &mut l.max_keys),
            ("ENCOMPUTE_MAX_INPUT_BYTES", &mut l.max_inputs),
        ] {
            if let Ok(v) = std::env::var(var) {
                *field = v.trim().parse().map_err(|_| {
                    Error::new(Code::BadInput, format!("{var} is a byte count, not {v:?}"))
                })?;
            }
        }
        Ok(l)
    }
}

/// A finished job: (job ID, outputs envelope, signed receipt bytes,
/// execution proof bytes or empty).
type Job = (String, Vec<u8>, Vec<u8>, Vec<u8>);

/// HTTP front end over an [`Engine`].
pub struct Evaluator {
    engine: Arc<dyn Engine>,
    limits: Limits,
    signer: EvaluatorSigner,
    results: Mutex<VecDeque<Job>>,
    jobs: AtomicU64,
    requests: AtomicU64,
    workers: usize,
    attestation: Option<Attested>,
    control: Option<Arc<crate::control::ControlLink>>,
}

/// The attested workload session receipts bind.
struct Attested {
    reference: WorkloadAttestationRef,
    record: Vec<u8>,
}

struct Reply {
    status: u16,
    body: Vec<u8>,
    json: bool,
}

fn ok_json(v: serde_json::Value) -> Reply {
    Reply {
        status: 200,
        body: v.to_string().into_bytes(),
        json: true,
    }
}

fn error_reply(e: &Error) -> Reply {
    let status = match e.code {
        Code::Envelope | Code::BadInput | Code::Parse | Code::Type | Code::MissingRange => 400,
        Code::WrongKey | Code::WrongParameters | Code::Incompatible | Code::Receipt => 409,
        Code::WrongProgram => 404,
        Code::Unsupported | Code::DepthExceeded | Code::PrecisionUnreachable => 422,
        Code::Remote => 413,
        // A job the control plane did not grant (or refused to start).
        Code::ServiceAuthentication | Code::Unauthenticated => 401,
        Code::Forbidden => 403,
        Code::NotFound => 404,
        Code::Conflict => 409,
        Code::Scheduling => 503,
        _ => 500,
    };
    Reply {
        status,
        body: json!({"code": e.code.as_str(), "message": e.message})
            .to_string()
            .into_bytes(),
        json: true,
    }
}

fn not_found(what: &str) -> Reply {
    Reply {
        status: 404,
        body: json!({"code": "ENC1701", "message": format!("{what} not found")})
            .to_string()
            .into_bytes(),
        json: true,
    }
}

impl Evaluator {
    /// In-process evaluator with a fresh (ephemeral) identity.
    pub fn new(backends: Backends, limits: Limits) -> Self {
        Self::with_engine(
            Arc::new(Local::new(backends)),
            limits,
            0,
            EvaluatorSigner::generate().expect("randomness"),
        )
    }

    /// Evaluator over any engine, signing receipts with `signer`; `workers`
    /// is reported in `/v1/info` (0 = in-process).
    pub fn with_engine(
        engine: Arc<dyn Engine>,
        limits: Limits,
        workers: usize,
        signer: EvaluatorSigner,
    ) -> Self {
        Self {
            engine,
            limits,
            signer,
            results: Mutex::new(VecDeque::new()),
            jobs: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            workers,
            attestation: None,
            control: None,
        }
    }

    /// Runs jobs only as granted by a control plane (see [`crate::control`]).
    pub fn with_control(mut self, link: Arc<crate::control::ControlLink>) -> Self {
        self.control = Some(link);
        self
    }

    /// Runs as an attested workload: every receipt binds `record`, which
    /// must bind this evaluator's signing key.
    pub fn with_attestation(mut self, record: AttestationRecord) -> Result<Self> {
        if record.evidence.binding.evaluator_public_key != self.signer.identity().public_key_hex() {
            return Err(Error::new(
                Code::Attestation,
                "the attestation record binds another evaluator key",
            ));
        }
        self.attestation = Some(Attested {
            reference: WorkloadAttestationRef {
                attestation_id: record.id()?,
                workload_session_id: record.session_id()?,
            },
            record: record.to_bytes()?,
        });
        Ok(self)
    }

    /// Load a program at startup; returns its ID.
    pub fn add_program(&self, eir: &str) -> Result<String> {
        Ok(self.engine.add_program(eir)?.program_id)
    }

    /// With a control plane, `/v1/info` lists only the program a valid
    /// grant for this evaluator names (other tenants' programs are not
    /// advertised); without one (local development), every program.
    fn info(&self, grant: Option<&str>) -> serde_json::Value {
        let programs: Vec<_> = match &self.control {
            None => self.engine.programs(),
            Some(c) => match c.authorize_upload(grant, None) {
                Ok(g) => self
                    .engine
                    .programs()
                    .into_iter()
                    .filter(|p| p.program_id == g.program_id)
                    .collect(),
                Err(_) => vec![],
            },
        };
        let b = self.engine.backend();
        let label = |k: BackendKind, scheme: &str| {
            let (backend, version) = k.label();
            json!({"scheme": scheme, "backend": backend, "backend_version": version})
        };
        json!({
            "protocol": PROTOCOL_VERSION,
            "encompute_version": env!("CARGO_PKG_VERSION"),
            "role": "evaluator",
            "holds_secret_keys": false,
            "evaluator": {
                "id": self.signer.identity().evaluator_id(),
                "public_key": self.signer.identity().public_key_hex(),
            },
            "backends": {
                "approximate": label(b.approx, "CKKS"),
                "exact": label(
                    b.exact,
                    if b.exact == BackendKind::TfheRs { "TFHE" } else { "BinFHE" },
                ),
            },
            "worker_processes": self.workers,
            "attestation": self.attestation.as_ref().map(|a| json!({
                "attestation_id": a.reference.attestation_id,
                "workload_session_id": a.reference.workload_session_id,
            })),
            "programs": programs,
        })
    }

    /// Prometheus text format: counters only, no identifiers or key
    /// material. Expose it internally.
    fn metrics(&self) -> String {
        let c = self.engine.key_cache_stats();
        let mut out = String::new();
        let mut m = |name: &str, kind: &str, help: &str, v: String| {
            out += &format!("# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {v}\n");
        };
        m(
            "encompute_evaluator_requests_total",
            "counter",
            "HTTP requests.",
            self.requests.load(Ordering::Relaxed).to_string(),
        );
        m(
            "encompute_evaluator_jobs_total",
            "counter",
            "Jobs executed.",
            self.jobs.load(Ordering::Relaxed).to_string(),
        );
        m(
            "encompute_key_cache_hits_total",
            "counter",
            "Evaluation-key cache hits.",
            c.hits.to_string(),
        );
        m(
            "encompute_key_cache_misses_total",
            "counter",
            "Evaluation-key cache misses.",
            c.misses.to_string(),
        );
        m(
            "encompute_key_cache_loads_total",
            "counter",
            "Evaluation keys deserialized.",
            c.loads.to_string(),
        );
        m(
            "encompute_key_cache_load_seconds_total",
            "counter",
            "Time spent deserializing evaluation keys.",
            format!("{:.6}", c.load_seconds),
        );
        m(
            "encompute_key_cache_evictions_total",
            "counter",
            "Evaluation keys evicted to stay within the bound.",
            c.evictions.to_string(),
        );
        m(
            "encompute_key_cache_bytes",
            "gauge",
            "Serialized evaluation-key bytes held.",
            c.bytes.to_string(),
        );
        m(
            "encompute_key_cache_entries",
            "gauge",
            "Evaluation-key sets held.",
            c.entries.to_string(),
        );
        m(
            "encompute_key_cache_max_bytes",
            "gauge",
            "The configured bound (ENCOMPUTE_KEY_CACHE_BYTES).",
            crate::keycache::max_bytes_from_env().to_string(),
        );
        out
    }

    fn route(&self, method: &Method, path: &str, body: &[u8], grant: Option<&str>) -> Reply {
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let r = match (method, parts.as_slice()) {
            (Method::Get, ["v1", "info"]) => Ok(ok_json(self.info(grant))),
            (Method::Get, ["metrics"]) => Ok(Reply {
                status: 200,
                body: self.metrics().into_bytes(),
                json: false,
            }),
            (Method::Get, ["v1", "attestation"]) => match &self.attestation {
                Some(a) => Ok(Reply {
                    status: 200,
                    body: a.record.clone(),
                    json: true,
                }),
                None => return not_found("attestation"),
            },
            (Method::Post, ["v1", "programs"]) => self.add_uploaded_program(body, grant),
            // With a control plane, whether a key is registered is told
            // only to a holder of a grant for the program.
            (Method::Get, ["v1", "programs", pid, "keys", kid]) => {
                match self
                    .authorize_upload(grant, Some(pid))
                    .and_then(|_| self.engine.has_key(pid, kid))
                {
                    Ok(true) => Ok(ok_json(json!({ "key_id": kid }))),
                    Ok(false) => return not_found("key"),
                    Err(e) => Err(e),
                }
            }
            (Method::Post, ["v1", "programs", pid, "keys"]) => self
                .authorize_upload(grant, Some(pid))
                .and_then(|_| self.engine.register_keys(pid, body))
                .map(|k| ok_json(json!({ "key_id": k }))),
            (Method::Post, ["v1", "programs", pid, "jobs"]) => self.job(pid, body, grant),
            (Method::Get, ["v1", "jobs", jid, what @ ("result" | "receipt" | "proof")]) => {
                return match self
                    .results
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .iter()
                    .find(|(j, ..)| j == jid)
                {
                    Some((_, _, _, proof)) if *what == "proof" && proof.is_empty() => {
                        not_found("proof")
                    }
                    Some((_, out, receipt, proof)) => Reply {
                        status: 200,
                        body: match *what {
                            "result" => out.clone(),
                            "receipt" => receipt.clone(),
                            _ => proof.clone(),
                        },
                        json: *what == "receipt",
                    },
                    None => not_found("job"),
                };
            }
            _ => return not_found("route"),
        };
        r.unwrap_or_else(|e| error_reply(&e))
    }

    /// With a control plane, an upload needs a grant for this evaluator.
    fn authorize_upload(&self, grant: Option<&str>, program_id: Option<&str>) -> Result<()> {
        match &self.control {
            Some(c) => c.authorize_upload(grant, program_id).map(|_| ()),
            None => Ok(()),
        }
    }

    fn add_uploaded_program(&self, body: &[u8], grant: Option<&str>) -> Result<Reply> {
        // With a control plane, the grant must name this program before
        // anything is compiled or loaded: a refused upload changes nothing.
        // The program ID is the hash of the parsed program's canonical text,
        // so it is known before compiling.
        self.authorize_upload(grant, None)?;
        let text = std::str::from_utf8(body)
            .map_err(|_| Error::new(Code::Parse, "program must be UTF-8 .eir text"))?;
        let expected = match &self.control {
            Some(c) => {
                let pid = crate::session::program_id(&encompute_ir::parse(text)?);
                c.authorize_upload(grant, Some(&pid))?;
                Some(pid)
            }
            None => None,
        };
        let i = self.engine.add_program(text)?;
        if expected.is_some_and(|pid| pid != i.program_id) {
            return Err(Error::new(
                Code::WrongProgram,
                "the program compiled to another ID than the one granted",
            ));
        }
        Ok(ok_json(json!({ "program_id": i.program_id })))
    }

    /// Execute, then sign a receipt over the exact request and response.
    fn job(&self, pid: &str, body: &[u8], grant: Option<&str>) -> Result<Reply> {
        // With a control plane: only granted jobs, started with its consent.
        let granted = match &self.control {
            // An unreachable control plane is not an oversized request.
            Some(c) => Some(c.authorize(grant, pid).map_err(|e| {
                if e.code == Code::Remote {
                    Error::new(
                        Code::Scheduling,
                        format!(
                            "the control plane did not authorize this job: {}",
                            e.message
                        ),
                    )
                } else {
                    e
                }
            })?),
            None => None,
        };
        let (out, times) = self.engine.execute(pid, body)?;
        let info = self
            .engine
            .programs()
            .into_iter()
            .find(|p| p.program_id == pid)
            .ok_or_else(crate::engine::unknown_program)?;
        let proof = execution_proof(
            &info.spec,
            info.transcript_hash.as_deref(),
            info.proof_required,
            body,
            &out,
        )?;
        let receipt = issue_receipt(
            &info.spec,
            info.transcript_hash.as_deref(),
            body,
            &out,
            proof.as_ref(),
            self.attestation.as_ref().map(|a| &a.reference),
            &self.signer,
        )?;
        let proof_bytes = match &proof {
            Some(p) => p.to_bytes()?,
            None => vec![],
        };
        let receipt_json: serde_json::Value =
            serde_json::from_slice(&receipt.to_bytes()?).expect("canonical JSON");
        if let (Some(c), Some(g)) = (&self.control, &granted) {
            let ms = times.evaluate as u64;
            c.completed(g, &receipt_json, ms);
        }
        self.jobs.fetch_add(1, Ordering::Relaxed);
        // 128 random bits: whoever has the ID can fetch the result.
        let mut r = [0u8; 16];
        getrandom::getrandom(&mut r)
            .map_err(|e| Error::new(Code::Remote, format!("no randomness: {e}")))?;
        let job = encompute_verification::hex(&r);
        let mut results = self.results.lock().unwrap_or_else(|p| p.into_inner());
        results.push_back((job.clone(), out, receipt.to_bytes()?, proof_bytes));
        while results.len() > self.limits.kept_results {
            results.pop_front();
        }
        Ok(ok_json(json!({
            "job_id": job,
            "status": "done",
            "timings_ms": times,
            "execution_id": receipt.receipt.execution_id,
            "receipt": receipt_json,
            "proof": proof.is_some(),
            "optimizer": info.optimizer,
        })))
    }

    fn limit_for(&self, path: &str) -> usize {
        if path.ends_with("/keys") {
            self.limits.max_keys
        } else if path.ends_with("/jobs") {
            self.limits.max_inputs
        } else {
            self.limits.max_program
        }
    }

    /// Handle one request (its body already read within limits): route,
    /// respond, log.
    pub fn handle(&self, req: http::Request) -> http::Response {
        let id = self.requests.fetch_add(1, Ordering::Relaxed);
        let t = Instant::now();
        let path = req.path().to_owned();
        let method = match req.method.as_str() {
            "GET" => Method::Get,
            "POST" => Method::Post,
            _ => Method::Other,
        };
        let grant = req
            .header(encompute_verification::service::H_JOB_GRANT)
            .map(str::to_owned);
        let limit = self.limit_for(&path);
        let body = req.body;
        let reply = if body.len() > limit {
            error_reply(&Error::new(
                Code::Remote,
                format!("request body above the {limit}-byte limit"),
            ))
        } else {
            self.route(&method, &path, &body, grant.as_deref())
        };
        let (status, len) = (reply.status, reply.body.len());
        let ctype = if reply.json {
            "application/json"
        } else if path == "/metrics" {
            "text/plain; version=0.0.4"
        } else {
            "application/octet-stream"
        };
        eprintln!(
            "req={id} {} {path} status={status} in={}B out={len}B {:.1}ms",
            req.method,
            body.len(),
            t.elapsed().as_secs_f64() * 1e3
        );
        http::Response::new(status, ctype, reply.body).with_header("X-Request-Id", &id.to_string())
    }

    /// Serve forever on `limits.http_threads` connection threads.
    pub fn serve(self, server: http::Server) {
        let limits = http::Limits {
            threads: self.limits.http_threads.max(1),
            ..server.limits().clone()
        };
        server.with_limits(limits).serve(&self);
    }
}

impl http::Handler for Evaluator {
    fn body_limit(&self, head: &http::Request) -> usize {
        self.limit_for(head.path())
    }

    fn handle(&self, req: http::Request) -> http::Response {
        Evaluator::handle(self, req)
    }

    /// An oversized body keeps the evaluator's error code (ENC1701).
    fn refused(&self, why: http::Refused) -> http::Response {
        match why {
            http::Refused::TooLarge { .. } => {
                let r = error_reply(&Error::new(Code::Remote, why.message()));
                http::Response::new(r.status, "application/json", r.body)
            }
            _ => why.response(),
        }
    }
}
