//! HTTP/1.1 evaluator service.
//!
//! | Method | Path | Body → Response |
//! |---|---|---|
//! | GET  | /v1/info | → protocol, versions, loaded programs |
//! | POST | /v1/programs | `.eir` text → `{program_id}` |
//! | GET  | /v1/programs/{p}/keys/{k} | → 200 if registered, else 404 |
//! | POST | /v1/programs/{p}/keys | evaluation-keys envelope → `{key_id}` |
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
//! Errors are `{"code": "ENC…", "message": …}`. Logs never contain payloads.
//! No TLS: terminate TLS at a reverse proxy.

use std::collections::VecDeque;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use encompute_ir::{Code, Error, Result};
use encompute_protocol::sha256_hex;
use serde_json::json;
use tiny_http::{Header, Method, Request, Response, Server};

use encompute_attestation::AttestationRecord;
use encompute_verification::{EvaluatorSigner, WorkloadAttestationRef};

use crate::engine::{Engine, Local};
use crate::session::{execution_proof, issue_receipt, BackendKind, Backends};

pub const PROTOCOL_VERSION: u32 = 1;

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
        }
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

    fn info(&self) -> serde_json::Value {
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
                "exact": label(b.exact, "TFHE"),
            },
            "worker_processes": self.workers,
            "attestation": self.attestation.as_ref().map(|a| json!({
                "attestation_id": a.reference.attestation_id,
                "workload_session_id": a.reference.workload_session_id,
            })),
            "programs": self.engine.programs(),
        })
    }

    fn route(&self, method: &Method, path: &str, body: &[u8]) -> Reply {
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let r = match (method, parts.as_slice()) {
            (Method::Get, ["v1", "info"]) => Ok(ok_json(self.info())),
            (Method::Get, ["v1", "attestation"]) => match &self.attestation {
                Some(a) => Ok(Reply {
                    status: 200,
                    body: a.record.clone(),
                    json: true,
                }),
                None => return not_found("attestation"),
            },
            (Method::Post, ["v1", "programs"]) => std::str::from_utf8(body)
                .map_err(|_| Error::new(Code::Parse, "program must be UTF-8 .eir text"))
                .and_then(|t| self.engine.add_program(t))
                .map(|i| ok_json(json!({ "program_id": i.program_id }))),
            (Method::Get, ["v1", "programs", pid, "keys", kid]) => {
                match self.engine.has_key(pid, kid) {
                    Ok(true) => Ok(ok_json(json!({ "key_id": kid }))),
                    Ok(false) => return not_found("key"),
                    Err(e) => Err(e),
                }
            }
            (Method::Post, ["v1", "programs", pid, "keys"]) => self
                .engine
                .register_keys(pid, body)
                .map(|k| ok_json(json!({ "key_id": k }))),
            (Method::Post, ["v1", "programs", pid, "jobs"]) => self.job(pid, body),
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

    /// Execute, then sign a receipt over the exact request and response.
    fn job(&self, pid: &str, body: &[u8]) -> Result<Reply> {
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
        let n = self.jobs.fetch_add(1, Ordering::Relaxed);
        let tail = &out[out.len().saturating_sub(32)..];
        let job = sha256_hex(&[&n.to_le_bytes()[..], tail].concat())[..32].to_owned();
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

    /// Handle one request: read the body within limits, route, respond, log.
    pub fn handle(&self, mut req: Request) {
        let id = self.requests.fetch_add(1, Ordering::Relaxed);
        let t = Instant::now();
        let method = req.method().clone();
        let path = req.url().split('?').next().unwrap_or("").to_owned();
        let limit = self.limit_for(&path);
        let declared = req.body_length().unwrap_or(0);
        let mut body = Vec::new();
        let too_big = || {
            error_reply(&Error::new(
                Code::Remote,
                format!("request body above the {limit}-byte limit"),
            ))
        };
        let reply = if declared > limit {
            too_big()
        } else {
            match req
                .as_reader()
                .take(limit as u64 + 1)
                .read_to_end(&mut body)
            {
                Ok(_) if body.len() > limit => too_big(),
                Ok(_) => self.route(&method, &path, &body),
                Err(e) => error_reply(&Error::new(Code::Remote, format!("reading request: {e}"))),
            }
        };
        let (status, len) = (reply.status, reply.body.len());
        let ctype = if reply.json {
            "application/json"
        } else {
            "application/octet-stream"
        };
        let mut resp = Response::from_data(reply.body).with_status_code(status);
        resp.add_header(Header::from_bytes("Content-Type", ctype).unwrap());
        resp.add_header(Header::from_bytes("X-Request-Id", id.to_string()).unwrap());
        let _ = req.respond(resp);
        eprintln!(
            "req={id} {method} {path} status={status} in={}B out={len}B {:.1}ms",
            body.len(),
            t.elapsed().as_secs_f64() * 1e3
        );
    }

    /// Serve forever on `limits.http_threads` threads.
    pub fn serve(self, server: Server) {
        let (me, server) = (Arc::new(self), Arc::new(server));
        let threads: Vec<_> = (0..me.limits.http_threads.max(1))
            .map(|_| {
                let (me, server) = (me.clone(), server.clone());
                std::thread::spawn(move || {
                    while let Ok(req) = server.recv() {
                        me.handle(req);
                    }
                })
            })
            .collect();
        for t in threads {
            let _ = t.join();
        }
    }
}
