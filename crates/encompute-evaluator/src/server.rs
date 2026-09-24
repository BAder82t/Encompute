//! HTTP/1.1 evaluator service (0.2 plan, D4).
//!
//! | Method | Path | Body → Response |
//! |---|---|---|
//! | GET  | /v1/info | → protocol, versions, loaded programs |
//! | POST | /v1/programs | `.eir` text → `{program_id}` |
//! | GET  | /v1/programs/{p}/keys/{k} | → 200 if registered, else 404 |
//! | POST | /v1/programs/{p}/keys | evaluation-keys envelope → `{key_id}` |
//! | POST | /v1/programs/{p}/jobs | inputs envelope → `{job_id, timings}` |
//! | GET  | /v1/jobs/{j}/result | → outputs envelope |
//!
//! Errors are `{"code": "ENC…", "message": …}`. Logs never contain payloads.
//! No TLS: terminate TLS at a reverse proxy.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::time::Instant;

use encompute_ir::{parse, Code, Error, Result};
use encompute_protocol::sha256_hex;
use serde_json::json;
use tiny_http::{Header, Method, Request, Response, Server};

use crate::session::{BackendKind, EvaluatorSession};

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
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_program: 64 << 20,
            max_keys: 4 << 30,
            max_inputs: 256 << 20,
            kept_results: 64,
        }
    }
}

/// All state of one evaluator process.
pub struct Evaluator {
    kind: BackendKind,
    limits: Limits,
    sessions: HashMap<String, EvaluatorSession>,
    results: VecDeque<(String, Vec<u8>)>,
    requests: u64,
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
        Code::WrongKey | Code::WrongProgram | Code::WrongParameters | Code::Incompatible => 409,
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
    pub fn new(kind: BackendKind, limits: Limits) -> Self {
        Self {
            kind,
            limits,
            sessions: HashMap::new(),
            results: VecDeque::new(),
            requests: 0,
        }
    }

    /// Load a program at startup; returns its ID.
    pub fn add_program(&mut self, eir: &str) -> Result<String> {
        let program = parse(eir)?;
        let session = EvaluatorSession::new(program, self.kind)?;
        let id = session.ids().program_id.clone();
        self.sessions.entry(id.clone()).or_insert(session);
        Ok(id)
    }

    fn info(&self) -> serde_json::Value {
        let (backend, backend_version) = self.kind.label();
        let programs: Vec<_> = self
            .sessions
            .values()
            .map(|s| {
                json!({
                    "name": s.program().name(),
                    "program_id": s.ids().program_id,
                    "parameter_set_id": s.ids().parameter_set_id,
                })
            })
            .collect();
        json!({
            "protocol": PROTOCOL_VERSION,
            "encompute_version": env!("CARGO_PKG_VERSION"),
            "role": "evaluator",
            "holds_secret_keys": false,
            "scheme": "CKKS",
            "backend": backend,
            "backend_version": backend_version,
            "programs": programs,
        })
    }

    fn session(&mut self, pid: &str) -> std::result::Result<&mut EvaluatorSession, Reply> {
        self.sessions
            .get_mut(pid)
            .ok_or_else(|| not_found("program"))
    }

    fn route(&mut self, method: &Method, path: &str, body: &[u8]) -> Reply {
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let r = match (method, parts.as_slice()) {
            (Method::Get, ["v1", "info"]) => Ok(ok_json(self.info())),
            (Method::Post, ["v1", "programs"]) => std::str::from_utf8(body)
                .map_err(|_| Error::new(Code::Parse, "program must be UTF-8 .eir text"))
                .and_then(|t| self.add_program(t))
                .map(|id| ok_json(json!({ "program_id": id }))),
            (Method::Get, ["v1", "programs", pid, "keys", kid]) => {
                return match self.session(pid) {
                    Ok(s) if s.has_key(kid) => ok_json(json!({ "key_id": kid })),
                    Ok(_) => not_found("key"),
                    Err(r) => r,
                };
            }
            (Method::Post, ["v1", "programs", pid, "keys"]) => {
                let s = match self.session(pid) {
                    Ok(s) => s,
                    Err(r) => return r,
                };
                s.register_keys(body)
                    .map(|k| ok_json(json!({ "key_id": k })))
            }
            (Method::Post, ["v1", "programs", pid, "jobs"]) => {
                let s = match self.session(pid) {
                    Ok(s) => s,
                    Err(r) => return r,
                };
                match s.execute(body) {
                    Ok((out, t)) => {
                        self.requests += 1;
                        let job = sha256_hex(
                            &[&self.requests.to_le_bytes()[..], &out[out.len() - 32..]].concat(),
                        )[..32]
                            .to_owned();
                        self.results.push_back((job.clone(), out));
                        while self.results.len() > self.limits.kept_results {
                            self.results.pop_front();
                        }
                        Ok(ok_json(json!({
                            "job_id": job,
                            "status": "done",
                            "timings_ms": {
                                "load": t.load.as_secs_f64() * 1e3,
                                "evaluate": t.evaluate.as_secs_f64() * 1e3,
                                "store": t.store.as_secs_f64() * 1e3,
                            },
                        })))
                    }
                    Err(e) => Err(e),
                }
            }
            (Method::Get, ["v1", "jobs", jid, "result"]) => {
                return match self.results.iter().find(|(j, _)| j == jid) {
                    Some((_, b)) => Reply {
                        status: 200,
                        body: b.clone(),
                        json: false,
                    },
                    None => not_found("job"),
                };
            }
            _ => return not_found("route"),
        };
        r.unwrap_or_else(|e| error_reply(&e))
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
    pub fn handle(&mut self, mut req: Request, id: u64) {
        let t = Instant::now();
        let method = req.method().clone();
        let path = req.url().split('?').next().unwrap_or("").to_owned();
        let limit = self.limit_for(&path);
        let declared = req.body_length().unwrap_or(0);
        let mut body = Vec::new();
        let reply = if declared > limit {
            error_reply(&Error::new(
                Code::Remote,
                format!("request body above the {limit}-byte limit"),
            ))
        } else {
            match req
                .as_reader()
                .take(limit as u64 + 1)
                .read_to_end(&mut body)
            {
                Ok(_) if body.len() > limit => error_reply(&Error::new(
                    Code::Remote,
                    format!("request body above the {limit}-byte limit"),
                )),
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

    /// Serve forever (single-threaded: OpenFHE calls are serialized anyway;
    /// worker processes scale out, P4).
    pub fn serve(mut self, server: Server) {
        for (id, req) in server.incoming_requests().enumerate() {
            self.handle(req, id as u64);
        }
    }
}
