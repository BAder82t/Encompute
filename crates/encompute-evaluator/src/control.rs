//! The evaluator's link to an Encompute control plane (optional).
//!
//! When configured, the evaluator:
//! - registers its backends, parameter profiles, capacity and receipt key,
//!   as its own service identity (signed requests, never an IP address);
//! - sends heartbeats (ready, or draining when told to drain);
//! - runs a job only with a job grant signed by the **pinned** control-plane
//!   key, naming this evaluator and the job's program, unexpired and unused;
//! - asks the control plane to start each job just before running it, so a
//!   job revoked or cancelled after scheduling never starts;
//! - reports each receipt as a signed message, retried until delivered.
//!
//! Configuration (environment; the key comes from a mounted secret file):
//! `ENCOMPUTE_CONTROL_URL`, `ENCOMPUTE_CONTROL_PUBLIC_KEY`,
//! `ENCOMPUTE_CONTROL_ID` (default `control-plane`), `ENCOMPUTE_SERVICE_ID`,
//! `ENCOMPUTE_SERVICE_KEY_FILE`, `ENCOMPUTE_ADVERTISE_URL`,
//! `ENCOMPUTE_CAPACITY`.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};

use encompute_ir::{Code, Error, Result};
use encompute_verification::service::{now, seal, signed_call, JobGrant, Scope};
use encompute_verification::ServiceSigner;

pub struct ControlLink {
    url: String,
    control_id: String,
    control_key: String,
    me: ServiceSigner,
    agent: ureq::Agent,
    used: Mutex<HashSet<String>>,
    outbox: Mutex<VecDeque<(String, Value)>>,
    draining: AtomicBool,
}

fn cfg(msg: impl Into<String>) -> Error {
    Error::new(Code::InsecureConfiguration, msg)
}

impl ControlLink {
    /// From the environment, or `None` when no control plane is configured.
    pub fn from_env() -> Result<Option<Self>> {
        let Ok(url) = std::env::var("ENCOMPUTE_CONTROL_URL") else {
            return Ok(None);
        };
        let control_key = std::env::var("ENCOMPUTE_CONTROL_PUBLIC_KEY")
            .map_err(|_| cfg("ENCOMPUTE_CONTROL_PUBLIC_KEY pins the control plane's key"))?;
        let id =
            std::env::var("ENCOMPUTE_SERVICE_ID").map_err(|_| cfg("set ENCOMPUTE_SERVICE_ID"))?;
        let key = std::env::var("ENCOMPUTE_SERVICE_KEY_FILE")
            .map_err(|_| cfg("set ENCOMPUTE_SERVICE_KEY_FILE (a mounted secret)"))?;
        let me = ServiceSigner::from_file(&id, std::path::Path::new(&key))?;
        Ok(Some(Self::new(
            &url,
            &std::env::var("ENCOMPUTE_CONTROL_ID").unwrap_or_else(|_| "control-plane".into()),
            &control_key,
            me,
        )))
    }

    pub fn new(url: &str, control_id: &str, control_key: &str, me: ServiceSigner) -> Self {
        Self {
            url: url.trim_end_matches('/').into(),
            control_id: control_id.into(),
            control_key: control_key.into(),
            me,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
            used: Mutex::new(HashSet::new()),
            outbox: Mutex::new(VecDeque::new()),
            draining: AtomicBool::new(false),
        }
    }

    pub fn id(&self) -> &str {
        self.me.id()
    }

    fn call(&self, method: &str, path: &str, bind: &[(&str, &str)], body: &Value) -> Result<Value> {
        let bind: BTreeMap<String, String> = bind
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        signed_call(
            &self.agent,
            &self.me,
            &self.url,
            &self.control_id,
            method,
            path,
            &bind,
            body,
        )
    }

    /// Registers this evaluator's capabilities and receipt key.
    pub fn register(
        &self,
        advertise_url: &str,
        receipt_key: &str,
        backends: &[&str],
        profiles: &[&str],
        capacity: u32,
    ) -> Result<()> {
        let v = self.call(
            "POST",
            "/v1/evaluators",
            &[],
            &json!({"id": self.me.id(), "url": advertise_url, "receipt_key": receipt_key,
                    "backends": backends, "profiles": profiles,
                    "openfhe_version": crate::session::BackendKind::OpenFhe.label().1,
                    "capacity": capacity}),
        )?;
        if v["control_public_key"].as_str() != Some(self.control_key.as_str()) {
            return Err(Error::new(
                Code::ServiceAuthentication,
                "the control plane answered with another key than the pinned one",
            ));
        }
        Ok(())
    }

    /// Stops taking new jobs (in-flight jobs finish), and tells the control
    /// plane.
    pub fn drain(&self) -> Result<()> {
        self.draining.store(true, Ordering::SeqCst);
        self.heartbeat()
    }

    /// Reports readiness; adopts a drain an operator ordered.
    pub fn heartbeat(&self) -> Result<()> {
        let status = if self.draining.load(Ordering::SeqCst) {
            "draining"
        } else {
            "ready"
        };
        let v = self.call(
            "POST",
            &format!("/v1/evaluators/{}/status", self.me.id()),
            &[],
            &json!({"status": status}),
        )?;
        if v["status"] == "draining" {
            self.draining.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    /// Checks a job's grant and asks the control plane to start it. Fails
    /// closed: no grant, a bad grant, a used grant, a draining evaluator or
    /// an unreachable control plane all refuse the job.
    pub fn authorize(&self, grant_header: Option<&str>, program_id: &str) -> Result<JobGrant> {
        if self.draining.load(Ordering::SeqCst) {
            return Err(Error::new(Code::Scheduling, "this evaluator is draining"));
        }
        let h = grant_header.ok_or_else(|| {
            Error::new(
                Code::ServiceAuthentication,
                "this evaluator runs only jobs granted by its control plane",
            )
        })?;
        let g = JobGrant::from_header(h)?;
        g.verify(&self.control_key, self.me.id(), program_id, now())?;
        {
            let mut used = self.used.lock().unwrap_or_else(|p| p.into_inner());
            if !used.insert(g.job_id.clone()) {
                return Err(Error::new(
                    Code::ServiceAuthentication,
                    "this job grant was already used",
                ));
            }
        }
        self.call(
            "POST",
            &format!("/v1/jobs/{}/start", g.job_id),
            &[("job", &g.job_id)],
            &Value::Null,
        )?;
        Ok(g)
    }

    /// Reports a job's receipt (queued; delivered now or by the heartbeat
    /// loop, at least once).
    pub fn completed(&self, g: &JobGrant, receipt: &Value, evaluation_ms: u64) {
        self.outbox
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back((
                g.job_id.clone(),
                json!({"receipt": receipt, "evaluation_ms": evaluation_ms}),
            ));
        self.flush();
    }

    /// Delivers queued completion messages.
    pub fn flush(&self) {
        loop {
            let next = self
                .outbox
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .front()
                .cloned();
            let Some((job, payload)) = next else { return };
            let sent = seal(
                &self.me,
                "job.completed",
                &self.control_id,
                Scope {
                    job: Some(job.clone()),
                    ..Scope::default()
                },
                &payload,
                24 * 3600,
            )
            .and_then(|m| {
                self.call(
                    "POST",
                    "/v1/messages",
                    &[("message", &m.message_id)],
                    &serde_json::to_value(&m).expect("serializable"),
                )
            });
            match sent {
                Ok(_) => {
                    self.outbox
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .pop_front();
                }
                Err(e) if e.code == Code::Remote => return, // retried later
                Err(e) => {
                    eprintln!("control plane refused the receipt of {job}: {}", e.message);
                    self.outbox
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .pop_front();
                }
            }
        }
    }

    /// Heartbeats and retries every `period` until the process exits.
    pub fn run(self: &std::sync::Arc<Self>, period: Duration) {
        let me = self.clone();
        std::thread::spawn(move || loop {
            if let Err(e) = me.heartbeat() {
                eprintln!("control plane heartbeat failed: {}", e.message);
            }
            me.flush();
            std::thread::sleep(period);
        });
    }
}
