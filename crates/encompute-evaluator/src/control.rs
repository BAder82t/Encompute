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
//! `ENCOMPUTE_CAPACITY`; for the machine profile it registers (used for
//! scheduling only), `ENCOMPUTE_EXACT_WORKERS` and
//! `ENCOMPUTE_BENCHMARK_PROFILE`.

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

    /// Registers this evaluator's capabilities, receipt key and machine
    /// profile.
    pub fn register(
        &self,
        advertise_url: &str,
        receipt_key: &str,
        backends: &[&str],
        profiles: &[&str],
        capacity: u32,
        machine: &MachineProfile,
    ) -> Result<()> {
        let mut body = json!({"id": self.me.id(), "url": advertise_url, "receipt_key": receipt_key,
                "backends": backends, "profiles": profiles,
                "openfhe_version": crate::session::BackendKind::OpenFhe.label().1,
                "capacity": capacity});
        if let (Value::Object(b), Value::Object(m)) = (&mut body, machine.to_json()) {
            b.extend(m);
        }
        let v = self.call("POST", "/v1/evaluators", &[], &body)?;
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

/// Threads per job when `ENCOMPUTE_EXACT_WORKERS` is unset: the logical
/// cores, at most this many.
pub const DEFAULT_MAX_PARALLEL_GATES: u32 = 8;

/// What this machine tells the control plane about itself, for placement
/// and completion estimates. Self-reported and unverified: the control
/// plane uses it for scheduling and performance only, never for a security
/// decision. Every field is optional; unknown values are left out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MachineProfile {
    pub cpu_model: Option<String>,
    pub logical_cores: Option<u32>,
    pub memory_bytes: Option<u64>,
    /// The calibrated cost profile this machine was benchmarked under
    /// (`ENCOMPUTE_BENCHMARK_PROFILE`, e.g. `openfhe-1.5.1/apple-m3-max`).
    pub benchmark_profile: Option<String>,
    /// Worker threads one job's gates use (`ENCOMPUTE_EXACT_WORKERS`,
    /// default min(logical cores, 8)).
    pub max_parallel_gates: Option<u32>,
}

impl MachineProfile {
    /// This machine: logical cores from the standard library; CPU model and
    /// memory from `/proc` (Linux) or `sysctl` (macOS), left out when that
    /// fails.
    pub fn detect() -> Self {
        let cores = std::thread::available_parallelism()
            .ok()
            .map(|n| n.get() as u32);
        Self::from_parts(
            cpu_model(),
            cores,
            memory_bytes(),
            std::env::var("ENCOMPUTE_BENCHMARK_PROFILE").ok(),
            std::env::var("ENCOMPUTE_EXACT_WORKERS").ok().as_deref(),
        )
    }

    /// A profile from detected values and the configured worker count
    /// (`workers`: the `ENCOMPUTE_EXACT_WORKERS` value, if set).
    pub fn from_parts(
        cpu_model: Option<String>,
        logical_cores: Option<u32>,
        memory_bytes: Option<u64>,
        benchmark_profile: Option<String>,
        workers: Option<&str>,
    ) -> Self {
        let clean = |s: Option<String>| {
            s.map(|s| {
                s.trim()
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(200)
                    .collect::<String>()
            })
            .filter(|s| !s.is_empty())
        };
        let logical_cores = logical_cores.filter(|c| *c > 0).map(|n| n.min(65_536));
        let max_parallel_gates = workers
            .and_then(|w| w.trim().parse::<u32>().ok())
            .filter(|n| *n > 0)
            .or_else(|| logical_cores.map(|c| c.min(DEFAULT_MAX_PARALLEL_GATES)))
            .unwrap_or(1)
            .min(65_536);
        Self {
            cpu_model: clean(cpu_model),
            logical_cores,
            memory_bytes: memory_bytes.filter(|m| *m > 0 && *m <= i64::MAX as u64),
            benchmark_profile: clean(benchmark_profile),
            max_parallel_gates: Some(max_parallel_gates),
        }
    }

    /// The registration fields that are known.
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        if let Some(v) = &self.cpu_model {
            m.insert("cpu_model".into(), json!(v));
        }
        if let Some(v) = self.logical_cores {
            m.insert("logical_cores".into(), json!(v));
        }
        if let Some(v) = self.memory_bytes {
            m.insert("memory_bytes".into(), json!(v));
        }
        if let Some(v) = &self.benchmark_profile {
            m.insert("benchmark_profile".into(), json!(v));
        }
        if let Some(v) = self.max_parallel_gates {
            m.insert("max_parallel_gates".into(), json!(v));
        }
        Value::Object(m)
    }
}

/// The CPU model: `model name` in `/proc/cpuinfo` (Linux), or
/// `sysctl -n machdep.cpu.brand_string` (macOS).
fn cpu_model() -> Option<String> {
    if cfg!(target_os = "linux") {
        parse_cpuinfo_model(&std::fs::read_to_string("/proc/cpuinfo").ok()?)
    } else if cfg!(target_os = "macos") {
        sysctl("machdep.cpu.brand_string")
    } else {
        None
    }
}

/// Physical memory: `MemTotal` in `/proc/meminfo` (Linux) or
/// `sysctl -n hw.memsize` (macOS).
fn memory_bytes() -> Option<u64> {
    if cfg!(target_os = "linux") {
        parse_meminfo_total(&std::fs::read_to_string("/proc/meminfo").ok()?)
    } else if cfg!(target_os = "macos") {
        sysctl("hw.memsize")?.parse().ok()
    } else {
        None
    }
}

fn sysctl(name: &str) -> Option<String> {
    let out = std::process::Command::new("sysctl")
        .args(["-n", name])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (!s.is_empty()).then_some(s)
}

/// The first `model name` of a `/proc/cpuinfo` (many ARM boards have none).
pub fn parse_cpuinfo_model(info: &str) -> Option<String> {
    info.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        Some(v.trim().to_owned()).filter(|v| k.trim() == "model name" && !v.is_empty())
    })
}

/// `MemTotal` of a `/proc/meminfo`, in bytes (the file counts kB).
pub fn parse_meminfo_total(info: &str) -> Option<u64> {
    info.lines().find_map(|l| {
        let kb: u64 = l
            .strip_prefix("MemTotal:")?
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse()
            .ok()?;
        kb.checked_mul(1024)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_files() {
        let cpu = "processor\t: 0\nvendor_id\t: GenuineIntel\n\
                   model name\t: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz\n\n\
                   processor\t: 1\nmodel name\t: other\n";
        assert_eq!(
            parse_cpuinfo_model(cpu).as_deref(),
            Some("Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz")
        );
        assert_eq!(
            parse_cpuinfo_model("processor : 0\nHardware : BCM2835\n"),
            None
        );
        let mem = "MemTotal:       16318412 kB\nMemFree:         1234 kB\n";
        assert_eq!(parse_meminfo_total(mem), Some(16_318_412 * 1024));
        assert_eq!(parse_meminfo_total("MemFree: 1 kB\n"), None);
    }

    #[test]
    fn worker_default_and_override() {
        let gates =
            |cores, w| MachineProfile::from_parts(None, cores, None, None, w).max_parallel_gates;
        assert_eq!(gates(Some(32), None), Some(DEFAULT_MAX_PARALLEL_GATES));
        assert_eq!(gates(Some(4), None), Some(4));
        assert_eq!(gates(Some(4), Some("12")), Some(12));
        // An unparsable or zero setting falls back to the default.
        assert_eq!(gates(Some(2), Some("zero")), Some(2));
        assert_eq!(gates(None, Some("0")), Some(1));
    }

    #[test]
    fn json_leaves_out_unknown_fields() {
        let p = MachineProfile::from_parts(
            Some("  Apple M3 Max \n".into()),
            Some(16),
            Some(1 << 36),
            Some(String::new()),
            None,
        );
        assert_eq!(
            p.to_json(),
            json!({"cpu_model": "Apple M3 Max", "logical_cores": 16,
                   "memory_bytes": 1u64 << 36, "max_parallel_gates": 8})
        );
        assert_eq!(MachineProfile::default().to_json(), json!({}));
        // Detection never panics and always knows its worker count.
        assert!(MachineProfile::detect().max_parallel_gates.is_some());
    }
}
