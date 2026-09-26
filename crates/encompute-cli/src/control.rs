//! `encompute` over a control plane (API v1): login, projects, assets,
//! jobs, trust reports and the audit trail. The CLI and the Python SDK call
//! the same API.
//!
//! Credentials, in order:
//! - a service identity (`ENCOMPUTE_SERVICE_ID` + `ENCOMPUTE_SERVICE_KEY_FILE`),
//!   for automation: every request is signed;
//! - `ENCOMPUTE_TOKEN` (an OIDC token from the organization's identity
//!   provider);
//! - the token saved by `encompute login` (`~/.config/encompute/control.json`,
//!   mode 0600).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Subcommand;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use encompute_ir::{Code, Error, Result};
use encompute_runtime::{ClientSession, Model, Remote};
use encompute_verification::service::signed_call;
use encompute_verification::{
    output_commitment, request_commitment, EvaluatorIdentity, JobGrant, ServiceSigner,
};

fn cfg_err(m: impl Into<String>) -> Error {
    Error::new(Code::Unauthenticated, m)
}

fn config_path() -> Result<PathBuf> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map_err(|_| cfg_err("no home directory for the saved login"))?;
    Ok(base.join("encompute").join("control.json"))
}

enum Auth {
    Bearer(Zeroizing<String>),
    Service(Box<ServiceSigner>, String),
}

pub struct ControlClient {
    url: String,
    auth: Auth,
    agent: ureq::Agent,
}

impl ControlClient {
    /// From the environment or the saved login.
    pub fn from_env(url: Option<&str>) -> Result<Self> {
        let saved: Value = config_path()
            .ok()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null);
        let url = url
            .map(str::to_owned)
            .or_else(|| std::env::var("ENCOMPUTE_CONTROL_URL").ok())
            .or_else(|| saved["url"].as_str().map(str::to_owned))
            .ok_or_else(|| {
                cfg_err("no control plane: encompute login --url URL, or set ENCOMPUTE_CONTROL_URL")
            })?;
        let auth = if let (Ok(id), Ok(key)) = (
            std::env::var("ENCOMPUTE_SERVICE_ID"),
            std::env::var("ENCOMPUTE_SERVICE_KEY_FILE"),
        ) {
            Auth::Service(
                Box::new(ServiceSigner::from_file(&id, Path::new(&key))?),
                std::env::var("ENCOMPUTE_CONTROL_ID").unwrap_or_else(|_| "control-plane".into()),
            )
        } else if let Ok(t) = std::env::var("ENCOMPUTE_TOKEN") {
            Auth::Bearer(Zeroizing::new(t))
        } else {
            Auth::Bearer(Zeroizing::new(
                saved["token"]
                    .as_str()
                    .ok_or_else(|| cfg_err("not logged in: encompute login"))?
                    .to_owned(),
            ))
        };
        Ok(Self {
            url: url.trim_end_matches('/').into(),
            auth,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(60))
                .build(),
        })
    }

    pub fn call(
        &self,
        method: &str,
        path: &str,
        body: Value,
        headers: &[(&str, &str)],
    ) -> Result<Value> {
        match &self.auth {
            Auth::Service(s, control) => {
                if !headers.is_empty() {
                    // Idempotency keys ride in the body's hash; signed calls
                    // carry them as a header too.
                    let bytes = serde_json::to_vec(&body).expect("serializable");
                    let h = s.sign_request(method, path, control, &BTreeMap::new(), &bytes)?;
                    let mut r = self
                        .agent
                        .request(method, &format!("{}{path}", self.url))
                        .set("Content-Type", "application/json");
                    for (k, v) in h
                        .to_pairs()
                        .iter()
                        .map(|(k, v)| (*k, v.as_str()))
                        .chain(headers.iter().copied())
                    {
                        r = r.set(k, v);
                    }
                    return reply(r.send_bytes(&bytes));
                }
                signed_call(
                    &self.agent,
                    s,
                    &self.url,
                    control,
                    method,
                    path,
                    &BTreeMap::new(),
                    &body,
                )
            }
            Auth::Bearer(t) => {
                let mut r = self
                    .agent
                    .request(method, &format!("{}{path}", self.url))
                    .set("Authorization", &format!("Bearer {}", t.as_str()))
                    .set("Content-Type", "application/json");
                for (k, v) in headers {
                    r = r.set(k, v);
                }
                reply(if body.is_null() {
                    r.call()
                } else {
                    r.send_json(body)
                })
            }
        }
    }

    pub fn get(&self, path: &str) -> Result<Value> {
        self.call("GET", path, Value::Null, &[])
    }

    pub fn post(&self, path: &str, body: Value) -> Result<Value> {
        self.call("POST", path, body, &[])
    }
}

fn reply(r: std::result::Result<ureq::Response, ureq::Error>) -> Result<Value> {
    match r {
        Ok(r) => r
            .into_json()
            .map_err(|e| Error::new(Code::Remote, e.to_string())),
        Err(ureq::Error::Status(status, r)) => {
            let v: Value = r.into_json().unwrap_or(Value::Null);
            let code = v["code"]
                .as_str()
                .and_then(Code::parse)
                .unwrap_or(Code::Remote);
            Err(Error::new(
                code,
                format!(
                    "control plane ({status}): {}",
                    v["message"].as_str().unwrap_or("")
                ),
            ))
        }
        Err(e) => Err(Error::new(
            Code::Remote,
            format!("cannot reach the control plane: {e}"),
        )),
    }
}

fn print(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).expect("JSON"));
}

/// `encompute login`: saves the control plane URL and a token (from a file
/// or standard input; never a command-line argument), mode 0600.
pub fn login(url: &str, token_file: Option<&Path>) -> Result<()> {
    let mut token = Zeroizing::new(String::new());
    match token_file {
        Some(f) => {
            *token =
                std::fs::read_to_string(f).map_err(|e| cfg_err(format!("{}: {e}", f.display())))?;
        }
        None => {
            std::io::stdin()
                .read_to_string(&mut token)
                .map_err(|e| cfg_err(format!("reading the token: {e}")))?;
        }
    }
    let token = Zeroizing::new(token.trim().to_owned());
    let c = ControlClient {
        url: url.trim_end_matches('/').into(),
        auth: Auth::Bearer(token.clone()),
        agent: ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build(),
    };
    let me = c.get("/v1/whoami")?;
    let p = config_path()?;
    std::fs::create_dir_all(p.parent().expect("dir")).map_err(|e| cfg_err(e.to_string()))?;
    let body =
        serde_json::to_vec_pretty(&json!({"url": c.url, "token": token.as_str()})).expect("JSON");
    let tmp = p.with_extension("tmp");
    {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(&tmp)
            .and_then(|mut f| f.write_all(&body))
            .map_err(|e| cfg_err(format!("{}: {e}", tmp.display())))?;
    }
    std::fs::rename(&tmp, &p).map_err(|e| cfg_err(e.to_string()))?;
    println!(
        "logged in to {} as {} ({})",
        c.url,
        me["id"].as_str().unwrap_or("?"),
        me["organization"].as_str().unwrap_or("platform")
    );
    Ok(())
}

#[derive(Subcommand)]
pub enum ProjectsCmd {
    List,
    Show {
        id: String,
    },
    Create {
        #[arg(long)]
        organization: String,
        #[arg(long)]
        name: String,
    },
    /// Adds a collaborating organization (project owner's admins).
    AddMember {
        id: String,
        #[arg(long)]
        organization: String,
    },
}

#[derive(Subcommand)]
pub enum AssetsCmd {
    List,
    Show {
        id: String,
    },
    /// Registers an asset's metadata (never its contents).
    Register {
        #[arg(long)]
        organization: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        name: String,
        /// The content digest; or compute it from `--file`.
        #[arg(long)]
        digest: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        storage_uri: Option<String>,
    },
    /// Approves an asset for a project and purpose (owners).
    Approve {
        id: String,
        #[arg(long)]
        project: String,
        #[arg(long)]
        purpose: String,
    },
    Revoke {
        id: String,
    },
    Lineage {
        id: String,
    },
}

#[derive(Subcommand)]
pub enum JobsCmd {
    List {
        #[arg(long)]
        project: Option<String>,
    },
    Status {
        id: String,
    },
    Cancel {
        id: String,
    },
    /// Plans and submits a job for a compiled model.
    Submit {
        model: PathBuf,
        #[arg(long)]
        project: String,
        #[arg(long)]
        purpose: String,
        #[arg(long = "source")]
        sources: Vec<String>,
        #[arg(long, default_value = "out")]
        output: String,
        /// Makes retries safe (default: derived from the request).
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Submits, waits for scheduling, runs on the scheduled evaluator with
    /// the job's grant, reports the receipt, and prints the result and the
    /// trust verdict.
    Run {
        model: PathBuf,
        #[arg(long)]
        project: String,
        #[arg(long)]
        purpose: String,
        #[arg(long = "source")]
        sources: Vec<String>,
        #[arg(short, long = "input")]
        inputs: Vec<String>,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

pub fn projects(cmd: ProjectsCmd) -> Result<()> {
    let c = ControlClient::from_env(None)?;
    print(&match cmd {
        ProjectsCmd::List => c.get("/v1/projects")?,
        ProjectsCmd::Show { id } => c.get(&format!("/v1/projects/{id}"))?,
        ProjectsCmd::Create { organization, name } => c.post(
            "/v1/projects",
            json!({"organization": organization, "name": name}),
        )?,
        ProjectsCmd::AddMember { id, organization } => c.post(
            &format!("/v1/projects/{id}/members"),
            json!({"organization": organization}),
        )?,
    });
    Ok(())
}

pub fn assets(cmd: AssetsCmd) -> Result<()> {
    let c = ControlClient::from_env(None)?;
    print(&match cmd {
        AssetsCmd::List => c.get("/v1/assets")?,
        AssetsCmd::Show { id } => c.get(&format!("/v1/assets/{id}"))?,
        AssetsCmd::Register {
            organization,
            kind,
            name,
            digest,
            file,
            storage_uri,
        } => {
            let digest = match (digest, file) {
                (Some(d), _) => d,
                (None, Some(f)) => encompute_verification::service::sha256_hex(
                    &std::fs::read(&f)
                        .map_err(|e| Error::new(Code::Artifact, format!("{}: {e}", f.display())))?,
                ),
                (None, None) => return Err(Error::new(Code::BadInput, "give --digest or --file")),
            };
            c.post(
                "/v1/assets",
                json!({"organization": organization, "kind": kind, "name": name, "digest": digest, "storage_uri": storage_uri}),
            )?
        }
        AssetsCmd::Approve {
            id,
            project,
            purpose,
        } => c.post(
            &format!("/v1/assets/{id}/approvals"),
            json!({"project": project, "purpose": purpose}),
        )?,
        AssetsCmd::Revoke { id } => c.post(&format!("/v1/assets/{id}/revoke"), Value::Null)?,
        AssetsCmd::Lineage { id } => c.get(&format!("/v1/assets/{id}/lineage"))?,
    });
    Ok(())
}

fn submit(
    c: &ControlClient,
    m: &Model,
    project: &str,
    purpose: &str,
    sources: &[String],
    output: &str,
    key: Option<String>,
) -> Result<Value> {
    let plan = c.post(
        "/v1/plans",
        json!({"project": project, "program": m.program().to_string()}),
    )?;
    let body = json!({"project": project, "plan": plan["id"], "purpose": purpose,
                      "source_assets": sources, "requested_output": output});
    let key = key.unwrap_or_else(|| {
        encompute_verification::service::sha256_hex(
            format!(
                "{project}\0{purpose}\0{}\0{}",
                m.ids().program_id,
                sources.join(",")
            )
            .as_bytes(),
        )[..32]
            .to_owned()
    });
    c.call("POST", "/v1/jobs", body, &[("Idempotency-Key", &key)])
}

pub fn jobs(cmd: JobsCmd, load: impl Fn(&Path) -> Result<Model>) -> Result<()> {
    let c = ControlClient::from_env(None)?;
    match cmd {
        JobsCmd::List { project } => print(&c.get(&match project {
            Some(p) => format!("/v1/jobs?project={p}"),
            None => "/v1/jobs".into(),
        })?),
        JobsCmd::Status { id } => print(&c.get(&format!("/v1/jobs/{id}"))?),
        JobsCmd::Cancel { id } => print(&c.post(&format!("/v1/jobs/{id}/cancel"), Value::Null)?),
        JobsCmd::Submit {
            model,
            project,
            purpose,
            sources,
            output,
            idempotency_key,
        } => {
            let m = load(&model)?;
            print(&submit(
                &c,
                &m,
                &project,
                &purpose,
                &sources,
                &output,
                idempotency_key,
            )?)
        }
        JobsCmd::Run {
            model,
            project,
            purpose,
            sources,
            inputs,
            keys,
            idempotency_key,
        } => {
            let m = load(&model)?;
            let inputs = crate::parse_inputs(&inputs, None)?;
            let job = submit(&c, &m, &project, &purpose, &sources, "out", idempotency_key)?;
            let id = job["id"].as_str().unwrap_or_default().to_owned();
            eprintln!("job {id}: {}", job["state"].as_str().unwrap_or("?"));
            // Wait for a compatible evaluator.
            let mut v = job;
            for _ in 0..120 {
                if v["state"] != "authorized" && v["state"] != "waiting_for_approval" {
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
                v = c.get(&format!("/v1/jobs/{id}"))?;
            }
            if v["state"] != "queued" {
                return Err(Error::new(
                    Code::Scheduling,
                    format!("job {id} is {}, not scheduled", v["state"]),
                ));
            }
            let grant: JobGrant = serde_json::from_value(v["grant"].clone())
                .map_err(|e| Error::new(Code::Remote, format!("job grant: {e}")))?;
            let url = v["evaluator_url"].as_str().unwrap_or_default().to_owned();
            let receipt_key = v["evaluator_receipt_key"].as_str().unwrap_or_default();
            // Trust the receipt key the evaluator registered with the control plane.
            let trusted = EvaluatorIdentity::from_public_key_hex(receipt_key)?;
            eprintln!("scheduled on {} ({url})", grant.evaluator);
            let read = |f: &str| {
                std::fs::read(keys.join(f)).map_err(|e| {
                    Error::new(Code::WrongKey, format!("{}: {e}", keys.join(f).display()))
                })
            };
            let mut client = ClientSession::restore(m.ids(), m.compiled(), &read("secret.key")?)?;
            let eval_keys = read("eval.keys").ok();
            if let Some(k) = &eval_keys {
                client.attach_evaluation_keys(k)?;
            }
            let run = Remote::new(&url).with_grant(&grant).run(
                &client,
                m.program(),
                eval_keys.as_deref(),
                &inputs,
                &trusted,
            )?;
            eprintln!("Evaluator receipt       verified (registered key)");
            let done = c.post(
                &format!("/v1/jobs/{id}/complete"),
                json!({"receipt": run.receipt, "request_commitment": request_commitment(&run.request),
                       "output_commitment": output_commitment(&run.response), "key_id": client.key_id()}),
            )?;
            let trust = c.get(&format!("/v1/trust/{id}"))?;
            eprintln!(
                "Job                     {}",
                done["state"].as_str().unwrap_or("?")
            );
            eprintln!(
                "Trust report            {}",
                trust["verdict"].as_str().unwrap_or("?")
            );
            print(&m.outputs_json(&run.outputs));
        }
    }
    Ok(())
}

pub fn trust_report(job: &str, json_out: bool) -> Result<bool> {
    let c = ControlClient::from_env(None)?;
    let r = c.get(&format!("/v1/trust/{job}"))?;
    if json_out {
        print(&r);
    } else {
        println!("Trust report for job {job}");
        for ch in r["checks"].as_array().into_iter().flatten() {
            println!(
                "  {:<22}{:<10}{}",
                ch["check"].as_str().unwrap_or(""),
                ch["status"].as_str().unwrap_or(""),
                ch["detail"].as_str().unwrap_or("")
            );
        }
        println!(
            "  {:<22}{}",
            "execution proof",
            r["execution_proof"].as_str().unwrap_or("")
        );
        println!("{}", r["verdict"].as_str().unwrap_or(""));
    }
    Ok(r["verdict"] == "SATISFIED")
}

pub fn audit_list(organization: Option<&str>, after: u64) -> Result<()> {
    let c = ControlClient::from_env(None)?;
    let mut q = format!("/v1/audit?after={after}");
    if let Some(o) = organization {
        q.push_str(&format!("&organization={o}"));
    }
    for e in c.get(&q)?.as_array().into_iter().flatten() {
        println!(
            "{:>6}  {:<28} {:<10} {:<10} {} {}",
            e["seq"],
            e["action"].as_str().unwrap_or(""),
            e["result"].as_str().unwrap_or(""),
            e["resource_type"].as_str().unwrap_or(""),
            e["resource_id"].as_str().unwrap_or(""),
            e["actor"].as_str().unwrap_or(""),
        );
    }
    Ok(())
}
