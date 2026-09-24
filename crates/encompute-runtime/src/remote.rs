//! HTTP client for a remote `encompute-evaluator` (0.2 plan, D4).

use std::io::Read;
use std::time::Duration;

use encompute_ir::{Code, Error, Program, Result};
use serde_json::Value;

use crate::client::ClientSession;

pub struct Remote {
    base: String,
    agent: ureq::Agent,
}

/// What one remote execution cost.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct RemoteStats {
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub evaluation_key_bytes_uploaded: usize,
    pub evaluator_ms: f64,
    /// Peak resident memory of the evaluator process that ran the job.
    pub evaluator_peak_rss_bytes: u64,
    pub round_trip_ms: f64,
}

fn remote_err(e: ureq::Error) -> Error {
    match e {
        ureq::Error::Status(status, resp) => {
            let body: Value = resp.into_json().unwrap_or(Value::Null);
            let code = body["code"]
                .as_str()
                .and_then(Code::parse)
                .unwrap_or(Code::Remote);
            let msg = body["message"].as_str().unwrap_or("no details");
            Error::new(code, format!("evaluator returned {status}: {msg}"))
        }
        ureq::Error::Transport(t) => {
            Error::new(Code::Remote, format!("cannot reach the evaluator: {t}"))
        }
    }
}

impl Remote {
    pub fn new(base: &str) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(900))
            .timeout_write(Duration::from_secs(900))
            .build();
        Self {
            base: base.trim_end_matches('/').to_owned(),
            agent,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub fn info(&self) -> Result<Value> {
        self.agent
            .get(&self.url("/v1/info"))
            .call()
            .map_err(remote_err)?
            .into_json()
            .map_err(|e| Error::new(Code::Remote, format!("bad info response: {e}")))
    }

    fn post(&self, path: &str, body: &[u8]) -> Result<Value> {
        self.agent
            .post(&self.url(path))
            .set("Content-Type", "application/octet-stream")
            .send_bytes(body)
            .map_err(remote_err)?
            .into_json()
            .map_err(|e| Error::new(Code::Remote, format!("bad response: {e}")))
    }

    /// Upload the program if the evaluator does not have it.
    pub fn ensure_program(&self, program: &Program, program_id: &str) -> Result<()> {
        let info = self.info()?;
        let loaded = info["programs"]
            .as_array()
            .is_some_and(|ps| ps.iter().any(|p| p["program_id"] == program_id));
        if loaded {
            return Ok(());
        }
        let got = self.post("/v1/programs", program.to_string().as_bytes())?;
        if got["program_id"] != program_id {
            return Err(Error::new(
                Code::WrongProgram,
                "the evaluator compiled the program to a different ID",
            ));
        }
        Ok(())
    }

    /// Upload evaluation keys if the evaluator does not have them. Returns
    /// the bytes uploaded.
    pub fn ensure_keys(
        &self,
        program_id: &str,
        key_id: &str,
        keys: Option<&[u8]>,
    ) -> Result<usize> {
        let url = self.url(&format!("/v1/programs/{program_id}/keys/{key_id}"));
        match self.agent.get(&url).call() {
            Ok(_) => return Ok(0),
            Err(ureq::Error::Status(404, _)) => {}
            Err(e) => return Err(remote_err(e)),
        }
        let keys = keys.ok_or_else(|| {
            Error::new(
                Code::WrongKey,
                "the evaluator lacks this client's evaluation keys; provide eval.keys",
            )
        })?;
        let got = self.post(&format!("/v1/programs/{program_id}/keys"), keys)?;
        if got["key_id"] != key_id {
            return Err(Error::new(
                Code::WrongKey,
                "the evaluator registered a different key ID",
            ));
        }
        Ok(keys.len())
    }

    /// Submit an inputs envelope and fetch the outputs envelope.
    pub fn execute(&self, program_id: &str, request: &[u8]) -> Result<(Vec<u8>, Value)> {
        let job = self.post(&format!("/v1/programs/{program_id}/jobs"), request)?;
        let id = job["job_id"]
            .as_str()
            .ok_or_else(|| Error::new(Code::Remote, "no job ID in response"))?;
        let resp = self
            .agent
            .get(&self.url(&format!("/v1/jobs/{id}/result")))
            .call()
            .map_err(remote_err)?;
        let mut out = Vec::new();
        resp.into_reader()
            .take(1 << 30)
            .read_to_end(&mut out)
            .map_err(|e| Error::new(Code::Remote, format!("reading result: {e}")))?;
        Ok((out, job["timings_ms"].clone()))
    }

    /// Full remote run: program and keys ensured, encrypted request, decrypted result.
    pub fn run(
        &self,
        client: &ClientSession,
        program: &Program,
        eval_keys: Option<&[u8]>,
        inputs: &encompute_ir::Inputs,
    ) -> Result<(encompute_ir::Outputs, RemoteStats)> {
        let t = std::time::Instant::now();
        let ids = client.ids();
        self.ensure_program(program, &ids.program_id)?;
        let uploaded = self.ensure_keys(
            &ids.program_id,
            client.key_id(),
            eval_keys.or(client.evaluation_keys()),
        )?;
        let request = client.encrypt(program, inputs)?;
        let (response, timings) = self.execute(&ids.program_id, &request)?;
        let outputs = client.decrypt(&response)?;
        Ok((
            outputs,
            RemoteStats {
                request_bytes: request.len(),
                response_bytes: response.len(),
                evaluation_key_bytes_uploaded: uploaded,
                evaluator_ms: timings["evaluate"].as_f64().unwrap_or(0.0),
                evaluator_peak_rss_bytes: timings["peak_rss_bytes"].as_u64().unwrap_or(0),
                round_trip_ms: t.elapsed().as_secs_f64() * 1e3,
            },
        ))
    }
}
