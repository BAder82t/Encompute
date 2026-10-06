//! HTTP client for a remote `encompute-evaluator`.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use encompute_ir::{Code, Error, Program, Result};
use encompute_verification::{
    EvaluatorIdentity, ExecutionProof, SignedExecutionReceipt, UploadGrant, UploadKind,
    VerificationState,
};
use serde_json::Value;

use crate::client::ClientSession;

/// Result of a verified remote run.
pub struct RemoteRun {
    pub outputs: encompute_ir::Outputs,
    pub stats: RemoteStats,
    /// The evaluator's signed receipt, verified before decryption.
    pub receipt: SignedExecutionReceipt,
    /// The verified receipt.
    pub verified: encompute_verification::VerifiedReceipt,
    /// How far the result was verified before decryption.
    pub state: VerificationState,
    /// The execution proof, for programs requiring verified execution.
    pub proof: Option<ExecutionProof>,
    /// The exact envelopes exchanged (for `encompute verify`).
    pub request: Vec<u8>,
    pub response: Vec<u8>,
}

/// Where a client gets the upload grants an evaluator managed by a control
/// plane asks for: the control plane, as the job's initiator.
pub trait UploadGrantSource: Send + Sync {
    /// A grant for one upload to the job's evaluator: the job's program, or
    /// (`key_id`) one set of evaluation keys.
    fn upload_grant(&self, kind: UploadKind, key_id: Option<&str>) -> Result<UploadGrant>;
}

pub struct Remote {
    base: String,
    agent: ureq::Agent,
    /// A control plane's job grant, sent with the job (hex of its JSON).
    grant: Option<String>,
    /// Where upload grants come from: an evaluator managed by a control
    /// plane takes a program or keys only with one, and one upload each.
    uploads: Option<Arc<dyn UploadGrantSource>>,
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

/// Largest JSON response read from an evaluator (the evaluator is not
/// trusted to keep them small).
const MAX_JSON: u64 = 16 << 20;

fn read_json(resp: ureq::Response) -> Result<Value> {
    let mut body = Vec::new();
    resp.into_reader()
        .take(MAX_JSON + 1)
        .read_to_end(&mut body)
        .map_err(|e| Error::new(Code::Remote, format!("reading response: {e}")))?;
    if body.len() as u64 > MAX_JSON {
        return Err(Error::new(Code::Remote, "evaluator response is too large"));
    }
    serde_json::from_slice(&body)
        .map_err(|e| Error::new(Code::Remote, format!("bad response: {e}")))
}

fn remote_err(e: ureq::Error) -> Error {
    match e {
        ureq::Error::Status(status, resp) => {
            let body: Value = read_json(resp).unwrap_or(Value::Null);
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
            grant: None,
            uploads: None,
        }
    }

    /// Asks `source` (the control plane) for an upload grant before each
    /// program and key upload.
    pub fn with_upload_grants(mut self, source: Arc<dyn UploadGrantSource>) -> Self {
        self.uploads = Some(source);
        self
    }

    /// The header of a fresh upload grant, or none without a source.
    fn upload_header(&self, kind: UploadKind, key_id: Option<&str>) -> Result<Option<String>> {
        self.uploads
            .as_ref()
            .map(|s| s.upload_grant(kind, key_id).map(|g| g.to_header()))
            .transpose()
    }

    /// Sends `grant` with the job: evaluators managed by a control plane run
    /// granted jobs only.
    pub fn with_grant(mut self, grant: &encompute_verification::JobGrant) -> Self {
        self.grant = Some(grant.to_header());
        self
    }

    /// The evaluator's base URL.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// A GET, carrying an upload grant if there is one: an evaluator managed
    /// by a control plane lists a program and answers key lookups only for
    /// a holder of an upload grant for it.
    fn get(&self, path: &str, upload: Option<&str>) -> ureq::Request {
        let r = self.agent.get(&self.url(path));
        match upload {
            Some(g) => r.set(encompute_verification::service::H_UPLOAD_GRANT, g),
            None => r,
        }
    }

    /// `/v1/info`, as seen by a holder of `upload` (a control-plane
    /// evaluator lists only the program such a grant names).
    fn info_with(&self, upload: Option<&str>) -> Result<Value> {
        self.get("/v1/info", upload)
            .call()
            .map_err(remote_err)
            .and_then(read_json)
    }

    pub fn info(&self) -> Result<Value> {
        self.info_with(None)
    }

    /// The identity the evaluator claims (from `/v1/info`). Trust it only by
    /// pinning (or comparing with a known ID): anyone can claim a key.
    pub fn evaluator_identity(&self) -> Result<EvaluatorIdentity> {
        let info = self.info()?;
        let key = info["evaluator"]["public_key"]
            .as_str()
            .ok_or_else(|| Error::new(Code::Remote, "evaluator announces no identity"))?;
        EvaluatorIdentity::from_public_key_hex(key)
    }

    /// An upload carries its upload grant: an evaluator managed by a control
    /// plane accepts programs and keys only with one, once.
    fn post(&self, path: &str, body: &[u8], upload: Option<&str>) -> Result<Value> {
        let mut r = self
            .agent
            .post(&self.url(path))
            .set("Content-Type", "application/octet-stream");
        if let Some(g) = upload {
            r = r.set(encompute_verification::service::H_UPLOAD_GRANT, g);
        }
        r.send_bytes(body).map_err(remote_err).and_then(read_json)
    }

    /// Upload the program if the evaluator does not have it.
    pub fn ensure_program(&self, program: &Program, program_id: &str) -> Result<()> {
        // One grant: it lets the evaluator list the program, and admits one
        // upload of it.
        let grant = self.upload_header(UploadKind::Program, None)?;
        let info = self.info_with(grant.as_deref())?;
        let loaded = info["programs"]
            .as_array()
            .is_some_and(|ps| ps.iter().any(|p| p["program_id"] == program_id));
        if loaded {
            return Ok(());
        }
        let got = self.post(
            "/v1/programs",
            program.to_string().as_bytes(),
            grant.as_deref(),
        )?;
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
        let grant = self.upload_header(UploadKind::Keys, Some(key_id))?;
        match self
            .get(
                &format!("/v1/programs/{program_id}/keys/{key_id}"),
                grant.as_deref(),
            )
            .call()
        {
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
        let got = self.post(
            &format!("/v1/programs/{program_id}/keys"),
            keys,
            grant.as_deref(),
        )?;
        if got["key_id"] != key_id {
            return Err(Error::new(
                Code::WrongKey,
                "the evaluator registered a different key ID",
            ));
        }
        Ok(keys.len())
    }

    /// Submit an inputs envelope and fetch the outputs envelope; the job
    /// JSON carries timings and the signed receipt.
    pub fn execute(&self, program_id: &str, request: &[u8]) -> Result<(Vec<u8>, Value)> {
        let mut r = self
            .agent
            .post(&self.url(&format!("/v1/programs/{program_id}/jobs")))
            .set("Content-Type", "application/octet-stream");
        if let Some(g) = &self.grant {
            r = r.set(encompute_verification::service::H_JOB_GRANT, g);
        }
        let job = r
            .send_bytes(request)
            .map_err(remote_err)
            .and_then(read_json)?;
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
        Ok((out, job))
    }

    /// The evaluator receipt keys to accept for a job a control plane
    /// schedules: `explicit` pins (command-line or SDK arguments), else
    /// `ENCOMPUTE_TRUSTED_EVALUATORS` (comma- or space-separated hex keys;
    /// set but empty pins nothing and refuses every evaluator). `None`
    /// accepts the key the control plane names, and is returned only with
    /// the explicit development opt-out (`allow_unpinned`, or
    /// `ENCOMPUTE_ALLOW_UNPINNED_EVALUATOR=1`), and only when
    /// `ENCOMPUTE_ENV=development` is set explicitly (unset or any other
    /// value refuses the opt-out). With no pin and no opt-out it fails
    /// closed: a compromised control plane could otherwise choose the
    /// evaluator and the receipt key that "verifies" its result.
    pub fn trusted_evaluators(
        explicit: Option<Vec<String>>,
        allow_unpinned: bool,
    ) -> Result<Option<std::collections::BTreeSet<String>>> {
        Self::trusted_evaluators_from(explicit, allow_unpinned, |k| std::env::var(k).ok())
    }

    /// [`Remote::trusted_evaluators`] with the environment given by `env`.
    pub fn trusted_evaluators_from(
        explicit: Option<Vec<String>>,
        allow_unpinned: bool,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<std::collections::BTreeSet<String>>> {
        let parse = |keys: &[String]| -> std::collections::BTreeSet<String> {
            keys.iter()
                .flat_map(|k| k.split(|c: char| c == ',' || c.is_whitespace()))
                .filter(|k| !k.is_empty())
                .map(str::to_lowercase)
                .collect()
        };
        if let Some(keys) = explicit {
            return Ok(Some(parse(&keys)));
        }
        if let Some(v) = env("ENCOMPUTE_TRUSTED_EVALUATORS") {
            return Ok(Some(parse(&[v])));
        }
        let opted_out = allow_unpinned
            || matches!(
                env("ENCOMPUTE_ALLOW_UNPINNED_EVALUATOR").as_deref(),
                Some("1" | "true" | "yes")
            );
        if !opted_out {
            return Err(Error::new(
                Code::InsecureConfiguration,
                "no trusted evaluator keys are pinned: pass --trust-evaluator KEY (or set \
                 ENCOMPUTE_TRUSTED_EVALUATORS) with the receipt keys of the evaluators you \
                 trust; for development only, --allow-unpinned-evaluator accepts the key the \
                 control plane names",
            ));
        }
        // Fails closed: the opt-out holds only where the environment says,
        // explicitly, that this is development. Unset, production or any
        // other value (a typo included) refuses it.
        if env("ENCOMPUTE_ENV").as_deref() != Some("development") {
            return Err(Error::new(
                Code::InsecureConfiguration,
                "an unpinned evaluator is for development only: the opt-out \
                 (--allow-unpinned-evaluator, ENCOMPUTE_ALLOW_UNPINNED_EVALUATOR) is honoured \
                 only with ENCOMPUTE_ENV=development; elsewhere pin the evaluator keys with \
                 --trust-evaluator KEY or ENCOMPUTE_TRUSTED_EVALUATORS",
            ));
        }
        Ok(None)
    }

    /// Refuses `receipt_key` unless it is among `trusted` (`None`: the
    /// development opt-out, any key).
    pub fn check_trusted_evaluator(
        trusted: Option<&std::collections::BTreeSet<String>>,
        receipt_key: &str,
    ) -> Result<()> {
        match trusted {
            Some(keys) if !keys.contains(&receipt_key.to_lowercase()) => Err(Error::new(
                Code::ServiceAuthentication,
                format!(
                    "the control plane scheduled evaluator key {receipt_key}, which is not \
                     among the trusted evaluators"
                ),
            )),
            _ => Ok(()),
        }
    }

    /// [`Remote::run`] for a job a control plane scheduled on the evaluator
    /// with `receipt_key`: the key is checked against `trusted` (see
    /// [`Remote::trusted_evaluators`]) before anything is sent.
    pub fn run_scheduled(
        &self,
        client: &ClientSession,
        program: &Program,
        eval_keys: Option<&[u8]>,
        inputs: &encompute_ir::Inputs,
        receipt_key: &str,
        trusted: Option<&std::collections::BTreeSet<String>>,
    ) -> Result<RemoteRun> {
        Self::check_trusted_evaluator(trusted, receipt_key)?;
        let identity = EvaluatorIdentity::from_public_key_hex(receipt_key)?;
        self.run(client, program, eval_keys, inputs, &identity)
    }

    /// Full remote run: program and keys ensured, encrypted request, then
    /// the receipt verified against `trusted` before the result is
    /// decrypted. A receipt is a signed claim by the evaluator, not a proof
    /// of correct execution.
    pub fn run(
        &self,
        client: &ClientSession,
        program: &Program,
        eval_keys: Option<&[u8]>,
        inputs: &encompute_ir::Inputs,
        trusted: &EvaluatorIdentity,
    ) -> Result<RemoteRun> {
        encompute_evaluator::refuse_aggregation(program)?;
        let t = std::time::Instant::now();
        let ids = client.ids();
        self.ensure_program(program, &ids.program_id)?;
        let uploaded = self.ensure_keys(
            &ids.program_id,
            client.key_id(),
            eval_keys.or(client.evaluation_keys()),
        )?;
        let request = client.encrypt(program, inputs)?;
        let (response, job) = self.execute(&ids.program_id, &request)?;
        let receipt: SignedExecutionReceipt = serde_json::from_value(job["receipt"].clone())
            .map_err(|e| {
                Error::new(
                    Code::Receipt,
                    format!("evaluator sent no valid receipt: {e}"),
                )
            })?;
        let proof = if job["proof"] == true {
            let id = job["job_id"].as_str().unwrap_or_default();
            let resp = self
                .agent
                .get(&self.url(&format!("/v1/jobs/{id}/proof")))
                .call()
                .map_err(remote_err)?;
            let mut bytes = Vec::new();
            resp.into_reader()
                .take(encompute_verification::proof::MAX_PROOF_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| Error::new(Code::Remote, format!("reading proof: {e}")))?;
            Some(ExecutionProof::from_bytes(&bytes)?)
        } else {
            None
        };
        let (outputs, state) =
            client.decrypt_proven(&request, &response, &receipt, proof.as_ref(), trusted)?;
        let verified = client.verify_receipt(&request, &response, &receipt, trusted)?;
        let timings = &job["timings_ms"];
        Ok(RemoteRun {
            outputs,
            stats: RemoteStats {
                request_bytes: request.len(),
                response_bytes: response.len(),
                evaluation_key_bytes_uploaded: uploaded,
                evaluator_ms: timings["evaluate"].as_f64().unwrap_or(0.0),
                evaluator_peak_rss_bytes: timings["peak_rss_bytes"].as_u64().unwrap_or(0),
                round_trip_ms: t.elapsed().as_secs_f64() * 1e3,
            },
            receipt,
            verified,
            state,
            proof,
            request,
            response,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(
        explicit: Option<&[&str]>,
        allow: bool,
        env: &[(&str, &str)],
    ) -> Result<Option<std::collections::BTreeSet<String>>> {
        let env: std::collections::HashMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Remote::trusted_evaluators_from(
            explicit.map(|k| k.iter().map(|s| s.to_string()).collect()),
            allow,
            |k| env.get(k).cloned(),
        )
    }

    /// Review findings EV-4 and PY-1 (ENC-SF-2026-046, ENC-SF-2026-078): pins are the client's, an empty pin
    /// set refuses every key, and without a pin only the explicit
    /// development opt-out, under an explicit `ENCOMPUTE_ENV=development`,
    /// accepts the control plane's choice.
    #[test]
    fn evaluator_pins_fail_closed() {
        let (a, b) = ("AB".repeat(32), "cd".repeat(32));
        let pins = resolve(Some(&[&a]), false, &[("ENCOMPUTE_TRUSTED_EVALUATORS", &b)])
            .unwrap()
            .unwrap();
        assert_eq!(pins.len(), 1, "explicit pins win over the environment");
        assert!(Remote::check_trusted_evaluator(Some(&pins), &a).is_ok());
        let e = Remote::check_trusted_evaluator(Some(&pins), &b).unwrap_err();
        assert_eq!(e.code, Code::ServiceAuthentication);
        let env = resolve(
            None,
            true,
            &[("ENCOMPUTE_TRUSTED_EVALUATORS", &format!("{a}, {b}"))],
        )
        .unwrap()
        .unwrap();
        assert_eq!(env.len(), 2, "a pin in the environment beats the opt-out");
        for empty in [
            resolve(Some(&[]), true, &[]),
            resolve(None, true, &[("ENCOMPUTE_TRUSTED_EVALUATORS", " , ")]),
        ] {
            let empty = empty.unwrap().unwrap();
            assert!(Remote::check_trusted_evaluator(Some(&empty), &a).is_err());
        }
        assert_eq!(
            resolve(None, false, &[]).unwrap_err().code,
            Code::InsecureConfiguration
        );
        let dev = ("ENCOMPUTE_ENV", "development");
        assert_eq!(resolve(None, true, &[dev]).unwrap(), None);
        assert_eq!(
            resolve(
                None,
                false,
                &[("ENCOMPUTE_ALLOW_UNPINNED_EVALUATOR", "1"), dev]
            )
            .unwrap(),
            None
        );
        // The opt-out is honoured only under an explicit
        // ENCOMPUTE_ENV=development: unset, production or anything else
        // (a typo included) fails closed.
        for env in [
            &[][..],
            &[("ENCOMPUTE_ENV", "production")][..],
            &[("ENCOMPUTE_ENV", "prod")][..],
            &[("ENCOMPUTE_ENV", "")][..],
            &[("ENCOMPUTE_ENV", "Development")][..],
            &[("ENCOMPUTE_ALLOW_UNPINNED_EVALUATOR", "1")][..],
        ] {
            let e = resolve(None, true, env).unwrap_err();
            assert_eq!(e.code, Code::InsecureConfiguration, "{env:?}");
            assert!(e.message.contains("ENCOMPUTE_ENV=development"), "{e}");
        }
        assert!(Remote::check_trusted_evaluator(None, &b).is_ok());
    }
}
