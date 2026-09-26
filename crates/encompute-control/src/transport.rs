//! Asynchronous messages between services.
//!
//! The transport is **not trusted** for confidentiality or correctness: it
//! may duplicate, delay, reorder, drop or replay messages. Security holds
//! regardless:
//!
//! - every message is signed by its sender's service key and names its
//!   recipient, organization, project, job and round where relevant;
//! - it expires;
//! - its payload is bound by digest;
//! - consumers apply each message ID once (the `inbox` table, in the same
//!   transaction as the message's effect), so a duplicate never counts
//!   twice.
//!
//! Large immutable data (ciphertexts, evaluation keys, models) never travels
//! in messages: a payload names an artifact URI and its digest.
//!
//! Implementations: [`HttpTransport`] (POST to the recipient's
//! `/v1/messages`) and [`InMemoryTransport`] (tests; can inject faults).
//! A broker adapter (e.g. a queue) implements the same trait.

use std::collections::BTreeMap;
use std::sync::Mutex;

use encompute_ir::{Code, Error, Result};
use encompute_verification::ServiceSigner;

use crate::model::MessageEnvelope;

pub use encompute_verification::service::{open, seal, Scope, MAX_PAYLOAD_BYTES};

pub trait MessageTransport: Send + Sync {
    /// Delivers `m` to the service at `url` (at least once is fine).
    fn send(&self, url: &str, m: &MessageEnvelope) -> Result<()>;
}

/// POSTs messages to `{url}/v1/messages`, as a signed service request.
pub struct HttpTransport {
    signer: ServiceSigner,
    agent: ureq::Agent,
}

impl HttpTransport {
    pub fn new(signer: ServiceSigner) -> Self {
        Self {
            signer,
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(30))
                .build(),
        }
    }
}

impl MessageTransport for HttpTransport {
    fn send(&self, url: &str, m: &MessageEnvelope) -> Result<()> {
        let body = serde_json::to_vec(m).expect("serializable");
        let mut bind = BTreeMap::new();
        bind.insert("message".to_owned(), m.message_id.clone());
        let h = self
            .signer
            .sign_request("POST", "/v1/messages", &m.recipient, &bind, &body)?;
        let mut r = self
            .agent
            .post(&format!("{}/v1/messages", url.trim_end_matches('/')))
            .set("Content-Type", "application/json");
        for (k, v) in h.to_pairs() {
            r = r.set(k, &v);
        }
        match r.send_bytes(&body) {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(code, resp)) => Err(Error::new(
                Code::Remote,
                format!(
                    "{url} refused message {} ({code}): {}",
                    m.message_id,
                    resp.into_string().unwrap_or_default()
                ),
            )),
            Err(e) => Err(Error::new(Code::Remote, format!("{url}: {e}"))),
        }
    }
}

/// Faults an [`InMemoryTransport`] injects: the behaviors a real broker
/// may show.
#[derive(Clone, Copy, Debug, Default)]
pub struct Faults {
    /// Deliver every message twice.
    pub duplicate: bool,
    /// Deliver in reverse order.
    pub reorder: bool,
    /// Drop every n-th message (0: none).
    pub drop_every: usize,
}

/// Queues messages in memory; [`InMemoryTransport::drain`] hands them out.
#[derive(Default)]
pub struct InMemoryTransport {
    queue: Mutex<Vec<(String, MessageEnvelope)>>,
    faults: Faults,
    sent: Mutex<usize>,
}

impl InMemoryTransport {
    pub fn with_faults(faults: Faults) -> Self {
        Self {
            faults,
            ..Self::default()
        }
    }

    /// Everything queued, with the configured faults applied.
    pub fn drain(&self) -> Vec<(String, MessageEnvelope)> {
        let mut q: Vec<_> =
            std::mem::take(&mut *self.queue.lock().unwrap_or_else(|p| p.into_inner()));
        if self.faults.duplicate {
            q = q.into_iter().flat_map(|m| [m.clone(), m]).collect();
        }
        if self.faults.reorder {
            q.reverse();
        }
        q
    }
}

impl MessageTransport for InMemoryTransport {
    fn send(&self, url: &str, m: &MessageEnvelope) -> Result<()> {
        let mut n = self.sent.lock().unwrap_or_else(|p| p.into_inner());
        *n += 1;
        if self.faults.drop_every > 0 && (*n).is_multiple_of(self.faults.drop_every) {
            return Ok(()); // lost in transit
        }
        self.queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((url.into(), m.clone()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encompute_verification::canonical::canonical_json;
    use encompute_verification::service::sha256_hex;

    #[test]
    fn messages_are_bound_signed_and_expire() {
        let s = ServiceSigner::from_seed("evaluator-1", &[1; 32]).unwrap();
        let pk = s.public_key_hex();
        let m = seal(
            &s,
            "job.completed",
            "control-plane",
            Scope {
                job: Some("job_1".into()),
                ..Scope::default()
            },
            &serde_json::json!({"receipt": "…"}),
            60,
        )
        .unwrap();
        let t = m.created_at;
        open(&m, &pk, "control-plane", t).unwrap();
        let refused = |m: &MessageEnvelope, me: &str, now: u64| {
            assert_eq!(
                open(m, &pk, me, now).unwrap_err().code,
                Code::ServiceAuthentication
            )
        };
        refused(&m, "keybroker-a", t);
        refused(&m, "control-plane", t + 61);
        let mut x = m.clone();
        x.job = Some("job_2".into());
        refused(&x, "control-plane", t);
        let mut x = m.clone();
        x.payload = serde_json::json!({"receipt": "forged"});
        refused(&x, "control-plane", t);
        let mut x = m.clone();
        x.payload_digest = sha256_hex(&canonical_json(&x.payload).unwrap());
        x.payload = serde_json::json!({"receipt": "forged"});
        refused(&x, "control-plane", t);
        let big = "x".repeat(MAX_PAYLOAD_BYTES + 1);
        assert!(seal(&s, "k", "control-plane", Scope::default(), &big, 60).is_err());
    }

    #[test]
    fn in_memory_faults() {
        let s = ServiceSigner::from_seed("secagg-1", &[2; 32]).unwrap();
        let t = InMemoryTransport::with_faults(Faults {
            duplicate: true,
            reorder: true,
            drop_every: 3,
        });
        for i in 0..6 {
            let m = seal(&s, "k", "control-plane", Scope::default(), &i, 60).unwrap();
            t.send("http://c", &m).unwrap();
        }
        let got = t.drain();
        assert_eq!(got.len(), 8, "4 delivered, each twice");
        assert_eq!(got[0].1.payload, serde_json::json!(4));
    }
}
