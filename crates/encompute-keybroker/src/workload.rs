use std::collections::BTreeMap;

use zeroize::Zeroizing;

use encompute_attestation::{AttestationRecord, Attester, GrantHeader, WorkloadSession};
use encompute_ir::{Code, Error, Result};

use crate::BrokerClient;

/// A key opened inside the workload session.
pub struct AcquiredKey {
    pub asset_id: String,
    pub header: GrantHeader,
    pub key: Zeroizing<Vec<u8>>,
    /// The attestation that authorized it.
    pub record: AttestationRecord,
}

impl std::fmt::Debug for AcquiredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AcquiredKey({} v{})",
            self.asset_id, self.header.key_version
        )
    }
}

fn refuse(m: impl Into<String>) -> Error {
    Error::new(Code::KeyRelease, m)
}

/// One broker session: its ID, the evidence that opened it, and the key
/// that signed its first grant.
struct Opened {
    session: String,
    record: AttestationRecord,
    signer: Option<String>,
}

/// The workload side: attest once to each broker (a fresh challenge, the
/// binding, a session), then receive and open the grant for each of its
/// `(broker, asset)` requests in that session. Fails on the first refusal.
///
/// A grant is accepted only from the broker key pinned on its
/// [`BrokerClient`]: `URL#KEY`, or the broker keys the workload's attested
/// identity names ([`BrokerClient::trusting`]), which takes the choice
/// away from whoever supplies the broker's address. An unpinned broker is
/// accepted only with the development (mock) attester, which gives no
/// hardware confidentiality anyway: with real hardware, whoever names the
/// broker could otherwise seal a key of its choosing to the session
/// (review finding KB-1). Every grant of one broker session must come from
/// one signer.
pub fn acquire_keys(
    attester: &dyn Attester,
    session: &WorkloadSession,
    execution_spec_id: &str,
    policy_id: Option<&str>,
    artifact_digest: &str,
    requests: &[(BrokerClient, String)],
) -> Result<Vec<AcquiredKey>> {
    let development = attester.provider() == encompute_attestation::mock::PROVIDER;
    let mut out = Vec::new();
    let mut warned = std::collections::BTreeSet::new();
    // Broker URL -> its session.
    let mut sessions: BTreeMap<String, Opened> = BTreeMap::new();
    for (broker, asset_id) in requests {
        let trusted = broker.trusted_brokers();
        if trusted.is_none() && broker.pinned_key().is_none() && !development {
            return Err(refuse(format!(
                "broker {} is not pinned: with a hardware attester, a grant is accepted only \
                 from a pinned broker key (URL#KEY)",
                broker.url()
            )));
        }
        if !sessions.contains_key(broker.url()) {
            let challenge = broker.challenge()?;
            let binding =
                session.binding(&challenge, execution_spec_id, policy_id, artifact_digest);
            let evidence = attester.attest(&challenge, &binding)?;
            let info = broker.attest(&evidence)?;
            if info.workload_session_id != session.session_id() {
                return Err(refuse("the broker opened a session for another workload"));
            }
            sessions.insert(
                broker.url().to_owned(),
                Opened {
                    session: info.session,
                    record: AttestationRecord::new(evidence),
                    signer: None,
                },
            );
        }
        let opened = sessions.get_mut(broker.url()).expect("opened above");
        let grant = broker.release(&opened.session, asset_id)?;
        // The grant is signed (checked when it is opened); only a pin says
        // the signer is the intended broker.
        let signer = &grant.header.broker_public_key;
        if let Some(t) = trusted {
            if t.get(&grant.header.broker_id) != Some(signer) {
                return Err(refuse(format!(
                    "the key grant for {asset_id} from {} is not signed by a broker key the \
                     workload's attested identity names",
                    broker.url()
                )));
            }
        }
        match broker.pinned_key() {
            Some(k) if signer != k => {
                return Err(refuse(format!(
                    "the key grant from {} is not signed by the pinned broker key",
                    broker.url()
                )));
            }
            Some(_) => {}
            None if trusted.is_none() && !warned.contains(broker.url()) => {
                warned.insert(broker.url().to_owned());
                eprintln!(
                    "warning: broker {} is not pinned (development attestation only): a grant \
                     is checked only against the key it names (pin it with URL#{})",
                    broker.url(),
                    signer
                );
            }
            None => {}
        }
        // One signer per broker session: grants from several signers
        // cannot be mixed behind one address.
        match &opened.signer {
            Some(first) if first != signer => {
                return Err(refuse(format!(
                    "the key grants from {} are signed by more than one broker key",
                    broker.url()
                )));
            }
            Some(_) => {}
            None => opened.signer = Some(signer.clone()),
        }
        if &grant.header.asset_id != asset_id || grant.header.execution_spec_id != execution_spec_id
        {
            return Err(refuse("the broker granted a different asset or execution"));
        }
        let key = session.open(&grant)?;
        out.push(AcquiredKey {
            asset_id: asset_id.clone(),
            header: grant.header,
            key,
            record: opened.record.clone(),
        });
    }
    Ok(out)
}
