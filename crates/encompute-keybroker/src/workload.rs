use std::collections::BTreeMap;

use zeroize::Zeroizing;

use encompute_attestation::{
    AttestationRecord, Attester, GrantHeader, KeyReleaseReceipt, WorkloadSession,
    GRANT_VERSION_GOVERNED,
};
use encompute_ir::{Code, Error, Result};
use encompute_verification::ticket::ReleaseTicket;

use crate::{BrokerClient, GovernedReleaseRequest};

/// A key opened inside the workload session.
pub struct AcquiredKey {
    pub asset_id: String,
    pub header: GrantHeader,
    pub key: Zeroizing<Vec<u8>>,
    /// The attestation that authorized it.
    pub record: AttestationRecord,
    /// A governed release's receipt, signed by the broker's grant key
    /// (checked against the grant).
    pub receipt: Option<KeyReleaseReceipt>,
}

/// One governed key request: the broker, the asset, the owner's
/// authorization the release is under, and the control plane's ticket
/// (absent only against a development broker that does not require one).
#[derive(Clone, Debug)]
pub struct GovernedKeyRequest {
    pub broker: BrokerClient,
    pub asset_id: String,
    pub authorization_id: String,
    pub ticket: Option<ReleaseTicket>,
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
///
/// With a per-asset broker binding ([`BrokerClient::trusting_per_asset`]),
/// a key's grant must also name the broker the binding gives for that key,
/// and be signed by that broker's pinned key: one owner's broker cannot
/// grant a key for another owner's asset, and a key the binding leaves out
/// is refused before it is asked for.
pub fn acquire_keys(
    attester: &dyn Attester,
    session: &WorkloadSession,
    execution_spec_id: &str,
    policy_id: Option<&str>,
    artifact_digest: &str,
    requests: &[(BrokerClient, String)],
) -> Result<Vec<AcquiredKey>> {
    let requests: Vec<(&BrokerClient, &str, Option<Governed>)> = requests
        .iter()
        .map(|(b, a)| (b, a.as_str(), None))
        .collect();
    acquire(
        attester,
        session,
        execution_spec_id,
        policy_id,
        artifact_digest,
        &requests,
    )
}

/// [`acquire_keys`] in a governed project: each key is asked for under the
/// owner's authorization, with the control plane's ticket. Besides the
/// checks there, each grant must be version 3 and name that authorization
/// and ticket, and come with a key-release receipt signed by the same
/// broker key over that grant.
pub fn acquire_keys_governed(
    attester: &dyn Attester,
    session: &WorkloadSession,
    execution_spec_id: &str,
    policy_id: Option<&str>,
    artifact_digest: &str,
    requests: &[GovernedKeyRequest],
) -> Result<Vec<AcquiredKey>> {
    let requests: Vec<(&BrokerClient, &str, Option<Governed>)> = requests
        .iter()
        .map(|r| {
            (
                &r.broker,
                r.asset_id.as_str(),
                Some(Governed {
                    authorization_id: &r.authorization_id,
                    ticket: r.ticket.as_ref(),
                }),
            )
        })
        .collect();
    acquire(
        attester,
        session,
        execution_spec_id,
        policy_id,
        artifact_digest,
        &requests,
    )
}

struct Governed<'a> {
    authorization_id: &'a str,
    ticket: Option<&'a ReleaseTicket>,
}

fn acquire(
    attester: &dyn Attester,
    session: &WorkloadSession,
    execution_spec_id: &str,
    policy_id: Option<&str>,
    artifact_digest: &str,
    requests: &[(&BrokerClient, &str, Option<Governed>)],
) -> Result<Vec<AcquiredKey>> {
    let development = attester.provider() == encompute_attestation::mock::PROVIDER;
    let mut out = Vec::new();
    let mut warned = std::collections::BTreeSet::new();
    // Broker URL -> its session.
    let mut sessions: BTreeMap<String, Opened> = BTreeMap::new();
    for (broker, asset_id, governed) in requests {
        let trusted = broker.trusted_brokers();
        // With a per-asset binding, the broker that must grant this key.
        // A key the binding leaves out is not asked for at all.
        let bound = match broker.asset_brokers() {
            Some(m) => Some(m.get(*asset_id).ok_or_else(|| {
                refuse(format!(
                    "the workload's attested identity binds {asset_id} to no key broker: its key \
                     is not accepted from any"
                ))
            })?),
            None => None,
        };
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
        let (grant, receipt) = match governed {
            None => (broker.release(&opened.session, asset_id)?, None),
            Some(g) => {
                let r = broker.release_governed(&GovernedReleaseRequest {
                    session: opened.session.clone(),
                    asset_id: asset_id.to_string(),
                    authorization_id: g.authorization_id.to_owned(),
                    ticket: g.ticket.cloned(),
                    execution_spec: None,
                    binding: None,
                })?;
                check_governed(&r.grant.header, &r.receipt, g)?;
                r.receipt.verify(&r.grant.header.broker_public_key)?;
                if r.receipt.grant_digest != r.grant.digest()? {
                    return Err(refuse("the key-release receipt is for another grant"));
                }
                (r.grant, Some(r.receipt))
            }
        };
        // The grant is signed (checked when it is opened); only a pin says
        // the signer is the intended broker.
        let signer = &grant.header.broker_public_key;
        // The binding is checked before the signer: a genuine grant from
        // another owner's broker (for a key it should not hold) and a grant
        // naming the bound broker but signed by another are both refused.
        if let Some(b) = bound {
            if grant.header.broker_id != *b {
                return Err(refuse(format!(
                    "the key grant for {asset_id} comes from key broker {}, but the workload's \
                     attested identity binds {asset_id} to {b}",
                    grant.header.broker_id
                )));
            }
        }
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
        if grant.header.asset_id != *asset_id || grant.header.execution_spec_id != execution_spec_id
        {
            return Err(refuse("the broker granted a different asset or execution"));
        }
        let key = session.open(&grant)?;
        out.push(AcquiredKey {
            asset_id: asset_id.to_string(),
            header: grant.header,
            key,
            record: opened.record.clone(),
            receipt,
        });
    }
    Ok(out)
}

/// A governed grant names the authorization and ticket it was asked for.
fn check_governed(header: &GrantHeader, receipt: &KeyReleaseReceipt, g: &Governed) -> Result<()> {
    let gov = header
        .governance
        .as_ref()
        .filter(|_| header.version == GRANT_VERSION_GOVERNED)
        .ok_or_else(|| refuse("the broker returned an ungoverned key grant"))?;
    let ticket_id = g.ticket.map(|t| t.ticket_id.as_str());
    if gov.authorization_id != g.authorization_id || gov.ticket_id.as_deref() != ticket_id {
        return Err(refuse(
            "the key grant names another authorization or ticket than requested",
        ));
    }
    if receipt.authorization_id != g.authorization_id
        || receipt.ticket_id.as_deref() != ticket_id
        || receipt.asset_id != header.asset_id
        || receipt.session_id != header.session_id
    {
        return Err(refuse(
            "the key-release receipt does not match the key grant",
        ));
    }
    Ok(())
}
