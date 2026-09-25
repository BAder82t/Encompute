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

/// The workload side: for each `(broker, asset)`, fetch a challenge, attest
/// the binding, open a session and receive and open the grant. Fails on the
/// first refusal.
pub fn acquire_keys(
    attester: &dyn Attester,
    session: &WorkloadSession,
    execution_spec_id: &str,
    policy_id: Option<&str>,
    artifact_digest: &str,
    requests: &[(BrokerClient, String)],
) -> Result<Vec<AcquiredKey>> {
    let mut out = Vec::new();
    for (broker, asset_id) in requests {
        let challenge = broker.challenge()?;
        let binding = session.binding(&challenge, execution_spec_id, policy_id, artifact_digest);
        let evidence = attester.attest(&challenge, &binding)?;
        let info = broker.attest(&evidence)?;
        if info.workload_session_id != session.session_id() {
            return Err(Error::new(
                Code::KeyRelease,
                "the broker opened a session for another workload",
            ));
        }
        let grant = broker.release(&info.session, asset_id)?;
        if &grant.header.asset_id != asset_id || grant.header.execution_spec_id != execution_spec_id
        {
            return Err(Error::new(
                Code::KeyRelease,
                "the broker granted a different asset or execution",
            ));
        }
        let key = session.open(&grant)?;
        out.push(AcquiredKey {
            asset_id: asset_id.clone(),
            header: grant.header,
            key,
            record: AttestationRecord::new(evidence),
        });
    }
    Ok(out)
}
