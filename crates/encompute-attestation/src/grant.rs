use std::fmt;

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use encompute_ir::{Code, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::EvaluatorIdentity;

use crate::binding::{AttestationChallenge, WorkloadBinding, BINDING_VERSION};
use crate::util::{check_hex, err, hex, tagged, GRANT_INFO, SESSION};

pub const GRANT_VERSION: u32 = 1;

type SessionKem = X25519HkdfSha256;

/// Everything a grant states, authenticated as HPKE associated data: a
/// grant cannot be re-labelled for another asset, session or policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantHeader {
    pub version: u32,
    pub broker_id: String,
    pub asset_id: String,
    pub key_version: u64,
    #[serde(default)]
    pub policy_id: Option<String>,
    pub execution_spec_id: String,
    /// The workload session the key is sealed to.
    pub session_id: String,
    /// Hex [`WorkloadBinding::hash`] of the attestation that authorized it.
    pub binding_hash: String,
    /// Digest of the attestation evidence.
    pub attestation_digest: String,
    pub expires_at: u64,
}

/// An asset key sealed (HPKE base mode, X25519-HKDF-SHA256,
/// ChaCha20-Poly1305) to an attested session key. Carries no key material
/// in the clear.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedKeyGrant {
    pub header: GrantHeader,
    /// HPKE encapsulated key, hex.
    pub encapsulated_key: String,
    /// Sealed asset key, hex.
    pub ciphertext: String,
}

/// Seals `key` to the session key in `binding` (the broker side).
pub fn seal_grant(
    header: GrantHeader,
    binding: &WorkloadBinding,
    key: &[u8],
) -> Result<EncryptedKeyGrant> {
    let pk_bytes = check_hex(
        Code::KeyRelease,
        "session key",
        &binding.session_public_key,
        32,
    )?;
    let pk = <SessionKem as Kem>::PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| err(Code::KeyRelease, format!("session key: {e}")))?;
    let aad = canonical_json(&header)?;
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, SessionKem>(
        &OpModeS::Base,
        &pk,
        GRANT_INFO,
        key,
        &aad,
    )
    .map_err(|e| err(Code::KeyRelease, format!("sealing the key grant: {e}")))?;
    Ok(EncryptedKeyGrant {
        header,
        encapsulated_key: hex(&enc.to_bytes()),
        ciphertext: hex(&ct),
    })
}

/// A workload session: the evaluator's identity plus an ephemeral HPKE key
/// pair generated inside the TEE. The private key never leaves it.
pub struct WorkloadSession {
    evaluator_public_key: [u8; 32],
    secret: <SessionKem as Kem>::PrivateKey,
    public: <SessionKem as Kem>::PublicKey,
}

impl WorkloadSession {
    pub fn new(evaluator: &EvaluatorIdentity) -> Self {
        let (secret, public) = SessionKem::gen_keypair();
        Self {
            evaluator_public_key: evaluator.public_key(),
            secret,
            public,
        }
    }

    pub fn session_public_key_hex(&self) -> String {
        hex(&self.public.to_bytes())
    }

    /// `SHA256("encompute.workload-session.v1" || 0x00 || evaluator key ||
    /// session key)`, hex: stable across the brokers a session talks to.
    pub fn session_id(&self) -> String {
        session_id(&self.evaluator_public_key, &self.public.to_bytes())
    }

    /// The session ID a binding names.
    pub fn session_id_of(binding: &WorkloadBinding) -> Result<String> {
        let c = Code::Attestation;
        let e = check_hex(c, "evaluator key", &binding.evaluator_public_key, 32)?;
        let s = check_hex(c, "session key", &binding.session_public_key, 32)?;
        Ok(session_id(&e, &s))
    }

    /// The binding for `challenge` and the given execution identity.
    pub fn binding(
        &self,
        challenge: &AttestationChallenge,
        execution_spec_id: &str,
        policy_id: Option<&str>,
        artifact_digest: &str,
    ) -> WorkloadBinding {
        WorkloadBinding {
            version: BINDING_VERSION,
            execution_spec_id: execution_spec_id.to_owned(),
            policy_id: policy_id.map(str::to_owned),
            artifact_digest: artifact_digest.to_owned(),
            evaluator_public_key: hex(&self.evaluator_public_key),
            session_public_key: self.session_public_key_hex(),
            challenge_nonce: challenge.nonce.clone(),
        }
    }

    /// Opens a grant sealed to this session.
    pub fn open(&self, grant: &EncryptedKeyGrant) -> Result<Zeroizing<Vec<u8>>> {
        if grant.header.session_id != self.session_id() {
            return Err(err(
                Code::KeyRelease,
                "the key grant is for another session",
            ));
        }
        let c = Code::KeyRelease;
        let enc = check_hex(c, "encapsulated key", &grant.encapsulated_key, 32)?;
        let ct = crate::util::unhex(&grant.ciphertext)
            .ok_or_else(|| err(c, "grant ciphertext is not hex"))?;
        let enc = <SessionKem as Kem>::EncappedKey::from_bytes(&enc)
            .map_err(|e| err(c, format!("encapsulated key: {e}")))?;
        let aad = canonical_json(&grant.header)?;
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, SessionKem>(
            &OpModeR::Base,
            &self.secret,
            &enc,
            GRANT_INFO,
            &ct,
            &aad,
        )
        .map(Zeroizing::new)
        .map_err(|_| err(c, "the key grant does not open under this session"))
    }
}

fn session_id(evaluator: &[u8], session: &[u8]) -> String {
    let mut b = evaluator.to_vec();
    b.extend_from_slice(session);
    hex(&tagged(SESSION, &b))
}

impl fmt::Debug for WorkloadSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WorkloadSession({})", self.session_id())
    }
}
