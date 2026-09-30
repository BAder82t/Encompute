use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
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

/// Version 2: grants are signed by the broker (version 1 grants were not,
/// and are refused).
pub const GRANT_VERSION: u32 = 2;
/// Version 3: a governed release ([`GrantHeader::governance`]), signed
/// under its own domain. Version 2 grants are unchanged.
pub const GRANT_VERSION_GOVERNED: u32 = 3;

/// Domain of the broker's signature over a version 2 grant.
const GRANT_SIGNATURE: &str = "encompute.key-grant-signature.v2";
/// Domain of the broker's signature over a version 3 (governed) grant.
const GRANT_SIGNATURE_GOVERNED: &str = "encompute.key-grant-signature.v3";

/// The broker's grant-signing key (Ed25519). HPKE base mode does not
/// authenticate the sender: without this signature anyone on the path
/// could seal a key of their choosing to the session.
pub struct GrantSigner(SigningKey);

impl GrantSigner {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    pub fn generate() -> Result<Self> {
        let seed = Zeroizing::new(crate::util::random32(Code::KeyRelease)?);
        Ok(Self::from_seed(&seed))
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// Hex Ed25519 public key: what workloads pin.
    pub fn public_key_hex(&self) -> String {
        hex(self.0.verifying_key().as_bytes())
    }
}

impl fmt::Debug for GrantSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GrantSigner({})", self.public_key_hex())
    }
}

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
    /// Hex Ed25519 key of the broker that signed the grant.
    #[serde(default)]
    pub broker_public_key: String,
    /// Version 3 (governed projects only): the owner's authorization and
    /// the release ticket the key was released under. Absent in version 2
    /// grants, whose bytes are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance: Option<GrantGovernanceHeader>,
}

/// What a governed grant names: the owner-signed authorization the key was
/// released under, its project, purpose and strict end, and the
/// control-plane ticket that asked for it (absent only on a development
/// broker that does not require tickets).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantGovernanceHeader {
    /// Hex authorization ID.
    pub authorization_id: String,
    pub project: String,
    /// Hex purpose ID.
    pub purpose_id: String,
    /// The authorization's strict end (`valid_from <= t < valid_until`).
    pub valid_until: u64,
    /// Hex ticket ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_id: Option<String>,
}

impl GrantHeader {
    /// The signature domain of this header's version: version 2 without
    /// governance, version 3 with it; anything else is refused.
    fn signature_domain(&self) -> Result<&'static str> {
        let c = Code::KeyRelease;
        match (self.version, &self.governance) {
            (GRANT_VERSION, None) => Ok(GRANT_SIGNATURE),
            (GRANT_VERSION_GOVERNED, Some(_)) => Ok(GRANT_SIGNATURE_GOVERNED),
            (GRANT_VERSION, Some(_)) => Err(err(
                c,
                "a version 2 key grant carries no governance; governed grants are version 3",
            )),
            (GRANT_VERSION_GOVERNED, None) => Err(err(
                c,
                "a version 3 key grant names the authorization it was released under",
            )),
            (v, _) => Err(err(
                c,
                format!(
                    "key grant version {v}: only signed grants (version {GRANT_VERSION}, or \
                     {GRANT_VERSION_GOVERNED} when governed) are accepted; upgrade the key broker"
                ),
            )),
        }
    }
}

/// An asset key sealed (HPKE base mode, X25519-HKDF-SHA256,
/// ChaCha20-Poly1305) to an attested session key, and signed by the
/// broker. Carries no key material in the clear.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedKeyGrant {
    pub header: GrantHeader,
    /// HPKE encapsulated key, hex.
    pub encapsulated_key: String,
    /// Sealed asset key, hex.
    pub ciphertext: String,
    /// The broker's Ed25519 signature (hex) over the header, encapsulated
    /// key and ciphertext.
    #[serde(default)]
    pub signature: String,
}

#[derive(Serialize)]
struct SignedGrant<'a> {
    header: &'a GrantHeader,
    encapsulated_key: &'a str,
    ciphertext: &'a str,
}

impl EncryptedKeyGrant {
    fn signed_digest(&self) -> Result<crate::util::Digest32> {
        let statement = SignedGrant {
            header: &self.header,
            encapsulated_key: &self.encapsulated_key,
            ciphertext: &self.ciphertext,
        };
        Ok(tagged(
            self.header.signature_domain()?,
            &canonical_json(&statement)?,
        ))
    }

    /// Checks the version and the signature by the broker key the header
    /// names: version 2 without governance, version 3 with it, each under
    /// its own domain. Whether that key is the expected broker's is the
    /// caller's check (a pinned key).
    pub fn verify_signature(&self) -> Result<()> {
        let c = Code::KeyRelease;
        self.header.signature_domain()?;
        let pk: [u8; 32] = check_hex(c, "broker key", &self.header.broker_public_key, 32)?
            .try_into()
            .expect("32 bytes");
        let pk = VerifyingKey::from_bytes(&pk).map_err(|_| err(c, "malformed broker key"))?;
        let sig = check_hex(c, "grant signature", &self.signature, 64)?;
        let sig = Signature::from_slice(&sig).map_err(|_| err(c, "malformed grant signature"))?;
        pk.verify_strict(&self.signed_digest()?, &sig)
            .map_err(|_| err(c, "the key grant's broker signature is invalid"))
    }
}

impl EncryptedKeyGrant {
    /// Lowercase hex of the digest the broker signed (header, encapsulated
    /// key and ciphertext): what a [`KeyReleaseReceipt`] binds.
    pub fn digest(&self) -> Result<String> {
        Ok(hex(&self.signed_digest()?))
    }
}

pub const RELEASE_RECEIPT_VERSION: u32 = 1;
/// Domain of the broker's signature over a key-release receipt.
const RELEASE_RECEIPT: &str = "encompute.key-release-receipt.v1";

/// A governed key release as the owner's broker records it, for the
/// evidence bundle: which key version of which source version was released
/// under which authorization and ticket, to which attested session, and
/// when. Signed with the broker's grant key; it never contains a key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyReleaseReceipt {
    pub version: u32,
    pub broker_id: String,
    pub organization: String,
    pub asset_id: String,
    /// Hex `AssetVersionId`.
    pub asset_version_id: String,
    pub key_version: u64,
    /// Hex authorization ID.
    pub authorization_id: String,
    /// Absent only on a development broker that does not require tickets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    pub project: String,
    /// Hex `PurposeId`.
    pub purpose_id: String,
    pub execution_spec_id: String,
    pub session_id: String,
    pub binding_hash: String,
    pub attestation_digest: String,
    /// [`EncryptedKeyGrant::digest`] of the grant it records.
    pub grant_digest: String,
    /// The broker's clock at release (Unix seconds).
    pub released_at: u64,
    /// Hex Ed25519 grant key of the broker.
    #[serde(default)]
    pub broker_public_key: String,
    #[serde(default)]
    pub signature: String,
}

impl KeyReleaseReceipt {
    fn digest(&self) -> Result<crate::util::Digest32> {
        let unsigned = Self {
            signature: String::new(),
            ..self.clone()
        };
        Ok(tagged(RELEASE_RECEIPT, &canonical_json(&unsigned)?))
    }

    /// Signs the receipt with the broker's grant key.
    pub fn sign(mut self, signer: &GrantSigner) -> Result<Self> {
        self.broker_public_key = signer.public_key_hex();
        self.signature = String::new();
        self.signature = hex(&signer.0.sign(&self.digest()?).to_bytes());
        Ok(self)
    }

    /// Checks the receipt was signed by `broker_key` (hex, pinned by the
    /// caller).
    pub fn verify(&self, broker_key: &str) -> Result<()> {
        let c = Code::KeyRelease;
        if self.version != RELEASE_RECEIPT_VERSION {
            return Err(err(
                c,
                format!("key-release receipt version {}", self.version),
            ));
        }
        if self.broker_public_key != broker_key {
            return Err(err(
                c,
                "the key-release receipt is not signed by the pinned broker key",
            ));
        }
        let pk: [u8; 32] = check_hex(c, "broker key", &self.broker_public_key, 32)?
            .try_into()
            .expect("32 bytes");
        let pk = VerifyingKey::from_bytes(&pk).map_err(|_| err(c, "malformed broker key"))?;
        let sig = check_hex(c, "receipt signature", &self.signature, 64)?;
        let sig = Signature::from_slice(&sig).map_err(|_| err(c, "malformed receipt signature"))?;
        pk.verify_strict(&self.digest()?, &sig)
            .map_err(|_| err(c, "the key-release receipt's signature is invalid"))
    }
}

/// Seals `key` to the session key in `binding` and signs the grant (the
/// broker side).
pub fn seal_grant(
    mut header: GrantHeader,
    binding: &WorkloadBinding,
    key: &[u8],
    signer: &GrantSigner,
) -> Result<EncryptedKeyGrant> {
    header.broker_public_key = signer.public_key_hex();
    header.signature_domain()?;
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
    let mut g = EncryptedKeyGrant {
        header,
        encapsulated_key: hex(&enc.to_bytes()),
        ciphertext: hex(&ct),
        signature: String::new(),
    };
    g.signature = hex(&signer.0.sign(&g.signed_digest()?).to_bytes());
    Ok(g)
}

/// A workload session: the evaluator's identity plus an ephemeral HPKE key
/// pair generated inside the TEE. The private key never leaves it.
pub struct WorkloadSession {
    evaluator_public_key: [u8; 32],
    secret: <SessionKem as Kem>::PrivateKey,
    public: <SessionKem as Kem>::PublicKey,
    /// The `PrivacyPolicyId` this workload applies, bound into every
    /// binding (absent: the workload applies none).
    privacy_policy_id: Option<String>,
}

impl WorkloadSession {
    pub fn new(evaluator: &EvaluatorIdentity) -> Self {
        let (secret, public) = SessionKem::gen_keypair();
        Self {
            evaluator_public_key: evaluator.public_key(),
            secret,
            public,
            privacy_policy_id: None,
        }
    }

    /// This session, for a workload applying `privacy_policy_id` (a
    /// training or aggregation workload under differential privacy): its
    /// bindings name it, so a key-release policy requiring it is satisfied
    /// only by a workload bound to exactly that privacy policy.
    pub fn with_privacy_policy(mut self, privacy_policy_id: Option<&str>) -> Self {
        self.privacy_policy_id = privacy_policy_id.map(str::to_owned);
        self
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
            privacy_policy_id: self.privacy_policy_id.clone(),
        }
    }

    /// Opens a grant sealed to this session, after checking its broker
    /// signature ([`EncryptedKeyGrant::verify_signature`]).
    pub fn open(&self, grant: &EncryptedKeyGrant) -> Result<Zeroizing<Vec<u8>>> {
        grant.verify_signature()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    const AAD: &str = r#"{"asset_id":"patients","attestation_digest":"5555555555555555555555555555555555555555555555555555555555555555","binding_hash":"4444444444444444444444444444444444444444444444444444444444444444","broker_id":"hospital","broker_public_key":"1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca","execution_spec_id":"1111111111111111111111111111111111111111111111111111111111111111","expires_at":1900000600,"key_version":3,"policy_id":"2222222222222222222222222222222222222222222222222222222222222222","session_id":"3333333333333333333333333333333333333333333333333333333333333333","version":2}"#;
    const DIGEST: &str = "84aa6fe29d6d78a3e5821bfc69f8cd8a6780b9650fc2846ffd37d7948cc256dd";
    const SIGNATURE: &str = "9d665d07cce9db2ec6c62684e9f36153aa39883403055ad4a6919fe4e09f150448e9da712685af1c4d4aeab9155046df2fb68aebd7f82afbebdfff34c282960e";

    fn v2_header() -> GrantHeader {
        GrantHeader {
            version: GRANT_VERSION,
            broker_id: "hospital".into(),
            asset_id: "patients".into(),
            key_version: 3,
            policy_id: Some("22".repeat(32)),
            execution_spec_id: "11".repeat(32),
            session_id: "33".repeat(32),
            binding_hash: "44".repeat(32),
            attestation_digest: "55".repeat(32),
            expires_at: 1_900_000_600,
            broker_public_key: GrantSigner::from_seed(&[8; 32]).public_key_hex(),
            governance: None,
        }
    }

    fn governance() -> GrantGovernanceHeader {
        GrantGovernanceHeader {
            authorization_id: "88".repeat(32),
            project: "prj_1".into(),
            purpose_id: "99".repeat(32),
            valid_until: 1_900_001_000,
            ticket_id: Some("aa".repeat(32)),
        }
    }

    fn signed(header: GrantHeader) -> EncryptedKeyGrant {
        let signer = GrantSigner::from_seed(&[8; 32]);
        let mut g = EncryptedKeyGrant {
            header,
            encapsulated_key: "66".repeat(32),
            ciphertext: "77".repeat(48),
            signature: String::new(),
        };
        // A header whose version and governance disagree has no signing
        // domain: sign it as the other version would have been.
        let digest = g.signed_digest().unwrap_or_else(|_| {
            let d = match g.header.version {
                GRANT_VERSION => GRANT_SIGNATURE,
                _ => GRANT_SIGNATURE_GOVERNED,
            };
            let statement = SignedGrant {
                header: &g.header,
                encapsulated_key: &g.encapsulated_key,
                ciphertext: &g.ciphertext,
            };
            tagged(d, &canonical_json(&statement).unwrap())
        });
        g.signature = hex(&signer.0.sign(&digest).to_bytes());
        g
    }

    /// Version 2 grants are byte for byte what 0.3.0 produced: the header
    /// (the HPKE associated data), the signed digest and the signature.
    #[test]
    fn v2_grant_bytes_unchanged() {
        let g = signed(v2_header());
        assert_eq!(
            String::from_utf8(canonical_json(&g.header).unwrap()).unwrap(),
            AAD
        );
        assert_eq!(hex(&g.signed_digest().unwrap()), DIGEST);
        assert_eq!(g.signature, SIGNATURE);
        assert!(!serde_json::to_string(&g).unwrap().contains("governance"));
        g.verify_signature().unwrap();
    }

    /// A governed grant is version 3, signed under its own domain: its
    /// signature never verifies as a version 2 grant's, nor the reverse.
    #[test]
    fn v3_grant_is_signed_under_its_own_domain() {
        let mut h = v2_header();
        h.version = GRANT_VERSION_GOVERNED;
        h.governance = Some(governance());
        let g = signed(h);
        g.verify_signature().unwrap();
        let mut as_v2 = g.clone();
        as_v2.header.version = GRANT_VERSION;
        as_v2.header.governance = None;
        assert!(as_v2.verify_signature().is_err());
        // Every governance field is signed.
        for edit in [
            &(|x: &mut GrantGovernanceHeader| x.authorization_id = "89".repeat(32))
                as &dyn Fn(&mut GrantGovernanceHeader),
            &|x| x.project = "prj_2".into(),
            &|x| x.purpose_id = "98".repeat(32),
            &|x| x.valid_until += 1,
            &|x| x.ticket_id = None,
        ] {
            let mut t = g.clone();
            edit(t.header.governance.as_mut().unwrap());
            assert!(t.verify_signature().is_err());
        }
    }

    #[test]
    fn v3_grant_without_governance_refused() {
        let mut h = v2_header();
        h.version = GRANT_VERSION_GOVERNED;
        let g = signed(h);
        assert_eq!(g.verify_signature().unwrap_err().code, Code::KeyRelease);
    }

    #[test]
    fn v2_grant_with_governance_refused() {
        let mut h = v2_header();
        h.governance = Some(governance());
        let g = signed(h);
        assert_eq!(g.verify_signature().unwrap_err().code, Code::KeyRelease);
    }
}
