//! Owner authorizations and revocations. A policy says what may happen to
//! an asset; an authorization is its owner's signed approval of one
//! program, under one confidentiality and privacy policy, for a purpose. It
//! closes the gap ADR-010 left open: kinds and derivations are the
//! program's claims, so owners approve the program itself. A revocation
//! withdraws an asset (or one authorization) from a given time on.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::{hex, unhex};

use crate::tagged;

pub const AUTHORIZATION_VERSION: u32 = 1;
const AUTHORIZATION: &str = "encompute.authorization.v1";
const REVOCATION: &str = "encompute.revocation.v1";

fn err(m: impl Into<String>) -> Error {
    Error::new(Code::TrustAuthorization, m)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub version: u32,
    pub party: String,
    pub asset: String,
    /// The program approved (hex program ID).
    pub program_id: String,
    pub policy_id: Option<String>,
    pub privacy_policy_id: Option<String>,
    pub purpose: Option<String>,
    pub issued_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub version: u32,
    pub party: String,
    pub asset: String,
    /// One authorization (its ID), or all of the asset's if absent.
    #[serde(default)]
    pub authorization: Option<String>,
    pub reason: String,
    pub issued_at: u64,
}

/// A body signed with the party's Ed25519 key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub body: T,
    pub public_key: String,
    pub signature: String,
}

pub type SignedAuthorization = Signed<Authorization>;
pub type SignedRevocation = Signed<Revocation>;

fn sign<T: Serialize>(domain: &str, body: T, key: &SigningKey) -> Result<Signed<T>> {
    let digest = tagged(domain, &canonical_json(&body)?);
    Ok(Signed {
        public_key: hex(&key.verifying_key().to_bytes()),
        signature: hex(&key.sign(&digest).to_bytes()),
        body,
    })
}

fn verify<T: Serialize>(domain: &str, s: &Signed<T>, expected_key: &str) -> Result<()> {
    if s.public_key != expected_key {
        return Err(err("signed by a key that is not the party's"));
    }
    let key = unhex(&s.public_key)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .ok_or_else(|| err("malformed party key"))?;
    let sig = unhex(&s.signature)
        .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
        .ok_or_else(|| err("malformed signature"))?;
    key.verify_strict(&tagged(domain, &canonical_json(&s.body)?), &sig)
        .map_err(|_| err("the signature is invalid"))
}

impl Authorization {
    pub fn sign(self, key: &SigningKey) -> Result<SignedAuthorization> {
        sign(AUTHORIZATION, self, key)
    }
}

impl Revocation {
    pub fn sign(self, key: &SigningKey) -> Result<SignedRevocation> {
        sign(REVOCATION, self, key)
    }
}

impl SignedAuthorization {
    pub fn verify(&self, party_key: &str) -> Result<()> {
        if self.body.version != AUTHORIZATION_VERSION {
            return Err(err("unknown authorization version"));
        }
        verify(AUTHORIZATION, self, party_key)
    }

    pub fn id(&self) -> Result<String> {
        Ok(crate::tagged_hex(AUTHORIZATION, &canonical_json(self)?))
    }
}

impl SignedRevocation {
    pub fn verify(&self, party_key: &str) -> Result<()> {
        if self.body.version != AUTHORIZATION_VERSION {
            return Err(err("unknown revocation version"));
        }
        verify(REVOCATION, self, party_key)
    }

    pub fn id(&self) -> Result<String> {
        Ok(crate::tagged_hex(REVOCATION, &canonical_json(self)?))
    }
}
