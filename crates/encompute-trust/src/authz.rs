//! Owner authorizations and revocations. A policy says what may happen to
//! an asset; an authorization is its owner's signed approval of one
//! program, under one confidentiality and privacy policy, for a purpose. It
//! closes the gap ADR-010 left open: kinds and derivations are the
//! program's claims, so owners approve the program itself. A revocation
//! withdraws an asset (or one authorization) from a given time on.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::governance::{is_hex32, ProgramRef, ReleaseClass};
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

// --- version 2: governed projects -------------------------------------------
//
// One owner-signed document per (organization, project, purpose, program or
// program set, asset version), signed with the organization's governance
// key (kept in its own KMS or HSM; the control plane holds only the public
// key). The control plane indexes it, the owner's key broker enforces it,
// and the governance report checks it: the same bytes everywhere. A v1
// authorization never satisfies a governed project.

pub const AUTHORIZATION_V2_VERSION: u32 = 2;
pub const PURPOSE_ACCEPTANCE_VERSION: u32 = 1;
const AUTHORIZATION_V2: &str = "encompute.authorization.v2";
const REVOCATION_V2: &str = "encompute.revocation.v2";
const APPROVAL: &str = "encompute.approval.v1";
const AUTHORIZATION_SET: &str = "encompute.authorization-set.v1";
const PURPOSE_ACCEPTANCE: &str = "encompute.purpose-acceptance.v1";
const GOVERNANCE_KEY: &str = "encompute.governance-key.v1";

fn check_hex32(what: &str, s: &str) -> Result<()> {
    if is_hex32(s) {
        Ok(())
    } else {
        Err(err(format!("{what} must be 32 bytes of lowercase hex")))
    }
}

fn check_label(what: &str, s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 200 || s.chars().any(|c| c.is_control()) {
        return Err(err(format!("{what} must be 1-200 printable characters")));
    }
    Ok(())
}

/// The ID (fingerprint) of a governance public key (hex Ed25519).
pub fn governance_key_id(public_key: &str) -> String {
    crate::tagged_hex(GOVERNANCE_KEY, public_key.as_bytes())
}

/// Whether an anchored governance key may still sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceKeyStatus {
    Active,
    /// Final: a revoked key never verifies again, whatever its documents'
    /// dates (a stolen key can backdate them).
    Revoked,
}

/// An organization's governance public key, anchored in a trust graph
/// ([`crate::TrustGraph::add_governance_keys`]) from the caller's own
/// record of it (the control plane's approved keys), never from a signed
/// document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceKey {
    pub organization: String,
    /// Hex Ed25519 public key.
    pub public_key: String,
    pub status: GovernanceKeyStatus,
}

impl GovernanceKey {
    /// A well-formed Ed25519 public key for a labelled organization.
    pub fn check(&self) -> Result<()> {
        check_label("organization", &self.organization)?;
        unhex(&self.public_key)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| VerifyingKey::from_bytes(&b).ok())
            .filter(|k| hex(&k.to_bytes()) == self.public_key)
            .map(|_| ())
            .ok_or_else(|| err("a governance key is a 32-byte Ed25519 public key in lowercase hex"))
    }

    pub fn key_id(&self) -> String {
        governance_key_id(&self.public_key)
    }
}

/// Usage limits an owner sets (all optional; enforced from the key-broker
/// and enforcement phases).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_executions: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_releases: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_subjects_per_job: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_evaluations_per_subject: Option<u64>,
}

impl AuthorizationLimits {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// One person's approval of an authorization: a statement over the
/// unapproved body, the approver and the role. The first implementation
/// verifies only the governance key's signature over the whole document;
/// the IdP fields are carried so that approvals can later be bound to ID
/// tokens (`nonce = statement_digest`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEvidence {
    pub statement_digest: String,
    pub approver_subject: String,
    pub idp_issuer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<u64>,
    /// Authentication context (MFA level), when the IdP says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    pub role: String,
    pub organization: String,
    pub at: u64,
}

/// An owner's authorization of one use of one asset version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationV2 {
    pub version: u32,
    /// The owning organization (its governance key signs).
    pub party: String,
    pub project: String,
    /// Mandatory: an authorization is for exactly one purpose.
    pub purpose_id: String,
    pub asset_version_id: String,
    /// A salted commitment to the version's digest.
    pub asset_digest_commitment: String,
    /// One program or one content-addressed program set; never a pattern.
    pub program: ProgramRef,
    pub policy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linkage_policy_id: Option<String>,
    /// The ceiling on what may be released.
    pub release_class: ReleaseClass,
    pub recipients: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_scope_id: Option<String>,
    /// An optional tighter pin to exact execution specs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_spec_ids: Option<BTreeSet<String>>,
    #[serde(default, skip_serializing_if = "AuthorizationLimits::is_empty")]
    pub limits: AuthorizationLimits,
    pub per_job_four_eyes: bool,
    pub valid_from: u64,
    pub valid_until: u64,
    pub issued_at: u64,
    /// 16 random bytes (hex): two otherwise equal authorizations differ.
    pub nonce: String,
    #[serde(default)]
    pub approvals: Vec<ApprovalEvidence>,
}

pub type SignedAuthorizationV2 = Signed<AuthorizationV2>;

impl AuthorizationV2 {
    /// The authorization ID (hex): the tagged hash of the whole body,
    /// approvals included (the signature is over the same digest).
    pub fn id(&self) -> String {
        crate::tagged_hex(
            AUTHORIZATION_V2,
            &canonical_json(self).expect("strings, integers and sets only"),
        )
    }

    /// `encauth2:<hex>`.
    pub fn display_id(&self) -> String {
        format!("encauth2:{}", self.id())
    }

    /// The body without approvals: what approvers approve.
    pub fn unapproved(&self) -> Self {
        Self {
            approvals: vec![],
            ..self.clone()
        }
    }

    /// `SHA256("encompute.approval.v1" || 0x00 || canonical {authorization
    /// (unapproved), issuer, approver, role})`, hex.
    pub fn approval_statement(
        &self,
        idp_issuer: &str,
        approver_subject: &str,
        role: &str,
    ) -> String {
        #[derive(Serialize)]
        struct Statement<'a> {
            authorization: &'a AuthorizationV2,
            idp_issuer: &'a str,
            approver_subject: &'a str,
            role: &'a str,
        }
        crate::tagged_hex(
            APPROVAL,
            &canonical_json(&Statement {
                authorization: &self.unapproved(),
                idp_issuer,
                approver_subject,
                role,
            })
            .expect("strings, integers and sets only"),
        )
    }

    /// Strict: `valid_from <= t < valid_until`, no margin.
    pub fn is_valid_at(&self, t: u64) -> bool {
        self.valid_from <= t && t < self.valid_until
    }

    /// Well formed: version 2, IDs as 32-byte hex, an exact program or a
    /// consistent program set, a non-empty window and recipients.
    pub fn check(&self) -> Result<()> {
        if self.version != AUTHORIZATION_V2_VERSION {
            return Err(err(format!("authorization version {}", self.version)));
        }
        check_label("party", &self.party)?;
        check_label("project", &self.project)?;
        check_hex32("purpose ID", &self.purpose_id)?;
        check_hex32("asset version ID", &self.asset_version_id)?;
        check_hex32("asset digest commitment", &self.asset_digest_commitment)?;
        check_hex32("policy ID", &self.policy_id)?;
        for d in [
            &self.privacy_policy_id,
            &self.linkage_policy_id,
            &self.privacy_scope_id,
        ]
        .into_iter()
        .flatten()
        {
            check_hex32("policy ID", d)?;
        }
        if let Some(s) = &self.execution_spec_ids {
            if s.is_empty() {
                return Err(err("an execution spec pin names at least one spec"));
            }
            for x in s {
                check_hex32("execution spec ID", x)?;
            }
        }
        self.program.check().map_err(|e| err(e.message))?;
        if self.recipients.is_empty() && self.release_class != ReleaseClass::Never {
            return Err(err("an authorization names at least one recipient"));
        }
        for r in &self.recipients {
            check_label("recipient", r)?;
        }
        if self.valid_from >= self.valid_until {
            return Err(err("an authorization's window must end after it starts"));
        }
        if self.nonce.len() != 32 || unhex(&self.nonce).is_none() {
            return Err(err("the nonce is 16 bytes of lowercase hex"));
        }
        self.check_approvals()
    }

    /// Each approval is a statement over this (unapproved) body by a person
    /// of the authorizing organization.
    pub fn check_approvals(&self) -> Result<()> {
        for a in &self.approvals {
            if a.organization != self.party {
                return Err(err(format!(
                    "an approval by {} does not count for {}",
                    a.organization, self.party
                )));
            }
            check_label("approver", &a.approver_subject)?;
            check_label("identity provider", &a.idp_issuer)?;
            check_label("role", &a.role)?;
            if a.statement_digest
                != self.approval_statement(&a.idp_issuer, &a.approver_subject, &a.role)
            {
                return Err(err(
                    "an approval is not a statement over this authorization",
                ));
            }
        }
        Ok(())
    }

    /// Four eyes: at least `min_distinct` different people (issuer,
    /// subject) approved, and `required_roles` (role → how many distinct
    /// people) are covered.
    pub fn check_quorum(
        &self,
        min_distinct: usize,
        required_roles: &BTreeMap<String, u32>,
    ) -> Result<()> {
        let four_eyes = |m: String| Error::new(Code::GovernanceFourEyesIncomplete, m);
        let people: BTreeSet<(&str, &str)> = self
            .approvals
            .iter()
            .map(|a| (a.idp_issuer.as_str(), a.approver_subject.as_str()))
            .collect();
        if people.len() < min_distinct.max(2) {
            return Err(four_eyes(format!(
                "{} distinct people approved; {} are required",
                people.len(),
                min_distinct.max(2)
            )));
        }
        for (role, n) in required_roles {
            let with_role: BTreeSet<(&str, &str)> = self
                .approvals
                .iter()
                .filter(|a| &a.role == role)
                .map(|a| (a.idp_issuer.as_str(), a.approver_subject.as_str()))
                .collect();
            if with_role.len() < *n as usize {
                return Err(four_eyes(format!("needs {n} approval(s) as {role}")));
            }
        }
        Ok(())
    }

    pub fn sign(self, key: &SigningKey) -> Result<SignedAuthorizationV2> {
        sign(AUTHORIZATION_V2, self, key)
    }
}

impl SignedAuthorizationV2 {
    /// Checks the body and the signature by `governance_key` (hex): the
    /// organization's active governance key, which the caller supplies
    /// (never the document's own key alone; in a trust graph, the key
    /// anchored for the organization, see
    /// [`crate::TrustGraph::add_authorization_v2`]).
    pub fn verify(&self, governance_key: &str) -> Result<()> {
        self.body.check()?;
        verify(AUTHORIZATION_V2, self, governance_key)
    }

    pub fn id(&self) -> String {
        self.body.id()
    }
}

/// An owner's revocation of one v2 authorization (supersession is revoke
/// and reissue). Revocation blocks new use; it is not retroactive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationV2 {
    pub version: u32,
    pub party: String,
    /// Hex authorization ID.
    pub authorization: String,
    pub reason: String,
    pub issued_at: u64,
}

pub type SignedRevocationV2 = Signed<RevocationV2>;

impl RevocationV2 {
    pub fn sign(self, key: &SigningKey) -> Result<SignedRevocationV2> {
        sign(REVOCATION_V2, self, key)
    }
}

impl SignedRevocationV2 {
    pub fn verify(&self, governance_key: &str) -> Result<()> {
        if self.body.version != AUTHORIZATION_V2_VERSION {
            return Err(err("unknown revocation version"));
        }
        check_label("party", &self.body.party)?;
        check_hex32("authorization ID", &self.body.authorization)?;
        verify(REVOCATION_V2, self, governance_key)
    }

    pub fn id(&self) -> Result<String> {
        Ok(crate::tagged_hex(
            REVOCATION_V2,
            &canonical_json(&self.body)?,
        ))
    }
}

/// An organization's acceptance of a purpose in a project, signed with its
/// governance key (`SignedPurpose`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurposeAcceptance {
    pub version: u32,
    pub organization: String,
    pub project: String,
    /// Hex purpose ID.
    pub purpose_id: String,
    pub accepted_at: u64,
}

pub type SignedPurposeAcceptance = Signed<PurposeAcceptance>;

impl PurposeAcceptance {
    pub fn sign(self, key: &SigningKey) -> Result<SignedPurposeAcceptance> {
        sign(PURPOSE_ACCEPTANCE, self, key)
    }
}

impl SignedPurposeAcceptance {
    pub fn verify(&self, governance_key: &str) -> Result<()> {
        if self.body.version != PURPOSE_ACCEPTANCE_VERSION {
            return Err(err("unknown purpose acceptance version"));
        }
        check_label("organization", &self.body.organization)?;
        check_label("project", &self.body.project)?;
        check_hex32("purpose ID", &self.body.purpose_id)?;
        verify(PURPOSE_ACCEPTANCE, self, governance_key)
    }
}

/// The ID of a job's set of authorizations: sorted, each once, never
/// empty.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationSetId(pub String);

impl AuthorizationSetId {
    pub fn of<I, S>(ids: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut set = BTreeSet::new();
        for i in ids {
            let i = i.into();
            check_hex32("authorization ID", &i)?;
            if !set.insert(i) {
                return Err(err("an authorization set names each authorization once"));
            }
        }
        if set.is_empty() {
            return Err(err("an authorization set is never empty"));
        }
        Ok(Self(crate::tagged_hex(
            AUTHORIZATION_SET,
            &canonical_json(&set)?,
        )))
    }

    pub fn hex(&self) -> &str {
        &self.0
    }
}
