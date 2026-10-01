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
use encompute_verification::service::{verify_signed, ServiceSigner};
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

pub(crate) fn sign<T: Serialize>(domain: &str, body: T, key: &SigningKey) -> Result<Signed<T>> {
    let digest = tagged(domain, &canonical_json(&body)?);
    Ok(Signed {
        public_key: hex(&key.verifying_key().to_bytes()),
        signature: hex(&key.sign(&digest).to_bytes()),
        body,
    })
}

pub(crate) fn verify<T: Serialize>(domain: &str, s: &Signed<T>, expected_key: &str) -> Result<()> {
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
const JOB_APPROVAL: &str = "encompute.job-approval.v1";

/// An organization's four-eyes rule over `approvals` (person, role): at
/// least `min_distinct` (never fewer than two) different people, and
/// `required_roles` (role → how many distinct people) covered. A person
/// counts once, whatever roles or keys they approved with. The one quorum
/// check for standing authorizations and per-job approvals alike; who may
/// count at all (a person of the organization, never a service account,
/// an auditor or the job's submitter) is the caller's to decide.
pub fn quorum_met<P: Ord, R: AsRef<str>>(
    approvals: impl IntoIterator<Item = (P, R)>,
    min_distinct: usize,
    required_roles: &BTreeMap<String, u32>,
) -> Result<()> {
    let four_eyes = |m: String| Error::new(Code::GovernanceFourEyesIncomplete, m);
    let approvals: Vec<(P, R)> = approvals.into_iter().collect();
    let people: BTreeSet<&P> = approvals.iter().map(|(p, _)| p).collect();
    let min = min_distinct.max(2);
    if people.len() < min {
        return Err(four_eyes(format!(
            "{} distinct people approved; {min} are required",
            people.len()
        )));
    }
    for (role, n) in required_roles {
        let with_role: BTreeSet<&P> = approvals
            .iter()
            .filter(|(_, r)| r.as_ref() == role)
            .map(|(p, _)| p)
            .collect();
        if with_role.len() < *n as usize {
            return Err(four_eyes(format!("needs {n} approval(s) as {role}")));
        }
    }
    Ok(())
}

/// The statement a person approves for one governed job (per-job four
/// eyes): `SHA256("encompute.job-approval.v1" || 0x00 || canonical {job,
/// spec_id, authorization_set_id})`, hex. It binds the job, its governed
/// execution spec and the set of authorizations it runs under, so an
/// approval never carries over to another spec or authorization set.
pub fn job_approval_statement(job: &str, spec_id: &str, authorization_set_id: &str) -> String {
    #[derive(Serialize)]
    struct Statement<'a> {
        job: &'a str,
        spec_id: &'a str,
        authorization_set_id: &'a str,
    }
    crate::tagged_hex(
        JOB_APPROVAL,
        &canonical_json(&Statement {
            job,
            spec_id,
            authorization_set_id,
        })
        .expect("strings only"),
    )
}

pub(crate) fn check_hex32(what: &str, s: &str) -> Result<()> {
    if is_hex32(s) {
        Ok(())
    } else {
        Err(err(format!("{what} must be 32 bytes of lowercase hex")))
    }
}

pub(crate) fn check_label(what: &str, s: &str) -> Result<()> {
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
    /// Final, from its revocation time on ([`GovernanceKey::revoked_at`]):
    /// nothing it signed is used at or after that time, and nothing it
    /// claims to have signed then or later is ever valid. A use before it
    /// (an execution or key release that happened while the key was
    /// active) stays verifiable as history, at a time taken from evidence
    /// the verifier trusts, never from the signed document's own dates (a
    /// stolen key can backdate them).
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
    /// When a revoked key was revoked (Unix seconds): present exactly when
    /// the key is revoked, and never changed once recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
}

impl GovernanceKey {
    /// A well-formed Ed25519 public key for a labelled organization; a
    /// revoked key carries its revocation time, an active one none.
    pub fn check(&self) -> Result<()> {
        check_label("organization", &self.organization)?;
        match (self.status, self.revoked_at) {
            (GovernanceKeyStatus::Active, None) | (GovernanceKeyStatus::Revoked, Some(_)) => {}
            (GovernanceKeyStatus::Active, Some(_)) => {
                return Err(err("an active governance key has no revocation time"))
            }
            (GovernanceKeyStatus::Revoked, None) => {
                return Err(err("a revoked governance key carries its revocation time"))
            }
        }
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

    /// Whether the key is revoked at `t`: from its revocation time on.
    pub fn revoked_by(&self, t: u64) -> bool {
        self.revoked_at.is_some_and(|r| t >= r)
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
    /// How many outputs of one job may be released as boolean-only (a
    /// boolean or a bounded category) from this source; absent: one.
    /// Several such outputs of one job could jointly encode a value.
    /// Skipped when absent, so existing AuthorizationIds are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_outputs_per_job: Option<u64>,
    /// Where work on this source may run and who may operate the machines
    /// (the owner's own residency rule). It can only tighten what the
    /// project's constraints allow, never loosen them; the control plane
    /// applies it when it binds a job and when it schedules, and the key
    /// broker checks it against the attested location of the session that
    /// asks for the key. Skipped when absent, so existing AuthorizationIds
    /// are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<encompute_verification::placement::PlacementConstraints>,
    /// The digest of the project placement constraints the owner accepts
    /// for this use. A job under this authorization is bound only to
    /// exactly these constraints, and the owner's broker releases only if
    /// the binding names this digest: the control plane cannot drop or
    /// swap the project's constraints for this owner's data. Absent, the
    /// project's constraints are enforced by the control plane only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_placement_digest: Option<String>,
}

/// Classes whose ceiling admits boolean-only releases (a boolean or a
/// bounded category): the ones repeated queries can probe.
pub fn admits_probing(class: ReleaseClass) -> bool {
    ReleaseClass::BooleanOnly.within(class)
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
    /// Probing controls (fail closed): an authorization whose ceiling
    /// admits boolean-only releases bounds how many jobs it runs and how
    /// many key releases it makes (`max_executions`, `max_releases`), so
    /// repeated yes/no questions about the same records are bounded. They
    /// bound that channel; they do not close it (ENC2709). The owner's
    /// placement constraints, if any, are checked here too: every path that
    /// proposes, signs or installs an authorization calls this.
    pub fn check_probing_limits(&self) -> Result<()> {
        if admits_probing(self.release_class)
            && (self.limits.max_executions.is_none() || self.limits.max_releases.is_none())
        {
            return Err(Error::new(
                Code::GovernanceReleaseClass,
                format!(
                    "an authorization with release class {} bounds repeated queries: it sets \
                     limits.max_executions and limits.max_releases",
                    self.release_class.as_str()
                ),
            ));
        }
        if self.limits.max_outputs_per_job == Some(0) {
            return Err(err("max_outputs_per_job is at least 1"));
        }
        if let Some(p) = &self.limits.placement {
            p.check().map_err(|e| err(e.message))?;
        }
        if let Some(d) = &self.limits.project_placement_digest {
            check_hex32("project placement digest", d)?;
        }
        Ok(())
    }

    /// Whether the job's `outputs` stay within this authorization's
    /// per-job cap on boolean-only outputs (`max_outputs_per_job`, one when
    /// absent). The control plane at submission and the key broker at key
    /// release both decide with this function.
    pub fn probing_outputs_within(
        &self,
        outputs: &BTreeMap<String, encompute_verification::governance::GovernanceOutput>,
    ) -> bool {
        let n = outputs
            .values()
            .filter(|o| o.release_class == ReleaseClass::BooleanOnly)
            .count() as u64;
        n <= self.limits.max_outputs_per_job.unwrap_or(1)
    }

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
        quorum_met(
            self.approvals.iter().map(|a| {
                (
                    (a.idp_issuer.as_str(), a.approver_subject.as_str()),
                    a.role.as_str(),
                )
            }),
            min_distinct,
            required_roles,
        )
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

    /// Whether the authorization may be used at `t`: for a submission,
    /// schedule, start, key release or export at `t`, or, as history, for
    /// an execution that ran at `t`. Its signature verifies under `key`
    /// (the organization's governance key as the caller records it, never
    /// the document's own); the key is not revoked at `t`, and did not
    /// sign after its revocation (ENC2708); `t` lies in the window
    /// (ENC2705); and the owner's `revocation` of it, if any (verified by
    /// the caller), is not in effect at `t` (ENC2706). Revocations, of the
    /// key or of the authorization, block use from their time on and are
    /// never retroactive. `t` comes from the verifier's own clock or from
    /// evidence it trusts (a signed receipt or grant), never from the
    /// authorization.
    pub fn usable_at(
        &self,
        key: &GovernanceKey,
        revocation: Option<&RevocationV2>,
        t: u64,
    ) -> Result<()> {
        key.check()?;
        if key.organization != self.body.party {
            return Err(err(format!(
                "a governance key of {} does not verify an authorization of {}",
                key.organization, self.body.party
            )));
        }
        self.verify(&key.public_key)?;
        if let Some(r) = key.revoked_at {
            let revoked = |m: String| Error::new(Code::GovernanceKeyRevoked, m);
            if self.body.issued_at >= r {
                return Err(revoked(format!(
                    "issued at {} under a governance key revoked at {r}",
                    self.body.issued_at
                )));
            }
            if t >= r {
                return Err(revoked(format!(
                    "the governance key that signed it was revoked at {r}: it is not used at {t}"
                )));
            }
        }
        if !self.body.is_valid_at(t) {
            return Err(Error::new(
                Code::GovernanceAuthorizationExpired,
                format!(
                    "valid from {} until {}, not at {t}",
                    self.body.valid_from, self.body.valid_until
                ),
            ));
        }
        if let Some(rev) = revocation {
            if rev.party != self.body.party || rev.authorization != self.id() {
                return Err(err("the revocation is for another authorization"));
            }
            if rev.in_effect_at(t) {
                return Err(Error::new(
                    Code::GovernanceAuthorizationRevoked,
                    format!("revoked by its owner at {}", rev.issued_at),
                ));
            }
        }
        Ok(())
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

    /// In effect from its issue time on, never before: a use at an earlier
    /// time stays valid.
    pub fn in_effect_at(&self, t: u64) -> bool {
        t >= self.issued_at
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

// --- derived results: the custodian's signed release record -----------------

pub const RELEASE_RECORD_VERSION: u32 = 1;
const RELEASE_RECORD: &str = "encompute.release-record.v1";

/// A released result recorded as a derived asset, signed by its custodian
/// (the recipient organization that decrypted it) with its governance key:
/// which job released which output, a salted commitment to it, its release
/// class, the exact source versions it came from, the authorizations it
/// was released under, the onward policy it is held under, and to whom,
/// under which export key, it may be exported. The custodian's key broker
/// holds the result's key and exports it only to a recipient this record
/// names, sealed to the key it names for it: the control plane can deny an
/// export, never redirect one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRecord {
    pub version: u32,
    /// The custodian: the recipient organization that holds the result.
    pub party: String,
    pub project: String,
    /// Hex `PurposeId`.
    pub purpose_id: String,
    pub job_id: String,
    /// Hex `GovernanceId` of the job's binding.
    pub governance_id: String,
    /// The job's output the result is.
    pub output: String,
    /// Salted commitment to the released value (hex).
    pub output_commitment: String,
    /// Hex `AssetVersionId` of the derived asset.
    pub derived_version_id: String,
    pub release_class: ReleaseClass,
    /// Hex `AssetVersionId`s of the job's sources: the result's parents.
    pub parents: BTreeSet<String>,
    /// Hex IDs of the owner authorizations the job ran under.
    pub authorization_ids: BTreeSet<String>,
    /// Hex digest of the onward policy the result is held under.
    pub onward_policy_id: String,
    /// Who may receive an export: organization → its export key (hex
    /// X25519). Never wider than every parent authorization's recipients.
    pub recipients: BTreeMap<String, String>,
    /// Every other organization owning data the result derives from, every
    /// hop up: organization → the ID of its governance key
    /// ([`governance_key_id`]). The custodian's broker releases or exports
    /// the result's key only with an installed authorization of each,
    /// verified under that key, which it pins.
    pub lineage_owners: BTreeMap<String, String>,
    pub issued_at: u64,
}

pub type SignedReleaseRecord = Signed<ReleaseRecord>;

impl ReleaseRecord {
    /// Well formed: version 1, IDs and keys as 32-byte hex, labels
    /// printable, at least one parent and one authorization.
    pub fn check(&self) -> Result<()> {
        if self.version != RELEASE_RECORD_VERSION {
            return Err(err(format!("release record version {}", self.version)));
        }
        check_label("party", &self.party)?;
        check_label("project", &self.project)?;
        check_label("job", &self.job_id)?;
        check_label("output", &self.output)?;
        check_hex32("purpose ID", &self.purpose_id)?;
        check_hex32("governance ID", &self.governance_id)?;
        check_hex32("output commitment", &self.output_commitment)?;
        check_hex32("derived version ID", &self.derived_version_id)?;
        check_hex32("onward policy ID", &self.onward_policy_id)?;
        if self.parents.is_empty() || self.authorization_ids.is_empty() {
            return Err(err(
                "a release record names the result's parents and the authorizations it was released under",
            ));
        }
        for p in &self.parents {
            check_hex32("parent version ID", p)?;
        }
        for a in &self.authorization_ids {
            check_hex32("authorization ID", a)?;
        }
        for (r, k) in &self.recipients {
            check_label("recipient", r)?;
            check_hex32("recipient export key", k)?;
        }
        for (o, k) in &self.lineage_owners {
            check_label("lineage owner", o)?;
            check_hex32("lineage owner's governance key ID", k)?;
        }
        if self.lineage_owners.contains_key(&self.party) {
            return Err(err(
                "the custodian is not among its result's lineage owners",
            ));
        }
        Ok(())
    }

    /// The record's ID (hex): the tagged hash of its body.
    pub fn id(&self) -> String {
        crate::tagged_hex(
            RELEASE_RECORD,
            &canonical_json(self).expect("strings, integers and sets only"),
        )
    }

    pub fn sign(self, key: &SigningKey) -> Result<SignedReleaseRecord> {
        sign(RELEASE_RECORD, self, key)
    }
}

impl SignedReleaseRecord {
    /// Checks the body and the signature by `governance_key` (hex): the
    /// custodian's governance key as the caller records it (a pinned or
    /// active key), never the document's own alone.
    pub fn verify(&self, governance_key: &str) -> Result<()> {
        self.body.check()?;
        verify(RELEASE_RECORD, self, governance_key)
    }

    pub fn id(&self) -> String {
        self.body.id()
    }
}

// --- the control plane's statements a custodian's broker relies on ---------
//
// A custodian runs its own key broker, so whatever it pins or binds there
// it could invent. Two facts it cannot invent alone are signed by the
// control plane, with its service key under domains of their own, and
// checked by the custodian's broker under the control-plane key pinned
// there: which governance key a lineage owner has (an attestation from the
// control plane's record of approved keys), and that a release record is
// the one the control plane validated against the result's real ancestry
// (a co-signature made when it registered the derived result).

pub const CONTROL_STATEMENT_VERSION: u32 = 1;
/// Domain of the control plane's attestation of a governance key.
pub const GOVERNANCE_KEY_ATTESTATION: &str = "encompute.governance-key-attestation.v1";
/// Domain of the control plane's co-signature of a derived result's
/// release record.
pub const DERIVED_RELEASE_COSIGNATURE: &str = "encompute.derived-release-cosignature.v1";

/// A statement signed by the control plane's service key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSigned<T> {
    pub body: T,
    /// The control plane's service ID.
    pub issuer: String,
    /// Its service public key (hex Ed25519).
    pub issuer_public_key: String,
    pub signature: String,
}

impl<T: Serialize> ControlSigned<T> {
    pub(crate) fn sign_as(domain: &str, body: T, signer: &ServiceSigner) -> Result<Self> {
        Ok(Self {
            signature: signer.sign(domain, &body)?,
            issuer: signer.id().to_owned(),
            issuer_public_key: signer.public_key_hex(),
            body,
        })
    }

    /// Signed under `domain` by `control_key` (hex): the control-plane key
    /// the caller pinned, never the statement's own key alone.
    pub(crate) fn verify_as(&self, domain: &str, control_key: &str) -> Result<()> {
        if self.issuer_public_key != control_key {
            return Err(err("not signed by the pinned control-plane key"));
        }
        verify_signed(control_key, domain, &self.body, &self.signature)
            .map_err(|_| err("the control plane's signature is invalid"))
    }
}

/// The control plane's attestation of an organization's governance key, from
/// its own record of approved keys: active (the key the organization signs
/// with now) or revoked (from `revoked_at` on). A custodian's broker pins a
/// lineage owner's key only from an active one, replaces it only with a
/// newer one, and unpins it on a revoked one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceKeyAttestation {
    pub version: u32,
    pub organization: String,
    /// [`governance_key_id`] of `public_key`.
    pub key_id: String,
    /// Hex Ed25519 public key.
    pub public_key: String,
    pub status: GovernanceKeyStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    /// When the control plane attested it (Unix seconds): of two
    /// attestations for one organization, the later one wins.
    pub issued_at: u64,
}

pub type SignedGovernanceKeyAttestation = ControlSigned<GovernanceKeyAttestation>;

impl GovernanceKeyAttestation {
    /// The key it attests.
    pub fn key(&self) -> GovernanceKey {
        GovernanceKey {
            organization: self.organization.clone(),
            public_key: self.public_key.clone(),
            status: self.status,
            revoked_at: self.revoked_at,
        }
    }

    /// Version 1, a well-formed key whose ID is `key_id`.
    pub fn check(&self) -> Result<()> {
        if self.version != CONTROL_STATEMENT_VERSION {
            return Err(err(format!(
                "governance key attestation version {}",
                self.version
            )));
        }
        self.key().check()?;
        if self.key_id != governance_key_id(&self.public_key) {
            return Err(err("the attested key ID is not the key's"));
        }
        Ok(())
    }

    pub fn sign(self, signer: &ServiceSigner) -> Result<SignedGovernanceKeyAttestation> {
        self.check()?;
        ControlSigned::sign_as(GOVERNANCE_KEY_ATTESTATION, self, signer)
    }
}

impl SignedGovernanceKeyAttestation {
    /// Well formed and signed by `control_key` (hex).
    pub fn verify(&self, control_key: &str) -> Result<()> {
        self.body.check()?;
        self.verify_as(GOVERNANCE_KEY_ATTESTATION, control_key)
    }
}

/// The control plane's co-signature of a derived result's release record:
/// made when it registered the result, after checking the record against
/// the result's real ancestry (its parents, the authorizations it was
/// released under and every lineage owner, under its active governance
/// key). The custodian's broker binds the result's key only to a record
/// the control plane co-signed, so a custodian cannot bind a record that
/// leaves a lineage owner out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedReleaseCosignature {
    pub version: u32,
    /// The custodian.
    pub organization: String,
    /// The derived asset's ID at the control plane.
    pub asset_id: String,
    /// The custodian's key broker and the key's reference there.
    pub broker: String,
    pub key_ref: String,
    /// Hex `AssetVersionId` of the derived result.
    pub derived_version_id: String,
    /// [`ReleaseRecord::id`] of the record the control plane validated.
    pub release_record_id: String,
    /// The lineage owners it validated (as the record names them).
    pub lineage_owners: BTreeMap<String, String>,
    pub issued_at: u64,
}

pub type SignedDerivedReleaseCosignature = ControlSigned<DerivedReleaseCosignature>;

impl DerivedReleaseCosignature {
    pub fn check(&self) -> Result<()> {
        if self.version != CONTROL_STATEMENT_VERSION {
            return Err(err(format!(
                "derived release co-signature version {}",
                self.version
            )));
        }
        check_label("organization", &self.organization)?;
        check_label("asset", &self.asset_id)?;
        check_label("broker", &self.broker)?;
        check_label("key reference", &self.key_ref)?;
        check_hex32("derived version ID", &self.derived_version_id)?;
        check_hex32("release record ID", &self.release_record_id)?;
        for (o, k) in &self.lineage_owners {
            check_label("lineage owner", o)?;
            check_hex32("lineage owner's governance key ID", k)?;
        }
        Ok(())
    }

    pub fn sign(self, signer: &ServiceSigner) -> Result<SignedDerivedReleaseCosignature> {
        self.check()?;
        ControlSigned::sign_as(DERIVED_RELEASE_COSIGNATURE, self, signer)
    }
}

impl SignedDerivedReleaseCosignature {
    /// Well formed and signed by `control_key` (hex).
    pub fn verify(&self, control_key: &str) -> Result<()> {
        self.body.check()?;
        self.verify_as(DERIVED_RELEASE_COSIGNATURE, control_key)
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
