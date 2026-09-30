//! Governed release: the owner's broker is the final release authority.
//!
//! A key bound to a source version ([`KeyBroker::bind_version`]) is
//! released only when both are present:
//!
//! 1. the owner's signed authorization, installed at this broker and
//!    verified under the owner's pinned governance key; and
//! 2. a control-plane release ticket: short-lived, single-use, signed by
//!    the pinned control-plane key, and matching the request.
//!
//! A ticket without an authorization releases nothing, so a compromised
//! control plane can only deny. An authorization without a ticket releases
//! nothing either, so it cannot be replayed outside a scheduled job.
//!
//! [`KeyBroker::prepare_governed_release`] runs the checks in a fixed
//! order and refuses at the first failure; it records the ticket as used
//! and counts the release. The caller then persists the state (the file,
//! then the generation mark in the organization's KMS, when configured) and
//! only then calls [`KeyBroker::finish_release`], which seals the key: a
//! release that was not persisted grants nothing. A governed production
//! broker needs a generation mark.

use std::fmt;

use serde::{Deserialize, Serialize};

use encompute_attestation::{
    seal_grant, EncryptedKeyGrant, GrantGovernanceHeader, GrantHeader, KeyReleaseReceipt,
    WorkloadBinding, GRANT_VERSION_GOVERNED, RELEASE_RECEIPT_VERSION,
};
use encompute_ir::{Code, Error, Result};
use encompute_trust::authz::{
    GovernanceKey, GovernanceKeyStatus, RevocationV2, SignedAuthorizationV2, SignedRevocationV2,
    AUTHORIZATION_V2_VERSION,
};
use encompute_verification::governance::{is_hex32, GovernanceBinding, ReleaseClass};
use encompute_verification::ticket::{ReleaseTicket, TicketKind, TICKET_SKEW_SECS};
use encompute_verification::ExecutionSpec;

use crate::{err, AuthCounter, BrokerMode, KeyBroker, KeyContext};

/// Authorizations installed at once.
const MAX_AUTHORIZATIONS: usize = 4096;
/// Used tickets kept at once (each until its end plus the skew).
const MAX_SEEN_TICKETS: usize = 65_536;
/// Revocations recorded at once. A revocation is kept for good (so the
/// authorization is never reinstalled); past this many, new ones are
/// refused rather than older ones dropped.
pub const MAX_REVOKED_AUTHORIZATIONS: usize = 16_384;

/// A governed broker's runtime configuration (not part of its state).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceConfig {
    /// The control plane's service key (hex Ed25519): only tickets it
    /// signed are accepted.
    pub control_key: String,
    /// Whether every governed release needs a ticket. `false` is a
    /// development escape for air-gapped trials only: it is refused unless
    /// the broker is in development mode and `ENCOMPUTE_ENV=development`.
    /// The owner's authorization is required either way.
    pub require_ticket: bool,
}

/// A workload's request for one governed key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedReleaseRequest {
    /// The attested session's handle ([`crate::SessionInfo::session`]).
    pub session: String,
    pub asset_id: String,
    /// Hex ID of the owner's authorization the release is under.
    pub authorization_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<ReleaseTicket>,
    /// Without a ticket (development escape only): the execution spec and
    /// governance binding the workload attested. With a ticket they come
    /// from the ticket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_spec: Option<ExecutionSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<GovernanceBinding>,
}

/// What `POST /v1/release/governed` returns.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedGrant {
    pub grant: EncryptedKeyGrant,
    pub receipt: KeyReleaseReceipt,
}

/// A release whose checks passed and which is counted in the broker's
/// state, but not yet sealed. Persist the state, then pass it to
/// [`KeyBroker::finish_release`]; dropped, it grants nothing (and stays
/// counted).
pub struct PendingRelease {
    broker_id: String,
    asset_id: String,
    key_version: u64,
    authorization_id: String,
    header: GrantHeader,
    binding: WorkloadBinding,
    receipt: KeyReleaseReceipt,
}

impl PendingRelease {
    pub fn asset_id(&self) -> &str {
        &self.asset_id
    }

    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }

    pub fn job_id(&self) -> Option<&str> {
        self.receipt.job_id.as_deref()
    }
}

impl fmt::Debug for PendingRelease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PendingRelease({} v{} under {})",
            self.asset_id, self.key_version, self.authorization_id
        )
    }
}

fn check_id(what: &str, s: &str) -> Result<()> {
    if is_hex32(s) {
        Ok(())
    } else {
        Err(err(
            Code::BadInput,
            format!("{what} must be 32 bytes of lowercase hex"),
        ))
    }
}

fn ticket_refused(msg: impl Into<String>) -> Error {
    err(Code::GovernanceReleaseTicket, msg)
}

impl KeyBroker {
    /// Accepts release tickets signed by `config.control_key`. A broker
    /// that does not require tickets must be a development broker in an
    /// environment that says, explicitly, `ENCOMPUTE_ENV=development`
    /// (ENC2605 otherwise).
    pub fn with_governance(self, config: GovernanceConfig) -> Result<Self> {
        let env = std::env::var("ENCOMPUTE_ENV").ok();
        self.with_governance_in(config, env.as_deref())
    }

    fn with_governance_in(mut self, config: GovernanceConfig, env: Option<&str>) -> Result<Self> {
        if !is_hex32(&config.control_key) {
            return Err(err(
                Code::InsecureConfiguration,
                "the control-plane key is a 32-byte Ed25519 public key in lowercase hex",
            ));
        }
        if !config.require_ticket
            && (self.state.mode != BrokerMode::Development || env != Some("development"))
        {
            return Err(err(
                Code::InsecureConfiguration,
                "key release without a release ticket is for air-gapped development only: it \
                 needs a development broker and ENCOMPUTE_ENV=development; elsewhere every \
                 governed release needs a ticket from the control plane",
            ));
        }
        if !config.require_ticket {
            eprintln!(
                "DEVELOPMENT ONLY: key broker {} releases governed keys without release tickets",
                self.state.broker_id
            );
        }
        self.governance = Some(config);
        Ok(self)
    }

    /// The control plane this broker accepts tickets from, if configured.
    pub fn governance(&self) -> Option<&GovernanceConfig> {
        self.governance.as_ref()
    }

    fn serving(&self) -> Result<String> {
        self.state.organization.clone().ok_or_else(|| {
            err(
                Code::KeyRelease,
                "this broker serves no organization yet: set it first (--organization)",
            )
        })
    }

    fn pinned_key(&self) -> Result<&GovernanceKey> {
        self.state.governance_key.as_ref().ok_or_else(|| {
            err(
                Code::GovernanceKeyRevoked,
                "no governance key is pinned at this broker: the owner pins it first \
                 (encompute keys governance-key pin)",
            )
        })
    }

    /// Pins the owner organization's governance key (hex Ed25519). It is
    /// set once: from then on the broker is governed, and only
    /// authorizations that key signed are installed.
    pub fn pin_governance_key(&mut self, public_key: &str) -> Result<()> {
        let organization = self.serving()?;
        let key = GovernanceKey {
            organization,
            public_key: public_key.to_owned(),
            status: GovernanceKeyStatus::Active,
            revoked_at: None,
        };
        key.check()?;
        match &self.state.governance_key {
            Some(k) if k.public_key == public_key => Ok(()),
            Some(k) => Err(err(
                Code::KeyRelease,
                format!(
                    "this broker's governance key is pinned already ({}); it is not replaced",
                    k.key_id()
                ),
            )),
            None => {
                self.state.governance_key = Some(key);
                Ok(())
            }
        }
    }

    /// Binds `asset_id`'s key to one source version (hex `AssetVersionId`).
    /// Set once: the same version again changes nothing, another is
    /// refused (ENC2704). A bound key is released only in a governed
    /// release.
    pub fn bind_version(&mut self, asset_id: &str, version_id: &str) -> Result<()> {
        check_id("an asset version ID", version_id)?;
        let s = self.secret_mut(asset_id)?;
        match &s.asset_version_id {
            Some(v) if v == version_id => Ok(()),
            Some(v) => Err(err(
                Code::GovernanceAssetVersionMismatch,
                format!("{asset_id} is bound to version {v}; a bound version never changes"),
            )),
            None => {
                s.asset_version_id = Some(version_id.to_owned());
                Ok(())
            }
        }
    }

    /// Installs an owner authorization after verifying it under the pinned
    /// governance key: it must be this organization's (ENC2701) and signed
    /// by that key (ENC2708). A revoked authorization is never reinstalled
    /// (ENC2706). Idempotent; returns its ID.
    pub fn install_authorization(&mut self, a: &SignedAuthorizationV2) -> Result<String> {
        let organization = self.serving()?;
        let key = self.pinned_key()?.public_key.clone();
        a.body.check()?;
        if a.body.party != organization {
            return Err(err(
                Code::GovernanceAuthorizationMissing,
                format!(
                    "an authorization of {} does not authorize releases of {organization}'s keys",
                    a.body.party
                ),
            ));
        }
        if a.public_key != key {
            return Err(err(
                Code::GovernanceKeyRevoked,
                "the authorization is not signed by the pinned governance key",
            ));
        }
        a.verify(&key).map_err(|e| {
            err(
                Code::GovernanceKeyRevoked,
                format!(
                    "the authorization does not verify under the pinned governance key: {}",
                    e.message
                ),
            )
        })?;
        let id = a.id();
        if self.state.revoked_authorizations.contains_key(&id) {
            return Err(err(
                Code::GovernanceAuthorizationRevoked,
                format!("authorization {id} was revoked; a revocation is never undone"),
            ));
        }
        if !self.state.authorizations.contains_key(&id)
            && self.state.authorizations.len() >= MAX_AUTHORIZATIONS
        {
            return Err(err(Code::KeyRelease, "too many installed authorizations"));
        }
        self.state.authorizations.insert(id.clone(), a.clone());
        Ok(id)
    }

    /// Applies the owner's signed revocation of an authorization, verified
    /// under the pinned governance key. It takes effect from its issue
    /// time; an earlier revocation of the same authorization stays.
    pub fn revoke_authorization_signed(&mut self, r: &SignedRevocationV2) -> Result<()> {
        let organization = self.serving()?;
        let key = self.pinned_key()?.public_key.clone();
        if r.body.party != organization {
            return Err(err(
                Code::GovernanceAuthorizationMissing,
                format!(
                    "a revocation by {} does not revoke {organization}'s authorizations",
                    r.body.party
                ),
            ));
        }
        if r.public_key != key {
            return Err(err(
                Code::GovernanceKeyRevoked,
                "the revocation is not signed by the pinned governance key",
            ));
        }
        r.verify(&key).map_err(|e| {
            err(
                Code::GovernanceKeyRevoked,
                format!(
                    "the revocation does not verify under the pinned governance key: {}",
                    e.message
                ),
            )
        })?;
        self.record_revocation(&r.body.authorization, r.body.issued_at)
    }

    /// Revokes an authorization at this broker, from `at` (default: now)
    /// on: the owner's act on its own broker, or a control plane's notice.
    /// It only denies, so it needs no signature, and it takes effect at
    /// once, without the control plane.
    /// It may name an authorization not installed yet, which is then never
    /// installed.
    pub fn revoke_authorization_local(&mut self, id: &str, at: Option<u64>) -> Result<()> {
        let at = at.unwrap_or_else(|| self.now());
        self.record_revocation(id, at)
    }

    /// A control plane's revocation notice (not signed by the owner): it
    /// only denies, and only for an authorization installed here. An
    /// unknown ID changes nothing (returns `false`), so a control plane
    /// cannot grow this broker's state.
    pub fn revoke_authorization_from_control(&mut self, id: &str, at: u64) -> Result<bool> {
        check_id("an authorization ID", id)?;
        if !self.state.authorizations.contains_key(id) {
            return Ok(false);
        }
        self.record_revocation(id, at)?;
        Ok(true)
    }

    fn record_revocation(&mut self, id: &str, at: u64) -> Result<()> {
        check_id("an authorization ID", id)?;
        let revoked = &mut self.state.revoked_authorizations;
        if let Some(t) = revoked.get_mut(id) {
            *t = (*t).min(at);
            return Ok(());
        }
        if revoked.len() >= MAX_REVOKED_AUTHORIZATIONS {
            return Err(err(
                Code::KeyRelease,
                format!(
                    "this broker holds {MAX_REVOKED_AUTHORIZATIONS} revoked authorizations, its \
                     limit; no further revocation is recorded"
                ),
            ));
        }
        revoked.insert(id.to_owned(), at);
        Ok(())
    }

    /// Checks a governed release in order and refuses at the first failure:
    ///
    /// 1. the session exists;
    /// 2. the key exists, is bound to a source version, and is neither
    ///    revoked nor expired;
    /// 3. the key's release policy (attestation, spec, policy) passes;
    /// 4. the authorization is installed, verifies under the pinned
    ///    governance key, is this organization's, and is not revoked here;
    /// 5. the attested execution (its spec and governance binding) is
    ///    covered by it: project, purpose, source version, program, policy,
    ///    privacy policy, linkage, spec pin and releases;
    /// 6. `valid_from <= now < valid_until` on this broker's clock, and the
    ///    attestation was issued before `valid_until`;
    /// 7. no placement is declared (attested placement cannot be verified
    ///    yet, and missing evidence never passes);
    /// 8. the ticket is signed by the pinned control plane, consistent,
    ///    inside its window (skew toward denial), for this organization,
    ///    broker, version, authorization, evaluator and spec, a key-release
    ///    ticket, and not seen before;
    /// 9. the authorization's limits allow the release.
    ///
    /// Then the ticket is recorded as used and the release counted, before
    /// any key is unwrapped.
    pub fn prepare_governed_release(
        &mut self,
        req: &GovernedReleaseRequest,
    ) -> Result<PendingRelease> {
        // A governed production broker without a generation mark could
        // have its counters and used tickets undone by a restored file.
        self.check_generation_mark()?;
        let now = self.now();
        self.prune(now);
        // 1. The session.
        let s = self.sessions.get(&req.session).ok_or_else(|| {
            err(
                Code::KeyRelease,
                "no attested session (keys are released only after attestation)",
            )
        })?;
        let w = &s.workload.binding;
        // 2. The key.
        let asset_id = req.asset_id.as_str();
        let secret = self
            .state
            .secrets
            .get(asset_id)
            .ok_or_else(|| err(Code::KeyRelease, format!("no key for asset {asset_id}")))?;
        if secret.versions[&secret.key_version].revoked {
            return Err(err(
                Code::KeyRelease,
                format!(
                    "key version {} of {asset_id} is revoked",
                    secret.key_version
                ),
            ));
        }
        if secret.expired {
            return Err(err(Code::KeyRelease, format!("{asset_id} has expired")));
        }
        let version_id = secret.asset_version_id.clone().ok_or_else(|| {
            err(
                Code::GovernanceAssetVersionMismatch,
                format!(
                    "the key of {asset_id} is bound to no source version: its owner binds it \
                     first (encompute keys bind-version)"
                ),
            )
        })?;
        // 3. The release policy.
        let policy = &secret.release_policy;
        policy.check(&s.workload)?;
        if s.workload
            .issued_at
            .is_none_or(|t| now > t.saturating_add(policy.max_evidence_age_secs))
        {
            return Err(err(
                Code::Freshness,
                "the attestation is stale for this asset",
            ));
        }
        // 4. The owner's authorization.
        let organization = self.serving()?;
        let key = self.pinned_key()?;
        let id = req.authorization_id.as_str();
        let signed = self.state.authorizations.get(id).ok_or_else(|| {
            err(
                Code::GovernanceAuthorizationMissing,
                format!("authorization {id} is not installed at this broker"),
            )
        })?;
        let a = &signed.body;
        if a.party != organization {
            return Err(err(
                Code::GovernanceAuthorizationMissing,
                format!("authorization {id} is not {organization}'s"),
            ));
        }
        signed.verify(&key.public_key).map_err(|e| {
            err(
                Code::GovernanceKeyRevoked,
                format!(
                    "authorization {id} does not verify under the pinned governance key: {}",
                    e.message
                ),
            )
        })?;
        let revoked_at = self.state.revoked_authorizations.get(id).copied();
        if revoked_at.is_some_and(|t| now >= t) {
            return Err(err(
                Code::GovernanceAuthorizationRevoked,
                format!("authorization {id} was revoked at this broker"),
            ));
        }
        // A ticket's contents are used only once it is known to come from
        // the pinned control plane: its signature and consistency are
        // checked here, before check 5 reads its spec and binding, so an
        // unsigned ticket never reaches coverage, window or placement
        // checks (and cannot probe them). Its time window, whether it
        // matches the request and whether it was seen stay at check 8.
        if let Some(t) = &req.ticket {
            let g = self.governance.as_ref().ok_or_else(|| {
                ticket_refused(
                    "no control-plane key is configured at this broker: it accepts no release \
                     ticket",
                )
            })?;
            t.verify_signature(&g.control_key)?;
        }
        // 5. Coverage of the attested execution.
        let (spec, binding, from_ticket) = match (&req.ticket, &req.execution_spec, &req.binding) {
            (Some(t), None, None) => (&t.execution_spec, &t.binding, true),
            (None, Some(spec), Some(b)) => (spec, b, false),
            (Some(_), _, _) => {
                return Err(ticket_refused(
                    "with a ticket, the execution spec and binding come from the ticket",
                ))
            }
            (None, _, _) => {
                return Err(ticket_refused(
                    "a governed release needs a release ticket from the control plane",
                ))
            }
        };
        let not_attested = |what: &str| {
            err(
                if from_ticket {
                    Code::GovernanceReleaseTicket
                } else {
                    Code::GovernanceProgramNotAuthorized
                },
                format!("the {what} is not the execution the workload attested"),
            )
        };
        let spec_id = spec.id().hex();
        if spec_id != w.execution_spec_id {
            return Err(not_attested("execution spec"));
        }
        if spec.governance_id.as_deref() != Some(binding.id().hex().as_str()) {
            return Err(not_attested("governance binding"));
        }
        if spec.policy_id != w.policy_id || spec.privacy_policy_id != w.privacy_policy_id {
            return Err(not_attested("policy"));
        }
        binding.check().map_err(|e| not_attested(&e.message))?;
        // The binding's per-asset broker map, when it has one: this key is
        // released here only if the map gives it to this broker.
        if !binding.asset_brokers.is_empty() {
            match binding.asset_brokers.get(asset_id) {
                Some(b) if b == self.id() => {}
                other => {
                    return Err(err(
                        Code::GovernanceCustody,
                        format!(
                            "the governance binding gives {asset_id}'s key to {}, not to this \
                             broker ({}): nothing is released",
                            other.map_or("no key broker", String::as_str),
                            self.id()
                        ),
                    ))
                }
            }
        }
        if binding.project != a.project || binding.purpose_id != a.purpose_id {
            return Err(err(
                Code::GovernancePurposeMismatch,
                format!("authorization {id} is for another project or purpose"),
            ));
        }
        if a.asset_version_id != version_id {
            return Err(err(
                Code::GovernanceAssetVersionMismatch,
                format!("authorization {id} is for another version of {asset_id}"),
            ));
        }
        if !binding.inputs.values().any(|i| {
            i.asset_version_id == a.asset_version_id
                && i.organization == a.party
                && i.digest_commitment == a.asset_digest_commitment
        }) {
            return Err(err(
                Code::GovernanceAssetVersionMismatch,
                "the execution does not use the authorized version as a source of its owner",
            ));
        }
        let program = |m: &str| err(Code::GovernanceProgramNotAuthorized, m.to_owned());
        if !a.program.covers(&spec.program_id) {
            return Err(program("the owner did not authorize this program"));
        }
        if spec.policy_id.as_deref() != Some(a.policy_id.as_str()) {
            return Err(program(
                "the program runs under another confidentiality policy than the owner authorized",
            ));
        }
        if spec.privacy_policy_id != a.privacy_policy_id {
            return Err(program(
                "the program runs under another privacy policy than the owner authorized",
            ));
        }
        if a.execution_spec_ids
            .as_ref()
            .is_some_and(|ids| !ids.contains(&spec_id))
        {
            return Err(program(
                "the owner's authorization is pinned to other execution specs",
            ));
        }
        if binding.linkage_policy_id != a.linkage_policy_id {
            return Err(err(
                Code::GovernanceLinkageMismatch,
                "the execution uses another linkage policy than the owner authorized",
            ));
        }
        for (name, o) in &binding.outputs {
            let class_ok =
                o.release_class == a.release_class || o.release_class == ReleaseClass::Never;
            if !class_ok || !o.recipients.is_subset(&a.recipients) {
                return Err(err(
                    Code::GovernanceReleaseClass,
                    format!("output {name} releases more, or to others, than the owner authorized"),
                ));
            }
        }
        // 6. The window, on this broker's clock, strictly.
        if !a.is_valid_at(now) {
            return Err(err(
                Code::GovernanceAuthorizationExpired,
                format!(
                    "authorization {id} is valid from {} until {}, not at {now}",
                    a.valid_from, a.valid_until
                ),
            ));
        }
        if s.workload.issued_at.is_none_or(|t| t >= a.valid_until) {
            return Err(err(
                Code::GovernanceAuthorizationExpired,
                format!("the attestation was not issued before authorization {id} ended"),
            ));
        }
        let revocation = revoked_at.map(|t| RevocationV2 {
            version: AUTHORIZATION_V2_VERSION,
            party: a.party.clone(),
            authorization: id.to_owned(),
            reason: "revoked at the key broker".into(),
            issued_at: t,
        });
        signed.usable_at(key, revocation.as_ref(), now)?;
        // 7. Placement: declared placement needs attested evidence, which
        // cannot be verified yet; missing evidence never passes.
        if binding.placement_digest.is_some() {
            return Err(err(
                Code::GovernanceResidency,
                "the execution declares placement constraints, and this broker cannot verify \
                 attested placement yet: no key is released",
            ));
        }
        // 8. The ticket.
        match (&req.ticket, &self.governance) {
            (None, Some(g)) if !g.require_ticket => {}
            (None, _) => {
                return Err(ticket_refused(
                    "a governed release needs a release ticket from the control plane",
                ))
            }
            (Some(_), None) => {
                return Err(ticket_refused(
                    "no control-plane key is configured at this broker: it accepts no release \
                     ticket",
                ))
            }
            (Some(t), Some(_)) => {
                // Signature and consistency were verified before check 5.
                t.check_window(now)?;
                if t.kind != TicketKind::KeyRelease {
                    return Err(ticket_refused("the ticket is not a key-release ticket"));
                }
                if t.organization != organization || t.broker != self.state.broker_id {
                    return Err(ticket_refused(
                        "the ticket is for another organization or broker",
                    ));
                }
                if t.asset_version_id != version_id {
                    return Err(ticket_refused("the ticket is for another source version"));
                }
                if !t.authorization_ids.contains(id) {
                    return Err(ticket_refused(format!(
                        "the ticket does not name authorization {id}"
                    )));
                }
                if t.workload_or_recipient != w.evaluator_public_key {
                    return Err(ticket_refused("the ticket was issued to another evaluator"));
                }
                if t.execution_spec_id != w.execution_spec_id
                    || t.project != a.project
                    || t.purpose_id != a.purpose_id
                {
                    return Err(ticket_refused("the ticket is for another execution"));
                }
                if self.state.seen_tickets.contains_key(&t.ticket_id) {
                    return Err(ticket_refused("the ticket was already used"));
                }
            }
        }
        // 9. The owner's limits.
        let job = match &req.ticket {
            Some(t) => t.job_id.clone(),
            None => format!("session:{}", s.info.workload_session_id),
        };
        let counter = self.state.counters.get(id).cloned().unwrap_or_default();
        let limit = |m: String| err(Code::GovernanceAuthorizationLimit, m);
        if let Some(max) = a.limits.max_releases {
            if counter.releases >= max {
                return Err(limit(format!(
                    "authorization {id} allows {max} key release(s); all are used"
                )));
            }
        }
        if let Some(max) = a.limits.max_executions {
            if !counter.jobs.contains(&job) && counter.jobs.len() as u64 >= max {
                return Err(limit(format!(
                    "authorization {id} allows {max} job(s); all are used"
                )));
            }
        }
        if req.ticket.is_some() && self.state.seen_tickets.len() >= MAX_SEEN_TICKETS {
            return Err(ticket_refused("too many open tickets; retry later"));
        }

        // Everything the grant and receipt state, before recording.
        let header = GrantHeader {
            version: GRANT_VERSION_GOVERNED,
            broker_id: self.state.broker_id.clone(),
            asset_id: asset_id.to_owned(),
            key_version: secret.key_version,
            policy_id: w.policy_id.clone(),
            execution_spec_id: w.execution_spec_id.clone(),
            session_id: s.info.workload_session_id.clone(),
            binding_hash: s.info.session.clone(),
            attestation_digest: s.info.attestation_digest.clone(),
            expires_at: s.info.expires_at.min(a.valid_until),
            broker_public_key: self.grant_signer.public_key_hex(),
            governance: Some(GrantGovernanceHeader {
                authorization_id: id.to_owned(),
                project: a.project.clone(),
                purpose_id: a.purpose_id.clone(),
                valid_until: a.valid_until,
                ticket_id: req.ticket.as_ref().map(|t| t.ticket_id.clone()),
            }),
        };
        let receipt = KeyReleaseReceipt {
            version: RELEASE_RECEIPT_VERSION,
            broker_id: self.state.broker_id.clone(),
            organization,
            asset_id: asset_id.to_owned(),
            asset_version_id: version_id,
            key_version: secret.key_version,
            authorization_id: id.to_owned(),
            ticket_id: req.ticket.as_ref().map(|t| t.ticket_id.clone()),
            job_id: req.ticket.as_ref().map(|t| t.job_id.clone()),
            project: a.project.clone(),
            purpose_id: a.purpose_id.clone(),
            execution_spec_id: w.execution_spec_id.clone(),
            session_id: s.info.workload_session_id.clone(),
            binding_hash: s.info.session.clone(),
            attestation_digest: s.info.attestation_digest.clone(),
            grant_digest: String::new(),
            released_at: now,
            broker_public_key: String::new(),
            signature: String::new(),
        };
        let pending = PendingRelease {
            broker_id: self.state.broker_id.clone(),
            asset_id: asset_id.to_owned(),
            key_version: secret.key_version,
            authorization_id: id.to_owned(),
            header,
            binding: w.clone(),
            receipt,
        };
        let limits_jobs = a.limits.max_executions.is_some();
        // Recorded now: the ticket is spent and the release counted, even
        // if the release is never finished.
        if let Some(t) = &req.ticket {
            self.state.seen_tickets.insert(
                t.ticket_id.clone(),
                t.not_after.saturating_add(TICKET_SKEW_SECS),
            );
        }
        let c: &mut AuthCounter = self.state.counters.entry(id.to_owned()).or_default();
        c.releases += 1;
        if limits_jobs {
            c.jobs.insert(job);
        }
        Ok(pending)
    }

    /// Seals the key of a prepared release to its session and signs the
    /// grant (version 3) and a key-release receipt. Call it only after the
    /// state recording the release was persisted. Refused if the key was
    /// revoked or rotated, or the authorization revoked, since.
    pub fn finish_release(
        &mut self,
        p: PendingRelease,
    ) -> Result<(EncryptedKeyGrant, KeyReleaseReceipt)> {
        let now = self.now();
        if p.broker_id != self.state.broker_id {
            return Err(err(
                Code::KeyRelease,
                "the release was prepared by another broker",
            ));
        }
        let secret = self
            .state
            .secrets
            .get(&p.asset_id)
            .ok_or_else(|| err(Code::KeyRelease, format!("no key for asset {}", p.asset_id)))?;
        let current = &secret.versions[&secret.key_version];
        if secret.key_version != p.key_version || current.revoked || secret.expired {
            return Err(err(
                Code::KeyRelease,
                format!(
                    "the key of {} changed since the release was prepared",
                    p.asset_id
                ),
            ));
        }
        if self
            .state
            .revoked_authorizations
            .get(&p.authorization_id)
            .is_some_and(|t| now >= *t)
        {
            return Err(err(
                Code::GovernanceAuthorizationRevoked,
                format!("authorization {} was revoked", p.authorization_id),
            ));
        }
        let key = self.store.unwrap_for_release(
            &KeyContext {
                broker_id: &self.state.broker_id,
                asset_id: &p.asset_id,
                version: p.key_version,
            },
            &current.key,
        )?;
        let grant = seal_grant(p.header, &p.binding, key.as_bytes(), &self.grant_signer)?;
        let receipt = KeyReleaseReceipt {
            grant_digest: grant.digest()?,
            ..p.receipt
        }
        .sign(&self.grant_signer)?;
        Ok((grant, receipt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broker(mode: BrokerMode) -> KeyBroker {
        let store: Box<dyn crate::SecretStore> = match mode {
            BrokerMode::Development => Box::new(crate::DevelopmentFileStore),
            BrokerMode::Production => Box::new(crate::LocalKekStore::from_key([5; 32])),
        };
        KeyBroker::new("b", mode, encompute_attestation::Verifier::new(), store).unwrap()
    }

    #[test]
    fn the_ticket_escape_needs_development_everywhere() {
        let cfg = |require_ticket| GovernanceConfig {
            control_key: "ab".repeat(32),
            require_ticket,
        };
        for (mode, env, ok) in [
            (BrokerMode::Development, Some("development"), true),
            (BrokerMode::Development, None, false),
            (BrokerMode::Development, Some("production"), false),
            (BrokerMode::Development, Some("Development"), false),
            (BrokerMode::Production, Some("development"), false),
        ] {
            let r = broker(mode).with_governance_in(cfg(false), env);
            assert_eq!(r.is_ok(), ok, "{mode:?} {env:?}");
            if let Err(e) = r {
                assert_eq!(e.code, Code::InsecureConfiguration);
            }
            // Requiring tickets is always allowed.
            broker(mode).with_governance_in(cfg(true), env).unwrap();
        }
        let bad = GovernanceConfig {
            control_key: "not-a-key".into(),
            require_ticket: true,
        };
        assert!(broker(BrokerMode::Development)
            .with_governance_in(bad, None)
            .is_err());
    }
}
