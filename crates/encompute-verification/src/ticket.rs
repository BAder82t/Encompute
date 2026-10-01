//! Release tickets (governed projects): the control plane's short-lived,
//! single-use request to an owner's key broker for one release in one
//! scheduled job.
//!
//! In a governed project an owner's broker releases a key only with both
//! the owner's signed authorization and a valid ticket. A ticket alone
//! releases nothing (the control plane cannot sign an authorization), and
//! an authorization alone releases nothing either: without a single-use,
//! job-bound ticket it could be replayed for any attested session.
//!
//! A ticket is signed by the control plane's service key under its own
//! domain ([`KEY_TICKET`]) and lives at most [`MAX_TICKET_TTL_SECS`]. It
//! carries the full [`ExecutionSpec`] and [`GovernanceBinding`] its IDs
//! name, so a broker can recompute both and check them against what the
//! workload attested, and against the owner's authorization.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use encompute_ir::{Code, Error, Result};

use crate::governance::{is_hex32, GovernanceBinding};
use crate::hash::hex;
use crate::service::{verify_signed, ServiceSigner};
use crate::ExecutionSpec;

/// Domain of the control plane's signature over a ticket.
pub const KEY_TICKET: &str = "encompute.key-release-ticket.v1";
pub const TICKET_VERSION: u32 = 1;
/// A ticket's window (`not_after - not_before`) is at most this long.
pub const MAX_TICKET_TTL_SECS: u64 = 300;
/// Clock skew allowed when validating a ticket, always toward denial: a
/// ticket is refused from `not_after - TICKET_SKEW_SECS` on, and never
/// accepted before `not_before`.
pub const TICKET_SKEW_SECS: u64 = 60;

fn refuse(msg: impl Into<String>) -> Error {
    Error::new(Code::GovernanceReleaseTicket, msg)
}

fn check_hex32(what: &str, s: &str) -> Result<()> {
    if is_hex32(s) {
        Ok(())
    } else {
        Err(refuse(format!(
            "the ticket's {what} must be 32 bytes of lowercase hex"
        )))
    }
}

fn check_label(what: &str, s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 200 || s.chars().any(|c| c.is_control()) {
        return Err(refuse(format!(
            "the ticket's {what} must be 1-200 printable characters"
        )));
    }
    Ok(())
}

/// What a ticket asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketKind {
    /// An asset key, released to an attested workload.
    KeyRelease,
    /// A decryption by a recipient.
    Decrypt,
    /// An export of a released result.
    Export,
}

/// A control-plane release ticket. Every field is signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTicket {
    pub version: u32,
    /// 32 random bytes (hex): a broker accepts each ticket once.
    pub ticket_id: String,
    pub kind: TicketKind,
    /// The owner organization whose broker the ticket is for.
    pub organization: String,
    /// The broker's ID.
    pub broker: String,
    /// Hex `AssetVersionId` of the source whose key is asked for.
    pub asset_version_id: String,
    /// Hex IDs of the authorizations the job runs under.
    pub authorization_ids: BTreeSet<String>,
    pub job_id: String,
    pub project: String,
    /// Hex `PurposeId`.
    pub purpose_id: String,
    /// Hex `GovernanceId` of [`binding`](Self::binding).
    pub governance_id: String,
    /// Hex PlanId of the job's confidential execution plan.
    pub plan_id: String,
    /// Hex `ExecutionSpecId` of [`execution_spec`](Self::execution_spec).
    pub execution_spec_id: String,
    /// Hex `PolicyId`, as the spec names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// For a key release, the scheduled evaluator's receipt key (hex
    /// Ed25519, as the workload binding names it); for an export, the
    /// recipient's export key (hex X25519) as the custodian's signed
    /// release record names it: the key is sealed to it.
    pub workload_or_recipient: String,
    /// For an export, the recipient organization (and only then). Skipped
    /// when absent, so key-release tickets are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// The binding's placement digest, when it declares placement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_digest: Option<String>,
    pub execution_spec: ExecutionSpec,
    pub binding: GovernanceBinding,
    pub not_before: u64,
    pub not_after: u64,
    /// The control plane's state-anchor counter when the ticket was issued
    /// (carried; not yet enforced).
    pub anchor_counter: u64,
    /// The control plane's service ID and key (hex Ed25519).
    pub issuer: String,
    pub issuer_public_key: String,
    #[serde(default)]
    pub signature: String,
}

impl ReleaseTicket {
    /// A fresh random ticket ID (hex).
    pub fn new_ticket_id() -> Result<String> {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).map_err(|e| refuse(format!("no randomness: {e}")))?;
        Ok(hex(&b))
    }

    /// The signed part (everything but the signature).
    pub fn unsigned(&self) -> Self {
        Self {
            signature: String::new(),
            ..self.clone()
        }
    }

    /// Signs the ticket as `signer` (the control plane), naming it as the
    /// issuer.
    pub fn sign(mut self, signer: &ServiceSigner) -> Result<Self> {
        self.issuer = signer.id().to_owned();
        self.issuer_public_key = signer.public_key_hex();
        self.signature = String::new();
        self.signature = signer.sign(KEY_TICKET, &self)?;
        Ok(self)
    }

    /// Checks the ticket was signed by `control_key` (the pinned control
    /// plane's key, hex), is consistent ([`check_consistent`]), has a
    /// window of at most [`MAX_TICKET_TTL_SECS`], and is valid at `now`
    /// with the skew applied toward denial. Whether it matches the request
    /// and has been seen before is the broker's check.
    ///
    /// [`check_consistent`]: Self::check_consistent
    pub fn verify(&self, control_key: &str, now: u64) -> Result<()> {
        self.verify_signature(control_key)?;
        self.check_window(now)
    }

    /// The time-independent part of [`verify`](Self::verify): the version,
    /// the signature by `control_key`, consistency and the window's length.
    /// Nothing else in a ticket is trustworthy before this passes.
    pub fn verify_signature(&self, control_key: &str) -> Result<()> {
        if self.version != TICKET_VERSION {
            return Err(refuse(format!("release ticket version {}", self.version)));
        }
        if self.issuer_public_key != control_key {
            return Err(refuse(
                "the release ticket was not issued by the pinned control plane",
            ));
        }
        verify_signed(control_key, KEY_TICKET, &self.unsigned(), &self.signature)
            .map_err(|_| refuse("the release ticket's signature is invalid"))?;
        self.check_consistent()?;
        if self.not_after <= self.not_before
            || self.not_after - self.not_before > MAX_TICKET_TTL_SECS
        {
            return Err(refuse(format!(
                "a release ticket's window is at most {MAX_TICKET_TTL_SECS} seconds"
            )));
        }
        Ok(())
    }

    /// Valid at `now`, with the skew applied toward denial: never before
    /// `not_before`, and not in the last [`TICKET_SKEW_SECS`] of the window.
    pub fn check_window(&self, now: u64) -> Result<()> {
        if now < self.not_before {
            return Err(refuse("the release ticket is not valid yet"));
        }
        if now.saturating_add(TICKET_SKEW_SECS) >= self.not_after {
            return Err(refuse("the release ticket has expired"));
        }
        Ok(())
    }

    /// The ticket agrees with itself: well-formed IDs, a carried spec and
    /// binding that are the ones its IDs name, and a body (project,
    /// purpose, policy, placement, asset version and organization) that
    /// agrees with them. A key-release ticket's version is a source of its
    /// organization in the binding; an export ticket names its recipient
    /// (its version is the derived result's).
    pub fn check_consistent(&self) -> Result<()> {
        check_hex32("ticket ID", &self.ticket_id)?;
        check_label("organization", &self.organization)?;
        check_label("broker", &self.broker)?;
        check_label("job", &self.job_id)?;
        check_label("project", &self.project)?;
        check_hex32("asset version ID", &self.asset_version_id)?;
        check_hex32("purpose ID", &self.purpose_id)?;
        check_hex32("governance ID", &self.governance_id)?;
        check_hex32("plan ID", &self.plan_id)?;
        check_hex32("execution spec ID", &self.execution_spec_id)?;
        check_hex32("workload or recipient key", &self.workload_or_recipient)?;
        for d in [&self.policy_id, &self.placement_digest]
            .into_iter()
            .flatten()
        {
            check_hex32("policy or placement digest", d)?;
        }
        if self.authorization_ids.is_empty() {
            return Err(refuse("a release ticket names at least one authorization"));
        }
        for a in &self.authorization_ids {
            check_hex32("authorization ID", a)?;
        }
        self.binding
            .check()
            .map_err(|e| refuse(format!("the ticket's binding: {}", e.message)))?;
        if self.binding.id().hex() != self.governance_id {
            return Err(refuse(
                "the ticket's governance binding is not the one its governance ID names",
            ));
        }
        if self.execution_spec.id().hex() != self.execution_spec_id {
            return Err(refuse(
                "the ticket's execution spec is not the one its spec ID names",
            ));
        }
        if self.execution_spec.governance_id.as_deref() != Some(self.governance_id.as_str()) {
            return Err(refuse(
                "the ticket's execution spec is not governed by its binding",
            ));
        }
        if self.binding.project != self.project || self.binding.purpose_id != self.purpose_id {
            return Err(refuse(
                "the ticket's project or purpose is not its binding's",
            ));
        }
        if self.execution_spec.policy_id != self.policy_id {
            return Err(refuse("the ticket's policy is not its spec's"));
        }
        if self.binding.placement_digest != self.placement_digest {
            return Err(refuse("the ticket's placement is not its binding's"));
        }
        match (self.kind, &self.recipient) {
            // An export is of a derived result, held by its custodian: the
            // version is not one of the job's sources, and the ticket names
            // the one recipient it is for.
            (TicketKind::Export, Some(r)) => check_label("recipient", r)?,
            (TicketKind::Export, None) => {
                return Err(refuse("an export ticket names its recipient"))
            }
            (_, Some(_)) => return Err(refuse("only an export ticket names a recipient")),
            (_, None) => {
                if !self.binding.inputs.values().any(|i| {
                    i.asset_version_id == self.asset_version_id
                        && i.organization == self.organization
                }) {
                    return Err(refuse(
                        "the ticket's asset version is not a source of its organization in the binding",
                    ));
                }
            }
        }
        Ok(())
    }
}
