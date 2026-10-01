//! What each organization sees of a governed project: one static table,
//! applied on top of the cross-organization redaction every project gets
//! (an asset's storage and key references only to its owner, other
//! organizations' actors only as `organization/kind`).
//!
//! | Data | Owner | Other participants | Auditor organization |
//! |---|---|---|---|
//! | project, members, purposes, linkage | full | full | full |
//! | asset version used (ID, organization, series@version, digest, status) | full | yes | yes |
//! | `key_ref`, `storage_uri`, size, other versions, other projects | yes | no | no |
//! | owner authorizations | real approvers | (organization, role, time) and a pseudonym | same |
//! | job spec, program, purpose, `governance_id`, state, evaluator | full | yes | yes |
//! | grant, evaluator URL and receipt key, initiator, actors | submitter | labels | labels |
//! | privacy scope ledger | full | totals | totals and the entries |
//! | audit | own organization (others' people labelled) | the project's events | the project's events |
//!
//! "Owner" is the organization a record belongs to: the submitter of a
//! job, the owner of an authorization or asset. Everyone else who takes
//! part in the project gets the shared view, and the shared view depends
//! only on the record, never on who asks: it is byte-identical for every
//! member and auditor organization. An approver appears to others as a
//! pseudonym, HMAC-SHA256 over the project and the approver's principal ID
//! under a key only the control plane holds ([`PseudonymKey`]): stable
//! within a project (two approvals by one person are seen to be one
//! person's), unlinkable across projects, and not confirmable by someone
//! who learns a principal ID. Evaluators see a
//! governed job's grant and nothing else. An asset's privacy ledger stays
//! the owner's. A project's privacy scope has a ledger of its own: the other
//! members see its totals (cap, spent, remaining, entry count and root),
//! the auditor organizations also its entries, and nobody but the owner the
//! population it belongs to.

use std::collections::BTreeMap;

use postgres::GenericClient;
use serde_json::{json, Value};
use sha2::Sha256;

use encompute_ir::Result;
use encompute_verification::hex;

use crate::authn::Principal;
use crate::authz::ProjectRow;
use crate::db::db_err;
use crate::model::PLATFORM_ORG;

/// Who looks at a record of a governed project.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    /// The organization the record belongs to.
    Owner,
    /// Another member organization of the project.
    Participant,
    /// An auditor organization of the project.
    Auditor,
}

/// A row of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Data {
    Project,
    AssetVersionUsed,
    AssetStorage,
    AuthorizationApprovers,
    Job,
    JobExecution,
    PrivacyLedger,
    Audit,
}

/// How much of a row an audience sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shown {
    Full,
    /// The shared fields.
    Shared,
    Hidden,
    /// (organization, role, time) and a pseudonym per approver.
    Pseudonyms,
    /// Actors as `organization/kind`.
    Labels,
    OwnOrganization,
    ProjectEvents,
    /// A scope's cap, spending, entry count and root: never an entry.
    Totals,
    /// The totals, and the scope's entries to read.
    TotalsAndEntries,
}

/// The table: (data, owner, other participants, auditor organization).
pub const TABLE: [(Data, Shown, Shown, Shown); 8] = [
    (Data::Project, Shown::Full, Shown::Full, Shown::Full),
    (
        Data::AssetVersionUsed,
        Shown::Full,
        Shown::Shared,
        Shown::Shared,
    ),
    (
        Data::AssetStorage,
        Shown::Full,
        Shown::Hidden,
        Shown::Hidden,
    ),
    (
        Data::AuthorizationApprovers,
        Shown::Full,
        Shown::Pseudonyms,
        Shown::Pseudonyms,
    ),
    (Data::Job, Shown::Full, Shown::Shared, Shown::Shared),
    (
        Data::JobExecution,
        Shown::Full,
        Shown::Labels,
        Shown::Labels,
    ),
    (
        Data::PrivacyLedger,
        Shown::Full,
        Shown::Totals,
        Shown::TotalsAndEntries,
    ),
    (
        Data::Audit,
        Shown::OwnOrganization,
        Shown::ProjectEvents,
        Shown::ProjectEvents,
    ),
];

/// What `audience` sees of `data`.
pub fn shown(data: Data, audience: Audience) -> Shown {
    let (_, owner, participant, auditor) = TABLE
        .iter()
        .find(|(d, ..)| *d == data)
        .copied()
        .expect("every row is in the table");
    match audience {
        Audience::Owner => owner,
        Audience::Participant => participant,
        Audience::Auditor => auditor,
    }
}

/// How `p` looks at a record of `project` owned by `owner`: `None` when it
/// takes no part in the project.
pub fn audience(p: &Principal, project: &ProjectRow, owner: &str) -> Option<Audience> {
    if p.member_of(owner) {
        Some(Audience::Owner)
    } else if project.members.iter().any(|o| p.member_of(o)) {
        Some(Audience::Participant)
    } else if project.auditors.iter().any(|o| p.member_of(o)) {
        Some(Audience::Auditor)
    } else {
        None
    }
}

/// HKDF salt and info of the pseudonym key: its own label, so the key is
/// independent of every other use of the signing key.
const PSEUDONYM_SALT: &[u8] = b"encompute.control-plane.v1";
const PSEUDONYM_INFO: &[u8] = b"encompute.approver-pseudonym.v1";

/// The key approver pseudonyms are computed under: HKDF-SHA256 of the
/// control plane's signing seed (stable across restarts, required in
/// production, never leaving the server) with its own label. Without it,
/// knowing a principal ID does not confirm a pseudonym. A new signing key
/// gives new pseudonyms.
pub struct PseudonymKey(zeroize::Zeroizing<[u8; 32]>);

impl PseudonymKey {
    pub fn derive(signing_seed: &[u8; 32]) -> Self {
        let mut k = zeroize::Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<Sha256>::new(Some(PSEUDONYM_SALT), signing_seed)
            .expand(PSEUDONYM_INFO, k.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 length");
        Self(k)
    }

    /// An approver as other organizations see it: `psn_` + hex
    /// HMAC-SHA256(key, project ‖ 0x00 ‖ principal ID). The same for every
    /// viewer and stable per (project, principal); unlinkable across
    /// projects without the key.
    pub fn pseudonym(&self, project: &str, principal: &str) -> String {
        use hmac::Mac;
        let mut m = hmac::Hmac::<Sha256>::new_from_slice(self.0.as_ref())
            .expect("HMAC takes a key of any length");
        m.update(project.as_bytes());
        m.update(&[0u8]);
        m.update(principal.as_bytes());
        format!("psn_{}", hex(&m.finalize().into_bytes()))
    }
}

/// Labels principals the same way for every viewer: a platform principal
/// (evaluators, the scheduler) or something that is not a principal (the
/// control plane itself, an operator's recovery) as itself, anyone else as
/// `organization/kind`. Cached per ID.
#[derive(Default)]
pub struct Labels(BTreeMap<String, String>);

impl Labels {
    pub fn label(&mut self, c: &mut impl GenericClient, actor: &str) -> Result<String> {
        self.label_outside(c, actor, None)
    }

    /// [`Self::label`], except that `own`'s principals keep their IDs: an
    /// organization's own trail names its own people, and only labels
    /// another organization's (who invited it, removed it, or revoked what
    /// its jobs ran under).
    pub fn label_outside(
        &mut self,
        c: &mut impl GenericClient,
        actor: &str,
        own: Option<&str>,
    ) -> Result<String> {
        if let Some(l) = self.0.get(actor) {
            return Ok(match own {
                Some(o) if l.starts_with(&format!("{o}/")) => actor.to_owned(),
                _ => l.clone(),
            });
        }
        let owner = c
            .query_opt(
                "SELECT organization_id, 'user' FROM users WHERE id = $1
                 UNION ALL
                 SELECT organization_id, 'service' FROM service_accounts WHERE id = $1
                 LIMIT 1",
                &[&actor],
            )
            .map_err(db_err)?
            .map(|r| (r.get::<_, Option<String>>(0), r.get::<_, String>(1)));
        let l = match owner {
            Some((Some(org), kind)) if org != PLATFORM_ORG => format!("{org}/{kind}"),
            _ => actor.to_owned(),
        };
        self.0.insert(actor.to_owned(), l.clone());
        Ok(match own {
            Some(o) if l.starts_with(&format!("{o}/")) => actor.to_owned(),
            _ => l,
        })
    }
}

/// One approval as others see it: (organization, role, time) and the
/// approver's pseudonym, never the identity (issuer, subject, principal).
pub fn shared_approval(
    key: &PseudonymKey,
    project: &str,
    approver: &str,
    organization: &str,
    role: &str,
    at: u64,
) -> Value {
    json!({"organization": organization, "role": role, "at": at,
           "approver": key.pseudonym(project, approver)})
}

/// The keys of an audit event's references that are shared: identifiers of
/// the project's own records. Anything else (broker names and key
/// references, message IDs, principals, roles granted) stays with the
/// organization that wrote it.
const SHARED_AUDIT_REFS: [&str; 26] = [
    "approval",
    "asset",
    "asset_version",
    "authorization_id",
    "authorization_set",
    "check",
    "custody",
    "evaluator",
    "execution",
    "governance",
    "governance_key",
    "kind",
    "member",
    "name",
    "not_after",
    "owner",
    "plan",
    "plan_id",
    "program",
    "purpose",
    "reason",
    "revoked_asset",
    "role",
    "spec",
    "stage",
    "state",
];

/// An audit event of the project as every participant sees it: no request
/// ID or chain hashes, actors labelled, only the shared references.
pub fn shared_audit_event(
    c: &mut impl GenericClient,
    labels: &mut Labels,
    e: &crate::audit::AuditEvent,
) -> Result<Value> {
    let refs: BTreeMap<&String, &String> = e
        .refs
        .iter()
        .filter(|(k, _)| SHARED_AUDIT_REFS.contains(&k.as_str()))
        .collect();
    Ok(json!({
        "seq": e.seq, "at_us": e.at_us, "organization": e.organization,
        "actor": labels.label(c, &e.actor)?, "action": e.action,
        "resource_type": e.resource_type, "resource_id": e.resource_id,
        "project": e.project, "result": e.result, "refs": refs,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_row_is_in_the_table_once() {
        for d in [
            Data::Project,
            Data::AssetVersionUsed,
            Data::AssetStorage,
            Data::AuthorizationApprovers,
            Data::Job,
            Data::JobExecution,
            Data::PrivacyLedger,
            Data::Audit,
        ] {
            assert_eq!(TABLE.iter().filter(|(x, ..)| *x == d).count(), 1, "{d:?}");
        }
        // A scope's ledger: totals to the project's other members, totals
        // and the entries to its auditor organizations.
        assert_eq!(
            shown(Data::PrivacyLedger, Audience::Participant),
            Shown::Totals
        );
        assert_eq!(
            shown(Data::PrivacyLedger, Audience::Auditor),
            Shown::TotalsAndEntries
        );
        // Storage is never shared; approvers are never shared as identities.
        for a in [Audience::Participant, Audience::Auditor] {
            assert_eq!(shown(Data::AssetStorage, a), Shown::Hidden);
            assert_eq!(shown(Data::AuthorizationApprovers, a), Shown::Pseudonyms);
            assert_eq!(shown(Data::JobExecution, a), Shown::Labels);
        }
    }

    #[test]
    fn pseudonyms_are_per_project() {
        let k = PseudonymKey::derive(&[7; 32]);
        let a = k.pseudonym("prj_1", "usr_1");
        assert_eq!(a, k.pseudonym("prj_1", "usr_1"));
        assert_eq!(
            a,
            PseudonymKey::derive(&[7; 32]).pseudonym("prj_1", "usr_1")
        );
        assert_ne!(a, k.pseudonym("prj_2", "usr_1"));
        assert_ne!(a, k.pseudonym("prj_1", "usr_2"));
        // The separator keeps (project, principal) unambiguous.
        assert_ne!(k.pseudonym("prj_1u", "sr_1"), a);
        // Another key, other pseudonyms.
        assert_ne!(
            PseudonymKey::derive(&[8; 32]).pseudonym("prj_1", "usr_1"),
            a
        );
        assert!(!a.contains("usr_1"));
        assert_eq!(a.len(), 4 + 64);
    }
}
