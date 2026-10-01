//! The governance evidence bundle (ADR-027): one canonical-JSON file,
//! `<project>-<job>.encgov.json`, that an institution can hand to its own
//! auditor and verify offline, against keys it pinned itself.
//!
//! ```text
//! { manifest: { format, view, project_id, job_ids, exported_at, exported_by,
//!               trust_root, sections: {trust, governance, audit, provenance},
//!               legal_boundary },
//!   signatures: [ {organization, public_key, signature} ],  // attribution only
//!   trust, governance, audit, provenance }
//! BundleId = SHA256("encompute.governance-bundle.v1" || 0x00 || canonical(manifest))
//! ```
//!
//! - **Content addressed.** Each section's digest is in the manifest, the
//!   manifest's root of the trust graph is the graph's own, and the file
//!   must be exactly the canonical encoding of what it parses to: any edit,
//!   omission, reordering or unknown field is refused (ENC2727).
//! - **No plaintext.** Sections are typed with `deny_unknown_fields`;
//!   data-dependent values appear only as salted commitments; ciphertexts
//!   and released values are not in it; and no string over
//!   [`MAX_STRING`] bytes is allowed outside the allowlisted text fields
//!   (ENC2729). The exporter runs the same check before it writes.
//! - **Shared-safe views.** A `shared` bundle carries no signed
//!   authorization (it names the approvers) and is the same bytes for every
//!   member; an `organization:<id>` bundle carries only that organization's
//!   own signed documents. A bundle that breaks this is refused (ENC2729),
//!   whoever produced it.
//! - **Signatures are attribution.** They say who vouches for this package
//!   and add no trust to the evidence, which is verified on its own against
//!   the verifier's [`Pins`].
//! - **Pins come from the verifier**, never from the bundle. Trust in a
//!   report is exactly trust in these pins.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::{hex, unhex};

use crate::governance::{
    AuditEvidence, AuthorizationEntry, GovernanceAnchors, GovernanceEvidence, GovernanceOptions,
    GovernanceReport, Verdict, GOVERNANCE_EVIDENCE_VERSION, LEGAL_BOUNDARY_ID,
};
use crate::graph::TrustGraph;
use crate::report::{Anchors, ReportOptions};
use crate::tagged_hex;

pub const BUNDLE_FORMAT: &str = "encompute.governance-bundle.v1";
const SECTION_DOMAIN: &str = "encompute.governance-bundle-section.v1";
const SIGNATURE_DOMAIN: &str = "encompute.governance-bundle-signature.v1";
pub const PROVENANCE_VERSION: u32 = 1;
/// The longest string a bundle may carry outside [`allowed_long`] fields.
pub const MAX_STRING: usize = 256;
/// The largest bundle file a reader parses.
pub const MAX_BUNDLE_BYTES: usize = 32 * 1024 * 1024;
/// How many of each repeated item a bundle may carry (ENC2730 beyond).
pub const MAX_EVENTS: usize = 5_000;
pub const MAX_ITEMS: usize = 1_000;
pub const MAX_SIGNATURES: usize = 100;
pub const MAX_NODES: usize = 10_000;
pub const MAX_EDGES: usize = 50_000;
pub const MAX_APPROVALS: usize = 100;
/// The most siblings an inclusion proof has (a tree of 2^64 leaves).
pub const MAX_PROOF_PATH: usize = 64;

fn malformed(m: impl Into<String>) -> Error {
    Error::new(Code::GovernanceBundleMalformed, m)
}

fn unverified(m: impl Into<String>) -> Error {
    Error::new(Code::GovernanceBundleUnverified, m)
}

fn too_big(m: impl Into<String>) -> Error {
    Error::new(Code::GovernanceBundleLimit, m)
}

/// An identifier that is safe as a path component and on a terminal:
/// `[A-Za-z0-9._-]{1,200}`.
pub fn check_ident(what: &str, v: &str) -> Result<()> {
    let ok = !v.is_empty()
        && v.len() <= 200
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(malformed(format!(
            "{what} is 1-200 characters of letters, digits, '.', '_' and '-'"
        )))
    }
}

fn plaintext(m: impl Into<String>) -> Error {
    Error::new(Code::GovernanceBundlePlaintext, m)
}

// --- the file -----------------------------------------------------------------

/// The digests of the sections the manifest commits to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionDigests {
    pub trust: String,
    pub governance: String,
    pub audit: String,
    pub provenance: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    /// `shared` or `organization:<id>`.
    pub view: String,
    pub project_id: String,
    pub job_ids: Vec<String>,
    pub exported_at: u64,
    /// Who exported it: a service or organization ID (never a person).
    pub exported_by: String,
    /// The trust graph's own root ([`TrustGraph::root`]).
    pub trust_root: String,
    pub sections: SectionDigests,
    /// [`LEGAL_BOUNDARY_ID`].
    pub legal_boundary: String,
}

/// An organization's signature of the BundleId: who vouches for this
/// package. It adds no trust to the evidence inside.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSignature {
    pub organization: String,
    pub public_key: String,
    /// What the signer says it did: the signature is over this statement.
    pub statement: SignatureStatement,
    pub signature: String,
}

/// The verdict a signer claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementVerdict {
    /// The signer verified nothing: attribution only.
    NotVerified,
    Satisfied,
    NotFullyEvidenced,
    NotSatisfied,
}

/// What a signature of a bundle states: which bundle, and what its signer
/// verified before signing (nothing, or a verdict against pins it names by
/// digest, with the acceptances it made).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureStatement {
    pub bundle_id: String,
    /// What the signer claims its machine concluded (a claim, not
    /// evidence: it adds no trust).
    pub verdict: StatementVerdict,
    /// The digest of the pins it verified against, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pins_digest: Option<String>,
    /// It signed although rows were unchecked or not evidenced.
    pub accepted_unchecked: bool,
    /// It signed without pins.
    pub accepted_unpinned: bool,
}

/// Where the software that ran the job came from: digests only, so the
/// bundle can name them without carrying them. Not available from the
/// control plane in this release, so every field is normally absent and
/// the report says provenance was not verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sigstore_bundle_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluator_image_digest: Option<String>,
}

impl SignatureStatement {
    /// The claimed verdict in words.
    pub fn verdict_name(&self) -> &'static str {
        match self.verdict {
            StatementVerdict::NotVerified => "nothing verified",
            StatementVerdict::Satisfied => "satisfied",
            StatementVerdict::NotFullyEvidenced => "not fully evidenced",
            StatementVerdict::NotSatisfied => "not satisfied",
        }
    }
}

impl Default for Provenance {
    fn default() -> Self {
        Self {
            version: PROVENANCE_VERSION,
            release_manifest_sha256: None,
            sigstore_bundle_sha256: None,
            evaluator_image_digest: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceBundle {
    pub manifest: Manifest,
    pub signatures: Vec<BundleSignature>,
    pub trust: TrustGraph,
    pub governance: GovernanceEvidence,
    pub audit: AuditEvidence,
    pub provenance: Provenance,
}

fn digest<T: Serialize>(name: &str, section: &T) -> Result<String> {
    let mut input = name.as_bytes().to_vec();
    input.push(0);
    input.extend(canonical_json(section)?);
    Ok(tagged_hex(SECTION_DOMAIN, &input))
}

/// `shared`, or `organization:<id>` for a well-formed ID.
pub fn check_view(view: &str) -> Result<()> {
    let ok = view == "shared"
        || view.strip_prefix("organization:").is_some_and(|o| {
            !o.is_empty()
                && o.len() <= 200
                && o.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        });
    if ok {
        Ok(())
    } else {
        Err(malformed(format!(
            "the view is `shared` or `organization:<id>`, not {view:?}"
        )))
    }
}

impl GovernanceBundle {
    /// Builds a bundle and checks it as the exporter must before it writes
    /// anything: every section digest and the graph root are computed here,
    /// the view's rules and the plaintext guard are applied, and what
    /// cannot pass is refused.
    pub fn build(
        view: &str,
        exported_at: u64,
        exported_by: &str,
        trust: TrustGraph,
        governance: GovernanceEvidence,
        audit: AuditEvidence,
        provenance: Provenance,
    ) -> Result<Self> {
        check_view(view)?;
        let manifest = Manifest {
            format: BUNDLE_FORMAT.into(),
            view: view.into(),
            project_id: governance.project.clone(),
            job_ids: vec![governance.job_id.clone()],
            exported_at,
            exported_by: exported_by.into(),
            trust_root: trust.root()?,
            sections: SectionDigests {
                trust: digest("trust", &trust)?,
                governance: digest("governance", &governance)?,
                audit: digest("audit", &audit)?,
                provenance: digest("provenance", &provenance)?,
            },
            legal_boundary: LEGAL_BOUNDARY_ID.into(),
        };
        let b = Self {
            manifest,
            signatures: vec![],
            trust,
            governance,
            audit,
            provenance,
        };
        b.check()?;
        Ok(b)
    }

    /// `SHA256("encompute.governance-bundle.v1" || 0x00 || canonical
    /// manifest)`, hex.
    pub fn id(&self) -> Result<String> {
        Ok(tagged_hex(BUNDLE_FORMAT, &canonical_json(&self.manifest)?))
    }

    /// The canonical bytes: what is written, and what is read back.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }

    /// Reads a bundle. The bytes must be exactly the canonical encoding of
    /// what they parse to (so an edit, a reordering, a duplicated key or
    /// whitespace changes them), with a known format and no unknown field.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(too_big(format!(
                "a bundle is at most {MAX_BUNDLE_BYTES} bytes"
            )));
        }
        let b: Self = serde_json::from_slice(bytes)
            .map_err(|e| malformed(format!("malformed governance bundle: {e}")))?;
        if b.manifest.format != BUNDLE_FORMAT {
            return Err(malformed(format!(
                "unknown governance bundle format {:?}",
                b.manifest.format
            )));
        }
        if b.to_bytes()? != bytes {
            return Err(malformed(
                "the bundle is not the canonical encoding of its content (edited, reordered or re-encoded)",
            ));
        }
        b.check()?;
        Ok(b)
    }

    /// Everything that needs no key: the manifest matches the sections,
    /// the sections match each other, the view is shared-safe and nothing
    /// longer than [`MAX_STRING`] hides outside the text fields.
    pub fn check(&self) -> Result<()> {
        let m = &self.manifest;
        if m.format != BUNDLE_FORMAT {
            return Err(malformed("unknown governance bundle format"));
        }
        // Counts first: nothing below costs more than a bundle this size.
        for (what, n, max) in [
            ("events", self.audit.events.len(), MAX_EVENTS),
            ("witnesses", self.audit.witnesses.len(), MAX_ITEMS),
            (
                "revocation heads",
                self.audit.revocation_heads.len(),
                MAX_ITEMS,
            ),
            ("members", self.audit.members.len(), MAX_ITEMS),
            ("signatures", self.signatures.len(), MAX_SIGNATURES),
            (
                "authorizations",
                self.governance.authorizations.len(),
                MAX_ITEMS,
            ),
            (
                "authorization revocations",
                self.governance.authorization_revocations.len(),
                MAX_ITEMS,
            ),
            (
                "purpose acceptances",
                self.governance.purpose_acceptances.len(),
                MAX_ITEMS,
            ),
            (
                "release records",
                self.governance.release_records.len(),
                MAX_ITEMS,
            ),
            ("jobs", m.job_ids.len(), 1),
        ] {
            if n > max {
                return Err(too_big(format!(
                    "a bundle carries at most {max} {what}, not {n}"
                )));
            }
        }
        if self
            .audit
            .events
            .iter()
            .any(|e| e.proof.path.len() > MAX_PROOF_PATH)
        {
            return Err(too_big("an inclusion proof is longer than any tree allows"));
        }
        check_view(&m.view)?;
        check_ident("the project", &m.project_id)?;
        check_ident("the exporter", &m.exported_by)?;
        check_ident("the project", &self.governance.project)?;
        check_ident("the project", &self.audit.project)?;
        check_ident("the job", &self.governance.job_id)?;
        for j in &m.job_ids {
            check_ident("a job", j)?;
        }
        if self.governance.purpose.description.len() > 2000
            || self
                .governance
                .purpose
                .description
                .chars()
                .any(|c| c.is_control())
        {
            return Err(malformed(
                "a purpose description is at most 2000 printable characters",
            ));
        }
        if m.legal_boundary != LEGAL_BOUNDARY_ID {
            return Err(malformed("the bundle names another legal boundary"));
        }
        if self.governance.version != GOVERNANCE_EVIDENCE_VERSION
            || self.audit.version != GOVERNANCE_EVIDENCE_VERSION
            || self.provenance.version != PROVENANCE_VERSION
        {
            return Err(malformed("a section has an unknown version"));
        }
        if m.project_id != self.governance.project || m.project_id != self.audit.project {
            return Err(malformed("the sections are of different projects"));
        }
        if m.job_ids != [self.governance.job_id.clone()] {
            return Err(malformed("the manifest's jobs are not the evidence's job"));
        }
        if self.trust.root()? != m.trust_root {
            return Err(malformed(
                "the trust graph's root is not the manifest's (edited or omitted evidence)",
            ));
        }
        for (name, want, got) in [
            ("trust", &m.sections.trust, digest("trust", &self.trust)?),
            (
                "governance",
                &m.sections.governance,
                digest("governance", &self.governance)?,
            ),
            ("audit", &m.sections.audit, digest("audit", &self.audit)?),
            (
                "provenance",
                &m.sections.provenance,
                digest("provenance", &self.provenance)?,
            ),
        ] {
            if *want != got {
                return Err(malformed(format!(
                    "the {name} section does not match its digest in the manifest (edited, omitted or reordered)"
                )));
            }
        }
        for p in [
            &self.provenance.release_manifest_sha256,
            &self.provenance.sigstore_bundle_sha256,
            &self.provenance.evaluator_image_digest,
        ]
        .into_iter()
        .flatten()
        {
            let d = p.strip_prefix("sha256:").unwrap_or(p);
            if d.len() != 64
                || !d
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(malformed(
                    "a provenance digest is 32 bytes of lowercase hex",
                ));
            }
        }
        self.check_signatures_shape()?;
        self.check_view_rules()?;
        check_no_plaintext(&serde_json::to_value(self).map_err(|e| malformed(e.to_string()))?)
    }

    fn check_signatures_shape(&self) -> Result<()> {
        let orgs: Vec<&String> = self.signatures.iter().map(|s| &s.organization).collect();
        for s in &self.signatures {
            check_ident("a signer's organization", &s.organization)?;
            check_statement(&s.statement)?;
        }
        if orgs.windows(2).any(|w| w[0] >= w[1]) {
            return Err(malformed("signatures are sorted by organization, one each"));
        }
        Ok(())
    }

    /// The view's promise: a shared bundle shows no approver's identity and
    /// is the same for everyone; an organization's names only its own.
    fn check_view_rules(&self) -> Result<()> {
        let leak = |m: String| plaintext(m);
        match self.manifest.view.strip_prefix("organization:") {
            None => {
                // Shared.
                for e in &self.governance.authorizations {
                    if let AuthorizationEntry::Signed { document } = e {
                        return Err(leak(format!(
                            "a shared view carries no signed authorization (authorization {} names its approvers)",
                            &document.id()[..12]
                        )));
                    }
                }
            }
            Some(org) => {
                for e in &self.governance.authorizations {
                    if let AuthorizationEntry::Signed { document } = e {
                        if document.body.party != org {
                            return Err(leak(format!(
                                "the view of {org} carries {}'s signed authorization",
                                document.body.party
                            )));
                        }
                    }
                }
            }
        }
        if let Some(s) = &self.governance.submitter {
            if !s.starts_with("psn_") {
                return Err(leak("the submitter is shown as a pseudonym only".into()));
            }
        }
        for e in &self.governance.authorizations {
            if let AuthorizationEntry::Card { card } = e {
                if card
                    .approvals
                    .iter()
                    .any(|a| !a.approver.starts_with("psn_"))
                {
                    return Err(leak(
                        "a card shows an approver other than as a pseudonym".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// An organization's signature of the BundleId (attribution) with the
    /// statement that nothing was verified. Replaces the organization's
    /// earlier signature.
    pub fn sign(&mut self, organization: &str, key: &SigningKey) -> Result<()> {
        let st = SignatureStatement {
            bundle_id: self.id()?,
            verdict: StatementVerdict::NotVerified,
            pins_digest: None,
            accepted_unchecked: false,
            accepted_unpinned: false,
        };
        self.sign_statement(organization, key, st)
    }

    /// A signature that states what the signer verified first.
    pub fn sign_statement(
        &mut self,
        organization: &str,
        key: &SigningKey,
        st: SignatureStatement,
    ) -> Result<()> {
        check_ident("an organization", organization)?;
        check_statement(&st)?;
        if st.bundle_id != self.id()? {
            return Err(malformed("the statement is about another bundle"));
        }
        let sig = hex(&key.sign(&signature_input(&st)?).to_bytes());
        self.signatures.retain(|s| s.organization != organization);
        self.signatures.push(BundleSignature {
            organization: organization.into(),
            public_key: hex(&key.verifying_key().to_bytes()),
            statement: st,
            signature: sig,
        });
        self.signatures
            .sort_by(|a, b| a.organization.cmp(&b.organization));
        Ok(())
    }
}

/// A claim to have verified something names the pins it was verified
/// against; nothing else is a claim.
fn check_statement(st: &SignatureStatement) -> Result<()> {
    let claims = st.verdict != StatementVerdict::NotVerified;
    if claims && st.pins_digest.is_none() {
        return Err(malformed(
            "a signature that claims a verdict names the pins it verified against",
        ));
    }
    if !claims && (st.pins_digest.is_some() || st.accepted_unchecked) {
        return Err(malformed(
            "a signature that verified nothing names no pins and accepts nothing",
        ));
    }
    if st.accepted_unpinned && st.pins_digest.is_some() {
        return Err(malformed("a signature cannot be both pinned and unpinned"));
    }
    Ok(())
}

fn signature_input(st: &SignatureStatement) -> Result<Vec<u8>> {
    let mut v = SIGNATURE_DOMAIN.as_bytes().to_vec();
    v.push(0);
    v.extend(canonical_json(st)?);
    Ok(v)
}

// --- the plaintext guard ---------------------------------------------------------

/// Whether a string of any length belongs at `path` (JSON keys from the
/// root): the program's own text, the purpose's description, an
/// attestation record (provider-signed tokens). Everything else is
/// identifiers, digests, commitments and signatures.
fn allowed_long(path: &[&str], root: &Value) -> bool {
    // trust.nodes.<id>.evidence.value[...] of a program or attestation.
    if let ["trust", "nodes", id, "evidence", ..] = path {
        let t = root
            .pointer(&format!(
                "/trust/nodes/{}/evidence/type",
                id.replace('~', "~0").replace('/', "~1")
            ))
            .and_then(Value::as_str);
        return matches!(t, Some("program") | Some("attestation"));
    }
    path == ["governance", "purpose", "description"]
}

/// Refuses any string over [`MAX_STRING`] bytes outside the allowlisted
/// text fields: the bundle holds identifiers, digests and commitments,
/// never records or released values (ENC2729).
pub fn check_no_plaintext(root: &Value) -> Result<()> {
    fn walk(v: &Value, path: &mut Vec<String>, root: &Value) -> Result<()> {
        match v {
            Value::String(s) if s.len() > MAX_STRING => {
                let p: Vec<&str> = path.iter().map(String::as_str).collect();
                if !allowed_long(&p, root) {
                    return Err(plaintext(format!(
                        "a string of {} bytes at {} is over the {MAX_STRING}-byte cap outside the text fields a bundle allows",
                        s.len(),
                        path.join(".")
                    )));
                }
                Ok(())
            }
            Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    path.push(i.to_string());
                    walk(x, path, root)?;
                    path.pop();
                }
                Ok(())
            }
            Value::Object(o) => {
                for (k, x) in o {
                    // A key is a label too.
                    if k.len() > MAX_STRING {
                        return Err(plaintext(format!(
                            "a key of {} bytes at {}",
                            k.len(),
                            path.join(".")
                        )));
                    }
                    path.push(k.clone());
                    walk(x, path, root)?;
                    path.pop();
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    walk(root, &mut vec![], root)
}

// --- pins -----------------------------------------------------------------------

/// A public key the verifier obtained itself, and where from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub key: String,
    /// How the verifier got it (an official publication, a visit, ...): so
    /// an auditor can see what a conclusion rests on.
    pub obtained: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationPin {
    /// The organization's governance public key.
    pub identity_key: String,
    pub obtained: String,
}

/// The auditor's pins file. Never taken from a bundle: trust in a report
/// is exactly trust in these. Agencies should publish their keys through
/// official channels.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pins {
    #[serde(default)]
    pub organizations: BTreeMap<String, OrganizationPin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_plane: Option<Pin>,
    #[serde(default)]
    pub evaluators: Vec<Pin>,
    #[serde(default)]
    pub coordinators: Vec<Pin>,
    /// Reserved: linkage authorities (no linkage evidence in this release).
    #[serde(default)]
    pub linkage_authorities: Vec<Pin>,
    /// Reserved: release signers (no release provenance in this release).
    #[serde(default)]
    pub release_signers: Vec<Pin>,
}

fn check_key(what: &str, k: &str) -> Result<()> {
    let ok = k.len() == 64 && unhex(k).is_some_and(|b| b.len() == 32) && k == k.to_lowercase();
    if ok {
        Ok(())
    } else {
        Err(unverified(format!(
            "pin {what}: not an Ed25519 public key (64 lowercase hex characters)"
        )))
    }
}

fn check_obtained(what: &str, o: &str) -> Result<()> {
    if o.trim().is_empty() || o.len() > 200 || o.chars().any(|c| c.is_control()) {
        return Err(unverified(format!(
            "pin {what}: say where the key was obtained (1-200 printable characters)"
        )));
    }
    Ok(())
}

impl Pins {
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let p: Self = serde_json::from_slice(b)
            .map_err(|e| unverified(format!("malformed pins file: {e}")))?;
        p.check()?;
        Ok(p)
    }

    pub fn check(&self) -> Result<()> {
        for (o, p) in &self.organizations {
            check_ident("a pinned organization", o)?;
            check_key(o, &p.identity_key)?;
            check_obtained(o, &p.obtained)?;
        }
        let singles = self
            .control_plane
            .iter()
            .chain(&self.evaluators)
            .chain(&self.coordinators)
            .chain(&self.linkage_authorities)
            .chain(&self.release_signers);
        for p in singles {
            check_key("key", &p.key)?;
            check_obtained("key", &p.obtained)?;
        }
        // One key, one role: two organizations on one key are not two
        // organizations, and a key that is an organization's and also the
        // control plane's or an evaluator's means one party plays both.
        let mut seen: BTreeSet<&String> = BTreeSet::new();
        for (o, p) in &self.organizations {
            if !seen.insert(&p.identity_key) {
                return Err(unverified(format!(
                    "pins: {o} shares its key with another organization"
                )));
            }
        }
        for (role, keys) in [
            (
                "the control plane",
                self.control_plane.iter().collect::<Vec<_>>(),
            ),
            ("an evaluator", self.evaluators.iter().collect()),
            ("a coordinator", self.coordinators.iter().collect()),
            (
                "a linkage authority",
                self.linkage_authorities.iter().collect(),
            ),
            ("a release signer", self.release_signers.iter().collect()),
        ] {
            for k in keys {
                if !seen.insert(&k.key) {
                    return Err(unverified(format!(
                        "pins: a key is pinned for {role} and for another role"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The anchors the reports check against.
    pub fn anchors(&self) -> (GovernanceAnchors, Anchors) {
        let orgs: BTreeMap<String, String> = self
            .organizations
            .iter()
            .map(|(o, p)| (o.clone(), p.identity_key.clone()))
            .collect();
        (
            GovernanceAnchors {
                organizations: orgs.clone(),
                control_plane: self.control_plane.as_ref().map(|p| p.key.clone()),
            },
            Anchors {
                parties: BTreeMap::new(),
                coordinators: self.coordinators.iter().map(|p| p.key.clone()).collect(),
                evaluators: self.evaluators.iter().map(|p| p.key.clone()).collect(),
                governance_keys: orgs,
            },
        )
    }

    /// A digest of the pins (what a signature's statement names).
    pub fn digest(&self) -> Result<String> {
        Ok(tagged_hex("encompute.pins.v1", &canonical_json(self)?))
    }

    pub fn is_empty(&self) -> bool {
        self.organizations.is_empty()
            && self.control_plane.is_none()
            && self.evaluators.is_empty()
            && self.coordinators.is_empty()
    }
}

// --- verification ---------------------------------------------------------------

/// What a signature of the bundle came to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Verified under the organization's pinned key.
    Verified,
    /// The organization's key is not pinned: the signature is
    /// self-consistent (it verifies under the key it carries) and
    /// attribution to the organization is not checked.
    Unpinned,
}

#[derive(Clone, Debug, Serialize)]
pub struct SignatureFinding {
    pub organization: String,
    pub status: SignatureStatus,
    /// What the signer said it verified.
    pub statement: SignatureStatement,
}

/// The one table of verification results (the CLI's exit codes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Every row passes (exit 0).
    Satisfied,
    /// A row failed or the base report did (exit 1).
    NotSatisfied,
    /// Malformed, forged, or refused (exit 2): returned as an `Err`.
    Refused,
    /// Nothing failed, but something is unchecked, not evidenced or not
    /// pinned (exit 3).
    Unchecked,
}

impl Outcome {
    pub fn exit_code(self) -> u8 {
        match self {
            Outcome::Satisfied => 0,
            Outcome::NotSatisfied => 1,
            Outcome::Refused => 2,
            Outcome::Unchecked => 3,
        }
    }
}

/// The documented exit codes of `encompute governance verify` and
/// `report`: one table.
pub const EXIT_CODES: &str = "0 every row satisfied (or accepted with --allow-unchecked/--allow-unpinned); 1 not satisfied (a row failed); 2 malformed, forged or refused; 3 unchecked, not evidenced or unpinned";

#[derive(Debug)]
pub struct Verified {
    pub bundle_id: String,
    pub view: String,
    pub signatures: Vec<SignatureFinding>,
    pub report: GovernanceReport,
    pub outcome: Outcome,
    /// Things the verifier could not do, in words (provenance, pins).
    pub notes: Vec<String>,
}

pub struct VerifyOptions<'a> {
    pub pins: &'a Pins,
    pub base: ReportOptions<'a>,
    /// Signed authorizations the owners disclosed (see
    /// [`GovernanceOptions::disclosures`]).
    pub disclosures: Vec<crate::authz::SignedAuthorizationV2>,
    pub as_of: Option<u64>,
    pub now: Option<u64>,
}

impl GovernanceBundle {
    /// The offline verification, in the plan's order: the content checks
    /// (format, digests, graph root, shared-safety, plaintext: refused
    /// with ENC2727 or ENC2729), the signatures against the pins (a forged
    /// signature is refused with ENC2728), then the base report and the
    /// governance rows, the checkpoint, the witnesses, the proofs and the
    /// revocation heads. Provenance is not verified in this release.
    pub fn verify(&self, opts: &VerifyOptions<'_>) -> Result<Verified> {
        self.check()?;
        opts.pins.check()?;
        let id = self.id()?;
        let (anchors, base_anchors) = opts.pins.anchors();
        let mut findings = vec![];
        for s in &self.signatures {
            if s.statement.bundle_id != id {
                return Err(unverified(format!(
                    "the signature of {} is about another bundle",
                    s.organization
                )));
            }
            // Every signature must verify under its own embedded key; a
            // pinned organization's must be under its pinned key. Unpinned
            // ones are self-consistent attribution only.
            let own = verify_signature(&s.public_key, &s.signature, &s.statement);
            let status = match opts.pins.organizations.get(&s.organization) {
                None => {
                    if !own {
                        return Err(unverified(format!(
                            "the signature of {} (not pinned) is invalid",
                            s.organization
                        )));
                    }
                    SignatureStatus::Unpinned
                }
                Some(p) => {
                    if p.identity_key != s.public_key || !own {
                        return Err(unverified(format!(
                            "the signature of {} does not verify under its pinned key",
                            s.organization
                        )));
                    }
                    SignatureStatus::Verified
                }
            };
            findings.push(SignatureFinding {
                organization: s.organization.clone(),
                status,
                statement: s.statement.clone(),
            });
        }
        let mut base = ReportOptions {
            anchors: base_anchors,
            now: opts.base.now.or(opts.now),
            ..ReportOptions::default()
        };
        base.require = opts.base.require.clone();
        base.plan_floor = opts.base.plan_floor.clone();
        base.verifier = opts.base.verifier;
        base.execution_policy = opts.base.execution_policy;
        base.program_facts = opts.base.program_facts;
        base.proof_check = opts.base.proof_check;
        let gopts = GovernanceOptions {
            base,
            anchors,
            as_of: opts.as_of,
            now: opts.now,
            disclosures: opts.disclosures.clone(),
        };
        let report = self
            .trust
            .governance_report(&self.governance, &self.audit, &gopts)?;
        let outcome = match report.verdict {
            Verdict::Satisfied => Outcome::Satisfied,
            Verdict::NotSatisfied => Outcome::NotSatisfied,
            Verdict::NotFullyEvidenced => Outcome::Unchecked,
        };
        let mut notes = vec![];
        if opts.pins.is_empty() {
            notes.push("no pins: nothing signed by an organization, the control plane or an evaluator was checked".into());
        }
        if self.provenance == Provenance::default() {
            notes.push("provenance (the release manifest, the evaluator image) is not in the bundle: not verified".into());
        } else {
            notes.push("provenance digests are named in the bundle; they are not verified offline in this release".into());
        }
        if self.signatures.is_empty() {
            notes.push("the bundle carries no signature: nobody vouches for this package".into());
        }
        Ok(Verified {
            bundle_id: id,
            view: self.manifest.view.clone(),
            signatures: findings,
            report,
            outcome,
            notes,
        })
    }
}

fn verify_signature(public_key: &str, signature: &str, st: &SignatureStatement) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Some(k) = unhex(public_key)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
    else {
        return false;
    };
    let Some(sig) = unhex(signature).and_then(|b| Signature::from_slice(&b).ok()) else {
        return false;
    };
    signature_input(st).is_ok_and(|m| k.verify_strict(&m, &sig).is_ok())
}
