# ADR-027 — Cross-agency trust report, `explain --governance` and the governance evidence bundle

Status: **Accepted** (2026-09-29) for the report rules (rows computed from
signed evidence only, execution-time validity, fail-closed statuses), the
plain-language explanation and the bundle's content rules (content
addressing, no plaintext, offline verification against pinned keys, views),
as design. The items under "Open decisions" are **Proposed** and not
decided. Implementation starts after 0.3.0 ships; nothing here is part of
0.3.

## Context

ADR-023 makes each agency's signed authorization the source of consent,
ADR-025 makes each agency's broker enforce it, and ADR-026 constrains where
the work runs. An institution still needs to answer, afterwards and without
trusting anyone else: what was computed over our data, under which of our
authorizations, where, by whom, and what was released to whom?

Encompute 0.3 has most of the verification machinery:

- The trust graph (ADR-014) is rebuilt from signed evidence, and the report
  reads only the rebuilt graph. A tampered report or a cached attribute
  changes nothing (INV-101).
- `encompute trust report` shows rows such as Evidence, Program, Policy,
  Plan, Owner authorization, Execution and Lineage, and a row without a
  trust anchor is shown as unchecked, never as passing.
- `encompute verify` exits 3 when a binding was not checked (INV-188).

What it lacks for cross-agency work:

- nothing in the graph names organizations, projects, purposes, dataset
  versions, approvals, grants, key releases, derived results or
  checkpoints;
- authorization expiry is judged on the verifier's clock, so a valid
  historical execution starts failing once its window closes;
- the report is written for engineers; a data-protection officer or a
  program manager cannot read it;
- there is no single, portable package an agency can hand to its own
  auditor and verify offline, and no rule that such a package contains no
  source records;
- there is no per-organization view, so exporting evidence could disclose
  one agency's private metadata to another.

## Decision

### 1. Principles

- **Evidence, never claims.** Every governance row is computed from signed
  evidence in the rebuilt graph. The control plane's database, a cached
  status or a previously produced report are never inputs.
- **Anchors come from the verifier.** Organization governance keys, the
  control-plane key, release signers and linkage authorities are supplied
  by the person verifying, from a pins file they obtained themselves. They
  are never read from the bundle. Trust in the report is exactly trust in
  these pins, and agencies should publish their keys through official
  channels.
- **Fail closed.** A row whose anchor is missing is UNCHECKED (displayed
  "PRESENT (not checked)"); a row whose evidence is missing is NOT
  PRESENT. Neither ever passes, and the overall verdict requires every row
  to pass.
- **Validity at execution time** (owner rule). An authorization is judged
  at the time the job ran or the key was released, from a signed time,
  never at the time of verification. Expiry or revocation after the fact
  does not fail a historical audit.
- **No plaintext.** Neither the report nor the bundle contains source
  records or released values.

### 2. Where the report lives

- `crates/encompute-trust/src/governance.rs` adds
  `TrustGraph::governance_report(&GovernanceOptions)`. It runs the existing
  `report()` first, and every base row must pass. It then adds the
  governance rows from the same rebuilt graph. INV-101 applies unchanged.
- `GRAPH_VERSION` becomes 2. Version 1 bundles load read-only, and their
  governance rows show NOT PRESENT.
- `GovernanceAnchors` adds `organizations` (organization to governance
  key), `control_plane`, `release_signers` and `linkage_authorities`, all
  from the caller.
- **New node kinds:** `Organization` (self-signed record: identity key,
  custody kind and fingerprint, region), `Project` (the co-signed charter),
  `Purpose`, `AssetVersion`, `Authorization` body v2, `Approval`,
  `Linkage`, `Grant`, `DerivedAsset` (the `SignedReleaseRecord`),
  `KeyRelease` (the broker's receipt), `Checkpoint`, `RevocationHead` and
  `Provenance` (release manifest, evaluator image, Sigstore bundle).
- **New edges:** `MemberOf`, `VersionOf`, `Declares`, `Scopes`,
  `LinkedUnder`, `Approves`, `CertifiedBy`, `Grants`, `Releases`,
  `OperatedBy` and `Witnessed`, plus the existing `Owns`, `DerivedFrom` and
  `Revokes`. Rebuild ordering in `ingest.rs` is extended to cover them.

### 3. The CROSS-AGENCY TRUST REPORT

Each row is a tally over the evidence it names.

| Row | How it is computed |
|---|---|
| Project | The charter verifies under every member's pinned governance key. |
| Organizations | Members are distinct organizations with distinct pinned keys. |
| Key custody | INDEPENDENT only if each asset version's key fingerprint lies in its owner's own namespace, no key is shared between organizations, and no project-wide key exists. |
| Purpose | Exactly one purpose. The program, every authorization, the grant and the linkage policy all carry the same `purpose_id`, and the grant's signed time is inside the purpose's window. |
| Source assets | The asset versions bound in the GovernanceId, each signed by its owner. |
| Linkage | Co-signed by every source owner, or N/A with an explicit `scheme: none` (ADR-024). |
| **Raw data centralized** | NO only if every step that consumed a source is one of: the owner's own client; FHE evaluation on an untrusted host; SecAgg masking; a TEE whose `KeyRelease` is signed by the owner's broker. Anything else is UNKNOWN, never NO. |
| **Decryption control** | States the key model in words, for example "recipient-held: benefits-agency; assumes the evaluator operator does not collude" (M1), or the attested decryptor (M2), or threshold (M3). FAILED if the key holder is the evaluator operator (ADR-026). The model shown is the one actually in the evidence; which models ship is open (K-2). |
| **Ownership retained** | YES only if no evidence changes any version's owner, custody or revocation authority. |
| Location | SATISFIED against the effective constraints recorded in the plan, with each location labelled "attested" or "declared" (ADR-025, ADR-026). |
| Mechanism | The mechanisms used, in plain words. |
| **Approvals** | Per agency: an AuthorizationV2 active at the grant's signed time, with a quorum of distinct humans of that agency; no approver is the submitter, a service account or an auditor. |
| **Authorization window** | VALID AT EXECUTION, from the grant's signed `issued_at` and `expires_at`, reached through the receipt's `grant_digest` (ADR-023, section 8). A separate line "now: VALID / EXPIRED / REVOKED" is informational and never fails a historical audit. |
| **Unauthorized releases** | NONE only if there is exactly one release record per receipt output, each release class is no wider than its parents', and each recipient set is a subset of every source authorization's recipients. |
| Privacy policy | Budgets spent, by privacy scope and population, or "no DP budget applies (record-level decision)". |
| Execution evidence | The execution spec is **recomputed** from the bundle, including `governance_id`, and matches the receipt. |
| Audit chain | The project checkpoint is present and witnessed; job events are proven by inclusion against it; each owner's revocation head is dated at or after the grant. |
| Revocations | A section, not a pass/fail row: who revoked what, when and why, the downstream results (`downstream(version)`), and the words "not erased". |

- The rows in bold are the ones a non-specialist reads first. They are
  shown with a positive value only when signed evidence backs it (INV-244).
- The result line reads **CROSS-AGENCY REQUIREMENTS SATISFIED** only if
  every base and governance row passes and nothing is unchecked. Otherwise
  it names the rows that did not pass.
- The result line is always followed by the one-line legal boundary
  (`encompute.legal-boundary.v1`, the text in
  [confidential cross-agency computation](../public-sector.md)): the
  report shows that the computation matched what the institutions
  technically authorized, not that the authorization was lawful.

### 4. `encompute explain --governance`

For readers who are not cryptographers: a data-protection officer, an
auditor, a program owner.

- `Explain.model` becomes optional. The command takes either
  `--governance JOB` (online) or `--governance --bundle FILE.encgov.json`
  (offline).
- Online, it fetches `GET /v1/jobs/{id}/governance-bundle?view=shared|org`
  and then verifies **locally** against the user's own pins, following the
  same principle as the client pin set (INV-184). The server's opinion of
  the result is never shown as the result.
- Rendering is in `governance_explain.rs`, in the style of `lineage.rs`,
  and reads verified evidence only.
- Sections, in order: What was computed; Who owned the data; Why (the
  purpose and the declared legal reference, marked "recorded, not
  checked"); Who approved; Where it ran; What was released; Which
  protections applied; What evidence exists; What this does not tell you;
  VERDICT.
- A section built on an unchecked row prints "not verified: <why>" in
  place of its content.
- "What this does not tell you" is always printed. It states the legal
  boundary, the key model's assumption where one applies, that declared
  locations are declarations, and that released results cannot be
  recalled.

An illustrative excerpt (names from the synthetic examples):

```
WHAT WAS COMPUTED
  eligibility-rule v3 (program 7f3c…) over 3 datasets, for 6 applicants.
  One yes/no answer per applicant was released.

WHO OWNED THE DATA
  residency-register@2026-12-31   Residency Agency   key held by its own broker
  income-records@2027-03-31       Tax Agency         key held by its own broker
  benefit-enrolment@2027-04-01    Benefits Agency    key held by its own broker
  Raw data centralized: NO

WHERE IT RAN
  Evaluator operated by state-it-services, eu-west-1 (declared, not attested).

WHAT WAS RELEASED
  eligible (yes/no) to Benefits Agency only. No other release.
  Decryption: held by Benefits Agency; this assumes the evaluator operator
  does not collude with it.

WHAT THIS DOES NOT TELL YOU
  Whether the purpose is lawful. What any institution did outside Encompute.
  ...

VERDICT
  CROSS-AGENCY REQUIREMENTS SATISFIED
  Encompute enforced the institutions' signed technical policy; it did not
  assess legality.
```

The "Decryption" line follows whichever key model is in the evidence (K-2).

### 5. The Governance Evidence Bundle

**Format.** One canonical-JSON file, `<project>-<job>.encgov.json`. A
`--split DIR` option writes the same content as separate files.

```
{ manifest: { format: "encompute.governance-bundle.v1",
              view: "shared" | "organization:<id>",
              project_id, job_ids, exported_at, exported_by, trust_root,
              sections: { trust, audit, provenance: { sha256 } },
              legal_boundary: "encompute.legal-boundary.v1" },
  signatures: [ { organization, public_key, signature } ],
  trust:      TrustGraph v2 with all evidence,
  audit:      { checkpoints, witnesses, events (project-scoped, payload-free),
                proofs, revocation_heads },
  provenance: { release_manifest, sigstore_bundle, evaluator_image } }

BundleId = SHA256("encompute.governance-bundle.v1" || 0x00 || canonical(manifest))
```

- **Content addressing.** Each section is hashed into the manifest, and the
  BundleId is the hash of the manifest. Any edit to any section changes a
  digest and fails verification.
- **Signatures are attribution only.** The exporting organization signs the
  manifest; other members may countersign the same BundleId. A signature
  says who vouches for this package. It adds no trust to the evidence
  inside, which is verified on its own.
- **No plaintext, by construction:**
  - sections are typed and refuse unknown fields;
  - data-dependent values appear only as salted commitments (INV-210);
  - ciphertexts and released values are excluded; the receipt's
    request/response binding is shown as "not re-checked (ciphertexts
    excluded)";
  - the exporter refuses any string longer than 256 bytes outside an
    allowlist of text fields;
  - a canary-seeded test searches the exported bytes for every source
    value.

**CLI** (`encompute governance`): `export`, `verify`, `report`,
`countersign` and `sign` (the last is ADR-023's KMS-backed signing).

**Offline verification.** `encompute governance verify BUNDLE --pins
FILE` runs, in order:

1. parse, refusing unknown format versions;
2. check each section digest against the manifest;
3. check manifest signatures against the pins;
4. rebuild the trust graph and compare its root;
5. run the base report and the governance rows;
6. check checkpoints, witnesses, inclusion proofs, and that a revocation
   head is present for every owner;
7. verify provenance offline (release manifest, Sigstore bundle, evaluator
   image).

Exit codes follow INV-188: 0 satisfied, 1 not satisfied, 2 malformed or
refused, 3 something unchecked.

**Pins file** (never taken from the bundle):
`organizations { id: { identity_key, obtained } }`, `control_plane`,
`evaluators`, `coordinators`, `linkage_authorities`, `release_signers`.
The `obtained` field records where the verifier got each key, so an
auditor can see what its conclusion rests on.

### 6. Cross-organization views

A bundle is exported in one of two views:

- **Shared.** Shared evidence only. It is byte-identical for every member
  (INV-229), so members can compare BundleIds and know they hold the same
  package.
- **Organization.** The shared evidence plus the exporting organization's
  own private metadata. Never another organization's.

What each party sees follows the governed-project view table:

| Data | Owner | Other members | Auditor organization |
|---|---|---|---|
| Project, members, purposes, linkage policy | full | full | full |
| Asset version used (ID, organization, series@version, commitment, class, status) | full | yes | yes |
| `key_ref`, storage location, size, other versions, other projects | yes | no | no |
| Signed authorizations | real approvers | organization, role and time, with a per-project pseudonym for the person | same as other members |
| Job spec, program, purpose, `governance_id`, state, receipt, evaluator | full | yes | yes |
| Privacy scope ledger | full | totals | totals |
| Audit events | own organization | project-visible events | project-visible events |

Redaction never removes evidence a row needs: approver pseudonyms still
let the report count distinct humans, and commitments still bind the
versions. What remains visible in the shared view is metadata by design,
and is listed as residual in the threat model.

### 7. Checkpoints and revocation heads

- Job events are proven by inclusion against a per-project checkpoint of
  the governance event log (ADR-023, section 12).
- Every owner signs a `SignedRevocationHead { organization, project, seq,
  root over its revocations, at }`. A bundle must carry, for every owner, a
  head dated at or after the grant, and the report honours those heads
  whatever else the bundle omits. An exporter cannot hide a revocation by
  leaving it out.
- **Member-witnessed checkpoints** are proposed: each member organization
  co-signs the project checkpoint, so a control plane that shows different
  members different histories is detected offline (INV-247). Whether
  witnessing and revocation heads are required in every bundle is open
  (G-2). Until it is decided, an unwitnessed checkpoint makes the Audit
  chain row UNCHECKED, not satisfied.

### 8. Invariants

In the `public-sector` area: INV-227 (a release links to its exact
versions, program, plan, grant and approvals), INV-229 (views), INV-243
(no plaintext; offline verification against pins only; any edit fails),
INV-244 (rows from signed evidence only) and INV-247 (split views
detected). INV-101 and INV-188 apply unchanged.

## As built (phase 8: report, explain and bundle)

Where the build refines or narrows the design above:

- **Typed governance section, not graph version 2.** The trust graph is
  unchanged (`GRAPH_VERSION` stays 1): the bundle carries the base graph
  (program, plan, execution receipt) and a typed, `deny_unknown_fields`
  section of governance evidence beside it (`GovernanceEvidence`: the
  purpose and the organizations' signed acceptances, the execution spec,
  the control plane's signed grant, the owners' authorizations, the
  custodians' signed release records) and `AuditEvidence` (the checkpoint,
  every event of the project's log with its inclusion proof, the
  witnesses, each owner's latest revocation head). The governance rows
  read the base graph after `rebuild()`, and the typed evidence against the
  caller's pins, so INV-101 holds as before. New node kinds can be added to
  the graph later without changing the bundle format.
- **Pins override bundle anchors in the base report too** (the P8
  prerequisite): `Anchors.governance_keys` replaces whatever governance key
  a bundle anchors for an organization before a v2 authorization in the
  graph is re-verified; without a pin the old behaviour (and no counting)
  stays.
- **Rows as built.** Project (each data owner's signed acceptance of the
  purpose; there is no charter object yet), Organizations, Key custody
  (read from the verified plan's custody requirements and the binding's
  broker map), Purpose, Source assets, Linkage, Raw data centralized,
  Decryption control, Ownership retained, Location, Mechanism, Approvals,
  Authorization window, Unauthorized releases, Privacy policy, Execution
  evidence and Audit chain, plus a Revocations section. Linkage, Location
  and Privacy policy are NOT APPLICABLE when the signed binding,
  purpose and authorizations do not declare the feature (a status of its
  own that is not a pass of a requirement) and NOT EVIDENCED when they do.
  Decryption control is always NOT EVIDENCED: the key model is open
  (K-2) and nothing records it. The base report's version 1 owner
  authorization row is not counted in a governed report: the version 2
  rows replace it.
- **Three verdicts.** SATISFIED, NOT FULLY EVIDENCED (nothing failed, but
  something is unchecked or not evidenced) and NOT SATISFIED. Exit codes
  0, 3 and 1; 2 is a malformed or refused bundle.
- **Shared view: cards and disclosures.** A signed authorization names its
  approvers, so the shared bundle carries a card (the body without
  approvals, each approval as a per-project pseudonym, the document's ID)
  instead, and what rests on it is UNCHECKED until the owner discloses
  the signed document (`--disclosure`); a disclosed document replaces a card
  only if its ID is the card's. The organization's own view carries its
  own signed documents.
- **Determinism.** `exported_at` is the time of the log state (the latest
  checkpoint or the grant), `exported_by` the control plane's service ID,
  so the shared view is the same bytes for every member asking for one
  state.
- **Provenance.** The section exists and is committed to by digest, but
  holds only digests the control plane does not have yet; the report says
  provenance is not verified.
- **Limits.** One bundle carries at most 5,000 log events (ENC2730), and
  the route is limited to 12 requests a minute per caller.
- **Errors.** ENC2727 (malformed), ENC2728 (refused: unverifiable,
  forged signature, bad pins), ENC2729 (plaintext or a leaking view),
  ENC2730 (limits).
- **Not built here:** `--split DIR`, a `governance report --html`, the
  per-job approvals as signed evidence, and countersignatures by the
  control plane.

## Open decisions

These are recorded in the milestone plan's open decisions and are not
decided here:

- **G-2 Checkpoint witnessing and revocation heads.** Whether every member
  must co-sign project checkpoints, and whether owner revocation heads are
  required in every bundle. Recommendation: yes to both; they are what
  makes split views and omitted revocations detectable offline.
- **G-4 Bundle format and CLI naming.** A single signed `.encgov.json`
  (recommended, as above) and the command group
  `encompute governance {export, verify, report, countersign, sign}`.
- **K-2 Decryption-key custody** (ADR-025) decides which values the
  "Decryption control" row can show.
- **L-10 Wording** of report and limitation entries for recipient-held
  decryption, the absence of threshold decryption, central DP and linkage
  re-identification.

## Consequences

- An institution can check a cross-agency computation with its own pins
  and no network access, and hand the same file to its auditor.
- A historical audit stays green after authorizations expire or are
  revoked, while still showing their current state.
- Reports are longer and slower to produce than 0.3's, because the base
  report runs first and the spec is recomputed.
- Readers must understand that the report's trust is exactly their trust
  in their pins. Keys obtained from the bundle, or from the control plane,
  prove nothing.
- The shared view necessarily discloses some metadata (members, versions
  used, counts where allowed). That is disclosed, not hidden.
- New evidence kinds and graph version 2 mean older verifiers cannot read
  governance bundles; version 1 bundles stay readable.

## Alternatives considered

- **A server-rendered report.** Rejected: an agency would be trusting the
  control plane's rendering of its own evidence.
- **Keys shipped inside the bundle.** Rejected: a bundle that brings its
  own anchors can verify anything.
- **Judging validity at verification time.** Rejected (owner rule):
  lawful-at-the-time executions would fail after expiry.
- **Including released values for completeness.** Rejected: the bundle
  would become a copy of the result and could not be shared with auditors
  who may not see it.
- **"Probably NO" for Raw data centralized when evidence is incomplete.**
  Rejected: the row is NO only with signed backing, otherwise UNKNOWN.
- **A single view for everyone.** Rejected: approver identities and
  storage locations are an agency's private metadata.

## Relevant source modules

Planned changes touch:

- `crates/encompute-trust/src/{graph,ingest,report}.rs`, a new
  `crates/encompute-trust/src/governance.rs`
- `crates/encompute-cli/src/trust.rs`, new `governance` commands and
  `governance_explain.rs`
- `crates/encompute-control` (`GET /v1/jobs/{id}/governance-bundle`,
  views)
- `crates/encompute-assurance/src/catalog.rs` (INV-227, 229, 243, 244, 247)
