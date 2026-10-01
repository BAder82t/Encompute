# ADR-023 — Governed projects and owner-signed authorizations

Status: **Accepted** (2026-09-29) as design. Implementation starts after
0.3.0 ships; nothing in this record is part of 0.3. The items under
"Still open" are not decided. Built on the development branch so far:
phases 1 and 2, and phase 3 (purpose, program and source enforcement:
governed jobs, per-job four eyes, auditors and views, release classes,
derived results and exports, retention), complete as of 2026-10-01; the
"As built" notes record where the build refines this design.

## Context

Public institutions want to compute across organizational boundaries
without pooling sensitive records: an eligibility rule over three
agencies' registers, regional statistics, a model trained on data no
single party may see. Encompute 0.3 already has most of the machinery:
exact and approximate FHE, secure aggregation, differential privacy,
attested key release, per-organization brokers and a control plane with
projects and asset approvals. What it lacks is an authority model that
survives a distrustful setting.

Today authority over a collaboration sits in the operator's database:

- Control-plane `asset_approvals` are unsigned rows. They have no validity
  window and no program binding, so an approval authorizes any program in
  the project. Only the database knows about them.
- The trust graph's `SignedAuthorization` is signed, but has no project,
  version, `valid_from`, plan or spec, and `purpose: None` acts as a
  wildcard.
- The two systems are not connected.
- Trust-report expiry is judged on the verifier's clock, so valid
  historical evidence starts failing once an authorization expires.
- Privacy budgets are per asset, so a new version or a new project starts
  from zero.
- The auditor role can be combined with other roles.
- The audit chain is global, so proving one project's events reveals
  other organizations' events.

For an agency, "the platform operator's database says we approved it" is
not consent. An agency needs to sign what it allows with a key it holds,
and needs every enforcement point, including its own key broker, to check
that signature.

The rc.4 review fixes (ENC-SF-2026-088 to 092) close the 0.3.x gaps that
matter already: job purpose and source assets bound to the program,
human-only job approval, anchored withdrawal, cross-organization
redaction, and one broker per training spec. They are release blockers
for 0.3.0 and are not part of this decision.

## Decision

### 1. Settled architecture

- **An agency-signed authorization is the source of consent.** It is
  signed with the agency's governance key. That key stays in the agency's
  own KMS, HSM or Vault. The control plane stores only the public key, its
  key ID and its revocation state, and never the private key.
- **The control plane coordinates and enforces, but is not an
  authority.** It indexes authorizations, collects approvals, plans,
  schedules and issues tickets. A compromised control-plane operator can
  deny service or lie about state. It cannot manufacture an agency's
  authorization or obtain its keys.
- **The agency's own key broker is the final release authority.** It
  releases a key only when an owner-signed authorization, verified against
  the owner's pinned governance key, and a valid control-plane release
  ticket are both present. The ticket format and the broker's checks are
  in ADR-025.

### 2. Governed mode

- `CreateProject` gains an optional `governance: "standard" | "governed"`
  (default `standard`) and an optional `organizations: [...]`.
- The mode is **immutable** for the life of the project, enforced by a
  database trigger. A standard project never becomes governed and the
  reverse.
- Everything in this record applies to governed projects only. Standard
  projects and API v1 behave exactly as in 0.3. Every change is additive:
  optional request fields, new routes, new response fields and new enum
  values, following `docs/api-stability.md`.
- In a governed project:
  - PartyId equals OrganizationId.
  - Listed organizations are invited, and each organization's admin must
    accept.
  - **Every source-asset owner authorizes explicitly** (D12). There is no
    implicit authorization from membership.
  - **An owner's use of its own asset needs an authorization too** (D2).
    Owning a dataset does not exempt a job from the purpose, program and
    window checks.
- **Project charter.** A `ProjectCharter{name, members with their
  governance-key fingerprints, appointed auditor organizations,
  created_at}` is co-signed by every member's governance key. A membership
  change is a new charter version, co-signed by all current members and the
  joiner. The charter is trust-graph evidence.

### 3. Governance keys

- One active governance key per organization (table `governance_keys`).
- Registration by a human org admin; activation by a **different** human
  `security_admin`; revocation is anchored.
- Signing happens in the agency's KMS through the CLI or broker
  (`encompute governance sign`). The private key never reaches the control
  plane (D3).
- A later phase binds approvals to the agency's identity provider (subject,
  issuer, authentication time, MFA level). The approval format carries
  these fields from the start, so that phase changes verification, not the
  format.

### 4. Purpose objects and PurposeId

```
Purpose { version, project_id, name, revision, description,
          legal_basis_ref?, modes, allowed_release_classes, recipients,
          linkage_policy_id?, placement?, min_aggregate_parties?,
          valid_from, valid_until, created_by_org }
PurposeId = SHA256("encompute.purpose.v1" || 0x00 || canonical JSON)
```

- `name` equals the IR `Confidentiality.purpose` of every program run
  under it.
- `modes` is a subset of `RecordLevelExact | Aggregate |
  ModelCollaboration`. `RecordLevelExact` requires a `linkage_policy_id`
  (ADR-024).
- `legal_basis_ref` is an opaque label. Encompute records it, binds it and
  shows it; it never interprets it.
- Lifecycle `proposed → active → retired`. A human `security_admin` of the
  proposing organization proposes; a **different** human approves; every
  source-owner organization accepts with a governance-key signature.
- Editing creates a new revision with a new PurposeId. Retirement is
  recorded in the governance event log (section 11).
- At planning and submission, the program's declared purpose, the
  `Purpose.name` and the job's purpose must be equal.

### 5. The binding chain

Every new identifier is `SHA256(tag || 0x00 || canonical JSON)`:
`PurposeId`, `LinkageId`, `AuthorizationId` (tag
`encompute.authorization.v2`), `AuthorizationSetId` (over the sorted IDs),
`ProgramSetId` (`encompute.program-set.v1`), `AssetVersionId` (the hash of
the owner-signed version record) and `GovernanceId`
(`encompute.governance-binding.v1`).

```
GovernanceBinding { version, project, purpose_id, linkage_policy_id?,
  inputs:  map input -> { asset_version_id, digest_commitment, organization },
  outputs: map output -> { release_class, recipients },
  placement_digest?, project_policy_digest? }
GovernanceId = H(GovernanceBinding)
```

- **PolicyId** keeps its form. New optional IR fields (linkage, release
  forms, placement) are skipped when absent, so existing PolicyIds do not
  change.
- **ExecutionSpec** gains one optional field, `governance_id`, skipped when
  absent. `SPEC_VERSION` stays 1, as it did when `policy_id` was added.
  Linkage reaches the spec through the PolicyId and the binding, so there is
  no separate `linkage_id` field.
- **Authorization IDs are not in the spec.** Reissuing an authorization
  must not change what is computed or the FHE key IDs. They are bound in
  JobGrant v2 instead.
- **ConfidentialExecutionPlan** gains optional `governance_id`, placement
  constraints and key-custody requirements, all bound into the PlanId.
  Placement is in ADR-026.
- **JobGrant v2** (governed projects only) carries the real PlanId (today
  the grant carries the `pln_` row ID), `purpose_id`, the full binding (so
  the evaluator recomputes the spec), `authorization_set_id`, the evaluator
  operator and location, the FHE key IDs, and
  `not_after = min(authorizations' valid_until, purpose valid_until,
  assets' delete_after)`, with `expires_at = min(t0 + TTL, not_after)`.
- **ExecutionReceipt v4** gains an optional `grant_digest`. It ties an
  execution to the control plane's signed grant, and so to a signed
  execution time (section 8).
- The protocol envelope `Header` gains an optional `governance_id`; a
  mismatch is refused, so ciphertexts cannot move between projects.
- Field-sweep tests show that changing any field of the purpose, linkage
  policy or binding changes the PolicyId, PlanId, ExecutionSpecId and
  GovernanceId.

### 6. One owner-signed authorization: AuthorizationV2

One document, with the same bytes enforced by the control plane (as an
index), the key broker (as its release authority) and the governance report
(as evidence).

```
AuthorizationV2 (unknown fields refused) {
  version: 2, party, project, purpose_id,
  asset_version_id, asset_digest_commitment,
  program: ProgramId | ProgramSetId,
  policy_id, privacy_policy_id?, linkage_policy_id?,
  release_class, recipients[], placement?,
  privacy_scope_id?, execution_spec_ids?,
  limits { max_executions?, max_releases?,
           max_subjects_per_job?, max_evaluations_per_subject? },
  per_job_four_eyes: bool,
  valid_from, valid_until, issued_at, nonce,
  approvals: [ ApprovalEvidence { statement_digest, approver_subject,
                                  idp_issuer, auth_time, acr?, amr?,
                                  role, organization, at } ] }
SignedAuthorizationV2 = governance-key signature, domain "encompute.authorization.v2"
RevocationV2 { party, authorization, reason, issued_at }   (signed)
Approval statement = SHA256("encompute.approval.v1" ||
                            canonical{body without approvals, approver, role})
```

- **Purpose and project are mandatory.** There is no wildcard. A v1
  authorization never satisfies a governed project.
- **Program binding (D4).** `program` is exactly one ProgramId or one
  content-addressed ProgramSetId. It is never a pattern, prefix or
  wildcard. A changed rule is a different ProgramId and needs a new
  authorization.
- **Asset binding.** The authorization names one asset version by its
  `AssetVersionId` and a salted digest commitment. The agency's client
  encrypts only a file whose salted digest matches.
- **Release ceiling.** `release_class` and `recipients` bound what the
  program may release from this asset.
- `execution_spec_ids` optionally pins the authorization tighter, to
  specific specs.
- **Supersession** is revoke plus reissue. There is no in-place edit.
- **An approved authorization is immutable evidence.** Once its quorum is
  met (`approved`), and so once signed (`active`), its approvals are
  closed: no approval is added or removed (the control plane refuses with
  ENC2604, and database triggers refuse to add, remove or change its
  approvals and recipients, or to return it to `proposed`). Any change of
  meaning (program or program set, purpose, asset version, validity,
  release class, recipients, approvers) is a new authorization with its
  own four eyes. Withdrawal is revocation: a state transition of its own,
  never an edit.
- Where it lives:
  - control plane: tables `authorizations`, `authorization_recipients` and
    `authorization_approvals`. An authorization is proposed, collects its
    quorum, and becomes `active` only when its signature verifies against
    an active governance key. Routes `/v1/authorizations` and
    `/v1/authorizations/{id}/approve|signature|revoke`;
  - key broker: installed by the owner (`encompute keys authorize FILE`) or
    pushed by the control plane. Either way the broker verifies it against
    its pinned governance key before storing it, with its release counters
    and local revocations, in its MAC-protected state;
  - trust graph: `Evidence::Authorization` body v2.

As built (release classes and forms):

- Release classes form a partial order, decided by the owners: every
  class is within itself; `boolean-only`, `aggregate-only` and
  `dp-aggregate-only` are within `authorized-agency-only`;
  `dp-aggregate-only` is within `aggregate-only`; `derived-artifact-only`
  and `never` are within only themselves. `ReleaseClass::within` is the
  order; the control plane (at submission and when an authorization is
  proposed) and the key broker (at key release) decide with one shared
  function, so they cannot disagree. An output released as `never`
  releases nothing and stays within any ceiling, as before.
- Each class allows forms: `boolean-only` a boolean or bounded category,
  `aggregate-only` an aggregate with or without differential privacy,
  `dp-aggregate-only` a DP aggregate, `derived-artifact-only` a derived
  artifact, `authorized-agency-only` any form. At submission a class other
  than `authorized-agency-only` or `never` must admit a form the compiler
  proves the output takes; an integer counts as a bounded category only
  under a bound its sources declared (otherwise it is a value). Refusals
  are ENC2709.
- The IR asset policy has optional release forms (`release R forms
  [boolean, bounded_category 3, aggregate, dp_aggregate,
  derived_artifact]`), joined by intersection and skipped when absent, so
  existing PolicyIds are unchanged. A released output that cannot be
  proven to take an allowed form does not compile (ENC1907). Because a
  plan is compiled before submission, that error appears at planning; the
  submission check that recomputes the forms reports it as ENC2709.
- A dataset version may carry its owner's registered policy: `ir_policy`
  (the typed IR asset policy) and `release_class`, columns frozen with the
  rest of the version (schema version 10). A governed job's program must
  declare a policy at least as strict for that source
  (`analysis::confidentiality::refines`: same owners, release no weaker,
  readers, purposes, forms and derivations within the registered ones, the
  job's purpose among them, the same privacy budget), and every output's
  class and every authorization of the version stay within its registered
  class.
- Every source version of a governed project carries its owner's
  registered policy and release class: a job reading a version without
  them, or an authorization of one, is refused (ENC2709). Standard
  projects need neither.
- Probing controls, fail closed. A boolean-only release reveals little per
  job, but repeated questions (twenty questions) add up, and several
  boolean outputs of one job could jointly encode a value. An
  authorization whose ceiling admits boolean-only releases
  (`boolean-only`, `authorized-agency-only`) must carry
  `limits.max_executions` and `limits.max_releases`; the control plane
  refuses to propose, approve or activate one without them and the key
  broker refuses to install or release under one (ENC2709). One job
  releases at most `limits.max_outputs_per_job` boolean-only outputs per
  source, one when absent (skipped when absent, so existing
  AuthorizationIds are unchanged); the control plane at submission and the
  broker at key release decide with one shared function. These limits
  bound the channel; they do not remove it. Statistics over records belong
  in the differential-privacy classes.
- An output released as `never` names no recipient (the governance
  binding refuses one), so no ticket or later export can name one for it.
- Bounded categories rest on the integer range analysis, which is tested
  on every input of adversarial and random programs to never
  under-approximate.
- Classes cross derived results and exports (section 9, as built). Not
  yet: the purpose's `min_aggregate_parties` against aggregation minimums.

### 7. Four-eyes (D5)

- **Standing authorizations** need an approval rule per (project,
  organization): at least two **distinct humans**, by default one
  `data_owner` and one `security_admin`.
- **Per-job four-eyes** is optional, switched on by `per_job_four_eyes`,
  and may be required for sensitive release classes. Its record binds the
  job, spec and authorization set.
- A human approver counts only if:
  - the principal is a user, not a service account;
  - the user is active;
  - the user belongs to the approving organization (roles held in another
    organization never count there);
  - the user holds no auditor role;
  - the user is not the job's submitter.
- **Service accounts never count** toward any quorum. One person with two
  keys or two roles is one approver.
- The first implementation verifies the governance-key signature over the
  approval evidence. Verifying the IdP token itself (OIDC with `nonce =
  statement_digest`) at the broker and in the report is a later phase.

As built (per-job four eyes):

- A job waits for approval when an authorization it runs under asks for
  per-job four eyes; each such owner organization reaches its own approval
  rule's quorum for the project. The approval rule is the same one standing
  authorizations use, and one quorum check serves both.
- An approval is a statement over the job, its governed spec and its
  authorization set (`encompute.job-approval.v1`), stored append-only.
- Approvals are checked again at execution time. At scheduling and start
  an approval counts only while its approver is still an active user,
  homed in the organization, holding the role the approval counted for and
  not an auditor there. A job not yet scheduled whose approvals stop
  counting waits for approval again (it is not failed); a job already
  scheduled is refused at start and fails. The approval row stays as
  evidence.
- An approval rule never requires `auditor` (auditors never approve, so
  the rule could never be met) and names only known roles; the database
  refuses any other rule.
- Four eyes assume one canonical identity per person. The control plane
  counts distinct user identities (issuer and subject); two identity
  provider accounts for the same human would count as two people. Keeping
  one identity per person is an onboarding control of each organization's
  identity provider, outside Encompute.

### 8. Expiry and execution-time validity (D7)

- **Expiry is strict:** `valid_from ≤ t < valid_until`, with no margin.
- The 60-second clock skew applies only to validating signed tokens
  (tickets, grants, attestation `issued_at`), and always in the direction
  of denial. It never extends an authorization window.
- Validity is checked at plan creation; at submission (with the
  authorizations locked); at approval; at scheduling (the grant is
  capped at `not_after`); at start (the whole set must still be active,
  otherwise the job fails and is anchored as ended); at ticket issue; at
  key release on the broker's own clock; and at export and derived use.
- A job that started before `not_after` may complete. Whether its export
  also needs a ticket inside the window is open (K-7).
- **Historical verification judges validity at execution time, never at
  verification time.** The execution time is the control plane's signed
  `issued_at`/`expires_at` in the grant, reached from the receipt's
  `grant_digest` (`ExecutionReceipt` itself has no timestamp). The report
  shows "VALID AT EXECUTION" from that, and a separate "now:
  VALID/EXPIRED/REVOKED" line that never fails a historical audit. The
  report's rows and the evidence bundle are in ADR-027.
- Revocation and expiry affect future actions only. Receipts from inside
  the window stay verifiable.
- **Revocations carry their time, and the time decides.** The control
  plane records when a governance key, an authorization, a purpose
  (retirement) or a dataset version is revoked, on its own clock, once
  (the database refuses to change or clear it). A use at time `t` is
  refused when a revocation's time is `<= t`, and allowed when it is
  later. So revoking a governance key at `T` cascades to every
  authorization it signed, for the future: from `T` on no plan,
  submission, schedule, start, key release or export uses them (ENC2708),
  and a new key revives none of them, while an execution before `T`
  stays verifiable. `authorization_usable_at(authorization, t)` in the
  control plane and `SignedAuthorizationV2::usable_at(key, revocation,
  t)` in the trust crate are the one check every enforcement point calls.
  A document claiming issue at or after its key's revocation is never
  valid, whatever `t`.
- In a trust graph a revoked governance key is anchored with its
  revocation time (`GovernanceKey.revoked_at`), which never changes. An
  authorization it signed is accepted for current use only while the key
  is not revoked; as evidence of a use at `t` (`add_authorization_v2_at`,
  `rebuild_at`) it is accepted only when `t` is before the revocation.
  Rebuilt without a time, such an authorization is not a failure but is
  never current evidence: the report lists it as historically valid only.
  The time `t` comes from evidence the verifier trusts (the grant's
  signed issue time, a receipt, a ticket), never from the authorization's
  own dates, which a stolen key could backdate. A `RevocationV2` takes
  effect from its `issued_at`, never before.

### 9. Derived assets and revocation (D6)

- A released result is a first-class asset,
  `POST /v1/jobs/{id}/derived-assets` after success only.
- Its parents are forced to the job's source versions; its class and
  policy are the join of the parents and are never wider; its custodian
  comes from governance policy (by default the recipient organization),
  never the control-plane operator.
- Evidence: a `SignedReleaseRecord` from the decrypting recipient (salted
  output commitment, class, recipients, parents, onward policy).
- **Revocation blocks new use; it is not retroactive.** Revoking a source
  marks descendants with `source_revoked_at`, which blocks new use, export,
  re-encryption, key release and further derivation, and fails their
  unstarted jobs. Results already released remain valid historically.
  Lineage shows the later revocation and never claims erasure.
- Export is a new, ticketed action: every ancestor's authorization must be
  active and the class must allow the recipient.

As built (derived results and exports):

- `POST /v1/jobs/{id}/derived-assets`, once the job succeeded, by a person
  (never a service account or an auditor) of an organization the output
  names as a recipient; that organization is the custodian (the owners'
  default), and the result is a dataset version of its own, its key at a
  broker it registered. Its parents are the job's source versions, and
  nothing else is accepted.
- Never wider: its release class is within the output's, every parent's
  registered class and every authorization's ceiling in its lineage; its
  onward policy is within the parents' registered policies joined (every
  owner kept, the weakest release none exceeds, the readers, purposes,
  forms and derivations all allow, the same privacy budget). Refusals are
  ENC2709.
- The evidence is a `SignedReleaseRecord` in the trust crate, signed with
  the custodian's governance key and verified under its active key: a
  salted output commitment, the class, the parents, the authorizations
  the job ran under, the onward policy's digest, and the recipients with
  the export key of each. Every field must be the job's (ENC2704), and
  every recipient must be named by every authorization in the lineage.
  The job, output, custodian and record are frozen (schema version 11).
- Revoking a source marks each derived result downstream
  `source_revoked_at` (set once) and fails their jobs that have not
  started; the answer lists them and says `"erased": false`. The mark is
  not the authority: every governed use, derivation, release ticket and
  export walks the ancestors, whose revocation the state anchor holds.
  Only the starting assets are share-locked, the ancestors read, so the
  lock order stays that of revocation (ancestor, then descendants).
- K-7 decided: a job that started inside its window may finish, but
  nothing it released is exported after any authorization in the lineage
  ends (ENC2705).
- `POST /v1/assets/{id}/exports`, by a person of the custodian, issues a
  single-use export ticket for one recipient (issuing is shared with
  release tickets), with one append-only export row per ticket (a UNIQUE
  ticket ID). An owner's `max_releases` also bounds the exports of what
  was released under its authorization (ENC2714). The custodian's broker
  redeems it (see the sovereign keys record).
- Consent carries through derivation: a governed job reading a derived
  result runs only under an authorization of its custodian and of every
  organization owning data anywhere up its lineage (such an owner may
  authorize the derived version); the custodian's alone never suffices
  (ENC2701), checked at submission, scheduling, start and ticket issue,
  and again by the custodian's key broker, which verifies every lineage
  owner's authorization under that owner's governance key (see the
  sovereign keys record). Lineage owners therefore share their governance
  public key with the custodians' brokers.
- Limits carry through derivation: every job reading a result derived
  under an authorization, however many hops down, counts against its
  `max_executions` (at submission, scheduling and start), and every
  export of such a result against its `max_releases` (ENC2714). A key
  broker counts the releases and exports it makes itself, against the
  custodian's and every lineage owner's authorization.
- A derived result is visible beyond its custodian only to the recipients
  its signed record names, the owners of the data it derives from, and the
  project's auditor organizations.
- The control plane co-signs the custodian's release record once it has
  checked it against the result's real ancestry (every lineage owner
  named, under its active governance key): a `DerivedReleaseCosignature`
  over the custodian, the asset, the broker and key, the derived version,
  the record's ID and the lineage owners, signed with the control plane's
  key under its own domain (`encompute.derived-release-cosignature.v1`),
  returned at registration and frozen with the record. The custodian's
  broker binds the result's key only with it, so a record that leaves a
  lineage owner out is never bound (ENC2704).
- Lineage owners' governance keys reach custodians' brokers only through
  the control plane's attestation (`GET
  /v1/organizations/{id}/governance-key-attestation`, signed under
  `encompute.governance-key-attestation.v1` from the approved-keys
  record), never as a bare key the custodian types in.
- Revocations are forwarded: once an original owner's revoked
  authorization is anchored, `authorization.revoked` (deny-only, through
  the same outbox and anchor-gated delivery) goes to the broker of every
  custodian holding a result derived, every hop down, from a job that ran
  under it, as well as to the owner's own brokers.
- The custodian is trusted for the derived data it holds. The broker
  checks defend against a compromised control plane and a careless
  custodian, not a malicious one: the custodian holds the key material and
  runs the broker. Since the control plane now attests lineage owners'
  keys and co-signs records, a compromised control plane and a malicious
  custodian together could fake a lineage owner's consent; neither alone
  can.
- Decided (2026-10-01): the default export class is the result's own
  class; a derived result's policy keeps its parents' owners (ownership
  never moves to the custodian); recording a result after its
  authorizations' window has ended is allowed, while its export is
  blocked.
- The co-signature is re-fetched by the custodian's members only
  (`GET /v1/assets/{id}/release-cosignature`; anyone else gets not found).
  A lineage owner's key rotation would otherwise strand a result bound
  under the old key ID, so a security admin of the custodian has the
  control plane re-issue the co-signature (`POST` on the same path) with
  every lineage owner's active key ID: the record, version, parents, key
  and broker unchanged, a later issue time, stored append-only beside the
  frozen original and audited for the custodian and every lineage owner.
  The custodian's broker re-binds the key only with a re-issue signed by
  its pinned control-plane key, for the binding in force, changing only
  the lineage owners' key IDs, each the key it pinned from the control
  plane's attestation, and newer than the co-signature it holds.
- A custodian's broker relies on a lineage owner's pinned key only while
  the attestation it was pinned from is younger than a maximum age (24
  hours by default, configurable, at most 7 days, never unset): a key
  revoked at the control plane is otherwise unpinned only when a revoked
  attestation reaches the broker. The control-plane key the broker checks
  everything against is pinned in its authenticated state the first time
  it is configured, and replacing it is the owner's explicit, logged act.

As built (retention, phase 3):

- A dataset version carries three retention times, owner-declared at
  registration: `delete_after` (no use from then on; fixed, only ever
  brought forward by the owner, decided 2026-09-30), `retention_until`
  (until when the owner keeps the data; fixed, never after
  `delete_after`, which then cannot be brought forward past it) and
  `evidence_retention_until` (only ever extended). The owner's security
  admins and data owners change them through
  `POST /v1/assets/{id}/retention`, audited; the database refuses the
  same changes (schema version 12).
- Expiry runs in the control plane's background task: a version past
  its `delete_after` is marked expired, every derived result downstream
  is marked `source_expired_at` (set once), their jobs that have not
  started fail, the expiry is anchored, and only then is
  `asset.expired` sent to the key broker. Expiry blocks new use as
  revocation does (ENC2705 rather than ENC2706): every use, derivation,
  ticket and export walks the ancestors, whose expiry the anchor holds,
  so a restored database that undid it changes nothing and does not
  start.
- Consistent with K-7, a job that started before the deletion date may
  finish; nothing it released is recorded or exported once its source
  expired.
- Evidence outlives the data: receipts, audit events, anchors, release
  records and the trust report (which notes the expiry and does not fail
  on it) stay verifiable after the source is deleted. Deleting the data
  is the owner's storage's job; Encompute blocks use and records the
  expiry, and never claims the deletion. Nothing purges evidence yet.

### 10. Shared population DP cap (D8)

- `privacy_populations` are per dataset series by default, so a new version
  does not reset the budget. Each carries a hard cap in ρ, and **the
  population cap is authoritative**.
- `privacy_scopes(population, project, purpose, program?)` are
  sub-ledgers, allocated with four-eyes. A spend locks scope, then
  population, then the audit head, and appends to both.
- Both are anchored. An unrelated project has no scope, so it cannot spend
  and inherits nothing. Spend composes at the population and
  privacy-unit identity.

### 11. Auditor exclusivity (D9)

- The auditor role is exclusive of every other role, in every
  organization. If 0.3 compatibility prevents enforcing that globally at
  once (bootstrap admins receive admin, operator and auditor today),
  governed mode enforces it immediately, the legacy-admin report lists
  existing combinations, and a later migration removes them.
- Every mutating handler refuses an auditor.
- An auditor organization, appointed in the charter, cannot own, submit,
  receive or approve. It reads authorizations, policies, privacy spending,
  evidence, lineage, revocations and exports.

As built (auditors and views):

- Governed mode enforces exclusivity: in an organization taking part in a
  governed project, granting auditor with another role is refused, and
  an organization with such a combination neither creates nor joins a
  governed project (ENC2716). Bootstrap admins keep admin, operator and
  auditor, since the platform organization never takes part in a
  project; the legacy-admin report lists every combination.
- An auditor organization joins with `participation = 'auditor'` (fixed
  by its invitation) and takes part in governed projects only as an
  auditor. It registers no key broker, is named as no recipient, and is
  issued no ticket.
- One static table (`views.rs`) gives every organization that does not
  own a record the same bytes: approvers as a keyed pseudonym (HMAC over
  the project and the principal, under a key derived from the control
  plane's signing key, so a known principal ID cannot be confirmed),
  actors as organization and kind, no storage or key references. The
  governance binding's broker map is keyed by asset version, never by key
  reference; the broker looks up the version its key is bound to. Privacy
  ledgers stay the owner's until privacy scopes exist.

### 12. Governance event log (D10)

- **Interim** (early phases): the signed state anchor gains sets of revoked
  authorizations, withdrawn approvals, retired purposes, revoked governance
  keys and expired assets. Startup refuses a database that has undone any
  of them. `authorization.revoked` reaches the broker only after anchoring.
- **Before GA:** these growing sets are replaced by an append-only,
  hash-chained governance event log. It records issuance, withdrawal and
  revocation of authorizations, purpose retirement, governance-key
  revocation, asset expiry and revocation, membership changes and privacy
  scope allocation. The anchor carries only its signed, checkpointed root
  and size, and startup checks that the database log extends it.
- The log is partitioned per project with a Merkle root per project, so
  `GET /v1/projects/{id}/audit` returns that project's events with
  inclusion proofs and never another organization's.
- Each owner signs revocation heads, so an exported bundle cannot silently
  omit a revocation.

As built (event log, schema version 13; its head anchored in place of the sets):

- Every transition the state anchor records appends exactly one event in
  the same transaction: an asset revoked or expired, a service account or
  user disabled, a job cancelled or failed, an approval withdrawn or a
  grant ended, a project membership or organization role removed, an owner
  authorization issued or revoked, and, newly recorded, a purpose retired
  and a governance key revoked. A key revocation goes to its organization
  and to every governed project the organization takes part in; an
  asset's revocation or expiry to its owner and to every governed project
  that uses it (an authorization names it, or a job read it or a result
  derived from it, or derived such a result there). A
  repeated request that changes nothing records nothing; recovery's
  re-applications record the transition again.
- Partitions: a governed project's transitions go to `p:<project>`;
  everything of a standard project, and an organization's own transitions
  (its people, roles, assets and keys), go to `o:<organization>`; platform
  accounts to `platform`. Standard projects behave as before.
- An event holds identifiers only: its kind, subject, organization, time
  and a few related IDs (project, authorization and key fingerprints).
  Never an actor, a storage location, a key reference, a stated reason
  or other free text.
- All events form one hash chain; each partition is an RFC 6962 Merkle
  tree whose complete subtrees are stored, so roots and inclusion and
  consistency proofs read O(log n) rows. The formats (events, signed
  partition checkpoints, members' witness signatures, owners' revocation
  heads and equivocation evidence) are in `encompute-trust` (`govlog.rs`),
  implemented there from RFC 6962 and RFC 9162 and checked against the
  published test vectors and an independent reference construction. The
  database refuses to update, delete or truncate any of it.
- Lock order: the log's head is taken immediately before the audit head,
  which stays last; the audit append and the audit checkpoint take it
  first, so the two are always locked in that order. The database's
  refusals do not stop a database superuser (as with the audit chain).
- The state anchor (version 2) holds the log's size and chain head in
  place of the sets of IDs and of the privacy ledgers' checkpoints, so it
  is constant in size (see "Phase 4 complete" below). Each security-negative transition checkpoints the log before it
  is acknowledged: the events after the anchored head must link and hash
  correctly, each partition they touched gets a signed checkpoint, and
  the anchor records the new head. A key broker hears of a revocation or
  an expiry only once its event lies within the anchored size.
- Every start recomputes the whole log and refuses one that does not hold
  the anchored head at the anchored size, or whose partitions' latest
  checkpoints are no longer their roots (GOVERNANCE LOG STATE ROLLBACK,
  ENC2202, the code every state rollback uses); then a database that
  shows undone any transition the log records (now including retired
  purposes and revoked governance keys), or lost the row of one, is
  refused naming it. These checks are SQL semi-joins on the log's index
  of kinds, never sets held in memory.
- Recovery re-applies what the log records, each re-application an event
  of its own (`<kind>.reapplied`; `row.lost` for a lost row,
  `ledger.frozen` for a frozen ledger). It needs the log to hold the
  anchored head first: after restoring a backup older than the anchor,
  the log's missing events come back from a newer copy of its tables or
  an export, which is accepted only if it continues the database's log
  and reaches the anchored head.
- The anchor store keeps a mirror of the log: each checkpoint writes the
  new events as an immutable segment before the anchor's compare-and-set,
  which stays the commit point. Recovery after an older database backup
  takes the missing events from it, only up to the signed anchor's size
  and head; a suffix past it is an orphan, never used. Every start checks
  that the mirror reaches the anchored head. A security-negative
  transition's call returns only after its checkpoint (mirror, then
  anchor) is durable; if that fails the call fails, the database still
  enforces the change, and a retry anchors it.
- A version-1 anchor migrates once, at the first start, only after every
  check its release made passes: one transaction writes the genesis event
  (the version-1 anchor's digest; the signed anchor kept beside the log,
  outside the shared leaf) and one event per ID of its sets, then the
  anchor is replaced compare-and-set. A crash in between resumes; a
  version-1 anchor stored again after the log moved on, or another one
  than the migrated, is refused. Earlier releases refuse a version-2
  anchor: there is no downgrade.
- Project audit and witnessing (as built):
  - `GET /v1/projects/{id}/audit?after=&limit=` returns the events of
    `p:<id>` after position `after` (at most 500 per page) up to the latest
    signed checkpoint, each with its leaf hash and inclusion proof against
    that checkpoint, with the checkpoint and its witnesses. The route
    reads that partition only. Readers are the project's members and
    appointed auditors, by the roles of the shared audit view (auditor,
    organization admin, security admin); anyone else gets not found.
    Events are the shared-safe leaves, so the answer is the same bytes for
    every reader. `GET /v1/projects/{id}/checkpoints/latest?since=` adds
    the control plane's signed consistency proof from `since`.
  - A member organization countersigns a checkpoint with
    `POST /v1/projects/{id}/checkpoints/{size}/witnesses`. The caller is a
    human security admin of that organization (never a service account or
    an auditor); the signature verifies under the organization's active
    governance key (ENC2708 when revoked, ENC2701 when not its key); the
    organization was a member when the log had `size` events; the
    partition, size and root are the stored checkpoint's (ENC2718). A
    checkpoint is `witnessed` when every member of that size signed it and
    `unwitnessed` otherwise. The label is advisory and gates nothing (G-2).
  - The members at a size come from the log: a member joining a governed
    project is a `membership.added` event of the project's partition (not
    a deny event, so no forced checkpoint), and a removal records whether
    a member, an auditor organization or an invitation left. A project that
    predates the event counts its current members as members from the
    start. The project's owner is a member from the start.
  - Cadence: deny events are checkpointed before their call returns, the
    rest by the background pass (two seconds), so every state of the log
    is soon a checkpoint a member can witness; the checkpoint is stored
    once per size and never replaced.
  - `encompute governance witness` fetches the latest checkpoint and the
    consistency proof from the last witnessed one (kept in a state file
    that pins the control plane's public key), signs only if the new
    checkpoint extends it, and otherwise exits 1 with an equivocation
    proof written beside the state file; `check-equivocation` verifies two
    signed checkpoints (the same size with different roots, or a larger
    tree that does not extend a smaller one by the control plane's own
    signed consistency proof). A rollback is a typed `RollbackProof`: a
    checkpoint the member holds, and the control plane's signed latest
    one of the same partition that has fewer events and was signed no
    earlier; both signatures are the control plane's, the verifier is in
    the trust crate and `check-equivocation` accepts it. A smaller
    checkpoint signed earlier is a stale answer: refused, no evidence.
    When `since` is larger than the latest checkpoint the control plane
    answers 200 with the checkpoint and no proof.
  - What witnessing does and does not detect, stated plainly. Split views
    are detected only when members exchange checkpoint files and run
    `check-equivocation`: there is no gossip. A control plane that
    freezes, withholds or serves an old checkpoint cannot be told from a
    network failure. A control plane that shows every member the same
    history, or that no member witnesses, is not caught. The `witnessed`
    label in an answer is the control plane's computation: `encompute
    governance verify-audit` recomputes it, verifying every inclusion
    proof, the members from the verified membership events (the owner,
    and members that predate the events, are on the control plane's word
    and listed as such) and each witness under the organizations' pinned
    governance keys; without pins it reports that witness signatures
    were not verified.
  - A former member may countersign the sizes at which it was a member
    (the witness route only; every read stays closed to it).
  - Cost: a page (200 events at most) of proofs reads its tree nodes in
    one range statement, complete subtrees are cached in memory (they
    never change), the membership events are read through a partial
    index, and a caller is limited to 120 requests a minute on the three
    routes (503). `after`, `limit` and `since` that are not whole numbers
    are 400.
- Owner revocation heads (as built, decision G-2: a bundle carries the
  owners' signed heads dated at or after the grant):
  - A head is `{version, organization, project, seq, root, at}` signed
    with the organization's governance key. Its `root` is an RFC 6962
    tree over the organization's revocations in the project, as sorted,
    distinct leaves `<kind>:<id>` (each hashed under its own domain; the
    empty set has a root of its own, never the digest of no bytes). The
    leaves are folded from the project's own partition by one function the
    control plane and every reader share: an authorization revoked (named
    by its signed document's ID, and its signed revocation as a leaf of
    its own), an asset of the organization revoked or expired where the
    project used it, a purpose it retired, a governance key it revoked.
  - `GET /v1/projects/{id}/revocation-heads/{org}/draft` states the
    leaves, the root and the next number to the organization's security
    admins and the project's auditors (read-only; the post route refuses an
    auditor). `encompute governance sign --kind revocation-head` recomputes
    the root from the leaves and refuses a draft whose root is not theirs;
    `--verify-draft` prints what would be signed.
  - `POST /v1/projects/{id}/revocation-heads` takes the log's head lock
    first (the audit head stays last), then checks the signature under the
    organization's active key (ENC2708, ENC2701), that the number is one
    past the previous head, that the date is at most 300 seconds ahead and
    not before the previous head, and that the root is the control
    plane's own fold of the log (ENC2717). It stores the head and appends
    `revocation_head.signed` (the number and root: not a deny event, no
    forced checkpoint). The organization must be the project's owner or a
    member; a former member and an auditor organization have no head.
  - Atomic revoke and head. A governed revocation owes the next head. The
    least intrusive design that keeps every existing revoke call working:
    the authorization revocation and the purpose retirement accept an
    optional `revocation_head` for the new set, checked after the
    revocation's events are appended in the same transaction, so a refused
    head (ENC2717) rolls the revocation back. Without one the revocation
    takes effect at once (a revocation must never wait for a signature)
    and records nothing more than its own event, so every transition
    stays exactly one event: a head covers the revocations recorded before
    its own event, so the head owed is the revocations after the latest
    head's event, derived from the log by anyone (`pending_since`). An
    asset's revocation or expiry and a governance key's reach several
    projects and cannot carry one head for them all: each leaves a head
    owed in every project it reached. Nothing blocks while a head is owed:
    the draft shows `pending_since`, `overdue` after 24 hours, and a
    bundle checked against a head that is behind is UNCHECKED. A standard
    project has no head, and naming one in its revoke is refused.
  - The trust crate decides what a head says of a bundle: `covers`
    (the root over exactly the bundle's leaves), `latest_at_or_after` and a
    verdict: covered, omitted revocation, head too old or missing
    (UNCHECKED, never a pass), head under a key revoked by its date, bad
    signature. `encompute governance verify-audit` with pins runs the same
    check per organization against the verified events and exits 3 without
    pins unless `--allow-unpinned` is given.
  - Judged through the log, not by the signer's date (review fixes). A
    verifier given the project's proven events (`check_revocation_heads`)
    takes the organization's latest `revocation_head.signed` event as the
    head that counts and requires that head to be supplied (a bundle with
    only an older head, or none, is UNCHECKED), signed under the pinned
    key and not recorded after its key's revocation event (a thief's head
    signed offline is not in the log). Covered means as of the head: it
    must be dated at or after `as_of` and nothing may be recorded after its
    event; revocations after it are a head owed (UNCHECKED), and
    OmittedRevocation means only that a revocation the head covered is
    missing. A head under another key than the pinned one is a head owed
    under the current key (UNCHECKED). Two heads of one number with
    different roots are an owner equivocation proof (`HeadEquivocation`).
    The control plane also refuses a head dated before the newest
    revocation it covers or more than 60 seconds ahead, and answers a
    refused head 409 with the current draft; the draft carries the log size
    and `cannot_sign_reason`. An organization that left or has no active
    key cannot clear a head it owes, and its bundles stay UNCHECKED.
  - Not covered: a revocation the owner never made; an owner that never
    signs a head, so its bundles stay UNCHECKED; and the time between a
    revocation and the next head.

### 13. Error codes (D13)

The block ENC2701 to ENC2712 is reserved for governed projects:

| Code | Meaning |
|---|---|
| ENC2701 | Missing owner authorization |
| ENC2702 | Purpose mismatch |
| ENC2703 | Program not authorized |
| ENC2704 | Asset or version mismatch |
| ENC2705 | Authorization expired |
| ENC2706 | Authorization withdrawn or revoked |
| ENC2707 | Four-eyes approval incomplete |
| ENC2708 | Governance key revoked |
| ENC2709 | Release class or output form not allowed |
| ENC2710 | Residency or placement unsatisfied |
| ENC2711 | Linkage mismatch |
| ENC2712 | Release ticket invalid or expired |

A compile-time output-form violation uses a new compiler code, ENC1907,
which maps to ENC2709 at runtime. The codes enter `docs/errors.md` when
their checks are implemented (ENC1907 and the release-class checks of
ENC2709 are in).

### 14. Invariants (D11)

- The public-sector invariants continue the catalog sequentially from
  **INV-218**, with area `public-sector`. There is no separate numbering
  block.
- The catalog's maximum is INV-217 on 2026-09-29. If the rc.4 fixes take
  IDs from 218, the whole block shifts to the next free ID, keeping its
  order.
- Existing claims are extended rather than duplicated where they already
  cover part of the ground (for example INV-194, 195 and 196).
- Every new enforcement point in this record gets a catalog entry with
  positive, negative and adversarial evidence, and the release gate
  requires area `public-sector` to pass.

## Consequences

- Consent moves out of the operator's database into documents each agency
  signs with a key it controls. A database edit, a restored backup or a
  compromised control plane cannot create an authorization; at worst it
  can deny service or delay a revocation's delivery, which the owner can
  still enforce locally at its broker.
- One document serves three enforcers. The control plane, the broker and
  the report cannot disagree about what was authorized, because they check
  the same signed bytes.
- Standard projects, API v1 and existing evidence are unaffected.
  Governed-mode objects are new versions (authorization v2, grant v2,
  receipt v4, trust graph v2); v1 objects stay verifiable, and v1 bundles
  load read-only.
- Agencies must operate a governance key in their own KMS or HSM and staff
  two distinct approvers per authorization. That is deliberate friction.
- Program binding without wildcards means every rule change needs new
  signatures. Program sets keep this manageable for a known family of
  programs.
- Strict expiry means jobs near the end of a window fail rather than run
  late. Historical evidence is unaffected.
- A shared population cap means cumulative privacy loss is tracked per
  population, across projects and versions. Scopes can run out while the
  population still has budget, but never the reverse.
- The anchor grows until the event log lands; the event log is a GA
  requirement, not optional.
- The design adds new failure modes to test: every enforcement point is
  paired with an invariant and an attack demonstration.

## Still open

These are recorded in the milestone plan and are not decided here:

- **K-7** (decided 2026-09-30): a job running when its window ends
  finishes, and its export is then blocked (built, section 9).
- **G-2:** whether every member must co-sign project checkpoints, and
  whether owner revocation heads are required in every bundle
  (recommended: yes to both).
- The IdP-bound approval phase: which identity providers and which MFA
  levels count.

## Alternatives considered

- **Database-only authorization (the 0.3 model, extended).** Add windows,
  programs and quorum to `asset_approvals`. Rejected: the operator's
  database stays the authority, so a compromised operator or a restored
  backup can create or resurrect consent, and no agency can check it
  independently.
- **Owner-signed only, no control-plane index.** Agencies exchange signed
  documents and brokers check them; the control plane knows nothing.
  Rejected: nothing would refuse a job at submission, collect quorums,
  cap grants or schedule against authorization windows. Failures would
  surface only at key release, after work was done.
- **Hybrid (chosen).** One owner-signed document, indexed and enforced
  early by the control plane, verified independently by the broker and the
  report.
- **A broker-local release authorization.** A separate record at each
  broker, written by the owner, independent of the control plane's
  record. Rejected as a separate document: two records drift. It survives
  as the broker's verified copy of the same AuthorizationV2 plus its local
  counters and revocations.
- **Program patterns or wildcards.** Rejected (D4): an authorization that
  matches "any version of this rule" authorizes rules nobody reviewed.
- **A clock-skew margin on authorization windows.** Rejected (D7): skew
  belongs to token validation, and always toward denial.
- **Judging validity at verification time.** Rejected: evidence of a
  lawful-at-the-time execution would fail after expiry, and auditors would
  learn nothing about when the job actually ran.
- **Independent per-project privacy budgets.** Rejected (D8): a new
  project or version would reset cumulative loss for the same people.
- **A separate INV-300 block.** Rejected (D11): the catalog stays one
  sequence.

## Relevant source modules

Planned changes touch:

- `crates/encompute-control/src/ops/{tenancy,assets,jobs}.rs`, new
  migrations under `crates/encompute-control/migrations/`
- `crates/encompute-trust/src/authz.rs`, `crates/encompute-trust/src/report.rs`
- `crates/encompute-verification/src/spec.rs`,
  `crates/encompute-verification/src/service.rs` (JobGrant)
- `crates/encompute-protocol/src/lib.rs` (envelope header)
- `crates/encompute-keybroker` (authorization install and verification)
- `crates/encompute-assurance/src/catalog.rs` (INV-218 onward)

As built (phase 4 complete; privacy ledger checkpoints in the log, a
constant-size anchor):

- A privacy ledger's checkpoint is an event of the platform partition:
  `privacy.ledger_checkpoint`, subject the asset, with the entry count
  (`seq`) and the root, which is what the version-1 anchor held per ledger
  and no more: no amount, no event ID. It is not a deny event. Spend
  amounts stay in the database and the ledger; only the checkpoint root
  the owners could already verify is shared.
- `anchor_ledger` (after each spend, and when a ledger is created)
  verifies the ledger outside any lock, then takes the log's head lock,
  reads the asset's latest checkpoint event (one probe of a partial
  index on subject, newest first) and requires the ledger to extend it:
  one that does not is refused (ENC2202, PRIVACY STATE ROLLBACK) and
  nothing is appended; one that is no further appends nothing. Otherwise
  it appends the checkpoint, then checkpoints the log (mirror, anchor)
  before returning, skipping the checkpoint when a concurrent spend's
  already covers its event. The spend's own transaction is unchanged; it
  reads the latest checkpoint event inside it (without the head lock) to
  refuse a rolled-back ledger at once.
- Startup takes each ledger's floor from the latest checkpoint event of
  each asset the log names, after the log has been checked against the
  anchored head; so a ledger restored behind it, or a missing ledger, is
  refused as before, and recovery freezes it and appends a checkpoint at
  what the database holds (the floor moves forward along the log; the
  freeze is a deny event, checkpointed before recovery returns).
- The anchor therefore carries no `ledgers` and no `frozen` field: it is
  the counter, the audit root and seq, the log's size and head, the
  migration record and the signature, constant in size. A version-1
  anchor's ledger checkpoints become `privacy.ledger_checkpoint` events
  after the genesis in the migration transaction (its frozen ledgers
  `ledger.frozen`, as before). Version 2 had not been released, so it
  stays version 2; earlier releases still refuse it.
- Cost: one event (about 300 bytes) per spend in the log and its mirror,
  one more durable write per spend (the mirror's open segment) beside the
  anchor's, and a startup that recomputes the whole log. Snapshots of the
  log's frontier for startup, and compaction of the mirror, are not built
  (the chain is always recomputed in full).
- Lock order: the log's head lock before the audit head, as everywhere;
  the anchor's lock is never waited for while a database lock is held.
