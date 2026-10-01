# ADR-025 — Sovereign keys and two-part key release

Status: **Accepted** (2026-09-29) for the two-part release rule, custody
modes, release tickets and the fail-closed behaviour, as design.
**Implemented** (2026-09-30) as phase 2 of the public-sector milestone:
two-part release, tickets, sovereign custody, per-asset broker binding and
the broker-state generation mark; see "Phase 2 as built" below. K-1, K-4
and K-5 are **decided**; the other items under "Open decisions" are
**Proposed** and not decided. Nothing here is part of 0.3.

## Context

In a cross-agency project, each agency must keep its keys under its own
control, in its own KMS, and must be the one that finally decides whether a
key is released. Encompute 0.3 goes part of the way:

- Each key broker's KEK is wrapped under the organization's root key in its
  KMS (OpenBao/Vault Transit), and a broker serves one organization.
- Attested key release binds the workload, spec and policy.
- But: a platform broker may hold any organization's keys; the rc.4 fixes
  restrict a training spec to one broker rather than binding each asset to
  its owner's broker; the client's FHE `secret.key` is an unencrypted file;
  and a broker releases on the strength of its release policy and the
  control plane's grant. A compromised control plane that forges state is
  therefore a key-release risk, not only an availability risk.

ADR-023 makes the agency-signed authorization the source of consent. This
record makes the agency's broker enforce it.

## Decision

### 1. Two-part release

The agency-owned key broker is the final release authority. It releases a
key only when **both** are present:

1. an **owner-signed AuthorizationV2** (ADR-023), installed at the broker
   and verified against the owner's pinned governance key; and
2. a **valid control-plane release ticket**: short-lived, single-use,
   signed by the pinned control-plane key, and matching the job.

A ticket without an authorization is useless, so a compromised control
plane can only deny. An authorization without a ticket releases nothing,
so a stolen authorization cannot be replayed outside a scheduled job.

### 2. Key classes

| Class | Holder | Protects |
|---|---|---|
| K1 org root key | the organization's KMS | K2 |
| K2 broker KEK (wrapped) | broker | K3, K4, the state MAC |
| K3 asset data key, per version | owner's broker | sealed assets |
| K4 grant-signing key | owner's broker | grants (pinned in the attested identity) |
| K5 FHE secret key | decryptor, KMS-wrapped | its ciphertexts |
| K6 FHE public and evaluation keys | encryptors and evaluator | encryption and evaluation |
| K7 evaluator receipt key | evaluator | receipts |
| K8 session HPKE key | TEE | grants in transit |
| K9 SecAgg keys | parties and coordinator | masks |
| K10 control-plane signer | control plane | grants, tickets, anchor |
| K11 governance key | the agency's KMS or HSM | authorizations, charter, versions, revocation heads |
| K12 linkage key | depends on the scheme (ADR-024) | pseudonyms |
| K13 derived-artifact key | custodian's broker | released artifacts |

No key is shared by the project, and the control plane holds no key that
protects data.

### 3. Custody modes

- `Custody{Standard, Sovereign}`. **Governed projects are always
  sovereign** (decided in phase 2; standard custody exists only for
  standard projects, and a project's custody never changes).
- Brokers are registered per organization:
  `POST /v1/organizations/{org}/key-brokers` (grant public key, provider
  kind, `key_ref` namespace, location).
- In Sovereign mode, registering an asset requires a broker of the asset's
  own organization.
- Planning checks each source's owner broker (instead of "some broker
  exists") and emits a key-custody requirement per asset, which binds
  custody into the PlanId and appears in the report.
- **Per-asset broker binding.** A map `asset_brokers: asset or key id →
  BrokerId` goes in the training spec and, through the GovernanceBinding,
  in execution identities. Acquiring a key requires
  `asset_brokers[asset] == grant.broker_id` and a pinned signer for that
  broker. This replaces the rc.4 one-broker-per-spec restriction safely,
  and lets confidential model collaboration keep each owner's keys at the
  owner's broker.
- **FHE secret keys** (K5) in governed projects are wrapped under the
  decryptor's K1, through a KMS-backed client key store. This also removes
  the unencrypted `secret.key` file for governed projects.

### 4. Release tickets

```
ReleaseTicket { ticket_id, kind: KeyRelease | Decrypt | Export,
  organization, broker, asset_version_id, authorization_ids,
  job_id, project, purpose_id, governance_id, plan_id,
  execution_spec_id, policy_id, workload_or_recipient,
  placement_digest, not_before,
  not_after = min(now + 300 s, job.not_after, grant.expires_at),
  anchor_counter, issuer, issuer_public_key, signature }
```

- Signed under its own domain (`KEY_TICKET`).
- Issued at scheduling, or on request by the scheduled workload or the
  recipient only (`POST /v1/jobs/{id}/release-ticket`). Every issue is
  audited.
- **TTL 300 seconds**, and never beyond the job's or grant's window. The
  owner decision was "minutes" (D7); the shorter of the two proposed
  values was taken.
- Single-use: the broker persists seen `ticket_id`s until `not_after`.

### 5. Broker checks

`release_key(session, asset, authorization_id, ticket)` checks, in order,
and refuses at the first failure:

1. the session exists;
2. the secret exists and is not revoked;
3. the existing release policy (attestation, spec, policy) passes;
4. the AuthorizationV2 is installed, verifies under the pinned governance
   key, belongs to this organization, and is not locally revoked;
5. the spec, policy, privacy policy, linkage policy and program are covered
   by it;
6. `valid_from ≤ now < valid_until` on the broker's own clock, strictly,
   and the attestation's `issued_at` is before `valid_until`;
7. the attested placement is admitted; missing placement evidence means
   not admitted;
8. the ticket is signed by the pinned control-plane key, is for this
   organization, matches the request, is inside its window (60 seconds of
   skew, applied toward denial) and has not been seen;
9. the authorization's limits allow the release; counters are incremented
   and persisted **before** the key is granted;
10. a grant header (version 3 as built; see below) is issued, naming the authorization, project, purpose,
    `valid_until` and ticket, with
    `expires_at = min(session expiry, valid_until)`.

The broker signs a `KeyRelease` receipt (never containing a key) for the
evidence bundle.

### 6. Fail-closed rules

- **Broker unreachable:** nothing is released.
- **Control plane down:** nothing is released, and the owner can still
  revoke locally at its broker. A local revocation takes effect at once,
  without the control plane.
- **Compromised control plane:** it can deny service or delay delivering a
  revocation. It cannot release a key, because it cannot sign an
  authorization.
- **Unknown or unpinned governance key, ticket signer or broker:** refused.
- **Revocation messages:** the control channel, which accepts only
  `asset.revoked` today, gains `authorization.revoked` and `asset.expired`.
  Each is sent only after it is anchored.
- **Missing evidence never passes:** no placement evidence, no installed
  authorization or an unparseable ticket are refusals, not warnings.

### 7. Placement evidence levels

- Evaluators and brokers carry a `Location{jurisdiction, provider, region,
  zone}` with evidence ordered
  `SelfDeclared < OperatorDeclared < Attested`:
  - `SelfDeclared`: the service says so. **Never satisfies production.**
  - `OperatorDeclared`: signed by a human `security_admin` of the operator
    organization, audited and recorded in the governance log.
  - `Attested`: taken from a verified TEE attestation (for Confidential
    Space, the GCE zone in the attestation), refreshed after a maximum
    evidence age.
- The report labels every location "attested" or "declared".
- The broker checks attested placement per session (check 7).
- Region is not jurisdiction. Placement constraints therefore also name
  allowed operators. The legal assessment of a location stays with the
  owner.
- How placement constraints are declared, combined, planned and enforced
  is in ADR-026.

## Phase 2 as built

Recorded 2026-09-30, closing phase 2. Where this differs from the design
above, this section is what was built.

- **Grant header version 3.** The governed grant header is version 3,
  not 2 as section 5 first said: version 2 was already taken by the
  governed job grant of phase 1. Version 2 grants are byte-identical to
  before.
- **Placement in phase 2.** Check 7 cannot be met yet, because there is no
  attested placement. The rule until it exists: a governed execution that
  declares placement is refused (ENC2710); one that declares none passes
  the check. Declared placement is never taken as evidence.
- **K-1 (decided): tickets are mandatory in governed projects.** A broker
  releases without a ticket only as a development broker in an
  environment that says so explicitly (`ENCOMPUTE_ENV=development` and
  development mode, `serve --no-require-ticket`); a production broker
  refuses the setting. An authorization is required either way. Once a
  governance key is pinned, the plain release path refuses every key.
- **K-4 (decided): platform brokers are refused in sovereign custody,**
  and governed projects are always sovereign. The control plane refuses a
  platform broker when an organization registers it as its own, when an
  asset of a governed project names it, when a ticket is requested and
  when a program reading such a source is planned.
- **K-5 (decided and built): the generation mark.** A governed broker
  records its state generation and state MAC in the organization's KMS
  (OpenBao or Vault KV-v2, compare-and-set) after writing its state file
  and before it grants or acknowledges. It refuses a state older than the
  mark, a different state at the mark's generation, and a state one save
  ahead of the mark unless that state names the mark's MAC as its
  previous state. Crash recovery at mark + 1 is therefore hash-chained:
  only the write that was actually in flight is recovered, never a file
  from another history. A governed production broker refuses to run
  without a mark; an unreachable mark grants nothing (503). The first
  marking can check an expected generation and MAC.
- **Missing rows count as undone.** On the control plane, revoked
  authorizations (row and document IDs) and expired assets are anchored,
  and `authorization.revoked` and `asset.expired` reach brokers only after
  anchoring. For every anchored security-negative set with rows (revoked
  assets and authorizations, disabled users and service accounts, ended
  jobs, expired assets), a row missing from the database refuses start as
  a rollback would; only recovery can acknowledge the loss, which it
  records in the signed anchor and the audit trail, and the ID stays
  blocked. Governance tables refuse DELETE.
- **Per-asset broker binding** is built as `asset_brokers` (key ID to
  broker) and `broker_organizations` (broker to party) in the training
  spec, and `asset_brokers` in the GovernanceBinding. Without them, IDs
  and the rc.4 one-broker rule are unchanged.
- **Tickets are issued on request only** (`POST /v1/jobs/{id}/release-ticket`,
  by the job's scheduled evaluator), not at scheduling. The ticket's
  `anchor_counter` is carried but not yet checked by brokers.
- **Invariants.** INV-232 (release tickets and two-part release), INV-235
  (sovereign custody and per-asset binding) and INV-236 (the control
  plane can only deny; broker-state rollback), in the `public-sector`
  area.

## Exports as built (phase 3)

- **Export tickets.** `TicketKind::Export` is issued by the one ticket
  path the control plane has (`issue_ticket`), to a person of a derived
  result's custodian for one recipient: the ticket names the recipient
  (`recipient`, present only on export tickets, so key-release tickets
  are unchanged), the result's version as `asset_version_id` (not a source
  in the binding), the job's execution spec, binding and authorizations,
  and, as `workload_or_recipient`, the export key the custodian's signed
  release record gives that recipient.
- **Redeemed at the custodian's broker** (`POST /v1/export/governed`),
  only for a key bound to a derived result (`bind_derived_version`, set
  once; such a key is never re-bound as a source, and a source key is
  never exported). The broker verifies the custodian's release record
  under its pinned governance key, then runs the same ticket functions a
  key release runs (signature before any field is used, window with the
  skew toward denial, kind, organization, broker and version, single use
  through the same seen-ticket set, persisted before the key is sealed),
  requires the ticket's job, binding and authorizations to be the
  record's and its recipient and key to be ones the record names, and
  seals the key to that export key. A compromised control plane can deny
  an export, never redirect one.
- **Lineage owners at the custodian's broker.** A derived result's release
  record names every other organization whose data it derives from, with
  its governance key ID; the custodian binds the result's key with the
  record and the control plane's co-signature of it
  (`bind_derived_version`, ENC2704 without a valid one for this record,
  broker, key and set of lineage owners), so a record the control plane
  did not validate against the result's ancestry, such as one leaving a
  lineage owner out, is never bound. Its owner pins each lineage owner's
  governance key at its broker from the control plane's attestation of it
  (`pin_lineage_governance_key`, `encompute keys governance-key
  pin-lineage --attestation FILE` or `--url`): signed under the pinned
  control-plane key, for that organization, with the key's own ID
  (ENC2708 otherwise). A later attestation of another key replaces the pin
  (rotation; results whose record names the old key then fail closed), an
  earlier one never does, and an attestation that the key was revoked
  unpins it for good. Each lineage owner installs its authorization there.
  A key release for a job over the result, and an export, then require an
  installed authorization of every lineage owner, named by the ticket,
  verified under its pinned key and passing the same coverage, window and
  limit checks as the custodian's own, and count against each. A missing
  or different pinned key is ENC2708, a missing authorization ENC2701. The
  control plane therefore cannot substitute for any lineage owner's
  consent.
- **Revocations reach custodians.** Once an original owner's revoked
  authorization is anchored, the control plane sends
  `authorization.revoked` to the broker of every custodian holding a
  result derived from a job under it (every hop), naming the custodian's
  organization; like any control-plane message it only denies, and only
  for an authorization installed there.
- **Who is trusted for what.** The custodian runs its broker and holds the
  derived result's key, so it is trusted for that data. The broker's
  lineage checks defend against a compromised control plane (it cannot
  sign a lineage owner's authorization) and a careless custodian (it
  cannot pin a key or bind a record the control plane did not vouch
  for), not a malicious one, which can use the key material it holds
  directly. A compromised control plane and a malicious custodian
  together could fake a lineage owner's consent (an attested rogue key,
  a co-signed record): that combined compromise is the residual.
- **Decryption tickets** are neither issued nor accepted.

## Open decisions

These are recorded in the milestone plan's open decisions and are not
decided here:

- **K-1 Development exception to tickets.** Decided 2026-09-30: tickets
  are mandatory in governed projects; the exception exists only for a
  development broker with `ENCOMPUTE_ENV=development` (see "Phase 2 as
  built").
- **K-2 Decryption-key custody for record-level and statistics
  collaboration.** M1, recipient-held and KMS-wrapped (ships soonest;
  confidentiality against the recipient rests on the evaluator operator not
  colluding, disclosed in the report); M2, an attested TEE decryptor (needs
  the Confidential Space live run); M3, threshold or multi-key decryption
  (research; BinFHE threshold support is unverified). Recommendation: M1
  now, M2 as the strong profile, M3 as research.
- **K-3 Location evidence in production.** `OperatorDeclared` as the floor;
  whether `Attested` is required when prohibited locations are declared.
  Recommendation: the floor now, `Attested` in the strong profile.
- **K-4 Platform brokers in sovereign projects.** Decided 2026-09-30:
  forbidden outright, and governed projects are always sovereign.
- **K-5 Broker state rollback guard.** Decided and built 2026-09-30: a
  generation mark in the organization's KMS (KV-v2 with compare-and-set),
  required for a governed production broker. A standard broker may still
  run without one, and there rollback is handled by procedure only.
- **K-6 One FHE key per (project, purpose, linkage epoch).** Cryptographic
  purpose separation, at about 525 MiB of BinFHE evaluation keys each.
  Recommendation: yes.
- **K-7 Expiry during a running job.** Finish but block export after
  `valid_until` (recommended), or abort.
- **K-8 Location taxonomy and KMS adapters.** Who maintains the location
  table, and the adapter order after OpenBao (PKCS#11, then GCP KMS/EKM,
  Azure Managed HSM, AWS KMS).
- **K-9 Residency scope.** Whether constraints cover ciphertexts, keys and
  evidence at rest, not only plaintext. Recommendation: all by default.
- **O-1 Operator-owned evaluators.** Evaluators are platform services
  today. Whether a designated operator organization may register them in
  governed projects, which operator separation needs. Recommendation: yes.

### External review scope (key model)

Together with ADR-024's linkage review:

- BinFHE public-key encryption with ciphertext switching: noise after
  switching, and the security label of the new profile;
- binding evaluation keys to the announced public key;
- the chosen decryption-key model (K-2), and its collusion assumptions.

## Consequences

- Each agency can check, from its own broker's state and receipts, that no
  key left it without its own signature.
- Brokers gain state (installed authorizations, counters, seen tickets),
  which makes broker state rollback matter; the K-5 generation mark
  addresses it. Governed releases at one broker are serialized behind the
  mark's compare-and-set.
- Key release needs the control plane and the broker both to be up. That
  is the price of the control plane not being an authority.
- Per-asset broker binding lifts the rc.4 one-broker restriction without
  reopening the cross-owner grant confusion it closed.
- Per-purpose FHE keys, if adopted, multiply evaluation-key storage and
  upload time.

## Alternatives considered

- **Broker trusts the control plane's grant (0.3).** Rejected for governed
  projects: a compromised control plane could release keys.
- **Broker checks only the owner's authorization, no ticket.** Rejected:
  the authorization is a standing document; without a single-use,
  job-bound ticket, it could be replayed for any session that passes
  attestation.
- **A project key or central KMS.** Rejected: it contradicts sovereign
  custody and makes the control-plane operator a key holder.
- **A 600-second ticket.** Rejected in favour of 300 seconds (D7 asks for
  minutes; the shorter was taken).

## Relevant source modules

Phase 2 changed:

- `crates/encompute-keybroker/src/{governed,generation,server,workload,lib}.rs`
- `crates/encompute-verification/src/ticket.rs`
- `crates/encompute-attestation/src/grant.rs` (grant header version 3)
- `crates/encompute-control/src/ops/custody.rs`, `anchor.rs`,
  migration `0006_sovereign_custody.sql`
- `crates/encompute-training/src/spec.rs` (`asset_brokers`)
- `crates/encompute-assurance/src/catalog.rs` (INV-232, 235, 236)

Still planned:

- `crates/encompute-keybroker/src/{server,store,root}.rs`
- `crates/encompute-attestation/src/{grant,gcp,policy}.rs`
- `crates/encompute-control/src/ops/{assets,jobs}.rs`
- `crates/encompute-openfhe-client` (KMS-wrapped key store, public-key
  encryption)
- `crates/encompute-planner/src/{model,requirements}.rs`
