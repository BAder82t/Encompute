# Deploying Encompute

This guide covers the first supported deployment: the control plane with
PostgreSQL, OpenFHE evaluators, key brokers backed by a customer-managed
root key, and secure-aggregation coordinators, on Docker Compose
([deploy/docker-compose](../deploy/docker-compose/)).

## Architecture

```text
                        Encompute API v1 (CLI, Python SDK)
                                     │
                           ┌─────────▼─────────┐
                           │   Control plane   │  organizations, users, roles,
                           │ encompute-control │  projects, assets, policies,
                           │                   │  plans, jobs, privacy ledgers,
                           │    PostgreSQL     │  trust reports, audit trail
                           └───┬──────┬──────┬─┘
         signed requests and   │      │      │
         messages (Ed25519)    │      │      │
                    ┌──────────▼┐ ┌───▼────┐ ┌▼────────────┐
                    │ Evaluator │ │ SecAgg │ │ Key broker  │
                    │ (OpenFHE) │ │ coord. │ │             │
                    └───────────┘ └────────┘ └──────┬──────┘
                                                    │ wrap / unwrap the KEK
                                             ┌──────▼──────────────┐
                                             │ Customer KMS / vault │
                                             │ (OpenBao, Vault)     │
                                             └──────────────────────┘
```

Each component has one job:

| Service | Does | Never |
|---|---|---|
| Control plane | Decides who may do what, which job exists, which policy and plan apply, what state a job is in, and what evidence exists. | Computes on protected data, holds a secret key, or declares anything trusted by itself. Trust reports are rebuilt from signed evidence on every request. |
| Evaluator | Runs encrypted computation: OpenFHE CKKS for approximate programs, OpenFHE exact (BinFHE) for exact ones. | Holds a client's secret key, or runs a job without a grant from its control plane. |
| Key broker | Releases asset keys to attested workloads under their owners' policies. | Holds the root key: that stays in the customer's KMS. |
| SecAgg coordinator | Runs protected multi-party aggregation rounds, and reports their privacy spending to the control plane. | Sees any single party's contribution. |

The control plane and the planner, policy, trust, asset, receipt and privacy
modules are one service. Only the four boundaries above are separate
services, because each is a different trust boundary.

## Identities

**People** log in through the organization's OpenID Connect provider. The
control plane checks each token against the provider's JWKS: signature,
issuer, audience, expiry, not-before, and an issue time (`iat`) that is not
in the future and at most `ENCOMPUTE_MAX_TOKEN_LIFETIME_SECS` (default
86400) before the expiry. The identity must be registered as an active user
of an organization. A user disabled through the API is refused from its
next request. A user (`alice@hospital-a.example`) is never the same thing as
a cryptographic party in a program's policy (`hospital-a`).

**Services** have their own Ed25519 keys: the control plane, each evaluator,
each key broker, each SecAgg coordinator, and any automation. A service signs
every request and message. The signature covers:

- the method, the path with its query string (parameters sorted into a
  canonical form) and a hash of the body;
- the sender and the recipient;
- a timestamp;
- a nonce (a replayed request is refused; a used nonce is kept for longer
  than the window in which its request could still be accepted);
- the IDs the request is about.

A source IP address, a hostname or a private network is never treated as an
identity. The signatures stay valid through proxies and brokers.

**TLS is the operator's job.** No Encompute service terminates TLS, and the
Docker Compose deployment provides none. Put a TLS proxy or load balancer in
front of every service. The control plane connects to PostgreSQL without
TLS: keep the database on a private network that only the control plane can
reach.

**Roles** (per organization):

| Role | Can |
|---|---|
| `organization_admin` | Add users and automation accounts, remove roles, disable users and service accounts, invite collaborators to its projects and accept invitations, create projects. |
| `security_admin` | Propose and approve policies (a different admin of the project owner's organization must approve), disable users and service accounts, revoke assets. Held by people only: no route grants it to a service account (see "Upgrading from 0.3.0-rc.3 or earlier" for accounts that already hold it). |
| `data_owner`, `model_owner` | Register their organization's assets (datasets for data owners; models, adapters and checkpoints for model owners), approve them for a project and purpose, revoke them. Data owners also read and export privacy ledgers, record privacy spending, and authorize SecAgg services to spend. |
| `ml_developer` | Create projects, plan and submit jobs, complete jobs with their receipts. |
| `auditor` | Read the audit trail and privacy ledgers. |
| `operator` | Platform operators: drain evaluators, checkpoint the audit trail. An organization's operators may also record privacy spending for its assets. |

Fine-grained rules about data (who may learn what, for which purpose) stay
in each program's confidentiality policy. The roles only decide who may act
on the control plane.

**Tenant isolation.** An identity sees only its own organizations'
resources, plus what an explicit collaboration grants:

- project membership: the project owner's admins invite an organization,
  and it becomes a member only once that organization's admins accept;
- an asset's approval for a project and purpose, given by its owner. It
  covers the organizations that are members when it is given: an
  organization that joins later needs a new approval.

Every grant can be withdrawn through the API: a user disabled, a role
removed, a member removed from a project, an asset approval withdrawn. The
withdrawal is audited and takes effect from the next request. Removing a
project member or withdrawing an approval also fails the jobs not yet
started that depended on it.

Anything else is reported as not found (ENC2603), so looking up another
tenant's ID does not confirm that the resource exists. Uniqueness conflicts
are the exception: registering an ID that is already taken fails with
ENC2604, which does reveal that the ID exists. Do not put secrets in IDs or
names. Platform admins create organizations and register platform
services, but cannot read tenant data.

## Jobs

```text
CREATED → PLANNING → PLANNED → (WAITING_FOR_APPROVAL) → AUTHORIZED → QUEUED → RUNNING → VERIFYING → SUCCEEDED
                                         any live state → FAILED | CANCELLED
```

1. The client submits a job with an `Idempotency-Key` header.
   - The same key and the same request return the same job; the same key
     with a different request is refused.
   - The job names a plan, which the control plane made from the program
     with the planner. It also names a purpose and its source assets.
   - Every asset must be visible, not revoked, and approved by its owner
     for this project and purpose while the submitting organization was a
     member.
2. The scheduler places the job on an evaluator that has:
   - registered the job's backend (`openfhe` or `openfhe-exact`) and
     parameter profile (for example `BINFHE_STD128_GINX_BITS_V1`);
   - status ready, a recent heartbeat, and spare capacity.

   Among the evaluators that pass these checks, it picks the one likely to
   finish first. Each plan records its cost in bootstrapped gates (exact
   programs; CKKS plans record 0 and count as one unit). The estimate on an
   evaluator is (gates of its queued and running jobs + this job's gates) ×
   55 ms ÷ min(`max_parallel_gates`, `logical_cores`). 55 ms is about one
   OpenFHE BinFHE STD128 gate on one core. An evaluator that sent no
   machine profile counts as one core. Ties go to the lowest evaluator ID.
   The estimate is recorded in the job (`estimated_ms`) and in the
   `job.scheduled` audit event. Cost only orders evaluators that already
   passed every check above. The machine profile is what the evaluator
   says about itself, and it is not verified: it steers placement and
   performance estimates, never a security decision.

   The control plane signs a job grant for that evaluator.
3. The client checks the evaluator's receipt key against its own pin set
   (`--trust-evaluator`, `ENCOMPUTE_TRUSTED_EVALUATORS`, or the SDK's
   `trusted_evaluators=`) before it sends anything, so the control plane
   cannot choose the key that verifies a result. A key outside the set is
   refused (ENC2607), an empty set refuses every evaluator, and without a
   pin the job is refused (ENC2605). Only in development, the explicit
   opt-out (`--allow-unpinned-evaluator`, `ENCOMPUTE_ALLOW_UNPINNED_EVALUATOR=1`)
   accepts the key the control plane names, and only with
   `ENCOMPUTE_ENV=development` set explicitly; unset or any other value
   refuses it. The client then sends its encrypted inputs to the evaluator
   with the grant. The evaluator:
   - checks the grant against the pinned control-plane key;
   - asks the control plane to start the job, which it refuses if the job
     was cancelled or an asset was revoked;
   - runs it and returns an encrypted result with a signed receipt.
4. The evaluator reports the receipt as a signed message. The client
   decrypts, then reports the receipt with its commitments to the exact
   bytes it sent and received. The control plane verifies every binding
   against the job's spec and the evaluator's registered key.

The control plane never sees inputs or outputs. On restart it keeps every
job's state. It never replays a security-sensitive step: a running job whose
evaluator disappears fails, and is not re-run.

**Draining an evaluator** before an upgrade: an operator sets it to
`draining` (`POST /v1/evaluators/{id}/status`). The evaluator takes no new
jobs and its in-flight jobs finish; the operator then replaces it. The
evaluator's own heartbeats, and its registering again when it restarts,
cannot undo a drain.

## Keys: bring your own key

```text
customer KMS / vault        the root key never leaves it
       │ wraps
wrapped KEK                 kek.wrapped.json (not secret; bound to the organization)
       │ wraps
wrapped asset keys          the key broker's state
       │ encrypt
encrypted assets
```

- **Adapter.** The first adapter is OpenBao or HashiCorp Vault Transit:

  ```sh
  encompute keys serve --root-key openbao:transit/modelco --organization modelco ...
  ```

  The broker reads `BAO_ADDR` and `BAO_TOKEN_FILE` from the environment.
  It follows no redirects, so the token never leaves for another host:
  point `BAO_ADDR` at the server itself. The token file must be a regular
  file not writable by group or others (0600, or 0644 for a mounted
  secret). A KEK file (`--kek`) must not be accessible to group or others
  (0600).
- **Broker state.** `broker.json` holds the wrapped asset keys and the
  release policies. It is authenticated: a generation number and an HMAC
  under a key derived from the KEK. A state file edited outside Encompute (a
  release policy, the mode, the organization or a key version) does not
  open; restore it from a backup instead. Without a generation mark, a
  state file restored together with the KEK it was saved under (a backup
  of both) does restore keys revoked since it was taken, a rollback this
  check does not detect: keep backups access-controlled, and see
  [Revoking a key and recovering a broker](#revoking-a-key-and-recovering-a-broker).
- **Generation mark.** A governed broker (a governance key pinned) in
  production refuses to start without a generation mark in the
  organization's KMS; any other broker may use one. Every save writes the
  state file, then advances the mark with compare-and-set, and only then
  grants a key or acknowledges a change. A state older than the mark, or
  at the same generation with another MAC, does not open (ENC2713). A state
  one save ahead (the broker stopped between the write and the mark) opens
  only if it names the mark's MAC as its previous one, so a file from
  another history with the same number is refused. If the mark cannot be
  reached, nothing is granted (ENC2713, HTTP 503). The first start under a
  mark trusts the state file it finds, so start from a state you trust:
  pass `--expect-generation N` (and `--expect-state-mac HEX`, the `mac` in
  `broker.json`) to the command that first attaches the mark, and a state
  that does not match is refused before any mark is written. Without them,
  the broker prints the generation and MAC it trusted; check them against
  your records. A governed production broker without a mark records no
  change at all: authorization installs and revocations, and control-plane
  messages, are refused with an error saying so (revoke offline with
  `encompute keys authorization revoke`; the control plane retries its
  messages). Once a state is saved under a mark, every `encompute keys`
  command on it needs `--generation-mark`.

  ```sh
  bao secrets enable -path=encompute-kv -version=2 kv
  encompute keys serve --root-key openbao:transit/modelco --organization modelco \
    --generation-mark openbao --kv-mount encompute-kv ...
  ```

  The mark uses the same `BAO_ADDR` and token as the Transit root key, and
  the same rules (https, no redirects, a 10-second timeout). Grant the
  broker's token only the Transit key and its own mark path:

  ```hcl
  path "transit/encrypt/modelco" { capabilities = ["update"] }
  path "transit/decrypt/modelco" { capabilities = ["update"] }
  path "encompute-kv/data/encompute/brokers/BROKER_ID/generation" {
    capabilities = ["create", "read", "update"]
  }
  ```

  Writes always carry `options.cas`, so a second broker running a copy of
  the state loses and grants nothing. A broker ID that is not a plain name
  (letters, digits, `-`, `_`, `.`) is stored under `sha256-` and the
  SHA-256 of the ID. Do not delete the mark: a state saved under it then
  does not open (KV-v2 keeps versions; undelete the latest one).
  `--generation-mark file:PATH` keeps the mark in a local file, for
  development only; production brokers refuse it.
- **Upgrading a broker from 0.3.0-rc.3.** Its state is not authenticated
  yet and does not open. Run `encompute keys upgrade-state` with the same
  `--kek`, or `--root-key` and `--organization`, flags the broker runs
  with. It prints what the state releases, and to whom: check it against
  your own records, then rerun with `--confirm`.
- **Attestation keys.** A broker with `--jwks google` refetches Google's
  Confidential Space key set when a token names an unknown key (at most once
  a minute) and once the set is an hour old.
- **What Encompute stores.** Only the key reference, the provider, the root
  key's version and the wrapped KEK: never the master secret.
- **Rotation.** `encompute keys rotate-root` re-wraps the KEK under the new
  root key version. Asset keys are unchanged. The rotation (old and new
  version) is printed for the audit trail.
- **Revocation.** Revoking an asset on the control plane is immediate: no
  new job may use it, jobs not yet running fail, and its key broker is told
  (a signed message, delivered at least once) to destroy every version of
  its key. The broker is told only once the revocation is in the state
  anchor. Revocations for an asset go only to a key broker of the platform
  or of the asset's organization. A revocation also replaces the broker's
  KEK (below).
- **Failures.** A provider that is unavailable, disabled, refuses the
  organization's context, or no longer decrypts a key version releases
  nothing. There is no fallback to local or plaintext keys. Production
  brokers refuse development stores.

### Revoking a key and recovering a broker

**What a revocation does to the broker's files.** Destroying a key in the
current `broker.json` is not enough: an older copy of the file still holds
the key, wrapped under the KEK. So a revocation, in the same change, also
replaces the KEK. The broker generates a new one and re-wraps every
surviving key and the state's authentication under it (`kek_id` in
`broker.json` changes). It writes the new KEK beside the live one
(`NAME.next.KEKID`, mode 0600; for a root-wrapped KEK, a wrapped KEK file)
before it writes the state. Then, on the save, it writes the state,
advances the generation mark with compare-and-set, and only then makes the
new KEK live, destroying the old file. A key revoked this way cannot be
recovered from an older state file with the KEK that is current
afterwards. Applies to a broker that keeps its KEK in a file (`--kek`) or
wrapped under a root key (`--wrapped-kek`); a development broker with
plaintext keys, or an embedding that holds the KEK in memory, replaces
nothing (`encompute keys revoke` prints `NOT SHREDDED`).

**What it does not do.**

- A copy of the *old* KEK still opens an older state file. With `--kek`,
  that is any backup or snapshot of the KEK file: keep the KEK file out of
  the backup set, or delete backups that predate a revocation. With a
  root-wrapped KEK, the old wrapped KEK in a backup is not secret and opens
  while the Transit key version that wraps it does. After revoking, run
  `encompute keys rotate-root --retire-old-versions` (same flags as the
  broker): it rotates the root key, re-wraps the live KEK under the new
  version, and sets Transit's `min_decryption_version`, so the older
  wrapped KEKs never open again. It is irreversible and applies to every KEK
  wrapped under that root key, so run `rotate-root` first for every other
  broker of the organization. The reference Compose files back up the broker
  volume (state and wrapped KEK) together: after a revocation, retire the old
  root versions, or treat the earlier `broker.tar` as still able to open
  the revoked key.
- Destroying a key does not recall plaintext a workload already received:
  revocation is not retroactive.
- A KMS that keeps old versions of a secret (KV-v2 for the generation mark)
  holds no key material: the mark records a generation number and a state
  MAC only.

**If the broker stops during a revocation.** Start it again with the same
flags. At each step the files are consistent:

| It stopped | What is on disk | On the next start |
| --- | --- | --- |
| After the new KEK was written, before the state | the old state under the old (live) KEK; an unused `.next.` file | the state opens as it was; the control plane retries the revocation; the unused file is removed by the next revocation |
| After the state was written, before the generation mark advanced | state one save ahead of the mark, naming the new KEK; the new KEK pending | the state opens only if it continues the mark's (ENC2713 otherwise); the broker adopts the pending KEK, advances the mark, then makes it live |
| After the mark advanced, before the new KEK became live | the same, with the mark current | the broker adopts the pending KEK and makes it live |

Never delete a `.next.` file while `kek_id` in `broker.json` names it: it
is the only copy of the key that opens the state. A file no saved state
names (check `kek_id`) is safe to delete.

**Recovering.**

- *ENC2713, the state is older than the mark.* An older copy was restored,
  or the newest state was lost. Put back the newest state file (the file
  the broker wrote last, with its KEK or wrapped KEK). Nothing older is
  accepted, whatever KEK it comes with. There is no supported command to
  lower or reset a mark; an owner who has lost every copy of the newest
  state (and with it the revocations, used tickets and counters since the
  last backup) re-protects the affected assets under new keys and
  registers new versions.
- *The mark was deleted.* A state saved under a mark does not open without
  it (ENC2713). Undelete the latest KV-v2 version of
  `encompute/brokers/BROKER_ID/generation`.
- *The state is intact, the KEK is lost.* Nothing can be recovered: the
  wrapped keys and the state's authentication need it. This is by design.
  Re-protect the assets under new keys.
- *Restoring a backup into a new volume.* `restore.sh` restores the broker
  volume only when it is empty, so an existing newer state wins. Start the
  broker with the mark: it refuses a state older than the mark, so a
  restored backup comes up only if nothing was revoked or released since.
  After a restore, check with the control plane that every revoked asset's
  key is revoked (it re-sends `asset.revoked` until the broker
  acknowledges).
- *Revoking at a stopped broker.* `encompute keys revoke` (with the broker's
  `--kek` or `--root-key` flags, and `--generation-mark` when the state is
  guarded) does the same as a message: it replaces the KEK and saves. Do not
  run it while the broker is serving the same files.

### Registering an organization's own key broker

A governed project is always in sovereign key custody: every source's key
must be held by a key broker the source's own organization registered,
never a platform broker (ENC2715). Asking for standard custody in a
governed project is refused (ENC2715); standard projects keep standard
custody. Custody never changes. To register a
broker for your organization:

1. An organization admin creates the broker's service account, owned by the
   organization, with the URL the control plane sends its messages to:

   ```sh
   curl -X POST $CONTROL/v1/organizations/tax-agency/service-accounts \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{"id": "tax-broker", "kind": "keybroker",
          "public_key": "<broker service key, hex>",
          "url": "https://keys.tax-agency.example:8760"}'
   ```

2. A person who is a security admin of the organization (not a service
   account, not an auditor) registers it as the organization's broker, with
   the public key it signs key grants with, the kind of KMS behind it, the
   key namespace it serves, and where it runs (self-declared):

   ```sh
   curl -X POST $CONTROL/v1/organizations/tax-agency/key-brokers \
     -H "Authorization: Bearer $SECURITY_ADMIN_TOKEN" \
     -d '{"id": "tax-broker", "grant_public_key": "<grant key, hex>",
          "provider_kind": "openbao-transit", "key_ref_namespace": "transit/tax",
          "location": {"country": "NL"}}'
   ```

   The registration is audited (`key_broker.registered`). A broker's
   identity, organization and grant key never change; disable its service
   account to retire it.

3. Data owners register each dataset version for the project with the
   broker in its `key_ref` (`"project": "<project ID>"` and `"key_ref":
   {"broker": "tax-broker", ...}` on `POST /v1/assets`).

Start the broker pinned to the control plane's public key (`GET /v1/info`
`public_key`): it accepts only release tickets and messages signed with it.
The scheduled evaluator of a governed job asks the control plane for a
ticket per source (`POST /v1/jobs/{id}/release-ticket`); a ticket lives at
most five minutes and never beyond the job's governed window or grant.
When an owner revokes an authorization, the control plane anchors the
revocation (its governance log event) first, then tells the organization's registered brokers
(`authorization.revoked`); the owner can always revoke at its own broker
directly, without the control plane.

### Residency and operators in a governed project

A governed project may carry placement constraints: where its ciphertexts
may be handled and which organizations may operate the machines.

- **Evaluators and their operators.** An evaluator's operator is the
  organization of its service account (`platform` for the platform's own).
  An organization may hold evaluator accounts of its own
  (`POST /v1/organizations/{id}/service-accounts` with `kind: evaluator`);
  they run only the governed jobs whose placement admits them, never a
  standard job, and never a job of a project where the organization owns a
  source or receives the result.
- **Locations.** An evaluator reports its location when it registers
  (`location: {provider, region, zone?}`, from the table in
  `encompute_verification::placement::locations`: Google Cloud, AWS and
  Azure regions, and an organization's own premises by country). That is
  self-declared. A person who is a security admin of the operator makes it
  `operator_declared` with `POST /v1/evaluators/{id}/location-declarations`
  (valid for at most 366 days, 90 by default; declare again to renew).
  Production never accepts a self-declared location where a constraint
  has a location rule. An evaluator that registers again with another
  location loses its evidence, and a job already scheduled on it fails at
  start.
- **Constraints.** The project's are set with `POST
  /v1/projects/{id}/placement` (a member's security admin tightens at
  once; loosening needs every member to send the same constraints). An
  owner's own are `limits.placement` in its signed authorization. A
  constraint is JSON: `allowed_regions` and `prohibited_locations` (patterns
  of `jurisdiction`, `provider`, `region`, `zone`; prohibited wins),
  `allowed_operators`, `allowed_evaluators`, `min_evidence`
  (`self_declared`, `operator_declared`, `attested`) and `applies_to`
  (`plaintext`, `ciphertext`, `keys`, `evidence`; all four by default).
- **Key brokers** judge the zone the workload's attestation names against
  the project's constraints (the signed ticket carries the document) and
  the owner's own; a Confidential Space token names a Compute Engine zone.
  A broker cannot see operators or evaluator IDs: those constraints are
  the control plane's to enforce.
- **Clients** can add their own rule: `encompute jobs run --placement
  constraints.json --evaluator-pins pins.json` sends nothing to an
  evaluator the client has not pinned inside its constraints.
- **Upgrading.** Migrations 0017 and 0018 add the evaluator location
  columns and the project constraint tables. Governed plans made before
  this release have no placement context: make them again (a job on such a
  plan is refused, ENC2710). Standard projects are unchanged.

## Upgrading from 0.3.0-rc.3 or earlier

- **Service accounts with `security_admin`.** Earlier releases let an
  organization admin give `security_admin` to an automation account, so
  one admin could supply both approvals of a policy. 0.3.0 refuses the
  grant on every path, and never counts a service account as a policy's
  proposer or approver. It does not strip the role from accounts that
  already hold it: they keep it for disabling, revoking and reading the
  audit trail. On every start the control plane logs a
  `legacy_service_admins` warning naming them, writes one
  `security.legacy_service_admins` audit event into each affected
  organization's trail, and sets the `encompute_legacy_service_admins`
  gauge. Find them with `encompute security legacy-service-admins` (exit
  1 while any remain) or `GET /v1/security/legacy-service-admins`, and
  have an organization admin of each organization remove the role:
  `POST /v1/organizations/{organization}/memberships/remove` with
  `{"principal": "<service account>", "role": "security_admin"}`. Give the
  role to people instead. The account keeps its other roles.
- **Removal window.** 0.3.x accepts these accounts with the warnings
  above. 0.4.0 will refuse them: either the control plane refuses to
  start while any remains, or a migration strips the role. Which one will
  be announced in advance. Run the check before upgrading.
- **No downgrade.** Take a database backup and a copy of the anchor
  before upgrading. After the upgrade, schema version 4 refuses an rc.3
  control plane, and once the new anchor sets (ended jobs, withdrawn
  approvals, removed memberships and roles) are written an rc.3 binary
  cannot read the anchor. To roll back, restore the pre-upgrade database
  backup together with its matching anchor, then start the older
  release.

## Upgrading from 0.3.0: state anchor version 2

The state anchor of 0.3.0 (version 1) held the sets of every revoked,
disabled, ended, withdrawn, removed and expired ID, and grew with each.
This release keeps them in the governance event log (one event per
transition, written in the same transaction) and anchors only the log's
size and head, so the anchor no longer grows with them. The version-1
anchor's ledger checkpoints become log events as well: the version-2
anchor is constant in size, whatever the number of assets, revocations and
spends.

- **Migration, at the first start.** Nothing to run by hand. The control
  plane first makes every check 0.3.0 made at its start; if the database
  does not extend the version-1 anchor, it refuses to start and migrates
  nothing (recover with 0.3.0 first, then upgrade). Otherwise one
  transaction writes an `anchor.genesis` event (the version-1 anchor's
  digest; the signed anchor itself is kept beside the log) and one event
  per ID of its sets (`migrated.<set>`, in the project's or
  organization's partition where the database knows it; `ledger.frozen`
  for a frozen ledger; `row.lost` for a row recovery recorded lost) and one
  `privacy.ledger_checkpoint` event per ledger checkpoint (each ledger's
  floor from then on), then
  the log's mirror is written into the anchor store and the anchor is
  replaced by version 2, compare-and-set on its counter. The checks, the
  gathering and the events share one snapshot under the log's lock: a
  transition committed meanwhile waits and is logged after them.
  The start logs `state_anchor_migrated`. The version-1 anchor stays
  authoritative until the replacement: there is no window in which a
  rollback goes unnoticed.
- **A crash during the migration** (after the transaction, before the
  replacement) is completed by the next start, which finds the genesis
  event with the stored anchor's digest. A start refuses a stored
  version-1 anchor once the log moved on after its migration, or that is
  another anchor than the one migrated (ANCHOR STATE ROLLBACK): the anchor
  store was rolled back or replaced.
- **No downgrade.** Earlier releases refuse a version-2 anchor and do not
  start. Take a database backup and a copy of the anchor before
  upgrading; to roll back, restore both together and start the older
  release.
- **Mirror.** The migration also writes the log's mirror (below) before it
  replaces the anchor.
- **Recovery** runs only on a version-2 anchor: `encompute-control
  recover` on a version-1 anchor tells you to recover with the release
  that wrote it.

## Privacy state and backups

The privacy ledgers (every charged release) live in PostgreSQL, hash-chained,
with an exclusive lock per ledger: two spends can never both use the last of
a budget. A duplicate delivery of the same event is charged once.

The control plane signs into the **state anchor**:

- the audit chain's head, with every checkpoint of the governance log
  (before the call returns for a security deny event, and otherwise at
  most every two seconds) and at each audit checkpoint;
- the governance event log's size and head. Each privacy spend appends its
  ledger's checkpoint (`privacy.ledger_checkpoint`: the asset, the entry
  count and the root, in the platform partition, nothing more) to the log
  and checkpoints the log before the spend is acknowledged; a spend that
  finds its event anchored already (a concurrent spend checkpointed past
  it) waits for nothing more. The log's head is also anchored after every
  security-negative transition and before it is acknowledged: revoked
  assets, frozen ledgers, disabled service accounts and users, cancelled
  and failed jobs, withdrawn asset approvals (including the grants an
  organization lost by leaving a project), removed project memberships,
  organization roles removed from a user or service account, revoked
  owner authorizations of governed projects, retired purposes, revoked
  governance keys and expired assets. Each is an event of the log,
  written in the same transaction; the anchor holds only where the log
  stands. A key broker is told of a revocation or an expiry only once its
  event is anchored.

The anchor is therefore constant in size (a few hundred bytes: a counter,
the audit root, the log's size and head, and the migration's record):
nothing in it grows with assets, revocations or spends, and no vault entry
limit applies to it. What grows is the governance log in the database and
its mirror in the anchor store (below).

The anchor is kept outside the database: on its own volume, or in the
customer's vault (OpenBao or Vault KV). It only moves forward along the
same chains. Run one control-plane process per anchor.

While the service runs, a spend on a ledger that no longer extends the
anchor is refused (ENC2202 PRIVACY STATE ROLLBACK), and so is an audit
checkpoint over a chain that does not extend the anchored one (ENC2202
AUDIT STATE ROLLBACK), and so is a governance log checkpoint over a log
that does not extend the anchored head (GOVERNANCE LOG STATE ROLLBACK).
None is written into the anchor. Each raises an
alarm: a `state_rollback_detected` log line and the
`encompute_state_rollback_total` metric. A ledger frozen in the governance
log is refused for spending whatever the database says (ENC2201). The
floor a ledger must extend is the latest `privacy.ledger_checkpoint` event
of its asset in the log, which is itself checked against the anchored
head: restoring an older ledger together with an older log is refused as a
GOVERNANCE LOG rollback, and an older ledger under the current log as a
PRIVACY rollback; recovery freezes it either way and moves its floor to
what the database holds.

At every start, the database must extend the anchor. If it does not, the
control plane refuses to start:

```text
error[ENC2202]: PRIVACY STATE ROLLBACK: ... STARTUP REFUSED
```

The same refusal names GOVERNANCE LOG (the log does not verify, or does
not hold the anchored head at the anchored size: events dropped,
truncated, reordered or rewritten), AUDIT, FREEZE (a frozen ledger shown
spendable), REVOCATION, SERVICE ACCOUNT, USER, JOB (a cancelled or failed
job shown live), APPROVAL (a withdrawn asset approval held again),
MEMBERSHIP (an organization listed again in a project it left), ROLE (a
removed role held again), AUTHORIZATION (a revoked owner authorization
shown unrevoked), EXPIRY (an expired asset shown unexpired), PURPOSE (a
retired purpose shown active) or GOVERNANCE KEY (a revoked governance key
shown unrevoked) when that is what the database undid. The startup check
recomputes the whole log (about 1.6 seconds for 100,000 events on a
development machine). That happens when an older
database backup was restored, or the database was edited. Recovery is
explicit:

```sh
encompute-control recover --operator NAME [--governance-log FILE]
```

### Privacy populations and scopes (governed projects)

Differential privacy in a governed project is charged to a **scope**, a
share of the **population** of the source's dataset series. Both are
privacy ledgers like an asset's (the same tables, under the keys
`population:<id>` and `scope:<id>`), so everything above applies to them
unchanged:

- each spend appends one checkpoint per ledger (the scope's and the
  population's: the key, the entry count and the root, in the platform
  partition) to the governance log and anchors the log before it is
  acknowledged; a job's start reserves in every source's scope and
  population and anchors them all before the evaluator is told the job
  started;
- a ledger that does not extend its latest checkpoint is refused at start
  (PRIVACY STATE ROLLBACK, naming `scope:<id>` or `population:<id>`), and
  on every spend while running; `encompute-control recover` freezes it,
  and a frozen scope or population is exhausted;
- a scope's allocation is an event of its project's log (`privacy.scope_allocated`),
  anchored before the approval returns.

Schema versions 14 to 16 add the populations, the scopes and a job's
reservations. Migration 14 drops the foreign key from `privacy_ledgers` to
`assets` (a population or scope is not an asset) and replaces it with a
trigger that keeps it for asset ledgers. A control plane that runs
migrations 14 to 16 cannot be downgraded.

Populations are per organization and series and are allocated once: take
care over their cap (`POST /v1/privacy/populations`). Scopes are proposed
and approved by two different security admins of the owning organization.
A SecAgg coordinator that reports a job's release needs the owner's
authorization for the scope (`POST /v1/privacy/scopes/{id}/spenders`) and
is acknowledged when its report is the job's own release, which the
control plane already reserved when the job started. Capacity: a scoped
spend or a job's start appends two checkpoint events per ledger touched
(one in each of the scope and the population), against one for an asset's
ledger.

### The governance log mirror

Every checkpoint appends the log's new events to a mirror in the anchor
store, **before** the signed anchor is replaced (the anchor's
compare-and-set is the commit point): events are appended, the new head
computed, the mirror written durably (fsync), then the anchor stored. In a
directory store the mirror is `governance-log/` next to
`state-anchor.json`: numbered segment files (`NNNNNNNNNNNN.jsonl`, the
number is the whole name), each holding contiguous events, at most 500
events and about 256 KiB (a read refuses more than 512 KiB; an OpenBao KV
entry may be 1 MiB). A checkpoint extends the last, not yet full,
segment by replacing it atomically (temporary file, fsync, rename, fsync of
the directory) with one that holds the same events and the new ones, and
creates a further segment (one create-only operation on its name: a hard
link, or an exclusive create where links are unsupported; in OpenBao KV a
`cas: 0` write of one entry under `<path>-glog/`) only when it fills, so
segments grow with the log, not with the number of checkpoints. Two
writers racing for a segment: exactly one wins, the other fails closed and
retries. Only one control plane per anchor store is supported. The anchor
file itself is written the same atomic way (unique temporary name, fsync,
rename, directory fsync; a leftover temporary file is ignored). The signed anchor is the only authority: the
mirror is used only up to the anchored size and only if it chains,
recomputed, to the anchored head. A suffix past it (a crash between the
mirror and the anchor) is an orphan: logged (`governance_mirror_orphan`),
never recovered from, and rewritten from the database's own events at the
next checkpoint. A replacement never shrinks or alters what the anchor already holds (a
stale writer is refused), and the anchor never moves unless the mirror
reaches the new head. A mirror that is truncated, reordered, forked or edited
refuses the start (GOVERNANCE LOG STATE ROLLBACK) until recovery rebuilds
it from a database that extends the anchor.

A security deny event (a revocation, expiry, disable, removal, retirement,
withdrawal, cancellation) checkpoints synchronously: the call returns
success only after the mirror and the anchor are durable, and a failed
checkpoint fails the call. The change may already be committed to the
database, which enforces it; retrying the call is idempotent and anchors
it, and the background task anchors it otherwise. Ordinary events are
batched by the background checkpoint; a privacy spend checkpoints
synchronously, like a deny event (concurrent spends share one checkpoint).

Size and pruning: about 300 bytes per event, so 100,000 events are about
30 MB in about 200 segments. Every privacy spend is one event, so a
deployment's mirror and log grow with its spending as well as its
transitions; budget the anchor store accordingly (10 million spends are
about 3 GB), and the startup check, which recomputes the whole log, grows
with it. Spends are limited per actor and asset to 1,200 a minute (a
refused spend is retried later; ENC2606, the
message names "privacy spend"), and a reservation must charge at least a
zCDP cost of 1e-9 (a noise multiplier of about 22,000 at sensitivity 1;
ENC2204), so a caller cannot grow the log faster than that for free. A
real deployment spends far less: a training run reserves and commits once
per round, so a hundred rounds a day across ten datasets are about 2,000
events a day, under 1 MB of mirror a day. Measured here: one event and
about 350 bytes of mirror per spend. The mirror is never pruned below the anchored head except by a
compaction (below), which archives what it prunes. Keep the anchor store
backed up with the anchor.

Recovery reads what to re-apply from the governance log, so the log must
first hold the anchored head. It takes the missing events from the mirror
by itself (streaming, segment by segment, verifying a running hash), exactly up to the anchored head; the export below is a second
path, and the only one when the mirror is lost too. A restored backup older than the anchor
lacks the log's latest events; recovery takes them from the **governance
log mirror** in the anchor store (below) on its own, exactly up to the
anchored head, after checking that they chain to it. If the mirror cannot
supply them (it was rolled back or truncated with the database, or
damaged), recovery refuses (GOVERNANCE LOG STATE ROLLBACK ... RECOVERY
REFUSED) until they are back: restore the log's tables
(`governance_events`, `governance_tree_nodes`, `governance_head`,
`governance_checkpoints`, `governance_anchor_genesis`) from a newer
backup or replica, or pass an export with `--governance-log FILE`
(`encompute-control export-governance-log > FILE`, JSON lines;
read-only). An export holds events and their hashes only, no private
data; recovery appends the events the database lacks only if they
continue its log and reach the anchored head, so an export from anywhere
is safe to use.

### The governance log mirror

Every checkpoint of the governance log writes the events since the
mirror's end into the anchor store **before** it replaces the anchor; the
anchor's compare-and-set is the commit point. The mirror lives next to the
anchor: `governance-log/` in the anchor directory (one immutable file per
segment, written to a temporary name, synced, linked into place without
replacing anything, and the directory synced), or `<path>-glog/<segment>`
entries in the OpenBao/Vault KV mount (created only if absent). A segment
is named by its number in write order and the events it holds
(`{n}-{from}-{to}`), at most 500 events each.

- The signed anchor is the only authority: recovery uses the mirror only
  up to the anchored size and only when it chains to the anchored head.
  Events past it (a crash between the mirror's write and the anchor's) are
  an orphan: logged (`governance_mirror_orphan`), never recovered from,
  and replaced by the next checkpoint with the database's own events.
- Every start checks that the mirror reaches the anchored head. A
  truncated, reordered, forked or edited mirror is refused (GOVERNANCE LOG
  STATE ROLLBACK); `encompute-control recover` rebuilds it from a database
  whose log extends the anchor (a new segment that starts at the first
  event, which reading then starts from).
- **Size.** The mirror grows with the log: roughly 400 bytes per event
  and one segment per checkpoint (each security-negative transition
  checkpoints at once). It is pruned only by a compaction (below), and
  only into an archive. On OpenBao each segment is one KV entry; reading
  the mirror at start reads every segment it holds.
- Back it up with the anchor (`backup.sh` captures the anchor volume, the
  mirror included; `restore.sh` restores both only into an empty volume).

### Compacting the governance log mirror

The mirror in the anchor store grows with the log. A compaction moves its
oldest segments to an **archive** you keep (a directory: a mounted volume
or an object-store mount) and prunes them from the anchor store, so the
anchor store holds the tail. The **database's log is not compacted**: it
keeps every event, tree node, checkpoint and witness, the start check
recomputes all of it as before, and nothing that detects a rollback, a
truncation or an undone revocation changes. Only the mirror, the copy
recovery imports from after a restore, shrinks. What a compaction does
not do: shrink the database, or shorten the start check (4.3 seconds for
120,100 events on a quiet machine; see KNOWN_LIMITATIONS.md).

```sh
# What would be sealed (writes and deletes nothing, not even the directory):
encompute-control compact-governance-mirror --archive-dir /mnt/archive/governance --dry-run
# Do it (the control plane may keep running; run it from one place at a time):
encompute-control compact-governance-mirror --archive-dir /mnt/archive/governance
# Check an archive against the state anchor (no database needed):
encompute-control verify-governance-archive --archive-dir /mnt/archive/governance
```

Retention: the mirror keeps the newest 10,000 events **or** anything
younger than 30 days. A segment is sealed (and so eligible for pruning)
only if it is older than **both**: it is not the newest, it ends at least
`--keep-events` events (default 10,000) before the anchored size, and its
last event is at least `--min-age-days` old (default 30). Both are
configurable; setting either to 0 removes that half of the window. The
effective values and the compaction time are recorded in the archive's
manifest (`policy`) for the audit trail, and are informational only: the
seal commits to the manifest without them, verifying an archive and
recovery never read them, and changing the retention of a later compaction
changes nothing about how history sealed earlier verifies. Compaction is
always run by an operator: there is no scheduler and nothing triggers one
automatically. Only
anchored and mirrored events are ever sealed, and the state is verified
(`verify-state`'s checks) before anything is written. The witnessed
checkpoints and the evidence they bind are in the database, which a
compaction does not touch, so they do not gate it.

Order and crash semantics. The sealed segments are verified (they chain
from the previous seal, or the empty log, to the database's own hash at
the seal) and copied, byte for byte, to `<archive>/segments/`, with
`<archive>/manifest-<size>.json` listing each with its SHA-256; the
archive is read back against the manifest. Then the state anchor is
replaced with a **seal** (the sealed size, the chain head there, the
manifest's digest): the anchor's compare-and-set is the commit point, and
the anchor becomes version 3, a few hundred bytes larger and constant. Only
then are the sealed segments deleted from the anchor store, oldest first,
each only if its bytes are the archived ones. A crash before the commit
point changes nothing (the archive holds files nothing refers to; running
the compaction again writes the same bytes). A crash after it leaves the
seal and some sealed segments still in the mirror: reading takes events up
to the seal as the archive's and ignores them, and the next compaction
deletes them. At no point is an event neither in the mirror nor in an
archive the anchor commits to.

Reading and recovery. The start, the checkpoints and recovery's rebuild
of a damaged mirror read from the sealed head: a truncated, gapped, edited
or forked tail, or an old sealed segment replayed after the tail, is
refused (GOVERNANCE LOG STATE ROLLBACK), as before. A restored backup is
refused as behind the anchor, as before. `recover` completes one that
reaches the seal from the tail alone. One that ends **inside the sealed
prefix** needs the archive:

```sh
encompute-control recover --operator NAME --archive-dir /mnt/archive/governance
```

The archive is checked against the seal (the manifest's digest, every
segment's SHA-256, the whole chain from the empty log to the anchored
head); a tampered, missing, swapped or substituted archive is refused and
recovery changes nothing. Without `--archive-dir` it says what is missing.
Keep the archive with the anchor's backups; **losing it costs
availability, never safety** (an old backup then cannot be brought back from
the mirror, and `export-governance-log` from a newer database still can).
Do not compact against another archive directory than the one the
previous compaction wrote: it is refused.

OpenBao. On OpenBao/Vault KV version 2 the delete destroys the key's
metadata, which removes every version of the segment and its entry in the
listing (a soft delete would leave the key listed). It is tested against a
real OpenBao 2.1.0 server in development mode (in-memory storage): the
compaction, the delete, a restart, and a recovery from the archive pass,
deleting again is harmless, a segment that is not the archived one is left
in place and reported, and an error from OpenBao in the middle of the
pruning (a token that may not delete one segment) leaves a mirror that
still verifies and a rerun finishes it. Not exercised: raft storage, a
Vault server, or an outage of the storage backend in the middle of a
delete, so plan the first compaction on a copy and keep the archive. The
token that compacts needs delete on the mirror's metadata path
(`<mount>/metadata/<path>-glog/*`) as well as what the control plane uses.

Versions. A compaction writes a version-3 anchor; a deployment that never
compacts keeps a version-2 anchor, which the previous release still reads.
A release that does not know seals refuses a version-3 anchor (state anchor
version 3 is not supported by this release): there is no downgrade after
the first compaction.

Recovery's import is batched: 1,000 events per statement, every event still
recomputed in memory (leaf, partition position, chain hash), in one
transaction, so a crash or a refusal anywhere leaves the database as it
was and the next run starts over (approximately 6x on the 120k-event
fixture in this environment, not a guaranteed benchmark: replaying
107,600 events took about 1,011 seconds one event at a time and about 160
seconds batched, on a heavily loaded machine).

**Restoring a database backup, step by step.** Since the state anchor holds
the audit chain's head with every checkpoint of the governance log (a deny
event's call returns only after it, and the background pass runs every two
seconds), restoring ANY database backup older than the last anchored
checkpoint is refused at start with `AUDIT STATE ROLLBACK` (or the
governance log or privacy refusal above when those moved too) until you
run `encompute-control recover`. In practice that is any backup older than
a couple of seconds or than the last deny event. Before this, a restore
within the old window of 100 audit events started silently with audit
events missing. The procedure:

1. Restore the database from the backup (the anchor is kept: it is newer).
2. Start the control plane, or run `encompute-control verify-state`: it is
   refused, naming what is behind (`AUDIT STATE ROLLBACK ... STARTUP REFUSED`).
3. Run `encompute-control recover --operator NAME` (with `--archive-dir`
   when the backup ends inside a compacted mirror's sealed prefix). It
   records the rewind in the audit chain as an `audit.gap.recorded` event
   (the anchored sequence and root are in it) and prints "audit chain:
   events after N were lost; the gap is recorded", and does everything
   below for the governance log and the ledgers.
4. Start the control plane.

The audit chain has **no mirror**: the audit events written after the
backup are lost for good. `recover` records that they were lost; it cannot
restore them. Keep database backups frequent if the audit trail matters,
and export audit events (`GET /v1/audit`) to your own archive.

Recovery also **freezes** every rolled-back ledger: the ledger is treated as exhausted,
so budget the database forgot is never spent again. Ledgers the governance log
records as frozen are frozen again. It re-applies every anchored revocation the
database forgot: the asset is revoked again, jobs that had not started
fail, and its key broker is told again. Disabled service accounts and users
are disabled again, and cancelled or failed jobs end again (never run
twice). Withdrawn asset approvals are withdrawn again, organizations
that left a project are removed from it again, and removed roles are
removed again. Revoked owner authorizations are revoked again and expired
assets expire again, each at the time of recovery, and their key brokers
are told again. Retired purposes are retired, and revoked governance keys
revoked, again, each at its originally recorded time. Each
re-application is a log event of its own (`<kind>.reapplied`, or the
transition's own kind where the usual path re-applies it), a row the
database lost is recorded lost (`row.lost`; its ID stays blocked), and a
ledger frozen is `ledger.frozen`. A version of a project's placement
constraints the restore dropped or rewrote (the log holds its number and
digest, not its content) is recorded lost in the project's own log
(`row.lost`, subject `<project>@<version>`; startup refused it as
`PLACEMENT STATE ROLLBACK`) and the project is held to the version the
database has until a member's security admin tightens it again, which takes
effect at once; location evidence a restore brought back after the log
recorded it lost, or another than the latest declaration, is taken back to
self-declared (`LOCATION EVIDENCE STATE ROLLBACK` refused the start) and the
operator declares it again. It records all of this,
and any audit gap, in the audit trail, then checkpoints the log. If the database lost a frozen
ledger's row but still holds its asset, recovery re-creates the row,
frozen, with no entries and a placeholder budget that pays for nothing
(audited as `privacy.ledger.frozen` with `ledger=recreated_missing_row`);
that ledger stays exhausted.

**Back up** ([backup.sh](../deploy/docker-compose/backup.sh)):

- PostgreSQL (with the governance log's tables);
- the anchor, with the governance log's mirror beside it;
- the key broker's state (wrapped keys only);
- the evaluator's receipt identity.

Large encrypted artifacts use object-store replication. **Restore**
([restore.sh](../deploy/docker-compose/restore.sh)) puts back an anchor only
into an empty anchor volume. An existing anchor is authoritative and is never
replaced by an older one. The key broker's state is restored the same way, so
a key destroyed by a revocation after the backup stays destroyed. The
database is restored in one transaction that stops at the first error, so
a partial restore fails and leaves the database as it was. The backup
captures the anchor before the database, so a backup taken while the
deployment runs always restores.

For production, keep the anchor in the customer's vault
(`ENCOMPUTE_ANCHOR_BAO_ADDR`, which must be https) rather than on a volume
that could be restored together with the database.

### Project checkpoints and witnessing

Every governed project has its own partition of the governance log, and
the control plane signs a checkpoint of it (its size and Merkle root) each
time the log is checkpointed:

- **Cadence.** A security deny event (a revocation, expiry, withdrawal,
  disable, removal, key revocation, purpose retirement, job end, ledger
  freeze) is checkpointed before its call returns, and so is a privacy
  spend (its ledger checkpoint is a platform event, never a project's).
  Everything else (an issued authorization, a member joining) is
  checkpointed by the background pass, which runs every two seconds while
  there are new events. So a checkpoint is never more than one background
  pass behind the log, and a member can witness any state of it. In short:
  the control plane checkpoints before it acknowledges anything that
  denies or spends, and within seconds otherwise; each member witnesses
  every few minutes (hourly where the log is quiet); the label is
  advisory and never blocks.
- **Witnessing.** Each member organization runs `encompute governance
  witness` on a schedule (every few minutes, or hourly where the log is
  quiet) with its governance key file and the credentials of a person who
  is a security admin of the organization (a token; a service account
  cannot witness):

  ```
  encompute governance witness --project PRJ --organization ORG \
      --key governance.key --state witness-PRJ.json --url https://control.example
  ```

  It fetches the latest checkpoint with the control plane's signed
  consistency proof from the one it witnessed last (kept in `--state`,
  which also pins the control plane's public key on first use; pass
  `--control-key` to pin it yourself), signs a witness and submits it. Exit
  0 means witnessed or nothing new; exit 1 means the control plane showed
  a history that does not extend the last one: nothing was signed and an
  equivocation proof was written beside the state file. Alert on a
  non-zero exit. Two members that suspect a split view compare what they
  hold with `encompute governance check-equivocation --state STATE A.json
  B.json`.
- **The label.** A checkpoint every member organization of that size
  signed is `witnessed`; any other is `unwitnessed`. It is advisory: it
  never blocks a job, an authorization or an export, and an organization
  that stops witnessing only leaves later checkpoints unwitnessed. A
  member that leaves a project can still countersign the checkpoints of
  sizes at which it was a member (a person with security_admin of that
  organization, over the witness route only; it reads nothing of the
  project), so a checkpoint is not left unwitnessed by a departure.
- **Reading.** `GET /v1/projects/{id}/audit` pages through the project's
  events with inclusion proofs (at most 200 per page; a caller may make
  120 requests a minute on the project log routes). `encompute governance
  verify-audit --project P --control-key K --pins pins.json` does the
  whole check without trusting the control plane's label: every inclusion
  proof against the checkpoint's signature, the members at that size from
  the verified membership events, each witness signature under the
  organizations' pinned governance keys (`pins.json`: organization to
  public key), and the `witnessed` label computed locally, and, with
  pins, each organization's latest revocation head (below). Exit codes:

  | Exit | Meaning |
  |---|---|
  | 0 | Everything checked and consistent (or the unchecked parts were accepted with `--allow-unpinned` / `--allow-unchecked`; the output still says `unpinned` and which organizations are UNCHECKED) |
  | 1 | The control plane's label or members differ, or a revocation head contradicts the log (omitted revocation, bad signature, recorded after its key was revoked, owner equivocation) |
  | 2 | A proof or signature fails, or an input cannot be read |
  | 3 | Nothing contradicted but not everything was checked: no `--pins` (unless `--allow-unpinned`), or any organization's revocation head is UNCHECKED (unless `--allow-unchecked`): none in the log, one owed, the latest one withheld from what was supplied, one dated before `--as-of`, one under an older key, or no pinned key for the organization |
- **Revocation heads.** Each owner and member organization also signs a
  head over every revocation it made in the project, so an evidence
  bundle cannot omit one unnoticed. `encompute governance sign --kind
  revocation-head --project PRJ --organization ORG --key governance.key
  --url https://control.example` fetches the control plane's draft, which
  lists the organization's revocations as sorted leaves with the root the
  head must carry, recomputes that root itself from the leaves (a draft
  whose root is not the root of its leaves is refused and nothing is
  signed; `--verify-draft` prints what would be signed and signs nothing),
  and prints the signed head, which the organization's security admin
  posts to `POST /v1/projects/PRJ/revocation-heads`. A governed
  revocation (an authorization or a purpose retirement) may carry its head
  in the same request: both are recorded or neither. Without one the
  revocation still takes effect at once, and the head is owed: it is the
  revocations recorded after the latest head's event that no head covers,
  and the draft shows `pending_since` and `overdue` after 24 hours. Sign the next head after any revocation, and
  after one that reaches several projects (an asset's revocation or
  expiry, a governance key's), once per project. While a head is owed a
  bundle checked against the latest head is UNCHECKED, never a pass; a
  head dated before the grant says nothing of later revocations, so a
  decision needs a head dated at or after it (`--as-of`, default now).
  Covered means as of the head: a head presented without a newer one the
  log records, or before a later revocation, is UNCHECKED. A head counts
  only through the log: `verify-audit` takes the latest
  `revocation_head.signed` event from the verified events and requires that
  head to be supplied, signed under the pinned key and recorded before the
  key's revocation event (a head's own date is the signer's claim and
  decides nothing about keys). Two signed heads with one number and
  different roots prove the owner equivocated (`encompute governance
  check-equivocation --org-key KEY HEAD1 HEAD2`; `verify-audit --heads
  FILE` checks copies you hold). A head must be dated no earlier than the
  newest revocation it covers and no more than a minute ahead; when
  signing together with a revocation date it a few seconds ahead. A head
  refused because the log moved on comes back as 409 with the current
  draft (`retryable`). Compare the draft's leaves with your own records:
  `sign --expect-leaves FILE` refuses a draft that omits one you list.
  An organization that left the project, or has no active governance key,
  cannot clear a head it owes: its bundles stay UNCHECKED and its draft
  says so (`cannot_sign_reason`); register a key before relying on a
  rotation. A schedule that signs and posts a head every hour keeps every
  bundle checkable. Alert when a draft is `overdue`.
- **What witnessing detects, and what it does not.** The control plane
  signs the checkpoints, so a member that checks nothing only has the
  control plane's word. Witnessing detects a control plane that shows
  different members different histories only when the members compare
  what they hold (exchange the checkpoint files or evidence and run
  `check-equivocation`): there is no gossip between members and nothing
  runs that comparison for them. It detects a rollback (a smaller
  checkpoint signed after a larger one) from the member's own stored
  checkpoint. It cannot tell a control plane that freezes or withholds
  checkpoints, or serves an old one, from a network failure (the tool
  reports a stale answer without evidence). The `witnessed` label on an
  answer is the control plane's own computation; it is a fact only to a
  reader who runs `verify-audit` with the organizations' keys.

### Governance evidence bundles

A governed job's evidence leaves the platform as one file,
`<project>-<job>.encgov.json`, that its institution can give to its own
auditor and verify offline. Everything below is `encompute governance`
(`export`, `verify`, `report`, `countersign`) and `encompute explain
--governance`; none of it needs the control plane after the export.

- **Export.** `encompute governance export JOB --pins pins.json --out
  FILE` fetches `GET /v1/jobs/{id}/governance-bundle` (`--view shared`, the
  same bytes for every member, or `--view org --organization ORG`),
  checks it before writing anything (format, section digests, the graph
  root, the view's rules, the plaintext guard, and everything this machine
  can verify against the pins) and writes it only if that passes. An
  existing file is never overwritten. `--sign-key KEY --sign-as ORG` adds
  the organization's signature (attribution: who vouches for this package;
  it adds no trust to the evidence inside). `countersign` adds another.
- **Pins file.** The verifier's own keys, never taken from the bundle or
  the control plane: `{"organizations": {"tax-agency": {"identity_key":
  "<64 hex>", "obtained": "published at ..."}}, "control_plane": {"key":
  "...", "obtained": "..."}, "evaluators": [{"key": "...", "obtained":
  "..."}]}` (`coordinators`, `linkage_authorities` and `release_signers`
  are accepted and reserved). `obtained` is required: it records where each
  key came from, so an auditor can see what a conclusion rests on. Trust
  in a report is exactly trust in these pins; agencies should publish their
  governance keys through official channels. Two organizations on one key
  are refused.
- **Exit codes** (one table, for `verify`, `report`, `explain
  --governance` and the check `export` and `countersign` run first):

  | code | meaning |
  |---|---|
  | 0 | every row satisfied, or accepted with `--allow-unchecked` / `--allow-unpinned` |
  | 1 | not satisfied: a row failed, or a pinned key contradicts the evidence; no flag accepts this |
  | 2 | malformed, forged or refused: not a bundle, an edit, an omission, a reordering, an unknown field, a forged signature, a leak, a bad pins file (ENC2727 to ENC2729) |
  | 3 | something is unchecked, not evidenced or unpinned (no `--pins`; a key not pinned; a shared view's cards without the owners' disclosures; evidence this release does not have) |

  `--allow-unchecked` accepts unchecked and not-evidenced rows; without
  `--pins`, `--allow-unpinned` is needed as well. The report always says
  what was accepted.
- **Shared views and disclosures.** A shared bundle shows another
  organization's authorization as a card. Its owner's signature cannot be
  checked from a card, so everything that rests on it is UNCHECKED until
  the owner discloses the signed document (`GET /v1/authorizations/{id}`
  as the owner, then `--disclosure FILE` on `verify`): a disclosed
  document replaces a card only if it is exactly the document the card
  names.
- **Stale revocation heads.** A revocation head says what was revoked as
  of its own date. By default a bundle is checked for the time of the run
  (the grant's signed time); `--as-of T` checks it for a later use, and a
  head dated before `T` is UNCHECKED, never covered.
- **Limits.** One bundle carries a contiguous run of at most 5,000 of the project's
  log events, ending at the signed checkpoint and starting at the earliest
  of the issuance of the job's authorizations and each owner's latest
  revocation head (the log's first event for an owner with none). The
  verifier checks the run: a gap, a duplicate or an end short of the
  checkpoint is refused, and a run that does not reach back far enough
  leaves the revocation rows UNCHECKED ("sign a fresh revocation head":
  owners who sign heads periodically keep their bundles checkable). When the run does not begin at the log's first event, the bundle also carries each owner's head leaf list (checked against the head's signed root; a governance-key revocation in it leaves the window UNCHECKED, an authorization revocation fails it), and the project's members can only be checked against `project_members` in your pins file (optional, all of them must witness; without it the witness row is UNCHECKED for a partial run). A file is at most 32 MiB, and its counts of witnesses, heads,
  members, authorizations and signatures are bounded (ENC2730). Every
  identifier in it is `[A-Za-z0-9._-]{1,200}` (ENC2727): the default file
  name is built from them and is never a path. The route is limited to 12
  requests a minute per caller and four builds at once.
- **Countersigning states what was verified.** A signature signs a
  statement: the BundleId, the verdict this machine reached, a digest of
  the pins used, and whether it accepted unchecked rows or no pins.
  `countersign` refuses an unchecked or unpinned bundle (exit 3) unless
  `--i-accept-unchecked` is given, and records that in the statement. A
  signature by an organization nobody pinned must still verify under the
  key it carries (reported as unpinned, attribution unchecked).
- **"Valid at grant".** A receipt carries no run time, so the report
  says the authorizations were valid when the grant was issued, and a
  revocation between the grant and its expiry is UNCHECKED.

## Audit

Every security-sensitive state transition writes an audit event in the same
transaction, with:

- the actor, the action, the resource and the result;
- the organization and project;
- the request ID;
- related IDs (plan, policy, spec, key version).

Audit events carry identifiers only. A value that looks like a payload is
refused.

The events form a hash chain. Signed checkpoints anchor the chain, so an
edited, deleted or reordered event before the last checkpoint is detected.
Events after the last checkpoint are covered only by the unkeyed hash chain
until the next checkpoint of the governance log, which anchors the audit
head with it (before the call returns for a security deny event, otherwise
by the background pass every two seconds; an audit checkpoint every
`ENCOMPUTE_AUDIT_CHECKPOINT_EVERY` events, default 100, also anchors it):
someone who can write the database could rewrite that tail undetected. Auditors read their own organization's events
(`GET /v1/audit`, `encompute audit list`).

## Configuration

Everything comes from the environment. Secrets should come from mounted
files (`*_FILE`), never from command-line arguments, and never from config
files in a repository.

Some secrets also accept the plain environment variable when the `_FILE`
variable is not set, and production mode accepts that too:
`ENCOMPUTE_DATABASE_URL` and `ENCOMPUTE_ANCHOR_BAO_TOKEN` for the control
plane, and `BAO_TOKEN` or `VAULT_TOKEN` for key brokers. Prefer the file:
environment variables are visible to anyone who can inspect the process.
Signing keys (`ENCOMPUTE_SIGNING_KEY_FILE`, `ENCOMPUTE_SERVICE_KEY_FILE`)
are read from files only.

| Variable | |
|---|---|
| `ENCOMPUTE_ENV` | required: `production` fails closed (below); `development` for local trials only. Unset or any other value refuses to start. Clients read it too: only `development` lets `jobs run` and the SDK accept an unpinned evaluator |
| `ENCOMPUTE_LISTEN` | default `127.0.0.1:8770` |
| `ENCOMPUTE_SERVICE_ID` | the control plane's service ID (default `control-plane`) |
| `ENCOMPUTE_WORKERS` | HTTP worker threads (default 8) |
| `ENCOMPUTE_DATABASE_URL_FILE` | PostgreSQL URL (a secret) |
| `ENCOMPUTE_SIGNING_KEY_FILE` | the control plane's Ed25519 seed (a secret) |
| `ENCOMPUTE_OIDC_ISSUER`, `ENCOMPUTE_OIDC_AUDIENCE` | the identity provider |
| `ENCOMPUTE_OIDC_JWKS_URL` / `_FILE` | its key set (default: `{issuer}/.well-known/jwks.json`) |
| `ENCOMPUTE_ANCHOR_DIR` or `ENCOMPUTE_ANCHOR_BAO_ADDR` (+ `_MOUNT`, `_PATH`, `_TOKEN_FILE`) | the state anchor |
| `ENCOMPUTE_AUDIT_CHECKPOINT_EVERY` | events between signed checkpoints (default 100) |
| `ENCOMPUTE_MAX_TOKEN_LIFETIME_SECS` | longest identity-token lifetime accepted, `exp - iat` (default 86400); must be a positive number |
| `ENCOMPUTE_METRICS_TOKEN_FILE` / `ENCOMPUTE_METRICS_TOKEN` | a bearer token `GET /metrics` requires (a secret), in either mode |
| `ENCOMPUTE_METRICS_PUBLIC` | `true` serves `/metrics` without a token in production (without a token, production refuses it); `true` or `false`, anything else refuses to start |
| `ENCOMPUTE_DEV_TOKEN_SECRET` / `_FILE` | development tokens only; production mode refuses to start when it is set |

Evaluators take `ENCOMPUTE_CONTROL_URL` and `ENCOMPUTE_CONTROL_PUBLIC_KEY`
(the pinned control-plane key), and `ENCOMPUTE_CONTROL_ID` (the control
plane's service ID, default `control-plane`; the CLI reads it too). They
also take `ENCOMPUTE_SERVICE_ID`, `ENCOMPUTE_SERVICE_KEY_FILE`,
`ENCOMPUTE_ADVERTISE_URL` and `ENCOMPUTE_CAPACITY`. At registration an evaluator also sends its machine
profile, which is used only for scheduling. It detects its logical cores,
CPU model and memory (Linux `/proc`, macOS `sysctl`). It takes
`ENCOMPUTE_EXACT_WORKERS` (threads per job, default the core count, at
most 8) and `ENCOMPUTE_BENCHMARK_PROFILE` (the calibrated cost profile it
was benchmarked under, for example `openfhe-1.5.1/apple-m3-max`). Key
brokers and SecAgg coordinators take the same service identity variables.

Clients that run jobs (`encompute jobs run`, the Python SDK) take
`ENCOMPUTE_TRUSTED_EVALUATORS`, the evaluator receipt keys they trust (hex,
separated by commas or spaces; set but empty pins nothing and refuses every
evaluator), and, for development only,
`ENCOMPUTE_ALLOW_UNPINNED_EVALUATOR=1` (honoured only with
`ENCOMPUTE_ENV=development` set explicitly; unset or any other value
refuses it).

Evaluator resource limits:

| Variable | |
|---|---|
| `ENCOMPUTE_EXACT_THREADS` | gate threads for all exact jobs of the process together (default: logical cores). A job waits for threads rather than oversubscribing the machine |
| `ENCOMPUTE_EXACT_WORKERS` | at most this many of them per job (default: cores, at most 8) |
| `ENCOMPUTE_KEY_CACHE_BYTES` | bound on cached evaluation keys, counted as the uploaded envelope bytes (default 4 GiB). Least recently used keys are evicted; a job in progress keeps its keys until it ends; an evicted key is reported missing and the client uploads it again. With worker processes, each worker has this bound |
| `ENCOMPUTE_EXACT_EXECUTION` | `reference` runs exact programs instruction by instruction (the correctness oracle) instead of the optimized circuit. For diagnosis only: results are identical, it is slower |
| `ENCOMPUTE_MAX_KEY_BYTES` | largest evaluation-key upload (default 4 GiB, sized for bootstrapping keys; lower it where keys are smaller) |
| `ENCOMPUTE_MAX_PROGRAM_BYTES`, `ENCOMPUTE_MAX_INPUT_BYTES` | largest program upload (default 64 MiB) and inputs envelope (default 256 MiB) |

With a control plane configured, an evaluator accepts program and key
uploads only with the job's grant, as it does jobs, and the grant must name
the uploaded program before it is compiled. Whether a key is registered is
answered only with a grant for the program, and `GET /v1/info` lists only
the program a presented grant names. Without a control plane (local
development) none of this needs a grant. Job IDs are 128-bit random.

OpenFHE exact keys do not depend on the program, so one upload serves every
exact program on that evaluator. They are still usable only by programs the
client registered them for, and a ciphertext only ever runs under the key its
envelope is bound to.

**Production mode refuses:**

- development tokens;
- a missing identity provider, or one over plain HTTP;
- a missing signing key;
- default or empty database passwords;
- an anchor vault over plain HTTP;
- development key stores and root keys (key brokers).

Every refusal is ENC2605.

## Operations

- **Health.** `GET /live` means the process is up. `GET /ready` means it can
  accept secure work (the database answers). Key brokers serve the same two.
- **Metrics.** `GET /metrics` (Prometheus text format). In production a
  scraper presents `Authorization: Bearer <metrics token>`
  (`ENCOMPUTE_METRICS_TOKEN_FILE`), unless `ENCOMPUTE_METRICS_PUBLIC=true`;
  otherwise it answers 401. The Compose deployment's `init.sh` creates the
  token in `secrets/metrics-token`. It exports:
  - jobs by state;
  - job and evaluation durations;
  - queue depth;
  - failed plans;
  - key-release denials;
  - privacy denials;
  - trust failures;
  - SecAgg round durations;
  - state rollbacks found while running (`encompute_state_rollback_total`,
    labelled `privacy`, `audit` or `governance`);
  - the governance log mirror's open segment: its size as last rewritten
    (`encompute_mirror_rewrite_bytes`, a gauge, at most about 256 KiB) and
    the time each rewrite takes (`encompute_mirror_write_seconds`);
  - service accounts still holding `security_admin`
    (`encompute_legacy_service_admins`, a gauge that should be 0);
  - contention on the state anchor: updates that lost the anchor's
    compare-and-set to another control plane (or found a mirror segment
    written meanwhile) and were attempted again from the stored anchor
    (`encompute_anchor_cas_retry_total`, a counter; a few under concurrent
    load are normal), and updates that lost it on all three attempts and
    were refused with ENC2202 (`encompute_anchor_cas_retry_exhausted_total`,
    which should stay 0: it also logs an `anchor_cas_exhausted` line; each
    retry logs `anchor_cas_retry`). A start's decision is committed before
    it is anchored, so an exhausted start returns ENC2202 with its decision
    kept and anchored by the next checkpoint, or by the evaluator's retry;
  - the size of the signed state anchor in bytes
    (`encompute_anchor_bytes`, a gauge). It is constant: security-negative
    transitions and privacy ledger checkpoints are governance log events,
    so nothing in the anchor grows with assets, revocations or spends. The
    gauge is a tripwire: a few hundred bytes is normal, and above 512 KiB
    every start and every anchor write logs an `anchor_size_warning`
    line, which should never happen. What to watch instead is the log's
    mirror in the anchor store (about 300 bytes per event, one per spend
    and per transition) against the store's capacity.

  Labels are closed sets: never identifiers or values.
- **Evaluator metrics.** Evaluators also serve `GET /metrics`: requests,
  jobs, and the evaluation-key cache (hits, misses, loads, load seconds,
  evictions, bytes, entries and the bound). No labels, no key IDs.
- **Logs.** One JSON object per line, with the service and the request,
  job, project and organization IDs where they apply. Logs never include
  request bodies, tokens, keys or payloads.
- **Canary tests.** `scripts/enterprise-e2e.sh` plants secrets in a dataset,
  an input value and an asset key, then scans every log, the database dump,
  the audit output and the metrics for them.

## Message transport

Asynchronous messages (job completions, privacy events, revocations) are
signed envelopes. Each one carries:

- a protocol version and a message ID;
- the sender and the recipient;
- the organization, project, job and round, where they apply;
- creation and expiry times;
- a payload digest.

The transport is not trusted for confidentiality or correctness. It may
duplicate, delay, reorder, drop or replay messages, and security holds
anyway:

- consumers apply each message once;
- expired or misaddressed messages are refused;
- large data travels as a URI and a digest, never inline.

HTTP delivery (with retries from an outbox) is built in; a queue adapter
implements the same interface. One exception: the CLI's SecAgg coordinator
(`encompute aggregate serve` with a control plane) sends its privacy events
and round reports directly, without an outbox. If the control plane is
unreachable, that send fails and is not retried later.

## Commands

```sh
encompute-control migrate                # apply database migrations (versioned; never edited)
encompute-control bootstrap --issuer ISS --subject SUB   # the first platform admin
encompute-control serve
encompute-control verify-state           # does the database extend the anchor?
encompute-control recover --operator NAME [--governance-log FILE]
encompute-control export-governance-log [--after GSEQ] > FILE   # the log's events, JSON lines
encompute-control public-key FILE        # a service key's public key, for registration

encompute login --url URL --token-file TOKEN
encompute projects list | create | show | add-member
encompute assets list | register | approve | revoke | lineage
encompute jobs submit | run | status | list | cancel
encompute trust report JOB
encompute audit list
```

## Relevant source modules

- `crates/encompute-control`: the control plane (API, authentication,
  authorization, jobs, scheduler, privacy ledgers, anchor, audit, transport).
- `crates/encompute-keybroker/src/root.rs`: root key providers and the
  root-wrapped KEK.
- `crates/encompute-verification/src/service.rs`: service identities, signed
  requests, messages and job grants.
- `crates/encompute-evaluator/src/control.rs`: the evaluator's link to the
  control plane.
- `deploy/docker-compose`: the Compose deployment, backup and restore.
- `docs/adr/0021-enterprise-deployment.md`.
