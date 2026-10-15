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
  open; restore it from a backup instead. A backup does restore keys revoked
  since it was taken (a rollback this check does not detect), so keep
  backups access-controlled.
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
  or of the asset's organization.
- **Failures.** A provider that is unavailable, disabled, refuses the
  organization's context, or no longer decrypts a key version releases
  nothing. There is no fallback to local or plaintext keys. Production
  brokers refuse development stores.

## Upgrading from 0.3.0 to 0.3.1 (security upgrade)

0.3.1 changes no database schema, API, wire format or anchor format:
`encompute-control migrate` reports schema version 4 before and after, and
the anchor file is read as it is. What changes is how the control plane
treats privacy ledgers and anchored revocations, and on an existing
installation that needs one reviewed operator action. Read this whole
section before you start. The [release notes](release-notes-0.3.1.md) and the
[changelog](../CHANGELOG.md) say what each finding was.

**What to do, in this order:**

1. **Back up the database and the anchor, together, before you install
   0.3.1.** Use [backup.sh](../deploy/docker-compose/backup.sh), or a
   `pg_dump` plus a copy of the anchor (the directory behind
   `ENCOMPUTE_ANCHOR_DIR`, or the vault path behind
   `ENCOMPUTE_ANCHOR_BAO_ADDR`). Keep the anchor copy where neither the
   database's backup tooling nor the database administrator can rewrite it,
   and take it before the database, as `backup.sh` does. Keep both until you
   have finished this section and trust the result: they are the only
   supported way back (see
   [No supported downgrade](#no-supported-downgrade-to-030)).
2. **Install 0.3.1 and start it.** There is no migration to run. Start-up is
   not refused because of this release. If any privacy ledger has no
   checkpoint in the anchor (see below), the log line `unanchored_ledgers`
   names it and the gauge `encompute_unanchored_ledgers` counts it. Go on to
   step 3 whatever the count is.
3. **Review every ledger's genesis against the data owner's own records,
   before you run `anchor-ledgers`.** The genesis holds the privacy budget
   (the cap: unit, epsilon and delta) that every spend is checked against.
   The control plane cannot tell a genuine budget from a forged one: nothing
   the data owner signed binds it in 0.3. Compare it with a record that does
   not come from this database: the registration request or configuration
   the owner submitted, the owner's ticket or contract, and so on. List the
   ledgers with a read-only query:

   ```sql
   SELECT l.asset_id, l.organization_id,
          l.genesis->'budget' AS budget,            -- unit, epsilon, delta: compare with the owner
          l.genesis->>'privacy_policy_id' AS policy_hash,
          l.frozen_reason, l.created_at,
          (SELECT count(*) FROM privacy_entries e WHERE e.asset_id = l.asset_id) AS entries
   FROM privacy_ledgers l
   ORDER BY l.created_at, l.asset_id;
   ```

   The budget of one asset is also returned by `GET /v1/privacy/{asset}`
   (fields `budget`, `spent`, `entries`, `root`, `frozen`) to a data owner,
   auditor, organization admin or security admin of the asset's
   organization; `GET /v1/privacy/{asset}/ledger` exports the whole ledger.
   Do this for **every** ledger, not only for the ones the log names as
   unanchored. A ledger that 0.3.0 already anchored keeps the genesis it was
   anchored with, and 0.3.1 cannot tell whether that genesis was genuine
   (see [What the upgrade does not repair](#what-the-upgrade-does-not-repair)).

   Compare the spending as well. Every accepted spend is one ledger entry
   and one audit event of the same asset; a duplicate delivery of an event
   adds neither:

   ```sql
   SELECT l.asset_id,
          count(*) FILTER (WHERE e.entry->'event'->>'kind' = 'reserve') AS ledger_reserves,
          count(*) FILTER (WHERE e.entry->'event'->>'kind' = 'commit')  AS ledger_commits,
          (SELECT count(*) FROM audit_events a
            WHERE a.resource_id = l.asset_id AND a.action = 'privacy.spent')     AS audit_spent,
          (SELECT count(*) FROM audit_events a
            WHERE a.resource_id = l.asset_id AND a.action = 'privacy.committed') AS audit_committed
   FROM privacy_ledgers l LEFT JOIN privacy_entries e ON e.asset_id = l.asset_id
   GROUP BY l.asset_id ORDER BY l.asset_id;
   ```

   `ledger_reserves` should equal `audit_spent`, and `ledger_commits`
   should equal `audit_committed`. More audit events than ledger entries
   means a spend was acknowledged and its entry later erased: the ledger's
   remaining budget is larger than the truth. Treat it as an incident. (The
   audit chain itself is checked by `encompute-control verify-state`. A
   database writer who can also rewrite the audit trail defeats this
   comparison.)
4. **Anchor the ledgers you checked, with the service stopped.** Stop the
   control plane, run the command with the environment the service uses
   (with Compose: `docker compose stop control`, then
   `docker compose run --rm control anchor-ledgers --operator NAME --asset ID`),
   and start the service again afterwards:

   ```sh
   encompute-control anchor-ledgers --operator NAME --asset ID [--asset ID ...]
   ```

   For each ledger the command prints the budget, the entry count and the
   checkpoint root, writes the audit event `privacy.ledger.genesis_anchored`,
   and ends with `ANCHORED N ledger(s)`. A ledger that already has an
   anchored checkpoint is refused (exit 2, "is not an unanchored privacy
   ledger") and nothing changes.

   Why the service must be stopped: the command starts its own control plane
   on the same anchor and writes the anchor from that second process. A
   running `serve` keeps its own in-memory copy of the anchor and re-reads
   the stored one only when one of its own anchor writes loses a
   compare-and-set, so it can keep refusing the ledger you just anchored. It
   also puts two processes on one anchor, against the one-process-per-anchor
   rule above.
   *Read in the code:* the CLI runs `Control::start` in its own process
   (`main.rs`); `Anchor` keeps the state in memory and reloads it only on a
   "changed concurrently" error in `try_update` (`anchor.rs`); a spend reads
   that in-memory copy (`anchor.snapshot()` in `ops/assets.rs`). *Not run:*
   the command against a live service. The upgrade check ran it with the
   service stopped.
5. **Check the result.** After the restart `encompute_unanchored_ledgers`
   should be 0, or list only the ledgers you decided not to anchor, and a
   spend on an anchored ledger is accepted.

**What `anchor-ledgers` is not.** It records the checkpoint the database
holds *now* as the ledger's anchored checkpoint. It is not a cryptographic
validation of the data owner's original privacy cap: no owner-signed cap
exists in 0.3, so the budget in the database is whatever the registration
request said, or whatever a database writer put there. The command trusts the
database for the ledgers it anchors, and the review in step 3, done by you,
is the only check that the number is the right one. An operator who anchors a
rewritten or forged genesis anchors it, and from then on the control plane
enforces that cap. **`--all` makes blind use easy:** it anchors every
unanchored ledger without asking about any of them. Use it only after every
ledger it will anchor has been reviewed as in step 3; otherwise name the
assets with `--asset`.

**What operators will see until the command has run.** A ledger that the
anchor holds no checkpoint for refuses every spend with HTTP 500 and
`ENC2202 PRIVACY STATE ROLLBACK: the privacy ledger of <asset> is not
anchored ...`. This is the intended fail-closed behavior, and it is
expected after the upgrade for those ledgers: nothing fails open, start-up
is not refused, and everything else keeps working. It is reported as a
rollback, though: each refused attempt writes the log line
`state_rollback_detected` (state `privacy-unanchored`) and raises
`encompute_state_rollback_total{label="privacy-unanchored"}`, and the gauge
`encompute_unanchored_ledgers` stays above 0. Tell whoever is paged by the
rollback alert before you upgrade. The ledgers affected are those 0.3.0
never anchored (an anchor write that failed during registration and was
followed by a crash, or a ledger row written into the database). Ledgers
whose creation 0.3.0 acknowledged are already anchored and need nothing.
Reading a ledger (`GET /v1/privacy/{asset}`) still works and shows what the
database holds, so you can do step 3.

### What the upgrade does not repair

- **A genesis that 0.3.0 already anchored is not re-examined, and nothing
  repairs it automatically.** On 0.3.0 a ledger whose genesis was forged or
  rewritten (before its first spend, or in the interval of its
  registration) was anchored with that genesis. After the upgrade it is
  anchored, passes every 0.3.1 check and spends up to the forged cap. The
  upgrade cannot detect this, and there is no command that corrects an
  anchored genesis; step 3 is the only check. If you find one that is wrong,
  stop spending on it and handle it as an incident.
- **Spends 0.3.0 forgot, and revocations it never anchored.** On 0.3.0 a
  spend erased between its commit and its anchoring, or a revocation,
  disable, cancellation, withdrawal or removal undone in that interval, was
  acknowledged and not anchored. 0.3.1 cannot find these afterwards. Use the
  comparison in step 3, and re-issue any revocation whose acknowledgement
  predates 0.3.1 if you cannot confirm the current state.

### No supported downgrade to 0.3.0

Do not roll back by putting the 0.3.0 binary back. It starts on the database
and anchor that 0.3.1 used, and it re-opens the findings 0.3.1 fixed. In a
check of that swap, 0.3.0 accepted and anchored a spend on a ledger whose
genesis had been forged with SQL (a budget of epsilon 3000), which 0.3.1 had
refused. 0.3.1 then started on the result and held that genesis as
authentic. Whatever is written during the rollback period is anchored on the
older, weaker terms.

The only supported rollback is to restore the database dump taken before the
upgrade **together with the anchor copy taken at the same time**, and then
start 0.3.0. The pre-upgrade dump with the newer anchor is refused by 0.3.0
(ENC2202). The other choice is to stay on 0.3.1.

### Restoring both the database and the anchor

If the database and the independently held anchor are both restored to an
old state that is consistent with itself, 0.3.1 does not detect it:
everything since that state is forgotten (privacy spending, revocations,
disables, cancellations, withdrawals and removals). That is out of scope for
this release, as it was for 0.3.0. Keep the anchor outside the database's
backup set, and restore it only into an empty volume.

### What the anchor does not cover

Restoration or deletion of the same anchored records is detected within the
implemented checks. Creation of NEW role, membership or approval records (or a
user/service account recreated under a new ID) may not be detectable through
an ID-based anchor. The external anchor does not independently authenticate
every newly introduced database authority. 0.3.1 does not prevent someone
with write access to the database from recreating authority that was revoked.

The interval between a request's check and the use it permits is not short by
guarantee, and it is not absent. How long a request can be held in it is
controlled by whoever holds locks on the database tables, so no duration
should be assumed.

<<B1-B2-WORDING>>

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

## Privacy state and backups

The privacy ledgers (every charged release) live in PostgreSQL, hash-chained,
with an exclusive lock per ledger: two spends can never both use the last of
a budget. A duplicate delivery of the same event is charged once.

The control plane signs into the **state anchor**:

- the ledgers' latest roots, after every spend;
- the audit chain's root, at each checkpoint;
- every security-negative transition: revoked assets, frozen ledgers,
  disabled service accounts and users, cancelled and failed jobs,
  withdrawn asset approvals (including the grants an organization lost by
  leaving a project), removed project memberships, and organization roles
  removed from a user or service account.

The anchor is kept outside the database: on its own volume, or in the
customer's vault (OpenBao or Vault KV). It only moves forward along the
same chains. Run one control-plane process per anchor.

While the service runs, a spend on a ledger that no longer extends the
anchor is refused (ENC2202 PRIVACY STATE ROLLBACK), and so is an audit
checkpoint over a chain that does not extend the anchored one (ENC2202
AUDIT STATE ROLLBACK). Neither is written into the anchor. Each raises an
alarm: a `state_rollback_detected` log line and the
`encompute_state_rollback_total` metric. A ledger frozen in the anchor is
refused for spending whatever the database says (ENC2201).

From 0.3.1 a spend (and the creation of an asset with a privacy budget) is
acknowledged only when the anchor holds exactly the entry, or genesis, that
call committed. A ledger changed between the commit and the anchoring is
refused with ENC2202 and the same alarm; the client sees an error, not an
acknowledgement, and retrying the same event is correct. Earlier 0.3
versions re-read whatever the database then showed and could acknowledge
a spend the ledger no longer held.

At every start, the database must extend the anchor. If it does not, the
control plane refuses to start:

```text
error[ENC2202]: PRIVACY STATE ROLLBACK: ... STARTUP REFUSED
```

The same refusal names AUDIT, FREEZE (a frozen ledger shown spendable),
REVOCATION, SERVICE ACCOUNT, USER, JOB (a cancelled or failed job shown
live), APPROVAL (a withdrawn asset approval held again), MEMBERSHIP (an
organization listed again in a project it left) or ROLE (a removed role
held again) when that is what the database undid. That happens when an older
database backup was restored, or the database was edited. Recovery is
explicit:

```sh
encompute-control recover --operator NAME
```

It **freezes** every rolled-back ledger: the ledger is treated as exhausted,
so budget the database forgot is never spent again. Ledgers the anchor had
frozen are frozen again. It re-applies every anchored revocation the
database forgot: the asset is revoked again, jobs that had not started
fail, and its key broker is told again. Disabled service accounts and users
are disabled again, and cancelled or failed jobs end again (never run
twice). Withdrawn asset approvals are withdrawn again, organizations
that left a project are removed from it again, and removed roles are
removed again. It records all of this,
and any audit gap, in the audit trail. If the database lost a frozen
ledger's row but still holds its asset, recovery re-creates the row,
frozen, with no entries and a placeholder budget that pays for nothing
(audited as `privacy.ledger.frozen` with `ledger=recreated_missing_row`);
that ledger stays exhausted.

**Unanchored ledgers.** A privacy ledger spends only when the anchor holds a
checkpoint for it. If the anchor store failed during an asset registration,
the process re-anchors the creation it committed on its next tick. After a
crash (or if a database writer inserted a ledger row), the ledger stays
unanchored: every spend on it is refused (ENC2202, "is not anchored"), the
log line `unanchored_ledgers` names it at start-up and on every tick and the
`encompute_unanchored_ledgers` gauge counts it (it should be 0). Compare each
named ledger's genesis (`GET /v1/privacy/{asset}`) with the data owner's
records, then:

```sh
encompute-control anchor-ledgers --operator NAME --asset ID [--asset ID ...]
encompute-control anchor-ledgers --operator NAME --all
```

Stop the service before you run it, and start it again afterwards. This
trusts the database for those ledgers: it anchors the checkpoint the
database holds now, prints it (budget, entry count, root) and audits it as
`privacy.ledger.genesis_anchored`. It is not a validation of the owner's
original cap, and `--all` anchors every unanchored ledger without asking
about any of them. After upgrading from 0.3.0 or an earlier 0.3.1 build,
ledgers that already have an anchored checkpoint need nothing; check the
gauge once. The full upgrade steps, with the review to do first, are in
[Upgrading from 0.3.0 to 0.3.1](#upgrading-from-030-to-031-security-upgrade).

**A latched control plane.** The service checks the database against every
anchored revocation, disable, cancellation, approval withdrawal, project leave
and role removal before each request and on each tick. If the database undoes
one while the service runs, the control plane latches: every request
(except `/live`, `/metrics` and `/v1/info`) fails with ENC2202 "CONTROL PLANE
LATCHED", `/ready` answers 503 and the log line `control_plane_latched` names
what was undone. Stop the service, restore the missing state or run
`encompute-control recover`, and start it again.

**Back up** ([backup.sh](../deploy/docker-compose/backup.sh)):

- PostgreSQL;
- the anchor;
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
until the next checkpoint (every `ENCOMPUTE_AUDIT_CHECKPOINT_EVERY` events,
default 100): someone who can write the database could rewrite that tail
undetected. Auditors read their own organization's events
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
    labelled `privacy` or `audit`);
  - service accounts still holding `security_admin`
    (`encompute_legacy_service_admins`, a gauge that should be 0);
  - the size of the signed state anchor in bytes
    (`encompute_anchor_bytes`, a gauge). The anchor keeps every ended job,
    disable, withdrawal and removal, and is rewritten whole on each
    update. OpenBao's KV store refuses an entry larger than its raft
    `max_entry_size` (1 MiB by default, roughly 25,000 to 30,000 ended
    jobs); from then on anchor writes fail and the control plane fails
    closed (privacy spends, cancellations and revocation acknowledgements
    stop). Above 512 KiB every start and every anchor write logs an
    `anchor_size_warning` line. Alert on `encompute_anchor_bytes >
    524288`, and raise `max_entry_size` on the vault before the limit is
    reached.

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

### Container hardening and the util-linux/libacl findings

The five images (control, evaluator, services, Confidential Space, training)
are built on Debian 12 and carry util-linux 2.38.1 and libacl1 2.3.1, for
which Debian has no fix yet. Image scans therefore report six High findings
in every image: CVE-2026-53613, CVE-2026-76642, CVE-2026-78408,
CVE-2026-78409 and CVE-2026-78410 (the `mount` and `nsenter` programs) and
CVE-2026-54369 (libacl). The release accepts them for as long as the
distribution has no fix, on conditions that you, the operator, must keep.
This is a conditional acceptance, not a claim that the findings cannot be
exploited.

- **What the images do.** Nothing Encompute runs calls `mount`, `umount`,
  `nsenter`, `su` or libacl. The images ship `/etc/fstab` with no entries,
  which is the precondition of the four `mount` findings, and the control,
  evaluator and services images run as unprivileged users (10002, 10001,
  10003). Exploiting any of the six first needs code execution inside a
  container, and then either an `fstab` entry that allows a non-root user to
  mount, or a privileged caller of `nsenter --join-cgroup` or of a libacl
  function working on a path the attacker controls.
- **What the Compose file sets.** The control, evaluator, key broker and
  secagg services run with `no-new-privileges:true` and `cap_drop: [ALL]`.
  With both, the setuid `mount`, `umount` and `su` in the image cannot raise
  privileges and the process holds no capability. Do not remove these
  settings, and do not add `privileged`, `cap_add` (in particular
  `SYS_ADMIN`), `user: root`, host PID or cgroup namespaces, or a writable
  `/etc/fstab` to these services.
- **If you run the images another way** (`docker run`, Kubernetes, another
  scheduler), set the same: `--security-opt no-new-privileges:true
  --cap-drop ALL`, or in Kubernetes `allowPrivilegeEscalation: false`,
  `capabilities.drop: [ALL]` and `runAsNonRoot: true`. This repository ships
  no Kubernetes manifests, so these settings are yours to apply and verify.
- **The two Confidential Space images** (confidential-space and training)
  run as root inside the attested virtual machine and are not covered by the
  Compose settings. Their protection is the launcher's container
  configuration and the VM itself, not these flags. Run them only as the
  approved image digest, with the workload launched by Confidential Space
  and no shell or operator command executed inside the container.
- **Do not run an operator command that touches an attacker-controlled path
  inside an Encompute container** (`nsenter`, or `tar`, `cp` or `getfacl`
  working on a mounted volume you do not trust).

The per-finding record, with what each image contains, what exploitation
needs and what was tested, is kept with the release evidence
(`CVE-DISPOSITIONS-HIGH.md`). Replacing the base image once Debian ships a
fix is the only change that removes the findings.

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
encompute-control recover --operator NAME
encompute-control anchor-ledgers --operator NAME (--asset ID ... | --all)   # anchor unanchored privacy ledgers, audited
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
