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
