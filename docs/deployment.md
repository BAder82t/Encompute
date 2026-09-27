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
issuer, audience and expiry. The identity must be registered as a user of an
organization. A user (`alice@hospital-a.example`) is never the same thing as
a cryptographic party in a program's policy (`hospital-a`).

**Services** have their own Ed25519 keys: the control plane, each evaluator,
each key broker, each SecAgg coordinator, and any automation. A service signs
every request and message. The signature covers:

- the method, the path and a hash of the body;
- the sender and the recipient;
- a timestamp;
- a nonce (a replayed request is refused);
- the IDs the request is about.

A source IP address, a hostname or a private network is never treated as an
identity. TLS (a proxy or load balancer in front of each service) protects
traffic in transit. The signatures stay valid through proxies and brokers.

**Roles** (per organization):

| Role | Can |
|---|---|
| `organization_admin` | Add users and automation accounts, add collaborators to its projects, create projects. |
| `security_admin` | Propose and approve policies (a different admin must approve), disable service accounts, revoke assets. |
| `data_owner`, `model_owner` | Register their organization's assets, approve them for a project and purpose, revoke them, spend privacy budget. |
| `ml_developer` | Create projects, plan and submit jobs, complete jobs with their receipts. |
| `auditor` | Read the audit trail and privacy ledgers. |
| `operator` | Platform operators: drain evaluators, checkpoint the audit trail. |

Fine-grained rules about data (who may learn what, for which purpose) stay
in each program's confidentiality policy. The roles only decide who may act
on the control plane.

**Tenant isolation.** An identity sees only its own organizations'
resources, plus what an explicit collaboration grants:

- project membership, added by the project owner's admins;
- an asset's approval for a project and purpose, given by its owner.

Anything else is reported as not found (ENC2603), so other tenants' IDs do
not even confirm that a resource exists. Platform admins create
organizations and register platform services, but cannot read tenant data.

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
     for this project and purpose.
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
3. The client sends its encrypted inputs to the evaluator with the grant.
   The evaluator:
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
evaluator's own heartbeats cannot undo a drain.

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
- **What Encompute stores.** Only the key reference, the provider, the root
  key's version and the wrapped KEK: never the master secret.
- **Rotation.** `encompute keys rotate-root` re-wraps the KEK under the new
  root key version. Asset keys are unchanged. The rotation (old and new
  version) is printed for the audit trail.
- **Revocation.** Revoking an asset on the control plane is immediate: no
  new job may use it, jobs not yet running fail, and its key broker is told
  (a signed message, delivered at least once) to destroy every version of
  its key.
- **Failures.** A provider that is unavailable, disabled, refuses the
  organization's context, or no longer decrypts a key version releases
  nothing. There is no fallback to local or plaintext keys. Production
  brokers refuse development stores.

## Privacy state and backups

The privacy ledgers (every charged release) live in PostgreSQL, hash-chained,
with an exclusive lock per ledger: two spends can never both use the last of
a budget. A duplicate delivery of the same event is charged once.

After every spend, the control plane signs the ledgers' latest roots, the
audit chain's root at each checkpoint, and every asset revocation, into the
**state anchor**. The
anchor is kept outside the database: on its own volume, or in the customer's
vault (OpenBao or Vault KV). At every start, the database must extend the
anchor. If it does not, the control plane refuses to start:

```text
error[ENC2202]: PRIVACY STATE ROLLBACK: ... STARTUP REFUSED
```

That happens when an older database backup was restored, or events were
deleted. Recovery is explicit:

```sh
encompute-control recover --operator NAME
```

It **freezes** every rolled-back ledger: the ledger is treated as exhausted,
so budget the database forgot is never spent again. It re-applies every
anchored revocation the database forgot (REVOCATION STATE ROLLBACK): the
asset is revoked again, jobs that had not started fail, and its key broker
is told again. It records the freeze, the revocations, and any audit gap,
in the audit trail.

**Back up** ([backup.sh](../deploy/docker-compose/backup.sh)):

- PostgreSQL;
- the anchor;
- the key broker's state (wrapped keys only);
- the evaluator's receipt identity.

Large encrypted artifacts use object-store replication. **Restore**
([restore.sh](../deploy/docker-compose/restore.sh)) puts back an anchor only
into an empty anchor volume. An existing anchor is authoritative and is never
replaced by an older one. The key broker's state is restored the same way, so
a key destroyed by a revocation after the backup stays destroyed. The backup
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
edited, deleted or reordered event is detected. Auditors read their own
organization's events (`GET /v1/audit`, `encompute audit list`).

## Configuration

Everything comes from the environment. Secrets come from mounted files
(`*_FILE`): never from command-line arguments, never from config files in a
repository.

| Variable | |
|---|---|
| `ENCOMPUTE_ENV` | `production` fails closed (below); default `development` |
| `ENCOMPUTE_LISTEN` | default `127.0.0.1:8770` |
| `ENCOMPUTE_DATABASE_URL_FILE` | PostgreSQL URL (a secret) |
| `ENCOMPUTE_SIGNING_KEY_FILE` | the control plane's Ed25519 seed (a secret) |
| `ENCOMPUTE_OIDC_ISSUER`, `ENCOMPUTE_OIDC_AUDIENCE` | the identity provider |
| `ENCOMPUTE_OIDC_JWKS_URL` / `_FILE` | its key set (default: `{issuer}/.well-known/jwks.json`) |
| `ENCOMPUTE_ANCHOR_DIR` or `ENCOMPUTE_ANCHOR_BAO_ADDR` (+ `_MOUNT`, `_PATH`, `_TOKEN_FILE`) | the state anchor |
| `ENCOMPUTE_AUDIT_CHECKPOINT_EVERY` | events between signed checkpoints (default 100) |

Evaluators take `ENCOMPUTE_CONTROL_URL` and `ENCOMPUTE_CONTROL_PUBLIC_KEY`
(the pinned control-plane key). They also take `ENCOMPUTE_SERVICE_ID`,
`ENCOMPUTE_SERVICE_KEY_FILE`, `ENCOMPUTE_ADVERTISE_URL` and
`ENCOMPUTE_CAPACITY`. At registration an evaluator also sends its machine
profile, which is used only for scheduling. It detects its logical cores,
CPU model and memory (Linux `/proc`, macOS `sysctl`). It takes
`ENCOMPUTE_EXACT_WORKERS` (threads per job, default the core count, at
most 8) and `ENCOMPUTE_BENCHMARK_PROFILE` (the calibrated cost profile it
was benchmarked under, for example `openfhe-1.5.1/apple-m3-max`). Key
brokers and SecAgg coordinators take the same service identity variables.

Evaluator resource limits:

| Variable | |
|---|---|
| `ENCOMPUTE_EXACT_THREADS` | gate threads for all exact jobs of the process together (default: logical cores). A job waits for threads rather than oversubscribing the machine |
| `ENCOMPUTE_EXACT_WORKERS` | at most this many of them per job (default: cores, at most 8) |
| `ENCOMPUTE_KEY_CACHE_BYTES` | bound on cached evaluation keys, counted as the uploaded envelope bytes (default 4 GiB). Least recently used keys are evicted; a job in progress keeps its keys until it ends; an evicted key is reported missing and the client uploads it again. With worker processes, each worker has this bound |
| `ENCOMPUTE_EXACT_EXECUTION` | `reference` runs exact programs instruction by instruction (the correctness oracle) instead of the optimized circuit. For diagnosis only: results are identical, it is slower |

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
- **Metrics.** `GET /metrics` (Prometheus text format) exports:
  - jobs by state;
  - job and evaluation durations;
  - queue depth;
  - failed plans;
  - key-release denials;
  - privacy denials;
  - trust failures;
  - SecAgg round durations.

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
implements the same interface.

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
