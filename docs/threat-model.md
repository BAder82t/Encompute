# Encompute threat model

This is the authoritative threat model for Encompute. Every artifact also
carries a short form of it in `security.json`.

- Cryptographic mechanisms and parameters: [cryptography.md](cryptography.md).
- Message formats: [security-review/protocols.md](../security-review/protocols.md).
- The evidence behind each claim: the invariant catalog
  ([`crates/encompute-assurance/src/catalog.rs`](../crates/encompute-assurance/src/catalog.rs)),
  summarized in [assurance.md](assurance.md). "INV-nnn" below refers to it.
- How findings are handled: [security-findings.md](security-findings.md).

A claim here means: the mechanism is implemented in the cited code, and the
cited tests or invariants check it for the tested cases. It does not mean
Encompute is proven secure. There is no formal proof of Encompute as a
whole.

## 1. How to read this page

Section 2 shows the components and which ones are trusted. Section 3 lists
the assets. Section 4 takes one adversary at a time. For each one it lists:

- the assets protected against it;
- the components that must be trusted;
- the assumptions;
- the attacks that are prevented or detected, each with the enforcing code
  and the evidence;
- the attacks that are out of scope.

Sections 5 to 7 give conditions the deployment must uphold, what the
evaluator always learns, and what no part of Encompute covers.

## 2. Security boundaries

```text
 CLIENT SIDE (trusted by its owner)          UNTRUSTED NETWORK             EVALUATOR SIDE (untrusted for data)
 ┌──────────────────────────────┐   plain HTTP; TLS is the            ┌──────────────────────────────────┐
 │ Client (CLI / Python SDK)    │   deployment's job                  │ encompute-evaluator [U]          │
 │  secret key (secret.key)     │ ───── ENCM envelopes ──────────────▶│  evaluation keys only            │
 │  encrypt / decrypt           │   ciphertexts, eval keys, grant     │  never a secret key              │
 │  verify receipt, then decrypt│ ◀──── ciphertexts + signed ─────────│  signs receipts (Ed25519)        │
 │  [T]                         │       receipt (+ proof, research)   │        │                         │
 └──────────────────────────────┘                                     │        ▼                         │
                │ OIDC login                                          │  OpenFHE v1.5.1 [T: library]     │
                ▼                                                     │  CKKS · BinFHE · BGV             │
 ┌────────────────────────────────────────────────────┐   job grant   └──────────────────────────────────┘
 │ CONTROL PLANE  encompute-control [P]               │ ─(Ed25519)──▶        ▲ consent-to-start
 │  API v1 · OIDC users · service identities          │ ◀────────────────────┘ receipt
 │  policy · planner · jobs/scheduler · audit chain   │
 │  privacy ledgers · trust reports (rebuilt from     │ ◀── signed privacy events ───┐
 │  signed evidence on every request)                 │                              │
 └──────┬──────────────────────────┬──────────────────┘                              │
        │ SQL (no TLS in driver)   │ signed anchor                                   │
        ▼                          ▼                                                 │
 ┌──────────────────┐   ┌────────────────────────────┐   ┌──────────────────────────┴─────┐
 │ PostgreSQL [P]   │   │ State anchor [T: storage]  │   │ SecAgg coordinator [P]         │
 │ identities,roles,│   │ directory or OpenBao KV;   │   │ sees masked vectors and the    │
 │ jobs, ledgers,   │   │ audit root + ledger        │   │ sum; adds DP noise (central)   │
 │ audit, metadata  │   │ checkpoints, signed        │   │ parties sign every message     │
 └──────────────────┘   └────────────────────────────┘   └────────────────────────────────┘
                                                                   ▲ masked vectors, encrypted shares
 ┌────────────────────────┐    ┌────────────────────────────────┐  │
 │ Artifact store [U]     │    │ Parties / data owners [T: own] │──┘
 │ .encompute artifacts,  │    │ SecAgg participants, training  │
 │ sealed models, data,   │    │ workers (attested TEE [P])     │
 │ adapters, checkpoints, │    └───────────────┬────────────────┘
 │ ledgers, trust bundles │                    │ attestation evidence + challenge
 └────────────────────────┘                    ▼
                               ┌────────────────────────────────┐   wrap / unwrap KEK   ┌──────────────────────────┐
                               │ Key broker (per owner) [T:own] │ ────────────────────▶ │ KMS: OpenBao / Vault      │
                               │ wrapped asset keys; releases   │   Transit (https)     │ Transit root key [T: own] │
                               │ HPKE-sealed grants to attested │                       │ never exported            │
                               │ sessions only                  │                       └──────────────────────────┘
                               └────────────────────────────────┘

 [T] trusted   [P] partially trusted   [U] untrusted   [T: own] trusted only by its owner
```

| Component | Trust | Why |
|---|---|---|
| Client (CLI, Python SDK) | Trusted by its owner | It holds the secret key, encrypts, decrypts and verifies. Everything protects the client's data from others, not from the client. |
| OpenFHE v1.5.1 | Trusted (library) | Correct implementation of CKKS, BinFHE and BGV, and the hardness of RLWE/LWE at the chosen parameters. Encompute does not re-verify OpenFHE. |
| Evaluator | Untrusted for confidentiality; trusted for correctness unless a proof is required; trusted for availability | It never receives a secret key. Without an execution proof, a wrong result it signs is attributable but not detected. |
| Control plane | Partially trusted | Trusted for coordination and authorization decisions (who may act, which job exists). Not trusted for confidentiality (it holds no key, plaintext or ciphertext) or for trust decisions (reports are rebuilt from signed evidence). See 4.2 and 4.6 for what a compromised control plane can still do. |
| PostgreSQL | Partially trusted | Holds identities, roles, jobs, ledgers and the audit chain. Trusted for availability and for authorization state; rollback of privacy and audit state is detected against the anchor. |
| State anchor | Trusted storage | Must be outside the database attacker's reach. It holds a signed, monotonic counter with the audit root and ledger checkpoints. |
| Key broker | Trusted by its owner | Each owner runs its own. It decides key release against the owner's attestation policy. |
| KMS (OpenBao / Vault Transit) | Trusted by its owner | Holds the organization's root key, which never leaves it. |
| SecAgg coordinator | Partially trusted | Untrusted for inputs: it sees only masked vectors. Trusted to add DP noise (central DP) as far as its attestation goes, and for availability. Not trusted for the aggregate's correctness, which is not verified. |
| TEE and attestation service (Google Confidential Space) | Trusted | Hardware isolation of the workload and Google's attestation verifier and launcher. |
| Attested workload (training worker, attested evaluator) | Partially trusted | Trusted only when its attestation verifies against the owner's policy (approved image, spec, policy, TEE, TCB, no debug). |
| OIDC identity provider | Trusted | It authenticates people. The control plane verifies its tokens. |
| Network, message transport | Untrusted | It may read, drop, delay, duplicate, reorder or replay. |
| Artifact storage | Untrusted | It may read, replace, delete or roll back what it stores. |

## 3. Assets

| Asset | Where it lives |
|---|---|
| Plaintext inputs, intermediates and outputs of FHE programs | client only |
| FHE secret keys | client only (`secret.key`) |
| Asset keys (models, datasets) | key broker (wrapped); attested workloads (in memory) |
| Key-encryption keys and the customer root key | key broker (wrapped); KMS |
| Private model weights, training data, per-unit gradients, raw LoRA updates | owner machines; attested workloads; sealed at rest |
| Individual SecAgg contributions | the contributing party |
| Privacy budgets and spending | ledgers (files and control-plane database), anchored |
| Integrity of results and evidence | receipts, proofs, trust bundles, audit chain |
| Tenant data and metadata on the control plane | PostgreSQL |
| Service identity keys (Ed25519) | each service |

## 4. Adversaries

### 4.1 Malicious evaluator

The evaluator runs encrypted computation on another machine. Here it
deviates arbitrarily: it inspects everything, returns wrong results, signs
lies, replays, or sends malformed data.

**Protected assets:** plaintext inputs, intermediates and outputs; the
client's secret key; with a required proof (research), the correctness of
the result.

**Trusted components:** the client; OpenFHE and the hardness of its
parameters; for verified execution, the client's own re-execution.

**Assumptions:**

- Decrypted results are never returned to the evaluator (section 5).
- Inputs are within their declared ranges; the client checks this before
  encrypting.
- The client pins the right evaluator key (`--trust-evaluator`, or the key
  pinned in the key directory on first use).

**Prevented or detected:**

| Attack | Enforced by | Evidence |
|---|---|---|
| Decrypt inputs, intermediates or outputs | The evaluator never receives a secret key: the client runs key generation (`crates/encompute-openfhe-client/cpp/client.cc`, `binclient.cc`) and sends only evaluation keys; the evaluator binary contains no Encompute client crypto (`scripts/audit-evaluator-binary.sh`) | INV-010, INV-011 |
| Learn a branch outcome | Both branches of a `select` are computed; there is no data-dependent control flow in plans (`crates/encompute-exact/src/lower.rs`, `circuit.rs`) | INV-002, INV-166 |
| Feed a ciphertext of another kind, scheme, parameter set, program or key | Envelope checks before any OpenFHE call (`crates/encompute-protocol/src/lib.rs` `Envelope::check`; `crates/encompute-openfhe-exact/src/lib.rs` `open`, `OpenFheGates::load`) | INV-006, INV-008, INV-152, INV-153 |
| Run a ciphertext under another client's evaluation keys | Sessions use only keys registered with them; a ciphertext runs only under the key its envelope names (`crates/encompute-evaluator/src/session.rs`, `keycache.rs`) | INV-171 |
| Replay or transfer a receipt to another request, output, program, policy or evaluator | The receipt signs commitments to the exact request and response bytes and the spec (`crates/encompute-verification/src/receipt.rs`, `verify.rs`); the client verifies before decrypting (`crates/encompute-runtime/src/client.rs`) | INV-020, INV-021 |
| Return a random, replayed, skipped, substituted or mutated result for a verified program | Re-execution proof on BGV: the client re-runs the computation and decrypts only on a byte-for-byte match (`crates/encompute-vfhe/src/lib.rs`, `crates/encompute-verification/src/proof.rs`) | INV-022 (research build) |
| Crash the client or evaluator with malformed input | Encompute's parsers are length-checked and never panic (`crates/encompute-protocol`, `crates/encompute-ir`) | INV-007 |
| Pick a cheaper backend that lacks a required proof | Verification requirements are checked before cost (`crates/encompute-planner/src/planner.rs`, `crates/encompute-evaluator/src/cost.rs`) | INV-169, INV-170 |

**Out of scope:**

- **A signed lie without a proof.** For CKKS and BinFHE programs, and for
  BGV programs without `verification="required"`, the evaluator can return
  a wrong result with a valid receipt. The receipt makes the claim
  attributable; it does not detect it.
- A malformed ciphertext crafted to exploit OpenFHE's deserializer in the
  client when it loads the response. Envelopes are checked first, but
  OpenFHE's parsers are not fuzzed (see [cryptography.md](cryptography.md),
  section 4.2).
- Denial of service, and learning what section 6 lists.

### 4.2 Malicious cloud provider or operator

The operator controls the hosts, hypervisors and networks where evaluators,
coordinators, training workers and the control plane run. It can read
memory of non-TEE processes, change images, relay or alter traffic, and
restart services.

**Protected assets:** asset keys; plaintext models, datasets and gradients
inside attested workloads; FHE plaintexts (as for 4.1); individual SecAgg
contributions.

**Trusted components:** the TEE hardware; Google Confidential Space's
attestation verifier and launcher; the reviewed workload image (its digest
is the measurement); each owner's key broker and KMS.

**Assumptions:**

- Production brokers run in production mode and refuse development
  evidence and development key stores.
- Each attestation policy names the approved images, TEE types, minimum
  TCB and the approved execution spec and policy.

**Prevented or detected:**

| Attack | Enforced by | Evidence |
|---|---|---|
| Run an unapproved image, or the approved image under another spec or policy, and get a key | Attestation policy check (`crates/encompute-attestation/src/policy.rs` `AttestationPolicy::check`), re-run at release (`crates/encompute-keybroker/src/lib.rs` `release_key`) | INV-040, INV-120, INV-145 |
| Run a debug-enabled or out-of-date workload | `dbgstat` and TCB checks (`crates/encompute-attestation/src/gcp.rs`) | INV-043, INV-144 |
| Present development (mock) evidence to a production broker | Production mode refuses non-production evidence, development policies and development stores (`crates/encompute-keybroker/src/lib.rs`) | INV-043, INV-143 |
| Replay stale evidence or reuse a challenge | Single-use challenges, 300 s challenge lifetime, freshness checks (`crates/encompute-keybroker/src/lib.rs` `verify_attestation`; `crates/encompute-attestation/src/provider.rs` `check_freshness`) | INV-040, INV-146 |
| Read a released key while relaying it | The key is HPKE-sealed to a session key generated inside the TEE (`crates/encompute-attestation/src/grant.rs`) | INV-041 |
| Substitute the evaluator key or session key in the evidence | Both are in the binding hash that is the token's nonce (`crates/encompute-attestation/src/binding.rs`) | INV-040 |
| Read an individual contribution while running the SecAgg coordinator | Masking (4.4) | INV-052 |
| Exfiltrate plaintext weights, records or gradients from the training workload | Sealed inputs and outputs, bound to spec and attestation (`crates/encompute-training/src/seal.rs`, `worker.rs`) | INV-147, INV-148 (tested deployment) |
| Read secret keys or plaintexts on an evaluator host | The evaluator holds no secret key (4.1) | INV-010, INV-011 |

**Out of scope:**

- Breaking the TEE hardware, side channels against a TEE, or a compromised
  attestation service.
- A workload image that is itself malicious but approved.
- Denial of service, including refusing to run or restarting services.
- **Grant authenticity.** The key broker does not sign grants, and HPKE
  base mode does not authenticate the sender. The workload knows a grant
  opens under its session key, not that its broker produced it. Run the
  broker behind TLS that the workload verifies.
- Local modes: `run --mode encrypted` without `--remote` runs client and
  evaluator in one process. Anyone who compromises that process sees both.

### 4.3 Malicious participant

A party in a collaboration: a SecAgg contributor, a data owner in a
training run, or a client of a shared evaluator. It deviates from the
protocol and may collude with other participants.

**Protected assets:** other parties' inputs and contributions; other
parties' privacy budgets; other clients' keys and results on a shared
evaluator.

**Trusted components:** the honest parties' own software; the aggregation
spec that fixes all party keys; for sampled DP-SGD rounds, the attested
worker.

**Assumptions:** colluding participants (with or without the coordinator)
stay within the declared `colluding` bound.

**Prevented or detected:**

| Attack | Enforced by | Evidence |
|---|---|---|
| Learn another party's input from the round | Pairwise and self masks; the threshold `t = max(minimum, ⌊(n + colluding)/2⌋ + 1)` (`crates/encompute-secagg/src/protocol.rs`, `round.rs`) | INV-052, INV-053 |
| Impersonate another party or alter its contribution | Every party message is signed and bound to the round and spec; contribution metadata is checked field by field (`crates/encompute-secagg/src/protocol.rs`, `round.rs`) | INV-050, INV-054 |
| Overflow the aggregate modulus to corrupt it | Quantization overflow is a compile error; clipping is reported (`crates/encompute-ir/src/confidentiality.rs` codec, `crates/encompute-analysis`) | INV-055 |
| Contribute outside the attested worker in a sampled DP-SGD round | Sampled rounds require attested contributors (`crates/encompute-secagg/src/round.rs`) | INV-130 |
| Spend more privacy than budgeted, or double-spend concurrently | Ledger reserve before release, locking, all-or-nothing (`crates/encompute-privacy/src/ledger.rs`, `release.rs`) | INV-063, INV-065, INV-069 |
| Use a program an asset owner did not approve | Owner-signed program authorizations in the trust graph (`crates/encompute-trust/src/authz.rs`, `report.rs`) | INV-102 |
| Declassify or misuse data against its policy | Compile-time policy checks (`crates/encompute-analysis/src/confidentiality.rs`) | INV-030, INV-031, INV-032, INV-033 |
| Run a ciphertext under another client's keys on a shared evaluator | Key-cache isolation (as in 4.1) | INV-171 |

**Out of scope:**

- Poisoning or biasing the aggregate: there is no input validation beyond
  clipping and range checks.
- Aborting a round by dropping out or sending bad shares (a round aborts;
  nothing is released).
- What the aggregate itself reveals without DP (for example, the sum and
  two known inputs give the third).
- Differencing across rounds when a party resubmits an unchanged vector to
  rounds with different participant sets.
- A client that encrypts out-of-range values: its own results are wrong;
  no other party's data is affected.

### 4.4 Malicious coordinator (secure aggregation)

The coordinator relays all round messages, chooses survivor sets, and
computes the aggregate. It may drop, forge, reorder or equivocate, and may
collude with participants up to the declared bound.

**Protected assets:** each honest party's contribution; each asset's
privacy budget (against over-spending and rollback).

**Trusted components:** the parties; the aggregation spec (the PKI); for
DP noise, the coordinator's attestation when the plan requires it.

**Assumptions:**

- At most `colluding` parties collude with the coordinator.
- Each party persists its round state (`--state`) so it never rejoins a
  failed round.

**Prevented or detected:**

| Attack | Enforced by | Evidence |
|---|---|---|
| Recover an honest party's input, alone or with up to `colluding` parties | Threshold rule, signed survivor-set consistency round, reveal only after t matching signatures, never both share kinds for one party (`crates/encompute-secagg/src/protocol.rs`) | INV-052, INV-053 |
| Equivocate on the survivor set (show different sets to different parties) | Parties require t signatures on the same set before revealing (`protocol.rs`, unmask round) | INV-052 (`equivocating_coordinator_learns_nothing`) |
| Rerun a round with other survivors to difference two aggregates | Parties refuse rounds not newer than the last they joined (`crates/encompute-secagg/src/round.rs`) | INV-054 |
| Release with too few contributors | Abort below the threshold and below `minimum` (`protocol.rs`, `round.rs`) | INV-051 |
| Release without noise, or with weaker noise, where DP is declared | The release path always samples noise; weaker mechanisms are not the approved spec (`crates/encompute-privacy/src/release.rs`) | INV-062 |
| Rewrite, truncate or roll back a ledger | Hash-chained ledgers; owners holding a later checkpoint detect rollback (`crates/encompute-privacy/src/ledger.rs`) | INV-066, INV-067 |
| Forge a privacy receipt or aggregation receipt | Ed25519 signatures over every field (`release.rs`, `round.rs`) | INV-068, INV-054 |
| Run unattested where the plan requires an attested coordinator | Parties check the coordinator's attestation at join (`round.rs`) | INV-043 (`attested_coordinator_round`), INV-112 |

**Out of scope:**

- **Correctness of the aggregate.** The coordinator can release a wrong
  aggregate or abort. The aggregation receipt shows who contributed under
  which spec, not that the sum is right.
- **Seeing the sum before noise.** DP is central: the coordinator sees the
  unmasked sum and is trusted to add noise, as far as its attestation
  (bound to the privacy policy) goes.
- Coordinator broadcasts (key lists, survivor lists, unmask requests) are
  not signed by the coordinator. Protection rests on the party-signed
  contents.
- Timing side channels of noise sampling.

### 4.5 Compromised user account

An attacker holds a valid OIDC session (token) of a user in one
organization, with that user's roles.

**Protected assets:** other organizations' projects, assets, policies,
jobs, ledgers, trust reports, key references and audit records; keys held
by key brokers; FHE plaintexts.

**Trusted components:** the OIDC provider; the control plane's
authorization code; the key brokers; the clients' own verification.

**Assumptions:** tokens are short-lived; the organization's admins can
disable the user.

**Prevented or detected:**

| Attack | Enforced by | Evidence |
|---|---|---|
| Read or use another organization's resources without a collaboration grant | Membership and role checks on every route, SQL filters on organization IDs (`crates/encompute-control/src/authz.rs`, `ops/*.rs`) | INV-156 |
| Use a forged, expired, wrong-audience or wrong-issuer token, or an HMAC token against an OIDC issuer | Signature against the issuer's JWKS, issuer, audience, expiry, asymmetric algorithms only (`crates/encompute-control/src/authn.rs`) | INV-156 (`credentials_are_checked`), INV-164 |
| Use a development token in production | Refused in configuration, at start and per token (`config.rs`, `authn.rs`) | INV-164 |
| Approve its own policy | Four eyes: the approver must differ from the proposer (`crates/encompute-control/src/ops/policies.rs`) | `every_route_authenticates_authorizes_and_isolates` |
| Obtain an asset key | Key release depends on attestation, not on the control plane (`crates/encompute-keybroker`) | INV-041 |
| Make a job's trust report say trusted | Reports are rebuilt from signed evidence (`crates/encompute-control/src/ops/jobs.rs`) | INV-165 |
| Keep using a revoked asset | Revocation fails queued jobs, refuses new submissions and destroys broker keys | INV-161 |

**Out of scope:**

- Anything the account's roles allow. For example a `data_owner` can
  approve its own assets for projects and spend their budget; an
  `ml_developer` can submit jobs; an `organization_admin` can add users
  and service accounts.
- A compromised identity provider.
- Token revocation before expiry. A disabled user is refused, but a valid
  token for an active user works until it expires. A signing key removed
  from the provider's JWKS stays trusted until the control plane restarts.

### 4.6 Database attacker

The attacker can read and write the control plane's PostgreSQL database,
and restore old backups. It does not hold the control plane's signing key
or the state anchor.

**Protected assets:** privacy spending; the audit trail; the integrity of
trust decisions. Confidentiality of keys and data holds because the
database holds none.

**Trusted components:** the state anchor (outside the database); the
control plane's signing key; the signed evidence (receipts, grants,
commitments, plans); the key brokers.

**Assumptions:** the anchor is stored where this attacker cannot write it
(for example OpenBao KV). A directory anchor on the same host or volume
as the database, or backed up with it, gives no protection against a
rollback.

**Prevented or detected:**

| Attack | Enforced by | Evidence |
|---|---|---|
| Read keys, plaintext data, weights or input values | The database holds identifiers, digests and wrapped-key references only; audit records carry no payloads (`crates/encompute-control/src/audit.rs`) | INV-162 |
| Edit records so a job looks trusted | Trust reports are rebuilt from signed evidence and trusted keys on every request (`ops/jobs.rs`) | INV-165 |
| Restore an older database to undo privacy spending or audit events | Startup compares the database with the signed anchor and refuses a rollback until an operator freezes the affected ledgers (`crates/encompute-control/src/control.rs`, `anchor.rs`) | INV-159, INV-160 |
| Edit, delete or reorder audit events up to the last anchored checkpoint | Hash chain, signed checkpoints, anchored root (`audit.rs`) | INV-162 |

**Out of scope:**

- Denial of service; hiding jobs from their owners.
- **Changing authorization state.** Roles, memberships, service accounts
  and approvals live in the database. A database attacker can grant
  itself any role and act as the control plane would. It still cannot
  decrypt, release a key or forge a receipt.
- Editing audit events after the last anchored checkpoint (one every 100
  events by default, `ENCOMPUTE_AUDIT_CHECKPOINT_EVERY`). The chain hash is
  unkeyed.
- Reading the database traffic: the control plane's PostgreSQL driver is
  configured without TLS (`crates/encompute-control/src/db.rs`). Run the
  database on a trusted network.

### 4.7 Message transport attacker

The attacker sits between services, or runs the message broker or a
proxy. It can read, drop, delay, duplicate, reorder and replay traffic.

**Protected assets:** integrity and authenticity of requests, messages,
grants and receipts; single application of security-sensitive effects;
FHE plaintexts; SecAgg shares.

**Trusted components:** the senders' and recipients' signing keys; the
pinned control-plane key on evaluators and brokers.

**Assumptions:** TLS runs in front of every service when confidentiality
of metadata, bearer tokens and ciphertexts in transit matters. The
services themselves speak plain HTTP (`tiny_http`), and so does the Compose
deployment.

**Prevented or detected:**

| Attack | Enforced by | Evidence |
|---|---|---|
| Forge or alter a service request | Ed25519 over method, path, sender, recipient, timestamp, nonce and body hash (`crates/encompute-verification/src/service.rs`) | INV-156 (`credentials_are_checked`) |
| Replay a service request to the control plane | ±300 s window and a nonce store in PostgreSQL (`crates/encompute-control/src/authn.rs`) | INV-156 |
| Duplicate, reorder or replay messages and job submissions | Signed messages with expiry; idempotent consumers; idempotency keys for jobs (`service.rs`, `ops/jobs.rs`, `ops/assets.rs`) | INV-158 |
| Forge a job grant, or reuse it for another evaluator or program | Signed by the pinned control-plane key; checks evaluator, program and expiry; the control plane starts a job only once (`service.rs` `JobGrant::verify`, `ops/jobs.rs`) | INV-163 |
| Alter ciphertexts or results in transit | Receipts bind the exact request and response bytes; the client verifies before decrypting | INV-020, INV-021 |
| Read or alter SecAgg shares | Shares are encrypted end to end between parties (ChaCha20-Poly1305) and every party message is signed (`crates/encompute-secagg`) | INV-050, INV-054 |
| Read a released key in transit | HPKE sealing to the attested session | INV-041 |

**Out of scope:**

- Confidentiality of anything sent over plain HTTP: bearer tokens,
  metadata, and ciphertexts (ciphertexts leak nothing about values, but
  their size and timing are visible).
- The key broker keeps its replay cache for control-plane messages in
  memory, so it is empty after a restart.
- The first contact with an evaluator when the client pins its key on first
  use: an attacker on that first connection can get its own key pinned.
  Pass `--trust-evaluator` to avoid this.
- Dropping or delaying traffic.

### 4.8 Artifact storage attacker

The attacker controls where artifacts and state files are stored:
compiled `.encompute` artifacts, sealed models, datasets, adapters and
checkpoints, ledgers, trust bundles, receipts and model packages.

**Protected assets:** keys (never in artifacts); confidentiality of sealed
assets; integrity of what is loaded; privacy state.

**Trusted components:** the loaders' checks; the IDs bound elsewhere
(signed approvals, receipts, attestation policies, anchors).

**Assumptions:** the program text (`program.eir`) and the compiler version
are the root of an artifact's identity. Owners approve program IDs, and
attestation policies name artifact or code digests.

**Prevented or detected:**

| Attack | Enforced by | Evidence |
|---|---|---|
| Find keys in an artifact | Artifacts never contain key material (`crates/encompute-runtime/src/artifact.rs`) | INV-005 |
| Tamper with a plan, parameters or policy inside an artifact | The loader recompiles `program.eir` and requires every file to match byte for byte (`artifact.rs`) | INV-005, INV-033 |
| Replace the program itself | The program ID changes: owner approvals, receipts and attestation policies no longer match | INV-102, INV-040 |
| Read or alter sealed models, datasets, adapters or checkpoints | ChaCha20-Poly1305 sealing bound to project, asset and digest (`crates/encompute-training/src/seal.rs`) | INV-147 |
| Roll a checkpoint back, or swap another run's checkpoint | Checkpoints bind project, run, spec, policies and ledger positions (`crates/encompute-training/src/checkpoint.rs`) | INV-123 |
| Edit, truncate or roll back a ledger file | Hash chain and checkpoints (`crates/encompute-privacy/src/ledger.rs`) | INV-066, INV-067 |
| Edit a trust bundle | The report rebuilds the graph from the signed evidence (`crates/encompute-trust/src/report.rs`) | INV-101 |
| Swap files in a model package, or smuggle pickled or remote code | Content-addressed packages; only safetensors, configuration and tokenizer files (`python/encompute/torch/hf.py`, `crates/encompute-training/src/hf.rs`) | INV-136, INV-137, INV-138 |

**Out of scope:**

- Deletion and availability.
- Confidentiality of artifacts: program structure, public weights, shapes
  and declared ranges are not encrypted.
- The artifact manifest is an unkeyed SHA-256 list, not a signature. Its
  protection comes from the recompilation check and from the IDs bound
  elsewhere.
- `secret.key` on the client is not encrypted at rest (see
  [cryptography.md](cryptography.md), section 3). Storage of the client's
  key directory is the client's responsibility.

## 5. Conditions the deployment must uphold

1. **Decrypted results are never returned to the evaluator.** CKKS is not
   IND-CPA-D secure (Li and Micciancio, 2021): an evaluator that sees
   decryptions of ciphertexts it computed can recover the secret key.
   Encompute adds no noise flooding. The same rule applies to exact
   programs, where decryption failures are negligible but not zero.
2. **Inputs lie within their declared ranges.** The client checks this
   before encrypting (ENC1102). Approximations are fitted to the range and
   overflow proofs assume it.
3. **TLS in front of every service.** Evaluators, the control plane, key
   brokers and SecAgg coordinators speak plain HTTP.
4. **The state anchor lives outside the database's failure domain** and
   outside its backups.
5. **Production mode everywhere.** Development tokens, mock attestation,
   development key stores and development root keys are refused only in
   production mode (INV-164).
6. **Pin evaluator and coordinator keys out of band** where possible
   (`--trust-evaluator`, `--coordinator-key`). In the SDK's control-plane
   flow, the client takes the evaluator's URL and receipt key from the
   control plane's job data (`python/encompute/client.py`), so for that
   flow the control plane chooses which evaluator key the client accepts.

## 6. What the evaluator always learns

- Program structure: operations and their order.
- Public constants: weights, polynomial coefficients.
- Input and output shapes, and declared input ranges.
- Timing and ciphertext sizes. They depend on the program and the declared
  ranges, not on input values.
- For exact programs, which scheme was chosen (BinFHE or BGV) and the
  circuit's size.

Values are never revealed, including the outcome of comparisons and
selections. Hiding the model itself (encrypted weights) is out of scope.

What the evaluator holds:

- CKKS programs: the relinearization key and the rotation keys for the
  plan's rotations.
- BinFHE programs: the bootstrapping (refresh) key and the key-switching
  key.
- BGV programs: the relinearization (evaluation multiplication) key.

## 7. Not covered anywhere

- A formal proof of Encompute, or of the composition of its mechanisms.
- Side channels on the client, the evaluator, the sampler or OpenFHE.
- Malicious-evaluator integrity outside the research re-execution proof.
- FHE key rotation and threshold decryption.
- Output integrity of secure aggregation.
- Noise added by a coordinator that is not attested (central DP).
- Poisoning of training or aggregation.
- Denial of service.
