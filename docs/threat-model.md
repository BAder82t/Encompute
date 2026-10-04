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
| Control plane | Partially trusted | Trusted for coordination and authorization decisions (who may act, which job exists). Not trusted for confidentiality (it holds no key, plaintext or ciphertext), for trust decisions (reports are rebuilt from signed evidence), or for which evaluator key a client accepts (clients pin receipt keys themselves, section 5). See 4.2 and 4.6 for what a compromised control plane can still do, and 4.9 for governed projects (not part of 0.3), where it can only deny. |
| PostgreSQL | Partially trusted | Holds identities, roles, jobs, ledgers and the audit chain. Trusted for availability and for authorization state; rollback of privacy and audit state is detected against the anchor. |
| State anchor | Trusted storage | Must be outside the database attacker's reach. It holds a signed, monotonic counter with the audit root and the governance event log's size and head, a constant size; the privacy ledgers' checkpoints are events of that log. |
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
- The client pins the right evaluator key. For a direct remote run:
  `--trust-evaluator`, or the key pinned in the key directory on first
  use. For a job a control plane schedules: the client's own pin set
  (section 5, condition 6).

**Prevented or detected:**

| Attack | Enforced by | Evidence |
|---|---|---|
| Decrypt inputs, intermediates or outputs | The evaluator never receives a secret key: the client runs key generation (`crates/encompute-openfhe-client/cpp/client.cc`, `binclient.cc`) and sends only evaluation keys; the evaluator binary contains no Encompute client crypto (`scripts/audit-evaluator-binary.sh`) | INV-010, INV-011 |
| Learn a branch outcome | Both branches of a `select` are computed; there is no data-dependent control flow in plans (`crates/encompute-exact/src/lower.rs`, `circuit.rs`) | INV-002, INV-166 |
| Feed a ciphertext of another kind, scheme, parameter set, program or key | Envelope checks before any OpenFHE call (`crates/encompute-protocol/src/lib.rs` `Envelope::check`; `crates/encompute-openfhe-exact/src/lib.rs` `open`, `OpenFheGates::load`) | INV-006, INV-008, INV-152, INV-153 |
| Run a ciphertext under another client's evaluation keys | Sessions use only keys registered with them; a ciphertext runs only under the key its envelope names (`crates/encompute-evaluator/src/session.rs`, `keycache.rs`); OpenFHE key tags are bound to the key material (4.3) | INV-171 |
| Return a wrong exact result that decrypts outside the output's proven range | The client compares every decrypted exact output with the interval range analysis proves for it, and refuses the result if it lies outside (`crates/encompute-runtime/src/client.rs`) | `exact_outputs_outside_their_proven_range_are_refused` |
| Replay or transfer a receipt to another request, output, program, policy or evaluator | The receipt signs commitments to the exact request and response bytes and the spec (`crates/encompute-verification/src/receipt.rs`, `verify.rs`); the client verifies before decrypting (`crates/encompute-runtime/src/client.rs`) | INV-020, INV-021 |
| Return a random, replayed, skipped, substituted or mutated result for a verified program | Re-execution proof on BGV: the client re-runs the computation and decrypts only on a byte-for-byte match (`crates/encompute-vfhe/src/lib.rs`, `crates/encompute-verification/src/proof.rs`) | INV-022 (research build) |
| Crash the client or evaluator with malformed input | Encompute's parsers are length-checked and never panic (`crates/encompute-protocol`, `crates/encompute-ir`) | INV-007 |
| Pick a cheaper backend that lacks a required proof | Verification requirements are checked before cost (`crates/encompute-planner/src/planner.rs`, `crates/encompute-evaluator/src/cost.rs`) | INV-169, INV-170 |

**Out of scope:**

- **A signed lie without a proof.** For CKKS and BinFHE programs, and for
  BGV programs without `verification="required"`, the evaluator can return
  a wrong result with a valid receipt. The receipt makes the claim
  attributable; it does not detect it. The client's range check catches
  only exact results outside their proven interval.
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
- The broker keys a workload trusts are fixed before attestation: in the
  training spec (`key_brokers`) or in the image (`/app/broker-keys`).

**Prevented or detected:**

| Attack | Enforced by | Evidence |
|---|---|---|
| Run an unapproved image, or the approved image under another spec or policy, and get a key | Attestation policy check (`crates/encompute-attestation/src/policy.rs` `AttestationPolicy::check`), re-run at release (`crates/encompute-keybroker/src/lib.rs` `release_key`) | INV-040, INV-120, INV-145 |
| Run a debug-enabled or out-of-date workload | `dbgstat` and TCB checks (`crates/encompute-attestation/src/gcp.rs`) | INV-043, INV-144 |
| Present development (mock) evidence to a production broker | Production mode refuses non-production evidence, development policies and development stores (`crates/encompute-keybroker/src/lib.rs`) | INV-043, INV-143 |
| Replay stale evidence or reuse a challenge | Single-use challenges, 300 s challenge lifetime, freshness checks (`crates/encompute-keybroker/src/lib.rs` `verify_attestation`; `crates/encompute-attestation/src/provider.rs` `check_freshness`) | INV-040, INV-146 |
| Read a released key while relaying it | The key is HPKE-sealed to a session key generated inside the TEE (`crates/encompute-attestation/src/grant.rs`) | INV-041 |
| Seal a key of the host's choosing to the workload (for example, substitute a training output key), by forging a grant or pointing the workload at another broker | The broker signs every grant (Ed25519 over the header, encapsulated key and ciphertext; the header names the signing key). The workload opens only grants whose signature verifies, and accepts only a signer bound into its attested identity: the training spec's `key_brokers` (broker ID to grant-signing key, part of the spec ID), or, for the FHE workload, `/app/broker-keys` in the measured image. The operator supplies only the broker's address. With any attester other than the development (mock) one, an unpinned broker is refused; all grants of one broker session must carry one signer. A spec naming several brokers binds each key to one of them (`asset_brokers`): a grant must name that broker and carry its pinned signer, so one owner's broker cannot grant a key for another owner's asset (`grant.rs`; `crates/encompute-keybroker/src/workload.rs` `acquire_keys`; `crates/encompute-training/src/spec.rs`; `deploy/confidential-space/run-workload.sh`) | INV-182; `a_hardware_workload_refuses_an_unpinned_broker`, `grants_from_two_signers_in_one_session_are_refused`, `only_broker_keys_from_the_attested_identity_are_trusted`, `a_spec_binds_its_key_brokers`, `a_grant_for_an_asset_from_another_owners_broker_is_refused` |
| Change a training job through its job descriptor (configuration, input adapter, plan, image) | The training configuration comes from the spec; values the descriptor repeats must equal it. The input adapter must be the spec's initial adapter (round 1) or the one the coordinator signed for the previous round. The plan must be the spec's and sample at its rate. The image digest in the worker's evidence comes from its own attestation. The descriptor sets only the round's seed, which the signed evidence records and which does not drive DP-SGD sampling, and the microbatch size, which does not change the result. The evidence commits to the input adapter, the configuration digest and the seed (`python/encompute/torch/cs_worker.py`, `worker.py`; `crates/encompute-training/src/worker.rs`) | `a_worker_trains_only_from_the_previous_recorded_adapter`, `worker_evidence_binds_its_spec_assets_and_attestation`, `test_the_descriptor_cannot_change_the_training`, `test_the_evidence_binds_what_the_worker_trained_from_and_with` |
| Name arbitrary code as the model factory, so the worker runs it after opening the data | The spec validator accepts only the factories the worker image ships (`encompute.torch.models:tiny_classifier`, or `encompute.torch.hf:from_config` with exactly the model package's own `config.json`), with schema-checked arguments, before any key is released. A worker whose own code digest differs from the spec's `code_digest` refuses before it attests (`crates/encompute-training/src/spec.rs` `Architecture`; `python/encompute/torch/worker.py` `check_code`) | `a_spec_names_only_an_allowlisted_factory`, `test_models_build_only_allowlisted_factories`, `test_the_worker_refuses_other_code_before_any_key` |
| Turn on test hooks (update canaries, failpoints) in a production worker | Test hooks are honoured only when the worker's own attestation is development (mock) evidence, whatever the environment says (`python/encompute/torch/worker.py` `development`) | `test_test_hooks_are_off_with_hardware_attestation` |
| Edit a key broker's state file to change what is released to whom (release policies, mode, organization, key versions, revocations) | The state is authenticated with an HMAC under a key derived from the KEK, and a production broker refuses a store that cannot authenticate it (4.8) | `an_edited_state_file_does_not_open`, `a_production_store_must_authenticate_state` |
| Learn an asset's release policy from a refused key request | A refusal tells the caller what its own evidence shows, never the expected spec, policies, artifact or minimum TCB; the full reason goes only to the broker's log (`crates/encompute-attestation/src/policy.rs` `public_denial`; `crates/encompute-keybroker/src/server.rs`) | `public_denials_withhold_expected_values`, `refusals_do_not_reveal_the_release_policy` |
| Substitute the evaluator key or session key in the evidence | Both are in the binding hash that is the token's nonce (`crates/encompute-attestation/src/binding.rs`) | INV-040 |
| Read an individual contribution while running the SecAgg coordinator | Masking (4.4) | INV-052 |
| Exfiltrate plaintext weights, records or gradients from the training workload | Sealed inputs and outputs, bound to spec and attestation (`crates/encompute-training/src/seal.rs`, `worker.rs`) | INV-147, INV-148 (tested deployment) |
| Read secret keys or plaintexts on an evaluator host | The evaluator holds no secret key (4.1) | INV-010, INV-011 |

**Out of scope:**

- Breaking the TEE hardware, side channels against a TEE, or a compromised
  attestation service.
- A workload image that is itself malicious but approved.
- Denial of service, including refusing to run or restarting services.
- Failing a training job: the operator can always withhold or alter its
  job descriptor so that the worker refuses.
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
| Replace another client's OpenFHE evaluation keys on a shared evaluator by uploading keys under its key tag, or block the victim's upload by uploading first (squatting the tag) | OpenFHE looks keys up by tag alone, in process-wide maps where the first keys under a tag stay. The shim checks an upload completely before inserting anything, requires the keys inside to carry the tag they are sent under, and inserts them under a tag of their own: the key tag and the SHA-256 of the key material. A ciphertext is mapped to that tag only inside the context that loaded those keys, and back to the client's tag when it leaves. So two uploads under one client-visible tag never meet: the attacker's keys sit beside the victim's, the victim's upload is accepted, and its result is computed under its own keys. Keys registered under key ID K are exactly the material whose SHA-256 is K (`crates/encompute-openfhe/cpp/shim.cc` `load_evaluation_keys`, `load_ciphertext`, `store_ciphertext`; `crates/encompute-evaluator/src/keycache.rs`). The namespace is by key material rather than by tenant because the evaluator's OpenFHE layer never learns the tenant, and a tenant-named tag would still let one tenant's own two key sets collide | INV-171; `another_clients_keys_under_the_victims_tag_are_never_used` |
| Crash a shared evaluator with crafted BinFHE bootstrapping keys | The refresh and switching keys are checked against the vetted context (GINX method, dimensions, moduli) before any gate runs (`crates/encompute-openfhe/cpp/binfhe.cc` `bin_load_keys`) | `foreign_bootstrapping_keys_are_refused_before_any_gate` |
| Load a program onto a shared evaluator without a grant for it | With a control plane, the upload's grant must name the program before anything is compiled or loaded; a refused upload changes nothing (`crates/encompute-evaluator/src/server.rs`) | INV-176; `a_refused_program_upload_loads_nothing` |
| Learn which programs other tenants run, or whether their keys are registered | With a control plane, `/v1/info` lists only the program a presented upload grant names, and the key lookup needs a grant for exactly those keys (`server.rs`) | INV-202; `with_a_control_plane_programs_and_keys_are_not_advertised` |
| Replay a copy of a client's upload grant (the job grant is visible to the whole submitting organization), or upload other keys with it, or race several uploads of one grant | An upload needs an upload grant that the control plane issues only to the principal that submitted the job. It names the evaluator, the kind, the program ID and the key ID (the key material's SHA-256, which holds the key tag), and carries a random ID and an expiry. The evaluator checks all of it before compiling or loading anything and spends the grant atomically: one upload per grant, a replay or a concurrent copy is ENC2608, a failed upload spends nothing. A job grant opens no upload (`crates/encompute-verification/src/service.rs` `UploadGrant`, `crates/encompute-evaluator/src/control.rs` `begin_upload`, `crates/encompute-control/src/ops/jobs.rs` `issue_upload_grant`) | INV-248; `an_upload_grant_admits_exactly_one_upload`, `concurrent_uploads_with_one_grant_succeed_once`, `an_upload_grant_binds_the_keys_it_names` |
| Reuse a spent upload grant after the evaluator restarts | Spent grants are kept in memory, one node. A restart forgets them, so the evaluator refuses every grant issued at or before its start, spent or not: a spent grant never becomes valid again while it is unexpired. The cost is that grants not yet used must be asked for again. Residual: this holds if the control plane's clock is not ahead of the evaluator's by more than the time between a grant's use and the restart | INV-248; `a_restarted_evaluator_accepts_no_earlier_grant` |
| Use assets approved for a project before the organization joined it | An asset approval covers the organizations that were active project members when the owner approved it; a later member needs a new approval (`crates/encompute-control/src/ops/assets.rs`; table `asset_approval_members`, migration 0003) | `a_late_joiner_inherits_no_asset_approval` |
| Add an organization to a project without its consent | The project owner's admins invite; the invited organization is a member only once its own admins accept. The answer to an invitation is the same whether or not the organization exists (`crates/encompute-control/src/ops/tenancy.rs`) | `membership_needs_the_invited_organizations_consent` |
| Read another agency's private metadata in a governed project (where its data is stored, which key protects it, who approved) | Every organization that does not own a record gets one shared view of it, the same bytes for each: sources without storage or key references, approvals as (organization, role, time) and a per-project pseudonym keyed by the control plane (a known principal ID cannot be confirmed), jobs and audit events with actors as `organization/kind`; a governed job's evaluator sees only its grant; another organization's IDs answer as unknown ones (`crates/encompute-control/src/views.rs`, `ops/governance.rs`, `ops/jobs.rs`) | INV-229; `governance_views_canary_scan`, `shared_view_identical_for_members`, `id_guessing_is_not_found` |
| Use an auditor role, or an auditor organization, to act in a governed project | Every mutating route refuses an auditor of an organization taking part, and anyone acting for an auditor organization; an auditor holds no other role there (ENC2716); an auditor organization owns, submits, receives, approves and holds keys nowhere in the project (`crates/encompute-control/src/authz.rs` `deny_auditor`) | INV-223; `every_mutating_route_refuses_an_auditor`, `auditor_org_cannot_submit_or_receive`, `combined_roles_refused_in_governed_projects` |

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
- A shared evaluator's memory: a tenant with valid upload grants can fill
  the key cache (bounded, least recently used evicted first) or the
  program table (no eviction until restart) with its own uploads. Upload
  grants limit each upload to one grant and one object; they are not a
  quota.

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
| Release a budgeted asset's aggregate exactly, with no ledger charge, by declaring the output sealed | A secure-aggregation aggregate is always a release: the protocol unmasks it to the coordinator, which writes it out. A plan with any privacy-budgeted contributor must add DP noise and charge the ledger, whatever the destination. Such a plan without `dp` does not compile, is not a valid aggregation spec, a budgeted party does not join its round, and the coordinator does not release it (`crates/encompute-analysis/src/confidentiality.rs`; `crates/encompute-secagg/src/round.rs`) | INV-062; `a_sealed_budgeted_aggregate_without_dp_is_not_a_valid_spec`, `a_budgeted_party_does_not_join_a_round_without_dp`, `a_sealed_budgeted_aggregate_without_dp_does_not_compile` |
| Release a budgeted asset without a control-plane reservation | With a control plane, every budgeted asset must map to its control-plane asset (`--control-asset`) and hold this round's local reservation before anything is sent or released. The control plane refuses a reservation whose declared sensitivity is below what its own noise and mechanism imply for the ledger's unit, and one whose mechanism is inconsistent with the ledger (a named level with other noise, a cost below the floor, Poisson sampling claimed for an organization-level ledger) (ENC2204), and charges the rest by its own accountant from the declared sensitivity and noise variance. The noise multiplier, clip norm and sampling rate of a release it did not plan stay the coordinator's declaration, vouched for by the coordinator's attestation; a governed job's reservation is derived from its program and compared (`crates/encompute-cli/src/aggregate.rs`; `crates/encompute-control/src/ops/assets.rs` `check_reservation`) | INV-186, INV-198; `unmapped_budgeted_assets_release_nothing`, `a_control_plane_coordinator_needs_every_budgeted_mapping_before_the_round`, `a_reservation_cannot_under_declare_its_sensitivity`, `an_organization_level_reservation_cannot_claim_sampling`, `golden_vectors_of_derived_reservations`, `tampered_declarations_are_refused` |
| Make a party rejoin a round by racing or crashing its state updates | The party's `--state` is updated under an exclusive lock, re-read, only ever raised, and replaced atomically (temporary file, fsync, rename). The last round joined is kept per aggregation spec (`crates/encompute-cli/src/aggregate.rs`) | `concurrent_state_updates_are_never_lost`, `state_is_monotonic_and_per_spec` |
| Rewrite, truncate or roll back a ledger | Hash-chained ledgers; owners holding a later checkpoint detect rollback (`crates/encompute-privacy/src/ledger.rs`) | INV-066, INV-067 |
| Spend a series' budget again through a new version, or a project or purpose it was not allocated to (governed projects) | A governed release is charged to a scope and its population: the population is one ledger per series, all versions, with a hard cap no scope raises; a scope serves one project, purpose and program and is allocated with four eyes; the release must fit in both, the population refusing first when scopes add up to more. A project with no scope cannot spend; a release never creates one (`crates/encompute-privacy/src/scoped.rs`, `crates/encompute-control/src/ops/privacy_scopes.rs`) | INV-230 |
| Under-declare how many sources one privacy unit spans, or the layout of the strata, to be charged less or to sum mismatched values | The sensitivity is multiplied by `max_sources_per_unit` (every participant when undeclared and scoped); it and the layout digest are in the plan every party approves, in each contribution's signed metadata and in the privacy receipts; the control plane refuses a reservation that is not the job's own release (`round.rs`, `ops/privacy_scopes.rs`) | INV-241 |
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
- **Exact control-plane charges for ungoverned releases.** The control
  plane does not hold the release's codec, so it bounds a reservation's
  charge instead of recomputing it. The reservation's `noise_multiplier`
  and `sampling_rate` are the coordinator's own declaration. (A governed
  job's release is computed by the control plane from its program.)
- **A coordinator that releases something larger and never reports it** is not caught by the control plane (it fails a job whose reserved release has no reported commit, but cannot see a release).
- **A coordinator that releases without reporting.** The scopes bound what
  the platform records and authorizes; a coordinator that never reports a
  release is stopped only by the parties' own checks (its attestation, the
  privacy receipts, the ledgers parties compare).

### 4.5 Compromised user account

An attacker holds a valid OIDC session (token) of a user in one
organization, with that user's roles.

**Protected assets:** other organizations' projects, assets, policies,
jobs, ledgers, trust reports, key references and audit records; keys held
by key brokers; FHE plaintexts.

**Trusted components:** the OIDC provider; the control plane's
authorization code; the key brokers; the clients' own verification.

**Assumptions:** tokens are short-lived; the organization's admins
disable the user (`POST /v1/organizations/{id}/users/{user}/disable`).

**Prevented or detected:**

| Attack | Enforced by | Evidence |
|---|---|---|
| Read or use another organization's resources without a collaboration grant | Membership and role checks on every route, SQL filters on organization IDs (`crates/encompute-control/src/authz.rs`, `ops/*.rs`) | INV-156 |
| Use a forged, expired, not-yet-valid, over-long, wrong-audience or wrong-issuer token, or an HMAC token against an OIDC issuer | Signature against the issuer's JWKS, issuer, audience, expiry, `nbf`, asymmetric algorithms only; `iat` is required and not in the future, and `exp - iat` is at most `ENCOMPUTE_MAX_TOKEN_LIFETIME_SECS` (default 86400) (`crates/encompute-control/src/authn.rs`) | INV-156 (`credentials_are_checked`), INV-164; `identity_tokens_have_bounded_lifetimes` |
| Use a development token in production | Refused in configuration, at start and per token (`config.rs`, `authn.rs`). `ENCOMPUTE_ENV` must be `production` or `development`; unset or any other value refuses to start | INV-164; `unset_or_misspelt_environment_refuses_to_start` |
| Approve its own policy, or meet four eyes alone with a second key | Four eyes: the approver is a different person holding `security_admin` in the project owner's organization; the author must be a person too. Service accounts cannot hold `security_admin`, propose or approve (`crates/encompute-control/src/ops/policies.rs`, `ops/tenancy.rs`) | `every_route_authenticates_authorizes_and_isolates`, `policy_four_eyes_are_two_people_of_the_projects_owner` |
| Keep a grant after it is withdrawn | Every grant has an audited API revocation, effective from the next request: disable a user (`POST /v1/organizations/{id}/users/{user}/disable`), remove a role (`POST /v1/organizations/{id}/memberships/remove`), remove a project member (`POST /v1/projects/{id}/members/remove`), withdraw an asset approval (`POST /v1/assets/{id}/approvals/withdraw`). Jobs not yet started that lose the grant fail (`crates/encompute-control/src/api.rs`, `ops/tenancy.rs`, `ops/assets.rs`) | `every_grant_can_be_withdrawn_through_the_api` |
| Register a key broker under another organization's broker ID, to receive its assets' revocations | An asset's key messages go to, and are accepted from, only a key broker owned by the platform or by the asset's organization (`ops/tenancy.rs`, `ops/assets.rs`, `ops/jobs.rs`) | `a_tenant_cannot_squat_another_organizations_key_broker` |
| Obtain an asset key | Key release depends on attestation, not on the control plane (`crates/encompute-keybroker`) | INV-041 |
| Make a job's trust report say trusted | Reports are rebuilt from signed evidence (`crates/encompute-control/src/ops/jobs.rs`) | INV-165 |
| Keep using a revoked asset | Revocation fails queued jobs, refuses new submissions and destroys broker keys | INV-161 |

**Out of scope:**

- Anything the account's roles allow. For example a `data_owner` can
  approve its own assets for projects and spend their budget; an
  `ml_developer` can submit jobs; an `organization_admin` can add users
  and service accounts.
- A compromised identity provider.
- **Issuers are not bound to organizations.** An organization admin can
  register an identity (issuer and subject) that another organization
  intends to onboard, and `create_user` answers a taken identity with a
  conflict, which tells the caller it exists.
- Token revocation before expiry. A disabled user is refused, but a valid
  token for an active user works until it expires. A signing key removed
  from the provider's JWKS stays trusted until the control plane refetches
  the key set, which it does only when a token names an unknown key (at
  most once a minute), or restarts.

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
| Restore an older database to undo privacy spending or audit events | Startup compares the database with the signed anchor and, through the governance log it anchors, each ledger with its latest checkpoint event, and refuses a rollback until an operator freezes the affected ledgers (`crates/encompute-control/src/control.rs`, `anchor.rs`) | INV-159, INV-160 |
| Roll a ledger or the audit chain back while the service runs, so that the fork is later anchored | A ledger checkpoint is appended to the governance log (and so anchored) only if the ledger extends its latest one, and the anchor only records an audit root or log head that extends the anchored one. A spend on a ledger that no longer extends its latest checkpoint is refused at once (ENC2202, PRIVACY STATE ROLLBACK), and an audit checkpoint over a chain that does not extend the anchored root is refused (AUDIT STATE ROLLBACK); both raise `encompute_state_rollback_total` (`ops/assets.rs` `privacy_spend`, `control.rs` `checkpoint_audit`, `anchor.rs`) | INV-160, INV-162, INV-226; `online_ledger_rollback_is_refused_and_never_anchored`, `ledger_restore_detected_through_the_log`, `online_audit_rollback_is_never_reanchored` |
| Unfreeze a frozen ledger, by a database update or by restoring a backup and running recovery again | Frozen ledgers are events of the governance log, whose head the anchor holds, and the freeze is anchored before recovery returns. A spend on one is refused (ENC2201) whatever the database says; startup refuses a database in which it is unfrozen (FREEZE STATE ROLLBACK); recovery freezes it again (`ops/assets.rs`, `control.rs`) | `a_frozen_ledger_stays_frozen_whatever_the_database_says`, `ledger_freeze_is_anchored_before_the_call_returns` |
| Restore a database to undo a revocation, a disabled service account or user, a cancelled or failed job, a withdrawn asset approval, an organization leaving a project, a removed role, a revoked owner authorization, a retired purpose, a revoked governance key or an expired asset | Each is an event of the governance log, written in the same transaction, and the log's head is anchored before the transition is acknowledged. Startup recomputes the log and refuses one that does not hold the anchored head at the anchored size (GOVERNANCE LOG STATE ROLLBACK), and a database that shows a logged transition undone (REVOCATION, SERVICE ACCOUNT, USER, JOB, APPROVAL, MEMBERSHIP, ROLE, AUTHORIZATION, EXPIRY, PURPOSE or GOVERNANCE KEY STATE ROLLBACK); recovery re-applies them once the log holds the anchored head (`govlog.rs`, `control.rs`). A role granted again after its removal is a new membership, never the anchored one | INV-178, INV-226; `restore_and_recovery_keep_disables_and_cancellations`, `restore_and_recovery_keep_withdrawn_approvals`, `restore_and_recovery_keep_a_left_project_left`, `restore_and_recovery_keep_a_removed_role_removed`, `restores_resurrecting_governed_state_are_refused_and_recovered` |
| Restore or edit a database to drop a project's placement tightening, or to show an evaluator's location evidence the log records lost | A tightening is an event naming its version and digest and is checkpointed before its call returns; startup refuses a database that lacks a logged version, holds it with another digest or constraints that no longer hash to it (PLACEMENT STATE ROLLBACK), and one that shows operator-declared evidence after the log's latest word was its loss, or another declaration than the latest, or one with no declaration on record (LOCATION EVIDENCE STATE ROLLBACK). Recovery cannot restore a lost version's content: it records the loss in the project's log, so every member sees it, and takes brought-back evidence to self-declared (`ops/placement.rs` `placement_losses`, `control.rs`) | INV-226; `a_restore_that_undoes_a_tightening_or_location_evidence_is_refused_and_recovered` |
| Drop, truncate, reorder or fork the governance log (with the triggers disabled), recomputing every hash | The anchor holds the log's size and chain head; every start recomputes the chain and each partition's latest signed checkpoint, so any change to the anchored prefix, however consistent, is refused (GOVERNANCE LOG STATE ROLLBACK); a checkpoint over a log that does not extend the anchored head is refused while running too (`govlog.rs` `checkpoint_extending`, `control.rs` `checkpoint_log`) | INV-226; `dropping_one_event_is_refused`, `truncating_a_project_or_the_tail_is_refused`, `swapping_gseq_is_refused`, `a_forked_chain_with_recomputed_hashes_is_refused` |
| Truncate, reorder, fork or edit the governance log mirror in the anchor store, or make recovery replay a mirrored suffix the anchor never committed | The mirror is used only up to the signed anchor's size and only when every event recomputes and chains to the anchored head; every start checks it and refuses a mirror that does not; a suffix past the anchor is an orphan, never recovered from, and replaced by the database's own events at the next checkpoint (`mirror.rs`) | INV-226; `truncated_mirror_is_refused`, `tampered_mirror_segment_is_refused`, `mirror_written_before_anchor_cas`, `old_backup_restore_recovers_from_mirror` |
| Compact the mirror to hide or lose history: prune early segments without the archive, truncate or gap a compacted mirror, replay an old sealed segment after the tail, put the pre-compaction anchor back, or tamper with, drop, swap or substitute archived segments or their manifest | A compaction seals a prefix in the signed anchor (size, chain head, manifest digest; version 3) before it prunes anything; the database's log is never compacted, so rollback and truncation detection do not change; a compacted mirror is read from the sealed head and a truncated, gapped, edited or replayed tail is refused; recovery that needs the archive checks its manifest against the seal, every segment against its SHA-256 and the whole chain to the anchored head (`compact.rs`, `archive.rs`, `mirror.rs`) | INV-251; `a_truncated_or_replayed_tail_is_refused`, `a_tampered_archive_is_refused`, `old_and_new_backups_after_a_compaction`, `a_crash_before_the_commit_point_changes_nothing`, `a_crash_after_the_commit_point_is_finished_by_the_next_run` |
| Put an older (version-1) anchor back after the upgrade, or migrate a database that already undid something | A version-1 anchor migrates only if the database passes every check its release made; once the log moved on after the migration, or was migrated from another anchor, a stored version-1 anchor is refused (`anchor_migration.rs`) | INV-226; `a_version_1_anchor_failing_its_checks_is_never_migrated`, `a_crash_between_genesis_and_the_anchor_resumes` |
| Make a key broker destroy a key for a revocation that a restore then forgets | A key broker receives a revocation or an expiry only once the transition's governance log event lies within the anchored log size (`ops/jobs.rs` `deliver_outbox`) | INV-193; `broker_revocation_is_delivered_only_once_anchored`, `authorization_revoked_reaches_the_broker_only_after_the_checkpoint` |
| Edit, delete or reorder audit events up to the last anchored checkpoint | Hash chain, signed checkpoints, anchored root (`audit.rs`) | INV-162 |

**Out of scope:**

- Denial of service; hiding jobs from their owners.
- **Authorization changes by a database writer.** Roles, memberships,
  service accounts and approvals live in the database, and only their
  security-negative transitions (revocations, disables, frozen ledgers,
  cancelled and failed jobs, withdrawn approvals, removed project
  memberships, removed roles, revoked owner authorizations, retired
  purposes, revoked governance keys, expired assets) are anchored, as
  events of the governance log whose head the anchor holds. A database
  attacker can grant
  itself any role and act as the control plane would. It still cannot
  decrypt, release a key or forge a receipt.
- **More than one control-plane process per anchor.** Updates are
  compare-and-set, and a process that loses the race reloads and
  re-applies, but only one replica per anchor is supported. The anchor is
  rewritten whole on each update, and is constant in size: security-negative
  transitions and the privacy ledgers' checkpoints are governance log
  events, not anchor fields. What grows is the log and its mirror.
- **Losing the anchor store's mirror together with the database.** A
  restored database whose governance log is behind the anchor is repaired
  from the log's mirror in the anchor store, which every checkpoint
  writes before the anchor. If the mirror was rolled back or truncated
  too, recovery refuses until the missing events are put back (a newer
  backup of the log's tables, or an export checked against the anchored
  head): the forgotten transitions are never silently dropped.
- **Losing the archive of a compacted mirror.** After a compaction the
  anchor store holds only the log's tail; the sealed prefix is in the
  archive the operator keeps. If the archive is lost, a database restored
  from a backup that ends inside the sealed prefix cannot be brought back
  from the mirror (an export from a newer database still can); the
  restore is refused as behind the anchor meanwhile, so nothing is
  accepted that should not be. Rollback and truncation detection never read
  the archive. The database's own log is not compacted.
- Editing audit events after the last anchored checkpoint. A checkpoint of
  the governance log anchors the audit head with it: before the call
  returns for a security deny event, and every two seconds in the
  background (an audit checkpoint every 100 events,
  `ENCOMPUTE_AUDIT_CHECKPOINT_EVERY`, also anchors it). Events of the
  window between are covered only by the unkeyed chain hash, and there is
  no mirror of the audit chain: the anchor detects a truncation, it does
  not restore.
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
| Repeat a query parameter so that the signed request and the request the recipient acts on differ | The signature covers the sorted query, so every verifier refuses a request target that names a parameter twice, even when it was signed (`service.rs` `repeats_a_query_parameter`) | `signed_requests_bind_everything`, `duplicate_query_parameters_are_refused` |
| Replay a service request to the control plane | ±300 s window and a nonce store in PostgreSQL. A nonce is kept until the request could no longer be accepted, plus a margin (`max(now, timestamp) + 300 s + 60 s`), by the control plane's own clock (`crates/encompute-control/src/authn.rs`) | INV-156; `nonces_outlive_their_acceptance_window` |
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
  use (a direct remote run): an attacker on that first connection can get
  its own key pinned. Pass `--trust-evaluator` to avoid this. Jobs a
  control plane schedules never pin on first use (section 5).
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
| Edit a key broker's state file (`broker.json`): release policies, mode, organization, key versions, revocations | Every field is covered by an HMAC-SHA256 under a key derived from the KEK by HKDF-SHA256 (domain `encompute.broker-state.v1`; formula in [protocols.md](../security-review/protocols.md), section 6); each save raises `generation`. An edited file does not open. A state without a MAC (written by 0.3.0-rc.3 or earlier) opens only through the owner's explicit `encompute keys upgrade-state --confirm`; a production broker refuses a store that cannot authenticate state (`crates/encompute-keybroker/src/lib.rs`, `store.rs`, `root.rs`) | `an_edited_state_file_does_not_open`, `an_unauthenticated_state_needs_its_owner_to_upgrade_it`, `a_production_store_must_authenticate_state`, `owner_changes_are_reauthenticated_and_generations_advance` |
| Restore an older authentic copy of a key broker's state file, to bring back an unrevoked authorization, a counter below its limit or an unused ticket; or run two copies of it | With a generation mark (required for a governed production broker): every save writes the file, then advances a mark in the organization's KMS (OpenBao or Vault KV-v2, compare-and-set) holding the generation and the state MAC, and only then grants or acknowledges. Opening refuses a state older than the mark, at its generation with another MAC, or one save ahead without naming the mark's MAC as its previous state (a hash chain) (ENC2713); a second writer loses the compare-and-set and grants nothing; an unreachable mark grants nothing (503). A state saved under a mark opens only with it. The first start under a mark trusts the state file, unless the operator pins the expected generation and MAC (`crates/encompute-keybroker/src/generation.rs`, `lib.rs`, `server.rs`) | `broker_state_rollback_refused_by_kms_generation`, `forked_state_same_generation_refused`, `crash_between_save_and_mark_recovers`, `divergent_file_at_mark_plus_one_refused`, `first_generation_mark_checks_the_expected_state`, `cas_conflict_denies_release`, `mark_unreachable_fails_closed`, `governed_production_broker_requires_a_mark`, `openbao_kv_generation_mark_refuses_rollback` |

**Out of scope:**

- Deletion and availability.
- **Rolling back the state of a key broker without a generation mark.**
  A writer without the KEK can only stop the broker, or replace its state
  with an older copy the broker itself wrote. Without a mark, that copy
  still holds keys revoked since, so it undoes those revocations. A
  governed production broker needs a mark in the organization's KMS, which
  refuses such a copy; a standard broker may run without one, and then
  rollback is handled by procedure. Whoever can rewrite both the state file
  and the KMS mark (or holds the KEK) is out of scope. Revocation does not
  rotate the KEK, so old state files and the unchanged KEK still yield
  revoked keys (no crypto-shredding). Keep broker backups
  access-controlled.
- Confidentiality of artifacts: program structure, public weights, shapes
  and declared ranges are not encrypted.
- The artifact manifest is an unkeyed SHA-256 list, not a signature. Its
  protection comes from the recompilation check and from the IDs bound
  elsewhere.
- `secret.key` on the client is not encrypted at rest (see
  [cryptography.md](cryptography.md), section 3). Storage of the client's
  key directory is the client's responsibility.

### 4.9 Compromised control plane (governed projects)

This section describes the public-sector governance work, which is not
part of Encompute 0.3.

The attacker controls the control plane of a governed project: its
process, its database, and its signing key. It can issue any job grant or
release ticket, send any control message, and answer any API call as it
likes. It does not hold an organization's governance key, a key broker's
KEK, or the organization's KMS.

**Protected assets:** the keys each organization's broker holds; each
owner's authorizations and revocations; the broker's release counters and
seen tickets.

**Trusted components:** each organization's own key broker and KMS; its
governance key; the attested workload.

**Assumptions:** each broker pins its owner's governance key and the
control plane's ticket key itself. Governed projects are always in
sovereign custody, so every source's key is at a broker its own
organization registered, never at a platform broker.

**Prevented or detected:**

| Attack | Enforced by | Evidence |
|---|---|---|
| Release a key by forging, replaying or reusing a release ticket | A ticket releases nothing without an owner-signed authorization installed at the broker; its signature is checked before any field is used, and it is single-use, job-bound and short-lived (`crates/encompute-keybroker/src/governed.rs`, `crates/encompute-verification/src/ticket.rs`) | INV-232, INV-236; `ticket_without_local_authorization_refused`, `forged_ticket_refused`, `replayed_ticket_refused` |
| Install an authorization the owner did not sign, or undo an owner's revocation | Authorizations and revocations verify under the owner's pinned governance key; a revoked authorization is never installed again; the control plane's own messages can only revoke or expire (`governed.rs`) | INV-236; `authorization_from_unpinned_governance_key_refused`, `install_of_revoked_authorization_refused`, `control_plane_messages_only_deny` |
| Keep a key flowing by suppressing a revocation | The owner revokes at its own broker, which takes effect at once without the control plane (`server.rs` `/v1/authorizations/revoke`, `encompute keys authorization revoke`) | INV-236; `ticket_refused_after_owner_revokes_locally_even_if_control_offline` |
| Point a source at a broker the owner does not run, such as a platform broker | Sovereign custody is fixed for governed projects; registration, ticket issue and planning require the owner's own registered broker; the workload accepts a key's grant only from the broker bound to it (`ops/custody.rs`, `crates/encompute-training/src/spec.rs`, `workload.rs`) | INV-235; `sovereign_project_refuses_platform_broker`, `a_grant_for_an_asset_from_another_owners_broker_is_refused` |
| Stretch an authorization past its limits or window | Counters and the strict window are the broker's own, on its own clock, persisted before the grant (`governed.rs`) | INV-232; `max_releases_exhausted_refused`, `expiry_at_valid_until_boundary_refused` |
| Redirect or replay an export of a derived result | An export ticket names one recipient and is single-use; the custodian's broker runs the same ticket checks as for a key release and seals the key only to the export key that the custodian's release record, verified under its pinned governance key, gives a recipient it names (`governed.rs` `prepare_governed_export`); the control plane records one export row per ticket (`ops/derived.rs`, migration 0011) | INV-221, INV-232; `broker_export_only_for_named_recipient`, `replayed_export_ticket_refused_2712` |
| A custodian pins a fake governance key for a lineage owner, or binds a release record that leaves a lineage owner out, to self-authorize that owner's consent | The custodian's broker pins a lineage owner's key only from the control plane's attestation of it, signed under the pinned control-plane key, for that organization and with the key's own ID (a later one replaces it, a revoked one unpins it), and binds a derived key only to a record the control plane co-signed after checking it against the result's ancestry (`governed.rs` `pin_lineage_governance_key`, `bind_derived_version`; `ops/derived.rs`, `ops/governance.rs`). Residual: the custodian holds the key material, so this defends against a careless custodian and a compromised control plane, not a malicious custodian; both compromised together could fake a lineage owner's consent | INV-236, INV-245; `forged_attestation_refused`, `attestation_for_other_org_refused`, `bind_with_record_omitting_owner_refused`, `revoked_lineage_key_unpins` |
| An original owner's revocation never reaches the custodian's broker, which keeps releasing a derived result | Once anchored, `authorization.revoked` goes to every custodian broker holding a result derived from a job under the authorization, every hop down, through the anchor-gated outbox (`ops/custody.rs` `queue_authorization_revoked`) | INV-236; `lineage_revocation_forwarded_to_custodian_brokers` |
| A lineage owner's key rotation is used to strand a derived result, or a forged or replayed re-binding to swap a lineage owner or its key | Only the custodian's security admin has the control plane re-issue the co-signature, with each lineage owner's active key; the custodian's broker re-binds only a re-issue signed by its pinned control-plane key, for the binding in force (same custodian, broker, key, derived version, asset, record and lineage owners), each key the one it pinned from the control plane's attestation, and newer than the co-signature it holds (`ops/derived.rs` `reissue_release_cosignature`, `governed.rs` `rebind_derived_lineage`) | INV-245; `rotation_strands_until_rebound`, `rebind_with_unattested_key_refused`, `rebind_cannot_change_record_or_owners`, `rotation_rebind_reissues_cosignature` |
| A custodian's broker keeps relying on a lineage owner's key the control plane has since revoked, because no revoked attestation reaches it | A pinned lineage key is used only while its attestation is younger than the broker's maximum age (24 hours by default, never unset, at most 7 days); older, nothing derived from that owner's data is released or exported until re-attested (`governed.rs` `lineage_authorization`). Residual: up to the maximum age | INV-236; `stale_lineage_attestation_needs_reattest` |
| Point a broker at another control plane (a different `--control-key` or `ENCOMPUTE_CONTROL_PUBLIC_KEY`) so that its tickets, attestations, co-signatures or revocation messages are accepted | The first control-plane key configured is pinned in the broker's authenticated state; any other is refused, and only `--replace-control-key` with another key, recorded in the broker's state and printed as an audit line, replaces it (`governed.rs` `pin_control_key`, CLI `keys serve`) | INV-236; `control_key_pinned_in_broker_state`, `governed_broker_commands` |
| Keep using a dataset version after its deletion date, or a result derived from it, for instance from a restored database that undid the expiry | Submission, scheduling, start, tickets, derivation and export compare the deletion date and walk the ancestors, whose expiry the anchored governance log records; the background task expires the version, marks results downstream `source_expired_at`, fails jobs not yet started and anchors the expiry before telling the broker; a restored database that undid an expiry does not start (`ops/retention.rs`, `ops/derived.rs` `check_lineage`) | INV-246; `version_past_delete_after_is_not_used_2705`, `expiry_cascades_to_derived_assets`, `restore_undoing_expiry_refuses_start`, `background_expiry_sends_asset_expired_after_anchor` |
| Push a deletion date back, keep data past it, or shorten evidence retention to hide what happened | The owner's route and the database only bring `delete_after` forward (never before `retention_until`, which is fixed) and only extend `evidence_retention_until`; every change is audited (migration 0012) | INV-246; `delete_after_can_only_be_shortened`, `evidence_retention_cannot_be_shortened` |
| Use, derive from or export a result after its source was revoked, for instance from a restored database that lost the mark | Every governed use, derivation, ticket and export walks the result's ancestors, whose revocation the anchored governance log records; after an authorization ends nothing released under it is exported (`ops/derived.rs` `check_lineage`, `export_asset`) | INV-245; `export_of_derived_asset_whose_source_was_revoked_2706`, `export_after_valid_until_refused_2705` |
| Show different members different histories of a project (a split view), or roll the log back after a member saw it | Each member organization countersigns the control plane's signed checkpoint of the project (RFC 6962 root) with its governance key, but only after checking, with the control plane's signed consistency proof, that it extends the one it witnessed before; a fork at one size, a larger tree that does not extend the earlier one and a smaller one are refused and written as evidence anyone holding the control plane's public key verifies. A checkpoint every member signed is `witnessed`, any other `unwitnessed` (a label, never a gate). The members at a size come from the log. Detection is by the members and only when they compare what they hold (there is no gossip: members exchange checkpoint files and run `check-equivocation`); a control plane that shows every member one history, or one that no member witnesses, is not caught, and one that freezes or withholds checkpoints cannot be told from a network failure. A rollback (a smaller checkpoint signed after a larger one) is provable from the member's own checkpoint. The `witnessed` label an answer carries is the control plane's own computation until a reader runs `encompute governance verify-audit` with the organizations' pinned keys, which recomputes it from verified proofs | INV-247; `an_equivocating_control_plane_is_detected_by_the_cli`, `every_member_witnesses_one_checkpoint`, `witness_refuses_what_does_not_extend_and_writes_the_evidence` |
| Export an evidence bundle that leaves out a revocation, or has a stale view of what an owner revoked | Each owner signs a revocation head: the root over every revocation it made in the project, which the control plane states from its log and accepts only as its own fold, under the organization's active governance key, numbered one past the previous head (ENC2717). The owner's tool recomputes the root from the leaves before signing. A bundle is checked through the project's proven log: the latest recorded head must be supplied and be dated at or after the time of the decision (covered means as of the head), a bundle that omits a revocation the head covers fails, a head recorded after its key's revocation is refused (the signer's own date decides nothing), two roots signed for one number are provable equivocation, and a missing, withheld, stale or older-key head is UNCHECKED, never a pass (`verify-audit` exits 3). A governed revocation carries its head or leaves one owed, which anyone derives from the shared log (the revocations after the owner's latest head), so a head that is behind is visible to every member. Not covered: a revocation the owner never made, a head the owner never signs (the bundle stays UNCHECKED, which is the finding), and the interval between a revocation and the owner's next head (`overdue` after 24 hours). `verify-audit` without pins verifies none of it and exits 3 | INV-247; `head_covers_every_revocation`, `bundle_omitting_a_revocation_fails`, `head_older_than_the_grant_is_unchecked`, `head_under_a_revoked_key_refused`, `skipped_or_replayed_seq_refused`, `head_root_must_match_the_control_planes_fold`, `governed_revoke_with_head_is_atomic`, `draft_recomputed_by_cli_before_signing` |
| Run a job where an owner's data may not go, by steering the scheduler, re-registering an evaluator elsewhere, or declaring a location falsely | A governed job is placed only on an evaluator whose operator takes part in the project (or is named by a constraint; the platform's own are the exception) and that the project's constraints and every owner's own admit under their evidence level; scheduling, start and every release ticket check again, and start also requires the evaluator to be the machine the grant recorded (same operator, location, evidence, URL and receipt key), so a moved or re-registered evaluator fails the job. A location comes from the table, never from the declarer; only a person who is a security admin of the operator declares one; a changed location loses its evidence and lapsed evidence counts as none; production never accepts a self-declared location (`ops/placement.rs`, `ops/jobs.rs` `revalidate_governed`, `schedule_job`, `ops/custody.rs`). Residual: a declared location is attributable, not proven | INV-233; `an_evaluator_that_moves_after_scheduling_fails_the_job`, `a_changed_location_loses_the_declaration`, `a_service_account_cannot_declare_a_location`, `a_job_is_held_not_moved_when_nothing_is_admissible` |
| Loosen the project's constraints after a job was bound, or alone | A tightening takes effect at once for any member's security admin; anything else needs every member to send the same constraints from the same version; a job is judged by the version its binding names together with the current one, so a loosening never widens it (`ops/placement.rs` `set_project_placement`, `job_admission`, migration 0018) | INV-233; `tightening_is_immediate_and_loosening_needs_every_member`, `a_later_loosening_never_widens_a_bound_job` |
| Release an owner's key to a workload outside its constraints | The broker judges the zone the signed attestation names against the owner's own constraints (in the installed authorization) and against the project's (the document the ticket carries, whose digest the binding names). The project's constraints are the owner's to pin: where its signed authorization pins their digest (`limits.project_placement_digest`) the broker requires the binding to name it, so the control plane cannot drop or swap them; **where it does not, the project's constraints are enforced by the control plane only**. No zone, an unknown zone or a missing document refuses. Operators and evaluator IDs are the control plane's to enforce (`governed.rs` `check_attested_placement`, `crates/encompute-attestation/src/gcp.rs`) | INV-233; `broker_refuses_zone_outside_placement`, `missing_placement_evidence_is_a_refusal`, `gce_zone_extracted` |
| A compromised control plane names the evaluator the client sends ciphertexts to | `jobs run --placement` judges what the client pinned about the evaluator (receipt key, operator, location, evidence) by the client's own constraints, and refuses when the control plane's record differs from the pin (`encompute-cli`, `crates/encompute-verification/src/placement.rs` `check_pinned_placement`) | INV-233; `placement_violation_refused_before_send` |
| An evaluator operated by a data owner or the recipient runs the job | Operator separation, assuming an honest control plane (the operator of an evaluator is its record of the service account; nothing the operator signs binds an evaluator to it, so a compromised control plane can misname one and place a job on an operator that separation or the constraints exclude; brokers cannot see operators and clients pin only key, URL, operator and location; what contains it is that an evaluator holds ciphertext only, so the exposure is availability, result integrity (bounded by receipts) and metadata): the planner admits no evaluator whose operator owns a source or holds a decryption key for an output, the validator recomputes it, submission refuses a job nothing else remains for (ENC2725), and scheduling, start and tickets check again. An organization's own evaluator never runs a standard job (`crates/encompute-planner/src/placement.rs`, `ops/jobs.rs`) | INV-234; `a_data_owner_operated_evaluator_is_refused`, `a_data_owner_operated_evaluator_gets_no_job_start_or_ticket`, `an_operators_evaluator_never_runs_a_standard_job` |

**Out of scope:**

- **Denial of service.** It can refuse or delay tickets, jobs and the
  delivery of revocations; nothing is released meanwhile, but the owner's
  own revocation at its broker is the reliable path.
- **Misuse inside an authorization.** Within what an owner signed, and
  while it is valid, a compromised control plane decides which scheduled
  job gets a ticket. The owner's limits (`max_releases`,
  `max_executions`) bound how often.
- **Placement.** What the rows above say is enforced; what they cannot
  say is not: a location an operator declares is attributable, not
  proven (only a zone the cloud attests is); a broker cannot see an
  operator or an evaluator ID, so those constraints rest on the control
  plane that issues the ticket; plaintext at an institution's own
  premises, network routing and copies made outside Encompute are not
  controlled (see KNOWN_LIMITATIONS).
- **Released copies.** Revoking a source blocks new use of what was
  derived from it; it cannot recall a result a recipient already holds or
  one exported before (see KNOWN_LIMITATIONS, "`source_revoked_at` is not
  erasure").
- **Standard projects.** There the broker trusts the control plane's grant
  as in 0.3.

### 4.10 Evidence bundles and reports (governed projects)

The governance evidence bundle and the cross-agency report are what an
institution shows its own auditor, so the attacks are on what they say.

| Attack | Defence | Evidence |
|---|---|---|
| Edit, omit or reorder part of a bundle, add a field, or re-encode it | The manifest commits to every section by digest and to the trust graph's root; the file must be exactly the canonical encoding of what it parses to; every type refuses unknown fields. An attacker who recomputes the digests changes the BundleId (breaking every signature) and still cannot change what the signed evidence says: each row reads signatures, proofs and pins, not the manifest (ENC2727) | INV-243; `every_single_field_edit_fails`, `omission_and_reordering_fail`, `a_rebuilt_manifest_does_not_launder_an_edit` |
| Bring your own keys: a bundle that anchors the keys it is verified under | Keys come only from the verifier's pins. A governance key the caller pins replaces whatever the bundle anchors; an unpinned key is UNCHECKED, never a pass | INV-244; `caller_pinned_governance_keys_override_a_bundles_own_anchors`, `missing_anchors_are_unchecked_not_satisfied` |
| Leak source records or another organization's metadata through an export | Typed sections; data-dependent values only as salted commitments; no string over 256 bytes outside the program, the purpose's description and attestation records; a shared view has no signed authorization (it names the approvers), only cards with per-project pseudonyms; an organization's view has only its own signed documents; the exporter and the verifier both refuse a breach (ENC2729) | INV-243; `no_source_value_appears_in_any_export`, `the_shared_bundle_leaks_no_other_organizations_private_metadata`, `governance_views_canary_scan` |
| Show a verdict of "no raw data centralized", "ownership retained" or "no unauthorized release" without evidence | Those rows are YES, NO or NONE only with signed backing: the plan's steps, the owners' verified signatures, one signed release record per output within every owner's class and recipients. Anything else is UNKNOWN or NOT EVIDENCED, and the verdict is then "not fully evidenced" | INV-244; `releases_are_none_only_with_signed_records_within_what_owners_allowed`, `ownership_is_retained_only_when_each_owner_signed_for_its_own_version` |
| Present a stale revocation head as covering a later run, or judge a historical run by today's clock | Authorizations are judged at the grant's signed time; what they say now is shown apart and never fails a historical audit. A head covers only what happened up to its own date; for a later `--as-of` it is UNCHECKED | `a_stale_revocation_head_is_not_covered_for_a_later_run`, `execution_time_validity_never_fails_a_historical_audit` |
| A control plane that shows members different histories | Members compare BundleIds of the shared view (one state, one id) and witness checkpoints; a bundle whose log is not witnessed by every member is UNCHECKED | INV-247 |

The plaintext guard (a length cap outside a few text fields, typed
sections, salted commitments) is a heuristic that catches the common
shapes of a leak, not a proof that no record is in a bundle: the types
and what the control plane never holds are the defence.

Not covered: the shared view's metadata by design (members, versions used,
counts, pseudonyms); a card's content, which is the control plane's word
until the owner discloses the signed document; the key model (who can
decrypt a result), which is not recorded in signed evidence in this
release and is shown as NOT EVIDENCED; where the job ran, until placement
is evidenced; the provenance of the software (not in the bundle yet); and
whether anything was lawful (every report ends with that boundary).

### 4.11 Member institutions, auditors and the attack suite (governed projects)

This section describes the public-sector governance work, which is not
part of Encompute 0.3.

The attacker is an institution taking part in a governed project (a data
owner, the submitter, a recipient), an auditor organization, or a person
or service account in one of them. It holds valid credentials of its own.
It tries to use another institution's data beyond what that institution
signed, to act where it may not, or to leave no trace.

**Protected assets:** every owner's data, keys and authorizations; what
may be released and to whom; the project's audit trail.

**Trusted components:** each owner's own governance key, key broker and
KMS; the control plane for availability and for the audit trail it writes
(its signed grants, tickets and checkpoints are checked by the others).

**Assumptions:** one identity per person (see KNOWN_LIMITATIONS); the
institutions' own approvals are not coerced.

`scripts/governance-attacks.sh` runs each attack below against the real
service or library, and checks the ENC code and the trail it leaves (an
audit event, an anchored log event or a refused start, and no job, ticket,
key release or budget).

| Attack | Defence | Refused with | Evidence |
|---|---|---|---|
| Activate an authorization the owner did not sign: a foreign key, an edited body, a malformed signature | Verified under the owner's own governance key, over the approved body; any edit changes the ID and voids the signature | ENC2701 | INV-218; `attack_a_forged_or_tampered_owner_signature_activates_nothing`, `governance_authorization_property` |
| Run a job under another purpose, program or dataset version than the owner signed | The purpose, program, policies and version are bound through the authorization, the job's spec and its GovernanceId | ENC2702, ENC2703, ENC2704 | INV-219, INV-231; `attack_a_job_outside_what_the_owners_signed_is_refused_and_audited` |
| Use an authorization after its window, after its owner revoked it, or after its key was revoked | Strict window (no margin), checked at submission, scheduling, start, ticket and export; revocation is anchored before it is acknowledged | ENC2705, ENC2706, ENC2708 | INV-220; `attack_an_expired_or_revoked_authorization_is_refused_and_audited`, `governance_authorization_property` |
| Release a result wider than the owners allowed, or to a recipient they did not name | Release classes are an order every layer decides with; the compiler proves the form of each output | ENC2709, ENC1907 | INV-221; `governance_release_class_order`, `attack_a_job_outside_what_the_owners_signed_is_refused_and_audited` |
| Act as an auditor, or hold an auditor role with another | Every mutating route refuses an auditor; no key or ticket is ever issued for one; combinations are refused | ENC2716 | INV-223; `auditor_org_cannot_submit_or_receive` |
| Approve as a service account, as the submitter, or as one person with two keys | Four eyes count distinct people of the approving organization only | ENC2707 | INV-228; `a_four_eyes_job_runs_only_after_two_distinct_people_of_the_owner_approve_it`, `service_account_cannot_approve_2707` |
| Get a key by asking for a ticket early, for another job's source, or by replaying or forging one | A ticket is issued only to the scheduled evaluator of a running job, for one of its sources; the broker also needs the owner's installed authorization; a refused request is audited | ENC2604, ENC2704, ENC2712 | INV-232, INV-236; `attack_a_release_ticket_for_a_job_that_is_not_running_is_refused`, `forged_ticket_refused`, `replayed_ticket_refused` |
| Spend privacy budget through a conflicting scope, or without one | A release is charged to a scope its owners allocated under the population's cap; conflicting pins are refused at submission | ENC2719 | INV-230; `two_authorizations_that_pin_different_scopes_are_refused`, `a_job_with_no_scope_cannot_spend` |
| Run where an owner's data may not go, or on a machine operated by a source owner or a decryptor | Placement is intersected (a prohibited place wins), judged at submission, scheduling, start and every ticket; operators are separated | ENC2710, ENC2725 | INV-233, INV-234; `governance_placement_property`, `a_data_owner_operated_evaluator_gets_no_job_start_or_ticket` |
| Use a derived result without every lineage owner's consent, or export it after a source was revoked | Every use walks the ancestors; the custodian's broker needs each lineage owner's authorization | ENC2701, ENC2706 | INV-245; `derived_source_needs_every_lineage_owners_authorization`, `export_of_derived_asset_whose_source_was_revoked_2706` |
| Undo a revocation or a spend by restoring an older database, or an older broker state | The anchor holds the governance log's head; the broker's state is guarded by a generation mark in the owner's KMS | ENC2202, ENC2713 | INV-226, INV-236; `restores_resurrecting_governed_state_are_refused_and_recovered`, `broker_state_rollback_refused_by_kms_generation` |
| Skip or replay a revocation head's number to hide a revocation | Heads are numbered one past the previous, under the owner's active key | ENC2717 | INV-247; `skipped_or_replayed_seq_refused` |
| Edit an evidence bundle or a report | The manifest and signatures are checked against the verifier's own pins; a cached or edited value changes nothing | ENC2727 | INV-243, INV-244; `every_single_field_edit_fails`, `a_tampered_report_or_cached_attribute_changes_nothing` |

**Residual (see KNOWN_LIMITATIONS):**

- **Anything inside an authorization.** Within what an owner signed, the
  submitter chooses which question to ask, and repeated boolean questions
  add up. Authorization limits bound how often (INV-240); they do not
  prevent it. Per-subject limits are not enforced: they need record
  linkage, which is not built.
- **Collusion.** A member institution colluding with the evaluator's
  operator, or with another member, learns what each of them can see
  together. The attack suite refuses single actors, not coalitions.
- **An owner lying about its own data.** Encompute binds a computation to
  the version an owner registered, by digest. It does not check that the
  version's contents are true.
- **A person who is two identities.** Four eyes count identities.
- **A request refused before any job is looked up** (a person asking for a
  release ticket) leaves the request log, not an audit event.

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
6. **Pin evaluator and coordinator keys out of band** (`--trust-evaluator`,
   `--coordinator-key`). For jobs a control plane schedules, every client
   that decrypts (CLI `encompute jobs run`, the Python SDK, the native SDK)
   checks the evaluator receipt key the control plane names against the
   client's own pin set: `--trust-evaluator KEY` (repeatable),
   `ENCOMPUTE_TRUSTED_EVALUATORS`, or `trusted_evaluators=` in the SDK. A
   key outside the set is refused before anything is sent to the
   evaluator (ENC2607); a set that is present but empty refuses every
   evaluator. With no pin at all the job is refused (ENC2605) unless the
   explicit development opt-out is given (`--allow-unpinned-evaluator`,
   `allow_unpinned_evaluator=True` or
   `ENCOMPUTE_ALLOW_UNPINNED_EVALUATOR=1`), which is itself honoured only
   under an explicit `ENCOMPUTE_ENV=development` and refused when it is
   unset or anything else (`crates/encompute-runtime/src/remote.rs`
   `trusted_evaluators`, `crates/encompute-cli/src/control.rs`,
   `python/encompute/client.py`).

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
- Whether a computation is lawful: the legal basis, the legitimacy or
  proportionality of a purpose, retention required by law, the rights of
  the people concerned. Encompute enforces what institutions declare and
  sign (see [public-sector.md](public-sector.md), "Technical enforcement
  and legal authority").
- Erasure of results already released. Revocation blocks new use and
  lists what was derived; it recalls nothing.
- Inference beyond the caps: repeated authorized queries, and the
  combination of released results with outside information.
- Re-identification through record linkage. Linkage is not built. When it
  is, whoever holds a linkage key can recompute the pseudonym of a person
  it can identify, and an institution colluding with the evaluator's
  operator can learn which of its people appear in another institution's
  records (see KNOWN_LIMITATIONS).
- Collusion between a result's decryptor and the evaluator's operator
  where one institution holds the decryption key: confidentiality of the
  inputs against that institution then rests on the operator not
  colluding with it. This is a property of the recipient-held key model
  planned for record-level exact computation, which is not built.
- Threshold or multi-key decryption: one holder decrypts a result.
- An owner's registered data being true.
