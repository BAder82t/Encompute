# Changelog

## Unreleased

### Trust graph

- **One verifiable record of a collaboration** (ADR-014, new crate
  `encompute-trust`): parties, assets, programs, policies, owner
  authorizations and revocations, aggregation rounds, aggregates, privacy
  releases, attestations and executions in one content-addressed bundle,
  with the signed evidence inside.
- **Owners approve programs**: signed `Authorization`s (program, policy,
  privacy policy, purpose, expiry) and `Revocation`s; a revocation lists
  every aggregate derived from the asset.
- **A trust report that trusts nothing the bundle says about itself**: it
  rebuilds the graph from the evidence (edges, nodes and attributes must
  match), checks signatures only against keys the verifier supplies
  (`--parties`, `--coordinator-key`, `--evaluator-key`), compares privacy
  spend with the budget the program declares, and never reports an empty
  or unchecked bundle as satisfied (`--require` for rows that must be
  present).
- CLI: `encompute trust init | authorize | revoke | add | report | lineage
  | graph`, `aggregate serve --trust-bundle`. Errors ENC2301–ENC2303.
- `PrivacyReceipt::sign`.

### Assurance

- **System assurance suite** (`encompute-assurance`, `docs/assurance.md`):
  46 security invariants, each with positive, negative, adversarial and
  end-to-end evidence; adversarial checks for DP crash injection,
  multi-parent atomicity, multi-process double spend, ledger tampering,
  receipt mutation and SecAgg at scale; `assurance-report` as the release
  gate in CI, nightly at larger scale with `cargo deny`.

### Differential privacy

- **Privacy budgets per asset** (ADR-013): `privacy unit "patient"
  epsilon 3.0 delta 1e-6` (Python `asset(..., privacy="strong",
  unit="patient")` or `DP(epsilon, delta)`), with named levels
  `standard`, `strong` and `maximum`.
- **Release boundaries**: outputs that reveal a budgeted asset must go
  through a DP mechanism (ENC2203); sealed values cost nothing.
- **Discrete Gaussian mechanism** on the secure-aggregation sum (`dp
  discrete_gaussian clip_norm C noise_multiplier z`; Python
  `secure_aggregate(..., privacy="strong")`): parties clip to L2 norm C,
  the coordinator adds exact integer noise (CKS 2020 sampler, CSPRNG).
- **zCDP accounting** with the CKS conversion; a hash-chained, locked,
  persistent **ledger** per asset with reserve-then-commit releases (no
  unaccounted release, no concurrent double spend); signed
  **PrivacyReceipts**; owners check their ledger (and its last checkpoint)
  before contributing and refuse over-budget rounds (ENC2201) or
  rolled-back ledgers (ENC2202).
- **PrivacyPolicyId** (`encprivacy1:`) in the execution spec, aggregation
  plan, ledgers, receipts and coordinator attestation.
- **Attested coordinators from the CLI**: `aggregate coordinator-policy`,
  `--coordinator-policy`, `aggregate serve --attester …`, and `join
  --mock-root`/`--jwks`.
- **Every owner checks every ledger**: each owner records every charged
  asset's checkpoint from the signed receipts and refuses a round that
  rolls back any of them.
- CI uses Node 24 actions (`checkout@v7`, `cache@v6`, `setup-python@v7`).
- New crate `encompute-privacy`. CLI: `encompute privacy budget`,
  `explain --ledger`, `aggregate serve --ledger`. Errors ENC2201–ENC2204.
  `examples/private_federated_training/`.

### Multi-party secure aggregation

- **Aggregation boundaries** (ADR-012). `aggregate "out" sum|mean minimum
  N colluding C clip [lo, hi] scale S modulus M` (Python
  `secure_aggregate(...)`)
  declares that an output is a sum of one input per party, released only by
  secure aggregation to its recipient if at least N parties contributed. It
  satisfies `aggregate_only` (ENC1905 otherwise); the aggregate gets a
  derived policy (contributors as owners, never public by default).
- **Compile-time quantization analysis**: clipping, scale and modulus are
  explicit, and encodings that could wrap the modulus are refused
  (ENC2105). Shown in `privacy explain`, `explain` and receipts.
- **`encompute-secagg`**: Bonawitz et al. (CCS 2017) secure aggregation,
  active-adversary variant (signed keys, consistency check). The declared
  collusion bound sets the threshold `max(N, ⌊(n + C)/2⌋ + 1)`; dropouts
  are tolerated down to it. Aggregation specs (`encagg1:`) and rounds
  (`encround1:`) bind every message; signed `AggregationReceipt`s record
  contributors, dropouts, commitments, attestations and the aggregate
  commitment. Optional attested contributors (ADR-011).
- Aggregation programs never run on a single evaluator (ENC1905).
- Each contribution carries signed metadata: RoundID, AssetID, PolicyID,
  ExecutionSpecID, codec ID, shape, protocol keys and attestation. The
  coordinator checks it and the receipt records it. The aggregate asset has
  its own AssetID, with the contributing assets as parents.
  `privacy explain` shows individual release PROHIBITED, aggregate release
  PERMITTED, and runtime enforcement ACTIVE.
- CLI: `encompute aggregate identity|serve|join|verify`;
  `examples/confidential_federated_update/`. Errors ENC2101–ENC2106.
- **Key broker storage**: `SecretStore` (`DevelopmentFileStore`,
  `LocalKekStore`); production brokers refuse plaintext key storage
  (`encompute keys … --kek FILE`). Revocation destroys key material, and
  `encompute keys rewrap --new-kek` rotates the KEK.

### Attested confidential compute

- **Policy-gated key release** (ADR-011). Asset keys are released only to a
  workload whose fresh hardware attestation binds the approved execution
  spec, `PolicyId`, artifact digest, evaluator receipt key and an ephemeral
  session key, and satisfies the asset's `AttestationPolicy` (TEE, image
  digest, debug, TCB, GPU). Keys travel as HPKE grants sealed to the
  attested session; the host relaying them cannot open them.
- **`encompute-attestation`**: provider-neutral `VerifiedWorkload` claims,
  `WorkloadBinding`, single-use challenges, `AttestationPolicy`. Providers:
  Google Confidential Space (OIDC tokens verified against Google's JWKS)
  and a development-only mock that production policies and brokers refuse.
- **`encompute-keybroker`**: challenges, attested sessions, release,
  rotation and revocation; HTTP server and client; workload-side
  `acquire_keys`.
- **Receipts bind the attested session** (receipt version 3: optional
  `attestation` with the record ID and session ID). `encompute-evaluator
  serve --attestation FILE`, `GET /v1/attestation`, and `encompute verify
  --attestation … --attestation-policy …` check the chain attestation →
  evaluator key → receipt.
- CLI: `encompute attest verify|policy|mock-root`, `encompute keys
  protect|challenge|release|rotate|revoke|serve`, `encompute workload
  keys|attest`. Errors ENC2001–ENC2004.
- `deploy/confidential-space/`: image, entrypoint and deploy script for the
  real Confidential Space run.

### Confidentiality IR

- **Parties, assets and policies** in the IR (ADR-010): owners, readers,
  purposes, release (`never`, `owner_only`, `allowed_parties`,
  `aggregate_only`, `public`), and owner-permitted derivations; secret
  inputs bind to assets; outputs are sealed, revealed to a party, or public.
  Requirements only: execution is unchanged.
- **Confidentiality analysis.** Every value's policy is the join of its
  inputs' (owners union, audience and purposes intersection, most
  restrictive release); policies weaken only through derivations every
  source permits. Illegal flows are compile errors ENC1901–ENC1906.
- **Policy identity.** `PolicyId` (`encpolicy1:`) is part of the execution
  spec when a program declares a policy, so receipts and proofs bind it.
  Artifacts (format 5) carry `policy.json`.
- `encompute privacy explain` and `privacy graph --format dot`; Python
  `Party`, `asset(...)`, `secret[shape, lo:hi, asset]`, `confidential(...)`,
  `reveal(...)`, `publish(...)`, `compile(purpose=...)`, `Model.privacy()`;
  `examples/confidential_training.py`.

### Verified execution (research)

- **Verified private execution.** `verification="required"` (Python) /
  `verification required` (`.eir`) compiles exact programs to a new OpenFHE
  BGV backend (u8, u16, bool; `+ - *`, constants, `& | ^ ~`) and fails with
  ENC1801 unless every instruction is provable. Each result carries an
  `ExecutionProof` (relation `FheEvaluationV1`, protocol `reexecution-v1`)
  bound in the signed receipt; the client re-executes over the committed
  request with its evaluation keys and decrypts only on a byte-for-byte
  match. Sound, not succinct (ADR-009). Research feature `vfhe-research`
  (crate `encompute-vfhe`).
- **Malicious evaluator caught.** Random, replayed, skipped, substituted
  and mutated results, each with a valid signed receipt, are rejected by
  the proof; with receipts alone the same lie is accepted.
- **Proof plumbing.** `VerificationRelation`, `CiphertextBinding` (checked
  against the commitments before a backend sees them),
  `VerificationKeyId` (`encvk1:`), `ExecutionProof` (`ENCP` encoding),
  receipt evidence `Vfhe` (proof digest), `VerificationState`
  (unverified / receipt verified / execution verified), capability
  negotiation, `GET /v1/jobs/{j}/proof`.
- **CLI.** `run --remote` prints `VERIFIED PRIVATE EXECUTION` only after the
  proof verifies and saves `proof.bin`; `verify --proof --evaluation-keys`.
- Research findings recorded in ADR-009: Fherret binds no output ciphertext
  and has no license; ZHE's published analysis had a bug; TFHE-rs
  evaluation is not byte-reproducible; OpenFHE BGV is.
- Cost (loan pre-check, M3 Max): evaluation 24 ms, verification 65 ms,
  proof 543 bytes.

### Semantic transcripts

- **Semantic transcripts.** Every exact plan maps deterministically to a
  `SemanticTranscript` (stable numeric opcodes, typed canonical constants,
  plan-local registers, inputs without values) with a stable hash
  (`enctrace1:…`), bound to the execution spec (ADR-008).
- **Receipts v2** bind the transcript hash; clients compute it from their
  own plan and refuse a mismatch (ENC1702). `verification.json` stores the
  transcript version and hash; `encompute audit` checks it.
- **Proof boundary.** `ExecutionStatement` (spec, commitments, transcript
  hash), `StatementShape`, `VerificationCapabilities`, and a
  `VerificationBackend` with proving/verification keys, witness and
  evidence types; `NoProofBackend` still proves nothing.
- **Observers** receive `InstructionEvent`s and can fail an execution;
  `TranscriptObserver` records the plan-derived transcript.
- `ReferenceTranscriptEvaluator` (plaintext replay, for tests only): 12 132
  generated plans replay exactly; nightly runs 25 000 programs.
- CLI: `encompute transcript`; `explain` reports verification readiness;
  `verify` checks the transcript hash against the artifact.
- Fix: evaluator worker processes kept the gateway's backends (a mock for
  one semantics replaced OpenFHE for the other).

### Execution identity and receipts

- **Execution specs.** `ExecutionSpec` binds program, plan, parameters,
  plan kind and version, semantics, scheme and backend; its domain-separated
  ID is stable across machines and compilations. Artifacts (format 4) carry
  `verification.json`.
- **Signed receipts.** Every evaluation (local or remote, CKKS or exact)
  produces an `ExecutionReceiptV1` signed with the evaluator's Ed25519
  identity, binding the spec, key, and exact request and response
  envelopes. Clients verify it before decrypting (ENC1606 on any mismatch).
  A receipt is a signed claim, not a proof: `evidence` is `None`.
- **Evaluator identity.** `encompute-evaluator serve --identity FILE`;
  clients pin the key on first use or take `--trust-evaluator`.
- **CLI.** `run --remote` prints receipt status and can
  `--save-receipt`/`--save-envelopes`; `encompute verify` checks saved
  receipts and prints `RECEIPT VERIFIED` / `EXECUTION PROOF NOT PRESENT`.
- **Proof hooks.** `ExecutionObserver` on exact plans (structure only, never
  values) and the `VerificationBackend` interface (`NoProofBackend`).
- Canonical JSON and domain separation: ADR-007.
- Exact tests: 10 000+ random programs on the mock; TFHE-rs on every
  operation at the boundaries of all eight integer widths and on random
  programs; benchmark example `exact_ops`.

### Exact programs

Exact private computation: integers and Booleans, computed exactly.

- **Exact types.** Integer (`u8`–`u64`, `i8`–`i64`) and `bool` values with
  `+ - *`, comparisons, logic, shifts, min/max, select, lookup tables, casts and
  division by public constants. Integer range analysis proves no operation
  overflows; a possible overflow is a compile error (ENC1303). Exact values
  at the API are integers within ±2^53 (ADR-006).
- **Python.** `secret[u8, 0:120]` … `secret[i64, lo:hi]`, `secret[bool_]`;
  `+ - *`, `< <= > >= == !=`, `& | ^ ~`, `<< >>`, `//` and `%` by constants,
  `encompute.select`, `minimum`, `maximum`, `lookup`, `cast`. Results come
  back as `int` and `bool`.
- **One compiler, two schemes (ADR-006).** The program's types choose the
  lowering: approximate programs → CKKS, exact programs → a
  backend-independent `ExactPlan` (validated before it runs). Mixed programs
  are refused until 0.4.
- **Scheme-neutral runtime.** `Model`, client and evaluator sessions,
  artifacts (format 3: `semantics`, `scheme`, per-plan-kind versions),
  envelopes (explicit scheme check), the evaluator service (one backend per
  semantics), worker processes, and `run`/`test`/`explain`/`bench`/`audit`/
  `keys` handle exact programs. Exact tests report matches and mismatches,
  never error metrics.
- **TFHE-rs backend** (`encompute-tfhe`, `encompute-tfhe-client`) behind the
  off-by-default `tfhe-rs` feature: research use only; Zama requires a patent
  license for commercial use. Encrypted results equal the clear reference on
  1000 random inputs of the eligibility example. `scripts/exact-demo.sh`
  runs it through a separate evaluator process.
- Rust toolchain 1.98.1.

## 0.2.0 — 2026-09-25

Real private execution: a client encrypts, a separate evaluator computes,
only the client decrypts.

- **Client/evaluator split.** `CkksClient` and `CkksEvaluator` traits; the
  OpenFHE code is split into `encompute-openfhe` (evaluation only) and
  `encompute-openfhe-client` (keys, encryption, decryption). The evaluator
  binary links no client crypto; `scripts/audit-evaluator-binary.sh` checks
  it in CI.
- **Envelopes.** Every ciphertext, key set and result is wrapped in a
  versioned, SHA-256-checksummed envelope bound to parameter set, program and
  key. Wrong key, program, parameters or kind, and corruption, are rejected
  with ENC16xx codes.
- **Evaluator service.** `encompute-evaluator serve` (HTTP): program upload,
  one-time evaluation-key registration, jobs. `--workers N` runs worker
  processes with crash restart and replay (ADR-005). Container image:
  `Dockerfile.evaluator`.
- **CLI.** `keys generate`, `serve`, `run --remote --keys`, `audit`,
  `explain --measure` (measured bytes, time, memory, error, ranking).
- **Hardening.** Parameter conformance against OpenFHE (10 080-point grid,
  nightly) and encrypted execution of random programs; fuzzing of the
  parser, envelopes and artifacts; artifact format 2 with versioned
  compiler, plan and parameter-selector provenance.
- **Demo.** `scripts/two-machine-demo.sh`: 384-d encrypted query vs 64
  documents on a containerized evaluator, max error 1.9e-7, top-5 equal to
  plaintext, no secret key in the container. Runs in CI.
- **Benchmarks.** `docs/benchmarks.md`: five workloads and evaluator
  concurrency.

Breaking: artifact format 2 (recompile 0.1 artifacts); error codes renamed
VEIL#### → ENC####; project renamed Veil → Encompute.

## 0.1.0 — 2026-09-24

First end-to-end version: typed Python → Encompute IR → CKKS plan →
OpenFHE, with automatic 128-bit parameters, Chebyshev sigmoid,
differential testing, `explain`, `bench` and reproducible artifacts.
