# Changelog

## Unreleased

### Enterprise deployment foundation

- **Control plane** (`encompute-control`, API v1). It manages:
  - organizations, users (OpenID Connect) and service accounts (Ed25519),
    with seven roles;
  - projects with explicit cross-organization collaboration;
  - an asset registry (metadata, digests and wrapped-key references only);
  - four-eyes policies, planned jobs, evaluator registration, privacy
    ledgers, trust reports and an audit trail.

  It coordinates and holds no keys. Trust reports are rebuilt from signed
  evidence on every request.
- **Tenant isolation.** Other tenants' resources are "not found". Every
  route is tested unauthenticated, with the wrong role, from the wrong
  tenant and authorized, and a cross-tenant attack suite runs on top.
- **Service identity.** Signed requests and messages bind the sender,
  recipient, timestamp, a single-use nonce, the body hash and the IDs they
  concern. Evaluators run only jobs granted by their pinned control plane,
  and ask before starting each one.
- **Jobs.**
  - An explicit state machine and idempotent submission (`Idempotency-Key`).
  - Capability-aware scheduling: backend, parameter profile, health,
    capacity, draining.
  - Recovery after a restart never replays a job.
  - OpenFHE exact and OpenFHE CKKS both run through the same control plane.
- **Customer-managed keys.** `RootKeyProvider`, with OpenBao/Vault Transit
  as the first adapter. The key broker's KEK is wrapped by the
  organization's root key. `encompute keys rotate-root` re-wraps only the
  KEK. Revocation reaches the broker as a signed message. There is no
  fallback to local or plaintext keys.
- **Durable privacy state.**
  - Hash-chained ledgers in PostgreSQL: race-safe and idempotent.
  - A signed state anchor outside the database. Restoring an older database
    is refused (PRIVACY STATE ROLLBACK).
  - `encompute-control recover` freezes rolled-back ledgers.
- **Audit.** A hash-chained, anchored event for every security-sensitive
  transition. Events carry identifiers only.
- **Operations.**
  - `/live`, `/ready`, Prometheus metrics, JSON logs.
  - Production mode refuses development identities, key stores and default
    credentials.
  - Secrets come only from files or the environment.
- **Message transport.** HTTP (with an outbox) and in-memory
  implementations. Signed envelopes, idempotent consumers. SecAgg
  coordinators report privacy events and round durations.
- **Clients.**
  - `encompute login`, `projects`, `assets`, `jobs submit|run|status|list|cancel`,
    `trust report JOB`, `audit list`.
  - Python `encompute.Client` (`project.run(...)`).
- **Deployment.** Docker Compose: control plane, PostgreSQL, OpenFHE
  evaluator, key broker (as a sidecar to its KMS), SecAgg coordinator. It
  comes with images, `init.sh`, `backup.sh`, `restore.sh` and `smoke.sh`.
- **Evidence.**
  - `scripts/enterprise-e2e.sh`, in production mode:
    - both golden paths and the SDK;
    - a full restart;
    - backup and restore, where an older backup is refused;
    - revocation;
    - a canary scan of logs, the database, audit output and metrics.
  - Invariants INV-156 to INV-165.
- **Documentation.** ADR-021, docs/deployment.md, docs/api.md. Error codes
  ENC2601–ENC2607.

### Commercial exact execution on OpenFHE

- **OpenFHE exact** (`openfhe-exact`, scheme BinFHE): exact programs run
  encrypted on OpenFHE 1.5.1 BinFHE. Each value is a vector of encrypted
  bits (two's complement), and every plan operation is a Boolean circuit:
  - add, sub, mul, and multiplication by constants;
  - signed and unsigned comparisons, select, min and max;
  - division and remainder by constants;
  - shifts, casts, Boolean logic;
  - lookups up to 256 entries.

  The language and `ExactPlan` are unchanged.
- **The default exact backend.** The compiler, the evaluator and the
  planner select OpenFHE exact for unverified exact programs. Verified
  programs stay on BGV with re-execution proofs.
- **One vetted profile**: `BINFHE_STD128_GINX_BITS_V1` (STD128, GINX,
  128-bit, 2^-135 per gate). It is bound into artifacts, evaluation keys
  and ciphertexts.
- **Versioned envelopes** (`ENCBINF1`) bind every key and ciphertext to
  its backend, parameter set, client key and type. Mismatches are refused
  before any gate runs.
- **TFHE-rs is research-only.** The feature is renamed `research-tfhe-rs`.
  Selecting TFHE-rs in a production build (the
  `ENCOMPUTE_RESEARCH_EXACT_BACKEND` variable, `--backend tfhe-rs`, or a
  TFHE-rs artifact) fails with ENC1501 BACKEND UNAVAILABLE; it never falls
  back.
- **Commercial build audit** (`scripts/audit-commercial-build.sh`) checks
  the dependency graph, a CycloneDX SBOM (`scripts/sbom.py`), and the CLI,
  evaluator and Python extension binaries; optionally also a wheel and a
  container image. CI runs it on production builds, and runs it on a
  research build as a negative control.
- **Capability matrix.** Operations outside it are refused at compile
  time. `explain` prints each program's bootstrapped gate count.
- **CLI and SDK.** `encompute info` has an `openfhe-exact` row, and
  `encompute.has_exact()` is new.
- **Evidence.**
  - Exhaustive 8-bit circuit tests.
  - OpenFHE exact equals the clear reference and the mock on every
    operation and on random programs.
  - Remote execution with receipts.
  - Backend-independent transcripts.
  - A research differential test: OpenFHE exact equals TFHE-rs.
  - Invariants INV-149 to INV-155.
- **Example 19** (`examples/19_openfhe_exact`) covers Boolean logic, a
  lookup, and remote eligibility with a verified receipt. It also runs 13
  attacks: forged keys, parameters and backends, corruption, a modified
  plan, receipt replay, overflow, unsupported operations, and TFHE-rs
  selection.
- Benchmarks: gate counts per operation and width; about 62 ms per gate;
  524 MiB of evaluation keys (docs/benchmarks.md).
- ADR-020.

### Confidential training on Google Confidential Space

- **Confidential training jobs**: `encompute.torch.job.prepare` plans a
  run for Intel TDX on Confidential Space and writes:
  - production attestation policies (the image digest, no debugging, no
    mock evidence);
  - a production broker with wrapped keys for the model, datasets, adapter
    and outputs;
  - sealed assets;
  - per-participant job descriptors with public commitments only.
- **The job worker** (`python -m encompute.torch.cs_worker`):
  - attests once per broker from an in-memory session, receives its keys
    sealed to that session, and decrypts and checks every asset in memory;
  - runs the same Hugging Face + PEFT DP-SGD step as example 17;
  - seals its contribution and signs **worker evidence** (run, spec,
    participant, round, model package, dataset, layout, image,
    attestation, output commitments).
  - Refusals: KEY RELEASE DENIED, TRAINING SPEC MISMATCH, ASSET MISMATCH,
    DATASET ASSET MISMATCH, MODEL PACKAGE MISMATCH.
- **Participant-scoped attestation**: a job attests to the spec scoped to
  its participant, so one session never receives another participant's
  dataset or output key, and the evidence's participant is attested.
- **Trust graph**: worker evidence nodes. The Training row verifies them
  against their spec and attestation, and flags a second output for one
  round.
- **The worker image** (`deploy/confidential-space-training`): pinned
  dependencies, `--locked` builds, offline Hugging Face. The launch policy
  lets the operator set only `JOB_URL`.
  - `deploy.sh`: `prepare-only`, `approved`, `tampered` and `debug`
    variants.
  - `cleanup.sh`, least-privilege worker identity, separate input and
    output buckets.
- **Local rehearsal**: `encompute attest simulate-launcher` (development
  only) and a production broker with a test JWKS; `job.py container` runs
  the built image.
- **CI**: builds the image and runs approved and tampered images on every
  pull request; `test_confidential_job.py`; example 18 required; a manual
  `confidential-space-live` workflow (SKIPPED without GCP); release-check
  rows for the image and the live run.
- **Broker**: one attestation per broker per session;
  `keys serve --requests-per-minute`; `trust init --attestation-policy`.
- **DP-SGD**: the gradient-path probe's tolerance is relative to the
  gradient's scale (see the benchmarks).
- ADR-019; INV-143–INV-148 (81 invariants). The live GCP run is pending a
  project.

### Hugging Face Transformers + PEFT

- **Hugging Face models**:
  - `encompute.torch.huggingface(source, revision=)` imports a local or
    Hub model into a content-addressed package (`enchf1:`). The revision is
    resolved to an immutable commit; only safetensors, configuration and
    tokenizer files are kept, each hashed.
  - Refused (ENC2504): remote code (`*.py`, `auto_map`,
    `trust_remote_code`), pickled weights, unknown files, a shard index
    naming anything but the package's safetensors, unsupported
    architectures, and other library versions than the package binds.
  - Credentials are used for the download only.
- **Workers never download.** They rebuild the Transformers-native class
  from its configuration and load the sealed weights. The training spec
  binds the whole package, which the lineage prints.
- **PEFT LoRA** (`method="peft-lora"`):
  - The official `peft` library adds the adapters. `PeftConfig` in the
    training spec binds every setting.
  - The adapter layout (the LoRA matrices and the head) is canonical.
  - The reference LoRA stays for `method="lora"`.
- **Text datasets**: `private_text_dataset(texts, labels, tokenizer=,
  max_length=, stride=, unit_ids=)`.
  - Every chunk keeps its patient.
  - The tokenization is bound per dataset, and must use the package's
    tokenizer.
- **Per-patient gradients for Transformers**:
  - a vectorized fast path and a one-patient-at-a-time reference path,
    with identical semantics, chosen per model by a probe;
  - training fails closed if neither works;
  - task adapters read structured outputs.
- **PEFT export**: `FineTuneResult.export_peft(dir)` writes standard PEFT
  files and `encompute-adapter.json`. It does so only when every owner
  permits (`adapters="public"`), no parent is revoked and the trust report
  is satisfied. The files load with `PeftModel.from_pretrained`.
- **Planner**: the training declaration names the framework (workload
  metadata).
- **Packaging**: the `encompute[huggingface]` extra.
- **CI**:
  - The fine-tuning gate now also runs `test_dpsgd.py`, which it
    previously missed, and `test_huggingface.py`.
  - Examples 15–17 are required.
  - `examples/17_huggingface_peft` runs with 22 attacks failing closed.
- ADR-018; INV-136–INV-142 (75 invariants).

### Patient-level differential privacy (DP-SGD)

- **DP-SGD for confidential fine-tuning**:
  `privacy="strong-patient"` or `"standard-patient"`, or
  `encompute.Privacy(unit="patient", ...)`, with
  `private_dataset(x, y, unit_ids=)`.
  - Each attested worker computes per-example LoRA gradients with
    `torch.func` (`vmap` over `grad`, microbatched). It groups each
    patient's records, clips each patient's gradient, and Poisson-samples
    patients with operating-system randomness.
  - Secure aggregation sums the clipped gradients. The attested
    coordinator adds discrete Gaussian noise.
  - One accounted step per round. Organization-level mode is unchanged.
- **Rényi DP accountant for Poisson-sampled releases**
  (`rdp-poisson-zw2019`: Zhu and Wang's general bound over the discrete
  Gaussian's zCDP curve; CKS conversion; rounded up).
  - Checked against 240 independent reference vectors (autodp and a
    60-digit mpmath evaluation).
  - `DpMechanism.sampling_rate` is in the IR text and the
    PrivacyPolicyId.
- **Every DP-SGD setting in the TrainingSpecId**: unit, clip, sampling,
  noise, delta, grouping, accountant and expected batch, plus each
  dataset's unit count and grouping digest.
- **Privacy preview**: a DP-SGD run over budget is denied before training
  (ENC2201). `encompute privacy explain --rounds N` prints the projection.
- **No false patient-level claims**:
  - the compiler refuses sampling with an organization unit;
  - the planner requires per-example clipping for a patient unit, and the
    plan shows the example level;
  - the trust report's Training row checks the unit;
  - the lineage prints it.
- `examples/16_patient_private_lora`: organization-level and patient-level
  privacy side by side, the preview denial, and eight attacks failing
  closed.
- `test_dpsgd.py`:
  - the vectorized gradients match the per-unit reference for any
    microbatch;
  - canary patient sensitivity;
  - sampling ignores seeds;
  - the ledgers match the preview;
  - the accuracy regression bound.
  The leakage canaries now run in both modes. INV-130–INV-135
  (68 invariants).

### Confidential PyTorch fine-tuning

- **Real PyTorch LoRA fine-tuning, protected end to end** (ADR-016, new
  crate `encompute-training`, `encompute.torch`):
  `Project.finetune(model=, data=, method="lora", privacy=,
  verification=)` plans the run, attests each participant's training
  worker, releases the model key only to it, trains LoRA locally with
  PyTorch, securely aggregates the clipped updates with differential
  privacy (organization-level), writes immutable sealed adapters and
  checkpoints, records signed adapter lineage, and verifies the whole run
  with one trust report.
- **Training spec** (`enctrain1:`) binding the plan, model and dataset
  digests, training code, LoRA configuration and tensor layout; workers
  rebuild models from bound factories (never pickles).
- **Checkpoint resume** refuses stale, foreign, tampered or rolled-back
  state against the authoritative privacy ledgers.
- `encompute lineage`, `encompute export` (EXPORT DENIED unless every
  parent permits), `encompute train`, `aggregate join --values -`; trust
  graph Training and Adapter nodes and a Training report row; attested
  inference with the adapter. Errors ENC2501–ENC2503.
- `examples/15_confidential_lora` with every attack failing closed.
- **The PyTorch boundary**: PyTorch computes in plaintext inside the
  attested workload; the TEE, secure aggregation and differential privacy
  protect it. Privacy unit: organization (each hospital's whole update is
  clipped). Patient-level DP requires per-example clipping (DP-SGD) and is
  not claimed.
- **Crash-safe rounds**: a round's adapter and checkpoint are provisional
  until its signed adapter record enters the trust bundle (the commit
  point); `recover` finalizes or discards after a crash, a released but
  uncommitted round stays charged, and `finetune(resume=workdir)`
  continues from the last accepted adapter (resume accepts only declared
  lost rounds after the checkpoint, checks the run ID and refuses once a
  parent is revoked).
- **Rust owns the formats**: TrainingSpec, checkpoints, adapter records,
  sealed-asset headers, the adapter layout (versioned, validated) and the
  canonical tensor file (pickles refused before loading), with contract
  fixtures checked by both the Rust tests and the Python bindings.
- **Release gate**: end-to-end, commitment, canary-leakage (datasets,
  weights, raw updates, keys), crash and kill (ten injection points) and
  contract tests run on every pull request, with example 15 required;
  `scripts/release-check.sh` from a clean checkout; export also refused
  after a revocation or a failed trust report. Package description:
  "Compiler and trust runtime for confidential AI".
- INV-120–INV-129 (62 invariants).

### Examples

- **A runnable example for every capability** (`examples/01`–`14`): CKKS
  and exact private computation, remote evaluation, receipts, verified
  execution, confidentiality policies, attested key release, secure
  aggregation, differential privacy, the trust graph, the planner, a full
  confidential collaboration with seven fail-closed attacks, the assurance
  suite, and the Python Project API. Each has `run.sh`, `expected.txt` and
  a README with its threat model and what it does not protect.
- `examples/run-all.sh quick|standard|crypto|full` with dependency
  detection (`encompute info`), in CI on every pull request (standard), in
  the OpenFHE job (crypto) and nightly (full).
- CONTRIBUTING: a user-visible feature is done with tests, docs and an
  example.
- Fixed: `aggregate verify --aggregate` now checks the released decoded
  values (and the asset's other fields) against the committed sum; an
  edited aggregate previously verified.
- `aggregate coordinator-policy --plan` and `trust init
  --coordinator-policy`, so planned rounds with attested coordinators work;
  `trust report --execution-policy`; `Project.plan(data=...)`; `explain`
  shows a declared DP mechanism; `transcript` defaults to the program's
  target backend; `assurance-report --only` refuses unknown checks.

### Planner

- **Declare trust requirements; Encompute chooses the mechanisms**
  (ADR-015, new crate `encompute-planner`): requirements derived from the
  confidentiality policy (hide from parties and the compute host,
  aggregate-only, purpose, privacy budgets, participants, correctness,
  attestation, region), profiles `standard`/`strong`/`maximum` that only
  add requirements, and selection among the existing mechanisms (FHE,
  verified execution, attested confidential compute with key release,
  secure aggregation, DP, local execution) by estimated cost. PLANNING
  FAILED (ENC2401) when nothing satisfies the policy; nothing is weakened.
- **Auditable, deterministic plans** with a reason and expected evidence
  for every requirement; `encplan1:` PlanIds; an independent validator
  (`verify_plan`, ENC2402).
- **Plans bound to execution**: `AggregationPlan.execution_plan_id` (spec,
  receipts, coordinator attestation), a Plan node in the trust graph, and a
  report row that fails on evidence outside the approved plan (ENC2403)
  and prints PLAN SATISFIED BY OBSERVED EXECUTION.
- CLI: `encompute plan`, `encompute check`, `explain --deep`,
  `aggregate … --plan`, `trust init --plan`. Python: `Project`, `.data`,
  `.model`, `.train(...)`, `PlanningFailed`.
- Assurance INV-110–INV-115: 50 000 generated planning scenarios nightly,
  every mechanism removal and plan-field mutation, the adversarial list.
- Fixed a flaky trust test (shared ledger directory between parallel
  tests).

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
  62 security invariants, each with positive, negative, adversarial and
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
