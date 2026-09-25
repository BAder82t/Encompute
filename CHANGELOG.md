# Changelog

## Unreleased

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
