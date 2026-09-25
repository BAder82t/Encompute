# Changelog

## Unreleased — 0.3 (in progress)

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
