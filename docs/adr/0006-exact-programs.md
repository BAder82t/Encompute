# ADR-006 — Exact programs: one compiler, two schemes

Status: **Accepted** (2026-09-25)

## Context

0.3 adds exact computation: fixed-width integers and Booleans with
comparisons, logic, selection and lookups, computed without approximation
error. CKKS cannot do this; TFHE can. Encompute must stay one product: the
same Python annotations, CLI, artifacts, envelopes and evaluator service,
whatever the scheme.

## Decision

1. **Semantics choose the scheme.** The IR types every value (`f64` or an
   exact type `u8`…`i64`, `bool`). A program's semantics are *approximate*
   (only `f64`) or *exact* (only exact types). `compile_program` lowers
   approximate programs to a CKKS plan and exact programs to a
   backend-independent `ExactPlan`. Programs mixing both are refused
   (ENC1005) until hybrid execution (0.4). Users do not name a scheme or a
   backend.
2. **Semantics, scheme, backend and mode stay separate.** Semantics:
   approximate or exact. Scheme: CKKS or TFHE, written into artifacts and
   every envelope and checked explicitly (never inferred from the backend).
   Backend: mock, OpenFHE or TFHE-rs. Mode: clear, mock or encrypted, where
   "encrypted" means the real backend for the program's scheme.
3. **Pluggable exact backends.** `ExactEvaluator`/`ExactClient` traits; a
   plaintext mock ships by default; TFHE-rs sits behind the off-by-default
   `tfhe-rs` feature (research use only: Zama requires a patent license for
   commercial use). No TFHE-rs type leaves `encompute-tfhe` (evaluator) and
   `encompute-tfhe-client` (client key). The evaluator binary never links the
   latter (`scripts/audit-evaluator-binary.sh`).
4. **Artifacts.** `plan.json` holds a CKKS plan or an exact plan; the
   manifest records `semantics`, `scheme`, and the plan's own
   `{kind, version}` (artifact format 3), so each plan format versions
   independently. Exact artifacts target the vetted TFHE-rs profile; its
   canonical JSON is `parameters.json` and its hash the parameter-set ID.
5. **Exact values cross the API as f64, bounded by 2^53.** The runtime's
   input/output type is `f64`, exact up to 2^53. Rather than redesign the
   transport now, exact inputs' ranges, constants and table entries must lie
   within ±2^53 (the IR builder refuses others), and range analysis proves
   every output does too. Intermediate values may use the full width of
   their type (e.g. a `u64` product). A 64-bit transport (integers in the
   `Inputs` type and in Python) is future work; until then Encompute does
   not claim full `u64`/`i64` input range.

## Consequences

- `encompute compile/run/test/explain/bench/audit/keys` and the evaluator
  service work unchanged for exact programs; reports are
  semantics-specific (matches/mismatches for exact, error for approximate).
- The default build runs exact programs on the mock only; `mode="encrypted"`
  for an exact program needs the research build and says so.
- Envelope scheme checks stop a CKKS ciphertext from entering an exact
  program and vice versa, even with a matching backend name (both mocks).

## Evidence

- `crates/encompute-runtime/tests/exact.rs`: flagship 1000/1000 exact on the
  mock, deterministic artifacts, cross-scheme rejection, key/program/
  parameter bindings, remote execution; TFHE-rs end to end (feature
  `tfhe-rs`), locally and over HTTP.
- `crates/encompute-evaluator/tests/workers.rs`: exact programs in worker
  processes.
- `python/tests/test_exact.py`: Python exact types, operators, diagnostics.
- `crates/encompute-tfhe-client/tests/exact.rs`: TFHE-rs equals the clear
  reference on 1000 random flagship inputs and on every operation at type
  boundaries.
