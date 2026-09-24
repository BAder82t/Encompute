# ADR-001 — OpenFHE FFI

Status: **Accepted** (M0, 2026-09-24)

## Decision

Veil owns a minimal `cxx` shim over OpenFHE, in `crates/veil-openfhe`.
It exposes only the CKKS surface Veil needs. Upper layers (`veil-ir`,
`veil-analysis`, `veil-ckks`, `veil-runtime`, the SDKs) MUST NOT depend on
OpenFHE types. They reach OpenFHE only through the backend trait in
`veil-backend` (M4).

OpenFHE is pinned to **v1.5.1** by `scripts/install-openfhe.sh`.

## M0 spike: openfhe-rs

Checked `fairmath/openfhe-rs` at commit `a60b38a101e9cccbada7629245c6a79a4c65741e`
(crate `openfhe` 0.3.2, last commit 2025-02-26).

| Gate | Result |
|---|---|
| Required CKKS calls (add, mult, rescale, rotate + keygen, sum, Chebyshev/poly, level) | pass |
| Serialization | pass |
| Bootstrapping exposed | pass |
| Version pinning | **fail**: README builds OpenFHE `main` unpinned; `build.rs` hardcodes `/usr/local/include/openfhe`; no release in 19 months |

One failure means no adoption. Further observations:

- The API mirrors OpenFHE's C++ classes one to one, so using it directly would
  put OpenFHE-shaped types into Veil's upper layers anyway.
- It has no guard against the concurrency bug below.

## Finding: OpenFHE is not thread-safe across contexts

Reproduced on OpenFHE v1.5.1, macOS arm64:

1. Two threads calling `GenCryptoContext` at once corrupt the heap
   (EXC_BAD_ACCESS in `ParameterGenerationCKKSRNS::ParamsGenCKKSRNSInternal`
   and in a `std::map` insert): 4 of 5 parallel runs crashed.
2. Concurrent *evaluation* on separate contexts, with context creation
   already serialized, corrupts results: decryption fails with "approximation
   error is too high" in 7 of 12 runs.

A reader/writer lock (exclusive for context creation and keygen, shared for
evaluation) fixed (1) but not (2). Making only the encode/decode paths
exclusive (2 of 12 failed) or only the evaluation paths exclusive (4 of 12
failed) was not enough either. The root cause is spread over several paths.

Mitigation in `cpp/shim.cc`: every OpenFHE call holds one process-wide
`std::mutex`. OpenFHE still uses all cores inside each call through
OpenMP; what is lost is parallelism between application threads.
Regression test: `contexts_can_be_created_and_used_concurrently` (8
threads) running alongside the other backend tests. Result: 20 of 20 runs
clean.

Follow-up: report upstream with a minimal reproducer; revisit for the 0.4
server, where requests arrive concurrently (process-per-worker is the
likely answer).

## Replaceability

The shim sits behind the backend trait. Switching to openfhe-rs later (once it
pins versions) or to another engine changes one crate.
