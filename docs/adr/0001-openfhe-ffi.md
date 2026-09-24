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

## Finding: OpenFHE context creation is not thread-safe

Two threads calling `GenCryptoContext` at the same time corrupt the heap
(EXC_BAD_ACCESS in `ParameterGenerationCKKSRNS::ParamsGenCKKSRNSInternal`
and in a `std::map` insert). Reproduced on OpenFHE v1.5.1, macOS arm64:
4 of 5 parallel test runs crashed.

Mitigation in `cpp/shim.cc`: a process-wide `std::shared_mutex`. Context
creation takes it exclusively; every other call takes it shared, so no call
reads the global precomputation tables while another thread writes them.
Regression test: `contexts_can_be_created_and_used_concurrently` (8 threads).
Result: 20 of 20 runs clean.

Consequence: context creation is serialized process-wide. That is acceptable
because contexts are long-lived. Revisit if a server needs to create many
contexts under load.

## Replaceability

The shim sits behind the backend trait. Switching to openfhe-rs later (once it
pins versions) or to another engine changes one crate.
