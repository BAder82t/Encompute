# ADR-002 — HEIR integration

Status: **Deferred to 0.2**

## Decision

v0.1 lowers Encompute IR directly to the OpenFHE backend (`encompute-ckks` →
`encompute-openfhe`). HEIR is not in the v0.1 build or critical path.

v0.1 packing is intentionally modest:

- fixed 1-D SIMD layout, one vector per ciphertext;
- rotation discovery for `sum`, `dot`, `matvec`, and generation of exactly
  those rotation keys;
- `matvec` by the diagonal method.

## Why

HEIR already has CKKS → OpenFHE lowering, parameter and noise analysis, and a
layout system (`layout-propagation`, `layout-optimization`), so Encompute should not
compete with it on packing. But HEIR is still changing quickly, including open
2026 work on OpenFHE sparse packing and layout mismatches in large CKKS
workloads. Depending on it in M0 would tie Encompute's schedule to HEIR's.

## 0.2 review

Benchmark native lowering against HEIR on the v0.1 demos plus one larger
workload. Compare: rotations, ciphertext count, depth, bootstraps, runtime,
compile time, memory, generated key material, implementation LOC and
maintenance burden.

If HEIR wins, the pipeline becomes:

```text
Encompute IR → Encompute privacy/range passes → MLIR export → HEIR → OpenFHE
```

Encompute keeps what sits above HEIR: privacy types, range inference, the developer
API, cost objectives, deployment, KMS, observability and backend planning.

## Constraint on v0.1

Encompute IR must stay backend-neutral enough to be exported to HEIR's input
dialects without changing the Python API. See ADR-004.
