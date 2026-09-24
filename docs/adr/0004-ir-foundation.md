# ADR-004 — Veil IR: custom Rust IR or MLIR

Status: **Accepted** (2026-09-24): option A, custom Rust IR, MLIR-exportable.

## Options

**A. Custom Rust IR, MLIR-exportable (recommended).** SSA graph in `veil-ir`,
plain Rust types, serde, textual `.vlir`. An MLIR text exporter is added at
0.2 for the HEIR benchmark (ADR-002).

**B. MLIR from day one.** Veil dialect defined in MLIR (TableGen/C++), driven
from Rust through `melior` or the MLIR C API, or Veil written as an MLIR/HEIR
project in C++.

## Assessment

| | A: custom Rust | B: MLIR |
|---|---|---|
| v0.1 IR size | ~20 tensor-level ops, no regions: 1–2k LOC | dialect + TableGen + C++ passes + bindings |
| Build | `cargo build` | pinned LLVM/MLIR build (tens of minutes, GBs); HEIR pins its own LLVM commit via Bazel, so sharing HEIR's build is not automatic |
| Python wheel | small | embeds MLIR, or requires it installed |
| Rust bindings | native | `melior` / C API: partial, version-locked to LLVM |
| HEIR interop | textual MLIR export (0.2) | native, if the LLVM versions match |
| Ecosystem passes (CSE, canonicalize, DCE) | write our own (small at v0.1 size) | free |
| Hiring / contributors | Rust | MLIR C++ (rarer) |
| Reversal cost | bounded, if the constraints below hold | high: MLIR types reach every pass |

The decisive points:

1. v0.1's IR is small and its analyses (privacy, range, depth, precision) are
   Veil-specific. MLIR's free passes are the generic ones.
2. The one thing MLIR would give — HEIR interop — is deferred to 0.2 by ADR-002
   and can go through textual MLIR, which is how HEIR's own frontends connect.

## Constraints if A is chosen

These keep option B, or a HEIR export, cheap later:

- Every Veil op documents its lowering to upstream MLIR (`arith`, `tensor`,
  `linalg`) wrapped in HEIR's `secret.generic`.
- SSA values, typed operands, no implicit state. Attributes (range, precision,
  visibility) are plain data that can be written as MLIR attributes.
- No control flow in v0.1 IR (no regions), matching the tracing frontend.
- Passes operate on `veil-ir` through a small visitor API, not by reaching into
  internal representation.
- The 0.2 HEIR benchmark includes a round trip: `veil export --mlir` → HEIR →
  OpenFHE, with differential tests against native lowering.

## Revisit triggers

- 0.2 HEIR benchmark shows HEIR lowering should become the default path.
- The IR needs regions or control flow (loops over secrets, SQL) earlier than planned.
- A second compiler frontend (ONNX, JAX) whose MLIR importer would be reused.
