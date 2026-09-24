# ADR-005 — Evaluator process isolation

Status: **Accepted** (2026-09-24)

## Context

OpenFHE v1.5.1 corrupts results under concurrent use, so every call in a
process holds one mutex (ADR-001). A server needs both throughput and
failure isolation.

## Decision

`encompute-evaluator serve --workers N` runs an HTTP gateway and N worker
processes (`encompute-evaluator worker`), talking length-prefixed frames on
stdin/stdout. The gateway does no cryptography. It keeps program texts and
evaluation-key envelopes, so a worker that dies is restarted and has them
replayed; only the job it was running fails. Each worker gets
`OMP_NUM_THREADS = cores / N`. `--workers 0` keeps the in-process mode.

The per-process mutex stays. It is removed only if a stress test proves
concurrent OpenFHE use safe.

## Evidence

- `crates/encompute-evaluator/tests/workers.rs`: 24 concurrent jobs over 3
  workers; `kill -9` of every worker, after which jobs succeed again with
  programs and keys replayed.
- `docs/benchmarks.md`: 4 workers give 1.8× (search) and 2.0× (logistic)
  the in-process throughput with 8 clients.

## Consequences

Memory: each worker holds its own copy of every registered key set
(13.8 MiB per client for the search demo; hundreds of MiB for deep programs).
Keys are replayed from gateway memory on restart, so the gateway holds a
copy too.
