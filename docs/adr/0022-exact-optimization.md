# ADR-022 — Optimized exact execution and backend selection

Status: **Accepted** (2026-09-27)

## Context

Exact programs run on OpenFHE BinFHE: one ciphertext per bit and a
bootstrapping of about 54 ms per gate. The reference lowering evaluated the
plan instruction by instruction, one gate at a time, behind a process-wide
lock. It used full-width arithmetic whatever the declared ranges, so a
realistic rule took about a minute. Evaluation keys (about 525 MiB) were
deserialized for each program session and never bounded. Arithmetic-only
programs, which BGV evaluates in milliseconds, still paid for every gate.

## Decision

1. **Plans become circuits; the reference lowering stays the oracle.**
   - The evaluator builds a gate circuit from its own compilation of the
     program (`encompute_exact::circuit`).
   - It folds public constants and bits the declared input ranges rule out,
     simplifies Boolean identities, reuses common subexpressions, removes
     dead gates, and chooses between ripple and parallel-prefix adders and
     comparators by rounds, then gates.
   - The reference lowering is unchanged and selectable
     (`ENCOMPUTE_EXACT_EXECUTION=reference`). Tests hold the optimized
     circuit equal to it, bit for bit.
2. **Optimization adds no trust assumption.**
   - Ranges come only from the declared input ranges, which the client
     enforces before encrypting. Circuits are built only for plans that
     passed overflow analysis.
   - Program, plan and transcript IDs, and receipts, do not depend on the
     optimizer. Its version is provenance: in the job response and in
     `explain`.
3. **Parallel gates are deterministic and bounded.**
   - Each level's independent gates run on a fixed partition of threads,
     using OpenFHE's gate evaluation without the global lock and one OpenMP
     thread per worker.
   - Threads come from a process budget (`ENCOMPUTE_EXACT_THREADS`), at most
     `ENCOMPUTE_EXACT_WORKERS` per job. A job waits for threads rather than
     oversubscribing the machine.
4. **One scheme per program, chosen by calibrated cost.**
   - An unverified program runs on BGV only if every operation is in the
     BGV subset and its estimated time is no larger than BinFHE's; ties go
     to BGV. Otherwise it runs on BinFHE. Schemes are never mixed, and
     nothing converts between them.
   - Verification and correctness requirements are checked before cost.
     Verified programs keep BGV with re-execution proofs.
   - The compiler and the planner use the same estimates and the same rule.
     The BinFHE estimate uses the reference gate count, so the choice does
     not move with the optimizer. The constants live in
     `crates/encompute-evaluator/src/cost.rs`, and the calibration is in
     `docs/benchmarks.md`.
5. **Evaluation keys are cached, bounded and isolated.**
   - Keys are loaded once per process into a least-recently-used cache
     bounded by `ENCOMPUTE_KEY_CACHE_BYTES`. OpenFHE exact keys do not
     depend on the program and are shared read-only by concurrent jobs.
   - A session uses only keys registered with it, and a ciphertext runs
     only under the key its envelope is bound to. An evicted key is
     reported missing, and the client uploads it again.
   - Hits, misses, loads, evictions and bytes are exported on the
     evaluator's `GET /metrics`.
6. **Functional bootstrapping is not used.** We measured lookup-table
   bootstrapping on OpenFHE BinFHE. At 8 workers it is 3 to 5 times slower
   than gates for 8-bit add, compare and select, and it needs 9 to 17 times
   larger keys.

## Consequences

- On the benchmark corpus, with 8 workers, exact programs run 1.7 to 9.4
  times faster, and every result matches the clear interpreter.
  `bench_baseline` fails the build if a gate count, depth or round count
  grows.
- Arithmetic-only programs take milliseconds on BGV instead of seconds.
- An evaluator's memory for keys is bounded; a client may need to upload
  keys again after an eviction.
- The optimized path and the reference path must both be maintained. The
  reference path is the definition of correct.

## Alternatives considered

- **Cross-scheme conversion (BGV to BinFHE within a program).** Rejected:
  it adds a new key-switching surface and a hard-to-audit precision
  boundary, for gains that whole-program selection already captures.
- **Optimizing inside the client's plan.** Rejected: the evaluator must not
  trust the client's compilation, and plan IDs must not depend on an
  optimizer version.
- **GPU or other FHE libraries.** Out of scope; TFHE-rs stays research-only.

## Relevant source modules

- `crates/encompute-exact/src/circuit.rs`, `bits.rs`
- `crates/encompute-openfhe/cpp/binfhe.cc` (concurrent gates)
- `crates/encompute-evaluator/src/session.rs`, `budget.rs`, `keycache.rs`,
  `cost.rs`, `server.rs` (`/metrics`)
- `crates/encompute-planner/src/planner.rs`
- `benches/exact/`, `crates/encompute-exact/tests/bench_baseline.rs`
