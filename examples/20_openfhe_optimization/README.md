# 20 — Optimized exact execution

## What this demonstrates

Exact programs compile to an `ExactPlan`: integer and Boolean instructions.
On OpenFHE BinFHE every Boolean gate is a bootstrapping of about 54 ms, so
the number of gates and how many can run at once decide the latency. This
example shows what the optimizer does to that cost and that it never
changes a result:

- **The optimized circuit.** The plan becomes a circuit of gates. Bits the
  declared input ranges rule out are dropped, public constants are folded,
  repeated subexpressions are computed once, and unused gates are removed.
  Adders and comparators use a parallel-prefix form when that finishes in
  fewer rounds. `explain` states the gate count and depth; `explain --deep`
  gives the full report.
- **Parallel gates.** The evaluator runs the independent gates of each
  level on several threads (`ENCOMPUTE_EXACT_WORKERS`, default up to 8),
  within a process-wide budget (`ENCOMPUTE_EXACT_THREADS`). The order is
  fixed, so the result bits are the same for any number of threads.
- **BGV for arithmetic.** A program whose operations are all in the BGV
  subset (u8/u16 additions, multiplications, constants and Boolean logic)
  runs as a whole on OpenFHE BGV when that is estimated no slower, which
  here is milliseconds instead of seconds. One operation outside the subset
  keeps the whole program on BinFHE; schemes are never mixed.
- **The reference lowering stays.** An evaluator started with
  `ENCOMPUTE_EXACT_EXECUTION=reference` runs the plan instruction by
  instruction. Both evaluators must return exactly the clear result.
- **Cached evaluation keys.** The 525 MiB of evaluation keys are loaded
  once. The evaluator's `GET /metrics` shows the loads, hits and entries of
  the bounded cache.

## Threat model

As in example 19, the evaluator never holds a secret key. The optimizer is
not a new trust assumption: it runs on the evaluator's own compilation of
the program, uses only the ranges the program declares (the client refuses
values outside them before encrypting), and runs only for programs that
passed the overflow analysis. The receipts, the program ID and the plan ID
do not depend on the optimizer; the job response reports the optimizer
version as provenance.

## Run it

```sh
cargo build --bins                       # explain, BGV selection, clear == mock
examples/20_openfhe_optimization/run.sh

cargo build --release --bins -p encompute-cli -p encompute-evaluator \
  --features encompute-cli/openfhe,encompute-evaluator/openfhe
BIN=target/release examples/20_openfhe_optimization/run.sh   # + encrypted
```

Without the `openfhe` build, the encrypted comparison is skipped. With it,
the run takes about two minutes and two evaluator processes each hold one
copy of the evaluation keys.

## Expected output

```text
== Compile the eligibility rule: reference lowering vs optimized circuit ==
  scheme                  BinFHE
  bootstrapped gates      533 (the same for every input; ~54 ms each on one core)
  optimized circuit       381 gates, depth 48 (optimizer v1; results equal the reference)
  parallelism             68 rounds of parallel gates with 8 workers

== Arithmetic only: the whole program is selected for BGV ==
  scheme                  BGV
  candidate BGV           ~4 ms (depth 1)  (selected)
  candidate BinFHE        ~9126 ms (169 bootstrapped gates)

== Two evaluators: optimized (default) and reference lowering ==
clear=True reference=True optimized=True MATCH
reference lowering: 38.7 s   optimized circuit: 14.0 s (includes key upload)

== Evaluation keys are cached: a second job does not reload them ==
second optimized run: 8.5 s
encompute_key_cache_hits_total 2
encompute_key_cache_loads_total 1
encompute_key_cache_entries 1
```

Times are from an Apple M3 Max (14 cores) and vary with the machine.

## Try breaking it

| Attack | Result |
|---|---|
| An age of 121, where the program declares [0, 120] and the optimizer dropped the bits above | refused before encryption: ENC1102 |
| `income * 1_000_000` in a u32 program | refused at compile time: ENC1303; no circuit is built |

## What Encompute guarantees

- Optimized, reference, mock and clear execution return the same bits for
  every input inside the declared ranges.
- The same plan, ranges and thread count build the same circuit.
- BGV is chosen only when every operation is supported, and never over a
  security or verification requirement.
- A ciphertext only ever runs under the evaluation keys its envelope is
  bound to, even though keys are cached and shared across programs.

## What Encompute does NOT guarantee

- The estimated times are calibrated on one machine; they order the
  candidates, they do not promise a latency.
- The optimizer does not reduce the evaluation-key size or key generation
  time.
- Functional bootstrapping (lookup tables in one bootstrapping) was
  measured and is not used: on these programs it is slower than gates
  (see docs/benchmarks.md).

## Relevant source modules

- `crates/encompute-exact/src/circuit.rs`: ranges, the circuit builder,
  simplification, strategies and parallel execution.
- `crates/encompute-exact/src/bits.rs`: ripple and parallel-prefix adders
  and comparators.
- `crates/encompute-evaluator/src/cost.rs`: the calibrated BinFHE and BGV
  estimates and the selection rule.
- `crates/encompute-evaluator/src/keycache.rs`, `budget.rs`: the key cache
  and the thread budget.
