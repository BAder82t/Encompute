# Exact performance corpus

Representative exact (integer and Boolean) programs, in the IR text form,
used to measure and gate the performance of exact execution on OpenFHE
exact (BinFHE). Every program compiles (`encompute_exact::compile`), and
every input declares a realistic range: the optimizer uses those ranges to
drop bits proven constant, so the ranges are part of the benchmark.

| program | what it exercises |
|---|---|
| `boolean_policy` | 12 Boolean facts combined by `and`, `or`, `xor`, `not` (no integers) |
| `cmp_u8` | `lt`, `le`, `eq` between two full-range `u8`s, `gt`/`ne` against a constant |
| `cmp_u16` | the same on `u16`s in `[0, 50000]` |
| `cmp_u32` | the same on `u32`s in `[0, 3e9]` |
| `eligibility` | `examples/02_exact_private_logic/eligibility.py`: age, debt-to-income (`u32` products), risk |
| `range_check` | a fixed band, a band with private bounds, and an alarm outside a safe band |
| `min_max` | `min`/`max` of four `u16` bids and a clamp |
| `lookup_small` | two 16-entry tables: one on a `u8` in `[0, 15]`, one on the top 4 bits of a score |
| `lookup_large` | a 256-entry unstructured table (the AES S-box) on a private byte |
| `arith_scoring` | weighted sum of six `u16` features with public weights, in `u32` |
| `const_arith` | constant-heavy `u32` arithmetic: affine map, `x * 100 / 7`, `% 1000`, reflection, masked shift |
| `branch_logic` | nested `select`s deciding a fee and a routing code |
| `mixed` | a secret × secret order total, a volume discount (`* 9 / 10`) and a budget comparison |
| `golden_eligibility` | **golden**: loan eligibility (age band, debt-to-income, risk, employment, defaults) and a reason code |
| `golden_policy` | **golden**: private access-policy evaluation, many Boolean conditions and a decision code via `select` |
| `golden_scoring` | **golden**: an exact credit score, arithmetic-heavy with two divisions and one clamp |

The three `golden_*` programs are the commercial golden benchmarks; the
nightly conformance workflow times them on OpenFHE.

## Stable quantities and the regression gate

`baseline.json` records, per program, the reference gate count and the
optimized circuit's gates, NOTs, depth, width, rounds, input bits and
optimizer counters at 1 and 8 workers. They are properties of the program
and the optimizer, identical on every machine.

```sh
cargo run --release -p encompute-exact --example exact_stats        # print them
cargo test -p encompute-exact --test bench_baseline                  # the gate
ENCOMPUTE_UPDATE_BASELINE=1 cargo test -p encompute-exact --test bench_baseline   # accept an improvement
```

The gate fails if any optimized gate count, depth, rounds(8) or active
input bits grew, or if a program was added or removed without
regenerating the baseline. It also checks that the optimized circuit
never needs more rounds at 8 workers than the reference circuit, that the
reference strategy never needs more gates than the reference lowering, and
that every optimized circuit computes what the clear interpreter does on
in-range inputs (boundaries included).

## Timed runs and the published history

```sh
OPENFHE_ROOT=$PWD/.deps/openfhe cargo run --release -p encompute-openfhe-client \
    --example exact_bench -- [--golden] [--workers 1,2,4,8] [PROGRAM...]
```

Each run appends one JSON line per program to `history.jsonl`: time,
git commit, machine, OpenFHE version, optimizer version, and compile,
key generation, encryption, reference and optimized evaluation (per
worker count), decryption times, request and response sizes, evaluation
key size and peak RSS. Results are decrypted and checked against the
clear interpreter. Commit the new lines to publish them.
