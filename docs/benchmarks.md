# Benchmarks

Machine: Apple Silicon (arm64), 14 cores, macOS; OpenFHE v1.5.1 static,
OpenMP. Numbers are from one run; rerun with the commands shown.

## Workloads (0.2 P5)

`cargo run --release --features openfhe -p encompute-runtime --example suite`

Encrypted on OpenFHE, client and evaluator in one fresh process per
workload. Times are medians of 5 runs; error is over 20 sampled inputs
(range endpoints first). Sizes are the envelopes that cross the network.
Target error 1e-3 for all.

| workload | N | depth | rot keys | compile ms | keygen ms | encrypt ms | eval ms | decrypt ms | eval keys MiB | request MiB | response MiB | peak RSS MiB | max abs err | max rel err |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| scalar_arith | 8192 | 2 | 0 | 0.2 | 162 | 13.2 | 12.4 | 4.9 | 1.50 | 0.75 | 0.25 | 37 | 2.8e-7 | 9.2e-7 |
| dot_1024 | 8192 | 1 | 10 | 0.1 | 395 | 7.4 | 27.4 | 6.8 | 8.26 | 0.25 | 0.25 | 94 | 2.8e-7 | 1.8e-6 |
| matvec_128x128 | 8192 | 1 | 22 | 1.0 | 543 | 7.3 | 93.7 | 7.2 | 17.26 | 0.25 | 0.25 | 177 | 4.3e-7 | 2.1e-4 |
| logistic_32 | 16384 | 7 | 5 | 1.0 | 1523 | 54.3 | 302.2 | 23.6 | 45.02 | 2.00 | 0.50 | 432 | 4.8e-4 | 1.3e-3 |
| similarity_384x64 | 8192 | 1 | 17 | 1.9 | 431 | 6.3 | 68.2 | 6.7 | 13.51 | 0.25 | 0.25 | 150 | 2.7e-7 | 1.0e-4 |

Relative error is |error| / max(|expected|, precision). Logistic's error is
dominated by the Chebyshev sigmoid approximation (degree chosen for half the
budget); the others are CKKS noise only.

## Evaluator concurrency (0.2 P4)

`cargo run --release --features openfhe -p encompute-runtime --example concurrency -- target/release/encompute-evaluator MODEL JOBS 8`

8 concurrent clients over HTTP on localhost. Each worker process gets
`OMP_NUM_THREADS = cores / workers`. Peak RSS is per evaluator process.

**Search** (384-d query vs 64 documents, N = 8192, depth 1), 64 jobs:

| Evaluator | jobs/s | p50 ms | p95 ms | peak RSS |
|---|---|---|---|---|
| in-process (OpenFHE serialized) | 14.1 | 491 | 840 | 92 MiB |
| 1 worker process | 15.1 | 510 | 667 | 83 MiB |
| 2 worker processes | 18.2 | 443 | 551 | 76 MiB |
| 4 worker processes | 25.0 | 287 | 407 | 87 MiB |

**Logistic** (32 features, sigmoid, N = 16384, depth 8), 32 jobs:

| Evaluator | jobs/s | p50 ms | p95 ms | peak RSS |
|---|---|---|---|---|
| in-process | 3.4 | 2185 | 3109 | 297 MiB |
| 1 worker process | 4.3 | 1665 | 1831 | 279 MiB |
| 2 worker processes | 5.3 | 1396 | 1446 | 291 MiB |
| 4 worker processes | 6.8 | 976 | 1502 | 287 MiB |

Caveat: the 8 benchmark clients share one process, whose client-side
OpenFHE calls (encrypt, decrypt) are also serialized. Real clients are
separate processes, so the evaluator scales further than shown.

## Exact programs on TFHE-rs (0.3 P7, research feature)

Apple M3 Max, 14 cores; TFHE-rs 1.8.1, profile
`PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`.

Keys: generation 0.9 s; compressed server key 57.4 MiB (uploaded once per
client), decompressed on the evaluator in 0.44 s; client key 30.7 KiB.

Per operation, milliseconds, median of 3
(`cargo run --release -p encompute-tfhe-client --features tfhe-rs --example exact_ops`):

| type | ciphertext | encrypt | decrypt | add | mul | mul by const | compare | compare to const | and | select | min | div by const | shift | lookup (16) | cast (widen) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| u8 | 65 KiB | 0 | 0 | 199 | 436 | 250 | 112 | 75 | 33 | 170 | 247 | 813 | 0 | 369 | 0 |
| u16 | 129 KiB | 1 | 0 | 242 | 1132 | 335 | 182 | 87 | 150 | 271 | 167 | 1626 | 0 | 423 | 0 |
| u32 | 258 KiB | 2 | 0 | 481 | 3957 | 692 | 265 | 204 | 154 | 485 | 736 | 3603 | 0 | 1115 | 0 |
| u64 | 516 KiB | 4 | 1 | 1047 | 15075 | 1171 | 597 | 346 | 312 | 1017 | 1278 | 9282 | 0 | 2076 | 0 |
| i8 | 65 KiB | 1 | 0 | 201 | 425 | 231 | 165 | 127 | 65 | 81 | 312 | 1316 | 0 | 474 | 45 |
| i16 | 129 KiB | 1 | 0 | 296 | 1375 | 404 | 223 | 137 | 94 | 154 | 516 | 1853 | 0 | 874 | 45 |
| i32 | 258 KiB | 2 | 0 | 641 | 4877 | 800 | 283 | 203 | 167 | 568 | 923 | 6747 | 0 | 1286 | 45 |
| i64 | 516 KiB | 5 | 0 | 1180 | 17313 | 1429 | 571 | 311 | 314 | 1013 | 1648 | 9609 | 0 | 2293 | 0 |

Shifts by a constant and widening casts of unsigned values are free
(block moves, no bootstrap). Multiplication and division grow roughly with
the square of the width: choose the narrowest type range analysis allows.

Eligibility example end to end (`scripts/exact-demo.sh`, separate evaluator
process, u8/u16/u32 inputs, 11 plan instructions): request 709 KiB,
response 16 KiB, evaluation 2.1 s.

Semantic transcript of the eligibility plan (8 instructions): built and
hashed in ~70 µs (release), against ~2 s of TFHE-rs evaluation: far below 1 %.
