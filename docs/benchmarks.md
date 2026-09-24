# Benchmarks

Machine: Apple Silicon (arm64), 14 cores, macOS; OpenFHE v1.5.1 static,
OpenMP. Numbers are from one run; rerun with the commands shown.

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
