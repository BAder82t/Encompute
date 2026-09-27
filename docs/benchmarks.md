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

## Exact programs on OpenFHE exact (production)

Apple M3 Max, 14 cores; OpenFHE 1.5.1 BinFHE, parameter set STD128 with
GINX bootstrapping (profile `BINFHE_STD128_GINX_BITS_V1`: 128-bit, failure
probability 2^-135 per gate). One ciphertext per bit; every AND, OR and XOR
is a bootstrapped gate, NOT and constants are free.

| | |
|---|---|
| secret key generation | 0.42 s |
| evaluation keys (bootstrapping 109 MB + key switching 440 MB) | 524 MiB, generated and written in ~7 s, uploaded once per client |
| secret key on disk | 4.8 KiB |
| ciphertext | 4.4 KiB per bit (u8 35 KiB, u32 141 KiB) |
| bootstrapped gate | 62 ms (one core; OpenFHE calls are serialized) |
| encrypt, decrypt | < 1 ms per bit |

Bootstrapped gates per operation, after constant folding
(`cargo run --release -p encompute-exact --example gate_counts`). They do
not depend on the inputs; time ≈ gates × 62 ms. `explain` prints a
program's total.

| operation | u8 | u16 | u32 | i32 | u64 |
|---|---:|---:|---:|---:|---:|
| add | 34 | 74 | 154 | 154 | 314 |
| sub | 35 | 75 | 155 | 155 | 315 |
| mul | 136 | 648 | 2824 | 2824 | 11784 |
| mul by constant 100 | 13 | 93 | 253 | 253 | 573 |
| div by constant 7 | 124 | 292 | 628 | 981 | 1300 |
| compare to constant (lt) | 12 | 28 | 60 | 59 | 124 |
| eq | 15 | 31 | 63 | 63 | 127 |
| lt | 31 | 63 | 127 | 127 | 255 |
| min | 55 | 111 | 223 | 223 | 447 |
| select (after its condition) | 24 | 48 | 96 | 96 | 192 |
| and (bitwise) | 8 | 16 | 32 | 32 | 64 |
| shift by a constant, cast | 0 | 0 | 0 | 0 | 0 |

Lookups are multiplexer trees over the index bits (tables up to 256
entries); their cost depends on the table and folds heavily for structured
tables.

Eligibility example end to end (`scripts/exact-demo.sh`, separate evaluator
process, u8/u16/u32 inputs, 533 gates): request 387 KiB, response 4 KiB,
evaluation 30 s, key upload 524 MiB once.

OpenFHE exact is roughly 10–15× slower than TFHE-rs's multi-bit integer
operations below, and its evaluation keys are about 9× larger. It is the
production backend because it carries no patent-license restriction on
commercial use. Parallel gate evaluation is the speed-up; functional
bootstrapping was measured and not adopted (see the last section).

## Exact programs on TFHE-rs (research feature, never in commercial builds)

Apple M3 Max, 14 cores; TFHE-rs 1.8.1, profile
`PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`.

Keys: generation 0.9 s; compressed server key 57.4 MiB (uploaded once per
client), decompressed on the evaluator in 0.44 s; client key 30.7 KiB.

Per operation, milliseconds, median of 3
(`cargo run --release -p encompute-tfhe-client --features research-tfhe-rs --example exact_ops`):

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

Eligibility example end to end (research build, separate evaluator
process, u8/u16/u32 inputs, 11 plan instructions): request 709 KiB,
response 16 KiB, evaluation 2.1 s.

Semantic transcript of the eligibility plan (8 instructions): built and
hashed in ~70 µs (release), against ~2 s of TFHE-rs evaluation: far below 1 %.

## Verified execution (research)

Loan pre-check (4 inputs, 6 instructions: u16 `* + −`, Boolean `& ~`),
OpenFHE BGV (t = 65537), Apple M3 Max, release, median of 5:

| | |
|---|---|
| evaluation (evaluator) | 24 ms |
| verification: re-execution + decryption (client) | 65 ms (2.7×) |
| proof | 543 bytes (header only) |
| verification key (the client's evaluation keys) | 769 KiB |
| request / response | 1027 KiB / 514 KiB |

Re-execution is sound but not succinct: the verifier redoes the work.

## Confidential LoRA fine-tuning

`examples/15_confidential_lora`: two hospitals and ModelCo; a tiny transformer
classifier (vocabulary 64, width 16); LoRA rank 4 on `q` and `v` (256
adapter parameters); 2 rounds of 10 local steps; development attestation.
Every party runs as a separate process on one Apple M3 Max. Debug build,
3 runs:

| Stage | Seconds |
|---|---|
| plain PyTorch, one party's local steps (the baseline) | 0.50–0.63 |
| workers attest and receive the model key; open, check and build the model | 1.05–1.11 |
| 2 rounds: local training, secure aggregation, DP release (coordinator and joins) | 5.81–5.86 |
| sealed adapters and checkpoints | 0.01 |
| adapter records into the trust graph | 0.04–0.05 |
| total | 8.36–8.38 |

For this model, the secure-aggregation round trips dominate: process start
and four protocol stages per round, on one machine. Nothing is optimized
yet; these numbers are a baseline. Real TEEs add hardware attestation and
key-release latency that the mock does not show.

## Patient-level DP-SGD

Per-example gradients for the same tiny classifier (LoRA rank 4 on `q` and
`v`, 256 adapter parameters), 64 records of 32 patients, CPU, Apple M3 Max,
mean of 20 runs:

| Gradient | Milliseconds |
|---|---|
| plain batch gradient (no per-example clipping) | 0.83 |
| per-example, `vmap` over `grad`, microbatch 64 | 2.16 |
| per-example, `vmap` over `grad`, microbatch 8 | 8.44 |
| per-example, one autograd call per record (the test reference) | 18.03 |

`examples/16_patient_private_lora`: two hospitals of 1,000 patients (2,000
records each), sampling rate 0.032, the same model. Seconds per round,
including secure aggregation and the DP release, all parties on one
machine, debug build:

| Privacy | Seconds per round | ε used (per hospital) | Held-out accuracy |
|---|---|---|---|
| organization (10 local steps, whole-update clip) | 2.8 | 6.34 of 8 after 2 rounds | 0.38 → 0.43 |
| patient (DP-SGD, one step) | 2.6 | 1.75 of 3 after 20 rounds | 0.38 → 0.73 |

The per-example gradients are a small part of a round; the protocol's round
trips dominate. Accuracy regression bound (`test_dpsgd.py`): with
strong-patient noise, simulated DP-SGD stays within 0.1 of the same training
without noise (about 0.76).

## Hugging Face + PEFT

`examples/17_huggingface_peft`:
- the model: a tiny BERT (2 layers, width 32), PEFT LoRA rank 4 on
  `query` and `value` plus the trained head (1,090 adapter parameters);
- the data: two hospitals of 2,000 patients (4,120 tokenized records
  each);
- privacy: patient-level DP-SGD at sampling rate 0.05, 20 rounds;
- setup: development attestation, all parties on one Apple M3 Max, debug
  build.

| Stage | Seconds |
|---|---|
| plain PyTorch + PEFT, one local step (the baseline) | 0.02 |
| workers attest, load Transformers, pick the gradient path | 2.6 |
| 20 rounds: per-patient gradients, secure aggregation, DP release | 57.5 |
| sealed checkpoints and adapters | 0.24 |
| adapter records into the trust graph | 0.71 |
| total | 62.6 |

Results:
- Held-out accuracy goes from 0.77 (the base model) to 0.96, at ε 2.57 of
  3 (δ 1e-6).
- The exported PEFT adapter, loaded with plain Transformers and PEFT,
  matches Encompute's attested inference to 1e-6.
- About 2.9 s per round, as for the reference model: the protocol's round
  trips dominate, not the per-patient gradients.

## Confidential training jobs (Confidential Space)

One participant's job from `examples/18_confidential_space_hf`:
- the model: a tiny BERT with PEFT LoRA (1,090 adapter parameters);
- the data: 300 patients (600 notes);
- one patient-level DP-SGD step;
- measured by the worker itself (`timings.json`).

| Stage | Local (macOS arm64, simulated launcher) | Container (Linux arm64 image, simulated launcher) |
|---|---|---|
| attestation and key release (one attestation, four grants) | 0.05 s | 0.03 s |
| sealed asset download | < 0.01 s | < 0.01 s |
| decryption | 0.04 s | < 0.01 s |
| model loading and gradient-path probe | 4.7 s | 0.6 s |
| training step (per-patient gradients) | 0.02 s (vectorized) | 0.59 s (one patient at a time) |
| output sealing | < 0.01 s | < 0.01 s |
| total in the worker | 4.8 s | 1.3 s |

In the container, this PyTorch build's vectorized gradients disagreed with
the reference by 1.5%. The probe chose the one-patient-at-a-time path:
slower, with the same privacy.

**Live Confidential Space: pending a GCP run.** `deploy.sh` records VM
startup, image build, staging, time to evidence and verification in
`deploy-timings-*.json`, and the worker's per-stage `timings.json`. The
setup is a `c3-standard-4` TDX VM (about $0.25 an hour in `us-central1`);
a run is expected to cost well under a dollar.

## Functional bootstrapping (LUTs): measured, not adopted

Question: would OpenFHE BinFHE functional bootstrapping (`EvalFunc` on a
lookup table over a small plaintext modulus p, or `EvalSign` on a wide
value) beat the production Boolean gates for 8-bit add, compare and select?
Answer: no. A LUT costs 8.5 to 28 times a gate, and an 8-bit operation
needs only 3 to 10 times fewer LUTs than gates (p = 8 or 16), not
enough to make up for it. Keys also grow about ten-fold.

Measured with `scripts/lut-measure.sh` (a standalone C++ program,
`crates/encompute-openfhe/bench/lut_measure.cc`, built against the same
static OpenFHE 1.5.1; not part of any Encompute build). Apple M3 Max,
14 cores, 36 GiB. Median of 10 single-thread runs (one OpenMP thread),
then 24 operations on 8 concurrent workers with one OpenMP thread each.
Every result was decrypted and checked: 0 wrong of 34 per row (too few to
say anything about failure probability). **Caveat:** other jobs kept the
machine at a load average of 28 to 100 during the runs. Absolute times are
inflated and noisy, and the 8-worker figures most of all. The ratios
between rows run back to back are the robust result.

Parameters. The production gate uses STD128 with GINX (n = 556, N = 1024,
q = 2048). OpenFHE's arbitrary-function variant of STD128
(`GenerateBinFHEContext(STD128, true, 12, N)`) uses n = 1305,
key-switching modulus 2^35, a 54-bit bootstrapping modulus Q split into
2 digits, and q = N, so p ≤ N/256. The ring dimension N comes from the
HE standard's 128-bit classical table (ternary secrets); N = 2048 allows
p ≤ 8, and p = 16 needs N = 4096. OpenFHE labels these sets 128-bit but
publishes no failure probability for them; the gate set's is 2^-135.
An arbitrary (non-negacyclic) table costs OpenFHE two bootstraps
(`EvalFunc` first reduces the input to half the range).

| operation | n / N | keygen (one thread) | refresh key | switching key | one thread, median (min–max) | 8 workers, wall per op |
|---|---|---:|---:|---:|---:|---:|
| gate AND (production) | 556 / 1024 | 0.43 s | 105 MiB | 420 MiB | 62.5 ms (59–73) | 18.2 ms |
| LUT, p = 4 | 1305 / 2048 | 6.0 s | 164 MiB | 4579 MiB | 530 ms (350–1070) | 80.9 ms |
| LUT, p = 8 | 1305 / 2048 | 10.3 s | 164 MiB | 4579 MiB | 577 ms (419–1270) | 208 ms |
| LUT, p = 8 (rerun) | 1305 / 2048 | 8.6 s | 164 MiB | 4579 MiB | 539 ms (391–633) | 76.3 ms |
| LUT, p = 16 | 1305 / 4096 | 16.9 s | 327 MiB | 9158 MiB | 1937 ms (1115–2104) | 194 ms |
| `EvalSign`, 17-bit modulus (p = 512) | 1305 / 2048 | 8.5 s | 327 MiB | 4579 MiB | 1721 ms (1122–2619) | 398 ms |
| gate AND, same run as p = 16 | 556 / 1024 | 0.62 s | 105 MiB | 420 MiB | 71.0 ms (67–123) | 20.6 ms |

Peak memory: 5.8 GiB for the p ≤ 8 runs and 10.0 GiB with p = 16, against
well under 1 GiB for the gate set. The switching key alone is 4.5 GiB at
N = 2048, and every client would upload it.

**Cost of 8-bit operations.** Gates, depth and rounds come from the
optimized circuit (`circuit::optimize`, 1 and 8 workers). For LUTs, an
8-bit value is split into radix-2^k digits, with p ≥ 2^(k+1) so that a
digit sum with its carry fits:
- add: ripple carry, one carry LUT and one digit LUT per digit;
- lt: ripple borrow, one LUT per digit;
- select: per digit, `c ? x : 0` and `c ? 0 : y` (linear sum), or one LUT
  when p ≥ 2^(k+2).

Linear steps (sums, constants) are free. Time = count × the median
latency above, one thread; with 8 workers, rounds × the same latency (a
lower bound for LUTs, since concurrency slows each LUT more than it slows a
gate).

| 8-bit op | gates (1 w.) | gate rounds (8 w.) | LUT p = 4: LUTs / rounds | LUT p = 8: LUTs / rounds | LUT p = 16: LUTs / rounds |
|---|---:|---:|---:|---:|---:|
| add | 34 | 8 (49 gates, depth 7) | 15 / 8 | 7 / 4 | 5 / 3 |
| lt | 31 | 9 (35 gates, depth 8) | 8 / 8 | 4 / 4 | 3 / 3 |
| select (condition given) | 24 | 3 (depth 3) | 16 / 2 | 8 / 1 | 4 / 1 |

| 8-bit op | gates, 1 thread | gates, 8 workers | best LUT, 1 thread | best LUT, 8 workers |
|---|---:|---:|---:|---:|
| add | 2.1 s | 0.50 s | 4.0 s (p = 8) | 2.3 s (p = 8) |
| lt | 1.9 s | 0.56 s | 1.7 s (`EvalSign`, packed input) / 2.3 s (p = 8) | 1.7 s (`EvalSign`) |
| select | 1.5 s | 0.19 s | 4.6 s (p = 8) | 0.58 s (p = 8) |

**Verdict: not adopted.** LUTs lose on every operation with 8 workers, by
3 to 5 times, and on add and select with one thread, by 2 to 3 times. For
an 8-bit add to break even, a LUT would have to cost under 5 gates; it
costs 8.5 to 9.2 at p ≤ 8 and about 27 at p = 16. The single near-tie,
`EvalSign` for a comparison on one thread, needs its input packed at a
17-bit modulus, which the rest of a gate or LUT circuit does not produce.
LUTs would also make the client's upload about ten times larger (4.6 GiB
instead of 525 MiB) and key generation 14 to 27 times slower. The cost
is structural: OpenFHE's arbitrary-function parameters (n = 1305, a 54-bit
Q in 2 digits) make each bootstrap several times heavier, and an arbitrary
table takes two of them. Parallel Boolean gates remain the production path.
Revisit if OpenFHE gains a multi-value or cheaper functional bootstrap
for 128-bit sets.
