# Performance

Realistic numbers for each flagship workload, so you can judge what
Encompute costs before you try it. Every number here comes from a
measurement already published in [benchmarks.md](benchmarks.md), the
exact benchmark history [benches/exact/history.jsonl](../benches/exact/history.jsonl),
or an example's README. Where nothing was measured, the table says
**not yet measured**. Nothing is estimated here unless it says so.

Read these numbers with three caveats:

- **One machine type.** Almost every number is from an Apple M3 Max
  laptop (14 cores, macOS, arm64). No server CPU, no Linux x86_64 machine
  and no real TEE has been benchmarked yet.
- **Mostly single runs.** Timings vary run to run, by up to 2× on a busy
  machine. Gate counts, depths, and key and ciphertext sizes do not vary.
- **Small models.** The AI workloads use tiny models (a transformer of
  width 16, a 2-layer BERT of width 32) to exercise the protocol. Nothing
  here says how a production-size model performs.

Reproduce commands are in [benchmarks.md](benchmarks.md).

## Summary

| Workload | Backend | Evaluation | Evaluation keys | Status |
|---|---|---|---|---|
| CKKS logistic regression, 32 features | OpenFHE CKKS | 302 ms | 45 MiB | Supported |
| CKKS 128×128 matrix–vector | OpenFHE CKKS | 94 ms | 17 MiB | Supported |
| Exact eligibility rule (381 gates) | OpenFHE exact (BinFHE) | 31.1 s on 1 worker, 7.8 s on 8 | 525 MiB | Supported |
| Exact arithmetic-only program | OpenFHE BGV | milliseconds (estimated ~4 ms) | not yet measured | Supported subset |
| Verified loan pre-check | OpenFHE BGV + re-execution | 24 ms, verification 65 ms | 769 KiB | Research only |
| Confidential LoRA, 2 hospitals, 2 rounds | PyTorch + SecAgg + DP, mock TEE | 8.4 s total | n/a | Supported subset |
| Patient-level DP-SGD, 2 hospitals | PyTorch + SecAgg + DP, mock TEE | 2.6 s per round | n/a | Supported |
| Hugging Face BERT + PEFT, 20 rounds | Transformers + PEFT + SecAgg + DP, mock TEE | 62.6 s total | n/a | Supported subset |
| Confidential Space training job, one participant | Transformers + PEFT, simulated launcher | 1.3–4.8 s in the worker | n/a | Experimental |

## Approximate programs on OpenFHE CKKS

Hardware: Apple Silicon (arm64), 14 cores, macOS; OpenFHE 1.5.1 static,
OpenMP. Client and evaluator in one fresh process per workload. Medians
of 5 runs. Sizes are the envelopes that cross the network. Target error
1e-3. Source: [benchmarks.md, Workloads](benchmarks.md#workloads-02-p5).

| Workload | Ring N | Depth | Key generation | Encrypt | Evaluation | Decrypt | Evaluation keys | Request | Response | Peak memory | Max abs. error |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| scalar arithmetic | 8192 | 2 | 162 ms | 13.2 ms | 12.4 ms | 4.9 ms | 1.50 MiB | 0.75 MiB | 0.25 MiB | 37 MiB | 2.8e-7 |
| dot product, 1024 | 8192 | 1 | 395 ms | 7.4 ms | 27.4 ms | 6.8 ms | 8.26 MiB | 0.25 MiB | 0.25 MiB | 94 MiB | 2.8e-7 |
| matrix–vector, 128×128 | 8192 | 1 | 543 ms | 7.3 ms | 93.7 ms | 7.2 ms | 17.26 MiB | 0.25 MiB | 0.25 MiB | 177 MiB | 4.3e-7 |
| logistic regression, 32 | 16384 | 7 | 1523 ms | 54.3 ms | 302.2 ms | 23.6 ms | 45.02 MiB | 2.00 MiB | 0.50 MiB | 432 MiB | 4.8e-4 |
| similarity search, 384×64 | 8192 | 1 | 431 ms | 6.3 ms | 68.2 ms | 6.7 ms | 13.51 MiB | 0.25 MiB | 0.25 MiB | 150 MiB | 2.7e-7 |

Evaluator throughput, 8 concurrent clients over HTTP on localhost
([benchmarks.md, Evaluator concurrency](benchmarks.md#evaluator-concurrency-02-p4)):

| Workload | Evaluator | Jobs per second | p50 | p95 | Peak memory per process |
|---|---|---:|---:|---:|---:|
| similarity search (N = 8192) | 4 worker processes | 25.0 | 287 ms | 407 ms | 87 MiB |
| logistic regression (N = 16384) | 4 worker processes | 6.8 | 976 ms | 1502 ms | 287 MiB |

The two-machine demo (`scripts/two-machine-demo.sh`) runs the similarity
search against a containerized evaluator with a maximum error of 1.9e-7
(CHANGELOG 0.2.0). Its timings are not published.

## Exact programs on OpenFHE exact (BinFHE)

Hardware: Apple M3 Max, 14 logical cores, macOS 26 (Darwin 25.6); OpenFHE
1.5.1, profile `BINFHE_STD128_GINX_BITS_V1`, optimizer version 1, commit
`81aebad`, one run on 2026-09-27. Evaluation time includes loading input
ciphertexts and sealing outputs. Every result was decrypted and checked.
Source: [benches/exact/history.jsonl](../benches/exact/history.jsonl) and
[benchmarks.md, optimized OpenFHE exact](benchmarks.md#exact-programs-optimized-openfhe-exact).

Costs shared by every exact program on one client:

| | |
|---|---|
| Key generation (secret key and evaluation keys) | 4.5 s |
| Evaluation keys | 525 MiB (549,982,005 bytes), uploaded once per client and evaluator |
| Evaluator setup (loading the keys) | 1.4 s |
| Secret key on disk | 4.8 KiB |
| Ciphertext | 4.4 KiB per bit: `u8` 35 KiB, `u32` 141 KiB |
| One bootstrapped gate, one core | 54 to 62 ms, depending on the run (61 ms in this run) |
| Peak memory, whole benchmark run | 3.6 GiB (key generation dominates) |

The three golden workloads, and the eligibility rule of examples 02 and
19:

| Program | Gates (optimized) | 1 worker | 8 workers | Reference lowering, 1 worker | Request | Response | Encrypt | Decrypt |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| eligibility | 381 | 31.10 s | 7.84 s | 36.99 s | 387 KiB | 4.5 KiB | 6.0 ms | 0.02 ms |
| golden eligibility | 663 | 36.11 s | 12.12 s | 54.47 s | 458 KiB | 40 KiB | 6.6 ms | 0.13 ms |
| golden policy | 80 | 7.63 s | 2.20 s | 6.39 s | 203 KiB | 40 KiB | 2.9 ms | 0.11 ms |
| golden scoring | 827 | 49.46 s | 21.19 s | 105.59 s | 423 KiB | 70 KiB | 4.7 ms | 0.24 ms |

All 16 programs of the corpus, with depth and 2 and 4 workers, are in
benchmarks.md. With 8 workers the corpus runs 1.7 to 9.4 times faster than
the reference lowering. Rule of thumb: time ≈ gates × 54–62 ms on one
core; `explain` prints a program's gate count before you run it.

Example 20 measured, end to end on the same machine type: reference
lowering 38.7 s, optimized 14.0 s including the key upload, and 8.5 s for
a second run with cached keys
([example 20](../examples/20_openfhe_optimization/README.md)).

### Exact programs on OpenFHE BGV

Unverified programs inside the BGV subset run on BGV when estimated no
slower. BGV costs per operation are measured
([benchmarks.md, calibration](benchmarks.md#exact-backend-selection-bgv-or-binfhe-calibration)):
at depth 1, key generation 12.5 ms, encryption 2.65 ms, a multiplication
1.27 ms. Whole programs: 32 scaled inputs summed, measured 32–34 ms; a
chain of 3 products, measured 28–36 ms. Example 20's arithmetic-only
program is estimated at ~4 ms on BGV against ~9.1 s on BinFHE.

BGV evaluation-key and ciphertext sizes for these programs: **not yet
measured**.

## Verified execution (research build)

Loan pre-check: 4 inputs, 6 instructions; OpenFHE BGV (t = 65537); Apple
M3 Max; release build; median of 5
([benchmarks.md, Verified execution](benchmarks.md#verified-execution-research)).

| | |
|---|---|
| Evaluation (evaluator) | 24 ms |
| Verification by re-execution and decryption (client) | 65 ms |
| Proof | 543 bytes |
| Verification key (the client's evaluation keys) | 769 KiB |
| Request / response | 1027 KiB / 514 KiB |
| Key generation | not yet measured |
| Memory | not yet measured |

## Confidential LoRA fine-tuning (example 15)

Two hospitals and a model owner; a tiny transformer classifier (vocabulary
64, width 16); LoRA rank 4 on `q` and `v` (256 adapter parameters); 2
rounds of 10 local steps; development (mock) attestation. Every party is a
separate process on one Apple M3 Max; debug build; 3 runs
([benchmarks.md](benchmarks.md#confidential-lora-fine-tuning)).

| Stage | Seconds |
|---|---:|
| Plain PyTorch, one party's local steps (baseline) | 0.50–0.63 |
| Attestation, model key release, model build | 1.05–1.11 |
| 2 rounds: training, secure aggregation, DP release | 5.81–5.86 |
| Sealed adapters and checkpoints | 0.01 |
| Adapter records into the trust graph | 0.04–0.05 |
| Total | 8.36–8.38 |

Memory, key sizes, release-build timings and real TEE attestation
latency: **not yet measured**.

## Patient-level DP-SGD (example 16)

Two hospitals of 1,000 patients (2,000 records each), sampling rate
0.032, the same tiny model; all parties on one Apple M3 Max; debug build
([benchmarks.md](benchmarks.md#patient-level-dp-sgd)).

| Privacy | Seconds per round | ε used per hospital | Held-out accuracy |
|---|---:|---|---|
| Organization level (10 local steps) | 2.8 | 6.34 of 8 after 2 rounds | 0.38 → 0.43 |
| Patient level (DP-SGD, one step) | 2.6 | 1.75 of 3 after 20 rounds | 0.38 → 0.73 |

Per-example gradients, 64 records of 32 patients, mean of 20 runs: plain
batch gradient 0.83 ms; vectorized per-example gradients 2.16 ms
(microbatch 64); one autograd call per record 18.03 ms. The protocol's
round trips dominate a round, not the gradients.

Memory: **not yet measured**.

## Hugging Face Transformers + PEFT (example 17)

A tiny BERT (2 layers, width 32), PEFT LoRA rank 4 on `query` and `value`
plus the head (1,090 adapter parameters); two hospitals of 2,000 patients
(4,120 tokenized records each); patient-level DP-SGD at sampling rate
0.05; 20 rounds; development attestation; all parties on one Apple M3
Max; debug build ([benchmarks.md](benchmarks.md#hugging-face--peft)).

| Stage | Seconds |
|---|---:|
| Plain PyTorch + PEFT, one local step (baseline) | 0.02 |
| Attestation, loading Transformers, choosing the gradient path | 2.6 |
| 20 rounds: per-patient gradients, secure aggregation, DP release | 57.5 |
| Sealed checkpoints and adapters | 0.24 |
| Adapter records into the trust graph | 0.71 |
| Total | 62.6 |

Held-out accuracy 0.77 → 0.96 at ε 2.57 of 3 (δ = 1e-6). The exported
adapter matches Encompute's attested inference to 1e-6.

A production-size model (for example BERT-base, 110M parameters), GPU
training and memory use: **not yet measured**.

## Confidential training job on Confidential Space (example 18)

One participant's job: the tiny BERT with PEFT LoRA, 300 patients (600
notes), one DP-SGD step, measured by the worker itself
([benchmarks.md](benchmarks.md#confidential-training-jobs-confidential-space)).

| Stage | macOS arm64, simulated launcher | Linux arm64 container, simulated launcher |
|---|---:|---:|
| Attestation and key release (one attestation, four grants) | 0.05 s | 0.03 s |
| Model loading and gradient-path probe | 4.7 s | 0.6 s |
| Training step | 0.02 s | 0.59 s |
| Total in the worker | 4.8 s | 1.3 s |

A live Confidential Space run (TDX VM start-up, real attestation, time to
evidence): **not yet measured**. The planned setup is a `c3-standard-4`
TDX VM.

## Not yet measured

- Any workload on Linux x86_64 servers, or on real TEE hardware.
- Control plane: job submission and scheduling latency, throughput,
  database size growth.
- Secure aggregation on its own: round latency and bandwidth as the number
  of parties grows (the assurance suite checks correctness up to 100
  parties, not timing).
- Key broker: attestation and release latency against real Confidential
  Space tokens.
- Memory use of the AI workloads.
- TFHE-rs is benchmarked in [benchmarks.md](benchmarks.md) for research
  comparison only. It is not a supported backend.
