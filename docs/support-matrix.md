# Support matrix

This is the one authoritative list of what Encompute supports, for release
0.3.0. The [status summary](guide/status-summary.md) is a
short version of this page. If they disagree, this page wins, and the
summary is a bug.

## Statuses

| Status | Meaning |
|---|---|
| **Supported** | In the production build. Tested in CI on every pull request. Security fixes apply. Compatibility follows [compatibility.md](compatibility.md). |
| **Supported subset** | Supported, but only for the stated subset. Anything outside it is refused with an error, never run silently. |
| **Experimental** | In the production build and tested, but not yet validated where it matters (for example, not yet run on real hardware), or its interface may still change in a minor release. Do not rely on it for production data without your own review. |
| **Research only** | Behind a research feature flag (`research-tfhe-rs`, `vfhe-research`). Not in production builds. No compatibility promise. Not for commercial use. |
| **Unsupported** | Refused, or not built or tested. It may work by accident; do not depend on it. |

The production build is the default feature set plus `openfhe`:

```sh
cargo build --release -p encompute-cli -p encompute-evaluator \
  --features encompute-cli/openfhe,encompute-evaluator/openfhe
maturin develop --release --features openfhe
```

`encompute info` prints what a given build contains.

## Encrypted computation

| Capability | Status | Details |
|---|---|---|
| Approximate programs on OpenFHE CKKS | **Supported** | OpenFHE 1.5.1, statically linked. Real numbers and tensors: `+ - *`, `sum`, `dot`, public-matrix `@`, `poly`, `sigmoid`, `x ** k`, division by public values. 128-bit parameters checked against the HE Standard table. No bootstrapping: depth is bounded by the largest 128-bit set (N = 2^16); deeper programs fail with ENC1201. |
| Exact programs on OpenFHE exact (BinFHE) | **Supported** | The production exact backend (`openfhe-exact`). Integers `u8`–`u64`, `i8`–`i64` and `bool`: `+ - *`, comparisons, `& \| ^ ~`, shifts, `//` and `%` by constants, `select`, `minimum`, `maximum`, `lookup` (tables up to 256 entries), `cast`. One vetted profile: `BINFHE_STD128_GINX_BITS_V1` (128-bit, failure probability 2^-135 per gate). Operations outside this matrix are refused at compile time (ENC1501). |
| Exact programs on OpenFHE BGV | **Supported subset** | Selected automatically for an unverified exact program when every operation is in the BGV subset (`u8`, `u16`, `bool`; add, sub, mul, constants, and/or/xor/not) and the calibrated estimate is no slower than BinFHE. `explain` shows both candidates. You cannot force BGV for a program outside the subset. |
| Optimized exact circuits, parallel gates | **Supported** | Default. `ENCOMPUTE_EXACT_EXECUTION=reference` runs the reference lowering for diagnosis. Results are identical. |
| Exact programs on TFHE-rs | **Research only** | TFHE-rs 1.8.1 behind the off-by-default `research-tfhe-rs` feature. Zama requires a patent license for commercial use. A production build refuses it with ENC1501 BACKEND UNAVAILABLE and never falls back. `scripts/audit-commercial-build.sh` checks that no TFHE-rs code is linked. |
| Mock backend | **Supported** (development and tests) | Plaintext; `mode="mock"`. Never protects data. Evaluators never advertise it to a control plane. |
| Differential testing (`test`, `encompute test`) | **Supported** | Encrypted against plaintext: within the precision for CKKS, exact matches for exact programs. |
| Compiled model artifacts (`.encompute`) | **Supported** | See [compatibility.md](compatibility.md). Artifacts never contain key material. |

## Execution and evidence

| Capability | Status | Details |
|---|---|---|
| Remote evaluator (`encompute-evaluator serve`, `run --remote`) | **Supported** | Plain HTTP, and its client of the control plane is plain HTTP: put a TLS proxy in front of it (the reference production topology does). The evaluator binary links no client cryptography (`scripts/audit-evaluator-binary.sh`). |
| Evaluator worker processes (`--workers N`) | **Supported** | Crash restart and replay within one machine. |
| Evaluator on several machines | **Unsupported** | Each evaluator is a single node. The control plane can schedule jobs across several registered evaluators, but one job never spans machines. |
| Evaluation-key cache | **Supported** | Bounded (`ENCOMPUTE_KEY_CACHE_BYTES`, LRU), per session. |
| Signed execution receipts | **Supported** | CKKS and exact, local and remote. Ed25519. A receipt is a signed claim, not a proof. |
| Semantic transcripts | **Supported** | Exact programs only. CKKS programs have none. |
| Verified execution (execution proofs) | **Research only** | Needs the `vfhe-research` build. Programs compiled with `verification="required"` run on OpenFHE BGV (`u8`, `u16`, `bool`; `+ - *`, constants, `& \| ^ ~`). The client re-executes to verify: sound, not succinct. A production build compiles such a program but cannot verify the proof, so the client refuses the result (ENC1801). |

## Multi-party confidentiality

| Capability | Status | Details |
|---|---|---|
| Confidentiality policies (parties, assets, purposes, release) | **Supported** | Checked at compile time (ENC1901–ENC1906) and bound into the execution spec. |
| Secure aggregation (`aggregate_only`) | **Supported** | Bonawitz et al., malicious-coordinator variant, dropouts down to the threshold, signed aggregation receipts. The coordinator can abort a round or report a wrong aggregate. |
| Organization-level differential privacy | **Supported** | Discrete Gaussian on secure aggregates, zCDP accounting, tamper-evident ledgers, owner-side checks. Central DP: the coordinator adds the noise. |
| Patient-level DP-SGD | **Supported** | `privacy="strong-patient"` or `"standard-patient"`. Per-patient clipping, Poisson sampling, Rényi DP accountant checked against 240 reference vectors. PyTorch fine-tuning only. |
| Trust graph and trust report | **Supported** | Rebuilt from signed evidence and checked only against keys the verifier supplies. |
| Planner (`plan`, `check`, `explain --deep`) | **Supported** | PLANNING FAILED (ENC2401) instead of weakening a requirement. |
| Attested key release: Google Confidential Space | **Experimental** | Intel TDX on Confidential Space. The provider, broker and worker are tested in CI with a production broker, a test JWKS and a simulated launcher. The live GCP run has not been done yet. |
| Attested key release: mock provider | **Unsupported** in production | Development and tests only. It signs whatever it is told. Production policies and brokers refuse its evidence (ENC2002). |
| Other TEEs (AWS Nitro, Azure, SEV-SNP, GPU TEEs) | **Unsupported** | No provider exists. |

## Confidential AI

| Capability | Status | Details |
|---|---|---|
| PyTorch LoRA fine-tuning (`method="lora"`) | **Supported subset** | Models built from a factory the worker image ships (`encompute.torch.models:tiny_classifier`, or a Hugging Face package's own `config.json`), through `encompute.torch.wrap_model`, never from a pickle. Other factories are refused before anything is imported (in a training spec: ENC2501). Attested workers, secure aggregation of LoRA updates, DP, sealed adapters and checkpoints, crash-safe rounds. PyTorch runs in plaintext inside the attested workload. Measured only on CPU with small models (see [performance.md](performance.md)). |
| Hugging Face Transformers + PEFT (`method="peft-lora"`) | **Supported subset** | Sequence classification only. Architectures: **BERT** and **DistilBERT** (tested end to end). Safetensors weights, immutable revisions, no remote code. `transformers>=4.46,<5`, `peft>=0.12,<1`; CI tests 4.46 and 0.12. |
| Hugging Face: RoBERTa | **Experimental** | Accepted by the package check, but not tested end to end. |
| Hugging Face: any other architecture or task | **Unsupported** | Refused on import (ENC2504, MODEL PACKAGE REFUSED). This includes decoder-only language models (GPT, Llama, Mistral), generation, token classification and vision models. |
| Attested inference with an adapter | **Supported** | `FineTuneResult.infer`. |
| PEFT adapter export | **Supported** | Only when every owner permits, no parent is revoked and the trust report is satisfied (ENC2503 otherwise). |
| Confidential training jobs on Confidential Space (`encompute.torch.job`, `cs_worker`) | **Experimental** | Same status as Confidential Space attestation: rehearsed locally and in CI, live run pending. |
| GPU training | **Unsupported** | Not tested. Attestation policies can require a GPU, but no GPU TEE provider exists. |

## Enterprise deployment

| Capability | Status | Details |
|---|---|---|
| Control plane (`encompute-control`, API v1) | **Supported** | Organizations, OIDC users, service accounts, roles, tenant isolation, projects, assets, plans, jobs, scheduling, audit. API v1 is frozen: [api-stability.md](api-stability.md). |
| PostgreSQL | **Supported** | PostgreSQL 16 is tested. Versioned migrations (`encompute-control migrate`). |
| OIDC identity providers | **Supported** | RS256, ES256 or PS256 tokens; JWKS over HTTPS in production. |
| Customer-managed root keys: OpenBao Transit | **Supported** | OpenBao 2.1.0 is tested in CI. |
| Customer-managed root keys: HashiCorp Vault Transit | **Supported subset** | Same Transit API and the same adapter. Not tested in CI against Vault itself. |
| Other KMS (AWS KMS, GCP KMS, Azure Key Vault) | **Unsupported** | No adapter yet. |
| Docker Compose deployment | **Supported** | Control plane, PostgreSQL, OpenFHE evaluator, key broker, SecAgg coordinator, with backup, restore and a smoke test. The bundled OpenBao runs in development mode, in memory: replace it with your own KMS for real keys, or use the reference production topology. |
| Reference production topology ([production-deployment.md](production-deployment.md)) | **Supported subset** | One machine, Docker Compose: a TLS edge (mutual TLS on its operations and key-broker listeners), PostgreSQL that accepts only TLS, an external OpenBao in server mode (not dev mode), secrets as files, health checks, a backup drill, and `deploy/production/validate.sh`, which checks configuration (not security properties) and fails a deliberately misconfigured topology (`deploy/production/negative/run.sh`). The control plane verifies PostgreSQL itself (production requires `sslmode=verify-full`; weaker modes need named opt-outs; a client certificate) and the key broker verifies the vault itself (`BAO_CACERT`): native TLS, no sidecars, in images built from this source (the published v0.3.0 images predate it). Other HTTPS clients (CLI, SDK, identity provider keys, the state-anchor client) still trust only the public roots. No high availability, no secure-aggregation coordinator, no KMS beyond OpenBao and Vault Transit. |
| Kubernetes, Helm | **Unsupported** | Not provided yet. |
| Message transport | **Supported subset** | HTTP with an outbox, and in-memory. No message-broker adapter yet. |

## SDKs and tools

| Capability | Status | Details |
|---|---|---|
| Python SDK (`encompute`) | **Supported** | Compile, run, test, explain, policies, planner, `Project`, `Client`. Requires Python 3.11 or later; CI tests 3.11 and 3.12. See [api-stability.md](api-stability.md) for which names are stable. |
| `encompute.torch` | **Supported** | Needs the `torch` or `huggingface` extra. |
| `encompute` CLI | **Supported** | Development-only flags (`--development`, `--mock-root`, `attest mock-root`, `attest simulate-launcher`, `plan --allow-development`) are unsupported in production. |
| Assurance suite (`assurance-report`) | **Supported** (release gate) | Not published. 150 invariants in 0.3.0 (179 in 0.4.0-rc.1). |

## Governed projects (0.4.0-rc.1, release candidate)

None of this is part of 0.3.0. It is in the 0.4.0 release candidate, which
is pre-release: it has no support status yet, has had no independent
security review (one is planned before 0.4.0), and its formats and names may
change before 0.4.0. The table says what is built, what is not, and what has
not been shown.
See [public-sector.md](public-sector.md).

| Capability | State | Details |
|---|---|---|
| Governed projects, owner-signed authorizations, purposes, optional per-job four eyes | Release candidate | Governance keys, one authorization per owner, purpose, program and dataset version, strict windows, non-retroactive revocation. |
| Sovereign key custody and two-part key release | Release candidate | Each institution's keys stay at a key broker it registered; a broker releases only with the owner's signed authorization and a single-use ticket. Rollback guard through a generation mark in the owner's KMS (OpenBao Transit and KV tested; no other KMS). |
| Release classes, derived results, retention, auditor | Release candidate | Compiler-checked release forms; derived results with lineage consent; deletion dates; a read-only auditor organization. |
| Governance log, anchor, verifiable audit | Release candidate | Needs the control plane's state anchor outside the database's failure domain. |
| Privacy scopes and aggregate mode (statistics) | Release candidate | Secure aggregation with differential privacy; central DP. Examples: [public-health-statistics](../examples/public-sector/public-health-statistics/). |
| Residency and operators | Release candidate | Constraints decide placement; declared locations are attributable, not proven; only attested zones are checked cryptographically, and today only by the key broker. |
| Cross-agency report and evidence bundle | Release candidate | The report cannot read SATISFIED yet (decryption control and linkage are not evidenced). |
| Bounded-category release to one agency | Release candidate | Single source, no linkage. Example: [fraud-signal](../examples/public-sector/fraud-signal/). |
| Confidential model collaboration | Experimental, as in 0.3.0 | Examples 15 to 18; no separate governed example. |
| Record linkage, record-level exact computation across institutions | **Unsupported**: not built | Needs external cryptographic review before it ships. Example A and the flagship demo wait for it. |
| Recipient-held, attested-decryptor or threshold decryption of a governed result | **Unsupported**: not built | The report row "Decryption control" is NOT EVIDENCED. |
| Release gating | In `scripts/release-check.sh` | The Examples row requires both public-sector examples to run; the governance attacks row runs `scripts/governance-attacks.sh` when the test services are configured; the assurance row runs the governance invariants. |

## Platforms

| Platform | Status | Evidence |
|---|---|---|
| Linux x86_64 (Ubuntu 24.04) | **Supported** | CI: every job, including OpenFHE, the control plane and the enterprise golden path. |
| Linux x86_64 containers (Debian bookworm) | **Supported** | `Dockerfile.control`, `Dockerfile.evaluator`, `Dockerfile.services`; the two-machine demo and the Compose smoke test. |
| macOS arm64 (Apple Silicon, macOS 14 or later) | **Supported** | CI: the OpenFHE job (`macos-14`). All published benchmarks were measured here. Needs `brew install libomp`. |
| Linux arm64 | **Experimental** | The Confidential Space training image was built and run on Linux arm64 locally. Not in CI. |
| macOS x86_64 | **Unsupported** | Not tested. |
| Windows | **Unsupported** | Not built or tested. Use Linux containers or WSL at your own risk. |

Build requirements: Rust 1.98.1 (pinned in `rust-toolchain.toml`), CMake, a
C++17 compiler, OpenFHE 1.5.1 built statically by
`scripts/install-openfhe.sh`.

## Unsupported combinations

These are refused, with the error shown. None of them falls back to a
weaker mode.

| Combination | Result |
|---|---|
| Verified execution with an approximate (CKKS) program | Refused at compile time: ENC1801. Execution proofs cover exact programs only. |
| Verified execution with an operation or type outside the BGV proof subset (comparisons, `select`, lookups, shifts, `u32` and wider, signed types) | Refused at compile time: ENC1801, with the coverage percentage. |
| Verified execution on OpenFHE exact (BinFHE) | Unsupported: BinFHE has no proof backend. Verified programs always run on BGV. |
| Verified execution in a production build | The program compiles, but the client cannot verify the proof and refuses the result (ENC1801). |
| TFHE-rs in a production build (`--backend tfhe-rs`, `ENCOMPUTE_RESEARCH_EXACT_BACKEND`, or a TFHE-rs artifact) | ENC1501 BACKEND UNAVAILABLE. |
| TFHE-rs in any commercial deployment | Unsupported: licensing, not only engineering. |
| Approximate and exact values in one program | Refused at compile time: ENC1301 from the Python frontend, ENC1005 from `.eir`. One encrypted scheme per program. Split the computation. |
| BGV and BinFHE within one program | Never: a program runs as a whole on one scheme. One operation outside the BGV subset keeps the whole program on BinFHE. |
| CKKS programs deeper than the largest 128-bit parameter set | ENC1201. No bootstrapping. |
| Lookup tables over 256 entries on OpenFHE exact | ENC1501 at compile time. |
| Exact values beyond ±2^53 at the API | ENC1303 or ENC1102. |
| Returning decrypted results to the evaluator | Unsupported. CKKS is not IND-CPA-D secure. |
| Mock attestation with a production policy or broker | ENC2002. |
| Development identities, tokens, key stores or default credentials in production mode | ENC2605. |
| A research backend registered with a control plane | Refused at registration. |
| Aggregation programs on a single evaluator | ENC1905. |
| Patient-level privacy claims from organization-level training | Refused by the compiler, the planner and the trust report. |
