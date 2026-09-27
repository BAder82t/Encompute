# Encompute 0.3.0-rc.2: release notes (draft)

**Status: draft.** This is the first release candidate of 0.3.0: the frozen
target for independent security review ([security-review/](../security-review/)).
No independent review has been completed yet. Features are frozen; only fixes go in
before 0.3.0.

Encompute compiles ordinary Python into encrypted computation, and lets
several organizations build AI together without revealing what each must
keep private. 0.3 is the first release with exact programs on OpenFHE,
execution receipts, confidentiality policies, attested key release, secure
aggregation, differential privacy, a trust graph, a planner, confidential
fine-tuning and an enterprise control plane.

## What can I safely use?

The production build (the default features plus `openfhe`) supports the
following. Details and limits for each are in the
[support matrix](support-matrix.md).

- **Approximate programs on OpenFHE CKKS**: real numbers and tensors,
  locally or on a remote evaluator.
- **Exact programs on OpenFHE exact (BinFHE)**: integers and Booleans,
  computed exactly, as an optimized circuit with parallel gates. Programs
  inside the BGV subset run on OpenFHE BGV when that is no slower.
- **Remote evaluators** with worker processes, and **signed execution
  receipts** for every evaluation.
- **Confidentiality policies**, the **planner** and the **trust graph**.
- **Secure aggregation** and **differential privacy**, organization level
  and patient-level DP-SGD.
- **Confidential fine-tuning** with PyTorch LoRA, and Hugging Face
  Transformers + PEFT for sequence classification with BERT or DistilBERT.
- **The control plane**: API v1 (frozen), PostgreSQL, OIDC, customer-managed
  root keys in OpenBao or Vault Transit, and the Docker Compose deployment.
- **The Python SDK** and the `encompute` CLI.
- **Platforms**: Linux x86_64 and macOS arm64.

"Safely" means: within the [threat model](threat-model.md), under the
assumptions below, and with the [known limitations](../KNOWN_LIMITATIONS.md).

## What remains experimental?

- **Google Confidential Space attestation**, and confidential training jobs
  on it. Tested locally and in CI with a simulated launcher; the live GCP
  run has not been done yet.
- **Hugging Face RoBERTa**: accepted, not tested end to end.
- **The evaluator and key broker HTTP APIs**: versioned, but not frozen.
  Run clients and evaluators of the same release.
- **`encompute train`, `lineage`, `export`**, and the `encompute.torch`
  Python API: tested, but their arguments may still change.
- **Linux arm64.**

Research only, never in production builds:

- **TFHE-rs** (`research-tfhe-rs`). Zama requires a patent license for
  commercial use.
- **Verified execution** (`vfhe-research`): execution proofs by
  re-execution on BGV, for a small exact subset.

The mock attestation provider and the development-mode OpenBao in Docker
Compose are for development and trials. They protect nothing.

## What changed since 0.2.0?

The full list is in the [CHANGELOG](../CHANGELOG.md). In short:

- **Exact programs.** Integer (`u8`–`u64`, `i8`–`i64`) and Boolean types,
  with range analysis proving no overflow. They run on **OpenFHE exact**
  (BinFHE), the production exact backend, with one vetted parameter
  profile (`BINFHE_STD128_GINX_BITS_V1`).
- **Exact optimization.** Range-aware circuits, simplification and
  parallel gates: 1.7 to 9.4 times faster than the reference lowering with
  8 workers. BGV or BinFHE is chosen per program by calibrated cost. A
  bounded evaluation-key cache.
- **Execution identity and receipts.** Execution specs, signed receipts,
  semantic transcripts; research execution proofs.
- **Confidentiality policies**: parties, assets, purposes, release rules,
  checked at compile time.
- **Attested key release**: Google Confidential Space and a development
  mock; a key broker with customer-managed root keys.
- **Secure aggregation** (Bonawitz et al.) and **differential privacy**
  (discrete Gaussian, zCDP and Rényi DP accounting, tamper-evident
  ledgers).
- **Trust graph** and **planner**.
- **Confidential fine-tuning**: PyTorch LoRA, patient-level DP-SGD, Hugging
  Face Transformers + PEFT, Confidential Space training jobs.
- **Enterprise control plane**: organizations, OIDC, service identities,
  tenant isolation, jobs, scheduling, durable privacy state with a signed
  anchor, audit trail, API v1, Docker Compose deployment.
- **Assurance suite**: 124 security invariants, a release gate in CI.
- **Examples**: 20 runnable examples, each with its threat model.
- **TFHE-rs** is isolated to research builds, and a commercial build audit
  proves it is absent from production builds.
- **Toolchain**: Rust 1.98.1 (was 1.89.0).

## What breaks compatibility?

- **Compiled artifacts.** 0.3 reads artifact format 5 only. 0.2 wrote
  format 2. Recompile every `.encompute` artifact; loading an old one fails
  with ENC1401.
- **Keys and ciphertexts.** Regenerate client keys (`encompute keys
  generate`) for recompiled artifacts. The envelope format (`ENCM`
  version 1) is unchanged, but envelopes are bound to the program and
  parameter set, which recompiling can change.
- **Client and evaluator must both be 0.3.** 0.3 clients verify a signed
  receipt before decrypting, and a 0.2 evaluator sends none. Start 0.3
  evaluators with `--identity FILE` so their receipt key stays stable, and
  pin it (`--trust-evaluator`, or on first use).
- **Stricter compilation.** Programs mixing approximate and exact values
  are refused (ENC1301 or ENC1005). Operations outside a backend's
  capability matrix are refused at compile time rather than at run time.
- **Package description** changed to "Compiler and trust runtime for
  confidential AI".

Nothing else from 0.2 persists: 0.2 had no receipts, ledgers, trust
bundles, training records or control-plane database. The compatibility
policy for everything 0.3 writes, and the planned `encompute migrate`,
are in [compatibility.md](compatibility.md).

## What security assumptions exist?

The full statements are in the [threat model](threat-model.md) and
[cryptography](cryptography.md). The main ones:

- **The FHE evaluator is honest-but-curious.** It never holds a secret key.
  A receipt makes its claim attributable, but does not prove the result
  correct; only research verified execution does.
- **Decrypted results never go back to the evaluator.** CKKS is not
  IND-CPA-D secure.
- **Inputs lie within their declared ranges.** The client checks this
  before encrypting.
- **Parameters.** CKKS parameters are checked against the HE Standard
  128-bit table. The BinFHE profile's 128-bit label and 2^-135 failure
  probability are OpenFHE's stated values for STD128.
- **Attestation trusts the TEE vendor** and its attestation service, and
  the reviewed image digest.
- **Secure aggregation** hides contributions from a coordinator colluding
  with up to the declared number of parties. The coordinator can still
  abort a round or report a wrong aggregate.
- **Differential privacy is central.** The coordinator adds the noise and
  is trusted to, as far as its attestation goes. The privacy unit is what
  data owners declare.
- **PyTorch computes in plaintext inside the attested workload.** The TEE
  protects data in use during fine-tuning, not FHE.
- **The control plane is trusted for coordination, not for trust
  decisions.** A compromised control plane can deny service, but cannot
  decrypt, release keys without attestation or forge receipts.
- **No formal proof of the whole system.** The assurance suite tests 124
  invariants; it does not prove the system secure.

## How do I upgrade?

From 0.2.0:

1. Install Rust 1.98.1 (`rustup` reads `rust-toolchain.toml`), and rebuild
   OpenFHE 1.5.1 with `./scripts/install-openfhe.sh` if you use a
   different install.
2. Build the production binaries and the Python SDK:

   ```sh
   cargo build --release -p encompute-cli -p encompute-evaluator \
     --features encompute-cli/openfhe,encompute-evaluator/openfhe
   maturin develop --release --features openfhe
   ```

3. Recompile every artifact: `encompute compile model.py:fn -o model.encompute`.
4. Regenerate client keys: `encompute keys generate model.encompute`.
5. Upgrade evaluators and clients together. Give each evaluator a
   persistent identity (`encompute-evaluator serve ... --identity FILE`),
   and pin its key on clients.
6. Check what the build contains with `encompute info`, and run
   `encompute test model.encompute --mode encrypted` on each artifact.
7. For production builds, run `scripts/audit-commercial-build.sh
   target/release` to confirm no TFHE-rs code is linked.

For a new control-plane deployment, follow [deployment.md](deployment.md).
Replace the Compose file's development-mode OpenBao with your own KMS
before you protect real keys.

## Reporting problems

Security issues: privately, as described in [SECURITY.md](../SECURITY.md).
Everything else: GitHub issues.
