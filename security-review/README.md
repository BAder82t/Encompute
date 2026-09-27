# Encompute security review package

Start here. This page should make a reviewer productive within an hour:
what Encompute is, what it trusts, where the code is, how to build and
test it, and how to attack it.

Encompute is pre-release software (workspace version 0.2.0; work on `main`
after the v0.2.0 release). The review targets the release candidate under
a feature freeze: documentation, tests and hardening only.

## Reading order (about an hour)

| Time | Read |
|---|---|
| 10 min | This page |
| 20 min | [Threat model](../docs/threat-model.md): components, trust, eight adversaries, attacks with their evidence |
| 15 min | [Cryptographic design](../docs/cryptography.md): schemes, parameters, keys, what is bound and what is not |
| 15 min | [Protocols](protocols.md): envelopes, receipts, service signatures, job grants, key release, SecAgg rounds, privacy events, anchors |

Then pick a brief:

- [Cryptography review brief](crypto-review-brief.md)
- [Application security review brief](appsec-review-brief.md)

Other references:

- [Security findings process](../docs/security-findings.md): severities,
  fix targets, and what every finding must get.
- [Known limitations](../KNOWN_LIMITATIONS.md) (repository root).
- [Assurance suite](../docs/assurance.md): the invariant matrix.
- [Deployment guide](../docs/deployment.md) and [API v1](../docs/api.md).
- Decision records: [docs/adr/](../docs/adr/). The security-relevant ones
  are [0005](../docs/adr/0005-evaluator-process-isolation.md) (evaluator
  isolation), [0007](../docs/adr/0007-verifiable-execution.md) (receipts),
  [0008](../docs/adr/0008-semantic-transcripts.md) (transcripts),
  [0009](../docs/adr/0009-vfhe-proof-backend.md) (re-execution proofs),
  [0010](../docs/adr/0010-confidentiality-ir.md) (policies),
  [0011](../docs/adr/0011-attested-key-release.md) (key release),
  [0012](../docs/adr/0012-secure-aggregation.md) (SecAgg),
  [0013](../docs/adr/0013-differential-privacy.md) and
  [0017](../docs/adr/0017-patient-level-dp.md) (DP),
  [0014](../docs/adr/0014-trust-graph.md) (trust graph),
  [0015](../docs/adr/0015-planner.md) (planner),
  [0020](../docs/adr/0020-openfhe-exact.md) and
  [0022](../docs/adr/0022-exact-optimization.md) (OpenFHE exact),
  [0021](../docs/adr/0021-enterprise-deployment.md) (control plane).
  Some decision records describe an earlier state; where they disagree
  with the code, the code and the threat model are authoritative.
- Vulnerability intake: [SECURITY.md](../SECURITY.md).

## Architecture in one page

Encompute compiles Python functions over declared secret values into
encrypted programs, and coordinates multi-party computation around them.

- **Client** (CLI `encompute`, Python SDK). Compiles the program, picks
  the scheme from the types (CKKS for real numbers; OpenFHE BinFHE or BGV
  for integers and Booleans), selects 128-bit parameters, generates keys,
  encrypts, and verifies and decrypts results. It holds the secret key.
- **Evaluator** (`encompute-evaluator`). A separate binary that runs the
  encrypted program on OpenFHE v1.5.1 with the client's evaluation keys.
  It never receives a secret key. It signs an execution receipt for every
  result.
- **Control plane** (`encompute-control`). Organizations, OIDC users,
  service identities, roles, projects, assets, policies, plans, jobs,
  privacy ledgers, audit trail, trust reports. PostgreSQL behind it, and a
  signed state anchor outside it. It holds no secret key, plaintext or
  ciphertext.
- **Key broker** (`encompute keys serve`). One per asset owner. Releases
  asset keys only to hardware-attested workloads (Google Confidential
  Space), sealed with HPKE to a session key made inside the TEE. Its
  key-encryption key is wrapped by the owner's KMS (OpenBao or Vault
  Transit).
- **SecAgg coordinator** (`encompute aggregate serve`). Runs Bonawitz et
  al. secure aggregation (malicious-coordinator variant) and adds
  discrete Gaussian noise for differential privacy (central DP).
- **Training workers** (Python, `encompute.torch`). PyTorch LoRA and
  Hugging Face PEFT fine-tuning inside attested workloads; updates leave
  only through secure aggregation.

The canonical boundary diagram is in the
[threat model](../docs/threat-model.md#2-security-boundaries).

## Trust assumptions (summary)

- The client is trusted by its owner. OpenFHE and its parameter tables are
  trusted.
- The evaluator is untrusted for confidentiality. Without an execution
  proof it is trusted for correctness: a receipt makes its claim
  attributable, not true.
- The control plane is trusted for coordination and authorization, not for
  confidentiality or trust decisions.
- Key brokers and KMSs are trusted by their owners. TEEs and Google's
  attestation service are trusted.
- The SecAgg coordinator is untrusted for inputs, trusted to add DP noise
  as far as its attestation goes, and not trusted for the aggregate's
  correctness.
- The network, message transport, database (for trust decisions) and
  artifact storage are untrusted.
- All services speak plain HTTP; TLS is the deployment's job.
- Decrypted CKKS results must never go back to the evaluator (CKKS is not
  IND-CPA-D secure).
- There is no formal proof of Encompute as a whole.

## Security invariants

Every security claim is an invariant `INV-nnn` in
[`crates/encompute-assurance/src/catalog.rs`](../crates/encompute-assurance/src/catalog.rs)
(104 entries). Each has up to four kinds of evidence: positive, negative,
adversarial and end-to-end. Evidence is an assurance check in that crate
or a reference to an existing test or script, and the report fails if a
referenced test no longer exists. The matrix and the known gaps are in
[docs/assurance.md](../docs/assurance.md).

| Area | IDs |
|---|---|
| Compiler, artifacts, envelopes | INV-001 to INV-008 |
| Evaluator key boundary | INV-010, INV-011 |
| Receipts, transcripts, malicious evaluator | INV-020 to INV-023 |
| Confidentiality policies | INV-030 to INV-033 |
| Attestation and key release | INV-040 to INV-043 |
| Secure aggregation | INV-050 to INV-055 |
| Differential privacy | INV-060 to INV-071 |
| Leakage | INV-080, INV-081 |
| Trust graph | INV-100 to INV-103 |
| Planner | INV-110 to INV-115 |
| Confidential fine-tuning, DP-SGD, Hugging Face, Confidential Space | INV-120 to INV-148 |
| OpenFHE exact | INV-149 to INV-155 |
| Enterprise deployment (control plane) | INV-156 to INV-165 |
| Exact optimization, backend selection, key cache | INV-166 to INV-171 |

Run the report:

```sh
cargo build --release -p encompute-assurance --bins --examples
./target/release/assurance-report --json assurance-report.json --md assurance-report.md
./target/release/assurance-report --nightly          # larger populations
./target/release/assurance-report --only dp_crash_injection
```

It exits 1 if any invariant is violated, if a check fails, panics or does
not run, or if a referenced test is missing. A passing report means the
documented invariants held for the tested cases. It does not mean
Encompute is secure.

## Known limitations

See [KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md) at the repository
root. The threat model's "out of scope" lists and
[cryptography.md, section 11](../docs/cryptography.md#11-what-is-not-claimed)
say what each mechanism does not protect.

## Build and test

Requirements: Rust (pinned in `rust-toolchain.toml`), CMake, a C++17
compiler, Python 3 and, on macOS, `brew install libomp`.

```sh
# Core: everything except OpenFHE and TFHE-rs
cargo build --bins
cargo test

# OpenFHE v1.5.1, static, into .deps/openfhe (or set OPENFHE_ROOT)
./scripts/install-openfhe.sh
cargo test --workspace --features encompute-runtime/openfhe,encompute-evaluator/openfhe,encompute-cli/openfhe

# Production binaries, the exact demo, and the build audits
cargo build --release -p encompute-cli -p encompute-evaluator \
  --features encompute-cli/openfhe,encompute-evaluator/openfhe
scripts/exact-demo.sh
scripts/audit-evaluator-binary.sh target/release/encompute-evaluator
scripts/audit-commercial-build.sh target/release

# Python SDK
python -m venv .venv && . .venv/bin/activate
pip install maturin pytest numpy
maturin develop --release --features openfhe    # omit --features for mock only
pytest -q python/tests

# Control plane and key broker: needs PostgreSQL and an OpenBao/Vault dev server
ENCOMPUTE_TEST_DATABASE_URL=postgres://USER:PASS@127.0.0.1:5432/postgres \
ENCOMPUTE_TEST_BAO_ADDR=http://127.0.0.1:8200 ENCOMPUTE_TEST_BAO_TOKEN=root \
  cargo test -p encompute-control -p encompute-keybroker
```

The whole release gate, from a clean checkout, is one script. It runs what
this machine supports and prints SKIPPED, with the reason, for the rest
(OpenFHE, PostgreSQL and OpenBao, Docker, GCP):

```sh
scripts/release-check.sh
```

Research features (never in a production build): `vfhe-research`
(re-execution proofs) and `research-tfhe-rs` (TFHE-rs, differential testing
only). `CONTRIBUTING.md` suggests `cargo test --workspace --all-features`,
which also enables these research features and needs OpenFHE installed;
the commands above are what the release gate runs.

## Attack examples

Each example's README has a **Try breaking it** section that runs attacks
and requires the refusal:

| Example | Attacks |
|---|---|
| [01 CKKS private inference](../examples/01_ckks_private_inference/README.md#try-breaking-it) | unreachable precision, branching on a secret |
| [02 exact private logic](../examples/02_exact_private_logic/README.md#try-breaking-it) | out-of-range and fractional inputs, possible overflow |
| [03 remote evaluator](../examples/03_remote_evaluator/README.md#try-breaking-it) | decrypt with only the evaluator's keys, a different evaluator identity |
| [04 execution receipts](../examples/04_execution_receipts/README.md#try-breaking-it) | flipped request or response bits, edited receipt fields, another backend, an untrusted key |
| [05 verified execution](../examples/05_verified_execution/README.md#try-breaking-it) | verification of an uncovered operation, proof tampering, malicious evaluator results (research build) |
| [06 confidentiality policy](../examples/06_confidentiality_policy/README.md#try-breaking-it) | leaking a confidential value, releasing an aggregate-only value directly, the wrong purpose |
| [07 attested key release](../examples/07_attested_key_release/README.md#try-breaking-it) | replayed evidence, wrong spec or policy, modified image, substituted session key |
| [08 secure aggregation](../examples/08_secure_aggregation/README.md#try-breaking-it) | unauthorized party, too few parties, replayed contribution or round, wrong round |
| [09 differential privacy](../examples/09_differential_privacy/README.md#try-breaking-it) | coordinator restart to forget spending, ledger reset |
| [10 trust graph](../examples/10_trust_graph/README.md#try-breaking-it) | deleted or edited evidence, revocation, missing or wrong keys, another plan |
| [11 automatic planner](../examples/11_automatic_planner/README.md#try-breaking-it) | requirements no mechanism can meet |
| [12 confidential collaboration](../examples/12_confidential_collaboration/README.md#try-breaking-it) | `./attack.sh NAME` against the full multi-party flow |
| [13 assurance suite](../examples/13_assurance_suite/README.md#try-breaking-it) | removing evidence makes the release gate fail |
| [14 Python Project API](../examples/14_python_project_api/README.md#try-breaking-it) | no infrastructure, mock TEE without opting in, aggregating one party |
| [15 confidential LoRA](../examples/15_confidential_lora/README.md#try-breaking-it) | `attack.py`: another image or spec, tampered model, wrong layout or dataset, cut DP noise |
| [16 patient-level DP-SGD](../examples/16_patient_private_lora/README.md#try-breaking-it) | `attack.py`: weaker DP settings, ungrouped records, unaccounted steps, unclipped contributions, false patient-level claims |
| [17 Hugging Face PEFT](../examples/17_huggingface_peft/README.md#try-breaking-it) | `attack.py`: swapped revision or shard, tampered weights, changed tokenizer, remote code, pickles, path escapes |
| [18 Confidential Space](../examples/18_confidential_space_hf/README.md#try-breaking-it) | modified image on genuine TDX, debug VM, another spec, weakened privacy, swapped assets, replayed token |
| [19 OpenFHE exact](../examples/19_openfhe_exact/README.md#try-breaking-it) | `forge.py`: envelopes under other keys, parameters or backends |
| [20 exact optimization](../examples/20_openfhe_optimization/README.md#try-breaking-it) | a value outside the range the optimizer relied on, possible overflow |

The control plane's golden path in production mode, with its attacks, is
[`scripts/enterprise-e2e.sh`](../scripts/enterprise-e2e.sh): insecure
configuration refused, revocation reaching the broker, a full restart, an
older database backup refused, and a canary scan of every log, the
database dump and the audit output. The Compose deployment runs the same
through [`deploy/docker-compose/smoke.sh`](../deploy/docker-compose/smoke.sh).

## Source entry points

| Crate | Role | Security-relevant files |
|---|---|---|
| `encompute-ir` | IR, types, privacy types, confidentiality declarations, DP presets, error codes | `src/confidentiality.rs` (codec, presets), `src/error.rs` |
| `encompute-analysis` | Range, overflow and confidentiality analyses | `src/confidentiality.rs` (threshold, codec overflow, DP checks), range analysis |
| `encompute-ckks` | CKKS lowering and parameter selection | `src/params.rs` |
| `encompute-exact` | Exact plans, bit circuits, optimizer, BGV subset, transcripts | `src/bits.rs` (profile), `src/circuit.rs`, `src/bgv.rs`, `src/transcript.rs` |
| `encompute-protocol` | `ENCM` envelopes | `src/lib.rs` |
| `encompute-openfhe` | OpenFHE evaluator shim (C++ via `cxx`) | `cpp/shim.cc`, `cpp/binfhe.cc`, `cpp/common.h`, `src/binfhe.rs`, `build.rs` |
| `encompute-openfhe-client` | Client shim: key generation, encryption, decryption | `cpp/client.cc`, `cpp/binclient.cc`, `src/exact.rs` |
| `encompute-openfhe-exact` | `ENCBINF1` envelopes, vetted profile, gate binding | `src/lib.rs` |
| `encompute-verification` | Specs, receipts, transcripts, proofs, service signatures, job grants, messages | `src/receipt.rs`, `src/verify.rs`, `src/spec.rs`, `src/service.rs`, `src/hash.rs`, `src/canonical.rs`, `src/identity.rs`, `src/proof.rs` |
| `encompute-vfhe` | Re-execution proof verifier (research) | `src/lib.rs` |
| `encompute-evaluator` | Evaluator HTTP service, sessions, key cache, worker pool, grants | `src/server.rs`, `src/session.rs`, `src/keycache.rs`, `src/pool.rs`, `src/control.rs`, `src/main.rs` |
| `encompute-runtime` | Client runtime, artifacts, remote client, audit command | `src/client.rs`, `src/artifact.rs`, `src/remote.rs`, `src/audit.rs`, `src/attested.rs` |
| `encompute-cli` | `encompute` command | `src/main.rs` (keys, verify, pinning), `src/attest.rs` (broker), `src/aggregate.rs` (SecAgg, privacy events), `src/control.rs` |
| `encompute-attestation` | Attestation evidence, bindings, policies, HPKE grants | `src/gcp.rs`, `src/binding.rs`, `src/policy.rs`, `src/provider.rs`, `src/grant.rs`, `src/mock.rs` |
| `encompute-keybroker` | Key release server, key stores, root-key providers | `src/lib.rs`, `src/server.rs`, `src/store.rs`, `src/root.rs`, `src/workload.rs` |
| `encompute-secagg` | Secure aggregation | `src/crypto.rs`, `src/protocol.rs`, `src/round.rs`, `src/service.rs` |
| `encompute-privacy` | DP sampler, accountants, ledgers, releases | `src/sampler.rs`, `src/accountant.rs`, `src/rdp.rs`, `src/ledger.rs`, `src/release.rs` |
| `encompute-training` | Training specs, sealed assets, checkpoints, adapters, HF packages | `src/seal.rs`, `src/checkpoint.rs`, `src/spec.rs`, `src/worker.rs`, `src/hf.rs` |
| `encompute-trust` | Trust graph and report | `src/report.rs`, `src/authz.rs`, `src/graph.rs` |
| `encompute-planner` | Mechanism selection and independent validator | `src/planner.rs`, `src/validate.rs`, `src/requirements.rs` |
| `encompute-control` | Control plane | `src/authn.rs`, `src/authz.rs`, `src/api.rs`, `src/config.rs`, `src/db.rs`, `src/audit.rs`, `src/anchor.rs`, `src/control.rs`, `src/transport.rs`, `src/ops/*.rs`, `migrations/` |
| `encompute-py`, `python/encompute` | Python SDK and PyTorch integration | `python/encompute/client.py`, `python/encompute/torch/dpsgd.py`, `worker.py`, `hf.py` |
| `encompute-assurance` | Invariant catalog and release-gate report | `src/catalog.rs`, `src/checks/` |
| `encompute-tfhe`, `encompute-tfhe-client` | TFHE-rs backend, research only | never in production builds (`scripts/audit-commercial-build.sh`) |
| Deployment | Containers and Compose | `Dockerfile.control`, `Dockerfile.evaluator`, `Dockerfile.services`, `deploy/docker-compose/`, `deploy/confidential-space*/` |
| Scripts | Audits and end-to-end checks | `scripts/audit-evaluator-binary.sh`, `scripts/audit-commercial-build.sh`, `scripts/sbom.py`, `scripts/enterprise-e2e.sh`, `scripts/release-check.sh`, `scripts/install-openfhe.sh` |

## Reporting

File each finding as described in
[docs/security-findings.md](../docs/security-findings.md): privately, one
advisory per finding, with a reproduction.
