# Known limitations

What Encompute 0.3 does not do, does slowly, or does only under
assumptions. Read this before you put real data through it. These are
documented limitations, not vulnerabilities: see [SECURITY.md](SECURITY.md)
for what to report.

Related: [support matrix](docs/support-matrix.md),
[threat model](docs/threat-model.md),
[cryptography](docs/cryptography.md), [performance](docs/performance.md).

## Security model

- **No formal proof of the whole system.** The cryptographic building
  blocks (CKKS, BinFHE, BGV, Ed25519, HPKE, secure aggregation, the
  discrete Gaussian) have published analyses. Their composition in
  Encompute has none. The assurance suite tests 104 security invariants
  with positive, negative, adversarial and end-to-end evidence. A passing
  report means those invariants held for the tested cases. It does not
  prove the system secure.
- **An independent security review is in progress** for this release
  candidate. It has not concluded.
- **Receipts are signed claims, not proofs.** An evaluator signs what it
  says it computed. A dishonest evaluator can sign a wrong result, and the
  receipt still verifies. Only verified execution rules this out, and it
  is research only.
- **Verified execution is research only.** It needs the `vfhe-research`
  build, covers only `u8`, `u16` and `bool` with `+ - *`, constants and
  `& | ^ ~` on BGV, and is sound but not succinct: the client redoes the
  whole computation to verify it. There is no proof for CKKS or BinFHE
  programs.
- **The evaluator is trusted to be honest-but-curious.** Malicious
  evaluators (outside verified execution), malicious clients and colluding
  parties are out of scope for FHE execution.
- **CKKS is not IND-CPA-D secure.** Never return decrypted CKKS results to
  the evaluator. Encompute adds no noise flooding. The same rule applies
  to exact programs, whose decryption failure probability is small but not
  zero.
- **The evaluator sees program structure.** Operations, public constants
  and weights, shapes, declared input ranges, timing and ciphertext sizes
  are visible to it by design. Encrypted model weights are not supported.
- **Envelope checksums are unkeyed SHA-256.** They detect corruption, not
  tampering: an attacker can recompute them. Integrity against an attacker
  comes from the receipts and from the program, parameter and key
  bindings, not from the checksum.
- **The BinFHE key ID is a random 16-byte label,** chosen at key
  generation. It is not a commitment to the keys: it tells keys apart, it
  does not prove which keys were used.
- **The BinFHE security labels are declared, not measured.** "128-bit" and
  "2^-135 per gate" for `BINFHE_STD128_GINX_BITS_V1` are the values
  OpenFHE states for its STD128 parameter set. Encompute did not measure
  them independently. CKKS parameters are checked against the HE Standard
  128-bit table; BinFHE parameters are taken from OpenFHE.
- **The evaluator binary links all of OpenFHE.** It statically links
  OpenFHE, including OpenFHE's own key-generation and decryption routines.
  It contains no Encompute key-generation, encryption or decryption code,
  and it never receives a secret key, so it cannot decrypt.
- **The client's secret key is stored unencrypted.** `secret.key` is
  written with file mode 0600 and no other protection. Protect it with
  disk encryption, or keep the key directory in a key store.
- **Local mode shares one process.** Without `--remote`, client and
  evaluator run in one process: anyone who compromises it sees both.
- **The evaluator speaks plain HTTP.** Put a TLS proxy in front of it.
- **No FHE key rotation and no threshold decryption.** One client holds
  each secret key.
- **Client side channels are out of scope,** and so are timing side
  channels of DP noise sampling.

## Encrypted computation

- **Exact FHE is slow.** Every AND, OR and XOR on OpenFHE exact is a
  bootstrapped gate of 54 to 62 ms on one core (Apple M3 Max, measured
  several times). The eligibility rule of example 19 needs 381 gates:
  31.1 s on one worker, 7.8 s on 8. The slowest corpus programs take
  69.6 s on one worker and 27.6 s on 8. An 8-bit addition costs 34 gates,
  a 32-bit multiplication 2,824 gates. Source:
  [docs/benchmarks.md](docs/benchmarks.md).
- **Exact evaluation keys are large.** About 525 MiB of BinFHE evaluation
  keys per client (bootstrapping and key switching), generated in about
  4.5 to 7 s and uploaded once per evaluator. Ciphertexts are 4.4 KiB per
  bit (141 KiB for a `u32`).
- **Exact programs support a fixed operation subset.** Integers `u8`–`u64`
  and `i8`–`i64`, and `bool`: `+ - *`, comparisons, `& | ^ ~`, shifts,
  `//` and `%` by public constants, `select`, `minimum`, `maximum`,
  `lookup` with tables up to 256 entries, and `cast`. No division by a
  secret, no secret indexing or loops, no floating point. Exact values at
  the API are integers within ±2^53. Anything else is refused at compile
  time.
- **BGV is used only for a narrow subset.** Programs whose operations are
  all `u8`, `u16` or `bool` additions, subtractions, multiplications,
  constants and Boolean logic may run on BGV. One operation outside the
  subset keeps the whole program on BinFHE.
- **One scheme per program.** Approximate (CKKS) and exact values cannot
  be mixed in one program, and BGV and BinFHE are never mixed within one
  program. Split the computation.
- **CKKS bootstrapping is not implemented.** A CKKS program's
  multiplicative depth is bounded by the largest 128-bit parameter set
  (N = 2^16); deeper programs are refused (ENC1201).
- **CKKS results are approximate** within the declared precision, and only
  for inputs within the declared ranges. The client checks ranges before
  encrypting; the evaluator cannot check them.
- **Functional bootstrapping is not used.** It was measured and was slower
  than Boolean gates on OpenFHE 1.5.1.
- **TFHE-rs is research only.** It is behind the off-by-default
  `research-tfhe-rs` feature, for research and differential testing. Zama
  requires a patent license for commercial use of TFHE-rs. Production
  builds refuse it (ENC1501 BACKEND UNAVAILABLE), and
  `scripts/audit-commercial-build.sh` checks that none of it is linked.

## Scale and deployment

- **Evaluators are single-node.** One job runs on one machine. Worker
  processes (`--workers N`) and parallel gates use the cores of that
  machine only. The control plane can schedule jobs across several
  evaluators, but there is no multi-machine execution of one job.
- **No high availability.** The Docker Compose deployment runs one
  control plane, one evaluator and one key broker. Migrations lock across
  control-plane replicas, but replicated control planes are not
  documented or tested.
- **The Compose OpenBao runs in development mode, in memory.** It stands
  in for a customer KMS in trials: its root keys disappear when it
  restarts, and its root token comes from `init.sh`. Point the key broker
  at your own OpenBao or Vault (over HTTPS) for real keys.
- **No built-in TLS.** No Encompute service terminates TLS, and the Compose
  deployment provides none. The control plane connects to PostgreSQL
  without TLS. Terminate TLS in front of every service and keep the
  database on a private network.
- **The newest audit events are only hash-chained.** Events after the last
  signed checkpoint (every 100 events by default) are covered by an
  unkeyed hash chain until the next checkpoint.
- **IDs can reveal existence through conflicts.** Other tenants' resources
  are "not found", but registering an ID that is already taken fails with
  a conflict.
- **Secrets have environment-variable fallbacks.** `*_FILE` is preferred,
  but production mode also accepts the plain variable (for example
  `ENCOMPUTE_DATABASE_URL`, `BAO_TOKEN`).
- **The CLI's SecAgg coordinator reports to the control plane directly,**
  without an outbox: if the control plane is unreachable, its privacy
  events are not retried later.
- **Only OpenBao and Vault Transit** are supported root-key providers.
  OpenBao 2.1.0 is tested in CI; Vault uses the same API but is not tested
  against Vault itself. There is no AWS, GCP or Azure KMS adapter.
- **No Kubernetes, Helm or message-broker adapter yet.** HTTP delivery
  with an outbox is the only message transport.
- **Evaluator machine profiles are self-reported.** They steer scheduling
  estimates only, never a security decision.
- **The scheduler's gate estimate is a constant.** It uses 55 ms per gate
  for every evaluator, whatever its hardware.
- **Platforms.** Supported: Linux x86_64 and macOS arm64. Linux arm64 is
  experimental. macOS x86_64 and Windows are not supported.
- **Benchmarks come from one machine type** (Apple M3 Max). Linux servers
  and real TEEs have not been benchmarked.

## Attestation and TEEs

- **Only Google Confidential Space** (Intel TDX) is implemented, and the
  live GCP run has not been done yet: it is rehearsed locally and in CI
  with a simulated launcher and a test JWKS. No AWS Nitro, Azure, AMD
  SEV-SNP or GPU TEE provider exists.
- **The mock attestation provider protects nothing.** It signs whatever it
  is told. Production policies and brokers refuse its evidence.
- **Attestation trusts the TEE vendor** and its attestation service (for
  Confidential Space: Google's verifier and launcher), and the reviewed
  image: the image digest is the measurement.

## Differential privacy

- **Central DP.** The SecAgg coordinator sees the aggregate before noise
  and is trusted to add the noise, as far as its attestation (bound to the
  privacy policy) goes. A coordinator that is not attested is trusted
  outright.
- **The privacy unit is what the data owner declares.** Patient-level
  guarantees hold only if `unit_ids` really identify patients, and every
  record of a patient carries the same ID. Encompute checks consistency,
  not truth.
- **Budgets cover releases through Encompute only.** Anything an owner
  releases about the same data elsewhere is not in the ledger.
- **Organization-level DP protects organizations, not individuals.** A
  hospital's whole update is the unit. Use patient-level DP-SGD
  (`privacy="strong-patient"`) to protect individual patients.
- **DP bounds what the released aggregate reveals** within (ε, δ). It
  does not hide the model architecture, the number of rounds or the
  training configuration, which are shared as metadata.
- **Randomness must be production randomness.** The deterministic noise
  feature exists for tests only and is refused in releases (ENC2204).
- **Secure aggregation does not guarantee a correct aggregate.** A
  malicious coordinator can abort a round or report a wrong aggregate. It
  cannot learn an honest party's input while it colludes with no more
  parties than the declared bound. Parties sign their messages; the
  coordinator's broadcasts are not signed.

## Confidential AI

- **PyTorch runs in plaintext inside the TEE.** Fine-tuning is protected
  by attestation, secure aggregation and DP, not by FHE. The TEE protects
  data in use.
- **Hugging Face support is narrow.** Only sequence classification, and
  only BERT and DistilBERT are tested end to end. RoBERTa is accepted but
  not tested end to end. Everything else is refused (ENC2504): decoder-only
  language models (GPT, Llama, Mistral and similar), text generation, token
  classification, question answering, vision and multimodal models, remote
  code (`trust_remote_code`, `auto_map`) and pickled weights.
- **Library versions are pinned per model package.** A package binds the
  major.minor versions of Transformers, PEFT and PyTorch it was imported
  with. Other versions are refused; re-import the model to move.
- **Only small models have been measured,** on CPU. GPU training,
  quantization and multi-GPU training are not tested or supported.
- **LoRA only.** Full fine-tuning and other adapter methods are not
  supported.

## Compatibility and upgrades

- **Every format reader accepts exactly one version.** There is no
  artifact migration tool yet (`encompute migrate` is planned). A compiler
  change can require recompiling `.encompute` artifacts, and clients and
  evaluators must run the same Encompute minor release. See
  [docs/compatibility.md](docs/compatibility.md).
- **Database migrations are forward only.** To downgrade, restore a backup
  taken before the upgrade.
- **Python 3.11 or later** is required. CI tests 3.11 and 3.12.
