# Encompute cryptographic design

This page lists every cryptographic mechanism Encompute uses, its
parameters, and the source file that implements it. It also says what each
mechanism does **not** give. The threat model is
[threat-model.md](threat-model.md). The protocol message formats are in
[security-review/protocols.md](../security-review/protocols.md).

Encompute builds on published schemes and standard libraries. It does not
design new cryptography. There is no formal proof of Encompute as a whole:
no proof that the composition of these mechanisms is secure. The evidence
is the assurance suite ([assurance.md](assurance.md)): tests of stated
invariants under attack, which cannot establish the security of the
primitives themselves.

## 1. Libraries and versions

| Library | Version | Used for | Pinned in |
|---|---|---|---|
| OpenFHE (`openfhe-development`) | v1.5.1, static libraries | CKKS, BinFHE, BGV | `scripts/install-openfhe.sh` (`OPENFHE_VERSION="v1.5.1"`), checked by `crates/encompute-openfhe/build.rs` |
| `ed25519-dalek` | 2.2.0 | every signature | `Cargo.lock` |
| `x25519-dalek` | 3.0.0 | SecAgg key agreement | `Cargo.lock` |
| `hpke` | 0.14.1 | sealing released keys to an attested session | `crates/encompute-attestation/Cargo.toml` |
| `chacha20poly1305` | 0.11.0 | every AEAD outside HPKE | `Cargo.lock` |
| `chacha20` | 0.10.2 | SecAgg mask PRG, DP noise CSPRNG | `Cargo.lock` |
| `vsss-rs` | 6.0.1 | Shamir secret sharing (SecAgg) | `crates/encompute-secagg/Cargo.toml` |
| `sha2` | 0.10.9 | every hash | `Cargo.lock` |
| `jsonwebtoken` | 11.1.0 | Confidential Space tokens and OIDC | `Cargo.lock` |
| `getrandom` | 0.2.17 (also 0.3, 0.4 transitively) | all randomness Encompute draws itself | `Cargo.lock` |
| `zeroize` | 1.9.0 | wiping key material in memory | `Cargo.lock` |
| TFHE-rs | 1.8.1 | **research builds only** (`research-tfhe-rs` feature); never in a production build | `scripts/audit-commercial-build.sh` checks |

OpenFHE is statically linked into the client, the evaluator and the Python
extension. `install-openfhe.sh` builds it from the `v1.5.1` git tag with
`-DWITH_OPENMP=ON`. The tag is fetched by name, not by commit hash.

## 2. Homomorphic encryption

Encompute uses three OpenFHE schemes. A program uses exactly one; schemes
never mix inside a program, and nothing converts between them.

| Program kind | Scheme | When |
|---|---|---|
| Approximate (real numbers) | CKKS (RNS) | always |
| Exact (integers, Booleans) | BinFHE, profile `BINFHE_STD128_GINX_BITS_V1` ("OpenFHE exact") | default for exact programs |
| Exact, in the BGV subset | BGV (RNS), plaintext modulus 65537 | programs compiled with `verification="required"`; and unverified programs whose every operation is in the subset when BGV is estimated no slower |

### 2.1 CKKS

Context creation: `make_context` in
`crates/encompute-openfhe/cpp/shim.cc` (lines 31-45).

| Setting | Value |
|---|---|
| Security level passed to OpenFHE | `HEStd_128_classic` |
| Secret key distribution | `UNIFORM_TERNARY` |
| Scaling | `FLEXIBLEAUTO` |
| Key switching | `HYBRID` |
| Features enabled | `PKE`, `KEYSWITCH`, `LEVELEDSHE` (no bootstrapping, no multiparty) |
| Ring dimension, depth, scale, first modulus, digits, batch size | chosen by Encompute (below) and passed explicitly |

Parameter selection: `select_params` in
`crates/encompute-ckks/src/params.rs`.

- **Scale bits** = ⌈log2(1/precision)⌉ + ⌈log2(max |value|)⌉ + 22, at least
  30 and at most 59. The 22-bit margin is calibrated against measured error;
  `encompute test` is the gate, not a proof.
- **First modulus bits** = scale bits + ⌈log2(max |value|)⌉ + 3, at most 60.
- **Multiplicative depth** = the plan's depth (at least 1); number of
  primes = depth + 1.
- **Key-switching digits (dnum)**: the first of 3, 2, 1 that OpenFHE
  accepts for that number of primes.
- **log2(Q·P)** is estimated the way OpenFHE v1.5.1 computes it
  (`estimate_log_qp`, mirroring `ParamsGenCKKSRNSInternal` and
  `EstimateLogP`).
- **Ring dimension** N: the smallest entry of the security table whose
  maximum log2(Q·P) is at least the estimate and whose N/2 is at least the
  slot count.

Security table (`SECURITY_TABLE` in `params.rs`): the HE Standard 128-bit
classical bounds for a uniform ternary secret, as pinned in OpenFHE v1.5.1
(`src/core/lib/lattice/stdlatticeparms.cpp`, `HEStd_ternary` /
`HEStd_128_classic`):

| N | 1024 | 2048 | 4096 | 8192 | 16384 | 32768 | 65536 |
|---|---|---|---|---|---|---|---|
| max log2(Q·P) | 27 | 54 | 109 | 218 | 438 | 881 | 1747 |

N is capped at 2^16. A program that needs more is refused (ENC code
`DepthExceeded`); a precision that needs more than a 59-bit scale is
refused (`PrecisionUnreachable`). Parameters are never weakened to fit.

Checks:

- OpenFHE re-checks the parameters against its own table when the context
  is created (`HEStd_128_classic`).
- `parameter_selection_conforms_to_table_and_openfhe`
  (`crates/encompute-openfhe/tests/conformance.rs`) runs a grid of depths,
  precisions, value bounds and slot counts. It asserts that Encompute's ring
  equals OpenFHE's minimum (larger only for slots) and that OpenFHE's
  actual log2(Q·P) is within Encompute's estimate and the table limit.
  Invariant INV-004.

Encryption and keys (`crates/encompute-openfhe-client/cpp/client.cc`):

- The client runs `KeyGen`, `EvalMultKeyGen` and, when the plan rotates,
  `EvalRotateKeyGen` for exactly the plan's rotation indices.
- Inputs are encrypted with the **public key** (`Encrypt(pk, …)`).
- The evaluator receives the relinearization key and the rotation keys
  only (`SerializeEvalMultKey`, `SerializeEvalAutomorphismKey`). It does not
  receive the public key or the secret key.

**IND-CPA-D.** CKKS is not IND-CPA-D secure (Li and Micciancio, 2021). An
evaluator that sees decryptions of ciphertexts it computed can recover the
secret key. Encompute applies no noise flooding. Decrypted results must
never be returned to the evaluator. The artifact's `security.json` and
`encompute audit` state this condition
(`crates/encompute-runtime/src/artifact.rs`, `audit.rs`). Nothing in the
code can enforce it: it is a condition on how the deployment uses results.

### 2.2 BinFHE: OpenFHE exact

Profile: `openfhe_exact_profile` in `crates/encompute-exact/src/bits.rs`
(lines 876-894).

| Field | Value |
|---|---|
| Backend | `openfhe-exact` |
| Backend version | `1.5.1` |
| Profile | `BINFHE_STD128_GINX_BITS_V1` |
| OpenFHE parameter set | `STD128` |
| Bootstrapping | GINX (chosen by name in `method_of`, `crates/encompute-openfhe/cpp/binfhe.cc`) |
| Stated security | `"128-bit"` |
| Stated failure probability | `"2^-135 per gate"` |
| Selector version | `openfhe-exact-v1` |

Representation: each exact value is a vector of BinFHE ciphertexts, one
per bit, two's complement, least significant bit first. Every operation is
a Boolean circuit of bootstrapped gates (AND, OR, XOR, NOT and constants).
The integer semantics are Encompute's code (`crates/encompute-exact/src/bits.rs`,
`circuit.rs`), not OpenFHE's.

The parameter-set ID is the SHA-256 of the profile's canonical JSON
(`parameter_id`, `crates/encompute-openfhe-exact/src/lib.rs`). The
evaluator accepts only this exact profile (`OpenFheGates::new` compares the
whole profile).

What this does **not** establish:

- **The security and failure-probability values are labels.** `"128-bit"`
  and `"2^-135 per gate"` are strings in the profile, bound into the
  parameter ID. Encompute does not measure or recompute them. They restate
  OpenFHE's documentation for its `STD128` set with GINX. The test
  `the_profile_is_vetted_and_bound_into_the_parameter_id` only checks that
  changing a label changes the ID.
- **No test checks the concrete LWE parameters.** `BinContext::lwe()`
  (`crates/encompute-openfhe/src/binfhe.rs`) returns the context's `n` and
  `q`, but nothing calls it. The lattice parameters are whatever OpenFHE
  v1.5.1 defines for `STD128`.
- **Ciphertext load checks only `n` and `q`.** `bin_load`
  (`binfhe.cc` lines 105-112) refuses a ciphertext whose LWE length or
  modulus differs from the context's. It does not check anything else about
  the ciphertext. Bootstrapping and key-switching keys are deserialized
  (`bin_load_keys`) without a parameter check of their own; the envelope's
  parameter ID is the check.
- The shim also accepts `STD128Q` and `STD128_LMKCDEY` (`bin_paramset`),
  but the vetted profile names only `STD128`, and `OpenFheGates::new`
  refuses any other profile.

Encryption and keys (`crates/encompute-openfhe-client/cpp/binclient.cc`,
`crates/encompute-openfhe-client/src/exact.rs`):

- The client runs `KeyGen` and `BTKeyGen` (bootstrapping and key-switching
  keys).
- Bits are encrypted with the **secret key** (symmetric LWE,
  `Encrypt(sk, bit)`).
- The evaluator receives the refresh (bootstrapping) key and the switching
  key, about 525 MiB per client. It never receives the secret key.

Concurrency: gates run in parallel through `bin_gate_concurrent`
(`binfhe.cc` lines 153-180), which calls OpenFHE's `EvalBinGate` without
the global OpenFHE lock. The Rust side argues safety from borrowing rules
and stress tests (`BinContext::gate_concurrent`). The `SAFETY` comment on
the `Send`/`Sync` impls in `binfhe.rs` and the comment in
`cpp/common.h` still say every call holds the lock; that is no longer
true for this function.

### 2.3 BGV

Context: `make_bgv_context` in `crates/encompute-openfhe/cpp/shim.cc`
(lines 49-59); profile: `profile` in `crates/encompute-exact/src/bgv.rs`.

| Setting | Value |
|---|---|
| Plaintext modulus | 65537 |
| Security level | `HEStd_128_classic` (OpenFHE chooses the ring dimension) |
| Scaling | `FIXEDAUTO` |
| Key switching | `HYBRID` |
| Secret key distribution | OpenFHE's default (not set by Encompute) |
| Multiplicative depth | from the plan (`mult_depth`): each ciphertext product, product by a constant, and Boolean AND/OR/XOR takes a level |
| Profile name | `BGVRNS_T65537_DEPTH{d}_HEStd128_FIXEDAUTO_HYBRID` |
| Stated failure probability | `"0 (exact modular arithmetic)"` |

The BGV subset: types `u8`, `u16`, `bool`; operations input, `+`, `-`,
`*`, constant add/sub/mul, constant minus value, `&`, `|`, `^`, `~`
(`capabilities` in `bgv.rs`). Range analysis proves values never wrap
modulo 65537.

The "0" failure probability is a claim about the arithmetic being exact.
Decryption correctness still depends on OpenFHE's modulus choice for the
declared depth; Encompute does not compute a noise bound of its own.

Encryption is with the public key (`client.cc`, line 212).

**Re-execution proofs (research build, `vfhe-research`).** For a verified
program the client re-runs the BGV computation over the exact ciphertexts
it sent, with its own evaluation keys, and decrypts only if the
evaluator's response matches byte for byte (`crates/encompute-vfhe`,
decision record [0009](adr/0009-vfhe-proof-backend.md)). This relies on
OpenFHE BGV evaluation being deterministic (no randomness in evaluation),
as `cpp/common.h` states. The proof is sound but not succinct: verifying
costs about one evaluation. It is not a zero-knowledge proof and not a
proof of correct decryption. INV-022.

### 2.4 Scheme and parameter binding

- Parameter-set IDs: SHA-256 of the canonical parameter JSON
  (`CkksParams::canonical_json`, `ExactProfile::canonical_json`).
- The execution spec binds program, plan, parameter set, scheme, backend
  and policy; its ID is a domain-separated SHA-256
  (`encompute.execution-spec.v1`, `crates/encompute-verification/src/spec.rs`).
- Envelopes carry the scheme and parameter-set ID; a reader refuses any
  mismatch (section 4).

### 2.5 Randomness inside OpenFHE

Encompute does not configure OpenFHE's pseudorandom generator. Key
generation and encryption use OpenFHE v1.5.1's default PRNG and its
default seeding. Reviewers should confirm the seeding source on each
target platform (see the crypto review brief).

## 3. Key ownership

| Key | Generated by | Held by | Can decrypt |
|---|---|---|---|
| CKKS / BGV secret key | client (`encompute keys generate`, or the SDK) | client only | the client |
| CKKS / BGV public key | client | client | nobody |
| CKKS relinearization and rotation keys; BGV evaluation keys | client | client and evaluator | nobody |
| BinFHE secret key | client | client only | the client |
| BinFHE bootstrapping and switching keys | client | client and evaluator | nobody |
| Evaluator identity (Ed25519) | evaluator operator | evaluator | n/a (signs receipts) |
| Service identities (Ed25519) | each service's operator | that service | n/a |
| SecAgg party identity (Ed25519) and per-round X25519 keys | each party | that party | its own shares |
| Asset keys (32 bytes) | key broker (`KeyMaterial::generate`) | key broker, wrapped; released to attested workloads | the attested workload |
| Broker KEK (32 bytes) | key broker | broker, wrapped by the root key | n/a |
| Customer root key | customer KMS (OpenBao or Vault Transit) | the KMS; never exported | n/a |
| HPKE session key (X25519) | inside the attested workload | that workload, in memory | grants sealed to it |

Rules:

- The evaluator never receives a secret key. Its binary contains no
  Encompute key-generation, encryption or decryption code; the audit
  `scripts/audit-evaluator-binary.sh` checks symbol names with `nm`
  (INV-010).
- **The evaluator binary does link OpenFHE's own `KeyGen`, `Encrypt` and
  `Decrypt`.** OpenFHE is one static library, and those routines are
  linked with it. The audit reports OpenFHE's `Decrypt(` symbols and does
  not fail on them. The guarantee is that the evaluator never receives a
  secret key, not that it cannot run decryption code.
- **`secret.key` is stored unencrypted.** `encompute keys generate`
  writes the secret-key envelope to `secret.key` with mode 0600 on Unix
  (`write_keys`, `crates/encompute-cli/src/main.rs`). There is no
  passphrase and no AEAD. The mode is applied only when the file is
  created; an existing file keeps its permissions. Protecting the file is
  the client machine's job.
- There is no FHE key rotation and no threshold decryption.

## 4. Ciphertext integrity and binding

FHE ciphertexts are malleable by design: anyone with the evaluation keys
can compute on them. Encompute does not authenticate ciphertexts
cryptographically. What it binds, and what that gives:

### 4.1 Envelopes

Two envelope formats wrap every FHE object:

- **`ENCM`** (`crates/encompute-protocol/src/lib.rs`): magic, format
  version, a JSON header (kind, scheme, backend, backend version,
  parameter-set ID, program ID, key ID, item lengths), payload, then the
  SHA-256 of everything before. Readers state what they expect
  (`Expect`) and any mismatch is refused with a specific code.
  - CKKS key ID: SHA-256 of the evaluation-key payload.
  - Program ID: SHA-256 of the artifact's `program.eir`.
- **`ENCBINF1`** (`crates/encompute-openfhe-exact/src/lib.rs`): magic,
  version, backend name, parameter-set ID, 16-byte key ID, object kind,
  element type, length-prefixed payloads, then the SHA-256 of everything
  before. Length and count limits: payload ≤ 1 GiB, ≤ 65 536 payloads.

What this gives:

- A reader refuses an object of the wrong kind, scheme, backend, parameter
  set, program or key before any OpenFHE call runs (INV-006, INV-008,
  INV-152).
- Accidental corruption and truncation are detected.

What this does **not** give:

- **The checksums are unkeyed.** A plain SHA-256 detects corruption, not
  an attacker. Anyone who can change the bytes can recompute the checksum.
- **The BinFHE key ID is a random label, not a commitment to the key.**
  `OpenFheExactClient::generate` draws it from `getrandom`
  (`crates/encompute-openfhe-client/src/exact.rs`). It is not derived from
  the key material, so it names a key but does not prove which key
  produced a ciphertext.
- No envelope proves who created it, or that a ciphertext encrypts what
  the client intended. An attacker on the path can substitute a
  well-formed ciphertext under the same key ID.

Integrity against an active attacker comes from other layers:

- **Receipts** bind the exact request and response bytes (section 5).
- **TLS** in front of each service protects transport (the services
  themselves speak plain HTTP; see the threat model).
- **Re-execution proofs** (research) catch a wrong result.

### 4.2 OpenFHE serialization trust boundary

- OpenFHE objects are serialized with `Serial::Serialize` / `Deserialize`
  in `SerType::BINARY` (cereal-based).
- The evaluator deserializes **client-supplied** bytes: evaluation keys,
  bootstrapping keys and ciphertexts. OpenFHE's deserializers were not
  written for hostile input. A malformed payload that passes the envelope
  checks reaches OpenFHE's parser.
- Encompute's defenses: the envelope is checked first (magic, checksum,
  lengths, kind, parameters, key); exceptions from OpenFHE are caught and
  turned into errors; after loading, the CKKS shim checks that a
  ciphertext belongs to the loaded context and to a key whose evaluation
  keys are loaded (`load_ciphertext`, `shim.cc`); the BinFHE shim checks
  `n` and `q`.
- INV-007 tests that Encompute's own parsers never panic on arbitrary
  input. There is no fuzzing of OpenFHE's deserializers.
- Treat the OpenFHE deserializer as part of the evaluator's attack
  surface. Memory-safety issues in the shim or OpenFHE are in scope for
  security reports (SECURITY.md).

## 5. Receipts, transcripts and proofs

- **Execution receipt** (`crates/encompute-verification/src/receipt.rs`):
  the evaluator signs, with Ed25519, `SHA256("encompute.execution-receipt.v1"
  || 0x00 || canonical JSON of the receipt)`. The receipt holds the spec,
  program, plan, parameter-set and key IDs, commitments to the exact
  request and response envelope bytes, scheme, backend, the transcript
  hash (exact programs), the evaluator ID, proof evidence and, when
  attested, the workload session.
- **A receipt is a signed claim, not a proof.** It makes the evaluator's
  statement attributable and non-transferable to another execution
  (INV-020, INV-021). It does not show that the evaluator computed
  honestly: an evaluator can sign a fabricated result.
- **Semantic transcript** (exact programs): the canonical operation list
  from request to result, with no runtime values. Its hash is in the
  receipt. It fixes what a proof must establish; it proves nothing itself
  (INV-023).
- **Execution proof**: only the research re-execution proof on BGV
  (section 2.3) shows correct execution.

## 6. Hashes and signatures

- **Hash:** SHA-256 everywhere. Object IDs use domain separation:
  `SHA256(domain || 0x00 || bytes)` (`crates/encompute-verification/src/hash.rs`),
  with one domain per object type (for example `encompute.execution-spec.v1`,
  `encompute.job-grant.v1`, `encompute.privacy-ledger.v1`). SecAgg uses the
  same pattern with length-prefixed parts (`tagged` in
  `crates/encompute-secagg/src/crypto.rs`).
- **Canonical encoding:** canonical JSON (`crates/encompute-verification/src/canonical.rs`)
  is hashed and signed, never an arbitrary serialization.
- **Signatures:** Ed25519 (`ed25519-dalek` 2.2) for execution receipts,
  service requests and messages, job grants, audit checkpoints, the state
  anchor, owner authorizations and revocations, SecAgg messages and
  aggregation receipts, privacy receipts, adapter records and mock
  attestation. SecAgg and mock attestation verify with `verify_strict`.
- **Confidential Space tokens:** RS256 JWTs from Google, verified against
  Google's JWKS (`crates/encompute-attestation/src/gcp.rs`).

## 7. Sealed keys and data (AEAD)

| Use | Construction | Nonce | Associated data | Source |
|---|---|---|---|---|
| Released asset key → attested workload | HPKE (RFC 9180) base mode, X25519-HKDF-SHA256, HKDF-SHA256, ChaCha20-Poly1305 | HPKE | `info = "encompute.key-grant.v1"`; `aad` = canonical grant header (broker, asset, key version, policy, spec, session, binding hash, attestation digest, expiry) | `crates/encompute-attestation/src/grant.rs` |
| Asset key wrapped under the broker KEK | ChaCha20-Poly1305, 32-byte KEK | 12 random bytes | `"encompute.broker-key.v1\0{broker}\0{asset}\0{version}"` | `crates/encompute-keybroker/src/store.rs` |
| KEK wrapped under the customer root key | OpenBao/Vault Transit `encrypt`/`decrypt` (the key type is set when the Transit key is created, outside Encompute) | Transit | `"encompute.root-wrapped-kek.v1\0{organization}"` as Transit associated data | `crates/encompute-keybroker/src/root.rs` |
| Development root key | ChaCha20-Poly1305 | 12 random bytes | as above | `root.rs` (`DevelopmentRootKey`, development only) |
| Sealed models, datasets, adapters, checkpoints | ChaCha20-Poly1305 (`ENCSEAL1` format), 32-byte asset key | 12 random bytes | magic, header length and canonical header (kind, project, asset, digest) | `crates/encompute-training/src/seal.rs` |
| SecAgg share encryption | ChaCha20-Poly1305, per-pair per-round key | `[from, to, 0…]` | `tagged("encompute.secagg.share-ciphertext.v1", round, from, to)` | `crates/encompute-secagg/src/crypto.rs`, `protocol.rs` |

Notes:

- HPKE base mode does not authenticate the sender. The broker does not
  sign grants. A workload knows a grant opens under its session key, not
  that the broker produced it.
- Key rotation via Transit rewrap is done as decrypt-then-encrypt, because
  Transit's `rewrap` endpoint ignores associated data (`root.rs`).
- Random-nonce ChaCha20-Poly1305 has a 96-bit nonce; with the number of
  wraps per key in this system, collisions are not a practical concern,
  but no counter enforces a limit.
- Key material in memory is held in `Zeroizing` buffers in the key broker,
  HPKE grants, sealed assets and SecAgg. Not every copy is wiped (for
  example the development root key's hex strings).

## 8. Secure aggregation

Protocol basis: Bonawitz et al., "Practical Secure Aggregation for
Privacy-Preserving Machine Learning" (CCS 2017), the variant secure
against a malicious coordinator. Implementation:
`crates/encompute-secagg/src/{crypto,protocol,round}.rs`; decision record
[0012](adr/0012-secure-aggregation.md).

Primitives (`crypto.rs`):

- **Key agreement:** X25519; non-contributory (low-order) results are
  refused.
- **Key derivation:** `SHA256(label || 0x00 || len || round_id || len || DH)`,
  labels `encompute.secagg.share-key.v1` and `encompute.secagg.mask-key.v1`.
  It is not HKDF.
- **Mask PRG:** the ChaCha20 keystream (RFC 8439) keyed by the seed, zero
  nonce, read as little-endian u64 values reduced mod 2^m.
- **Share encryption:** ChaCha20-Poly1305 (table in section 7).
- **Secret sharing:** Shamir over GF(2^8), byte-wise (`vsss-rs`). Party IDs
  1..255, so at most 255 parties per round.
- **Signatures:** Ed25519, strict verification. Party keys are fixed in the
  aggregation spec, which acts as the PKI.

Security parameters:

- **Threshold:** `t = max(minimum, ⌊(n + colluding)/2⌋ + 1)`. A bound the
  parties cannot meet (`t > n` or `colluding ≥ n`) is refused.
- The coordinator learns masked vectors, participation sets, and the sum
  modulo 2^m. It cannot collect both the self-mask share and the mask-key
  share of one honest party while colluding with at most `colluding`
  parties (INV-052, INV-053).
- **No output integrity.** A malicious coordinator can abort a round or
  release a wrong aggregate. Coordinator broadcasts are not signed; the
  protection rests on party-signed contents.
- Quantization: fixed-point codec with clip range, scale and `modulus_bits`
  (8 to 62); an overflow of `levels × participants ≥ 2^modulus_bits` is a
  compile error (INV-055).

## 9. Differential privacy

Implementation: `crates/encompute-privacy`; decision records
[0013](adr/0013-differential-privacy.md) and
[0017](adr/0017-patient-level-dp.md).

- **Mechanism:** the discrete Gaussian, sampled exactly with a
  line-by-line port of Canonne, Kamath and Steinke's reference sampler
  (NeurIPS 2020), in big-integer rational arithmetic
  (`sampler.rs`). The variance σ² is an integer.
  - Randomness: `Csprng`, the ChaCha20 keystream under a 32-byte key from
    the OS (`getrandom`), fresh per release.
  - A seeded generator exists only behind the `insecure-deterministic-noise`
    feature; its output is labelled `INSECURE-DETERMINISTIC-TESTING-ONLY` in
    the ledger and refused by verification.
  - The sampler is not constant-time (rejection loops). Timing side
    channels of noise sampling are out of scope.
- **Noise and sensitivity** (`release.rs`): σ² = ⌈(z · clip · scale)²⌉;
  Δ = ⌈k · clip · scale⌉ + ⌈√d⌉, with k = 2 for organization-level units
  and 1 otherwise; the √d term covers rounding.
- **zCDP accounting** (`accountant.rs`): ρ = Δ²/(2σ²) per release (CKS
  2020, Theorem 14); composition by addition; conversion to (ε, δ) with
  CKS Corollary 13, ported from `cdp2adp.py`. Arithmetic uses `libm` so
  every party gets identical bits, and results round up. Accountant ID
  `zcdp-cks2020`.
- **Rényi DP for Poisson-subsampled releases** (`rdp.rs`, DP-SGD): the
  general upper bound of Zhu and Wang (2019, Theorem 6) for integer orders
  2..256 plus eight larger orders up to 1024, capped by αρ; conversion by
  CKS Proposition 12. The Gaussian-specific bound is deliberately not used,
  because the noise is discrete. Checked against autodp and an mpmath
  evaluation on 240 cases (INV-131). Accountant ID `rdp-poisson-zw2019`.
- **Where noise is added:** central DP. The SecAgg coordinator adds noise
  to the unmasked sum (`round.rs`, `finalize`). It sees the sum before
  noise and is trusted to add it, as far as its attestation (bound to the
  privacy policy) goes.
- **DP-SGD** (`python/encompute/torch/dpsgd.py`): per-example gradients,
  summed per privacy unit, clipped per unit, Poisson sampling of units,
  noise added by the coordinator to the securely aggregated sum.
  - Sampling: a `torch.Generator` (Mersenne Twister) seeded with 64 bits
    from `os.urandom`, then `torch.rand(…) < q` in float32. This is not a
    CSPRNG stream, and q has float32 resolution. The seed is fresh per call
    and inside the attested worker (INV-132).
- **Presets** (`crates/encompute-ir/src/confidentiality.rs`), clip norm 1.0:

  | Name | ε | δ | Noise multiplier z |
  |---|---|---|---|
  | `standard` | 8.0 | 1e-5 | 2.2 |
  | `strong` | 3.0 | 1e-6 | 6.0 |
  | `maximum` | 1.0 | 1e-7 | 18.0 |
  | `standard-patient` (DP-SGD) | 8.0 | 1e-5 | 1.0 |
  | `strong-patient` (DP-SGD) | 3.0 | 1e-6 | 1.2 |

- **Ledgers** (`ledger.rs`): hash-chained JSON lines per asset, reserve
  before noise and commit after, exclusive file lock, fsync per append;
  privacy receipts signed with Ed25519 by the releasing coordinator.

## 10. Randomness

| Randomness | Source |
|---|---|
| FHE keys and encryption | OpenFHE's internal PRNG (not configured by Encompute) |
| BinFHE key ID, receipt execution IDs, request nonces, message IDs | `getrandom` (OS) |
| Ed25519 identity seeds, asset keys, KEKs, AEAD nonces, attestation challenge nonces | `getrandom` (OS) |
| HPKE ephemeral and session keys | `getrandom` via the `hpke` crate |
| SecAgg DH secrets, self-mask seeds, round nonces, Shamir coefficients | `getrandom` (OS) |
| DP noise | ChaCha20 under an OS-random key |
| DP-SGD Poisson sampling | Mersenne Twister seeded from 64 bits of `os.urandom` |

If the OS generator fails, key-generating code returns an error (the
SecAgg Shamir adapter panics instead).

## 11. What is not claimed

- No formal proof of Encompute as a whole, or of any composition of these
  mechanisms.
- No authenticated encryption of FHE ciphertexts, and no proof of correct
  execution outside the research re-execution proof.
- No IND-CPA-D security for CKKS.
- No output integrity for secure aggregation.
- No independent measurement of BinFHE's failure probability or of the
  concrete security of OpenFHE's parameter sets beyond the HE Standard
  tables OpenFHE ships.
- No side-channel resistance claims (timing, cache, power) for the client,
  the sampler or OpenFHE.
