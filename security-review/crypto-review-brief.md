# Cryptography review brief

For the external cryptography reviewer. Each property below states the
claim, where it is implemented, how it is tested, and the questions we
want answered. Background: [cryptography.md](../docs/cryptography.md),
[threat-model.md](../docs/threat-model.md), [protocols.md](protocols.md).

Out of scope for this brief: application security of the control plane
and services ([appsec-review-brief.md](appsec-review-brief.md)), and TEE
hardware.

Encompute has no formal proof of the system as a whole. We want your view
of where a proof, or a stronger argument, is most needed.

## P1. OpenFHE parameter selection

**Claim.** Every CKKS, BinFHE and BGV context meets 128-bit classical
security according to the HE Standard tables that OpenFHE v1.5.1 ships.
Depth or precision that cannot be reached is refused, never weakened
(INV-004, INV-153).

**Where.**

- CKKS: `crates/encompute-ckks/src/params.rs` (`select_params`,
  `estimate_log_qp`, `SECURITY_TABLE`, `NOISE_MARGIN_BITS = 22`);
  `crates/encompute-openfhe/cpp/shim.cc` (`make_context`:
  `HEStd_128_classic`, `UNIFORM_TERNARY`, `FLEXIBLEAUTO`, `HYBRID`).
- BinFHE: `crates/encompute-exact/src/bits.rs` (`openfhe_exact_profile`),
  `crates/encompute-openfhe/cpp/binfhe.cc` (`bin_paramset`, `method_of`).
- BGV: `crates/encompute-exact/src/bgv.rs` (`profile`, `mult_depth`),
  `shim.cc` (`make_bgv_context`: t = 65537, `HEStd_128_classic`,
  `FIXEDAUTO`, `HYBRID`).
- OpenFHE pin: `scripts/install-openfhe.sh` (tag `v1.5.1`),
  `crates/encompute-openfhe/build.rs`.

**Tests.**

- `parameter_selection_conforms_to_table_and_openfhe` and
  `refusals_are_justified` (`crates/encompute-openfhe/tests/conformance.rs`);
  nightly: the full 10 080-point grid.
- `shallow_circuit_fits_small_ring`, `errors_have_codes` (`params.rs`).
- `the_profile_is_vetted_and_bound_into_the_parameter_id`
  (`crates/encompute-openfhe-exact/src/lib.rs`): only checks that labels
  are bound into the parameter ID.

**Known gaps.**

- The BinFHE values "128-bit" and "2^-135 per gate" are strings, not
  measured. No test reads the concrete LWE `n` and `q`
  (`BinContext::lwe()` is unused).
- BGV relies on OpenFHE to choose the ring dimension and moduli for the
  depth; Encompute computes no noise bound for it.
- OpenFHE is fetched by tag, not by commit hash.

**Questions.**

1. Is the HE Standard ternary-secret table the right basis in 2026, given
   recent lattice-estimator results? At which ring dimensions is the margin
   thinnest?
2. Does `estimate_log_qp` match OpenFHE v1.5.1 for every accepted
   combination, including the `dnum` choice? Can Encompute accept
   parameters that OpenFHE silently adjusts?
3. Is the 22-bit CKKS noise margin adequate for deep circuits with
   `FLEXIBLEAUTO`, or can precision fail silently within the declared
   target?
4. Are OpenFHE's `STD128` / GINX parameters and its stated failure
   probability appropriate for circuits of the sizes in
   `docs/benchmarks.md` (up to millions of gates)? What is the
   program-level failure probability?
5. For BGV with t = 65537 and the depths Encompute produces, is decryption
   failure negligible with OpenFHE's modulus choice?

## P2. Exact lowering semantics, and the optimizer against the reference

**Claim.** Accepted exact programs compute the reference interpreter's
result bit for bit. Possible overflow is a compile error. The optimized
circuit equals the reference lowering for every strategy and worker count,
and optimization never bypasses range or overflow checks (INV-002,
INV-003, INV-149, INV-166, INV-167, INV-168).

**Where.**

- `crates/encompute-exact/src/bits.rs` (bit-level integer semantics:
  ripple-carry add, comparisons from carry-out, shift-and-add multiply,
  restoring division by constants, lookups as multiplexer trees).
- `crates/encompute-exact/src/circuit.rs` (optimizer: range-aware widths,
  constant folding, Boolean simplification, common subexpressions,
  parallel-prefix adders, deterministic parallel scheduling).
- `crates/encompute-analysis` (range and overflow analysis).
- `crates/encompute-openfhe/cpp/binfhe.cc` (`bin_gate_concurrent`: gates
  without the global OpenFHE lock).

**Tests.** `eight_bit_operations_are_exhaustively_exact`
(`crates/encompute-exact/tests/bits.rs`);
`random_programs_are_identical_under_every_strategy_and_worker_count`,
`adversarial_boundaries`,
`optimization_cannot_bypass_range_or_overflow_validation`
(`tests/circuit.rs`); `exact_analysis_is_sound`
(`crates/encompute-analysis/tests/exact.rs`);
`optimized_circuits_equal_reference_on_openfhe`,
`random_programs_on_openfhe_exact`
(`crates/encompute-openfhe-client/tests/exact.rs`). Nightly: a
25 000-program differential run.

**Questions.**

1. The optimizer drops bits that the declared input ranges rule out. The
   client enforces ranges before encrypting, but the evaluator cannot. If a
   client encrypts an out-of-range value, is the only effect a wrong result
   for that client, or can it leak anything?
2. Is running `EvalBinGate` concurrently on one `BinFHEContext`, without
   the global lock, safe in OpenFHE v1.5.1 (shared state in the
   bootstrapping keys, OpenMP, internal caches)? The `SAFETY` comment in
   `crates/encompute-openfhe/src/binfhe.rs` predates this path.
3. Are signed division and remainder semantics (truncating) and the
   two's-complement comparisons correct at the type boundaries?
4. Does any optimization make the gate count or timing depend on secret
   values (it should depend only on the program and declared ranges)?

## P3. Client and evaluator key separation

**Claim.** The evaluator never receives a secret key, and its binary
contains no Encompute key-generation, encryption or decryption code
(INV-010, INV-011).

**Where.**

- Client: `crates/encompute-openfhe-client/cpp/client.cc`
  (`KeyGen`, `EvalMultKeyGen`, `EvalRotateKeyGen`, public-key `Encrypt`),
  `cpp/binclient.cc` (`KeyGen`, `BTKeyGen`, secret-key `Encrypt`),
  `src/exact.rs`.
- Evaluator: `crates/encompute-openfhe`, `crates/encompute-openfhe-exact`,
  `crates/encompute-evaluator`.
- Audit: `scripts/audit-evaluator-binary.sh` (symbol names via `nm`).
  `encompute audit --evaluator` (`crates/encompute-runtime/src/audit.rs`)
  is a weaker variant.
- Secret key at rest: `write_keys` in `crates/encompute-cli/src/main.rs`
  (`secret.key`, mode 0600 when created, unencrypted).

**Tests.** The audit script (CI); `remote_round_trip_uploads_program_and_keys_once`
(`crates/encompute-runtime/tests/network.rs`); `remote_receipts_and_verify`
(`crates/encompute-cli/tests/cli.rs`); `scripts/two-machine-demo.sh`.

**Known facts.** The evaluator binary links OpenFHE's own `KeyGen`,
`Encrypt` and `Decrypt`, because OpenFHE is one static library. The
guarantee rests on the evaluator never receiving a secret key.

**Questions.**

1. Can any evaluation key Encompute sends (CKKS relinearization and
   rotation keys, BinFHE refresh and switching keys, BGV multiplication
   keys) be combined with what the evaluator sees to recover the secret
   key, other than through IND-CPA-D (P8)?
2. Are the BinFHE bootstrapping keys (about 525 MiB) safe to cache and
   share read-only across concurrent jobs of the same client
   (`crates/encompute-evaluator/src/keycache.rs`)?
3. Is a symbol-name audit adequate evidence, or should the audit be
   replaced by a link-level check?

## P4. Ciphertext and protocol binding

**Claim.** Every FHE object travels in an envelope bound to kind, scheme,
backend, parameter set, program and key. A mismatched object is refused
before any OpenFHE call runs (INV-006, INV-008, INV-152).

**Where.** `crates/encompute-protocol/src/lib.rs` (`ENCM`),
`crates/encompute-openfhe-exact/src/lib.rs` (`ENCBINF1`),
`crates/encompute-openfhe/cpp/shim.cc` (`load_ciphertext`: context and key
tag checks), `binfhe.cc` (`bin_load`: LWE `n` and `q`).

**Tests.** `every_binding_is_enforced`, `mutations_never_pass_or_panic`,
`arbitrary_bytes_never_panic` (`crates/encompute-protocol/tests/envelope.rs`);
`wrong_keys_parameters_backends_and_corruption_fail_closed`
(`crates/encompute-openfhe-client/tests/exact.rs`);
`examples/19_openfhe_exact/forge.py`.

**Known limits.**

- The envelope checksums are unkeyed SHA-256: they detect corruption, not
  an attacker.
- The BinFHE key ID is a random 16-byte label, not a commitment to the key.
- Only LWE `n` and `q` are checked when a BinFHE ciphertext is loaded.
- OpenFHE's `Serial::Deserialize` parses client-supplied bytes on the
  evaluator, and evaluator-supplied bytes on the client. It is not fuzzed.

**Questions.**

1. Given malleable ciphertexts and unkeyed envelopes, what can a network
   attacker achieve without TLS, beyond what receipts detect? Should
   envelopes be MACed or signed?
2. Can a ciphertext crafted for another key but carrying this key's ID
   (BinFHE) cause anything worse than a wrong result?
3. Should the BinFHE key ID be derived from the bootstrapping-key bytes, as
   the CKKS key ID is?
4. Which OpenFHE deserializers are reachable with attacker-controlled
   bytes, and what validation do they perform?

## P5. Secure aggregation

**Claim.** Bonawitz et al.'s protocol, malicious-coordinator variant: a
coordinator colluding with at most `colluding` parties learns no honest
party's input; dropouts down to the threshold still give the survivors'
sum; below it nothing is released (INV-050 to INV-055).

**Where.** `crates/encompute-secagg/src/crypto.rs` (X25519 with
contributory check; KDF = domain-separated SHA-256 over round ID and DH
output; ChaCha20 mask PRG with zero nonce; ChaCha20-Poly1305 share
encryption with nonce `[from, to, 0…]`; Shamir over GF(2^8) via
`vsss-rs`; Ed25519 strict), `protocol.rs` (rounds, threshold
`t = max(minimum, ⌊(n + c)/2⌋ + 1)`, "never both shares"), `round.rs`
(spec, rounds, replay state, receipts). Decision record
[0012](../docs/adr/0012-secure-aggregation.md).

**Tests.** `secagg_sum_sweep`, `secagg_collusion_bound`,
`secagg_coordinator_sees_no_input` (assurance checks);
`equivocating_coordinator_learns_nothing`,
`collusion_bound_defeats_split_survivor_sets`,
`thresholds_below_a_majority_are_refused`,
`messages_are_authenticated_and_bound`
(`crates/encompute-secagg/tests/protocol.rs`).

**Questions.**

1. Is the threshold rule sufficient against a malicious coordinator with
   `c` colluders, including across the consistency round and with
   dropouts at every stage?
2. The KDF does not include party identities, only the round ID and the DH
   output. Is that sufficient?
3. Is a fixed nonce per (sender, recipient) safe here, given the share key
   is derived per pair per round and each direction sends one message?
4. Mask PRG output is reduced mod 2^m by masking 64-bit words. Is the
   masking uniform for every supported `m` (8 to 62)?
5. Coordinator broadcasts are unsigned. Does any attack follow from that?
6. What does a coordinator learn from the participation sets and from
   aborted rounds?

## P6. Differential privacy accounting

**Claim.** Each release is charged at its true cost; composition is never
optimistic; the discrete Gaussian sampler is exact; budgets cannot be
double-spent or rolled back undetected (INV-060 to INV-071, INV-130 to
INV-134).

**Where.** `crates/encompute-privacy/src/sampler.rs` (port of Canonne,
Kamath and Steinke's sampler, big-rational arithmetic, integer σ²),
`accountant.rs` (ρ = Δ²/(2σ²); CKS Corollary 13 conversion via `libm`;
rounding up), `rdp.rs` (Zhu–Wang 2019 Theorem 6 general bound, integer
orders 2..256 plus eight up to 1024; CKS Proposition 12 conversion),
`release.rs` (σ² = ⌈(z·clip·scale)²⌉; Δ = ⌈k·clip·scale⌉ + ⌈√d⌉),
`ledger.rs`; presets in `crates/encompute-ir/src/confidentiality.rs`;
DP-SGD in `python/encompute/torch/dpsgd.py`.

**Tests.** `matches_the_reference`, `monotone_and_conservative`
(`accountant.rs`); `curves_match_the_reference_and_are_never_optimistic`
(`crates/encompute-privacy/tests/rdp.rs`, against autodp and mpmath,
240 cases); `discrete_gaussian_statistics` (mean and variance only);
`dp_sampler_statistics`, `dp_rdp_accountant_properties`,
`dp_crash_injection`, `dp_multi_process_double_spend` (assurance checks).

**Questions.**

1. Is the sensitivity formula right for the codec (quantization, clipping
   before or after encoding, the ⌈√d⌉ rounding term), for organization
   units (k = 2) and for patient units?
2. Is using the general Zhu–Wang bound for the discrete Gaussian sound and
   not needlessly loose? Is the order grid adequate?
3. Is the sampler port faithful? Only mean and variance are tested; there
   is no distributional test and no reference-vector test.
4. Central DP: the coordinator sees the pre-noise sum. Is the combination
   with attestation adequately described?
5. DP-SGD Poisson sampling uses a Mersenne Twister generator seeded with 64
   bits from `os.urandom` and float32 comparisons. Does that affect the
   privacy guarantee in practice?
6. The sampler is not constant-time. Is the release timing exposed
   anywhere in a way that matters?

## P7. Randomness

**Claim.** All randomness Encompute draws itself comes from the operating
system (`getrandom`), directly or through ChaCha20 keyed from it. No
party's seed chooses DP noise or DP-SGD samples (INV-132).

**Where.** See [cryptography.md, section 10](../docs/cryptography.md#10-randomness).
OpenFHE's internal PRNG is used for FHE key generation and encryption;
Encompute does not configure it.

**Questions.**

1. How does OpenFHE v1.5.1 seed its PRNG on Linux and macOS, and is that
   adequate for key generation?
2. The DP CSPRNG is ChaCha20 with a zero nonce under a fresh key per
   release. Any concern?
3. The SecAgg Shamir RNG adapter panics if the OS generator fails. Any
   concern beyond availability?

## P8. Receipts, proofs and their interpretation

**Claim.** A receipt is a signed, attributable, non-transferable claim by
the evaluator, not a proof of correct execution. Only the research
re-execution proof on BGV shows correct execution (INV-020 to INV-023).
CKKS results must never be returned to the evaluator (IND-CPA-D).

**Where.** `crates/encompute-verification/src/{receipt,verify,spec,transcript,proof}.rs`;
`crates/encompute-vfhe/src/lib.rs`; `crates/encompute-exact/src/bgv.rs`;
`crates/encompute-runtime/src/client.rs` (`decrypt_verified`,
`decrypt_proven`); `crates/encompute-cli/src/main.rs` (`verify`).

**Tests.** `every_tampering_fails_closed`,
`receipts_do_not_transfer_between_executions`
(`crates/encompute-verification/tests/receipts.rs`);
`execution_receipt_mutation` (assurance check);
`malicious_evaluator_is_caught`, `proof_tampering_fails_closed`
(`crates/encompute-runtime/tests/vfhe.rs`).

**Questions.**

1. Is the re-execution proof sound under the stated assumption that
   OpenFHE BGV evaluation is deterministic? Cross-platform byte
   reproducibility is argued from the source code but not tested.
2. The verification key ID binds the plan ID and key ID, not the key
   bytes; callers check `SHA-256(evaluation keys) == key_id`. Is that
   enough?
3. Could a user read `RECEIPT VERIFIED`, or the trust report's execution
   row, as more than it is? The offline `encompute verify` does not check
   the receipt's `evidence` kind.
4. Is the IND-CPA-D condition stated strongly enough, and is there any
   path in the product where decrypted CKKS results reach an evaluator
   (for example through the control plane or training flows)?
5. For BinFHE, is decryption-failure information a practical risk if
   results do flow back?
