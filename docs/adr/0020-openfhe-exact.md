# ADR-020 — Commercial exact execution on OpenFHE

Status: **Accepted** (2026-09-26). Amends ADR-006.

## Context

Exact programs (integers and Booleans) ran encrypted only on TFHE-rs,
behind a research feature. Zama states that commercial use of TFHE-rs
technology requires a separate patent license. Encompute is sold under a
commercial license, so a production build cannot depend on TFHE-rs, and
exact programs had no commercial encrypted backend.

OpenFHE (BSD-2-Clause) is already the production runtime for CKKS and BGV.
It also implements BinFHE: FHEW/TFHE-style Boolean gates with bootstrapping
(GINX or LMKCDEY), under OpenFHE's own license.

## Decision

1. **A bit-level exact backend, `openfhe-exact`.**
   - Each exact value is a vector of encrypted bits in two's complement
     (`bool` is one bit).
   - Every operation of the `ExactPlan` is a Boolean circuit:
     - ripple-carry add and subtract;
     - comparisons from the carry-out of `a + ~b + 1`, signed ones by
       flipping the sign bits;
     - shift-and-add multiplication;
     - restoring division and remainder by constants, with truncating
       semantics for signed values;
     - `min` and `max` as comparison plus multiplexer;
     - lookups as multiplexer trees over the index bits;
     - casts as sign or zero extension.
   - Constants fold: gates with a public input are simplified away.
   - The circuits are generic over a gate library. The same code runs on
     plaintext bits for exhaustive tests and on OpenFHE ciphertexts in
     production.
   - The language, the IR and the `ExactPlan` do not change.
2. **One vetted profile.**
   - Profile `BINFHE_STD128_GINX_BITS_V1`: OpenFHE 1.5.1, parameter set
     STD128, GINX bootstrapping, 128-bit security, failure probability
     2^-135 per gate.
   - STD128_LMKCDEY was measured: 45 ms per gate against 55 ms (about 20 %
     faster), but OpenFHE documents a higher failure probability for it. We
     kept STD128.
   - The profile's canonical JSON hash is the parameter-set ID. It is bound
     into the artifact, the evaluation keys and every ciphertext.
   - The evaluator accepts no other profile.
3. **Versioned envelopes.**
   - Every BinFHE object is wrapped in an `ENCBINF1` envelope that carries:
     - a format version;
     - the backend name;
     - the parameter-set ID;
     - a 16-byte random key ID;
     - the kind (ciphertext, evaluation keys or secret key);
     - the element type;
     - length-prefixed payloads;
     - a SHA-256 checksum.
   - Objects under another key, parameter set or backend are refused
     (ENC1605, ENC1603, ENC1602) before any gate runs. So are corrupted,
     truncated or mistyped objects (ENC1601).
   - The outer Encompute envelope still binds the program, the key and the
     scheme (`BinFHE`).
4. **The client/evaluator split holds.**
   - Key generation, encryption and decryption live in
     `encompute-openfhe-client`. The evaluator links only the gate
     operations (`encompute-openfhe`, `encompute-openfhe-exact`).
   - The evaluator binary audit also checks that no exact-client symbol is
     linked.
5. **Selection.**
   - Unverified exact programs compile to `openfhe-exact` by default.
     Verified programs still use BGV with re-execution proofs.
   - The planner offers BinFHE first. It offers BGV only when correctness
     is required. It offers TFHE only in a research catalog, and never
     over OpenFHE exact.
   - TFHE-rs sits behind the `research-tfhe-rs` feature. It is selected
     only by `ENCOMPUTE_RESEARCH_EXACT_BACKEND=tfhe-rs` in a research
     build. A production build answers that request with ENC1501 BACKEND
     UNAVAILABLE. It never falls back. The same holds for
     `encompute-evaluator --backend tfhe-rs` and for loading a TFHE-rs
     artifact.
6. **A capability matrix.**
   - It is machine-readable (`encompute_exact::bits::CAPABILITIES`). Every
     operation is supported for every exact type, except that lookup
     tables are limited to 256 entries.
   - Programs outside the matrix are refused at compile time.
7. **The commercial boundary is audited.**
   - `scripts/audit-commercial-build.sh` checks:
     - the production dependency graph and a CycloneDX SBOM
       (`scripts/sbom.py`);
     - the CLI, evaluator and Python extension binaries (symbols and
       dynamic libraries);
     - optionally, a wheel and a container image.
   - Any TFHE-rs, `tfhe-*`, `concrete*` or `zama*` component fails it.
   - CI runs the audit on the production build. It also runs it on a
     research build as a negative control, which must fail.
8. **Correctness evidence, no tolerance.**
   - Every 8-bit operation is checked exhaustively against the reference
     semantics on plaintext bits; wider types are sampled.
   - OpenFHE exact equals the clear reference and the mock on every
     operation, on random programs and on the flagship. It also runs end
     to end, locally and over HTTP, with receipts.
   - Semantic transcripts are identical across backends.
   - Research CI checks that OpenFHE exact equals TFHE-rs on the same
     programs.

## Consequences

- Exact programs are commercially usable end to end, with no
  patent-license dependency.
- OpenFHE exact is slower than TFHE-rs:
  - about 62 ms per bootstrapped gate on one core;
  - a u32 comparison is 127 gates;
  - the eligibility example takes about 30 s, against about 2 s on TFHE-rs.
- Evaluation keys are 524 MiB per client, uploaded once.
- `explain` prints each program's gate count, which does not depend on the
  inputs, so the cost is known before running.
- Speed-ups are future work: parallel gate evaluation (OpenFHE calls are
  serialized today) and multi-bit functional bootstrapping.
- TFHE-rs stays useful as an independent implementation for differential
  testing.

## Alternatives considered

- **Licensing TFHE-rs.** This would tie every commercial deployment to a
  third-party patent license. It remains possible later as an optional
  accelerated backend.
- **BGV or BFV for all exact programs.** BGV and BFV can compute integer
  arithmetic exactly. Comparisons, however, need deep polynomial
  circuits, and we would have to add full parameter selection. BGV stays
  the proof-carrying backend for the small verified subset.
- **LMKCDEY bootstrapping.** It is faster, but its failure probability is
  higher. We may revisit this with an explicit profile version.

## Relevant source modules

- `crates/encompute-exact/src/bits.rs`
- `crates/encompute-openfhe-exact/src/lib.rs`
- `crates/encompute-openfhe/cpp/binfhe.cc`, `crates/encompute-openfhe/src/binfhe.rs`
- `crates/encompute-openfhe-client/cpp/binclient.cc`, `crates/encompute-openfhe-client/src/exact.rs`
- `crates/encompute-evaluator/src/compiled.rs`, `crates/encompute-evaluator/src/session.rs`
- `crates/encompute-planner/src/planner.rs`
- `scripts/audit-commercial-build.sh`, `scripts/sbom.py`
