# ADR-009 — Verifiable-FHE proof backend

Status: **Accepted** (2026-09-25): A (re-execution on OpenFHE BGV) first, then B (zkVM).

## Context

V3 must prove that the response ciphertext is a correct homomorphic
evaluation of the semantic transcript (ADR-008) over the *actual* request
ciphertext: `C_out = Eval_T(C_in, evk)` under the context bound by the
execution spec. A proof of the plaintext function `f(x) = y` does not
qualify. The verifier holds neither plaintext nor secret key.

## Findings (sources in the V3 research notes)

**Fherret** (Huth, Joux, Santato; ePrint 2025/700, IACR CiC 3(2) 2026;
MPC-in-the-Head over OpenFHE BGV-RNS):
- Proves, in the random-oracle model, that a function from a declared
  class was evaluated so that the *decrypted majority* equals `f(m)`. It
  does not bind one output ciphertext: the prover sends λ pairs of
  evaluations of random shares, and the final check needs the secret key.
- Its main benefit, hiding `f` (which needs circuit privacy, not provided
  by OpenFHE BGV), is irrelevant to Encompute, whose programs are public.
  With `f` public, a verifier holding `evk` re-runs the evaluation once;
  Fherret's verifier performs about 2λ evaluations.
- Reported cost (smallest class, 12 slots, λ = 130, EPYC 9374F): prover
  37.5 s / verifier 22.5 s single core; the ePrint and journal overhead
  figures disagree.
- Code: github.com/GiacomoSantato/FHErret has **no license** (all rights
  reserved): unusable in AGPL/commercial Encompute without relicensing.

**ZHE** (ePrint 2025/770): the full version fixes a bug in the proceedings
analysis; do not rely on the originally published overhead. No code found.

**Other work with code**: Viand et al. (SEAL + Circom/Groth16/Rinocchio;
minutes per ciphertext multiplication; license unclear); Zama vPBS
(one TFHE bootstrap in plonky2, 18 min on 192 cores; patented);
HasteBoots (seconds per bootstrap; no license); Greco (proves correct
*encryption*, MIT); TFHE-rs zk-pok (correct *encryption* only).

**Determinism** (measured and read from source):
- OpenFHE v1.5.1 BGV-RNS evaluation (add, sub, mult + relinearization,
  mult by constant, modulus switching) is exact integer arithmetic with no
  randomness: bit-for-bit reproducible given the same context, keys and
  ciphertexts.
- TFHE-rs 1.8.1 bootstrapped operations are **not** reproducible: the FFT
  algorithm is chosen by timing at run time and carry propagation depends
  on the thread count; the same inputs and key gave different output bytes
  across runs (all decrypting correctly). Not a proof target.

## Options

**A. Deterministic re-execution on OpenFHE BGV (`reexecution-v1`).**
The verifier re-runs `Eval_T(C_in, evk)` and compares bytes with `C_out`.
- Proves exactly `C_out = Eval_T(C_in, evk)` for the committed
  ciphertexts; soundness is unconditional given a correct evaluator.
- Not succinct: the verifier needs `evk` and about the evaluator's compute.
  Useful to an auditor or a client that can afford one evaluation; it does
  not make outsourcing cheaper.
- Evidence is empty (or a transcript of intermediate ciphertext hashes);
  weeks → days to build: a new OpenFHE BGV exact backend for the subset.

**B. zkVM over a pure-integer BGV evaluator (`vfhe-zkvm-v1`).**
Run an integer BGV/BFV evaluator (e.g. fhe.rs, MIT) inside RISC Zero or SP1
(Apache-2.0); the public journal is `H(spec, evk, C_in, transcript) →
H(C_out)`.
- Succinct and publicly verifiable; binds the actual ciphertexts (the zkVM
  executes the encrypted evaluation, not the plaintext function).
- Soundness rests on the zkVM's STARK and Fiat–Shamir assumptions.
- Cost unknown: NTT/relinearization at N ≥ 4096 inside a zkVM may take
  minutes to hours; benchmark one ciphertext multiplication first.
- Needs the execution backend to be that same integer evaluator (or byte
  compatible with it); a new toolchain in CI.

**C. Fherret-style MPC-in-the-Head.** Not viable now: no usable code,
does not bind `C_out`, costlier than re-execution for public programs.
Revisit only for private-program verification.

## Recommendation

A first, then B:
1. **Re-execution (A)** on a new OpenFHE BGV exact backend for the
   first subset (u8/u16 `ADD`, `SUB`, `MUL_CONST`, `AND`/`OR`/`NOT` on
   bools), end to end with receipts, `ExecutionProof`, the malicious-
   evaluator demo and CI byte-reproducibility tests. Labelled honestly:
   relation `FheEvaluationV1`, protocol `reexecution-v1`, "sound, not
   succinct: verification costs one evaluation".
2. **Succinct zkVM proof (B)**, starting with a benchmark of one BGV
   ciphertext multiplication inside RISC Zero/SP1, then the same subset;
   same relation, protocol `vfhe-zkvm-v1`, same `ExecutionProof` object.

Both keep TFHE-rs execution-only.

## Answers the milestone asks for

| Question | A (re-execution) | B (zkVM) |
|---|---|---|
| What is proven | `C_out = Eval_T(C_in, evk)` | same, in zero knowledge of nothing (all inputs public) |
| FHE assumptions | none beyond a correct evaluator | same, plus zkVM soundness |
| Reveals the program | yes (programs are public) | yes |
| Needs circuit privacy | no | no |
| Proves ciphertext correctness | yes, bytes | yes, bytes |
| Protects against malformed-output attacks | yes: a wrong `C_out` is rejected before decryption | yes |
| Public | spec, transcript, `evk`, `C_in`, `C_out` | same (hashed into the journal) |
| Witness | none | the evaluation trace |
| Proof size | 0 | zkVM receipt (≈ hundreds of KB, to measure) |
| Prover overhead | none | to measure (large) |
| Verifier overhead | one evaluation | milliseconds |
| Parallelizable | as evaluation | yes (zkVM segments) |
| First backend | OpenFHE BGV (new exact backend) | integer BGV in a zkVM |

## Re-execution result (2026-09-25)

Implemented: `verification required` programs (Python
`@encompute.compile(verification="required")`) compile to the OpenFHE BGV
exact backend (plaintext modulus 65537; u8, u16, bool; `+ - *`, constants,
`& | ^ ~` on Booleans) and fail with ENC1801 if any instruction is not
covered. The evaluator attaches an `ExecutionProof` (relation
`FheEvaluationV1`, protocol `reexecution-v1`, no proof bytes) bound by
digest in its signed receipt; the verification key ID binds the plan and
the evaluation key. The client re-executes over the committed request with
its evaluation keys and decrypts only if every output ciphertext matches
byte for byte: no proof, no decryption. Crate `encompute-vfhe`, feature
`vfhe-research`.

Evidence (`crates/encompute-runtime/tests/vfhe.rs`):
- an honest evaluation is `EXECUTION VERIFIED`, locally and over HTTP;
- five malicious-evaluator attacks (random output, replayed old output,
  skipped operation, substituted program, mutated ciphertext), each with a
  validly signed receipt, are all rejected by the proof check; the same lie
  is accepted when only a receipt is required;
- tampering with the proof's spec, transcript, verification key,
  commitments or protocol, a truncated proof, a proof from another
  execution, a missing proof, and another client's evaluation keys all fail
  closed.

Measured (Apple M3 Max, release; the loan pre-check: 4 inputs, 6
instructions): BGV evaluation 24 ms; verification (re-execution +
decryption) 65 ms (2.7×); proof 543 bytes (header only); verification key =
evaluation keys, 769 KiB; request 1027 KiB, response 514 KiB.

Open: cross-platform byte reproducibility of OpenFHE BGV (Linux vs macOS,
HEXL/NATIVE_SIZE builds) is argued from the source, not yet tested against
shared fixtures; the succinct zkVM proof is next. The re-execution backend stays as the reference verifier against which succinct proof systems are differential-tested.
