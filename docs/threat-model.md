# Encompute threat model (v0.3)

Also written into every artifact's `security.json`.

## Parties

| Party | Trust | Holds |
|---|---|---|
| Client | trusted | secret key; encrypts inputs, decrypts outputs |
| Evaluator | honest-but-curious | CKKS: public key, relinearization key, rotation keys for the plan's rotations. Exact (TFHE): the compressed server key |
| Network | untrusted | ciphertexts in transit |
| Storage | untrusted | ciphertexts and artifacts at rest |

The evaluator follows the protocol but may try to learn from what it sees.
Malicious evaluators, malicious clients and colluding parties are out of
scope.

## Guarantees

- The evaluator role never receives the secret key, so it cannot decrypt inputs,
  intermediate values or outputs. Security: CKKS (RNS, OpenFHE v1.5.1) at
  128-bit classical security, parameters checked against the HE Standard
  ternary-secret table (`encompute-ckks/src/params.rs`), and re-checked by OpenFHE
  when the context is created.
- Exact programs (TFHE-rs 1.8.1, research feature): the vetted profile
  `PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`, 128-bit security, failure
  probability 2^-128 per bootstrap. The evaluator checks every incoming key
  and ciphertext against the profile (TFHE-rs conformance) before use.
  Results are exact: range analysis proves no operation overflows.
- Envelopes name their scheme (CKKS or TFHE), backend, parameter set,
  program and key; a mismatch is refused, so data for one scheme never
  enters a program of the other.
- Every evaluation returns a receipt signed by the evaluator's Ed25519
  identity, binding the execution spec, key, and exact request and response
  bytes; clients verify it before decrypting. A receipt makes the
  evaluator's claim attributable. It does not prove correct execution
  (ADR-007). For exact programs the receipt also binds the semantic
  transcript a future proof must follow (ADR-008); that is public program
  structure, not a proof.
- Confidentiality policies (ADR-010) are checked at compile time and bound
  into the execution spec; they state which party may learn which value.
  They are not yet enforced at run time: today the client that holds the
  key decrypts every output it receives.
- Asset keys held by a key broker (ADR-011) are released only to a workload
  whose fresh hardware attestation binds the approved execution spec,
  policy, artifact, evaluator key and session key, and satisfies the
  asset's attestation policy; they are sealed (HPKE) to the attested
  session key. This trusts the TEE and its attestation service (for
  Confidential Space: Google's verifier and launcher), and the reviewed
  image: the image digest is the measurement. Development (mock) evidence
  protects nothing and production brokers refuse it.
- Artifacts never contain key material.

## Deployment

Since 0.2 the evaluator runs as its own binary (`encompute-evaluator`),
usually on another machine. It receives programs, evaluation keys and
encrypted inputs, and returns encrypted outputs. It never receives the
secret key, and its binary contains no Encompute key-generation, encryption
or decryption code (`encompute audit --evaluator`). OpenFHE's own internal
routines are linked into it, but without the secret key they cannot
decrypt.

In local modes (`run --mode encrypted` without `--remote`), client and
evaluator still share one process: anyone who compromises it sees both
roles' data.

The evaluator speaks plain HTTP: run it behind a TLS proxy. Envelopes carry
checksums against corruption, but there is no client authentication in 0.2.

## Conditions

1. **Decrypted results are never returned to the evaluator.** CKKS is not
   IND-CPA-D secure (Li–Micciancio, 2021). An evaluator that sees decryptions
   of ciphertexts it computed can recover the secret key. Encompute adds no
   noise flooding; returning results to the evaluator is unsupported. The
   same rule applies to exact programs, where decryption failures are
   negligible (2^-128) but not zero.
2. **Inputs lie within their declared ranges.** The client checks this before
   encrypting (ENC1102). Out-of-range inputs would not leak data, but the
   results would be wrong (approximations are fitted to the range; exact
   overflow proofs assume the range).

## What the evaluator learns

- Program structure: operations and their order.
- Public constants: weights, polynomial coefficients.
- Input and output shapes and declared input ranges.
- Timing and ciphertext sizes (they depend only on the program, not on input values).

Values are never revealed, including the outcome of comparisons and
selections: both branches of a `select` are computed. Hiding the model
itself (encrypted weights) is out of scope.

## Not covered in v0.3

Side channels on the client; malicious-evaluator integrity outside
verified execution (receipts bind what the evaluator claims, and an
evaluator can sign a fabricated result: only programs compiled with
`verification="required"`, in the research build, carry execution proofs
that rule this out; ADR-009); key rotation, threshold decryption, and
multi-party settings.
