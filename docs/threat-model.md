# Encompute v0.1 threat model

Also written into every artifact's `security.json`.

## Parties

| Party | Trust | Holds |
|---|---|---|
| Client | trusted | secret key; encrypts inputs, decrypts outputs |
| Evaluator | honest-but-curious | public key, relinearization key, rotation keys for the plan's rotations |
| Network | untrusted | ciphertexts in transit |
| Storage | untrusted | ciphertexts and artifacts at rest |

The evaluator follows the protocol but may try to learn from what it sees.
Malicious evaluators, malicious clients and colluding parties are out of
scope for v0.1.

## Guarantees

- The evaluator role never receives the secret key, so it cannot decrypt inputs,
  intermediate values or outputs. Security: CKKS (RNS, OpenFHE v1.5.1) at
  128-bit classical security, parameters checked against the HE Standard
  ternary-secret table (`encompute-ckks/src/params.rs`), and re-checked by OpenFHE
  when the context is created.
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
   of ciphertexts it computed can recover the secret key. v0.1 adds no noise
   flooding; returning results to the evaluator is unsupported.
2. **Inputs lie within their declared ranges.** The client checks this before
   encrypting (ENC1102). Out-of-range inputs would not leak data, but the
   results would be wrong (approximations are fitted to the range).

## What the evaluator learns

- Program structure: operations and their order.
- Public constants: weights, polynomial coefficients.
- Input and output shapes and declared input ranges.
- Timing and ciphertext sizes (they depend only on the program, not on input values).

Values are never revealed. Hiding the model itself (encrypted weights)
is out of scope for v0.1.

## Not covered in v0.1

Side channels on the client, malicious-evaluator integrity (results are not
verifiable), key rotation, threshold decryption, and multi-party settings.
