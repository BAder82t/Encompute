# Encompute threat model

Also written into every artifact's `security.json`.

## Parties

| Party | Trust | Holds |
|---|---|---|
| Client | trusted | secret key; encrypts inputs, decrypts outputs |
| Evaluator | honest-but-curious | CKKS: public key, relinearization key, rotation keys for the plan's rotations. Exact (OpenFHE exact): the BinFHE bootstrapping and key-switching keys |
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
- Exact programs (OpenFHE exact: OpenFHE v1.5.1 BinFHE): the vetted
  profile `BINFHE_STD128_GINX_BITS_V1` (parameter set STD128, GINX
  bootstrapping), 128-bit security, failure probability 2^-135 per gate.
  Every key and ciphertext carries the profile's parameter-set ID, the
  client's key ID and its type; the evaluator refuses any mismatch, and
  OpenFHE re-checks the LWE dimension and modulus when loading. Results are
  exact: range analysis proves no operation overflows. Research builds may
  also run TFHE-rs 1.8.1 (profile
  `PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`, 2^-128 per bootstrap)
  when explicitly selected; production builds cannot.
- Envelopes name their scheme (CKKS, BinFHE, BGV, or TFHE in research builds), backend, parameter set,
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
  In a single-client run the client that holds the key decrypts every
  output it receives; across parties they are enforced at run time by
  attested key release, secure aggregation and differential privacy
  (below).
- Asset keys held by a key broker (ADR-011) are released only to a workload
  whose fresh hardware attestation binds the approved execution spec,
  policy, artifact, evaluator key and session key, and satisfies the
  asset's attestation policy; they are sealed (HPKE) to the attested
  session key. This trusts the TEE and its attestation service (for
  Confidential Space: Google's verifier and launcher), and the reviewed
  image: the image digest is the measurement. Development (mock) evidence
  protects nothing and production brokers refuse it. Production brokers
  keep keys wrapped under a key-encryption key outside their state file.
- Secure aggregation (ADR-012): the coordinator and cloud operator see only
  masked contributions and the aggregate; a malicious coordinator cannot
  obtain an honest party's input while it colludes with no more parties
  than the declaration's `colluding` bound, which sets the threshold. It can abort a round or report a wrong aggregate. The
  aggregate itself is protected only where differential privacy is declared.
  See the adversary table in ADR-012.
- Differential privacy (ADR-013) bounds what released aggregates reveal
  about each privacy unit, per asset budget, composed across releases and
  enforced by the coordinator's ledger and by each owner's own check. It is
  central DP: the coordinator sees the aggregate before noise and is trusted
  to add it, as far as its attestation (bound to the privacy policy) goes.
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
checksums against corruption.

### With a control plane

When a control plane manages the deployment, the parties and what each one
is trusted with change as follows (see docs/deployment.md):

| Party | Trust | Holds |
|---|---|---|
| Control plane | trusted for coordination, not for trust decisions | identities, roles, metadata, digests, wrapped-key references, privacy ledgers, audit trail; no secret key, no plaintext, no ciphertext |
| Key broker | trusted by its owner | wrapped asset keys; the KEK only while running, unwrapped by the customer's KMS |
| Customer KMS | trusted by its owner | the organization's root key (never exported) |
| Message transport | untrusted | signed envelopes; it may duplicate, delay, reorder, drop or replay them |
| Other tenants | untrusted | nothing of this organization's, unless a project collaboration and the owner's asset approvals grant it |

- **Authentication.** People authenticate with OpenID Connect. Services
  authenticate with Ed25519-signed requests: sender, recipient, timestamp,
  single-use nonce, body hash and bound IDs. Network location is never an
  identity.
- **Evaluators.** An evaluator runs a job only with a grant from the pinned
  control-plane key, naming it and the job's program, and only after the
  control plane consents to the start.
- **Trust reports.** They are rebuilt from signed evidence and trusted keys:
  a compromised control-plane database cannot make a job trusted. It can
  refuse service, or hide jobs from their owners.
- **Privacy state.** Privacy spending and the audit chain are anchored
  outside the database. An older database cannot silently undo spending.
- **What a compromised control plane can do.** It can schedule a job to a
  registered evaluator, and it can deny service. It cannot:
  - decrypt anything;
  - release a key without attestation (the key broker decides);
  - forge an evaluator's receipt;
  - make a client accept a result the client did not verify.

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

## Not covered

Side channels on the client; malicious-evaluator integrity outside
verified execution (receipts bind what the evaluator claims, and an
evaluator can sign a fabricated result: only programs compiled with
`verification="required"`, in the research build, carry execution proofs
that rule this out; ADR-009); FHE key rotation and threshold decryption;
correctness of a secure aggregate (a malicious coordinator can abort or
report a wrong aggregate, ADR-012); noise added by a coordinator that is not
attested (central DP, ADR-013); timing side channels of noise sampling.
