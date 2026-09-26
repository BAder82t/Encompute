# 04 — Execution receipts

## What this demonstrates

Every remote job returns a receipt: a statement signed by the evaluator's
identity key that binds the program, plan, parameters, client key, backend,
a commitment to the request, a commitment to the response, and the
program's semantic transcript hash.

The client checks the receipt before decrypting. With `--save-receipt` and
`--save-envelopes`, the receipt and the exact bytes exchanged
(`request.bin`, `response.bin`) are kept, so anyone holding them can re-check
the bindings later with `encompute verify`. Then the script tampers with
each piece and requires verification to fail.

**A valid receipt proves the evaluator signed these bindings. It does not
by itself prove the evaluator computed correctly.** An evaluator that
returns a wrong ciphertext can sign it just as well; the receipt then makes
it accountable for that answer, but does not detect it. Checking the
computation is verified execution (example 05).

## Threat model

The evaluator may lie about what it ran, or a party in the middle may alter
the request, the response, or the receipt. The client trusts one evaluator
signing key (pinned on first use in `keys/evaluator.pub`, or given with
`--trust-evaluator`). The evaluator's signing key is assumed not stolen.

## Architecture

```text
client                          evaluator (identity key sk_E)
request.bin ──────────────────► run program P
response.bin ◄──────────────────┤
receipt ◄───────────────────────┘ sign_E(P, plan, params, key, backend,
                                          H(request), H(response), transcript)

verifier: encompute verify receipt --model P --request --response --trust-evaluator pk_E
```

## Run it

```sh
cargo build --bins
examples/04_execution_receipts/run.sh
```

Runs in quick mode with the mock evaluator. Receipts are the same for every
backend.

## Expected output

```text
trusting evaluator enc-eval:<id> on first use (pinned in keys/evaluator.pub)
Evaluator receipt       verified
Execution proof         not present
Encrypted result        accepted (receipt only)
...
  Trusted         yes (--trust-evaluator)
  Signature       VALID
Bindings
  Artifact        checked
  Backend         checked
  Request         checked
  Response        checked
  Transcript      checked
...
TRANSCRIPT AVAILABLE
RECEIPT VERIFIED
EXECUTION PROOF NOT PRESENT
```

## Try breaking it

`run.sh` runs each of these; every one must fail.

| Tampering | Result |
|---|---|
| flip one bit of `response.bin` | exit 1, `INVALID: receipt output commitment does not match` |
| flip one bit of `request.bin` | exit 2, ENC1601 (envelope checksum mismatch) |
| edit a receipt field (`scheme` BinFHE → CKKS) | exit 1, `INVALID: receipt signature is invalid` |
| verify expecting another backend (`--backend openfhe-exact`) | exit 1, `INVALID: receipt spec ID does not match` |
| trust a different evaluator key | exit 1, `INVALID: receipt was signed by an untrusted evaluator key` |
| `encompute verify receipt.json` alone | exit 3, `RECEIPT SIGNATURE VALID (some bindings not checked)`: a partial check is not success |
| run against a new evaluator (new identity) | exit 2, ENC1606: the pinned key does not match |

The expected backend comes from the request the client made, never from the
receipt, so an evaluator cannot quietly run a different backend.

## What Encompute guarantees

- The client refuses to decrypt a result whose receipt is missing, badly
  signed, signed by an untrusted key, or bound to another program, plan,
  parameter set, key, request or response (ENC1606).
- `encompute verify` checks the same bindings offline and exits 0 only if
  every one was checked and matched.
- A receipt can be shown to a third party: it names exactly what the
  evaluator claimed to run, on which inputs, producing which outputs.

## What Encompute does NOT guarantee

- A receipt is not a correctness proof. It proves the evaluator signed
  these bindings, not that the response is the correct result of running
  the program. `EXECUTION PROOF NOT PRESENT` says so on every run.
- A compromised signing key lets anyone forge receipts.
- The mock backend encrypts nothing; the receipt mechanism is the same, the
  confidentiality is not.
- The workload is not attested here (`NOT ATTESTED`): the receipt says
  nothing about what software or hardware the evaluator ran on
  (example 07).

## Relevant source modules

- `crates/encompute-verification`: receipts, commitments, verification.
- `crates/encompute-runtime/src/client.rs`: receipt checks before
  decryption, evaluator pinning.
- `crates/encompute-evaluator/src/server.rs`: signing receipts.
- `crates/encompute-cli`: `run --save-receipt --save-envelopes`, `verify`,
  `transcript`.
- `docs/adr/0007-verifiable-execution.md`,
  `docs/adr/0008-semantic-transcripts.md`.
