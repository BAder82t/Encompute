# Verification

Execution receipts, the three verification states, and verified execution (research).

Every evaluation (local or remote) returns an **execution receipt** signed
with the evaluator's Ed25519 identity. It binds the execution spec (program,
plan, parameters, scheme, backend), the key, and the exact encrypted request
and response. Clients verify it before decrypting; the evaluator's key is
pinned on first use or given with `--trust-evaluator`.

For exact programs the receipt also binds a **semantic transcript**: the
canonical list of operations connecting the request to the result
(`encompute transcript model.encompute`). It fixes what a future execution
proof must establish.

Encompute keeps three verification states apart:

| State | Meaning |
|---|---|
| `UNVERIFIED` | No receipt. |
| `RECEIPT VERIFIED` | This evaluator signed a statement binding this spec, key, request and response. |
| `EXECUTION VERIFIED` | A proof shows the response is a correct homomorphic evaluation of the transcript over the request. Research build, small exact subset. |

A receipt does **not** prove that the evaluator computed honestly, that the
result is correct, or that it was not fabricated: an evaluator can sign a
lie. Only an execution proof rules that out.

**Verified execution (research).** Programs compiled with
`verification="required"` run on OpenFHE BGV (u8, u16, bool; `+ - *`,
constants, `& | ^ ~`) and every result carries an execution proof. The
client re-runs the computation over the exact ciphertexts it sent, with its
own evaluation keys, and decrypts only if the response matches byte for
byte: no proof, no decryption. A malicious evaluator returning a random,
replayed, skipped, substituted or mutated result, even with a valid signed
receipt, is rejected. This proof is sound but not succinct: verifying costs
about one evaluation. A succinct proof is next.

```python
@encompute.compile(verification="required")
def precheck(income: secret[u16, 0:5000], member: secret[bool_], flagged: secret[bool_]):
    return {"score": income * 3 + 7, "ok": member & ~flagged}
```

Build with `--features vfhe-research` (implies `openfhe`) for the verifier;
`encompute run --remote` then prints `VERIFIED PRIVATE EXECUTION`, and
`encompute verify ... --proof exchange/proof.bin --evaluation-keys KEYS/eval.keys`
re-checks a saved result.
