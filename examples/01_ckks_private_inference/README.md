# 01 — CKKS private inference

## What this demonstrates

An ordinary Python function becomes an encrypted computation. A
logistic-regression score over 32 private features is compiled once, then
run three ways, and the results must agree within the declared precision:

| Mode | What runs | Needs |
|---|---|---|
| clear | the reference semantics, in plaintext | nothing |
| mock | the compiled CKKS plan, without encryption | nothing |
| encrypted | the plan on OpenFHE ciphertexts | an OpenFHE build |

`semantic_search.py` does the same for a 384-dimensional similarity search,
and `logistic_regression.py` adds `explain`, `test` and `bench`.

## Threat model

The evaluator is honest-but-curious: it runs the program but wants to learn
the inputs. The client holds the secret key and is trusted.

## Architecture

```text
client                                   evaluator
x (plaintext) ─ encrypt ─► ciphertext ─► sigmoid(w·x + b) on ciphertexts
score ◄─────── decrypt ─── ciphertext ◄─┘
```

## Run it

```sh
cargo build --bins && maturin develop -m crates/encompute-py/Cargo.toml
examples/01_ckks_private_inference/run.sh
```

With OpenFHE (`maturin develop --features openfhe`), the encrypted mode
runs too (`examples/run-all.sh crypto`).

## Expected output

```text
Scheme            approximate (CKKS)
Clear result      0.71138
Mock result       0.71130
Absolute error    0.00008
Allowed error     0.00100
Sampled inputs    100 cases, max error 3.73e-04
PASS
```

## Try breaking it

- Ask for more precision than the parameters can reach:
  `@encompute.compile(precision=1e-12)`. Compilation fails with ENC1202
  (precision unreachable). Encompute never silently weakens parameters.
- Compare approximate secrets (`if x > 0:`). Tracing refuses with ENC1003:
  CKKS values are approximate, so comparisons need an exact program
  (example 02).

## What Encompute guarantees

- The evaluator only ever sees ciphertexts. The secret key never leaves the
  client.
- The parameters meet the 128-bit security table for the circuit's depth.
- Results match the plaintext semantics within the declared precision,
  checked on sampled inputs (`score.test`).

## What Encompute does NOT guarantee

- CKKS is approximate: results carry error up to the declared precision.
  Use exact programs (example 02) when exactness matters.
- An evaluator that decrypts nothing can still return a wrong result.
  Receipts (example 04) bind what it claims to have run; verified execution
  (example 05) checks the computation.
- The weights here are public constants: they are compiled into the
  program. Private models need a confidentiality policy and attested
  execution (examples 06, 07).
- Mock mode encrypts nothing: it only checks the plan.

## Relevant source modules

- `python/encompute/_frontend.py`: tracing Python into the IR.
- `crates/encompute-ckks`: lowering, Chebyshev approximation, parameters.
- `crates/encompute-openfhe-client`: encryption and decryption (client
  only).
