# Encompute

Encompute compiles ordinary programs into encrypted computation. You declare which
values are secret and their ranges; Encompute picks the scheme from the
types (CKKS for approximate numbers, TFHE for exact integers and Booleans),
builds a plan, picks 128-bit parameters, and checks the encrypted result
against plaintext.

```python
import numpy as np
import encompute
from encompute import secret, Tensor

w, b = np.random.default_rng(0).normal(0, 0.3, 32), 0.1

@encompute.compile(precision=1e-3)
def score(x: secret[Tensor[32], -1.0:1.0]):
    return encompute.sigmoid(encompute.dot(w, x) + b)

x = np.random.default_rng(1).uniform(-1, 1, 32)
score(x)                         # plaintext reference
score(x, mode="encrypted")       # encrypted end to end on OpenFHE
print(score.test(cases=1000, mode="encrypted"))   # measured error vs. plaintext
print(score.explain())           # depth, rotations, parameters, precision
score.save("score.encompute")         # reproducible artifact, no keys
```

Exact programs use integer and Boolean types, with comparisons and
encrypted selection:

```python
from encompute import secret, u8, u16, u32

@encompute.compile()
def approve(age: secret[u8, 0:120], income: secret[u32, 0:1_000_000],
            debt: secret[u32, 0:500_000], risk: secret[u16, 0:1000]):
    return (age >= 18) & (debt * 100 < income * 40) & (risk <= 650)

approve(35, 100_000, 20_000, 400, mode="mock")    # True, exactly
print(approve.test(cases=1000))                   # 1000 matches, 0 mismatches
```

Status: **0.3 / 0.4 in progress** (last release: v0.2.0). Approximate (CKKS)
and exact (integer/Boolean) programs run end to end over the client/evaluator
boundary; every evaluation returns a signed execution receipt, and exact
programs have a semantic transcript fixing what a future execution proof
must show. No execution proof exists yet. See the [changelog](CHANGELOG.md), the
[benchmarks](docs/benchmarks.md), the
[decision records](docs/adr/), the [threat model](docs/threat-model.md) and
the [error codes](docs/errors.md).

## What 0.2 does

- **Privacy types.** `secret[float, lo:hi]` and `secret[Tensor[n], lo:hi]`.
  Using a secret in `if`, `print`, a comparison or a division by a secret is a
  compile-time error with a stable code, not a silent leak.
- **Operations.** `+ - *`, `sum`, `dot`, public-matrix `@`, `poly`, `sigmoid`,
  `x ** k`, division by public values.
- **Compiler.** Range analysis, CKKS lowering with SIMD packing, hybrid
  diagonal matrix–vector products, depth-optimal polynomial evaluation,
  Chebyshev approximation of `sigmoid` with the degree chosen to meet the
  precision, and parameter selection against the HE Standard 128-bit table
  (cross-checked against OpenFHE's own choice).
- **Runtime.** `clear`, `mock` and `encrypted` modes; client and evaluator
  roles kept apart in the API (the evaluator role never receives the secret key).
  Locally both roles run in one process; `run --remote` puts a network
  boundary between them.
- **Differential testing.** `test()` / `encompute test` compares encrypted and
  plaintext outputs on range endpoints plus random samples.

## Exact programs (0.3, in progress)

- **Types.** `secret[u8, lo:hi]` … `secret[u64, lo:hi]`, `secret[i8, lo:hi]` …
  `secret[i64, lo:hi]` and `secret[bool_]`. Exact values at the API are
  integers within ±2^53 (ADR-006).
- **Operations.** `+ - *`, comparisons, `& | ^ ~`, shifts, `//` and `%` by
  constants, `encompute.select`, `minimum`/`maximum`, `lookup`, `cast`.
  `if` on an encrypted Boolean is still a compile error (ENC1001).
- **Checked arithmetic.** Integer range analysis proves that no operation
  overflows for inputs in range; a possible overflow is a compile error
  (ENC1303).
- **Backends.** A plaintext mock by default. TFHE-rs behind the
  off-by-default `tfhe-rs` feature, for research use only: Zama requires a
  patent license for commercial use of its technology.
- **Same workflow.** `compile`, `run` (local or `--remote`), `test` (exact
  matches, no tolerance), `explain`, `bench`, `audit`, `keys generate`.

Out of scope for 0.3: programs mixing approximate and exact values (0.4),
bootstrapping for CKKS, GPU, TLS and client authentication, KMS.

## Build

Requires Rust (pinned in `rust-toolchain.toml`), CMake, a C++17 compiler and,
on macOS, `brew install libomp`.

```sh
cargo test                               # everything except OpenFHE
./scripts/install-openfhe.sh             # builds OpenFHE v1.5.1 (static) into .deps/openfhe
cargo test --workspace --features encompute-runtime/openfhe,encompute-evaluator/openfhe,encompute-cli/openfhe
                                         # adds the OpenFHE backend
```

Set `OPENFHE_ROOT` to use another static OpenFHE v1.5.1 install.

The TFHE-rs backend for exact programs is a research feature (Zama requires
a patent license for commercial use):

```sh
cargo test --release -p encompute-runtime --features tfhe-rs --test exact
cargo build --release -p encompute-cli -p encompute-evaluator \
  --features encompute-cli/tfhe-rs,encompute-evaluator/tfhe-rs
scripts/exact-demo.sh      # encrypted eligibility decision via a separate evaluator
```

### Python

```sh
python -m venv .venv && . .venv/bin/activate
pip install maturin pytest numpy
maturin develop --release --features openfhe   # omit --features for mock only
pytest -q
python examples/logistic_regression.py
python examples/semantic_search.py
```

### CLI

```sh
cargo build --release --features openfhe -p encompute-cli
encompute compile model.py:score -o score.encompute     # or a .eir file
encompute run score.encompute --input x=0.1,0.2,... --mode encrypted
encompute test score.encompute --cases 1000 --mode encrypted
encompute explain score.encompute --measure 100 --mode encrypted
encompute bench score.encompute --mode encrypted
```

Remote evaluation (the evaluator never receives the secret key):

```sh
cargo build --release --features openfhe -p encompute-cli -p encompute-evaluator
encompute keys generate score.encompute -o score.keys     # secret.key stays here
encompute-evaluator serve score.encompute --listen 0.0.0.0:8750   # on the evaluator machine
encompute run score.encompute --remote http://EVALUATOR:8750 --keys score.keys --input x=...
```

Every remote job returns a receipt signed by the evaluator's identity key.
`run --remote` verifies it before decrypting (the evaluator's key is pinned
on first use, or given with `--trust-evaluator`) and can save it:

```sh
encompute run score.encompute --remote http://EVALUATOR:8750 --keys score.keys \
  --input x=... --save-receipt result.receipt.json --save-envelopes exchange/
encompute verify result.receipt.json --model score.encompute \
  --request exchange/request.bin --response exchange/response.bin --trust-evaluator KEY
```

`verify` exits 0 only when every binding was checked (trusted key, artifact,
backend, request and response), 3 when some were not, 1 when any check
fails. The expected backend comes from the request you sent (or
`--backend`), never from the receipt.

### What an execution receipt proves

It proves that a particular evaluator signed a statement binding a specific
execution specification (program, plan, parameters, scheme, backend), key,
request ciphertext and output ciphertext.

It does **not** prove that the evaluator executed every operation honestly,
that the output ciphertext is mathematically correct, or that the result was
not fabricated. That needs an execution proof, which is future work (0.4 V3);
receipts say `EXECUTION PROOF NOT PRESENT`. See ADR-007.

For exact programs, receipts also bind a *semantic transcript*: the
canonical list of operations a proof will have to cover
(`encompute transcript model.encompute`). It is public program structure,
not a proof: `TRANSCRIPT AVAILABLE`, `EXECUTION PROOF NOT PRESENT`
(ADR-008).

The evaluator speaks plain HTTP; put a TLS proxy in front of it for remote
clients. `scripts/audit-evaluator-binary.sh` checks that the evaluator binary
contains no Encompute key-generation, encryption or decryption code.

## Layout

| Path | Role |
|---|---|
| `crates/encompute-ir` | Scheme-independent SSA IR, `.eir` text form, reference semantics |
| `crates/encompute-analysis` | Range and privacy analyses |
| `crates/encompute-ckks` | Lowering to CKKS plans; Chebyshev approximation; parameter selection |
| `crates/encompute-exact` | Lowering to backend-independent exact plans; plan validation and execution |
| `crates/encompute-backend` | Client and evaluator traits; mock backend |
| `crates/encompute-protocol` | Versioned, checksummed envelopes bound to parameters, program and key |
| `crates/encompute-verification` | Execution specs, signed execution receipts, receipt verification (no FHE dependency) |
| `crates/encompute-openfhe` | OpenFHE evaluator side (no keygen, encryption or decryption) |
| `crates/encompute-openfhe-client` | OpenFHE client side: keys, encryption, decryption |
| `crates/encompute-tfhe` | TFHE-rs evaluator side (research feature) |
| `crates/encompute-tfhe-client` | TFHE-rs client side: keys, encryption, decryption (research feature) |
| `crates/encompute-evaluator` | Evaluator sessions; never links client crypto |
| `crates/encompute-runtime` | Execution, differential testing, explain, bench, artifacts |
| `crates/encompute-cli` | `encompute` command |
| `crates/encompute-py`, `python/encompute` | Python SDK: extension module and tracing frontend |
| `examples/` | Demos: logistic scoring, semantic search, the two-machine search model, exact eligibility |

## License

AGPL-3.0-only, with commercial licenses available: see [LICENSING.md](LICENSING.md).
Encompute statically links OpenFHE (BSD 2-Clause); research builds with the
`tfhe-rs` feature also link TFHE-rs (BSD-3-Clause-Clear, plus Zama's patent
terms); see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
Security reports: [SECURITY.md](SECURITY.md).

