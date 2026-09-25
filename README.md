# Encompute

Encompute compiles ordinary Python into encrypted computation. You declare
which values are secret and their ranges; Encompute picks the encryption
scheme from the types, builds a plan, chooses 128-bit parameters, runs it
on an evaluator that never sees your data, and checks the encrypted result
against plaintext.

Two kinds of programs share one API:

```python
import numpy as np
import encompute
from encompute import secret, Tensor, u8, u16, u32

# Approximate: real numbers, CKKS (OpenFHE), within a declared precision.
w, b = np.random.default_rng(0).normal(0, 0.3, 32), 0.1

@encompute.compile(precision=1e-3)
def score(x: secret[Tensor[32], -1.0:1.0]):
    return encompute.sigmoid(encompute.dot(w, x) + b)

# Exact: integers and Booleans, comparisons, encrypted selection.
@encompute.compile()
def approve(age: secret[u8, 0:120], income: secret[u32, 0:1_000_000],
            debt: secret[u32, 0:500_000], risk: secret[u16, 0:1000]):
    return (age >= 18) & (debt * 100 < income * 40) & (risk <= 650)

x = np.random.default_rng(1).uniform(-1, 1, 32)
score(x)                                   # plaintext reference
score(x, mode="encrypted")                 # CKKS on OpenFHE
approve(35, 100_000, 20_000, 400, mode="mock")   # True, exactly
print(approve.test(cases=1000))            # 1000 matches, 0 mismatches
print(score.explain())                     # plan, parameters, precision, verification
score.save("score.encompute")              # reproducible artifact, no keys
```

**Status: 0.3 and 0.4 in progress** (last release: v0.2.0). See the
[changelog](CHANGELOG.md), [benchmarks](docs/benchmarks.md),
[decision records](docs/adr/), [threat model](docs/threat-model.md) and
[error codes](docs/errors.md).

| Area | State |
|---|---|
| Approximate programs (CKKS, OpenFHE) | working, end to end, local and remote |
| Exact programs (integers, Booleans) | working on the mock; on TFHE-rs in the research build |
| Client/evaluator split over HTTP, worker processes | working |
| Signed execution receipts | working, CKKS and exact |
| Semantic transcripts (the statement a proof must satisfy) | working, exact programs |
| Cryptographic proof of correct execution | **not yet** (0.4 V3, research) |

## What Encompute does

**Privacy types.** `secret[float, lo:hi]` and `secret[Tensor[n], lo:hi]`
(approximate); `secret[u8, lo:hi]` … `secret[u64, lo:hi]`,
`secret[i8, lo:hi]` … `secret[i64, lo:hi]` and `secret[bool_]` (exact).
Using a secret in `if`, `print`, `int()` or as a divisor is a compile-time
error with a stable code, not a silent leak. Exact values at the API are
integers within ±2^53 (ADR-006).

**Operations.**
- Approximate: `+ - *`, `sum`, `dot`, public-matrix `@`, `poly`, `sigmoid`,
  `x ** k`, division by public values.
- Exact: `+ - *`, comparisons, `& | ^ ~`, shifts, `//` and `%` by constants,
  `encompute.select`, `minimum`/`maximum`, `lookup`, `cast`.

**Compiler.** The program's types choose the scheme: approximate programs
lower to CKKS (SIMD packing, hybrid diagonal matrix–vector products,
Chebyshev approximation of `sigmoid` to the requested precision, parameters
checked against the HE Standard 128-bit table); exact programs lower to a
backend-independent plan, with integer range analysis proving that no
operation overflows (a possible overflow is ENC1303). Programs mixing both
kinds are refused until hybrid execution (0.4+).

**Runtime.** `clear`, `mock` and `encrypted` modes. Client and evaluator
are separate roles talking only through versioned, checksummed envelopes
bound to scheme, backend, parameters, program and key; the evaluator never
receives the secret key and its binary links no client crypto. Locally both
roles run in one process; `run --remote` puts a network between them.

**Testing.** `test()` / `encompute test` compares encrypted and plaintext
results: within the precision for approximate programs, exactly (matches
and mismatches, boundary values first) for exact ones.

**Backends.**
- OpenFHE v1.5.1 (CKKS), statically linked.
- A plaintext mock for both kinds, for development and tests.
- TFHE-rs 1.8.1 for exact programs, behind the off-by-default `tfhe-rs`
  feature, for research use only: Zama requires a patent license for
  commercial use of its technology.

## Verification

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
| `EXECUTION VERIFIED` | A cryptographic proof shows the response is a correct homomorphic evaluation of the transcript over the request. **Not available yet.** |

A receipt does **not** prove that the evaluator computed honestly, that the
result is correct, or that it was not fabricated: an evaluator can sign a
lie. Only an execution proof rules that out (0.4 V3). Encompute prints
`RECEIPT VERIFIED` and `EXECUTION PROOF NOT PRESENT` until then (ADR-007,
ADR-008).

## Build

Requires Rust (pinned in `rust-toolchain.toml`), CMake, a C++17 compiler
and, on macOS, `brew install libomp`.

```sh
cargo test                               # everything except OpenFHE and TFHE-rs
./scripts/install-openfhe.sh             # builds OpenFHE v1.5.1 (static) into .deps/openfhe
cargo test --workspace --features encompute-runtime/openfhe,encompute-evaluator/openfhe,encompute-cli/openfhe
```

Set `OPENFHE_ROOT` to use another static OpenFHE v1.5.1 install.

TFHE-rs (research feature):

```sh
cargo test --release -p encompute-runtime --features tfhe-rs --test exact
cargo build --release -p encompute-cli -p encompute-evaluator \
  --features encompute-cli/tfhe-rs,encompute-evaluator/tfhe-rs
scripts/exact-demo.sh        # encrypted eligibility decision via a separate evaluator
```

### Python

```sh
python -m venv .venv && . .venv/bin/activate
pip install maturin pytest numpy
maturin develop --release --features openfhe   # omit --features for mock only
pytest -q
python examples/logistic_regression.py
python examples/eligibility.py
```

### CLI

```sh
cargo build --release --features openfhe -p encompute-cli
encompute compile model.py:score -o score.encompute     # or a .eir file
encompute run score.encompute --input x=0.1,0.2,... --mode encrypted
encompute test score.encompute --cases 1000 --mode encrypted
encompute explain score.encompute --measure 100 --mode encrypted
encompute bench score.encompute --mode encrypted
encompute audit score.encompute
encompute transcript approve.encompute          # exact programs
```

### Remote evaluation

```sh
cargo build --release --features openfhe -p encompute-cli -p encompute-evaluator
encompute keys generate score.encompute -o score.keys          # secret.key stays here
encompute-evaluator serve score.encompute --listen 0.0.0.0:8750 --identity evaluator.key
encompute run score.encompute --remote http://EVALUATOR:8750 --keys score.keys --input x=... \
  --save-receipt result.receipt.json --save-envelopes exchange/
encompute verify result.receipt.json --model score.encompute \
  --request exchange/request.bin --response exchange/response.bin --trust-evaluator KEY
```

`verify` exits 0 only when every binding was checked (trusted key, artifact,
backend, transcript, request and response), 3 when some were not, and 1
when any check fails. The evaluator speaks plain HTTP: put a TLS proxy in
front of it. `scripts/audit-evaluator-binary.sh` checks that the evaluator
binary contains no Encompute key-generation, encryption or decryption code.

## Layout

| Path | Role |
|---|---|
| `crates/encompute-ir` | Scheme-independent SSA IR, `.eir` text form, reference semantics |
| `crates/encompute-analysis` | Range, overflow and privacy analyses |
| `crates/encompute-ckks` | Lowering to CKKS plans; Chebyshev approximation; parameter selection |
| `crates/encompute-exact` | Exact plans: lowering, validation, execution, semantic transcripts |
| `crates/encompute-backend` | Client and evaluator traits; mock backends |
| `crates/encompute-protocol` | Versioned, checksummed envelopes |
| `crates/encompute-verification` | Execution specs, signed receipts, transcripts, proof interfaces (no FHE dependency) |
| `crates/encompute-openfhe`, `-openfhe-client` | OpenFHE evaluator side; client side (keys, encryption, decryption) |
| `crates/encompute-tfhe`, `-tfhe-client` | TFHE-rs evaluator side; client side (research feature) |
| `crates/encompute-evaluator` | Evaluator sessions and HTTP service; never links client crypto |
| `crates/encompute-runtime` | Execution, differential testing, explain, bench, audit, artifacts |
| `crates/encompute-cli` | `encompute` command |
| `crates/encompute-py`, `python/encompute` | Python SDK: extension module and tracing frontend |
| `examples/` | Logistic scoring, semantic search, two-machine search, exact eligibility |

## Roadmap

- **0.4 V3**: a first cryptographic proof of correct encrypted execution for
  a small exact subset (research).
- **Next**: first-class parties, assets and confidentiality policies in the
  IR.

## License

AGPL-3.0-only, with commercial licenses available: see [LICENSING.md](LICENSING.md).
Encompute statically links OpenFHE (BSD 2-Clause); research builds with the
`tfhe-rs` feature also link TFHE-rs (BSD-3-Clause-Clear, plus Zama's patent
terms); see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
Security reports: [SECURITY.md](SECURITY.md).
