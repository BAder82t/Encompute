# Encompute

Encompute compiles ordinary programs into encrypted computation. You declare which
values are secret and their ranges; Encompute builds a CKKS plan, picks 128-bit
parameters, runs it on OpenFHE, and checks the encrypted result against
plaintext.

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

Status: **v0.1**. See the [v0.1 plan](docs/v0.1-plan.md), the
[decision records](docs/adr/), the [threat model](docs/threat-model.md) and
the [error codes](docs/errors.md).

## What v0.1 does

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
  roles kept apart (the evaluator never holds the secret key).
- **Differential testing.** `test()` / `encompute test` compares encrypted and
  plaintext outputs on range endpoints plus random samples.

Out of scope for v0.1: comparisons and integers (TFHE, 0.3), bootstrapping
and GPU (0.2), networking and KMS (0.2/0.4).

## Build

Requires Rust (pinned in `rust-toolchain.toml`), CMake, a C++17 compiler and,
on macOS, `brew install libomp`.

```sh
cargo test                               # everything except OpenFHE
./scripts/install-openfhe.sh             # builds OpenFHE v1.5.1 (static) into .deps/openfhe
cargo test --workspace --all-features    # adds the OpenFHE backend
```

Set `OPENFHE_ROOT` to use another static OpenFHE v1.5.1 install.

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

## Layout

| Path | Role |
|---|---|
| `crates/encompute-ir` | Scheme-independent SSA IR, `.eir` text form, reference semantics |
| `crates/encompute-analysis` | Range and privacy analyses |
| `crates/encompute-ckks` | Lowering to CKKS plans; Chebyshev approximation; parameter selection |
| `crates/encompute-backend` | Backend trait; mock backend |
| `crates/encompute-openfhe` | OpenFHE CKKS through a `cxx` shim |
| `crates/encompute-runtime` | Execution, differential testing, explain, bench, artifacts |
| `crates/encompute-cli` | `encompute` command |
| `crates/encompute-py`, `python/encompute` | Python SDK: extension module and tracing frontend |
| `examples/` | The two v0.1 demos |

## License

AGPL-3.0-only, with commercial licenses available: see [LICENSING.md](LICENSING.md).
Encompute statically links OpenFHE (BSD 2-Clause); see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
Security reports: [SECURITY.md](SECURITY.md).

