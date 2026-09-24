# Veil

*Internal codename, see [ADR-003](docs/adr/0003-project-name.md).*

Veil is a compiler and runtime for private computation. Developers declare
which values are secret; Veil compiles the program to fully homomorphic
encryption, picks parameters, and checks that the encrypted result matches
plaintext.

Status: **M0**, workspace and OpenFHE bridge. See the
[v0.1 plan](docs/v0.1-plan.md) and the [decision records](docs/adr/).

## Build

Requires Rust 1.89 (pinned in `rust-toolchain.toml`), CMake, a C++17
compiler and, on macOS, `brew install libomp`.

```sh
cargo test                           # everything except the OpenFHE backend
./scripts/install-openfhe.sh         # builds OpenFHE v1.5.1 into .deps/openfhe
cargo test --workspace --all-features
```

To use an existing OpenFHE v1.5.1 install instead, set `OPENFHE_ROOT` to its
prefix.

## Layout

| Crate | Role |
|---|---|
| `veil-ir` | Scheme-independent SSA IR |
| `veil-analysis` | Privacy, range, depth, precision analyses |
| `veil-ckks` | Lowering to CKKS plans; parameter selection |
| `veil-backend` | Backend trait; mock backend |
| `veil-openfhe` | OpenFHE CKKS through a `cxx` shim |
| `veil-runtime` | Execution, differential testing, artifacts |
| `veil-cli` | `veil` command |

The Python SDK (`veilcompute`) arrives in M2.
