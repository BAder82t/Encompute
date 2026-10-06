# Build, test and the command line

Build Encompute from source, run the tests, and use the Python SDK and the `encompute` command.

## Build from source

Requires Rust (pinned in `rust-toolchain.toml`), CMake, a C++17 compiler
and, on macOS, `brew install libomp`. On Linux, building the Python wheel
with OpenFHE also needs `patchelf` (`apt install patchelf`), which maturin
uses to bundle `libgomp`.

```sh
cargo test                               # everything except OpenFHE and TFHE-rs
./scripts/install-openfhe.sh             # builds OpenFHE v1.5.1 (static) into .deps/openfhe
cargo test --workspace --features encompute-runtime/openfhe,encompute-evaluator/openfhe,encompute-cli/openfhe
```

Set `OPENFHE_ROOT` to use another static OpenFHE v1.5.1 install.

Exact programs on OpenFHE exact, and the commercial build audit:

```sh
cargo build --release -p encompute-cli -p encompute-evaluator \
  --features encompute-cli/openfhe,encompute-evaluator/openfhe
scripts/exact-demo.sh                        # encrypted eligibility decision via a separate evaluator
scripts/audit-commercial-build.sh target/release   # no TFHE-rs anywhere in the build
```

The control plane (PostgreSQL and OpenBao for the service tests; any dev
servers will do):

```sh
ENCOMPUTE_TEST_DATABASE_URL=postgres://USER:PASS@127.0.0.1:5432/postgres \
ENCOMPUTE_TEST_BAO_ADDR=http://127.0.0.1:8200 ENCOMPUTE_TEST_BAO_TOKEN=root \
  cargo test -p encompute-control -p encompute-keybroker
scripts/test-full.sh                   # the full run: precheck, every suite, verified to have run
scripts/enterprise-e2e.sh              # the commercial golden path in production mode
deploy/docker-compose/smoke.sh         # the same through the Compose deployment
```

The database-TLS tests also need a TLS-enabled PostgreSQL that requires a
client certificate: `scripts/tls-test-db.sh up` starts one on port 55445 (a
throwaway PKI; `eval "$(scripts/tls-test-db.sh env)"` sets what the tests
read, `down` removes it).

Without those variables the service-backed tests skip and still "pass". A
plain `cargo test` is for development: `ENCOMPUTE_REQUIRE_SERVICES=1` turns a
skip into a failure, and `scripts/test-full.sh` goes further. It checks
PostgreSQL, OpenBao, OpenFHE and the migrations first, runs the suites listed
in `scripts/test-manifest-governance.json` (which extends `scripts/test-manifest.json`), and fails on a missing service, a skipped,
empty or failed required suite, or a test count below the recorded minimums
(it prints `FULL TEST PASSED` or `FULL TEST FAILED` and writes a JSON summary to
`target/test-full/summary.json`). Release gates use it.

Database-backed tests run in one of two modes (`ENCOMPUTE_TEST_DB_MODE`):

- `template` (the default for `cargo test`): the migrations run once per
  schema revision into a sealed template database, and each test gets its own
  clone. Fast; for development and pull requests.
- `cold`: each test creates an empty database and the control plane migrates
  it itself. Slower; `scripts/test-full.sh` and the release check always use
  it, so a clone can never hide a broken migration or bootstrap.

TFHE-rs (research feature; never in commercial builds):

```sh
cargo test --release -p encompute-runtime --features research-tfhe-rs --test research_tfhe
cargo test --release -p encompute-runtime --features openfhe,research-tfhe-rs --test cross_backend
```

## Python

```sh
python -m venv .venv && . .venv/bin/activate
pip install maturin pytest numpy
maturin develop --release --features openfhe   # omit --features for mock only
pytest -q
examples/run-all.sh quick   # or: python examples/01_ckks_private_inference/model.py
```

## CLI

```sh
cargo build --release --features openfhe -p encompute-cli
encompute compile model.py:score -o score.encompute     # or a .eir file
encompute run score.encompute --input x=0.1,0.2,... --mode encrypted
encompute test score.encompute --cases 1000 --mode encrypted
encompute explain score.encompute --measure 100 --mode encrypted
encompute bench score.encompute --mode encrypted
encompute audit score.encompute
encompute transcript approve.encompute          # exact programs
encompute privacy explain step.encompute        # confidentiality graph
```
