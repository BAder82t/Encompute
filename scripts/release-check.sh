#!/usr/bin/env bash
# Release check: from a clean checkout to a trusted adapter, using only
# documented commands. The core (Rust workspace, Python SDK, confidential
# fine-tuning, examples, assurance) must pass; OpenFHE, TFHE-rs and
# Confidential Space checks run when available and report SKIPPED otherwise.
#
#   scripts/release-check.sh            # expects cargo, python3, network for pip
set -uo pipefail
cd "$(dirname "$0")/.."
LOG="$(mktemp -d)"
trap 'rm -rf "$LOG"' EXIT
status=0

row() { printf '%-28s%s\n' "$1" "$2"; }

check() {  # check NAME command...
  local name="$1"
  shift
  if "$@" > "$LOG/$name.log" 2>&1; then
    row "$name" PASS
  else
    row "$name" FAIL
    tail -n 30 "$LOG/$name.log" | sed 's/^/    | /'
    status=1
  fi
}

python_env() {
  [ -x .venv/bin/python ] || python3 -m venv .venv
  .venv/bin/pip install -q maturin pytest numpy &&
    .venv/bin/pip install -q torch --index-url https://download.pytorch.org/whl/cpu &&
    (unset CONDA_PREFIX; VIRTUAL_ENV="$PWD/.venv" PATH="$PWD/.venv/bin:$PATH" maturin develop -q)
}

check "Rust workspace" bash -c 'cargo build --bins && cargo test -q && cargo clippy -q --all-targets -- -D warnings'
check "Python SDK" bash -c "$(declare -f python_env); python_env && .venv/bin/python -m pytest -q python/tests \
  --ignore=python/tests/test_finetune.py --ignore=python/tests/test_finetune_matrix.py \
  --ignore=python/tests/test_finetune_leakage.py --ignore=python/tests/test_finetune_crash.py"
check "Fine-tuning E2E" .venv/bin/python -m pytest -q python/tests/test_finetune.py \
  python/tests/test_finetune_matrix.py python/tests/test_finetune_leakage.py \
  python/tests/test_finetune_crash.py python/tests/test_training_contract.py
check "Examples" env PYTHON="$PWD/.venv/bin/python" EXAMPLES_REQUIRE="15" examples/run-all.sh standard
check "Assurance" bash -c 'cargo build -q --release -p encompute-assurance --bins --examples && target/release/assurance-report'

if [ -d .deps/openfhe ]; then
  check "OpenFHE" bash -c 'cargo build -q --release --bins --features encompute-cli/openfhe,encompute-evaluator/openfhe -p encompute-cli -p encompute-evaluator && BIN=target/release examples/run-all.sh crypto'
else
  row "OpenFHE" "SKIPPED (scripts/install-openfhe.sh)"
fi
if [ -n "${ENCOMPUTE_TFHE:-}" ]; then
  check "TFHE research" cargo test -q --release -p encompute-tfhe-client --features tfhe-rs
else
  row "TFHE research" "SKIPPED (set ENCOMPUTE_TFHE=1; research feature)"
fi
if [ -n "${ENCOMPUTE_GCP_PROJECT:-}" ]; then
  row "Confidential Space" "SKIPPED (run deploy/confidential-space manually; see docs)"
else
  row "Confidential Space" "SKIPPED (needs a GCP project: ENCOMPUTE_GCP_PROJECT)"
fi
echo
[ $status -eq 0 ] && echo "RELEASE CHECK PASSED" || echo "RELEASE CHECK FAILED"
exit $status
