#!/usr/bin/env bash
# Release check: from a clean checkout to a trusted adapter, using only
# documented commands. The core (Rust workspace, Python SDK, confidential
# fine-tuning, examples, assurance) must pass; OpenFHE (CKKS and exact, and
# the commercial dependency audit), TFHE-rs research and Confidential Space
# checks run when available and report SKIPPED otherwise.
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
    .venv/bin/pip install -q "transformers==4.46.3" "peft==0.12.0" &&
    (unset CONDA_PREFIX; VIRTUAL_ENV="$PWD/.venv" PATH="$PWD/.venv/bin:$PATH" maturin develop -q)
}

check "Rust workspace" bash -c 'cargo build --bins && cargo test -q && cargo clippy -q --all-targets -- -D warnings'
check "Python SDK" bash -c "$(declare -f python_env); python_env && .venv/bin/python -m pytest -q python/tests \
  --ignore=python/tests/test_finetune.py --ignore=python/tests/test_finetune_matrix.py \
  --ignore=python/tests/test_finetune_leakage.py --ignore=python/tests/test_finetune_crash.py"
check "Fine-tuning E2E" .venv/bin/python -m pytest -q python/tests/test_finetune.py \
  python/tests/test_finetune_matrix.py python/tests/test_finetune_leakage.py \
  python/tests/test_finetune_crash.py python/tests/test_training_contract.py \
  python/tests/test_dpsgd.py python/tests/test_huggingface.py python/tests/test_confidential_job.py
check "Examples" env PYTHON="$PWD/.venv/bin/python" EXAMPLES_REQUIRE="15 16 17 18" examples/run-all.sh standard
check "Assurance" bash -c 'cargo build -q --release -p encompute-assurance --bins --examples && target/release/assurance-report'

if [ -d .deps/openfhe ]; then
  check "OpenFHE" bash -c 'cargo build -q --release --bins --features encompute-cli/openfhe,encompute-evaluator/openfhe -p encompute-cli -p encompute-evaluator && BIN=target/release EXAMPLES_REQUIRE="19" examples/run-all.sh crypto'
  check "OpenFHE Exact" cargo test -q --release -p encompute-openfhe-client -p encompute-openfhe-exact
  check "Exact remote execution" bash -c 'cargo test -q --release -p encompute-runtime --features openfhe --test openfhe_exact && scripts/exact-demo.sh'
  # The release binaries were just built with the production features.
  check "Commercial dependency audit" scripts/audit-commercial-build.sh target/release
  if grep -q "TFHE-rs contamination NONE" "$LOG/Commercial dependency audit.log"; then
    row "TFHE-rs contamination" "NONE"
  else
    row "TFHE-rs contamination" "FOUND (see the audit)"
    status=1
  fi
else
  for r in "OpenFHE" "OpenFHE Exact" "Exact remote execution" "Commercial dependency audit" "TFHE-rs contamination"; do
    row "$r" "SKIPPED (scripts/install-openfhe.sh)"
  done
fi
if [ -n "${ENCOMPUTE_TFHE:-}" ]; then
  check "TFHE-rs research" cargo test -q --release -p encompute-tfhe-client --features research-tfhe-rs
else
  row "TFHE-rs research" "SKIPPED (set ENCOMPUTE_TFHE=1; research feature, never shipped)"
fi
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  check "CS training image" bash -c 'D=deploy/confidential-space-training/Dockerfile &&
    docker build -q -f $D -t encompute-training:production . >/dev/null &&
    docker run --rm --entrypoint sh encompute-training:production -c "! command -v encompute" &&
    docker build -q --target rehearsal -f $D -t encompute-training:approved . >/dev/null &&
    docker build -q --target rehearsal --build-arg VARIANT=tampered -f $D -t encompute-training:tampered . >/dev/null &&
    W="$(mktemp -d)" && ENCOMPUTE_CLI="$PWD/target/debug/encompute" .venv/bin/python examples/18_confidential_space_hf/job.py container "$W/a" &&
    ENCOMPUTE_CLI="$PWD/target/debug/encompute" .venv/bin/python examples/18_confidential_space_hf/job.py container "$W/t" --run encompute-training:tampered'
else
  row "CS training image" "SKIPPED (needs docker)"
fi
# Live Confidential Space training: real hardware attestation on GCP. Needs
# a project, a reachable broker URL and gcloud; never a secret.
if [ -n "${ENCOMPUTE_GCP_PROJECT:-}" ] && [ -n "${ENCOMPUTE_BROKER_URL:-}" ] && command -v gcloud >/dev/null 2>&1; then
  check "CS training (live)" bash -c 'for v in approved tampered debug; do PROJECT="$ENCOMPUTE_GCP_PROJECT" BROKER_URL="$ENCOMPUTE_BROKER_URL" PYTHON="$PWD/.venv/bin/python" CLEANUP=1 deploy/confidential-space-training/deploy.sh "$v" || exit 1; done'
else
  row "CS training (live)" "SKIPPED — GCP environment unavailable (ENCOMPUTE_GCP_PROJECT, ENCOMPUTE_BROKER_URL, gcloud)"
fi
row "CS key release (live)" "SKIPPED (manual: deploy/confidential-space)"
echo
[ $status -eq 0 ] && echo "RELEASE CHECK PASSED" || echo "RELEASE CHECK FAILED"
exit $status
