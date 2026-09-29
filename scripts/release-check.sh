#!/usr/bin/env bash
# Release check: from a clean checkout to a release candidate, using only
# documented commands, with a final PASS/FAIL table (docs/release-process.md).
#
#   scripts/release-check.sh                  # every row; a required SKIP fails
#   scripts/release-check.sh --allow-skip     # required rows may be SKIPPED
#   scripts/release-check.sh --only "SecAgg,DP"   # a subset (never a release)
#   scripts/release-check.sh --repro          # also the reproducibility check
#   scripts/release-check.sh --list           # the rows and what they run
#
# Required rows (the release gate): Rust workspace, Python SDK, OpenFHE CKKS,
# OpenFHE Exact, optimized/reference diff, remote execution, SecAgg, DP,
# patient DP-SGD, HF/PEFT, control plane, tenant isolation, backup/restore,
# assurance, commercial dependency, SBOM, security scans. The other rows
# (fine-tuning, examples, deployment, Confidential Space, TFHE-rs research,
# pins) are reported; a FAIL there still fails the check, a SKIP does not.
#
# What each row needs when it is not SKIPPED:
#   OpenFHE rows        scripts/install-openfhe.sh (.deps/openfhe) or OPENFHE_ROOT
#   control plane,      ENCOMPUTE_TEST_DATABASE_URL, ENCOMPUTE_TEST_BAO_ADDR,
#   tenant isolation    ENCOMPUTE_TEST_BAO_TOKEN (PostgreSQL, OpenBao dev servers)
#   backup/restore      scripts/release/backup-drill.sh; else the enterprise E2E
#                       (OpenFHE, the services above, pg_dump/psql); else the
#                       Compose smoke test (docker, images :dev)
#   security scans      cargo-deny, cargo-audit, pip-audit; IMAGES="a b" adds a
#                       container scan (trivy or grype) and container SBOMs (syft);
#                       a release lists the TEE images too (encompute-confidential-
#                       space, encompute-training) and sets REQUIRE_IMAGES
#   Python rows         python3 and network access for pip (first run)
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
LOG="$(mktemp -d)"
trap 'rm -rf "$LOG"' EXIT

ALLOW_SKIP=0; ONLY=""; REPRO=0; LIST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --allow-skip) ALLOW_SKIP=1 ;;
    --only) ONLY="$2"; shift ;;
    --repro) REPRO=1 ;;
    --list) LIST=1 ;;
    -h|--help) sed -n '2,33p' "$0"; exit 0 ;;
    *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

REQUIRED="|Rust workspace|Python SDK|OpenFHE CKKS|OpenFHE Exact|optimized/reference diff|remote execution|SecAgg|DP|patient DP-SGD|HF/PEFT|control plane|tenant isolation|backup/restore|assurance|commercial dependency|SBOM|security scans|"
NAMES=(); RESULTS=()
status=0

is_required() { case "$REQUIRED" in *"|$1|"*) return 0 ;; esac; return 1; }
wanted() {
  [ -z "$ONLY" ] && return 0
  case ",$ONLY," in *",$1,"*) return 0 ;; esac
  return 1
}
record() {  # record NAME RESULT
  NAMES+=("$1"); RESULTS+=("$2")
  printf '%-28s%s\n' "$1" "$2"
}
logf() { echo "$LOG/$(echo "$1" | tr '/ ' '__').log"; }  # a row's log file
check() {  # check NAME command...
  local name="$1" log
  shift
  wanted "$name" || return 0
  if [ "$LIST" = 1 ]; then printf '%-28s%s\n' "$name" "$*"; return 0; fi
  log="$(logf "$name")"
  if "$@" > "$log" 2>&1; then
    record "$name" PASS
  else
    record "$name" FAIL
    tail -n 30 "$log" | sed 's/^/    | /'
  fi
}
skip() {  # skip NAME REASON
  wanted "$1" || return 0
  if [ "$LIST" = 1 ]; then printf '%-28s%s\n' "$1" "SKIPPED: $2"; return 0; fi
  record "$1" "SKIPPED ($2)"
}
# A row whose full meaning needs something absent: its available part runs
# and must pass, and the row is still reported as SKIPPED.
partial() {  # partial NAME REASON command...
  local name="$1" reason="$2"
  shift 2
  wanted "$name" || return 0
  if [ "$LIST" = 1 ]; then printf '%-28s%s  [then SKIPPED: %s]\n' "$name" "$*" "$reason"; return 0; fi
  local log
  log="$(logf "$name")"
  if "$@" > "$log" 2>&1; then
    record "$name" "SKIPPED (partial run passed; $reason)"
  else
    record "$name" FAIL
    tail -n 30 "$log" | sed 's/^/    | /'
  fi
}

# --- Environment -----------------------------------------------------------------
export PYTHON="$ROOT/.venv/bin/python"
PY="$ROOT/.venv/bin/python"
OPENFHE=0
if [ -n "${OPENFHE_ROOT:-}" ] && [ -d "$OPENFHE_ROOT" ]; then OPENFHE=1
elif [ -d .deps/openfhe ]; then OPENFHE=1; export OPENFHE_ROOT="$ROOT/.deps/openfhe"; fi
NO_OPENFHE="OpenFHE not installed: scripts/install-openfhe.sh or OPENFHE_ROOT"
SERVICES=0
if [ -n "${ENCOMPUTE_TEST_DATABASE_URL:-}" ] && [ -n "${ENCOMPUTE_TEST_BAO_ADDR:-}" ] &&
   [ -n "${ENCOMPUTE_TEST_BAO_TOKEN:-}" ]; then SERVICES=1; fi
NO_SERVICES="set ENCOMPUTE_TEST_DATABASE_URL, ENCOMPUTE_TEST_BAO_ADDR, ENCOMPUTE_TEST_BAO_TOKEN"
# The enterprise E2E takes the same services under its own names.
export ENCOMPUTE_E2E_DATABASE_URL="${ENCOMPUTE_E2E_DATABASE_URL:-${ENCOMPUTE_TEST_DATABASE_URL:-}}"
export BAO_ADDR="${BAO_ADDR:-${ENCOMPUTE_TEST_BAO_ADDR:-}}"
export BAO_TOKEN="${BAO_TOKEN:-${ENCOMPUTE_TEST_BAO_TOKEN:-}}"
if [ "$OPENFHE" = 1 ]; then
  RELEASE_FEATURES="encompute-cli/openfhe,encompute-evaluator/openfhe"
else
  RELEASE_FEATURES=""
fi

python_env() {
  [ -x .venv/bin/python ] || python3 -m venv .venv
  .venv/bin/pip install -q maturin pytest numpy &&
    # The versions the confidential training image pins: a model package
    # binds them, and the worker refuses packages made with others.
    .venv/bin/pip install -q -r deploy/confidential-space-training/requirements.txt \
      --extra-index-url https://download.pytorch.org/whl/cpu &&
    (unset CONDA_PREFIX; VIRTUAL_ENV="$PWD/.venv" PATH="$PWD/.venv/bin:$PATH" maturin develop -q)
}
# The release wheel (with OpenFHE when it is installed), built once, and a
# separate environment with it and without PyTorch for the encrypted
# examples. (On macOS, OpenFHE's libomp and PyTorch's own libomp in one
# process crash: docs/release-process.md, "Known issues".)
release_wheel() {
  [ -f "$LOG/.release-wheel" ] && return 0
  local f=()
  [ -z "$RELEASE_FEATURES" ] || f=(--features openfhe)
  rm -rf target/release-check-wheels
  (unset CONDA_PREFIX; VIRTUAL_ENV="$PWD/.venv" PATH="$PWD/.venv/bin:$PATH" \
    maturin build -q --release --locked ${f[@]+"${f[@]}"} -m crates/encompute-py/Cargo.toml -o target/release-check-wheels) &&
    touch "$LOG/.release-wheel"
}
openfhe_sdk() {
  release_wheel || return 1
  [ -x target/release-check-venv/bin/python ] || python3 -m venv target/release-check-venv
  target/release-check-venv/bin/pip install -q numpy pytest cryptography &&
    target/release-check-venv/bin/pip install -q --force-reinstall --no-deps target/release-check-wheels/*.whl
}
# The release binaries (CLI, evaluator, control plane), with OpenFHE when it
# is installed; built once, shared by the rows below.
release_bins() {
  [ -f "$LOG/.release-bins" ] && return 0
  local f=()
  [ -z "$RELEASE_FEATURES" ] || f=(--features "$RELEASE_FEATURES")
  cargo build -q --release --locked -p encompute-cli -p encompute-evaluator -p encompute-control ${f[@]+"${f[@]}"} &&
    touch "$LOG/.release-bins"
}
# One example, checked against its expected.txt (as examples/run-all.sh does).
example() {  # example NN [BIN]
  local dir out code
  dir="$(ls -d examples/"$1"_*/ | head -n 1)"
  out="$(BIN="${2:-target/debug}" bash "$dir/run.sh" 2>&1)"; code=$?
  echo "$out"
  [ $code -eq 0 ] || { echo "example $1 exited $code"; return 1; }
  [ -f "$dir/expected.txt" ] || return 0
  while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    echo "$out" | grep -qF -- "$line" || { echo "example $1: missing: $line"; return 1; }
  done < "$dir/expected.txt"
}
pytest_() { "$PY" -m pytest -q "$@"; }
export -f python_env release_bins release_wheel openfhe_sdk example pytest_ logf
export LOG RELEASE_FEATURES PY

[ "$LIST" = 1 ] && printf '%-28s%s\n' "ROW" "COMMAND"

# --- Core ------------------------------------------------------------------------
check "Rust workspace" bash -c 'cargo build --bins && cargo test -q && cargo clippy -q --all-targets -- -D warnings'
check "Python SDK" bash -c 'python_env && pytest_ python/tests \
  --ignore=python/tests/test_finetune.py --ignore=python/tests/test_finetune_matrix.py \
  --ignore=python/tests/test_finetune_leakage.py --ignore=python/tests/test_finetune_crash.py \
  --ignore=python/tests/test_dpsgd.py --ignore=python/tests/test_huggingface.py'

# --- OpenFHE ---------------------------------------------------------------------
if [ "$OPENFHE" = 1 ]; then
  check "OpenFHE CKKS" bash -c 'release_bins && openfhe_sdk &&
    cargo test -q --release -p encompute-runtime --features openfhe --test openfhe &&
    PYTHON="$PWD/target/release-check-venv/bin/python" BIN=target/release EXAMPLES_REQUIRE="01 03 19" examples/run-all.sh crypto'
  check "OpenFHE Exact" cargo test -q --release -p encompute-openfhe-client -p encompute-openfhe-exact
  check "optimized/reference diff" bash -c 'cargo test -q --release -p encompute-exact --test circuit &&
    release_bins && openfhe_sdk &&
    PYTHON="$PWD/target/release-check-venv/bin/python" example 20 target/release | grep -q "reference=.* optimized=.* MATCH"'
  check "remote execution" bash -c 'cargo test -q -p encompute-runtime --test network &&
    cargo test -q --release -p encompute-runtime --features openfhe --test openfhe_exact &&
    release_bins && openfhe_sdk && PYTHON="$PWD/target/release-check-venv/bin/python" scripts/exact-demo.sh'
else
  skip "OpenFHE CKKS" "$NO_OPENFHE"
  skip "OpenFHE Exact" "$NO_OPENFHE"
  partial "optimized/reference diff" "the encrypted comparison needs OpenFHE" \
    cargo test -q --release -p encompute-exact --test circuit
  partial "remote execution" "remote OpenFHE execution needs OpenFHE" \
    cargo test -q -p encompute-runtime --test network
fi

# --- Collaboration and privacy -----------------------------------------------------
check "SecAgg" bash -c 'cargo test -q -p encompute-secagg && cargo test -q -p encompute-runtime --test aggregation &&
  pytest_ python/tests/test_aggregation.py && example 08'
check "DP" bash -c 'cargo test -q -p encompute-privacy && cargo test -q -p encompute-runtime --test privacy &&
  pytest_ python/tests/test_privacy.py && example 09'
check "patient DP-SGD" bash -c 'pytest_ python/tests/test_dpsgd.py && example 16'
check "HF/PEFT" bash -c 'pytest_ python/tests/test_huggingface.py && example 17'
check "Fine-tuning E2E" pytest_ python/tests/test_finetune.py \
  python/tests/test_finetune_matrix.py python/tests/test_finetune_leakage.py \
  python/tests/test_finetune_crash.py python/tests/test_training_contract.py \
  python/tests/test_confidential_job.py
check "Examples" env EXAMPLES_REQUIRE="15 16 17 18" examples/run-all.sh standard

# --- Enterprise ------------------------------------------------------------------
if [ "$SERVICES" = 1 ]; then
  check "control plane" env ENCOMPUTE_REQUIRE_SERVICES=1 cargo test -q -p encompute-control -p encompute-keybroker -p encompute-verification
  check "tenant isolation" env ENCOMPUTE_REQUIRE_SERVICES=1 cargo test -q -p encompute-control --test isolation
else
  skip "control plane" "$NO_SERVICES"
  skip "tenant isolation" "$NO_SERVICES"
fi
# Backup and restore: the dedicated drill when present, else the enterprise
# E2E (database backup, restore, an older backup refused), else the Compose
# smoke test (backup.sh, destroy, restore.sh).
E2E_READY=0
if [ "$OPENFHE" = 1 ] && [ -n "$ENCOMPUTE_E2E_DATABASE_URL" ] && [ -n "$BAO_ADDR" ] && [ -n "$BAO_TOKEN" ] &&
   command -v "${PG_DUMP:-pg_dump}" >/dev/null 2>&1 && command -v "${PSQL:-psql}" >/dev/null 2>&1; then E2E_READY=1; fi
COMPOSE_READY=0
if command -v docker >/dev/null 2>&1 && docker image inspect encompute-evaluator:dev >/dev/null 2>&1 &&
   docker image inspect encompute-control:dev >/dev/null 2>&1 && docker image inspect encompute-services:dev >/dev/null 2>&1 &&
   [ "$OPENFHE" = 1 ]; then COMPOSE_READY=1; fi
E2E_DONE=""; COMPOSE_DONE=""
if [ -x scripts/release/backup-drill.sh ]; then
  # The drill's OIDC test issuer needs `cryptography`: use the release-check
  # environment, not whatever python3 the machine has.
  check "backup/restore" bash -c 'openfhe_sdk && TOOL_PYTHON="$PWD/target/release-check-venv/bin/python" scripts/release/backup-drill.sh'
elif [ "$E2E_READY" = 1 ]; then
  check "backup/restore" bash -c 'release_bins && openfhe_sdk && SDK_PYTHON="$PWD/target/release-check-venv/bin/python" TOOL_PYTHON="$PWD/target/release-check-venv/bin/python" scripts/enterprise-e2e.sh'
  E2E_DONE="backup/restore"
elif [ "$COMPOSE_READY" = 1 ]; then
  check "backup/restore" bash -c 'release_bins && openfhe_sdk && SDK_PYTHON="$PWD/target/release-check-venv/bin/python" TOOL_PYTHON="$PWD/target/release-check-venv/bin/python" deploy/docker-compose/smoke.sh'
  COMPOSE_DONE="backup/restore"
else
  skip "backup/restore" "scripts/release/backup-drill.sh not present yet; the enterprise E2E needs OpenFHE, the services and pg_dump/psql; the Compose smoke test needs docker and the :dev images"
fi
if [ -n "$E2E_DONE" ]; then
  if wanted "Enterprise E2E"; then
    if [ "$LIST" = 1 ]; then printf '%-28s%s\n' "Enterprise E2E" "(the backup/restore run)"
    else record "Enterprise E2E" "same run as $E2E_DONE"; fi
  fi
elif [ "$E2E_READY" = 1 ]; then
  check "Enterprise E2E" bash -c 'release_bins && openfhe_sdk && SDK_PYTHON="$PWD/target/release-check-venv/bin/python" TOOL_PYTHON="$PWD/target/release-check-venv/bin/python" scripts/enterprise-e2e.sh'
else
  skip "Enterprise E2E" "needs OpenFHE, ENCOMPUTE_TEST_* (or ENCOMPUTE_E2E_DATABASE_URL, BAO_ADDR, BAO_TOKEN), pg_dump, psql"
fi
if [ -n "$COMPOSE_DONE" ]; then
  if wanted "Compose deployment"; then
    if [ "$LIST" = 1 ]; then printf '%-28s%s\n' "Compose deployment" "(the backup/restore run)"
    else record "Compose deployment" "same run as $COMPOSE_DONE"; fi
  fi
elif [ "$COMPOSE_READY" = 1 ]; then
  check "Compose deployment" bash -c 'release_bins && openfhe_sdk && SDK_PYTHON="$PWD/target/release-check-venv/bin/python" TOOL_PYTHON="$PWD/target/release-check-venv/bin/python" deploy/docker-compose/smoke.sh'
else
  skip "Compose deployment" "build the images: deploy/docker-compose/README.md"
fi

# --- Assurance and the release artifacts ------------------------------------------
check "assurance" bash -c 'cargo build -q --release -p encompute-assurance --bins --examples && target/release/assurance-report'
# The commercial boundary: the release binaries, a wheel (WHEEL=, else one is
# built), and IMAGES. The same research ban is enforced by cargo-deny.
commercial() {
  release_bins || return 1
  local w="${WHEEL:-}"
  if [ -z "$w" ]; then
    release_wheel || return 1
    w="$(ls target/release-check-wheels/*.whl | head -n 1)"
  fi
  WHEEL="$w" IMAGES="${IMAGES:-}" scripts/audit-commercial-build.sh target/release
}
export -f commercial
check "commercial dependency" bash -c commercial
if [ "$LIST" = 0 ] && wanted "TFHE-rs contamination"; then
  if [ -f "$(logf "commercial dependency")" ] && grep -q "TFHE-rs contamination NONE" "$(logf "commercial dependency")"; then
    record "TFHE-rs contamination" "NONE"
  elif [ -f "$(logf "commercial dependency")" ]; then
    record "TFHE-rs contamination" "FAIL (FOUND or not audited: see the commercial dependency row)"
  fi
fi
if [ "$OPENFHE" = 1 ]; then
  check "SBOM" bash -c 'release_bins && OPENFHE=1 BIN=target/release WHEEL="$(ls target/release-check-wheels/*.whl 2>/dev/null | head -n 1)" \
    IMAGES="${IMAGES:-}" scripts/release/sbom-all.sh target/sbom'
else
  partial "SBOM" "the release SBOMs record the OpenFHE builds" \
    bash -c 'OPENFHE=0 BIN=target/release IMAGES="${IMAGES:-}" scripts/release/sbom-all.sh target/sbom'
fi
check "security scans" env IMAGES="${IMAGES:-}" REQUIRE_IMAGES="${REQUIRE_IMAGES:-}" scripts/release/scan.sh
check "build pins" scripts/release/check-pins.sh
if [ "$REPRO" = 1 ]; then
  if [ "$OPENFHE" = 1 ]; then check "reproducibility" scripts/release/repro-check.sh --openfhe
  else check "reproducibility" scripts/release/repro-check.sh; fi
fi

# --- Research and live checks (never shipped, or needing a cloud) -------------------
if [ -n "${ENCOMPUTE_TFHE:-}" ]; then
  check "TFHE-rs research" cargo test -q --release -p encompute-tfhe-client --features research-tfhe-rs
else
  skip "TFHE-rs research" "set ENCOMPUTE_TFHE=1; research feature, never shipped"
fi
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  check "CS training image" bash -c 'D=deploy/confidential-space-training/Dockerfile &&
    docker build -q -f $D -t encompute-training:production . >/dev/null &&
    docker run --rm --entrypoint sh encompute-training:production -c "! command -v encompute" &&
    docker build -q --target rehearsal -f $D -t encompute-training:approved . >/dev/null &&
    docker build -q --target rehearsal --build-arg VARIANT=tampered -f $D -t encompute-training:tampered . >/dev/null &&
    W="$(mktemp -d)" && ENCOMPUTE_CLI="$PWD/target/debug/encompute" "$PY" examples/18_confidential_space_hf/job.py container "$W/a" &&
    ENCOMPUTE_CLI="$PWD/target/debug/encompute" "$PY" examples/18_confidential_space_hf/job.py container "$W/t" --run encompute-training:tampered'
else
  skip "CS training image" "needs docker"
fi
# Live Confidential Space training: real hardware attestation on GCP. Needs
# a project, a reachable broker URL and gcloud; never a secret.
if [ -n "${ENCOMPUTE_GCP_PROJECT:-}" ] && [ -n "${ENCOMPUTE_BROKER_URL:-}" ] && command -v gcloud >/dev/null 2>&1; then
  check "CS training (live)" bash -c 'for v in approved tampered debug; do PROJECT="$ENCOMPUTE_GCP_PROJECT" BROKER_URL="$ENCOMPUTE_BROKER_URL" PYTHON="$PY" CLEANUP=1 deploy/confidential-space-training/deploy.sh "$v" || exit 1; done'
else
  skip "CS training (live)" "GCP environment unavailable (ENCOMPUTE_GCP_PROJECT, ENCOMPUTE_BROKER_URL, gcloud)"
fi
skip "CS key release (live)" "manual: deploy/confidential-space"

[ "$LIST" = 1 ] && exit 0

# --- The table -------------------------------------------------------------------
echo
printf '%-28s %-9s %s\n' "ROW" "REQUIRED" "RESULT"
printf '%-28s %-9s %s\n' "---" "--------" "------"
for i in "${!NAMES[@]}"; do
  n="${NAMES[$i]}"; r="${RESULTS[$i]}"
  req=no; is_required "$n" && req=yes
  case "$r" in
    PASS|NONE|"same run as"*) ;;
    SKIPPED*) if [ "$req" = yes ] && [ "$ALLOW_SKIP" = 0 ]; then r="$r -> FAIL (required; --allow-skip to accept)"; status=1; fi ;;
    *) status=1 ;;
  esac
  printf '%-28s %-9s %s\n' "$n" "$req" "$r"
done
# Required rows that did not run at all (--only).
if [ -z "$ONLY" ]; then
  IFS='|' read -r -a req_rows <<< "${REQUIRED#|}"
  for n in "${req_rows[@]}"; do
    [ -n "$n" ] || continue
    printf '%s\n' "${NAMES[@]}" | grep -qxF "$n" || { printf '%-28s %-9s %s\n' "$n" yes "MISSING -> FAIL"; status=1; }
  done
fi
echo
if [ -n "$ONLY" ]; then
  [ $status -eq 0 ] && echo "RELEASE CHECK (subset: $ONLY) PASSED" || echo "RELEASE CHECK (subset: $ONLY) FAILED"
  echo "A subset never qualifies a release."
else
  [ $status -eq 0 ] && echo "RELEASE CHECK PASSED" || echo "RELEASE CHECK FAILED"
fi
exit $status
