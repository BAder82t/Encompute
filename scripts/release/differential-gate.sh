#!/usr/bin/env bash
# Release gate: differential testing of every execution path.
#
#   Exact: clear interpreter == mock == OpenFHE optimized circuit == OpenFHE
#          reference lowering, on a fixed seed set of random programs, the
#          golden benchmark programs and boundary inputs
#          (crates/encompute-openfhe-client/tests/differential.rs).
#   CKKS:  clear vs mock vs OpenFHE within each program's declared
#          precision (parameter conformance, the run tier, the demos, and
#          the mock's lowering property tests).
#
#   scripts/release/differential-gate.sh            # production gate
#   RESEARCH_TFHE=1 scripts/release/differential-gate.sh
#                                                    # research CI: + TFHE-rs
#
# Needs OpenFHE (OPENFHE_ROOT, default .deps/openfhe). About ten minutes in
# release on eight threads. Knobs (see differential.rs): GATE_WORKERS (8),
# ENCOMPUTE_GATE_PROGRAMS (6), ENCOMPUTE_GATE_MAX_GATES (250),
# ENCOMPUTE_GATE_CORPUS=all. Exits non-zero if any check fails.
set -uo pipefail
cd "$(dirname "$0")/../.."
export OPENFHE_ROOT="${OPENFHE_ROOT:-$PWD/.deps/openfhe}"
if [ ! -d "$OPENFHE_ROOT" ]; then
  echo "differential gate: OpenFHE not found at $OPENFHE_ROOT (set OPENFHE_ROOT)" >&2
  exit 2
fi
export ENCOMPUTE_GATE_WORKERS="${GATE_WORKERS:-8}"
LOG="$(mktemp -d)"
trap 'rm -rf "$LOG"' EXIT
status=0
row() { printf '%-44s%s\n' "$1" "$2"; }
check() {  # check NAME command...
  local name="$1"; shift
  local t0=$SECONDS
  if "$@" > "$LOG/log" 2>&1; then
    row "$name" "PASS ($((SECONDS - t0))s)"
    grep -E 'DIFFERENTIAL GATE PASSED|plaintext gate:|run tier:|^(random|corpus|boundary) ' "$LOG/log" | sed 's/^/    /'
  else
    row "$name" "FAIL ($((SECONDS - t0))s)"
    tail -n 40 "$LOG/log" | sed 's/^/    | /'
    status=1
  fi
}

EXACT_FEATURES=()
LABEL=""
if [ "${RESEARCH_TFHE:-0}" = 1 ]; then
  # Research only: never part of a production build.
  EXACT_FEATURES=(--features research-tfhe-rs)
  LABEL=" == TFHE-rs"
fi

echo "== exact: clear == mock == OpenFHE optimized == OpenFHE reference$LABEL"
check "exact differential gate (OpenFHE)" \
  cargo test --release -p encompute-openfhe-client ${EXACT_FEATURES[@]+"${EXACT_FEATURES[@]}"} --test differential -- \
    --include-ignored --nocapture --test-threads 1
check "exact optimizer vs reference (plain bits)" \
  cargo test --release -p encompute-exact

echo "== CKKS: clear vs mock vs OpenFHE within the declared precision"
check "CKKS parameter conformance (OpenFHE)" \
  cargo test --release -p encompute-openfhe --test conformance
check "CKKS clear vs OpenFHE (run tier, demos)" \
  cargo test --release -p encompute-runtime --features openfhe --test conformance --test openfhe -- --nocapture
check "CKKS clear vs mock" \
  cargo test --release -p encompute-runtime --test mock

if [ "$status" = 0 ]; then echo "DIFFERENTIAL GATE: PASS"; else echo "DIFFERENTIAL GATE: FAIL"; fi
exit "$status"
