# Shared helpers for the examples: sourced by every example's run.sh.
#
#   BIN=path/to/target/release   use other binaries (default: target/debug)
#   PYTHON=path/to/python        the Python with the SDK (default: .venv)
#   EXAMPLES_MODE=quick|standard|crypto|full   set by run-all.sh
#
# An example that cannot run here exits 77 after printing SKIPPED and why.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${BIN:-$ROOT/target/debug}"
case "$BIN" in /*) ;; *) BIN="$ROOT/$BIN" ;; esac
E="$BIN/encompute"
EVAL="$BIN/encompute-evaluator"
if [ -z "${PYTHON:-}" ]; then
  if [ -x "$ROOT/.venv/bin/python" ]; then PYTHON="$ROOT/.venv/bin/python"; else PYTHON=python3; fi
fi
# The CLI runs $PYTHON to compile Python functions; no __pycache__ litter.
export PYTHON PYTHONDONTWRITEBYTECODE=1
MODE="${EXAMPLES_MODE:-standard}"

skip() {
  echo "SKIPPED"
  echo "Reason: $*"
  exit 77
}

need_cli() {
  [ -x "$E" ] || skip "the encompute CLI is not built (cargo build --bins)"
}

need_evaluator() {
  [ -x "$EVAL" ] || skip "encompute-evaluator is not built (cargo build --bins)"
}

need_python() {
  "$PYTHON" -c "import encompute" 2>/dev/null ||
    skip "the Python SDK is not installed (maturin develop -m crates/encompute-py/Cargo.toml)"
}

# has openfhe | openfhe-exact | tfhe-rs | verified-execution
has() {
  "$E" info 2>/dev/null | grep -q "^$1 *yes"
}

need() {
  has "$1" || skip "$1 unavailable in this build (see README: Build)"
}

# A scratch directory, removed with every background process on exit.
W="$(mktemp -d)"
cleanup() {
  local pids
  pids="$(jobs -p)"
  if [ -n "$pids" ]; then kill $pids 2>/dev/null || true; fi
  wait 2>/dev/null || true
  rm -rf "$W"
}
trap cleanup EXIT

step() {
  printf '\n== %s ==\n' "$*"
}

# Wait until a URL answers.
ready() {
  for _ in $(seq 150); do
    curl -s -o /dev/null "$1" && return 0
    sleep 0.2
  done
  echo "$1 did not start" >&2
  exit 1
}

# Wait until a TCP port accepts connections.
ready_port() {
  for _ in $(seq 150); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    sleep 0.2
  done
  echo "port $1 did not open" >&2
  exit 1
}

# A free port.
free_port() {
  "$PYTHON" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}

# Run an attack: it must fail. Prints the boundary's error.
#   attack "what" command...
attack() {
  local what="$1"
  shift
  local out
  if out="$("$@" 2>&1)"; then
    echo "$out"
    echo "ATTACK SUCCEEDED (this is a bug): $what" >&2
    exit 1
  fi
  printf 'ATTACK   %s\nREFUSED  %s\n' "$what" "$(echo "$out" | grep -E 'ENC[0-9]{4}|DENIED|FAILED|REFUSED|INVALID|refused|invalid' | head -n 2 | tr '\n' ' ')"
}
