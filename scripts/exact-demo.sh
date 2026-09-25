#!/usr/bin/env bash
# Encompute 0.3 exact demo: the client encrypts age, income, debt and risk;
# a separate evaluator process decides eligibility on ciphertexts with
# TFHE-rs and returns an encrypted Boolean; only the client decrypts.
#
#   scripts/exact-demo.sh [EVALUATOR_URL]
#
# Needs the research build (TFHE-rs; commercial use needs a patent license
# from Zama):
#   cargo build --release -p encompute-cli -p encompute-evaluator \
#     --features encompute-cli/tfhe-rs,encompute-evaluator/tfhe-rs
# Without a URL, an evaluator is started here as a separate process with no
# access to the client's key directory. With a URL, an evaluator already
# running elsewhere (encompute-evaluator serve --backend tfhe-rs) is used.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
ENCOMPUTE="${ENCOMPUTE:-$ROOT/target/release/encompute}"
EVALUATOR="${EVALUATOR:-$ROOT/target/release/encompute-evaluator}"
PYTHON="${PYTHON:-python3}"
URL="${1:-}"
PID=""
cleanup() {
  if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

step "client: compile the program (exact: integers and Booleans)"
"$ENCOMPUTE" compile "$ROOT/examples/eligibility.py:eligibility" -o "$WORK/eligibility.encompute"
"$ENCOMPUTE" explain "$WORK/eligibility.encompute" | sed -n '/Plan/,/Security/p'

step "client: generate TFHE keys (secret.key never leaves the client)"
"$ENCOMPUTE" keys generate "$WORK/eligibility.encompute" -o "$WORK/client.keys"
ls -l "$WORK/client.keys"

if [ -z "$URL" ]; then
  step "evaluator: start a separate process with the TFHE-rs backend (no keys)"
  mkdir -p "$WORK/evaluator"
  (cd "$WORK/evaluator" && exec "$EVALUATOR" serve --listen 127.0.0.1:18751 --backend tfhe-rs) &
  PID=$!
  URL="http://127.0.0.1:18751"
  for _ in $(seq 1 60); do curl -fs "$URL/v1/info" >/dev/null && break; sleep 1; done
fi
curl -fs "$URL/v1/info"; echo

step "client → evaluator: upload program and server key, send encrypted inputs, decrypt"
run() {
  "$ENCOMPUTE" run "$WORK/eligibility.encompute" --remote "$URL" --keys "$WORK/client.keys" \
    --input age="$1" --input income="$2" --input debt="$3" --input risk="$4"
}
run 31 120000 21000 400 | tee "$WORK/yes.json"
run 17 120000 21000 400 | tee "$WORK/no.json"

step "client: compare with plaintext (exact: no tolerance)"
"$ENCOMPUTE" run "$WORK/eligibility.encompute" --mode clear \
  --input age=31 --input income=120000 --input debt=21000 --input risk=400 > "$WORK/yes.clear.json"
"$ENCOMPUTE" run "$WORK/eligibility.encompute" --mode clear \
  --input age=17 --input income=120000 --input debt=21000 --input risk=400 > "$WORK/no.clear.json"
cmp "$WORK/yes.json" "$WORK/yes.clear.json"
cmp "$WORK/no.json" "$WORK/no.clear.json"
echo "encrypted results equal plaintext results"

if [ -n "$PID" ]; then
  step "evaluator: holds no secret key and no client crypto"
  echo "secret.key files in the evaluator's directory: $(find "$WORK/evaluator" -name secret.key | wc -l | tr -d ' ')"
  "$ROOT/scripts/audit-evaluator-binary.sh" "$EVALUATOR"
fi
echo; echo "DEMO PASSED"
