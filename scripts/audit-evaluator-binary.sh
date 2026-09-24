#!/usr/bin/env bash
# Fail if the evaluator binary contains Encompute's client crypto
# (key generation, encryption, decryption, secret-key handling).
# OpenFHE's own internal routines are statically linked and reported, not
# failed: the guarantee is that the evaluator never receives a secret key
# (docs/v0.2-plan.md, D2).
set -euo pipefail
BIN="${1:-target/release/encompute-evaluator}"
[ -x "$BIN" ] || { echo "no evaluator binary at $BIN" >&2; exit 2; }

client_syms="$(nm "$BIN" | grep -c 'encompute_openfhe_client' || true)"
mock_client="$(nm "$BIN" | grep -E 'MockClient' | grep -c . || true)"
echo "encompute client-crypto symbols: ${client_syms}"
echo "mock client symbols:             ${mock_client}"
echo "OpenFHE-internal Decrypt symbols (library code, no key present): $(nm "$BIN" | c++filt | grep -c 'Decrypt(' || true)"
if [ "${client_syms}" != "0" ] || [ "${mock_client}" != "0" ]; then
  echo "FAIL: evaluator binary links client crypto" >&2
  exit 1
fi
echo "PASS: no Encompute client crypto in ${BIN}"
