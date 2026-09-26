#!/usr/bin/env bash
# Fail if the evaluator binary contains Encompute's client crypto
# (key generation, encryption, decryption, secret-key handling), for both
# CKKS (OpenFHE), exact (OpenFHE BinFHE) and research exact (TFHE-rs) programs.
# OpenFHE's own internal routines are statically linked and reported, not
# failed: the guarantee is that the evaluator never receives a secret key
# (docs/threat-model.md).
set -euo pipefail
BIN="${1:-target/release/encompute-evaluator}"
[ -x "$BIN" ] || { echo "no evaluator binary at $BIN" >&2; exit 2; }

total="$(nm "$BIN" 2>/dev/null | wc -l | tr -d ' ')"
ours="$(nm "$BIN" 2>/dev/null | grep -c 'encompute' || true)"
if [ "${total}" = "0" ] || [ "${ours}" = "0" ]; then
  # A stripped binary, or one this nm cannot read (e.g. macOS nm on a Linux
  # ELF), would pass vacuously.
  echo "CANNOT AUDIT: ${BIN} has no readable symbols (stripped, or wrong nm for its format)" >&2
  exit 2
fi
client_syms="$(nm "$BIN" | grep -cE 'encompute_(openfhe|tfhe)_client' || true)"
mock_client="$(nm "$BIN" | grep -E 'MockClient|PlainExactClient' | grep -c . || true)"
tfhe_client="$(nm "$BIN" | grep -c 'ClientKey' || true)"
# OpenFHE exact (BinFHE) client: key generation, encryption, decryption.
exact_client="$(nm "$BIN" | grep -cE 'OpenFheExactClient|bin_(generate|restore|encrypt|decrypt|export_secret)' || true)"
echo "encompute client-crypto symbols: ${client_syms}"
echo "mock client symbols:             ${mock_client}"
echo "TFHE-rs ClientKey symbols:       ${tfhe_client}"
echo "OpenFHE exact client symbols:    ${exact_client}"
echo "OpenFHE-internal Decrypt symbols (library code, no key present): $(nm "$BIN" | c++filt | grep -c 'Decrypt(' || true)"
if [ "${client_syms}" != "0" ] || [ "${mock_client}" != "0" ] || [ "${tfhe_client}" != "0" ] ||
   [ "${exact_client}" != "0" ]; then
  echo "FAIL: evaluator binary links client crypto" >&2
  exit 1
fi
echo "PASS: no Encompute client crypto in ${BIN}"
