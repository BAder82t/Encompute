#!/usr/bin/env bash
# 00: hello, encrypted. A five-minute first run. Real encryption when OpenFHE
# is in the build (the released wheel has it); mock mode otherwise.
source "$(dirname "$0")/../lib.sh"
need_python

if [ "$MODE" = crypto ]; then
  "$PYTHON" -c "import encompute,sys; sys.exit(0 if encompute.has_openfhe() else 1)" ||
    skip "OpenFHE unavailable (maturin develop --features openfhe)"
fi

step "Score four private test results without revealing them"
if "$PYTHON" -c "import encompute,sys; sys.exit(0 if encompute.has_openfhe() else 1)"; then
  "$PYTHON" "$HERE/hello.py" --encrypted
else
  echo "(OpenFHE not built: mock mode only; nothing is encrypted in this run)"
  "$PYTHON" "$HERE/hello.py"
fi
