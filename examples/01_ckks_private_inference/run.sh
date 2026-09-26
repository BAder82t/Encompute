#!/usr/bin/env bash
# 01: CKKS private inference. Mock always; OpenFHE when built (crypto/full).
source "$(dirname "$0")/../lib.sh"
need_python

step "Compile and run a private logistic-regression score"
if [ "$MODE" = crypto ] || [ "$MODE" = full ]; then
  "$PYTHON" -c "import encompute,sys; sys.exit(0 if encompute.has_openfhe() else 1)" ||
    { [ "$MODE" = crypto ] && skip "OpenFHE unavailable (maturin develop --features openfhe)"; }
fi
if "$PYTHON" -c "import encompute,sys; sys.exit(0 if encompute.has_openfhe() else 1)"; then
  "$PYTHON" "$HERE/model.py" --encrypted
else
  echo "(OpenFHE not built: mock mode only; the plan and parameters are the real ones)"
  "$PYTHON" "$HERE/model.py"
fi
