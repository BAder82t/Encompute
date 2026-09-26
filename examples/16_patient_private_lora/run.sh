#!/usr/bin/env bash
# 16: patient-level DP-SGD next to organization-level privacy, then attacks.
source "$(dirname "$0")/../lib.sh"
need_cli
need_python
"$PYTHON" -c "import torch" 2>/dev/null ||
  skip "PyTorch is not installed (pip install torch --index-url https://download.pytorch.org/whl/cpu)"
export ENCOMPUTE_CLI="$E"

step "Fine-tune twice: organization-level, then patient-level privacy"
"$PYTHON" "$HERE/finetune.py" "$W/run"

step "Try breaking patient-level privacy"
"$PYTHON" "$HERE/attack.py" "$W/run"
