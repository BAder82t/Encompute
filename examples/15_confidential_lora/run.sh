#!/usr/bin/env bash
# 15: confidential LoRA fine-tuning with PyTorch, then every attack.
source "$(dirname "$0")/../lib.sh"
need_cli
need_python
"$PYTHON" -c "import torch" 2>/dev/null ||
  skip "PyTorch is not installed (pip install torch --index-url https://download.pytorch.org/whl/cpu)"
export ENCOMPUTE_CLI="$E"

step "Fine-tune ModelCo's private model on two hospitals' private data"
"$PYTHON" "$HERE/finetune.py" "$W/run"

step "Try breaking it"
"$PYTHON" "$HERE/attack.py" "$W/run"
