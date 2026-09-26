#!/usr/bin/env bash
# 17: a Hugging Face model, PEFT LoRA and patient-level DP, then attacks.
source "$(dirname "$0")/../lib.sh"
need_cli
need_python
"$PYTHON" -c "import torch, transformers, peft" 2>/dev/null ||
  skip "Hugging Face support is not installed (pip install 'encompute[huggingface]', or torch, transformers and peft)"
export ENCOMPUTE_CLI="$E" TOKENIZERS_PARALLELISM=false

step "Import a Hugging Face model and fine-tune it with PEFT and patient-level privacy"
"$PYTHON" "$HERE/finetune.py" "$W/work"

step "Try breaking it"
"$PYTHON" "$HERE/attack.py" "$W/work"
