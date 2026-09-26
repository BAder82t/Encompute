#!/usr/bin/env bash
# 18: a Hugging Face + PEFT training step in Google Confidential Space.
#
#   examples/18_confidential_space_hf/run.sh --local      rehearse on this machine (default)
#   examples/18_confidential_space_hf/run.sh --gcp-project PROJECT --region REGION \
#       --broker-url URL [--zone ZONE] [approved|tampered|debug]
source "$(dirname "$0")/../lib.sh"
need_cli
need_python
"$PYTHON" -c "import torch, transformers, peft" 2>/dev/null ||
  skip "Hugging Face support is not installed (pip install 'encompute[huggingface]')"
export ENCOMPUTE_CLI="$E" TOKENIZERS_PARALLELISM=false

MODE=local
VARIANT=approved
while [ $# -gt 0 ]; do
  case "$1" in
    --local) MODE=local ;;
    --gcp-project) MODE=gcp; export PROJECT="$2"; shift ;;
    --region) export REGION="$2"; shift ;;
    --zone) export ZONE="$2"; shift ;;
    --broker-url) export BROKER_URL="$2"; shift ;;
    approved|tampered|debug) VARIANT="$1" ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$MODE" = gcp ]; then
  step "REAL CONFIDENTIAL SPACE: hardware attestation on Google Cloud"
  PYTHON="$PYTHON" exec "$ROOT/../deploy/confidential-space-training/deploy.sh" "$VARIANT"
fi

step "LOCAL REHEARSAL: production broker, simulated Confidential Space launcher (no hardware)"
"$PYTHON" "$HERE/job.py" local "$W/work"
