#!/usr/bin/env bash
# 11: the automatic planner. Declare parties, assets and requirements;
# Encompute chooses the mechanisms, or refuses without weakening anything.
source "$(dirname "$0")/../lib.sh"
need_cli
need_python
cd "$W"

step "Python: Project.train (requirements in, mechanisms out)"
"$PYTHON" "$HERE/planner.py" "$W"

step "CLI: plan and check the same program"
echo "infrastructure: $(cat mock-tee.json)"
echo "training:       $(cat training.json)"
plan() { "$E" plan train.eir --training training.json "$@"; }
plan --infrastructure mock-tee.json --allow-development -o plan.json 2> plan.log |
  sed -n '/^RESULT/,$p'
grep -qF "$(cat plan-id)" plan.log && echo "same plan ID as Python's (plans are deterministic)"
"$E" check train.eir --training training.json --infrastructure mock-tee.json --allow-development
echo
echo "Without a TEE:"
if "$E" check train.eir --training training.json --infrastructure no-tee.json; then
  echo "planned without a TEE: this is a bug" >&2
  exit 1
fi

step "Deep explanation: every candidate the planner weighed"
echo "(encompute explain --deep: the aggregation step)"
"$E" explain train.eir --deep | sed -n '/^Candidates/,/^Security assumptions/p' | sed '$d'
echo "(encompute plan --deep: one training step)"
plan --infrastructure mock-tee.json --allow-development --deep 2>/dev/null |
  sed -n '/^Candidates/,/^train:patients-b/p' | sed '1,2d;$d'
echo
"$E" explain train.eir --deep | sed -n '/^Security assumptions/,/^$/p' | sed '$d'

# The planner must refuse; prints the rejected TEE candidate's reason.
#   refused "what" command...
refused() {
  local what="$1" out
  shift
  if out="$("$@" 2>&1)"; then
    echo "$out"
    echo "ATTACK SUCCEEDED (this is a bug): $what" >&2
    exit 1
  fi
  printf '\nATTACK   %s\n' "$what"
  echo "$out" | grep -m 1 -E '^  - .*TEE' | sed 's/.*: /REJECTED /'
  echo "$out" | grep -m 1 'PLANNING FAILED'
}

step "Try breaking it"
echo '{"tees": [{"tee": "intel-tdx", "provider": "gcp-confidential-space", "gpu": true, "cloud": true, "debug_only": true}], "key_broker": true}' > debug-tee.json
echo '{"tees": [{"tee": "intel-tdx", "provider": "gcp-confidential-space", "gpu": true, "cloud": true}], "key_broker": true}' > tdx.json
refused "accept mock attestation without --allow-development" \
  plan --infrastructure mock-tee.json
refused "mock attestation under the maximum profile" \
  plan --infrastructure mock-tee.json --allow-development --profile maximum
refused "a TEE that only runs debug workloads" \
  plan --infrastructure debug-tee.json
refused "a cloud TEE when nothing may run in the cloud" \
  plan --infrastructure tdx.json --local-only
