#!/usr/bin/env bash
# 12: attacks on the collaboration. Each runs the real flow up to the point
# of attack, then shows the boundary that refuses it and why.
#
#   ./attack.sh stale-attestation | wrong-party | replay-gradient |
#               weaken-dp | rollback-ledger | tamper-output | wrong-plan | all
source "$(dirname "$0")/../lib.sh"
need_cli
need_python
source "$HERE/setup.sh"

WHAT="${1:-all}"
QUIET=1

setup() {
  declare_collaboration
  plan_collaboration
  approve >/dev/null
  protect_model_key
}

# refused BOUNDARY LOG...: prints the first error line from the logs.
refused() {
  local boundary="$1"
  shift
  echo "BOUNDARY  $boundary"
  echo "REFUSED   $(grep -hoE 'error\[ENC[0-9]{4}\].*|INVALID: .*|REFUSED: ENC[0-9]{4}.*' "$@" 2>/dev/null | head -n 1)"
  [ -n "${DEBUG:-}" ] && tail -n 5 "$@"
  echo "RESULT    FAIL CLOSED"
}

stale_attestation() {
  step "ATTACK: replay a workload's attestation evidence to get the key again"
  "$E" keys challenge --broker broker.json > challenge.json
  "$E" workload attest collab.encompute --backend mock --challenge challenge.json \
    --identity workload.id --attester mock --mock-seed hw.seed --mock-image "$IMAGE" \
    --out evidence.json 2>/dev/null >/dev/null
  "$E" keys release --asset base-model --attestation evidence.json --mock-root "$MOCK_ROOT" \
    --broker broker.json --out grant.json | grep "KEY RELEASE"
  if "$E" keys release --asset base-model --attestation evidence.json --mock-root "$MOCK_ROOT" \
      --broker broker.json --out grant2.json > replay.log 2>&1; then
    echo "ATTACK SUCCEEDED"; exit 1
  fi
  refused "key broker: each challenge is answered once (freshness)" replay.log
}

wrong_party() {
  step "ATTACK: Hospital D, not in the consortium, contributes"
  "$E" aggregate identity --party hospital-d --key d.key >/dev/null
  if round 1 collab.encompute plan.json a b c d; then echo "ATTACK SUCCEEDED"; exit 1; fi
  refused "parties.json: only listed parties' signed messages count" join-d-1.log
}

replay_gradient() {
  step "ATTACK: the coordinator runs round 1 again to collect the updates twice"
  round 1 >/dev/null || { cat coordinator-1.log; exit 1; }
  echo "round 1: AGGREGATION COMPLETE"
  mv coordinator-1.log first-coordinator.log
  if round 1; then echo "ATTACK SUCCEEDED"; exit 1; fi
  refused "each party's round state: a round is joined once" join-a-1.log
}

weaken_dp() {
  step "ATTACK: the coordinator weakens the privacy noise"
  write_program 1.0 weak.eir
  "$E" compile weak.eir -o weak.encompute >/dev/null
  # Under the approved plan, the coordinator refuses to start...
  if round 1 weak.encompute plan.json; then echo "ATTACK SUCCEEDED"; exit 1; fi
  refused "the approved plan is for another program (noise 1.0)" coordinator-1.log
  # ...without the plan, weak noise is charged at its true cost...
  "$E" aggregate coordinator-policy weak.encompute --image "$IMAGE" --tee mock \
    --development > weak-policy.json
  if COORD_POLICY=weak-policy.json round 2 weak.encompute none; then
    echo "ATTACK SUCCEEDED"; exit 1
  fi
  refused "the privacy ledger charges the noise actually used (noise 1.0)" coordinator-2.log
  # ...and noise that fits the budget but is not the approved spec is
  # refused by every party.
  write_program 3.0 weaker.eir
  "$E" compile weaker.eir -o weaker.encompute >/dev/null
  "$E" aggregate coordinator-policy weaker.encompute --image "$IMAGE" --tee mock \
    --development > weaker-policy.json
  if COORD_POLICY=weaker-policy.json round 3 weaker.encompute none; then
    echo "ATTACK SUCCEEDED"; exit 1
  fi
  refused "each party checks the coordinator's spec is the approved one (noise 3.0)" join-a-3.log
}

rollback_ledger() {
  step "ATTACK: after round 1, the coordinator resets the privacy ledgers"
  round 1 >/dev/null || { cat coordinator-1.log; exit 1; }
  echo "round 1: AGGREGATION COMPLETE, budget charged"
  rm -rf ledgers
  if round 2; then echo "ATTACK SUCCEEDED"; exit 1; fi
  refused "each party's ledger checkpoint: the ledger must extend what it saw" join-a-2.log
}

tamper_output() {
  step "ATTACK: the released update is edited after the round"
  round 1 >/dev/null || { cat coordinator-1.log; exit 1; }
  "$PYTHON" - <<'PY'
import json
a = json.load(open("update-1.json"))
a["values"][0] += 0.5
json.dump(a, open("update-1.json", "w"))
PY
  if "$E" aggregate verify receipt-1.json collab.encompute --parties parties.json \
      --plan plan.json --coordinator-policy coord-policy.json --aggregate update-1.json \
      > verify.log 2>&1; then echo "ATTACK SUCCEEDED"; exit 1; fi
  refused "the aggregation receipt commits to the released aggregate" verify.log
}

wrong_plan() {
  step "ATTACK: the coordinator runs under a plan the owners did not approve"
  "$E" plan collab.encompute --profile strong --infrastructure infra.json \
    --training training.json --allow-development --prefer cost -o other-plan.json \
    >/dev/null 2>&1
  if round 1 collab.encompute other-plan.json; then echo "ATTACK SUCCEEDED"; exit 1; fi
  refused "the aggregation spec binds the approved PlanId" join-a-1.log coordinator-1.log
}

run() {
  ( setup >/dev/null; "$1" )
}

case "$WHAT" in
  stale-attestation) run stale_attestation ;;
  wrong-party) run wrong_party ;;
  replay-gradient) run replay_gradient ;;
  weaken-dp) run weaken_dp ;;
  rollback-ledger) run rollback_ledger ;;
  tamper-output) run tamper_output ;;
  wrong-plan) run wrong_plan ;;
  all)
    for a in stale_attestation wrong_party replay_gradient weaken_dp rollback_ledger \
             tamper_output wrong_plan; do
      (W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT; run "$a")
    done
    ;;
  *) echo "unknown attack $WHAT" >&2; exit 2 ;;
esac
