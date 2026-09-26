#!/usr/bin/env bash
# 09: secure aggregation plus differential privacy. Each round spends
# privacy budget; when the next would exceed it, the release is denied, and
# a restarted coordinator does not get a fresh budget.
source "$(dirname "$0")/../lib.sh"
need_cli
cd "$W"
"$E" compile "$HERE/fedavg.eir" -o fedavg.encompute > /dev/null
for x in a b c; do "$E" aggregate identity --party "hospital-$x" --key "$x.key"; done > parties.jsonl
"$PYTHON" -c 'import json,sys; print(json.dumps([json.loads(l) for l in open(sys.argv[1])]))' \
  parties.jsonl > parties.json

# serve SEQUENCE LEDGER: a coordinator process for one round. Returns 1 if
# it exits before opening the round (a denied release); sets URL and COORD.
serve() {
  local port
  port="$(free_port)"
  URL="http://127.0.0.1:$port"
  CLOG="coordinator-$1.log"
  "$E" aggregate serve fedavg.encompute --parties parties.json --key coordinator.key \
    --listen "127.0.0.1:$port" --sequence "$1" --ledger "$2" --stage-timeout 20 \
    --out "round-$1.json" --receipt "receipt-$1.json" > "$CLOG" 2>&1 &
  COORD=$!
  for _ in $(seq 150); do
    curl -s -o /dev/null "$URL/v1/round" && return 0
    kill -0 "$COORD" 2>/dev/null || return 1
    sleep 0.1
  done
  echo "the coordinator did not start" >&2
  exit 1
}

# Hospitals A, B and C contribute from separate processes.
contribute() {
  local pids="" x
  for x in a b c; do
    "$E" aggregate join fedavg.encompute --parties parties.json --coordinator "$URL" \
      --party "hospital-$x" --key "$x.key" --values "$HERE/hospital-$x.json" --state "$x.state" \
      > "join-$x-$1.log" 2>&1 &
    pids="$pids $!"
  done
  for x in $pids; do wait "$x"; done
  wait "$COORD"
}

# The coordinator must refuse to open the round, with RELEASE DENIED.
denied() {
  if wait "$COORD"; then echo "UNEXPECTED: round $1 ran" >&2; exit 1; fi
  [ ! -e "round-$1.json" ] || { echo "UNEXPECTED: round $1 released" >&2; exit 1; }
  grep -q ENC2201 "$CLOG" || { cat "$CLOG"; exit 1; }
  printf 'Round %s  DENIED     ' "$1"
  grep ENC2201 "$CLOG"
}

budget() {
  "$E" privacy budget --ledger ledger --asset gradient-a | grep -E '^  (Budget|Consumed|Remaining) '
}

step "The policy: secure aggregation, then differential privacy"
"$E" privacy explain fedavg.encompute | sed -n '/^Differential privacy/,/STATUS/p'

step "Rounds until the budget is spent (Hospital A's asset; B and C are the same)"
round=0
while :; do
  round=$((round + 1))
  [ "$round" -le 10 ] || { echo "UNEXPECTED: no round was denied" >&2; exit 1; }
  if ! serve "$round" ledger; then denied "$round"; break; fi
  contribute "$round"
  "$PYTHON" - "$round" <<'PY'
import json, sys
r = sys.argv[1]
p = next(p for p in json.load(open(f"receipt-{r}.json"))["manifest"]["privacy"]
         if p["asset_id"] == "gradient-a")
print(f"Round {r}  PERMITTED  epsilon this round {float(p['epsilon_cost']):.3f}, "
      f"spent {float(p['cumulative_epsilon']):.3f} of {p['budget_epsilon']}")
PY
done
last=$round

step "Hospital A's ledger"
budget | tee before.txt

step "Restart: every process has exited; a new coordinator opens the same ledger"
serve $((last + 1)) ledger && { echo "UNEXPECTED: the restarted coordinator opened a round" >&2; exit 1; }
denied $((last + 1))
budget > after.txt
cmp -s before.txt after.txt || { echo "UNEXPECTED: the budget changed" >&2; diff before.txt after.txt; exit 1; }
echo "Budget after restart: unchanged ($(grep Consumed after.txt | sed 's/^ *Consumed *//'))"

step "Try breaking it: a coordinator with a fresh, empty ledger"
serve $((last + 2)) ledger-reset
join_a() {
  "$E" aggregate join fedavg.encompute --parties parties.json --coordinator "$URL" \
    --party hospital-a --key a.key --values "$HERE/hospital-a.json" --state a.state --timeout 3
}
attack "The coordinator resets the ledger to get a new budget" join_a
