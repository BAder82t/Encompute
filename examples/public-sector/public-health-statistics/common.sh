# Shared by run.sh and the attack scripts (source ../../lib.sh first).
source "$HERE/../common.sh"

REGIONS="n s e w"
PROGRAM="$HERE/surveillance.eir"

region_name() {
  case "$1" in n) echo North ;; s) echo South ;; e) echo East ;; w) echo West ;; esac
}

# The consortium: the compiled program, each authority's identity key and
# parties.json, the list of identities every side agrees on.
consortium() {
  cd "$W"
  "$E" compile "$PROGRAM" -o surveillance.encompute > /dev/null
  for x in $REGIONS; do "$E" aggregate identity --party "region-$x" --key "$x.key"; done > parties.jsonl
  "$PYTHON" -c 'import json,sys; print(json.dumps([json.loads(l) for l in open(sys.argv[1])]))' \
    parties.jsonl > parties.json
}

# allocate PROJECT LEDGER_DIR SCOPING_FILE [SCOPE_PREFIX]: the owners'
# allocation for PROJECT: each region's scope of its population (created
# first, once, in LEDGER_DIR), at the population's whole epsilon.
allocate() {
  local project="$1" dir="$2" scoping="$3" prefix="${4:-scope}" x
  for x in $REGIONS; do
    "$E" privacy scope --ledger "$dir" --population "residents-$x" --id "$prefix-$x" \
      --project "$project" --purpose "$PS_PURPOSE" --epsilon 1.0 --asset "counts-$x" \
      --scoping "$scoping" > /dev/null
  done
}

# coordinator PROGRAM SEQUENCE SCOPING LEDGER [serve options]: a
# coordinator process for one round, in the background. Sets URL, COORD (its
# pid) and CLOG (its log). Returns 1 if it exits before opening the round (a
# refused release).
coordinator() {
  local program="$1" seq="$2" scoping="$3" ledger="$4" port scoping_flag=""
  shift 4
  [ "$scoping" = - ] || scoping_flag="--scoping $scoping"
  port="$(free_port)"
  URL="http://127.0.0.1:$port"
  CLOG="coordinator-$seq-$port.log"
  "$E" aggregate serve "$program" --parties parties.json $scoping_flag \
    --key coordinator.key --listen "127.0.0.1:$port" --sequence "$seq" --ledger "$ledger" \
    --stage-timeout "${STAGE_TIMEOUT:-20}" --out "round-$seq.json" --receipt "receipt-$seq.json" \
    "$@" > "$CLOG" 2>&1 &
  COORD=$!
  for _ in $(seq 150); do
    curl -s -o /dev/null "$URL/v1/round" && return 0
    kill -0 "$COORD" 2>/dev/null || return 1
    sleep 0.1
  done
  echo "the coordinator did not start" >&2
  exit 1
}

# join X PROGRAM SCOPING [join options]: authority X's own process contributes
# its counts.
join() {
  local x="$1" program="$2" scoping="$3"
  shift 3
  "$E" aggregate join "$program" --parties parties.json --scoping "$scoping" \
    --coordinator "$URL" --party "region-$x" --key "$x.key" \
    --values "$HERE/data/region-$x.json" --labels "$HERE/data/strata.json" --state "$x.round" "$@"
}

# week N: the four authorities contribute to week N's round (sequence 10 x N,
# so the attacks can run between weeks) of the plan against the project's
# scopes; returns 1 when the release is denied.
week() {
  local seq=$(($1 * 10)) pids="" x
  coordinator surveillance.encompute "$seq" scoping.json ledger || return 1
  for x in $REGIONS; do
    join "$x" surveillance.encompute scoping.json > "join-$x-$seq.log" 2>&1 &
    pids="$pids $!"
  done
  for x in $pids; do wait "$x"; done
  wait "$COORD"
}

# The coordinator refused to open the round: it must say RELEASE DENIED
# (ENC2201), or `want`.
denied() {
  local seq="$1" want="${2:-ENC2201}"
  if wait "$COORD"; then echo "UNEXPECTED: round $seq ran" >&2; exit 1; fi
  [ ! -e "round-$seq.json" ] || { echo "UNEXPECTED: round $seq released" >&2; exit 1; }
  grep -q "$want" "$CLOG" || { cat "$CLOG"; exit 1; }
  grep "$want" "$CLOG" | head -n 1
}

# What week N cost the first region's scope and its population.
spent() {
  "$PYTHON" - "$1" <<'PY'
import json, sys
week = sys.argv[1]
r = json.load(open(f"receipt-{int(week) * 10}.json"))["manifest"]["privacy"]
p = next(p for p in r if p["asset_id"] == "scope-n")
q = next(p for p in r if p["asset_id"] == "residents-n")
print(f"Week {week}  RELEASED  epsilon this week {float(p['epsilon_cost']):.3f}, "
      f"scope spent {float(p['cumulative_epsilon']):.3f}, "
      f"population spent {float(q['cumulative_epsilon']):.3f} of {p['budget_epsilon']}")
PY
}

# open_round PROGRAM SEQUENCE SCOPING LEDGER: succeeds if the coordinator
# opens a round, and otherwise prints its refusal and fails (for `attack`).
open_round() {
  if coordinator "$@"; then
    echo "round $2 is open"
    return 0
  fi
  wait "$COORD" 2>/dev/null || true
  cat "$CLOG"
  return 1
}

# stop_coordinator: ends a round nobody will join.
stop_coordinator() {
  kill "$COORD" 2>/dev/null || true
  wait "$COORD" 2>/dev/null || true
}
