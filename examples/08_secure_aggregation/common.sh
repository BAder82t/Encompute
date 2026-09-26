# Shared by run.sh and the attack scripts (source lib.sh first).

# The consortium: the compiled program, each hospital's identity key, and
# parties.json, the list of identities every side agrees on.
consortium() {
  cd "$W"
  "$E" compile "$HERE/fedavg.eir" -o fedavg.encompute > /dev/null
  for x in a b c; do "$E" aggregate identity --party "hospital-$x" --key "$x.key"; done > parties.jsonl
  "$PYTHON" -c 'import json,sys; print(json.dumps([json.loads(l) for l in open(sys.argv[1])]))' \
    parties.jsonl > parties.json
}

# coordinator SEQUENCE [serve options]: a coordinator process for one round,
# in the background. Sets URL, COORD (its pid) and CLOG (its log).
coordinator() {
  local seq="$1"
  shift
  local port
  port="$(free_port)"
  URL="http://127.0.0.1:$port"
  CLOG="coordinator-$seq-$port.log"
  "$E" aggregate serve fedavg.encompute --parties parties.json --key coordinator.key \
    --listen "127.0.0.1:$port" --sequence "$seq" --stage-timeout "${STAGE_TIMEOUT:-20}" "$@" \
    > "$CLOG" 2>&1 &
  COORD=$!
  ready "$URL/v1/round"
}

# join X [join options]: Hospital X's own process contributes its vector.
join() {
  local x="$1"
  shift
  "$E" aggregate join fedavg.encompute --parties parties.json --coordinator "$URL" \
    --party "hospital-$x" --key "$x.key" --values "$HERE/hospital-$x.json" --state "$x.round" "$@"
}

# A full round: A, B and C contribute concurrently.
full_round() {
  coordinator "$@"
  local pids="" x
  for x in a b c; do
    join "$x" > "join-$x-$1.log" 2>&1 &
    pids="$pids $!"
  done
  for x in $pids; do wait "$x"; done
  wait "$COORD"
}

# Waits for the coordinator to exit, prints its log, and succeeds only if
# it released an aggregate. (Usable inside `attack`.)
round_released() {
  while kill -0 "$COORD" 2>/dev/null; do sleep 0.1; done
  cat "$CLOG"
  grep -q "AGGREGATION COMPLETE" "$CLOG"
}

# refused CODE BOUNDARY WHAT command...: the attack must fail with CODE.
refused() {
  local code="$1" boundary="$2" out
  shift 2
  out="$(attack "$@")"
  echo "$out"
  echo "BOUNDARY $boundary"
  echo "$out" | grep -q "$code" || { echo "UNEXPECTED: refused without $code" >&2; exit 1; }
}
