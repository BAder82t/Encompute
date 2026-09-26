#!/usr/bin/env bash
# A contribution is bound to one round of one approved spec. The coordinator
# offers an older round, then a round of a weaker spec.
source "$(dirname "$0")/../lib.sh"
need_cli
source "$HERE/common.sh"
consortium
full_round 2
coordinator 1 --out old.json
refused ENC2102 "Hospital A's client: round numbers must increase" \
  "The coordinator opens round 1 after round 2 finished" join a --timeout 3
kill "$COORD"
wait "$COORD" 2>/dev/null || true

# The same program, but the coordinator lowers the minimum to 2 parties.
sed 's/minimum 3 colluding 2/minimum 2 colluding 1/' "$HERE/fedavg.eir" > weak.eir
"$E" compile weak.eir -o weak.encompute > /dev/null
port="$(free_port)"
URL="http://127.0.0.1:$port"
"$E" aggregate serve weak.encompute --parties parties.json --key coordinator.key \
  --listen "127.0.0.1:$port" --sequence 3 --stage-timeout 20 > weak.log 2>&1 &
ready "$URL/v1/round"
refused ENC2102 "Hospital A's client: the offered spec must equal the one it approved" \
  "Round 3 runs a spec with minimum 2 instead of the approved 3" join a --timeout 3
