#!/usr/bin/env bash
# Only two of the four authorities contribute; the program requires three.
# (Run by run.sh, in its world.)
source "$(dirname "$0")/../../lib.sh"
need_cli
source "$HERE/common.sh"
cd "${PS_WORLD:?run this through run.sh}"
SEQ=25
STAGE_TIMEOUT=2 coordinator surveillance.encompute "$SEQ" scoping.json ledger
for x in n s; do join "$x" surveillance.encompute scoping.json > "join-$x-below.log" 2>&1 & done
round_released() {
  while kill -0 "$COORD" 2>/dev/null; do sleep 0.1; done
  cat "$CLOG"
  grep -q "AGGREGATION COMPLETE" "$CLOG"
}
out="$(attack "The coordinator runs a round with 2 of the required 3 authorities" round_released)"
echo "$out"
echo "$out" | grep -q ENC2103 || { echo "UNEXPECTED: refused without ENC2103" >&2; exit 1; }
[ ! -e "round-$SEQ.json" ] && [ ! -e "receipt-$SEQ.json" ] ||
  { echo "UNEXPECTED: something was released" >&2; exit 1; }
echo "RELEASED nothing, and nothing was charged to any scope"
