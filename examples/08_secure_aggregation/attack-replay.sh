#!/usr/bin/env bash
# A party's vector must enter exactly one aggregate. Two ways to get it twice:
# resubmit within a round, or replay a finished round to the same party.
source "$(dirname "$0")/../lib.sh"
need_cli
source "$HERE/common.sh"
consortium
coordinator 1
join a > join-a.log 2>&1 &
a=$!
# Hospital A's state file is written just before it contributes.
while [ ! -s a.round ]; do sleep 0.1; done
sleep 0.5
resubmit() {
  "$E" aggregate join fedavg.encompute --parties parties.json --coordinator "$URL" \
    --party hospital-a --key a.key --values "$HERE/hospital-a.json" --state a-copy.round --timeout 3
}
refused ENC2102 "the coordinator: one message per party per stage" \
  "Hospital A's vector submitted twice in round 1 (a key copy, fresh state)" resubmit
for x in b c; do join "$x" > "join-$x.log" 2>&1 & done
wait "$COORD"
wait "$a"

coordinator 1 --out replay.json
refused ENC2102 "Hospital A's client: its state file refuses any round not newer than the last" \
  "The coordinator replays round 1 to collect Hospital A's vector again" join a --timeout 3
