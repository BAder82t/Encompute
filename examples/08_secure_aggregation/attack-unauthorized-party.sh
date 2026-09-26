#!/usr/bin/env bash
# Hospital D is not in parties.json. It tries to join the round, first as
# itself, then claiming to be Hospital A with its own key.
source "$(dirname "$0")/../lib.sh"
need_cli
source "$HERE/common.sh"
consortium
"$E" aggregate identity --party hospital-d --key d.key > /dev/null
coordinator 1
d_joins() {
  "$E" aggregate join fedavg.encompute --parties parties.json --coordinator "$URL" \
    --party "$1" --key d.key --values "$HERE/hospital-d.json" --state "d-$1.round"
}
refused ENC2101 "parties.json, checked by the joining client; the coordinator checks it again" \
  "Hospital D (not in parties.json) joins the round" d_joins hospital-d
refused ENC2101 "the key listed for hospital-a in parties.json (client, then coordinator)" \
  "Hospital D joins as hospital-a, signing with its own key" d_joins hospital-a
