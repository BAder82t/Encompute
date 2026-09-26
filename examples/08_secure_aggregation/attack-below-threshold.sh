#!/usr/bin/env bash
# Only Hospitals A and B show up; the program requires 3 contributions.
source "$(dirname "$0")/../lib.sh"
need_cli
source "$HERE/common.sh"
consortium
STAGE_TIMEOUT=2 coordinator 1
for x in a b; do join "$x" > "join-$x.log" 2>&1 & done
refused ENC2103 "the coordinator's minimum of 3 (masks are secret-shared with threshold 3)" \
  "The coordinator runs a round with 2 of the required 3 parties" round_released
[ ! -e aggregate.json ] && [ ! -e aggregation-receipt.json ] ||
  { echo "UNEXPECTED: something was released" >&2; exit 1; }
echo "RELEASED nothing (no aggregate, no receipt)"
