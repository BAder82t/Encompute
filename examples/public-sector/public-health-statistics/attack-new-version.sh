#!/usr/bin/env bash
# A new version of each region's dataset (new asset IDs, as a new weekly
# file is) used to get a fresh per-asset ledger, and so a fresh budget. A
# population is the series', not the version's: the budget carries over.
# (Run by run.sh, in its world.)
source "$(dirname "$0")/../../lib.sh"
need_cli
source "$HERE/common.sh"
cd "${PS_WORLD:?run this through run.sh}"
"$E" compile "$HERE/surveillance-new-version.eir" -o new-version.encompute > /dev/null
echo "Without scopes the new version's asset IDs have fresh ledgers: the round opens"
open_round new-version.encompute 110 - ledger-unscoped
stop_coordinator
# The owners' scoping carries over to the new versions' asset IDs: the same
# series, so the same scopes and populations.
sed 's/"counts-\([nsew]\)"/"counts-\1-w05"/' scoping.json > scoping-new-version.json
attack "A new version of the data to reset the budget (scoped to the same population)" \
  open_round new-version.encompute 120 scoping-new-version.json ledger | tee new-version.out
grep -q ENC2201 new-version.out || { echo "UNEXPECTED: refused without ENC2201" >&2; exit 1; }
[ ! -e round-120.json ] || { echo "UNEXPECTED: released" >&2; exit 1; }
