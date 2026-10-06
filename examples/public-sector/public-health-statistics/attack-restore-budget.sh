#!/usr/bin/env bash
# The coordinator restores the ledgers from after week 2, to forget weeks 3
# and 4 and get the budget back. Every authority remembers what it saw.
# (Run by run.sh, in its world.)
source "$(dirname "$0")/../../lib.sh"
need_cli
source "$HERE/common.sh"
cd "${PS_WORLD:?run this through run.sh}"
mv ledger ledger-current
cp -R ledger-after-week-2 ledger
SEQ=100
coordinator surveillance.encompute "$SEQ" scoping.json ledger ||
  { echo "UNEXPECTED: the restored ledgers were refused by the coordinator" >&2; exit 1; }
echo "The coordinator opens round $SEQ on the restored ledgers (it has no memory of weeks 3 and 4)"
attack "The coordinator restores an old budget; North's authority joins" \
  join n surveillance.encompute scoping.json --timeout 3 | tee restore.out
grep -q ENC2202 restore.out || { echo "UNEXPECTED: refused without ENC2202" >&2; exit 1; }
kill "$COORD" 2>/dev/null || true
wait "$COORD" 2>/dev/null || true
rm -rf ledger
mv ledger-current ledger
[ ! -e "round-$SEQ.json" ] || { echo "UNEXPECTED: released" >&2; exit 1; }
