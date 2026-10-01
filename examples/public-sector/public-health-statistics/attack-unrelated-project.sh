#!/usr/bin/env bash
# Another project of the same authorities: with a scope of its own it still
# draws on the same populations (which the first project spent), and with
# no scope allocated it can spend nothing and inherits nothing.
# (Run by run.sh, in its world.)
source "$(dirname "$0")/../../lib.sh"
need_cli
source "$HERE/common.sh"
cd "${PS_WORLD:?run this through run.sh}"
allocate another-project ledger scoping-other.json scope-other
echo "SCOPES allocated to another-project: each for the population's whole epsilon"
attack "A second project with scopes of its own spends the populations again" \
  open_round surveillance.encompute 130 scoping-other.json ledger | tee other.out
grep -q "ENC2201" other.out && grep -q "population residents-" other.out ||
  { echo "UNEXPECTED: refused without the population's cap" >&2; exit 1; }
# A project nobody allocated a scope for: its scope ledgers do not exist,
# and a release never creates one.
for x in $REGIONS; do rm "ledger/scope-other-$x.ledger"; done
attack "A third project, with no scope allocated, tries to spend" \
  open_round surveillance.encompute 140 scoping-other.json ledger | tee unrelated.out
grep -q ENC2719 unrelated.out || { echo "UNEXPECTED: refused without ENC2719" >&2; exit 1; }
[ ! -e ledger/scope-other-n.ledger ] || { echo "UNEXPECTED: a scope was created" >&2; exit 1; }
