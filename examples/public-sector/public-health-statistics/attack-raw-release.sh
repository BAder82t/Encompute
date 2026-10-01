#!/usr/bin/env bash
# A program that releases one region's own counts, not the aggregate.
source "$(dirname "$0")/../../lib.sh"
need_cli
source "$HERE/common.sh"
cd "$W"
out="$(attack "A program releases North's counts to the ministry" \
  "$E" compile "$HERE/raw-regional-release.eir" -o raw.encompute)"
echo "$out"
echo "$out" | grep -q ENC2203 || { echo "UNEXPECTED: compiled, or refused without ENC2203" >&2; exit 1; }
[ ! -e raw.encompute ] || { echo "UNEXPECTED: an artifact was written" >&2; exit 1; }
