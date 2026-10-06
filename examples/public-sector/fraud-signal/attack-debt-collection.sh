#!/usr/bin/env bash
# A program uses the income data for a purpose its owner did not allow.
source "$(dirname "$0")/../../lib.sh"
need_cli
source "$HERE/common.sh"
out="$(attack "A program uses the data for debt collection" \
  "$E" compile "$HERE/debt-collection.eir" -o "$W/x.encompute")"
echo "$out"
echo "$out" | grep -q ENC1903 || { echo "UNEXPECTED: compiled, or refused without ENC1903" >&2; exit 1; }
[ ! -e "$W/x.encompute" ] || { echo "UNEXPECTED: an artifact was written" >&2; exit 1; }
