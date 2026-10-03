#!/usr/bin/env bash
# A program releases the signal to an agency the owner did not name.
source "$(dirname "$0")/../../lib.sh"
need_cli
source "$HERE/common.sh"
out="$(attack "A program releases the signal to the Housing Agency" \
  "$E" compile "$HERE/housing-agency.eir" -o "$W/x.encompute")"
echo "$out"
echo "$out" | grep -q ENC1902 || { echo "UNEXPECTED: compiled, or refused without ENC1902" >&2; exit 1; }
[ ! -e "$W/x.encompute" ] || { echo "UNEXPECTED: an artifact was written" >&2; exit 1; }
