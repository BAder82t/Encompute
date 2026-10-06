#!/usr/bin/env bash
# A program releases four categories where the owner allowed three.
source "$(dirname "$0")/../../lib.sh"
need_cli
source "$HERE/common.sh"
out="$(attack "A program widens the categories to four" \
  "$E" compile "$HERE/widened-categories.eir" -o "$W/x.encompute")"
echo "$out"
echo "$out" | grep -q ENC1907 || { echo "UNEXPECTED: compiled, or refused without ENC1907" >&2; exit 1; }
[ ! -e "$W/x.encompute" ] || { echo "UNEXPECTED: an artifact was written" >&2; exit 1; }
