#!/usr/bin/env bash
# A program releases the income gap itself, not its category.
source "$(dirname "$0")/../../lib.sh"
need_cli
source "$HERE/common.sh"
out="$(attack "The Tax Agency's income gap is released to the integrity unit" \
  "$E" compile "$HERE/release-the-gap.eir" -o "$W/x.encompute")"
echo "$out"
echo "$out" | grep -q ENC1907 || { echo "UNEXPECTED: compiled, or refused without ENC1907" >&2; exit 1; }
[ ! -e "$W/x.encompute" ] || { echo "UNEXPECTED: an artifact was written" >&2; exit 1; }
