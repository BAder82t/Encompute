#!/usr/bin/env bash
# Fails when a tracked file holds an unresolved merge-conflict marker: a line
# that starts with seven '<' or seven '>' followed by a space. (A bare line of
# seven '=' is not matched: Markdown and reStructuredText headings use it.)
# A conflict committed by mistake once sat in docs/public-sector.md for days:
# nothing else in the gate reads prose.
#
# A file that documents or tests conflict markers on purpose can be listed, one
# path per line, in scripts/conflict-markers.allow (lines starting with # are
# comments). Nothing is listed today; each entry needs a reason in a comment.
#
#   scripts/check-conflict-markers.sh
set -euo pipefail
cd "$(dirname "$0")/.."
allow=scripts/conflict-markers.allow
excl=()
if [ -f "$allow" ]; then
  while IFS= read -r path; do
    case "$path" in ''|'#'*) continue ;; esac
    excl+=(":!$path")
  done < "$allow"
fi
# No file is excluded: the tests of this check build the marker text at run
# time, so no line of this repository starts with one.
if hits="$(git grep -nE '^(<{7} |>{7} )' -- . ${excl[@]+"${excl[@]}"})"; then
  printf '%s\n' "$hits"
  echo "CONFLICT MARKERS FOUND: resolve them before committing" >&2
  exit 1
fi
echo "no unresolved merge-conflict markers in tracked files"
