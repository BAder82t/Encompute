#!/usr/bin/env bash
# Fail-closed guard: a Linux release binary must not name a build path.
#
#   scripts/release/check-binary-paths.sh [--allowlist FILE] [--report-only] BINARY...
#
# The release build maps every local path to a fixed prefix (env.sh and
# install-openfhe.sh): /target, /encompute, /cargo, /rustup, /openfhe and
# /openfhe-src are the only prefixes a path in a binary may start with. This
# script looks at the printable strings of each binary (strings -a, or a
# python scan when `strings` is missing) and fails, listing the offending
# strings, if any of them contains:
#
#   /.deps/                      OpenFHE's checkout or install under .deps
#   /openfhe-development         OpenFHE's source tree
#   /home/ /Users/ /root/        a user's home directory (the runner's too)
#   /tmp/ /var/ /builds/ /runner/    a temporary or CI build directory
#
# Exit status: 0 clean, 1 a binary names a build path (or is missing/empty),
# 2 usage. --report-only prints the same report and always exits 0 (the
# nonpublishing diagnostic). An excused string is listed in the allowlist
# (default scripts/release/binary-paths.allow): one line per exception,
# "FIXED STRING<TAB>justification"; an offending string that contains the
# fixed string is excused. A line without a justification is an error.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ALLOW="$ROOT/scripts/release/binary-paths.allow"
REPORT_ONLY=0
FILES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --allowlist) ALLOW="${2:?--allowlist FILE}"; shift ;;
    --report-only) REPORT_ONLY=1 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    -*) echo "usage: $0 [--allowlist FILE] [--report-only] BINARY..." >&2; exit 2 ;;
    *) FILES+=("$1") ;;
  esac
  shift
done
[ ${#FILES[@]} -gt 0 ] || { echo "usage: $0 [--allowlist FILE] [--report-only] BINARY..." >&2; exit 2; }

PATTERN='/\.deps/|/openfhe-development|/(home|Users|root|tmp|var|builds|runner)/'

# The excused strings (fixed), with a justification each.
EXCUSE="$(mktemp)"; trap 'rm -f "$EXCUSE"' EXIT
if [ -f "$ALLOW" ]; then
  n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    case "$line" in ''|'#'*) continue ;; esac
    str="${line%%$'\t'*}"; why="${line#*$'\t'}"
    if [ "$str" = "$line" ] || [ -z "$str" ] || [ -z "${why// /}" ]; then
      echo "check-binary-paths: $ALLOW line $n needs 'string<TAB>justification'" >&2; exit 2
    fi
    printf '%s\n' "$str" >> "$EXCUSE"
  done < "$ALLOW"
else
  echo "check-binary-paths: allowlist $ALLOW not found" >&2; exit 2
fi

printable() {  # printable FILE: the printable strings, one per line
  if command -v strings >/dev/null 2>&1; then strings -a "$1"
  else python3 -I -c '
import re, sys
data = open(sys.argv[1], "rb").read()
for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
    print(m.group().decode("ascii"))' "$1"
  fi
}

status=0
for f in "${FILES[@]}"; do
  if [ ! -s "$f" ]; then echo "FAIL  $f: missing or empty"; status=1; continue; fi
  hits="$(printable "$f" | grep -E -- "$PATTERN" || true)"
  if [ -s "$EXCUSE" ] && [ -n "$hits" ]; then
    hits="$(printf '%s\n' "$hits" | grep -vF -f "$EXCUSE" || true)"
  fi
  if [ -z "$hits" ]; then
    echo "PASS  $f: no build path"
  else
    cnt="$(printf '%s\n' "$hits" | wc -l | tr -d ' ')"
    echo "FAIL  $f: $cnt string(s) name a build path"
    printf '%s\n' "$hits" | sort -u | head -n 20 | cut -c1-240 | sed 's/^/    | /'
    [ "$cnt" -le 20 ] || echo "    | ... ($cnt in all; the first 20 distinct shown)"
    status=1
  fi
done
if [ $status -ne 0 ]; then
  echo "BINARY PATH CHECK FAILED: a release binary names a build path; fix the path remap (scripts/release/env.sh, scripts/install-openfhe.sh) rather than the allowlist"
  [ $REPORT_ONLY = 1 ] && { echo "(report only: exit status 0)"; exit 0; }
  exit 1
fi
echo "BINARY PATH CHECK PASSED"
