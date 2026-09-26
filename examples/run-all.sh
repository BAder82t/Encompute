#!/usr/bin/env bash
# Runs the examples and checks each against its expected.txt (every
# non-comment line must appear in the output; unstable values such as IDs,
# timings and ciphertexts are never listed there).
#
#   examples/run-all.sh quick      mock-only examples, a couple of minutes
#   examples/run-all.sh standard   every example that needs no cloud or crypto build
#   examples/run-all.sh crypto     the OpenFHE / OpenFHE exact / verified-execution examples
#   examples/run-all.sh full       everything this machine can run
#
# Build first: cargo build --bins, and (for Python examples)
# maturin develop -m crates/encompute-py/Cargo.toml.
set -uo pipefail
cd "$(dirname "$0")"
MODE="${1:-quick}"

QUICK="01 02 04 06 08 09 10 11 13 14 15"
STANDARD="$QUICK 03 07 12 16 17 18"
CRYPTO="01 03 05 19"
case "$MODE" in
  quick) LIST="$QUICK" ;;
  standard) LIST="$STANDARD" ;;
  crypto) LIST="$CRYPTO" ;;
  full) LIST="$STANDARD 05 19" ;;
  *) echo "usage: $0 quick|standard|crypto|full" >&2; exit 2 ;;
esac
export EXAMPLES_MODE="$MODE"

pass=0; fail=0; skipped=0
for n in $(echo $LIST | tr ' ' '\n' | sort -u); do
  dir="$(ls -d ${n}_*/ 2>/dev/null | head -n 1)"
  dir="${dir%/}"
  [ -n "$dir" ] || { echo "no example $n" >&2; fail=$((fail + 1)); continue; }
  start=$(date +%s)
  out="$(bash "$dir/run.sh" 2>&1)"
  code=$?
  secs=$(( $(date +%s) - start ))
  if [ $code -eq 77 ]; then
    reason="$(echo "$out" | sed -n 's/^Reason: //p' | head -n 1)"
    # EXAMPLES_REQUIRE lists examples that must run (a release gate).
    if echo " ${EXAMPLES_REQUIRE:-} " | grep -q " $n "; then
      printf '%-34s FAIL     (required, but skipped: %s)\n' "$dir" "$reason"
      fail=$((fail + 1))
    else
      printf '%-34s SKIPPED  %s\n' "$dir" "$reason"
      skipped=$((skipped + 1))
    fi
    continue
  fi
  missing=""
  if [ $code -eq 0 ] && [ -f "$dir/expected.txt" ]; then
    while IFS= read -r line; do
      case "$line" in ''|'#'*) continue ;; esac
      echo "$out" | grep -qF -- "$line" || missing="$missing\n    missing: $line"
    done < "$dir/expected.txt"
  fi
  if [ $code -eq 0 ] && [ -z "$missing" ]; then
    printf '%-34s PASS     (%ss)\n' "$dir" "$secs"
    pass=$((pass + 1))
  else
    printf '%-34s FAIL     (exit %s)%b\n' "$dir" "$code" "$missing"
    echo "$out" | tail -n 25 | sed 's/^/    | /'
    fail=$((fail + 1))
  fi
done
printf '\n%s passed, %s failed, %s skipped (%s)\n' "$pass" "$fail" "$skipped" "$MODE"
[ $fail -eq 0 ]
