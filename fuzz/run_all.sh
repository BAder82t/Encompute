#!/usr/bin/env bash
# Runs every fuzz target (or those named) for SECONDS each; exits non-zero
# if any target found a crash, timeout or out-of-memory input.
#
#   fuzz/run_all.sh 300                 # 5 minutes per target
#   fuzz/run_all.sh 60 eir_parse pool_frame
#
# New corpus entries go to $FUZZ_WORK/corpus/<target> (the checked-in seeds
# in fuzz/corpus are read, never written); findings go to
# $FUZZ_WORK/artifacts/<target>/ and logs to $FUZZ_WORK/<target>.log.
set -uo pipefail

cd "$(dirname "$0")"
secs="${1:?usage: run_all.sh SECONDS [target...]}"
shift
work="${FUZZ_WORK:-$PWD/work}"
# AddressSanitizer on Linux. On macOS its runtime can deadlock at start-up
# under recent dyld, so the default there is no sanitizer (Rust code is
# memory safe; panics, aborts, timeouts and OOMs are still caught).
if [ "$(uname -s)" = Darwin ]; then
  sanitizer="${FUZZ_SANITIZER:-none}"
else
  sanitizer="${FUZZ_SANITIZER:-address}"
fi
if [ "$#" -eq 0 ]; then
  set -- $(cargo +nightly fuzz list)
fi

cargo +nightly fuzz build -O -s "$sanitizer" || exit 1
failed=0
for t in "$@"; do
  mkdir -p "$work/corpus/$t" "$work/artifacts/$t"
  cargo +nightly fuzz run -O -s "$sanitizer" "$t" "$work/corpus/$t" "corpus/$t" -- \
    -max_total_time="$secs" -rss_limit_mb=4096 -timeout=30 -print_final_stats=1 \
    -artifact_prefix="$work/artifacts/$t/" >"$work/$t.log" 2>&1
  status=$?
  if [ "$status" -ne 0 ] || [ -n "$(ls -A "$work/artifacts/$t")" ]; then
    echo "FAIL $t (exit $status): see $work/$t.log"
    grep -E 'panicked|ERROR|SUMMARY|Test unit written' "$work/$t.log" | head -5
    failed=1
  else
    echo "ok   $t $(grep -E '^stat::number_of_executed_units' "$work/$t.log" | head -1)"
  fi
done
exit "$failed"
