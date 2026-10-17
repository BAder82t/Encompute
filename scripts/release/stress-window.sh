#!/usr/bin/env bash
# Window stress, one test per run (nonpublishing). For every test of stress-summary.py --list:
# RUNS runs (the negative control: 5) of
#   cargo test -q -p encompute-control --test <bin> <name> -- --exact --nocapture
# under CPU load (LOAD_LOOPS busy loops, default 4 x cores), then the accounting of
# stress-summary.py. The status is the summary's; every run is attempted even after a failure.
#
#   scripts/release/stress-window.sh [LOGDIR]       LOGDIR defaults to stress-logs
#   env: RUNS (45), LOAD_LOOPS, ONLY (substring filter on the test name, for local tests),
#        DEADLINE_MIN (215: no new run is started after that many minutes, so the summary and the
#        logs still exist when the job's own 240 minute limit would have cut it; the missing runs
#        then fail the summary)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
LOGDIR="${1:-stress-logs}"
RUNS="${RUNS:-45}"
export RUNS
mkdir -p "$LOGDIR"
: > "$LOGDIR/results.tsv"

cores="$( (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1) | head -n1)"
LOAD_LOOPS="${LOAD_LOOPS:-$(( cores * 4 ))}"
for _ in $(seq "$LOAD_LOOPS"); do yes > /dev/null & done
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT
DEADLINE_MIN="${DEADLINE_MIN:-215}"
out_of_time=0
echo "load: $LOAD_LOOPS busy loops on $cores cores; $RUNS runs per proven-window test"

while IFS=$'\t' read -r bin name kind runs; do
  case "$name" in *"${ONLY:-}"*) ;; *) continue ;; esac
  for i in $(seq "$runs"); do
    if [ "$SECONDS" -ge $(( DEADLINE_MIN * 60 )) ]; then out_of_time=1; break; fi
    log="$LOGDIR/$bin.$name.$i.log"
    start=$SECONDS
    cargo test -q -p encompute-control --test "$bin" "$name" -- --exact --nocapture > "$log" 2>&1
    rc=$?
    printf '%s\t%s\t%s\t%s\t%s\n' "$bin" "$name" "$i" "$rc" "$(( SECONDS - start ))" >> "$LOGDIR/results.tsv"
    [ "$rc" = 0 ] || { echo "FAIL $bin $name run $i (exit $rc)"; tail -n 20 "$log"; }
  done
  echo "done $kind $name"
done < <(python3 "$ROOT/scripts/release/stress-summary.py" --list)

[ "$out_of_time" = 0 ] || echo "DEADLINE reached after ${DEADLINE_MIN} minutes: runs are missing"
kill $(jobs -p) 2>/dev/null || true
python3 "$ROOT/scripts/release/stress-summary.py" "$LOGDIR"
