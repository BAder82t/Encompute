#!/usr/bin/env bash
# TEST-ONLY, NONPUBLISHING diagnostic: reruns the two regression tests that failed in the
# v0.3.2 release workflow, many times, and records evidence to classify each failure as a
# harness defect, a product security failure or inconclusive.
#
#   w05_genesis_rewritten_in_the_window_of_the_first_spend   (anchor_window_adversarial)
#   role_removal_undone_in_the_window_is_not_acknowledged    (anchor_negatives)
#
# Phase A: the ORIGINAL, unmodified test binaries, run exactly as the release check runs
#          them (`cargo test -q -p encompute-control --test <binary>`, default parallelism),
#          and the single test alone (--exact).
# Phase B: the instrumented copies (generated, passive; see tests/diag/trace_window.rs),
#          same repetition, with ENCOMPUTE_TEST_TRACE=<file> per run.
#
# usage: diag-tests.sh <outdir>
# env:   ENCOMPUTE_TEST_DATABASE_URL   required (the PostgreSQL service)
#        DIAG_N              repetitions of each run kind (default 40)
#        DIAG_FULL_RUNS      whole-crate sequential runs, as the control plane row (default 2)
#        DIAG_RUNNER         label of this runner (default 1)
#        DIAG_PG_CONTAINER   docker id of the PostgreSQL service: when set and
#                            track_commit_timestamp is off, it is enabled between phase A and
#                            B (ALTER SYSTEM + restart) so phase B can order commits exactly
set -uo pipefail

OUT="${1:?usage: diag-tests.sh <outdir>}"
N="${DIAG_N:-40}"
FULL="${DIAG_FULL_RUNS:-2}"
RUNNER="${DIAG_RUNNER:-1}"
: "${ENCOMPUTE_TEST_DATABASE_URL:?set ENCOMPUTE_TEST_DATABASE_URL}"
mkdir -p "$OUT/logs" "$OUT/trace"
OUT="$(cd "$OUT" && pwd)"
RES="$OUT/results.jsonl"
: >"$RES"

ADV_BIN=anchor_window_adversarial
ADV_TEST=w05_genesis_rewritten_in_the_window_of_the_first_spend
NEG_BIN=anchor_negatives
NEG_TEST=role_removal_undone_in_the_window_is_not_acknowledged

psql_q() { # psql_q <sql>: through the service container when known, else the local client
  if [ -n "${DIAG_PG_CONTAINER:-}" ]; then
    docker exec "$DIAG_PG_CONTAINER" psql -U encompute -d encompute -Atc "$1"
  else
    psql "$ENCOMPUTE_TEST_DATABASE_URL" -Atc "$1"
  fi
}

record_env() {
  {
    echo "date: $(date -u +%FT%TZ)"
    echo "runner: $RUNNER  host: $(hostname)"
    uname -a
    echo "cpus: $(nproc 2>/dev/null || sysctl -n hw.ncpu)"
    grep -E 'MemTotal' /proc/meminfo 2>/dev/null || true
    echo "rustc: $(rustc -V)  cargo: $(cargo -V)"
    echo "N=$N FULL=$FULL"
    echo "commit: $(git rev-parse HEAD 2>/dev/null)"
    echo "--- postgres"
    for s in server_version max_connections track_commit_timestamp shared_buffers fsync synchronous_commit; do
      echo "$s = $(psql_q "SHOW $s" 2>&1)"
    done
    [ -n "${DIAG_PG_CONTAINER:-}" ] && docker inspect --format '{{.Config.Image}} {{.Image}}' "$DIAG_PG_CONTAINER"
  } >"$OUT/env-$1.txt" 2>&1
}

enable_commit_ts() {
  local cur
  cur="$(psql_q 'SHOW track_commit_timestamp' 2>/dev/null)"
  if [ "$cur" = on ]; then echo "track_commit_timestamp already on" | tee -a "$OUT/notes.txt"; return 0; fi
  if [ -z "${DIAG_PG_CONTAINER:-}" ]; then
    echo "track_commit_timestamp off and no container to restart: phase B orders commits by lock grant" | tee -a "$OUT/notes.txt"
    return 0
  fi
  psql_q "ALTER SYSTEM SET track_commit_timestamp = on" >/dev/null 2>&1 || true
  docker restart "$DIAG_PG_CONTAINER" >/dev/null 2>&1 || true
  local i
  for i in $(seq 1 60); do
    docker exec "$DIAG_PG_CONTAINER" pg_isready -U encompute -d encompute >/dev/null 2>&1 && break
    sleep 1
  done
  cur="$(psql_q 'SHOW track_commit_timestamp' 2>/dev/null)"
  echo "track_commit_timestamp after restart: ${cur:-unknown}" | tee -a "$OUT/notes.txt"
}

# run_one <variant> <mode> <iteration> <binary> <test> <require 0|1>
run_one() {
  local variant="$1" mode="$2" it="$3" bin="$4" test="$5" req="$6"
  local id="r${RUNNER}-${variant}-${mode}-${bin}-$(printf %03d "$it")"
  local b="$bin"
  [ "$variant" = traced ] && b="${bin}_traced"
  local log="logs/$id.log" tr=""
  # A fresh TMPDIR per run: the harness names its anchor directories after the process id, and
  # a reused id must never find the files of an earlier process.
  local tmp
  tmp="$(mktemp -d "$OUT/tmp.XXXXXX")"
  local -a env_cmd=(env "TMPDIR=$tmp")
  [ "$req" = 1 ] && env_cmd+=(ENCOMPUTE_REQUIRE_SERVICES=1)
  if [ "$variant" = traced ]; then tr="trace/$id.jsonl"; env_cmd+=("ENCOMPUTE_TEST_TRACE=$OUT/$tr"); fi
  local -a cmd=(cargo test -q -p encompute-control --test "$b")
  [ "$mode" = alone ] && cmd+=(-- --exact "$test")
  local t0 t1 rc
  t0=$(date +%s)
  "${env_cmd[@]}" "${cmd[@]}" >"$OUT/$log" 2>&1
  rc=$?
  t1=$(date +%s)
  rm -rf "$tmp"
  printf '{"id":"%s","runner":"%s","variant":"%s","mode":"%s","iteration":%d,"binary":"%s","test":"%s","rc":%d,"secs":%d,"start":%d,"log":"%s","trace":"%s"}\n' \
    "$id" "$RUNNER" "$variant" "$mode" "$it" "$b" "$test" "$rc" "$((t1 - t0))" "$t0" "$log" "$tr" >>"$RES"
  echo "[$(date -u +%T)] $id rc=$rc $((t1 - t0))s"
}

phase() { # phase <variant>
  local v="$1" i
  for ((i = 1; i <= N; i++)); do
    run_one "$v" load "$i" "$ADV_BIN" "$ADV_TEST" 0   # 'Rust workspace' row: no ENCOMPUTE_REQUIRE_SERVICES
    run_one "$v" load "$i" "$NEG_BIN" "$NEG_TEST" 1   # 'control plane' row: ENCOMPUTE_REQUIRE_SERVICES=1
    run_one "$v" alone "$i" "$ADV_BIN" "$ADV_TEST" 0
    run_one "$v" alone "$i" "$NEG_BIN" "$NEG_TEST" 1
  done
}

echo "== build (once)"
( cargo test -q -p encompute-control --no-run ) >"$OUT/build.log" 2>&1 || { tail -30 "$OUT/build.log"; echo "build failed"; exit 1; }
record_env before

echo "== phase A: original tests"
phase original

# Whole-crate sequential runs (all test binaries of the crate one after the other, as the
# control plane row runs them), original tests, to keep the sequence the release check has.
# The original test targets only (the instrumented copies are separate *_traced targets).
FULL_ARGS=(--lib --bins)
for f in crates/encompute-control/tests/*.rs; do
  b="$(basename "$f" .rs)"
  case "$b" in *_traced) ;; *) FULL_ARGS+=(--test "$b") ;; esac
done
for ((i = 1; i <= FULL; i++)); do
  id="r${RUNNER}-original-full-$(printf %03d "$i")"
  tmp="$(mktemp -d "$OUT/tmp.XXXXXX")"
  TMPDIR="$tmp" ENCOMPUTE_REQUIRE_SERVICES=1 cargo test -q -p encompute-control "${FULL_ARGS[@]}" >"$OUT/logs/$id.log" 2>&1
  rc=$?
  rm -rf "$tmp"
  printf '{"id":"%s","runner":"%s","variant":"original","mode":"full","iteration":%d,"binary":"all","test":"*","rc":%d,"secs":0,"start":0,"log":"logs/%s.log","trace":""}\n' \
    "$id" "$RUNNER" "$i" "$rc" "$id" >>"$RES"
  echo "[$(date -u +%T)] $id rc=$rc"
done

echo "== commit timestamps for phase B"
enable_commit_ts
record_env after

echo "== phase B: instrumented copies"
phase traced

echo "== classification"
python3 -I "$(dirname "$0")/diag-classify-window.py" "$OUT" --detail >"$OUT/classification.txt" 2>&1 || true
cat "$OUT/classification.txt"
