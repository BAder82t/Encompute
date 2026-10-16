#!/usr/bin/env bash
# Diagnostic experiment (nonpublishing): does the order of exporting OPENFHE_ROOT
# and sourcing scripts/release/env.sh change the bytes of the release binaries?
#
# Run from the repository root after scripts/install-openfhe.sh. It builds the
# three release binaries in clean, separate target directories:
#
#   A0  OLD ORDER, EXPECTED TO DIFFER, in $PWD/target. The v0.3.1 shipping
#       order (env.sh sourced with OPENFHE_ROOT still unset, exported after),
#       kept as the intentionally defective reference. It is not part of any
#       pass/fail.
#   A   OLD ORDER, EXPECTED TO DIFFER, in diag/target-A:
#         . scripts/release/env.sh DIR; export OPENFHE_ROOT=...; cargo build ...
#       (env.sh now defaults OPENFHE_ROOT when the install exists, so for
#       A0 and A the install directory is hidden while env.sh is sourced.)
#   B   THE SHIPPING BUILD: scripts/release/build-release-binaries.sh, the
#       script the binaries job runs, with OPENFHE_ROOT given before env.sh
#   C   B again, in a fresh shell and a fresh target directory
#   D   the gate's way: OPENFHE_ROOT exported, then repro-check.sh --openfhe
#       (it builds twice by itself: D1 and D2)
#
# and writes into diag/: digests-<cfg>.txt, paths-<cfg>-<binary>.txt,
# env-<cfg>.txt, host.txt, SUMMARY.txt and the binaries (diag/bin/<cfg>/).
# A difference of digests never fails the script (it is an experiment); a
# failed build does.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
OUT="$ROOT/diag"
BINS=(encompute encompute-evaluator encompute-control)
PKGS=(-p encompute-cli -p encompute-evaluator -p encompute-control)
FEATURES="encompute-cli/openfhe,encompute-evaluator/openfhe"
OPENFHE_DIR="$ROOT/.deps/openfhe"
PATTERNS=('/openfhe/' '/.deps/' '/home/runner' 'openfhe-development' '/encompute/.deps')

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

mkdir -p "$OUT/bin"

# The same timestamp in every configuration: the commit's, as the shipping job's.
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export SOURCE_DATE_EPOCH
echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
echo "commit: $(git rev-parse HEAD)"

host_info() {
  echo "gcc: $(gcc --version 2>&1 | head -1)"
  echo "cmake: $(cmake --version 2>&1 | head -1)"
  echo "ImageVersion: ${ImageVersion:-unset}"
  echo "ImageOS: ${ImageOS:-unset}"
  echo "uname: $(uname -a)"
  echo "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"
  echo "commit: $(git rev-parse HEAD)"
  echo "--- lscpu Model name"; (lscpu 2>/dev/null | grep 'Model name') || true
  echo "--- /proc/cpuinfo model name"; (grep -m1 'model name' /proc/cpuinfo 2>/dev/null) || true
  echo "--- rustc -Vv"; rustc -Vv 2>&1 || true
  echo "--- cargo -V"; cargo -V 2>&1 || true
}
host_info | tee "$OUT/host.txt"

# Environment of one configuration, without secrets and GitHub's own variables.
dump_env() {  # dump_env CFG
  {
    echo "# env of $1 (filtered)"
    env | sort | grep -viE '^(GITHUB_|ACTIONS_|RUNNER_TRACKING)|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE|_KEY=' || true
    echo "# the build variables"
    for v in RUSTFLAGS CFLAGS CXXFLAGS SOURCE_DATE_EPOCH OPENFHE_ROOT CARGO_TARGET_DIR ZERO_AR_DATE; do
      echo "$v=${!v-<unset>}"
    done
    env | sort | grep '^CARGO_' || true
  } > "$OUT/env-$1.txt"
}

# What a configuration starts from: nothing of an earlier configuration.
clean_env() {
  unset RUSTFLAGS CFLAGS CXXFLAGS OPENFHE_ROOT CARGO_TARGET_DIR ENCOMPUTE_EXTRA_RUSTFLAGS \
        CARGO_INCREMENTAL CARGO_PROFILE_RELEASE_CODEGEN_UNITS CARGO_PROFILE_RELEASE_DEBUG \
        CARGO_PROFILE_RELEASE_INCREMENTAL ZERO_AR_DATE
}

# Keep the binaries, their digests and their path-string reports.
collect() {  # collect CFG BINDIR [TAG]
  local cfg="$1" dir="$2"
  mkdir -p "$OUT/bin/$cfg"
  : > "$OUT/digests-$cfg.txt"
  local b
  for b in "${BINS[@]}"; do
    [ -f "$dir/$b" ] || { echo "MISSING $dir/$b" >&2; return 1; }
    cp "$dir/$b" "$OUT/bin/$cfg/$b"
    echo "$(sha "$dir/$b")  $b" >> "$OUT/digests-$cfg.txt"
    path_report "$cfg" "$b" "$dir/$b"
  done
  # The path guard of the release, in report-only mode: it never fails this
  # experiment, it records what the release guard would say.
  scripts/release/check-binary-paths.sh --report-only \
    "$dir/${BINS[0]}" "$dir/${BINS[1]}" "$dir/${BINS[2]}" > "$OUT/pathguard-$cfg.txt" 2>&1 || true
}

# The strings of a binary that name build paths: counts and the first 40 lines.
path_report() {  # path_report CFG BINARY FILE
  local f="$OUT/paths-$1-$2.txt" tmp
  tmp="$(mktemp)"
  strings -a "$3" > "$tmp"
  {
    echo "# $1 $2 sha256=$(sha "$3")"
    local p
    for p in "${PATTERNS[@]}"; do
      echo "count[$p]=$(grep -cF -- "$p" "$tmp" || true)"
    done
    echo "lines matching any pattern=$(grep -cE -- "$(printf '%s|' "${PATTERNS[@]}" | sed 's/|$//')" "$tmp" || true)"
    echo "--- first 40 matching lines"
    grep -E -- "$(printf '%s|' "${PATTERNS[@]}" | sed 's/|$//')" "$tmp" | head -n 40 || true
  } > "$f"
  rm -f "$tmp"
}

build_cfg() {  # build_cfg CFG ORDER TARGET   (ORDER: old-order = the defective v0.3.1 order | root-first | ship = the shipping script)
  local cfg="$1" order="$2" target="$3"
  echo "=== configuration $cfg ($order) in $target"
  if [ "$order" = ship ]; then
    # The real shipping script, by construction. It sources env.sh itself, so
    # nothing is sourced beforehand (env.sh appends to CFLAGS and CXXFLAGS).
    (
      clean_env
      OPENFHE_ROOT="$OPENFHE_DIR" scripts/release/build-release-binaries.sh "$target"
    )
    # The environment the script used, recorded from a separate subshell.
    ( clean_env; export OPENFHE_ROOT="$OPENFHE_DIR"; . scripts/release/env.sh "$target"; dump_env "$cfg" )
    ( clean_env; collect "$cfg" "$target/release" )
    rm -rf "$target"
    return 0
  fi
  (
    clean_env
    case "$order" in
      old-order)  # the OLD order: env.sh runs while OPENFHE_ROOT is unset
        mv "$OPENFHE_DIR" "$OPENFHE_DIR.hidden"
        rc=0; . scripts/release/env.sh "$target" || rc=$?
        mv "$OPENFHE_DIR.hidden" "$OPENFHE_DIR"
        [ "$rc" = 0 ] || exit "$rc"
        export OPENFHE_ROOT="$OPENFHE_DIR" ;;
      root-first)
        export OPENFHE_ROOT="$OPENFHE_DIR"
        . scripts/release/env.sh "$target" ;;
    esac
    dump_env "$cfg"
    cargo build --release --locked "${PKGS[@]}" --features "$FEATURES"
    collect "$cfg" "$target/release"
  )
  rm -rf "$target"
}

build_cfg A0 old-order "$ROOT/target"
build_cfg A old-order "$OUT/target-A"
build_cfg B ship "$OUT/target-B"
build_cfg C ship "$OUT/target-C"

# D: the gate's invocation (scripts/release-check.sh exports OPENFHE_ROOT, then
# runs repro-check.sh --openfhe --digests ...). --keep leaves its two builds
# in a temporary directory so that both can be read.
echo "=== configuration D (gate style, two internal builds)"
(
  clean_env
  export OPENFHE_ROOT="$OPENFHE_DIR"
  dump_env D
  set +e
  scripts/release/repro-check.sh --openfhe --keep --digests "$OUT/D-digests.txt" > "$OUT/D-repro.log" 2>&1
  rc=$?
  set -e
  cat "$OUT/D-repro.log"
  echo "repro-check exit status: $rc" | tee -a "$OUT/D-repro.log"
  if grep -q 'REPRO CHECK FAILED: build\|REPRO CHECK FAILED: could not\|REPRO CHECK FAILED: no binar' "$OUT/D-repro.log"; then
    echo "a build of configuration D failed" >&2
    exit 1
  fi
  d1="$(sed -n 's/^== build 1 in \(.*\)$/\1/p' "$OUT/D-repro.log" | head -n 1)"
  d2="$(sed -n 's/^== build 2 in \(.*\)$/\1/p' "$OUT/D-repro.log" | head -n 1)"
  [ -d "$d1/release" ] && [ -d "$d2/release" ] || { echo "cannot find the kept builds of D" >&2; exit 1; }
  collect D1 "$d1/release"
  collect D2 "$d2/release"
  rm -rf "$(dirname "$(dirname "$d1")")"
)

# ---- summary ----
CFGS=(A0 A B C D1 D2)
digest_of() {  # digest_of CFG BINARY
  awk -v b="$2" '$2==b {print $1}' "$OUT/digests-$1.txt" 2>/dev/null
}
same() {  # same CFG1 CFG2 -> "yes", "no" or "partial (bin=yes/no ...)"
  local y=0 n=0 detail="" b r
  for b in "${BINS[@]}"; do
    if [ "$(digest_of "$1" "$b")" = "$(digest_of "$2" "$b")" ] && [ -n "$(digest_of "$1" "$b")" ]; then
      y=$((y + 1)); r=yes; else n=$((n + 1)); r=no; fi
    detail="$detail $b=$r"
  done
  if [ $n -eq 0 ]; then echo yes; elif [ $y -eq 0 ]; then echo "no ($detail )"; else echo "partial ($detail )"; fi
}
{
  echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
  echo "commit=$(git rev-parse HEAD)"
  echo
  printf '%-6s' cfg; for b in "${BINS[@]}"; do printf ' %-66s' "$b"; done; echo
  for c in "${CFGS[@]}"; do
    printf '%-6s' "$c"
    for b in "${BINS[@]}"; do printf ' %-66s' "$(digest_of "$c" "$b")"; done
    echo
  done
  echo
  echo "(A and A0 are the old order, expected to differ from B; informational only)"
  echo "A==B?   $(same A B)"
  echo "B==C?   $(same B C)"
  echo "B==D?   $(same B D1)   (D2: $(same B D2))"
  echo "A0==A?  $(same A0 A)"
  echo "D1==D2? $(same D1 D2)"
  echo "A==D?   $(same A D1)"
  echo
  echo "# the release path guard (report only), verdict per configuration"
  for c in "${CFGS[@]}"; do
    if [ -f "$OUT/pathguard-$c.txt" ]; then
      printf '%-6s %s binaries with build paths (of 3)\n' "$c" "$(grep -c '^FAIL' "$OUT/pathguard-$c.txt" || true)"
    else printf '%-6s n/a\n' "$c"; fi
  done
  echo
  echo "# build-path strings per binary (count of lines matching any pattern)"
  for c in "${CFGS[@]}"; do
    for b in "${BINS[@]}"; do
      printf '%-6s %-22s %s\n' "$c" "$b" "$(grep '^lines matching' "$OUT/paths-$c-$b.txt" 2>/dev/null || echo n/a)"
    done
  done
} | tee "$OUT/SUMMARY.txt"
exit 0
