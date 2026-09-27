#!/usr/bin/env bash
# Reproducibility check: builds the release binaries twice, each in a fresh
# target directory at a different path, with the release environment
# (scripts/release/env.sh), and compares their SHA-256 digests.
#
#   scripts/release/repro-check.sh                 # CLI, no OpenFHE (fast)
#   scripts/release/repro-check.sh --openfhe       # CLI and evaluator with OpenFHE
#   scripts/release/repro-check.sh --packages "encompute-cli encompute-control"
#
# Exit status: 0 when every binary is byte-identical, 1 otherwise. A
# difference is reported with the first differing sections where the
# platform tools allow (docs/release-process.md explains the known ones).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
PACKAGES="encompute-cli"
FEATURES=""
KEEP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --openfhe) PACKAGES="encompute-cli encompute-evaluator"
               FEATURES="encompute-cli/openfhe,encompute-evaluator/openfhe" ;;
    --packages) PACKAGES="$2"; shift ;;
    --features) FEATURES="$2"; shift ;;
    --keep) KEEP=1 ;;
    *) echo "usage: $0 [--openfhe] [--packages \"a b\"] [--features f] [--keep]" >&2; exit 2 ;;
  esac
  shift
done
W="$(mktemp -d)"
[ -n "$KEEP" ] || trap 'rm -rf "$W"' EXIT

build() {  # build N
  local t="$W/build-$1/target"
  mkdir -p "$t"
  local args=(build --release --locked)
  for p in $PACKAGES; do args+=(-p "$p"); done
  [ -z "$FEATURES" ] || args+=(--features "$FEATURES")
  echo "== build $1 in $t"
  (
    # shellcheck source=/dev/null
    . scripts/release/env.sh "$t"
    echo "   SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
    cargo "${args[@]}" 2>&1 | tail -n 2
  ) || return 1
}

build 1 || { echo "REPRO CHECK FAILED: build 1"; exit 1; }
build 2 || { echo "REPRO CHECK FAILED: build 2"; exit 1; }

bins() {  # the binaries a package produces
  cargo metadata --format-version 1 --no-deps --locked | python3 -c '
import json, sys
wanted = set(sys.argv[1].split())
for p in json.load(sys.stdin)["packages"]:
    if p["name"] in wanted:
        for t in p["targets"]:
            if "bin" in t["kind"]:
                print(t["name"])' "$PACKAGES"
}

status=0
printf '\n%-28s %-66s %s\n' "binary" "sha256 (build 1)" "result"
for b in $(bins); do
  a="$W/build-1/target/release/$b"; c="$W/build-2/target/release/$b"
  [ -f "$a" ] && [ -f "$c" ] || { printf '%-28s %-66s %s\n' "$b" "-" "MISSING"; status=1; continue; }
  ha="$(shasum -a 256 "$a" | cut -d' ' -f1)"; hc="$(shasum -a 256 "$c" | cut -d' ' -f1)"
  if [ "$ha" = "$hc" ]; then
    printf '%-28s %-66s %s\n' "$b" "$ha" "IDENTICAL"
  else
    printf '%-28s %-66s %s\n' "$b" "$ha" "DIFFERENT (build 2: $hc)"
    status=1
    cmp -l "$a" "$c" | wc -l | xargs printf '    %s bytes differ\n'
    # Name the differing sections where the tools exist.
    if command -v objdump >/dev/null 2>&1; then
      for s in $(objdump -h "$a" 2>/dev/null | awk '/^ *[0-9]+ /{print $2}'); do
        if ! cmp -s <(objdump -s -j "$s" "$a" 2>/dev/null | tail -n +4) \
                    <(objdump -s -j "$s" "$c" 2>/dev/null | tail -n +4); then
          echo "    section differs: $s"
        fi
      done
    fi
    # Local paths that should have been remapped.
    for p in "$W/build-1" "$W/build-2" "$ROOT" "$HOME"; do
      n="$(strings "$a" | grep -c "$p" || true)"
      [ "$n" = "0" ] || echo "    $n strings still name $p"
    done
  fi
done
echo
[ $status -eq 0 ] && echo "REPRO CHECK PASSED: $PACKAGES byte-identical across two clean builds" ||
  echo "REPRO CHECK FAILED: see docs/release-process.md (Reproducibility)"
exit $status
