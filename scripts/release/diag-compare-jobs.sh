#!/usr/bin/env bash
# Diagnostic (nonpublishing): compares the digests that two independent runs of
# scripts/release/diag-openfhe-order.sh recorded, within each job and across
# the two. It never fails because digests differ.
#
#   scripts/release/diag-compare-jobs.sh DIR1 DIR2
set -uo pipefail
D1="${1:?usage: $0 DIR1 DIR2}"; D2="${2:?usage: $0 DIR1 DIR2}"
BINS=(encompute encompute-evaluator encompute-control)
CFGS=(A0 A B C D1 D2)
# The artifact may keep or drop a leading diag/ directory.
file_of() {  # file_of DIR CFG
  local f
  for f in "$1/digests-$2.txt" "$1/diag/digests-$2.txt"; do [ -f "$f" ] && { echo "$f"; return; }; done
}
dg() {  # dg DIR CFG BINARY
  local f; f="$(file_of "$1" "$2")"
  [ -n "$f" ] && awk -v b="$3" '$2==b {print $1}' "$f" || true
}
for d in "$D1" "$D2"; do
  for f in SUMMARY.txt host.txt; do
    for p in "$d/$f" "$d/diag/$f"; do [ -f "$p" ] && { echo "##### $p"; cat "$p"; break; }; done
  done
done
echo
echo "##### digests per configuration and binary (job 1 | job 2)"
printf '%-6s %-22s %-14s %-14s %s\n' cfg binary "job1" "job2" "across jobs"
ident=()
for c in "${CFGS[@]}"; do
  all=yes
  for b in "${BINS[@]}"; do
    a="$(dg "$D1" "$c" "$b")"; z="$(dg "$D2" "$c" "$b")"
    if [ -n "$a" ] && [ "$a" = "$z" ]; then r=identical; else r=DIFFERENT; all=no; fi
    printf '%-6s %-22s %-14s %-14s %s\n' "$c" "$b" "${a:0:12}" "${z:0:12}" "$r"
  done
  [ "$all" = yes ] && ident+=("$c")
done
echo
echo "##### within each job: configuration against configuration"
for job in "$D1" "$D2"; do
  echo "job: $job"
  for pair in "A B" "B C" "B D1" "A0 A" "D1 D2" "A D1"; do
    set -- $pair; y=0
    for b in "${BINS[@]}"; do
      x="$(dg "$job" "$1" "$b")"; w="$(dg "$job" "$2" "$b")"
      [ -n "$x" ] && [ "$x" = "$w" ] && y=$((y + 1))
    done
    printf '  %-7s identical for %d of %d binaries\n' "$1==$2" "$y" "${#BINS[@]}"
  done
done
echo
echo "##### configurations identical across the two independently provisioned jobs (all three binaries):"
if [ ${#ident[@]} -gt 0 ]; then echo "  ${ident[*]}"; else echo "  none"; fi
exit 0
