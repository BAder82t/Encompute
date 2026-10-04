#!/usr/bin/env bash
# Proves the TLS-library bans in deny.toml fire: a scratch crate (outside the
# repository, never committed) that depends on each banned crate must FAIL
# `cargo deny check bans`, and the workspace itself must pass it.
#
#   scripts/test-deny-tls-bans.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
ROOT="$PWD"
command -v cargo-deny >/dev/null 2>&1 || { echo "cargo-deny is not installed"; exit 2; }
W="$(mktemp -d "${TMPDIR:-/tmp}/deny-tls.XXXXXX")"
trap 'rm -rf "$W"' EXIT
# The repository's deny.toml without its [graph] (the scratch crate has none
# of the workspace's features): the same bans, the same reasons.
python3 - "$ROOT/deny.toml" "$W/deny.toml" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
t = re.sub(r"\[graph\].*?\n\]\n", "", t, count=1, flags=re.S)
assert "[graph]" not in t
open(sys.argv[2], "w").write(t)
PY
status=0
echo "cargo-deny: $(cargo deny --version)"
if cargo deny check bans >"$W/workspace.out" 2>&1; then echo "PASS  the workspace passes the bans"
else echo "FAIL  the workspace fails cargo deny check bans"; tail -5 "$W/workspace.out"; status=1; fi
for crate in openssl openssl-sys native-tls aws-lc-rs aws-lc-sys; do
  d="$W/$crate"
  mkdir -p "$d/src"; : > "$d/src/lib.rs"
  printf '[package]\nname = "scratch"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\n%s = "*"\n' "$crate" > "$d/Cargo.toml"
  # No --config (not an option of `check` in every cargo-deny version): the
  # config is discovered next to the manifest, from the directory we run in.
  cp "$W/deny.toml" "$d/deny.toml"
  (cd "$d" && cargo deny check bans >"$W/$crate.out" 2>&1); code=$?
  # Only a ban diagnostic for this crate counts. A usage error, a missing
  # network or any other failure is a hard FAIL, never a pass.
  if [ "$code" -eq 0 ]; then
    echo "FAIL  a crate depending on $crate was NOT refused"; status=1
  elif grep -qiE "^Usage:|unexpected argument" "$W/$crate.out"; then
    echo "FAIL  $crate: cargo-deny rejected its command line (usage error):"; head -5 "$W/$crate.out"; status=1
  elif grep -qE "error\[banned\]" "$W/$crate.out" && grep -E "banned" "$W/$crate.out" | grep -q "$crate"; then
    echo "PASS  $crate is refused (error[banned])"
  else
    echo "FAIL  $crate: failed, but not with a ban diagnostic:"; tail -8 "$W/$crate.out"; status=1
  fi
done
exit $status
