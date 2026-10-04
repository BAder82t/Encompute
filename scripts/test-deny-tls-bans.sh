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
if cargo deny check bans >/dev/null 2>&1; then echo "PASS  the workspace passes the bans"
else echo "FAIL  the workspace fails cargo deny check bans"; status=1; fi
for crate in openssl openssl-sys native-tls aws-lc-rs aws-lc-sys; do
  mkdir -p "$W/$crate/src"; : > "$W/$crate/src/lib.rs"
  printf '[package]\nname = "scratch"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\n%s = "*"\n' "$crate" > "$W/$crate/Cargo.toml"
  if (cd "$W/$crate" && cargo deny --manifest-path Cargo.toml check --config "$W/deny.toml" bans >"$W/$crate.out" 2>&1); then
    echo "FAIL  a crate depending on $crate was NOT refused"; status=1
  elif grep -q "$crate" "$W/$crate.out"; then echo "PASS  $crate is refused"
  else echo "FAIL  the check failed for another reason:"; tail -5 "$W/$crate.out"; status=1; fi
done
exit $status
